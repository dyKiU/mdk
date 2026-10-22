//! Experimental storage for account-synchronized archives, never MLS evidence.
//!
//! The caller authenticates device membership, consent and the manifest over the
//! pairing channel before admission. Hashes here bind that admitted manifest to
//! its chunks; they are integrity checks, not signatures or enrollment proofs.
//! Staged records are invisible until the final chunk commits. Imported records
//! cannot authorize moderation, change membership or advance recovery cursors.

use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::StorageError;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_SYNCHRONIZED_HISTORY_CHUNKS: usize = 128;
pub const MAX_SYNCHRONIZED_HISTORY_RECORDS_PER_CHUNK: usize = 200;
pub const MAX_SYNCHRONIZED_HISTORY_CHUNK_BYTES: usize = 1_048_576;
pub const MAX_SYNCHRONIZED_HISTORY_TRANSFERS: i64 = 128;
pub const MAX_SYNCHRONIZED_HISTORY_PAGE: usize = 200;
pub const MAX_SYNCHRONIZED_HISTORY_BYTES: i64 = 536_870_912;

#[derive(thiserror::Error, Debug)]
pub enum SynchronizedHistoryError {
    #[error("synchronized history storage failed: {0}")]
    Storage(#[from] StorageError),
    #[error("synchronized history manifest is invalid")]
    InvalidManifest,
    #[error("synchronized history account does not match this store")]
    WrongAccount,
    #[error("synchronized history transfer binding changed")]
    TransferConflict,
    #[error("synchronized history chunk integrity failed")]
    IntegrityMismatch,
    #[error("synchronized history chunk is out of order")]
    OutOfOrder,
    #[error("synchronized history record conflicts with retained history")]
    RecordConflict,
    #[error("synchronized history limit exceeded")]
    LimitExceeded,
    #[error("synchronized history import cancelled")]
    Cancelled,
}
type Result<T> = std::result::Result<T, SynchronizedHistoryError>;

/// Already authenticated, recipient-specific transfer context. No secret fields.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynchronizedHistoryBinding {
    pub transfer_id: [u8; 32],
    pub account_id: [u8; 32],
    pub source_device: [u8; 32],
    pub recipient_device: [u8; 32],
    /// Opaque variable-length MLS group id encoded as lowercase hex.
    pub group_id_hex: String,
    pub snapshot_timestamp_ceiling: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynchronizedHistoryManifest {
    pub binding: SynchronizedHistoryBinding,
    /// Ordered digests; the manifest must be authenticated by the caller.
    pub chunk_digests: Vec<[u8; 32]>,
    /// Receiving device's explicit retention floor, fixed for this transfer.
    pub retain_since: u64,
    /// Receiving-device ceiling, independent of any exporter-supplied expiry.
    /// None preserves non-disappearing history; Some never extends source expiry.
    pub max_record_lifetime_seconds: Option<u64>,
}

/// An exporter-attested logical record, never independently MLS-verified.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynchronizedHistoryRecord {
    pub message_id: [u8; 32],
    pub author: [u8; 32],
    pub created_at: u64,
    pub kind: u64,
    /// Exact logical archive bytes; storage never parses or applies this payload.
    pub payload: Vec<u8>,
    pub expires_at: Option<u64>,
    /// A tombstone suppresses synchronized copies, never authenticated traffic.
    pub deleted: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProvenancedSynchronizedHistoryRecord {
    pub record: SynchronizedHistoryRecord,
    pub transfer_id: [u8; 32],
    pub source_device: [u8; 32],
    pub manifest_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SynchronizedHistoryImportProgress {
    pub imported_records: usize,
    pub skipped_records: usize,
    pub next_chunk: usize,
    pub complete: bool,
    pub replayed: bool,
}

fn bounded_sql_usize(value: i64, maximum: usize) -> Result<usize> {
    let value = usize::try_from(value).map_err(|_| SynchronizedHistoryError::InvalidManifest)?;
    if value > maximum {
        return Err(SynchronizedHistoryError::InvalidManifest);
    }
    Ok(value)
}

fn bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| SynchronizedHistoryError::InvalidManifest)
}

fn digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    for part in parts {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

impl SynchronizedHistoryManifest {
    pub fn digest(&self) -> Result<[u8; 32]> {
        validate_manifest(self)?;
        Ok(digest(
            b"marmot-experimental-history-manifest-v1",
            &[&bytes(self)?],
        ))
    }
}

/// Stable v1 integrity encoding. It binds every chunk to the exact transfer,
/// source/recipient devices, account, group, snapshot timestamp ceiling and chunk ordinal.
pub fn synchronized_history_chunk_digest(
    binding: &SynchronizedHistoryBinding,
    index: usize,
    records: &[SynchronizedHistoryRecord],
) -> Result<[u8; 32]> {
    validate_records(records)?;
    if index >= MAX_SYNCHRONIZED_HISTORY_CHUNKS {
        return Err(SynchronizedHistoryError::LimitExceeded);
    }
    let body = bytes(&records)?;
    if body.len() > MAX_SYNCHRONIZED_HISTORY_CHUNK_BYTES {
        return Err(SynchronizedHistoryError::LimitExceeded);
    }
    Ok(digest(
        b"marmot-experimental-history-chunk-v1",
        &[&bytes(binding)?, &(index as u64).to_be_bytes(), &body],
    ))
}

fn validate_manifest(manifest: &SynchronizedHistoryManifest) -> Result<()> {
    let b = &manifest.binding;
    if b.group_id_hex.is_empty() || b.group_id_hex.len() > 510 {
        return Err(SynchronizedHistoryError::InvalidManifest);
    }
    let group =
        hex::decode(&b.group_id_hex).map_err(|_| SynchronizedHistoryError::InvalidManifest)?;
    if group.is_empty()
        || group.len() > 255
        || hex::encode(&group) != b.group_id_hex
        || b.source_device == b.recipient_device
        || b.snapshot_timestamp_ceiling > i64::MAX as u64
        || manifest.retain_since > b.snapshot_timestamp_ceiling
        || manifest
            .max_record_lifetime_seconds
            .is_some_and(|t| t > i64::MAX as u64)
        || manifest.chunk_digests.is_empty()
    {
        return Err(SynchronizedHistoryError::InvalidManifest);
    }
    if manifest.chunk_digests.len() > MAX_SYNCHRONIZED_HISTORY_CHUNKS {
        return Err(SynchronizedHistoryError::LimitExceeded);
    }
    if bytes(manifest)?.len() > 32768 {
        return Err(SynchronizedHistoryError::LimitExceeded);
    }
    Ok(())
}

fn validate_records(records: &[SynchronizedHistoryRecord]) -> Result<()> {
    if records.len() > MAX_SYNCHRONIZED_HISTORY_RECORDS_PER_CHUNK {
        return Err(SynchronizedHistoryError::LimitExceeded);
    }
    for record in records {
        if record.payload.len() > 65_536 {
            return Err(SynchronizedHistoryError::LimitExceeded);
        }
        if record.created_at > i64::MAX as u64
            || record.kind > i64::MAX as u64
            || record.expires_at.is_some_and(|t| t > i64::MAX as u64)
            || (record.deleted && !record.payload.is_empty())
        {
            return Err(SynchronizedHistoryError::InvalidManifest);
        }
    }
    Ok(())
}

fn logical_identity_digest(record: &SynchronizedHistoryRecord) -> Result<[u8; 32]> {
    Ok(digest(
        b"marmot-experimental-history-record-v1",
        &[&bytes(&(
            record.message_id,
            record.author,
            record.created_at,
            record.kind,
            &record.payload,
        ))?],
    ))
}

fn refresh_history_byte_accounting(conn: &rusqlite::Connection, group: &str) -> Result<()> {
    conn.execute("UPDATE synchronized_history_transfers AS t SET charged_bytes=(SELECT coalesce(sum(length(record_json)),0) FROM synchronized_history_records WHERE transfer_id=t.transfer_id) WHERE group_id_hex=?1",[group]).storage()?;
    Ok(())
}

impl SqliteAccountStorage {
    /// Persist an authenticated transfer manifest. Re-admission is idempotent
    /// only for an identical manifest; no existing transfer can be overwritten.
    pub fn admit_synchronized_history(&self, manifest: &SynchronizedHistoryManifest) -> Result<()> {
        let hash = manifest.digest()?;
        let encoded = bytes(manifest)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let account_matches: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM account_state WHERE local_account_id_hex=?1)",
                [hex::encode(manifest.binding.account_id)], |r| r.get(0),
            ).storage()?;
            if !account_matches { return Err(SynchronizedHistoryError::WrongAccount); }
            let previous: Option<(Vec<u8>, bool)> = conn.query_row(
                "SELECT manifest_digest,cancelled FROM synchronized_history_transfers WHERE transfer_id=?1",
                [manifest.binding.transfer_id.as_slice()], |r| Ok((r.get(0)?, r.get(1)?)),
            ).optional().storage()?;
            if let Some((previous, cancelled)) = previous {
                if cancelled { return Err(SynchronizedHistoryError::Cancelled); }
                return if previous == hash { Ok(()) } else { Err(SynchronizedHistoryError::TransferConflict) };
            }
            let count: i64 = conn.query_row("SELECT count(*) FROM synchronized_history_transfers", [], |r| r.get(0)).storage()?;
            if count >= MAX_SYNCHRONIZED_HISTORY_TRANSFERS { return Err(SynchronizedHistoryError::LimitExceeded); }
            conn.execute(
                "INSERT INTO synchronized_history_transfers(transfer_id,group_id_hex,source_device,manifest_digest,manifest_json,next_chunk,complete) VALUES(?1,?2,?3,?4,?5,0,0)",
                params![manifest.binding.transfer_id.as_slice(), manifest.binding.group_id_hex, manifest.binding.source_device.as_slice(), hash.as_slice(), encoded],
            ).storage()?;
            Ok(())
        })
    }

    /// Commit one bounded chunk with its receipt in one transaction. A callback
    /// cancellation rolls back every write from this chunk, including completion.
    /// Previously committed chunks remain resumable after terminal store close.
    pub fn import_synchronized_history_chunk(
        &self,
        manifest: &SynchronizedHistoryManifest,
        index: usize,
        records: &[SynchronizedHistoryRecord],
        now: u64,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<SynchronizedHistoryImportProgress> {
        if now > i64::MAX as u64 {
            return Err(SynchronizedHistoryError::InvalidManifest);
        }
        if cancelled() {
            return Err(SynchronizedHistoryError::Cancelled);
        }
        let manifest_hash = manifest.digest()?;
        let chunk_hash = synchronized_history_chunk_digest(&manifest.binding, index, records)?;
        if manifest.chunk_digests.get(index) != Some(&chunk_hash) {
            return Err(SynchronizedHistoryError::IntegrityMismatch);
        }
        if records
            .iter()
            .any(|r| r.created_at > manifest.binding.snapshot_timestamp_ceiling)
        {
            return Err(SynchronizedHistoryError::InvalidManifest);
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let stored: Option<(Vec<u8>, i64, bool, bool)> = conn.query_row(
                "SELECT manifest_digest,next_chunk,complete,cancelled FROM synchronized_history_transfers WHERE transfer_id=?1",
                [manifest.binding.transfer_id.as_slice()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            ).optional().storage()?;
            let Some((stored_hash, next, complete, permanently_cancelled)) = stored else { return Err(SynchronizedHistoryError::TransferConflict); };
            let next = bounded_sql_usize(next, MAX_SYNCHRONIZED_HISTORY_CHUNKS)?;
            if permanently_cancelled { return Err(SynchronizedHistoryError::Cancelled); }
            if stored_hash != manifest_hash { return Err(SynchronizedHistoryError::TransferConflict); }
            if index < next {
                let receipt: (Vec<u8>, i64, i64) = conn.query_row(
                    "SELECT chunk_digest,imported_records,skipped_records FROM synchronized_history_chunks WHERE transfer_id=?1 AND chunk_index=?2",
                    params![manifest.binding.transfer_id.as_slice(), index as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                ).storage()?;
                if receipt.0 != chunk_hash { return Err(SynchronizedHistoryError::IntegrityMismatch); }
                return Ok(SynchronizedHistoryImportProgress { imported_records: bounded_sql_usize(receipt.1, MAX_SYNCHRONIZED_HISTORY_RECORDS_PER_CHUNK)?, skipped_records: bounded_sql_usize(receipt.2, MAX_SYNCHRONIZED_HISTORY_RECORDS_PER_CHUNK)?, next_chunk: next, complete, replayed: true });
            }
            if index != next || complete { return Err(SynchronizedHistoryError::OutOfOrder); }

            let mut imported = 0;
            let mut skipped = 0;
            for original in records {
                let mut effective = original.clone();
                if let Some(lifetime) = manifest.max_record_lifetime_seconds {
                    let ceiling = effective.created_at.saturating_add(lifetime).min(i64::MAX as u64);
                    effective.expires_at = Some(effective.expires_at.map_or(ceiling, |source| source.min(ceiling)));
                }
                let record = &effective;
                if cancelled() { return Err(SynchronizedHistoryError::Cancelled); }
                let id = hex::encode(record.message_id);
                let live: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM app_events WHERE group_id_hex=?1 AND message_id_hex=?2)",
                    params![manifest.binding.group_id_hex, id], |r| r.get(0),
                ).storage()?;
                let fenced: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM synchronized_history_retention_fences WHERE group_id_hex=?1 AND message_id_hex=?2)", params![manifest.binding.group_id_hex, id], |r| r.get(0)).storage()?;
                if !record.deleted && (record.created_at < manifest.retain_since || record.expires_at.is_some_and(|t| t <= now)) {
                    conn.execute("INSERT OR IGNORE INTO synchronized_history_retention_intents(transfer_id,message_id_hex) VALUES(?1,?2)", params![manifest.binding.transfer_id.as_slice(), id]).storage()?;
                    skipped += 1; continue;
                }
                let tombstoned: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM synchronized_history_records r JOIN synchronized_history_transfers t USING(transfer_id) WHERE t.group_id_hex=?1 AND r.message_id_hex=?2 AND r.deleted=1 AND (t.complete=1 OR t.transfer_id=?3))", params![manifest.binding.group_id_hex, id, manifest.binding.transfer_id.as_slice()], |r| r.get(0)).storage()?;
                if live || fenced || (!record.deleted && tombstoned) { skipped += 1; continue; }
                let body = bytes(original)?;
                let identity = logical_identity_digest(original)?;
                // Logical message bodies are immutable. A tombstone can only
                // suppress synchronized copies, never alter live moderation.
                let conflicts: i64 = conn.query_row(
                    "SELECT count(*) FROM synchronized_history_records r JOIN synchronized_history_transfers t USING(transfer_id) WHERE t.group_id_hex=?1 AND r.message_id_hex=?2 AND r.deleted=0 AND r.identity_digest<>?3 AND (t.complete=1 OR t.transfer_id=?4)",
                    params![manifest.binding.group_id_hex, id, identity.as_slice(), manifest.binding.transfer_id.as_slice()], |r| r.get(0),
                ).storage()?;
                if !record.deleted && conflicts != 0 { return Err(SynchronizedHistoryError::RecordConflict); }
                let previous: Option<(bool, Vec<u8>, Option<i64>)> = conn.query_row(
                    "SELECT deleted,identity_digest,expires_at FROM synchronized_history_records WHERE transfer_id=?1 AND message_id_hex=?2",
                    params![manifest.binding.transfer_id.as_slice(), id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                ).optional().storage()?;
                if let Some((deleted, prior, prior_expiry)) = previous {
                    if deleted { skipped += 1; continue; }
                    if !record.deleted && prior != identity { return Err(SynchronizedHistoryError::RecordConflict); }
                    let expiry = record.expires_at.map(|t| t as i64);
                    if !record.deleted && prior == identity && (expiry.is_none() || prior_expiry.is_some_and(|t| expiry.is_some_and(|e| t <= e))) { skipped += 1; continue; }
                }
                conn.execute(
                    "INSERT INTO synchronized_history_records(transfer_id,message_id_hex,record_json,deleted,created_at,expires_at,identity_digest) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(transfer_id,message_id_hex) DO UPDATE SET record_json=excluded.record_json,deleted=excluded.deleted,created_at=excluded.created_at,expires_at=CASE WHEN synchronized_history_records.expires_at IS NULL THEN excluded.expires_at WHEN excluded.expires_at IS NULL THEN synchronized_history_records.expires_at ELSE min(synchronized_history_records.expires_at,excluded.expires_at) END,identity_digest=excluded.identity_digest",
                    params![manifest.binding.transfer_id.as_slice(), id, body, record.deleted, record.created_at as i64, record.expires_at.map(|t| t as i64), identity.as_slice()],
                ).storage()?;
                imported += 1;
            }
            if cancelled() { return Err(SynchronizedHistoryError::Cancelled); }
            let complete = index + 1 == manifest.chunk_digests.len();
            if complete {
                conn.execute("INSERT OR IGNORE INTO synchronized_history_retention_fences(group_id_hex,message_id_hex) SELECT ?2,message_id_hex FROM synchronized_history_retention_intents WHERE transfer_id=?1", params![manifest.binding.transfer_id.as_slice(),manifest.binding.group_id_hex]).storage()?;
                conn.execute("DELETE FROM synchronized_history_records WHERE transfer_id IN (SELECT transfer_id FROM synchronized_history_transfers WHERE group_id_hex=?1) AND message_id_hex IN (SELECT message_id_hex FROM synchronized_history_retention_fences WHERE group_id_hex=?1)", [&manifest.binding.group_id_hex]).storage()?;
                // Another transfer may have completed after an earlier chunk was staged.
                let conflicts: i64 = conn.query_row("SELECT count(*) FROM synchronized_history_records r JOIN synchronized_history_records x ON x.message_id_hex=r.message_id_hex JOIN synchronized_history_transfers xt ON xt.transfer_id=x.transfer_id WHERE r.transfer_id=?1 AND xt.complete=1 AND xt.group_id_hex=?2 AND r.deleted=0 AND x.deleted=0 AND r.identity_digest<>x.identity_digest", params![manifest.binding.transfer_id.as_slice(), manifest.binding.group_id_hex], |r| r.get(0)).storage()?;
                if conflicts != 0 { return Err(SynchronizedHistoryError::RecordConflict); }
                // Completed tombstones erase retained archive payloads, never live events.
                conn.execute("DELETE FROM synchronized_history_records WHERE deleted=0 AND message_id_hex IN (SELECT message_id_hex FROM synchronized_history_records WHERE transfer_id=?1 AND deleted=1) AND transfer_id IN (SELECT transfer_id FROM synchronized_history_transfers WHERE group_id_hex=?2)", params![manifest.binding.transfer_id.as_slice(), manifest.binding.group_id_hex]).storage()?;
            }
            conn.execute("INSERT INTO synchronized_history_chunks(transfer_id,chunk_index,chunk_digest,imported_records,skipped_records) VALUES(?1,?2,?3,?4,?5)",
                params![manifest.binding.transfer_id.as_slice(), index as i64, chunk_hash.as_slice(), imported as i64, skipped as i64]).storage()?;
            if complete {
                // Receiving retention only tightens. Overlapping snapshots share
                // immutable identity while their local expiry can differ.
                conn.execute("UPDATE synchronized_history_records AS r SET expires_at=(SELECT min(x.expires_at) FROM synchronized_history_records x JOIN synchronized_history_transfers xt USING(transfer_id) WHERE xt.group_id_hex=?2 AND x.message_id_hex=r.message_id_hex AND (xt.complete=1 OR xt.transfer_id=?1)) WHERE r.transfer_id IN (SELECT transfer_id FROM synchronized_history_transfers WHERE group_id_hex=?2 AND (complete=1 OR transfer_id=?1))",params![manifest.binding.transfer_id.as_slice(),manifest.binding.group_id_hex]).storage()?;
            }
            conn.execute("UPDATE synchronized_history_transfers SET next_chunk=?2,complete=?3 WHERE transfer_id=?1", params![manifest.binding.transfer_id.as_slice(), (index + 1) as i64, complete]).storage()?;
            refresh_history_byte_accounting(&conn,&manifest.binding.group_id_hex)?;
            let total:i64=conn.query_row("SELECT coalesce(sum(charged_bytes),0) FROM synchronized_history_transfers",[],|r|r.get(0)).storage()?;
            if total>MAX_SYNCHRONIZED_HISTORY_BYTES { return Err(SynchronizedHistoryError::LimitExceeded); }
            Ok(SynchronizedHistoryImportProgress { imported_records: imported, skipped_records: skipped, next_chunk: index + 1, complete, replayed: false })
        })
    }

    /// Permanently fence an incomplete transfer and erase its staged payloads.
    /// The manifest fence survives close/reopen; callback cancellation alone is
    /// retryable and only rolls back the current chunk.
    pub fn cancel_synchronized_history(&self, transfer_id: &[u8; 32]) -> Result<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let complete: Option<bool> = conn
                .query_row(
                    "SELECT complete FROM synchronized_history_transfers WHERE transfer_id=?1",
                    [transfer_id.as_slice()],
                    |r| r.get(0),
                )
                .optional()
                .storage()?;
            match complete {
                None | Some(true) => return Err(SynchronizedHistoryError::TransferConflict),
                Some(false) => (),
            }
            conn.execute(
                "UPDATE synchronized_history_transfers SET cancelled=1 WHERE transfer_id=?1",
                [transfer_id.as_slice()],
            )
            .storage()?;
            conn.execute(
                "DELETE FROM synchronized_history_records WHERE transfer_id=?1",
                [transfer_id.as_slice()],
            )
            .storage()?;
            conn.execute(
                "DELETE FROM synchronized_history_retention_intents WHERE transfer_id=?1",
                [transfer_id.as_slice()],
            )
            .storage()?;
            conn.execute(
                "UPDATE synchronized_history_transfers SET charged_bytes=0 WHERE transfer_id=?1",
                [transfer_id.as_slice()],
            )
            .storage()?;
            Ok(())
        })
    }

    /// Apply receiving-device retention without permitting replay resurrection.
    /// Tombstones remain payload-free. Returns the number of purged records.
    pub fn prune_synchronized_history(
        &self,
        group_id_hex: &str,
        retain_since: u64,
        now: u64,
    ) -> Result<usize> {
        if retain_since > i64::MAX as u64 || now > i64::MAX as u64 {
            return Err(SynchronizedHistoryError::InvalidManifest);
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute("INSERT OR IGNORE INTO synchronized_history_retention_fences(group_id_hex,message_id_hex) SELECT ?1,r.message_id_hex FROM synchronized_history_records r JOIN synchronized_history_transfers t USING(transfer_id) WHERE t.group_id_hex=?1 AND t.complete=1 AND r.deleted=0 AND (r.created_at<?2 OR r.expires_at<=?3)", params![group_id_hex,retain_since as i64,now as i64]).storage()?;
            let removed = conn.execute("DELETE FROM synchronized_history_records WHERE transfer_id IN (SELECT transfer_id FROM synchronized_history_transfers WHERE group_id_hex=?1) AND message_id_hex IN (SELECT message_id_hex FROM synchronized_history_retention_fences WHERE group_id_hex=?1)", [group_id_hex]).storage()?;
            refresh_history_byte_accounting(&conn,group_id_hex)?;
            Ok(removed)
        })
    }

    /// Read completed archive records with source provenance. Live app events
    /// always shadow these rows, including live tombstones and invalidations.
    /// A synced tombstone wins among archive copies, even after late replay.
    pub fn synchronized_history_page(
        &self,
        group_id_hex: &str,
        after_message_id: Option<&[u8; 32]>,
        limit: usize,
        now: u64,
    ) -> Result<Vec<ProvenancedSynchronizedHistoryRecord>> {
        if limit == 0 || limit > MAX_SYNCHRONIZED_HISTORY_PAGE || now > i64::MAX as u64 {
            return Err(SynchronizedHistoryError::LimitExceeded);
        }
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT r.record_json,t.transfer_id,t.source_device,t.manifest_digest,r.expires_at FROM synchronized_history_records r JOIN synchronized_history_transfers t USING(transfer_id)
             WHERE t.complete=1 AND t.cancelled=0 AND t.group_id_hex=?1 AND r.message_id_hex>?2
             AND (r.deleted=1 OR r.expires_at IS NULL OR r.expires_at>?4)
             AND NOT EXISTS(SELECT 1 FROM synchronized_history_retention_fences f WHERE f.group_id_hex=t.group_id_hex AND f.message_id_hex=r.message_id_hex)
             AND NOT EXISTS(SELECT 1 FROM app_events a WHERE a.group_id_hex=t.group_id_hex AND a.message_id_hex=r.message_id_hex)
             AND NOT EXISTS(SELECT 1 FROM synchronized_history_records x JOIN synchronized_history_transfers xt USING(transfer_id)
                WHERE xt.complete=1 AND xt.group_id_hex=t.group_id_hex AND x.message_id_hex=r.message_id_hex
                AND (x.deleted>r.deleted OR (x.deleted=r.deleted AND x.transfer_id<r.transfer_id)))
             ORDER BY r.message_id_hex LIMIT ?3",
        ).storage()?;
        let rows = stmt
            .query_map(
                params![
                    group_id_hex,
                    after_message_id.map(hex::encode).unwrap_or_default(),
                    limit as i64,
                    now as i64
                ],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .storage()?;
        rows.map(|row| {
            let (body, transfer, source, manifest, expiry) = row.storage()?;
            let mut record: SynchronizedHistoryRecord = serde_json::from_slice(&body)
                .map_err(|_| SynchronizedHistoryError::InvalidManifest)?;
            record.expires_at = expiry
                .map(u64::try_from)
                .transpose()
                .map_err(|_| SynchronizedHistoryError::InvalidManifest)?;
            Ok(ProvenancedSynchronizedHistoryRecord {
                record,
                transfer_id: transfer
                    .try_into()
                    .map_err(|_| SynchronizedHistoryError::InvalidManifest)?,
                source_device: source
                    .try_into()
                    .map_err(|_| SynchronizedHistoryError::InvalidManifest)?,
                manifest_digest: manifest
                    .try_into()
                    .map_err(|_| SynchronizedHistoryError::InvalidManifest)?,
            })
        })
        .collect()
    }
}

#[cfg(test)]
#[path = "synchronized_history/tests.rs"]
mod tests;
