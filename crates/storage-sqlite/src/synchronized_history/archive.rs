//! Bounded opaque fragments, never consent or independently verified MLS history.
use super::*;

pub const MAX_HISTORY_ARCHIVE_FRAGMENT_BYTES: usize = 1536;
pub const MAX_HISTORY_ARCHIVE_BYTES: usize =
    MAX_SYNCHRONIZED_HISTORY_CHUNKS * MAX_HISTORY_ARCHIVE_FRAGMENT_BYTES;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SynchronizedHistoryArchive {
    pub format_version: u8,
    pub manifest: SynchronizedHistoryManifest,
    #[serde(with = "wire_records")]
    pub chunks: Vec<Vec<SynchronizedHistoryRecord>>,
}

// The logical record integrity encoding stays unchanged. Only this new
// versioned transport archive encodes payload bytes compactly.
mod wire_records {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WireRecord {
        message_id: [u8; 32],
        author: [u8; 32],
        created_at: u64,
        kind: u64,
        payload: String,
        expires_at: Option<u64>,
        deleted: bool,
    }
    pub fn serialize<S: serde::Serializer>(
        chunks: &[Vec<SynchronizedHistoryRecord>],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let wire: Vec<Vec<WireRecord>> = chunks
            .iter()
            .map(|chunk| {
                chunk
                    .iter()
                    .map(|record| WireRecord {
                        message_id: record.message_id,
                        author: record.author,
                        created_at: record.created_at,
                        kind: record.kind,
                        payload: STANDARD.encode(&record.payload),
                        expires_at: record.expires_at,
                        deleted: record.deleted,
                    })
                    .collect()
            })
            .collect();
        wire.serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Vec<Vec<SynchronizedHistoryRecord>>, D::Error> {
        let wire = Vec::<Vec<WireRecord>>::deserialize(deserializer)?;
        wire.into_iter()
            .map(|chunk| {
                chunk
                    .into_iter()
                    .map(|record| {
                        let payload = STANDARD
                            .decode(&record.payload)
                            .map_err(serde::de::Error::custom)?;
                        if STANDARD.encode(&payload) != record.payload {
                            return Err(serde::de::Error::custom("noncanonical archive payload"));
                        }
                        Ok(SynchronizedHistoryRecord {
                            message_id: record.message_id,
                            author: record.author,
                            created_at: record.created_at,
                            kind: record.kind,
                            payload,
                            expires_at: record.expires_at,
                            deleted: record.deleted,
                        })
                    })
                    .collect()
            })
            .collect()
    }
}

/// Captured from the authenticated original request; persisted facts never
/// restore the original request, recipient consent or its fixed lifetime.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryArchiveStagingManifest {
    pub binding: SynchronizedHistoryBinding,
    pub request_digest: [u8; 32],
    pub archive_digest: [u8; 32],
    pub encoded_bytes: u32,
    pub fragment_count: u32,
    pub record_count: u32,
    /// Recipient policy captured by the live original consent, not the exporter.
    pub retain_since: u64,
    pub max_record_lifetime_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryArchiveFragmentDisposition {
    Staged,
    Imported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryArchiveFragmentReceipt {
    pub ordinal: u32,
    pub body_digest: [u8; 32],
    pub disposition: HistoryArchiveFragmentDisposition,
    pub imported_records: u32,
    pub skipped_records: u32,
    pub replayed: bool,
}

fn validate_scope(scope: &HistoryArchiveStagingManifest) -> Result<()> {
    validate_manifest(&SynchronizedHistoryManifest {
        binding: scope.binding.clone(),
        chunk_digests: vec![[0; 32]],
        retain_since: scope.retain_since,
        max_record_lifetime_seconds: scope.max_record_lifetime_seconds,
    })?;
    let size = scope.encoded_bytes as usize;
    if size == 0
        || size > MAX_HISTORY_ARCHIVE_BYTES
        || scope.fragment_count as usize != size.div_ceil(MAX_HISTORY_ARCHIVE_FRAGMENT_BYTES)
        || scope.record_count as usize
            > MAX_SYNCHRONIZED_HISTORY_CHUNKS * MAX_SYNCHRONIZED_HISTORY_RECORDS_PER_CHUNK
        || bytes(scope)?.len() > 32768
    {
        return Err(SynchronizedHistoryError::InvalidManifest);
    }
    Ok(())
}

fn decode_archive(
    encoded: &[u8],
    scope: &HistoryArchiveStagingManifest,
) -> Result<SynchronizedHistoryArchive> {
    if encoded.len() != scope.encoded_bytes as usize
        || <[u8; 32]>::from(Sha256::digest(encoded)) != scope.archive_digest
    {
        return Err(SynchronizedHistoryError::IntegrityMismatch);
    }
    let archive: SynchronizedHistoryArchive =
        serde_json::from_slice(encoded).map_err(|_| SynchronizedHistoryError::InvalidManifest)?;
    if archive.format_version != 1
        || archive.manifest.binding != scope.binding
        || archive.chunks.len() != archive.manifest.chunk_digests.len()
        || archive.chunks.iter().map(Vec::len).sum::<usize>() != scope.record_count as usize
        || bytes(&archive)? != encoded
    {
        return Err(SynchronizedHistoryError::InvalidManifest);
    }
    archive.manifest.digest()?;
    for (ordinal, records) in archive.chunks.iter().enumerate() {
        if synchronized_history_chunk_digest(&scope.binding, ordinal, records)?
            != archive.manifest.chunk_digests[ordinal]
        {
            return Err(SynchronizedHistoryError::IntegrityMismatch);
        }
    }
    Ok(archive)
}

fn check_cancelled(cancelled: &dyn Fn() -> bool) -> Result<()> {
    if cancelled() {
        Err(SynchronizedHistoryError::Cancelled)
    } else {
        Ok(())
    }
}

impl SqliteAccountStorage {
    /// Caller retains its live original authority through the SQL transaction.
    /// Only the final receipt attests a completed logical import in that transaction.
    pub fn stage_synchronized_history_archive_fragment(
        &self,
        manifest: &HistoryArchiveStagingManifest,
        ordinal: u32,
        body: &[u8],
        now: u64,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<HistoryArchiveFragmentReceipt> {
        validate_scope(manifest)?;
        check_cancelled(cancelled)?;
        if now > i64::MAX as u64 || ordinal >= manifest.fragment_count {
            return Err(SynchronizedHistoryError::InvalidManifest);
        }
        let expected = if ordinal + 1 == manifest.fragment_count {
            manifest.encoded_bytes as usize - ordinal as usize * MAX_HISTORY_ARCHIVE_FRAGMENT_BYTES
        } else {
            MAX_HISTORY_ARCHIVE_FRAGMENT_BYTES
        };
        if body.len() != expected {
            return Err(SynchronizedHistoryError::LimitExceeded);
        }
        let scope = bytes(manifest)?;
        let id = manifest.binding.transfer_id.as_slice();
        let body_digest = Sha256::digest(body).into();
        self.connection.with_transaction(|| {
            check_cancelled(cancelled)?;
            let next;
            {
                let conn = self.lock()?;
                let matches: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM account_state WHERE local_account_id_hex=?1)",
                    [hex::encode(manifest.binding.account_id)], |r| r.get(0),
                ).storage()?;
                if !matches { return Err(SynchronizedHistoryError::WrongAccount); }
                let stored: Option<(Vec<u8>, u32, u8)> = conn.query_row(
                    "SELECT scope,next_fragment,state FROM history_archive_staging WHERE transfer_id=?1",
                    [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                ).optional().storage()?;
                if let Some((prior, position, state)) = stored {
                    if prior != scope { return Err(SynchronizedHistoryError::TransferConflict); }
                    if state == 2 { return Err(SynchronizedHistoryError::Cancelled); }
                    if ordinal < position {
                        let encoded: Vec<u8> = conn.query_row(
                            "SELECT receipt FROM history_archive_fragments WHERE transfer_id=?1 AND ordinal=?2",
                            params![id, ordinal], |r| r.get(0),
                        ).storage()?;
                        let mut receipt: HistoryArchiveFragmentReceipt = serde_json::from_slice(&encoded)
                            .map_err(|_| SynchronizedHistoryError::InvalidManifest)?;
                        if receipt.body_digest != body_digest { return Err(SynchronizedHistoryError::IntegrityMismatch); }
                        receipt.replayed = true;
                        check_cancelled(cancelled)?;
                        return Ok(receipt);
                    }
                    if state != 0 { return Err(SynchronizedHistoryError::OutOfOrder); }
                    next = position;
                } else {
                    if ordinal != 0 { return Err(SynchronizedHistoryError::OutOfOrder); }
                    let occupied: bool = conn.query_row(
                        "SELECT EXISTS(SELECT 1 FROM synchronized_history_transfers WHERE transfer_id=?1)",
                        [id], |r| r.get(0),
                    ).storage()?;
                    if occupied { return Err(SynchronizedHistoryError::TransferConflict); }
                    let count: i64 = conn.query_row("SELECT count(*) FROM history_archive_staging", [], |r| r.get(0)).storage()?;
                    if count >= MAX_SYNCHRONIZED_HISTORY_TRANSFERS { return Err(SynchronizedHistoryError::LimitExceeded); }
                    conn.execute("INSERT INTO history_archive_staging(transfer_id,scope) VALUES(?1,?2)", params![id, scope]).storage()?;
                    next = 0;
                }
                if ordinal != next { return Err(SynchronizedHistoryError::OutOfOrder); }
            }
            let mut receipt = HistoryArchiveFragmentReceipt {
                ordinal, body_digest, disposition: HistoryArchiveFragmentDisposition::Staged,
                imported_records: 0, skipped_records: 0, replayed: false,
            };
            let final_fragment = ordinal + 1 == manifest.fragment_count;
            if final_fragment {
                let mut encoded = Vec::with_capacity(manifest.encoded_bytes as usize);
                {
                    let conn = self.lock()?;
                    let mut statement = conn.prepare("SELECT body FROM history_archive_fragments WHERE transfer_id=?1 ORDER BY ordinal").storage()?;
                    let rows = statement.query_map([id], |r| r.get::<_, Vec<u8>>(0)).storage()?;
                    for row in rows {
                        encoded.extend(row.storage()?);
                        if encoded.len() > MAX_HISTORY_ARCHIVE_BYTES { return Err(SynchronizedHistoryError::LimitExceeded); }
                    }
                }
                encoded.extend_from_slice(body);
                let archive = decode_archive(&encoded, manifest)?;
                let mut effective = archive.manifest;
                effective.retain_since = effective.retain_since.max(manifest.retain_since);
                effective.max_record_lifetime_seconds = match (effective.max_record_lifetime_seconds, manifest.max_record_lifetime_seconds) {
                    (Some(a), Some(b)) => Some(a.min(b)), (a, b) => a.or(b),
                };
                check_cancelled(cancelled)?;
                self.admit_synchronized_history_with_archive(&effective, Some(&scope))?;
                for (index, records) in archive.chunks.iter().enumerate() {
                    let progress = self.import_synchronized_history_chunk(&effective, index, records, now, cancelled)?;
                    receipt.imported_records += progress.imported_records as u32;
                    receipt.skipped_records += progress.skipped_records as u32;
                    if index + 1 == archive.chunks.len() && !progress.complete {
                        return Err(SynchronizedHistoryError::IntegrityMismatch);
                    }
                }
                receipt.disposition = HistoryArchiveFragmentDisposition::Imported;
            }
            {
                let conn = self.lock()?;
                conn.execute("INSERT INTO history_archive_fragments(transfer_id,ordinal,body,receipt) VALUES(?1,?2,?3,?4)",
                    params![id, ordinal, body, bytes(&receipt)?]).storage()?;
                conn.execute("UPDATE history_archive_staging SET next_fragment=?2,state=?3 WHERE transfer_id=?1",
                    params![id, ordinal + 1, u8::from(final_fragment)]).storage()?;
                if final_fragment {
                    conn.execute("UPDATE history_archive_fragments SET body=NULL WHERE transfer_id=?1", [id]).storage()?;
                }
            }
            // Includes receipt insertion, final import effects, and payload retirement.
            check_cancelled(cancelled)?;
            Ok(receipt)
        })
    }

    /// Permanent denial of an unfinished original transfer. Completed imports remain.
    pub fn cancel_synchronized_history_archive(
        &self,
        manifest: &HistoryArchiveStagingManifest,
    ) -> Result<()> {
        validate_scope(manifest)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let id = manifest.binding.transfer_id.as_slice();
            let stored: Option<(Vec<u8>, u8)> = conn
                .query_row(
                    "SELECT scope,state FROM history_archive_staging WHERE transfer_id=?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .storage()?;
            let Some((scope, state)) = stored else {
                return Err(SynchronizedHistoryError::TransferConflict);
            };
            if scope != bytes(manifest)? || state == 1 {
                return Err(SynchronizedHistoryError::TransferConflict);
            }
            conn.execute(
                "UPDATE history_archive_staging SET state=2 WHERE transfer_id=?1",
                [id],
            )
            .storage()?;
            conn.execute(
                "UPDATE history_archive_fragments SET body=NULL WHERE transfer_id=?1",
                [id],
            )
            .storage()?;
            Ok(())
        })
    }
}
