//! Canonical logical records, separately acknowledged from catalog discovery.
use super::*;
#[cfg(all(test, feature = "test-policy-overrides"))]
#[path = "tests/record_source_lookup.rs"]
mod source_lookup_tests;
use cgka_traits::account_chat_record_stream::{AccountChatRecordBatch, AccountChatRecordReceipt};
use cgka_traits::mirrored_chat_messages::MirroredChatRecord;

const MAX_RECORD_WIRE_BYTES: usize = 96 * 1024;
// Keep eight of the original 128 bodies available for authenticated receipts.
const RECORD_BODY_BUDGET: u64 = 120;

#[derive(Default)]
pub(super) struct RecordProgress {
    group_after: Option<crate::GroupId>,
    group: Option<crate::GroupId>,
    cursor: Option<storage_sqlite::AppEventReplayCursor>,
    pending: Option<PendingRecord>,
    assembly: Option<Assembly>,
}
#[derive(PartialEq, Eq)]
pub(super) struct RecordPublicationIdentity {
    group: crate::GroupId,
    batch_digest: [u8; 32],
    first_sequence: u64,
    last_sequence: u64,
    record_count: u32,
    peer_generation: u64,
    published_at: Option<std::time::Instant>,
}
pub(super) struct RecordSourceCursor {
    group_after: Option<crate::GroupId>,
    group: Option<crate::GroupId>,
    cursor: Option<storage_sqlite::AppEventReplayCursor>,
}
impl RecordProgress {
    pub(super) fn publication_identity(&self) -> Option<RecordPublicationIdentity> {
        self.pending
            .as_ref()
            .map(|pending| RecordPublicationIdentity {
                group: pending.group.clone(),
                batch_digest: pending.batch.batch_digest,
                first_sequence: pending.batch.first_sequence,
                last_sequence: pending.batch.last_sequence,
                record_count: pending.batch.record_count,
                peer_generation: pending.peer_generation,
                published_at: pending.published_at,
            })
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(super) fn test_progress(&self) -> String {
        format!(
            "record_group={}, record_cursor={}, record_assembly={}",
            self.group.is_some(),
            self.cursor.is_some(),
            self.assembly.is_some()
        )
    }
    pub(super) fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
    pub(super) fn take_source_cursor(&mut self) -> RecordSourceCursor {
        RecordSourceCursor {
            group_after: self.group_after.take(),
            group: self.group.take(),
            cursor: self.cursor.take(),
        }
    }
    pub(super) fn restore_source_cursor(&mut self, cursor: RecordSourceCursor) {
        self.group_after = cursor.group_after;
        self.group = cursor.group;
        self.cursor = cursor.cursor;
    }
}
struct PendingRecord {
    group: crate::GroupId,
    batch: AccountChatRecordBatch,
    peer_generation: u64,
    published_at: Option<std::time::Instant>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactRecord {
    event_id: [u8; 32],
    author: [u8; 32],
    created_at: u64,
    kind: u16,
    payload: String,
    content_digest: Option<[u8; 32]>,
    expires_at: Option<u64>,
    deleted: bool,
    source_epoch: u64,
    source_sequence: u64,
    source_digest: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accepted_origin: Option<cgka_traits::mirrored_chat_catalog::AcceptedChatOrigin>,
}
impl CompactRecord {
    fn from_record(record: &MirroredChatRecord) -> Self {
        Self {
            event_id: record.event_id,
            author: record.author,
            created_at: record.created_at,
            kind: record.kind,
            payload: base64::engine::general_purpose::STANDARD.encode(&record.payload),
            content_digest: record.content_digest,
            expires_at: record.expires_at,
            deleted: record.deleted,
            source_epoch: record.source_epoch,
            source_sequence: record.source_sequence,
            source_digest: record.source_digest,
            accepted_origin: record.accepted_origin,
        }
    }
    fn into_record(self) -> Result<MirroredChatRecord, AccountSharingError> {
        let payload = base64::engine::general_purpose::STANDARD
            .decode(&self.payload)
            .map_err(|_| AccountSharingError::NotReady)?;
        if base64::engine::general_purpose::STANDARD.encode(&payload) != self.payload {
            return Err(AccountSharingError::NotReady);
        }
        Ok(MirroredChatRecord {
            event_id: self.event_id,
            author: self.author,
            created_at: self.created_at,
            kind: self.kind,
            payload,
            content_digest: self.content_digest,
            expires_at: self.expires_at,
            deleted: self.deleted,
            source_epoch: self.source_epoch,
            source_sequence: self.source_sequence,
            source_digest: self.source_digest,

            accepted_origin: self.accepted_origin,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordWire {
    version: u8,
    group: String,
    batch_digest: [u8; 32],
    first_sequence: u64,
    last_sequence: u64,
    record_count: u32,
    records: Vec<CompactRecord>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordReceiptWire {
    version: u8,
    group: String,
    receipt: AccountChatRecordReceipt,
}
fn encode_group(group: &crate::GroupId) -> String {
    base64::engine::general_purpose::STANDARD.encode(group.as_slice())
}
fn decode_group(value: &str) -> Result<crate::GroupId, AccountSharingError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| AccountSharingError::NotReady)?;
    if !(1..=255).contains(&bytes.len())
        || base64::engine::general_purpose::STANDARD.encode(&bytes) != value
    {
        return Err(AccountSharingError::NotReady);
    }
    Ok(crate::GroupId::new(bytes))
}

impl AppClient {
    pub(super) fn accept_automatic_records(
        &self,
        entry: &mut AutomaticChannel,
        bytes: &[u8],
    ) -> Result<(), AccountSharingError> {
        let fragment: CatalogFragment =
            serde_json::from_slice(bytes).map_err(|_| AccountSharingError::NotReady)?;
        if serde_json::to_vec(&fragment).map_err(|_| AccountSharingError::NotReady)? != bytes
            || fragment.version != 1
            || fragment.count == 0
            || fragment.count as usize > MAX_RECORD_WIRE_BYTES.div_ceil(FRAGMENT_BYTES)
            || fragment.ordinal >= fragment.count
        {
            return Err(AccountSharingError::NotReady);
        }
        let part = base64::engine::general_purpose::STANDARD
            .decode(&fragment.body)
            .map_err(|_| AccountSharingError::NotReady)?;
        if part.is_empty()
            || part.len() > FRAGMENT_BYTES
            || base64::engine::general_purpose::STANDARD.encode(&part) != fragment.body
        {
            return Err(AccountSharingError::NotReady);
        }
        if entry
            .records
            .assembly
            .as_ref()
            .is_none_or(|old| old.digest != fragment.digest)
        {
            entry.records.assembly = Some(Assembly {
                digest: fragment.digest,
                fragments: vec![None; fragment.count as usize],
            });
        }
        let assembly = entry.records.assembly.as_mut().expect("record assembly");
        if assembly.fragments.len() != fragment.count as usize {
            return Err(AccountSharingError::NotReady);
        }
        let slot = &mut assembly.fragments[fragment.ordinal as usize];
        if slot.as_ref().is_some_and(|old| old != &part) {
            return Err(AccountSharingError::NotReady);
        }
        *slot = Some(part);
        if assembly.fragments.iter().any(Option::is_none) {
            return Ok(());
        }
        let bytes: Vec<u8> = assembly
            .fragments
            .iter()
            .flat_map(|part| part.as_ref().expect("complete record part").iter().copied())
            .collect();
        if bytes.len() > MAX_RECORD_WIRE_BYTES
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != fragment.digest
        {
            return Err(AccountSharingError::NotReady);
        }
        let wire: RecordWire =
            serde_json::from_slice(&bytes).map_err(|_| AccountSharingError::NotReady)?;
        if wire.version != 1
            || serde_json::to_vec(&wire).map_err(|_| AccountSharingError::NotReady)? != bytes
        {
            return Err(AccountSharingError::NotReady);
        }
        let group = decode_group(&wire.group)?;
        let records = wire
            .records
            .into_iter()
            .map(CompactRecord::into_record)
            .collect::<Result<Vec<_>, _>>()?;
        let batch = AccountChatRecordBatch {
            batch_digest: wire.batch_digest,
            first_sequence: wire.first_sequence,
            last_sequence: wire.last_sequence,
            record_count: wire.record_count,
            encoded_records: serde_json::to_vec(&records)
                .map_err(|_| AccountSharingError::NotReady)?,
        };
        let scope = MirroredChatScope {
            account: entry.policy.account,
            local_device: entry.policy.local_device,
            source_device: entry.policy.peer_device,
            policy_digest: Self::automatic_policy_id(&entry.policy)?,
            protected_group: entry.policy.protected_group.clone(),
            protected_generation: entry.channel.scope().local_generation,
        };
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if records_cut_acceptance::hold_complete_records(
            self.app.account_home().root(),
            &group,
            batch.batch_digest,
            entry.policy.peer_device,
            entry.channel.scope().nonce,
        ) {
            return Err(AccountSharingError::NotReady);
        }
        let applied = storage
            .account_chat_record_stream_storage()
            .ok_or(AccountSharingError::NotReady)?
            .apply_account_chat_record_batch(
                &scope,
                &group,
                &batch,
                crate::unix_now_seconds(),
                &|| self.automatic_record_original(entry),
            );
        let receipt = match applied {
            Ok(receipt) => receipt,
            Err(error) => {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                records_cut_acceptance::observe_record_failure(
                    self.app.account_home().root(),
                    &group,
                    batch.batch_digest,
                    entry.policy.peer_device,
                    entry.channel.scope().nonce,
                    matches!(
                        &error,
                        cgka_traits::storage::StorageError::MirroredRecordDeniedByDeparture
                    ),
                );
                #[cfg(all(test, feature = "test-policy-overrides"))]
                self.test_trace_catalog_stage(
                    "record_sql",
                    diagnostics::storage_category(&error),
                    None,
                );
                if matches!(
                    error,
                    cgka_traits::storage::StorageError::MirroredRecordDeniedByDeparture
                ) {
                    // Revalidate the original at this negative disposition's tail.
                    // A refused batch creates neither an import nor a receipt.
                    self.automatic_record_original(entry)
                        .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
                    entry.records.assembly = None;
                    return Ok(());
                }
                return Err(AccountSharingError::RuntimeUnavailable);
            }
        };
        #[cfg(all(test, feature = "test-policy-overrides"))]
        records_cut_acceptance::observe_committed_record_receipt(
            self.app.account_home().root(),
            batch.batch_digest,
        );
        // Wake observation owners only after the original-checked SQL commit.
        // Their worker reads still revalidate current policy at publication.
        self.notify_mirrored_presentation_changed();
        // A rollback retains complete authenticated bytes. A committed import
        // alone creates the typed receipt, independently of relay publication.
        entry.records.assembly = None;
        let bytes = serde_json::to_vec(&RecordReceiptWire {
            version: 1,
            group: encode_group(&group),
            receipt,
        })
        .map_err(|_| AccountSharingError::NotReady)?;
        if bytes.len() > cgka_engine::account_chat_sharing::MAX_ACCOUNT_SHARED_BODY_BYTES
            || entry.pending.len() >= CHANNEL_BODY_BUDGET as usize
        {
            return Err(AccountSharingError::NotReady);
        }
        entry.pending.push_back(PendingBody {
            kind: AccountSharedBodyKind::RecordReceipt,
            bytes,
        });
        Ok(())
    }

    pub(super) fn accept_automatic_record_receipt(
        &self,
        entry: &mut AutomaticChannel,
        bytes: &[u8],
    ) -> Result<(), AccountSharingError> {
        let wire: RecordReceiptWire =
            serde_json::from_slice(bytes).map_err(|_| AccountSharingError::NotReady)?;
        if wire.version != 1
            || serde_json::to_vec(&wire).map_err(|_| AccountSharingError::NotReady)? != bytes
        {
            return Err(AccountSharingError::NotReady);
        }
        let group = decode_group(&wire.group)?;
        let Some(pending) = entry.records.pending.as_ref() else {
            return Ok(());
        };
        if group != pending.group
            || wire.receipt.batch_digest != pending.batch.batch_digest
            || wire.receipt.first_sequence != pending.batch.first_sequence
            || wire.receipt.last_sequence != pending.batch.last_sequence
            || wire.receipt.record_count != pending.batch.record_count
            || wire.receipt.imported_count > wire.receipt.record_count
        {
            return Err(AccountSharingError::NotReady);
        }
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        storage
            .account_chat_record_stream_storage()
            .ok_or(AccountSharingError::NotReady)?
            .acknowledge_account_chat_record_batch_for_generation(
                &Self::automatic_policy_id(&entry.policy)?,
                &group,
                &wire.receipt,
                pending.peer_generation,
                &|| self.automatic_record_original(entry),
            )
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(probe) = &self.account_sharing_owner.record_receipt_probe {
            probe
                .committed
                .fetch_add(1, std::sync::atomic::Ordering::Release);
        }
        entry.records.pending = None;
        Ok(())
    }

    pub(super) fn automatic_record_publication_current(
        &self,
        entry: &mut AutomaticChannel,
    ) -> Result<bool, AccountSharingError> {
        let Some(pending) = entry.records.pending.as_ref() else {
            return Ok(true);
        };
        if !self.automatic_record_batch_source_current(entry, &pending.group, &pending.batch)? {
            let storage = self
                .app
                .account_storage(&self.state.label)
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
            storage
                .account_chat_record_stream_storage()
                .ok_or(AccountSharingError::NotReady)?
                .deny_account_chat_record_batch(
                    &Self::automatic_policy_id(&entry.policy)?,
                    &pending.group,
                    &pending.batch.batch_digest,
                    &|| self.automatic_record_original(entry),
                )
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
            entry.renew = true;
            entry.records.cursor = None;
            return Ok(false);
        }
        if pending
            .published_at
            .is_some_and(|published| published.elapsed() >= std::time::Duration::from_secs(10))
        {
            entry.renew = true;
            return Ok(false);
        }
        Ok(true)
    }

    pub(super) fn automatic_record_publication_deadline(
        &self,
        entry: &AutomaticChannel,
    ) -> Result<std::time::Instant, AccountSharingError> {
        if !entry
            .pending
            .front()
            .is_some_and(|body| body.kind == AccountSharedBodyKind::Records)
        {
            return Ok(entry.original.deadline);
        }
        let Some(pending) = entry.records.pending.as_ref() else {
            return Err(AccountSharingError::NotReady);
        };
        let records: Vec<MirroredChatRecord> =
            serde_json::from_slice(&pending.batch.encoded_records)
                .map_err(|_| AccountSharingError::NotReady)?;
        let now = crate::unix_now_seconds();
        let deadline = records
            .iter()
            .filter(|record| !record.deleted)
            .filter_map(|record| record.expires_at)
            .min()
            .map(|expiry| {
                std::time::Instant::now()
                    + std::time::Duration::from_secs(expiry.saturating_sub(now).saturating_sub(1))
            })
            .unwrap_or(entry.original.deadline);
        Ok(deadline.min(entry.original.deadline))
    }

    pub(super) fn automatic_record_mark_published(&self, entry: &mut AutomaticChannel) {
        if entry.pending.is_empty()
            && let Some(pending) = entry.records.pending.as_mut()
            && pending.published_at.is_none()
        {
            pending.published_at = Some(std::time::Instant::now());
        }
    }

    fn automatic_record_original(
        &self,
        entry: &AutomaticChannel,
    ) -> cgka_traits::storage::StorageResult<()> {
        self.automatic_policy_current(&entry.policy)
            .and_then(|()| {
                self.runtime
                    .session()
                    .validate_account_sharing_channel(&entry.channel)
                    .map_err(|_| AccountSharingError::Closed)
            })
            .map_err(|_| {
                cgka_traits::storage::StorageError::Serialization(
                    "automatic record original unavailable".into(),
                )
            })
    }

    fn automatic_record_source_epoch(
        &self,
        entry: &AutomaticChannel,
        group: &crate::GroupId,
    ) -> Result<Option<u64>, AccountSharingError> {
        if !self
            .automatic_chat_source_accepted(group)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?
        {
            return Ok(None);
        }
        let source = self
            .runtime
            .session()
            .account_chat_catalog_entry(&entry.policy.protected_group, group)
            .map_err(|_| AccountSharingError::Closed)?;
        Ok(source.map(|source| source.epoch))
    }

    fn automatic_record_batch_source_current(
        &self,
        entry: &AutomaticChannel,
        group: &crate::GroupId,
        batch: &AccountChatRecordBatch,
    ) -> Result<bool, AccountSharingError> {
        let Some(epoch) = self.automatic_record_source_epoch(entry, group)? else {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_catalog_stage("record_source_current", "no_actual_source_epoch", None);
            return Ok(false);
        };
        let records: Vec<MirroredChatRecord> = serde_json::from_slice(&batch.encoded_records)
            .map_err(|_| AccountSharingError::NotReady)?;
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        for record in records {
            let Some(row) = storage
                .app_storage()
                .app_message(
                    &hex::encode(group.as_slice()),
                    &hex::encode(record.event_id),
                )
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?
            else {
                return Ok(false);
            };
            let Some(current) = self.automatic_record_from_source(
                entry,
                group,
                epoch,
                &row,
                crate::unix_now_seconds(),
            )?
            else {
                return Ok(false);
            };
            let digest: [u8; 32] = Sha256::digest(
                serde_json::to_vec(&current).map_err(|_| AccountSharingError::NotReady)?,
            )
            .into();
            if digest != record.source_digest {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                self.test_trace_catalog_stage("record_source_current", &format!("attestation_changed, origin_same={}, current_origin_present={}, retained_origin_present={}", current.accepted_origin == record.accepted_origin, current.accepted_origin.is_some(), record.accepted_origin.is_some()), None);
                return Ok(false);
            }
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        self.test_trace_catalog_stage("record_source_current", "current", None);
        Ok(true)
    }

    pub(super) fn prepare_automatic_records(
        &self,
        entry: &mut AutomaticChannel,
    ) -> Result<(), AccountSharingError> {
        if entry.records.pending.is_some() {
            return Ok(());
        }
        if entry.records.group.is_none() {
            let page = self
                .runtime
                .session()
                .account_chat_catalog(
                    &entry.policy.protected_group,
                    entry.records.group_after.as_ref(),
                    1,
                )
                .map_err(|_| AccountSharingError::Closed)?;
            let Some(source) = page.entries.first() else {
                // A cursor is not coverage: restart a bounded fresh scan for
                // late older events, retention changes and future messages.
                entry.records.group_after = None;
                return Ok(());
            };
            // Pending or declined ordinary Welcomes are deliberately absent
            // from the shared catalog. Do not let one pin the raw Core scan
            // ahead of an accepted source; a fresh scan revisits later accepts.
            if !self
                .automatic_chat_source_accepted(&source.group_id)
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?
            {
                entry.records.group_after = Some(source.group_id.clone());
                return Ok(());
            }
            // Accepted sources still wait for their actual catalog delivery.
            if !entry.sent.contains_key(source.group_id.as_slice()) {
                return Ok(());
            }
            entry.records.group = Some(source.group_id.clone());
        }
        let group = entry.records.group.as_ref().expect("source group").clone();
        let Some(epoch) = self.automatic_record_source_epoch(entry, &group)? else {
            entry.records.group_after = Some(group);
            entry.records.group = None;
            entry.records.cursor = None;
            return Ok(());
        };
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        let store = storage
            .account_chat_record_stream_storage()
            .ok_or(AccountSharingError::NotReady)?;
        let policy = Self::automatic_policy_id(&entry.policy)?;
        let peer_generation = entry
            .channel
            .authenticated_peer_generation()
            .map_err(|_| AccountSharingError::Closed)?;
        let mut pending = store
            .pending_account_chat_record_batches(&policy, &group, None, 1)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        if pending.is_empty() {
            let rows = storage
                .app_storage()
                .app_messages_page(
                    storage_sqlite::StoredAppMessageQuery {
                        group_id_hex: Some(hex::encode(group.as_slice())),
                        kinds: Some(vec![9, 1009]),
                        limit: Some(1),
                    },
                    entry.records.cursor.as_ref(),
                )
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
            let Some(row) = rows.first() else {
                entry.records.group_after = Some(group);
                entry.records.group = None;
                entry.records.cursor = None;
                return Ok(());
            };
            let Some(mut record) = self.automatic_record_from_source(
                entry,
                &group,
                epoch,
                row,
                crate::unix_now_seconds(),
            )?
            else {
                entry.records.cursor = Some(row.replay_cursor());
                return Ok(());
            };
            let attestation: [u8; 32] = Sha256::digest(
                serde_json::to_vec(&record).map_err(|_| AccountSharingError::NotReady)?,
            )
            .into();
            let validate = || self.automatic_record_original(entry);
            record.source_sequence = store
                .reserve_account_chat_record_sequence(
                    &policy,
                    &group,
                    &record.event_id,
                    &attestation,
                    &validate,
                )
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
            record.source_digest = attestation;
            let encoded_records = serde_json::to_vec(std::slice::from_ref(&record))
                .map_err(|_| AccountSharingError::NotReady)?;
            let batch = AccountChatRecordBatch {
                batch_digest: Sha256::digest(&encoded_records).into(),
                first_sequence: record.source_sequence,
                last_sequence: record.source_sequence,
                record_count: 1,
                encoded_records,
            };
            store
                .stage_account_chat_record_batch(&policy, &group, &batch, &validate)
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
            // A global ACK erases the old payload, but does not cover a new
            // authenticated peer projection. Only this freshly encoded, still
            // authorized source batch may replay; no receipt restores a body.
            let replay = store
                .account_chat_record_generation_receipt(
                    &policy,
                    &group,
                    &batch.batch_digest,
                    peer_generation,
                    &validate,
                )
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?
                .is_none();
            // Advance only after guarded durable admission or an exact
            // generation ACK; this cursor is never proof of recipient import.
            entry.records.cursor = Some(row.replay_cursor());
            if replay {
                pending.push(batch);
            }
        }
        let Some(batch) = pending.into_iter().next() else {
            return Ok(());
        };
        if !self.automatic_record_batch_source_current(entry, &group, &batch)? {
            store
                .deny_account_chat_record_batch(&policy, &group, &batch.batch_digest, &|| {
                    self.automatic_record_original(entry)
                })
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
            entry.records.cursor = None;
            return Ok(());
        }
        let records: Vec<MirroredChatRecord> = serde_json::from_slice(&batch.encoded_records)
            .map_err(|_| AccountSharingError::NotReady)?;
        let bytes = serde_json::to_vec(&RecordWire {
            version: 1,
            group: encode_group(&group),
            batch_digest: batch.batch_digest,
            first_sequence: batch.first_sequence,
            last_sequence: batch.last_sequence,
            record_count: batch.record_count,
            records: records.iter().map(CompactRecord::from_record).collect(),
        })
        .map_err(|_| AccountSharingError::NotReady)?;
        if bytes.len() > MAX_RECORD_WIRE_BYTES {
            return Err(AccountSharingError::NotReady);
        }
        let count = bytes.len().div_ceil(FRAGMENT_BYTES) as u32;
        if entry.next_body + u64::from(count) > RECORD_BODY_BUDGET {
            entry.renew = true;
            return Ok(());
        }
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        for (ordinal, body) in bytes.chunks(FRAGMENT_BYTES).enumerate() {
            entry.pending.push_back(PendingBody {
                kind: AccountSharedBodyKind::Records,
                bytes: serde_json::to_vec(&CatalogFragment {
                    version: 1,
                    digest,
                    ordinal: ordinal as u32,
                    count,
                    body: base64::engine::general_purpose::STANDARD.encode(body),
                })
                .map_err(|_| AccountSharingError::NotReady)?,
            });
        }
        entry.records.pending = Some(PendingRecord {
            group,
            batch,
            peer_generation,
            published_at: None,
        });
        Ok(())
    }

    fn automatic_record_from_source(
        &self,
        entry: &AutomaticChannel,
        group: &crate::GroupId,
        epoch: u64,
        row: &storage_sqlite::StoredAppMessageRecord,
        now: u64,
    ) -> Result<Option<MirroredChatRecord>, AccountSharingError> {
        if row.group_id_hex != hex::encode(group.as_slice()) || !matches!(row.kind, 9 | 1009) {
            return Err(AccountSharingError::NotReady);
        }
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        let (visible_id, active_edit) = if row.kind == 1009 {
            let Some(active) = storage
                .app_storage()
                .message_edit_source_is_active(&row.group_id_hex, &row.message_id_hex)
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?
            else {
                return Ok(None);
            };
            (
                row.tags
                    .iter()
                    .find(|tag| tag.first().is_some_and(|name| name == "e"))
                    .and_then(|tag| tag.get(1))
                    .map(String::as_str)
                    .unwrap_or(""),
                active,
            )
        } else {
            (row.message_id_hex.as_str(), true)
        };
        let visible = storage
            .app_storage()
            .timeline_message(&row.group_id_hex, visible_id)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        let expires_at = visible
            .as_ref()
            .and_then(|message| message.retention_expires_at)
            .into_iter()
            .chain(
                row.retention
                    .as_ref()
                    .and_then(|decision| decision.expires_at),
            )
            .min();
        // Check the original's visibility and native edit validity before encoding
        // any modifier plaintext; target retention also restricts edited content.
        let deleted = row.invalidated
            || !active_edit
            || expires_at.is_some_and(|expiry| expiry <= now)
            || visible
                .as_ref()
                .is_none_or(|message| message.deleted || message.invalidation_status.is_some());
        let payload = if deleted {
            Vec::new()
        } else {
            // Preserve the canonical original event, not an edited timeline
            // projection under the original event ID. Modifiers are separate.
            serde_json::to_vec(&(&row.plaintext, &row.tags))
                .map_err(|_| AccountSharingError::NotReady)?
        };
        if payload.len() > cgka_traits::mirrored_chat_messages::MAX_MIRRORED_MESSAGE_PAYLOAD {
            return Err(AccountSharingError::NotReady);
        }
        let content_digest = (!deleted).then(|| Sha256::digest(&payload).into());
        let accepted_origin = storage
            .app_storage()
            .current_account_chat_source_origin(
                &entry.policy.account,
                &entry.policy.local_device,
                group,
            )
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        #[cfg(all(test, feature = "test-policy-overrides"))]
        let accepted_origin = if self.test_uses_legacy_account_chat_encoding() {
            None
        } else {
            accepted_origin
        };
        Ok(Some(MirroredChatRecord {
            event_id: hex::decode(&row.message_id_hex)
                .map_err(|_| AccountSharingError::NotReady)?
                .as_slice()
                .try_into()
                .map_err(|_| AccountSharingError::NotReady)?,
            author: hex::decode(&row.sender)
                .map_err(|_| AccountSharingError::NotReady)?
                .as_slice()
                .try_into()
                .map_err(|_| AccountSharingError::NotReady)?,
            created_at: row.recorded_at,
            kind: u16::try_from(row.kind).map_err(|_| AccountSharingError::NotReady)?,
            payload,
            content_digest,
            expires_at,
            deleted,
            source_epoch: epoch,
            source_sequence: 0,
            source_digest: [0; 32],

            accepted_origin,
        }))
    }
}
