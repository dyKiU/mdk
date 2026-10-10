//! Whole-snapshot construction from retained logical rows; never MLS state export.
use crate::history_transfer::HistoryTransferError;
use cgka_engine::history_transfer::{HistoryScope, HistorySnapshotDescriptor};
use sha2::{Digest, Sha256};
use storage_sqlite::{
    SynchronizedHistoryArchive, SynchronizedHistoryBinding, SynchronizedHistoryManifest,
    SynchronizedHistoryRecord,
};

pub(super) fn binding(
    scope: &HistoryScope,
    ceiling: u64,
) -> Result<SynchronizedHistoryBinding, HistoryTransferError> {
    Ok(SynchronizedHistoryBinding {
        transfer_id: scope.transfer,
        account_id: scope
            .protected
            .account
            .as_slice()
            .try_into()
            .map_err(|_| HistoryTransferError::NotReady)?,
        source_device: scope
            .source
            .as_slice()
            .try_into()
            .map_err(|_| HistoryTransferError::NotReady)?,
        recipient_device: scope
            .recipient
            .as_slice()
            .try_into()
            .map_err(|_| HistoryTransferError::NotReady)?,
        group_id_hex: hex::encode(scope.ordinary_group.as_slice()),
        snapshot_timestamp_ceiling: ceiling,
    })
}
pub(super) fn snapshot(
    scope: &HistoryScope,
    records: &[SynchronizedHistoryRecord],
    ceiling: u64,
) -> Result<(HistorySnapshotDescriptor, Vec<u8>), HistoryTransferError> {
    if records.is_empty() || records.len() > 200 {
        return Err(HistoryTransferError::NotReady);
    }
    let binding = binding(scope, ceiling)?;
    let digest = storage_sqlite::synchronized_history_chunk_digest(&binding, 0, records)
        .map_err(|_| HistoryTransferError::NotReady)?;
    let archive = SynchronizedHistoryArchive {
        format_version: 1,
        manifest: SynchronizedHistoryManifest {
            binding,
            chunk_digests: vec![digest],
            retain_since: 0,
            max_record_lifetime_seconds: None,
        },
        chunks: vec![records.to_vec()],
    };
    let wire = serde_json::to_vec(&archive).map_err(|_| HistoryTransferError::NotReady)?;
    if wire.is_empty() || wire.len() > storage_sqlite::MAX_HISTORY_ARCHIVE_BYTES {
        return Err(HistoryTransferError::NotReady);
    }
    Ok((
        HistorySnapshotDescriptor {
            archive_digest: Sha256::digest(&wire).into(),
            timestamp_ceiling: ceiling,
            encoded_bytes: wire.len() as u32,
            fragment_count: wire
                .len()
                .div_ceil(storage_sqlite::MAX_HISTORY_ARCHIVE_FRAGMENT_BYTES)
                as u32,
            record_count: records.len() as u32,
        },
        wire,
    ))
}
