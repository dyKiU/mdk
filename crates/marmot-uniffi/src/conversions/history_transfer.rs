//! Authenticated history review observations. Records never restore an original action.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct HistoryTransferSnapshotFfi {
    pub revision: u64,
    pub imported_records: u32,
    pub complete: bool,
    pub group_id_hex: String,
    pub source_device: Vec<u8>,
    pub recipient_device: Vec<u8>,
    pub snapshot_timestamp_ceiling: u64,
    pub record_count: u32,
    pub encoded_bytes: u32,
    pub fragment_count: u32,
}
impl From<marmot_app::HistoryTransferSnapshot> for HistoryTransferSnapshotFfi {
    fn from(value: marmot_app::HistoryTransferSnapshot) -> Self {
        Self {
            revision: value.revision,
            imported_records: value.imported_records,
            complete: value.complete,
            group_id_hex: hex::encode(value.group.as_slice()),
            source_device: value.source_device,
            recipient_device: value.recipient_device,
            snapshot_timestamp_ceiling: value.snapshot_timestamp_ceiling,
            record_count: value.record_count,
            encoded_bytes: value.encoded_bytes,
            fragment_count: value.fragment_count,
        }
    }
}
