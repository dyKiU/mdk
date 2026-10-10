//! Review observations; no record can reconstruct original consent.
use crate::macros::c_mirror;
use marmot_uniffi::conversions::*;

c_mirror! { MarmotHistoryTransferSnapshot from HistoryTransferSnapshotFfi, free marmot_history_transfer_snapshot_free {
    copy revision: u64, copy imported_records: u32, copy complete: bool,
    str group_id_hex, bytes source_device/source_device_len,
    bytes recipient_device/recipient_device_len,
    copy snapshot_timestamp_ceiling: u64, copy record_count: u32,
    copy encoded_bytes: u32, copy fragment_count: u32,
} }
