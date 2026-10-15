//! Captured scope and per-group observations, never Remove authority.
use crate::macros::c_mirror;
use marmot_uniffi::DeviceRevocationSnapshotFfi;

c_mirror! { MarmotDeviceRevocationSnapshot from DeviceRevocationSnapshotFfi,
    free marmot_device_revocation_snapshot_free {
    copy revision: u64, copy complete: bool, str protected_group_id_hex,
    str_vec ordinary_group_ids_hex/ordinary_group_ids_hex_len,
    str_vec completed_group_ids_hex/completed_group_ids_hex_len,
    bytes target_device/target_device_len,
} }
