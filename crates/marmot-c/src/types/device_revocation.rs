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

c_mirror! { MarmotDeviceRevocationTarget from marmot_uniffi::DeviceRevocationTargetFfi {
    copy leaf_index: u32, bytes device/device_len,
} }
c_mirror! { MarmotDeviceRevocationTargets from marmot_uniffi::DeviceRevocationTargetsFfi,
    free marmot_device_revocation_targets_free {
    str protected_group_id_hex, copy protected_epoch: u64,
    vec targets/targets_len: MarmotDeviceRevocationTarget,
} }
