//! Read-only authenticated observations; records never reconstruct approval.
use crate::macros::c_mirror;
use marmot_uniffi::conversions::*;
c_mirror! { MarmotAccountSharingSnapshot from AccountSharingSnapshotFfi, free marmot_account_sharing_snapshot_free {
    str protected_group_id_hex, copy protected_epoch: u64,
    bytes source_device/source_device_len, bytes recipient_device/recipient_device_len,
    copy revision: u64, copy approved: bool, copy complete: bool,
} }
c_mirror! { MarmotAccountSharingTarget from AccountSharingTargetFfi {
    copy leaf_index: u32, bytes device/device_len,
} }
c_mirror! { MarmotAccountSharingTargets from AccountSharingTargetsFfi, free marmot_account_sharing_targets_free {
    str protected_group_id_hex, copy protected_epoch: u64,
    vec targets/targets_len: MarmotAccountSharingTarget,
} }
