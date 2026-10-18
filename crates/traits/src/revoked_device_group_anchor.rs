//! Authenticated single-Remove successor metadata; retained rows never restore consent.
use crate::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use crate::private_device_invite::PrivateInviteOrigin;
use crate::storage::StorageResult;
use crate::types::GroupId;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedDeviceGroupDraft {
    pub account: [u8; 32],
    pub local_device: [u8; 32],
    pub group_id: GroupId,
    pub predecessor: DeviceGroupAnchorRoster,
    pub predecessor_origin: PrivateInviteOrigin,
    pub predecessor_settlement_generation: u64,
    pub source_leaf_index: u32,
    pub source_device: [u8; 32],
    pub removed_leaf_index: u32,
    pub removed_device: [u8; 32],
    pub actual_commit_digest: [u8; 32],
    pub action_binding: [u8; 32],
    pub nonce: [u8; 32],
    pub context_digest: [u8; 32],
    pub successor: DeviceGroupAnchorRoster,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedDeviceGroupFact {
    pub generation: u64,
    pub draft: RevokedDeviceGroupDraft,
    /// Permanent negative fence, never a grant.
    pub denied: bool,
}

/// Optional bounded metadata, installed only within authenticated original Core
/// Remove apply. Persistence carries no live admission, consent or deadline.
pub trait RevokedDeviceGroupStorage: Send + Sync {
    /// Bounded retained lineage for negative privacy checks only.
    fn revoked_anchors(&self) -> StorageResult<Vec<RevokedDeviceGroupFact>>;
    fn revoked_anchor(&self) -> StorageResult<Option<RevokedDeviceGroupFact>>;
    fn install_revoked_anchor(
        &self,
        draft: &RevokedDeviceGroupDraft,
    ) -> StorageResult<RevokedDeviceGroupFact>;
    fn deny_revoked_anchor(&self, generation: u64, group: &GroupId) -> StorageResult<()>;
}
