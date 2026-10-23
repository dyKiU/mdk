//! Original existing-member successor metadata. Persistence never restores consent.
use crate::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use crate::private_device_invite::PrivateInviteOrigin;
use crate::storage::StorageResult;
use crate::types::GroupId;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExistingDeviceGroupDraft {
    pub account: [u8; 32],
    pub local_device: [u8; 32],
    pub group_id: GroupId,
    pub predecessor: DeviceGroupAnchorRoster,
    pub predecessor_origin: PrivateInviteOrigin,
    pub predecessor_settlement_generation: u64,
    pub action_binding: [u8; 32],
    pub nonce: [u8; 32],
    pub context_digest: [u8; 32],
    pub coordinator: [u8; 32],
    pub recipient: [u8; 32],
    pub key_package_reference: [u8; 32],
    pub key_package_digest: [u8; 32],
    pub commit_digest: [u8; 32],
    pub successor: DeviceGroupAnchorRoster,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExistingDeviceGroupFact {
    pub generation: u64,
    pub draft: ExistingDeviceGroupDraft,
    /// Permanent negative fence for this generation; never an approval flag.
    pub denied: bool,
}

/// Optional bounded metadata store in the original guarded single-Add SQL unit.
/// Only authenticated Core apply may install a draft. No row, native DTO or
/// reopened database can manufacture the original live action or settlement guard.
pub trait ExistingDeviceGroupStorage: Send + Sync {
    fn existing_anchor(&self) -> StorageResult<Option<ExistingDeviceGroupFact>>;
    fn install_existing_anchor(
        &self,
        draft: &ExistingDeviceGroupDraft,
    ) -> StorageResult<ExistingDeviceGroupFact>;
    fn deny_existing_anchor(&self, generation: u64, group: &GroupId) -> StorageResult<()>;
}
