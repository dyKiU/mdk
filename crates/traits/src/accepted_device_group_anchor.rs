//! Trusted-core accepted successor facts. Persistence never recreates SDK consent.
use crate::device_group_genesis::GenesisLeaf;
use crate::device_linking_key_package::PurposeAttemptScope;
use crate::storage::StorageError;
use crate::types::{EpochId, GroupId};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGroupAnchorRoster {
    pub epoch: EpochId,
    pub epoch_authenticator_digest: [u8; 32],
    pub leaves: Vec<GenesisLeaf>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedDeviceGroupAnchorDraft {
    pub format_version: u16,
    pub purpose: PurposeAttemptScope,
    pub group_id: GroupId,
    pub nonce: [u8; 32],
    pub context_digest: [u8; 32],
    pub key_package_reference: [u8; 32],
    pub welcome_digest: [u8; 32],
    pub approver: [u8; 32],
    pub recipient: [u8; 32],
    pub predecessor: DeviceGroupAnchorRoster,
    pub successor: DeviceGroupAnchorRoster,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGroupAnchorScope {
    pub account: [u8; 32],
    pub local_device: [u8; 32],
    pub selection_generation: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedDeviceGroupAnchorFact {
    pub scope: DeviceGroupAnchorScope,
    pub draft: AcceptedDeviceGroupAnchorDraft,
    /// Permanent denial for this generation, never an approval flag.
    pub denied: bool,
}
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("a device group anchor selection is already active")]
    SelectionBusy,
    #[error("device group anchor scope mismatch")]
    ScopeMismatch,
    #[error("invalid device group anchor fact")]
    InvalidFact,
    #[error("device group anchor generation exhausted")]
    GenerationExhausted,
    #[error("device group anchor storage unavailable")]
    Unsupported,
    #[error(transparent)]
    Storage(#[from] StorageError),
}
pub type AnchorResult<T> = Result<T, AnchorError>;

/// Optional, bounded fact store participating in the actual Welcome SQL unit.
/// Only trusted core persistence supplies these drafts, after sealed SDK evidence
/// and actual authenticated tree validation. Never accept drafts from native/wire
/// DTOs, or use a stored fact to manufacture a verifier or settlement permission.
pub trait AcceptedDeviceGroupAnchorStorage: Send + Sync {
    fn accepted_anchor(&self) -> AnchorResult<Option<AcceptedDeviceGroupAnchorFact>>;
    fn install_accepted_anchor(
        &self,
        draft: &AcceptedDeviceGroupAnchorDraft,
    ) -> AnchorResult<AcceptedDeviceGroupAnchorFact>;
    fn deny_accepted_anchor(
        &self,
        scope: &DeviceGroupAnchorScope,
        group_id: &GroupId,
    ) -> AnchorResult<()>;
}
