//! Default-off private-group birth provenance. Persistence facts are never permissions.
use crate::storage::StorageError;
use crate::types::{EpochId, GroupId};
use serde::{Deserialize, Serialize};

/// Application-owned experimental allocation; not a Marmot protocol identifier.
pub const PRIVATE_DEVICE_GROUP_COMPONENT_ID: u16 = 0xf574;
pub const PRIVATE_DEVICE_GROUP_PROFILE: &[u8] = b"whitenoise.experimental.device-group.v1";
pub const PRIVATE_DEVICE_GROUP_FEATURE: &str = "whitenoise.experimental.device-sync.v1";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisScope {
    pub account: [u8; 32],
    pub local_device: [u8; 32],
    pub selection_generation: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisLeaf {
    pub leaf_index: u32,
    pub account: [u8; 32],
    pub signature_public_key: [u8; 32],
}
/// Actual freshly created tree metadata; no caller-supplied generation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisBirthDraft {
    pub format_version: u16,
    pub group_id: GroupId,
    pub epoch: EpochId,
    pub epoch_authenticator_digest: [u8; 32],
    pub leaves: Vec<GenesisLeaf>,
    pub roster_commitment: [u8; 32],
}
/// Immutable completed birth metadata, not SDK consent or successor approval.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGroupGenesisFact {
    pub scope: GenesisScope,
    pub birth: GenesisBirthDraft,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGroupGenesisSelection {
    pub fact: DeviceGroupGenesisFact,
    /// Permanent denial for this selected lineage; never an approval flag.
    pub active_denied: bool,
}
#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    #[error("a private group selection is already active")]
    SelectionBusy,
    #[error("private group selection scope mismatch")]
    ScopeMismatch,
    #[error("invalid private group birth fact")]
    InvalidFact,
    #[error("private group selection generation exhausted")]
    GenerationExhausted,
    #[error("private group provenance storage unavailable")]
    Unsupported,
    #[error(transparent)]
    Storage(#[from] StorageError),
}
pub type GenesisResult<T> = Result<T, GenesisError>;

/// Optional transaction-participating fact storage. No public grant ingestion.
/// Inputs belong to trusted core persistence; they are never accepted from wire
/// DTOs. Only the engine's genuine creation path establishes birth provenance.
pub trait DeviceGroupGenesisStorage: Send + Sync {
    fn genesis_selection(&self) -> GenesisResult<Option<DeviceGroupGenesisSelection>>;
    /// Assigns a checked local generation, in the same SQL unit as fresh MLS creation.
    fn store_genesis_birth(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        birth: &GenesisBirthDraft,
    ) -> GenesisResult<DeviceGroupGenesisSelection>;
    /// Exact-scope permanent denial. Birth bytes remain unchanged.
    fn deny_genesis_selection(&self, scope: &GenesisScope, group_id: &GroupId)
    -> GenesisResult<()>;
}
