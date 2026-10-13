//! Trusted-core outgoing Add facts. These records cannot reconstruct SDK consent.
use crate::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use crate::device_linking_key_package::PurposeAttemptScope;
use crate::storage::StorageError;
use crate::{GroupId, TransportMessage};
use serde::{Deserialize, Serialize};

pub const MAX_PRIVATE_INVITE_COMMIT_BYTES: usize = 262_144;
pub const MAX_PRIVATE_INVITE_WELCOME_BYTES: usize = 2_097_152;
pub const MAX_PRIVATE_INVITE_BINDING_BYTES: usize = 131_072;
// Pinned private transport uses 24 KiB chunks for the bounded 2 MiB artifact.
pub const MAX_PRIVATE_INVITE_WELCOME_MESSAGES: usize = 86;
pub const MAX_PRIVATE_INVITE_TRANSPORT_BYTES: usize = 16_777_216;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateInviteScope {
    pub account: [u8; 32],
    pub local_device: [u8; 32],
    pub staging_generation: u64,
}

/// Exact selected origin kind; generation numbers from different stores differ.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "generation")]
pub enum PrivateInviteOrigin {
    Genesis(u64),
    Accepted(u64),
    Confirmed(u64),
    Existing(u64),
    Revoked(u64),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateInviteBinding {
    pub format_version: u16,
    pub approver_scope: PurposeAttemptScope,
    pub recipient_generation: u64,
    pub origin: PrivateInviteOrigin,
    pub group_id: GroupId,
    pub recipient: [u8; 32],
    pub nonce: [u8; 32],
    pub context_digest: [u8; 32],
    pub key_package_reference: [u8; 32],
    pub key_package_digest: [u8; 32],
    pub commit_digest: [u8; 32],
    pub welcome_digest: [u8; 32],
    pub predecessor: DeviceGroupAnchorRoster,
    pub successor: DeviceGroupAnchorRoster,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateInviteRawDraft {
    pub binding: PrivateInviteBinding,
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateInviteTransport {
    pub commit: TransportMessage,
    /// Cached for trusted confirmed-membership delivery, never ready to publish.
    pub welcomes: Vec<TransportMessage>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i64)]
pub enum PrivateInvitePhase {
    RawStaged = 0,
    Wrapped = 1,
    Dispatching = 2,
    PublicationUnknown = 3,
    Retired = 4,
    Confirmed = 5,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateInviteFact {
    pub scope: PrivateInviteScope,
    pub raw: PrivateInviteRawDraft,
    pub transport: Option<PrivateInviteTransport>,
    pub phase: PrivateInvitePhase,
}

/// Retained separately: retiring the next pending Add cannot erase this anchor.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmedPrivateInviteFact {
    pub scope: PrivateInviteScope,
    pub binding: PrivateInviteBinding,
    pub denied: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum PrivateInviteStorageError {
    #[error("private invite selection is busy")]
    Busy,
    #[error("private invite scope mismatch")]
    ScopeMismatch,
    #[error("invalid private invite fact")]
    InvalidFact,
    #[error("private invite generation exhausted")]
    GenerationExhausted,
    #[error("private invite publication requires reconciliation")]
    PublicationUncertain,
    #[error("private invite storage unavailable")]
    Unsupported,
    #[error(transparent)]
    Storage(#[from] StorageError),
}
pub type PrivateInviteStorageResult<T> = Result<T, PrivateInviteStorageError>;

/// All writes participate in actual engine crypto/SQL transactions. Only trusted
/// core supplies actual staged/published evidence; no native or wire draft inlet.
/// Capability absence must deny preparation. Rows never restore verifier leases.
pub trait PrivateDeviceInviteStorage: Send + Sync {
    fn private_invite(&self) -> PrivateInviteStorageResult<Option<PrivateInviteFact>>;
    fn confirmed_private_invite(
        &self,
    ) -> PrivateInviteStorageResult<Option<ConfirmedPrivateInviteFact>>;
    fn stage_private_invite(
        &self,
        draft: &PrivateInviteRawDraft,
    ) -> PrivateInviteStorageResult<PrivateInviteFact>;
    fn cache_private_invite_transport(
        &self,
        scope: &PrivateInviteScope,
        transport: &PrivateInviteTransport,
    ) -> PrivateInviteStorageResult<PrivateInviteFact>;
    fn mark_private_invite_dispatch(
        &self,
        scope: &PrivateInviteScope,
    ) -> PrivateInviteStorageResult<PrivateInviteFact>;
    fn mark_private_invite_publication_unknown(
        &self,
        scope: &PrivateInviteScope,
    ) -> PrivateInviteStorageResult<()>;
    fn confirm_private_invite(
        &self,
        scope: &PrivateInviteScope,
        actual_successor: &DeviceGroupAnchorRoster,
    ) -> PrivateInviteStorageResult<ConfirmedPrivateInviteFact>;
    /// Reject dispatched/unknown publication; retirement is not an assumed failure.
    fn retire_undispatched_private_invite(
        &self,
        scope: &PrivateInviteScope,
    ) -> PrivateInviteStorageResult<()>;
    fn deny_confirmed_private_invite(
        &self,
        scope: &PrivateInviteScope,
        group: &GroupId,
    ) -> PrivateInviteStorageResult<()>;
}
