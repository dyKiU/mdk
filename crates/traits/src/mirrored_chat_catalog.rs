//! Paired-source chat observations, separate from MLS membership and permission.
use crate::{GroupId, group::ProtocolProfile, storage::StorageResult};
use serde::{Deserialize, Serialize};

pub const MAX_MIRRORED_CHAT_PAGE: usize = 128;
pub const MAX_MIRRORED_CHAT_ROWS: usize = 8192;
pub const MAX_MIRRORED_CHAT_SCOPES: usize = 128;

/// Exact recipient/source policy context. Persisting this never restores consent.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirroredChatScope {
    pub account: [u8; 32],
    pub local_device: [u8; 32],
    pub source_device: [u8; 32],
    pub policy_digest: [u8; 32],
    pub protected_group: GroupId,
    pub protected_generation: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MirroredChatState {
    Active,
    Left,
    Deleted,
}

/// A source-attested sidebar observation, never an independently joined group.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirroredChatEntry {
    pub group_id: GroupId,
    pub source_epoch: u64,
    pub source_sequence: u64,
    pub source_digest: [u8; 32],
    pub profile: ProtocolProfile,
    pub name: String,
    pub description: String,
    pub state: MirroredChatState,
}

/// Optional storage of already authenticated observations. Core owns approval,
/// decryption and fresh roster validation; neither read nor write grants them.
pub trait MirroredChatCatalogStorage: Send + Sync {
    /// Apply one bounded page atomically, checking the original owner's validity
    /// before work and before commit. Exact retries are idempotent; stale records
    /// cannot override newer observations or reactivate terminal conversations.
    fn apply_mirrored_chat_catalog(
        &self,
        scope: &MirroredChatScope,
        entries: &[MirroredChatEntry],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<usize>;

    /// Canonical group-ID pagination, including terminal fences. The caller must
    /// retain a live policy owner before publishing these observations to an app.
    fn mirrored_chat_catalog_page(
        &self,
        scope: &MirroredChatScope,
        after: Option<&GroupId>,
        limit: usize,
    ) -> StorageResult<Vec<MirroredChatEntry>>;
}
