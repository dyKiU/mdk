//! Source-attested logical messages; never ordinary MLS evidence or permissions.
use crate::{GroupId, mirrored_chat_catalog::MirroredChatScope, storage::StorageResult};
use serde::{Deserialize, Serialize};

pub const MAX_MIRRORED_MESSAGE_PAGE: usize = 128;
pub const MAX_MIRRORED_MESSAGE_PAYLOAD: usize = 65536;
pub const MAX_MIRRORED_MESSAGE_ROWS: usize = 100000;
pub const MAX_MIRRORED_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirroredChatRecord {
    pub event_id: [u8; 32],
    pub author: [u8; 32],
    pub created_at: u64,
    pub kind: u16,
    /// Canonical logical (content,tags) bytes; never MLS ciphertext or secrets.
    pub payload: Vec<u8>,
    /// SHA256 of original logical payload; unknown only for empty tombstones.
    pub content_digest: Option<[u8; 32]>,
    pub expires_at: Option<u64>,
    pub deleted: bool,
    pub source_epoch: u64,
    pub source_sequence: u64,
    pub source_digest: [u8; 32],
    /// Immutable accepted source lineage; absence preserves the legacy strict fence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_origin: Option<crate::mirrored_chat_catalog::AcceptedChatOrigin>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirroredChatCursor {
    pub created_at: u64,
    pub event_id: [u8; 32],
}

pub trait MirroredChatMessageStorage: Send + Sync {
    /// Atomic bounded already-authenticated logical import. Requires an active
    /// source catalog observation and original before/tail validation.
    fn apply_mirrored_chat_messages(
        &self,
        scope: &MirroredChatScope,
        group: &GroupId,
        records: &[MirroredChatRecord],
        now: u64,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<usize>;
    /// Chronological cursor page, with permanent global terminal/retention fences.
    /// Expired payloads are never returned. Reads do not restore policy authority.
    fn mirrored_chat_message_page(
        &self,
        scope: &MirroredChatScope,
        group: &GroupId,
        after: Option<&MirroredChatCursor>,
        limit: usize,
        now: u64,
    ) -> StorageResult<Vec<MirroredChatRecord>>;
    /// Bounded payload purge retaining identity, digest and terminal references.
    /// This local negative retention transition never increments source sequence.
    fn purge_expired_mirrored_chat_messages(
        &self,
        scope: &MirroredChatScope,
        group: &GroupId,
        now: u64,
        limit: usize,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<usize>;
}
