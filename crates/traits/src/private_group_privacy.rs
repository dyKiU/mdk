//! Permanent negative chat-presentation facts. Never membership or consent.
use crate::{GroupId, storage::StorageResult};

/// Trusted-core storage participating in the same transaction as actual private
/// birth or accepted join. Rows survive group deletion and selection replacement.
/// Readers must reject owner mismatch, never fall back to ordinary presentation.
pub trait PrivateGroupPrivacyStorage: Send + Sync {
    fn mark_private_group_for_chat_exclusion(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        group: &GroupId,
    ) -> StorageResult<()>;
    fn private_group_chat_excluded(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        group: &GroupId,
    ) -> StorageResult<bool>;
}
