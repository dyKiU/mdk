//! Independent selected-chat recipient facts. Stored metadata never recreates consent.
use crate::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use crate::storage::StorageResult;
use crate::types::{EpochId, GroupId};
use serde::{Deserialize, Serialize};

pub const MAX_SELECTED_CHAT_PURPOSE_ROWS: usize = 128;
pub const MAX_SELECTED_CHAT_KEY_PACKAGE_BYTES: usize = 16_384;
pub const MAX_SELECTED_CHAT_PURPOSE_CONTEXT_BYTES: usize = 131_072;
pub const MAX_SELECTED_CHAT_GROUP_ID_BYTES: usize = 256;
pub const MAX_SELECTED_CHAT_LEAF_HASH_BYTES: usize = 512;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectedChatPurposeScope {
    pub account: [u8; 32],
    pub local_device: [u8; 32],
    pub generation: u64,
    pub request_binding: [u8; 32],
}

/// Observed context only. Actual decrypted group and original live owner must
/// be validated by Core before and through the join transaction.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectedChatPurposeContext {
    pub approved_response_digest: [u8; 32],
    pub protected_group: GroupId,
    pub protected_anchor: DeviceGroupAnchorRoster,
    pub protected_settlement_generation: u64,
    pub ordinary_group: GroupId,
    pub ordinary_epoch: EpochId,
    pub ordinary_own_leaf_index: u32,
    pub ordinary_own_leaf_hash: Vec<u8>,
    pub ordinary_roster_digest: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelectedChatPurposeState {
    Pending,
    Consumed,
    Denied,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectedChatPurposeKeyPackage {
    pub scope: SelectedChatPurposeScope,
    pub context: SelectedChatPurposeContext,
    pub public_bytes: Vec<u8>,
    pub reference: [u8; 32],
    pub signature_public_key: [u8; 32],
    pub state: SelectedChatPurposeState,
}

/// Optional atomic backend capability, independent of pairing-purpose storage.
/// Nontransactional backends must not expose it: private bundle writes and
/// tentative consumption must share one real transaction. Mutations match the
/// complete scope and exact reference, and check the backend account/device
/// identity rather than accepting caller-supplied ownership as authority.
/// Keep terminal reference tombstones and fail closed at the bounded capacity.
/// No row grants permission, persists a deadline, or restores a process owner.
/// New rows are Pending only; at most one Pending row is retained. Exact Pending
/// retries compare every field and remain valid at capacity. Consumed/Denied
/// never become Pending again. Terminal repeats retain the existing state;
/// cancelling a consumed reference leaves it Consumed. Capacity includes all
/// tombstones. Group snapshots and deletion cannot remove these account facts.
pub trait SelectedChatKeyPackageStorage: Send + Sync {
    /// Bounded cleanup inspection, including terminal tombstones. Core owns
    /// deletion of each exact private bundle within the same SQL transaction.
    fn selected_chat_key_packages(&self) -> StorageResult<Vec<SelectedChatPurposeKeyPackage>>;
    fn selected_chat_key_package_by_ref(
        &self,
        reference: &[u8; 32],
    ) -> StorageResult<Option<SelectedChatPurposeKeyPackage>>;
    fn selected_chat_key_package(
        &self,
        scope: &SelectedChatPurposeScope,
    ) -> StorageResult<Option<SelectedChatPurposeKeyPackage>>;
    fn put_selected_chat_key_package(
        &self,
        package: &SelectedChatPurposeKeyPackage,
    ) -> StorageResult<()>;
    fn consume_selected_chat_key_package(
        &self,
        scope: &SelectedChatPurposeScope,
        reference: &[u8; 32],
    ) -> StorageResult<()>;
    fn deny_selected_chat_key_package(
        &self,
        scope: &SelectedChatPurposeScope,
        reference: &[u8; 32],
    ) -> StorageResult<()>;
    /// Startup abandonment records negative facts only. It never restores approval.
    fn deny_pending_selected_chat_key_packages(&self) -> StorageResult<()>;
}
