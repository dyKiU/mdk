//! Durable logical sends and authenticated receipt metadata, never live permission.
use crate::{GroupId, storage::StorageResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_ACCOUNT_CHAT_SEND_PAYLOAD: usize = 65536;
pub const MAX_ACCOUNT_CHAT_SEND_INTENTS: usize = 4096;
pub const MAX_ACCOUNT_CHAT_SEND_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ACCOUNT_CHAT_SEND_ROUTES: usize = 8192;
pub const MAX_ACCOUNT_CHAT_SEND_RECEIPTS: usize = 32768;
pub const MAX_ACCOUNT_CHAT_SEND_PAGE: usize = 128;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountChatSendIntent {
    pub intent_id: [u8; 32],
    pub account: [u8; 32],
    pub originating_device: [u8; 32],
    pub group: GroupId,
    /// Canonical inner event ID, never a queue or MLS envelope ID.
    pub ordinary_event_id: [u8; 32],
    /// Exact encoded MarmotAppEvent, constructed once on the originating device.
    pub event_payload: Vec<u8>,
    pub payload_digest: [u8; 32],
    pub created_at: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountChatSendRoute {
    pub policy_id: [u8; 32],
    pub local_device: [u8; 32],
    pub peer_device: [u8; 32],
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountChatSendState {
    Queued,
    Received,
    Published { event_id: [u8; 32] },
    Denied,
}
/// Fair bounded retry traversal, distinct from chronological message cursors.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountChatSendCursor {
    pub intent_id: [u8; 32],
    pub policy_id: [u8; 32],
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountChatQueuedSend {
    pub intent: AccountChatSendIntent,
    pub route: AccountChatSendRoute,
    pub state: AccountChatSendState,
}
/// Read-only retry observation. Terminal rows retain identity/digest/time but
/// erase payload; this value never restores a live sharing or send permission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountChatSendIntentObservation {
    pub intent: AccountChatSendIntent,
    pub state: AccountChatSendState,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountChatSendReceipt {
    pub intent_id: [u8; 32],
    pub route: AccountChatSendRoute,
    /// Actual independently validated ordinary-chat member, separate from origin.
    pub actual_member_device: [u8; 32],
    pub state: AccountChatSendState,
}
impl AccountChatSendReceipt {
    /// Versioned exact receipt identity; does not authenticate these bytes.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"WN-account-chat-send-receipt-v1");
        h.update(self.intent_id);
        h.update(self.route.policy_id);
        // Stable across the two local route orientations.
        let (first, second) = if self.route.local_device < self.route.peer_device {
            (self.route.local_device, self.route.peer_device)
        } else {
            (self.route.peer_device, self.route.local_device)
        };
        h.update(first);
        h.update(second);
        h.update(self.actual_member_device);
        match self.state {
            AccountChatSendState::Queued => h.update([0]),
            AccountChatSendState::Received => h.update([1]),
            AccountChatSendState::Published { event_id } => {
                h.update([2]);
                h.update(event_id);
            }
            AccountChatSendState::Denied => h.update([3]),
        }
        h.finalize().into()
    }
}
pub trait AccountChatSendQueueStorage: Send + Sync {
    fn account_chat_send_intent(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        intent_id: &[u8; 32],
    ) -> StorageResult<Option<AccountChatSendIntentObservation>>;
    /// Admit immutable event and one exact approved route atomically. Core must
    /// validate fresh original policy, account and lifecycle before and at tail.
    fn admit_account_chat_send_intent(
        &self,
        intent: &AccountChatSendIntent,
        route: &AccountChatSendRoute,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()>;
    fn pending_account_chat_sends(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        after: Option<&AccountChatSendCursor>,
        limit: usize,
    ) -> StorageResult<Vec<AccountChatQueuedSend>>;
    /// Actual member transition and outgoing exact receipt in one transaction.
    fn stage_account_chat_send_receipt(
        &self,
        account: &[u8; 32],
        receipt: &AccountChatSendReceipt,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()>;
    /// Authenticated incoming receipt; does not generate an ACK loop.
    fn receive_account_chat_send_receipt(
        &self,
        account: &[u8; 32],
        receipt: &AccountChatSendReceipt,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()>;
    fn pending_account_chat_send_receipts(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        after_digest: Option<&[u8; 32]>,
        limit: usize,
    ) -> StorageResult<Vec<AccountChatSendReceipt>>;
    fn acknowledge_account_chat_send_receipt(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        receipt_digest: &[u8; 32],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()>;
    /// Origin cancellation is a permanent global fence; a route denial is local.
    fn deny_account_chat_send_intent(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        intent_id: &[u8; 32],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipt_identity_is_role_symmetric_and_binds_member_state_and_ordinary_id() {
        let mut receipt = AccountChatSendReceipt {
            intent_id: [5; 32],
            route: AccountChatSendRoute {
                policy_id: [4; 32],
                local_device: [2; 32],
                peer_device: [3; 32],
            },
            actual_member_device: [3; 32],
            state: AccountChatSendState::Published { event_id: [6; 32] },
        };
        let original = receipt.digest();
        std::mem::swap(
            &mut receipt.route.local_device,
            &mut receipt.route.peer_device,
        );
        assert_eq!(original, receipt.digest());
        for n in 0..5 {
            let mut changed = receipt.clone();
            match n {
                0 => changed.actual_member_device = [2; 32],
                1 => changed.state = AccountChatSendState::Received,
                2 => changed.state = AccountChatSendState::Published { event_id: [7; 32] },
                3 => changed.route.policy_id = [8; 32],
                _ => changed.intent_id = [9; 32],
            };
            assert_ne!(original, changed.digest());
        }
    }
}
