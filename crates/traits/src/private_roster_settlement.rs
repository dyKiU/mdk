//! Experimental same-transaction settlement facts. Never permission or live admission.
use crate::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use crate::private_device_invite::PrivateInviteOrigin;
use crate::storage::StorageResult;
use crate::types::{GroupId, MessageId};
use serde::{Deserialize, Serialize};
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSettlementAnchor {
    pub origin: PrivateInviteOrigin,
    pub account: [u8; 32],
    pub local_device: [u8; 32],
    pub group_id: GroupId,
    pub successor: DeviceGroupAnchorRoster,
    pub roster_commitment: [u8; 32],
    pub enrollment_nonce: [u8; 32],
    pub context_digest: [u8; 32],
    pub coordinator: [u8; 32],
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivateSettlementPhase {
    Pending,
    Completed,
    Denied,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSettlementState {
    pub format_version: u16,
    pub generation: u64,
    pub phase: PrivateSettlementPhase,
    pub anchor: PrivateSettlementAnchor,
    pub round_nonce: Option<[u8; 32]>,
    pub coordinator_leaf_index: Option<u32>,
    pub prepared_ciphertext: Option<Vec<u8>>,
    pub outbound: Option<Vec<u8>>,
    /// Crypto-sealed ACK receipts awaiting the genuine coordinator Challenge.
    /// These are not counted confirmations and cannot bind a round nonce.
    #[serde(default)]
    pub deferred_acks: Vec<PrivateSettlementDeferredAck>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSettlementFact {
    pub format_version: u16,
    pub generation: u64,
    pub leaf_index: u32,
    pub signature_public_key: [u8; 32],
    pub message_id: MessageId,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSettlementDeferredAck {
    pub fact: PrivateSettlementFact,
    pub round_nonce: [u8; 32],
}
/// One fresh storage read, never a retained authorization or settled-roster proof.
/// Backends may include the facts already validated while reading this state.
/// `None` leaves fact loading to the caller at its original validation point.
pub struct PrivateSettlementRead {
    pub state: PrivateSettlementState,
    pub loaded_facts: Option<Vec<PrivateSettlementFact>>,
}

/// Trusted-core fact storage; caller crypto SQL transaction encloses ratchets.
/// No method mints live admission, SDK consent or a validated settled roster.
pub trait PrivateRosterSettlementStorage: Send + Sync {
    fn read_round(&self) -> StorageResult<Option<PrivateSettlementState>>;
    /// Optional combined read. The conservative default does not read facts:
    /// callers retain their existing early-return and error precedence.
    fn read_round_with_loaded_facts(&self) -> StorageResult<Option<PrivateSettlementRead>> {
        self.read_round().map(|state| state.map(|state| PrivateSettlementRead {
            state,
            loaded_facts: None,
        }))
    }

    fn select_round(
        &self,
        anchor: &PrivateSettlementAnchor,
    ) -> StorageResult<PrivateSettlementState>;
    fn bind_round_nonce(
        &self,
        generation: u64,
        nonce: [u8; 32],
        coordinator_leaf_index: u32,
    ) -> StorageResult<()>;
    fn record_local_confirmation(
        &self,
        fact: &PrivateSettlementFact,
        ciphertext: &[u8],
    ) -> StorageResult<()>;
    fn record_remote_confirmation(&self, fact: &PrivateSettlementFact) -> StorageResult<()>;
    fn defer_remote_ack(&self, ack: &PrivateSettlementDeferredAck) -> StorageResult<()>;
    fn clear_deferred_acks(&self, generation: u64) -> StorageResult<()>;
    fn put_outbound(&self, generation: u64, bytes: &[u8]) -> StorageResult<()>;
    fn deny_round(&self, generation: u64) -> StorageResult<()>;
    fn abandon_pending_on_startup(&self) -> StorageResult<bool>;
    fn read_facts(&self) -> StorageResult<Vec<PrivateSettlementFact>>;
}
