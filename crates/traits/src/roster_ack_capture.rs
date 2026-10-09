//! Experimental bounded capture metadata. These facts never grant permission.
use crate::storage::StorageResult;
use crate::types::{EpochId, GroupId, MemberId, MessageId};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterAckCaptureLeaf {
    pub leaf_index: u32,
    pub signature_public_key: Vec<u8>,
}

/// A locally selected scope, not an approved roster or consent anchor.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterAckCaptureState {
    pub format_version: u16,
    pub generation: u64,
    /// Permanent denial for this round, never an approval bit.
    pub invalidated: bool,
    pub account: MemberId,
    pub local_device: Vec<u8>,
    pub group_id: GroupId,
    pub epoch: EpochId,
    pub epoch_authenticator_digest: [u8; 32],
    pub roster_commitment: [u8; 32],
    pub leaves: Vec<RosterAckCaptureLeaf>,
    pub round_nonce: Option<[u8; 32]>,
    /// The challenge sender must be an authenticated occupied source leaf.
    pub challenge_source: Option<u32>,
    /// One exact encrypted publication, serialized SendResult, never evidence.
    pub outbound: Option<Vec<u8>>,
    /// Exact serialized MLS ciphertext, atomic with its sender ratchet.
    pub prepared_ciphertext: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterAckCaptureFact {
    pub format_version: u16,
    pub generation: u64,
    pub leaf_index: u32,
    pub signature_public_key: Vec<u8>,
    pub message_id: MessageId,
}

/// Optional same-transaction storage only; no grant or public proof ingestion.
pub trait RosterAckCaptureStorage: Send + Sync {
    fn capture_state(&self) -> StorageResult<Option<RosterAckCaptureState>>;
    /// Replaces the one local round; assigns a checked monotonic generation.
    fn select_capture(&self, state: &RosterAckCaptureState)
    -> StorageResult<RosterAckCaptureState>;
    fn invalidate_capture(&self, generation: u64) -> StorageResult<()>;
    fn accept_capture_challenge(
        &self,
        generation: u64,
        nonce: [u8; 32],
        source: u32,
    ) -> StorageResult<()>;
    fn put_prepared_capture_ciphertext(&self, generation: u64, bytes: &[u8]) -> StorageResult<()>;
    fn put_capture_outbound(&self, generation: u64, bytes: &[u8]) -> StorageResult<()>;
    fn put_capture_fact(&self, fact: &RosterAckCaptureFact) -> StorageResult<()>;
    fn capture_facts(&self) -> StorageResult<Vec<RosterAckCaptureFact>>;
}
