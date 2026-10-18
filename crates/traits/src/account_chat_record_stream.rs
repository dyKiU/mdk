//! Durable logical-delivery metadata. Never restored channel keys or authority.
use crate::{GroupId, mirrored_chat_catalog::MirroredChatScope, storage::StorageResult};
use serde::{Deserialize, Serialize};

pub const MAX_ACCOUNT_CHAT_RECORD_BATCH_BYTES: usize = 1024 * 1024;
pub const MAX_ACCOUNT_CHAT_RECORD_OUTBOX_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ACCOUNT_CHAT_RECORD_OUTBOX: usize = 4096;
pub const MAX_ACCOUNT_CHAT_RECORD_RECEIPTS: usize = 8192;
pub const MAX_ACCOUNT_CHAT_RECORD_JOURNAL: usize = 100000;
pub const MAX_ACCOUNT_CHAT_RECORD_GENERATION_RECEIPTS: usize = 8192;

/// Canonical JSON Vec<MirroredChatRecord>, ordered by distinct source sequence.
/// Group and stable policy are supplied separately and checked on every operation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountChatRecordBatch {
    pub batch_digest: [u8; 32],
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub record_count: u32,
    pub encoded_records: Vec<u8>,
}

/// Immutable acknowledgment of a committed batch, including exact retry result.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountChatRecordReceipt {
    pub batch_digest: [u8; 32],
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub record_count: u32,
    pub imported_count: u32,
}

pub trait AccountChatRecordStreamStorage: Send + Sync {
    /// Independent of catalog counters and message chronology. Only the current
    /// exact attestation retries its sequence; a changed attestation advances it.
    fn reserve_account_chat_record_sequence(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        event_id: &[u8; 32],
        attestation_digest: &[u8; 32],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<u64>;
    /// Retain exact canonical bytes before publication. Terminal identities count
    /// toward lifetime limits; already acknowledged batches cannot be reopened.
    fn stage_account_chat_record_batch(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        batch: &AccountChatRecordBatch,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()>;
    /// Digest cursor is for bounded outbox fairness, never chronological coverage.
    fn pending_account_chat_record_batches(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        after: Option<&[u8; 32]>,
        limit: usize,
    ) -> StorageResult<Vec<AccountChatRecordBatch>>;
    /// Caller must freshly authenticate the actual peer receipt. Matching metadata
    /// atomically clears encoded bytes while retaining the immutable acknowledgment.
    fn acknowledge_account_chat_record_batch(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        receipt: &AccountChatRecordReceipt,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()>;
    /// Read only an exact authenticated peer-generation acknowledgment. Absence
    /// is not permission to replay: the caller must freshly encode current source
    /// records and own a current channel. No payload or original owner is restored.
    fn account_chat_record_generation_receipt(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        batch_digest: &[u8; 32],
        peer_generation: u64,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<Option<AccountChatRecordReceipt>> {
        let _ = (
            policy_id,
            group,
            batch_digest,
            peer_generation,
            validate_original,
        );
        Err(crate::storage::StorageError::Serialization(
            "paired record generation receipts unavailable".into(),
        ))
    }
    /// Atomically keep the immutable global receipt and retain acknowledgment
    /// for the peer generation authenticated by the caller's original channel.
    /// Original before/tail validation is mandatory; terminal payload stays erased.
    fn acknowledge_account_chat_record_batch_for_generation(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        receipt: &AccountChatRecordReceipt,
        peer_generation: u64,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        let _ = (
            policy_id,
            group,
            receipt,
            peer_generation,
            validate_original,
        );
        Err(crate::storage::StorageError::Serialization(
            "paired record generation receipts unavailable".into(),
        ))
    }
    /// Permanent negative retirement, distinct from acknowledgment. Clear retained
    /// bytes on source deletion/expiry/revocation; the same batch cannot reopen.
    /// The exact configured owner may retire a revoked policy's pending outbox.
    fn deny_account_chat_record_batch(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        batch_digest: &[u8; 32],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()>;
    /// Logical apply, immutable receipt and maximum observed stream sequence share
    /// one SQL transaction. Earlier batches still apply using per-event fences.
    fn apply_account_chat_record_batch(
        &self,
        scope: &MirroredChatScope,
        group: &GroupId,
        batch: &AccountChatRecordBatch,
        now: u64,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<AccountChatRecordReceipt>;
}
