//! Experimental purpose-owned public metadata. No verifier secrets or grants.
use crate::storage::StorageResult;
use serde::{Deserialize, Serialize};

/// Checked local reservation, established before an exact package exists.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurposeAttemptScope {
    pub account: [u8; 32],
    pub local_device: [u8; 32],
    pub generation: u64,
}

/// Frozen only after the canonical context includes the exact package.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurposeContextBinding {
    pub nonce: [u8; 32],
    pub context_digest: [u8; 32],
}

/// One bounded public record; private material remains in OpenMLS storage.
/// Consumed is a storage fact and never grants enrollment or history access.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurposeKeyPackage {
    pub scope: PurposeAttemptScope,
    pub public_bytes: Vec<u8>,
    pub reference: Vec<u8>,
    pub signature_public_key: Vec<u8>,
    pub context: Option<PurposeContextBinding>,
    pub consumed: bool,
}

/// Optional backend capability. Every mutation participates in the same atomic
/// transaction as the private MLS bundle. Unsupported/nontransactional backends
/// must not expose this capability. Implementations check the current durable
/// reservation scope; these methods persist facts, never verifier permissions.
pub trait PurposeKeyPackageStorage: Send + Sync {
    fn check_purpose_reservation(&self, scope: &PurposeAttemptScope) -> StorageResult<()>;
    fn purpose_key_package(&self) -> StorageResult<Option<PurposeKeyPackage>>;
    fn put_purpose_key_package(&self, package: &PurposeKeyPackage) -> StorageResult<()>;
    fn bind_purpose_context(
        &self,
        scope: &PurposeAttemptScope,
        binding: &PurposeContextBinding,
    ) -> StorageResult<()>;
    /// Exact frozen binding and verified fact fence; still not a live permit.
    fn check_purpose_join(&self, scope: &PurposeAttemptScope) -> StorageResult<()>;
    /// Recheck current scope/frozen binding after tentative consumption writes.
    fn check_purpose_commit(&self, scope: &PurposeAttemptScope) -> StorageResult<()>;
    fn consume_purpose_key_package(&self, scope: &PurposeAttemptScope) -> StorageResult<()>;
    /// Only terminal attempts may retire; the engine deletes the exact private
    /// bundle within this same transaction before clearing its public record.
    fn retire_purpose_key_package(&self, scope: &PurposeAttemptScope) -> StorageResult<()>;
}

/// Privacy-safe trusted-owner policy denial, not an SDK error or account id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LinkingWelcomeDenied {
    #[error("no live linking verifier")]
    NoLiveVerifier,
    #[error("linking verification expired")]
    Expired,
    #[error("linking verification cancelled")]
    Cancelled,
    #[error("linking Welcome context does not match")]
    ContextMismatch,
    #[error("linking ownership capability unavailable")]
    UnsupportedStorage,
}
