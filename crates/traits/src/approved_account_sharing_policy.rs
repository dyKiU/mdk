//! Durable explicit pairing approval metadata, never a restored live grant.
use crate::{
    GroupId,
    storage::{StorageError, StorageResult},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ACCOUNT_SHARING_POLICY_VERSION: u16 = 1;
pub const ACCOUNT_SHARING_CAPABILITIES: u8 = 0x0f;
pub const MAX_ACCOUNT_SHARING_POLICIES: usize = 128;
pub const MAX_ACCOUNT_SHARING_JOURNAL_GROUPS: usize = 8192;

/// Immutable approval context. Reading it only schedules fresh Core validation.
/// The epoch is a negative revocation watermark, never enrollment evidence.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedAccountSharingPolicy {
    pub account: [u8; 32],
    pub local_device: [u8; 32],
    pub peer_device: [u8; 32],
    pub protected_group: GroupId,
    pub approval_id: [u8; 32],
    pub version: u16,
    pub capabilities: u8,
    pub created_at: u64,
    pub approved_protected_epoch: u64,
    pub revoked: bool,
}

/// Stable symmetric identity, independent of channel keys, nonces, deadlines,
/// local timestamps and roster generations. All identities remain opaque bytes.
pub fn approved_account_sharing_identity(
    account: &[u8; 32],
    protected_group: &GroupId,
    first: &[u8; 32],
    second: &[u8; 32],
    approval_id: &[u8; 32],
) -> StorageResult<[u8; 32]> {
    if [account, first, second, approval_id]
        .iter()
        .any(|id| **id == [0; 32])
        || first == second
        || !(1..=255).contains(&protected_group.as_slice().len())
    {
        return Err(StorageError::Serialization(
            "invalid account sharing policy".into(),
        ));
    }
    let mut hash = Sha256::new();
    hash.update(b"WN-approved-account-chat-sharing-v1");
    hash.update(account);
    hash.update((protected_group.as_slice().len() as u16).to_be_bytes());
    hash.update(protected_group.as_slice());
    let (low, high) = if first < second {
        (first, second)
    } else {
        (second, first)
    };
    hash.update(low);
    hash.update(high);
    hash.update(approval_id);
    hash.update(ACCOUNT_SHARING_POLICY_VERSION.to_be_bytes());
    hash.update([ACCOUNT_SHARING_CAPABILITIES]);
    Ok(hash.finalize().into())
}

pub trait ApprovedAccountSharingPolicyStorage: Send + Sync {
    /// Only an original explicit approval owner may insert this immutable fact.
    fn put_approved_account_sharing_policy(
        &self,
        policy: &ApprovedAccountSharingPolicy,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()>;
    /// Retained facts (including revoked) cannot restore original action ownership.
    fn approved_account_sharing_policies(&self)
    -> StorageResult<Vec<ApprovedAccountSharingPolicy>>;
    /// Permanent negative state. An old approval cannot be reactivated or deleted.
    fn revoke_account_sharing_policy(
        &self,
        policy_id: &[u8; 32],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()>;
    /// Reserve one local-source sequence atomically. The current exact body retries
    /// its sequence; an earlier body after a change receives a new sequence.
    fn reserve_account_chat_sequence(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        digest: &[u8; 32],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<u64>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stable_policy_identity_is_symmetric_and_context_bound() {
        let g = GroupId::new(vec![5; 16]);
        let id =
            approved_account_sharing_identity(&[1; 32], &g, &[2; 32], &[3; 32], &[4; 32]).unwrap();
        assert_eq!(
            id,
            approved_account_sharing_identity(&[1; 32], &g, &[3; 32], &[2; 32], &[4; 32]).unwrap()
        );
        assert_ne!(
            id,
            approved_account_sharing_identity(&[9; 32], &g, &[2; 32], &[3; 32], &[4; 32]).unwrap()
        );
        assert_ne!(
            id,
            approved_account_sharing_identity(
                &[1; 32],
                &GroupId::new(vec![5; 17]),
                &[2; 32],
                &[3; 32],
                &[4; 32]
            )
            .unwrap()
        );
        assert_ne!(
            id,
            approved_account_sharing_identity(&[1; 32], &g, &[2; 32], &[8; 32], &[4; 32]).unwrap()
        );
        assert_ne!(
            id,
            approved_account_sharing_identity(&[1; 32], &g, &[2; 32], &[3; 32], &[8; 32]).unwrap()
        );
        assert!(
            approved_account_sharing_identity(&[0; 32], &g, &[2; 32], &[3; 32], &[4; 32]).is_err()
        );
        assert!(
            approved_account_sharing_identity(&[1; 32], &g, &[2; 32], &[2; 32], &[4; 32]).is_err()
        );
        assert!(
            approved_account_sharing_identity(
                &[1; 32],
                &GroupId::new(vec![]),
                &[2; 32],
                &[3; 32],
                &[4; 32]
            )
            .is_err()
        );
        assert!(
            approved_account_sharing_identity(
                &[1; 32],
                &GroupId::new(vec![5; 256]),
                &[2; 32],
                &[3; 32],
                &[4; 32]
            )
            .is_err()
        );
    }
}
