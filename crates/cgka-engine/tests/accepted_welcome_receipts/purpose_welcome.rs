//! Purpose-owned generic Welcomes must never derive permission from SQL facts.
use super::*;
use cgka_traits::device_linking_key_package::{PurposeAttemptScope, PurposeContextBinding};
use cgka_traits::storage::{MessageStorage, StorageProvider};

#[tokio::test]
async fn purpose_welcome_without_live_verifier_gate_is_denied_before_consumption() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut recipient = client(storage.clone());
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let account: [u8; 32] = pad32(ACCOUNT).try_into().unwrap();
    storage
        .app_storage().ensure_account_projection_with_identity(
            "isolated-purpose-join-test",
            &hex::encode(account),
        )
        .unwrap();
    let public = recipient.fresh_key_package().await.unwrap();
    let device: [u8; 32] = hex::decode(
        key_package_metadata(&public)
            .unwrap()
            .signature_public_key_hex,
    )
    .unwrap()
    .try_into()
    .unwrap();
    let generation = storage
        .reserve_device_linking_attempt(&account, &device)
        .unwrap();
    let scope = PurposeAttemptScope {
        account,
        local_device: device,
        generation,
    };
    let kp = recipient.resolve_linking_key_package(&scope).await.unwrap();
    let binding = storage_sqlite::DeviceLinkingBinding {
        generation,
        nonce: [21; 32],
        context_digest: [22; 32],
    };
    storage.bind_device_linking_context(&binding).unwrap();
    storage
        .device_linking_key_package_storage()
        .unwrap()
        .bind_purpose_context(
            &scope,
            &PurposeContextBinding {
                nonce: binding.nonce,
                context_digest: binding.context_digest,
            },
        )
        .unwrap();
    storage
        .bind_device_linking_flow(&binding, "isolated-verified-flow")
        .unwrap();
    storage
        .finish_device_linking_attempt(
            generation,
            storage_sqlite::DeviceLinkingOutcome::PairingVerified,
        )
        .unwrap();
    let (group, welcome) = invite(&mut approver, kp.clone()).await;
    assert!(
        recipient.join_welcome(welcome.clone()).await.is_err(),
        "durable verified facts must never authorize this generic join"
    );
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&kp)
    );
    assert!(recipient.epoch(&group).is_err());
    assert!(
        recipient
            .accepted_welcome_receipt(&welcome.id)
            .unwrap()
            .is_none()
    );
    assert!(
        !storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap()
            .consumed
    );
}

// Trusted injection fixture only: it tests the engine transaction boundary,
// not SAS verification. The production policy remains absent until the real
// private SDK result and its original owner deadline are connected.
use cgka_engine::linking_welcome_policy::{
    AuthenticatedLinkingWelcome, LinkingWelcomeDenied, LinkingWelcomeLease, LinkingWelcomePolicy,
};
use cgka_traits::accepted_welcome::AcceptedWelcomeReceipt;
use cgka_traits::device_linking_key_package::PurposeKeyPackage;
use std::sync::{Arc, Mutex};
#[derive(Clone)]
struct PolicyFixture {
    expected: PurposeKeyPackage,
    group: cgka_traits::types::GroupId,
    approver: Vec<u8>,
    state: Arc<Mutex<FixtureState>>,
    expire_after_authenticated: bool,
}
#[derive(Default)]
struct FixtureState {
    leased: bool,
    consumed: bool,
    expired: bool,
    accepted: usize,
}
struct LeaseFixture {
    policy: Arc<PolicyFixture>,
}
impl LinkingWelcomePolicy for PolicyFixture {
    fn begin_join(
        &self,
        purpose: &PurposeKeyPackage,
    ) -> Result<Box<dyn LinkingWelcomeLease>, LinkingWelcomeDenied> {
        if *purpose != self.expected {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        let mut state = self.state.lock().unwrap();
        if state.expired {
            return Err(LinkingWelcomeDenied::Expired);
        }
        if state.leased || state.consumed {
            return Err(LinkingWelcomeDenied::NoLiveVerifier);
        }
        state.leased = true;
        Ok(Box::new(LeaseFixture {
            policy: Arc::new(self.clone()),
        }))
    }
}
impl LinkingWelcomeLease for LeaseFixture {
    fn check_authenticated(
        &mut self,
        welcome: &AuthenticatedLinkingWelcome,
    ) -> Result<(), LinkingWelcomeDenied> {
        if welcome.group_id != self.policy.group
            || welcome.own_account.as_slice() != self.policy.expected.scope.account
            || welcome.own_signature_public_key != self.policy.expected.scope.local_device
            || welcome.welcomer_account.as_slice() != self.policy.expected.scope.account
            || welcome.welcomer_signature_public_key != self.policy.approver
        {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        if self.policy.expire_after_authenticated {
            self.policy.state.lock().unwrap().expired = true;
        }
        Ok(())
    }
    fn check_live_before_commit(&mut self) -> Result<(), LinkingWelcomeDenied> {
        if self.policy.state.lock().unwrap().expired {
            Err(LinkingWelcomeDenied::Expired)
        } else {
            Ok(())
        }
    }
    fn commit_accepted(self: Box<Self>, receipt: &AcceptedWelcomeReceipt) {
        assert!(receipt.group_id == self.policy.group);
        assert!(receipt.consumed_key_package_ref == self.policy.expected.reference);
        let mut state = self.policy.state.lock().unwrap();
        state.consumed = true;
        state.accepted += 1;
    }
}
impl Drop for LeaseFixture {
    fn drop(&mut self) {
        self.policy.state.lock().unwrap().leased = false;
    }
}
pub(super) async fn verified_package(
    storage: &SqliteAccountStorage,
    recipient: &mut Engine<SqliteAccountStorage>,
) -> (PurposeKeyPackage, cgka_traits::engine::KeyPackage) {
    let account: [u8; 32] = pad32(ACCOUNT).try_into().unwrap();
    storage
        .app_storage().ensure_account_projection_with_identity("isolated-policy-fixture", &hex::encode(account))
        .unwrap();
    let public = recipient.fresh_key_package().await.unwrap();
    let device: [u8; 32] = hex::decode(
        key_package_metadata(&public)
            .unwrap()
            .signature_public_key_hex,
    )
    .unwrap()
    .try_into()
    .unwrap();
    let generation = storage
        .reserve_device_linking_attempt(&account, &device)
        .unwrap();
    let scope = PurposeAttemptScope {
        account,
        local_device: device,
        generation,
    };
    let package = recipient.resolve_linking_key_package(&scope).await.unwrap();
    let binding = storage_sqlite::DeviceLinkingBinding {
        generation,
        nonce: [31; 32],
        context_digest: [32; 32],
    };
    storage.bind_device_linking_context(&binding).unwrap();
    storage
        .device_linking_key_package_storage()
        .unwrap()
        .bind_purpose_context(
            &scope,
            &PurposeContextBinding {
                nonce: binding.nonce,
                context_digest: binding.context_digest,
            },
        )
        .unwrap();
    storage
        .bind_device_linking_flow(&binding, "policy-fixture-flow")
        .unwrap();
    storage
        .finish_device_linking_attempt(
            generation,
            storage_sqlite::DeviceLinkingOutcome::PairingVerified,
        )
        .unwrap();
    (
        storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap(),
        package,
    )
}
fn policy(
    expected: PurposeKeyPackage,
    group: cgka_traits::types::GroupId,
    approver: Vec<u8>,
    expire_after_authenticated: bool,
) -> Arc<PolicyFixture> {
    Arc::new(PolicyFixture {
        expected,
        group,
        approver,
        state: Arc::new(Mutex::new(FixtureState::default())),
        expire_after_authenticated,
    })
}
#[tokio::test]
async fn purpose_welcome_authenticated_context_mismatch_rolls_back_then_exact_retry_consumes_once()
{
    for mismatch in 0..3 {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let mut recipient = client(storage.clone());
        let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
        let approver_key = hex::decode(
            key_package_metadata(&approver.fresh_key_package().await.unwrap())
                .unwrap()
                .signature_public_key_hex,
        )
        .unwrap();
        let (expected, kp) = verified_package(&storage, &mut recipient).await;
        let (group, welcome) = invite(&mut approver, kp.clone()).await;
        let correct = policy(expected.clone(), group.clone(), approver_key.clone(), false);
        let mut wrong = expected.clone();
        let mut wrong_group = group.clone();
        let mut wrong_approver = approver_key;
        match mismatch {
            0 => wrong_group = cgka_traits::types::GroupId::new(vec![77; 19]),
            1 => wrong_approver[0] ^= 1,
            _ => wrong.scope.local_device[0] ^= 1,
        }
        let denied = policy(wrong, wrong_group, wrong_approver, false);
        recipient.install_trusted_linking_welcome_policy(denied.clone());
        assert!(matches!(
            recipient.join_welcome(welcome.clone()).await,
            Err(cgka_traits::EngineError::LinkingWelcomeDenied(
                LinkingWelcomeDenied::ContextMismatch
            ))
        ));
        assert!(
            recipient
                .durably_owned_key_packages()
                .unwrap()
                .contains(&kp)
        );
        assert!(recipient.epoch(&group).is_err());
        assert!(
            recipient
                .accepted_welcome_receipt(&welcome.id)
                .unwrap()
                .is_none()
        );
        assert!(
            !storage
                .device_linking_key_package_storage()
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .unwrap()
                .consumed
        );
        assert_eq!(denied.state.lock().unwrap().accepted, 0);
        recipient.install_trusted_linking_welcome_policy(correct.clone());
        recipient.join_welcome(welcome.clone()).await.unwrap();
        assert!(
            !recipient
                .durably_owned_key_packages()
                .unwrap()
                .contains(&kp)
        );
        assert!(
            storage
                .device_linking_key_package_storage()
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .unwrap()
                .consumed
        );
        assert_eq!(correct.state.lock().unwrap().accepted, 1);
        assert!(correct.state.lock().unwrap().consumed);
        assert!(recipient.join_welcome(welcome).await.is_err());
        assert_eq!(correct.state.lock().unwrap().accepted, 1);
    }
}
#[tokio::test]
async fn purpose_welcome_final_expiry_check_rolls_back_all_tentative_writes() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut recipient = client(storage.clone());
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let approver_key = hex::decode(
        key_package_metadata(&approver.fresh_key_package().await.unwrap())
            .unwrap()
            .signature_public_key_hex,
    )
    .unwrap();
    let (expected, kp) = verified_package(&storage, &mut recipient).await;
    let (group, welcome) = invite(&mut approver, kp.clone()).await;
    let expired = policy(expected.clone(), group.clone(), approver_key, true);
    recipient.install_trusted_linking_welcome_policy(expired.clone());
    assert!(matches!(
        recipient.join_welcome(welcome.clone()).await,
        Err(cgka_traits::EngineError::LinkingWelcomeDenied(
            LinkingWelcomeDenied::Expired
        ))
    ));
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&kp)
    );
    assert!(recipient.epoch(&group).is_err());
    assert!(
        recipient
            .accepted_welcome_receipt(&welcome.id)
            .unwrap()
            .is_none()
    );
    assert!(
        storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap()
            == expected
    );
    let state = expired.state.lock().unwrap();
    assert!(!state.consumed);
    assert!(!state.leased);
    assert_eq!(state.accepted, 0);
}

#[tokio::test]
async fn purpose_welcome_ingest_exclusion_does_not_poison_exact_later_retry() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut recipient = client(storage.clone());
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let approver_key = hex::decode(
        key_package_metadata(&approver.fresh_key_package().await.unwrap())
            .unwrap()
            .signature_public_key_hex,
    )
    .unwrap();
    let (expected, kp) = verified_package(&storage, &mut recipient).await;
    let (group, welcome) = invite(&mut approver, kp.clone()).await;
    assert!(
        matches!(
            recipient.ingest(welcome.clone()).await,
            Ok(cgka_traits::ingest::IngestOutcome::Ignored {
                category: cgka_traits::ingest::InputRejectionCategory::AuthorizationFailed
            })
        ),
        "a classifiable purpose policy exclusion must not abort generic inbox draining"
    );
    assert!(!storage.has_ingress_dedup_marker(&welcome.id).unwrap());
    assert!(recipient.last_ingest_left_object_unpersisted());
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&kp)
    );
    let correct = policy(expected, group, approver_key, false);
    recipient.install_trusted_linking_welcome_policy(correct.clone());
    assert!(matches!(
        recipient.ingest(welcome).await.unwrap(),
        cgka_traits::ingest::IngestOutcome::Processed
    ));
    assert_eq!(correct.state.lock().unwrap().accepted, 1);
}

#[path = "joined_tree_welcome.rs"]
mod joined_tree_welcome;
