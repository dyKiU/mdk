//! Genuine private Add/Welcome/SQL tests with injected policy, not SDK/NIP59.
use crate::Engine;
use crate::device_group_genesis::tests::{PassthroughPeeler as MockPeeler, current_test_engine};
use crate::linking_welcome_policy::*;
use async_trait::async_trait;
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::device_linking_key_package::{
    PurposeAttemptScope, PurposeContextBinding, PurposeKeyPackage,
};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::PeeledMessage;
use cgka_traits::peeler::{PrivateLinkingWelcomeContext, TransportPeeler};
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::{EncryptedPayload, TransportMessage};
use cgka_traits::types::{GroupId, MemberId};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use storage_sqlite::{DeviceLinkingBinding, DeviceLinkingOutcome, SqliteAccountStorage};
include!("../tests/support/private_linking_receive_fixture.rs");

pub(crate) async fn joined_pair(
    storage: SqliteAccountStorage,
) -> (
    Engine<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
    GroupId,
) {
    let mut recipient = current_test_engine(storage.clone());
    recipient.peeler = Box::new(BatchPeeler);
    let account = recipient.self_id().as_slice().try_into().unwrap();
    let local_device = recipient.identity.signer.public().try_into().unwrap();
    storage
        .app_storage()
        .ensure_account_projection_with_identity(
            "isolated-successor-recipient",
            &hex::encode(account),
        )
        .unwrap();
    let generation = storage
        .app_storage().reserve_device_linking_attempt(&account, &local_device)
        .unwrap();
    let scope = PurposeAttemptScope {
        account,
        local_device,
        generation,
    };
    let package = recipient.resolve_linking_key_package(&scope).await.unwrap();
    let binding = DeviceLinkingBinding {
        generation,
        nonce: [6; 32],
        context_digest: [7; 32],
    };
    storage.app_storage().bind_device_linking_context(&binding).unwrap();
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
        .app_storage().bind_device_linking_flow(&binding, "isolated-successor-receive-policy")
        .unwrap();
    storage
        .app_storage().finish_device_linking_attempt(generation, DeviceLinkingOutcome::PairingVerified)
        .unwrap();
    let purpose = storage
        .device_linking_key_package_storage()
        .unwrap()
        .purpose_key_package()
        .unwrap()
        .unwrap();
    let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let genesis = approver.create_private_device_group_genesis().unwrap();
    crate::private_device_invite::prepare_tests::install(
        &mut approver,
        genesis.scope().selection_generation,
    );
    let mut prepared = approver
        .prepare_private_device_invite(genesis.group_id(), package)
        .await
        .unwrap();
    let fact = approver
        .storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    let b = &fact.raw.binding;
    let context = PrivateLinkingWelcomeContext {
        account: b.approver_scope.account,
        approver: b.approver_scope.local_device,
        recipient: b.recipient,
        approver_generation: b.approver_scope.generation,
        recipient_generation: b.recipient_generation,
        group_id: b.group_id.clone(),
        nonce: b.nonce,
        context_digest: b.context_digest,
        key_package_reference: b.key_package_reference,
        key_package_digest: b.key_package_digest,
        commit_digest: b.commit_digest,
        welcome_digest: b.welcome_digest,
    };
    recipient.install_trusted_linking_welcome_policy(Arc::new(IncomingPolicy {
        purpose,
        context: context.clone(),
        predecessor: b.predecessor.clone(),
        successor: b.successor.clone(),
        live: Arc::new(AtomicBool::new(true)),
        consumed: Arc::new(AtomicUsize::new(0)),
        expire_after_predecessor: false,
    }));
    let group = recipient
        .join_private_linking_welcome_batch(
            fact.transport.as_ref().unwrap().welcomes.clone(),
            &context,
        )
        .await
        .unwrap();
    assert!(
        storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap()
            .consumed
    );
    approver
        .dispatch_prepared_private_device_invite(
            &mut prepared,
            &crate::private_device_invite::prepare_tests::Publisher(AtomicUsize::new(0)),
        )
        .await
        .unwrap();
    let confirmed = approver
        .ingest(fact.transport.as_ref().unwrap().commit.clone())
        .await
        .unwrap();
    assert!(matches!(confirmed, cgka_traits::IngestOutcome::Processed));
    assert!(
        approver
            .validated_private_successor(&group)
            .unwrap()
            .is_some()
    );
    (approver, recipient, group)
}
async fn joined_recipient(
    storage: SqliteAccountStorage,
) -> (Engine<SqliteAccountStorage>, GroupId) {
    let (_, recipient, group) = joined_pair(storage).await;
    (recipient, group)
}

#[tokio::test]
async fn private_successor_recipient_validates_real_acceptance_and_refuses_permanent_denial() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let (recipient, group) = joined_recipient(storage.clone()).await;
    let validated = recipient
        .validated_private_successor(&group)
        .unwrap()
        .expect("actual accepted private successor");
    assert!(
        validated.candidate()
            == &recipient
                .candidate_device_group_snapshot(&group)
                .unwrap()
                .unwrap()
    );
    let store = storage.accepted_device_group_anchor_storage().unwrap();
    let fact = store.accepted_anchor().unwrap().unwrap();
    store.deny_accepted_anchor(&fact.scope, &group).unwrap();
    assert!(
        recipient
            .validated_private_successor(&group)
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
async fn private_successor_recipient_reopen_validates_membership_without_restoring_join_consent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-successor.db");
    let key = storage_sqlite::SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (recipient, group) = joined_recipient(storage.clone()).await;
    let prior = recipient
        .candidate_device_group_snapshot(&group)
        .unwrap()
        .unwrap();
    assert!(
        recipient
            .validated_private_successor(&group)
            .unwrap()
            .is_some()
    );
    drop(recipient);
    drop(storage);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut reopened = current_test_engine(storage.clone());
    reopened.hydrate_all_stored_groups().unwrap();
    assert!(
        reopened.linking_welcome_policy.is_none(),
        "reopen must not restore injected consent"
    );
    assert!(
        reopened
            .validated_private_successor(&group)
            .unwrap()
            .unwrap()
            .candidate()
            == &prior
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
}
#[tokio::test]
async fn private_successor_ordinary_candidate_and_unconfirmed_birth_are_not_protected_successors() {
    let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let mut peer = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = peer.fresh_key_package().await.unwrap();
    let (group, _) = approver
        .create_group(CreateGroupRequest {
            name: "isolated-ordinary-candidate".into(),
            description: String::new(),
            members: vec![package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    assert!(
        approver
            .candidate_device_group_snapshot(&group)
            .unwrap()
            .is_some()
    );
    assert!(
        approver
            .validated_private_successor(&group)
            .unwrap()
            .is_none()
    );
    let genesis = approver.create_private_device_group_genesis().unwrap();
    assert!(
        approver
            .candidate_device_group_snapshot(genesis.group_id())
            .unwrap()
            .is_some()
    );
    assert!(
        approver
            .validated_private_successor(genesis.group_id())
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn private_roster_settlement_requires_exact_confirmations_on_both_real_successors() {
    let (mut initiator, mut responder, group) =
        joined_pair(SqliteAccountStorage::in_memory().unwrap()).await;
    assert!(
        initiator
            .validated_private_successor(&group)
            .unwrap()
            .is_some()
    );
    assert!(
        responder
            .validated_private_successor(&group)
            .unwrap()
            .is_some()
    );
    assert!(
        initiator
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_none()
    );
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_none()
    );
    responder
        .select_private_roster_settlement(&group)
        .expect("genuine accepted successor must select an anchored confirmation round");
    let SendResult::ApplicationMessage { msg: challenge, .. } = initiator
        .start_private_roster_settlement(&group)
        .await
        .expect("genuine confirmed coordinator must prepare an encrypted confirmation challenge")
    else {
        panic!("expected actual encrypted private challenge");
    };
    responder.ingest(challenge).await.unwrap();
    assert!(
        initiator
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_none()
    );
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_none()
    );
    let SendResult::ApplicationMessage { msg: ack, .. } =
        responder.prepare_private_roster_ack(&group).await.unwrap()
    else {
        panic!("expected actual encrypted private confirmation");
    };
    // Local completion means this copy observed every occupied leaf, not that
    // the peer received its publication or common knowledge of completion.
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
    assert!(
        initiator
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_none()
    );
    initiator.ingest(ack.clone()).await.unwrap();
    let left = initiator
        .validated_settled_device_roster(&group)
        .unwrap()
        .unwrap();
    let right = responder
        .validated_settled_device_roster(&group)
        .unwrap()
        .unwrap();
    assert!(left.candidate() == right.candidate());
    assert_eq!(left.candidate().leaves.len(), 2);
    assert_eq!(left.candidate().epoch.0, 1);
    initiator.ingest(ack).await.unwrap();
    assert!(
        initiator
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
}

struct FailSettlementWrapPeeler;
#[async_trait]
impl TransportPeeler for FailSettlementWrapPeeler {
    async fn peel_group_message(
        &self,
        message: &TransportMessage,
        context: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        MockPeeler.peel_group_message(message, context).await
    }
    async fn peel_welcome(&self, message: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        MockPeeler.peel_welcome(message).await
    }
    async fn wrap_group_message(
        &self,
        _: &EncryptedPayload,
        _: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::WrapFailed(
            "isolated settlement wrap fault".into(),
        ))
    }
    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        MockPeeler.wrap_welcome(payload, recipient).await
    }
}

#[tokio::test]
async fn private_roster_settlement_wrap_retry_retains_actual_cipher_and_live_round() {
    let (mut initiator, mut responder, group) =
        joined_pair(SqliteAccountStorage::in_memory().unwrap()).await;
    responder.select_private_roster_settlement(&group).unwrap();
    initiator.peeler = Box::new(FailSettlementWrapPeeler);
    assert!(matches!(
        initiator.start_private_roster_settlement(&group).await,
        Err(cgka_traits::EngineError::Peeler(PeelerError::WrapFailed(_)))
    ));
    let admission = initiator.settlement_admission_for(&group).unwrap().unwrap();
    let store = initiator
        .storage
        .private_roster_settlement_storage()
        .unwrap();
    let before = store.read_round().unwrap().unwrap();
    let cipher = before
        .prepared_ciphertext
        .clone()
        .expect("actual MLS ciphertext survives wrapping failure");
    assert!(before.outbound.is_none());
    assert_eq!(store.read_facts().unwrap().len(), 1);
    assert!(
        initiator
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_none()
    );
    initiator.peeler = Box::new(MockPeeler);
    let SendResult::ApplicationMessage { msg: challenge, .. } = initiator
        .start_private_roster_settlement(&group)
        .await
        .unwrap()
    else {
        panic!("expected retry of actual private challenge");
    };
    let after = initiator
        .storage
        .private_roster_settlement_storage()
        .unwrap()
        .read_round()
        .unwrap()
        .unwrap();
    assert_eq!(after.generation, before.generation);
    assert_eq!(
        after.prepared_ciphertext.as_deref(),
        Some(cipher.as_slice())
    );
    assert!(
        Arc::ptr_eq(
            &admission,
            &initiator.settlement_admission_for(&group).unwrap().unwrap()
        ),
        "wrapping retry must not replace or extend the original live round"
    );
    responder.ingest(challenge).await.unwrap();
    let SendResult::ApplicationMessage { msg: ack, .. } =
        responder.prepare_private_roster_ack(&group).await.unwrap()
    else {
        panic!("expected actual responder confirmation");
    };
    initiator.ingest(ack).await.unwrap();
    assert!(
        initiator
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn private_roster_settlement_unsolicited_challenge_is_hidden_without_selection() {
    let (mut initiator, mut responder, group) =
        joined_pair(SqliteAccountStorage::in_memory().unwrap()).await;
    responder.drain_events();
    let SendResult::ApplicationMessage { msg: challenge, .. } = initiator
        .start_private_roster_settlement(&group)
        .await
        .unwrap()
    else {
        panic!("expected actual private challenge");
    };
    responder.ingest(challenge).await.unwrap();
    assert!(responder.prepare_private_roster_ack(&group).await.is_err());
    assert!(
        responder
            .storage
            .private_roster_settlement_storage()
            .unwrap()
            .read_round()
            .unwrap()
            .is_none()
    );
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_none()
    );
    assert!(!responder.drain_events().iter().any(|event| matches!(
        event,
        cgka_traits::engine::GroupEvent::MessageReceived { .. }
    )));
}

#[tokio::test]
async fn private_roster_settlement_cancelled_recipient_cannot_accept_or_publish_confirmation() {
    let (mut initiator, mut responder, group) =
        joined_pair(SqliteAccountStorage::in_memory().unwrap()).await;
    responder.select_private_roster_settlement(&group).unwrap();
    responder.cancel_private_roster_settlement(&group).unwrap();
    let SendResult::ApplicationMessage { msg: challenge, .. } = initiator
        .start_private_roster_settlement(&group)
        .await
        .unwrap()
    else {
        panic!("expected actual private challenge");
    };
    responder.drain_events();
    responder.ingest(challenge).await.unwrap();
    assert!(responder.prepare_private_roster_ack(&group).await.is_err());
    let store = responder
        .storage
        .private_roster_settlement_storage()
        .unwrap();
    assert!(matches!(
        store.read_round().unwrap().unwrap().phase,
        cgka_traits::private_roster_settlement::PrivateSettlementPhase::Denied
    ));
    assert!(store.read_facts().unwrap().is_empty());
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_none()
    );
    assert!(!responder.drain_events().iter().any(|event| matches!(
        event,
        cgka_traits::engine::GroupEvent::MessageReceived { .. }
    )));
}
