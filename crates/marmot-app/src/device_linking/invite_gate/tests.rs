//! Genuine SDK consent bound to actual private MLS input; synthetic storage only.
use super::*;
use crate::device_linking::runtime_gate::tests::verified_for_context;
use crate::device_linking::{LinkingContext, PredecessorRoster};
use crate::external_signer::AccountSigner;
use cgka_engine::key_package::key_package_metadata;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::ingest::PeeledMessage;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::{EncryptedPayload, GroupContextSnapshot, MemberId, TransportMessage};
use std::sync::Arc;
use storage_sqlite::SqliteAccountStorage;

struct SyntheticPreparationPeeler;
#[async_trait::async_trait]
impl TransportPeeler for SyntheticPreparationPeeler {
    async fn peel_group_message(
        &self,
        _: &TransportMessage,
        _: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Err(PeelerError::InvalidSignature)
    }
    async fn peel_welcome(&self, _: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Err(PeelerError::InvalidSignature)
    }
    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        context: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(synthetic_transport(
            payload,
            cgka_traits::TransportEnvelope::GroupMessage {
                transport_group_id: context.transport_group_id().unwrap_or_default().to_vec(),
            },
        ))
    }
    async fn wrap_private_linking_welcome(
        &self,
        payload: &EncryptedPayload,
        context: &cgka_traits::peeler::PrivateLinkingWelcomeContext,
    ) -> Result<Vec<TransportMessage>, PeelerError> {
        Ok(vec![
            self.wrap_welcome(payload, &MemberId::new(context.account.to_vec()))
                .await?,
        ])
    }
    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(synthetic_transport(
            payload,
            cgka_traits::TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        ))
    }
}
fn synthetic_transport(
    payload: &EncryptedPayload,
    envelope: cgka_traits::TransportEnvelope,
) -> TransportMessage {
    use sha2::{Digest, Sha256};
    TransportMessage {
        id: cgka_traits::MessageId::new(Sha256::digest(&payload.ciphertext).to_vec()),
        payload: payload.ciphertext.clone(),
        timestamp: cgka_traits::Timestamp(1),
        causal_deps: vec![],
        source: cgka_traits::TransportSource("isolated-private-invite-test".into()),
        envelope,
    }
}
fn engine(
    storage: SqliteAccountStorage,
    keys: &nostr::prelude::Keys,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .supported_app_components(
            cgka_traits::app_components::default_group_components()
                .into_iter()
                .chain([cgka_traits::app_components::NOSTR_ROUTING_COMPONENT_ID]),
        )
        .identity(keys.public_key().to_bytes().to_vec())
        .account_identity_proof_signer(AccountSigner::Local(keys.clone()).as_proof_signer())
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(SyntheticPreparationPeeler))
        .build()
        .unwrap()
}
async fn fixture() -> (
    VerifiedPairing,
    PrivateDeviceGroupGenesisEvidence,
    AuthenticatedPrivateInvite,
) {
    let (token, origin, input, _) = fixture_with_storage().await;
    (token, origin, input)
}
async fn fixture_with_storage() -> (
    VerifiedPairing,
    PrivateDeviceGroupGenesisEvidence,
    AuthenticatedPrivateInvite,
    Arc<SqliteAccountStorage>,
) {
    let (token, origin, input, storage, _) = fixture_with_engine().await;
    (token, origin, input, storage)
}
async fn fixture_with_engine() -> (
    VerifiedPairing,
    PrivateDeviceGroupGenesisEvidence,
    AuthenticatedPrivateInvite,
    Arc<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
) {
    let (token, origin, input, storage, engine, _) = fixture_with_engine_kind(false).await;
    (token, origin, input, storage, engine)
}
async fn fixture_with_engine_kind(
    real_nostr: bool,
) -> (
    VerifiedPairing,
    PrivateDeviceGroupGenesisEvidence,
    AuthenticatedPrivateInvite,
    Arc<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
    nostr::prelude::Keys,
) {
    fixture_with_engine_storage(real_nostr, SqliteAccountStorage::in_memory().unwrap()).await
}
async fn fixture_with_engine_storage(
    real_nostr: bool,
    approver_storage: SqliteAccountStorage,
) -> (
    VerifiedPairing,
    PrivateDeviceGroupGenesisEvidence,
    AuthenticatedPrivateInvite,
    Arc<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
    nostr::prelude::Keys,
) {
    let keys = nostr::prelude::Keys::generate();
    let account = keys.public_key().to_bytes();
    let new_store = Arc::new(SqliteAccountStorage::in_memory().unwrap());
    let old_store = Arc::new(approver_storage);
    for store in [&new_store, &old_store] {
        store
            .ensure_account_projection_with_identity(
                "isolated-invite-policy",
                &hex::encode(account),
            )
            .unwrap();
    }
    let mut approver = if real_nostr {
        EngineBuilder::new((*old_store).clone())
            .supported_app_components(
                cgka_traits::app_components::default_group_components()
                    .into_iter()
                    .chain([cgka_traits::app_components::NOSTR_ROUTING_COMPONENT_ID]),
            )
            .identity(keys.public_key().to_bytes().to_vec())
            .account_identity_proof_signer(AccountSigner::Local(keys.clone()).as_proof_signer())
            .protocol_profile(ProtocolProfile::Current)
            .peeler(Box::new(
                transport_nostr_peeler::NostrMlsPeeler::new().with_welcome_signer(keys.clone()),
            ))
            .build()
            .unwrap()
    } else {
        engine((*old_store).clone(), &keys)
    };
    let origin = if real_nostr {
        use cgka_traits::app_components::{
            AppComponentData, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, encode_nostr_routing_v1,
        };
        let routing = NostrRoutingV1::new([73; 32], vec!["wss://isolated.example".into()]).unwrap();
        approver
            .create_private_device_group_genesis_with_components(vec![AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: encode_nostr_routing_v1(&routing).unwrap(),
            }])
            .unwrap()
    } else {
        approver.create_private_device_group_genesis().unwrap()
    };
    let mut recipient = engine((*new_store).clone(), &keys);
    let kp = recipient.fresh_linking_key_package().await.unwrap();
    let metadata = key_package_metadata(&kp).unwrap();
    let input = approver
        .validate_private_invite_input(origin.group_id(), &kp)
        .unwrap();
    let context = LinkingContext {
        version: 1,
        nonce: [59; 32],
        new_device_generation: 1,
        approver_generation: 1,
        account,
        exact_key_package: kp.bytes().to_vec(),
        key_package_reference: hex::decode(metadata.key_package_ref_hex)
            .unwrap()
            .try_into()
            .unwrap(),
        device_group: origin.group_id().as_slice().to_vec(),
        predecessor: PredecessorRoster::from_candidate(origin.current()).unwrap(),
        approver: origin.scope().local_device,
        recipient: hex::decode(metadata.signature_public_key_hex)
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let (_, token) = verified_for_context(context, new_store, old_store.clone()).await;
    (token, origin, input, old_store, approver, keys)
}
#[tokio::test]
async fn invite_gate_genuine_approver_sdk_result_authorizes_exact_actual_input() {
    let (token, origin, input) = fixture().await;
    let gate = RuntimeInviteGate::new();
    assert!(matches!(
        gate.begin_prepare(&input),
        Err(LinkingWelcomeDenied::NoLiveVerifier)
    ));
    gate.arm_genesis(token, &origin).unwrap();
    let lease = gate
        .begin_prepare(&input)
        .expect("genuine Approver verification must authorize exact private input");
    assert!(
        lease.consent().approver_scope.account.as_slice() == input.predecessor.account.as_slice()
    );
    assert!(
        lease.consent().origin
            == cgka_traits::private_device_invite::PrivateInviteOrigin::Genesis(
                origin.scope().selection_generation
            )
    );
    drop(lease);
    assert!(gate.begin_prepare(&input).is_ok());
}

#[tokio::test]
async fn invite_gate_substitution_preserves_only_exact_original_retry() {
    let (token, origin, mut input) = fixture().await;
    let gate = RuntimeInviteGate::new();
    gate.arm_genesis(token, &origin).unwrap();
    input.key_package_reference[0] ^= 1;
    assert!(matches!(
        gate.begin_prepare(&input),
        Err(LinkingWelcomeDenied::ContextMismatch)
    ));
    input.key_package_reference[0] ^= 1;
    input.own_leaf_index += 1;
    assert!(matches!(
        gate.begin_prepare(&input),
        Err(LinkingWelcomeDenied::ContextMismatch)
    ));
    input.own_leaf_index -= 1;
    let mut lease = gate.begin_prepare(&input).unwrap();
    assert!(gate.begin_prepare(&input).is_err());
    lease.check_live_before_commit().unwrap();
    drop(lease);
    assert!(gate.begin_prepare(&input).is_ok());
}

struct ManualClock(std::sync::Mutex<std::time::Instant>);
impl Clock for ManualClock {
    fn now(&self) -> std::time::Instant {
        *self.0.lock().unwrap()
    }
}
#[tokio::test]
async fn invite_gate_original_expiry_revokes_held_lease_and_rollback_retry() {
    let (token, origin, input) = fixture().await;
    let deadline = token.owner_deadline.unwrap();
    let clock = Arc::new(ManualClock(std::sync::Mutex::new(
        deadline - std::time::Duration::from_secs(1),
    )));
    let gate = RuntimeInviteGate::with_clock(clock.clone());
    gate.arm_genesis(token, &origin).unwrap();
    let mut lease = gate.begin_prepare(&input).unwrap();
    *clock.0.lock().unwrap() = deadline;
    assert!(matches!(
        lease.check_live_before_commit(),
        Err(LinkingWelcomeDenied::Expired)
    ));
    drop(lease);
    assert!(!gate.maintain().unwrap());
    assert!(matches!(
        gate.begin_prepare(&input),
        Err(LinkingWelcomeDenied::Expired)
    ));
}
#[tokio::test]
async fn invite_gate_committed_preparation_keeps_live_lease_but_drop_consumes_permission() {
    let (token, origin, input) = fixture().await;
    let gate = RuntimeInviteGate::new();
    gate.arm_genesis(token, &origin).unwrap();
    let mut lease = gate.begin_prepare(&input).unwrap();
    lease.preparation_committed(&cgka_traits::private_device_invite::PrivateInviteScope {
        account: origin.scope().account,
        local_device: origin.scope().local_device,
        staging_generation: 1,
    });
    lease.check_live_before_commit().unwrap();
    drop(lease);
    assert!(matches!(
        gate.begin_prepare(&input),
        Err(LinkingWelcomeDenied::NoLiveVerifier)
    ));
    assert!(RuntimeInviteGate::new().begin_prepare(&input).is_err());
}
#[tokio::test]
async fn invite_gate_cancel_and_shutdown_revoke_even_held_leases() {
    for shutdown in [false, true] {
        let (token, origin, input) = fixture().await;
        let gate = RuntimeInviteGate::new();
        gate.arm_genesis(token, &origin).unwrap();
        let mut lease = gate.begin_prepare(&input).unwrap();
        if shutdown {
            gate.shutdown();
        } else {
            gate.cancel();
        }
        assert!(matches!(
            lease.check_live_before_commit(),
            Err(LinkingWelcomeDenied::Cancelled)
        ));
        drop(lease);
        assert!(matches!(
            gate.begin_prepare(&input),
            Err(LinkingWelcomeDenied::Cancelled)
        ));
        assert!(!gate.maintain().unwrap());
    }
}

struct CancelDuringArmClock {
    now: std::time::Instant,
    action: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl Clock for CancelDuringArmClock {
    fn now(&self) -> std::time::Instant {
        let action = self.action.lock().unwrap().take();
        if let Some(action) = action {
            action();
        }
        self.now
    }
}
#[tokio::test]
async fn invite_gate_cancellation_during_arming_cannot_recreate_consent() {
    let (token, origin, input) = fixture().await;
    let clock = Arc::new(CancelDuringArmClock {
        now: std::time::Instant::now(),
        action: std::sync::Mutex::new(None),
    });
    let gate = Arc::new(RuntimeInviteGate::with_clock(clock.clone()));
    let weak = Arc::downgrade(&gate);
    *clock.action.lock().unwrap() = Some(Box::new(move || weak.upgrade().unwrap().cancel()));
    assert!(matches!(
        gate.arm_genesis(token, &origin),
        Err(LinkingWelcomeDenied::Cancelled)
    ));
    assert!(gate.begin_prepare(&input).is_err());
}

#[tokio::test]
async fn invite_gate_account_owner_drop_revokes_held_lease_and_retained_policy() {
    let (token, origin, input, storage) = fixture_with_storage().await;
    let owner = crate::client::device_linking::AccountLinkingOwner::attach(
        storage,
        &input.predecessor.account,
    )
    .unwrap();
    let policy = owner.invite_policy();
    owner.arm_invite_genesis(token, &origin).unwrap();
    let mut lease = policy.begin_prepare(&input).unwrap();
    drop(owner);
    assert!(matches!(
        lease.check_live_before_commit(),
        Err(LinkingWelcomeDenied::Cancelled)
    ));
    drop(lease);
    assert!(matches!(
        policy.begin_prepare(&input),
        Err(LinkingWelcomeDenied::Cancelled)
    ));
}

#[tokio::test]
async fn invite_gate_genuine_sdk_lease_prepares_actual_add_and_cancellation_consumes_it() {
    use cgka_traits::StorageProvider;
    use cgka_traits::private_device_invite::PrivateInvitePhase;
    let (token, origin, input, storage, mut approver) = fixture_with_engine().await;
    let gate = Arc::new(RuntimeInviteGate::new());
    gate.arm_genesis(token, &origin).unwrap();
    approver.install_trusted_private_invite_policy(gate.clone());
    let prepared = approver
        .prepare_private_device_invite(origin.group_id(), input.exact_key_package.clone())
        .await
        .unwrap();
    let cap = storage.private_device_invite_storage().unwrap();
    let fact = cap.private_invite().unwrap().unwrap();
    assert_eq!(fact.phase, PrivateInvitePhase::Wrapped);
    assert!(fact.scope == *prepared.scope());
    assert_eq!(fact.raw.binding.successor.leaves.len(), 2);
    assert!(
        fact.raw
            .binding
            .successor
            .leaves
            .iter()
            .any(|leaf| leaf.signature_public_key == input.recipient_signature_public_key)
    );
    assert!(cap.confirmed_private_invite().unwrap().is_none());
    approver
        .cancel_prepared_private_device_invite(prepared)
        .unwrap();
    assert_eq!(
        cap.private_invite().unwrap().unwrap().phase,
        PrivateInvitePhase::Retired
    );
    assert!(matches!(
        gate.begin_prepare(&input),
        Err(LinkingWelcomeDenied::NoLiveVerifier)
    ));
}

#[tokio::test]
async fn invite_gate_genuine_sdk_prepares_real_private_nostr_welcome_batch() {
    use cgka_traits::StorageProvider;
    let (token, origin, input, storage, mut approver, keys) = fixture_with_engine_kind(true).await;
    let gate = Arc::new(RuntimeInviteGate::new());
    gate.arm_genesis(token, &origin).unwrap();
    approver.install_trusted_private_invite_policy(gate);
    let prepared = approver
        .prepare_private_device_invite(origin.group_id(), input.exact_key_package.clone())
        .await
        .unwrap();
    let fact = storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    let binding = &fact.raw.binding;
    let expected = cgka_traits::peeler::PrivateLinkingWelcomeContext {
        account: binding.approver_scope.account,
        approver: binding.approver_scope.local_device,
        recipient: input.recipient_signature_public_key,
        approver_generation: binding.approver_scope.generation,
        recipient_generation: binding.recipient_generation,
        group_id: origin.group_id().clone(),
        nonce: binding.nonce,
        context_digest: binding.context_digest,
        key_package_reference: input.key_package_reference,
        key_package_digest: binding.key_package_digest,
        commit_digest: binding.commit_digest,
        welcome_digest: binding.welcome_digest,
    };
    let peeler = transport_nostr_peeler::NostrMlsPeeler::new().with_welcome_signer(keys);
    let batch = &fact.transport.as_ref().unwrap().welcomes;
    assert!(!batch.is_empty());
    assert!(
        peeler
            .peel_private_linking_welcome_batch(batch, &expected)
            .await
            .unwrap()
            == fact.raw.welcome
    );
    let mut wrong = expected;
    wrong.recipient[0] ^= 1;
    assert!(
        peeler
            .peel_private_linking_welcome_batch(batch, &wrong)
            .await
            .is_err()
    );
    assert!(
        storage
            .private_device_invite_storage()
            .unwrap()
            .confirmed_private_invite()
            .unwrap()
            .is_none()
    );
    approver
        .cancel_prepared_private_device_invite(prepared)
        .unwrap();
}

#[derive(Default)]
struct CommitRecorder(std::sync::Mutex<Vec<TransportMessage>>);
#[async_trait::async_trait]
impl cgka_engine::private_device_invite::TrustedPrivateInvitePublisher for CommitRecorder {
    async fn publish_commit(
        &self,
        commit: &TransportMessage,
    ) -> Result<(), cgka_traits::EngineError> {
        self.0.lock().unwrap().push(commit.clone());
        Ok(())
    }
}

#[tokio::test]
async fn invite_gate_dispatch_sql_failure_preserves_original_sdk_lease_for_exact_retry() {
    use cgka_engine::private_device_invite::PrivateInviteError;
    use cgka_traits::StorageProvider;
    use cgka_traits::private_device_invite::{PrivateInvitePhase, PrivateInviteStorageError};
    enum AfterFailure {
        Retry,
        Expire,
        Cancel,
        Shutdown,
    }
    for after_failure in [
        AfterFailure::Retry,
        AfterFailure::Expire,
        AfterFailure::Cancel,
        AfterFailure::Shutdown,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("isolated-dispatch-retry.db");
        let key = storage_sqlite::SqlCipherKey::new("8d".repeat(32)).unwrap();
        let (token, origin, input, storage, mut approver, _) = fixture_with_engine_storage(
            true,
            SqliteAccountStorage::open_encrypted(&path, &key).unwrap(),
        )
        .await;
        let deadline = token.owner_deadline.unwrap();
        let clock = Arc::new(ManualClock(
            std::sync::Mutex::new(std::time::Instant::now()),
        ));
        let gate = Arc::new(RuntimeInviteGate::with_clock(clock.clone()));
        gate.arm_genesis(token, &origin).unwrap();
        approver.install_trusted_private_invite_policy(gate.clone());
        let mut prepared = approver
            .prepare_private_device_invite(origin.group_id(), input.exact_key_package.clone())
            .await
            .unwrap();
        let cap = storage.private_device_invite_storage().unwrap();
        let before = cap.private_invite().unwrap().unwrap();
        let injector = rusqlite::Connection::open(&path).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &injector,
            &key,
            storage_sqlite::SqlCipherHardening::default(),
        )
        .unwrap();
        injector.execute_batch("CREATE TRIGGER fail_dispatch BEFORE UPDATE OF phase ON private_device_invite_staging WHEN NEW.phase=2 BEGIN SELECT RAISE(ABORT,'isolated dispatch fault'); END;").unwrap();
        let publisher = CommitRecorder::default();
        assert!(matches!(
            approver
                .dispatch_prepared_private_device_invite(&mut prepared, &publisher)
                .await,
            Err(PrivateInviteError::Storage(
                PrivateInviteStorageError::Storage(_)
            ))
        ));
        let after = cap.private_invite().unwrap().unwrap();
        assert!(
            after.phase == PrivateInvitePhase::Wrapped
                && after.raw == before.raw
                && after.transport == before.transport
        );
        assert!(publisher.0.lock().unwrap().is_empty());
        assert!(
            gate.maintain().is_err(),
            "the original committed SDK lease must remain exclusively owned for retry"
        );

        injector
            .execute_batch("DROP TRIGGER fail_dispatch")
            .unwrap();
        match after_failure {
            AfterFailure::Retry => {
                prepared.check_live_permission().unwrap();
                approver
                    .dispatch_prepared_private_device_invite(&mut prepared, &publisher)
                    .await
                    .unwrap();
                assert!(
                    cap.private_invite().unwrap().unwrap().phase
                        == PrivateInvitePhase::PublicationUnknown
                );
                {
                    let published = publisher.0.lock().unwrap();
                    assert!(
                        published.len() == 1
                            && published[0] == before.transport.as_ref().unwrap().commit
                    );
                }
                assert!(
                    approver
                        .dispatch_prepared_private_device_invite(&mut prepared, &publisher)
                        .await
                        .is_err()
                );
                assert_eq!(publisher.0.lock().unwrap().len(), 1);
            }
            terminal => {
                let expected = match terminal {
                    AfterFailure::Expire => {
                        *clock.0.lock().unwrap() = deadline;
                        LinkingWelcomeDenied::Expired
                    }
                    AfterFailure::Cancel => {
                        gate.cancel();
                        LinkingWelcomeDenied::Cancelled
                    }
                    AfterFailure::Shutdown => {
                        gate.shutdown();
                        LinkingWelcomeDenied::Cancelled
                    }
                    AfterFailure::Retry => unreachable!(),
                };
                assert!(
                    matches!(approver.dispatch_prepared_private_device_invite(&mut prepared, &publisher).await,
                Err(PrivateInviteError::Denied(actual)) if actual == expected)
                );
                assert!(
                    cap.private_invite().unwrap().unwrap().phase == PrivateInvitePhase::Retired
                );
                assert!(publisher.0.lock().unwrap().is_empty());
                drop(prepared);
                assert!(!gate.maintain().unwrap());
                assert!(gate.begin_prepare(&input).is_err());
            }
        }
    }
}
