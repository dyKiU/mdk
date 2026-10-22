//! Real isolated MLS staging with an injected trusted-core policy, not SDK consent.
use super::*;
use crate::device_group_genesis::tests::current_test_engine;
use cgka_traits::device_linking_key_package::{LinkingWelcomeDenied, PurposeAttemptScope};
use cgka_traits::engine::CgkaEngine;
use cgka_traits::private_device_invite::*;
use cgka_traits::storage::MessageStorage;
use cgka_traits::storage::StorageProvider;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use storage_sqlite::{DeviceLinkingBinding, DeviceLinkingOutcome, SqliteAccountStorage};

struct Policy {
    consent: PrivateInviteConsent,
    live: Arc<AtomicBool>,
}
struct Lease {
    consent: PrivateInviteConsent,
    live: Arc<AtomicBool>,
}
impl TrustedPrivateInvitePolicy for Policy {
    fn begin_prepare(
        &self,
        _: &AuthenticatedPrivateInvite,
    ) -> Result<Box<dyn PrivateInviteLease>, LinkingWelcomeDenied> {
        Ok(Box::new(Lease {
            consent: self.consent.clone(),
            live: self.live.clone(),
        }))
    }
}
impl PrivateInviteLease for Lease {
    fn consent(&self) -> &PrivateInviteConsent {
        &self.consent
    }
    fn check_staged(&mut self, _: &AuthenticatedPrivateAdd) -> Result<(), LinkingWelcomeDenied> {
        self.check_live_before_commit()
    }
    fn check_live_before_commit(&mut self) -> Result<(), LinkingWelcomeDenied> {
        if self.live.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(LinkingWelcomeDenied::Cancelled)
        }
    }
    fn preparation_committed(&mut self, _: &PrivateInviteScope) {}
}
fn install(engine: &mut Engine<SqliteAccountStorage>, origin: u64) -> Arc<AtomicBool> {
    let account = engine.self_id().as_slice().try_into().unwrap();
    let device = engine.identity.signer.public().try_into().unwrap();
    engine
        .storage
        .ensure_account_projection_with_identity("isolated-engine-prepare", &hex::encode(account))
        .unwrap();
    let generation = engine
        .storage
        .reserve_device_linking_attempt(&account, &device)
        .unwrap();
    let binding = DeviceLinkingBinding {
        generation,
        nonce: [6; 32],
        context_digest: [7; 32],
    };
    engine
        .storage
        .bind_device_linking_context(&binding)
        .unwrap();
    engine
        .storage
        .bind_device_linking_flow(&binding, "isolated-engine-policy")
        .unwrap();
    engine
        .storage
        .finish_device_linking_attempt(generation, DeviceLinkingOutcome::PairingVerified)
        .unwrap();
    let live = Arc::new(AtomicBool::new(true));
    engine.install_trusted_private_invite_policy(Arc::new(Policy {
        consent: PrivateInviteConsent {
            approver_scope: PurposeAttemptScope {
                account,
                local_device: device,
                generation,
            },
            recipient_generation: 1,
            origin: PrivateInviteOrigin::Genesis(origin),
            nonce: [6; 32],
            context_digest: [7; 32],
        },
        live: live.clone(),
    }));
    live
}
#[tokio::test]
async fn trusted_private_prepare_stages_real_single_add_without_ordinary_sent_or_deliverable_welcome()
 {
    use cgka_traits::engine::CgkaEngine;
    let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = recipient.fresh_linking_key_package().await.unwrap();
    install(&mut approver, origin.scope().selection_generation);
    let prepared = approver
        .prepare_private_device_invite(&group, package.clone())
        .await
        .unwrap();
    let fact = approver
        .storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    assert!(prepared.scope() == &fact.scope);
    assert!(fact.phase == PrivateInvitePhase::Wrapped);
    assert_eq!(fact.raw.binding.successor.leaves.len(), 2);
    assert_eq!(fact.raw.binding.successor.epoch.0, 1);
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&package)
    );
    assert!(
        approver
            .storage
            .list_messages(&group, cgka_traits::EpochId(0))
            .unwrap()
            .is_empty()
    );
    assert!(approver.confirm_published(prepared.pending).await.is_err());
    approver
        .cancel_prepared_private_device_invite(prepared)
        .unwrap();
    assert!(
        approver
            .validated_private_device_group_genesis(&group)
            .unwrap()
            .is_some()
    );
}
#[tokio::test]
async fn trusted_private_prepare_raw_insert_failure_rolls_back_actual_pending_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-private-prepare.db");
    let key = storage_sqlite::SqlCipherKey::new("86".repeat(32)).unwrap();
    let mut approver =
        current_test_engine(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = recipient.fresh_linking_key_package().await.unwrap();
    install(&mut approver, origin.scope().selection_generation);
    injector.execute_batch("CREATE TRIGGER fail_private_raw BEFORE INSERT ON private_device_invite_staging BEGIN SELECT RAISE(ABORT, 'isolated injected fault'); END;").unwrap();
    assert!(
        approver
            .prepare_private_device_invite(&group, package.clone())
            .await
            .is_err()
    );
    assert!(
        approver
            .storage
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            .is_none()
    );
    assert!(
        approver
            .validated_private_device_group_genesis(&group)
            .unwrap()
            .is_some()
    );
    injector
        .execute_batch("DROP TRIGGER fail_private_raw;")
        .unwrap();
    assert!(
        approver
            .prepare_private_device_invite(&group, package)
            .await
            .is_ok()
    );
}

struct Publisher(std::sync::atomic::AtomicUsize);
#[async_trait::async_trait]
impl TrustedPrivateInvitePublisher for Publisher {
    async fn publish_commit(
        &self,
        commit: &cgka_traits::TransportMessage,
    ) -> Result<(), cgka_traits::EngineError> {
        assert!(!commit.payload.is_empty());
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
#[tokio::test]
async fn cancelled_original_lease_never_invokes_publisher_and_retires_actual_pending_add() {
    let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = recipient.fresh_linking_key_package().await.unwrap();
    let live = install(&mut approver, origin.scope().selection_generation);
    let prepared = approver
        .prepare_private_device_invite(&group, package)
        .await
        .unwrap();
    live.store(false, Ordering::SeqCst);
    let publisher = Publisher(std::sync::atomic::AtomicUsize::new(0));
    assert!(matches!(
        approver
            .dispatch_prepared_private_device_invite(prepared, &publisher)
            .await,
        Err(PrivateInviteError::Denied(LinkingWelcomeDenied::Cancelled))
    ));
    assert_eq!(publisher.0.load(Ordering::SeqCst), 0);
    assert!(
        approver
            .storage
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            .unwrap()
            .phase
            == PrivateInvitePhase::Retired
    );
    assert!(
        approver
            .validated_private_device_group_genesis(&group)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn final_cache_failure_keeps_exact_raw_add_for_live_retry_and_reopen_cannot_publish() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-private-cache.db");
    let key = storage_sqlite::SqlCipherKey::new("87".repeat(32)).unwrap();
    let mut approver =
        current_test_engine(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = recipient.fresh_linking_key_package().await.unwrap();
    install(&mut approver, origin.scope().selection_generation);
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER fail_private_transport BEFORE UPDATE OF transport ON private_device_invite_staging WHEN NEW.phase=1 BEGIN SELECT RAISE(ABORT,'isolated cache fault'); END;").unwrap();
    assert!(matches!(
        approver
            .prepare_private_device_invite(&group, package.clone())
            .await,
        Err(PrivateInviteError::Storage(
            PrivateInviteStorageError::Storage(_)
        ))
    ));
    let first = approver
        .storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    assert!(first.phase == PrivateInvitePhase::RawStaged && first.transport.is_none());
    let mut reopened =
        current_test_engine(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    assert!(matches!(
        reopened
            .prepare_private_device_invite(&group, package.clone())
            .await,
        Err(PrivateInviteError::Denied(
            LinkingWelcomeDenied::NoLiveVerifier
        ))
    ));
    assert!(
        reopened
            .storage
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            .unwrap()
            == first
    );
    drop(reopened);
    let wrong = recipient.fresh_linking_key_package().await.unwrap();
    assert!(
        approver
            .prepare_private_device_invite(&group, wrong)
            .await
            .is_err()
    );
    assert!(
        approver
            .storage
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            .unwrap()
            == first
    );
    injector
        .execute_batch("DROP TRIGGER fail_private_transport")
        .unwrap();
    let prepared = approver
        .prepare_private_device_invite(&group, package)
        .await
        .unwrap();
    let final_fact = approver
        .storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    assert!(first.raw == final_fact.raw && first.scope == final_fact.scope);
    assert!(final_fact.phase == PrivateInvitePhase::Wrapped);
    let transport = final_fact.transport.unwrap();
    assert!(
        transport.commit.payload == first.raw.commit
            && transport.welcomes[0].payload == first.raw.welcome
    );
    approver
        .cancel_prepared_private_device_invite(prepared)
        .unwrap();
}

#[tokio::test]
async fn live_dispatch_calls_only_commit_once_and_keeps_unknown_membership_blocked() {
    let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = recipient.fresh_linking_key_package().await.unwrap();
    install(&mut approver, origin.scope().selection_generation);
    let prepared = approver
        .prepare_private_device_invite(&group, package)
        .await
        .unwrap();
    let pending = prepared.pending;
    let scope = prepared.scope().clone();
    let publisher = Publisher(std::sync::atomic::AtomicUsize::new(0));
    approver
        .dispatch_prepared_private_device_invite(prepared, &publisher)
        .await
        .unwrap();
    assert_eq!(publisher.0.load(Ordering::SeqCst), 1);
    let cap = approver.storage.private_device_invite_storage().unwrap();
    assert!(cap.private_invite().unwrap().unwrap().phase == PrivateInvitePhase::PublicationUnknown);
    assert!(matches!(
        cap.retire_undispatched_private_invite(&scope),
        Err(PrivateInviteStorageError::PublicationUncertain)
    ));
    assert!(approver.confirm_published(pending).await.is_err());
    assert!(approver.publish_failed(pending).await.is_err());
    assert!(
        approver
            .storage
            .list_messages(&group, cgka_traits::EpochId(0))
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn authenticated_private_commit_echo_confirms_exact_successor_without_ordinary_welcome() {
    use cgka_traits::storage::GroupStorage;
    let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = recipient.fresh_linking_key_package().await.unwrap();
    install(&mut approver, origin.scope().selection_generation);
    let prepared = approver
        .prepare_private_device_invite(&group, package)
        .await
        .unwrap();
    let before = approver
        .storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    let echo = before.transport.as_ref().unwrap().commit.clone();
    approver
        .dispatch_prepared_private_device_invite(
            prepared,
            &Publisher(std::sync::atomic::AtomicUsize::new(0)),
        )
        .await
        .unwrap();
    let outcome = approver.ingest(echo.clone()).await.unwrap();
    assert!(matches!(outcome, cgka_traits::IngestOutcome::Processed));
    assert_eq!(approver.storage.get_group(&group).unwrap().epoch.0, 1);
    let cap = approver.storage.private_device_invite_storage().unwrap();
    assert!(cap.private_invite().unwrap().unwrap().phase == PrivateInvitePhase::Confirmed);
    let confirmed = cap.confirmed_private_invite().unwrap().unwrap();
    assert!(confirmed.binding == before.raw.binding && !confirmed.denied);
    assert!(matches!(
        approver.ingest(echo).await.unwrap(),
        cgka_traits::IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::Duplicate
                | cgka_traits::ingest::InputRejectionCategory::OwnEcho
        }
    ));
    for record in approver
        .storage
        .list_messages(&group, cgka_traits::EpochId(0))
        .unwrap()
    {
        assert!(record.state != cgka_traits::MessageState::Sent);
        let payload = cgka_traits::StoredMessagePayload::decode(&record.payload).unwrap();
        assert!(!matches!(
            payload,
            cgka_traits::StoredMessagePayload::OutboundWelcome(_)
                | cgka_traits::StoredMessagePayload::StagedInviteWelcome { .. }
        ));
    }
}

#[tokio::test]
async fn cached_private_commit_before_dispatch_is_denied_without_poisoning_exact_echo_retry() {
    let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = recipient.fresh_linking_key_package().await.unwrap();
    install(&mut approver, origin.scope().selection_generation);
    let prepared = approver
        .prepare_private_device_invite(&group, package)
        .await
        .unwrap();
    let fact = approver
        .storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    let echo = fact.transport.unwrap().commit;
    assert!(matches!(
        approver.ingest(echo.clone()).await.unwrap(),
        cgka_traits::IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::AuthorizationFailed
        }
    ));
    assert!(
        approver
            .storage
            .list_messages(&group, cgka_traits::EpochId(0))
            .unwrap()
            .is_empty()
    );
    approver
        .dispatch_prepared_private_device_invite(
            prepared,
            &Publisher(std::sync::atomic::AtomicUsize::new(0)),
        )
        .await
        .unwrap();
    assert!(matches!(
        approver.ingest(echo).await.unwrap(),
        cgka_traits::IngestOutcome::Processed
    ));
}

#[tokio::test]
async fn uncertain_private_commit_reopen_preserves_actual_staged_add_for_exact_echo() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("isolated-private-echo-reopen.db");
    let key = storage_sqlite::SqlCipherKey::new("89".repeat(32)).unwrap();
    let mut approver =
        current_test_engine(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = recipient.fresh_linking_key_package().await.unwrap();
    install(&mut approver, origin.scope().selection_generation);
    let prepared = approver
        .prepare_private_device_invite(&group, package)
        .await
        .unwrap();
    let fact = approver
        .storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    let echo = fact.transport.unwrap().commit;
    approver
        .dispatch_prepared_private_device_invite(
            prepared,
            &Publisher(std::sync::atomic::AtomicUsize::new(0)),
        )
        .await
        .unwrap();
    drop(approver);
    let mut reopened =
        current_test_engine(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    reopened.hydrate_all_stored_groups().unwrap();
    assert!(
        reopened
            .with_mls_group(&group, |group| Ok(group.pending_commit().is_some()))
            .unwrap(),
        "uncertain dispatch must retain its actual staged MLS commit after reopen"
    );
    assert!(!reopened.epoch_manager.can_ingest(&group));
    assert!(matches!(
        reopened.ingest(echo).await.unwrap(),
        cgka_traits::IngestOutcome::Processed
    ));
    assert!(
        reopened
            .storage
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            .unwrap()
            .phase
            == PrivateInvitePhase::Confirmed
    );
    assert!(reopened.epoch_manager.can_ingest(&group));
}

#[tokio::test]
async fn private_commit_post_cas_mls_and_projection_failures_rollback_and_exact_retry() {
    use cgka_traits::storage::GroupStorage;
    for (trigger, expect_backend) in [
        (
            "CREATE TRIGGER fail_confirmation BEFORE INSERT ON openmls_values WHEN NEW.label=x'47726f75705374617465' BEGIN SELECT RAISE(ABORT,'isolated merge fault'); END;",
            true,
        ),
        (
            "CREATE TRIGGER fail_confirmation BEFORE UPDATE ON cgka_groups BEGIN SELECT RAISE(ABORT,'isolated projection fault'); END;",
            false,
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("isolated-private-confirmation-fault.db");
        let key = storage_sqlite::SqlCipherKey::new("8a".repeat(32)).unwrap();
        let mut approver =
            current_test_engine(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
        let origin = approver.create_private_device_group_genesis().unwrap();
        let group = origin.group_id().clone();
        let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
        let package = recipient.fresh_linking_key_package().await.unwrap();
        install(&mut approver, origin.scope().selection_generation);
        let prepared = approver
            .prepare_private_device_invite(&group, package)
            .await
            .unwrap();
        let fact = approver
            .storage
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            .unwrap();
        let echo = fact.transport.as_ref().unwrap().commit.clone();
        approver
            .dispatch_prepared_private_device_invite(
                prepared,
                &Publisher(std::sync::atomic::AtomicUsize::new(0)),
            )
            .await
            .unwrap();
        let snapshots = approver.storage.list_group_snapshots(&group).unwrap();
        let checkpoints = approver
            .storage
            .list_group_state_checkpoints(&group)
            .unwrap();
        let injector = rusqlite::Connection::open(&path).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &injector,
            &key,
            storage_sqlite::SqlCipherHardening::default(),
        )
        .unwrap();
        injector.execute_batch(trigger).unwrap();
        let error = approver.ingest(echo.clone()).await.unwrap_err();
        if expect_backend {
            assert!(matches!(error, cgka_traits::EngineError::Backend(_)));
        } else {
            assert!(matches!(error, cgka_traits::EngineError::Storage(_)));
        }
        let cap = approver.storage.private_device_invite_storage().unwrap();
        let failed = cap.private_invite().unwrap().unwrap();
        assert!(
            failed.phase == PrivateInvitePhase::PublicationUnknown
                && failed.raw == fact.raw
                && failed.transport == fact.transport
        );
        assert!(cap.confirmed_private_invite().unwrap().is_none());
        assert_eq!(approver.storage.get_group(&group).unwrap().epoch.0, 0);
        assert!(approver.storage.list_group_snapshots(&group).unwrap() == snapshots);
        assert!(
            approver
                .storage
                .list_group_state_checkpoints(&group)
                .unwrap()
                == checkpoints
        );
        assert!(
            approver
                .storage
                .list_messages(&group, cgka_traits::EpochId(0))
                .unwrap()
                .is_empty()
        );
        assert!(
            approver
                .with_mls_group(&group, |group| Ok(
                    group.epoch().as_u64() == 0 && group.pending_commit().is_some()
                ))
                .unwrap()
        );
        let birth = approver
            .storage
            .device_group_genesis_storage()
            .unwrap()
            .genesis_selection()
            .unwrap()
            .unwrap();
        assert!(!birth.active_denied && birth.fact.birth == *origin.birth());
        injector
            .execute_batch("DROP TRIGGER fail_confirmation")
            .unwrap();
        drop(approver);
        let mut reopened =
            current_test_engine(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
        reopened.hydrate_all_stored_groups().unwrap();
        assert!(matches!(
            reopened.ingest(echo).await.unwrap(),
            cgka_traits::IngestOutcome::Processed
        ));
        assert_eq!(reopened.storage.get_group(&group).unwrap().epoch.0, 1);
    }
}

#[tokio::test]
async fn private_commit_denied_origin_reopen_preserves_uncertainty_without_confirmation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("isolated-private-denied-reopen.db");
    let key = storage_sqlite::SqlCipherKey::new("8b".repeat(32)).unwrap();
    let mut approver =
        current_test_engine(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = recipient.fresh_linking_key_package().await.unwrap();
    install(&mut approver, origin.scope().selection_generation);
    let prepared = approver
        .prepare_private_device_invite(&group, package)
        .await
        .unwrap();
    let fact = approver
        .storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    let echo = fact.transport.unwrap().commit;
    approver
        .dispatch_prepared_private_device_invite(
            prepared,
            &Publisher(std::sync::atomic::AtomicUsize::new(0)),
        )
        .await
        .unwrap();
    approver
        .storage
        .device_group_genesis_storage()
        .unwrap()
        .deny_genesis_selection(origin.scope(), &group)
        .unwrap();
    drop(approver);
    let mut reopened =
        current_test_engine(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    reopened.hydrate_all_stored_groups().unwrap();
    assert!(matches!(
        reopened.ingest(echo).await,
        Err(cgka_traits::EngineError::LinkingWelcomeDenied(_))
    ));
    assert!(!reopened.epoch_manager.can_ingest(&group));
    assert!(
        reopened
            .with_mls_group(&group, |group| Ok(
                group.epoch().as_u64() == 0 && group.pending_commit().is_some()
            ))
            .unwrap()
    );
    let cap = reopened.storage.private_device_invite_storage().unwrap();
    assert!(cap.private_invite().unwrap().unwrap().phase == PrivateInvitePhase::PublicationUnknown);
    assert!(cap.confirmed_private_invite().unwrap().is_none());
    assert!(
        reopened
            .storage
            .list_messages(&group, cgka_traits::EpochId(0))
            .unwrap()
            .is_empty()
    );
    assert!(
        reopened
            .validated_private_device_group_genesis(&group)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn private_commit_substituted_cached_transport_bytes_cannot_poison_genuine_echo() {
    let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = recipient.fresh_linking_key_package().await.unwrap();
    install(&mut approver, origin.scope().selection_generation);
    let prepared = approver
        .prepare_private_device_invite(&group, package)
        .await
        .unwrap();
    let fact = approver
        .storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    let echo = fact.transport.unwrap().commit;
    approver
        .dispatch_prepared_private_device_invite(
            prepared,
            &Publisher(std::sync::atomic::AtomicUsize::new(0)),
        )
        .await
        .unwrap();
    let mut altered = echo.clone();
    altered.payload[0] ^= 1;
    assert!(matches!(
        approver.ingest(altered).await.unwrap(),
        cgka_traits::IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::AuthorizationFailed
        }
    ));
    let mut altered = echo.clone();
    altered.envelope = cgka_traits::TransportEnvelope::GroupMessage {
        transport_group_id: vec![99],
    };
    assert!(matches!(
        approver.ingest(altered).await.unwrap(),
        cgka_traits::IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::AuthorizationFailed
        }
    ));
    assert!(
        approver
            .storage
            .list_messages(&group, cgka_traits::EpochId(0))
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        approver.ingest(echo).await.unwrap(),
        cgka_traits::IngestOutcome::Processed
    ));
}

#[tokio::test]
async fn private_commit_delayed_reconciliation_uses_authenticated_staged_kp_after_public_expiry() {
    use tls_codec::Serialize;
    let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let provider = crate::provider::EngineOpenMlsProvider::<SqliteAccountStorage>::new(
        &recipient.crypto,
        recipient.storage.mls_storage(),
    );
    let bundle = openmls::prelude::KeyPackage::builder()
        .key_package_lifetime(openmls::prelude::Lifetime::new(10))
        .leaf_node_capabilities(crate::capabilities::leaf_capabilities(
            &recipient.registry,
            recipient.ciphersuite,
            recipient.new_protocol_profile,
        ))
        .leaf_node_extensions(
            recipient
                .identity
                .leaf_extensions(&recipient.supported_app_components)
                .unwrap(),
        )
        .build(
            recipient.ciphersuite,
            &provider,
            &recipient.identity.signer,
            recipient.identity.credential_with_key.clone(),
        )
        .unwrap();
    let expires = bundle.key_package().life_time().not_after();
    let wire: openmls::prelude::MlsMessageOut = bundle.key_package().clone().into();
    let package = cgka_traits::engine::KeyPackage::new(wire.tls_serialize_detached().unwrap())
        .with_protocol_profile(cgka_traits::group::ProtocolProfile::Current);
    install(&mut approver, origin.scope().selection_generation);
    let prepared = approver
        .prepare_private_device_invite(&group, package.clone())
        .await
        .unwrap();
    let echo = approver
        .storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap()
        .transport
        .unwrap()
        .commit;
    approver
        .dispatch_prepared_private_device_invite(
            prepared,
            &Publisher(std::sync::atomic::AtomicUsize::new(0)),
        )
        .await
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    tokio::time::sleep(std::time::Duration::from_secs(
        expires.saturating_add(1).saturating_sub(now),
    ))
    .await;
    assert!(
        approver.parse_key_package(&package).is_err(),
        "public KP lifetime must remain enforced"
    );
    assert!(matches!(
        approver.ingest(echo).await.unwrap(),
        cgka_traits::IngestOutcome::Processed
    ));
}

struct BackpressuredPublisher {
    live: Arc<AtomicBool>,
    effects: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl TrustedPrivateInvitePublisher for BackpressuredPublisher {
    async fn publish_commit(
        &self,
        _: &cgka_traits::TransportMessage,
    ) -> Result<(), cgka_traits::EngineError> {
        let mut yielded = false;
        std::future::poll_fn(|cx| {
            if !yielded {
                yielded = true;
                self.live.store(false, Ordering::SeqCst);
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            } else {
                self.effects.fetch_add(1, Ordering::SeqCst);
                std::task::Poll::Ready(Ok(()))
            }
        })
        .await
    }
}
#[tokio::test]
async fn cancellation_during_publisher_backpressure_never_polls_network_effect_again() {
    let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = recipient.fresh_linking_key_package().await.unwrap();
    let live = install(&mut approver, origin.scope().selection_generation);
    let prepared = approver
        .prepare_private_device_invite(&group, package)
        .await
        .unwrap();
    let publisher = BackpressuredPublisher {
        live,
        effects: std::sync::atomic::AtomicUsize::new(0),
    };
    assert!(matches!(
        approver
            .dispatch_prepared_private_device_invite(prepared, &publisher)
            .await,
        Err(PrivateInviteError::Denied(LinkingWelcomeDenied::Cancelled))
    ));
    assert_eq!(publisher.effects.load(Ordering::SeqCst), 0);
    assert!(
        approver
            .storage
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            .unwrap()
            .phase
            == PrivateInvitePhase::PublicationUnknown
    );
}

struct LateCancellationPolicy {
    consent: PrivateInviteConsent,
    live: Arc<AtomicBool>,
}
struct LateCancellationLease {
    base: Lease,
    checks: usize,
}
impl TrustedPrivateInvitePolicy for LateCancellationPolicy {
    fn begin_prepare(
        &self,
        _: &AuthenticatedPrivateInvite,
    ) -> Result<Box<dyn PrivateInviteLease>, LinkingWelcomeDenied> {
        Ok(Box::new(LateCancellationLease {
            base: Lease {
                consent: self.consent.clone(),
                live: self.live.clone(),
            },
            checks: 0,
        }))
    }
}
impl PrivateInviteLease for LateCancellationLease {
    fn consent(&self) -> &PrivateInviteConsent {
        &self.base.consent
    }
    fn check_staged(
        &mut self,
        actual: &AuthenticatedPrivateAdd,
    ) -> Result<(), LinkingWelcomeDenied> {
        self.base.check_staged(actual)
    }
    fn check_live_before_commit(&mut self) -> Result<(), LinkingWelcomeDenied> {
        self.checks += 1;
        if self.checks == 3 {
            self.base.live.store(false, Ordering::SeqCst);
        }
        self.base.check_live_before_commit()
    }
    fn preparation_committed(&mut self, _: &PrivateInviteScope) {
        panic!("cancelled final SQL must not commit consent");
    }
}
#[tokio::test]
async fn final_sql_original_lease_cancellation_rolls_back_cache_and_retires_raw_pending_add() {
    let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = recipient.fresh_linking_key_package().await.unwrap();
    let live = install(&mut approver, origin.scope().selection_generation);
    let input = approver
        .validate_private_invite_input(&group, &package)
        .unwrap();
    let consent = approver
        .private_invite_policy
        .as_ref()
        .unwrap()
        .begin_prepare(&input)
        .unwrap()
        .consent()
        .clone();
    approver
        .install_trusted_private_invite_policy(Arc::new(LateCancellationPolicy { consent, live }));
    assert!(matches!(
        approver
            .prepare_private_device_invite(&group, package)
            .await,
        Err(PrivateInviteError::Denied(LinkingWelcomeDenied::Cancelled))
    ));
    let fact = approver
        .storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    assert!(fact.phase == PrivateInvitePhase::Retired && fact.transport.is_none());
    assert!(
        approver
            .validated_private_device_group_genesis(&group)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn actual_private_preparation_never_consumes_queued_unapproved_add() {
    use openmls_traits::OpenMlsProvider;
    let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group_id = origin.group_id().clone();
    let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = recipient.fresh_linking_key_package().await.unwrap();
    let mut unwanted = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let unwanted_package = unwanted.fresh_linking_key_package().await.unwrap();
    let unwanted_signer = unwanted.identity.signer.public().to_vec();
    let provider = crate::provider::EngineOpenMlsProvider::<SqliteAccountStorage>::new(
        &approver.crypto,
        approver.storage.mls_storage(),
    );
    let mut group = openmls::group::MlsGroup::load(
        provider.storage(),
        &openmls::group::GroupId::from_slice(group_id.as_slice()),
    )
    .unwrap()
    .unwrap();
    group
        .propose_add_member(
            &provider,
            &approver.identity.signer,
            &approver.parse_key_package(&unwanted_package).unwrap(),
        )
        .unwrap();
    assert_eq!(group.pending_proposals().count(), 1);
    install(&mut approver, origin.scope().selection_generation);
    let prepared = approver
        .prepare_private_device_invite(&group_id, package)
        .await
        .unwrap();
    let fact = approver
        .storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    assert_eq!(fact.raw.binding.successor.leaves.len(), 2);
    assert!(
        !fact
            .raw
            .binding
            .successor
            .leaves
            .iter()
            .any(|leaf| leaf.signature_public_key.as_slice() == unwanted_signer)
    );
    approver
        .cancel_prepared_private_device_invite(prepared)
        .unwrap();
}

#[tokio::test]
async fn mls_pending_state_write_failure_is_backend_not_consent_denial_and_rolls_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-private-mls-fault.db");
    let key = storage_sqlite::SqlCipherKey::new("88".repeat(32)).unwrap();
    let mut approver =
        current_test_engine(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = recipient.fresh_linking_key_package().await.unwrap();
    install(&mut approver, origin.scope().selection_generation);
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER fail_actual_mls_pending BEFORE INSERT ON openmls_values WHEN NEW.label=x'47726f75705374617465' BEGIN SELECT RAISE(ABORT,'isolated MLS state fault'); END;").unwrap();
    assert!(matches!(
        approver
            .prepare_private_device_invite(&group, package.clone())
            .await,
        Err(PrivateInviteError::Engine(
            cgka_traits::EngineError::Backend(_)
        ))
    ));
    assert!(
        approver
            .storage
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            .is_none()
    );
    assert!(
        approver
            .validated_private_device_group_genesis(&group)
            .unwrap()
            .is_some()
    );
    injector
        .execute_batch("DROP TRIGGER fail_actual_mls_pending")
        .unwrap();
    let prepared = approver
        .prepare_private_device_invite(&group, package)
        .await
        .unwrap();
    approver
        .cancel_prepared_private_device_invite(prepared)
        .unwrap();
}

#[tokio::test]
async fn raw_retirement_requires_active_exact_scope_and_leaves_terminal_lineage_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-private-raw-cancel.db");
    let key = storage_sqlite::SqlCipherKey::new("89".repeat(32)).unwrap();
    let mut approver =
        current_test_engine(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let package = recipient.fresh_linking_key_package().await.unwrap();
    install(&mut approver, origin.scope().selection_generation);
    let scope = PurposeAttemptScope {
        account: approver.self_id().as_slice().try_into().unwrap(),
        local_device: approver.identity.signer.public().try_into().unwrap(),
        generation: 1,
    };
    assert!(
        !approver
            .retire_unprepared_private_device_invite(&scope)
            .unwrap()
    );
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER fail_raw_wrapping BEFORE UPDATE OF transport ON private_device_invite_staging WHEN NEW.phase=1 BEGIN SELECT RAISE(ABORT,'isolated wrapping failure'); END;").unwrap();
    assert!(matches!(
        approver
            .prepare_private_device_invite(&group, package.clone())
            .await,
        Err(PrivateInviteError::Storage(
            PrivateInviteStorageError::Storage(_)
        ))
    ));
    let raw = approver
        .storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    let mut stale = scope.clone();
    stale.generation += 1;
    assert!(
        approver
            .retire_unprepared_private_device_invite(&stale)
            .is_err()
    );
    assert!(
        approver
            .storage
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            == Some(raw)
    );
    injector.execute_batch("CREATE TRIGGER fail_raw_retire BEFORE UPDATE OF phase ON private_device_invite_staging WHEN NEW.phase=4 BEGIN SELECT RAISE(ABORT,'isolated retire failure'); END;").unwrap();
    assert!(matches!(
        approver.retire_unprepared_private_device_invite(&scope),
        Err(PrivateInviteError::Storage(
            PrivateInviteStorageError::Storage(_)
        ))
    ));
    injector
        .execute_batch("DROP TRIGGER fail_raw_retire; DROP TRIGGER fail_raw_wrapping;")
        .unwrap();
    assert!(
        approver
            .retire_unprepared_private_device_invite(&scope)
            .unwrap()
    );
    let terminal = approver
        .storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    assert!(terminal.phase == PrivateInvitePhase::Retired);
    assert!(
        !approver
            .retire_unprepared_private_device_invite(&stale)
            .unwrap()
    );
    assert!(
        approver
            .storage
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            == Some(terminal)
    );
    assert!(
        approver
            .validated_private_device_group_genesis(&group)
            .unwrap()
            .is_some()
    );
    assert!(
        approver
            .with_mls_group(&group, |group| Ok(group.pending_commit().is_none()))
            .unwrap()
    );
    install(&mut approver, origin.scope().selection_generation);
    let prepared = approver
        .prepare_private_device_invite(&group, package)
        .await
        .unwrap();
    let mut current = scope;
    current.generation += 1;
    assert!(matches!(
        approver.retire_unprepared_private_device_invite(&current),
        Err(PrivateInviteError::Storage(PrivateInviteStorageError::Busy))
    ));
    injector.execute_batch("CREATE TRIGGER fail_borrowed_retire BEFORE UPDATE OF phase ON private_device_invite_staging WHEN NEW.phase=4 BEGIN SELECT RAISE(ABORT,'isolated borrowed retire failure'); END;").unwrap();
    assert!(matches!(
        approver.retire_prepared_private_device_invite(&prepared),
        Err(PrivateInviteError::Storage(
            PrivateInviteStorageError::Storage(_)
        ))
    ));
    let mut prepared = prepared;
    assert!(prepared.check_live_permission().is_ok());
    injector
        .execute_batch("DROP TRIGGER fail_borrowed_retire")
        .unwrap();
    approver
        .retire_prepared_private_device_invite(&prepared)
        .unwrap();
    assert!(
        approver
            .with_mls_group(&group, |group| Ok(group.pending_commit().is_none()))
            .unwrap()
    );
}

/// Explicit two-writer operational fixture: original runner generates valid MLS
/// pending state; the new runner bridges metadata before exact crypto ingest.
#[tokio::test]
#[ignore = "run generator and verifier sequentially with their recorded writer sources"]
async fn private_ledger_real_crypto_old_writer_fixture() {
    let directory = std::path::PathBuf::from(
        std::env::var("MDK_PRIVATE_LEDGER_FIXTURE_DIR").expect("isolated fixture directory"),
    );
    let path = directory.join("legacy-private-unknown.db");
    let artifact = directory.join("synthetic-echo.json");
    let key = storage_sqlite::SqlCipherKey::new("91".repeat(32)).unwrap();
    if std::env::var("MDK_PRIVATE_LEDGER_FIXTURE_STAGE").unwrap() == "generate" {
        let mut approver =
            current_test_engine(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
        let origin = approver.create_private_device_group_genesis().unwrap();
        let group = origin.group_id().clone();
        let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
        let package = recipient.fresh_linking_key_package().await.unwrap();
        install(&mut approver, origin.scope().selection_generation);
        let prepared = approver
            .prepare_private_device_invite(&group, package)
            .await
            .unwrap();
        let fact = approver
            .storage
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            .unwrap();
        let echo = fact.transport.unwrap().commit;
        approver
            .dispatch_prepared_private_device_invite(
                prepared,
                &Publisher(std::sync::atomic::AtomicUsize::new(0)),
            )
            .await
            .unwrap();
        assert!(
            approver
                .with_mls_group(&group, |group| Ok(group.pending_commit().is_some()))
                .unwrap()
        );
        drop(approver);
        let connection = rusqlite::Connection::open(&path).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &connection,
            &key,
            storage_sqlite::SqlCipherHardening::default(),
        )
        .unwrap();
        let old: i64 = connection
            .query_row(
                "SELECT count(*) FROM cgka_schema_migrations WHERE version BETWEEN 103 AND 110",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old, 8, "generator must use original runner");
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(artifact)
            .unwrap();
        file.write_all(&serde_json::to_vec(&(group, echo)).unwrap())
            .unwrap();
        file.sync_all().unwrap();
        return;
    }
    let (group, echo): (cgka_traits::GroupId, cgka_traits::TransportMessage) =
        serde_json::from_slice(&std::fs::read(artifact).unwrap()).unwrap();
    let mut reopened =
        current_test_engine(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    reopened.hydrate_all_stored_groups().unwrap();
    assert!(!reopened.epoch_manager.can_ingest(&group));
    assert!(
        reopened
            .with_mls_group(&group, |group| Ok(
                group.epoch().as_u64() == 0 && group.pending_commit().is_some()
            ))
            .unwrap()
    );
    let cap = reopened.storage.private_device_invite_storage().unwrap();
    assert!(cap.private_invite().unwrap().unwrap().phase == PrivateInvitePhase::PublicationUnknown);
    assert!(cap.confirmed_private_invite().unwrap().is_none());
    assert!(matches!(
        reopened.ingest(echo).await.unwrap(),
        cgka_traits::IngestOutcome::Processed
    ));
    assert!(
        reopened
            .storage
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            .unwrap()
            .phase
            == PrivateInvitePhase::Confirmed
    );
    assert!(reopened.epoch_manager.can_ingest(&group));
    drop(reopened);
    let connection = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    let old: i64 = connection
        .query_row(
            "SELECT count(*) FROM cgka_schema_migrations WHERE version>102",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let audited: i64 = connection
        .query_row(
            "SELECT count(*) FROM cgka_experimental_device_sync_migration_bridge_audit",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(old, 0);
    assert_eq!(audited, 8);
}
