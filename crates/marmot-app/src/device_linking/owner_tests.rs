use super::*;
use storage_sqlite::SqlCipherKey;
fn storage() -> Arc<SqliteAccountStorage> {
    let storage = Arc::new(SqliteAccountStorage::in_memory().unwrap());
    storage
        .app_storage()
        .ensure_account_projection_with_identity("isolated-owner-test", &hex::encode([2; 32]))
        .unwrap();
    storage
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_runtime_owner_terminalizes_its_active_generation() {
    let storage = storage();
    let mut owner = LinkingOwner::startup(storage.clone(), [2; 32], [7; 32]).unwrap();
    owner.reserve().unwrap();
    owner
        .begin(
            super::super::tests::context(),
            Role::NewDevice,
            Instant::now(),
        )
        .await
        .unwrap();
    let binding = owner.binding.as_ref().unwrap().clone();
    drop(owner);
    assert!(
        matches!(
            storage.app_storage().bind_device_linking_context(&binding),
            Err(storage_sqlite::DeviceLinkingError::Terminal)
        ),
        "dropping the runtime owner must persist shutdown before releasing session ownership"
    );
    assert_eq!(
        storage
            .app_storage()
            .reserve_device_linking_attempt(&[2; 32], &[7; 32])
            .unwrap(),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_runtime_owner_after_storage_close_leaves_restart_fence_as_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("closed-owner.db");
    let key = SqlCipherKey::new("08".repeat(32)).unwrap();
    let storage = Arc::new(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    storage
        .app_storage()
        .ensure_account_projection_with_identity("isolated-owner-test", &hex::encode([2; 32]))
        .unwrap();
    let mut owner = LinkingOwner::startup(storage.clone(), [2; 32], [7; 32]).unwrap();
    owner.reserve().unwrap();
    owner
        .begin(
            super::super::tests::context(),
            Role::NewDevice,
            Instant::now(),
        )
        .await
        .unwrap();
    let binding = owner.binding.as_ref().unwrap().clone();
    storage.close().unwrap();
    drop(owner);
    drop(storage);
    let reopened = Arc::new(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    let mut restarted = LinkingOwner::startup(reopened.clone(), [2; 32], [7; 32]).unwrap();
    assert!(matches!(
        reopened.app_storage().bind_device_linking_context(&binding),
        Err(storage_sqlite::DeviceLinkingError::Terminal)
    ));
    assert_eq!(restarted.reserve().unwrap(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_attempt_cannot_restart_its_deadline_by_delaying_sas_setup() {
    let mut owner = LinkingOwner::startup(storage(), [2; 32], [7; 32]).unwrap();
    assert_eq!(owner.reserve().unwrap(), 1);
    let after_reservation = Instant::now();
    assert!(
        matches!(
            owner
                .begin(
                    super::super::tests::context(),
                    Role::NewDevice,
                    after_reservation + ATTEMPT_LIFETIME + Duration::from_secs(1),
                )
                .await,
            Err(OwnerError::Verifier(LinkError::Expired))
        ),
        "the durable reservation's lifetime starts before SAS setup"
    );
    assert!(owner.linker.attempt.is_none());
    assert_eq!(owner.reserve().unwrap(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_sdk_setup_does_not_extend_the_reserved_attempt_lifetime() {
    let now = Instant::now();
    let (mut a, mut b) = ready(now + Duration::from_secs(100)).await;
    let setup = now + Duration::from_secs(100);
    a.confirm(setup).await.unwrap();
    drain(&mut a, &mut b, setup).await;
    b.confirm(setup).await.unwrap();
    let frame = b
        .outgoing(setup)
        .unwrap()
        .into_iter()
        .find(|frame| {
            serde_json::from_slice::<Value>(&frame.event_json).unwrap()["type"]
                == "m.key.verification.mac"
        })
        .unwrap();
    assert!(
        matches!(
            a.receive(
                &frame,
                Instant::now() + ATTEMPT_LIFETIME + Duration::from_secs(1)
            )
            .await,
            Err(OwnerError::Verifier(LinkError::Expired))
        ),
        "late request/response setup must not extend the reservation"
    );
    assert!(a.linker.attempt.is_none());
    assert_eq!(a.reserve().unwrap(), 2);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_verifier_releases_only_a_new_durable_generation() {
    let storage = storage();
    let now = Instant::now();
    let mut owner = LinkingOwner::startup(storage.clone(), [2; 32], [7; 32]).unwrap();
    assert_eq!(owner.reserve().unwrap(), 1);
    owner
        .begin(super::super::tests::context(), Role::NewDevice, now)
        .await
        .unwrap();
    owner.cancel().unwrap();
    assert_eq!(
        owner
            .reserve()
            .expect("cancelled verifier must persist its terminal fence"),
        2
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_after_encrypted_reopen_abandons_sdk_secrets_and_old_generation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("owner.db");
    let key = SqlCipherKey::new("07".repeat(32)).unwrap();
    let storage = Arc::new(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    storage
        .app_storage()
        .ensure_account_projection_with_identity("isolated-owner-test", &hex::encode([2; 32]))
        .unwrap();
    let mut owner = LinkingOwner::startup(storage.clone(), [2; 32], [7; 32]).unwrap();
    owner.reserve().unwrap();
    owner
        .begin(
            super::super::tests::context(),
            Role::NewDevice,
            Instant::now(),
        )
        .await
        .unwrap();
    drop(owner);
    storage.close().unwrap();
    drop(storage);
    let storage = Arc::new(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    let mut restarted = LinkingOwner::startup(storage, [2; 32], [7; 32]).unwrap();
    assert_eq!(
        restarted
            .reserve()
            .expect("startup must abandon interrupted verification"),
        2
    );
}

async fn drain(from: &mut LinkingOwner, to: &mut LinkingOwner, now: Instant) {
    for frame in from.outgoing(now).unwrap() {
        to.receive(&frame, now).await.unwrap();
        from.acknowledge(&frame.token, now).await.unwrap();
    }
}
async fn ready(now: Instant) -> (LinkingOwner, LinkingOwner) {
    let mut a = LinkingOwner::startup(storage(), [2; 32], [7; 32]).unwrap();
    let mut b = LinkingOwner::startup(storage(), [2; 32], [6; 32]).unwrap();
    a.reserve().unwrap();
    b.reserve().unwrap();
    a.begin(super::super::tests::context(), Role::NewDevice, now)
        .await
        .unwrap();
    b.begin(super::super::tests::context(), Role::Approver, now)
        .await
        .unwrap();
    let ao = a.offer(now).unwrap();
    let bo = b.offer(now).unwrap();
    a.admit_peer(&bo, now).await.unwrap();
    b.admit_peer(&ao, now).await.unwrap();
    a.start_verification(now).await.unwrap();
    for _ in 0..8 {
        drain(&mut a, &mut b, now).await;
        drain(&mut b, &mut a, now).await;
    }
    assert_eq!(a.decimals(now).unwrap(), b.decimals(now).unwrap());
    assert!(a.decimals(now).unwrap().is_some());
    (a, b)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genuine_verification_releases_result_only_after_done_delivery_and_terminal_write() {
    let now = Instant::now();
    let (mut a, mut b) = ready(now).await;
    a.confirm(now).await.unwrap();
    assert!(matches!(
        a.take_verified(now).await,
        Err(OwnerError::Verifier(LinkError::NotReady))
    ));
    drain(&mut a, &mut b, now).await;
    assert!(matches!(
        a.take_verified(now).await,
        Err(OwnerError::Verifier(LinkError::NotReady))
    ));
    b.confirm(now).await.unwrap();
    for _ in 0..4 {
        drain(&mut b, &mut a, now).await;
        drain(&mut a, &mut b, now).await;
    }
    let binding = a.binding.as_ref().unwrap().clone();
    let flow = a.linker.attempt.as_ref().unwrap().flow.clone().unwrap();
    let original_deadline = a.reservation_deadline.unwrap();
    let verified = a.take_verified(now).await.unwrap();
    assert_eq!(verified.owner_deadline, Some(original_deadline));
    assert!(a.reservation_deadline.is_none());
    assert_eq!(verified.context.digest().unwrap(), binding.context_digest);
    assert!(matches!(verified.role, Role::NewDevice));
    assert!(matches!(
        a.storage
            .app_storage()
            .check_device_linking_flow(&binding, &flow),
        Err(storage_sqlite::DeviceLinkingError::Terminal)
    ));
    assert!(a.take_verified(now).await.is_err());
    b.take_verified(now).await.unwrap();
    assert_eq!(a.reserve().unwrap(), 2);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn externally_terminal_storage_fact_cannot_create_a_verified_result() {
    let now = Instant::now();
    let (mut a, mut b) = ready(now).await;
    a.confirm(now).await.unwrap();
    b.confirm(now).await.unwrap();
    for _ in 0..4 {
        drain(&mut a, &mut b, now).await;
        drain(&mut b, &mut a, now).await;
    }
    a.storage
        .app_storage()
        .finish_device_linking_attempt(1, DeviceLinkingOutcome::PairingVerified)
        .unwrap();
    assert!(matches!(
        a.take_verified(now).await,
        Err(OwnerError::Storage)
    ));
    assert!(a.linker.attempt.is_none());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_genuine_mac_persists_expiry_before_fresh_reservation() {
    let now = Instant::now();
    let (mut a, mut b) = ready(now).await;
    a.confirm(now).await.unwrap();
    drain(&mut a, &mut b, now).await;
    b.confirm(now).await.unwrap();
    let frame = b
        .outgoing(now)
        .unwrap()
        .into_iter()
        .find(|f| {
            serde_json::from_slice::<Value>(&f.event_json).unwrap()["type"]
                == "m.key.verification.mac"
        })
        .unwrap();
    assert!(matches!(
        a.receive(&frame, now + ATTEMPT_LIFETIME).await,
        Err(OwnerError::Verifier(LinkError::Expired))
    ));
    assert_eq!(a.reserve().unwrap(), 2);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reservation_identity_mismatch_does_not_burn_or_mutate_current_generation() {
    let now = Instant::now();
    let mut a = LinkingOwner::startup(storage(), [2; 32], [7; 32]).unwrap();
    a.reserve().unwrap();
    for field in 0..3 {
        let mut changed = super::super::tests::context();
        match field {
            0 => changed.account[0] ^= 1,
            1 => changed.recipient[0] ^= 1,
            _ => changed.new_device_generation = 99,
        }
        assert!(matches!(
            a.begin(changed, Role::NewDevice, now).await,
            Err(OwnerError::Verifier(LinkError::BindingMismatch))
        ));
        assert!(a.offer(now).is_err());
    }
    a.begin(super::super::tests::context(), Role::NewDevice, now)
        .await
        .unwrap();
    assert!(a.offer(now).is_ok());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_and_competing_local_reservation_persist_terminal_fences() {
    let now = Instant::now();
    let mut a = LinkingOwner::startup(storage(), [2; 32], [7; 32]).unwrap();
    a.reserve().unwrap();
    a.begin(super::super::tests::context(), Role::NewDevice, now)
        .await
        .unwrap();
    assert!(matches!(
        a.reserve(),
        Err(OwnerError::Verifier(LinkError::SimultaneousRequest))
    ));
    assert_eq!(a.reserve().unwrap(), 2);
    a.shutdown().unwrap();
    assert!(matches!(
        a.reserve(),
        Err(OwnerError::Verifier(LinkError::Closed))
    ));
    assert_eq!(
        a.storage
            .app_storage()
            .reserve_device_linking_attempt(&[2; 32], &[7; 32])
            .unwrap(),
        3
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_sdk_flow_is_durable_before_request_frame_release() {
    let now = Instant::now();
    let (mut a, _b) = ready(now).await;
    let binding = a.binding.as_ref().unwrap();
    let flow = a.linker.attempt.as_ref().unwrap().flow.as_ref().unwrap();
    a.storage
        .app_storage()
        .check_device_linking_flow(binding, flow)
        .unwrap();
    a.storage
        .app_storage()
        .finish_device_linking_attempt(1, DeviceLinkingOutcome::Cancelled)
        .unwrap();
    assert!(matches!(a.outgoing(now), Err(OwnerError::Storage)));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_owner_survives_encrypted_reopen_with_fresh_generation_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cancelled.db");
    let key = SqlCipherKey::new("06".repeat(32)).unwrap();
    let storage = Arc::new(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    storage
        .app_storage()
        .ensure_account_projection_with_identity("isolated-owner-test", &hex::encode([2; 32]))
        .unwrap();
    let mut a = LinkingOwner::startup(storage.clone(), [2; 32], [7; 32]).unwrap();
    a.reserve().unwrap();
    a.begin(
        super::super::tests::context(),
        Role::NewDevice,
        Instant::now(),
    )
    .await
    .unwrap();
    a.cancel().unwrap();
    drop(a);
    storage.close().unwrap();
    drop(storage);
    let storage = Arc::new(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    let mut a = LinkingOwner::startup(storage, [2; 32], [7; 32]).unwrap();
    assert_eq!(a.reserve().unwrap(), 2);
    assert!(matches!(
        a.begin(
            super::super::tests::context(),
            Role::NewDevice,
            Instant::now()
        )
        .await,
        Err(OwnerError::Verifier(LinkError::BindingMismatch))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn competing_wire_flow_persists_anomaly_without_accepting_new_request() {
    let now = Instant::now();
    let (_a, mut b) = ready(now).await;
    let mut other = LinkingOwner::startup(storage(), [2; 32], [7; 32]).unwrap();
    other.reserve().unwrap();
    other
        .begin(super::super::tests::context(), Role::NewDevice, now)
        .await
        .unwrap();
    let offer = b.offer(now).unwrap();
    other.admit_peer(&offer, now).await.unwrap();
    other.start_verification(now).await.unwrap();
    let request = other.outgoing(now).unwrap().remove(0);
    assert!(matches!(
        b.receive(&request, now).await,
        Err(OwnerError::Verifier(LinkError::SimultaneousRequest))
    ));
    assert_eq!(b.reserve().unwrap(), 2);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_peer_mac_terminalizes_durable_owner_without_result() {
    let now = Instant::now();
    let (mut a, mut b) = ready(now).await;
    a.confirm(now).await.unwrap();
    drain(&mut a, &mut b, now).await;
    b.confirm(now).await.unwrap();
    let mut frame = b
        .outgoing(now)
        .unwrap()
        .into_iter()
        .find(|f| {
            serde_json::from_slice::<Value>(&f.event_json).unwrap()["type"]
                == "m.key.verification.mac"
        })
        .unwrap();
    let mut event: Value = serde_json::from_slice(&frame.event_json).unwrap();
    event["content"]["keys"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    frame.event_json = serde_json::to_vec(&event).unwrap();
    assert!(matches!(
        a.receive(&frame, now).await,
        Err(OwnerError::Verifier(LinkError::Cancelled))
    ));
    assert!(a.take_verified(now).await.is_err());
    assert_eq!(a.reserve().unwrap(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintenance_expires_original_reservation_without_sdk_input() {
    let storage = storage();
    let mut owner = LinkingOwner::startup(storage.clone(), [2; 32], [7; 32]).unwrap();
    let scope = owner.reserve_scope().unwrap();
    let deadline = owner.reservation_deadline.unwrap();
    assert!(owner.maintain(deadline - Duration::from_nanos(1)).unwrap());
    assert!(!owner.maintain(deadline).unwrap());
    assert!(!owner.maintain(deadline).unwrap());
    let binding = DeviceLinkingBinding {
        generation: scope.generation,
        nonce: [1; 32],
        context_digest: [2; 32],
    };
    assert!(matches!(
        storage.app_storage().bind_device_linking_context(&binding),
        Err(storage_sqlite::DeviceLinkingError::Terminal)
    ));
    assert_eq!(
        owner.reserve_scope().unwrap().generation,
        scope.generation + 1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintenance_retries_failed_cancellation_without_waiting_for_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("terminal-retry.db");
    let key = SqlCipherKey::new("09".repeat(32)).unwrap();
    let storage = Arc::new(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
    storage
        .app_storage()
        .ensure_account_projection_with_identity("isolated-owner-test", &hex::encode([2; 32]))
        .unwrap();
    let mut owner = LinkingOwner::startup(storage.clone(), [2; 32], [7; 32]).unwrap();
    owner.reserve().unwrap();
    owner
        .begin(
            super::super::tests::context(),
            Role::NewDevice,
            Instant::now(),
        )
        .await
        .unwrap();
    let binding = owner.binding.as_ref().unwrap().clone();
    let injector = rusqlite::Connection::open(path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER reject_linking_terminal BEFORE UPDATE ON device_linking_attempt WHEN NEW.state >= 3 BEGIN SELECT RAISE(ABORT,'injected terminal failure'); END;").unwrap();
    assert!(matches!(owner.cancel(), Err(OwnerError::Storage)));
    assert!(
        owner.linker.attempt.is_none(),
        "cancellation must discard SDK secrets even when SQL fails"
    );
    assert!(matches!(
        owner
            .begin(
                super::super::tests::context(),
                Role::NewDevice,
                Instant::now()
            )
            .await,
        Err(OwnerError::Verifier(LinkError::Cancelled))
    ));
    injector
        .execute_batch("DROP TRIGGER reject_linking_terminal;")
        .unwrap();
    assert!(
        !owner.maintain(Instant::now()).unwrap(),
        "maintenance must retry the cancelled terminal fact before the original deadline"
    );
    assert!(matches!(
        storage.app_storage().bind_device_linking_context(&binding),
        Err(storage_sqlite::DeviceLinkingError::Terminal)
    ));
    assert_eq!(
        injector
            .query_row(
                "SELECT state FROM device_linking_attempt WHERE singleton=1",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        DeviceLinkingOutcome::Cancelled as i64
    );
    assert_eq!(owner.reserve().unwrap(), binding.generation + 1);
}

// A raw peer owner deliberately bypasses the App approver-genesis policy here.
// Genuine SDK verification still cannot approve arbitrary bootstrap rosters.
// Public purpose bytes test owner fencing; this fixture does not parse/join MLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn singleton_bootstrap_rejects_noninitial_rosters_without_consuming_sdk_result() {
    use cgka_traits::StorageProvider;
    use cgka_traits::device_linking_key_package::PurposeKeyPackage;
    for case in 0..4 {
        let now = Instant::now();
        let mut context = super::super::tests::context();
        context.predecessor.epoch = 0;
        context.predecessor.leaves = vec![super::super::PredecessorLeaf {
            leaf_index: 0,
            signature_public_key: context.approver,
        }];
        match case {
            1 => context.predecessor.epoch = 1,
            2 => context
                .predecessor
                .leaves
                .push(super::super::PredecessorLeaf {
                    leaf_index: 1,
                    signature_public_key: [8; 32],
                }),
            3 => context.predecessor.leaves[0].leaf_index = 1,
            _ => {}
        }
        let a_store = storage();
        let mut a =
            LinkingOwner::startup(a_store.clone(), context.account, context.recipient).unwrap();
        let mut b = LinkingOwner::startup(storage(), context.account, context.approver).unwrap();
        let scope = a.reserve_scope().unwrap();
        b.reserve().unwrap();
        a_store
            .device_linking_key_package_storage()
            .unwrap()
            .put_purpose_key_package(&PurposeKeyPackage {
                scope: scope.clone(),
                public_bytes: context.exact_key_package.clone(),
                reference: context.key_package_reference.to_vec(),
                signature_public_key: context.recipient.to_vec(),
                context: None,
                consumed: false,
            })
            .unwrap();
        a.begin_for_scope(&scope, context.clone(), Role::NewDevice, now)
            .await
            .unwrap();
        b.begin(context, Role::Approver, now).await.unwrap();
        let ao = a.offer(now).unwrap();
        let bo = b.offer(now).unwrap();
        a.admit_peer(&bo, now).await.unwrap();
        b.admit_peer(&ao, now).await.unwrap();
        a.start_verification(now).await.unwrap();
        for _ in 0..8 {
            drain(&mut a, &mut b, now).await;
            drain(&mut b, &mut a, now).await;
        }
        assert!(a.decimals(now).unwrap().is_some());
        assert!(a.decimals(now).unwrap() == b.decimals(now).unwrap());
        a.confirm(now).await.unwrap();
        b.confirm(now).await.unwrap();
        for _ in 0..8 {
            drain(&mut a, &mut b, now).await;
            drain(&mut b, &mut a, now).await;
        }
        let mut wrong = scope.clone();
        wrong.generation += 1;
        assert!(a.validate_singleton_bootstrap(&wrong, now).is_err());
        let checked = a.validate_singleton_bootstrap(&scope, now);
        if case == 0 {
            checked.unwrap();
        } else {
            assert!(
                matches!(
                    checked,
                    Err(OwnerError::Verifier(LinkError::BindingMismatch))
                ),
                "verified peer cannot authorize a noninitial bootstrap roster"
            );
        }
        // Both successful negative validation and refusal leave the actual
        // original SDK continuation intact; neither operation consumes it.
        let result = a.take_verified(now).await.unwrap();
        assert!(result.original_deadline().is_some());
    }
}
