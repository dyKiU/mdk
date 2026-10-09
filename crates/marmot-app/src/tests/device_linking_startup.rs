//! Exercise restart fencing through the same local open used by account workers.
use super::*;
use cgka_traits::StorageProvider;
use cgka_traits::storage::AccountDeviceSignerStorage;
use storage_sqlite::{DeviceLinkingBinding, DeviceLinkingError, SqliteAccountStorage};

fn scope(app: &MarmotApp, label: &str) -> (SqliteAccountStorage, [u8; 32], [u8; 32]) {
    let account: [u8; 32] = hex::decode(app.account_home().account(label).unwrap().account_id_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let storage = app.account_storage(label).unwrap();
    let device = storage
        .account_device_signer(&cgka_traits::MemberId::new(account.to_vec()))
        .unwrap()
        .unwrap()
        .mls_signature_public_key
        .try_into()
        .unwrap();
    (storage, account, device)
}

fn pending_flow(
    storage: &SqliteAccountStorage,
    account: &[u8; 32],
    device: &[u8; 32],
) -> DeviceLinkingBinding {
    let binding = DeviceLinkingBinding {
        generation: storage
            .reserve_device_linking_attempt(account, device)
            .unwrap(),
        nonce: [1; 32],
        context_digest: [2; 32],
    };
    storage.bind_device_linking_context(&binding).unwrap();
    storage
        .bind_device_linking_flow(&binding, "isolated-sdk-flow")
        .unwrap();
    binding
}

async fn drain_client_verifier(
    from: &mut AppClient,
    from_scope: &cgka_traits::device_linking_key_package::PurposeAttemptScope,
    to: &mut AppClient,
    to_scope: &cgka_traits::device_linking_key_package::PurposeAttemptScope,
) {
    for frame in from.device_linking_outgoing(from_scope).unwrap() {
        to.receive_device_linking_frame(to_scope, &frame)
            .await
            .unwrap();
        from.acknowledge_device_linking_frame(from_scope, frame.acknowledgement_token())
            .await
            .unwrap();
    }
}

#[test]
fn device_linking_client_failed_context_freeze_cannot_expose_an_offer() {
    run_composed_app_runtime_test("linking-client-freeze-failure", || async {
        use crate::device_linking::{LinkingContext, Role};
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("test")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let plane = MarmotRelayPlane::new(None, Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app
            .local_client_with_relay_plane("test", &plane, None)
            .await
            .unwrap();
        let prepared = client.prepare_device_linking().await.unwrap();
        let metadata = cgka_engine::key_package::key_package_metadata(&prepared.package).unwrap();
        let context = LinkingContext {
            version: 1,
            nonce: [42; 32],
            new_device_generation: prepared.scope.generation,
            approver_generation: 1,
            account: prepared.scope.account,
            exact_key_package: prepared.package.bytes.clone(),
            key_package_reference: hex::decode(metadata.key_package_ref_hex)
                .unwrap()
                .try_into()
                .unwrap(),
            device_group: vec![17; 16],
            predecessor: crate::device_linking::PredecessorRoster {
                artifact_digest: None,
                epoch: 0,
                epoch_authenticator_digest: [31; 32],
                leaves: vec![crate::device_linking::PredecessorLeaf {
                    leaf_index: 0,
                    signature_public_key: [3; 32],
                }],
            },
            approver: [3; 32],
            recipient: prepared.scope.local_device,
        };
        let path = app.account_storage_path("test");
        let keys = app.account_home().load_signing_keys("test").unwrap();
        let key = app
            .sqlcipher_key("test", &keys, &path, SqlcipherDatabaseKind::Session)
            .unwrap();
        let injector = rusqlite::Connection::open(path).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &injector,
            &key,
            storage_sqlite::SqlCipherHardening::cipher_only(),
        )
        .unwrap();
        injector.execute_batch("CREATE TRIGGER reject_purpose_freeze BEFORE UPDATE OF nonce,context_digest ON device_linking_key_package BEGIN SELECT RAISE(ABORT,'injected context freeze failure'); END;").unwrap();
        assert!(
            client
                .begin_device_linking(&prepared.scope, context, Role::NewDevice)
                .await
                .is_err()
        );
        assert!(
            client.device_linking_offer(&prepared.scope).is_err(),
            "failed durable purpose binding must never expose a live SDK offer"
        );
        let state: i64 = injector
            .query_row(
                "SELECT state FROM device_linking_attempt WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            state,
            storage_sqlite::DeviceLinkingOutcome::IntegrityFailure as i64
        );
        injector
            .execute_batch("DROP TRIGGER reject_purpose_freeze;")
            .unwrap();
        client
            .maintain_device_linking(std::time::Instant::now())
            .await
            .unwrap();
        assert!(
            !client
                .runtime
                .session()
                .durably_owned_key_packages()
                .unwrap()
                .contains(&prepared.package)
        );
        let next = client.prepare_device_linking().await.unwrap();
        assert_eq!(next.scope.generation, prepared.scope.generation + 1);
    });
}

#[test]
fn device_linking_real_clients_verify_scoped_exact_packages_without_admitting_welcome() {
    run_composed_app_runtime_test("linking-client-verifier", || async {
        use crate::client::device_linking::ClientLinkingError;
        use crate::device_linking::{LinkingContext, Role};
        let keys = Keys::generate();
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        for dir in [&a_dir, &b_dir] {
            AccountHome::open(dir.path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
        }
        let a_app = MarmotApp::with_relay(a_dir.path(), "wss://relay.example");
        let b_app = MarmotApp::with_relay(b_dir.path(), "wss://relay.example");
        let plane = MarmotRelayPlane::new(None, Arc::new(ScriptedPushRelayClient::default()));
        let mut a = a_app
            .local_client_with_relay_plane("test", &plane, None)
            .await
            .unwrap();
        let mut b = b_app
            .local_client_with_relay_plane("test", &plane, None)
            .await
            .unwrap();
        let old = a.prepare_device_linking().await.unwrap();
        a.cancel_device_linking_scope(&old.scope).await.unwrap();
        let prepared = a.prepare_device_linking().await.unwrap();
        let b_scope = b.reserve_device_linking().unwrap();
        assert!(prepared.scope.account == b_scope.account);
        assert!(prepared.scope.local_device != b_scope.local_device);
        let origin = b.create_private_device_group_genesis().unwrap();
        let group = origin.group_id().clone();
        let candidate = origin.current();
        let metadata = cgka_engine::key_package::key_package_metadata(&prepared.package).unwrap();
        let context = LinkingContext {
            version: 1,
            nonce: [41; 32],
            new_device_generation: prepared.scope.generation,
            approver_generation: b_scope.generation,
            account: prepared.scope.account,
            exact_key_package: prepared.package.bytes.clone(),
            key_package_reference: hex::decode(metadata.key_package_ref_hex)
                .unwrap()
                .try_into()
                .unwrap(),
            device_group: group.as_slice().to_vec(),
            predecessor: crate::device_linking::PredecessorRoster::from_candidate(candidate)
                .unwrap(),
            approver: b_scope.local_device,
            recipient: prepared.scope.local_device,
        };
        assert!(matches!(
            a.begin_device_linking(&old.scope, context.clone(), Role::NewDevice)
                .await,
            Err(ClientLinkingError::Owner(
                crate::device_linking::OwnerError::Verifier(
                    crate::device_linking::LinkError::StaleFlow
                )
            ))
        ));
        let mut forged_package = context.clone();
        forged_package.exact_key_package[0] ^= 1;
        assert!(
            a.begin_device_linking(&prepared.scope, forged_package, Role::NewDevice)
                .await
                .is_err()
        );
        a.begin_device_linking(&prepared.scope, context.clone(), Role::NewDevice)
            .await
            .unwrap();
        b.begin_device_linking(&b_scope, context, Role::Approver)
            .await
            .unwrap();
        let (store, _, _) = scope(&a_app, "test");
        let purpose = store
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap();
        assert!(purpose.context.is_some());
        let ao = a.device_linking_offer(&prepared.scope).unwrap();
        let bo = b.device_linking_offer(&b_scope).unwrap();
        a.admit_device_linking_peer(&prepared.scope, &bo)
            .await
            .unwrap();
        b.admit_device_linking_peer(&b_scope, &ao).await.unwrap();
        assert!(
            a.take_device_linking_verified(&prepared.scope)
                .await
                .is_err()
        );
        a.start_device_linking_verification(&prepared.scope)
            .await
            .unwrap();
        for _ in 0..8 {
            drain_client_verifier(&mut a, &prepared.scope, &mut b, &b_scope).await;
            drain_client_verifier(&mut b, &b_scope, &mut a, &prepared.scope).await;
        }
        let digits = a.device_linking_decimals(&prepared.scope).unwrap();
        assert!(digits.is_some());
        assert!(digits == b.device_linking_decimals(&b_scope).unwrap());
        a.confirm_device_linking(&prepared.scope).await.unwrap();
        b.confirm_device_linking(&b_scope).await.unwrap();
        for _ in 0..8 {
            drain_client_verifier(&mut a, &prepared.scope, &mut b, &b_scope).await;
            drain_client_verifier(&mut b, &b_scope, &mut a, &prepared.scope).await;
        }
        let _new_device_proof = a
            .take_device_linking_verified(&prepared.scope)
            .await
            .unwrap();
        let _approver_proof = b.take_device_linking_verified(&b_scope).await.unwrap();
        assert!(
            a.take_device_linking_verified(&prepared.scope)
                .await
                .is_err()
        );
        let purpose = store
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap();
        assert!(
            a.linking_welcome_policy().begin_join(&purpose).is_err(),
            "SAS proof must not arm Welcome admission before approved-roster validation"
        );
    });
}

#[test]
fn device_linking_approver_rejects_generic_group_before_exposing_offer() {
    run_composed_app_runtime_test("linking-unapproved-origin", || async {
        use crate::device_linking::{LinkingContext, Role};
        use cgka_traits::engine::CreateGroupRequest;
        let keys = Keys::generate();
        let recipient_dir = tempfile::tempdir().unwrap();
        let approver_dir = tempfile::tempdir().unwrap();
        for dir in [&recipient_dir, &approver_dir] {
            AccountHome::open(dir.path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
        }
        let recipient_app = MarmotApp::with_relay(recipient_dir.path(), "wss://relay.example");
        let approver_app = MarmotApp::with_relay(approver_dir.path(), "wss://relay.example");
        let plane = MarmotRelayPlane::new(None, Arc::new(ScriptedPushRelayClient::default()));
        let mut recipient = recipient_app
            .local_client_with_relay_plane("test", &plane, None)
            .await
            .unwrap();
        let mut approver = approver_app
            .local_client_with_relay_plane("test", &plane, None)
            .await
            .unwrap();
        let prepared = recipient.prepare_device_linking().await.unwrap();
        let approver_scope = approver.reserve_device_linking().unwrap();
        let group = approver
            .runtime
            .session_mut()
            .create_group(CreateGroupRequest {
                name: "ordinary solo chat".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap()
            .group_id;
        let candidate = approver
            .runtime
            .session()
            .candidate_device_group_snapshot(&group)
            .unwrap()
            .unwrap();
        let metadata = cgka_engine::key_package::key_package_metadata(&prepared.package).unwrap();
        let context = LinkingContext {
            version: 1,
            nonce: [51; 32],
            new_device_generation: prepared.scope.generation,
            approver_generation: approver_scope.generation,
            account: prepared.scope.account,
            exact_key_package: prepared.package.bytes.clone(),
            key_package_reference: hex::decode(metadata.key_package_ref_hex)
                .unwrap()
                .try_into()
                .unwrap(),
            device_group: group.as_slice().to_vec(),
            predecessor: crate::device_linking::PredecessorRoster::from_candidate(&candidate)
                .unwrap(),
            approver: approver_scope.local_device,
            recipient: prepared.scope.local_device,
        };
        assert!(
            approver
                .begin_device_linking(&approver_scope, context, Role::Approver)
                .await
                .is_err(),
            "an ordinary one-member chat must not become an approved device origin"
        );
        assert!(approver.device_linking_offer(&approver_scope).is_err());
        assert_eq!(
            approver.runtime.session().epoch(&group).unwrap(),
            cgka_traits::EpochId(0)
        );
    });
}

#[test]
fn device_linking_startup_fences_only_the_exclusively_reopened_account() {
    run_composed_app_runtime_test("linking-startup-fence", || async {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        home.create_account("bob").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let plane = MarmotRelayPlane::new(None, Arc::new(ScriptedPushRelayClient::default()));
        let alice = app
            .local_client_with_relay_plane("alice", &plane, None)
            .await
            .unwrap();
        let bob = app
            .local_client_with_relay_plane("bob", &plane, None)
            .await
            .unwrap();
        let (alice_storage, alice_account, alice_device) = scope(&app, "alice");
        let (bob_storage, bob_account, bob_device) = scope(&app, "bob");
        let alice_binding = pending_flow(&alice_storage, &alice_account, &alice_device);
        let bob_binding = pending_flow(&bob_storage, &bob_account, &bob_device);

        assert!(matches!(
            app.local_client_with_relay_plane("alice", &plane, None)
                .await,
            Err(AppError::AccountSessionBusy)
        ));
        alice_storage
            .check_device_linking_flow(&alice_binding, "isolated-sdk-flow")
            .unwrap();

        drop(alice);
        let reopened = app
            .local_client_with_relay_plane_and_hydration("alice", &plane, None, true, None)
            .await
            .unwrap();
        assert!(matches!(
            alice_storage.check_device_linking_flow(&alice_binding, "isolated-sdk-flow"),
            Err(DeviceLinkingError::Terminal)
        ));
        let next = alice_storage
            .reserve_device_linking_attempt(&alice_account, &alice_device)
            .unwrap();
        assert_eq!(next, alice_binding.generation + 1);
        bob_storage
            .check_device_linking_flow(&bob_binding, "isolated-sdk-flow")
            .unwrap();
        assert!(matches!(
            bob_storage.reserve_device_linking_attempt(&bob_account, &bob_device),
            Err(DeviceLinkingError::Busy)
        ));
        drop(reopened);
        drop(bob);
    });
}

#[test]
fn device_linking_client_owns_actual_identity_and_fences_before_releasing_session() {
    run_composed_app_runtime_test("linking-client-owner", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let plane = MarmotRelayPlane::new(None, Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app
            .local_client_with_relay_plane("alice", &plane, None)
            .await
            .unwrap();
        let (storage, account, device) = scope(&app, "alice");
        let attempt = client.reserve_device_linking().unwrap();
        assert!(attempt.account == account);
        assert!(attempt.local_device == device);
        let private_package = client
            .runtime
            .session_mut()
            .resolve_linking_key_package(&attempt)
            .await
            .unwrap();
        let purpose = storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap();
        let retained_policy = client.linking_welcome_policy();
        assert!(matches!(
            retained_policy.begin_join(&purpose),
            Err(cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier)
        ));
        let binding = DeviceLinkingBinding {
            generation: attempt.generation,
            nonce: [3; 32],
            context_digest: [4; 32],
        };
        storage.bind_device_linking_context(&binding).unwrap();
        assert!(matches!(
            app.local_client_with_relay_plane("alice", &plane, None)
                .await,
            Err(AppError::AccountSessionBusy)
        ));
        storage.bind_device_linking_context(&binding).unwrap();
        assert!(
            storage
                .device_linking_key_package_storage()
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .is_some()
        );
        drop(client);
        assert!(matches!(
            retained_policy.begin_join(&purpose),
            Err(cgka_traits::device_linking_key_package::LinkingWelcomeDenied::Cancelled)
        ));
        // Teardown must fence while this client still holds the session lease.
        assert!(matches!(
            storage.bind_device_linking_context(&binding),
            Err(DeviceLinkingError::Terminal)
        ));
        let mut reopened = app
            .local_client_with_relay_plane("alice", &plane, None)
            .await
            .unwrap();
        assert!(
            storage
                .device_linking_key_package_storage()
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .is_none()
        );
        assert!(
            reopened
                .runtime
                .session()
                .durably_owned_key_packages()
                .unwrap()
                .iter()
                .all(|package| package != &private_package)
        );
        let next = reopened.reserve_device_linking().unwrap();
        assert_eq!(next.generation, attempt.generation + 1);
        assert!(next.account == account && next.local_device == device);
    });
}

#[test]
fn device_linking_client_cancellation_retires_only_its_unjoined_private_package() {
    run_composed_app_runtime_test("linking-client-cancel", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let plane = MarmotRelayPlane::new(None, Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app
            .local_client_with_relay_plane("alice", &plane, None)
            .await
            .unwrap();
        let (storage, account, device) = scope(&app, "alice");
        let ordinary_package = client
            .runtime
            .session_mut()
            .fresh_key_package()
            .await
            .unwrap();
        let ordinary = client
            .runtime
            .session()
            .durably_owned_key_packages()
            .unwrap();
        assert!(ordinary.contains(&ordinary_package));
        let prepared = client.prepare_device_linking().await.unwrap();
        assert!(prepared.scope.account == account && prepared.scope.local_device == device);
        let purpose = storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap();
        assert!(purpose.scope == prepared.scope && !purpose.consumed);
        assert!(
            client
                .runtime
                .session()
                .durably_owned_key_packages()
                .unwrap()
                .iter()
                .any(|package| package == &prepared.package)
        );
        client.cancel_device_linking().await.unwrap();
        assert!(
            storage
                .device_linking_key_package_storage()
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .is_none()
        );
        let remaining = client
            .runtime
            .session()
            .durably_owned_key_packages()
            .unwrap();
        assert!(remaining.iter().all(|package| package != &prepared.package));
        assert!(ordinary.iter().all(|package| remaining.contains(package)));
        client.cancel_device_linking().await.unwrap();
        let next = client.prepare_device_linking().await.unwrap();
        assert_eq!(next.scope.generation, prepared.scope.generation + 1);
        assert!(next.package != prepared.package);
    });
}

#[test]
fn device_linking_client_stale_cancel_cannot_retire_a_newer_preparation() {
    run_composed_app_runtime_test("linking-client-stale-cancel", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let plane = MarmotRelayPlane::new(None, Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app
            .local_client_with_relay_plane("alice", &plane, None)
            .await
            .unwrap();
        let (storage, _, _) = scope(&app, "alice");
        let old = client.prepare_device_linking().await.unwrap();
        client
            .cancel_device_linking_scope(&old.scope)
            .await
            .unwrap();
        let current = client.prepare_device_linking().await.unwrap();
        assert!(matches!(
            client.cancel_device_linking_scope(&old.scope).await,
            Err(crate::client::device_linking::ClientLinkingError::Owner(
                crate::device_linking::OwnerError::Verifier(
                    crate::device_linking::LinkError::StaleFlow
                )
            ))
        ));
        let mut wrong_identity = current.scope.clone();
        wrong_identity.local_device[0] ^= 1;
        assert!(matches!(
            client.cancel_device_linking_scope(&wrong_identity).await,
            Err(crate::client::device_linking::ClientLinkingError::Owner(
                crate::device_linking::OwnerError::Verifier(
                    crate::device_linking::LinkError::BindingMismatch
                )
            ))
        ));
        let purpose = storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap();
        assert!(purpose.scope == current.scope && !purpose.consumed);
        assert!(
            client
                .runtime
                .session()
                .durably_owned_key_packages()
                .unwrap()
                .contains(&current.package)
        );
        client
            .cancel_device_linking_scope(&current.scope)
            .await
            .unwrap();
        client
            .cancel_device_linking_scope(&current.scope)
            .await
            .unwrap();
        assert!(
            storage
                .device_linking_key_package_storage()
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn device_linking_client_deadline_cleanup_retires_only_expired_preparation() {
    run_composed_app_runtime_test("linking-client-deadline-cleanup", || async {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let plane = MarmotRelayPlane::new(None, Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app
            .local_client_with_relay_plane("alice", &plane, None)
            .await
            .unwrap();
        let (storage, _, _) = scope(&app, "alice");
        let ordinary = client
            .runtime
            .session_mut()
            .fresh_key_package()
            .await
            .unwrap();
        let prepared = client.prepare_device_linking().await.unwrap();
        client
            .maintain_device_linking(std::time::Instant::now())
            .await
            .unwrap();
        assert!(
            storage
                .device_linking_key_package_storage()
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .is_some()
        );
        let due = std::time::Instant::now() + std::time::Duration::from_secs(601);
        client.maintain_device_linking(due).await.unwrap();
        assert!(
            storage
                .device_linking_key_package_storage()
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .is_none()
        );
        let inventory = client
            .runtime
            .session()
            .durably_owned_key_packages()
            .unwrap();
        assert!(inventory.contains(&ordinary));
        assert!(!inventory.contains(&prepared.package));
        client.maintain_device_linking(due).await.unwrap();
        let next = client.prepare_device_linking().await.unwrap();
        assert_eq!(next.scope.generation, prepared.scope.generation + 1);
    });
}

#[cfg(feature = "test-policy-overrides")]
#[test]
fn device_linking_worker_commands_are_scoped_and_idle_cleanup_retries() {
    run_composed_app_runtime_test("linking-worker-lifecycle", || async {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        home.create_account("bob").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.reconcile_accounts().await.unwrap();
        let accounts = runtime.accounts();
        let old = accounts.prepare_device_linking("alice").await.unwrap();
        let bob = accounts.prepare_device_linking("bob").await.unwrap();
        accounts
            .cancel_device_linking("alice", &old.scope)
            .await
            .unwrap();
        let current = accounts.prepare_device_linking("alice").await.unwrap();
        assert!(matches!(
            accounts.cancel_device_linking("alice", &old.scope).await,
            Err(crate::client::device_linking::ClientLinkingError::Owner(
                crate::device_linking::OwnerError::Verifier(
                    crate::device_linking::LinkError::StaleFlow
                )
            ))
        ));
        let (alice_storage, _, _) = scope(&app, "alice");
        let (bob_storage, _, _) = scope(&app, "bob");
        assert!(
            bob_storage
                .device_linking_key_package_storage()
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .unwrap()
                .scope
                == bob.scope
        );
        let path = app.account_storage_path("alice");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let key = app
            .sqlcipher_key("alice", &keys, &path, SqlcipherDatabaseKind::Session)
            .unwrap();
        let injector = rusqlite::Connection::open(path).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &injector,
            &key,
            storage_sqlite::SqlCipherHardening::cipher_only(),
        )
        .unwrap();
        injector.execute_batch("CREATE TRIGGER reject_linking_retirement BEFORE DELETE ON device_linking_key_package BEGIN SELECT RAISE(ABORT,'injected retirement failure'); END;").unwrap();
        let due = std::time::Instant::now() + std::time::Duration::from_secs(601);
        assert!(
            accounts
                .maintain_device_linking_at_for_test("alice", due)
                .await
                .is_err()
        );
        assert!(
            alice_storage
                .device_linking_key_package_storage()
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .unwrap()
                .scope
                == current.scope
        );
        injector
            .execute_batch("DROP TRIGGER reject_linking_retirement;")
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if alice_storage
                    .device_linking_key_package_storage()
                    .unwrap()
                    .purpose_key_package()
                    .unwrap()
                    .is_none()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the independent worker tick must retry cleanup without another command");
        assert!(
            bob_storage
                .device_linking_key_package_storage()
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .unwrap()
                .scope
                == bob.scope
        );
        let next = accounts.prepare_device_linking("alice").await.unwrap();
        assert_eq!(next.scope.generation, current.scope.generation + 1);
        accounts
            .cancel_device_linking("alice", &next.scope)
            .await
            .unwrap();
        accounts
            .cancel_device_linking("bob", &bob.scope)
            .await
            .unwrap();
        runtime.shutdown().await;
    });
}

#[test]
fn device_linking_real_clients_arm_only_scoped_singleton_bootstrap() {
    run_composed_app_runtime_test("linking-client-bootstrap", || async {
        use crate::client::device_linking::ClientLinkingError;
        use crate::device_linking::{LinkingContext, Role};
        let keys = Keys::generate();
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        for dir in [&a_dir, &b_dir] {
            AccountHome::open(dir.path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
        }
        let a_app = MarmotApp::with_relay(a_dir.path(), "wss://relay.example");
        let b_app = MarmotApp::with_relay(b_dir.path(), "wss://relay.example");
        let plane = MarmotRelayPlane::new(None, Arc::new(ScriptedPushRelayClient::default()));
        let mut a = a_app
            .local_client_with_relay_plane("test", &plane, None)
            .await
            .unwrap();
        let mut b = b_app
            .local_client_with_relay_plane("test", &plane, None)
            .await
            .unwrap();
        let old = a.prepare_device_linking().await.unwrap();
        a.cancel_device_linking_scope(&old.scope).await.unwrap();
        let prepared = a.prepare_device_linking().await.unwrap();
        let b_scope = b.reserve_device_linking().unwrap();
        assert!(prepared.scope.account == b_scope.account);
        assert!(prepared.scope.local_device != b_scope.local_device);
        let origin = b.create_private_device_group_genesis().unwrap();
        let group = origin.group_id().clone();
        let candidate = origin.current();
        let metadata = cgka_engine::key_package::key_package_metadata(&prepared.package).unwrap();
        let context = LinkingContext {
            version: 1,
            nonce: [41; 32],
            new_device_generation: prepared.scope.generation,
            approver_generation: b_scope.generation,
            account: prepared.scope.account,
            exact_key_package: prepared.package.bytes.clone(),
            key_package_reference: hex::decode(metadata.key_package_ref_hex)
                .unwrap()
                .try_into()
                .unwrap(),
            device_group: group.as_slice().to_vec(),
            predecessor: crate::device_linking::PredecessorRoster::from_candidate(candidate)
                .unwrap(),
            approver: b_scope.local_device,
            recipient: prepared.scope.local_device,
        };
        assert!(matches!(
            a.begin_device_linking(&old.scope, context.clone(), Role::NewDevice)
                .await,
            Err(ClientLinkingError::Owner(
                crate::device_linking::OwnerError::Verifier(
                    crate::device_linking::LinkError::StaleFlow
                )
            ))
        ));
        let mut forged_package = context.clone();
        forged_package.exact_key_package[0] ^= 1;
        assert!(
            a.begin_device_linking(&prepared.scope, forged_package, Role::NewDevice)
                .await
                .is_err()
        );
        a.begin_device_linking(&prepared.scope, context.clone(), Role::NewDevice)
            .await
            .unwrap();
        b.begin_device_linking(&b_scope, context, Role::Approver)
            .await
            .unwrap();
        let (store, _, _) = scope(&a_app, "test");
        let purpose = store
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap();
        assert!(purpose.context.is_some());
        let ao = a.device_linking_offer(&prepared.scope).unwrap();
        let bo = b.device_linking_offer(&b_scope).unwrap();
        a.admit_device_linking_peer(&prepared.scope, &bo)
            .await
            .unwrap();
        b.admit_device_linking_peer(&b_scope, &ao).await.unwrap();
        assert!(
            a.take_device_linking_verified(&prepared.scope)
                .await
                .is_err()
        );
        a.start_device_linking_verification(&prepared.scope)
            .await
            .unwrap();
        for _ in 0..8 {
            drain_client_verifier(&mut a, &prepared.scope, &mut b, &b_scope).await;
            drain_client_verifier(&mut b, &b_scope, &mut a, &prepared.scope).await;
        }
        let digits = a.device_linking_decimals(&prepared.scope).unwrap();
        assert!(digits.is_some());
        assert!(digits == b.device_linking_decimals(&b_scope).unwrap());
        a.confirm_device_linking(&prepared.scope).await.unwrap();
        b.confirm_device_linking(&b_scope).await.unwrap();
        for _ in 0..8 {
            drain_client_verifier(&mut a, &prepared.scope, &mut b, &b_scope).await;
            drain_client_verifier(&mut b, &b_scope, &mut a, &prepared.scope).await;
        }
        a.arm_singleton_device_welcome(&prepared.scope)
            .await
            .unwrap();
        let purpose = store
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap();
        assert!(
            a.linking_welcome_policy().begin_join(&purpose).is_ok(),
            "genuine scoped singleton SAS must arm its exact recipient purpose"
        );
        assert!(a.cancel_device_linking_scope(&old.scope).await.is_err());
        assert!(
            a.linking_welcome_policy().begin_join(&purpose).is_ok(),
            "stale cancellation must preserve the current recipient lease"
        );
        a.cancel_device_linking_scope(&prepared.scope)
            .await
            .unwrap();
        assert!(
            a.linking_welcome_policy().begin_join(&purpose).is_err(),
            "matching cancellation must revoke recipient admission"
        );
    });
}

#[test]
fn device_linking_client_session_observes_authentic_chunk_without_join_permission() {
    run_composed_app_runtime_test("linking-session-observation", || async {
        use cgka_traits::peeler::{PrivateLinkingWelcomeContext, TransportPeeler};
        use cgka_traits::transport::EncryptedPayload;
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("test")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let plane = MarmotRelayPlane::new(None, Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app
            .local_client_with_relay_plane("test", &plane, None)
            .await
            .unwrap();
        let prepared = client.prepare_device_linking().await.unwrap();
        let metadata = cgka_engine::key_package::key_package_metadata(&prepared.package).unwrap();
        let payload = EncryptedPayload {
            ciphertext: vec![17; 100_000],
            aad: vec![],
        };
        // Opaque bytes/context exercise authentication forwarding only, not MLS.
        let context = PrivateLinkingWelcomeContext {
            account: prepared.scope.account,
            approver: [3; 32],
            recipient: prepared.scope.local_device,
            approver_generation: 1,
            recipient_generation: prepared.scope.generation,
            group_id: cgka_traits::GroupId::new(vec![17; 16]),
            nonce: [41; 32],
            context_digest: [42; 32],
            key_package_reference: hex::decode(metadata.key_package_ref_hex)
                .unwrap()
                .try_into()
                .unwrap(),
            key_package_digest: Sha256::digest(&prepared.package.bytes).into(),
            commit_digest: [9; 32],
            welcome_digest: Sha256::digest(&payload.ciphertext).into(),
        };
        let peeler = transport_nostr_peeler::NostrMlsPeeler::new()
            .with_welcome_signer_arc(client.transport_signer.clone());
        let messages = peeler
            .wrap_private_linking_welcome(&payload, &context)
            .await
            .unwrap();
        assert!(messages.len() > 1);
        let observation = client
            .runtime
            .session()
            .observe_private_linking_welcome(&messages[0])
            .await
            .unwrap();
        assert!(observation.context == context);
        assert_eq!(observation.index, 0);
        assert_eq!(observation.count, messages.len());
        assert_eq!(observation.total, payload.ciphertext.len());
        let purpose = app
            .account_storage("test")
            .unwrap()
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap();
        assert!(
            client
                .linking_welcome_policy()
                .begin_join(&purpose)
                .is_err(),
            "authenticated chunk metadata must not arm recipient admission"
        );
    });
}

#[test]
fn device_linking_real_clients_collect_and_join_singleton_without_chat_projection() {
    run_composed_app_runtime_test("linking-client-recipient-join", || async {
        use crate::client::device_linking::ClientLinkingError;
        use crate::device_linking::{LinkingContext, Role};
        let keys = Keys::generate();
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        for dir in [&a_dir, &b_dir] {
            AccountHome::open(dir.path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
        }
        let a_app = MarmotApp::with_relay(a_dir.path(), "wss://relay.example");
        let b_app = MarmotApp::with_relay(b_dir.path(), "wss://relay.example");
        let plane = MarmotRelayPlane::new(None, Arc::new(ScriptedPushRelayClient::default()));
        let mut a = a_app
            .local_client_with_relay_plane("test", &plane, None)
            .await
            .unwrap();
        let mut b = b_app
            .local_client_with_relay_plane("test", &plane, None)
            .await
            .unwrap();
        let old = a.prepare_device_linking().await.unwrap();
        a.cancel_device_linking_scope(&old.scope).await.unwrap();
        let prepared = a.prepare_device_linking().await.unwrap();
        let b_scope = b.reserve_device_linking().unwrap();
        assert!(prepared.scope.account == b_scope.account);
        assert!(prepared.scope.local_device != b_scope.local_device);
        let origin = b.create_private_device_group_genesis().unwrap();
        let group = origin.group_id().clone();
        let candidate = origin.current();
        let metadata = cgka_engine::key_package::key_package_metadata(&prepared.package).unwrap();
        let context = LinkingContext {
            version: 1,
            nonce: [41; 32],
            new_device_generation: prepared.scope.generation,
            approver_generation: b_scope.generation,
            account: prepared.scope.account,
            exact_key_package: prepared.package.bytes.clone(),
            key_package_reference: hex::decode(metadata.key_package_ref_hex)
                .unwrap()
                .try_into()
                .unwrap(),
            device_group: group.as_slice().to_vec(),
            predecessor: crate::device_linking::PredecessorRoster::from_candidate(candidate)
                .unwrap(),
            approver: b_scope.local_device,
            recipient: prepared.scope.local_device,
        };
        assert!(matches!(
            a.begin_device_linking(&old.scope, context.clone(), Role::NewDevice)
                .await,
            Err(ClientLinkingError::Owner(
                crate::device_linking::OwnerError::Verifier(
                    crate::device_linking::LinkError::StaleFlow
                )
            ))
        ));
        let mut forged_package = context.clone();
        forged_package.exact_key_package[0] ^= 1;
        assert!(
            a.begin_device_linking(&prepared.scope, forged_package, Role::NewDevice)
                .await
                .is_err()
        );
        a.begin_device_linking(&prepared.scope, context.clone(), Role::NewDevice)
            .await
            .unwrap();
        b.begin_device_linking(&b_scope, context, Role::Approver)
            .await
            .unwrap();
        let (store, _, _) = scope(&a_app, "test");
        let purpose = store
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap();
        assert!(purpose.context.is_some());
        let ao = a.device_linking_offer(&prepared.scope).unwrap();
        let bo = b.device_linking_offer(&b_scope).unwrap();
        a.admit_device_linking_peer(&prepared.scope, &bo)
            .await
            .unwrap();
        b.admit_device_linking_peer(&b_scope, &ao).await.unwrap();
        assert!(
            a.take_device_linking_verified(&prepared.scope)
                .await
                .is_err()
        );
        a.start_device_linking_verification(&prepared.scope)
            .await
            .unwrap();
        for _ in 0..8 {
            drain_client_verifier(&mut a, &prepared.scope, &mut b, &b_scope).await;
            drain_client_verifier(&mut b, &b_scope, &mut a, &prepared.scope).await;
        }
        let digits = a.device_linking_decimals(&prepared.scope).unwrap();
        assert!(digits.is_some());
        assert!(digits == b.device_linking_decimals(&b_scope).unwrap());
        a.confirm_device_linking(&prepared.scope).await.unwrap();
        b.confirm_device_linking(&b_scope).await.unwrap();
        for _ in 0..8 {
            drain_client_verifier(&mut a, &prepared.scope, &mut b, &b_scope).await;
            drain_client_verifier(&mut b, &b_scope, &mut a, &prepared.scope).await;
        }
        a.arm_singleton_device_welcome(&prepared.scope)
            .await
            .unwrap();
        // This qualifies only recipient admission of genuine prepared transport.
        // It does not claim confirmed sender delivery or settled roster authority.
        b.prepare_private_device_invite(&b_scope).await.unwrap();
        let (b_store, _, _) = scope(&b_app, "test");
        let fact = b_store
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            .unwrap();
        let messages = fact.transport.unwrap().welcomes;
        assert!(!messages.is_empty());
        assert!(
            a.collect_private_device_welcome(&old.scope, messages[0].clone())
                .await
                .is_err()
        );
        let mut joined = None;
        for (index, message) in messages.iter().enumerate() {
            let result = a
                .collect_private_device_welcome(&prepared.scope, message.clone())
                .await
                .expect(
                    "real owned recipient must collect through Session and join its exact Welcome",
                );
            if index + 1 < messages.len() {
                assert!(result.is_none());
            }
            joined = result;
        }
        assert!(joined.as_ref() == Some(&group));
        assert_eq!(
            a.runtime.session().epoch(&group).unwrap(),
            cgka_traits::EpochId(1)
        );
        let purpose = store
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap();
        assert!(purpose.consumed);
        assert!(
            store
                .accepted_device_group_anchor_storage()
                .unwrap()
                .accepted_anchor()
                .unwrap()
                .is_some()
        );
        a.reconcile_live_engine_groups().unwrap();
        assert!(
            a.state.groups.is_empty(),
            "private recipient membership must not create chat state"
        );
        assert!(
            a.collect_private_device_welcome(&prepared.scope, messages[0].clone())
                .await
                .is_err(),
            "consumed original verifier cannot grant another admission"
        );
    });
}
