#[cfg(not(feature = "experimental-device-sync"))]
use super::*;
#[cfg(not(feature = "experimental-device-sync"))]
use crate::{MarmotApp, MarmotAppRuntime};

#[cfg(not(feature = "experimental-device-sync"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_selected_chat_copy_is_unsupported_before_account_or_worker_effects() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), "wss://relay.example"));
    let accounts = runtime.accounts();
    assert!(matches!(
        accounts
            .begin_selected_chat_copy("missing", &GroupId::new(vec![]), vec![0; 600_000])
            .await,
        Err(SelectedChatCopyError::Unsupported)
    ));
    let request = SelectedChatCopy { _private: () };
    assert!(matches!(
        request.snapshot().await,
        Err(SelectedChatCopyError::Unsupported)
    ));
    assert!(matches!(
        request.continue_copy(0).await,
        Err(SelectedChatCopyError::Unsupported)
    ));
    assert!(matches!(
        request.cancel().await,
        Err(SelectedChatCopyError::Unsupported)
    ));
    assert!(matches!(
        request.request_packet(0).await,
        Err(SelectedChatCopyError::Unsupported)
    ));
    assert!(matches!(
        request.receive_consent_packet(0, vec![0; 600_000]).await,
        Err(SelectedChatCopyError::Unsupported)
    ));
    assert!(matches!(
        request.receive_offer_packet(0, vec![0; 600_000]).await,
        Err(SelectedChatCopyError::Unsupported)
    ));
    assert!(matches!(
        accounts
            .receive_selected_chat_copy_request("missing", vec![0; 600_000])
            .await,
        Err(SelectedChatCopyError::Unsupported)
    ));
    let consent = SelectedChatConsent { _private: () };
    assert!(matches!(
        consent.snapshot().await,
        Err(SelectedChatCopyError::Unsupported)
    ));
    assert!(matches!(
        consent.approve(0).await,
        Err(SelectedChatCopyError::Unsupported)
    ));
    assert!(matches!(
        consent.response_packet(0).await,
        Err(SelectedChatCopyError::Unsupported)
    ));
    assert!(matches!(
        consent.offer_packet(0).await,
        Err(SelectedChatCopyError::Unsupported)
    ));
    assert!(matches!(
        consent.cancel().await,
        Err(SelectedChatCopyError::Unsupported)
    ));
    assert!(accounts.managed_accounts().unwrap().is_empty());
    runtime.shutdown_and_close().await.unwrap();
}

#[cfg(all(
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
mod actual {
    use crate::native_device_linking::*;
    use crate::{MarmotApp, MarmotAppRuntime};
    use cgka_traits::{
        MessageStorage, OutboundFanoutStorage,
        storage::{KeyPackageBundleStorage, StorageProvider},
    };
    use marmot_account::AccountHome;
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invalid_selected_chat_bounds_refuse_before_account_or_worker_effects() {
        let dir = tempfile::tempdir().unwrap();
        let runtime =
            MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), "wss://relay.example"));
        let accounts = runtime.accounts();
        for (group, selector) in [
            (cgka_traits::GroupId::new(vec![]), vec![1]),
            (cgka_traits::GroupId::new(vec![1; 257]), vec![2]),
            (cgka_traits::GroupId::new(vec![1]), vec![]),
            (cgka_traits::GroupId::new(vec![1]), vec![2; 257]),
            (cgka_traits::GroupId::new(vec![1]), vec![1]),
        ] {
            assert!(matches!(
                accounts
                    .begin_selected_chat_copy("missing", &group, selector)
                    .await,
                Err(crate::SelectedChatCopyError::InvalidSelection)
            ));
        }
        assert!(accounts.managed_accounts().unwrap().is_empty());
        runtime.shutdown_and_close().await.unwrap();
    }
    async fn drain(from: &DeviceLinkingSession, to: &DeviceLinkingSession) {
        for packet in from.outgoing_packets().await.unwrap() {
            to.receive_packet(packet.bytes).await.unwrap();
            from.acknowledge_packet(packet.acknowledgement_id)
                .await
                .unwrap();
        }
    }

    async fn verify_public_pair(a: &DeviceLinkingSession, c: &DeviceLinkingSession) {
        c.receive_setup_packet(a.setup_packet()).await.unwrap();
        for _ in 0..8 {
            drain(a, c).await;
            drain(c, a).await;
        }
        let ac = a.snapshot().await.unwrap();
        let cc = c.snapshot().await.unwrap();
        assert_eq!(ac.phase, DeviceLinkingPhase::ComparisonAvailable);
        assert_eq!(ac.decimals, cc.decimals);
        a.confirm_comparison(ac.revision).await.unwrap();
        c.confirm_comparison(cc.revision).await.unwrap();
        for _ in 0..8 {
            drain(a, c).await;
            drain(c, a).await;
        }
        assert_eq!(
            a.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending
        );
        assert_eq!(
            c.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending
        );
    }
    async fn wait_actual_roster(apps: &[MarmotApp], leaves: usize) {
        use cgka_traits::StorageProvider;
        use cgka_traits::private_roster_settlement::PrivateSettlementPhase;
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if apps.iter().all(|app| {
                    let storage = app.account_storage("test").unwrap();
                    let store = storage.private_roster_settlement_storage().unwrap();
                    store.read_round().unwrap().is_some_and(|r| {
                        r.phase == PrivateSettlementPhase::Completed
                            && r.anchor.successor.leaves.len() == leaves
                            && store.read_facts().unwrap().len() == leaves
                    })
                }) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("all original native devices must settle their actual complete indexed roster");
    }

    struct SelectedChatFixture {
        _relay: nostr_relay_builder::LocalRelay,
        dirs: [tempfile::TempDir; 3],
        _d_dir: tempfile::TempDir,
        url: String,
        apps: [MarmotApp; 3],
        runtimes: [MarmotAppRuntime; 3],
        d_app: MarmotApp,
        d_runtime: MarmotAppRuntime,
        chat: cgka_traits::GroupId,
        chat_hex: String,
        before_id: String,
        _a: DeviceLinkingSession,
        _c: DeviceLinkingSession,
        _approval: DeviceLinkingApproval,
    }

    async fn actual_selected_chat_fixture() -> SelectedChatFixture {
        actual_selected_chat_fixture_with_consent_lifetime(None).await
    }

    async fn actual_selected_chat_fixture_with_consent_lifetime(
        lifetime: Option<std::time::Duration>,
    ) -> SelectedChatFixture {
        let relay =
            nostr_relay_builder::LocalRelay::new(nostr_relay_builder::RelayBuilder::default());
        relay.run().await.unwrap();
        let url = relay.url().await.to_string();
        let keys = nostr::prelude::Keys::generate();
        let dirs: [tempfile::TempDir; 3] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
        let apps = std::array::from_fn::<_, 3, _>(|i| {
            AccountHome::open(dirs[i].path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
            let mut app = MarmotApp::with_relay(dirs[i].path(), &url);
            if i == 1 {
                app.selected_chat_consent_test_lifetime = lifetime;
            }
            app
        });
        let runtimes = apps.clone().map(MarmotAppRuntime::new);
        for r in &runtimes {
            r.reconcile_accounts().await.unwrap();
        }
        let managers = runtimes.each_ref().map(|r| r.accounts());
        let b = managers[1]
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let initial_a = managers[0]
            .approve_device_linking_session("test", b.setup_packet(), None)
            .await
            .unwrap();
        verify_public_pair(&initial_a, &b).await;
        b.continue_linking(b.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        initial_a
            .continue_linking(initial_a.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        wait_actual_roster(&apps[..2], 2).await;
        initial_a.cancel().await.unwrap();
        b.cancel().await.unwrap();
        let targets = managers[0]
            .device_linking_targets("test")
            .await
            .expect("public discovery must authenticate the completed original two-device target");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].device_count, 2);
        let c = managers[2]
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let a = managers[0]
            .approve_device_linking_session(
                "test",
                c.setup_packet(),
                Some(targets[0].selector.clone()),
            )
            .await
            .unwrap();
        verify_public_pair(&a, &c).await;
        c.continue_linking(c.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        a.continue_linking(a.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        let approval = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let mut pending = managers[1]
                    .pending_device_linking_approvals("test")
                    .await
                    .unwrap();
                if let Some(p) = pending.pop() {
                    break p;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("B must receive A's actual encrypted proposal as an opaque native action");
        approval
            .approve(approval.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        let packet = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if let Ok(packet) = a
                    .enrollment_packet(a.snapshot().await.unwrap().revision)
                    .await
                {
                    break packet;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("original A must collect B's authentic endorsement");
        c.receive_enrollment_packet(c.snapshot().await.unwrap().revision, packet.clone())
            .await
            .unwrap();
        approval
            .receive_enrollment_packet(approval.snapshot().await.unwrap().revision, packet)
            .await
            .unwrap();
        a.finalize_linking(a.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        wait_actual_roster(&apps, 3).await;
        assert_eq!(
            a.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::EnrollmentComplete
        );
        assert_eq!(
            c.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::EnrollmentComplete
        );
        assert_eq!(
            approval.snapshot().await.unwrap().phase,
            DeviceLinkingApprovalPhase::Settled
        );

        // D has an independent account/device and ordinary public KeyPackage.
        // Nothing copies a database, private MLS state, or ratchet into B/C.
        let d_dir = tempfile::tempdir().unwrap();
        let d_keys = nostr::prelude::Keys::generate();
        let d_account = AccountHome::open(d_dir.path())
            .import_account("test", &d_keys.secret_key().to_secret_hex())
            .unwrap();
        let d_app = MarmotApp::with_relay(d_dir.path(), &url);
        let d_runtime = MarmotAppRuntime::new(d_app.clone());
        d_runtime.reconcile_accounts().await.unwrap();
        crate::tests::remember_test_member_inbox(&apps[0], &d_account.account_id_hex, &url);
        d_runtime.publish_key_package("test").await.unwrap();
        let chat = runtimes[0]
            .create_group(
                "test",
                "Selected ordinary chat",
                std::slice::from_ref(&d_account.account_id_hex),
                None,
            )
            .await
            .unwrap();
        let chat_hex = hex::encode(chat.as_slice());
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if d_app.group("test", &chat_hex).unwrap().is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("D must really join A's ordinary chat over the relay");
        for runtime in [&runtimes[0], &d_runtime] {
            let state = runtime.group_mls_state("test", &chat).await.unwrap();
            assert_eq!(state.protocol_profile, crate::AppProtocolProfile::Current);
            assert_eq!(state.member_count, 2);
        }
        let before = runtimes[0]
            .send_message("test", &chat, b"before sibling chat consent".to_vec())
            .await
            .unwrap();
        assert_eq!(before.message_ids.len(), 1);
        let before_id = before.message_ids[0].clone();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if d_app
                    .timeline_message("test", &chat_hex, &before_id)
                    .unwrap()
                    .is_some()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("prejoin ordinary message must reach actual D projection");
        for app in &apps[1..] {
            assert!(app.group("test", &chat_hex).unwrap().is_none());
            assert!(
                app.timeline_message("test", &chat_hex, &before_id)
                    .unwrap()
                    .is_none()
            );
        }
        SelectedChatFixture {
            _relay: relay,
            dirs,
            _d_dir: d_dir,
            url,
            apps,
            runtimes,
            d_app,
            d_runtime,
            chat,
            chat_hex,
            before_id,
            _a: a,
            _c: c,
            _approval: approval,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn selected_chat_copy_requires_explicit_request_after_public_three_device_linking() {
        let SelectedChatFixture {
            _relay: relay,
            dirs,
            _d_dir,
            url,
            apps,
            runtimes,
            d_app: _,
            d_runtime,
            chat,
            chat_hex,
            before_id,
            _a,
            _c,
            _approval,
        } = actual_selected_chat_fixture().await;
        let managers = runtimes.each_ref().map(|runtime| runtime.accounts());
        // D is a genuinely joined nonadmin of this actual Current A/D chat.
        // Refuse its ordinary role before any protected-roster target lookup.
        let role = d_runtime.group_roster("test", &chat).await.unwrap();
        assert!(
            role.members
                .iter()
                .any(|member| member.is_self && !member.is_admin)
        );
        let target = managers[0]
            .device_linking_targets("test")
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(target.device_count, 3);
        let before_bundles: Vec<_> = apps
            .iter()
            .map(|app| {
                app.account_storage("test")
                    .unwrap()
                    .stored_key_package_bundles()
                    .unwrap()
            })
            .collect();
        let before_fanouts: Vec<_> = apps
            .iter()
            .map(|app| {
                app.account_storage("test")
                    .unwrap()
                    .list_outbound_fanouts()
                    .unwrap()
            })
            .collect();
        let request = managers[0]
            .begin_selected_chat_copy("test", &chat, target.selector.clone())
            .await
            .expect("explicit ordinary admin request must retain a new independent original owner");
        assert!(matches!(
            managers[0]
                .begin_selected_chat_copy("test", &chat, vec![])
                .await,
            Err(crate::SelectedChatCopyError::InvalidSelection)
        ));
        assert!(matches!(
            d_runtime
                .accounts()
                .begin_selected_chat_copy("test", &chat, target.selector.clone())
                .await,
            Err(crate::SelectedChatCopyError::NotAdmin)
        ));
        assert!(matches!(
            managers[0]
                .begin_selected_chat_copy("test", &chat, target.selector.clone())
                .await,
            Err(crate::SelectedChatCopyError::Busy)
        ));
        let snapshot = request.snapshot().await.unwrap();
        assert_eq!(
            snapshot.phase,
            crate::SelectedChatCopyPhase::AwaitingSiblingConsent
        );
        assert_eq!(snapshot.sibling_count, 2);
        assert!(snapshot.revision > 0);
        let request_packet = request
            .request_packet(snapshot.revision)
            .await
            .expect("original selected-chat request must export an authenticated consent request");
        assert_eq!(snapshot.consenting_sibling_count, 0);
        assert!(
            managers[0]
                .receive_selected_chat_copy_request("test", request_packet.clone())
                .await
                .is_err()
        );
        assert!(
            d_runtime
                .accounts()
                .receive_selected_chat_copy_request("test", request_packet.clone())
                .await
                .is_err()
        );
        let mut malformed = request_packet.clone();
        malformed[0] ^= 1;
        assert!(
            managers[1]
                .receive_selected_chat_copy_request("test", malformed)
                .await
                .is_err()
        );
        let mut siblings = Vec::new();
        let mut original_responses = Vec::new();
        for manager in &managers[1..] {
            let consent = manager
                .receive_selected_chat_copy_request("test", request_packet.clone())
                .await
                .unwrap();
            let alias = manager
                .receive_selected_chat_copy_request("test", request_packet.clone())
                .await
                .unwrap();
            drop(alias);
            let received = consent.snapshot().await.unwrap();
            assert_eq!(
                received.phase,
                crate::SelectedChatConsentPhase::AwaitingApproval
            );
            assert_eq!(received.chat_selector, chat.as_slice());
            assert!(consent.response_packet(received.revision).await.is_err());
            consent.approve(received.revision).await.unwrap();
            let approved = consent.snapshot().await.unwrap();
            assert_eq!(approved.phase, crate::SelectedChatConsentPhase::Approved);
            assert!(matches!(
                consent.approve(received.revision).await,
                Err(crate::SelectedChatCopyError::StaleRevision)
            ));
            assert!(matches!(
                consent.response_packet(received.revision).await,
                Err(crate::SelectedChatCopyError::StaleRevision)
            ));
            let response = consent.response_packet(approved.revision).await.unwrap();
            assert!(response == consent.response_packet(approved.revision).await.unwrap());
            let mut malformed = response.clone();
            malformed[0] ^= 1;
            assert!(
                request
                    .receive_consent_packet(request.snapshot().await.unwrap().revision, malformed)
                    .await
                    .is_err()
            );
            assert!(matches!(
                request.receive_consent_packet(0, response.clone()).await,
                Err(crate::SelectedChatCopyError::StaleRevision)
            ));
            original_responses.push(response.clone());
            request
                .receive_consent_packet(request.snapshot().await.unwrap().revision, response)
                .await
                .unwrap();
            let collected = request.snapshot().await.unwrap();
            assert_eq!(
                collected.consenting_sibling_count,
                siblings.len() as u32 + 1
            );
            request
                .receive_consent_packet(
                    collected.revision,
                    original_responses.last().unwrap().clone(),
                )
                .await
                .unwrap();
            assert_eq!(
                request.snapshot().await.unwrap().revision,
                collected.revision
            );
            assert!(request.request_packet(collected.revision).await.unwrap() == request_packet);
            siblings.push(consent);
        }
        // The original approved B owner must survive a real SQL failure;
        // the generated private bundle and purpose row roll back together.
        let package_storage_path = apps[1].account_storage_path("test");
        let package_keys = apps[1].account_home().load_signing_keys("test").unwrap();
        let package_sql_key = apps[1]
            .sqlcipher_key(
                "test",
                &package_keys,
                &package_storage_path,
                crate::sqlcipher::SqlcipherDatabaseKind::Session,
            )
            .unwrap();
        let package_injector = rusqlite::Connection::open(&package_storage_path).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &package_injector,
            &package_sql_key,
            storage_sqlite::SqlCipherHardening::cipher_only(),
        )
        .unwrap();
        package_injector.execute_batch("CREATE TRIGGER reject_selected_package BEFORE INSERT ON selected_chat_key_packages BEGIN SELECT RAISE(ABORT,'isolated selected package rollback'); END;").unwrap();
        let approved_b = siblings[0].snapshot().await.unwrap();
        assert!(siblings[0].offer_packet(approved_b.revision).await.is_err());
        let b_storage = apps[1].account_storage("test").unwrap();
        assert!(b_storage.stored_key_package_bundles().unwrap() == before_bundles[1]);
        assert!(
            b_storage
                .selected_chat_key_package_storage()
                .unwrap()
                .selected_chat_key_packages()
                .unwrap()
                .is_empty()
        );
        package_injector
            .execute_batch("DROP TRIGGER reject_selected_package;")
            .unwrap();
        for (index, consent) in siblings.iter().enumerate() {
            let current = consent.snapshot().await.unwrap();
            let offer = consent.offer_packet(current.revision).await.expect(
                "original approved sibling must export one independent private package offer",
            );
            assert!(offer == consent.offer_packet(current.revision).await.unwrap());
            let revision = request.snapshot().await.unwrap().revision;
            assert!(matches!(
                request.receive_offer_packet(0, offer.clone()).await,
                Err(crate::SelectedChatCopyError::StaleRevision)
            ));
            let marker = b"\"signature\":[";
            let start = offer
                .windows(marker.len())
                .position(|bytes| bytes == marker)
                .unwrap()
                + marker.len();
            let end = start
                + offer[start..]
                    .iter()
                    .position(|byte| *byte == b',' || *byte == b']')
                    .unwrap();
            let mut forged = offer.clone();
            // Flip a decimal value, retaining valid canonical JSON and byte range.
            forged[end - 1] ^= 1;
            let _: serde_json::Value = serde_json::from_slice(&forged).unwrap();
            let mut invalid_carriers = Vec::new();
            // Mutations retain canonical framing, so they reach authenticated
            // transport identity/content/reference validation rather than a
            // malformed JSON rejection.
            for marker in [b"\"sig\":\"".as_slice(), b"\"content\":\"", b"[\"i\",\""] {
                let position = offer
                    .windows(marker.len())
                    .position(|bytes| bytes == marker)
                    .unwrap()
                    + marker.len();
                let mut changed = offer.clone();
                changed[position] = if changed[position] == b'0' {
                    b'1'
                } else {
                    b'0'
                };
                let _: serde_json::Value = serde_json::from_slice(&changed).unwrap();
                invalid_carriers.push(changed);
            }
            for invalid in [
                offer[..offer.len() - 1].to_vec(),
                vec![0; cgka_engine::selected_chat_consent::MAX_SELECTED_CHAT_PACKET_BYTES + 1],
                forged,
            ]
            .into_iter()
            .chain(invalid_carriers)
            {
                assert!(matches!(
                    request.receive_offer_packet(revision, invalid).await,
                    Err(crate::SelectedChatCopyError::InvalidPacket)
                ));
                let unchanged = request.snapshot().await.unwrap();
                assert_eq!(unchanged.revision, revision);
                assert_eq!(unchanged.offered_sibling_count, index as u32);
            }
            request
                .receive_offer_packet(revision, offer.clone())
                .await
                .expect(
                    "original request must collect authentic offers from its approved siblings",
                );
            let collected = request.snapshot().await.unwrap();
            assert_eq!(collected.offered_sibling_count, index as u32 + 1);
            request
                .receive_offer_packet(collected.revision, offer)
                .await
                .unwrap();
            assert_eq!(
                request.snapshot().await.unwrap().revision,
                collected.revision
            );
        }
        for (i, app) in apps.iter().enumerate() {
            let storage = app.account_storage("test").unwrap();
            // Compare private material without formatting it on a failed assertion.
            let owned = storage.stored_key_package_bundles().unwrap();
            if i == 0 {
                assert!(owned == before_bundles[i]);
            } else {
                assert_eq!(owned.len(), before_bundles[i].len() + 1);
                let rows = storage
                    .selected_chat_key_package_storage()
                    .unwrap()
                    .selected_chat_key_packages()
                    .unwrap();
                assert_eq!(rows.len(), 1);
                assert!(rows[0].state == cgka_traits::selected_chat_key_package::SelectedChatPurposeState::Pending);
            }
            assert!(storage.list_outbound_fanouts().unwrap() == before_fanouts[i]);
        }
        for app in &apps[1..] {
            assert!(app.group("test", &chat_hex).unwrap().is_none());
            assert!(
                app.timeline_message("test", &chat_hex, &before_id)
                    .unwrap()
                    .is_none()
            );
        }
        for runtime in [&runtimes[0], &d_runtime] {
            assert_eq!(
                runtime
                    .group_mls_state("test", &chat)
                    .await
                    .unwrap()
                    .member_count,
                2
            );
        }
        assert_eq!(
            request.snapshot().await.unwrap().consenting_sibling_count,
            2
        );
        siblings[0].cancel().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let storage = apps[1].account_storage("test").unwrap();
                let rows = storage
                    .selected_chat_key_package_storage()
                    .unwrap()
                    .selected_chat_key_packages()
                    .unwrap();
                if rows.len() == 1
                    && rows[0].state
                        == cgka_traits::selected_chat_key_package::SelectedChatPurposeState::Denied
                {
                    assert!(storage.stored_key_package_bundles().unwrap() == before_bundles[1]);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("cancelled original private package must retire exactly");
        assert!(
            apps[2]
                .account_storage("test")
                .unwrap()
                .selected_chat_key_package_storage()
                .unwrap()
                .selected_chat_key_packages()
                .unwrap()[0]
                .state
                == cgka_traits::selected_chat_key_package::SelectedChatPurposeState::Pending
        );
        assert!(
            siblings[0]
                .response_packet(siblings[0].snapshot().await.unwrap().revision)
                .await
                .is_err()
        );
        assert!(
            managers[1]
                .receive_selected_chat_copy_request("test", request_packet.clone())
                .await
                .is_err()
        );
        request.cancel().await.unwrap();
        assert_eq!(
            request.snapshot().await.unwrap().phase,
            crate::SelectedChatCopyPhase::Cancelled
        );
        let replacement = managers[0]
            .begin_selected_chat_copy("test", &chat, target.selector.clone())
            .await
            .unwrap();
        let fresh_packet = replacement
            .request_packet(replacement.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        assert!(
            replacement
                .receive_consent_packet(
                    replacement.snapshot().await.unwrap().revision,
                    original_responses[0].clone()
                )
                .await
                .is_err()
        );
        assert_eq!(
            replacement
                .snapshot()
                .await
                .unwrap()
                .consenting_sibling_count,
            0
        );
        let fresh_consent = managers[1]
            .receive_selected_chat_copy_request("test", fresh_packet.clone())
            .await
            .unwrap();
        siblings[0].cancel().await.unwrap();
        assert_eq!(
            fresh_consent.snapshot().await.unwrap().phase,
            crate::SelectedChatConsentPhase::AwaitingApproval
        );
        let fresh_revision = fresh_consent.snapshot().await.unwrap().revision;
        fresh_consent.approve(fresh_revision).await.unwrap();
        let fresh_revision = fresh_consent.snapshot().await.unwrap().revision;
        let fresh_offer = fresh_consent.offer_packet(fresh_revision).await.unwrap();
        let fresh_alias = managers[1]
            .receive_selected_chat_copy_request("test", fresh_packet.clone())
            .await
            .unwrap();
        drop(fresh_alias);
        assert!(fresh_consent.offer_packet(fresh_revision).await.unwrap() == fresh_offer);
        siblings[0].cancel().await.unwrap();
        assert!(
            apps[1]
                .account_storage("test")
                .unwrap()
                .selected_chat_key_package_storage()
                .unwrap()
                .selected_chat_key_packages()
                .unwrap()
                .iter()
                .any(|row| row.state
                    == cgka_traits::selected_chat_key_package::SelectedChatPurposeState::Pending)
        );
        drop(fresh_consent);
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let storage = apps[1].account_storage("test").unwrap();
                let rows = storage.selected_chat_key_package_storage().unwrap().selected_chat_key_packages().unwrap();
                if rows.len() == 2 && rows.iter().all(|row| row.state == cgka_traits::selected_chat_key_package::SelectedChatPurposeState::Denied) {
                    assert!(storage.stored_key_package_bundles().unwrap() == before_bundles[1]);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }).await.expect("last shared original handle must retire its exact package");
        assert!(
            managers[1]
                .receive_selected_chat_copy_request("test", fresh_packet)
                .await
                .is_err()
        );
        // Cancelling an old request must not retire a newer original owner.
        request.cancel().await.unwrap();
        assert_eq!(
            replacement.snapshot().await.unwrap().phase,
            crate::SelectedChatCopyPhase::AwaitingSiblingConsent
        );
        drop(replacement);
        let after_drop = managers[0]
            .begin_selected_chat_copy("test", &chat, target.selector)
            .await
            .unwrap();
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
        assert_eq!(
            after_drop.snapshot().await.unwrap().phase,
            crate::SelectedChatCopyPhase::Closed
        );
        assert_eq!(
            siblings[1].snapshot().await.unwrap().phase,
            crate::SelectedChatConsentPhase::Closed
        );
        let reopened_app = MarmotApp::with_relay(dirs[2].path(), &url);
        let reopened = reopened_app.client("test").await.unwrap();
        let reopened_storage = reopened_app.account_storage("test").unwrap();
        assert!(reopened_storage.stored_key_package_bundles().unwrap() == before_bundles[2]);
        let abandoned = reopened_storage
            .selected_chat_key_package_storage()
            .unwrap()
            .selected_chat_key_packages()
            .unwrap();
        assert_eq!(abandoned.len(), 1);
        assert!(
            abandoned[0].state
                == cgka_traits::selected_chat_key_package::SelectedChatPurposeState::Denied
        );
        drop(reopened);
        d_runtime.shutdown_and_close().await.unwrap();
        relay.shutdown();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn selected_chat_copy_admits_original_siblings_and_delivers_new_messages() {
        selected_chat_delivery(RecipientAdmissionScenario::None).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn selected_chat_welcome_storage_failure_retains_original_consent_for_retry() {
        selected_chat_delivery(RecipientAdmissionScenario::Retry).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn selected_chat_welcome_cancel_during_storage_retry_cannot_admit_or_deliver() {
        selected_chat_delivery(RecipientAdmissionScenario::Cancel).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn selected_chat_welcome_original_expiry_during_storage_retry_cannot_admit_or_deliver() {
        selected_chat_delivery(RecipientAdmissionScenario::Expire).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn selected_chat_welcome_foreign_package_event_refuses_without_consuming_original() {
        selected_chat_delivery(RecipientAdmissionScenario::ForeignPackageEvent).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn selected_chat_blocked_commit_cancel_prevents_late_publication() {
        selected_chat_delivery(RecipientAdmissionScenario::CommitCancel).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn selected_chat_blocked_commit_lost_reply_prevents_late_publication() {
        selected_chat_delivery(RecipientAdmissionScenario::CommitLostReply).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn selected_chat_blocked_welcome_cancel_preserves_confirmation_without_late_join() {
        selected_chat_delivery(RecipientAdmissionScenario::WelcomeCancel).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn selected_chat_blocked_welcome_lost_reply_preserves_confirmation_without_late_join() {
        selected_chat_delivery(RecipientAdmissionScenario::WelcomeLostReply).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_recipient_query_observes_actual_linked_leaves_without_creating_originals() {
        selected_chat_delivery(RecipientAdmissionScenario::HistoryRecipientQuery).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_transfer_requires_original_recipient_consent_and_committed_prejoin_record() {
        selected_chat_delivery(RecipientAdmissionScenario::HistoryTransfer).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_transfer_cancelled_original_cannot_restart_from_fresh_outer_request() {
        selected_chat_delivery(RecipientAdmissionScenario::HistoryRequestReplay).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_transfer_expired_unpruned_source_never_serializes_plaintext() {
        selected_chat_delivery(RecipientAdmissionScenario::HistoryExpiredUnpruned).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_transfer_cancelled_prefix_cleanup_retries_original_sql_failure() {
        selected_chat_delivery(RecipientAdmissionScenario::HistoryCleanupRetry).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_transfer_committed_import_remains_observable_after_original_cancel_before_seal()
     {
        selected_chat_delivery(RecipientAdmissionScenario::HistoryCancelAfterImport).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_transfer_original_cancel_interrupts_actual_blocked_chunk_publication() {
        selected_chat_delivery(RecipientAdmissionScenario::HistoryPublicationCancel).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_transfer_lost_continue_reply_interrupts_actual_blocked_chunk_publication() {
        selected_chat_delivery(RecipientAdmissionScenario::HistoryPublicationLostReply).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_transfer_original_fixed_expiry_interrupts_actual_blocked_chunk_publication() {
        selected_chat_delivery(RecipientAdmissionScenario::HistoryPublicationExpire).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_transfer_runtime_shutdown_interrupts_actual_blocked_chunk_publication() {
        selected_chat_delivery(RecipientAdmissionScenario::HistoryPublicationShutdown).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_transfer_cancelled_original_cannot_restart_after_encrypted_recipient_reopen() {
        selected_chat_delivery(RecipientAdmissionScenario::HistoryRequestReopen).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn group_device_revocation_requires_fresh_original_for_exact_same_account_leaf() {
        selected_chat_delivery(RecipientAdmissionScenario::DeviceLeafRevocation).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn group_device_revocation_approved_original_removes_only_one_occupied_leaf() {
        selected_chat_delivery(RecipientAdmissionScenario::DeviceLeafRemoval).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn group_device_revocation_original_cancel_interrupts_actual_blocked_remove_publication()
    {
        selected_chat_delivery(RecipientAdmissionScenario::DeviceLeafRemovalCancel).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn group_device_revocation_lost_approval_reply_interrupts_actual_blocked_remove_publication()
     {
        selected_chat_delivery(RecipientAdmissionScenario::DeviceLeafRemovalLostReply).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn group_device_revocation_removed_leaf_stays_evicted_after_encrypted_reopen() {
        selected_chat_delivery(RecipientAdmissionScenario::DeviceLeafRemovalReopen).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_revocation_original_removes_exact_leaf_from_protected_and_two_ordinary_groups()
    {
        selected_chat_delivery(RecipientAdmissionScenario::DeviceRosterRemoval).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_revocation_survivors_regain_fresh_original_history_authority() {
        selected_chat_delivery(RecipientAdmissionScenario::DeviceRosterSuccessor).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_revocation_retained_remove_cannot_restore_positive_guard_after_encrypted_reopen()
     {
        selected_chat_delivery(RecipientAdmissionScenario::DeviceRosterSuccessorReopen).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_revocation_original_receipt_survives_incoming_storage_rollback_retry() {
        selected_chat_delivery(RecipientAdmissionScenario::DeviceRosterSuccessorStorageRetry).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_revocation_challenge_published_before_storage_retry_preserves_fresh_authority()
    {
        selected_chat_delivery(RecipientAdmissionScenario::DeviceRosterChallengeBeforeRetry).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_revocation_challenge_initial_peel_before_storage_retry_preserves_fresh_authority()
     {
        selected_chat_delivery(
            RecipientAdmissionScenario::DeviceRosterChallengeInitialPeelBeforeRetry,
        )
        .await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_revocation_original_rollback_keeps_actual_receive_route_until_reconciliation() {
        selected_chat_delivery(RecipientAdmissionScenario::DeviceRosterRefreshedRollbackRoute)
            .await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn successive_device_revocation_rollback_keeps_fresh_challenge_intake() {
        Box::pin(selected_chat_delivery(
            RecipientAdmissionScenario::DeviceRosterSuccessiveRevocationRollback,
        ))
        .await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_revocation_confirmation_fact_rollback_preserves_owned_successor_authority() {
        selected_chat_delivery(RecipientAdmissionScenario::DeviceRosterConfirmationStorageRetry)
            .await;
    }
    #[derive(Clone, Copy)]
    enum ChallengeBeforeRetry {
        Receipt,
        InitialPeel,
        ConfirmationWriteAfterSuccessor,
        RefreshedRollbackRoute,
    }
    #[derive(Clone, Copy, PartialEq)]
    enum RecipientAdmissionScenario {
        None,
        Retry,
        Cancel,
        Expire,
        ForeignPackageEvent,
        DeviceLeafRevocation,
        DeviceLeafRemoval,
        DeviceLeafRemovalCancel,
        DeviceLeafRemovalLostReply,
        DeviceLeafRemovalReopen,
        DeviceRosterRemoval,
        DeviceRosterSuccessor,
        DeviceRosterSuccessorReopen,
        DeviceRosterSuccessorStorageRetry,
        DeviceRosterChallengeBeforeRetry,
        DeviceRosterChallengeInitialPeelBeforeRetry,
        DeviceRosterRefreshedRollbackRoute,
        DeviceRosterSuccessiveRevocationRollback,
        DeviceRosterConfirmationStorageRetry,
        HistoryTransfer,
        HistoryRecipientQuery,
        HistoryRequestReplay,
        HistoryRequestReopen,
        HistoryExpiredUnpruned,
        HistoryCleanupRetry,
        HistoryCancelAfterImport,
        HistoryPublicationCancel,
        HistoryPublicationLostReply,
        HistoryPublicationExpire,
        HistoryPublicationShutdown,
        CommitCancel,
        CommitLostReply,
        WelcomeCancel,
        WelcomeLostReply,
    }

    async fn selected_chat_delivery(scenario: RecipientAdmissionScenario) {
        let fixture = actual_selected_chat_fixture_with_consent_lifetime(
            (scenario == RecipientAdmissionScenario::Expire)
                .then_some(std::time::Duration::from_secs(10)),
        )
        .await;
        let recipient_bundles_before = fixture.apps[1]
            .account_storage("test")
            .unwrap()
            .stored_key_package_bundles()
            .unwrap();
        let directory_reader = crate::network_proxy::nostr_builder().build();
        directory_reader
            .add_relay(fixture.url.clone())
            .capabilities(nostr_sdk::prelude::RelayCapabilities::READ)
            .await
            .unwrap();
        directory_reader.connect().await;
        let public_packages_before =
            directory_reader
                .fetch_events(nostr_sdk::prelude::ReqTarget::single(
                    fixture.url.as_str(),
                    [nostr_sdk::prelude::Filter::new()
                        .kind(nostr_sdk::prelude::Kind::Custom(30_443))],
                ))
                .timeout(std::time::Duration::from_secs(5))
                .await
                .unwrap();
        assert!(
            !public_packages_before.is_empty(),
            "D's ordinary public package is the directory baseline"
        );
        let managers = fixture
            .runtimes
            .each_ref()
            .map(|runtime| runtime.accounts());
        let target = managers[0]
            .device_linking_targets("test")
            .await
            .unwrap()
            .pop()
            .unwrap();
        let request = managers[0]
            .begin_selected_chat_copy("test", &fixture.chat, target.selector)
            .await
            .unwrap();
        let packet = request
            .request_packet(request.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        let mut original_consents = Vec::new();
        for manager in &managers[1..] {
            let consent = manager
                .receive_selected_chat_copy_request("test", packet.clone())
                .await
                .unwrap();
            consent
                .approve(consent.snapshot().await.unwrap().revision)
                .await
                .unwrap();
            let response = consent
                .response_packet(consent.snapshot().await.unwrap().revision)
                .await
                .unwrap();
            request
                .receive_consent_packet(request.snapshot().await.unwrap().revision, response)
                .await
                .unwrap();
            let offer = consent
                .offer_packet(consent.snapshot().await.unwrap().revision)
                .await
                .unwrap();
            request
                .receive_offer_packet(request.snapshot().await.unwrap().revision, offer)
                .await
                .unwrap();
            original_consents.push(consent);
        }
        let mut recipient_errors = fixture.runtimes[1].subscribe();
        let injector = if matches!(
            scenario,
            RecipientAdmissionScenario::Retry
                | RecipientAdmissionScenario::Cancel
                | RecipientAdmissionScenario::Expire
        ) {
            let app = &fixture.apps[1];
            let path = app.account_storage_path("test");
            let keys = app.account_home().load_signing_keys("test").unwrap();
            let key = app
                .sqlcipher_key(
                    "test",
                    &keys,
                    &path,
                    crate::sqlcipher::SqlcipherDatabaseKind::Session,
                )
                .unwrap();
            let connection = rusqlite::Connection::open(path).unwrap();
            storage_sqlite::open_hardened_sqlcipher(
                &connection,
                &key,
                storage_sqlite::SqlCipherHardening::cipher_only(),
            )
            .unwrap();
            connection.execute_batch("CREATE TRIGGER reject_selected_join BEFORE UPDATE OF state ON selected_chat_key_packages WHEN NEW.state=1 BEGIN SELECT RAISE(ABORT,'isolated selected admission rollback'); END;").unwrap();
            Some(connection)
        } else {
            None
        };
        assert_eq!(request.snapshot().await.unwrap().offered_sibling_count, 2);
        let publication_control = match scenario {
            RecipientAdmissionScenario::CommitCancel => Some((false, false)),
            RecipientAdmissionScenario::CommitLostReply => Some((false, true)),
            RecipientAdmissionScenario::WelcomeCancel => Some((true, false)),
            RecipientAdmissionScenario::WelcomeLostReply => Some((true, true)),
            _ => None,
        };
        if let Some((welcome, lost_reply)) = publication_control {
            assert_blocked_selected_publication_terminal(
                &fixture,
                request,
                &directory_reader,
                welcome,
                lost_reply,
            )
            .await;
            directory_reader.shutdown().await;
            for runtime in [
                &fixture.runtimes[0],
                &fixture.runtimes[1],
                &fixture.runtimes[2],
                &fixture.d_runtime,
            ] {
                runtime.shutdown_and_close().await.unwrap();
            }
            return;
        } else if scenario == RecipientAdmissionScenario::ForeignPackageEvent {
            let account = fixture.apps[0].account_home().account("test").unwrap();
            let (held, release) =
                fixture.apps[0]
                    .relay_plane
                    .hold_next_selected_welcome(cgka_traits::MemberId::new(
                        hex::decode(account.account_id_hex).unwrap(),
                    ));
            let release_on_drop = ReleaseSelectedWelcome(release.clone());
            let revision = request.snapshot().await.unwrap().revision;
            let continuation = request.continue_copy(revision);
            tokio::pin!(continuation);
            let message = tokio::time::timeout(std::time::Duration::from_secs(20), async {
                tokio::select! {
                    message = held => message.unwrap(),
                    result = &mut continuation => panic!("original continuation escaped publication gate: {result:?}"),
                }
            }).await.expect("actual selected Welcome must reach the real publisher gate");
            assert_foreign_selected_welcome_refused(&fixture, message).await;
            release.notify_one();
            continuation
                .await
                .expect("unchanged rightful Welcome must still publish");
            drop(release_on_drop);
        } else {
            request.continue_copy(request.snapshot().await.unwrap().revision).await
                .expect("the original selected request and explicit sibling consents must admit both fresh device leaves");
        }
        if let Some(connection) = injector {
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                loop {
                    if let crate::MarmotAppEvent::AccountError(error) =
                        recipient_errors.recv().await.unwrap()
                        && error.message.starts_with("runtime receive failed")
                    {
                        assert_eq!(
                            error.message, "runtime receive failed: storage_backend",
                            "the observed failure must be the typed SQL admission failure"
                        );
                        break;
                    }
                }
            })
            .await
            .expect("actual selected Welcome must reach the injected admission failure");
            let storage = fixture.apps[1].account_storage("test").unwrap();
            let rows = storage
                .selected_chat_key_package_storage()
                .unwrap()
                .selected_chat_key_packages()
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert!(
                rows[0].state
                    == cgka_traits::selected_chat_key_package::SelectedChatPurposeState::Pending
            );
            assert!(
                openmls::group::MlsGroup::load(
                    storage.mls_storage(),
                    &openmls::group::GroupId::from_slice(fixture.chat.as_slice())
                )
                .unwrap()
                .is_none()
            );
            let original = &original_consents[0];
            let snapshot = original.snapshot().await.unwrap();
            assert_eq!(
                snapshot.phase,
                crate::SelectedChatConsentPhase::Approved,
                "incoming storage rollback must retain the original approved sibling owner"
            );
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                original.offer_packet(snapshot.revision),
            )
            .await
            .expect("the same account worker must remain available during admission retry")
            .expect("original approved offer must remain usable after incoming storage rollback");
            if matches!(
                scenario,
                RecipientAdmissionScenario::Cancel | RecipientAdmissionScenario::Expire
            ) {
                let terminal = if scenario == RecipientAdmissionScenario::Cancel {
                    tokio::time::timeout(std::time::Duration::from_millis(500), original.cancel())
                        .await
                        .expect("original cancellation must remain responsive during storage retry")
                        .unwrap();
                    crate::SelectedChatConsentPhase::Cancelled
                } else {
                    tokio::time::timeout(std::time::Duration::from_secs(15), async {
                        loop {
                            if original.snapshot().await.unwrap().phase == crate::SelectedChatConsentPhase::Expired {
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        }
                    }).await.expect("unchanged original construction deadline must expire during retained SQL retry");
                    crate::SelectedChatConsentPhase::Expired
                };
                assert_eq!(original.snapshot().await.unwrap().phase, terminal);
                if scenario == RecipientAdmissionScenario::Expire {
                    let expired = original.snapshot().await.unwrap();
                    assert!(matches!(
                        original.offer_packet(expired.revision).await,
                        Err(crate::SelectedChatCopyError::Closed)
                    ));
                    assert!(matches!(
                        managers[1]
                            .receive_selected_chat_copy_request("test", packet.clone())
                            .await,
                        Err(crate::SelectedChatCopyError::Closed)
                    ));
                    assert_eq!(original.snapshot().await.unwrap(), expired);
                }
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    loop {
                        let rows = storage.selected_chat_key_package_storage().unwrap().selected_chat_key_packages().unwrap();
                        if rows.len() == 1 && rows[0].state == cgka_traits::selected_chat_key_package::SelectedChatPurposeState::Denied {
                            assert!(storage.stored_key_package_bundles().unwrap() == recipient_bundles_before);
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }).await.expect("exact terminal purpose and private bundle must retire");
            }
            connection
                .execute_batch("DROP TRIGGER reject_selected_join;")
                .unwrap();
        }
        if matches!(
            scenario,
            RecipientAdmissionScenario::Cancel | RecipientAdmissionScenario::Expire
        ) {
            assert_terminal_recipient_stays_out(&fixture, &request).await;
            directory_reader.shutdown().await;
            for runtime in [
                &fixture.runtimes[0],
                &fixture.runtimes[1],
                &fixture.runtimes[2],
                &fixture.d_runtime,
            ] {
                runtime.shutdown_and_close().await.unwrap();
            }
            return;
        }
        let public_packages_after =
            directory_reader
                .fetch_events(nostr_sdk::prelude::ReqTarget::single(
                    fixture.url.as_str(),
                    [nostr_sdk::prelude::Filter::new()
                        .kind(nostr_sdk::prelude::Kind::Custom(30_443))],
                ))
                .timeout(std::time::Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(
            public_packages_after.len(),
            public_packages_before.len(),
            "selected private package metadata must not publish additional public directory events"
        );
        let actual_epoch = managers[0]
            .group_mls_state("test", &fixture.chat)
            .await
            .unwrap()
            .epoch;
        let displayed = fixture.apps[0]
            .group("test", &fixture.chat_hex)
            .unwrap()
            .unwrap();
        assert_eq!(
            displayed.nostr_routing_last_epoch, actual_epoch,
            "the original sender's ordinary chat projection must reflect its confirmed Add before reporting success"
        );
        let all_apps = [
            &fixture.apps[0],
            &fixture.apps[1],
            &fixture.apps[2],
            &fixture.d_app,
        ];
        let all_runtimes = [
            &fixture.runtimes[0],
            &fixture.runtimes[1],
            &fixture.runtimes[2],
            &fixture.d_runtime,
        ];
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let mut complete = true;
                for runtime in all_runtimes {
                    complete &= runtime
                        .group_mls_state("test", &fixture.chat)
                        .await
                        .is_ok_and(|state| {
                            state.member_count == 4
                                && state.protocol_profile == crate::AppProtocolProfile::Current
                        });
                }
                if complete {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("all four independent MLS copies must adopt the actual selected Add");
        let mut own_indices = std::collections::BTreeSet::new();
        let mut own_signers = std::collections::BTreeSet::new();
        for app in all_apps {
            let storage = app.account_storage("test").unwrap();
            let group = openmls::group::MlsGroup::load(
                storage.mls_storage(),
                &openmls::group::GroupId::from_slice(fixture.chat.as_slice()),
            )
            .unwrap()
            .unwrap();
            assert_eq!(group.members().count(), 4);
            assert!(own_indices.insert(group.own_leaf_index().u32()));
            assert!(
                own_signers.insert(
                    group
                        .own_leaf_node()
                        .unwrap()
                        .signature_key()
                        .as_slice()
                        .to_vec()
                )
            );
        }
        let mut consumed_refs = std::collections::BTreeSet::new();
        for app in &fixture.apps[1..] {
            let storage = app.account_storage("test").unwrap();
            let rows = storage
                .selected_chat_key_package_storage()
                .unwrap()
                .selected_chat_key_packages()
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert!(
                rows[0].state
                    == cgka_traits::selected_chat_key_package::SelectedChatPurposeState::Consumed
            );
            assert!(consumed_refs.insert(rows[0].reference));
            assert!(
                app.timeline_message("test", &fixture.chat_hex, &fixture.before_id)
                    .unwrap()
                    .is_none()
            );
        }
        if matches!(
            scenario,
            RecipientAdmissionScenario::DeviceRosterRemoval
                | RecipientAdmissionScenario::DeviceRosterSuccessor
                | RecipientAdmissionScenario::DeviceRosterSuccessorReopen
                | RecipientAdmissionScenario::DeviceRosterSuccessorStorageRetry
                | RecipientAdmissionScenario::DeviceRosterChallengeBeforeRetry
                | RecipientAdmissionScenario::DeviceRosterChallengeInitialPeelBeforeRetry
                | RecipientAdmissionScenario::DeviceRosterRefreshedRollbackRoute
                | RecipientAdmissionScenario::DeviceRosterSuccessiveRevocationRollback
                | RecipientAdmissionScenario::DeviceRosterConfirmationStorageRetry
        ) {
            request.cancel().await.unwrap();
            drop(original_consents);
            use futures::FutureExt;
            let verdict = std::panic::AssertUnwindSafe(async {
                let _predecessor_owners = if scenario
                    == RecipientAdmissionScenario::DeviceRosterSuccessiveRevocationRollback
                {
                    Some(Box::pin(establish_actual_revoked_predecessor(&fixture, &managers)).await)
                } else {
                    None
                };
                assert_device_roster_removal(
                    &fixture,
                    &managers,
                    &directory_reader,
                    matches!(
                    scenario,
                    RecipientAdmissionScenario::DeviceRosterSuccessor
                        | RecipientAdmissionScenario::DeviceRosterSuccessorStorageRetry
                        | RecipientAdmissionScenario::DeviceRosterChallengeBeforeRetry
                        | RecipientAdmissionScenario::DeviceRosterChallengeInitialPeelBeforeRetry
                        | RecipientAdmissionScenario::DeviceRosterRefreshedRollbackRoute
                | RecipientAdmissionScenario::DeviceRosterSuccessiveRevocationRollback
                        | RecipientAdmissionScenario::DeviceRosterConfirmationStorageRetry
                ),
                    scenario == RecipientAdmissionScenario::DeviceRosterSuccessorReopen,
                    matches!(
                    scenario,
                    RecipientAdmissionScenario::DeviceRosterSuccessorStorageRetry
                        | RecipientAdmissionScenario::DeviceRosterChallengeBeforeRetry
                        | RecipientAdmissionScenario::DeviceRosterChallengeInitialPeelBeforeRetry
                        | RecipientAdmissionScenario::DeviceRosterRefreshedRollbackRoute
                | RecipientAdmissionScenario::DeviceRosterSuccessiveRevocationRollback
                ),
                    (match scenario {
                        RecipientAdmissionScenario::DeviceRosterChallengeBeforeRetry => {
                            Some(ChallengeBeforeRetry::Receipt)
                        }
                        RecipientAdmissionScenario::DeviceRosterChallengeInitialPeelBeforeRetry
                        | RecipientAdmissionScenario::DeviceRosterSuccessiveRevocationRollback => {
                            Some(ChallengeBeforeRetry::InitialPeel)
                        }
                        RecipientAdmissionScenario::DeviceRosterRefreshedRollbackRoute => {
                            Some(ChallengeBeforeRetry::RefreshedRollbackRoute)
                        }
                        RecipientAdmissionScenario::DeviceRosterConfirmationStorageRetry => {
                            Some(ChallengeBeforeRetry::ConfirmationWriteAfterSuccessor)
                        }
                        _ => None,
                    },
                    _predecessor_owners
                        .as_ref()
                        .map(|owners| &owners.previous_b_fact)),
                )
                .await;
                _predecessor_owners.map(|owners| {
                    (
                        owners.custody.clone(),
                        owners.original_group.clone(),
                        owners.original_binding,
                    )
                })
            })
            .catch_unwind()
            .await;
            directory_reader.shutdown().await;
            for runtime in all_runtimes {
                runtime.shutdown_and_close().await.unwrap();
            }
            eprintln!("revocation_runtime_positive_closes=4 original_verdict_preserved=true");
            match verdict {
                Err(panic) => std::panic::resume_unwind(panic),
                Ok(Some((custody, group, binding))) => {
                    let observed = custody.lock().unwrap();
                    assert!(
                        !observed.overflow,
                        "custody observation overflow is an unqualified fixture prerequisite failure"
                    );
                    let stale = observed
                        .entries
                        .iter()
                        .any(|(actual_group, actual_binding)| {
                            actual_group == &group && actual_binding == &binding
                        });
                    drop(observed);
                    eprintln!(
                        "successive_revocation_custody actual_second_remove_fault_and_history=true previous_completed_original_queued={stale}"
                    );
                    assert!(
                        !stale,
                        "previous Completed original must not take raw-delivery custody of a new Remove"
                    );
                }
                Ok(None) => {}
            }
            return;
        }
        if matches!(
            scenario,
            RecipientAdmissionScenario::DeviceLeafRevocation
                | RecipientAdmissionScenario::DeviceLeafRemoval
                | RecipientAdmissionScenario::DeviceLeafRemovalCancel
                | RecipientAdmissionScenario::DeviceLeafRemovalLostReply
                | RecipientAdmissionScenario::DeviceLeafRemovalReopen
        ) {
            let recipient_storage = fixture.apps[2].account_storage("test").unwrap();
            let recipient_group = openmls::group::MlsGroup::load(
                recipient_storage.mls_storage(),
                &openmls::group::GroupId::from_slice(fixture.chat.as_slice()),
            )
            .unwrap()
            .unwrap();
            let target_device = recipient_group
                .own_leaf_node()
                .unwrap()
                .signature_key()
                .as_slice()
                .to_vec();
            let recipient_identity = openmls::prelude::BasicCredential::try_from(
                recipient_group
                    .members()
                    .find(|member| member.index == recipient_group.own_leaf_index())
                    .unwrap()
                    .credential,
            )
            .unwrap()
            .identity()
            .to_vec();
            assert_eq!(
                recipient_group
                    .members()
                    .filter(|member| {
                        openmls::prelude::BasicCredential::try_from(member.credential.clone())
                            .unwrap()
                            .identity()
                            == recipient_identity.as_slice()
                    })
                    .count(),
                3,
                "the target shares its account with two surviving independent leaves"
            );
            let original = managers[0]
                .begin_group_device_revocation("test", &fixture.chat, target_device.clone())
                .await;
            assert!(
                original.is_ok(),
                "fresh explicit administrator action must select exactly C's actual occupied leaf"
            );
            let original = original.unwrap();
            let review = original.snapshot().await.unwrap();
            assert_eq!(review.group, fixture.chat);
            assert_eq!(review.epoch, recipient_group.epoch().as_u64());
            assert_eq!(
                review.target_leaf_index,
                recipient_group.own_leaf_index().u32()
            );
            assert_eq!(review.target_device, target_device);
            assert_eq!(review.surviving_same_account_leaves, 2);
            assert_eq!(review.revision, 1);
            assert!(matches!(
                managers[0]
                    .begin_group_device_revocation("test", &fixture.chat, target_device.clone())
                    .await,
                Err(crate::GroupDeviceRevocationError::Busy)
            ));
            for app in [&fixture.apps[0], &fixture.d_app] {
                let storage = app.account_storage("test").unwrap();
                let group = openmls::group::MlsGroup::load(
                    storage.mls_storage(),
                    &openmls::group::GroupId::from_slice(fixture.chat.as_slice()),
                )
                .unwrap()
                .unwrap();
                let refused_target = group
                    .own_leaf_node()
                    .unwrap()
                    .signature_key()
                    .as_slice()
                    .to_vec();
                assert!(matches!(
                    managers[0]
                        .begin_group_device_revocation("test", &fixture.chat, refused_target)
                        .await,
                    Err(crate::GroupDeviceRevocationError::InvalidSelection)
                ));
            }
            original.cancel();
            assert!(matches!(
                original.snapshot().await,
                Err(crate::GroupDeviceRevocationError::Closed)
            ));
            let next = managers[0]
                .begin_group_device_revocation("test", &fixture.chat, target_device.clone())
                .await
                .unwrap();
            original.cancel();
            assert_eq!(next.snapshot().await.unwrap(), review);
            drop(next);
            let changed = managers[0]
                .begin_group_device_revocation("test", &fixture.chat, target_device.clone())
                .await
                .unwrap();
            fixture.runtimes[0]
                .update_group_profile(
                    "test",
                    &fixture.chat,
                    Some("fresh authenticated epoch invalidates old review".into()),
                    None,
                )
                .await
                .unwrap();
            assert!(matches!(
                changed.snapshot().await,
                Err(crate::GroupDeviceRevocationError::InvalidSelection)
            ));
            drop(changed);
            let fresh = managers[0]
                .begin_group_device_revocation("test", &fixture.chat, target_device)
                .await
                .unwrap();
            assert_eq!(fresh.snapshot().await.unwrap().epoch, review.epoch + 1);
            if matches!(
                scenario,
                RecipientAdmissionScenario::DeviceLeafRemovalCancel
                    | RecipientAdmissionScenario::DeviceLeafRemovalLostReply
            ) {
                assert_blocked_original_leaf_removal_terminal(
                    &fixture,
                    fresh,
                    &directory_reader,
                    scenario == RecipientAdmissionScenario::DeviceLeafRemovalLostReply,
                )
                .await;
                directory_reader.shutdown().await;
                for runtime in all_runtimes {
                    runtime.shutdown_and_close().await.unwrap();
                }
                drop(original_consents);
                return;
            }
            if matches!(
                scenario,
                RecipientAdmissionScenario::DeviceLeafRemoval
                    | RecipientAdmissionScenario::DeviceLeafRemovalReopen
            ) {
                let displayed = fresh.snapshot().await.unwrap();
                assert!(matches!(
                    fresh.approve(displayed.revision + 1).await,
                    Err(crate::GroupDeviceRevocationError::StaleRevision)
                ));
                let approved = fresh.approve(displayed.revision).await;
                assert!(
                    approved.is_ok(),
                    "explicit approval of the exact original review must publish one exact-leaf Remove"
                );
                tokio::time::timeout(std::time::Duration::from_secs(20), async {
                    loop {
                        if [0usize, 1, 3].iter().all(|&index| {
                            let storage = all_apps[index].account_storage("test").unwrap();
                            let group = openmls::group::MlsGroup::load(
                                storage.mls_storage(),
                                &openmls::group::GroupId::from_slice(fixture.chat.as_slice()),
                            )
                            .unwrap()
                            .unwrap();
                            group.members().count() == 3
                                && group.members().all(|member| {
                                    member.signature_key.as_slice()
                                        != displayed.target_device.as_slice()
                                })
                        }) {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                })
                .await
                .expect("A, B and D must retain their independent leaves after C alone is removed");
                tokio::time::timeout(std::time::Duration::from_secs(20), async {
                    loop {
                        let storage = all_apps[2].account_storage("test").unwrap();
                        if cgka_traits::GroupStorage::get_group(&storage, &fixture.chat).unwrap().removed { break; }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }).await.expect("C must authenticate and realize its own exact-leaf eviction before outbound refusal");
                assert!(
                    all_runtimes[2]
                        .send_message("test", &fixture.chat, b"removed C cannot send".to_vec())
                        .await
                        .is_err()
                );
                for sender in [0usize, 1, 3] {
                    let payload =
                        format!("surviving independent leaf {sender} after exact C removal");
                    let published = all_runtimes[sender]
                        .send_message("test", &fixture.chat, payload.as_bytes().to_vec())
                        .await
                        .unwrap();
                    assert_eq!(published.message_ids.len(), 1);
                    let id = &published.message_ids[0];
                    tokio::time::timeout(std::time::Duration::from_secs(20), async {
                        loop {
                            if [0usize, 1, 3].iter().all(|&index| {
                                all_apps[index]
                                    .timeline_message("test", &fixture.chat_hex, id)
                                    .unwrap()
                                    .is_some_and(|message| {
                                        message.message_id_hex == *id
                                            && message.plaintext == payload
                                    })
                            }) {
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        }
                    })
                    .await
                    .expect("new messages must reach all three surviving independent MLS leaves");
                    assert!(
                        all_apps[2]
                            .timeline_message("test", &fixture.chat_hex, id)
                            .unwrap()
                            .is_none()
                    );
                }
                let committed = fresh.snapshot().await.unwrap();
                assert!(committed.complete);
                assert_eq!(committed.revision, displayed.revision + 1);
                assert!(matches!(
                    fresh.approve(displayed.revision).await,
                    Err(crate::GroupDeviceRevocationError::StaleRevision)
                ));
                fresh.approve(committed.revision).await.unwrap();
                if scenario == RecipientAdmissionScenario::DeviceLeafRemovalReopen {
                    drop(recipient_group);
                    drop(recipient_storage);
                    all_runtimes[2].shutdown_and_close().await.unwrap();
                    let reopened_app = MarmotApp::with_relay(fixture.dirs[2].path(), &fixture.url);
                    let reopened = MarmotAppRuntime::new(reopened_app.clone());
                    reopened.reconcile_accounts().await.unwrap();
                    let storage = reopened_app.account_storage("test").unwrap();
                    assert!(
                        cgka_traits::GroupStorage::get_group(&storage, &fixture.chat)
                            .unwrap()
                            .removed
                    );
                    assert!(
                        reopened
                            .send_message(
                                "test",
                                &fixture.chat,
                                b"reopened removed leaf cannot send".to_vec()
                            )
                            .await
                            .is_err()
                    );
                    let payload = "future epoch ciphertext after C encrypted reopen";
                    let sent = all_runtimes[0]
                        .send_message("test", &fixture.chat, payload.as_bytes().to_vec())
                        .await
                        .unwrap();
                    assert_eq!(sent.message_ids.len(), 1);
                    let id = &sent.message_ids[0];
                    tokio::time::timeout(std::time::Duration::from_secs(20), async {
                        loop {
                            if [0usize,1,3].iter().all(|&index| all_apps[index].timeline_message("test", &fixture.chat_hex, id).unwrap().is_some_and(|message| message.plaintext == payload)) {break;}
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        }
                    }).await.expect("fresh future ciphertext must reach each surviving leaf after recipient reopen");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    assert!(
                        reopened_app
                            .timeline_message("test", &fixture.chat_hex, id)
                            .unwrap()
                            .is_none()
                    );
                    reopened.shutdown_and_close().await.unwrap();
                }
                directory_reader.shutdown().await;
                for runtime in all_runtimes {
                    runtime.shutdown_and_close().await.unwrap();
                }
                drop(original_consents);
                return;
            }
            fresh.cancel();
        }
        if matches!(
            scenario,
            RecipientAdmissionScenario::HistoryTransfer
                | RecipientAdmissionScenario::HistoryRecipientQuery
                | RecipientAdmissionScenario::HistoryRequestReplay
                | RecipientAdmissionScenario::HistoryRequestReopen
                | RecipientAdmissionScenario::HistoryExpiredUnpruned
                | RecipientAdmissionScenario::HistoryCleanupRetry
                | RecipientAdmissionScenario::HistoryCancelAfterImport
                | RecipientAdmissionScenario::HistoryPublicationCancel
                | RecipientAdmissionScenario::HistoryPublicationLostReply
                | RecipientAdmissionScenario::HistoryPublicationExpire
                | RecipientAdmissionScenario::HistoryPublicationShutdown
        ) {
            let ordinary_epochs = [
                all_runtimes[0]
                    .group_mls_state("test", &fixture.chat)
                    .await
                    .unwrap()
                    .epoch,
                all_runtimes[1]
                    .group_mls_state("test", &fixture.chat)
                    .await
                    .unwrap()
                    .epoch,
            ];
            let recipient_storage = fixture.apps[1].account_storage("test").unwrap();
            let recipient_mls = openmls::group::MlsGroup::load(
                recipient_storage.mls_storage(),
                &openmls::group::GroupId::from_slice(fixture.chat.as_slice()),
            )
            .unwrap()
            .unwrap();
            let recipient_selector = recipient_mls
                .own_leaf_node()
                .unwrap()
                .signature_key()
                .as_slice()
                .to_vec();
            assert!(
                recipient_storage
                    .app_storage()
                    .synchronized_history_page(&fixture.chat_hex, None, 200, 0)
                    .unwrap()
                    .is_empty()
            );
            let larger = fixture.runtimes[0]
                .send_message("test", &fixture.chat, vec![b'x'; 8192])
                .await
                .unwrap();
            let larger_id = &larger.message_ids[0];
            tokio::time::timeout(std::time::Duration::from_secs(15), async {
                loop {
                    if [1usize, 2].into_iter().all(|i| {
                        fixture.apps[i]
                            .timeline_message("test", &fixture.chat_hex, larger_id)
                            .unwrap()
                            .is_some()
                    }) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("actual larger logical record must reach ordinary MLS recipients");
            if scenario == RecipientAdmissionScenario::HistoryExpiredUnpruned {
                // Genuine decrypted ordinary data is still stored: exercise delayed
                // pruning by marking only its actual persisted retention deadline.
                let app = &fixture.apps[0];
                let path = app.account_storage_path("test");
                let keys = app.account_home().load_signing_keys("test").unwrap();
                let key = app
                    .sqlcipher_key(
                        "test",
                        &keys,
                        &path,
                        crate::sqlcipher::SqlcipherDatabaseKind::Session,
                    )
                    .unwrap();
                let connection = rusqlite::Connection::open(path).unwrap();
                storage_sqlite::open_hardened_sqlcipher(
                    &connection,
                    &key,
                    storage_sqlite::SqlCipherHardening::cipher_only(),
                )
                .unwrap();
                let expiry: i64 = crate::unix_now_seconds().try_into().unwrap();
                assert_eq!(connection.execute("UPDATE app_events SET retention_seconds=1,retention_expires_at=?1 WHERE group_id_hex=?2 AND message_id_hex=?3",rusqlite::params![expiry,fixture.chat_hex,larger_id]).unwrap(),1);
                let stored = app
                    .account_storage("test")
                    .unwrap()
                    .app_storage()
                    .timeline_message(&fixture.chat_hex, larger_id)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    stored.plaintext.len(),
                    8192,
                    "fixture must retain actual unpruned plaintext"
                );
                assert!(
                    stored
                        .retention_expires_at
                        .is_some_and(|t| t <= crate::unix_now_seconds())
                );
            }
            if scenario == RecipientAdmissionScenario::HistoryPublicationExpire {
                managers[0]
                    .next_original_history_lifetime_for_test(
                        "test",
                        std::time::Duration::from_secs(5),
                    )
                    .await
                    .unwrap();
            }
            let recipient_selector =
                if scenario == RecipientAdmissionScenario::HistoryRecipientQuery {
                    let source_storage = fixture.apps[0].account_storage("test").unwrap();
                    let round = source_storage
                        .private_roster_settlement_storage()
                        .unwrap()
                        .read_round()
                        .unwrap()
                        .unwrap();
                    let actual = openmls::group::MlsGroup::load(
                        source_storage.mls_storage(),
                        &openmls::group::GroupId::from_slice(round.anchor.group_id.as_slice()),
                    )
                    .unwrap()
                    .unwrap();
                    let mut expected: Vec<_> = actual
                        .members()
                        .filter(|leaf| leaf.index != actual.own_leaf_index())
                        .map(|leaf| (leaf.index.u32(), leaf.signature_key))
                        .collect();
                    expected.sort_unstable_by_key(|leaf| leaf.0);
                    let before = managers[0]
                        .observed_history_chunks_for_test("test")
                        .await
                        .unwrap();
                    let choices = managers[0]
                        .history_transfer_recipients("test", &fixture.chat)
                        .await
                        .expect("public SDK must list genuine settled linked recipients");
                    assert_eq!(choices.len(), 2);
                    assert!(
                        choices
                            .iter()
                            .map(|v| (v.leaf_index, v.device.clone()))
                            .collect::<Vec<_>>()
                            == expected
                    );
                    assert!(
                        managers[0]
                            .pending_history_requests("test")
                            .await
                            .unwrap()
                            .is_empty()
                    );
                    assert!(
                        managers[1]
                            .pending_history_requests("test")
                            .await
                            .unwrap()
                            .is_empty()
                    );
                    assert_eq!(
                        managers[0]
                            .observed_history_chunks_for_test("test")
                            .await
                            .unwrap(),
                        before
                    );
                    assert!(
                        recipient_storage
                            .app_storage()
                            .synchronized_history_page(&fixture.chat_hex, None, 200, 0)
                            .unwrap()
                            .is_empty()
                    );
                    // Actually start through a returned choice, retaining explicit recipient approval below.
                    choices
                        .into_iter()
                        .find(|choice| choice.device == recipient_selector)
                        .unwrap()
                        .device
                } else {
                    recipient_selector
                };
            let transfer = managers[0].begin_history_transfer("test", &fixture.chat, recipient_selector.clone()).await
                .expect("a fresh opt-in history request must retain its original actor owner after actual four-leaf admission");
            assert!(
                recipient_storage
                    .app_storage()
                    .synchronized_history_page(&fixture.chat_hex, None, 200, 0)
                    .unwrap()
                    .is_empty(),
                "request is not recipient consent"
            );
            if scenario == RecipientAdmissionScenario::HistoryExpiredUnpruned {
                let id: [u8; 32] = hex::decode(larger_id).unwrap().try_into().unwrap();
                assert_eq!(
                    transfer.original_record_for_test(id).await.unwrap(),
                    (true, 0),
                    "expired-unpruned plaintext must be absent from the actual frozen signed transport archive, not merely hidden by recipient retention"
                );
            }

            let consent = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if let Some(consent) = managers[1]
                        .pending_history_requests("test")
                        .await
                        .unwrap()
                        .pop()
                    {
                        break consent;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("actual encrypted request must reach its addressed original recipient");
            if scenario == RecipientAdmissionScenario::HistoryRequestReopen {
                consent.cancel();
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    loop {
                        if managers[1]
                            .observed_history_chunks_for_test("test")
                            .await
                            .unwrap()
                            .3
                            == 0
                        {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                })
                .await
                .expect("cancelled original must retire before actual encrypted close/reopen");
                fixture.runtimes[1].shutdown_and_close().await.unwrap();
                assert!(matches!(
                    consent.snapshot().await,
                    Err(crate::HistoryTransferError::Closed)
                ));
                drop(recipient_storage);
                let reopened_app = MarmotApp::with_relay(fixture.dirs[1].path(), &fixture.url);
                let reopened = MarmotAppRuntime::new(reopened_app.clone());
                reopened.reconcile_accounts().await.unwrap();
                let reopened_manager = reopened.accounts();
                assert!(
                    reopened_manager
                        .pending_history_requests("test")
                        .await
                        .unwrap()
                        .is_empty(),
                    "reopen cannot restore original recipient consent from historical metadata"
                );
                let before = reopened_manager
                    .observed_history_chunks_for_test("test")
                    .await
                    .unwrap()
                    .2;
                let epoch = reopened
                    .group_mls_state("test", &fixture.chat)
                    .await
                    .unwrap()
                    .epoch;
                transfer
                    .republish_original_request_for_test()
                    .await
                    .unwrap();
                tokio::time::timeout(std::time::Duration::from_secs(10),async{
                    loop {if reopened_manager.observed_history_chunks_for_test("test").await.unwrap().2>before{break;} tokio::time::sleep(std::time::Duration::from_millis(20)).await;}
                }).await.expect("reopened original device must authenticate same signed request in fresh actual MLS outer frame");
                assert!(
                    reopened_manager
                        .pending_history_requests("test")
                        .await
                        .unwrap()
                        .is_empty(),
                    "durable negative request identity must prevent new receiver consent/clock after encrypted reopen"
                );
                assert_eq!(
                    reopened
                        .group_mls_state("test", &fixture.chat)
                        .await
                        .unwrap()
                        .epoch,
                    epoch
                );
                assert!(
                    reopened_app
                        .account_storage("test")
                        .unwrap()
                        .app_storage()
                        .synchronized_history_page(&fixture.chat_hex, None, 200, 0)
                        .unwrap()
                        .is_empty()
                );
                transfer.cancel();
                let fresh = managers[0]
                    .begin_history_transfer("test", &fixture.chat, recipient_selector)
                    .await
                    .unwrap();
                let next = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    loop {
                        if let Some(next) = reopened_manager
                            .pending_history_requests("test")
                            .await
                            .unwrap()
                            .into_iter()
                            .next()
                        {
                            break next;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                })
                .await
                .expect("fresh distinct authenticated request remains possible after reopen");
                next.cancel();
                fresh.cancel();
                reopened.shutdown_and_close().await.unwrap();
                directory_reader.shutdown().await;
                for runtime in all_runtimes {
                    runtime.shutdown_and_close().await.unwrap();
                }
                return;
            }
            if scenario == RecipientAdmissionScenario::HistoryRequestReplay {
                let before = managers[1]
                    .observed_history_chunks_for_test("test")
                    .await
                    .unwrap()
                    .2;
                consent.cancel();
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    loop {
                        if managers[1]
                            .observed_history_chunks_for_test("test")
                            .await
                            .unwrap()
                            .3
                            == 0
                        {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                })
                .await
                .expect("cancel must retire the actual original receiver entry before replay");
                transfer
                    .republish_original_request_for_test()
                    .await
                    .unwrap();
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    loop {
                        if managers[1].observed_history_chunks_for_test("test").await.unwrap().2 > before { break; }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }).await.expect("B must authenticate the same signed request in a genuine fresh MLS outer frame");
                assert!(
                    managers[1]
                        .pending_history_requests("test")
                        .await
                        .unwrap()
                        .is_empty(),
                    "a cancelled original request must not create a new receiver owner or renew its deadline"
                );
                assert!(
                    recipient_storage
                        .app_storage()
                        .synchronized_history_page(&fixture.chat_hex, None, 200, 0)
                        .unwrap()
                        .is_empty()
                );
                transfer.cancel();
                directory_reader.shutdown().await;
                for runtime in all_runtimes {
                    runtime.shutdown_and_close().await.unwrap();
                }
                return;
            }
            let review = consent.snapshot().await.unwrap();
            assert_eq!(review.group, fixture.chat);
            assert_eq!(review.record_count, 2);
            if scenario == RecipientAdmissionScenario::HistoryExpiredUnpruned {
                assert!(review.encoded_bytes < 8192);
            } else {
                assert!(review.fragment_count > 1 && review.encoded_bytes > 8192);
            }
            if matches!(
                scenario,
                RecipientAdmissionScenario::HistoryCleanupRetry
                    | RecipientAdmissionScenario::HistoryCancelAfterImport
            ) {
                let imported = scenario == RecipientAdmissionScenario::HistoryCancelAfterImport;
                let app = &fixture.apps[1];
                let path = app.account_storage_path("test");
                let keys = app.account_home().load_signing_keys("test").unwrap();
                let key = app
                    .sqlcipher_key(
                        "test",
                        &keys,
                        &path,
                        crate::sqlcipher::SqlcipherDatabaseKind::Session,
                    )
                    .unwrap();
                let connection = rusqlite::Connection::open(path).unwrap();
                storage_sqlite::open_hardened_sqlcipher(
                    &connection,
                    &key,
                    storage_sqlite::SqlCipherHardening::cipher_only(),
                )
                .unwrap();
                if !imported {
                    connection.execute_batch("CREATE TRIGGER reject_history_negative_cleanup BEFORE UPDATE OF state ON history_archive_staging WHEN NEW.state=2 BEGIN SELECT RAISE(ABORT,'isolated history cancellation storage fault'); END;").unwrap();
                }
                managers[1]
                    .cancel_after_original_history_stage_for_test("test", imported)
                    .await
                    .unwrap();
                consent.approve(review.revision).await.unwrap();
                let continuation =
                    transfer.continue_transfer(transfer.snapshot().await.unwrap().revision);
                tokio::pin!(continuation);
                let witness = async {
                    loop {
                        if imported {
                            if recipient_storage
                                .app_storage()
                                .synchronized_history_page(&fixture.chat_hex, None, 200, 0)
                                .unwrap()
                                .iter()
                                .any(|r| hex::encode(r.record.message_id) == fixture.before_id)
                            {
                                break;
                            }
                        } else if managers[1]
                            .observed_history_chunks_for_test("test")
                            .await
                            .unwrap()
                            .4
                            > 0
                        {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                };
                tokio::time::timeout(std::time::Duration::from_secs(25),async{
                    tokio::select! { result=&mut continuation=>panic!("source escaped actual stage cancellation boundary: {result:?}"), ()=witness=>() }
                }).await.expect("actual encrypted history must reach the original SQL/cancellation boundary");
                if imported {
                    let observation=consent.snapshot().await.expect("committed import must remain observable after original cancellation before receipt sealing");
                    assert!(observation.complete && observation.imported_records > 0);
                    tokio::time::timeout(std::time::Duration::from_secs(5),async{
                        loop { if managers[1].observed_history_chunks_for_test("test").await.unwrap().3==0 {break;} tokio::time::sleep(std::time::Duration::from_millis(20)).await; }
                    }).await.expect("completed cancelled entry must retire without trying to deny imported SQL facts");
                    assert_eq!(
                        managers[1]
                            .observed_history_chunks_for_test("test")
                            .await
                            .unwrap()
                            .4,
                        0
                    );
                    assert_eq!(
                        connection
                            .query_row("SELECT state FROM history_archive_staging", [], |r| r
                                .get::<_, i64>(0))
                            .unwrap(),
                        1
                    );
                } else {
                    assert!(matches!(
                        consent.snapshot().await,
                        Err(crate::HistoryTransferError::Closed)
                    ));
                    assert_eq!(
                        connection
                            .query_row("SELECT state FROM history_archive_staging", [], |r| r
                                .get::<_, i64>(0))
                            .unwrap(),
                        0
                    );
                    assert!(connection.query_row("SELECT count(*) FROM history_archive_fragments WHERE body IS NOT NULL",[],|r|r.get::<_,i64>(0)).unwrap()>0);
                    connection
                        .execute_batch("DROP TRIGGER reject_history_negative_cleanup;")
                        .unwrap();
                    tokio::time::timeout(std::time::Duration::from_secs(5),async{
                        loop {
                            if connection.query_row("SELECT state FROM history_archive_staging",[],|r|r.get::<_,i64>(0)).unwrap()==2 {break;}
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        }
                    }).await.expect("original negative cleanup identity must survive typed SQL failure and retry after fault removal");
                    assert_eq!(connection.query_row("SELECT count(*) FROM history_archive_fragments WHERE body IS NOT NULL",[],|r|r.get::<_,i64>(0)).unwrap(),0);
                    assert!(
                        recipient_storage
                            .app_storage()
                            .synchronized_history_page(&fixture.chat_hex, None, 200, 0)
                            .unwrap()
                            .is_empty()
                    );
                }
                assert!(
                    !transfer.snapshot().await.unwrap().complete,
                    "recipient SQL commit without authenticated ACK cannot mark source complete"
                );
                transfer.cancel();
                tokio::time::timeout(std::time::Duration::from_secs(5), &mut continuation)
                    .await
                    .unwrap()
                    .expect_err("source original cancellation retires its unfinished reply");
                directory_reader.shutdown().await;
                for runtime in all_runtimes {
                    runtime.shutdown_and_close().await.unwrap();
                }
                return;
            }
            let revision_before_consent = transfer.snapshot().await.unwrap().revision;
            consent.approve(review.revision).await.unwrap();
            if matches!(
                scenario,
                RecipientAdmissionScenario::HistoryPublicationCancel
                    | RecipientAdmissionScenario::HistoryPublicationLostReply
                    | RecipientAdmissionScenario::HistoryPublicationExpire
                    | RecipientAdmissionScenario::HistoryPublicationShutdown
            ) {
                let account = fixture.apps[0].account_home().account("test").unwrap();
                let (held, release) = fixture.apps[0].relay_plane.hold_next_selected_commit(
                    cgka_traits::MemberId::new(hex::decode(account.account_id_hex).unwrap()),
                );
                let _release_on_drop = ReleaseSelectedWelcome(release.clone());
                let transfer = std::sync::Arc::new(transfer);
                // Recipient approval publishes asynchronously. Wait for this original
                // source to authenticate Consent before reading its action revision.
                // Otherwise queued consent can invalidate the revision before dispatch.
                let revision = tokio::time::timeout(std::time::Duration::from_secs(20), async {
                    loop {
                        let snapshot = transfer.snapshot().await.unwrap();
                        if snapshot.revision > revision_before_consent {
                            break snapshot.revision;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                })
                .await
                .expect("source must authenticate actual Consent before chunk continuation");
                let operation = transfer.clone();
                let mut continuation =
                    tokio::spawn(async move { operation.continue_transfer(revision).await });
                let _abort_on_drop = AbortSelectedContinuation(continuation.abort_handle());
                let message=tokio::time::timeout(std::time::Duration::from_secs(20),async{
                    tokio::select! {message=held=>message.unwrap(),result=&mut continuation=>panic!("original history escaped actual chunk gate: {result:?}")}
                }).await.expect("actual signed/encrypted history chunk must reach original transport gate");
                assert!(matches!(
                    message.envelope,
                    cgka_traits::TransportEnvelope::GroupMessage { .. }
                ));
                if scenario == RecipientAdmissionScenario::HistoryPublicationShutdown {
                    let runtime = all_runtimes[0].clone();
                    let shutdown = tokio::spawn(async move { runtime.shutdown_and_close().await });
                    let _abort_shutdown = AbortSelectedContinuation(shutdown.abort_handle());
                    tokio::time::timeout(std::time::Duration::from_millis(500),async {
                        loop {if matches!(transfer.snapshot().await,Err(crate::HistoryTransferError::Closed)){break;} tokio::time::sleep(std::time::Duration::from_millis(10)).await;}
                    }).await.expect("runtime shutdown must revoke original history before blocked transport release or forced worker abort");
                    tokio::time::timeout(std::time::Duration::from_secs(2), shutdown)
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap();
                    assert!(
                        tokio::time::timeout(std::time::Duration::from_secs(2), continuation)
                            .await
                            .unwrap()
                            .unwrap()
                            .is_err()
                    );
                } else if scenario == RecipientAdmissionScenario::HistoryPublicationExpire {
                    assert!(
                        transfer.snapshot().await.is_ok(),
                        "original must still be live when its actual chunk reaches the gate"
                    );
                    assert!(matches!(
                        tokio::time::timeout(std::time::Duration::from_secs(6), continuation)
                            .await
                            .expect("fixed original expiry must interrupt the held publication")
                            .unwrap(),
                        Err(crate::HistoryTransferError::Closed)
                    ));
                    assert!(matches!(
                        transfer.snapshot().await,
                        Err(crate::HistoryTransferError::Closed)
                    ));
                } else if scenario == RecipientAdmissionScenario::HistoryPublicationLostReply {
                    continuation.abort();
                    assert!(continuation.await.unwrap_err().is_cancelled());
                    tokio::time::timeout(std::time::Duration::from_secs(2),async{
                        loop {if matches!(transfer.snapshot().await,Err(crate::HistoryTransferError::Closed)){break;} tokio::time::sleep(std::time::Duration::from_millis(20)).await;}
                    }).await.expect("lost original continuation reply must retire custody before blocked publication releases");
                } else {
                    transfer.cancel();
                    assert!(matches!(tokio::time::timeout(std::time::Duration::from_secs(2),continuation).await.expect("original cancellation must interrupt actual blocked history publication").unwrap(),Err(crate::HistoryTransferError::Closed)));
                }
                if scenario != RecipientAdmissionScenario::HistoryPublicationShutdown {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        managers[0].observed_history_chunks_for_test("test"),
                    )
                    .await
                    .expect("source worker must resume before transport gate release")
                    .unwrap();
                }
                release.notify_waiters();
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                assert!(
                    recipient_storage
                        .app_storage()
                        .synchronized_history_page(&fixture.chat_hex, None, 200, 0)
                        .unwrap()
                        .is_empty()
                );
                assert_eq!(
                    managers[1]
                        .observed_history_chunks_for_test("test")
                        .await
                        .unwrap()
                        .0,
                    0,
                    "releasing canceled transport must not deliver the held archive chunk"
                );
                directory_reader.shutdown().await;
                for runtime in all_runtimes {
                    runtime.shutdown_and_close().await.unwrap();
                }
                return;
            }
            transfer
                .continue_transfer(transfer.snapshot().await.unwrap().revision)
                .await
                .unwrap();
            let archived = recipient_storage
                .app_storage()
                .synchronized_history_page(&fixture.chat_hex, None, 200, 0)
                .unwrap();
            assert!(
                archived
                    .iter()
                    .any(|r| hex::encode(r.record.message_id) == fixture.before_id),
                "committed archive must contain actual prejoin logical record"
            );
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if managers[2]
                        .observed_history_chunks_for_test("test")
                        .await
                        .unwrap()
                        .0
                        > 0
                    {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("genuine C must decrypt and authenticate an outer MLS history chunk");
            assert!(
                managers[2]
                    .observed_history_chunks_for_test("test")
                    .await
                    .unwrap()
                    .1
                    > 0,
                "C's Core must refuse constructing an original recipient from B's actual authenticated request"
            );
            assert!(
                managers[2]
                    .pending_history_requests("test")
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(
                fixture.apps[2]
                    .account_storage("test")
                    .unwrap()
                    .app_storage()
                    .synchronized_history_page(&fixture.chat_hex, None, 200, 0)
                    .unwrap()
                    .is_empty(),
                "outer MLS membership gives C no original recipient HPKE channel or imported B archive"
            );
            let progress = transfer.snapshot().await.unwrap();
            assert!(
                progress.complete && progress.imported_records > 0,
                "transport publication alone cannot report a committed import receipt"
            );
            for (index, epoch) in ordinary_epochs.into_iter().enumerate() {
                assert_eq!(
                    all_runtimes[index]
                        .group_mls_state("test", &fixture.chat)
                        .await
                        .unwrap()
                        .epoch,
                    epoch,
                    "logical archive cannot advance MLS state"
                );
            }
        }
        for (sender, runtime) in all_runtimes.into_iter().enumerate() {
            let payload = format!("fresh selected chat message from independent leaf {sender}");
            let published = runtime
                .send_message("test", &fixture.chat, payload.as_bytes().to_vec())
                .await
                .unwrap();
            assert_eq!(published.message_ids.len(), 1);
            let id = &published.message_ids[0];
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                loop {
                    if all_apps.iter().all(|app| {
                        app.timeline_message("test", &fixture.chat_hex, id)
                            .unwrap()
                            .is_some_and(|message| {
                                message.message_id_hex == *id && message.plaintext == payload
                            })
                    }) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .expect(
                "each authenticated event ID and payload must project on every intended device",
            );
        }
        for app in &fixture.apps[1..] {
            assert!(
                app.timeline_message("test", &fixture.chat_hex, &fixture.before_id)
                    .unwrap()
                    .is_none()
            );
        }
        directory_reader.shutdown().await;
        for runtime in all_runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
        drop(original_consents);
    }
    async fn assert_blocked_original_leaf_removal_terminal(
        fixture: &SelectedChatFixture,
        action: crate::GroupDeviceRevocation,
        relay_reader: &nostr_sdk::prelude::Client,
        lost_reply: bool,
    ) {
        let before = fixture.runtimes[0]
            .group_mls_state("test", &fixture.chat)
            .await
            .unwrap();
        let account = fixture.apps[0].account_home().account("test").unwrap();
        let account = cgka_traits::MemberId::new(hex::decode(account.account_id_hex).unwrap());
        let (held, release) = fixture.apps[0]
            .relay_plane
            .hold_next_selected_commit(account);
        let release_on_drop = ReleaseSelectedWelcome(release.clone());
        let action = std::sync::Arc::new(action);
        let displayed = action.snapshot().await.unwrap();
        let operation = action.clone();
        let mut publication =
            tokio::spawn(async move { operation.approve(displayed.revision).await });
        let _abort_on_drop = AbortSelectedContinuation(publication.abort_handle());
        let held = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            tokio::select! {
                message = held => message.unwrap(),
                result = &mut publication => panic!("original removal escaped real publication gate: {result:?}"),
            }
        }).await.expect("actual original Remove must reach transport before cancellation control");
        assert!(!matches!(
            held.envelope,
            cgka_traits::TransportEnvelope::Welcome { .. }
        ));
        if lost_reply {
            publication.abort();
            assert!(publication.await.unwrap_err().is_cancelled());
        } else {
            action.cancel();
            assert!(matches!(
                tokio::time::timeout(std::time::Duration::from_secs(2), publication)
                    .await
                    .expect("original cancellation must interrupt blocked Remove")
                    .unwrap(),
                Err(crate::GroupDeviceRevocationError::Closed)
            ));
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if matches!(
                    action.snapshot().await,
                    Err(crate::GroupDeviceRevocationError::Closed)
                ) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("lost reply must negatively retire the exact original removal");
        assert!(matches!(
            action.approve(displayed.revision).await,
            Err(crate::GroupDeviceRevocationError::Closed)
        ));
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let actual = fixture.runtimes[0]
                    .group_mls_state("test", &fixture.chat)
                    .await
                    .unwrap();
                if actual.lifecycle_state == crate::AppGroupLifecycleState::Stable {
                    assert_eq!(actual.epoch, before.epoch);
                    assert_eq!(actual.member_count, before.member_count);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("exact negative pending cleanup must preserve original four-leaf epoch");
        let storage = fixture.apps[0].account_storage("test").unwrap();
        let actual = openmls::group::MlsGroup::load(
            storage.mls_storage(),
            &openmls::group::GroupId::from_slice(fixture.chat.as_slice()),
        )
        .unwrap()
        .unwrap();
        assert!(actual.pending_commit().is_none());
        assert_eq!(actual.epoch().as_u64(), before.epoch);
        assert_eq!(actual.members().count(), 4);
        release.notify_one();
        drop(release_on_drop);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let event_id = nostr_sdk::prelude::EventId::from_slice(held.id.as_slice()).unwrap();
        let published = relay_reader
            .fetch_events(nostr_sdk::prelude::ReqTarget::single(
                fixture.url.as_str(),
                [nostr_sdk::prelude::Filter::new().ids([event_id])],
            ))
            .timeout(std::time::Duration::from_secs(5))
            .await
            .unwrap();
        assert!(
            published.is_empty(),
            "late released original Remove must never publish after negative retirement"
        );
        for app in [
            &fixture.apps[0],
            &fixture.apps[1],
            &fixture.apps[2],
            &fixture.d_app,
        ] {
            let storage = app.account_storage("test").unwrap();
            let actual = openmls::group::MlsGroup::load(
                storage.mls_storage(),
                &openmls::group::GroupId::from_slice(fixture.chat.as_slice()),
            )
            .unwrap()
            .unwrap();
            assert!(actual.is_active());
            assert_eq!(actual.members().count(), 4);
        }
        let fresh = fixture.runtimes[0]
            .accounts()
            .begin_group_device_revocation("test", &fixture.chat, displayed.target_device)
            .await
            .unwrap();
        assert_eq!(fresh.snapshot().await.unwrap().epoch, before.epoch);
        fresh.cancel();
    }
    async fn assert_blocked_selected_publication_terminal(
        fixture: &SelectedChatFixture,
        request: crate::SelectedChatCopy,
        relay_reader: &nostr_sdk::prelude::Client,
        welcome: bool,
        lost_reply: bool,
    ) {
        let before = fixture.runtimes[0]
            .group_mls_state("test", &fixture.chat)
            .await
            .unwrap();
        let account = fixture.apps[0].account_home().account("test").unwrap();
        let account = cgka_traits::MemberId::new(hex::decode(account.account_id_hex).unwrap());
        let (held, release) = if welcome {
            fixture.apps[0]
                .relay_plane
                .hold_next_selected_welcome(account)
        } else {
            fixture.apps[0]
                .relay_plane
                .hold_next_selected_commit(account)
        };
        let release_on_drop = ReleaseSelectedWelcome(release.clone());
        let request = std::sync::Arc::new(request);
        let revision = request.snapshot().await.unwrap().revision;
        let operation = request.clone();
        let mut continuation = tokio::spawn(async move { operation.continue_copy(revision).await });
        let _abort_on_drop = AbortSelectedContinuation(continuation.abort_handle());
        let held = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            tokio::select! {
                message = held => message.unwrap(),
                result = &mut continuation => panic!("original continuation escaped publication gate: {result:?}"),
            }
        }).await.expect("actual selected publication must reach its original transport gate");
        assert_eq!(
            matches!(
                held.envelope,
                cgka_traits::TransportEnvelope::Welcome { .. }
            ),
            welcome
        );
        if lost_reply {
            continuation.abort();
            assert!(continuation.await.unwrap_err().is_cancelled());
        } else {
            tokio::time::timeout(std::time::Duration::from_millis(500), request.cancel())
                .await
                .expect("exact cancellation must not wait for blocked transport")
                .unwrap();
            assert!(matches!(
                tokio::time::timeout(std::time::Duration::from_secs(2), continuation)
                    .await
                    .expect("original cancellation must release continuation")
                    .unwrap(),
                Err(crate::SelectedChatCopyError::Closed)
            ));
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if request.snapshot().await.unwrap().phase
                    == crate::SelectedChatCopyPhase::Cancelled
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("lost reply must retire the same original request");
        assert!(matches!(
            request
                .continue_copy(request.snapshot().await.unwrap().revision)
                .await,
            Err(crate::SelectedChatCopyError::Closed)
        ));
        let expected_epoch = before.epoch + u64::from(welcome);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let actual = fixture.runtimes[0]
                    .group_mls_state("test", &fixture.chat)
                    .await
                    .unwrap();
                if actual.lifecycle_state == crate::AppGroupLifecycleState::Stable {
                    assert_eq!(
                        actual.epoch, expected_epoch,
                        "negative cleanup must preserve canonical confirmation"
                    );
                    assert_eq!(
                        actual.member_count,
                        if welcome { 4 } else { before.member_count }
                    );
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("exact pending publication cleanup must restore stable owned state");
        let storage = fixture.apps[0].account_storage("test").unwrap();
        let actual = openmls::group::MlsGroup::load(
            storage.mls_storage(),
            &openmls::group::GroupId::from_slice(fixture.chat.as_slice()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(actual.epoch().as_u64(), expected_epoch);
        assert!(actual.pending_commit().is_none());
        release.notify_one();
        drop(release_on_drop);
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let event_id = nostr_sdk::prelude::EventId::from_slice(held.id.as_slice()).unwrap();
        let published = relay_reader
            .fetch_events(nostr_sdk::prelude::ReqTarget::single(
                fixture.url.as_str(),
                [nostr_sdk::prelude::Filter::new().ids([event_id])],
            ))
            .timeout(std::time::Duration::from_secs(5))
            .await
            .unwrap();
        assert!(
            published.is_empty(),
            "released blocked original must never publish after cancellation or lost reply"
        );
        let remote = fixture
            .d_runtime
            .group_mls_state("test", &fixture.chat)
            .await
            .unwrap();
        assert_eq!(remote.epoch, expected_epoch);
        for index in [1, 2] {
            assert!(
                fixture.runtimes[index]
                    .group_mls_state("test", &fixture.chat)
                    .await
                    .is_err()
            );
            assert!(
                fixture.apps[index]
                    .group("test", &fixture.chat_hex)
                    .unwrap()
                    .is_none()
            );
            let rows = fixture.apps[index]
                .account_storage("test")
                .unwrap()
                .selected_chat_key_package_storage()
                .unwrap()
                .selected_chat_key_packages()
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert!(
                rows[0].state
                    == cgka_traits::selected_chat_key_package::SelectedChatPurposeState::Pending
            );
        }
    }

    async fn observe_challenge_while_successor_rolled_back(
        fixture: &SelectedChatFixture,
        relay_reader: &nostr_sdk::prelude::Client,
        protected: &cgka_traits::GroupId,
        observation: ChallengeBeforeRetry,
        intake: Option<&cgka_engine::private_settlement_test_observation::Observer>,
    ) -> Result<bool, &'static str> {
        let source = fixture.apps[0]
            .account_storage("test")
            .map_err(|_| "source storage unavailable")?;
        let recipient = fixture.apps[1]
            .account_storage("test")
            .map_err(|_| "recipient storage unavailable")?;
        let predecessor_epoch = if matches!(
            observation,
            ChallengeBeforeRetry::InitialPeel | ChallengeBeforeRetry::RefreshedRollbackRoute
        ) {
            let actual = openmls::group::MlsGroup::load(
                recipient.mls_storage(),
                &openmls::group::GroupId::from_slice(protected.as_slice()),
            )
            .map_err(|_| "recipient predecessor MLS unavailable")?
            .ok_or("recipient predecessor MLS absent")?;
            let epoch = actual.epoch().as_u64();
            if epoch == 0 {
                return Err("initial peel discriminator requires nonzero actual predecessor epoch");
            }
            Some(epoch)
        } else {
            None
        };
        let (message, canonical, ciphertext, event, account) =
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                loop {
                    let roster = source
                        .private_roster_settlement_storage()
                        .ok_or("source roster unavailable")?;
                    let round = roster
                        .read_round()
                        .map_err(|_| "source round unavailable")?
                        .ok_or("source round absent")?;
                    if round.anchor.group_id != *protected
                        || !matches!(
                            round.anchor.origin,
                            cgka_traits::private_device_invite::PrivateInviteOrigin::Revoked(_)
                        )
                    {
                        return Err("source successor scope mismatch");
                    }
                    if let (Some(bytes), Some(ciphertext)) =
                        (&round.outbound, &round.prepared_ciphertext)
                    {
                        let actual = openmls::group::MlsGroup::load(
                            source.mls_storage(),
                            &openmls::group::GroupId::from_slice(protected.as_slice()),
                        )
                        .map_err(|_| "source MLS observation unavailable")?
                        .ok_or("source MLS group absent")?;
                        if actual.epoch().as_u64() != round.anchor.successor.epoch.0
                            || !actual.own_leaf_node().is_some_and(|leaf| {
                                leaf.signature_key().as_slice() == round.anchor.coordinator
                            })
                        {
                            return Err("source current successor mismatch");
                        }
                        let result: cgka_traits::engine::SendResult = serde_json::from_slice(bytes)
                            .map_err(|_| "outbound decode unavailable")?;
                        let cgka_traits::engine::SendResult::ApplicationMessage {
                            msg,
                            group_id,
                            source_epoch,
                            ..
                        } = result
                        else {
                            return Err("outbound kind mismatch");
                        };
                        if group_id != *protected || source_epoch != round.anchor.successor.epoch {
                            return Err("outbound successor mismatch");
                        }
                        let fact = roster
                            .read_facts()
                            .map_err(|_| "source facts unavailable")?
                            .into_iter()
                            .find(|fact| {
                                fact.generation == round.generation
                                    && Some(fact.leaf_index) == round.coordinator_leaf_index
                                    && fact.signature_public_key == round.anchor.coordinator
                            })
                            .ok_or("exact coordinator fact absent")?;
                        let event_id = nostr_sdk::prelude::EventId::from_slice(msg.id.as_slice())
                            .map_err(|_| "outbound event unavailable")?;
                        let events = relay_reader
                            .fetch_events(nostr_sdk::prelude::ReqTarget::single(
                                fixture.url.as_str(),
                                [nostr_sdk::prelude::Filter::new().ids([event_id])],
                            ))
                            .timeout(std::time::Duration::from_secs(2))
                            .await
                            .map_err(|_| "relay observation unavailable")?;
                        if let Some(event) = events
                            .iter()
                            .find(|event| event.id == event_id && event.verify().is_ok())
                        {
                            break Ok((
                                msg,
                                fact.message_id,
                                ciphertext.clone(),
                                event.clone(),
                                round.anchor.account,
                            ));
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .map_err(|_| "challenge publication prerequisite timed out")??;
        // A transport wrapper may be parked before MLS keys are available. A
        // canonical row instead proves exact peeled ciphertext receipt. Neither
        // row state grants a live original or a settled roster.
        let mut exact_attempt_observation = None;
        let observed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                for id in [&message.id, &canonical] {
                    match recipient.get_message(id) {
                        Ok(row) => {
                            let payload = cgka_traits::StoredMessagePayload::decode(&row.payload)
                                .map_err(|_| "recipient payload unavailable")?;
                            let exact_outer = payload.as_exact_transport().is_some_and(|stored| {
                                stored.id == message.id && stored.payload == message.payload
                            });
                            let exact_inner = row.id == canonical
                                && row.group_id == *protected
                                && payload
                                    .as_openmls_wire()
                                    .is_some_and(|stored| stored.payload == ciphertext);
                            if matches!(observation, ChallengeBeforeRetry::InitialPeel | ChallengeBeforeRetry::RefreshedRollbackRoute) {
                                if exact_outer || exact_inner {
                                    exact_attempt_observation = Some((row.state,
                                        Some(row.epoch.0) == predecessor_epoch));
                                }
                                // These bytes and epoch come from the real handler's
                                // persisted row, not a fixture rewrite. The only two raw
                                // PeelDeferred writes stamp epoch0 before quarantine,
                                // or current_epoch after completed peel/fallback refusal.
                                // A nonzero exact predecessor stamp distinguishes the
                                // latter; it does not prove private-frame decryption.
                                if exact_outer && row.group_id == *protected
                                    && row.state == cgka_traits::MessageState::PeelDeferred
                                    && Some(row.epoch.0) == predecessor_epoch
                                {
                                    eprintln!("revocation_challenge_initial_peel exact_outer=true state=peel_deferred persisted_epoch_matches_actual_nonzero_predecessor=true private_frame_decryption_proven=false");
                                    return Ok(true);
                                }
                            } else if exact_outer || exact_inner {
                                return Ok(true);
                            }
                        }
                        Err(cgka_traits::storage::StorageError::NotFound) => {}
                        Err(_) => return Err("recipient row unavailable"),
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        match observed {
            Ok(result) => result,
            Err(_)
                if matches!(
                    observation,
                    ChallengeBeforeRetry::InitialPeel
                        | ChallengeBeforeRetry::RefreshedRollbackRoute
                ) =>
            {
                eprintln!(
                    "revocation_challenge_initial_peel_prerequisite_unmet exact_state_epoch_matches_predecessor={exact_attempt_observation:?}"
                );
                // Observe only after the unchanged prerequisite has failed.
                // Neither cached/filter evidence nor private intake counts grant authority.
                let account = cgka_traits::MemberId::new(account.to_vec());
                let plane = &fixture.apps[1].relay_plane;
                let notifications = plane
                    .account_notification_disposition_for_test(&account, &event.id.to_string());
                let sdk = match serde_json::to_string(&event) {
                    Ok(encoded) => Some(
                        tokio::time::timeout(
                            std::time::Duration::from_secs(2),
                            plane.account_sdk_event_observation_for_test(&account, &encoded),
                        )
                        .await,
                    ),
                    Err(_) => None,
                };
                eprintln!(
                    "revocation_initial_peel_post_failure notification_raw_zero_positive_error_router_missing_present={notifications:?} sdk_cached_filter_untimed={sdk:?} core_exact={:?} core_group={:?}",
                    intake.map(|observer| observer.summary(Some(&canonical))),
                    intake.map(|observer| observer.summary(None))
                );
                Err("exact challenge initial peel epoch prerequisite timed out")
            }
            Err(_) => Ok(false), // Publication is known; arrival remains unproved.
        }
    }

    struct RevokedPredecessorOwners {
        custody: crate::client::device_linking::RevocationRetryCustodyForTest,
        original_group: cgka_traits::GroupId,
        original_binding: [u8; 32],
        previous_b_fact: cgka_traits::revoked_device_group_anchor::RevokedDeviceGroupFact,
        _source: DeviceLinkingSession,
        _recipient: DeviceLinkingSession,
        _approvals: Vec<DeviceLinkingApproval>,
    }

    /// Create a genuine previous Revoked original through explicit public
    /// all-leaf enrollment and an actual first Remove. No SQL grants or MLS
    /// state are copied. This is not automatic fourth-device enrollment proof.
    async fn establish_actual_revoked_predecessor(
        fixture: &SelectedChatFixture,
        managers: &[crate::runtime::AccountManager; 3],
    ) -> RevokedPredecessorOwners {
        use cgka_traits::GroupStorage;
        use futures::FutureExt;
        fixture._a.cancel().await.unwrap();
        fixture._c.cancel().await.unwrap();
        fixture._approval.cancel().await.unwrap();
        let e_dir = tempfile::tempdir().unwrap();
        let keys = fixture.apps[0]
            .account_home()
            .load_signing_keys("test")
            .unwrap();
        AccountHome::open(e_dir.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        let e_app = MarmotApp::with_relay(e_dir.path(), &fixture.url);
        let e_runtime = MarmotAppRuntime::new(e_app.clone());
        e_runtime.reconcile_accounts().await.unwrap();
        let e_manager = e_runtime.accounts();
        let verdict = std::panic::AssertUnwindSafe(async {
            let targets = managers[0].device_linking_targets("test").await.unwrap();
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].device_count, 3);
            let e = e_manager.begin_device_linking_session("test").await.unwrap();
            let a = managers[0].approve_device_linking_session("test", e.setup_packet(), Some(targets[0].selector.clone())).await.unwrap();
            verify_public_pair(&a, &e).await;
            e.continue_linking(e.snapshot().await.unwrap().revision).await.unwrap();
            a.continue_linking(a.snapshot().await.unwrap().revision).await.unwrap();
            let mut approvals = Vec::new();
            for manager in &managers[1..] {
                let approval = tokio::time::timeout(std::time::Duration::from_secs(20), async {
                    loop {
                        if let Some(original) = manager.pending_device_linking_approvals("test").await.unwrap().pop() { break original; }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }).await.expect("each actual B/C device must receive the genuine fourth-device proposal");
                let review = approval.snapshot().await.unwrap();
                assert_eq!(review.phase, DeviceLinkingApprovalPhase::AwaitingApproval);
                approval.approve(review.revision).await.unwrap();
                approvals.push(approval);
            }
            assert_eq!(approvals.len(), 2);
            let packet = tokio::time::timeout(std::time::Duration::from_secs(20), async {
                loop {
                    if let Ok(packet) = a.enrollment_packet(a.snapshot().await.unwrap().revision).await { break packet; }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }).await.expect("original A must collect both authentic B/C endorsements");
            e.receive_enrollment_packet(e.snapshot().await.unwrap().revision, packet.clone()).await.unwrap();
            for approval in &approvals {
                approval.receive_enrollment_packet(approval.snapshot().await.unwrap().revision, packet.clone()).await.unwrap();
            }
            a.finalize_linking(a.snapshot().await.unwrap().revision).await.unwrap();
            let enrolled = [fixture.apps[0].clone(), fixture.apps[1].clone(), fixture.apps[2].clone(), e_app.clone()];
            wait_actual_roster(&enrolled, 4).await;
            let e_storage = e_app.account_storage("test").unwrap();
            let before = fixture.apps[0].account_storage("test").unwrap()
                .private_roster_settlement_storage().unwrap().read_round().unwrap().unwrap();
            let protected = before.anchor.group_id;
            let e_group = openmls::group::MlsGroup::load(e_storage.mls_storage(), &openmls::group::GroupId::from_slice(protected.as_slice())).unwrap().unwrap();
            assert_eq!(e_group.members().count(), 4);
            let exact_e = e_group.own_leaf_node().unwrap().signature_key().as_slice().to_vec();
            let first = managers[0].begin_device_revocation("test", exact_e.clone()).await.unwrap();
            let review = first.snapshot().await.unwrap();
            assert_eq!(review.protected_group, protected);
            assert!(review.ordinary_groups.is_empty(), "fresh E must not have inherited ordinary MLS state");
            first.approve(review.revision).await.unwrap();
            wait_actual_roster(&fixture.apps, 3).await;
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                loop {
                    if e_storage.get_group(&protected).unwrap().removed { break; }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }).await.expect("E must actually realize its authenticated protected removal");
            assert!(first.snapshot().await.unwrap().complete);
            let b_round = fixture.apps[1].account_storage("test").unwrap()
                .private_roster_settlement_storage().unwrap().read_round().unwrap().unwrap();
            assert!(b_round.phase == cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed);
            assert!(matches!(b_round.anchor.origin, cgka_traits::private_device_invite::PrivateInviteOrigin::Revoked(_)));
            assert_eq!(b_round.anchor.successor.leaves.len(), 3);
            let previous_b_fact = fixture.apps[1].account_storage("test").unwrap()
                .revoked_device_group_anchor_storage().unwrap().revoked_anchor().unwrap()
                .expect("actual first E removal must retain its negative provenance");
            assert!(previous_b_fact.draft.group_id == protected
                && previous_b_fact.draft.removed_device.as_slice() == exact_e.as_slice()
                && previous_b_fact.draft.predecessor.leaves.len() == 4
                && previous_b_fact.draft.successor.leaves.len() == 3,
                "captured B negative provenance must be the genuine first E removal");
            let (before_cancel, custody) = managers[1].live_revocation_settlement_binding_for_test("test", &protected).await.unwrap();
            assert!(before_cancel == Some(b_round.anchor.context_digest), "B must retain its actual Completed Revoked original binding");
            // Release only the completed A source action's exclusive slot.
            // B's actual received original is independently owned and stays live.
            first.cancel();
            let (after_cancel, _) = managers[1].live_revocation_settlement_binding_for_test("test", &protected).await.unwrap();
            assert!(after_cancel == before_cancel, "cancelling only A must preserve B's independent received original");
            eprintln!("successive_revocation_predecessor actual_four_leaf_enrollment=true first_remove_completed=true previous_received_control_live=true source_only_cancelled=true");
            {
                let observed = custody.lock().unwrap();
                assert!(observed.entries.is_empty() && !observed.overflow, "no previous fault may populate the fresh custody observation");
            }
            RevokedPredecessorOwners { custody, original_group: protected, original_binding: b_round.anchor.context_digest, previous_b_fact, _source: a, _recipient: e, _approvals: approvals }
        }).catch_unwind().await;
        e_runtime.shutdown_and_close().await.unwrap();
        eprintln!("successive_revocation_extra_positive_closes=1 original_verdict_preserved=true");
        match verdict {
            Ok(owners) => owners,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    async fn assert_device_roster_removal(
        fixture: &SelectedChatFixture,
        managers: &[crate::runtime::AccountManager; 3],
        relay_reader: &nostr_sdk::prelude::Client,
        require_fresh_successor: bool,
        retained_remove_reopen: bool,
        retained_remove_storage_retry: bool,
        observation: (
            Option<ChallengeBeforeRetry>,
            Option<&cgka_traits::revoked_device_group_anchor::RevokedDeviceGroupFact>,
        ),
    ) {
        let (challenge_before_retry, preceding_revoked_anchor) = observation;
        use cgka_traits::{GroupStorage, StorageProvider};
        let d = fixture.d_app.account_home().account("test").unwrap();
        fixture.d_runtime.publish_key_package("test").await.unwrap();
        let second = fixture.runtimes[0]
            .create_group(
                "test",
                "Second independently joined chat",
                std::slice::from_ref(&d.account_id_hex),
                None,
            )
            .await
            .unwrap();
        assert_ne!(second, fixture.chat);
        let second_hex = hex::encode(second.as_slice());
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while fixture.d_app.group("test", &second_hex).unwrap().is_none() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("D must genuinely join the second ordinary chat");
        let target = managers[0]
            .device_linking_targets("test")
            .await
            .unwrap()
            .pop()
            .unwrap();
        let copy = managers[0]
            .begin_selected_chat_copy("test", &second, target.selector)
            .await
            .unwrap();
        let packet = copy
            .request_packet(copy.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        let mut consents = Vec::new();
        for manager in &managers[1..] {
            let consent = manager
                .receive_selected_chat_copy_request("test", packet.clone())
                .await
                .unwrap();
            consent
                .approve(consent.snapshot().await.unwrap().revision)
                .await
                .unwrap();
            let response = consent
                .response_packet(consent.snapshot().await.unwrap().revision)
                .await
                .unwrap();
            copy.receive_consent_packet(copy.snapshot().await.unwrap().revision, response)
                .await
                .unwrap();
            let offer = consent
                .offer_packet(consent.snapshot().await.unwrap().revision)
                .await
                .unwrap();
            copy.receive_offer_packet(copy.snapshot().await.unwrap().revision, offer)
                .await
                .unwrap();
            consents.push(consent);
        }
        copy.continue_copy(copy.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        let runtimes = [
            &fixture.runtimes[0],
            &fixture.runtimes[1],
            &fixture.runtimes[2],
            &fixture.d_runtime,
        ];
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let mut joined = true;
                for runtime in runtimes {
                    joined &= runtime
                        .group_mls_state("test", &second)
                        .await
                        .is_ok_and(|state| state.member_count == 4);
                }
                if joined {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("all four independent devices must join the second real chat");
        let storage = fixture.apps[0].account_storage("test").unwrap();
        let old_round = storage
            .private_roster_settlement_storage()
            .unwrap()
            .read_round()
            .unwrap()
            .unwrap();
        let protected = old_round.anchor.group_id.clone();
        let predecessor_generations: Vec<_> = fixture.apps[..2]
            .iter()
            .map(|app| {
                app.account_storage("test")
                    .unwrap()
                    .private_roster_settlement_storage()
                    .unwrap()
                    .read_round()
                    .unwrap()
                    .unwrap()
                    .generation
            })
            .collect();
        let c_storage = fixture.apps[2].account_storage("test").unwrap();
        let c_group = openmls::group::MlsGroup::load(
            c_storage.mls_storage(),
            &openmls::group::GroupId::from_slice(protected.as_slice()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(c_group.members().count(), 3);
        let target_device = c_group
            .own_leaf_node()
            .unwrap()
            .signature_key()
            .as_slice()
            .to_vec();
        let mut before_epochs = std::collections::BTreeMap::new();
        for group in [&fixture.chat, &second, &protected] {
            let actual = openmls::group::MlsGroup::load(
                storage.mls_storage(),
                &openmls::group::GroupId::from_slice(group.as_slice()),
            )
            .unwrap()
            .unwrap();
            assert!(
                actual
                    .members()
                    .any(|leaf| leaf.signature_key.as_slice() == target_device)
            );
            before_epochs.insert(hex::encode(group.as_slice()), actual.epoch().as_u64());
        }
        let original = managers[0].begin_device_revocation("test", target_device.clone()).await
            .expect("fresh original device review must cover the protected roster and both actual ordinary chats");
        let review = original.snapshot().await.unwrap();
        assert_eq!(review.protected_group, protected);
        assert_eq!(review.target_device, target_device);
        assert!(!review.complete);
        assert!(review.completed_groups.is_empty());
        assert!(matches!(
            original.approve(review.revision + 1).await,
            Err(crate::GroupDeviceRevocationError::StaleRevision)
        ));
        assert!(matches!(
            managers[0]
                .begin_device_revocation("test", target_device.clone())
                .await,
            Err(crate::GroupDeviceRevocationError::Busy)
        ));
        assert!(matches!(
            managers[0]
                .begin_group_device_revocation("test", &protected, target_device.clone())
                .await,
            Err(crate::GroupDeviceRevocationError::InvalidSelection)
        ));
        for app in [&fixture.apps[0], &fixture.d_app] {
            let local = app.account_storage("test").unwrap();
            let actual = openmls::group::MlsGroup::load(
                local.mls_storage(),
                &openmls::group::GroupId::from_slice(fixture.chat.as_slice()),
            )
            .unwrap()
            .unwrap();
            let refused = actual
                .own_leaf_node()
                .unwrap()
                .signature_key()
                .as_slice()
                .to_vec();
            assert!(matches!(
                managers[0].begin_device_revocation("test", refused).await,
                Err(crate::GroupDeviceRevocationError::InvalidSelection)
            ));
        }
        assert_eq!(
            review
                .ordinary_groups
                .iter()
                .map(|group| hex::encode(group.as_slice()))
                .collect::<std::collections::BTreeSet<_>>(),
            [fixture.chat_hex.clone(), second_hex.clone()]
                .into_iter()
                .collect()
        );
        let confirmation_write_fault = matches!(
            challenge_before_retry,
            Some(ChallengeBeforeRetry::ConfirmationWriteAfterSuccessor)
        );
        let predecessor_settlement = if challenge_before_retry.is_some() {
            let storage = fixture.apps[1].account_storage("test").unwrap();
            let roster = storage.private_roster_settlement_storage().unwrap();
            let round = roster.read_round().unwrap().unwrap();
            assert!(
                round.phase
                    == cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed,
                "actual retry predecessor must already be Completed"
            );
            Some((
                round.generation,
                round.phase,
                roster.read_facts().unwrap().len(),
            ))
        } else {
            None
        };
        let settlement_intake =
            (retained_remove_storage_retry || confirmation_write_fault).then(|| {
                (|| -> Result<_, &'static str> {
                    let storage = fixture.apps[1]
                        .account_storage("test")
                        .map_err(|_| "intake observer storage unavailable")?;
                    let group = openmls::group::MlsGroup::load(
                        storage.mls_storage(),
                        &openmls::group::GroupId::from_slice(protected.as_slice()),
                    )
                    .map_err(|_| "intake observer group unavailable")?
                    .ok_or("intake observer group absent")?;
                    let recipient: [u8; 32] = group
                        .own_leaf_node()
                        .ok_or("intake observer recipient absent")?
                        .signature_key()
                        .as_slice()
                        .try_into()
                        .map_err(|_| "intake observer recipient unavailable")?;
                    cgka_engine::private_settlement_test_observation::arm(&protected, recipient)
                })()
            });
        let mut a_errors = fixture.runtimes[0].subscribe();
        let mut b_errors = fixture.runtimes[1].subscribe();
        let held_route_challenge = matches!(
            challenge_before_retry,
            Some(ChallengeBeforeRetry::RefreshedRollbackRoute)
        )
        .then(|| {
            let account = fixture.apps[0].account_home().account("test").unwrap();
            fixture.apps[0].relay_plane.hold_next_private_confirmation(
                cgka_traits::MemberId::new(hex::decode(account.account_id_hex).unwrap()),
                protected.clone(),
            )
        });
        let fault = if retained_remove_reopen || retained_remove_storage_retry {
            let app = &fixture.apps[1];
            let path = app.account_storage_path("test");
            let keys = app.account_home().load_signing_keys("test").unwrap();
            let key = app
                .sqlcipher_key(
                    "test",
                    &keys,
                    &path,
                    crate::sqlcipher::SqlcipherDatabaseKind::Session,
                )
                .unwrap();
            let connection = rusqlite::Connection::open(path).unwrap();
            storage_sqlite::open_hardened_sqlcipher(
                &connection,
                &key,
                storage_sqlite::SqlCipherHardening::cipher_only(),
            )
            .unwrap();
            connection.execute_batch("CREATE TRIGGER reject_revoked_successor BEFORE INSERT ON revoked_device_group_anchor BEGIN SELECT RAISE(ABORT,'isolated Remove successor rollback'); END;").unwrap();
            Some(connection)
        } else {
            None
        };
        if confirmation_write_fault {
            let account = fixture.apps[0].account_home().account("test").unwrap();
            let (held, release) = fixture.apps[0].relay_plane.hold_next_private_confirmation(
                cgka_traits::MemberId::new(hex::decode(account.account_id_hex).unwrap()),
                protected.clone(),
            );
            let inject_late_fault = async {
                let actual_wire = tokio::time::timeout(std::time::Duration::from_secs(20), held)
                    .await
                    .expect("actual source Challenge must reach the real publication seam")
                    .expect("source confirmation observation remains owned");
                let source = fixture.apps[0].account_storage("test").unwrap();
                let source_roster = source.private_roster_settlement_storage().unwrap();
                let source_round = source_roster.read_round().unwrap().unwrap();
                let coordinator = source_round.coordinator_leaf_index.unwrap();
                assert_eq!(
                    source_round.anchor.local_device, source_round.anchor.coordinator,
                    "held source must be the actual current coordinator"
                );
                let canonical = source_roster
                    .read_facts()
                    .unwrap()
                    .into_iter()
                    .find(|fact| {
                        fact.generation == source_round.generation
                            && fact.leaf_index == coordinator
                            && fact.signature_public_key == source_round.anchor.coordinator
                    })
                    .expect("actual coordinator must have prepared the held Challenge")
                    .message_id;
                let actual: cgka_traits::engine::SendResult =
                    serde_json::from_slice(source_round.outbound.as_ref().unwrap()).unwrap();
                let cgka_traits::engine::SendResult::ApplicationMessage {
                    msg,
                    group_id,
                    source_epoch,
                    ..
                } = actual
                else {
                    panic!("actual held Challenge kind");
                };
                assert!(
                    msg.id == actual_wire.id
                        && msg.payload == actual_wire.payload
                        && group_id == protected
                        && source_epoch == source_round.anchor.successor.epoch
                );
                let recipient = fixture.apps[1].account_storage("test").unwrap();
                tokio::time::timeout(std::time::Duration::from_secs(20), async {
                    loop {
                        let tree = openmls::group::MlsGroup::load(
                            recipient.mls_storage(),
                            &openmls::group::GroupId::from_slice(protected.as_slice()),
                        )
                        .unwrap()
                        .unwrap();
                        let anchor = recipient
                            .revoked_device_group_anchor_storage()
                            .unwrap()
                            .revoked_anchor()
                            .unwrap();
                        if tree.epoch().as_u64()
                            == before_epochs[&hex::encode(protected.as_slice())] + 1
                            && tree.members().count() == 2
                            && !tree
                                .members()
                                .any(|leaf| leaf.signature_key.as_slice() == target_device)
                            && anchor.is_some_and(|anchor| {
                                !anchor.denied
                                    && anchor.draft.successor == source_round.anchor.successor
                            })
                        {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                })
                .await
                .expect(
                    "real B protected Remove successor must commit before fact fault injection",
                );
                let round = recipient
                    .private_roster_settlement_storage()
                    .unwrap()
                    .read_round()
                    .unwrap()
                    .unwrap();
                assert!(
                    round.phase
                        == cgka_traits::private_roster_settlement::PrivateSettlementPhase::Pending
                        && round.generation == predecessor_settlement.unwrap().0 + 1
                        && round.anchor.successor == source_round.anchor.successor
                        && recipient
                            .private_roster_settlement_storage()
                            .unwrap()
                            .read_facts()
                            .unwrap()
                            .is_empty()
                );
                let app = &fixture.apps[1];
                let path = app.account_storage_path("test");
                let keys = app.account_home().load_signing_keys("test").unwrap();
                let key = app
                    .sqlcipher_key(
                        "test",
                        &keys,
                        &path,
                        crate::sqlcipher::SqlcipherDatabaseKind::Session,
                    )
                    .unwrap();
                let connection = rusqlite::Connection::open(path).unwrap();
                storage_sqlite::open_hardened_sqlcipher(
                    &connection,
                    &key,
                    storage_sqlite::SqlCipherHardening::cipher_only(),
                )
                .unwrap();
                connection.execute_batch(&format!("CREATE TRIGGER reject_revoked_confirmation BEFORE INSERT ON private_roster_settlement_facts WHEN NEW.leaf_index={coordinator} BEGIN SELECT RAISE(ABORT,'isolated successor confirmation rollback'); END;")).unwrap();
                eprintln!(
                    "revocation_confirmation_fault_successor_committed=true exact_held_challenge=true successor_round_pending_zero_facts=true"
                );
                drop(release); // Unchanged real relay publication under the same original.
                let observer = settlement_intake
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .expect("exact private intake observation must be armed");
                tokio::time::timeout(std::time::Duration::from_secs(20), async {
                    loop {
                        let summary = observer.summary(Some(&canonical));
                        assert!(
                            !summary.incomplete,
                            "exact confirmation fault observation must remain bounded"
                        );
                        if summary
                            .counts
                            .iter()
                            .any(|(kind, count)| *kind == "confirmation_write_error" && *count > 0)
                        {
                            eprintln!(
                                "revocation_confirmation_fault_exact_handler_write_failed=true"
                            );
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                })
                .await
                .expect("genuine exact Challenge must attempt B's failed confirmation write");
                connection
                    .execute_batch("DROP TRIGGER reject_revoked_confirmation;")
                    .unwrap();
                drop(connection);
            };
            let (approved, ()) = tokio::join!(original.approve(review.revision), inject_late_fault);
            approved.unwrap();
        } else {
            original.approve(review.revision).await.unwrap();
        }
        if let Some(connection) = fault {
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                loop {
                    if let crate::MarmotAppEvent::AccountError(error) =
                        b_errors.recv().await.unwrap()
                        && error.message.starts_with("runtime receive failed")
                    {
                        assert_eq!(error.message, "runtime receive failed: storage_backend");
                        break;
                    }
                }
            })
            .await
            .expect("actual protected Remove must reach the atomic successor storage fault");
            let retained_after_refresh = if let Some((held, release)) = held_route_challenge {
                let actual_wire = tokio::time::timeout(std::time::Duration::from_secs(20), held)
                    .await
                    .expect("actual source Challenge must be held before rollback route refresh")
                    .expect("actual source publication observation remains owned");
                let source = fixture.apps[0].account_storage("test").unwrap();
                let round = source
                    .private_roster_settlement_storage()
                    .unwrap()
                    .read_round()
                    .unwrap()
                    .unwrap();
                let actual: cgka_traits::engine::SendResult =
                    serde_json::from_slice(round.outbound.as_ref().unwrap()).unwrap();
                let cgka_traits::engine::SendResult::ApplicationMessage {
                    msg,
                    group_id,
                    source_epoch,
                    ..
                } = actual
                else {
                    panic!(
                        "held original Challenge must be the actual protected successor publication"
                    );
                };
                assert!(
                    msg.id == actual_wire.id
                        && msg.payload == actual_wire.payload
                        && group_id == protected
                        && source_epoch == round.anchor.successor.epoch
                );
                let (original_retry, evidence_absent, retained) = managers[1]
                    .refresh_revocation_receive_route_for_test("test", &protected)
                    .await
                    .unwrap();
                assert!(
                    original_retry && evidence_absent,
                    "actual live rollback original and unavailable current route evidence must be observed before Challenge release"
                );
                eprintln!(
                    "revocation_rollback_route actual_original_retry=true evidence_absent=true actual_subscriptions_refreshed=true retained={retained}"
                );
                drop(release);
                Some(retained)
            } else {
                None
            };
            let b_storage = fixture.apps[1].account_storage("test").unwrap();
            if let Some(previous) = preceding_revoked_anchor {
                let actual = b_storage
                    .revoked_device_group_anchor_storage()
                    .unwrap()
                    .revoked_anchor()
                    .unwrap();
                assert!(
                    actual.as_ref() == Some(previous),
                    "second Remove rollback must preserve every field of the actual previous negative anchor"
                );
            } else {
                assert!(
                    b_storage
                        .revoked_device_group_anchor_storage()
                        .unwrap()
                        .revoked_anchor()
                        .unwrap()
                        .is_none()
                );
            }
            let before = openmls::group::MlsGroup::load(
                b_storage.mls_storage(),
                &openmls::group::GroupId::from_slice(protected.as_slice()),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                before.epoch().as_u64(),
                before_epochs[&hex::encode(protected.as_slice())]
            );
            let challenge_observation = if let Some(observation) = challenge_before_retry {
                let observed = observe_challenge_while_successor_rolled_back(
                    fixture,
                    relay_reader,
                    &protected,
                    observation,
                    settlement_intake
                        .as_ref()
                        .and_then(|result| result.as_ref().ok()),
                )
                .await;
                // Recheck after the observation, before releasing the real SQL fault.
                // Relay publication alone never establishes B receipt or permission.
                if let Some(previous) = preceding_revoked_anchor {
                    let actual = b_storage
                        .revoked_device_group_anchor_storage()
                        .unwrap()
                        .revoked_anchor()
                        .unwrap();
                    assert!(
                        actual.as_ref() == Some(previous),
                        "observing a second Challenge must preserve every field of the actual previous negative anchor"
                    );
                } else {
                    assert!(
                        b_storage
                            .revoked_device_group_anchor_storage()
                            .unwrap()
                            .revoked_anchor()
                            .unwrap()
                            .is_none()
                    );
                }
                let still_before = openmls::group::MlsGroup::load(
                    b_storage.mls_storage(),
                    &openmls::group::GroupId::from_slice(protected.as_slice()),
                )
                .unwrap()
                .unwrap();
                assert_eq!(
                    still_before.epoch().as_u64(),
                    before_epochs[&hex::encode(protected.as_slice())]
                );
                let roster = b_storage.private_roster_settlement_storage().unwrap();
                let round = roster.read_round().unwrap().unwrap();
                let facts = roster.read_facts().unwrap().len();
                let before = predecessor_settlement.unwrap();
                let phase = match round.phase {
                    cgka_traits::private_roster_settlement::PrivateSettlementPhase::Pending => {
                        "pending"
                    }
                    cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed => {
                        "completed"
                    }
                    cgka_traits::private_roster_settlement::PrivateSettlementPhase::Denied => {
                        "denied"
                    }
                };
                eprintln!(
                    "revocation_held_rollback_round generation={} phase={phase} facts={facts}",
                    round.generation
                );
                assert!(
                    round.generation == before.0 && round.phase == before.1 && facts == before.2,
                    "failed successor transaction must retain exact Completed predecessor generation/phase/fact count"
                );
                Some(observed)
            } else {
                None
            };
            if retained_remove_reopen {
                fixture.runtimes[1].shutdown_and_close().await.unwrap();
            }
            connection
                .execute_batch("DROP TRIGGER reject_revoked_successor;")
                .unwrap();
            drop(connection);
            if let Some(observed) = challenge_observation {
                let received = observed.expect("genuine current successor challenge must be published while B's actual Remove is rolled back");
                assert!(
                    retained_after_refresh.unwrap_or(true),
                    "actual live rollback original must retain its existing receive route through subscription refresh"
                );
                eprintln!(
                    "revocation_challenge_before_retry relay_seen=true recipient_exact_wire_seen={received} recipient_old_epoch=true recipient_successor_anchor_absent=true"
                );
            }
            if retained_remove_reopen {
                let reopened_app = MarmotApp::with_relay(fixture.dirs[1].path(), &fixture.url);
                let reopened = MarmotAppRuntime::new(reopened_app.clone());
                reopened.reconcile_accounts().await.unwrap();
                let reopened_storage = reopened_app.account_storage("test").unwrap();
                tokio::time::timeout(std::time::Duration::from_secs(20), async {
                    loop {
                        let actual = openmls::group::MlsGroup::load(reopened_storage.mls_storage(), &openmls::group::GroupId::from_slice(protected.as_slice())).unwrap().unwrap();
                        if actual.epoch().as_u64() == before_epochs[&hex::encode(protected.as_slice())] + 1 { break; }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }).await.expect("retained authenticated Remove may complete negative membership replay after actual encrypted reopen");
                assert!(
                    reopened_storage
                        .revoked_device_group_anchor_storage()
                        .unwrap()
                        .revoked_anchor()
                        .unwrap()
                        .is_none_or(|fact| fact.denied),
                    "retained pre-restart Remove bytes must not reconstruct a fresh original positive successor guard"
                );
                let round = reopened_storage
                    .private_roster_settlement_storage()
                    .unwrap()
                    .read_round()
                    .unwrap()
                    .unwrap();
                assert!(
                    round.phase
                        == cgka_traits::private_roster_settlement::PrivateSettlementPhase::Denied
                );
                let (original_retry, evidence_absent, retained) = reopened
                    .accounts()
                    .refresh_revocation_receive_route_for_test("test", &protected)
                    .await
                    .unwrap();
                assert!(
                    !original_retry && evidence_absent && !retained,
                    "encrypted reopen must not reconstruct a private receive route from a retired rollback original"
                );
                reopened.shutdown_and_close().await.unwrap();
                return;
            }
        }
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let mut complete = true;
                for group in [&fixture.chat, &second, &protected] {
                    for (index, app) in [&fixture.apps[0], &fixture.apps[1], &fixture.d_app].into_iter().enumerate() {
                        if group == &protected && index == 2 { continue; }
                        let local = app.account_storage("test").unwrap();
                        let actual = openmls::group::MlsGroup::load(local.mls_storage(), &openmls::group::GroupId::from_slice(group.as_slice())).unwrap().unwrap();
                        complete &= actual.epoch().as_u64() == before_epochs[&hex::encode(group.as_slice())] + 1
                            && actual.members().count() == if group == &protected { 2 } else { 3 }
                            && !actual.members().any(|leaf| leaf.signature_key.as_slice() == target_device);
                    }
                    complete &= c_storage.get_group(group).unwrap().removed;
                }
                if complete { break; }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }).await.expect("exact C leaf must be evicted from the protected group and both chats while A/B/D survive");
        let completed = original.snapshot().await.unwrap();
        assert!(completed.complete);
        assert_eq!(completed.revision, review.revision + 1);
        assert_eq!(completed.completed_groups.len(), 3);
        assert!(matches!(
            original.approve(review.revision).await,
            Err(crate::GroupDeviceRevocationError::StaleRevision)
        ));
        original.approve(completed.revision).await.unwrap();
        // Old positive lineage cannot survive an authenticated protected-tree change.
        let mut retained_origins = 0;
        for (index, app) in fixture.apps.iter().enumerate() {
            let local = app.account_storage("test").unwrap();
            let round = local
                .private_roster_settlement_storage()
                .unwrap()
                .read_round()
                .unwrap()
                .unwrap();
            if index == 2 {
                assert!(
                    round.phase
                        == cgka_traits::private_roster_settlement::PrivateSettlementPhase::Denied
                );
            }
            if index < 2 {
                assert!(round.generation > predecessor_generations[index]);
                assert!(matches!(
                    round.anchor.origin,
                    cgka_traits::private_device_invite::PrivateInviteOrigin::Revoked(_)
                ));
            }
            if let Some(fact) = local
                .accepted_device_group_anchor_storage()
                .unwrap()
                .accepted_anchor()
                .unwrap()
                && fact.draft.group_id == protected
            {
                assert!(fact.denied);
                retained_origins += 1;
            }
            if let Some(fact) = local
                .private_device_invite_storage()
                .unwrap()
                .confirmed_private_invite()
                .unwrap()
                && fact.binding.group_id == protected
            {
                assert!(fact.denied);
                retained_origins += 1;
            }
            if let Some(fact) = local
                .existing_device_group_anchor_storage()
                .unwrap()
                .existing_anchor()
                .unwrap()
                && fact.draft.group_id == protected
            {
                assert!(fact.denied);
                retained_origins += 1;
            }
        }
        assert!(
            retained_origins >= 3,
            "all actual device origins must retain negative provenance"
        );
        for group in [&fixture.chat, &second] {
            assert!(
                fixture.runtimes[2]
                    .send_message("test", group, b"revoked device".to_vec())
                    .await
                    .is_err()
            );
            let message = fixture
                .d_runtime
                .send_message("test", group, b"after exact multigroup revocation".to_vec())
                .await
                .unwrap();
            assert_eq!(message.message_ids.len(), 1);
            let id = &message.message_ids[0];
            let group_hex = hex::encode(group.as_slice());
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                loop {
                    if [&fixture.apps[0], &fixture.apps[1], &fixture.d_app]
                        .into_iter()
                        .all(|app| {
                            app.timeline_message("test", &group_hex, id)
                                .unwrap()
                                .is_some()
                        })
                    {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            assert!(
                fixture.apps[2]
                    .timeline_message("test", &group_hex, id)
                    .unwrap()
                    .is_none()
            );
        }
        if require_fresh_successor {
            let surviving = fixture.apps[1].account_storage("test").unwrap();
            let actual = openmls::group::MlsGroup::load(
                surviving.mls_storage(),
                &openmls::group::GroupId::from_slice(protected.as_slice()),
            )
            .unwrap()
            .unwrap();
            let recipient = actual
                .own_leaf_node()
                .unwrap()
                .signature_key()
                .as_slice()
                .to_vec();
            let mut recipient_not_ready = 0;
            let mut begin_not_ready = 0;
            let fresh_started = std::time::Instant::now();
            let fresh = tokio::time::timeout(std::time::Duration::from_secs(25), async {
                loop {
                    let choices = match managers[0]
                        .history_transfer_recipients("test", &fixture.chat)
                        .await
                    {
                        Ok(choices) => choices,
                        Err(crate::HistoryTransferError::NotReady) => {
                            recipient_not_ready += 1;
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                            continue;
                        }
                        Err(error) => panic!("fresh successor recipient query failed: {error:?}"),
                    };
                    assert_eq!(
                        choices.len(),
                        1,
                        "only the surviving linked B device is eligible"
                    );
                    assert!(
                        choices.iter().all(|choice| choice.device != target_device),
                        "removed C cannot remain a public history recipient choice"
                    );
                    let chosen = choices
                        .into_iter()
                        .find(|choice| choice.device == recipient)
                        .expect("public query must return the actual surviving B leaf");
                    match managers[0]
                        .begin_history_transfer("test", &fixture.chat, chosen.device)
                        .await
                    {
                        Ok(original) => break original,
                        Err(crate::HistoryTransferError::NotReady) => {
                            begin_not_ready += 1;
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        }
                        Err(error) => panic!(
                            "fresh successor history authority failed before settlement: {error:?}"
                        ),
                    }
                }
            })
            .await;
            let fresh_wait_ms = fresh_started.elapsed().as_millis();
            if fresh.is_err() || retained_remove_storage_retry || confirmation_write_fault {
                // Failure-only structural observations distinguish discovery from
                // original construction without emitting keys, packets or payloads.
                let observe_rounds = || {
                    fixture.apps[..2].iter().map(|app| -> Result<_, &'static str> {
                    let storage = app.account_storage("test").map_err(|_| "account storage unavailable")?;
                    let roster = storage.private_roster_settlement_storage().ok_or("roster storage unavailable")?;
                    let round = roster.read_round().map_err(|_| "roster observation failed")?;
                    let facts = roster.read_facts().map_err(|_| "fact observation failed")?.len();
                    Ok(round.map(|round| {
                        let phase = match round.phase {
                            cgka_traits::private_roster_settlement::PrivateSettlementPhase::Pending => "pending",
                            cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed => "completed",
                            cgka_traits::private_roster_settlement::PrivateSettlementPhase::Denied => "denied",
                        };
                        (round.generation, phase, facts, round.deferred_acks.len())
                    }))
                }).collect::<Vec<_>>()
                };
                let rounds = observe_rounds();
                // These are comparisons of retained observations, never live admission.
                // Account/group and shared successor fields must match; local_device is
                // deliberately excluded because A and B are distinct surviving leaves.
                let observe_shared_anchor = || -> Result<_, &'static str> {
                    let read = |index: usize| {
                        fixture.apps[index]
                            .account_storage("test")
                            .map_err(|_| "anchor storage unavailable")?
                            .private_roster_settlement_storage()
                            .ok_or("anchor roster unavailable")?
                            .read_round()
                            .map_err(|_| "anchor round unavailable")?
                            .ok_or("anchor round absent")
                    };
                    let a = read(0)?;
                    let b = read(1)?;
                    Ok((
                        a.anchor.account == b.anchor.account,
                        a.anchor.group_id == b.anchor.group_id,
                        a.anchor.successor == b.anchor.successor,
                        a.anchor.roster_commitment == b.anchor.roster_commitment,
                        a.anchor.enrollment_nonce == b.anchor.enrollment_nonce,
                        a.anchor.context_digest == b.anchor.context_digest,
                        a.anchor.coordinator == b.anchor.coordinator,
                        (a.round_nonce.is_some(), b.round_nonce.is_some()),
                        a.round_nonce.zip(b.round_nonce).map(|(a, b)| a == b),
                    ))
                };
                let shared_anchor = observe_shared_anchor();
                // Snapshot before the bounded post-deadline relay observation.
                // A local confirmation precedes publication; it is not an ACK.
                let observe_delivery = || -> Result<_, &'static str> {
                    let a = fixture.apps[0]
                        .account_storage("test")
                        .map_err(|_| "source storage unavailable")?;
                    let b = fixture.apps[1]
                        .account_storage("test")
                        .map_err(|_| "recipient storage unavailable")?;
                    let roster = a
                        .private_roster_settlement_storage()
                        .ok_or("source roster unavailable")?;
                    let round = roster
                        .read_round()
                        .map_err(|_| "source round unavailable")?
                        .ok_or("source round absent")?;
                    let fact = roster
                        .read_facts()
                        .map_err(|_| "source facts unavailable")?
                        .into_iter()
                        .find(|fact| {
                            fact.generation == round.generation
                                && Some(fact.leaf_index) == round.coordinator_leaf_index
                                && fact.signature_public_key == round.anchor.coordinator
                        });
                    let received = fact
                        .as_ref()
                        .map(|fact| match b.get_message(&fact.message_id) {
                            Ok(row) => Ok(Some((row.group_id == round.anchor.group_id, row.state))),
                            Err(cgka_traits::storage::StorageError::NotFound) => Ok(None),
                            Err(_) => Err("recipient row unavailable"),
                        })
                        .transpose()?;
                    let outbound = round
                        .outbound
                        .as_ref()
                        .map(|bytes| {
                            serde_json::from_slice::<cgka_traits::engine::SendResult>(bytes)
                                .map_err(|_| "outbound decode unavailable")
                        })
                        .transpose()?;
                    let event_id = match outbound {
                        Some(cgka_traits::engine::SendResult::ApplicationMessage {
                            msg,
                            group_id,
                            source_epoch,
                            ..
                        }) if group_id == round.anchor.group_id
                            && source_epoch == round.anchor.successor.epoch =>
                        {
                            Some(
                                nostr_sdk::prelude::EventId::from_slice(msg.id.as_slice())
                                    .map_err(|_| "outbound event unavailable")?,
                            )
                        }
                        Some(_) => return Err("outbound scope unavailable"),
                        None => None,
                    };
                    Ok((
                        (
                            round.prepared_ciphertext.is_some(),
                            round.outbound.is_some(),
                            round.round_nonce.is_some(),
                            fact.is_some(),
                            received,
                        ),
                        event_id,
                        fact.map(|fact| fact.message_id),
                    ))
                };
                let delivery = observe_delivery();
                let exact_challenge = delivery.as_ref().ok().and_then(|(_, _, id)| id.clone());
                let intake = settlement_intake.as_ref().map(|observer| match observer {
                    Ok(observer) => Ok(observer.summary(exact_challenge.as_ref())),
                    Err(error) => Err(*error),
                });
                let source_original = match tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    original.snapshot(),
                )
                .await
                {
                    Ok(Ok(snapshot)) => Ok((snapshot.complete, snapshot.completed_groups.len())),
                    Ok(Err(_)) => Err("original snapshot refused"),
                    Err(_) => Err("original snapshot unavailable"),
                };
                let error_observations = [&mut a_errors, &mut b_errors].map(|subscription| {
                    let mut counts = [0usize; 7];
                    let mut incomplete = true;
                    for _ in 0..256 {
                        match subscription.try_recv() {
                            Ok(crate::MarmotAppEvent::AccountError(error)) => {
                                let bucket = match error.message.as_str() {
                                    "runtime receive failed: storage_backend" => 0,
                                    message if message.starts_with("runtime receive failed:") => 1,
                                    "scheduled convergence failed: storage_backend"
                                    | "scheduled convergence sync failed: storage_backend" => 2,
                                    message if message.starts_with("scheduled convergence") => 3,
                                    message
                                        if message.starts_with("scheduled maintenance failed:") =>
                                    {
                                        4
                                    }
                                    message
                                        if message.starts_with("runtime startup")
                                            || message.starts_with("runtime restart") =>
                                    {
                                        5
                                    }
                                    _ => 6,
                                };
                                counts[bucket] += 1;
                            }
                            Ok(_) => {}
                            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                                incomplete = false;
                                break;
                            }
                            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_))
                            | Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
                        }
                    }
                    (counts, incomplete)
                });
                let (delivery_state, relay_seen) = match delivery {
                    Ok((state, Some(event_id), _)) => {
                        let observed = relay_reader
                            .fetch_events(nostr_sdk::prelude::ReqTarget::single(
                                fixture.url.as_str(),
                                [nostr_sdk::prelude::Filter::new().ids([event_id])],
                            ))
                            .timeout(std::time::Duration::from_secs(2))
                            .await;
                        (
                            Ok(state),
                            observed
                                .map(|events| events.iter().any(|event| event.id == event_id))
                                .map_err(|_| "relay observation unavailable"),
                        )
                    }
                    Ok((state, None, _)) => (Ok(state), Err("outbound absent")),
                    Err(error) => (Err(error), Err("relay observation unavailable")),
                };
                match &fresh {
                    Ok(_) => eprintln!(
                        "revocation_original_progress fresh_wait_ms={fresh_wait_ms} rounds(generation,phase,facts,deferred)={rounds:?}; source(prepared,outbound,nonce,coordinator_fact,recipient_row_scope_state)={delivery_state:?}; exact_outbound_relay_seen={relay_seen:?}; actual_source_original_complete_groups={source_original:?}; shared_anchor(account,group,successor,roster,enrollment,context,coordinator,nonce_present,nonce_equal)={shared_anchor:?}; exact_challenge_intake={intake:?}; source_recipient_errors(receive_storage,receive_other,convergence_storage,convergence_other,maintenance,restart,other;incomplete)={error_observations:?}"
                    ),
                    Err(error) => {
                        // The original fixed-deadline failure is irrevocable. This
                        // observation cannot construct fresh authority or turn it into
                        // a pass; it only distinguishes delayed settlement from a stall.
                        eprintln!(
                            "revocation_original_deadline_failed fresh_wait_ms={fresh_wait_ms}; shared_anchor={shared_anchor:?}; rounds={rounds:?}; source={delivery_state:?}; relay={relay_seen:?}; exact_challenge_intake={intake:?}"
                        );
                        let later_started = tokio::time::Instant::now();
                        let later = tokio::time::timeout(
                            std::time::Duration::from_secs(55),
                            async {
                                loop {
                                    let completed = fixture.apps[..2].iter().all(|app| {
                                        app.account_storage("test")
                                            .ok()
                                            .and_then(|storage| {
                                                storage.private_roster_settlement_storage()
                                                    .and_then(|roster| roster.read_round().ok().flatten())
                                            })
                                            .is_some_and(|round| round.phase == cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed)
                                    });
                                    if completed {
                                        break;
                                    }
                                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                }
                            },
                        ).await;
                        let later_delivery = observe_delivery();
                        let later_relay = match &later_delivery {
                            Ok((_, Some(event_id), _)) => relay_reader
                                .fetch_events(nostr_sdk::prelude::ReqTarget::single(
                                    fixture.url.as_str(),
                                    [nostr_sdk::prelude::Filter::new().ids([*event_id])],
                                ))
                                .timeout(std::time::Duration::from_secs(2))
                                .await
                                .map(|events| events.iter().any(|event| event.id == *event_id))
                                .map_err(|_| "later relay observation unavailable"),
                            _ => Err("later outbound unavailable"),
                        };
                        let later_intake =
                            settlement_intake.as_ref().map(|observer| match observer {
                                Ok(observer) => Ok(observer.summary(exact_challenge.as_ref())),
                                Err(error) => Err(*error),
                            });
                        // Remove retained identifiers before safe formatting.
                        let later_delivery = later_delivery.map(|(state, _, _)| state);
                        eprintln!(
                            "revocation_original_post_failure observation_ms={} both_rounds_completed={} rounds={:?} shared_anchor={:?} source={later_delivery:?} relay={later_relay:?} exact_challenge_intake={later_intake:?}; original_failure_preserved=true",
                            later_started.elapsed().as_millis(),
                            later.is_ok(),
                            observe_rounds(),
                            observe_shared_anchor()
                        );
                        panic!(
                            "surviving A/B must regain fresh original history authority from an actually settled protected Remove successor, while every old origin remains denied: {error:?}; recipient_not_ready={recipient_not_ready}; begin_not_ready={begin_not_ready}; rounds(generation,phase,facts,deferred)={rounds:?}; source(prepared,outbound,nonce,coordinator_fact,recipient_row_scope_state)={delivery_state:?}; exact_outbound_relay_seen={relay_seen:?}; actual_source_original_complete_groups={source_original:?}; shared_anchor(account,group,successor,roster,enrollment,context,coordinator,nonce_present,nonce_equal)={shared_anchor:?}; exact_challenge_intake={intake:?}; source_recipient_errors(receive_storage,receive_other,convergence_storage,convergence_other,maintenance,restart,other;incomplete)={error_observations:?}"
                        );
                    }
                }
            }
            let fresh =
                fresh.expect("fresh authority failure already reported with safe observations");
            assert!(
                matches!(
                    managers[0]
                        .begin_history_transfer("test", &fixture.chat, target_device.clone())
                        .await,
                    Err(crate::HistoryTransferError::NotReady)
                ),
                "removed C cannot become a fresh original history recipient"
            );
            let consent = tokio::time::timeout(std::time::Duration::from_secs(15), async {
                loop {
                    if let Some(consent) = managers[1]
                        .pending_history_requests("test")
                        .await
                        .unwrap()
                        .into_iter()
                        .next()
                    {
                        break consent;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("surviving B must receive the actual fresh successor history request");
            let review = consent.snapshot().await.unwrap();
            assert_eq!(review.group, fixture.chat);
            assert_eq!(review.recipient_device, recipient);
            assert!(review.record_count > 0);
            consent.approve(review.revision).await.unwrap();
            fresh
                .continue_transfer(fresh.snapshot().await.unwrap().revision)
                .await
                .unwrap();
            let progress = fresh.snapshot().await.unwrap();
            assert!(
                progress.complete && progress.imported_records > 0,
                "fresh successor authority must reach a committed recipient import receipt"
            );
            let archived = surviving
                .app_storage()
                .synchronized_history_page(&fixture.chat_hex, None, 200, 0)
                .unwrap();
            assert!(
                archived
                    .iter()
                    .any(|record| hex::encode(record.record.message_id) == fixture.before_id),
                "surviving B must receive the genuine prejoin record after protected revocation settlement"
            );
            assert!(
                fixture.apps[2]
                    .account_storage("test")
                    .unwrap()
                    .app_storage()
                    .synchronized_history_page(&fixture.chat_hex, None, 200, 0)
                    .unwrap()
                    .is_empty(),
                "removed C must not receive the survivor's archive"
            );
            for (index, app) in fixture.apps[..2].iter().enumerate() {
                let round = app
                    .account_storage("test")
                    .unwrap()
                    .private_roster_settlement_storage()
                    .unwrap()
                    .read_round()
                    .unwrap()
                    .unwrap();
                assert!(round.phase == cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed);
                assert_eq!(round.anchor.group_id, protected);
                assert!(round.generation > predecessor_generations[index]);
            }
        }
        drop(consents);
    }

    struct AbortSelectedContinuation(tokio::task::AbortHandle);
    impl Drop for AbortSelectedContinuation {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    struct ReleaseSelectedWelcome(std::sync::Arc<tokio::sync::Notify>);
    impl Drop for ReleaseSelectedWelcome {
        fn drop(&mut self) {
            self.0.notify_one();
        }
    }

    async fn assert_foreign_selected_welcome_refused(
        fixture: &SelectedChatFixture,
        original: cgka_traits::TransportMessage,
    ) {
        use cgka_traits::peeler::TransportPeeler;
        let storage = fixture.apps[1].account_storage("test").unwrap();
        let bundles = storage.stored_key_package_bundles().unwrap();
        let packages = storage
            .selected_chat_key_package_storage()
            .unwrap()
            .selected_chat_key_packages()
            .unwrap();
        assert_eq!(packages.len(), 1);
        assert!(
            packages[0].state
                == cgka_traits::selected_chat_key_package::SelectedChatPurposeState::Pending
        );
        let keys = fixture.apps[1]
            .account_home()
            .load_signing_keys("test")
            .unwrap();
        let peeler = transport_nostr_peeler::NostrMlsPeeler::new().with_welcome_signer(keys);
        let (peeled, provenance) = peeler
            .peel_welcome_with_provenance(&original)
            .await
            .unwrap();
        let cgka_traits::ingest::PeeledContent::Welcome { bytes, .. } = peeled.content else {
            panic!("held publication is not a genuine MLS Welcome")
        };
        let cgka_traits::TransportEnvelope::Welcome { recipient } = original.envelope else {
            panic!("held publication lost its actual recipient")
        };
        let foreign_id = [0x9d; 32];
        assert_ne!(provenance.key_package_event_id, foreign_id);
        let sender = fixture.apps[0]
            .account_home()
            .load_signing_keys("test")
            .unwrap();
        let altered = transport_nostr_peeler::NostrMlsPeeler::new()
            .with_welcome_signer(sender)
            .wrap_welcome_with_metadata(
                &cgka_traits::EncryptedPayload {
                    ciphertext: bytes.clone(),
                    aad: vec![],
                },
                &recipient,
                &cgka_traits::engine::WelcomeMetadata {
                    key_package_event_id: cgka_traits::MessageId::new(foreign_id.to_vec()),
                    relays: vec![cgka_traits::TransportEndpoint(fixture.url.clone())],
                },
            )
            .await
            .unwrap();
        let (check, altered_provenance) =
            peeler.peel_welcome_with_provenance(&altered).await.unwrap();
        let cgka_traits::ingest::PeeledContent::Welcome {
            bytes: checked_bytes,
            ..
        } = check.content
        else {
            panic!("altered transport lost the real MLS Welcome")
        };
        assert_eq!(
            checked_bytes, bytes,
            "only authenticated transport metadata changes"
        );
        assert_eq!(altered_provenance.key_package_event_id, foreign_id);
        let event = transport_nostr_peeler::NostrTransportEvent::from_transport_message(&altered)
            .unwrap()
            .to_verified_nostr_event()
            .unwrap();
        let publisher = nostr_sdk::prelude::Client::default();
        publisher.add_relay(fixture.url.clone()).await.unwrap();
        publisher.connect().await;
        let actual_ingest = fixture.apps[1]
            .relay_plane
            .observe_exact_welcome_ingest(altered.id.clone());
        publisher.send_event(&event).await.unwrap();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(20), actual_ingest)
            .await
            .expect("exact altered source message must reach actual recipient admission")
            .expect("recipient ingest observation must remain owned");
        publisher.shutdown().await;
        assert_eq!(
            outcome,
            Some(cgka_traits::IngestOutcome::Ignored {
                category: cgka_traits::InputRejectionCategory::AuthorizationFailed
            }),
            "foreign authenticated KeyPackage event must be refused by actual recipient admission"
        );
        assert!(
            fixture.runtimes[1]
                .group_mls_state("test", &fixture.chat)
                .await
                .is_err(),
            "foreign authenticated KeyPackage event must not consume original selected consent or admit the recipient"
        );
        let after = storage
            .selected_chat_key_package_storage()
            .unwrap()
            .selected_chat_key_packages()
            .unwrap();
        assert!(
            after == packages,
            "refusal must preserve the exact pending purpose rows"
        );
        assert_eq!(storage.stored_key_package_bundles().unwrap(), bundles);
        assert!(!storage.has_ingress_dedup_marker(&altered.id).unwrap());
        use sha2::Digest as _;
        let content_id = cgka_traits::MessageId::new(sha2::Sha256::digest(&bytes).to_vec());
        assert!(!storage.has_ingress_dedup_marker(&content_id).unwrap());
    }

    async fn assert_terminal_recipient_stays_out(
        fixture: &SelectedChatFixture,
        request: &crate::SelectedChatCopy,
    ) {
        assert_eq!(
            request.snapshot().await.unwrap().phase,
            crate::SelectedChatCopyPhase::InviteConfirmed
        );
        let admitted = [
            &fixture.runtimes[0],
            &fixture.runtimes[2],
            &fixture.d_runtime,
        ];
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let mut complete = true;
                for runtime in admitted {
                    complete &= runtime
                        .accounts()
                        .group_mls_state("test", &fixture.chat)
                        .await
                        .is_ok_and(|state| state.member_count == 4);
                }
                if complete {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("other original recipients must adopt the actual selected Add");
        // Observe beyond two retry intervals after removing the fault. These
        // actual worker queries must not turn a terminal original into a renewed join.
        let until = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while tokio::time::Instant::now() < until {
            assert!(
                fixture.runtimes[1]
                    .accounts()
                    .group_mls_state("test", &fixture.chat)
                    .await
                    .is_err()
            );
            assert!(
                fixture.apps[1]
                    .group("test", &fixture.chat_hex)
                    .unwrap()
                    .is_none()
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let payload = b"fresh message after original recipient became terminal";
        let sent = fixture.runtimes[0]
            .send_message("test", &fixture.chat, payload.to_vec())
            .await
            .unwrap();
        assert_eq!(sent.message_ids.len(), 1);
        let id = &sent.message_ids[0];
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if [&fixture.apps[0], &fixture.apps[2], &fixture.d_app]
                    .iter()
                    .all(|app| {
                        app.timeline_message("test", &fixture.chat_hex, id)
                            .unwrap()
                            .is_some_and(|message| {
                                message.message_id_hex == *id
                                    && message.plaintext.as_bytes() == payload
                            })
                    })
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("other live copies must still receive actual new messages");
        assert!(
            fixture.apps[1]
                .timeline_message("test", &fixture.chat_hex, id)
                .unwrap()
                .is_none()
        );
        assert!(
            fixture.apps[1]
                .timeline_message("test", &fixture.chat_hex, &fixture.before_id)
                .unwrap()
                .is_none()
        );
    }
}
