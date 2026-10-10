#[cfg(not(feature = "experimental-device-sync"))]
use super::*;
#[cfg(not(feature = "experimental-device-sync"))]
use crate::{MarmotApp, MarmotAppRuntime};

#[cfg(not(feature = "experimental-device-sync"))]
#[tokio::test]
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
    #[tokio::test]
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
                &[d_account.account_id_hex.clone()],
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

    #[tokio::test]
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
    #[tokio::test]
    async fn selected_chat_copy_admits_original_siblings_and_delivers_new_messages() {
        selected_chat_delivery(RecipientAdmissionScenario::None).await;
    }

    #[tokio::test]
    async fn selected_chat_welcome_storage_failure_retains_original_consent_for_retry() {
        selected_chat_delivery(RecipientAdmissionScenario::Retry).await;
    }

    #[tokio::test]
    async fn selected_chat_welcome_cancel_during_storage_retry_cannot_admit_or_deliver() {
        selected_chat_delivery(RecipientAdmissionScenario::Cancel).await;
    }

    #[tokio::test]
    async fn selected_chat_welcome_original_expiry_during_storage_retry_cannot_admit_or_deliver() {
        selected_chat_delivery(RecipientAdmissionScenario::Expire).await;
    }

    #[tokio::test]
    async fn selected_chat_welcome_foreign_package_event_refuses_without_consuming_original() {
        selected_chat_delivery(RecipientAdmissionScenario::ForeignPackageEvent).await;
    }

    #[tokio::test]
    async fn selected_chat_blocked_commit_cancel_prevents_late_publication() {
        selected_chat_delivery(RecipientAdmissionScenario::CommitCancel).await;
    }

    #[tokio::test]
    async fn selected_chat_blocked_commit_lost_reply_prevents_late_publication() {
        selected_chat_delivery(RecipientAdmissionScenario::CommitLostReply).await;
    }

    #[tokio::test]
    async fn selected_chat_blocked_welcome_cancel_preserves_confirmation_without_late_join() {
        selected_chat_delivery(RecipientAdmissionScenario::WelcomeCancel).await;
    }

    #[tokio::test]
    async fn selected_chat_blocked_welcome_lost_reply_preserves_confirmation_without_late_join() {
        selected_chat_delivery(RecipientAdmissionScenario::WelcomeLostReply).await;
    }

    #[tokio::test]
    async fn history_transfer_requires_original_recipient_consent_and_committed_prejoin_record() {
        selected_chat_delivery(RecipientAdmissionScenario::HistoryTransfer).await;
    }

    #[tokio::test]
    async fn history_transfer_cancelled_original_cannot_restart_from_fresh_outer_request() {
        selected_chat_delivery(RecipientAdmissionScenario::HistoryRequestReplay).await;
    }

    #[derive(Clone, Copy, PartialEq)]
    enum RecipientAdmissionScenario {
        None,
        Retry,
        Cancel,
        Expire,
        ForeignPackageEvent,
        HistoryTransfer,
        HistoryRequestReplay,
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
        let directory_reader = nostr_sdk::prelude::Client::builder().build();
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
            RecipientAdmissionScenario::HistoryTransfer
                | RecipientAdmissionScenario::HistoryRequestReplay
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
            let transfer = managers[0].begin_history_transfer("test", &fixture.chat, recipient_selector).await
                .expect("a fresh opt-in history request must retain its original actor owner after actual four-leaf admission");
            assert!(
                recipient_storage
                    .synchronized_history_page(&fixture.chat_hex, None, 200, 0)
                    .unwrap()
                    .is_empty(),
                "request is not recipient consent"
            );
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
            assert!(review.fragment_count > 1 && review.encoded_bytes > 8192);
            consent.approve(review.revision).await.unwrap();
            transfer
                .continue_transfer(transfer.snapshot().await.unwrap().revision)
                .await
                .unwrap();
            let archived = recipient_storage
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
