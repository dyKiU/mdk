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
    use cgka_traits::{OutboundFanoutStorage, storage::KeyPackageBundleStorage};
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

    #[tokio::test]
    async fn selected_chat_copy_requires_explicit_request_after_public_three_device_linking() {
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
            MarmotApp::with_relay(dirs[i].path(), &url)
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
        for (i, app) in apps.iter().enumerate() {
            let storage = app.account_storage("test").unwrap();
            // Compare private material without formatting it on a failed assertion.
            assert!(storage.stored_key_package_bundles().unwrap() == before_bundles[i]);
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
        drop(fresh_consent);
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
        d_runtime.shutdown_and_close().await.unwrap();
        relay.shutdown();
    }
}
