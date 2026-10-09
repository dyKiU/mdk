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
        let missing = managers[0]
            .begin_selected_chat_copy("test", &chat, target.selector)
            .await;
        assert!(matches!(
            missing,
            Err(crate::SelectedChatCopyError::NotReady)
        ));
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
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
        d_runtime.shutdown_and_close().await.unwrap();
        relay.shutdown();
    }
}
