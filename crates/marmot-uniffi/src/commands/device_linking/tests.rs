use super::*;
#[cfg(feature = "experimental-device-sync")]
use crate::DeviceLinkingPhaseFfi;
use marmot_app::MarmotApp;
#[cfg(feature = "experimental-device-sync")]
use marmot_app::MarmotAppConfig;

#[cfg(not(feature = "experimental-device-sync"))]
#[tokio::test]
async fn default_binding_refuses_before_account_effects() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let kit = Marmot {
        runtime: app.runtime(),
        app,
    };
    assert!(!kit.device_linking_capabilities().verification_supported);
    assert!(matches!(
        kit.begin_device_linking_session("missing".into()).await,
        Err(MarmotKitError::DeviceLinkingUnsupported)
    ));
    assert!(matches!(
        kit.approve_device_linking_session("missing".into(), vec![0; 600_000], None)
            .await,
        Err(MarmotKitError::DeviceLinkingUnsupported)
    ));
    assert!(matches!(
        kit.device_linking_targets("missing".into()).await,
        Err(MarmotKitError::DeviceLinkingUnsupported)
    ));
    assert!(matches!(
        kit.pending_device_linking_approvals("missing".into()).await,
        Err(MarmotKitError::DeviceLinkingUnsupported)
    ));
    assert!(
        kit.runtime
            .accounts()
            .managed_accounts()
            .unwrap()
            .is_empty()
    );
    kit.runtime.shutdown_and_close().await.unwrap();
}

#[cfg(feature = "experimental-device-sync")]
#[tokio::test(flavor = "multi_thread")]
async fn native_binding_continues_original_actions_and_close_wakes_waiter() {
    let relay = nostr_relay_builder::LocalRelay::new(nostr_relay_builder::RelayBuilder::default());
    relay.run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let kits = dirs
        .iter()
        .map(|dir| {
            marmot_account::AccountHome::open(dir.path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
            let app = MarmotApp::with_relay_and_config(
                dir.path(),
                relay_url.clone(),
                MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
            );
            Marmot {
                runtime: app.runtime(),
                app,
            }
        })
        .collect::<Vec<_>>();
    for kit in &kits {
        kit.runtime.reconcile_accounts().await.unwrap();
    }
    let c = kits[1]
        .begin_device_linking_session("test".into())
        .await
        .unwrap();
    let a = kits[0]
        .approve_device_linking_session("test".into(), c.setup_packet(), None)
        .await
        .unwrap();
    c.receive_setup_packet(a.setup_packet()).await.unwrap();
    for _ in 0..8 {
        drain(&a, &c).await;
        drain(&c, &a).await;
    }
    let ac = a.snapshot().await.unwrap();
    let cc = c.snapshot().await.unwrap();
    assert_eq!(ac.phase, DeviceLinkingPhaseFfi::ComparisonAvailable);
    assert_eq!(ac.decimals, cc.decimals);
    assert!(ac.decimals.is_some());
    assert!(matches!(
        a.confirm_comparison(ac.revision + 1).await,
        Err(MarmotKitError::DeviceLinkingStaleRevision)
    ));
    a.confirm_comparison(ac.revision).await.unwrap();
    c.confirm_comparison(cc.revision).await.unwrap();
    for _ in 0..8 {
        drain(&a, &c).await;
        drain(&c, &a).await;
    }
    assert_eq!(
        a.snapshot().await.unwrap().phase,
        DeviceLinkingPhaseFfi::VerificationCompleteEnrollmentPending
    );
    assert_eq!(
        c.snapshot().await.unwrap().phase,
        DeviceLinkingPhaseFfi::VerificationCompleteEnrollmentPending
    );
    assert!(kits[0].device_linking_capabilities().enrollment_supported);
    c.continue_linking(c.snapshot().await.unwrap().revision)
        .await
        .unwrap();
    a.continue_linking(a.snapshot().await.unwrap().revision)
        .await
        .unwrap();
    let sub = a.subscribe();
    sub.next().await.unwrap();
    let pending = {
        let sub = sub.clone();
        tokio::spawn(async move { sub.next().await })
    };
    tokio::task::yield_now().await;
    sub.close();
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(2), pending)
            .await
            .unwrap()
            .unwrap(),
        Err(MarmotKitError::DeviceLinkingClosed)
    ));
    a.cancel().await.unwrap();
    c.cancel().await.unwrap();
    for kit in kits {
        kit.runtime.shutdown_and_close().await.unwrap();
    }
    relay.shutdown();
}
#[cfg(feature = "experimental-device-sync")]
async fn drain(from: &DeviceLinkingSession, to: &DeviceLinkingSession) {
    for packet in from.outgoing_packets().await.unwrap() {
        to.receive_packet(packet.bytes).await.unwrap();
        from.acknowledge_packet(packet.acknowledgement_id)
            .await
            .unwrap();
    }
}

#[cfg(feature = "experimental-device-sync")]
#[tokio::test(flavor = "multi_thread")]
async fn opaque_binding_three_device_enrollment_reports_actual_completion() {
    use crate::DeviceLinkingApprovalPhaseFfi;
    use std::time::Duration;
    let relay = nostr_relay_builder::LocalRelay::new(nostr_relay_builder::RelayBuilder::default());
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs: [tempfile::TempDir; 3] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
    let kits = dirs
        .iter()
        .map(|dir| {
            marmot_account::AccountHome::open(dir.path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
            let app = MarmotApp::with_relay_and_config(
                dir.path(),
                url.clone(),
                MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
            );
            Marmot {
                runtime: app.runtime(),
                app,
            }
        })
        .collect::<Vec<_>>();
    for kit in &kits {
        kit.runtime.reconcile_accounts().await.unwrap();
    }
    let b = kits[1]
        .begin_device_linking_session("test".into())
        .await
        .unwrap();
    let initial_a = kits[0]
        .approve_device_linking_session("test".into(), b.setup_packet(), None)
        .await
        .unwrap();
    verify_binding_pair(&initial_a, &b).await;
    b.continue_linking(b.snapshot().await.unwrap().revision)
        .await
        .unwrap();
    initial_a
        .continue_linking(initial_a.snapshot().await.unwrap().revision)
        .await
        .unwrap();
    wait_binding_complete(&initial_a).await;
    wait_binding_complete(&b).await;
    initial_a.cancel().await.unwrap();
    b.cancel().await.unwrap();
    let targets = kits[0].device_linking_targets("test".into()).await.unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].device_count, 2);
    let c = kits[2]
        .begin_device_linking_session("test".into())
        .await
        .unwrap();
    let a = kits[0]
        .approve_device_linking_session(
            "test".into(),
            c.setup_packet(),
            Some(targets[0].selector.clone()),
        )
        .await
        .unwrap();
    verify_binding_pair(&a, &c).await;
    c.continue_linking(c.snapshot().await.unwrap().revision)
        .await
        .unwrap();
    a.continue_linking(a.snapshot().await.unwrap().revision)
        .await
        .unwrap();
    let approval = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(approval) = kits[1]
                .pending_device_linking_approvals("test".into())
                .await
                .unwrap()
                .pop()
            {
                break approval;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("opaque B approval must arrive through actual encrypted relay publication");
    let observed = approval.snapshot().await.unwrap();
    assert_eq!(
        observed.phase,
        DeviceLinkingApprovalPhaseFfi::AwaitingApproval
    );
    assert!(matches!(
        approval.approve(observed.revision + 1).await,
        Err(MarmotKitError::DeviceLinkingStaleRevision)
    ));
    assert!(matches!(
        approval.review_metadata(observed.revision + 1).await,
        Err(MarmotKitError::DeviceLinkingStaleRevision)
    ));
    let review = approval
        .review_metadata(observed.revision)
        .await
        .expect("original opaque approval must expose authenticated review metadata");
    assert_eq!(review.revision, observed.revision);
    assert_eq!(review.existing_device_count, 2);
    assert_eq!(review.source_device_public_key.len(), 32);
    assert_eq!(review.joining_device_public_key.len(), 32);
    assert_ne!(
        review.source_device_public_key,
        review.joining_device_public_key
    );
    assert_eq!(approval.snapshot().await.unwrap(), observed);
    approval.approve(observed.revision).await.unwrap();
    assert!(matches!(
        approval
            .review_metadata(approval.snapshot().await.unwrap().revision)
            .await,
        Err(MarmotKitError::DeviceLinkingNotReady)
    ));
    let packet = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match a
                .enrollment_packet(a.snapshot().await.unwrap().revision)
                .await
            {
                Ok(packet) => break packet,
                Err(MarmotKitError::DeviceLinkingNotReady) => {
                    tokio::time::sleep(Duration::from_millis(20)).await
                }
                Err(error) => panic!("original all-leaf packet export failed: {error}"),
            }
        }
    })
    .await
    .expect("original A action must export all-leaf approval before lease transfer");
    assert!(packet.len() <= 16 * 1024);
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
    wait_binding_complete(&a).await;
    wait_binding_complete(&c).await;
    tokio::time::timeout(Duration::from_secs(20), async {
        while approval.snapshot().await.unwrap().phase != DeviceLinkingApprovalPhaseFfi::Settled {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("original B action must observe protected settlement");
    for kit in &kits {
        let targets = kit.device_linking_targets("test".into()).await.unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].device_count, 3);
    }
    assert!(matches!(
        approval
            .review_metadata(approval.snapshot().await.unwrap().revision)
            .await,
        Err(MarmotKitError::DeviceLinkingNotReady | MarmotKitError::DeviceLinkingClosed)
    ));
    selected_chat_binding_request_after_actual_abc(&kits, &url).await;
    a.cancel().await.unwrap();
    c.cancel().await.unwrap();
    approval.cancel().await.unwrap();
    drop((a, c, approval, initial_a, b));
    for kit in kits {
        kit.runtime.shutdown_and_close().await.unwrap();
    }
    relay.shutdown();
}

#[cfg(feature = "experimental-device-sync")]
async fn verify_binding_pair(a: &DeviceLinkingSession, c: &DeviceLinkingSession) {
    c.receive_setup_packet(a.setup_packet()).await.unwrap();
    for _ in 0..8 {
        drain(a, c).await;
        drain(c, a).await;
    }
    let ac = a.snapshot().await.unwrap();
    let cc = c.snapshot().await.unwrap();
    assert_eq!(ac.phase, DeviceLinkingPhaseFfi::ComparisonAvailable);
    assert_eq!(ac.decimals, cc.decimals);
    assert!(ac.decimals.is_some());
    a.confirm_comparison(ac.revision).await.unwrap();
    c.confirm_comparison(cc.revision).await.unwrap();
    for _ in 0..8 {
        drain(a, c).await;
        drain(c, a).await;
    }
}

#[cfg(feature = "experimental-device-sync")]
async fn wait_binding_complete(session: &DeviceLinkingSession) {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let snapshot = session.snapshot().await.unwrap();
            if snapshot.phase == DeviceLinkingPhaseFfi::EnrollmentComplete {
                assert!(snapshot.decimals.is_none());
                break;
            }
            assert!(!matches!(
                snapshot.phase,
                DeviceLinkingPhaseFfi::Cancelled
                    | DeviceLinkingPhaseFfi::Expired
                    | DeviceLinkingPhaseFfi::Failed
            ));
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("native completion must follow actual protected settlement");
}

#[cfg(feature = "experimental-device-sync")]
async fn selected_chat_binding_request_after_actual_abc(kits: &[Marmot], url: &str) {
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let keys = nostr::prelude::Keys::generate();
    let account = marmot_account::AccountHome::open(dir.path())
        .import_account("test", &keys.secret_key().to_secret_hex())
        .unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url,
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let d = Marmot {
        runtime: app.runtime(),
        app,
    };
    d.runtime.reconcile_accounts().await.unwrap();
    // Ordinary D setup uses the production relay-list publisher, not injected membership.
    d.app
        .set_account_inbox_relays(
            "test",
            vec![cgka_traits::TransportEndpoint(url.into())],
            vec![cgka_traits::TransportEndpoint(url.into())],
        )
        .await
        .unwrap();
    d.publish_new_key_package("test".into()).await.unwrap();
    let chat = kits[0]
        .create_group(
            "test".into(),
            "Native selected chat".into(),
            vec![account.account_id_hex],
            None,
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if d.group_mls_state("test".into(), chat.clone()).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("D must genuinely join the ordinary A/D chat");
    assert_eq!(
        d.group_mls_state("test".into(), chat.clone())
            .await
            .unwrap()
            .member_count,
        2
    );
    let targets = kits[0].device_linking_targets("test".into()).await.unwrap();
    assert_eq!(targets[0].device_count, 3);
    let request = kits[0]
        .begin_selected_chat_copy("test".into(), chat.clone(), targets[0].selector.clone())
        .await
        .unwrap();
    let alias = request.clone();
    drop(request);
    let request = alias; // One foreign alias disappearing must not cancel the original.
    let observed = request.snapshot().await.unwrap();
    assert_eq!(observed.sibling_count, 2);
    assert_eq!(observed.consenting_sibling_count, 0);
    assert_eq!(observed.offered_sibling_count, 0);
    assert!(matches!(
        request.request_packet(observed.revision + 1).await,
        Err(MarmotKitError::SelectedChatCopyStaleRevision)
    ));
    let packet = request.request_packet(observed.revision).await.unwrap();
    assert!(packet.len() <= 16384);
    assert!(matches!(
        request
            .receive_consent_packet(observed.revision, vec![0; 16385])
            .await,
        Err(MarmotKitError::SelectedChatCopyInvalidPacket)
    ));
    assert_eq!(request.snapshot().await.unwrap(), observed);
    let mut consents = Vec::new();
    for kit in &kits[1..] {
        let consent = kit
            .receive_selected_chat_copy_request("test".into(), packet.clone())
            .await
            .unwrap();
        let observed = consent.snapshot().await.unwrap();
        assert_eq!(
            observed.phase,
            crate::SelectedChatConsentPhaseFfi::AwaitingApproval
        );
        assert_eq!(observed.chat_selector, hex::decode(&chat).unwrap());
        assert!(matches!(
            consent.response_packet(observed.revision).await,
            Err(MarmotKitError::SelectedChatCopyNotReady)
        ));
        assert!(matches!(
            consent.approve(observed.revision + 1).await,
            Err(MarmotKitError::SelectedChatCopyStaleRevision)
        ));
        consent.approve(observed.revision).await.unwrap();
        let observed = consent.snapshot().await.unwrap();
        assert_eq!(observed.phase, crate::SelectedChatConsentPhaseFfi::Approved);
        let response = consent.response_packet(observed.revision).await.unwrap();
        request
            .receive_consent_packet(request.snapshot().await.unwrap().revision, response)
            .await
            .unwrap();
        let offer = consent.offer_packet(observed.revision).await.unwrap();
        assert!(offer.len() <= 16384);
        assert_eq!(
            consent.offer_packet(observed.revision).await.unwrap(),
            offer
        );
        let revision = request.snapshot().await.unwrap().revision;
        request
            .receive_offer_packet(revision, offer.clone())
            .await
            .unwrap();
        let captured = request.snapshot().await.unwrap();
        request
            .receive_offer_packet(captured.revision, offer)
            .await
            .unwrap();
        assert_eq!(request.snapshot().await.unwrap(), captured);
        consents.push(consent);
    }
    let observed = request.snapshot().await.unwrap();
    assert_eq!(observed.consenting_sibling_count, 2);
    assert_eq!(observed.offered_sibling_count, 2);
    assert!(matches!(
        request.continue_copy(observed.revision + 1).await,
        Err(MarmotKitError::SelectedChatCopyStaleRevision)
    ));
    request.continue_copy(observed.revision).await.unwrap();
    assert_eq!(
        request.snapshot().await.unwrap().phase,
        crate::SelectedChatCopyPhaseFfi::InviteConfirmed
    );
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let mut complete = true;
            for kit in kits.iter().chain(std::iter::once(&d)) {
                complete &= kit
                    .group_mls_state("test".into(), chat.clone())
                    .await
                    .is_ok_and(|state| state.member_count == 4);
            }
            if complete {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("opaque consent must genuinely admit both siblings");
    let sent = kits[1]
        .send_text(
            "test".into(),
            chat.clone(),
            "native opaque selected delivery".into(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let complete = kits.iter().chain(std::iter::once(&d)).all(|kit| {
                kit.messages("test".into(), Some(chat.clone()), None, None)
                    .unwrap()
                    .iter()
                    .any(|message| message.message_id_hex == sent.message_ids[0])
            });
            if complete {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("new sibling message must reach all four independent native runtimes");
    for consent in &consents {
        consent.cancel().await.unwrap();
    }
    request.cancel().await.unwrap();
    assert!(matches!(
        request
            .continue_copy(request.snapshot().await.unwrap().revision)
            .await,
        Err(MarmotKitError::SelectedChatCopyClosed)
    ));
    drop((request, consents));
    d.runtime.shutdown_and_close().await.unwrap();
}
