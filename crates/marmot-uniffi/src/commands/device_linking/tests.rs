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
        kit.approve_automatic_device_linking_session("missing".into(), "invalid".into(), None)
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
        .approve_automatic_device_linking_session(
            "test".into(),
            c.automatic_pairing_code().await.unwrap(),
            None,
        )
        .await
        .unwrap();
    a.automatic_pairing_code().await.unwrap();
    wait_for_automatic_binding_phase(&a, &c, DeviceLinkingPhaseFfi::ComparisonAvailable).await;
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
    wait_for_automatic_binding_phase(
        &a,
        &c,
        DeviceLinkingPhaseFfi::VerificationCompleteEnrollmentPending,
    )
    .await;
    assert_eq!(
        a.snapshot().await.unwrap().phase,
        DeviceLinkingPhaseFfi::VerificationCompleteEnrollmentPending
    );
    assert_eq!(
        c.snapshot().await.unwrap().phase,
        DeviceLinkingPhaseFfi::VerificationCompleteEnrollmentPending
    );
    assert!(kits[0].device_linking_capabilities().enrollment_supported);
    assert!(matches!(
        c.continue_automatic_linking(c.snapshot().await.unwrap().revision + 1, true)
            .await,
        Err(MarmotKitError::DeviceLinkingStaleRevision)
    ));
    c.continue_automatic_linking(c.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    a.continue_automatic_linking(a.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if a.snapshot().await.unwrap().phase == DeviceLinkingPhaseFfi::EnrollmentComplete
                && c.snapshot().await.unwrap().phase == DeviceLinkingPhaseFfi::EnrollmentComplete
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    crate::commands::account_chat_sharing::verify_account_sharing_binding_originals(&kits).await;
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
    assert!(matches!(
        c.continue_linking_and_share_chats(0).await,
        Err(MarmotKitError::DeviceLinkingClosed)
    ));
    for kit in kits {
        kit.runtime.shutdown_and_close().await.unwrap();
    }
    relay.shutdown();
}
#[cfg(feature = "experimental-device-sync")]
async fn wait_for_automatic_binding_phase(
    a: &DeviceLinkingSession,
    c: &DeviceLinkingSession,
    phase: DeviceLinkingPhaseFfi,
) {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            if a.snapshot().await.unwrap().phase == phase
                && c.snapshot().await.unwrap().phase == phase
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
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
    native_three_device_fixture(false, None).await;
}

#[cfg(feature = "experimental-device-sync")]
#[tokio::test(flavor = "multi_thread")]
async fn opaque_device_revocation_retains_original_scope_revision_and_cancellation() {
    native_three_device_fixture(true, None).await;
}

#[cfg(feature = "experimental-device-sync")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum CancelBoundary {
    Session,
    Approval,
    Request,
    Consent,
}

#[cfg(feature = "experimental-device-sync")]
#[tokio::test]
async fn dropped_session_cancel_export_retires_actual_original() {
    Box::pin(native_three_device_fixture(false, Some(CancelBoundary::Session))).await;
}

#[cfg(feature = "experimental-device-sync")]
#[tokio::test]
async fn dropped_approval_cancel_export_retires_actual_original() {
    Box::pin(native_three_device_fixture(false, Some(CancelBoundary::Approval))).await;
}

#[cfg(feature = "experimental-device-sync")]
#[tokio::test]
async fn dropped_request_cancel_export_retires_actual_original() {
    Box::pin(native_three_device_fixture(false, Some(CancelBoundary::Request))).await;
}

#[cfg(feature = "experimental-device-sync")]
#[tokio::test]
async fn dropped_consent_cancel_export_retires_actual_original() {
    Box::pin(native_three_device_fixture(false, Some(CancelBoundary::Consent))).await;
}

#[cfg(feature = "experimental-device-sync")]
async fn first_poll_then_drop<F: std::future::Future>(future: F) {
    let mut future = Box::pin(future);
    assert!(futures::poll!(&mut future).is_pending(), "export must first enqueue its runtime task");
    drop(future);
    // No runtime task can run on this current-thread executor until after
    // the caller drops the export. The caller retains the public original.
    tokio::task::yield_now().await;
}

#[cfg(feature = "experimental-device-sync")]
async fn observe_cancelled<F: std::future::Future<Output = bool>>(
    mut cancelled: impl FnMut() -> F,
) -> bool {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if cancelled().await { break; }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }).await.is_ok()
}

#[cfg(feature = "experimental-device-sync")]
async fn native_three_device_fixture(revoke: bool, cancel_boundary: Option<CancelBoundary>) {
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
    if cancel_boundary == Some(CancelBoundary::Session) {
        assert_eq!(c.snapshot().await.unwrap().phase, DeviceLinkingPhaseFfi::AwaitingSetup);
        first_poll_then_drop(c.__ffi_cancel()).await;
        let fenced = observe_cancelled(|| async { c.snapshot().await.unwrap().phase == DeviceLinkingPhaseFfi::Cancelled }).await;
        let late_refused = matches!(c.continue_linking(0).await, Err(MarmotKitError::DeviceLinkingClosed));
        a.cancel().await.unwrap();
        c.cancel().await.unwrap();
        for kit in &kits { kit.runtime.shutdown_and_close().await.unwrap(); }
        relay.shutdown();
        eprintln!("private_boundary_positive_closes=3 original=Session actual_public_pair=true");
        assert!(fenced && late_refused, "dropped Session cancel left actual original live");
        return;
    }
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
    if cancel_boundary == Some(CancelBoundary::Approval) {
        first_poll_then_drop(approval.__ffi_cancel()).await;
        let fenced = observe_cancelled(|| async { approval.snapshot().await.unwrap().phase == DeviceLinkingApprovalPhaseFfi::Cancelled }).await;
        let late_refused = matches!(approval.approve(observed.revision).await, Err(MarmotKitError::DeviceLinkingClosed));
        a.cancel().await.unwrap();
        c.cancel().await.unwrap();
        approval.cancel().await.unwrap();
        for kit in &kits { kit.runtime.shutdown_and_close().await.unwrap(); }
        relay.shutdown();
        eprintln!("private_boundary_positive_closes=3 original=Approval actual_encrypted_proposal=true");
        assert!(fenced && late_refused, "dropped Approval cancel left actual original live");
        return;
    }
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
    let mut cancellation_fenced = true;
    let revocation = selected_chat_binding_request_after_actual_abc(&kits, &url, revoke, cancel_boundary, &mut cancellation_fenced).await;
    a.cancel().await.unwrap();
    c.cancel().await.unwrap();
    approval.cancel().await.unwrap();
    drop((a, c, approval, initial_a, b));
    for kit in kits {
        kit.runtime.shutdown_and_close().await.unwrap();
    }
    if let Some(original) = revocation {
        assert!(matches!(
            original.snapshot().await,
            Err(MarmotKitError::DeviceRevocationClosed
                | MarmotKitError::DeviceRevocationRuntimeUnavailable)
        ));
    }
    relay.shutdown();
    eprintln!("private_boundary_positive_closes=4 actual_abc_and_independent_d=true");
    assert!(cancellation_fenced, "dropped selected cancel left actual original live");
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
async fn selected_chat_binding_request_after_actual_abc(
    kits: &[Marmot],
    url: &str,
    revoke: bool,
    cancel_boundary: Option<CancelBoundary>,
    cancellation_fenced: &mut bool,
) -> Option<std::sync::Arc<crate::DeviceRevocation>> {
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
    if cancel_boundary == Some(CancelBoundary::Request) {
        first_poll_then_drop(request.__ffi_cancel()).await;
        *cancellation_fenced = observe_cancelled(|| async { request.snapshot().await.unwrap().phase == crate::SelectedChatCopyPhaseFfi::Cancelled }).await;
        *cancellation_fenced &= matches!(request.continue_copy(request.snapshot().await.unwrap().revision).await, Err(MarmotKitError::SelectedChatCopyClosed));
        eprintln!("private_cancel_boundary original=Request actual_owner_fenced={cancellation_fenced}");
    }
    if cancel_boundary == Some(CancelBoundary::Consent) {
        let consent = &consents[0];
        first_poll_then_drop(consent.__ffi_cancel()).await;
        *cancellation_fenced = observe_cancelled(|| async { consent.snapshot().await.unwrap().phase == crate::SelectedChatConsentPhaseFfi::Cancelled }).await;
        *cancellation_fenced &= matches!(consent.approve(consent.snapshot().await.unwrap().revision).await, Err(MarmotKitError::SelectedChatCopyClosed));
        eprintln!("private_cancel_boundary original=Consent actual_owner_fenced={cancellation_fenced}");
    }
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
    let revocation = if revoke {
        Some(revoke_actual_selected_device(kits, &d, &chat).await)
    } else {
        None
    };
    d.runtime.shutdown_and_close().await.unwrap();
    revocation
}

#[cfg(feature = "experimental-device-sync")]
async fn revoke_actual_selected_device(
    kits: &[Marmot],
    d: &Marmot,
    chat: &str,
) -> std::sync::Arc<crate::DeviceRevocation> {
    use std::time::Duration;
    let a_choices = kits[0]
        .history_transfer_recipients("test".into(), chat.into())
        .await
        .unwrap();
    let c_choices = kits[2]
        .history_transfer_recipients("test".into(), chat.into())
        .await
        .unwrap();
    assert_eq!(a_choices.len(), 2);
    let target = a_choices
        .iter()
        .find(|item| !c_choices.iter().any(|other| item.device == other.device))
        .expect("actual C is excluded from its own authenticated recipient choices")
        .device
        .clone();
    assert!(matches!(
        kits[0]
            .begin_device_revocation("missing".into(), target.clone())
            .await,
        Err(MarmotKitError::DeviceRevocationRuntimeUnavailable)
    ));
    let first = kits[0]
        .begin_device_revocation("test".into(), target.clone())
        .await
        .unwrap();
    let alias = first.clone();
    drop(first);
    let captured = alias.snapshot().await.unwrap();
    assert_eq!(captured.target_device, target);
    assert_eq!(captured.ordinary_group_ids_hex, vec![chat.to_owned()]);
    assert!(captured.completed_group_ids_hex.is_empty());
    assert!(!captured.complete);
    assert!(matches!(
        alias.approve(captured.revision + 1).await,
        Err(MarmotKitError::DeviceRevocationStaleRevision)
    ));
    assert_eq!(alias.snapshot().await.unwrap(), captured);
    assert!(matches!(
        kits[0]
            .begin_device_revocation("test".into(), target.clone())
            .await,
        Err(MarmotKitError::DeviceRevocationBusy)
    ));
    alias.cancel();
    assert!(matches!(
        alias.snapshot().await,
        Err(MarmotKitError::DeviceRevocationClosed)
    ));
    assert!(matches!(
        alias.approve(captured.revision).await,
        Err(MarmotKitError::DeviceRevocationClosed)
    ));
    assert!(
        kits[2]
            .group_mls_state("test".into(), chat.into())
            .await
            .is_ok()
    );
    let original = kits[0]
        .begin_device_revocation("test".into(), target)
        .await
        .unwrap();
    let reviewed = original.snapshot().await.unwrap();
    original.approve(reviewed.revision).await.unwrap();
    let complete = original.snapshot().await.unwrap();
    assert!(complete.complete);
    assert!(complete.completed_group_ids_hex.contains(&chat.to_owned()));
    assert!(
        complete
            .completed_group_ids_hex
            .contains(&complete.protected_group_id_hex)
    );
    assert_eq!(complete.completed_group_ids_hex.len(), 2);
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let mut ready = true;
            for kit in [&kits[0], &kits[1], d] {
                ready &= kit
                    .group_mls_state("test".into(), chat.into())
                    .await
                    .is_ok_and(|state| state.member_count == 3);
            }
            ready &= kits[2]
                .group_roster("test".into(), chat.into())
                .await
                .is_ok_and(|state| {
                    matches!(
                        state.self_membership,
                        crate::conversions::SelfMembershipFfi::Removed
                    )
                });
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("actual Remove must reach surviving and removed independent runtimes");
    assert!(
        kits[2]
            .send_text(
                "test".into(),
                chat.into(),
                "removed sender must refuse".into()
            )
            .await
            .is_err()
    );
    let sent = kits[1]
        .send_text("test".into(), chat.into(), "survivor future epoch".into())
        .await
        .unwrap();
    let id = &sent.message_ids[0];
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let ready = [&kits[0], &kits[1], d].into_iter().all(|kit| {
                kit.messages("test".into(), Some(chat.into()), None, None)
                    .unwrap()
                    .iter()
                    .any(|message| &message.message_id_hex == id)
            });
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("actual survivor epoch message must reach every intended runtime");
    assert!(
        kits[2]
            .messages("test".into(), Some(chat.into()), None, None)
            .unwrap()
            .iter()
            .all(|message| &message.message_id_hex != id)
    );
    original
}
