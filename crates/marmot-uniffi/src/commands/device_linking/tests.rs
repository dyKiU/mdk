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
    assert!(!kits[0].device_linking_capabilities().enrollment_supported);
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
    approval.approve(observed.revision).await.unwrap();
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
