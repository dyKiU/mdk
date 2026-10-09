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
async fn native_binding_completes_real_sdk_and_close_wakes_waiter() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
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
    assert!(matches!(
        a.continue_linking(a.snapshot().await.unwrap().revision)
            .await,
        Err(MarmotKitError::DeviceLinkingNotReady)
    ));
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
