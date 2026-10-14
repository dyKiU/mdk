use super::*;
use crate::{MarmotApp, MarmotAppRuntime};
use marmot_account::AccountHome;

#[tokio::test]
async fn dropped_scanner_factory_cannot_export_a_response_before_host_adoption() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let runtimes = std::array::from_fn::<_, 2, _>(|index| {
        AccountHome::open(dirs[index].path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        MarmotAppRuntime::new(MarmotApp::with_relay(dirs[index].path(), &url))
    });
    for runtime in &runtimes {
        runtime.reconcile_accounts().await.unwrap();
    }
    let displayed = runtimes[0]
        .accounts()
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let code = displayed.automatic_pairing_code().await.unwrap();
    let scanner = runtimes[1]
        .accounts()
        .approve_automatic_device_linking_session("test", code, None)
        .await
        .unwrap();
    let retired = scanner.automatic_retirement_probe_for_test();
    drop(scanner);
    assert!(retired());
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert_eq!(
        displayed.snapshot().await.unwrap().phase,
        DeviceLinkingPhase::AwaitingSetup
    );
    drop(retired);
    displayed.cancel().await.unwrap();
    for runtime in runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
}

#[tokio::test]
async fn automatic_one_scan_exchange_keeps_both_human_comparisons_required() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    for displaying_device in [0, 1] {
        let keys = nostr::prelude::Keys::generate();
        let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        let runtimes = std::array::from_fn::<_, 2, _>(|index| {
            AccountHome::open(dirs[index].path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
            MarmotAppRuntime::new(MarmotApp::with_relay(dirs[index].path(), &url))
        });
        for runtime in &runtimes {
            runtime.reconcile_accounts().await.unwrap();
        }
        let displayed = runtimes[displaying_device]
            .accounts()
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let code = displayed.automatic_pairing_code().await.unwrap();
        assert!(code.len() <= 1024);
        assert_eq!(displayed.automatic_pairing_code().await.unwrap(), code);
        // Exactly one bootstrap import; no manual packet reads/transfers/ACKs.
        let scanner = runtimes[1 - displaying_device]
            .accounts()
            .approve_automatic_device_linking_session("test", code, None)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(
            displayed.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::AwaitingSetup
        );
        // Activation is programmatic after host account-scope adoption,
        // never another QR scan or implicit comparison confirmation.
        scanner.automatic_pairing_code().await.unwrap();
        wait_for_automatic_phase(
            &displayed,
            &scanner,
            DeviceLinkingPhase::ComparisonAvailable,
        )
        .await;
        let a = displayed.snapshot().await.unwrap();
        let b = scanner.snapshot().await.unwrap();
        assert!(a.decimals.is_some());
        assert_eq!(a.decimals, b.decimals);
        assert!(matches!(
            displayed.continue_linking(a.revision).await,
            Err(DeviceLinkingError::NotReady)
        ));
        displayed.confirm_comparison(a.revision).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        assert_ne!(
            scanner.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending
        );
        scanner.confirm_comparison(b.revision).await.unwrap();
        wait_for_automatic_phase(
            &displayed,
            &scanner,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending,
        )
        .await;
        displayed.cancel().await.unwrap();
        scanner.cancel().await.unwrap();
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
    }
}

async fn wait_for_automatic_phase(
    a: &DeviceLinkingSession,
    b: &DeviceLinkingSession,
    phase: DeviceLinkingPhase,
) {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let ap = a.snapshot().await.unwrap().phase;
            let bp = b.snapshot().await.unwrap().phase;
            assert!(!matches!(
                ap,
                DeviceLinkingPhase::Failed
                    | DeviceLinkingPhase::Cancelled
                    | DeviceLinkingPhase::Expired
            ));
            assert!(!matches!(
                bp,
                DeviceLinkingPhase::Failed
                    | DeviceLinkingPhase::Cancelled
                    | DeviceLinkingPhase::Expired
            ));
            if ap == phase && bp == phase {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("automatic pairing did not reach required phase");
}

#[tokio::test]
async fn automatic_transport_cannot_keep_dropped_original_authority_alive() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .import_account(
            "test",
            &nostr::prelude::Keys::generate()
                .secret_key()
                .to_secret_hex(),
        )
        .unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(
        dir.path(),
        relay.url().await.to_string(),
    ));
    runtime.reconcile_accounts().await.unwrap();
    let original = runtime
        .accounts()
        .begin_device_linking_session("test")
        .await
        .unwrap();
    original.automatic_pairing_code().await.unwrap();
    let retired = original.automatic_retirement_probe_for_test();
    drop(original);
    assert!(retired());
    drop(retired);
    runtime.shutdown_and_close().await.unwrap();
}
