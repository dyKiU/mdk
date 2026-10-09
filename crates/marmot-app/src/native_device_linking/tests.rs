use super::*;
use crate::{MarmotApp, MarmotAppRuntime};

#[cfg(not(feature = "experimental-device-sync"))]
#[tokio::test]
async fn default_native_verification_is_unsupported_before_account_or_worker_effects() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), "wss://relay.example"));
    let accounts = runtime.accounts();
    assert_eq!(
        accounts.device_linking_capabilities(),
        DeviceLinkingCapabilities {
            verification_supported: false,
            enrollment_supported: false
        }
    );
    assert!(matches!(
        accounts.begin_device_linking_session("missing").await,
        Err(DeviceLinkingError::Unsupported)
    ));
    assert!(matches!(
        accounts
            .approve_device_linking_session("missing", vec![0; 600_000], None)
            .await,
        Err(DeviceLinkingError::Unsupported)
    ));
    assert!(accounts.managed_accounts().unwrap().is_empty());
    runtime.shutdown_and_close().await.unwrap();
}

#[cfg(all(
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
mod actual {
    use super::*;
    use marmot_account::AccountHome;
    use std::sync::Arc;

    async fn workers() -> ([tempfile::TempDir; 2], [MarmotAppRuntime; 2]) {
        let keys = nostr::prelude::Keys::generate();
        let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        let runtimes = std::array::from_fn(|i| {
            AccountHome::open(dirs[i].path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
            MarmotAppRuntime::new(
                MarmotApp::with_relay(dirs[i].path(), "wss://relay.example")
                    .with_test_relay_client(Arc::new(
                        crate::tests::ScriptedPushRelayClient::default(),
                    )),
            )
        });
        for runtime in &runtimes {
            runtime.reconcile_accounts().await.unwrap();
        }
        (dirs, runtimes)
    }
    async fn drain(from: &DeviceLinkingSession, to: &DeviceLinkingSession) {
        for packet in from.outgoing_packets().await.unwrap() {
            to.receive_packet(packet.bytes).await.unwrap();
            from.acknowledge_packet(packet.acknowledgement_id)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn opaque_native_sessions_complete_real_sdk_with_revision_bound_human_actions() {
        let (_dirs, runtimes) = workers().await;
        let c = runtimes[1]
            .accounts()
            .begin_device_linking_session("test")
            .await
            .unwrap();
        assert_eq!(
            c.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::AwaitingSetup
        );
        let a = runtimes[0]
            .accounts()
            .approve_device_linking_session("test", c.setup_packet(), None)
            .await
            .unwrap();
        c.receive_setup_packet(a.setup_packet()).await.unwrap();
        assert!(c.receive_packet(vec![0; 600_000]).await.is_err());
        for _ in 0..8 {
            drain(&a, &c).await;
            drain(&c, &a).await;
        }
        let ac = a.snapshot().await.unwrap();
        let cc = c.snapshot().await.unwrap();
        assert_eq!(ac.phase, DeviceLinkingPhase::ComparisonAvailable);
        assert!(ac.decimals.is_some());
        assert_eq!(ac.decimals, cc.decimals);
        assert!(matches!(
            a.confirm_comparison(ac.revision + 1).await,
            Err(DeviceLinkingError::StaleRevision)
        ));
        assert_eq!(
            a.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::ComparisonAvailable
        );
        a.confirm_comparison(ac.revision).await.unwrap();
        c.confirm_comparison(cc.revision).await.unwrap();
        for _ in 0..8 {
            drain(&a, &c).await;
            drain(&c, &a).await;
        }
        assert_eq!(
            a.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending
        );
        assert_eq!(
            c.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending
        );
        assert!(
            !runtimes[0]
                .accounts()
                .device_linking_capabilities()
                .enrollment_supported
        );
        assert!(matches!(
            a.continue_linking(a.snapshot().await.unwrap().revision)
                .await,
            Err(DeviceLinkingError::NotReady)
        ));
        a.cancel().await.unwrap();
        c.cancel().await.unwrap();
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn native_subscription_close_wakes_wait_and_exact_session_cancel_allows_new_attempt() {
        let (_dirs, runtimes) = workers().await;
        let manager = runtimes[1].accounts();
        let session = manager.begin_device_linking_session("test").await.unwrap();
        let subscription = Arc::new(session.subscribe());
        subscription.next().await.unwrap();
        let pending = {
            let sub = subscription.clone();
            tokio::spawn(async move { sub.next().await })
        };
        tokio::task::yield_now().await;
        subscription.close();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(2), pending)
                .await
                .unwrap()
                .unwrap(),
            Err(DeviceLinkingError::Closed)
        ));
        session.cancel().await.unwrap();
        assert!(matches!(
            session.outgoing_packets().await,
            Err(DeviceLinkingError::Closed)
        ));
        let next = manager.begin_device_linking_session("test").await.unwrap();
        assert_eq!(
            next.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::AwaitingSetup
        );
        next.cancel().await.unwrap();
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn native_drop_closes_observation_and_allows_fresh_original_purpose() {
        let (_dirs, runtimes) = workers().await;
        let manager = runtimes[1].accounts();
        let session = manager.begin_device_linking_session("test").await.unwrap();
        let old_setup = session.setup_packet();
        let subscription = session.subscribe();
        subscription.next().await.unwrap();
        drop(session);
        let closed = tokio::time::timeout(std::time::Duration::from_secs(2), subscription.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(closed.phase, DeviceLinkingPhase::Cancelled);
        assert!(closed.decimals.is_none());
        let next = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if let Ok(next) = manager.begin_device_linking_session("test").await {
                    break next;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_ne!(next.setup_packet(), old_setup);
        assert_eq!(
            next.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::AwaitingSetup
        );
        next.cancel().await.unwrap();
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn native_subscription_close_wakes_both_change_and_receiver_admission() {
        let (_dirs, runtimes) = workers().await;
        let session = runtimes[1]
            .accounts()
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let sub = Arc::new(session.subscribe());
        sub.next().await.unwrap();
        let first = {
            let sub = sub.clone();
            tokio::spawn(async move { sub.next().await })
        };
        tokio::task::yield_now().await;
        let second = {
            let sub = sub.clone();
            tokio::spawn(async move { sub.next().await })
        };
        tokio::task::yield_now().await;
        sub.close();
        for pending in [first, second] {
            assert!(matches!(
                tokio::time::timeout(std::time::Duration::from_secs(2), pending)
                    .await
                    .unwrap()
                    .unwrap(),
                Err(DeviceLinkingError::Closed)
            ));
        }
        assert_eq!(
            session.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::AwaitingSetup
        );
        session.cancel().await.unwrap();
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn native_original_worker_expiry_cannot_revive_terminal_session() {
        let (_dirs, runtimes) = workers().await;
        let manager = runtimes[1].accounts();
        let session = manager.begin_device_linking_session("test").await.unwrap();
        let old_setup = session.setup_packet();
        manager
            .maintain_device_linking_at_for_test(
                "test",
                std::time::Instant::now() + std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap();
        let terminal = session.snapshot().await.unwrap();
        assert!(matches!(
            terminal.phase,
            DeviceLinkingPhase::Expired
                | DeviceLinkingPhase::Cancelled
                | DeviceLinkingPhase::Failed
        ));
        assert!(terminal.decimals.is_none());
        assert!(matches!(
            session.confirm_comparison(terminal.revision).await,
            Err(DeviceLinkingError::Closed)
        ));
        assert!(matches!(
            session.outgoing_packets().await,
            Err(DeviceLinkingError::Closed)
        ));
        let next = manager.begin_device_linking_session("test").await.unwrap();
        assert_ne!(next.setup_packet(), old_setup);
        assert_eq!(session.snapshot().await.unwrap(), terminal);
        next.cancel().await.unwrap();
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn native_shutdown_closes_original_session_without_a_new_worker() {
        let (_dirs, runtimes) = workers().await;
        let manager = runtimes[1].accounts();
        let session = manager.begin_device_linking_session("test").await.unwrap();
        runtimes[1].shutdown_and_close().await.unwrap();
        let terminal = session.snapshot().await.unwrap();
        assert!(matches!(
            terminal.phase,
            DeviceLinkingPhase::Cancelled | DeviceLinkingPhase::Failed
        ));
        assert!(matches!(
            session.continue_linking(terminal.revision).await,
            Err(DeviceLinkingError::Closed)
        ));
        assert!(manager.begin_device_linking_session("test").await.is_err());
        assert_eq!(session.snapshot().await.unwrap(), terminal);
        runtimes[0].shutdown_and_close().await.unwrap();
    }
}
