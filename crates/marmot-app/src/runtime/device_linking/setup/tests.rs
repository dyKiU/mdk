use super::*;
use crate::{MarmotApp, MarmotAppRuntime};
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
                .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default())),
        )
    });
    for runtime in &runtimes {
        runtime.reconcile_accounts().await.unwrap();
    }
    (dirs, runtimes)
}

async fn drain(
    from: &AccountManager,
    a: &PurposeAttemptScope,
    to: &AccountManager,
    b: &PurposeAttemptScope,
) {
    for frame in from.device_linking_outgoing("test", a).await.unwrap() {
        let token = frame.acknowledgement_token().to_owned();
        to.receive_device_linking_frame("test", b, frame)
            .await
            .unwrap();
        from.acknowledge_device_linking_frame("test", a, token)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn worker_setup_packets_complete_original_sdk_without_host_context() {
    let (_dirs, runtimes) = workers().await;
    let [a, c] = runtimes.each_ref().map(|r| r.accounts());
    let request = c.reserve_device_linking_setup("test").await.unwrap();
    let challenge = a
        .approve_device_linking_setup("test", request.packet, None)
        .await
        .unwrap();
    c.accept_device_linking_setup("test", &request.scope, challenge.packet.clone())
        .await
        .unwrap();
    c.accept_device_linking_setup("test", &request.scope, challenge.packet)
        .await
        .unwrap();
    let ao = a
        .device_linking_offer("test", &challenge.scope)
        .await
        .unwrap();
    let co = c
        .device_linking_offer("test", &request.scope)
        .await
        .unwrap();
    a.admit_device_linking_peer("test", &challenge.scope, co)
        .await
        .unwrap();
    c.admit_device_linking_peer("test", &request.scope, ao)
        .await
        .unwrap();
    c.start_device_linking_verification("test", &request.scope)
        .await
        .unwrap();
    for _ in 0..8 {
        drain(&a, &challenge.scope, &c, &request.scope).await;
        drain(&c, &request.scope, &a, &challenge.scope).await;
    }
    let digits = a
        .device_linking_decimals("test", &challenge.scope)
        .await
        .unwrap();
    assert!(digits.is_some());
    assert_eq!(
        digits,
        c.device_linking_decimals("test", &request.scope)
            .await
            .unwrap()
    );
    assert!(
        a.take_device_linking_verified("test", &challenge.scope)
            .await
            .is_err()
    );
    assert!(
        c.take_device_linking_verified("test", &request.scope)
            .await
            .is_err()
    );
    a.confirm_device_linking("test", &challenge.scope)
        .await
        .unwrap();
    c.confirm_device_linking("test", &request.scope)
        .await
        .unwrap();
    for _ in 0..4 {
        drain(&a, &challenge.scope, &c, &request.scope).await;
        drain(&c, &request.scope, &a, &challenge.scope).await;
    }
    a.take_device_linking_verified("test", &challenge.scope)
        .await
        .unwrap();
    c.take_device_linking_verified("test", &request.scope)
        .await
        .unwrap();
    for runtime in runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
}

#[tokio::test]
async fn worker_setup_rejects_wrong_scope_and_packet_without_losing_valid_retry() {
    let (_dirs, runtimes) = workers().await;
    let [a, c] = runtimes.each_ref().map(|r| r.accounts());
    let request = c.reserve_device_linking_setup("test").await.unwrap();
    let challenge = a
        .approve_device_linking_setup("test", request.packet, None)
        .await
        .unwrap();
    let mut wrong = request.scope.clone();
    wrong.generation += 1;
    assert!(
        c.accept_device_linking_setup("test", &wrong, challenge.packet.clone())
            .await
            .is_err()
    );
    assert!(
        c.accept_device_linking_setup("test", &request.scope, vec![0; 512 * 1024 + 1])
            .await
            .is_err()
    );
    c.accept_device_linking_setup("test", &request.scope, challenge.packet.clone())
        .await
        .unwrap();
    c.cancel_device_linking("test", &request.scope)
        .await
        .unwrap();
    assert!(
        c.accept_device_linking_setup("test", &request.scope, challenge.packet)
            .await
            .is_err()
    );
    for runtime in runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
}

#[tokio::test]
async fn worker_abandoned_setup_reply_retires_original_reservation() {
    let (_dirs, runtimes) = workers().await;
    let c = runtimes[1].accounts();
    let commands = c.worker_commands("test").await.unwrap();
    let (respond, receiver) = tokio::sync::oneshot::channel();
    drop(receiver);
    commands
        .send(super::super::AccountWorkerCommand::DeviceLinkingVerifier(
            Box::new(VerifierCommand::Setup(SetupCommand::ReserveRequest {
                respond,
            })),
        ))
        .await
        .unwrap();
    // Serial ordering requires the lost reply's exact cleanup before this next reservation.
    let request = c.reserve_device_linking_setup("test").await.unwrap();
    assert!(request.scope.generation >= 2);
    c.cancel_device_linking("test", &request.scope)
        .await
        .unwrap();
    for runtime in runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
}
