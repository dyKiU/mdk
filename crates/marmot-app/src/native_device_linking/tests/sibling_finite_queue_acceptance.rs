//! One real sibling timer quantum precedes the second of three finite read RPCs.
use super::*;
use futures::FutureExt;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_sibling_due_turn_precedes_second_finite_status_reply() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs: [tempfile::TempDir; 3] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
    let apps = dirs.each_ref().map(|dir| {
        AccountHome::open(dir.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        MarmotApp::with_relay(dir.path(), &url)
    });
    let runtimes = apps.clone().map(MarmotAppRuntime::new);
    let mut facts = [false; 6];
    let mut service_after = None;
    let mut command_replies = 0;
    let attempt = std::panic::AssertUnwindSafe(async {
        for runtime in &runtimes {
            runtime.reconcile_accounts().await.unwrap();
        }
        let managers = runtimes.each_ref().map(|runtime| runtime.accounts());
        let first_b = managers[1]
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let first_a = managers[0]
            .approve_automatic_device_linking_session(
                "test",
                first_b.automatic_pairing_code().await.unwrap(),
                None,
            )
            .await
            .unwrap();
        first_a.automatic_pairing_code().await.unwrap();
        compare_and_confirm_pair(&first_a, &first_b).await;
        first_b
            .continue_automatic_linking(first_b.snapshot().await.unwrap().revision, true)
            .await
            .unwrap();
        first_a
            .continue_automatic_linking(first_a.snapshot().await.unwrap().revision, true)
            .await
            .unwrap();
        wait_for_automatic_phase(&first_a, &first_b, DeviceLinkingPhase::EnrollmentComplete).await;
        first_a.cancel().await.unwrap();
        first_b.cancel().await.unwrap();
        drop(first_a);
        drop(first_b);
        let ordinary = runtimes[1]
            .create_group("test", "finite status control", &[], None)
            .await
            .unwrap();
        runtimes[1]
            .group_recovery_status("test", &ordinary)
            .await
            .unwrap();
        let sender = runtimes[1]
            .sibling_finite_queue_sender_for_test("test")
            .await
            .unwrap();

        let target = managers[0]
            .device_linking_targets("test")
            .await
            .unwrap()
            .pop()
            .unwrap();
        let c = managers[2]
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let a = managers[0]
            .approve_automatic_device_linking_session(
                "test",
                c.automatic_pairing_code().await.unwrap(),
                Some(target.selector),
            )
            .await
            .unwrap();
        a.automatic_pairing_code().await.unwrap();
        compare_and_confirm_pair(&a, &c).await;
        c.continue_automatic_linking(c.snapshot().await.unwrap().revision, true)
            .await
            .unwrap();
        a.continue_automatic_linking(a.snapshot().await.unwrap().revision, true)
            .await
            .unwrap();
        // Capture the actual recipient original before B approves: it has no B channel yet.
        let proof_gate = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                c.snapshot().await.unwrap();
                if let Some(gate) = c.arm_late_peer_proof_for_test() {
                    break gate;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("actual recipient original before B approval");
        let approval = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(approval) = managers[1]
                    .pending_device_linking_approvals("test")
                    .await
                    .unwrap()
                    .pop()
                {
                    break approval;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        let revision = approval.snapshot().await.unwrap().revision;
        approval.review_metadata(revision).await.unwrap();
        approval.approve_and_share_chats(revision).await.unwrap();
        let original = approval
            .sharing_original_for_test()
            .expect("actual B sharing original");
        // Genuine C proof is held before actual relay publication; B's
        // already-onboarded source original and channel remain live.
        let nonce = tokio::time::timeout(Duration::from_secs(15), proof_gate.observed())
            .await
            .expect("actual C proof hold")
            .expect("actual C proof nonce");
        facts[0] = original.status_for_test() == (true, false);
        let gate = runtimes[1].observe_sibling_finite_queue_for_test(
            Arc::downgrade(&original),
            nonce,
            ordinary.clone(),
        );
        tokio::time::timeout(Duration::from_secs(10), gate.observed())
            .await
            .expect("real sibling interval tick latched for the exact live source");
        facts[1] = true;
        // Exactly three ordinary checked commands are queued while this actor
        // is stopped after the actual timer latch. No clock or deadline changes.
        let mut replies = Vec::new();
        for _ in 0..3 {
            let (respond, reply) = tokio::sync::oneshot::channel();
            sender
                .try_send(
                    crate::runtime::account_worker::AccountWorkerCommand::GroupRecoveryStatus {
                        group_id: ordinary.clone(),
                        respond,
                    },
                )
                .expect("finite ordinary status queue capacity");
            replies.push(reply);
        }
        gate.release();
        for reply in replies {
            tokio::time::timeout(Duration::from_secs(15), reply)
                .await
                .expect("finite status reply deadline")
                .expect("ordinary status reply remains owned")
                .expect("ordinary hydrated group status succeeds");
            command_replies += 1;
        }
        // If the counterfactual drained all three commands first, still allow
        // its real service to return before freezing the negative ordinal.
        tokio::time::timeout(Duration::from_secs(15), gate.serviced())
            .await
            .expect("actual matched sibling maintenance returns successfully");
        let (latched, commands, after, live) = gate.result();
        facts[2] = latched && commands == 3 && live;
        service_after = after;
        facts[3] = original.status_for_test().0;
        drop(gate);
        drop(proof_gate);
        wait_for_automatic_phase(&a, &c, DeviceLinkingPhase::EnrollmentComplete).await;
        facts[4] = true;
        a.cancel().await.unwrap();
        c.cancel().await.unwrap();
        approval.cancel().await.unwrap();
        facts[5] = true;
        drop(approval);
        drop(original);
    })
    .catch_unwind()
    .await;
    let mut runtime_closes = 0;
    for runtime in runtimes {
        if runtime.shutdown_and_close().await.is_ok() {
            runtime_closes += 1;
        }
    }
    let mut planes_shutdown = 0;
    for app in &apps {
        app.relay_plane.shutdown().await;
        planes_shutdown += 1;
    }
    relay.shutdown();
    let address = url.strip_prefix("ws://").unwrap().trim_end_matches('/');
    let relay_closed = owned_loopback_listener_is_closed(address).await;
    eprintln!(
        "sibling-finite-queue live_source={} real_latch={} matched_service={} original_live={} enrollment_complete={} public_cancelled={} command_replies={} service_after={:?} runtime_closes={} planes_shutdown={} relay_closed={} attempt_completed={}",
        facts[0],
        facts[1],
        facts[2],
        facts[3],
        facts[4],
        facts[5],
        command_replies,
        service_after,
        runtime_closes,
        planes_shutdown,
        relay_closed,
        attempt.is_ok()
    );
    assert!(
        facts.into_iter().all(|value| value)
            && command_replies == 3
            && service_after.is_some_and(|after| after <= 1)
            && runtime_closes == 3
            && planes_shutdown == 3
            && relay_closed
            && attempt.is_ok(),
        "live_sibling_due_turn_must_precede_second_finite_status_reply"
    );
}

// Probe only this fixture's owned loopback MockRelay listener.
#[allow(clippy::disallowed_methods)]
async fn owned_loopback_listener_is_closed(address: &str) -> bool {
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Ok(socket) = tokio::net::TcpStream::connect(address).await {
            drop(socket);
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok()
}
