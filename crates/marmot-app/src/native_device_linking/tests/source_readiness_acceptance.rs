//! Genuine fresh source readiness must schedule its first Request without its sibling timer.
use super::*;
use futures::FutureExt;
use std::sync::Arc;
use std::time::Duration;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_completed_source_starts_request_without_sibling_periodic_tick() {
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
    let mut facts = [false; 10];
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
        let request_gate = proof_gate.hold_recipient_request_for_test();
        // This NEW gate blocks only sibling_tick, never broad linking_tick.
        let periodic = runtimes[1].hold_sibling_only_periodic_for_test("test");
        tokio::time::timeout(Duration::from_secs(10), periodic.observed())
            .await
            .unwrap();
        facts[0] = true;
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
            .expect("actual B original");
        let owner = Arc::downgrade(&original);
        let ready = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(row) = managers[1]
                    .source_readiness_snapshot_for_test("test", owner.clone())
                    .await
                    .unwrap()
                    && row.facts.into_iter().all(|fact| fact)
                {
                    break row;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("real fresh Core Completed/guard/roster/request while only sibling timer is gated");
        facts[1] = ready.facts.into_iter().all(|fact| fact);
        let deadline = ready.deadline;
        let early = tokio::time::timeout(Duration::from_secs(15), request_gate.observed())
            .await
            .ok();
        // This is the sole intended baseline FALSE. No inference from task
        // preparation/SDK ACK/Processed or an observer that calls maintenance.
        facts[2] = early.as_ref().is_some_and(|request| {
            request.owner.ptr_eq(&owner)
                && request.message_id.as_slice().len() == 32
                && request.payload_nonempty
        });
        let still_ready = managers[1]
            .source_readiness_snapshot_for_test("test", owner.clone())
            .await
            .unwrap()
            .expect("same actual original after the fixed verdict window");
        facts[3] =
            still_ready.facts.into_iter().all(|fact| fact) && still_ready.deadline == deadline;
        drop(periodic);
        facts[4] = true;
        let request = match early {
            Some(request) => request,
            None => tokio::time::timeout(Duration::from_secs(15), request_gate.observed())
                .await
                .expect("same real Request follows ordinary periodic release"),
        };
        facts[5] = request.owner.ptr_eq(&owner)
            && request.message_id.as_slice().len() == 32
            && request.payload_nonempty;
        let actual = managers[1]
            .peer_proof_snapshot_for_test("test", owner.clone())
            .await
            .unwrap()
            .unwrap();
        facts[6] = actual.nonce == request.nonce
            && actual.deadline == deadline
            && actual.flags[0]
            && actual.flags[1]
            && actual.flags[5]
            && !actual.flags[6];
        drop(request_gate);
        drop(proof_gate);
        facts[7] = true;
        wait_for_automatic_phase(&a, &c, DeviceLinkingPhase::EnrollmentComplete).await;
        facts[8] = true;
        a.cancel().await.unwrap();
        c.cancel().await.unwrap();
        approval.cancel().await.unwrap();
        facts[9] = true;
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
        "source-readiness periodic_observed={} fresh_core_prerequisites={} first_request_before_periodic_release={} prerequisites_still_fresh={} periodic_released={} actual_request_identity={} exact_channel_nonce_deadline={} guards_released={} enrollment_complete={} public_cancelled={} runtime_closes={} planes_shutdown={} relay_closed={} attempt_completed={}",
        facts[0],
        facts[1],
        facts[2],
        facts[3],
        facts[4],
        facts[5],
        facts[6],
        facts[7],
        facts[8],
        facts[9],
        runtime_closes,
        planes_shutdown,
        relay_closed,
        attempt.is_ok()
    );
    assert!(
        facts.into_iter().all(|fact| fact)
            && runtime_closes == 3
            && planes_shutdown == 3
            && relay_closed
            && attempt.is_ok(),
        "fresh_completed_owned_source_must_start_first_request_without_sibling_periodic_tick"
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
