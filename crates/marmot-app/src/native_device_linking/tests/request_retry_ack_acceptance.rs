//! Real successful SDK results held from harvest; no fabricated ACK or authority.
use super::*;
use futures::FutureExt;
use std::sync::Arc;
use std::time::Duration;
use crate::client::device_linking::sibling_sharing::peer_proof_probe::retry_completion;
#[derive(Clone, Copy)]
enum Scenario { Initial, Proof }
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_consent_cannot_retire_initial_request_ack() { run(Scenario::Initial).await; }
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_peer_proof_cannot_replace_own_proof_ack() { run(Scenario::Proof).await; }
async fn run(scenario: Scenario) {
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
    let mut samples = 0usize;
    let mut window_elapsed_us = 0u128;
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
        let request_hold = proof_gate.hold_recipient_request_for_test();
        let approval = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(approval) = managers[1].pending_device_linking_approvals("test").await.unwrap().pop() { break approval; }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.unwrap();
        let revision = approval.snapshot().await.unwrap().revision;
        approval.review_metadata(revision).await.unwrap();
        approval.approve_and_share_chats(revision).await.unwrap();
        let original = approval.sharing_original_for_test().expect("actual source original");
        let owner = Arc::downgrade(&original);
        let request = tokio::time::timeout(Duration::from_secs(15), request_hold.observed()).await.unwrap();
        facts[0] = request.owner.ptr_eq(&owner) && request.message_id.as_slice().len() == 32 && request.payload_nonempty;
        let before = managers[1].peer_proof_snapshot_for_test("test", owner.clone()).await.unwrap().expect("exact held source channel");
        let nonce = request.nonce;
        let deadline = before.deadline;
        facts[1] = before.nonce == nonce && before.flags[0] && before.flags[1]
            && before.consent_ordering == [false, false] && before.flags[5];
        let ack = match scenario {
            Scenario::Initial => retry_completion::arm_initial(owner.clone(), nonce, deadline),
            Scenario::Proof => retry_completion::arm_proof(owner.clone(), nonce, deadline),
        };
        drop(request_hold);
        // No fake peer proof: release this real recipient publication gate.
        drop(proof_gate);
        tokio::time::timeout(Duration::from_secs(15), ack.observed()).await.unwrap();
        let held = ack.observation();
        facts[2] = held.captured_exact_publication && held.real_sdk_ack_held && held.publish_calls == 1
            && !held.release_requested && !held.future_dropped;
        // The source's ready flag is only set by successful real Core Consent
        // binding. The proof scenario additionally waits for actual peer proof.
        let bound = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(row) = managers[1].peer_proof_snapshot_for_test("test", owner.clone()).await.unwrap()
                    && row.nonce == nonce && row.deadline == deadline && row.flags[0] && row.flags[1]
                    && row.consent_ordering[0] && (matches!(scenario, Scenario::Initial) || row.flags[4])
                { break row; }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.unwrap();
        facts[3] = bound.consent_ordering[0];
        facts[4] = match scenario { Scenario::Initial => !bound.consent_ordering[1], Scenario::Proof => bound.consent_ordering[1] && bound.flags[2] && bound.flags[4] && bound.flags[7] };
        // Observe the protected negative throughout ONE fixed15s window,
        // not a single snapshot before asynchronous task destruction can run.
        let window_start = std::time::Instant::now();
        let stop = window_start + Duration::from_secs(15);
        let mut protected = true;
        loop {
            let fresh = managers[1].peer_proof_snapshot_for_test("test", owner.clone()).await.unwrap();
            let held = ack.observation();
            let valid = fresh.is_some_and(|row| {
                row.nonce == nonce && row.deadline == deadline && deadline > std::time::Instant::now()
                    && row.flags[0] && row.flags[1] && row.flags[5] && !row.flags[6]
                    && row.consent_ordering[0]
                    && match scenario {
                        Scenario::Initial => !row.consent_ordering[1] && !row.flags[2] && !row.flags[3] && !row.flags[7],
                        Scenario::Proof => row.consent_ordering[1] && row.flags[2] && !row.flags[3] && row.flags[4] && row.flags[7],
                    }
            }) && held.real_sdk_ack_held && held.publish_calls == 1 && !held.future_dropped
                && !held.dropped_before_release && !held.release_requested && !held.normal_release;
            protected &= valid;
            samples += 1;
            if std::time::Instant::now() >= stop { break; }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        window_elapsed_us = window_start.elapsed().as_micros();
        facts[5] = protected && samples >= 2 && window_elapsed_us >= 15_000_000;
        ack.release();
        tokio::time::timeout(Duration::from_secs(15), ack.dropped()).await.unwrap();
        let released = ack.observation();
        facts[6] = released.normal_release && released.future_dropped && !released.dropped_before_release;
        wait_for_automatic_phase(&a, &c, DeviceLinkingPhase::EnrollmentComplete).await;
        facts[7] = true;
        a.cancel().await.unwrap(); c.cancel().await.unwrap(); approval.cancel().await.unwrap();
        facts[8] = true;
        facts[9] = ack.observation().release_requested;
        drop(approval); drop(original);
    }).catch_unwind().await;
    let mut runtime_closes = 0;
    for runtime in runtimes {
        if runtime.shutdown_and_close().await.is_ok() { runtime_closes += 1; }
    }
    let mut planes_shutdown = 0;
    for app in &apps { app.relay_plane.shutdown().await; planes_shutdown += 1; }
    relay.shutdown();
    let address = url.strip_prefix("ws://").unwrap().trim_end_matches('/');
    let relay_closed = owned_loopback_listener_is_closed(address).await;
    let label = match scenario { Scenario::Initial => "initial", Scenario::Proof => "proof" };
    eprintln!("request-retry-ack scenario={} exact_request={} initial_owned={} real_sdk_ack_held={} consent_bound={} phase_prerequisites={} protected_window={} normal_release={} enrollment_complete={} public_cancelled={} guards_released={} samples={} window_elapsed_us={} runtime_closes={} planes_shutdown={} relay_closed={} attempt_completed={}",
        label,facts[0],facts[1],facts[2],facts[3],facts[4],facts[5],facts[6],facts[7],facts[8],facts[9],samples,window_elapsed_us,runtime_closes,planes_shutdown,relay_closed,attempt.is_ok());
    assert!(facts.into_iter().all(|fact| fact) && samples >= 2 && runtime_closes == 3 && planes_shutdown == 3 && relay_closed && attempt.is_ok(),
        "required_initial_or_proof_ack_must_remain_owned_until_real_report_release");
}
// Probe only this fixture's owned loopback MockRelay listener.
#[allow(clippy::disallowed_methods)]
async fn owned_loopback_listener_is_closed(address: &str) -> bool {
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Ok(socket) = tokio::net::TcpStream::connect(address).await {
            drop(socket); tokio::task::yield_now().await;
        }
    }).await.is_ok()
}
