//! Actual public cancellation and explicitly injected post-auth validation rejection.
use super::*;
use futures::FutureExt;
use std::sync::Arc;
use std::time::Duration;
use crate::client::device_linking::sibling_sharing::peer_proof_probe::negative;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario { PublicCancel, InjectedValidation }

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_peer_proof_public_cancel_cannot_complete_original() { run(Scenario::PublicCancel).await; }

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_peer_proof_injected_validation_rejection_retains_and_recovers() { run(Scenario::InjectedValidation).await; }

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
    let mut observations = [0usize; 4];
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
        // Automatic continuation stores its negative choice first; refreshing the
        // original captures the SDK sharing owner asynchronously. B has not yet
        // approved, so its addressed C proof cannot be prepared before this hold.
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
        .expect("actual recipient sharing original must be captured before B approval");
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
            .expect("actual existing approval original");
        let owner = Arc::downgrade(&original);
        let nonce = tokio::time::timeout(Duration::from_secs(15), proof_gate.observed())
            .await
            .unwrap()
            .unwrap();
        facts[0] = true;
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(row) = managers[1]
                    .peer_proof_snapshot_for_test("test", owner.clone())
                    .await
                    .unwrap()
                    && row.nonce == nonce
                    && row.flags == [true, true, true, true, false, false, false, true]
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        facts[1] = true;
        let periodic = runtimes[1].hold_periodic_linking_for_test("test");
        tokio::time::timeout(Duration::from_secs(10), periodic.observed())
            .await
            .unwrap();
        facts[2] = true;
        let before = managers[1]
            .peer_proof_snapshot_for_test("test", owner.clone())
            .await
            .unwrap()
            .unwrap();
        facts[3] = before.nonce == nonce && before.pending_controls == 0
            && before.flags == [true, true, true, true, false, false, false, true];
        let deadline = before.deadline;
        let probe = negative::arm(&original, nonce, scenario == Scenario::InjectedValidation);
        if scenario == Scenario::PublicCancel {
            approval.cancel().await.unwrap();
            let status = original.status_for_test();
            facts[4] = !status.0 && !status.1;
            proof_gate.release();
            // This actor reply is a barrier on the exact old original, not a row-derived grant.
            let after = managers[1].peer_proof_snapshot_for_test("test", owner.clone()).await.unwrap();
            facts[5] = after.as_ref().is_none_or(|row| !row.flags[6]);
            facts[7] = after.as_ref().is_none_or(|row| row.nonce == nonce && row.deadline == deadline);
        } else {
            proof_gate.release();
            let blocked = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if let Some(row) = managers[1].peer_proof_snapshot_for_test("test", owner.clone()).await.unwrap()
                        && row.nonce == nonce && row.flags[4] && probe.counts()[1] > 0 {
                        break row;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }).await.unwrap();
            // Freeze the negative verdict while the real proof is retained and
            // periodic completion is still gated. No input or committed flag is fabricated.
            facts[4] = !blocked.flags[6] && blocked.flags[0] && blocked.flags[1]
                && blocked.flags[2] && blocked.flags[3] && blocked.flags[4] && blocked.flags[7];
            facts[7] = blocked.deadline == deadline && blocked.pending_controls == 0;
            probe.clear();
        }
        drop(periodic);
        drop(proof_gate);
        if scenario == Scenario::InjectedValidation {
            let recovered = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if let Some(row) = managers[1].peer_proof_snapshot_for_test("test", owner.clone()).await.unwrap()
                        && row.nonce == nonce && row.flags[6] { break row; }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }).await.unwrap();
            facts[5] = recovered.flags[0] && recovered.flags[1] && recovered.flags[2]
                && recovered.flags[3] && recovered.flags[4] && recovered.flags[7];
            facts[7] &= recovered.deadline == deadline && recovered.pending_controls == 0;
        }
        wait_for_automatic_phase(&a, &c, DeviceLinkingPhase::EnrollmentComplete).await;
        facts[8] = true;
        // Recheck the exact old actor after actual peer publication and normal enrollment.
        let final_row = managers[1].peer_proof_snapshot_for_test("test", owner.clone()).await.unwrap();
        let counts = probe.counts();
        observations = counts;
        facts[6] = counts[2] == 0 && if scenario == Scenario::InjectedValidation {
            counts[0] == 1 && counts[1] > 0 && counts[3] == 1 && final_row.as_ref().is_some_and(|row| row.pending_controls == 0)
        } else {
            counts[0] == 0 && counts[1] == 0 && counts[3] == 0 && !original.status_for_test().0
                && !original.status_for_test().1 && final_row.as_ref().is_none_or(|row| !row.flags[6])
        };
        a.cancel().await.unwrap(); c.cancel().await.unwrap();
        if scenario == Scenario::InjectedValidation { approval.cancel().await.unwrap(); }
        drop(approval); drop(original);
        facts[9] = true;
    }).catch_unwind().await;
    let mut runtime_closes = 0;
    for runtime in runtimes { if runtime.shutdown_and_close().await.is_ok() { runtime_closes += 1; } }
    let mut planes_shutdown = 0;
    for app in &apps { app.relay_plane.shutdown().await; planes_shutdown += 1; }
    relay.shutdown();
    let address = url.strip_prefix("ws://").unwrap().trim_end_matches('/');
    let relay_closed = owned_loopback_listener_is_closed(address).await;
    let mode = if scenario == Scenario::PublicCancel { "public-cancel" } else { "injected-validation" };
    eprintln!("late-peer-negative mode={} held={} own_harvested={} periodic_observed={} fresh_before={} negative_preserved={} recovered_or_retired={} no_replay={} ownership_preserved={} enrollment_complete={} public_cancelled={} accepted={} validation_rejections={} own_publications={} open_attempts={} runtime_closes={} planes_shutdown={} relay_closed={} attempt_completed={}",
        mode,facts[0],facts[1],facts[2],facts[3],facts[4],facts[5],facts[6],facts[7],facts[8],facts[9],
        observations[0],observations[1],observations[2],observations[3],runtime_closes,planes_shutdown,relay_closed,attempt.is_ok());
    assert!(facts.into_iter().all(|value| value) && runtime_closes == 3 && planes_shutdown == 3
        && relay_closed && attempt.is_ok(), "late_peer_proof_negative_guard_and_positive_cleanup");
}

// Only the owned MockRelay's loopback listener is probed, never an external endpoint.
#[allow(clippy::disallowed_methods)]
async fn owned_loopback_listener_is_closed(address: &str) -> bool {
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Ok(socket) = tokio::net::TcpStream::connect(address).await {
            drop(socket); tokio::task::yield_now().await;
        }
    }).await.is_ok()
}
