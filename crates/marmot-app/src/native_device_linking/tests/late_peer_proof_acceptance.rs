//! Directed real late peer-proof ordering; test observations grant no authority.
use super::*;
use futures::FutureExt;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_late_peer_proof_completes_without_periodic_tick() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs: [tempfile::TempDir; 3] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
    let apps = dirs.each_ref().map(|dir| {
        AccountHome::open(dir.path()).import_account("test", &keys.secret_key().to_secret_hex()).unwrap();
        MarmotApp::with_relay(dir.path(), &url)
    });
    let runtimes = apps.clone().map(MarmotAppRuntime::new);
    // [held exact proof, own proof harvested+policy durable, periodic observed,
    // fresh before barrier, exact authenticated peer received, completed while gated,
    // original full enrollment completed, public cancellation completed].
    let mut facts = [false; 8];
    let attempt = std::panic::AssertUnwindSafe(async {
        for runtime in &runtimes { runtime.reconcile_accounts().await.unwrap(); }
        let managers = runtimes.each_ref().map(|runtime| runtime.accounts());
        let first_b = managers[1].begin_device_linking_session("test").await.unwrap();
        let first_a = managers[0].approve_automatic_device_linking_session(
            "test", first_b.automatic_pairing_code().await.unwrap(), None).await.unwrap();
        first_a.automatic_pairing_code().await.unwrap();
        compare_and_confirm_pair(&first_a, &first_b).await;
        first_b.continue_automatic_linking(first_b.snapshot().await.unwrap().revision, true).await.unwrap();
        first_a.continue_automatic_linking(first_a.snapshot().await.unwrap().revision, true).await.unwrap();
        wait_for_automatic_phase(&first_a, &first_b, DeviceLinkingPhase::EnrollmentComplete).await;
        first_a.cancel().await.unwrap(); first_b.cancel().await.unwrap();
        drop(first_a); drop(first_b);
        let target = managers[0].device_linking_targets("test").await.unwrap().pop().unwrap();
        let c = managers[2].begin_device_linking_session("test").await.unwrap();
        let a = managers[0].approve_automatic_device_linking_session(
            "test", c.automatic_pairing_code().await.unwrap(), Some(target.selector)).await.unwrap();
        a.automatic_pairing_code().await.unwrap();
        compare_and_confirm_pair(&a, &c).await;
        c.continue_automatic_linking(c.snapshot().await.unwrap().revision, true).await.unwrap();
        a.continue_automatic_linking(a.snapshot().await.unwrap().revision, true).await.unwrap();
        // Automatic continuation stores its negative choice first; refreshing the
        // original captures the SDK sharing owner asynchronously. B has not yet
        // approved, so its addressed C proof cannot be prepared before this hold.
        let proof_gate = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                c.snapshot().await.unwrap();
                if let Some(gate) = c.arm_late_peer_proof_for_test() { break gate; }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.expect("actual recipient sharing original must be captured before B approval");
        let approval = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(approval) = managers[1].pending_device_linking_approvals("test").await.unwrap().pop() { break approval; }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.unwrap();
        let revision = approval.snapshot().await.unwrap().revision;
        approval.review_metadata(revision).await.unwrap();
        approval.approve_and_share_chats(revision).await.unwrap();
        let original = approval.sharing_original_for_test().expect("actual existing approval original");
        let owner = Arc::downgrade(&original);
        drop(original);
        let nonce = tokio::time::timeout(Duration::from_secs(15), proof_gate.observed()).await.unwrap().unwrap();
        facts[0] = true;
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(row) = managers[1].peer_proof_snapshot_for_test("test", owner.clone()).await.unwrap()
                    && row.nonce == nonce && row.flags == [true,true,true,true,false,false,false,true] {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.unwrap();
        facts[1] = true;
        let periodic = runtimes[1].hold_periodic_linking_for_test("test");
        tokio::time::timeout(Duration::from_secs(10), periodic.observed()).await.unwrap();
        facts[2] = true;
        let before = managers[1].peer_proof_snapshot_for_test("test", owner.clone()).await.unwrap().unwrap();
        facts[3] = before.nonce == nonce && before.flags == [true,true,true,true,false,false,false,true];
        proof_gate.release();
        let observed = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(row) = managers[1].peer_proof_snapshot_for_test("test", owner.clone()).await.unwrap()
                    && row.nonce == nonce && row.flags[4] {
                    break row;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await;
        if let Ok(row) = observed {
            facts[4] = row.flags[0] && row.flags[1] && row.flags[2] && row.flags[3] && row.flags[4] && row.flags[7];
            facts[5] = row.flags[6];
        }
        // Freeze the verdict before releasing either schedule/publication guard.
        drop(periodic); drop(proof_gate);
        wait_for_automatic_phase(&a, &c, DeviceLinkingPhase::EnrollmentComplete).await;
        facts[6] = true;
        a.cancel().await.unwrap(); c.cancel().await.unwrap();
        drop(approval);
        facts[7] = true;
    }).catch_unwind().await;
    let mut runtime_closes = 0;
    for runtime in runtimes {
        if runtime.shutdown_and_close().await.is_ok() { runtime_closes += 1; }
    }
    let mut planes_shutdown = 0;
    for app in &apps {
        app.relay_plane.shutdown().await;
        planes_shutdown += 1;
    }
    relay.shutdown();
    let address = url.strip_prefix("ws://").unwrap().trim_end_matches('/');
    let relay_closed = owned_loopback_listener_is_closed(address).await;
    eprintln!("late-peer-proof held={} own_harvested={} periodic_observed={} fresh_before={} authenticated_peer={} gated_complete={} enrollment_complete={} public_cancelled={} runtime_closes={} planes_shutdown={} relay_closed={} attempt_completed={}",
        facts[0],facts[1],facts[2],facts[3],facts[4],facts[5],facts[6],facts[7],runtime_closes,planes_shutdown,relay_closed,attempt.is_ok());
    assert!(facts.into_iter().all(|value| value) && runtime_closes == 3 && planes_shutdown == 3 && relay_closed && attempt.is_ok(),
        "authenticated_late_peer_proof_must_complete_without_periodic_tick");
}

// The address comes only from this test's owned MockRelay, never an external
// endpoint. This final probe proves the owned loopback listener has closed.
#[allow(clippy::disallowed_methods)]
async fn owned_loopback_listener_is_closed(address: &str) -> bool {
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Ok(socket) = tokio::net::TcpStream::connect(address).await {
            drop(socket);
            tokio::task::yield_now().await;
        }
    }).await.is_ok()
}
