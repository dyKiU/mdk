//! Real Request ACK harvested before actual authenticated sibling Consent.
//! This separate event-ordering witness is not qualification of the original four-device failures.
use super::*;
use futures::FutureExt;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_late_consent_starts_initial_proof_without_periodic_tick() {
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
    // Actual Consent held, actual Request ACK harvested, periodic gate observed,
    // fresh exact original before release, real Consent bound, exact C proof held,
    // policy and own proof harvested while gated, normal enrollment, public cancellation.
    let mut facts = [false; 9];
    let attempt = std::panic::AssertUnwindSafe(async {
        for runtime in &runtimes {
            runtime.reconcile_accounts().await.unwrap();
        }
        let managers = runtimes.each_ref().map(|runtime| runtime.accounts());
        let first_b = managers[1].begin_device_linking_session("test").await.unwrap();
        let first_a = managers[0]
            .approve_automatic_device_linking_session("test", first_b.automatic_pairing_code().await.unwrap(), None)
            .await.unwrap();
        first_a.automatic_pairing_code().await.unwrap();
        compare_and_confirm_pair(&first_a, &first_b).await;
        first_b.continue_automatic_linking(first_b.snapshot().await.unwrap().revision, true).await.unwrap();
        first_a.continue_automatic_linking(first_a.snapshot().await.unwrap().revision, true).await.unwrap();
        wait_for_automatic_phase(&first_a, &first_b, DeviceLinkingPhase::EnrollmentComplete).await;
        first_a.cancel().await.unwrap();
        first_b.cancel().await.unwrap();
        drop(first_a);
        drop(first_b);
        let target = managers[0].device_linking_targets("test").await.unwrap().pop().unwrap();
        let c = managers[2].begin_device_linking_session("test").await.unwrap();
        let a = managers[0]
            .approve_automatic_device_linking_session("test", c.automatic_pairing_code().await.unwrap(), Some(target.selector))
            .await.unwrap();
        a.automatic_pairing_code().await.unwrap();
        compare_and_confirm_pair(&a, &c).await;
        c.continue_automatic_linking(c.snapshot().await.unwrap().revision, true).await.unwrap();
        a.continue_automatic_linking(a.snapshot().await.unwrap().revision, true).await.unwrap();
        // Capture the actual recipient original before B approves: it has no B channel yet.
        let proof_gate = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                c.snapshot().await.unwrap();
                if let Some(gate) = c.arm_late_peer_proof_for_test() { break gate; }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.expect("actual recipient original before B approval");
        let (consent_observed, consent_release) = apps[2].relay_plane.hold_next_sibling_consent(
            cgka_traits::MemberId::new(keys.public_key().to_bytes().to_vec()),
        );
        struct ConsentRelease(Arc<tokio::sync::Notify>);
        impl Drop for ConsentRelease {
            fn drop(&mut self) { self.0.notify_one(); }
        }
        let consent_release = ConsentRelease(consent_release);
        let approval = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(approval) = managers[1].pending_device_linking_approvals("test").await.unwrap().pop() {
                    break approval;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.unwrap();
        let revision = approval.snapshot().await.unwrap().revision;
        approval.review_metadata(revision).await.unwrap();
        approval.approve_and_share_chats(revision).await.unwrap();
        let original = approval.sharing_original_for_test().expect("actual B sharing original");
        let owner = Arc::downgrade(&original);
        let held_consent = tokio::time::timeout(Duration::from_secs(15), consent_observed).await.unwrap().unwrap();
        facts[0] = held_consent.id.as_slice().len() == 32 && !held_consent.payload.is_empty();
        // handshake_published becomes true only after the exact owned successful
        // SDK result is harvested, not when a Request task is merely prepared/sent.
        let before = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(row) = managers[1].peer_proof_snapshot_for_test("test", owner.clone()).await.unwrap()
                    && row.consent_ordering == [false, true] && !row.flags[5] { break row; }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.unwrap();
        let nonce = before.nonce;
        facts[1] = before.flags == [true, true, false, false, false, false, false, false];
        let periodic = runtimes[1].hold_periodic_linking_for_test("test");
        tokio::time::timeout(Duration::from_secs(10), periodic.observed()).await.unwrap();
        facts[2] = true;
        // A Request retry may already have started before the gate latched. Let
        // its genuine owned completion harvest, never cancel it or invent an ACK.
        let fresh = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(row) = managers[1].peer_proof_snapshot_for_test("test", owner.clone()).await.unwrap()
                    && row.nonce == nonce && row.consent_ordering == [false, true] && !row.flags[5] { break row; }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.unwrap();
        facts[3] = fresh.flags == [true, true, false, false, false, false, false, false];
        drop(consent_release);
        // ready=true on this source channel is set only after Core successfully
        // binds the genuine received Consent to the same retained nonce.
        let bound = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(row) = managers[1].peer_proof_snapshot_for_test("test", owner.clone()).await.unwrap()
                    && row.nonce == nonce && row.consent_ordering == [true, true] { break row; }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.unwrap();
        facts[4] = bound.flags[0] && bound.flags[1] && !bound.flags[4];
        let proof_nonce = tokio::time::timeout(Duration::from_secs(15), proof_gate.observed()).await.unwrap().unwrap();
        facts[5] = proof_nonce == nonce;
        // Freeze only the intended progress verdict. Failure here must still
        // release both gates and establish real normal enrollment/positive closes.
        facts[6] = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(row) = managers[1].peer_proof_snapshot_for_test("test", owner.clone()).await.unwrap()
                    && row.nonce == nonce && row.consent_ordering == [true, true]
                    && row.flags == [true, true, true, true, false, false, false, true] { break; }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.is_ok();
        drop(periodic);
        drop(proof_gate);
        wait_for_automatic_phase(&a, &c, DeviceLinkingPhase::EnrollmentComplete).await;
        facts[7] = true;
        a.cancel().await.unwrap();
        c.cancel().await.unwrap();
        approval.cancel().await.unwrap();
        drop(approval);
        drop(original);
        facts[8] = true;
    }).catch_unwind().await;
    let mut runtime_closes = 0;
    for runtime in runtimes { if runtime.shutdown_and_close().await.is_ok() { runtime_closes += 1; } }
    let mut planes_shutdown = 0;
    for app in &apps { app.relay_plane.shutdown().await; planes_shutdown += 1; }
    relay.shutdown();
    let address = url.strip_prefix("ws://").unwrap().trim_end_matches('/');
    let relay_closed = owned_loopback_listener_is_closed(address).await;
    eprintln!("late-sibling-consent consent_held={} request_ack_harvested={} periodic_observed={} fresh_before={} consent_bound={} peer_proof_held={} initial_progress={} enrollment_complete={} public_cancelled={} runtime_closes={} planes_shutdown={} relay_closed={} attempt_completed={}",
        facts[0],facts[1],facts[2],facts[3],facts[4],facts[5],facts[6],facts[7],facts[8],runtime_closes,planes_shutdown,relay_closed,attempt.is_ok());
    assert!(facts.into_iter().all(|value| value) && runtime_closes == 3 && planes_shutdown == 3 && relay_closed && attempt.is_ok(),
        "authenticated_late_consent_must_start_initial_proof_without_periodic_tick");
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
