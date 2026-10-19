//! Genuine first Request ACK, a later retry SDK result held, then real Consent.
use super::*;
use crate::client::device_linking::sibling_sharing::peer_proof_probe::retry_completion;
use futures::FutureExt;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_consent_retires_obsolete_request_retry_before_proof() {
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
    let mut facts = [false; 12];
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
        let (consent_observed, consent_release) =
            apps[2]
                .relay_plane
                .hold_next_sibling_consent(cgka_traits::MemberId::new(
                    keys.public_key().to_bytes().to_vec(),
                ));
        struct ConsentRelease(Arc<tokio::sync::Notify>);
        impl Drop for ConsentRelease {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }
        let consent_release = ConsentRelease(consent_release);
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
        let owner = Arc::downgrade(&original);
        let held_consent = tokio::time::timeout(Duration::from_secs(15), consent_observed)
            .await
            .unwrap()
            .unwrap();
        facts[0] = held_consent.id.as_slice().len() == 32 && !held_consent.payload.is_empty();
        // handshake_published becomes true only after the exact owned successful
        // SDK result is harvested, not when a Request task is merely prepared/sent.
        let before = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(row) = managers[1]
                    .peer_proof_snapshot_for_test("test", owner.clone())
                    .await
                    .unwrap()
                    && row.consent_ordering == [false, true]
                    && !row.flags[5]
                {
                    break row;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        let nonce = before.nonce;
        facts[1] = before.flags == [true, true, false, false, false, false, false, false];
        // Only the exact Weak original/nonce/deadline can match. Initial Request,
        // recipient Consent and proof publications cannot enter this hold.
        let retry = retry_completion::arm(owner.clone(), nonce, before.deadline);
        tokio::time::timeout(Duration::from_secs(15), retry.observed())
            .await
            .unwrap();
        let held_retry = retry.observation();
        facts[2] = held_retry.captured_exact_retry
            && held_retry.real_sdk_ack_held
            && held_retry.publish_calls == 1
            && !held_retry.release_requested
            && !held_retry.future_dropped;
        let periodic = runtimes[1].hold_periodic_linking_for_test("test");
        tokio::time::timeout(Duration::from_secs(10), periodic.observed())
            .await
            .unwrap();
        facts[4] = true;
        let fresh = managers[1]
            .peer_proof_snapshot_for_test("test", owner.clone())
            .await
            .unwrap()
            .expect("exact original still owns held retry");
        facts[3] = fresh.nonce == nonce
            && fresh.deadline == before.deadline
            && fresh.consent_ordering == [false, true]
            && fresh.flags == [true, true, false, false, false, true, false, false];
        drop(consent_release);
        let bound = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(row) = managers[1]
                    .peer_proof_snapshot_for_test("test", owner.clone())
                    .await
                    .unwrap()
                    && row.nonce == nonce
                    && row.deadline == before.deadline
                    && row.consent_ordering == [true, true]
                {
                    break row;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        facts[5] = bound.flags[0] && bound.flags[1] && !bound.flags[4];
        let proof_nonce = tokio::time::timeout(Duration::from_secs(15), proof_gate.observed())
            .await
            .unwrap()
            .unwrap();
        facts[11] = proof_nonce == nonce;
        // Freeze the intended oracle without asserting; every gate is then
        // released and normal real enrollment/positive closes must still pass.
        let _verdict_window = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let fresh = managers[1]
                    .peer_proof_snapshot_for_test("test", owner.clone())
                    .await
                    .unwrap();
                facts[6] = fresh.is_some_and(|row| {
                    row.nonce == nonce
                        && row.deadline == before.deadline
                        && row.consent_ordering == [true, true]
                        && row.flags == [true, true, true, true, false, false, false, true]
                });
                let observed_retry = retry.observation();
                facts[7] = observed_retry.future_dropped
                    && observed_retry.dropped_before_release
                    && !observed_retry.release_requested
                    && !observed_retry.normal_release;
                if facts[6] && facts[7] {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        // Both independent observations share the same fixed15s window. A
        // pending abort is never inferred from policy/proof progress alone.
        retry.release();
        drop(periodic);
        drop(proof_gate);
        tokio::time::timeout(Duration::from_secs(15), retry.dropped())
            .await
            .unwrap();
        facts[10] = retry.observation().future_dropped && retry.observation().release_requested;
        wait_for_automatic_phase(&a, &c, DeviceLinkingPhase::EnrollmentComplete).await;
        facts[8] = true;
        a.cancel().await.unwrap();
        c.cancel().await.unwrap();
        approval.cancel().await.unwrap();
        drop(approval);
        drop(original);
        facts[9] = true;
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
        "request-retry-completion consent_held={} first_request_ack={} retry_sdk_ack_held={} fresh_pending_retry={} periodic_observed={} consent_bound={} proof_progress_before_release={} retry_future_dropped_before_release={} enrollment_complete={} public_cancelled={} guards_released={} peer_proof_held={} runtime_closes={} planes_shutdown={} relay_closed={} attempt_completed={}",
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
        facts[10],
        facts[11],
        runtime_closes,
        planes_shutdown,
        relay_closed,
        attempt.is_ok()
    );
    assert!(
        facts.into_iter().all(|value| value)
            && runtime_closes == 3
            && planes_shutdown == 3
            && relay_closed
            && attempt.is_ok(),
        "authenticated_consent_must_retire_only_obsolete_request_retry_before_proof"
    );
}

// Probe only this fixture's owned loopback MockRelay listener.
#[allow(clippy::disallowed_methods)]
pub(super) async fn owned_loopback_listener_is_closed(address: &str) -> bool {
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Ok(socket) = tokio::net::TcpStream::connect(address).await {
            drop(socket);
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok()
}
