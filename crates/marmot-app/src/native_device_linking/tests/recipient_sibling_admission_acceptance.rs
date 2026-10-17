//! Genuine recipient Request admission must schedule its first real Consent.
//! A distinct event-ordering regression; original enrollment qualification remains separate.
use super::*;
use futures::FutureExt;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_recipient_starts_first_consent_without_periodic_tick() {
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
    // Periodic gate, fresh Core-approved admission, initial Consent before gate
    // release (the intended verdict), actual Consent transport hold, exact proof
    // nonce, normal enrollment and explicit public cancellation.
    let mut facts = [false; 7];
    let mut primary_ready = false;
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
                if c.sibling_completion_aggregates_for_test() == Some((true, Some(1), 0, 0)) {
                    primary_ready = true;
                    if let Some(gate) = c.arm_late_peer_proof_for_test() {
                        break gate;
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("actual recipient original before B approval");
        let admission = proof_gate.arm_recipient_admission_for_test();
        let periodic = runtimes[2].hold_periodic_linking_for_test("test");
        tokio::time::timeout(Duration::from_secs(10), periodic.observed())
            .await
            .expect("recipient periodic gate reached before sibling approval");
        facts[0] = true;
        let (mut consent_observed, consent_release) = apps[2]
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
        // No snapshot/maintenance RPC on C while gated: the observation is
        // emitted only after actual protected Request intake and Core approval.
        let child = tokio::time::timeout(Duration::from_secs(15), admission.observed())
            .await
            .expect("actual fresh recipient child admitted while periodic work is gated");
        facts[1] = child.flags == [true, true, true, true, false, false];
        // Preserve the receiver if the intended first-publication verdict is
        // negative. Cleanup and ordinary positive progress must still execute.
        let first = tokio::time::timeout(Duration::from_secs(15), &mut consent_observed)
            .await
            .ok()
            .map(|result| result.expect("actual Consent transport observation"));
        facts[2] = first.is_some();
        drop(periodic);
        let held = match first {
            Some(message) => message,
            None => tokio::time::timeout(Duration::from_secs(15), consent_observed)
                .await
                .expect("same genuine Consent begins after periodic gate release")
                .expect("actual Consent transport observation after gate release"),
        };
        facts[3] = held.id.as_slice().len() == 32 && !held.payload.is_empty();
        drop(consent_release);
        let proof_nonce = tokio::time::timeout(Duration::from_secs(15), proof_gate.observed())
            .await
            .expect("real recipient proof follows released Consent")
            .expect("exact recipient proof nonce");
        facts[4] = proof_nonce == child.nonce;
        drop(proof_gate);
        wait_for_automatic_phase(&a, &c, DeviceLinkingPhase::EnrollmentComplete).await;
        facts[5] = true;
        a.cancel().await.unwrap();
        c.cancel().await.unwrap();
        approval.cancel().await.unwrap();
        facts[6] = true;
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
        "recipient-sibling-admission primary_ready={} periodic_observed={} fresh_admitted={} first_consent_before_gate={} actual_consent_held={} exact_proof_nonce={} enrollment_complete={} public_cancelled={} runtime_closes={} planes_shutdown={} relay_closed={} attempt_completed={}",
        primary_ready,
        facts[0],
        facts[1],
        facts[2],
        facts[3],
        facts[4],
        facts[5],
        facts[6],
        runtime_closes,
        planes_shutdown,
        relay_closed,
        attempt.is_ok()
    );
    assert!(
        primary_ready
            && facts.into_iter().all(|value| value)
            && runtime_closes == 3
            && planes_shutdown == 3
            && relay_closed
            && attempt.is_ok(),
        "admitted_recipient_must_start_first_consent_without_periodic_tick"
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
