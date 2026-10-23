//! Older recipient proof retry wins over a later Consent, using real timers.
use super::*;
use crate::client::device_linking::sibling_sharing::peer_proof_probe::recipient_retry_priority as priority;
use futures::FutureExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn older_recipient_proof_retry_precedes_later_consent_retry() {
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
    let mut selected_proof = false;
    let mut release_witnesses = Vec::new();
    let attempt = std::panic::AssertUnwindSafe(async {
        for runtime in &runtimes {
            runtime.reconcile_accounts().await.unwrap();
        }
        let managers = runtimes.each_ref().map(|runtime| runtime.accounts());
        let b = managers[1]
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let a = managers[0]
            .approve_automatic_device_linking_session(
                "test",
                b.automatic_pairing_code().await.unwrap(),
                None,
            )
            .await
            .unwrap();
        a.automatic_pairing_code().await.unwrap();
        compare_and_confirm_pair(&a, &b).await;
        for session in [&a, &b] {
            session
                .continue_automatic_linking(session.snapshot().await.unwrap().revision, true)
                .await
                .unwrap();
        }
        wait_for_automatic_phase(&a, &b, DeviceLinkingPhase::EnrollmentComplete).await;
        a.cancel().await.unwrap();
        b.cancel().await.unwrap();
        drop(a);
        drop(b);
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
        // Existing Request hold lets us bind B's exact original before its proof.
        // The old recipient proof gate is released before C's own proof can be required.
        let temporary_recipient_proof_gate = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                c.snapshot().await.unwrap();
                if let Some(gate) = c.arm_late_peer_proof_for_test() {
                    break gate;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("actual C original before B approval");
        let request_hold = temporary_recipient_proof_gate.hold_recipient_request_for_test();
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
        .expect("actual B approval");
        let revision = approval.snapshot().await.unwrap().revision;
        approval.review_metadata(revision).await.unwrap();
        approval.approve_and_share_chats(revision).await.unwrap();
        let original = approval
            .sharing_original_for_test()
            .expect("actual B original");
        let owner = Arc::downgrade(&original);
        let request = tokio::time::timeout(Duration::from_secs(15), request_hold.observed())
            .await
            .unwrap();
        let source = managers[1]
            .peer_proof_snapshot_for_test("test", owner.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(request.owner.ptr_eq(&owner) && request.nonce == source.nonce);
        let held_source = priority::arm_source(owner, request.nonce, source.deadline);
        let recipient = c
            .arm_recipient_retry_priority_for_test(request.nonce)
            .expect("actual C choice");
        release_witnesses.push(held_source.release_witness());
        release_witnesses.push(recipient.release_witness());
        drop(request_hold);
        drop(temporary_recipient_proof_gate);
        tokio::time::timeout(Duration::from_secs(15), held_source.observed())
            .await
            .expect("real B proof prepared before SDK dispatch");
        facts[0] = held_source.captured();
        // First require actual C Consent and proof ACK harvest. No timer write.
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(row) = recipient.snapshot()
                    && !row.invalid
                    && row.live == [true, true]
                    && row.flags == [true, true, true, true, false, false]
                    && row.harvested[0] >= 1
                    && row.harvested[1] >= 1
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("real recipient initial Consent and proof ACKs");
        // Hold the next genuine recipient Consent using the EXISTING transport
        // seam, then gate periodic offers BEFORE releasing its actual ACK.
        // This avoids racing a timer offer after the desired ACK was harvested.
        let (consent_observed, consent_release) =
            apps[2]
                .relay_plane
                .hold_next_sibling_consent(cgka_traits::MemberId::new(
                    keys.public_key().to_bytes().to_vec(),
                ));
        struct ConsentRelease(std::sync::Arc<tokio::sync::Notify>);
        impl Drop for ConsentRelease {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }
        let consent_release = ConsentRelease(consent_release);
        let held_consent = tokio::time::timeout(Duration::from_secs(15), consent_observed)
            .await
            .expect("actual recipient Consent retry reaches existing hold")
            .unwrap();
        assert!(recipient.held_consent_matches(&held_consent.id));
        let periodic = runtimes[2].hold_periodic_linking_for_test("test");
        tokio::time::timeout(Duration::from_secs(5), periodic.observed())
            .await
            .expect("recipient periodic offer actually gated");
        drop(consent_release);
        // Actual ACK/completion harvest remains available while ticks are gated.
        let frozen = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(row) = recipient.snapshot()
                    && !row.invalid
                    && row.live == [true, true]
                    && row.flags == [true, true, true, true, false, false]
                    && row.harvested[0] >= 2
                    && row.harvested[1] >= 1
                    && let [Some(handshake), Some(proof)] = row.retry_at
                    && proof < handshake
                {
                    break row;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("real ACK creates a stable recipient frontier under gated ticks");
        assert!(
            !frozen.invalid
                && frozen.live == [true, true]
                && frozen.flags == [true, true, true, true, false, false]
        );
        assert!(frozen.harvested[0] >= 2 && frozen.harvested[1] >= 1);
        let [Some(handshake), Some(proof)] = frozen.retry_at else {
            panic!("actual retry timers required");
        };
        assert!(proof < handshake);
        facts[1] = true;
        // Sleep only until both EXISTING real retry instants are due. This does
        // not mutate the clock or any production retry/deadline field.
        tokio::time::timeout(Duration::from_secs(5), async {
            while Instant::now() < handshake || Instant::now() < proof {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("existing one-second retry timers become due");
        let ready = recipient.snapshot().unwrap();
        assert!(
            ready.version == frozen.version
                && !ready.invalid
                && ready.live == [true, true]
                && ready.flags == frozen.flags
                && ready.retry_at == frozen.retry_at
        );
        let now = Instant::now();
        assert!(
            now < source.deadline && ready.deadlines.into_iter().all(|deadline| now < deadline)
        );
        facts[2] = true;
        recipient.arm_next();
        drop(periodic);
        let next = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(next) = recipient.next()
                    && next.acknowledged
                {
                    break next;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the actual next recipient publication must receive a real SDK ACK");
        facts[3] = true;
        selected_proof = next.kind == priority::WireKind::Proof;
        // Release the genuinely prepared source proof before every positive
        // completion/cancellation/closure assertion, even for a wrong next kind.
        held_source.release();
        tokio::time::timeout(Duration::from_secs(15), async {
            while !held_source.dispatched_and_acknowledged_after_release() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("exact held source proof dispatched and met actual SDK ACKs after release");
        facts[4] = held_source.dispatched_and_acknowledged_after_release();
        tokio::time::timeout(Duration::from_secs(15), async {
            while !recipient.peer_authenticated() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("C authenticated B's proof on the exact original nonce");
        facts[5] = recipient.peer_authenticated();
        drop(held_source);
        wait_for_automatic_phase(&a, &c, DeviceLinkingPhase::EnrollmentComplete).await;
        facts[6] = true;
        a.cancel().await.unwrap();
        c.cancel().await.unwrap();
        approval.cancel().await.unwrap();
        facts[7] = !original.status_for_test().0;
        let cancelled = recipient
            .snapshot()
            .expect("retained negative original snapshot");
        facts[8] = cancelled.live == [false, false];
        drop(original);
        drop(approval);
        drop(recipient);
    })
    .catch_unwind()
    .await;
    let mut runtime_closes = 0;
    let mut storage_closes = 0;
    for runtime in runtimes {
        if runtime.shutdown_and_close().await.is_ok() {
            runtime_closes += 1;
        }
        if runtime.storage_is_closed() {
            storage_closes += 1;
        }
    }
    facts[9] = release_witnesses.len() == 2
        && release_witnesses
            .iter()
            .all(priority::ReleaseWitness::released);
    let mut planes_shutdown = 0;
    for app in &apps {
        app.relay_plane.shutdown().await;
        planes_shutdown += 1;
    }
    relay.shutdown();
    let address = url.strip_prefix("ws://").unwrap().trim_end_matches('/');
    let relay_closed =
        super::request_retry_completion_acceptance::owned_loopback_listener_is_closed(
            address, &relay,
        )
        .await;
    eprintln!(
        "recipient-retry-priority source_proof_held={} real_frontier={} both_due_unchanged={} next_real_ack={} source_dispatch_ack_after_release={} exact_peer_proof_authenticated={} enrollment_complete={} source_cancelled={} recipient_cancelled={} probe_custody_released={} selected_proof={} runtime_closes={} storage_closes={} planes_shutdown={} relay_closed={} attempt_completed={}",
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
        selected_proof,
        runtime_closes,
        storage_closes,
        planes_shutdown,
        relay_closed,
        attempt.is_ok()
    );
    assert!(
        facts.into_iter().all(|value| value)
            && runtime_closes == 3
            && storage_closes == 3
            && planes_shutdown == 3
            && relay_closed
            && attempt.is_ok(),
        "real recipient retry prerequisites and cleanup must complete"
    );
    assert!(
        selected_proof,
        "older real recipient proof retry must precede a later Consent retry"
    );
}
