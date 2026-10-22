//! Actual public cancellation and explicitly injected post-auth validation rejection.
use super::*;
use crate::client::device_linking::sibling_sharing::peer_proof_probe::negative;
use futures::FutureExt;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    PublicCancel,
    PublicCancelWithOrdinary,
    InjectedValidation,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_peer_proof_public_cancel_cannot_complete_original() {
    run(Scenario::PublicCancel).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_peer_proof_injected_validation_rejection_retains_and_recovers() {
    run(Scenario::InjectedValidation).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_peer_proof_public_cancel_does_not_block_independent_ordinary_delivery() {
    run(Scenario::PublicCancelWithOrdinary).await;
}

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
    let ordinary_case = scenario == Scenario::PublicCancelWithOrdinary;
    let public_cancel = matches!(
        scenario,
        Scenario::PublicCancel | Scenario::PublicCancelWithOrdinary
    );
    let mut ordinary_peer = None;
    let mut ordinary_facts = [false; 14];
    let mut ordinary_counts = [0usize; 6];
    let mut ordinary_diagnostic = None;
    let mut native_route = [false; 9];
    let mut native_counts = [0u64; 3];
    let mut route_before_verdict = false;
    let mut observations = [0usize; 6];
    // Last completed existing PublicCancel poll; false row facts are unknown if absent.
    let mut public_cancel_sample = [false; 5];
    let attempt = std::panic::AssertUnwindSafe(async {
        if ordinary_case {
            // The existing incoming-chat fixture requires one active installation:
            // account-level Welcomes may otherwise be selected by a sibling.
            runtimes[1].reconcile_accounts().await.unwrap();
            let account = apps[1].account_home().account("test").unwrap().account_id_hex;
            ordinary_peer = Some(crate::native_device_linking::tests::automatic_forwarding_non_admin_acceptance::IncomingPeer::create(
                &url, &apps[1], &runtimes[1], &account,
            ).await);
            // create() proves the real independent Welcome, acceptance, two-member
            // roster and one ordinary message before the original linking flow.
            ordinary_facts[0] = true;
            for runtime in [&runtimes[0], &runtimes[2]] {
                runtime.reconcile_accounts().await.unwrap();
            }
        } else {
            for runtime in &runtimes {
                runtime.reconcile_accounts().await.unwrap();
            }
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
        facts[3] = before.nonce == nonce
            && before.pending_controls == 0
            && before.flags == [true, true, true, true, false, false, false, true];
        let deadline = before.deadline;
        let digest = proof_gate
            .prepared_digest(nonce)
            .expect("actual held Core-sealed proof digest");
        let probe = negative::arm(
            &original,
            nonce,
            digest,
            scenario == Scenario::InjectedValidation,
        );
        if public_cancel {
            approval.cancel().await.unwrap();
            let status = original.status_for_test();
            facts[4] = !status.0 && !status.1;
            proof_gate.release();
            // Positive evidence that the exact sealed C proof reached the cancelled
            // B actor and its live gate denied it, while periodic removal is held.
            let after = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    let row = managers[1]
                        .peer_proof_snapshot_for_test("test", owner.clone())
                        .await
                        .unwrap();
                    let counts = probe.counts();
                    observations = counts;
                    public_cancel_sample = [
                        true,
                        row.is_some(),
                        row.as_ref().is_some_and(|value| !value.flags[0]),
                        row.as_ref().is_some_and(|value| value.nonce == nonce),
                        row.as_ref().is_some_and(|value| value.deadline == deadline),
                    ];
                    // Only the distinct ordinary-progress setup observes first-denial-ever.
                    // The original PublicCancel predicate and final exact 1/1 remain unchanged.
                    if (ordinary_case && counts[4] >= 1 && counts[5] >= 1)
                        || (!ordinary_case && counts[4] == 1 && counts[5] == 1) {
                        break row.expect("matched closed original remains while periodic is held");
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .unwrap();
            facts[5] = !after.flags[0] && !after.flags[6];
            facts[7] =
                after.nonce == nonce && after.deadline == deadline && after.pending_controls == 0;
            if ordinary_case {
                use crate::native_device_linking::tests::automatic_forwarding_non_admin_acceptance::ORDINARY_PROGRESS_TEXT;
                let first_denied_at = std::time::Instant::now();
                ordinary_facts[1] = observations[4] >= 1 && observations[5] >= 1;
                ordinary_facts[2] = facts[4] && facts[5] && facts[7]
                    && !after.flags[1] && observations[..4].iter().all(|count| *count == 0);
                let published = ordinary_peer.as_ref().unwrap()
                    .publish_ordinary_progress(after.native_identity.as_ref()).await;
                native_route[0] = before.native_identity.as_ref().zip(after.native_identity.as_ref())
                    .is_some_and(|(before, after)| before.matches(after));
                native_route[1] = published.native_watch.as_ref().zip(after.native_identity.as_ref())
                    .is_some_and(|(watch, identity)| watch.matches(identity));
                ordinary_facts[3] = published.published_once;
                ordinary_facts[4] = published.source_row_bound;
                ordinary_facts[5] = published.group != after.protected_group;
                let group_hex = hex::encode(published.group.as_slice());
                // A missing source binding is unknown, never an artificial timed wait.
                let projected = if let (true, Some(app_id), Some(canonical_id)) =
                    (published.source_row_bound && published.published_once,
                     published.app_id.as_ref(), published.canonical_id.as_ref()) {
                    ordinary_facts[6] = true;
                    Some(tokio::time::timeout(Duration::from_secs(30), async {
                        loop {
                            let storage = apps[1].account_storage("test").unwrap();
                            let row = storage.app_storage().app_message(&group_hex, app_id).unwrap();
                            let timeline = storage.app_storage().timeline_message(&group_hex, app_id).unwrap();
                            if let Some(watch) = published.native_watch.as_ref() { watch.sample_custody(); }
                            let now = std::time::Instant::now();
                            let native_complete = published.native_watch.as_ref().is_some_and(|watch| {
                                let (_, observed) = watch.facts(first_denied_at, now);
                                native_route[0] && native_route[1] && observed.into_iter().all(|value| value)
                            });
                            let live_complete = published.packet_id.as_ref().is_some_and(|packet| {
                                let account = cgka_traits::MemberId::new(hex::decode(
                                    apps[1].account_home().account("test").unwrap().account_id_hex,
                                ).unwrap());
                                let timing = apps[1].relay_plane.account_notification_timing_for_test(&account, packet);
                                timing.as_ref().is_some_and(|row| !row.4.3
                                    && row.4.0.is_some() && row.4.1 > 0
                                    && row.3[0].zip(row.4.2).is_some_and(|(accepted, dequeued)|
                                        first_denied_at <= accepted && accepted <= dequeued && dequeued <= now))
                                    && apps[1].relay_plane.account_notification_same_receiver_for_test(
                                        &account, packet, &after.receiver_identity,
                                    ) == Some(true)
                            });
                            let exact_projection = row.as_ref().is_some_and(|row| row.message_id_hex == *app_id
                                && row.group_id_hex == group_hex && row.sender == published.sender
                                && row.plaintext == ORDINARY_PROGRESS_TEXT
                                && row.direction == "received" && !row.invalidated)
                                && timeline.as_ref().is_some_and(|row| row.message_id_hex == *app_id
                                    && row.source_message_id_hex.as_ref() == Some(canonical_id)
                                    && row.group_id_hex == group_hex && row.sender == published.sender
                                    && row.plaintext == ORDINARY_PROGRESS_TEXT
                                    && row.direction == "received" && !row.deleted);
                            ordinary_facts[7] = exact_projection;
                            if exact_projection && (native_complete || live_complete) {
                                route_before_verdict = true;
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }).await.is_ok())
                } else { None };
                // Freeze the actual ordinary receive verdict before releasing either hold.
                let frozen_at = std::time::Instant::now();
                // Preserve the actual last projection observation even if route
                // provenance stayed unavailable and the unchanged wait expired.
                let _ = projected;
                if let Some(watch) = published.native_watch.as_ref() {
                    let (counts, observed) = watch.facts(first_denied_at, frozen_at);
                    native_counts = counts;
                    native_route[2..6].copy_from_slice(&observed[..4]);
                    native_route[8] = observed[4];
                }
                native_route[6] = route_before_verdict;
                if let Some(packet_id) = published.packet_id.as_ref().filter(|_| published.source_row_bound) {
                    let account = cgka_traits::MemberId::new(hex::decode(
                        apps[1].account_home().account("test").unwrap().account_id_hex,
                    ).unwrap());
                    let timing = apps[1].relay_plane.account_notification_timing_for_test(&account, packet_id);
                    let same = apps[1].relay_plane.account_notification_same_receiver_for_test(
                        &account, packet_id, &after.receiver_identity,
                    );
                    ordinary_facts[8] = timing.is_some() && same.is_some();
                    ordinary_facts[9] = timing.as_ref().is_some_and(|row|
                        row.3[0].is_some() && row.4.0.is_some());
                    ordinary_facts[10] = same == Some(true);
                    ordinary_facts[11] = timing.as_ref().is_some_and(|row|
                        !row.4.3 && row.4.1 > 0
                            && row.3[0].zip(row.4.2).is_some_and(|(accepted, dequeued)|
                                first_denied_at <= accepted && accepted <= dequeued && dequeued <= frozen_at));
                    // The original verdict and its absolute wait have already ended.
                    // These extra reads do not repair, drain, retry, or change that verdict.
                    let (raw_read, timeline_read) = match apps[1].account_storage("test") {
                        Ok(storage) => (
                            published.app_id.as_ref().and_then(|app_id| storage.app_storage().app_message(&group_hex, app_id).ok()),
                            published.app_id.as_ref().and_then(|app_id| storage.app_storage().timeline_message(&group_hex, app_id).ok()),
                        ),
                        Err(_) => (None, None),
                    };
                    let raw = raw_read.as_ref().and_then(|value| value.as_ref());
                    let timeline = timeline_read.as_ref().and_then(|value| value.as_ref());
                    let raw_matches = raw.zip(published.app_id.as_ref()).map(|(row, app_id)| [
                        row.message_id_hex == *app_id,
                        row.group_id_hex == group_hex,
                        row.sender == published.sender,
                        row.plaintext == ORDINARY_PROGRESS_TEXT,
                        row.direction == "received",
                        !row.invalidated,
                    ]).unwrap_or([false; 6]);
                    let timeline_matches = timeline.zip(published.app_id.as_ref()).map(|(row, app_id)| [
                        row.message_id_hex == *app_id,
                        row.source_message_id_hex.as_ref() == published.canonical_id.as_ref(),
                        row.group_id_hex == group_hex,
                        row.sender == published.sender,
                        row.plaintext == ORDINARY_PROGRESS_TEXT,
                        row.direction == "received",
                        !row.deleted,
                    ]).unwrap_or([false; 7]);
                    let depths = timing.as_ref().and_then(|row| row.4.0);
                    let dequeue_time = timing.as_ref().and_then(|row| row.4.2);
                    let accepted_time = timing.as_ref().and_then(|row| row.3[0]);
                    ordinary_diagnostic = Some(serde_json::json!({
                        "collected": true,
                        "raw_read": raw_read.is_some(), "timeline_read": timeline_read.is_some(),
                        "raw_present": raw.is_some(), "timeline_present": timeline.is_some(),
                        "raw_matches": raw_matches, "timeline_matches": timeline_matches,
                        "timing_present": timing.is_some(),
                        "accepted_after_first_denial_before_verdict": accepted_time.is_some_and(|accepted|
                            first_denied_at <= accepted && accepted <= frozen_at),
                        "dispositions": timing.as_ref().map(|row| row.0).unwrap_or([0; 8]),
                        "placements": timing.as_ref().map(|row| row.2).unwrap_or([0; 6]),
                        "dequeued": timing.as_ref().map_or(0, |row| row.4.1),
                        "depth_known": depths.is_some(),
                        "depth_before": depths.map_or(0, |value| value.0),
                        "depth_after": depths.map_or(0, |value| value.1),
                        "dequeue_time_known": dequeue_time.is_some(),
                        "dequeue_order_known": accepted_time.is_some() && dequeue_time.is_some(),
                        "dequeue_after_accept": accepted_time.zip(dequeue_time).is_some_and(|(accepted, dequeued)| accepted <= dequeued),
                        "dequeue_before_verdict": dequeue_time.is_some_and(|dequeued| dequeued <= frozen_at),
                        "invalid_custody": timing.as_ref().is_some_and(|row| row.4.3),
                    }));
                }
                // The verdict above is already frozen. This existing read-only
                // actor command checks the recipient again before either hold is
                // released; timeout/missing/error is an unknown prerequisite.
                let final_receiver = tokio::time::timeout(Duration::from_secs(15),
                    managers[1].peer_proof_snapshot_for_test("test", owner.clone()),
                ).await;
                if let (Ok(Ok(Some(final_receiver))), Some(packet_id)) =
                    (final_receiver, published.packet_id.as_ref()) {
                    let account = cgka_traits::MemberId::new(hex::decode(
                        apps[1].account_home().account("test").unwrap().account_id_hex,
                    ).unwrap());
                    native_route[7] = final_receiver.nonce == nonce
                        && final_receiver.deadline == deadline
                        && final_receiver.protected_group == after.protected_group
                        && before.native_identity.as_ref().zip(after.native_identity.as_ref())
                            .is_some_and(|(before, after)| before.matches(after))
                        && final_receiver.native_identity.as_ref().zip(after.native_identity.as_ref())
                            .is_some_and(|(final_identity, after)| final_identity.matches(after))
                        && published.native_watch.as_ref().zip(final_receiver.native_identity.as_ref())
                            .is_some_and(|(watch, identity)| watch.matches(identity));
                    ordinary_facts[13] = final_receiver.nonce == nonce
                        && final_receiver.deadline == deadline
                        && final_receiver.protected_group == after.protected_group
                        && apps[1].relay_plane.account_notification_same_receiver_for_test(
                            &account, packet_id, &final_receiver.receiver_identity,
                        ) == Some(true);
                }
                ordinary_counts = probe.counts();
                let status = original.status_for_test();
                ordinary_facts[12] = ordinary_counts[..4].iter().all(|count| *count == 0)
                    && !status.0 && !status.1;
            }
        } else {
            proof_gate.release();
            let blocked = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if let Some(row) = managers[1]
                        .peer_proof_snapshot_for_test("test", owner.clone())
                        .await
                        .unwrap()
                        && row.nonce == nonce
                        && row.flags[4]
                        && probe.counts()[1] > 0
                    {
                        break row;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .unwrap();
            // Freeze the negative verdict while the real proof is retained and
            // periodic completion is still gated. No input or committed flag is fabricated.
            facts[4] = !blocked.flags[6]
                && blocked.flags[0]
                && blocked.flags[1]
                && blocked.flags[2]
                && blocked.flags[3]
                && blocked.flags[4]
                && blocked.flags[7];
            facts[7] = blocked.deadline == deadline && blocked.pending_controls == 0;
            probe.clear();
        }
        drop(periodic);
        drop(proof_gate);
        if scenario == Scenario::InjectedValidation {
            let recovered = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if let Some(row) = managers[1]
                        .peer_proof_snapshot_for_test("test", owner.clone())
                        .await
                        .unwrap()
                        && row.nonce == nonce
                        && row.flags[6]
                    {
                        break row;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .unwrap();
            facts[5] = recovered.flags[0]
                && recovered.flags[1]
                && recovered.flags[2]
                && recovered.flags[3]
                && recovered.flags[4]
                && recovered.flags[7];
            facts[7] &= recovered.deadline == deadline && recovered.pending_controls == 0;
        }
        wait_for_automatic_phase(&a, &c, DeviceLinkingPhase::EnrollmentComplete).await;
        facts[8] = true;
        // Recheck the exact old actor after actual peer publication and normal enrollment.
        let final_row = managers[1]
            .peer_proof_snapshot_for_test("test", owner.clone())
            .await
            .unwrap();
        let counts = probe.counts();
        observations = counts;
        facts[6] = counts[2] == 0
            && if scenario == Scenario::InjectedValidation {
                counts[0] == 1
                    && counts[1] > 0
                    && counts[3] == 1
                    && counts[4] == 0
                    && counts[5] == 0
                    && final_row
                        .as_ref()
                        .is_some_and(|row| row.pending_controls == 0)
            } else {
                counts[0] == 0
                    && counts[1] == 0
                    && counts[3] == 0
                    && counts[4] == 1
                    && counts[5] == 1
                    && !original.status_for_test().0
                    && !original.status_for_test().1
            };
        a.cancel().await.unwrap();
        c.cancel().await.unwrap();
        if scenario == Scenario::InjectedValidation {
            approval.cancel().await.unwrap();
        }
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
    let (ordinary_closed, ordinary_plane_shutdown) = if let Some(peer) = ordinary_peer.as_ref() {
        peer.close_ordinary_progress_peer().await
    } else {
        (false, false)
    };
    drop(ordinary_peer);
    relay.shutdown();
    let address = url.strip_prefix("ws://").unwrap().trim_end_matches('/');
    let relay_closed = owned_loopback_listener_is_closed(address).await;
    let mode = if public_cancel {
        "public-cancel"
    } else {
        "injected-validation"
    };
    if public_cancel {
        #[cfg(feature = "test-policy-overrides")]
        crate::test_support::emit_line(format_args!(
            "late-peer-public-cancel-sample collected={} row_present={} original_closed={} exact_nonce={} exact_deadline={}",
            public_cancel_sample[0],
            public_cancel_sample[1],
            public_cancel_sample[2],
            public_cancel_sample[3],
            public_cancel_sample[4]
        ));
    }
    eprintln!(
        "late-peer-negative mode={} held={} own_harvested={} periodic_observed={} fresh_before={} negative_preserved={} recovered_or_retired={} no_replay={} ownership_preserved={} enrollment_complete={} public_cancelled={} accepted={} validation_rejections={} own_publications={} open_attempts={} routed_after_cancel={} closed_denials={} runtime_closes={} planes_shutdown={} relay_closed={} attempt_completed={}",
        mode,
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
        observations[0],
        observations[1],
        observations[2],
        observations[3],
        observations[4],
        observations[5],
        runtime_closes,
        planes_shutdown,
        relay_closed,
        attempt.is_ok()
    );
    if ordinary_case {
        if let Some(diagnostic) = &ordinary_diagnostic {
            crate::test_support::emit_line(format_args!(
                "late-peer-ordinary-frozen {}",
                diagnostic
            ));
        }
        crate::test_support::emit_line(format_args!(
            "late-peer-ordinary-progress independent_ready={} first_denial_seen={} original_closed_exact={} published_once={} source_packet_app_bound={} unrelated_group={} wait_sampled={} ordinary_projected={} custody_sampled={} queue_accepted={} same_receiver={} ordered_valid_custody={} negative_preserved={} final_receiver_matches={} no_replay={} accepted={} validation_rejections={} own_publications={} open_attempts={} routed_after_cancel={} closed_denials={} original_facts_complete={} runtime_closes={} planes_shutdown={} independent_closed={} independent_plane_shutdown={} relay_closed={} attempt_completed={}",
            ordinary_facts[0],
            ordinary_facts[1],
            ordinary_facts[2],
            ordinary_facts[3],
            ordinary_facts[4],
            ordinary_facts[5],
            ordinary_facts[6],
            ordinary_facts[7],
            ordinary_facts[8],
            ordinary_facts[9],
            ordinary_facts[10],
            ordinary_facts[11],
            ordinary_facts[12],
            ordinary_facts[13],
            facts[6],
            ordinary_counts[0],
            ordinary_counts[1],
            ordinary_counts[2],
            ordinary_counts[3],
            ordinary_counts[4],
            ordinary_counts[5],
            facts.iter().all(|value| *value),
            runtime_closes,
            planes_shutdown,
            ordinary_closed,
            ordinary_plane_shutdown,
            relay_closed,
            attempt.is_ok()
        ));
        crate::test_support::emit_line(format_args!(
            "late-peer-native-route before_current={} armed_current={} consumer_current={} bounded={} complete={} ordered_before_verdict={} route_before_verdict={} final_consumer_matches={} frame_custody_before_verdict={} borrowed={} ingested={} acknowledged={}",
            native_route[0], native_route[1], native_route[2], native_route[3],
            native_route[4], native_route[5], native_route[6], native_route[7], native_route[8],
            native_counts[0], native_counts[1], native_counts[2],
        ));
        let custody_complete = (ordinary_facts[8..12].iter().all(|value| *value)
                && ordinary_facts[13] && route_before_verdict)
            || native_route.into_iter().all(|value| value);
        assert!(
            ordinary_facts[..8].iter().all(|value| *value)
                && ordinary_facts[12] && custody_complete
                && facts.into_iter().all(|value| value)
                && runtime_closes == 3
                && planes_shutdown == 3
                && ordinary_closed
                && ordinary_plane_shutdown
                && relay_closed
                && attempt.is_ok(),
            "cancelled sibling proof must not block independent ordinary receive"
        );
        return;
    }
    assert!(
        facts.into_iter().all(|value| value)
            && runtime_closes == 3
            && planes_shutdown == 3
            && relay_closed
            && attempt.is_ok(),
        "late_peer_proof_negative_guard_and_positive_cleanup"
    );
}

// Only the owned MockRelay's loopback listener is probed, never an external endpoint.
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
