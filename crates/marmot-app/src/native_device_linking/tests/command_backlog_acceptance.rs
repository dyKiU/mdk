//! Real authenticated Body0 versus eight bounded actor read commands; independent scheduling regression.
use super::*;
use futures::FutureExt;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScenarioMode {
    QueuedBody,
    HeldBody,
}
struct ScenarioOutcome {
    facts: [bool; 13],
    completed_before: Option<usize>,
    runtime_closes: usize,
    planes_shutdown: usize,
    relay_closed: bool,
    attempt_completed: bool,
    queue: QueueFacts,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_body_is_serviced_before_eight_queued_history_reads() {
    let ScenarioOutcome {
        facts,
        completed_before,
        runtime_closes,
        planes_shutdown,
        relay_closed,
        attempt_completed,
        queue,
    } = Box::pin(run_command_scenario(ScenarioMode::QueuedBody)).await;
    eprintln!(
        "command-backlog facts={:?} completed_before={:?} runtime_closes={} plane_shutdown_returns={} relay_closed={} attempt_completed={}",
        facts, completed_before, runtime_closes, planes_shutdown, relay_closed, attempt_completed
    );
    emit_queue(queue);
    assert!(
        facts.into_iter().all(|value| value)
            && runtime_closes == 3
            && planes_shutdown == 3
            && relay_closed
            && attempt_completed,
        "authenticated_body_must_precede_second_queued_history_read"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eight_history_reads_complete_while_actual_peer_proof_is_held() {
    let ScenarioOutcome {
        facts,
        completed_before,
        runtime_closes,
        planes_shutdown,
        relay_closed,
        attempt_completed,
        queue,
    } = Box::pin(run_command_scenario(ScenarioMode::HeldBody)).await;
    // These are independently observed real setup/command/auth/cleanup facts;
    // the queued-body order/witness slots5/11 are not used by this counterpart.
    let progress_facts = [
        facts[0], facts[1], facts[2], facts[3], facts[4], facts[6], facts[7], facts[8], facts[9],
        facts[10], facts[12],
    ];
    eprintln!(
        "command-backlog-progress facts={:?} completed_before={:?} runtime_closes={} plane_shutdown_returns={} relay_closed={} attempt_completed={}",
        progress_facts,
        completed_before,
        runtime_closes,
        planes_shutdown,
        relay_closed,
        attempt_completed
    );
    emit_queue(queue);
    assert!(
        progress_facts.into_iter().all(|value| value)
            && completed_before == Some(8)
            && runtime_closes == 3
            && planes_shutdown == 3
            && relay_closed
            && attempt_completed,
        "eight_real_history_reads_must_finish_before_releasing_actual_peer_proof"
    );
}

async fn run_command_scenario(mode: ScenarioMode) -> ScenarioOutcome {
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _serial = SERIAL.lock().await;
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
    let mut facts = [false; 13];
    facts[12] = true;
    let mut completed_before = None;
    let mut queue_observations = QueueFacts::default();
    let mut ingress_schedule = None;
    let account = cgka_traits::MemberId::new(keys.public_key().to_bytes().to_vec());
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
        let backlog = proof_gate
            .arm_command_backlog_for_test(owner.clone(), nonce)
            .expect("exact real recipient proof gate and source original");
        // Dormant: the actual fully-ready B preselect hook activates this
        // single-router arrival schedule. Nothing is withheld before that.
        ingress_schedule = apps[1]
            .relay_plane
            .prepare_account_ingress_schedule_for_test(account.clone());
        assert!(ingress_schedule.is_some(), "one_owned_ingress_schedule");
        drop(consent_release);
        let proof_nonce = tokio::time::timeout(Duration::from_secs(15), proof_gate.observed())
            .await
            .unwrap()
            .unwrap();
        facts[2] = proof_nonce == nonce;
        let paused = tokio::time::timeout(Duration::from_secs(15), backlog.paused())
            .await
            .unwrap()
            .unwrap();
        facts[3] = paused.into_iter().all(|value| value) && backlog.ingress_armed();
        let message = backlog
            .message()
            .expect("first actual peer Body0 transport ID");
        facts[4] = message.as_slice().len() == 32;
        let id = hex::encode(message.as_slice());
        queue_observations.pause_rx_len = backlog.pause_rx_len();
        let own_message = backlog.own_message();
        queue_observations.own_id_bound = Some(own_message.is_some());
        queue_observations.own = own_message.as_ref().and_then(|message| {
            queue_observation(&apps[1], &account, &hex::encode(message.as_slice()))
        });
        if mode == ScenarioMode::QueuedBody {
            // The exact target actor is parked BEFORE select. No receive, SQL/Core
            // query, or actor RPC is used to establish the queue witness.
            drop(proof_gate);
            let queue = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    let row = queue_observation(&apps[1], &account, &id);
                    queue_observations.target = row;
                    if let Some(row) = row
                        && row.1[0] > 0
                        && (row.2.is_some() || row.5)
                    {
                        break row;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .unwrap();
            facts[5] = (queue.2, queue.3, queue.4, queue.5) == (Some((0, 1)), 0, false, false);
            let replies = managers[1]
                .enqueue_command_backlog_reads_for_test("test")
                .await
                .unwrap();
            facts[6] = backlog.install_replies(replies);
            backlog.release();
            let accepted = tokio::time::timeout(Duration::from_secs(15), backlog.accepted())
                .await
                .unwrap()
                .unwrap();
            completed_before = Some(accepted.0);
            facts[7] = accepted.1 && accepted.0 <= 8;
            facts[11] = accepted.0 <= 1;
            facts[8] = tokio::time::timeout(Duration::from_secs(15), backlog.drain_replies())
                .await
                .unwrap();
        } else {
            // C's genuine proof future remains held while all eight real read
            // commands complete. No command waits for the missing target Body0.
            let replies = managers[1]
                .enqueue_command_backlog_reads_for_test("test")
                .await
                .unwrap();
            facts[6] = backlog.install_replies(replies);
            backlog.release();
            facts[8] = tokio::time::timeout(Duration::from_secs(15), backlog.drain_replies())
                .await
                .unwrap();
            drop(proof_gate);
            let accepted = tokio::time::timeout(Duration::from_secs(15), backlog.accepted())
                .await
                .unwrap()
                .unwrap();
            completed_before = Some(accepted.0);
            facts[7] = accepted == (8, true);
            queue_observations.target = queue_observation(&apps[1], &account, &id);
        }
        // Replay all genuine competitors, in held FIFO order through the same
        // production router, before normal enrollment can finish.
        let schedule = ingress_schedule.as_ref().expect("owned ingress schedule");
        schedule.release_and_flush().await;
        let snapshot = schedule.snapshot();
        facts[12] &= snapshot.armed
            && snapshot.valid
            && snapshot.released
            && snapshot.flushed
            && snapshot.target_passes == 1
            && snapshot.held == snapshot.replayed;
        wait_for_automatic_phase(&a, &c, DeviceLinkingPhase::EnrollmentComplete).await;
        facts[9] = true;
        a.cancel().await.unwrap();
        c.cancel().await.unwrap();
        approval.cancel().await.unwrap();
        facts[10] = true;
        facts[12] &= backlog.known();
        drop(backlog);
        drop(approval);
        drop(original);
    })
    .catch_unwind()
    .await;
    // This runs even after a setup/body panic. Drop merely requests release;
    // only the positive router acknowledgement proves held delivery replay.
    if let Some(schedule) = ingress_schedule {
        schedule.release_and_flush().await;
        let snapshot = schedule.snapshot();
        facts[12] &= snapshot.armed
            && snapshot.valid
            && snapshot.released
            && snapshot.flushed
            && snapshot.target_passes == 1
            && snapshot.held == snapshot.replayed;
        queue_observations.ingress = Some(snapshot);
    } else {
        facts[12] = false;
    }
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
    ScenarioOutcome {
        facts,
        completed_before,
        runtime_closes,
        planes_shutdown,
        relay_closed,
        attempt_completed: attempt.is_ok(),
        queue: queue_observations,
    }
}

type QueueObservation = ([u64; 8], [u64; 6], Option<(usize, usize)>, u64, bool, bool);
#[derive(Default)]
struct QueueFacts {
    pause_rx_len: Option<usize>,
    target: Option<QueueObservation>,
    own_id_bound: Option<bool>,
    own: Option<QueueObservation>,
    ingress: Option<transport_nostr::AccountIngressScheduleSnapshot>,
}
fn queue_observation(
    app: &MarmotApp,
    account: &cgka_traits::MemberId,
    id: &str,
) -> Option<QueueObservation> {
    app.relay_plane
        .account_notification_timing_for_test(account, id)
        .map(|row| (row.0, row.2, row.4.0, row.4.1, row.4.2.is_some(), row.4.3))
}
fn emit_queue(queue: QueueFacts) {
    eprintln!(
        "command-backlog-ingress schedule={:?}",
        queue.ingress.map(|value| (
            [value.armed, value.valid, value.released, value.flushed],
            value.target_passes,
            value.held,
            value.replayed,
            value.overflow,
        ))
    );
    eprintln!(
        "command-backlog-queue pause_rx_len={:?} target={:?} own_id_bound={:?} own={:?}",
        queue.pause_rx_len, queue.target, queue.own_id_bound, queue.own
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
