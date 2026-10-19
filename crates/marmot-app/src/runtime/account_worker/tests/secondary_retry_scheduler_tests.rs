//! Real managed-worker scheduling under overdue confirmed relay replication.
use super::*;

#[derive(Clone, Debug)]
enum Observation {
    Turn {
        pending: usize,
        buffered: usize,
        yielded: bool,
        due: bool,
        owed: bool,
        retry_ready: bool,
    },
    Command(bool),
    Drain(TokioInstant),
    Pass,
}

struct Probe {
    observations: Mutex<Vec<Observation>>,
    tail_barrier: Mutex<Option<Arc<tokio::sync::Barrier>>>,
    tail_delay: Duration,
}

static PROBES: std::sync::LazyLock<Mutex<HashMap<String, Arc<Probe>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn probe(account: &str) -> Option<Arc<Probe>> {
    PROBES.lock().unwrap().get(account).cloned()
}

pub(in crate::runtime::account_worker) fn record_turn(
    account: &str,
    pending: usize,
    buffered: usize,
    yielded: bool,
    due: bool,
    owed: bool,
    retry_ready: bool,
) {
    if let Some(probe) = probe(account) {
        probe.observations.lock().unwrap().push(Observation::Turn {
            pending,
            buffered,
            yielded,
            due,
            owed,
            retry_ready,
        });
    }
}

pub(in crate::runtime::account_worker) fn record_command(
    account: &str,
    command: &AccountWorkerCommand,
) {
    if let AccountWorkerCommand::SetGroupArchived { archived, .. } = command
        && let Some(probe) = probe(account)
    {
        probe
            .observations
            .lock()
            .unwrap()
            .push(Observation::Command(*archived));
    }
}

pub(in crate::runtime::account_worker) fn record_drain(account: &str) {
    #[cfg(feature = "test-policy-overrides")]
    cutoff_observe(account, CutoffEvent::Drain);
    if let Some(probe) = probe(account) {
        probe
            .observations
            .lock()
            .unwrap()
            .push(Observation::Drain(TokioInstant::now()));
    }
}

pub(in crate::runtime::account_worker) async fn pass_tail(account: &str) {
    if let Some(probe) = probe(account) {
        probe.observations.lock().unwrap().push(Observation::Pass);
        let barrier = probe.tail_barrier.lock().unwrap().take();
        if let Some(barrier) = barrier {
            barrier.wait().await;
            barrier.wait().await;
        }
        // Model ordinary local tail work exceeding the existing 10ms floor;
        // no production interval or frozen retry timestamp is changed.
        sleep(probe.tail_delay).await;
    }
}

struct ProbeGuard(String);
impl Drop for ProbeGuard {
    fn drop(&mut self) {
        PROBES.lock().unwrap().remove(&self.0);
        HELD_SCHEDULED_CONVERGENCE_ACCOUNTS
            .lock()
            .unwrap()
            .remove(&self.0);
    }
}

/// Both queued commands and confirmed secondary retries precede this durable
/// send. Overdue local passes must eventually give the durable owner a turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overdue_secondary_groups_service_durable_send_after_deferred_predecessors() {
    overdue_secondary_groups_service_durable_send(2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overdue_secondary_groups_service_durable_send_after_buffered_predecessors() {
    overdue_secondary_groups_service_durable_send(0).await;
}

async fn overdue_secondary_groups_service_durable_send(deferred_count: usize) {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://progress.example")
        .with_test_relay_client(relay.clone());
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let mut groups = Vec::new();
    for name in ["first due group", "second due group"] {
        groups.push(
            client
                .create_group_with_options(
                    name,
                    &[],
                    AppCreateGroupOptions {
                        relays: Some(vec![
                            "wss://index.example".into(),
                            "wss://progress.example".into(),
                        ]),
                        ..Default::default()
                    },
                )
                .await
                .unwrap(),
        );
    }
    relay
        .block_indexer_publish
        .store(true, std::sync::atomic::Ordering::SeqCst);
    for group in &groups {
        client
            .send(group, b"confirmed secondary fixture")
            .await
            .unwrap();
        let retained = client
            .runtime
            .session()
            .outbound_fanouts_for_group(group)
            .unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].outcome().accepted_targets, 1);
        assert_eq!(retained[0].outcome().outstanding_targets, 1);
    }
    let last_seed = TokioInstant::now();
    drop(client);
    HELD_SCHEDULED_CONVERGENCE_ACCOUNTS
        .lock()
        .unwrap()
        .insert(account.account_id_hex.clone());
    let probe_guard = ProbeGuard(account.account_id_hex.clone());
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    let commands = runtime.accounts().worker_commands("alice").await.unwrap();
    let mut window = runtime
        .open_conversation_window("alice", &groups[0], Default::default())
        .await
        .unwrap();
    while window.snapshot.presentation.header.epoch.is_none() {
        window.snapshot = timeout(Duration::from_secs(5), window.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    // Both real persisted 30s fanout cutoffs must expire before the held pass.
    tokio::time::sleep_until(last_seed + Duration::from_secs(31)).await;
    let first_pass = Arc::new(tokio::sync::Barrier::new(2));
    runtime
        .shared_services()
        .set_next_scheduled_convergence_barrier(first_pass.clone());
    let tail = Arc::new(tokio::sync::Barrier::new(2));
    let probe = Arc::new(Probe {
        observations: Mutex::new(Vec::new()),
        tail_barrier: Mutex::new(Some(tail.clone())),
        tail_delay: Duration::from_millis(25),
    });
    PROBES
        .lock()
        .unwrap()
        .insert(account.account_id_hex.clone(), probe.clone());
    HELD_SCHEDULED_CONVERGENCE_ACCOUNTS
        .lock()
        .unwrap()
        .remove(&account.account_id_hex);
    let (respond, _response) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: groups[0].clone(),
            respond,
        })
        .unwrap();
    timeout(Duration::from_secs(5), first_pass.wait())
        .await
        .unwrap();
    let mut predecessors = Vec::new();
    for archived in [true, false].into_iter().take(deferred_count) {
        let (respond, response) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::SetGroupArchived {
                group_id: groups[0].clone(),
                archived,
                respond,
            })
            .unwrap();
        predecessors.push(response);
    }
    // This snapshot read fences the two mutation commands into the deferred FIFO.
    let (respond, response) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::Members {
            group_id: groups[0].clone(),
            respond,
        })
        .unwrap();
    timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let accepted = runtime
        .submit_text(
            "alice",
            &groups[0],
            "durable after command predecessors".into(),
            "overdue-durable".into(),
        )
        .await
        .unwrap();
    let admission_gate = runtime
        .shared_services()
        .local_submission_gate(&account.account_id_hex);
    let held_admission = admission_gate.lock().await;
    first_pass.wait().await;
    timeout(Duration::from_secs(5), tail.wait()).await.unwrap();
    // These are still buffered in the channel when the finished pass returns.
    for archived in [true, false, true, false]
        .into_iter()
        .take(4 - deferred_count)
    {
        let (respond, response) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::SetGroupArchived {
                group_id: groups[0].clone(),
                archived,
                respond,
            })
            .unwrap();
        predecessors.push(response);
    }
    tail.wait().await;
    // Repeated optional passes must preserve the ordinary 100ms gate-contention backoff.
    sleep(Duration::from_millis(700)).await;
    // A loaded machine may fit fewer drains into that sleep than the
    // assertions below need; hold admission until two have run.
    let retry_result = timeout(Duration::from_secs(5), async {
        while probe
            .observations
            .lock()
            .unwrap()
            .iter()
            .filter(|event| matches!(event, Observation::Drain(_)))
            .count()
            < 2
        {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if retry_result.is_err() {
        // Read existing observations only after the original timeout verdict.
        // No account keys, command data, raw trace or timestamps leave the fixture.
        let observations = probe.observations.lock().unwrap();
        let last_turn = observations.iter().rev().find_map(|event| match event {
            Observation::Turn {
                pending,
                buffered,
                yielded,
                due,
                owed,
                retry_ready,
            } => Some(serde_json::json!({
                "pending": pending, "buffered": buffered, "yielded": yielded,
                "due": due, "owed": owed, "retry_ready": retry_ready,
            })),
            _ => None,
        });
        eprintln!(
            "secondary-retry-control {}",
            serde_json::json!({
                "deferred_count": deferred_count,
                "drain_count": observations.iter().filter(|event| matches!(event, Observation::Drain(_))).count(),
                "predecessor_command_count": observations.iter().filter(|event| matches!(event, Observation::Command(_))).count(),
                "pass_count": observations.iter().filter(|event| matches!(event, Observation::Pass)).count(),
                "turn_count": observations.iter().filter(|event| matches!(event, Observation::Turn { .. })).count(),
                "last_turn": last_turn,
            })
        );
    }
    retry_result.expect("the held admission gate makes the durable drain retry");
    let admission_released = TokioInstant::now();
    drop(held_admission);
    let observed = timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = window.recv().await.unwrap().unwrap();
            if snapshot.page.page().messages.iter().any(|row| {
                row.message_id_hex == accepted.message_id_hex && row.source_message_id_hex.is_some()
            }) {
                break;
            }
        }
    })
    .await;
    let observations = probe.observations.lock().unwrap().clone();
    drop(probe_guard);
    relay
        .block_indexer_publish
        .store(false, std::sync::atomic::Ordering::SeqCst);
    relay.indexer_publish_release.notify_waiters();
    runtime.shutdown_and_close().await.unwrap();
    observed.expect("overdue confirmed secondary groups must service the durable send while their ACKs remain held");
    for response in predecessors {
        response.await.unwrap().unwrap();
    }
    let first_drain = observations
        .iter()
        .position(|event| matches!(event, Observation::Drain(_)))
        .unwrap();
    let prior_commands = observations[..first_drain]
        .iter()
        .filter_map(|event| match event {
            Observation::Command(value) => Some(*value),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        prior_commands,
        vec![true, false, true, false],
        "all deferred and buffered predecessors must run before durable execution"
    );
    if deferred_count > 0 {
        assert!(observations.iter().any(|event| matches!(event, Observation::Turn { pending, .. } if *pending >= deferred_count)), "fixture must exercise the deferred FIFO");
    } else {
        assert!(observations.iter().any(|event| matches!(event, Observation::Turn { pending: 0, buffered, yielded: true, .. } if *buffered > 0)), "fixture must exercise a buffered predecessor while the command arm is fairness-gated");
    }
    let blocked_drains = observations
        .iter()
        .filter_map(|event| match event {
            Observation::Drain(at) if *at < admission_released => Some(*at),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        blocked_drains.len() >= 2,
        "fixture must exercise repeated unavailable-row drains"
    );
    assert!(
        blocked_drains
            .windows(2)
            .all(|times| times[1].duration_since(times[0]) >= Duration::from_millis(100)),
        "secondary pressure must not reset the ordinary drain's 100ms retry backoff"
    );
    assert!(
        observations
            .iter()
            .filter(|event| matches!(event, Observation::Pass))
            .count()
            >= 2
    );
}

// These one-shot test-only observers never insert, select, or change commands.
#[cfg(feature = "test-policy-overrides")]
struct CutoffFacts {
    before_archives: usize,
    before_had_fence: bool,
    after_archives: usize,
    no_archive_or_drain: bool,
    due_retry_owed: bool,
}
#[cfg(feature = "test-policy-overrides")]
struct CutoffRendezvous {
    reached: oneshot::Sender<CutoffFacts>,
    release: oneshot::Receiver<()>,
    released: Arc<std::sync::atomic::AtomicBool>,
}
#[cfg(feature = "test-policy-overrides")]
#[derive(Clone, Copy)]
enum CutoffEvent {
    ArchiveCompleted(bool),
    ArchiveFailed,
    Drain,
}
#[cfg(feature = "test-policy-overrides")]
struct CutoffProbe {
    rendezvous: Mutex<Option<CutoffRendezvous>>,
    observations: Mutex<(Vec<CutoffEvent>, bool)>,
}
#[cfg(feature = "test-policy-overrides")]
static CUTOFFS: std::sync::LazyLock<Mutex<HashMap<String, Arc<CutoffProbe>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
#[cfg(feature = "test-policy-overrides")]
struct CutoffGuard(String);
#[cfg(feature = "test-policy-overrides")]
impl Drop for CutoffGuard {
    fn drop(&mut self) {
        CUTOFFS.lock().unwrap().remove(&self.0);
    }
}
#[cfg(feature = "test-policy-overrides")]
fn cutoff_observe(account: &str, event: CutoffEvent) {
    let probe = CUTOFFS.lock().unwrap().get(account).cloned();
    if let Some(probe) = probe {
        let mut observations = probe.observations.lock().unwrap();
        if observations.0.len() < 128 {
            observations.0.push(event);
        } else {
            observations.1 = true;
        }
    }
}
#[cfg(feature = "test-policy-overrides")]
pub(in crate::runtime::account_worker) fn record_cutoff_archive_result(
    account: &str,
    archived: bool,
    succeeded: bool,
) {
    cutoff_observe(
        account,
        if succeeded {
            CutoffEvent::ArchiveCompleted(archived)
        } else {
            CutoffEvent::ArchiveFailed
        },
    );
}
#[cfg(feature = "test-policy-overrides")]
pub(in crate::runtime::account_worker) fn before_prefix_capture(
    account: &str,
    pending: &VecDeque<AccountWorkerCommand>,
) -> Option<(usize, bool)> {
    let probe = CUTOFFS.lock().unwrap().get(account).cloned()?;
    if probe.rendezvous.lock().unwrap().is_none() {
        return None;
    }
    Some((
        pending
            .iter()
            .filter(|command| matches!(command, AccountWorkerCommand::SetGroupArchived { .. }))
            .count(),
        pending
            .iter()
            .any(|command| matches!(command, AccountWorkerCommand::LocalSubmissionFence)),
    ))
}
#[cfg(feature = "test-policy-overrides")]
pub(in crate::runtime::account_worker) async fn after_prefix_capture(
    account: &str,
    before: (usize, bool),
    after_archives: usize,
    due_retry_owed: bool,
) {
    let (before_archives, before_had_fence) = before;
    let probe = CUTOFFS.lock().unwrap().get(account).cloned();
    let Some(probe) = probe else {
        return;
    };
    let rendezvous = probe.rendezvous.lock().unwrap().take();
    let Some(rendezvous) = rendezvous else {
        return;
    };
    let no_completion_or_drain = probe.observations.lock().unwrap().0.is_empty();
    let no_archive_or_drain = no_completion_or_drain
        && self::probe(account).is_some_and(|original| {
            original
                .observations
                .lock()
                .unwrap()
                .iter()
                .all(|event| !matches!(event, Observation::Command(_) | Observation::Drain(_)))
        });
    let facts = CutoffFacts {
        before_archives,
        before_had_fence,
        after_archives,
        no_archive_or_drain,
        due_retry_owed,
    };
    if rendezvous.reached.send(facts).is_err() {
        return;
    }
    // Neither side can retain the other through a missing test-only release.
    if matches!(
        timeout(Duration::from_secs(5), rendezvous.release).await,
        Ok(Ok(()))
    ) {
        rendezvous
            .released
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(feature = "test-policy-overrides")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn captured_deferred_prefix_drains_before_later_archive_commands() {
    captured_prefix_drains_before_later_archive_commands(2).await;
}

#[cfg(feature = "test-policy-overrides")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn captured_buffered_prefix_drains_before_later_archive_commands() {
    captured_prefix_drains_before_later_archive_commands(0).await;
}

#[cfg(feature = "test-policy-overrides")]
async fn captured_prefix_drains_before_later_archive_commands(deferred_count: usize) {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://progress.example")
        .with_test_relay_client(relay.clone());
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let mut groups = Vec::new();
    for name in ["first due group", "second due group"] {
        groups.push(
            client
                .create_group_with_options(
                    name,
                    &[],
                    AppCreateGroupOptions {
                        relays: Some(vec![
                            "wss://index.example".into(),
                            "wss://progress.example".into(),
                        ]),
                        ..Default::default()
                    },
                )
                .await
                .unwrap(),
        );
    }
    relay
        .block_indexer_publish
        .store(true, std::sync::atomic::Ordering::SeqCst);
    for group in &groups {
        client
            .send(group, b"confirmed secondary fixture")
            .await
            .unwrap();
        let retained = client
            .runtime
            .session()
            .outbound_fanouts_for_group(group)
            .unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].outcome().accepted_targets, 1);
        assert_eq!(retained[0].outcome().outstanding_targets, 1);
    }
    let last_seed = TokioInstant::now();
    drop(client);
    HELD_SCHEDULED_CONVERGENCE_ACCOUNTS
        .lock()
        .unwrap()
        .insert(account.account_id_hex.clone());
    let probe_guard = ProbeGuard(account.account_id_hex.clone());
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime.catch_up_accounts().await.unwrap();
    let commands = runtime.accounts().worker_commands("alice").await.unwrap();
    let mut window = runtime
        .open_conversation_window("alice", &groups[0], Default::default())
        .await
        .unwrap();
    while window.snapshot.presentation.header.epoch.is_none() {
        window.snapshot = timeout(Duration::from_secs(5), window.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    // Both real persisted 30s fanout cutoffs must expire before the held pass.
    tokio::time::sleep_until(last_seed + Duration::from_secs(31)).await;
    let first_pass = Arc::new(tokio::sync::Barrier::new(2));
    runtime
        .shared_services()
        .set_next_scheduled_convergence_barrier(first_pass.clone());
    let tail = Arc::new(tokio::sync::Barrier::new(2));
    let probe = Arc::new(Probe {
        observations: Mutex::new(Vec::new()),
        tail_barrier: Mutex::new(Some(tail.clone())),
        tail_delay: Duration::from_millis(25),
    });
    PROBES
        .lock()
        .unwrap()
        .insert(account.account_id_hex.clone(), probe.clone());
    let (cutoff_reached, cutoff_observed) = oneshot::channel();
    let (cutoff_release, release) = oneshot::channel();
    let cutoff_released = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cutoff_probe = Arc::new(CutoffProbe {
        rendezvous: Mutex::new(Some(CutoffRendezvous {
            reached: cutoff_reached,
            release,
            released: cutoff_released.clone(),
        })),
        observations: Mutex::new((Vec::new(), false)),
    });
    CUTOFFS
        .lock()
        .unwrap()
        .insert(account.account_id_hex.clone(), cutoff_probe.clone());
    let cutoff_guard = CutoffGuard(account.account_id_hex.clone());
    HELD_SCHEDULED_CONVERGENCE_ACCOUNTS
        .lock()
        .unwrap()
        .remove(&account.account_id_hex);
    let (respond, _response) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::GroupRecoveryStatus {
            group_id: groups[0].clone(),
            respond,
        })
        .unwrap();
    timeout(Duration::from_secs(5), first_pass.wait())
        .await
        .unwrap();
    let mut predecessors = Vec::new();
    for archived in [true, false].into_iter().take(deferred_count) {
        let (respond, response) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::SetGroupArchived {
                group_id: groups[0].clone(),
                archived,
                respond,
            })
            .unwrap();
        predecessors.push(response);
    }
    // This snapshot read fences the two mutation commands into the deferred FIFO.
    let (respond, response) = oneshot::channel();
    commands
        .try_send(AccountWorkerCommand::Members {
            group_id: groups[0].clone(),
            respond,
        })
        .unwrap();
    timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let accepted = runtime
        .submit_text(
            "alice",
            &groups[0],
            "durable after command predecessors".into(),
            "overdue-durable".into(),
        )
        .await
        .unwrap();
    let admission_gate = runtime
        .shared_services()
        .local_submission_gate(&account.account_id_hex);
    let held_admission = admission_gate.lock().await;
    first_pass.wait().await;
    timeout(Duration::from_secs(5), tail.wait()).await.unwrap();
    // These are still buffered in the channel when the finished pass returns.
    for archived in [true, false, true, false]
        .into_iter()
        .take(4 - deferred_count)
    {
        let (respond, response) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::SetGroupArchived {
                group_id: groups[0].clone(),
                archived,
                respond,
            })
            .unwrap();
        predecessors.push(response);
    }
    tail.wait().await;
    let cutoff = timeout(Duration::from_secs(5), cutoff_observed)
        .await
        .expect("real prefix capture must reach its bounded rendezvous")
        .expect("real prefix capture must retain its observation sender");
    let captured_initial_four = !cutoff.before_had_fence && cutoff.after_archives == 4;
    // Each boolean means the actual count matches this requested scenario,
    // including the zero deferred prefix of the buffered case.
    let original_deferred_prefix = cutoff.before_archives == deferred_count;
    // The synchronous capture only appends commands: this actual kind-count
    // difference binds captured archives while preserving other FIFO controls.
    let original_buffered_prefix =
        cutoff.after_archives.checked_sub(cutoff.before_archives) == Some(4 - deferred_count);
    assert!(
        captured_initial_four
            && original_deferred_prefix
            && original_buffered_prefix
            && cutoff.no_archive_or_drain
            && cutoff.due_retry_owed,
        "cutoff fixture must witness all four real predecessors and an already due owed retry"
    );
    // These real mutations arrive only after the existing capture has finished.
    // Their finite replies must also complete; they are not an infinite flood.
    let later_count = if deferred_count == 2 { 2 } else { 4 };
    let mut later_responses = Vec::new();
    for archived in [true, false, true, false].into_iter().take(later_count) {
        let (respond, response) = oneshot::channel();
        commands
            .try_send(AccountWorkerCommand::SetGroupArchived {
                group_id: groups[0].clone(),
                archived,
                respond,
            })
            .unwrap();
        later_responses.push(response);
    }
    let later_commands_enqueued_after_cutoff = later_responses.len() == later_count;
    cutoff_release
        .send(())
        .expect("observing worker must still own the cutoff release");
    // Repeated optional passes must preserve the ordinary 100ms gate-contention backoff.
    sleep(Duration::from_millis(700)).await;
    // A loaded machine may fit fewer drains into that sleep than the
    // assertions below need; hold admission until two have run.
    let retry_result = timeout(Duration::from_secs(5), async {
        while probe
            .observations
            .lock()
            .unwrap()
            .iter()
            .filter(|event| matches!(event, Observation::Drain(_)))
            .count()
            < 2
        {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if retry_result.is_err() {
        // Read existing observations only after the original timeout verdict.
        // No account keys, command data, raw trace or timestamps leave the fixture.
        let observations = probe.observations.lock().unwrap();
        let last_turn = observations.iter().rev().find_map(|event| match event {
            Observation::Turn {
                pending,
                buffered,
                yielded,
                due,
                owed,
                retry_ready,
            } => Some(serde_json::json!({
                "pending": pending, "buffered": buffered, "yielded": yielded,
                "due": due, "owed": owed, "retry_ready": retry_ready,
            })),
            _ => None,
        });
        eprintln!(
            "secondary-cutoff-timeout {}",
            serde_json::json!({
                "deferred_count": deferred_count,
                "drain_count": observations.iter().filter(|event| matches!(event, Observation::Drain(_))).count(),
                "predecessor_command_count": observations.iter().filter(|event| matches!(event, Observation::Command(_))).count(),
                "pass_count": observations.iter().filter(|event| matches!(event, Observation::Pass)).count(),
                "turn_count": observations.iter().filter(|event| matches!(event, Observation::Turn { .. })).count(),
                "last_turn": last_turn,
            })
        );
    }
    retry_result
        .expect("cutoff fixture held admission gate must exercise the ordinary durable retry");
    let admission_released = TokioInstant::now();
    drop(held_admission);
    let observed = timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = window.recv().await.unwrap().unwrap();
            if snapshot.page.page().messages.iter().any(|row| {
                row.message_id_hex == accepted.message_id_hex && row.source_message_id_hex.is_some()
            }) {
                break;
            }
        }
    })
    .await;
    for response in predecessors {
        response.await.unwrap().unwrap();
    }
    for response in later_responses {
        response.await.unwrap().unwrap();
    }
    let cutoff_observations = cutoff_probe.observations.lock().unwrap().0.clone();
    let cutoff_overflow = cutoff_probe.observations.lock().unwrap().1;
    let observations = probe.observations.lock().unwrap().clone();
    drop(cutoff_guard);
    drop(probe_guard);
    relay
        .block_indexer_publish
        .store(false, std::sync::atomic::Ordering::SeqCst);
    relay.indexer_publish_release.notify_waiters();
    runtime.shutdown_and_close().await.unwrap();
    let runtime_closed = true;
    observed.expect("overdue confirmed secondary groups must service the durable send while their ACKs remain held");
    let published_send_observed = true;
    let all_archives = cutoff_observations
        .iter()
        .filter_map(|event| match event {
            CutoffEvent::ArchiveCompleted(value) => Some(*value),
            _ => None,
        })
        .collect::<Vec<_>>();
    let first_completed_drain = cutoff_observations
        .iter()
        .position(|event| matches!(event, CutoffEvent::Drain))
        .expect("actual due drain must be observed");
    let completed_before_drain = cutoff_observations[..first_completed_drain]
        .iter()
        .filter_map(|event| match event {
            CutoffEvent::ArchiveCompleted(value) => Some(*value),
            _ => None,
        })
        .collect::<Vec<_>>();
    let initial_predecessors_before_first_drain =
        completed_before_drain.get(..4) == Some(&[true, false, true, false][..]);
    let later_commands_after_first_drain = completed_before_drain.len() == 4;
    let all_commands_completed = !cutoff_overflow
        && all_archives.len() == 4 + later_count
        && !cutoff_observations
            .iter()
            .any(|event| matches!(event, CutoffEvent::ArchiveFailed));
    assert!(
        all_commands_completed,
        "all actual archive handlers and replies must succeed without observation loss"
    );
    assert!(
        initial_predecessors_before_first_drain,
        "all deferred and buffered predecessors must run before durable execution"
    );
    assert_eq!(
        all_archives.len(),
        4 + later_count,
        "all original and later archive commands must actually execute"
    );
    // Unlike a sampled scheduler Turn, these are the actual capture boundary.
    assert!(
        original_deferred_prefix && original_buffered_prefix,
        "fixture must exercise the requested deferred and buffered capture prefixes"
    );
    let blocked_drains = observations
        .iter()
        .filter_map(|event| match event {
            Observation::Drain(at) if *at < admission_released => Some(*at),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        blocked_drains.len() >= 2,
        "fixture must exercise repeated unavailable-row drains"
    );
    assert!(
        blocked_drains
            .windows(2)
            .all(|times| times[1].duration_since(times[0]) >= Duration::from_millis(100)),
        "secondary pressure must not reset the ordinary drain's 100ms retry backoff"
    );
    assert!(
        observations
            .iter()
            .filter(|event| matches!(event, Observation::Pass))
            .count()
            >= 2
    );
    let held_backoff_preserved = true;
    let optional_passes_observed = true;
    let cutoff_rendezvous_completed = cutoff_released.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        cutoff_rendezvous_completed,
        "cutoff release must be consumed by the actual worker"
    );
    eprintln!(
        "secondary-cutoff-prerequisites {}",
        serde_json::json!({
            "captured_initial_four": captured_initial_four,
            "original_deferred_prefix": original_deferred_prefix,
            "original_buffered_prefix": original_buffered_prefix,
            "no_archive_or_drain_before_cutoff": cutoff.no_archive_or_drain,
            "due_retry_owed": cutoff.due_retry_owed,
            "later_commands_enqueued_after_cutoff": later_commands_enqueued_after_cutoff,
        })
    );
    eprintln!(
        "secondary-cutoff-result {}",
        serde_json::json!({
            "initial_predecessors_before_first_drain": initial_predecessors_before_first_drain,
            "later_commands_after_first_drain": later_commands_after_first_drain,
            "all_commands_completed": all_commands_completed,
            "published_send_observed": published_send_observed,
            "runtime_closed": runtime_closed,
            "held_backoff_preserved": held_backoff_preserved,
            "optional_passes_observed": optional_passes_observed,
            "cutoff_rendezvous_completed": cutoff_rendezvous_completed,
        })
    );
    assert!(
        initial_predecessors_before_first_drain && later_commands_after_first_drain,
        "captured predecessor prefix must drain before post-cutoff archive commands"
    );
}
