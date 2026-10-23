//! Cross-account storage isolation and committed-deletion timing boundaries.

use super::*;
use cgka_traits::storage::StorageProvider;
use marmot_account::AccountHomeError;

fn queue_snapshot(runtime: &crate::MarmotAppRuntime) -> crate::RuntimePerformanceSnapshot {
    runtime
        .app_performance_snapshot()
        .runtime_operations
        .into_iter()
        .find(|snapshot| snapshot.operation == RuntimeOp::SendQueue)
        .unwrap()
}

struct HeldDatabase {
    release: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for HeldDatabase {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// SIBLING_WORKER_PASSIVE_BEGIN
#[cfg(feature = "test-policy-overrides")]
pub(in crate::runtime::account_worker) mod passive_bob {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, LazyLock, Mutex};

    type Turn = (u64, u64, bool, bool, bool, bool);
    #[derive(Clone, Copy, Default)]
    pub(super) struct Counts {
        checkpoints: u64,
        drain_attempts: u64,
        last_turn: Option<Turn>,
        phase: Option<u8>,
        overflow: bool,
    }
    static ACTIVE: AtomicBool = AtomicBool::new(false);
    pub(in crate::runtime::account_worker) fn active() -> bool {
        ACTIVE.load(Ordering::Acquire)
    }
    static SLOTS: LazyLock<Mutex<HashMap<String, Arc<Mutex<Counts>>>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    pub(super) struct Guard {
        account: String,
        counts: Arc<Mutex<Counts>>,
    }
    impl Guard {
        pub(super) fn snapshot(&self) -> Counts {
            *self
                .counts
                .lock()
                .unwrap_or_else(|error| error.into_inner())
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let mut slots = SLOTS.lock().unwrap_or_else(|error| error.into_inner());
            if slots
                .get(&self.account)
                .is_some_and(|counts| Arc::ptr_eq(counts, &self.counts))
            {
                slots.remove(&self.account);
            }
            ACTIVE.store(!slots.is_empty(), Ordering::Release);
        }
    }
    pub(super) fn install(account: &str) -> Option<Guard> {
        let mut slots = SLOTS.lock().unwrap_or_else(|error| error.into_inner());
        if slots.len() >= 4 || account.len() > 128 || slots.contains_key(account) {
            return None;
        }
        let counts = Arc::new(Mutex::new(Counts::default()));
        slots.insert(account.to_owned(), counts.clone());
        ACTIVE.store(true, Ordering::Release);
        Some(Guard {
            account: account.to_owned(),
            counts,
        })
    }
    fn update(account: &str, record: impl FnOnce(&mut Counts)) {
        if !ACTIVE.load(Ordering::Acquire) {
            return;
        }
        let counts = SLOTS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(account)
            .cloned();
        if let Some(counts) = counts {
            record(&mut counts.lock().unwrap_or_else(|error| error.into_inner()));
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(in crate::runtime::account_worker) fn record_turn(
        account: &str,
        pending: usize,
        buffered: usize,
        yielded: bool,
        due: bool,
        owed: bool,
        retry_ready: bool,
    ) {
        update(account, |counts| {
            match (
                counts.checkpoints.checked_add(1),
                u64::try_from(pending),
                u64::try_from(buffered),
            ) {
                (Some(next), Ok(pending), Ok(buffered)) => {
                    counts.checkpoints = next;
                    counts.last_turn = Some((pending, buffered, yielded, due, owed, retry_ready));
                }
                _ => counts.overflow = true,
            }
        });
    }
    // Last reached location only; not an exact blocker or task-poll observation.
    pub(in crate::runtime::account_worker) fn record_phase(account: &str, phase: u8) {
        update(account, |counts| counts.phase = Some(phase));
    }
    pub(in crate::runtime::account_worker) fn record_drain(account: &str) {
        update(account, |counts| {
            if let Some(next) = counts.drain_attempts.checked_add(1) {
                counts.drain_attempts = next;
            } else {
                counts.overflow = true;
            }
        });
    }
    #[derive(serde::Serialize)]
    pub(super) struct Frozen {
        registered: bool,
        before_phase: Option<u8>,
        after_phase: Option<u8>,
        checkpoints: Option<u64>,
        drain_attempts: Option<u64>,
        last_turn: Option<Turn>,
        overflow: bool,
        elapsed_ms: Option<u64>,
    }
    pub(super) fn freeze(
        guard: Option<&Guard>,
        before: Option<Counts>,
        elapsed_ms: Option<u64>,
    ) -> Frozen {
        let (Some(guard), Some(before)) = (guard, before) else {
            return Frozen {
                registered: false,
                before_phase: None,
                after_phase: None,
                checkpoints: None,
                drain_attempts: None,
                last_turn: None,
                overflow: false,
                elapsed_ms,
            };
        };
        let after = guard.snapshot();
        let checkpoints = after.checkpoints.checked_sub(before.checkpoints);
        let drain_attempts = after.drain_attempts.checked_sub(before.drain_attempts);
        let overflow =
            before.overflow || after.overflow || checkpoints.is_none() || drain_attempts.is_none();
        Frozen {
            registered: true,
            before_phase: before.phase,
            after_phase: after.phase,
            checkpoints: if overflow { None } else { checkpoints },
            drain_attempts: if overflow { None } else { drain_attempts },
            last_turn: if !overflow && checkpoints.is_some_and(|count| count > 0) {
                after.last_turn
            } else {
                None
            },
            overflow,
            elapsed_ms,
        }
    }
}
// SIBLING_WORKER_PASSIVE_END

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_account_admission_does_not_delay_sibling_send_or_resurrect_deleted_timing() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("blocked").unwrap();
    let bob = home.create_account("healthy").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let alice_group = app
        .client(&alice.label)
        .await
        .unwrap()
        .create_group("blocked group", &[])
        .await
        .unwrap();
    let bob_group = app
        .client(&bob.label)
        .await
        .unwrap()
        .create_group("healthy group", &[])
        .await
        .unwrap();
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    #[cfg(feature = "test-policy-overrides")]
    let bob_observer = passive_bob::install(&bob.account_id_hex);
    runtime.reconcile_accounts().await.unwrap();
    for account in [&alice, &bob] {
        runtime
            .accounts()
            .wait_for_account_network_startup_to_settle(&account.label)
            .await
            .unwrap();
    }
    let storage = app.account_storage(&alice.label).unwrap();
    let (entered, entered_wait) = oneshot::channel();
    let (release, release_wait) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        StorageProvider::with_transaction(&storage, |_| {
            entered.send(()).unwrap();
            release_wait
                .recv_timeout(Duration::from_secs(10))
                .expect("fixture releases blocked database");
            Ok::<_, AppError>(())
        })
        .unwrap();
    });
    let held = HeldDatabase {
        release: Some(release),
        thread: Some(thread),
    };
    entered_wait.await.unwrap();
    let account_gate = runtime
        .shared_services()
        .local_submission_gate(&alice.account_id_hex);
    let admitting = {
        let runtime = runtime.clone();
        let alice = alice.clone();
        tokio::spawn(async move {
            runtime
                .submit_text(
                    &alice.label,
                    &alice_group,
                    "blocked admission".into(),
                    "blocked-token".into(),
                )
                .await
        })
    };
    timeout(Duration::from_secs(2), async {
        while account_gate.try_lock().is_ok() {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the blocked account owns its admission/selection gate");
    let mut submit_returned = false;
    let mut status_polls = 0_u64;
    let mut last_status = "unknown";
    #[cfg(feature = "test-policy-overrides")]
    let bob_before = bob_observer.as_ref().map(passive_bob::Guard::snapshot);
    #[cfg(feature = "test-policy-overrides")]
    let healthy_started = TokioInstant::now();
    let healthy = timeout(Duration::from_secs(1), async {
        let accepted = runtime
            .submit_text(
                &bob.label,
                &bob_group,
                "healthy sibling".into(),
                "healthy-token".into(),
            )
            .await;
        submit_returned = true;
        let accepted = accepted?;
        loop {
            status_polls += 1;
            let status = runtime.local_send_status(&bob.label, &bob_group, "healthy-token")?;
            last_status = match &status {
                None => "none",
                Some(crate::LocalSendStatus::Queued) => "queued",
                Some(crate::LocalSendStatus::EngineOwned) => "engine_owned",
                Some(crate::LocalSendStatus::Rejected) => "rejected",
                Some(crate::LocalSendStatus::Completed(_)) => "completed",
            };
            if let Some(crate::LocalSendStatus::Completed(summary)) = status {
                break Ok::<_, AppError>((accepted, summary));
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let healthy_observation = (submit_returned, status_polls, last_status);
    #[cfg(feature = "test-policy-overrides")]
    let worker_observation = passive_bob::freeze(
        bob_observer.as_ref(),
        bob_before,
        u64::try_from(healthy_started.elapsed().as_millis()).ok(),
    );
    // Removal must wait for the owned admission before committing its wipe
    // and cancelling observations. Only UUID/temp fixture identities exist.
    let removing = {
        let runtime = runtime.clone();
        let alice = alice.clone();
        tokio::spawn(async move { runtime.accounts().remove_account(&alice.label).await })
    };
    drop(held);
    let admitted = timeout(Duration::from_secs(5), admitting)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(admitted.client_token, "blocked-token");
    timeout(Duration::from_secs(5), removing)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    eprintln!(
        "sibling-send-observation {}",
        serde_json::json!({
            "submit_returned": healthy_observation.0,
            "status_polls": healthy_observation.1,
            "last_status": healthy_observation.2,
        })
    );
    #[cfg(feature = "test-policy-overrides")]
    eprintln!(
        "sibling-worker-observation {}",
        serde_json::json!(worker_observation)
    );
    let (accepted, published) = healthy
        .expect("one account's database contention cannot postpone another account's durable send")
        .unwrap();
    assert_eq!(
        published.accept_disposition,
        cgka_traits::SendAcceptDisposition::Published
    );
    assert_eq!(published.published, 1);
    assert_eq!(published.message_ids, vec![accepted.message_id_hex]);
    assert!(matches!(
        home.account(&alice.label),
        Err(AccountHomeError::UnknownAccount(_))
    ));
    let snapshot = queue_snapshot(&runtime);
    assert_eq!(
        snapshot.in_flight, 0,
        "an admission cannot register phantom timing after committed deletion"
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_permanent_removal_preserves_live_row_timing_then_committed_removal_cancels_it() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("remove-held-send").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let group = app
        .client(&account.label)
        .await
        .unwrap()
        .create_group("retained send", &[])
        .await
        .unwrap();
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime
        .shared_services()
        .set_next_startup_sync_barrier(Arc::new(tokio::sync::Barrier::new(2)));
    runtime.reconcile_accounts().await.unwrap();
    let accepted = runtime
        .submit_text(
            &account.label,
            &group,
            "retain until removal commits".into(),
            "remove-token".into(),
        )
        .await
        .unwrap();
    assert!(matches!(
        runtime
            .local_send_status(&account.label, &group, "remove-token")
            .unwrap(),
        Some(crate::LocalSendStatus::Queued)
    ));
    assert_eq!(queue_snapshot(&runtime).in_flight, 1);
    let obstruction = home.root().join(".wipe-tombstones");
    fs_private::write_private(&obstruction, b"synthetic pre-commit failure").unwrap();
    let failed = runtime.accounts().remove_account(&account.label).await;
    assert!(failed.is_err());
    assert!(home.account(&account.label).is_ok());
    assert_eq!(
        app.account_storage(&account.label)
            .unwrap()
            .app_storage()
            .local_submission(&hex::encode(&group), "remove-token")
            .unwrap()
            .unwrap()
            .message_id_hex,
        accepted.message_id_hex
    );
    let snapshot = queue_snapshot(&runtime);
    assert_eq!(
        snapshot.in_flight, 1,
        "a pre-commit removal failure keeps the live admission instant"
    );
    assert_eq!(snapshot.cancelled, 0);
    std::fs::remove_file(obstruction).unwrap();
    runtime
        .accounts()
        .remove_account(&account.label)
        .await
        .unwrap();
    let snapshot = queue_snapshot(&runtime);
    assert_eq!(snapshot.in_flight, 0);
    assert_eq!(snapshot.cancelled, 1);
    assert!(matches!(
        home.account(&account.label),
        Err(AccountHomeError::UnknownAccount(_))
    ));
    runtime.shutdown_and_close().await.unwrap();
}
