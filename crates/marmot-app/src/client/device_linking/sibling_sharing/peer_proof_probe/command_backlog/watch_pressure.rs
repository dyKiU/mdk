//! Finite real watch hints, counted only after actual owner service returns.
//! This is scheduling pressure, never a publication result or sharing authority.
use super::*;

/// Fixed diagnostic stages, scoped to the existing actual owned watch fixture.
#[derive(Clone, Copy)]
pub(crate) enum SelectStage {
    WatchYield,
    WatchSelected,
    ReplayAfterClearedDebt,
    ReplayWithDebt,
    ReplayWithoutDebt,
    ReceiveArm,
    AppReceiveFirstPending,
    AppReceiveFirstReady,
    ReceiveSelected,
}
// Stage counts, first owning select ordinal, service count at that first stage,
// total select ordinals, unknown/overflow. No identities or authority retained.
pub(crate) type SelectSnapshot = ([u64; 9], [u64; 9], [u64; 9], u64, bool);
#[derive(Default)]
struct SelectState {
    counts: [u64; 9],
    first_turn: [u64; 9],
    first_services: [u64; 9],
    turns: u64,
}
/// This owns only a Weak to the already-installed test probe, never its target.
pub(crate) struct SelectRecorder {
    probe: Weak<Probe>,
    turn: u64,
}
impl SelectRecorder {
    pub(crate) fn record(&self, stage: SelectStage) {
        let Some(probe) = self.probe.upgrade() else { return; };
        let Some(pressure) = probe.watch_pressure.get() else { return; };
        if pressure.select_closed.load(Ordering::Acquire) { return; }
        let Ok(mut state) = pressure.select_state.try_lock() else {
            pressure.select_unknown.store(true, Ordering::Release);
            return;
        };
        let index = stage as usize;
        let Some(next) = state.counts[index].checked_add(1).filter(|next| *next <= 256) else {
            pressure.select_unknown.store(true, Ordering::Release);
            return;
        };
        state.counts[index] = next;
        if state.first_turn[index] == 0 {
            state.first_turn[index] = self.turn;
            state.first_services[index] = pressure.services.load(Ordering::Acquire) as u64;
        }
    }
}

pub(super) struct Pressure {
    sender: OnceLock<tokio::sync::watch::Sender<()>>,
    started: AtomicBool,
    services: AtomicUsize,
    notifications: AtomicUsize,
    errors: AtomicUsize,
    done: Notify,
    select_state: Mutex<SelectState>,
    select_closed: AtomicBool,
    select_unknown: AtomicBool,
    select_at_acceptance: OnceLock<SelectSnapshot>,
}
impl Pressure {
    fn new() -> Self {
        Self {
            sender: OnceLock::new(),
            started: AtomicBool::new(false),
            services: AtomicUsize::new(0),
            notifications: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            done: Notify::new(),
            select_state: Mutex::new(SelectState::default()),
            select_closed: AtomicBool::new(false),
            select_unknown: AtomicBool::new(false),
            select_at_acceptance: OnceLock::new(),
        }
    }
    pub(super) fn capture_sender(&self, sender: &tokio::sync::watch::Sender<()>) {
        // The actual ready/preselect hook calls this only for the registered
        // B original/nonce. A clone owns a wake channel, not an AppClient/State.
        if self.sender.get().is_none() {
            let _ = self.sender.set(sender.clone());
        }
    }
    fn start(&self) -> bool {
        let Some(sender) = self.sender.get() else {
            return false;
        };
        if self.started.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.notifications.store(1, Ordering::Release);
        sender.send_replace(());
        true
    }
    fn returned(&self, ok: bool) {
        if !self.started.load(Ordering::Acquire) {
            return;
        }
        let count = self.services.load(Ordering::Acquire);
        if count >= 8 {
            return;
        }
        // This exact serial actor alone calls returned. The fixture never
        // rearms via a racing waiter task and never fabricates changed().
        if !ok {
            self.errors.fetch_add(1, Ordering::AcqRel);
        }
        self.services.store(count + 1, Ordering::Release);
        if count + 1 < 8 {
            if let Some(sender) = self.sender.get() {
                self.notifications.fetch_add(1, Ordering::AcqRel);
                sender.send_replace(());
            }
        } else {
            self.done.notify_one();
        }
    }
    fn select_snapshot(&self) -> Option<SelectSnapshot> {
        let Ok(state) = self.select_state.try_lock() else {
            self.select_unknown.store(true, Ordering::Release);
            return None;
        };
        Some((state.counts, state.first_turn, state.first_services, state.turns,
              self.select_unknown.load(Ordering::Acquire)))
    }
    pub(super) fn accepted(&self, probe: &Probe) {
        // Freeze diagnostics at the same actual authenticated Body acceptance.
        // Original acceptance recording and all test oracles remain below.
        if !self.select_closed.swap(true, Ordering::AcqRel)
            && let Some(snapshot) = self.select_snapshot() {
            let _ = self.select_at_acceptance.set(snapshot);
        }
        let Ok(mut accepted) = probe.accepted.try_lock() else {
            probe.known.store(false, Ordering::Release);
            return;
        };
        if accepted.is_some() {
            return;
        }
        let count = self.services.load(Ordering::Acquire);
        *accepted = Some((
            count,
            self.started.load(Ordering::Acquire) && self.errors.load(Ordering::Acquire) == 0,
        ));
        drop(accepted);
        probe.accepted_observed.notify_one();
    }
}

pub(crate) struct WatchGuard(Guard);
impl std::ops::Deref for WatchGuard {
    type Target = Guard;
    fn deref(&self) -> &Guard {
        &self.0
    }
}
impl Guard {
    pub(crate) fn into_watch_pressure(self) -> Option<WatchGuard> {
        self.0.watch_pressure.set(Pressure::new()).ok()?;
        Some(WatchGuard(self))
    }
}
impl WatchGuard {
    pub(crate) fn start_watch_pressure(&self) -> bool {
        self.0.0.watch_pressure.get().is_some_and(Pressure::start)
    }
    pub(crate) async fn finish_watch_pressure(&self) -> bool {
        let Some(pressure) = self.0.0.watch_pressure.get() else {
            return false;
        };
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let done = pressure.done.notified();
                if pressure.services.load(Ordering::Acquire) == 8 {
                    break;
                }
                done.await;
            }
        })
        .await
        .is_ok()
            && pressure.errors.load(Ordering::Acquire) == 0
    }
    pub(crate) fn watch_select_snapshot(&self) -> (Option<SelectSnapshot>, Option<SelectSnapshot>) {
        let Some(pressure) = self.0.0.watch_pressure.get() else { return (None, None); };
        (pressure.select_snapshot(), pressure.select_at_acceptance.get().copied())
    }
    pub(crate) fn watch_pressure_snapshot(&self) -> (bool, usize, usize, usize) {
        let pressure = self
            .0
            .0
            .watch_pressure
            .get()
            .expect("attached watch pressure");
        (
            pressure.started.load(Ordering::Acquire),
            pressure.services.load(Ordering::Acquire),
            pressure.notifications.load(Ordering::Acquire),
            pressure.errors.load(Ordering::Acquire),
        )
    }
}

pub(in super::super::super) fn service(entries: &[SiblingChannel], ok: bool) {
    let Some(probe) = probe() else {
        return;
    };
    if !entries
        .iter()
        .any(|entry| target(&probe, entry) && entry.original.live() && entry.state.live())
    {
        return;
    }
    if let Some(pressure) = probe.watch_pressure.get() {
        pressure.returned(ok);
    }
}

// Capture after the real pause, before borrowing the client into select futures.
// Each ordinal belongs to this exact original/nonce; a missing/busy record is unknown.
pub(in super::super::super) fn selection(entries: &[SiblingChannel]) -> Option<SelectRecorder> {
    let probe = probe()?;
    if !entries.iter().any(|entry| target(&probe, entry)
        && entry.original.live() && entry.state.live()) { return None; }
    let pressure = probe.watch_pressure.get()?;
    if !pressure.started.load(Ordering::Acquire)
        || pressure.select_closed.load(Ordering::Acquire) { return None; }
    let Ok(mut state) = pressure.select_state.try_lock() else {
        pressure.select_unknown.store(true, Ordering::Release);
        return None;
    };
    let Some(turn) = state.turns.checked_add(1).filter(|turn| *turn <= 256) else {
        pressure.select_unknown.store(true, Ordering::Release);
        return None;
    };
    state.turns = turn;
    Some(SelectRecorder { probe: Arc::downgrade(&probe), turn })
}
