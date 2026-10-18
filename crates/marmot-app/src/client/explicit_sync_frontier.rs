//! Opt-in fixed numeric observations of one already-owned client's explicit sync.
//! No account, message, Core, transport, or application owner is retained here.
use super::AppClient;
use std::sync::{Arc, atomic::{AtomicU64, Ordering::SeqCst}};
use std::time::Instant;

#[derive(Clone, Copy)]
pub(crate) enum Phase {
    Setup = 1, FirstDrain, Credit, SecondDrain, RecoveryJob,
    RecoveryNetwork, RecoveryAdmission, SubscriptionRefresh, Finalization, Returned,
}
// [calls,status,phase,call_start,phase_start,call_end,drain_ordinal,
// physical_delivery_receives,ingested,skipped,refused,last_receive,last_wait,invalid].
// Time values are microseconds from the fixture's existing origin PLUS ONE;
// zero means unobserved. Status:0none,1running,2Ok,3Err,4uncompleted scope drop
// (cancellation OR an early error return; this does not invent which happened).
pub(crate) struct Probe { origin: Instant, cells: [AtomicU64; 14] }
impl Probe {
    fn new(origin: Instant) -> Self {
        Self { origin, cells: std::array::from_fn(|_| AtomicU64::new(0)) }
    }
    fn now(&self) -> u64 {
        let value = Instant::now().checked_duration_since(self.origin)
            .and_then(|value| u64::try_from(value.as_micros()).ok())
            .and_then(|value| value.checked_add(1));
        match value { Some(value) => value, None => { self.cells[13].store(1, SeqCst); 0 } }
    }
    fn increment(&self, index: usize) {
        if self.cells[index].fetch_update(SeqCst, SeqCst, |value| value.checked_add(1)).is_err() {
            self.cells[13].store(1, SeqCst);
        }
    }
    fn running(&self) -> bool { self.cells[1].load(SeqCst) == 1 }
    fn begin(self: &Arc<Self>) -> Span {
        self.increment(0);
        for index in 5..13 { self.cells[index].store(0, SeqCst); }
        self.cells[3].store(self.now(), SeqCst);
        self.cells[1].store(1, SeqCst);
        let _ = self.phase(Phase::Setup);
        Span { probe: self.clone(), finished: false }
    }
    pub(crate) fn phase(&self, phase: Phase) -> Option<u64> {
        if !self.running() { return None; }
        let previous = self.cells[2].swap(phase as u64, SeqCst);
        self.cells[4].store(self.now(), SeqCst);
        Some(previous)
    }
    fn restore(&self, previous: Option<u64>) {
        if self.running() && let Some(previous) = previous {
            self.cells[2].store(previous, SeqCst);
            self.cells[4].store(self.now(), SeqCst);
        }
    }
    pub(crate) fn drain(&self) {
        if !self.running() { return; }
        self.increment(6);
        for index in 7..13 { self.cells[index].store(0, SeqCst); }
    }
    pub(crate) fn wait(&self) {
        if self.running() { self.cells[12].store(self.now(), SeqCst); }
    }
    pub(crate) fn received(&self) {
        if self.running() { self.increment(7); self.cells[11].store(self.now(), SeqCst); }
    }
    pub(crate) fn counts(&self, ingested: u64, skipped: u64, refused: u64) {
        if self.running() {
            for (index, value) in [(8, ingested), (9, skipped), (10, refused)] {
                self.cells[index].store(value, SeqCst);
            }
        }
    }
    pub(crate) fn snapshot(&self) -> [u64; 15] {
        // Separate atomic reads: never a joint snapshot/authority or CPU measure.
        // Cell14 is this snapshot's existing-origin time, not an operation result.
        let snapshot_time = self.now();
        std::array::from_fn(|index| if index == 14 { snapshot_time } else { self.cells[index].load(SeqCst) })
    }
}
pub(crate) struct Span { probe: Arc<Probe>, finished: bool }
impl Span {
    pub(crate) fn finish(mut self, ok: bool) {
        if ok { let _ = self.probe.phase(Phase::Returned); }
        self.probe.cells[5].store(self.probe.now(), SeqCst);
        self.probe.cells[1].store(if ok { 2 } else { 3 }, SeqCst);
        self.finished = true;
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        if !self.finished {
            // Keep the last BEFORE-await phase when the original future drops.
            self.probe.cells[5].store(self.probe.now(), SeqCst);
            self.probe.cells[1].store(4, SeqCst);
        }
    }
}
impl AppClient {
    pub(crate) fn test_observe_explicit_sync(&mut self, origin: Instant) -> Arc<Probe> {
        let probe = Arc::new(Probe::new(origin));
        self.explicit_sync_frontier = Some(probe.clone());
        probe
    }
    pub(crate) fn test_begin_explicit_sync(&self, explicit: bool) -> Option<Span> {
        if explicit { self.explicit_sync_frontier.as_ref().map(Probe::begin) } else { None }
    }
    pub(crate) fn test_sync_phase(&self, phase: Phase) -> Option<u64> {
        self.explicit_sync_frontier.as_ref().and_then(|probe| probe.phase(phase))
    }
    pub(crate) fn test_restore_sync_phase(&self, previous: Option<u64>) {
        if let Some(probe) = &self.explicit_sync_frontier { probe.restore(previous); }
    }
}
