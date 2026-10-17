//! Optional exact-original passive diagnostics. No scheduling or authority changes.
use super::*;
use std::sync::Weak;

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub(crate) enum Stage {
    WorkerLoop, BeforeSelect, TickLatched, Selected, Enter, OpaqueStart, OpaqueDone,
    PendingStart, PendingDone, BeginStart, BeginDone, LoopStart, AdvanceStart,
    AdvanceEnd, Return, ChildAdded,
}
const LIMIT: u64 = 1_000_000_000;
pub(crate) type Snapshot = ([u64; 16], [Option<u64>; 16], Option<(Stage, Option<usize>, u64)>,
                           Option<(Stage, u64)>, Option<[bool; 3]>, bool, u64);
struct Progress {
    counts: [u64; 16],
    times: [Option<u64>; 16],
    point: Option<(Stage, Option<usize>, Instant)>,
    returned: Option<(Stage, u64)>,
    due: Option<[bool; 3]>,
    entered: Option<Instant>,
}
pub(crate) struct Probe {
    origin: Instant,
    progress: Mutex<Progress>,
}
impl Probe {
    pub(crate) fn enabled() -> Option<Arc<Self>> {
        (std::env::var_os("WN_ORDINARY_SIBLING_TURN_TRACE").as_deref() == Some(std::ffi::OsStr::new("1"))).then(|| Arc::new(Self {
            origin: Instant::now(),
            progress: Mutex::new(Progress { counts: [0; 16], times: [None; 16], point: None,
                returned: None, due: None, entered: None }),
        }))
    }
    fn milliseconds(duration: std::time::Duration) -> u64 { duration.as_millis().min(u128::from(LIMIT)) as u64 }
    pub(crate) fn mark(&self, stage: Stage, index: Option<usize>) {
        let now = Instant::now();
        let mut row = self.progress.lock().expect("ordinary sibling turn trace");
        let slot = stage as usize;
        row.counts[slot] = row.counts[slot].saturating_add(1).min(LIMIT);
        row.times[slot] = Some(Self::milliseconds(now.duration_since(self.origin)));
        if !matches!(stage, Stage::ChildAdded) { row.point = Some((stage, index.filter(|value| *value < 128), now)); }
    }
    pub(crate) fn snapshot(&self) -> Snapshot {
        let row = self.progress.lock().expect("ordinary sibling turn trace");
        (row.counts, row.times, row.point.map(|(stage, index, at)| (stage, index, Self::milliseconds(at.elapsed()))),
         row.returned, row.due, row.entered.is_some(), Self::milliseconds(self.origin.elapsed()))
    }
}
#[derive(Clone)]
pub(crate) struct Trace {
    owner: Weak<OriginalEnrollmentSharingChoice>,
    probe: Arc<Probe>,
}
impl Trace {
    fn matches(&self) -> bool {
        self.owner.upgrade().is_some_and(|owner| owner.turn_probe.as_ref().is_some_and(|probe| Arc::ptr_eq(probe, &self.probe)))
    }
}
pub(crate) fn current(client: &AppClient) -> Option<Trace> {
    let owner = client.linking_owner.sharing_approval.as_ref()?;
    Some(Trace { owner: Arc::downgrade(owner), probe: owner.turn_probe.clone()? })
}
pub(crate) fn mark(trace: &Option<Trace>, stage: Stage) {
    if let Some(trace) = trace && trace.matches() { trace.probe.mark(stage, None); }
}
pub(crate) fn mark_current(client: &AppClient, stage: Stage) { mark(&current(client), stage); }
pub(crate) fn before_select(client: &AppClient, due: bool, yielded: bool, service: bool) {
    if let Some(trace) = current(client) && trace.matches() {
        trace.probe.progress.lock().expect("ordinary sibling turn trace").due = Some([due, yielded, service]);
        trace.probe.mark(Stage::BeforeSelect, None);
    }
}
pub(crate) struct Routine(Option<Trace>);
impl Routine {
    pub(crate) fn enter(trace: Option<Trace>) -> Self {
        if let Some(trace) = &trace && trace.matches() {
            trace.probe.progress.lock().expect("ordinary sibling turn trace").entered = Some(Instant::now());
            trace.probe.mark(Stage::Enter, None);
        }
        Self(trace)
    }
}
impl Drop for Routine {
    fn drop(&mut self) {
        if let Some(trace) = &self.0 && trace.matches() {
            {
                let mut row = trace.probe.progress.lock().expect("ordinary sibling turn trace");
                let stage = row.point.map(|point| point.0).unwrap_or(Stage::Enter);
                row.returned = row.entered.take().map(|at| (stage, Probe::milliseconds(at.elapsed())));
            }
            trace.probe.mark(Stage::Return, None);
        }
    }
}
pub(crate) struct Advance { trace: Option<Trace>, index: usize }
impl Advance {
    pub(crate) fn enter(trace: Option<Trace>, index: usize) -> Self {
        if let Some(trace) = &trace && trace.matches() { trace.probe.mark(Stage::AdvanceStart, Some(index)); }
        Self { trace, index }
    }
}
impl Drop for Advance {
    fn drop(&mut self) {
        if let Some(trace) = &self.trace && trace.matches() { trace.probe.mark(Stage::AdvanceEnd, Some(self.index)); }
    }
}
