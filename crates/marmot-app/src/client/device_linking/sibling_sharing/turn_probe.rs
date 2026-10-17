//! Optional exact-original passive diagnostics. No scheduling or authority changes.
use super::*;
use std::sync::Weak;

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub(crate) enum Stage {
    WorkerLoop,
    BeforeSelect,
    Enter,
    OpaqueStart,
    OpaqueDone,
    PendingStart,
    PendingDone,
    BeginStart,
    BeginDone,
    LoopStart,
    AdvanceStart,
    AdvanceEnd,
    Return,
    ChildAdded,
}
const LIMIT: u64 = 1_000_000_000;
pub(crate) type Snapshot = (
    [u64; 14],
    [Option<u64>; 14],
    Option<(Stage, Option<usize>, u64)>,
    Option<(Stage, u64)>,
    Option<[bool; 3]>,
    bool,
    u64,
);
pub(crate) type TimerSnapshot = (
    [u64; 3],
    [Option<u64>; 3],
    Option<(bool, u64)>,
    Option<bool>,
    Option<[bool; 2]>,
    [u64; 2],
    [u64; 2],
    u64,
    Option<bool>,
);
#[derive(Default)]
struct TimerProgress {
    counts: [u64; 3],
    times: [Option<u64>; 3],
    scheduled_vs_observed: Option<(bool, u64)>,
    stopping: Option<bool>,
    last_budget: Option<[bool; 2]>,
    overdue_pending: [u64; 2],
    maximum_overdue_ms: [u64; 2],
    maximum_poll_gap_ms: u64,
    last_pending_overdue: Option<bool>,
    last_poll: Option<tokio::time::Instant>,
}
struct Progress {
    counts: [u64; 14],
    times: [Option<u64>; 14],
    point: Option<(Stage, Option<usize>, Instant)>,
    returned: Option<(Stage, u64)>,
    due: Option<[bool; 3]>,
    entered: Option<Instant>,
}
pub(crate) struct Probe {
    origin: Instant,
    progress: Mutex<Progress>,
    timer: Mutex<TimerProgress>,
}
impl Probe {
    pub(crate) fn enabled() -> Option<Arc<Self>> {
        (std::env::var_os("WN_ORDINARY_SIBLING_TURN_TRACE").as_deref()
            == Some(std::ffi::OsStr::new("1")))
        .then(|| {
            Arc::new(Self {
                origin: Instant::now(),
                timer: Mutex::default(),
                progress: Mutex::new(Progress {
                    counts: [0; 14],
                    times: [None; 14],
                    point: None,
                    returned: None,
                    due: None,
                    entered: None,
                }),
            })
        })
    }
    fn milliseconds(duration: std::time::Duration) -> u64 {
        duration.as_millis().min(u128::from(LIMIT)) as u64
    }
    pub(crate) fn mark(&self, stage: Stage, index: Option<usize>) {
        let now = Instant::now();
        let mut row = self.progress.lock().expect("ordinary sibling turn trace");
        let slot = stage as usize;
        row.counts[slot] = row.counts[slot].saturating_add(1).min(LIMIT);
        row.times[slot] = Some(Self::milliseconds(now.duration_since(self.origin)));
        if !matches!(stage, Stage::ChildAdded) {
            row.point = Some((stage, index.filter(|value| *value < 128), now));
        }
    }
    pub(crate) fn timer_snapshot(&self) -> TimerSnapshot {
        let row = self.timer.lock().expect("ordinary sibling timer trace");
        (
            row.counts,
            row.times,
            row.scheduled_vs_observed,
            row.stopping,
            row.last_budget,
            row.overdue_pending,
            row.maximum_overdue_ms,
            row.maximum_poll_gap_ms,
            row.last_pending_overdue,
        )
    }
    pub(crate) fn snapshot(&self) -> Snapshot {
        let row = self.progress.lock().expect("ordinary sibling turn trace");
        (
            row.counts,
            row.times,
            row.point
                .map(|(stage, index, at)| (stage, index, Self::milliseconds(at.elapsed()))),
            row.returned,
            row.due,
            row.entered.is_some(),
            Self::milliseconds(self.origin.elapsed()),
        )
    }
}
#[derive(Clone)]
pub(crate) struct Trace {
    owner: Weak<OriginalEnrollmentSharingChoice>,
    probe: Arc<Probe>,
}
impl Trace {
    fn matches(&self) -> bool {
        self.owner.upgrade().is_some_and(|owner| {
            owner
                .turn_probe
                .as_ref()
                .is_some_and(|probe| Arc::ptr_eq(probe, &self.probe))
        })
    }
}
pub(crate) fn current(client: &AppClient) -> Option<Trace> {
    let owner = client.linking_owner.sharing_approval.as_ref()?;
    Some(Trace {
        owner: Arc::downgrade(owner),
        probe: owner.turn_probe.clone()?,
    })
}
pub(crate) fn mark(trace: &Option<Trace>, stage: Stage) {
    if let Some(trace) = trace
        && trace.matches()
    {
        trace.probe.mark(stage, None);
    }
}
pub(crate) fn mark_current(client: &AppClient, stage: Stage) {
    mark(&current(client), stage);
}
pub(crate) fn before_select(client: &AppClient, due: bool, yielded: bool, service: bool) {
    if let Some(trace) = current(client)
        && trace.matches()
    {
        trace
            .probe
            .progress
            .lock()
            .expect("ordinary sibling turn trace")
            .due = Some([due, yielded, service]);
        trace.probe.mark(Stage::BeforeSelect, None);
    }
}
pub(crate) struct Routine(Option<Trace>);
impl Routine {
    pub(crate) fn enter(trace: Option<Trace>) -> Self {
        if let Some(trace) = &trace
            && trace.matches()
        {
            trace
                .probe
                .progress
                .lock()
                .expect("ordinary sibling turn trace")
                .entered = Some(Instant::now());
            trace.probe.mark(Stage::Enter, None);
        }
        Self(trace)
    }
}
impl Drop for Routine {
    fn drop(&mut self) {
        if let Some(trace) = &self.0
            && trace.matches()
        {
            {
                let mut row = trace
                    .probe
                    .progress
                    .lock()
                    .expect("ordinary sibling turn trace");
                let stage = row.point.map(|point| point.0).unwrap_or(Stage::Enter);
                row.returned = row
                    .entered
                    .take()
                    .map(|at| (stage, Probe::milliseconds(at.elapsed())));
            }
            trace.probe.mark(Stage::Return, None);
        }
    }
}
pub(crate) struct Advance {
    trace: Option<Trace>,
    index: usize,
}
impl Advance {
    pub(crate) fn enter(trace: Option<Trace>, index: usize) -> Self {
        if let Some(trace) = &trace
            && trace.matches()
        {
            trace.probe.mark(Stage::AdvanceStart, Some(index));
        }
        Self { trace, index }
    }
}
impl Drop for Advance {
    fn drop(&mut self) {
        if let Some(trace) = &self.trace
            && trace.matches()
        {
            trace.probe.mark(Stage::AdvanceEnd, Some(self.index));
        }
    }
}

// This adapter preserves the real Interval and delegates each poll exactly once.
// Its optional Trace owns only a Weak original and the numeric probe.
pub(crate) struct ObservedInterval {
    inner: tokio::time::Interval,
    trace: Option<Trace>,
    next_deadline_not_after: Option<tokio::time::Instant>,
}
impl ObservedInterval {
    pub(crate) fn new(inner: tokio::time::Interval) -> Self {
        Self {
            inner,
            trace: None,
            next_deadline_not_after: None,
        }
    }
    pub(crate) fn observe(&mut self, trace: Option<Trace>, stopping: bool) {
        self.trace = trace;
        if let Some(trace) = &self.trace
            && trace.matches()
        {
            trace
                .probe
                .timer
                .lock()
                .expect("ordinary sibling timer trace")
                .stopping = Some(stopping);
        }
    }
    pub(crate) async fn tick(&mut self) -> tokio::time::Instant {
        let trace = self.trace.clone();
        let period = self.inner.period();
        let deadline_bound = &mut self.next_deadline_not_after;
        let tick = self.inner.tick();
        let mut tick = std::pin::pin!(tick);
        std::future::poll_fn(|cx| {
            let before = tokio::task::coop::has_budget_remaining();
            let result = std::future::Future::poll(tick.as_mut(), cx);
            let after = tokio::task::coop::has_budget_remaining();
            let observed = tokio::time::Instant::now();
            let overdue =
                (*deadline_bound).and_then(|bound| observed.checked_duration_since(bound));
            if result.is_ready() {
                // Delay never rearms later than observation + period. This
                // observation does not register, reset, or otherwise drive it.
                *deadline_bound = Some(observed + period);
            }
            if let Some(trace) = &trace
                && trace.matches()
            {
                let elapsed = Probe::milliseconds(trace.probe.origin.elapsed());
                let mut row = trace
                    .probe
                    .timer
                    .lock()
                    .expect("ordinary sibling timer trace");
                row.last_budget = Some([before, after]);
                if let Some(previous) = row.last_poll {
                    row.maximum_poll_gap_ms = row
                        .maximum_poll_gap_ms
                        .max(Probe::milliseconds(observed.duration_since(previous)));
                }
                row.last_poll = Some(observed);
                if result.is_pending() {
                    row.last_pending_overdue = (*deadline_bound).map(|_| overdue.is_some());
                    if let Some(lateness) = overdue {
                        let category = usize::from(before);
                        row.overdue_pending[category] =
                            row.overdue_pending[category].saturating_add(1).min(LIMIT);
                        row.maximum_overdue_ms[category] =
                            row.maximum_overdue_ms[category].max(Probe::milliseconds(lateness));
                    }
                }
                row.counts[0] = row.counts[0].saturating_add(1).min(LIMIT);
                row.times[0] = Some(elapsed);
                let slot = if let std::task::Poll::Ready(scheduled) = &result {
                    let now = tokio::time::Instant::now();
                    let (late, difference) =
                        if let Some(lag) = now.checked_duration_since(*scheduled) {
                            (true, lag)
                        } else {
                            (false, scheduled.duration_since(now))
                        };
                    row.scheduled_vs_observed = Some((late, Probe::milliseconds(difference)));
                    2
                } else {
                    1
                };
                row.counts[slot] = row.counts[slot].saturating_add(1).min(LIMIT);
                row.times[slot] = Some(elapsed);
            }
            result
        })
        .await
    }
}
