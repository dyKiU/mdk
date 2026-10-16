//! Temporary numeric observations. No keys, signatures, storage or authority.
use std::sync::{
    LazyLock, LockResult,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use std::time::Instant;
const CAPACITY: usize = 16;
const N: usize = 16;
const NAMES: [&str; N] = [
    "attempts",
    "hits",
    "cold_calls",
    "bypass",
    "lookup_poison",
    "insert_poison",
    "insertions",
    "evictions",
    "verifier_ok",
    "verifier_error",
    "cpu_ns",
    "wall_ns",
    "unknown_cpu",
    "cpu_read_failures",
    "active",
    "entries_peak",
];
const GLOBAL_NAMES: [&str; 8] = [
    "calls",
    "ok",
    "error",
    "cpu_ns",
    "wall_ns",
    "unknown_cpu",
    "cpu_read_failures",
    "active",
];
static PHASE: AtomicUsize = AtomicUsize::new(0);
static NEXT: AtomicUsize = AtomicUsize::new(0);
static OVERFLOW: AtomicU64 = AtomicU64::new(0);
static CONFLICTS: AtomicU64 = AtomicU64::new(0);
static ORIGIN: LazyLock<Instant> = LazyLock::new(Instant::now);
struct EngineRecord {
    created_ms: AtomicU64,
    dropped_ms: AtomicU64,
    counts: [[AtomicU64; N]; 3],
}
static ENGINES: LazyLock<[EngineRecord; CAPACITY]> = LazyLock::new(|| {
    std::array::from_fn(|_| EngineRecord {
        created_ms: AtomicU64::new(0),
        dropped_ms: AtomicU64::new(u64::MAX),
        counts: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
    })
});
static GLOBAL: LazyLock<[[AtomicU64; 8]; 3]> =
    LazyLock::new(|| std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))));
static READS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
fn cpu(phase: usize) -> Option<u64> {
    READS[phase].fetch_add(1, Ordering::Relaxed);
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        let mut buffer = [0_u8; 128];
        let count = std::fs::File::open("/proc/thread-self/schedstat")
            .ok()?
            .read(&mut buffer)
            .ok()?;
        std::str::from_utf8(&buffer[..count])
            .ok()?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
struct Timing {
    wall: Instant,
    cpu: Option<u64>,
    phase: usize,
}
impl Timing {
    fn start(phase: usize) -> Self {
        Self {
            cpu: cpu(phase),
            wall: Instant::now(),
            phase,
        }
    }
    fn finish(&self) -> (Option<u64>, u64, u64) {
        let end = cpu(self.phase);
        (
            self.cpu
                .zip(end)
                .and_then(|(start, end)| end.checked_sub(start)),
            self.wall.elapsed().as_nanos() as u64,
            u64::from(self.cpu.is_none()) + u64::from(end.is_none()),
        )
    }
}
/// Fixed observer slot, not a retained Engine or memo entry. No per-call locks.
pub(crate) struct EngineProbe {
    slot: Option<usize>,
}
impl Default for EngineProbe {
    fn default() -> Self {
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let slot = if index < CAPACITY {
            ENGINES[index]
                .created_ms
                .store(ORIGIN.elapsed().as_millis() as u64, Ordering::Relaxed);
            Some(index)
        } else {
            OVERFLOW.fetch_add(1, Ordering::Relaxed);
            None
        };
        Self { slot }
    }
}
impl Drop for EngineProbe {
    fn drop(&mut self) {
        if let Some(slot) = self.slot {
            ENGINES[slot]
                .dropped_ms
                .store(ORIGIN.elapsed().as_millis() as u64, Ordering::Relaxed);
        }
    }
}
impl EngineProbe {
    pub(crate) fn event(&self, index: usize) {
        if let Some(slot) = self.slot {
            ENGINES[slot].counts[PHASE.load(Ordering::Acquire)][index]
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub(crate) fn peak(&self, entries: usize) {
        if let Some(slot) = self.slot {
            ENGINES[slot].counts[PHASE.load(Ordering::Acquire)][15]
                .fetch_max(entries as u64, Ordering::Relaxed);
        }
    }
    pub(crate) fn verifier(&self) -> Span {
        Span::new(self.slot, false)
    }
}
pub(crate) fn observe_lock<T>(
    result: LockResult<T>,
    probe: &EngineProbe,
    lookup: bool,
) -> LockResult<T> {
    if result.is_err() {
        probe.event(if lookup { 4 } else { 5 });
    }
    result
}
pub(crate) struct Span {
    slot: Option<usize>,
    global: bool,
    phase: usize,
    timing: Option<Timing>,
    ok: bool,
}
impl Span {
    fn new(slot: Option<usize>, global: bool) -> Self {
        let phase = PHASE.load(Ordering::Acquire);
        if global {
            GLOBAL[phase][0].fetch_add(1, Ordering::Relaxed);
            if phase != 0 {
                GLOBAL[phase][7].fetch_add(1, Ordering::Relaxed);
            }
        } else if let Some(slot) = slot {
            ENGINES[slot].counts[phase][2].fetch_add(1, Ordering::Relaxed);
            if phase != 0 {
                ENGINES[slot].counts[phase][14].fetch_add(1, Ordering::Relaxed);
            }
        }
        Self {
            slot,
            global,
            phase,
            timing: (phase != 0).then(|| Timing::start(phase)),
            ok: false,
        }
    }
    pub(crate) fn success(&mut self) {
        self.ok = true;
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        let measured = self.timing.as_ref().map(Timing::finish);
        if PHASE.load(Ordering::Acquire) != self.phase {
            CONFLICTS.fetch_add(1, Ordering::Relaxed);
        }
        if self.global {
            let row = &GLOBAL[self.phase];
            row[if self.ok { 1 } else { 2 }].fetch_add(1, Ordering::Relaxed);
            if let Some((cpu, wall, failed)) = measured {
                row[3].fetch_add(cpu.unwrap_or(0), Ordering::Relaxed);
                row[4].fetch_add(wall, Ordering::Relaxed);
                row[5].fetch_add(u64::from(cpu.is_none()), Ordering::Relaxed);
                row[6].fetch_add(failed, Ordering::Relaxed);
                row[7].fetch_sub(1, Ordering::Relaxed);
            }
        } else if let Some(slot) = self.slot {
            let row = &ENGINES[slot].counts[self.phase];
            row[if self.ok { 8 } else { 9 }].fetch_add(1, Ordering::Relaxed);
            if let Some((cpu, wall, failed)) = measured {
                row[10].fetch_add(cpu.unwrap_or(0), Ordering::Relaxed);
                row[11].fetch_add(wall, Ordering::Relaxed);
                row[12].fetch_add(u64::from(cpu.is_none()), Ordering::Relaxed);
                row[13].fetch_add(failed, Ordering::Relaxed);
                row[14].fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}
pub(crate) fn cold_verifier_span() -> Span {
    Span::new(None, true)
}
/// Drops on original assertion unwind; no new polling or service calls.
pub struct PhaseGuard {
    start_us: u64,
    phase: usize,
    timing: Timing,
    completed: bool,
}
impl PhaseGuard {
    pub fn begin(phase: usize) -> Self {
        assert!(phase == 1 || phase == 2);
        if PHASE.swap(phase, Ordering::AcqRel) != 0 {
            CONFLICTS.fetch_add(1, Ordering::Relaxed);
        }
        Self {
            phase,
            timing: Timing::start(phase),
            start_us: elapsed_us(),
            completed: false,
        }
    }
    pub fn completed(&mut self) {
        self.completed = true;
    }
}
impl Drop for PhaseGuard {
    fn drop(&mut self) {
        let (cpu, wall, read_failures) = self.timing.finish();
        PHASE.store(0, Ordering::Release);
        let rows: Vec<_> = ENGINES.iter().take(NEXT.load(Ordering::Relaxed).min(CAPACITY)).enumerate().map(|(ordinal, entry)| {
            let dropped = entry.dropped_ms.load(Ordering::Relaxed);
            serde_json::json!({"ordinal":ordinal, "created_ms_since_first_registration":entry.created_ms.load(Ordering::Relaxed), "dropped_ms_since_first_registration":if dropped == u64::MAX { None } else { Some(dropped) }, "alive_at_snapshot":dropped == u64::MAX, "counts":entry.counts[self.phase].iter().map(|value| value.load(Ordering::Relaxed)).collect::<Vec<_>>(), "outside_counts":entry.counts[0].iter().map(|value| value.load(Ordering::Relaxed)).collect::<Vec<_>>()})
        }).collect();
        let output = serde_json::json!({"phase":if self.phase == 1 {"third"} else {"fourth"}, "completion_success_marker":self.completed, "panicking":std::thread::panicking(), "phase_cpu_ns":cpu, "phase_start_us":self.start_us,"phase_wall_ns":wall, "phase_cpu_read_failures":read_failures, "observer_cpu_reads":READS[self.phase].load(Ordering::Relaxed), "engine_capacity":CAPACITY, "engine_overflow":OVERFLOW.load(Ordering::Relaxed), "phase_conflicts":CONFLICTS.load(Ordering::Relaxed), "counter_names":NAMES, "global_names":GLOBAL_NAMES, "global":GLOBAL[self.phase].iter().map(|value| value.load(Ordering::Relaxed)).collect::<Vec<_>>(), "engines":rows, "cpu_resolution":"unknown; zero deltas may be quantized", "cpu_scope":"scheduled current thread shared across actors; synchronous verifier spans inclusive and nested", "observer_overhead":"relaxed atomics and two schedstat reads per timed span; no per-call registry mutex, allocation or logging"});
        eprintln!("proof-memo-cost-diagnostic {output}");
        let costs = serde_json::json!({"phase":if self.phase==1 {"third"}else{"fourth"},"names":COST_NAMES,"counters":["calls","cpu_ns","wall_ns","unknown_cpu","read_failures","active"],"rows":COSTS[self.phase].iter().map(|row|row.iter().map(|v|v.load(Ordering::Relaxed)).collect::<Vec<_>>()).collect::<Vec<_>>()});
        eprintln!("proof-partition-diagnostic {costs}");
    }
}

/// Temporary fixed synchronous buckets. All nested durations are nonadditive.
const COST_NAMES: [&str; 11] = [
    "roster",
    "successor",
    "candidate",
    "fresh-mls-load",
    "completed",
    "round-read",
    "facts-read",
    "tree-origin",
    "leaf-loop",
    "sharing",
    "sharing-signature-encoding",
];
static COSTS: LazyLock<[[[AtomicU64; 6]; 11]; 3]> = LazyLock::new(|| {
    std::array::from_fn(|_| std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))))
});
pub struct CostSpan {
    phase: usize,
    bucket: usize,
    timing: Option<Timing>,
}
impl CostSpan {
    pub fn begin(bucket: usize) -> Self {
        let phase = PHASE.load(Ordering::Acquire);
        if phase != 0 {
            COSTS[phase][bucket][0].fetch_add(1, Ordering::Relaxed);
            COSTS[phase][bucket][5].fetch_add(1, Ordering::Relaxed);
        }
        Self {
            phase,
            bucket,
            timing: (phase != 0).then(|| Timing::start(phase)),
        }
    }
}
impl Drop for CostSpan {
    fn drop(&mut self) {
        if let Some(timing) = &self.timing {
            let (cpu, wall, failed) = timing.finish();
            let row = &COSTS[self.phase][self.bucket];
            row[1].fetch_add(cpu.unwrap_or(0), Ordering::Relaxed);
            row[2].fetch_add(wall, Ordering::Relaxed);
            row[3].fetch_add(u64::from(cpu.is_none()), Ordering::Relaxed);
            row[4].fetch_add(failed, Ordering::Relaxed);
            row[5].fetch_sub(1, Ordering::Relaxed);
            if PHASE.load(Ordering::Acquire) != self.phase {
                CONFLICTS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
/// Numeric-only bounded publication generations; never stores event/owner identity.
#[derive(Clone, Copy, Default)]
struct TaskRecord {
    kind: u64,
    scheduled: u64,
    started: u64,
    exited: u64,
    outcome: u64,
    visits: u64,
    last_visit: u64,
    finished: u64,
    harvested: u64,
}
static PUBLICATION_NEXT: AtomicU64 = AtomicU64::new(0);
pub struct PublicationProbe {
    ordinal: u64,
    inner: std::sync::Mutex<PublicationRecords>,
}
struct PublicationRecords {
    count: usize,
    overflow: u64,
    rows: [TaskRecord; 32],
}
impl Default for PublicationProbe {
    fn default() -> Self {
        Self {
            ordinal: PUBLICATION_NEXT.fetch_add(1, Ordering::Relaxed),
            inner: std::sync::Mutex::new(PublicationRecords {
                count: 0,
                overflow: 0,
                rows: [TaskRecord::default(); 32],
            }),
        }
    }
}
fn elapsed_us() -> u64 {
    ORIGIN.elapsed().as_micros() as u64
}
impl PublicationProbe {
    pub fn schedule(&self, kind: u64) -> usize {
        let mut inner = self.inner.lock().expect("numeric publication observer");
        if inner.count == 32 {
            inner.overflow += 1;
            return 32;
        }
        let index = inner.count;
        inner.count += 1;
        inner.rows[index] = TaskRecord {
            kind,
            scheduled: elapsed_us(),
            ..TaskRecord::default()
        };
        index
    }
    fn update(&self, index: usize, operation: impl FnOnce(&mut TaskRecord)) {
        if index < 32 {
            operation(
                &mut self
                    .inner
                    .lock()
                    .expect("numeric publication observer")
                    .rows[index],
            );
        }
    }
    pub fn task(&self, index: usize) -> PublicationTask<'_> {
        self.update(index, |row| row.started = elapsed_us());
        PublicationTask {
            probe: self,
            index,
            finished: false,
        }
    }
    pub fn visit(&self, index: usize, finished: bool) {
        self.update(index, |row| {
            row.visits += 1;
            row.last_visit = elapsed_us();
            row.finished = u64::from(finished);
        });
    }
    pub fn harvest(&self, index: usize) {
        self.update(index, |row| row.harvested = elapsed_us());
    }
    pub fn dump(&self) {
        let inner = self.inner.lock().expect("numeric publication observer");
        let now = elapsed_us();
        let rows: Vec<_> = inner.rows[..inner.count]
            .iter()
            .enumerate()
            .map(|(generation, row)| {
                [
                    generation as u64,
                    row.kind,
                    row.scheduled,
                    row.started,
                    row.exited,
                    row.outcome,
                    row.visits,
                    row.last_visit,
                    row.finished,
                    row.harvested,
                    if row.exited > 0 && row.harvested == 0 {
                        now.saturating_sub(row.exited)
                    } else {
                        0
                    },
                ]
            })
            .collect();
        let output = serde_json::json!({"state_ordinal":self.ordinal,"snapshot_us":now,"capacity":32,"overflow":inner.overflow,"rows":rows});
        eprintln!("proof-publication-diagnostic {output}");
    }
}
pub struct PublicationTask<'a> {
    probe: &'a PublicationProbe,
    index: usize,
    finished: bool,
}
impl PublicationTask<'_> {
    pub fn finish(&mut self, success: bool) {
        self.probe.update(self.index, |row| {
            row.exited = elapsed_us();
            row.outcome = if success { 1 } else { 2 };
        });
        self.finished = true;
    }
}
impl Drop for PublicationTask<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.probe.update(self.index, |row| {
                row.exited = elapsed_us();
                row.outcome = 3;
            });
        }
    }
}
