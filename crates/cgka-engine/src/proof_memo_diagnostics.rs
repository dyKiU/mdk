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
        let output = serde_json::json!({"phase":if self.phase == 1 {"third"} else {"fourth"}, "completion_success_marker":self.completed, "panicking":std::thread::panicking(), "phase_cpu_ns":cpu, "phase_wall_ns":wall, "phase_cpu_read_failures":read_failures, "observer_cpu_reads":READS[self.phase].load(Ordering::Relaxed), "engine_capacity":CAPACITY, "engine_overflow":OVERFLOW.load(Ordering::Relaxed), "phase_conflicts":CONFLICTS.load(Ordering::Relaxed), "counter_names":NAMES, "global_names":GLOBAL_NAMES, "global":GLOBAL[self.phase].iter().map(|value| value.load(Ordering::Relaxed)).collect::<Vec<_>>(), "engines":rows, "cpu_resolution":"unknown; zero deltas may be quantized", "cpu_scope":"scheduled current thread shared across actors; synchronous verifier spans inclusive and nested", "observer_overhead":"relaxed atomics and two schedstat reads per timed span; no per-call registry mutex, allocation or logging"});
        eprintln!("proof-memo-cost-diagnostic {output}");
    }
}
