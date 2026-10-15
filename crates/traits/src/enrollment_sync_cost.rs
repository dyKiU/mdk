//! Bounded test-policy diagnostics for synchronous enrollment work only.
//! Nested bucket times are inclusive and must never be added together.
use std::sync::{
    Mutex,
    atomic::{AtomicU8, Ordering},
};
use std::time::Instant;

const COUNT: usize = 23;
const NAMES: [&str; COUNT] = [
    "roster",
    "successor",
    "candidate",
    "completed",
    "completed-round-sql",
    "completed-record-sql",
    "completed-facts-sql",
    "completed-facts-check",
    "completed-tree-origin",
    "completed-leaf-proof",
    "sharing-verify",
    "sharing-decode",
    "sharing-roster",
    "sharing-context",
    "sharing-ed25519",
    "sql-state-query",
    "sql-state-decode",
    "sql-state-validate",
    "sql-read-consistency",
    "sql-facts-whole",
    "sql-facts-query-setup",
    "sql-fact-decode",
    "sql-fact-validate",
];
static PHASE: AtomicU8 = AtomicU8::new(0);
static TOTALS: Mutex<[[Totals; COUNT]; 2]> = Mutex::new([[Totals::EMPTY; COUNT]; 2]);

#[derive(Clone, Copy)]
struct Totals {
    count: u64,
    byte_observations: u64,
    bytes_total: u64,
    max_bytes: u64,
    cpu_ns: u64,
    wall_ns: u64,
    unknown_cpu: u64,
    cpu_reads: u64,
    cpu_read_failures: u64,
    active: u64,
    max_cpu_ns: u64,
    max_wall_ns: u64,
}
impl Totals {
    const EMPTY: Self = Self {
        count: 0,
        byte_observations: 0,
        bytes_total: 0,
        max_bytes: 0,
        cpu_ns: 0,
        wall_ns: 0,
        unknown_cpu: 0,
        cpu_reads: 0,
        cpu_read_failures: 0,
        active: 0,
        max_cpu_ns: 0,
        max_wall_ns: 0,
    };
}

pub enum Bucket {
    Roster,
    Successor,
    Candidate,
    Completed,
    CompletedRoundSql,
    CompletedRecordSql,
    CompletedFactsSql,
    CompletedFactsCheck,
    CompletedTreeOrigin,
    CompletedLeafProof,
    SharingVerify,
    SharingDecode,
    SharingRoster,
    SharingContext,
    SharingEd25519,
    SqlStateQuery,
    SqlStateDecode,
    SqlStateValidate,
    SqlReadConsistency,
    SqlFactsWhole,
    SqlFactsQuerySetup,
    SqlFactDecode,
    SqlFactValidate,
}
#[derive(Clone, Copy)]
pub enum Phase {
    Third,
    Fourth,
}

fn cpu_ns() -> Option<u64> {
    // No await: this is the calling thread's scheduled CPU, not elapsed time
    // attributed across another actor's execution. Reads add probe overhead.
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/thread-self/schedstat")
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

/// Blob sizes only; bytes themselves never leave the original local read.
pub fn record_bytes(bucket: Bucket, size: usize) {
    let phase = PHASE.load(Ordering::Relaxed);
    if !(1..=2).contains(&phase) { return; }
    let mut totals = TOTALS.lock().unwrap_or_else(|error| error.into_inner());
    let item = &mut totals[usize::from(phase - 1)][bucket as usize];
    let size = u64::try_from(size).unwrap_or(u64::MAX);
    item.byte_observations = item.byte_observations.saturating_add(1);
    item.bytes_total = item.bytes_total.saturating_add(size);
    item.max_bytes = item.max_bytes.max(size);
}

pub struct Probe {
    enabled: Option<(usize, usize, Instant, Option<u64>)>,
}
impl Probe {
    pub fn start(bucket: Bucket) -> Self {
        let phase = PHASE.load(Ordering::Relaxed);
        if !(1..=2).contains(&phase) {
            return Self { enabled: None };
        }
        let phase = usize::from(phase - 1);
        let bucket = bucket as usize;
        let wall = Instant::now();
        let cpu = cpu_ns();
        let mut totals = TOTALS.lock().unwrap_or_else(|error| error.into_inner());
        totals[phase][bucket].active += 1;
        Self {
            enabled: Some((phase, bucket, wall, cpu)),
        }
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        let Some((phase, bucket, wall, before)) = self.enabled else {
            return;
        };
        let after = cpu_ns();
        let wall = u64::try_from(wall.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let cpu = before
            .zip(after)
            .and_then(|(before, after)| after.checked_sub(before));
        let mut totals = TOTALS.lock().unwrap_or_else(|error| error.into_inner());
        let item = &mut totals[phase][bucket];
        item.active = item.active.saturating_sub(1);
        item.count = item.count.saturating_add(1);
        item.cpu_reads = item.cpu_reads.saturating_add(2);
        item.cpu_read_failures = item
            .cpu_read_failures
            .saturating_add(u64::from(before.is_none()) + u64::from(after.is_none()));
        item.wall_ns = item.wall_ns.saturating_add(wall);
        item.max_wall_ns = item.max_wall_ns.max(wall);
        if let Some(cpu) = cpu {
            item.cpu_ns = item.cpu_ns.saturating_add(cpu);
            item.max_cpu_ns = item.max_cpu_ns.max(cpu);
        } else {
            item.unknown_cpu = item.unknown_cpu.saturating_add(1);
        }
    }
}

pub struct PhaseGuard {
    phase: usize,
    arm_conflict: bool,
}
impl PhaseGuard {
    pub fn begin(phase: Phase) -> Self {
        let phase = match phase {
            Phase::Third => 0,
            Phase::Fourth => 1,
        };
        let mut totals = TOTALS.lock().unwrap_or_else(|error| error.into_inner());
        totals[phase] = [Totals::EMPTY; COUNT];
        let old = PHASE.swap((phase + 1) as u8, Ordering::Relaxed);
        Self {
            phase,
            arm_conflict: old != 0,
        }
    }
}
impl Drop for PhaseGuard {
    fn drop(&mut self) {
        PHASE.store(0, Ordering::Relaxed);
        let totals = *TOTALS.lock().unwrap_or_else(|error| error.into_inner());
        let phase = if self.phase == 0 { "third" } else { "fourth" };
        eprintln!(
            "enrollment-sync-cost-boundary phase={phase} arm_conflict={} panicking={}",
            self.arm_conflict,
            std::thread::panicking()
        );
        for (index, item) in totals[self.phase].iter().enumerate() {
            let bucket = NAMES[index];
            eprintln!(
                "enrollment-sync-cost phase={phase} bucket={bucket} count={} cpu_ns={} wall_ns={} unknown_cpu={} cpu_reads={} cpu_read_failures={} active={} max_cpu_ns={} max_wall_ns={} byte_observations={} bytes_total={} max_bytes={}",
                item.count,
                item.cpu_ns,
                item.wall_ns,
                item.unknown_cpu,
                item.cpu_reads,
                item.cpu_read_failures,
                item.active,
                item.max_cpu_ns,
                item.max_wall_ns,
                item.byte_observations,
                item.bytes_total,
                item.max_bytes
            );
        }
    }
}
