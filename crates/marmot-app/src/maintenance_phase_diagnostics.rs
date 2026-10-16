//! Test-only aggregate synchronous poll observations; never protocol inputs.
use std::time::Instant;
const WORKER_LIMIT: usize = 16;
static POLL_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static ACTIVE_POLLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LOAD_UNKNOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
// completed, sum_ns, max_ns, active_epoch, window_completed, window_sum_ns,
// window_max_ns, straddling_completed, unwound_polls. Numeric slots are not roles.
static WORKER_POLLS: std::sync::Mutex<Vec<[u64; 9]>> = std::sync::Mutex::new(Vec::new());
fn load_time() -> Option<u64> {
    static ORIGIN: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    ORIGIN
        .get_or_init(Instant::now)
        .elapsed()
        .as_nanos()
        .try_into()
        .ok()
}
fn add(value: &mut u64, amount: u64) {
    if let Some(next) = value.checked_add(amount) {
        *value = next;
    } else {
        LOAD_UNKNOWN.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}
fn record_poll(slot: Option<usize>, entry_epoch: u64, elapsed: Option<u64>) {
    use std::sync::atomic::Ordering;
    let Some(slot) = slot else {
        LOAD_UNKNOWN.store(true, Ordering::Relaxed);
        return;
    };
    let Ok(mut rows) = WORKER_POLLS.lock() else {
        LOAD_UNKNOWN.store(true, Ordering::Relaxed);
        return;
    };
    let Some(row) = rows.get_mut(slot) else {
        LOAD_UNKNOWN.store(true, Ordering::Relaxed);
        return;
    };
    record_row(row, entry_epoch, elapsed);
}
fn record_row(row: &mut [u64; 9], entry_epoch: u64, elapsed: Option<u64>) {
    use std::sync::atomic::Ordering;
    let Some(elapsed) = elapsed else {
        add(&mut row[8], 1);
        LOAD_UNKNOWN.store(true, Ordering::Relaxed);
        return;
    };
    add(&mut row[0], 1);
    add(&mut row[1], elapsed);
    row[2] = row[2].max(elapsed);
    let exit_epoch = POLL_EPOCH.load(Ordering::SeqCst);
    if entry_epoch % 2 == 1 && entry_epoch == exit_epoch {
        if row[3] != entry_epoch {
            row[3] = entry_epoch;
            row[4..7].fill(0);
        }
        add(&mut row[4], 1);
        add(&mut row[5], elapsed);
        row[6] = row[6].max(elapsed);
    } else if entry_epoch != exit_epoch {
        add(&mut row[7], 1);
    }
}
struct PollObservation {
    slot: Option<usize>,
    epoch: u64,
    returned: bool,
}
impl Drop for PollObservation {
    fn drop(&mut self) {
        if !self.returned {
            record_poll(self.slot, self.epoch, None);
        }
        ACTIVE_POLLS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
pub(crate) fn observe_worker<F: std::future::Future>(
    mut future: std::pin::Pin<Box<F>>,
) -> impl std::future::Future<Output = F::Output> {
    use std::sync::atomic::Ordering;
    let slot = match WORKER_POLLS.lock() {
        Ok(mut rows) if rows.len() < WORKER_LIMIT => {
            rows.push([0; 9]);
            Some(rows.len() - 1)
        }
        _ => {
            LOAD_UNKNOWN.store(true, Ordering::Relaxed);
            None
        }
    };
    std::future::poll_fn(move |context| {
        ACTIVE_POLLS.fetch_add(1, Ordering::SeqCst);
        let mut observation = PollObservation {
            slot,
            epoch: POLL_EPOCH.load(Ordering::SeqCst),
            returned: false,
        };
        let start = Instant::now();
        let result = future.as_mut().poll(context);
        let elapsed = start.elapsed().as_nanos().try_into().ok();
        observation.returned = true;
        record_poll(slot, observation.epoch, elapsed);
        result
    })
}
fn parse_thread_cpu_fields(bytes: &[u8]) -> Option<[u64; 2]> {
    if bytes.is_empty() || bytes.len() > 4096 || bytes.last() != Some(&b'\n') {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let end = text.rfind(')')?;
    let (process, _) = text[..end].split_once(" (")?;
    if process.is_empty()
        || !process.bytes().all(|byte| byte.is_ascii_digit())
        || text[..text.len() - 1].contains('\n')
    {
        return None;
    }
    let rest = text.get(end + 1..)?.strip_prefix(' ')?;
    let mut fields = rest.split_whitespace();
    let state = fields.next()?;
    if state.len() != 1 || !b"RSDZTWtXxKPI".contains(state.as_bytes().first()?) {
        return None;
    }
    // Remaining iterator starts at field 4. utime/stime are fields 14/15.
    let user = fields.nth(10)?.parse::<u64>().ok()?;
    let system = fields.next()?.parse::<u64>().ok()?;
    if fields.count() < 37 {
        return None;
    }
    user.checked_add(system)?;
    Some([user, system])
}
fn thread_cpu_ticks() -> Option<[u64; 2]> {
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        let mut bytes = Vec::with_capacity(4097);
        std::fs::File::open("/proc/thread-self/stat")
            .ok()?
            .take(4097)
            .read_to_end(&mut bytes)
            .ok()?;
        parse_thread_cpu_fields(&bytes)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
fn load_boundary(start: bool) -> serde_json::Value {
    use std::sync::atomic::Ordering;
    let cpu = thread_cpu_ticks();
    let wall = load_time();
    let previous = POLL_EPOCH.fetch_add(1, Ordering::SeqCst);
    let epoch = if start { previous + 1 } else { previous };
    let (rows, active) = match WORKER_POLLS.lock() {
        Ok(rows) => (Some(rows.clone()), ACTIVE_POLLS.load(Ordering::SeqCst)),
        Err(_) => (None, ACTIVE_POLLS.load(Ordering::SeqCst)),
    };
    if rows.is_none() {
        LOAD_UNKNOWN.store(true, Ordering::Relaxed);
    }
    let phases = match PHASE_POLLS.lock() {
        Ok(rows) => Some(*rows),
        Err(_) => {
            LOAD_UNKNOWN.store(true, Ordering::Relaxed);
            None
        }
    };
    let active_phases: Vec<_> = ACTIVE_PHASES
        .iter()
        .map(|active| active.load(Ordering::SeqCst))
        .collect();
    serde_json::json!({"boundary":if start {"start"} else {"end"}, "epoch":epoch,
        "wall_ns":wall, "thread_cpu_ticks":cpu, "active_polls":active,
        "unknown":LOAD_UNKNOWN.load(Ordering::Relaxed), "workers":rows, "phases":phases, "active_phases":active_phases})
}

#[test]
fn maintenance_phase_cpu_stat_parser_refuses_unqualified_fields() {
    let sample = |user: &str, system: &str| {
        format!(
            "17 (worker ) name) R {}{user} {system} {}\n",
            "0 ".repeat(10),
            "0 ".repeat(37)
        )
    };
    assert_eq!(
        parse_thread_cpu_fields(sample("12", "3").as_bytes()),
        Some([12, 3])
    );
    assert_eq!(
        parse_thread_cpu_fields(sample("0", "0").as_bytes()),
        Some([0, 0])
    );
    let mut invalid = vec![
        Vec::new(),
        b"bad\n".to_vec(),
        vec![b'x'; 4097],
        b"17 (x) R 0\n".to_vec(),
        vec![255, b'\n'],
    ];
    invalid.extend(
        [
            sample("-1", "0"),
            sample("x", "0"),
            sample("0", "-1"),
            sample("18446744073709551615", "1"),
            sample("18446744073709551616", "0"),
            sample("0", "0").trim_end().to_owned(),
            sample("0", "0").replace(") R ", ") ? "),
        ]
        .into_iter()
        .map(String::into_bytes),
    );
    invalid.extend(
        [
            sample("0", "0").replacen("17 (", "bad (", 1),
            format!("17 (x) R {}0 0\n", "0 ".repeat(10)),
        ]
        .into_iter()
        .map(String::into_bytes),
    );
    for input in &invalid {
        assert_eq!(parse_thread_cpu_fields(input), None);
    }
    eprintln!(
        "maintenance-phase-cpu-parser positive=2 negative={}",
        invalid.len()
    );
}

// Phase0 selected packages + pending;1 revocation;2 original history;
//3 existing pair + approval persistence;4 siblings;5 automatic;6 housekeeping.
//7..16 observe existing worker future subtrees; nested measurements are inclusive/nonadditive.
static PHASE_POLLS: std::sync::Mutex<[[u64; 9]; 18]> = std::sync::Mutex::new([[0; 9]; 18]);
static ACTIVE_PHASES: [std::sync::atomic::AtomicU64; 18] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 18];
struct PhaseObservation {
    phase: usize,
    epoch: u64,
    returned: bool,
}
impl Drop for PhaseObservation {
    fn drop(&mut self) {
        if !self.returned {
            record_phase(self.phase, self.epoch, None);
        }
        ACTIVE_PHASES[self.phase].fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
fn record_phase(phase: usize, epoch: u64, elapsed: Option<u64>) {
    match PHASE_POLLS.lock() {
        Ok(mut rows) => record_row(&mut rows[phase], epoch, elapsed),
        Err(_) => LOAD_UNKNOWN.store(true, std::sync::atomic::Ordering::Relaxed),
    }
}
pub(crate) fn observe_phase<F: std::future::Future>(
    phase: usize,
    mut future: std::pin::Pin<Box<F>>,
) -> impl std::future::Future<Output = F::Output> {
    std::future::poll_fn(move |context| {
        use std::sync::atomic::Ordering;
        ACTIVE_PHASES[phase].fetch_add(1, Ordering::SeqCst);
        let mut observation = PhaseObservation {
            phase,
            epoch: POLL_EPOCH.load(Ordering::SeqCst),
            returned: false,
        };
        let start = Instant::now();
        let result = future.as_mut().poll(context);
        let elapsed = start.elapsed().as_nanos().try_into().ok();
        observation.returned = true;
        record_phase(phase, observation.epoch, elapsed);
        result
    })
}
static WINDOW: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(crate) fn boundary(start: bool) {
    use std::sync::atomic::Ordering;
    if start {
        WINDOW.store(true, Ordering::SeqCst);
    } else if !WINDOW.swap(false, Ordering::SeqCst) {
        return;
    }
    let value = load_boundary(start);
    eprintln!("maintenance-phase {value}");
}

// Phase17 counts immediate synchronous invocations, not future polls.
pub(crate) fn observe_sync<R>(phase: usize, action: impl FnOnce() -> R) -> R {
    use std::sync::atomic::Ordering;
    ACTIVE_PHASES[phase].fetch_add(1, Ordering::SeqCst);
    let mut observation = PhaseObservation { phase, epoch: POLL_EPOCH.load(Ordering::SeqCst), returned: false };
    let start = Instant::now();
    let result = action();
    let elapsed = start.elapsed().as_nanos().try_into().ok();
    observation.returned = true;
    record_phase(phase, observation.epoch, elapsed);
    result
}
