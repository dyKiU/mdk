//! Optional aggregate diagnostics, never a verification cache or an authority.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

const LIMIT: u64 = 1_000_000_000_000_000_000;
struct State {
    rows: [[u64; 5]; 2],
    overflow: bool,
}
struct Collector {
    origin: Instant,
    state: Mutex<State>,
    window: AtomicBool,
}
fn collector() -> Option<&'static Collector> {
    static VALUE: OnceLock<Option<Collector>> = OnceLock::new();
    VALUE
        .get_or_init(|| {
            (std::env::var_os("WN_ORDINARY_SIBLING_TURN_TRACE").as_deref()
                == Some(std::ffi::OsStr::new("1")))
            .then(|| Collector {
                origin: Instant::now(),
                state: Mutex::new(State {
                    rows: [[0; 5]; 2],
                    overflow: false,
                }),
                window: AtomicBool::new(false),
            })
        })
        .as_ref()
}
fn bounded(value: u128, overflow: &mut bool) -> u64 {
    if value > u128::from(LIMIT) {
        *overflow = true;
        LIMIT
    } else {
        value as u64
    }
}
pub(crate) struct Span {
    collector: &'static Collector,
    index: usize,
    started: Instant,
}
pub(crate) fn span(index: usize) -> Option<Span> {
    let collector = collector()?;
    let mut state = collector.state.lock().ok()?;
    let mut overflow = state.overflow;
    state.rows[index][0] = bounded(u128::from(state.rows[index][0]) + 1, &mut overflow);
    state.rows[index][4] = bounded(u128::from(state.rows[index][4]) + 1, &mut overflow);
    state.overflow = overflow;
    drop(state);
    Some(Span {
        collector,
        index,
        started: Instant::now(),
    })
}
impl Drop for Span {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed().as_nanos();
        if let Ok(mut state) = self.collector.state.lock() {
            let mut overflow = state.overflow;
            let row = &mut state.rows[self.index];
            row[1] = bounded(u128::from(row[1]) + 1, &mut overflow);
            row[2] = bounded(u128::from(row[2]) + elapsed, &mut overflow);
            row[3] = row[3].max(bounded(elapsed, &mut overflow));
            row[4] = row[4].saturating_sub(1);
            state.overflow = overflow;
        }
    }
}
fn emit(collector: &Collector, stage: u64, begin: bool) -> bool {
    // Terminal ownership is independent of the observation mutex: poison must
    // not leave the window armed and produce a second terminal snapshot on Drop.
    if begin {
        if collector
            .window
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
    } else if !collector.window.swap(false, Ordering::AcqRel) {
        return false;
    }
    let mut values = [0u64; 14];
    values[0] = stage;
    match collector.state.lock() {
        Ok(mut state) => {
            let mut overflow = state.overflow;
            values[1] = bounded(collector.origin.elapsed().as_nanos(), &mut overflow);
            state.overflow = overflow;
            values[2] = 1;
            values[3] = u64::from(overflow);
            values[4..9].copy_from_slice(&state.rows[0]);
            values[9..14].copy_from_slice(&state.rows[1]);
        }
        Err(_) => {
            // Poisoned observation is explicitly unknown, never a product error.
        }
    }
    eprintln!("ordinary-proof-cost values={values:?}");
    begin
}

/// Cumulative start/end snapshots; this never drives an Engine or actor.
pub struct Window(bool);
pub fn begin_window() -> Window {
    Window(collector().is_some_and(|collector| emit(collector, 0, true)))
}
pub fn finish_window() {
    if let Some(collector) = collector() {
        emit(collector, 1, false);
    }
}
impl Drop for Window {
    fn drop(&mut self) {
        if self.0
            && let Some(collector) = collector()
        {
            // Unwinding outside the normal failure/success marker is distinct.
            emit(collector, 2, false);
        }
    }
}
