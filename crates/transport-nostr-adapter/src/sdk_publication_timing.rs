//! Test-feature-only fixed first-publication observations. Never publication authority.
use nostr_sdk::prelude::EventId;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, TryLockError, Weak};
use std::time::Instant;
const FROZEN: u32 = 1 << 31;
const MAX_US: u64 = 600_000_000;
#[derive(Clone)]
struct Row {
    id: [u8; 32],
    called: bool,
    times: [Option<u64>; 15],
    // Verification/retain/connect success; real send category 0OK/1Rejected/2Other;
    // accepted receipt preserved typed ACK; final prepared-call Result success.
    outcomes: [Option<u8>; 7],
    route: Option<u8>, // 0 opaque SDK client; 1 owned relay.
    later_calls: u32,
    later_sends: u32,
    scope_dropped: bool,
}
struct Probe {
    origin: Instant,
    status: AtomicU32,
    rows: Mutex<[Option<Row>; 6]>,
}
struct Registry {
    slots: [OnceLock<Weak<Probe>>; 2],
    next: std::sync::atomic::AtomicUsize,
    active: std::sync::atomic::AtomicUsize,
}
fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry {
        slots: [OnceLock::new(), OnceLock::new()],
        next: std::sync::atomic::AtomicUsize::new(0),
        active: std::sync::atomic::AtomicUsize::new(2),
    })
}
fn active_probe() -> Option<Arc<Probe>> {
    let registry = registry();
    let index = registry.active.load(Ordering::Acquire);
    let probe = registry.slots.get(index)?.get()?.upgrade()?;
    (probe.status.load(Ordering::Acquire) & FROZEN == 0).then_some(probe)
}
fn register(probe: &Arc<Probe>) {
    let registry = registry();
    let index = registry
        .next
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
            if next < 2 { Some(next + 1) } else { None }
        })
        .unwrap_or(2);
    let Some(slot) = registry.slots.get(index) else {
        probe.loss(4);
        return;
    };
    if slot.set(Arc::downgrade(probe)).is_err() {
        probe.loss(64);
        return;
    }
    // Publish only after this immutable weak slot is initialized. No reuse/wrap.
    registry.active.store(index, Ordering::Release);
}

impl Probe {
    fn loss(&self, bit: u32) {
        let _ = self
            .status
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                (v & FROZEN == 0).then_some(v | bit)
            });
    }
    fn observe(&self, f: impl FnOnce(&mut [Option<Row>; 6], u64)) {
        if self.status.load(Ordering::Acquire) & FROZEN != 0 {
            return;
        }
        match self.rows.try_lock() {
            Ok(mut rows) => {
                if self.status.load(Ordering::Acquire) & FROZEN != 0 {
                    return;
                }
                let elapsed = self.origin.elapsed().as_micros();
                if elapsed > u128::from(MAX_US) {
                    self.loss(16);
                    return;
                }
                f(&mut rows, elapsed as u64);
            }
            Err(TryLockError::WouldBlock) => self.loss(1),
            Err(TryLockError::Poisoned(_)) => self.loss(2),
        }
    }
}
/// Owned only by the existing App test probe; the SDK retains a Weak registry.
pub struct Guard(Arc<Probe>);
impl Guard {
    pub fn arm(origin: Instant) -> Self {
        let probe = Arc::new(Probe {
            origin,
            status: AtomicU32::new(0),
            rows: Mutex::new(std::array::from_fn(|_| None)),
        });
        register(&probe);
        Self(probe)
    }
    pub fn bind(&self, index: usize, actual_message_id: &[u8]) {
        let Ok(id) = <[u8; 32]>::try_from(actual_message_id) else {
            self.0.loss(8);
            return;
        };
        self.0.observe(|rows, _| {
            if index >= rows.len() {
                self.0.loss(4);
                return;
            }
            if rows.iter().flatten().any(|row| row.id == id) || rows[index].is_some() {
                self.0.loss(8);
                return;
            }
            rows[index] = Some(Row {
                id,
                called: false,
                times: [None; 15],
                outcomes: [None; 7],
                route: None,
                later_calls: 0,
                later_sends: 0,
                scope_dropped: false,
            });
        });
    }
    /// Returns a bounded closed report; recognized App test fixture prints it.
    pub fn freeze(&self) -> String {
        let old = self.0.status.fetch_or(FROZEN, Ordering::AcqRel);
        let snapshot = match self.0.rows.try_lock() {
            Ok(rows) => Some(rows.clone()),
            Err(_) => None,
        };
        let mut loss = old & !FROZEN;
        if snapshot.is_none() {
            loss |= if self.0.rows.is_poisoned() { 2 } else { 1 };
        }
        let mut text = String::new();
        let _ = writeln!(
            &mut text,
            "native5-sdk-timing known={} loss_mask={} snapshot_available={}",
            loss == 0,
            loss,
            snapshot.is_some()
        );
        if let Some(rows) = snapshot {
            for (index, row) in rows.into_iter().enumerate() {
                let safe = row.map(|r| {
                    (
                        r.called,
                        r.times,
                        r.outcomes,
                        r.route,
                        r.later_calls,
                        r.later_sends,
                        r.scope_dropped,
                    )
                });
                let _ = writeln!(
                    &mut text,
                    "native5-sdk-slot index={index} observation={safe:?}"
                );
            }
        }
        if text.len() > 16384 {
            return "native5-sdk-timing known=false loss_mask=4 snapshot_available=false\n"
                .to_owned();
        }
        text
    }
}
#[derive(Clone)]
pub(crate) struct Token {
    probe: Weak<Probe>,
    index: usize,
    id: [u8; 32],
}
impl Token {
    fn with(&self, f: impl FnOnce(&mut Row, u64, &Probe)) {
        let Some(p) = self.probe.upgrade() else {
            return;
        };
        p.observe(|rows, time| {
            let Some(row) = rows.get_mut(self.index).and_then(Option::as_mut) else {
                p.loss(8);
                return;
            };
            if row.id != self.id || !row.called {
                p.loss(8);
                return;
            }
            f(row, time, &p);
        });
    }
    pub(crate) fn stage(&self, index: usize, outcome: Option<(usize, u8)>) {
        self.with(|row, time, p| {
            let Some(field) = row.times.get_mut(index) else {
                p.loss(8);
                return;
            };
            if field.is_some() {
                p.loss(64);
                return;
            }
            *field = Some(time);
            if let Some((index, value)) = outcome {
                if let Some(v) = row.outcomes.get_mut(index) {
                    *v = Some(value);
                } else {
                    p.loss(8);
                }
            }
        });
    }
    pub(crate) fn verified(&self, event_id: [u8; 32], ok: bool) {
        if event_id != self.id {
            if let Some(p) = self.probe.upgrade() {
                p.loss(8);
            }
            return;
        }
        self.stage(2, Some((0, u8::from(ok))));
    }
    pub(crate) fn route(&self, route: u8) {
        self.with(|row, _, p| {
            if row.route.replace(route).is_some() {
                p.loss(64);
            }
        });
    }
    pub(crate) fn later_send(&self) {
        self.with(|row, _, p| {
            if let Some(next) = row.later_sends.checked_add(1) {
                row.later_sends = next;
            } else {
                row.later_sends = u32::MAX;
                p.loss(16);
            }
        });
    }
}
/// Only this owner marks scope destruction. Cloned weak Tokens have no Drop side effect.
pub(crate) struct FirstCall {
    token: Token,
}
impl FirstCall {
    pub(crate) fn token(&self) -> Token {
        self.token.clone()
    }
}
impl Drop for FirstCall {
    fn drop(&mut self) {
        self.token.with(|row, _, _| {
            if row.times[13].is_none() {
                row.scope_dropped = true;
            }
        });
    }
}
pub(crate) fn begin(dto_id: &str, endpoint_count: usize) -> Option<FirstCall> {
    let p = active_probe()?;
    let id = EventId::from_hex(dto_id).ok()?.to_bytes();
    let mut token = None;
    p.observe(|rows, time| {
        let Some((index, row)) = rows
            .iter_mut()
            .enumerate()
            .find_map(|(i, r)| r.as_mut().filter(|r| r.id == id).map(|r| (i, r)))
        else {
            return;
        };
        if endpoint_count != 1 {
            p.loss(8);
            return;
        }
        if row.called {
            if let Some(next) = row.later_calls.checked_add(1) {
                row.later_calls = next;
            } else {
                row.later_calls = u32::MAX;
                p.loss(16);
            }
            return;
        }
        row.called = true;
        row.times[0] = Some(time);
        token = Some(Token {
            probe: Arc::downgrade(&p),
            index,
            id,
        });
    });
    token.map(|token| FirstCall { token })
}
