//! Passive CI-only timeline. Weak keys are ordinalized; no identity is exported.
use super::{AppClient, OriginalEnrollmentSharingChoice, State};
use std::sync::{
    Arc, LazyLock, Mutex, TryLockError, Weak,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use std::time::Instant;

static ENABLED: LazyLock<bool> =
    LazyLock::new(|| std::env::var("MDK_UPSTREAM_BROAD_TRACE").as_deref() == Ok("1"));
// Low bits: loss=1, frozen=2, active=4. Upper bits are CLOSED loss
// reasons, atomically captured with the frozen flag; never exact lost counts.
static STATUS: AtomicU32 = AtomicU32::new(0);
#[derive(Clone, Copy)]
#[repr(u32)]
enum Loss {
    Timestamp = 1, EventCapacity = 2, KeyCapacity = 4,
    RecordWouldBlock = 8, RecordPoisoned = 16,
    ChildWouldBlock = 32, ChildPoisoned = 64,
    RepeatedBegin = 128, BeginWouldBlock = 256, BeginPoisoned = 512,
}
fn unknown(reason: Loss) {
    let _ = STATUS.fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
        if old & 2 == 0 { Some(old | 1 | ((reason as u32) << 3)) } else { None }
    });
}
enum EventLoss { Timestamp, Capacity }
static TRACE: LazyLock<Mutex<Trace>> = LazyLock::new(|| {
    Mutex::new(Trace {
        origin: Instant::now(),
        keys: Vec::new(),
        events: Vec::new(),
    })
});
const MAX_KEYS: usize = 64;
const MAX_EVENTS: usize = 8192;
enum Key {
    Choice(Weak<AtomicBool>),
    Channel(Weak<State>),
}
impl Key {
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Choice(a), Self::Choice(b)) => a.ptr_eq(b),
            (Self::Channel(a), Self::Channel(b)) => a.ptr_eq(b),
            _ => false,
        }
    }
}
struct Trace {
    origin: Instant,
    keys: Vec<Key>,
    events: Vec<[u64; 4]>,
}
impl Trace {
    fn key(&mut self, key: Key) -> Option<u64> {
        if let Some(index) = self.keys.iter().position(|old| old.same(&key)) {
            return Some(index as u64 + 1);
        }
        if self.keys.len() == MAX_KEYS {
            return None;
        }
        self.keys.push(key);
        Some(self.keys.len() as u64)
    }
    fn event(&mut self, key: u64, stage: u64, value: u64) -> Result<(), EventLoss> {
        let Ok(elapsed) = u64::try_from(self.origin.elapsed().as_micros()) else {
            unknown(Loss::Timestamp);
            return Err(EventLoss::Timestamp);
        };
        if self.events.len() == MAX_EVENTS {
            unknown(Loss::EventCapacity);
            return Err(EventLoss::Capacity);
        }
        self.events.push([elapsed, key, stage, value]);
        Ok(())
    }
}
fn record(key: Option<Key>, stage: u64, value: u64) {
    if !*ENABLED || STATUS.load(Ordering::Acquire) & 6 != 4 {
        return;
    }
    let mut trace = match TRACE.try_lock() {
        Ok(trace) => trace,
        Err(TryLockError::WouldBlock) => { unknown(Loss::RecordWouldBlock); return; }
        Err(TryLockError::Poisoned(_)) => { unknown(Loss::RecordPoisoned); return; }
    };
    if STATUS.load(Ordering::Acquire) & 6 != 4 {
        return;
    }
    let key = match key {
        Some(key) => match trace.key(key) {
            Some(key) => key,
            None => {
                unknown(Loss::KeyCapacity);
                return;
            }
        },
        None => 0,
    };
    let _ = trace.event(key, stage, value);
}
pub(crate) fn choice(choice: &OriginalEnrollmentSharingChoice, stage: u64, value: u64) {
    record(
        Some(Key::Choice(Arc::downgrade(&choice.lifetime))),
        stage,
        value,
    );
}
pub(crate) fn channel(state: &Arc<State>, stage: u64, value: u64) {
    record(Some(Key::Channel(Arc::downgrade(state))), stage, value);
}
pub(crate) fn child(choice: &OriginalEnrollmentSharingChoice, state: &Arc<State>) {
    if !*ENABLED || STATUS.load(Ordering::Acquire) & 6 != 4 {
        return;
    }
    let mut trace = match TRACE.try_lock() {
        Ok(trace) => trace,
        Err(TryLockError::WouldBlock) => { unknown(Loss::ChildWouldBlock); return; }
        Err(TryLockError::Poisoned(_)) => { unknown(Loss::ChildPoisoned); return; }
    };
    if STATUS.load(Ordering::Acquire) & 6 != 4 {
        return;
    }
    let parent = trace.key(Key::Choice(Arc::downgrade(&choice.lifetime)));
    let child = trace.key(Key::Channel(Arc::downgrade(state)));
    match (parent, child) {
        (Some(parent), Some(child)) => { let _ = trace.event(parent, 31, child); }
        _ => unknown(Loss::KeyCapacity),
    }
}
pub(crate) fn global(stage: u64) {
    record(None, stage, 0);
}
impl AppClient {
    pub(crate) fn broad_trace_for_test(&self, stage: u64) {
        if !*ENABLED || STATUS.load(Ordering::Acquire) & 6 != 4 {
            return;
        }
        let mut attributed = false;
        if let Some(original) = &self.linking_owner.sharing_approval {
            choice(original, stage, 0);
            attributed = true;
        }
        // Attribute existing source housekeeping even before channel creation.
        // When its same State already occurs below, do not emit it twice.
        if let Some(state) = self.broad_existing_sharing_state_for_test()
            && !self
                .linking_owner
                .sibling_channels
                .iter()
                .any(|entry| Arc::ptr_eq(&entry.state, state))
        {
            channel(state, stage, 0);
            attributed = true;
        }
        for entry in &self.linking_owner.sibling_channels {
            channel(&entry.state, stage, 0);
            attributed = true;
        }
        if !attributed {
            global(stage);
        }
    }
}
/// Start only before the unchanged fourth-device continuation. No setup
/// event is a lost observation: it is outside this explicitly scoped window.
pub(crate) fn window_begin() {
    if !*ENABLED {
        return;
    }
    if STATUS.load(Ordering::Acquire) != 0 {
        unknown(Loss::RepeatedBegin);
        return;
    }
    let mut trace = match TRACE.try_lock() {
        Ok(trace) => trace,
        Err(TryLockError::WouldBlock) => { unknown(Loss::BeginWouldBlock); return; }
        Err(TryLockError::Poisoned(_)) => { unknown(Loss::BeginPoisoned); return; }
    };
    let _ = trace.event(0, 40, 0);
    drop(trace);
    // Publish only after unlocking, so racing first actor events do not report
    // artificial lock contention against the initialization itself.
    STATUS.fetch_or(4, Ordering::Release);
}
pub(crate) struct Dump;
impl Dump {
    pub(crate) fn begin() -> Self {
        Self
    }
}
impl Drop for Dump {
    fn drop(&mut self) {
        if !*ENABLED {
            return;
        }
        // Freeze before the nonblocking snapshot. Later actor observations are
        // outside this diagnostic lifetime and cannot change its known flag.
        let status = STATUS.fetch_or(2, Ordering::AcqRel);
        let loss_mask = status >> 3;
        if status & 4 == 0 {
            eprintln!("broad-trace unavailable loss_mask={loss_mask} terminal=1");
            return;
        }
        let mut trace = match TRACE.try_lock() {
            Ok(trace) => trace,
            Err(TryLockError::WouldBlock) => {
                eprintln!("broad-trace unavailable loss_mask={loss_mask} terminal=2"); return;
            }
            Err(TryLockError::Poisoned(_)) => {
                eprintln!("broad-trace unavailable loss_mask={loss_mask} terminal=3"); return;
            }
        };
        // Terminal append happens after freeze; return its typed failure locally
        // instead of racing an update to the already-frozen atomic reason mask.
        let terminal = match trace.event(0, 41, 0) {
            Ok(()) => 0,
            Err(EventLoss::Timestamp) => 4,
            Err(EventLoss::Capacity) => 5,
        };
        let known = status & 1 == 0 && loss_mask == 0 && terminal == 0;
        let kinds: Vec<u8> = trace
            .keys
            .iter()
            .map(|key| match key {
                Key::Choice(_) => 1,
                Key::Channel(_) => 2,
            })
            .collect();
        let events = std::mem::take(&mut trace.events);
        drop(trace);
        eprintln!(
            "broad-trace summary known={known} keys={} events={} loss_mask={loss_mask} terminal={terminal}",
            kinds.len(),
            events.len()
        );
        for (index, kind) in kinds.iter().enumerate() {
            eprintln!("broad-trace key={} kind={kind}", index + 1);
        }
        for event in &events {
            eprintln!("broad-trace event={event:?}");
        }
    }
}
