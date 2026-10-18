//! Passive CI-only timeline. Weak keys are ordinalized; no identity is exported.
use super::{AppClient, OriginalEnrollmentSharingChoice, State};
use std::sync::{
    Arc, LazyLock, Mutex, Weak,
    atomic::{AtomicBool, AtomicU8, Ordering},
};
use std::time::Instant;

static ENABLED: LazyLock<bool> =
    LazyLock::new(|| std::env::var("MDK_UPSTREAM_BROAD_TRACE").as_deref() == Ok("1"));
// Bits: loss=1, frozen=2, active=4. The setup prefix is intentionally omitted.
static STATUS: AtomicU8 = AtomicU8::new(0);
fn unknown() {
    let _ = STATUS.fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
        if old & 2 == 0 { Some(old | 1) } else { None }
    });
}
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
    fn event(&mut self, key: u64, stage: u64, value: u64) {
        let Ok(elapsed) = u64::try_from(self.origin.elapsed().as_micros()) else {
            unknown();
            return;
        };
        if self.events.len() == MAX_EVENTS {
            unknown();
            return;
        }
        self.events.push([elapsed, key, stage, value]);
    }
}
fn record(key: Option<Key>, stage: u64, value: u64) {
    if !*ENABLED || STATUS.load(Ordering::Acquire) & 6 != 4 {
        return;
    }
    let Ok(mut trace) = TRACE.try_lock() else {
        unknown();
        return;
    };
    if STATUS.load(Ordering::Acquire) & 6 != 4 {
        return;
    }
    let key = match key {
        Some(key) => match trace.key(key) {
            Some(key) => key,
            None => {
                unknown();
                return;
            }
        },
        None => 0,
    };
    trace.event(key, stage, value);
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
    let Ok(mut trace) = TRACE.try_lock() else {
        unknown();
        return;
    };
    if STATUS.load(Ordering::Acquire) & 6 != 4 {
        return;
    }
    let parent = trace.key(Key::Choice(Arc::downgrade(&choice.lifetime)));
    let child = trace.key(Key::Channel(Arc::downgrade(state)));
    match (parent, child) {
        (Some(parent), Some(child)) => trace.event(parent, 31, child),
        _ => unknown(),
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
        if let Some(original) = self.linking_owner.received_endorsement.as_ref()
            .and_then(|action| action.sharing.as_ref())
            && !self.linking_owner.sibling_channels.iter()
                .any(|entry| Arc::ptr_eq(&entry.state, &original.state))
        {
            channel(&original.state, stage, 0);
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
        unknown();
        return;
    }
    let Ok(mut trace) = TRACE.try_lock() else {
        unknown();
        return;
    };
    trace.event(0, 40, 0);
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
        if status & 4 == 0 {
            eprintln!("broad-trace unavailable");
            return;
        }
        let Ok(mut trace) = TRACE.try_lock() else {
            eprintln!("broad-trace unavailable");
            return;
        };
        let mut known = status & 1 == 0 && trace.events.len() < MAX_EVENTS;
        trace.event(0, 41, 0);
        known &= trace.events.last().is_some_and(|event| event[2] == 41);
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
            "broad-trace summary known={known} keys={} events={}",
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
