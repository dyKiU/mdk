//! Passive test-only last receive frontier; no authority or global registry.
use super::super::OriginalEnrollmentSharingChoice;
use std::sync::{
    Arc, OnceLock, Weak,
    atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering},
};
use std::time::Instant;

pub(crate) type Snapshot = (
    bool,
    u32,
    u32,
    bool,
    Option<(u64, bool)>,
    Option<u64>,
    [Option<u64>; 3],
    Option<bool>,
);
#[derive(Default)]
pub(crate) struct Recorder {
    origin: OnceLock<Instant>,
    active: AtomicBool,
    frozen: AtomicBool,
    inflight: AtomicU32,
    loss: AtomicU32,
    gate: AtomicU64,
    receive: AtomicU64,
    before: AtomicU64,
    after: AtomicU64,
    observed: AtomicU64,
    outcome: AtomicU8,
}
impl Recorder {
    fn observe(&self, update: impl FnOnce(u64)) {
        if !self.active.load(Ordering::Acquire) {
            return;
        }
        if self
            .inflight
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .is_err()
        {
            self.loss.fetch_or(2, Ordering::AcqRel);
            return;
        }
        if !self.frozen.load(Ordering::SeqCst) {
            let time = self
                .origin
                .get()
                .and_then(|origin| u64::try_from(origin.elapsed().as_micros()).ok())
                .and_then(|us| us.checked_add(1));
            if let Some(time) = time {
                update(time);
            } else {
                self.loss.fetch_or(2, Ordering::AcqRel);
            }
        }
        self.inflight.fetch_sub(1, Ordering::SeqCst);
    }
    pub(crate) fn active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
    pub(crate) fn gate(&self, enabled: bool) {
        self.observe(|time| {
            if let Some(packed) = time
                .checked_mul(2)
                .and_then(|v| v.checked_add(u64::from(enabled)))
            {
                self.gate.store(packed, Ordering::Release);
            } else {
                self.loss.fetch_or(2, Ordering::AcqRel);
            }
        });
    }
    pub(crate) fn receive(&self) {
        self.observe(|time| self.receive.store(time, Ordering::Release));
    }
    fn once(&self, cell: &AtomicU64) {
        self.observe(|time| {
            if cell
                .compare_exchange(0, time, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                self.loss.fetch_or(1, Ordering::AcqRel);
            }
        });
    }
    pub(crate) fn wait_before(&self) {
        self.once(&self.before);
    }
    pub(crate) fn wait_after(&self) {
        self.once(&self.after);
    }
    pub(crate) fn wait_observed(&self, ok: bool) {
        self.observe(|time| {
            if self
                .observed
                .compare_exchange(0, time, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.outcome
                    .store(if ok { 1 } else { 2 }, Ordering::Release);
            } else {
                self.loss.fetch_or(1, Ordering::AcqRel);
            }
        });
    }
}
pub(crate) struct Guard {
    owner: Weak<OriginalEnrollmentSharingChoice>,
    data: Arc<Recorder>,
    snapshot: OnceLock<Snapshot>,
}
impl Guard {
    pub(crate) fn arm(owner: &Arc<OriginalEnrollmentSharingChoice>) -> Self {
        let data = owner.receive_frontier.clone();
        if data.origin.set(Instant::now()).is_err() || data.active.swap(true, Ordering::AcqRel) {
            data.loss.fetch_or(1, Ordering::AcqRel);
        }
        Self {
            owner: Arc::downgrade(owner),
            data,
            snapshot: OnceLock::new(),
        }
    }
    pub(crate) fn freeze(&self) -> Snapshot {
        *self.snapshot.get_or_init(|| {
            self.data.frozen.store(true, Ordering::SeqCst);
            self.data.active.store(false, Ordering::Release);
            let inflight = self.data.inflight.load(Ordering::SeqCst);
            let loss = self.data.loss.load(Ordering::Acquire);
            let opt = |value: u64| value.checked_sub(1);
            let packed = self.data.gate.load(Ordering::Acquire);
            let gate = if packed == 0 {
                None
            } else {
                opt(packed / 2).map(|time| (time, packed & 1 != 0))
            };
            (
                loss == 0 && inflight == 0,
                loss,
                inflight,
                self.owner.strong_count() != 0,
                gate,
                opt(self.data.receive.load(Ordering::Acquire)),
                [
                    opt(self.data.before.load(Ordering::Acquire)),
                    opt(self.data.after.load(Ordering::Acquire)),
                    opt(self.data.observed.load(Ordering::Acquire)),
                ],
                match self.data.outcome.load(Ordering::Acquire) {
                    1 => Some(true),
                    2 => Some(false),
                    _ => None,
                },
            )
        })
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.data.frozen.store(true, Ordering::SeqCst);
        self.data.active.store(false, Ordering::Release);
    }
}
