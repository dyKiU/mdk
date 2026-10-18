//! Explicit finite arrival scheduling for the authenticated command-backlog test.
//! No synthetic deliveries, ACKs, receipts or queue consumers are introduced.
use super::{MemberId, MessageId};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock, Weak, atomic::{AtomicBool, AtomicUsize, Ordering}};
use tokio::sync::Notify;
use transport_nostr_adapter::ObservedTransportDelivery;

const HELD_CAPACITY: usize = 32;

#[derive(Clone, Copy)]
pub struct AccountIngressScheduleSnapshot {
    pub armed: bool,
    pub valid: bool,
    pub released: bool,
    pub flushed: bool,
    pub target_passes: usize,
    pub held: usize,
    pub replayed: usize,
    pub overflow: bool,
}

struct State {
    account: MemberId,
    target: OnceLock<MessageId>,
    requested: AtomicBool,
    armed: AtomicBool,
    valid: AtomicBool,
    released: AtomicBool,
    flushed: AtomicBool,
    target_passes: AtomicUsize,
    held: AtomicUsize,
    replayed: AtomicUsize,
    overflow: AtomicBool,
    changed: Notify,
    control: Weak<Control>,
}
impl State {
    fn release(&self) {
        self.released.store(true, Ordering::Release);
        if let Some(control) = self.control.upgrade() {
            control.changed.notify_one();
        }
    }
}

/// Fixture-owned lease. Drop requests release; callers must await the router's
/// positive flush acknowledgement before claiming cleanup.
pub struct AccountIngressScheduleForTest(Arc<State>);
impl AccountIngressScheduleForTest {
    pub async fn release_and_flush(&self) -> bool {
        self.0.release();
        let flushed = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let changed = self.0.changed.notified();
                if self.0.flushed.load(Ordering::Acquire) { break; }
                changed.await;
            }
        }).await.is_ok();
        if !flushed { self.0.valid.store(false, Ordering::Release); }
        flushed
    }
    pub fn snapshot(&self) -> AccountIngressScheduleSnapshot {
        // Independent atomic observations; final callers read after flush.
        AccountIngressScheduleSnapshot {
            armed: self.0.armed.load(Ordering::Acquire),
            valid: self.0.valid.load(Ordering::Acquire),
            released: self.0.released.load(Ordering::Acquire),
            flushed: self.0.flushed.load(Ordering::Acquire),
            target_passes: self.0.target_passes.load(Ordering::Acquire),
            held: self.0.held.load(Ordering::Acquire),
            replayed: self.0.replayed.load(Ordering::Acquire),
            overflow: self.0.overflow.load(Ordering::Acquire),
        }
    }
}
impl Drop for AccountIngressScheduleForTest {
    fn drop(&mut self) { self.0.release(); }
}

#[derive(Default)]
pub(super) struct Control {
    slot: Mutex<Option<Arc<State>>>,
    pub(super) changed: Notify,
}
impl Control {
    pub(super) fn prepare(self: &Arc<Self>, account: MemberId) -> Option<AccountIngressScheduleForTest> {
        let mut slot = self.slot.lock().ok()?;
        if slot.is_some() { return None; }
        let state = Arc::new(State {
            account, target: OnceLock::new(), requested: AtomicBool::new(false),
            armed: AtomicBool::new(false), valid: AtomicBool::new(true),
            released: AtomicBool::new(false), flushed: AtomicBool::new(false),
            target_passes: AtomicUsize::new(0), held: AtomicUsize::new(0),
            replayed: AtomicUsize::new(0), overflow: AtomicBool::new(false),
            changed: Notify::new(), control: Arc::downgrade(self),
        });
        *slot = Some(state.clone());
        Some(AccountIngressScheduleForTest(state))
    }
    pub(super) fn activate(&self, account: &MemberId, target: &MessageId) -> bool {
        let Ok(slot) = self.slot.lock() else { return false; };
        let Some(state) = slot.as_ref() else { return false; };
        if &state.account != account || state.released.load(Ordering::Acquire) {
            return false;
        }
        if let Some(existing) = state.target.get() {
            if existing != target {
                state.valid.store(false, Ordering::Release);
                state.release();
                return false;
            }
        } else if state.target.set(target.clone()).is_err() {
            state.valid.store(false, Ordering::Release);
            state.release();
            return false;
        }
        if !state.requested.swap(true, Ordering::AcqRel) {
            self.changed.notify_one();
        }
        // Only the single router publishes acknowledgement, after all earlier
        // synchronous routing finished. The actor cannot pause before this.
        state.armed.load(Ordering::Acquire) && state.valid.load(Ordering::Acquire)
    }
}

#[derive(Default)]
pub(super) struct Router {
    state: Option<Arc<State>>,
    held: VecDeque<ObservedTransportDelivery>,
}
impl Router {
    pub(super) fn control(&mut self, control: &Control, mut route: impl FnMut(ObservedTransportDelivery)) {
        if self.state.is_none() {
            self.state = control.slot.lock().unwrap_or_else(|p| p.into_inner()).clone();
        }
        let Some(state) = self.state.as_ref() else { return; };
        if state.released.load(Ordering::Acquire) {
            self.flush(control, &mut route);
        } else if state.requested.load(Ordering::Acquire) && state.target.get().is_some() {
            if !state.armed.swap(true, Ordering::AcqRel) {
                state.changed.notify_one();
            }
        }
    }
    pub(super) fn delivery(&mut self, delivery: ObservedTransportDelivery, mut route: impl FnMut(ObservedTransportDelivery)) -> Option<ObservedTransportDelivery> {
        let Some(state) = self.state.as_ref() else { return Some(delivery); };
        if state.released.load(Ordering::Acquire) {
            if let Some(control) = state.control.upgrade() {
                self.flush(&control, &mut route);
            }
            return Some(delivery);
        }
        if !state.armed.load(Ordering::Acquire) || state.account != delivery.account_id {
            return Some(delivery);
        }
        if state.target.get() == Some(&delivery.message.id)
            && state.target_passes.load(Ordering::Acquire) == 0 {
            state.target_passes.store(1, Ordering::Release);
            return Some(delivery);
        }
        if self.held.len() == HELD_CAPACITY {
            // Fail setup and replay genuine retained deliveries, never discard
            // or spill them through a test-specific bypass. Only this router
            // calls production routing, retaining its reserved-slot invariant.
            state.overflow.store(true, Ordering::Release);
            state.valid.store(false, Ordering::Release);
            state.release();
            if let Some(control) = state.control.upgrade() {
                self.flush(&control, &mut route);
            }
            return Some(delivery);
        }
        self.held.push_back(delivery);
        state.held.fetch_add(1, Ordering::AcqRel);
        None
    }
    fn flush(&mut self, control: &Control, route: &mut impl FnMut(ObservedTransportDelivery)) {
        let Some(state) = self.state.take() else { return; };
        while let Some(delivery) = self.held.pop_front() {
            route(delivery);
            state.replayed.fetch_add(1, Ordering::AcqRel);
        }
        let mut slot = control.slot.lock().unwrap_or_else(|p| p.into_inner());
        if slot.as_ref().is_some_and(|registered| Arc::ptr_eq(registered, &state)) {
            *slot = None;
        } else {
            state.valid.store(false, Ordering::Release);
        }
        drop(slot);
        state.flushed.store(true, Ordering::Release);
        state.changed.notify_one();
    }
    pub(super) fn finish(&mut self, control: &Control, route: impl FnMut(ObservedTransportDelivery)) {
        if let Some(state) = &self.state {
            // Router closure cannot qualify the controlled experiment, even
            // if normal routing of the buffered genuine inputs still succeeds.
            state.valid.store(false, Ordering::Release);
            state.release();
        }
        self.control(control, route);
    }
}
