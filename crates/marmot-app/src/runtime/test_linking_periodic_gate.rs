//! Test-only schedule gate. No protocol calls, clock changes, or owner authority.
use super::{MarmotAppRuntime, RuntimeSharedServices};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{Notify, watch};
pub(super) struct PeriodicGate {
    sender: watch::Sender<bool>,
    observed: Notify,
    // CADENCE_TEST_BEGIN
    turns_permitted: std::sync::atomic::AtomicUsize,
    turns_selected: std::sync::atomic::AtomicUsize,
    turns_completed: std::sync::atomic::AtomicUsize,
    turn_completed: Notify,
    // CADENCE_TEST_END
}
pub(crate) struct PeriodicGateGuard {
    gate: Arc<PeriodicGate>,
    map: Arc<Mutex<HashMap<String, Arc<PeriodicGate>>>>,
    account: String,
}
// CADENCE_TEST_BEGIN
pub(super) struct SelectedPeriodicTurnForTest {
    gate: Arc<PeriodicGate>,
    ordinal: usize,
}
impl SelectedPeriodicTurnForTest {
    pub(super) fn complete(self) {
        self.gate.turns_completed.store(self.ordinal, std::sync::atomic::Ordering::Release);
        self.gate.turn_completed.notify_waiters();
    }
}
// CADENCE_TEST_END
impl PeriodicGateGuard {
    // CADENCE_TEST_BEGIN
    pub(crate) async fn one_selected_turn_for_test(&self) -> usize {
        use std::sync::atomic::Ordering;
        let expected = self.gate.turns_selected.load(Ordering::Acquire) + 1;
        assert_eq!(self.gate.turns_permitted.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire), Ok(0), "one periodic turn permit");
        self.gate.sender.send_replace(false);
        loop {
            let completed = self.gate.turn_completed.notified();
            tokio::pin!(completed);
            completed.as_mut().enable();
            if self.gate.turns_completed.load(Ordering::Acquire) >= expected { return expected; }
            completed.await;
        }
    }
    // CADENCE_TEST_END
    pub(crate) async fn observed(&self) {
        self.gate.observed.notified().await;
    }
}
impl Drop for PeriodicGateGuard {
    fn drop(&mut self) {
        {
            let mut map = self.map.lock().expect("periodic test gate");
            if map
                .get(&self.account)
                .is_some_and(|gate| Arc::ptr_eq(gate, &self.gate))
            {
                map.remove(&self.account);
            }
        }
        self.gate.sender.send_replace(false);
    }
}
impl MarmotAppRuntime {
    pub(crate) fn hold_periodic_linking_for_test(&self, account: &str) -> PeriodicGateGuard {
        let gate = Arc::new(PeriodicGate {
            sender: watch::channel(true).0,
            observed: Notify::new(),
            // CADENCE_TEST_BEGIN
            turns_permitted: std::sync::atomic::AtomicUsize::new(0),
            turns_selected: std::sync::atomic::AtomicUsize::new(0),
            turns_completed: std::sync::atomic::AtomicUsize::new(0),
            turn_completed: Notify::new(),
            // CADENCE_TEST_END
        });
        assert!(
            self.shared
                .linking_periodic_test_gates
                .lock()
                .expect("periodic test gate")
                .insert(account.to_owned(), gate.clone())
                .is_none(),
            "one periodic gate per account"
        );
        PeriodicGateGuard {
            gate,
            map: self.shared.linking_periodic_test_gates.clone(),
            account: account.to_owned(),
        }
    }
}
impl RuntimeSharedServices {
    // CADENCE_TEST_BEGIN
    pub(super) fn selected_periodic_turn_for_test(&self, account: &str) -> Option<SelectedPeriodicTurnForTest> {
        use std::sync::atomic::Ordering;
        let gate = self.linking_periodic_test_gates.lock().expect("periodic test gate").get(account).cloned()?;
        if gate.turns_permitted.compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire).is_err() { return None; }
        // Only actual arm selection consumes a permit. A canceled readiness
        // future cannot spend it. Re-close BEFORE the unchanged arm body.
        gate.sender.send_replace(true);
        let ordinal = gate.turns_selected.fetch_add(1, Ordering::AcqRel) + 1;
        Some(SelectedPeriodicTurnForTest { gate, ordinal })
    }
    // CADENCE_TEST_END
    pub(super) async fn wait_periodic_linking_for_test(&self, account: &str) {
        let gate = self
            .linking_periodic_test_gates
            .lock()
            .expect("periodic test gate")
            .get(account)
            .cloned();
        if let Some(gate) = gate {
            let mut receiver = gate.sender.subscribe();
            loop {
                if !*receiver.borrow_and_update() {
                    return;
                }
                gate.observed.notify_one();
                if receiver.changed().await.is_err() {
                    return;
                }
            }
        }
    }
}
