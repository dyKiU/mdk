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
}
pub(crate) struct PeriodicGateGuard {
    gate: Arc<PeriodicGate>,
    map: Arc<Mutex<HashMap<String, Arc<PeriodicGate>>>>,
    account: String,
}
impl PeriodicGateGuard {
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
// SOURCE_READINESS_TEST_BEGIN

// Separate map: existing hold_periodic_linking_for_test still gates BOTH lanes.
impl MarmotAppRuntime {
    pub(crate) fn hold_sibling_only_periodic_for_test(&self, account: &str) -> PeriodicGateGuard {
        let gate = Arc::new(PeriodicGate {
            sender: watch::channel(true).0,
            observed: Notify::new(),
        });
        assert!(
            self.shared
                .sibling_periodic_only_test_gates
                .lock()
                .expect("sibling-only periodic gate")
                .insert(account.to_owned(), gate.clone())
                .is_none(),
            "one sibling-only periodic gate per account"
        );
        PeriodicGateGuard {
            gate,
            map: self.shared.sibling_periodic_only_test_gates.clone(),
            account: account.to_owned(),
        }
    }
}
impl RuntimeSharedServices {
    pub(super) async fn wait_sibling_only_periodic_for_test(&self, account: &str) {
        let gate = self
            .sibling_periodic_only_test_gates
            .lock()
            .expect("sibling-only periodic gate")
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
// SOURCE_READINESS_TEST_END
