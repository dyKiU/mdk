//! Fixture-owned scheduling observation; never constructs protocol authority.
use super::account_worker::AccountWorkerCommand;
use super::*;
use crate::client::AppClient;
use crate::client::private_enrollment_proposal::OriginalSiblingSharingApproval;
use std::sync::Weak;

pub(super) struct Probe {
    owner: Weak<OriginalSiblingSharingApproval>,
    nonce: [u8; 32],
    group: GroupId,
    latched: AtomicBool,
    observed: Notify,
    release: Notify,
    serviced: Notify,
    state: StdMutex<State>,
}
#[derive(Default)]
struct State {
    commands: usize,
    before: Option<(bool, usize)>,
    failed: bool,
    // Command count when the first matched, successful service returned.
    service_after: Option<usize>,
    original_live: bool,
}
pub(crate) struct Guard {
    probe: Arc<Probe>,
    slot: Arc<StdMutex<Option<Arc<Probe>>>>,
}
impl Guard {
    pub(crate) async fn observed(&self) {
        self.probe.observed.notified().await;
    }
    pub(crate) async fn serviced(&self) {
        loop {
            let changed = self.probe.serviced.notified();
            {
                let state = self.probe.state.lock().expect("finite queue state");
                if state.commands == 3 && state.service_after.is_some() {
                    return;
                }
            }
            changed.await;
        }
    }
    pub(crate) fn release(&self) {
        self.probe.release.notify_one();
    }
    pub(crate) fn result(&self) -> (bool, usize, Option<usize>, bool) {
        let state = self.probe.state.lock().expect("finite queue state");
        (
            self.probe.latched.load(Ordering::Acquire),
            state.commands,
            state.service_after,
            state.original_live,
        )
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.release();
        let mut slot = self.slot.lock().expect("finite queue probe");
        if slot
            .as_ref()
            .is_some_and(|probe| Arc::ptr_eq(probe, &self.probe))
        {
            *slot = None;
        }
    }
}
impl MarmotAppRuntime {
    pub(crate) fn observe_sibling_finite_queue_for_test(
        &self,
        owner: Weak<OriginalSiblingSharingApproval>,
        nonce: [u8; 32],
        group: GroupId,
    ) -> Guard {
        let probe = Arc::new(Probe {
            owner,
            nonce,
            group,
            latched: AtomicBool::new(false),
            observed: Notify::new(),
            release: Notify::new(),
            serviced: Notify::new(),
            state: StdMutex::new(State::default()),
        });
        let mut slot = self
            .shared
            .sibling_finite_queue_probe
            .lock()
            .expect("finite queue probe");
        assert!(slot.is_none(), "one owned finite queue probe per runtime");
        *slot = Some(probe.clone());
        Guard {
            probe,
            slot: self.shared.sibling_finite_queue_probe.clone(),
        }
    }
    // Use the ordinary onboarding/identity/lifecycle-checked sender. The fixture
    // acquires it before gating its already enrolled B worker.
    pub(crate) async fn sibling_finite_queue_sender_for_test(
        &self,
        account: &str,
    ) -> Result<mpsc::Sender<AccountWorkerCommand>, AppError> {
        self.accounts.worker_commands(account).await
    }
}
fn probe(shared: &RuntimeSharedServices) -> Option<Arc<Probe>> {
    shared
        .sibling_finite_queue_probe
        .lock()
        .expect("finite queue probe")
        .clone()
}
pub(super) fn latched(shared: &RuntimeSharedServices, client: &AppClient) -> Option<Arc<Probe>> {
    let probe = probe(shared)?;
    if !client
        .sibling_finite_queue_observation_for_test(&probe.owner, probe.nonce)
        .is_some_and(|(live, _)| live)
        || probe.latched.swap(true, Ordering::AcqRel)
    {
        return None;
    }
    Some(probe)
}
pub(super) async fn wait_latched(shared: &RuntimeSharedServices, probe: Arc<Probe>) {
    let mut stopping = shared.lifecycle().subscribe_shutdown();
    probe.observed.notify_one();
    tokio::select! {
        _ = probe.release.notified() => {},
        _ = wait_for_runtime_shutdown(&mut stopping) => {},
    }
}
pub(super) fn before_service(shared: &RuntimeSharedServices, client: &AppClient) {
    if let Some(probe) = probe(shared) {
        let mut state = probe.state.lock().expect("finite queue state");
        if probe.latched.load(Ordering::Acquire) && state.service_after.is_none() {
            state.before =
                client.sibling_finite_queue_observation_for_test(&probe.owner, probe.nonce);
            state.failed = false;
        }
    }
}
pub(super) fn failed_service(shared: &RuntimeSharedServices) {
    if let Some(probe) = probe(shared) {
        probe.state.lock().expect("finite queue state").failed = true;
    }
}
pub(super) fn returned_service(shared: &RuntimeSharedServices, client: &AppClient) {
    if let Some(probe) = probe(shared) {
        let after = client.sibling_finite_queue_observation_for_test(&probe.owner, probe.nonce);
        let mut state = probe.state.lock().expect("finite queue state");
        if let (Some((true, before)), Some((true, after))) = (state.before.take(), after)
            && after > before
            && !state.failed
            && state.service_after.is_none()
        {
            state.service_after = Some(state.commands);
            state.original_live = true;
            probe.serviced.notify_one();
        }
    }
}
pub(super) fn replied(shared: &RuntimeSharedServices, group: &GroupId) {
    if let Some(probe) = probe(shared)
        && probe.latched.load(Ordering::Acquire)
        && probe.group == *group
    {
        let mut state = probe.state.lock().expect("finite queue state");
        state.commands = (state.commands + 1).min(4);
        probe.serviced.notify_one();
    }
}
