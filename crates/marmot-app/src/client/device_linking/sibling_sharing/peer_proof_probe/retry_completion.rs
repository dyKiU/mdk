//! Exact original retry completion hold; actual SDK reports are never fabricated.
use super::*;
use crate::MarmotRelayPlaneAccountAdapter;
use cgka_engine::account_chat_sharing::AccountSharingControl;
use cgka_traits::{TransportAdapterError, TransportPublishReport, TransportPublishRequest};
use std::sync::atomic::AtomicUsize;

type Existing = crate::client::private_enrollment_proposal::OriginalSiblingSharingApproval;
struct Gate {
    owner: Weak<Existing>,
    nonce: [u8; 32],
    deadline: Instant,
    captured: AtomicBool,
    sdk_ack_held: AtomicBool,
    publish_calls: AtomicUsize,
    release_requested: AtomicBool,
    normal_release: AtomicBool,
    future_dropped: AtomicBool,
    dropped_before_release: AtomicBool,
    observed: Notify,
    release: Notify,
    dropped: Notify,
}
#[derive(Clone, Copy)]
pub(crate) struct Observation {
    pub(crate) captured_exact_retry: bool,
    pub(crate) real_sdk_ack_held: bool,
    pub(crate) publish_calls: usize,
    pub(crate) release_requested: bool,
    pub(crate) normal_release: bool,
    pub(crate) future_dropped: bool,
    pub(crate) dropped_before_release: bool,
}
pub(crate) struct Guard(Arc<Gate>);
impl Guard {
    pub(crate) async fn observed(&self) {
        self.0.observed.notified().await;
    }
    pub(crate) fn observation(&self) -> Observation {
        Observation {
            captured_exact_retry: self.0.captured.load(Ordering::Acquire),
            real_sdk_ack_held: self.0.sdk_ack_held.load(Ordering::Acquire),
            publish_calls: self.0.publish_calls.load(Ordering::Acquire),
            release_requested: self.0.release_requested.load(Ordering::Acquire),
            normal_release: self.0.normal_release.load(Ordering::Acquire),
            future_dropped: self.0.future_dropped.load(Ordering::Acquire),
            dropped_before_release: self.0.dropped_before_release.load(Ordering::Acquire),
        }
    }
    pub(crate) fn release(&self) {
        self.0.release_requested.store(true, Ordering::Release);
        self.0.release.notify_one();
    }
    pub(crate) async fn dropped(&self) {
        while !self.0.future_dropped.load(Ordering::Acquire) {
            self.0.dropped.notified().await;
        }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.release();
    }
}
fn registry() -> &'static Mutex<Vec<Weak<Gate>>> {
    static REGISTRY: OnceLock<Mutex<Vec<Weak<Gate>>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}
pub(crate) fn arm(owner: Weak<Existing>, nonce: [u8; 32], deadline: Instant) -> Guard {
    let gate = Arc::new(Gate {
        owner,
        nonce,
        deadline,
        captured: AtomicBool::new(false),
        sdk_ack_held: AtomicBool::new(false),
        publish_calls: AtomicUsize::new(0),
        release_requested: AtomicBool::new(false),
        normal_release: AtomicBool::new(false),
        future_dropped: AtomicBool::new(false),
        dropped_before_release: AtomicBool::new(false),
        observed: Notify::new(),
        release: Notify::new(),
        dropped: Notify::new(),
    });
    let mut entries = registry().lock().expect("retry completion probe registry");
    entries.retain(|old| old.strong_count() != 0);
    assert!(
        entries.len() < 4,
        "bounded original retry completion probes"
    );
    assert!(
        !entries
            .iter()
            .filter_map(Weak::upgrade)
            .any(|old| old.owner.ptr_eq(&gate.owner))
    );
    entries.push(Arc::downgrade(&gate));
    Guard(gate)
}

// Constructed ONLY after the exact real SDK report met required ACKs. A task
// abort must actually drop this waiting future before the verdict can claim it.
struct Waiting(Arc<Gate>);
impl Drop for Waiting {
    fn drop(&mut self) {
        if !self.0.normal_release.load(Ordering::Acquire)
            && !self.0.release_requested.load(Ordering::Acquire)
        {
            self.0.dropped_before_release.store(true, Ordering::Release);
        }
        self.0.future_dropped.store(true, Ordering::Release);
        self.0.dropped.notify_one();
    }
}

/// Test-only shadow preserves both canonical adapter routes. Its delayed real
/// report remains inside the original shutdown/revocation/deadline select.
pub(crate) struct Adapter {
    inner: MarmotRelayPlaneAccountAdapter,
    gate: Option<Arc<Gate>>,
}
impl Adapter {
    pub(crate) fn capture(
        inner: MarmotRelayPlaneAccountAdapter,
        entry: &SiblingChannel,
        kind: AccountSharingControl,
    ) -> Self {
        let gate = if kind == AccountSharingControl::Request
            && !entry.recipient
            && entry.handshake_published
            && !entry.ready
        {
            if let SiblingOriginal::Existing { original, .. } = entry.original.as_ref() {
                registry()
                    .lock()
                    .expect("retry completion probe registry")
                    .iter()
                    .filter_map(Weak::upgrade)
                    .find(|gate| {
                        gate.owner.ptr_eq(&Arc::downgrade(original))
                            && gate.nonce == entry.channel.scope().nonce
                            && gate.deadline == entry.state.deadline
                            && !gate.captured.swap(true, Ordering::AcqRel)
                    })
            } else {
                None
            }
        } else {
            None
        };
        Self { inner, gate }
    }
    pub(crate) async fn publish_selected_chat(
        &self,
        request: TransportPublishRequest,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        if let Some(gate) = &self.gate {
            gate.publish_calls.fetch_add(1, Ordering::AcqRel);
        }
        let report = self.inner.publish_selected_chat(request).await?;
        if let Some(gate) = &self.gate
            && report.met_required_acks()
        {
            let _waiting = Waiting(gate.clone());
            gate.sdk_ack_held.store(true, Ordering::Release);
            gate.observed.notify_one();
            gate.release.notified().await;
            gate.normal_release.store(true, Ordering::Release);
        }
        Ok(report)
    }
    pub(crate) async fn publish_sibling_consent(
        &self,
        request: TransportPublishRequest,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        self.inner.publish_sibling_consent(request).await
    }
}
