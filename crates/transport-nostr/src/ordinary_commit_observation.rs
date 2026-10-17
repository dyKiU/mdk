//! One-publication test callback; product-specific inspection stays in the app.
use super::*;

type PublicationObserver = dyn Fn(&TransportPublishRequest) -> bool + Send + Sync;

pub(super) struct Watch {
    callback: Arc<PublicationObserver>,
}

/// Owns one test observation. Dropping it removes only that registration.
#[doc(hidden)]
pub struct PublicationObservationGuard {
    plane: Weak<MarmotRelayPlaneInner>,
    watch: Arc<Watch>,
}

impl Drop for PublicationObservationGuard {
    fn drop(&mut self) {
        if let Some(plane) = self.plane.upgrade() {
            let mut slot = plane.ordinary_commit_observation.lock().unwrap_or_else(|e| e.into_inner());
            if slot.as_ref().is_some_and(|current| Arc::ptr_eq(current, &self.watch)) {
                slot.take();
            }
        }
    }
}

impl MarmotRelayPlane {
    /// Observe actual requests before real relay publication. `true` retires this
    /// registration; the callback supplies no transport result or permission.
    #[doc(hidden)]
    pub fn observe_publications_for_test(
        &self,
        callback: Arc<PublicationObserver>,
    ) -> PublicationObservationGuard {
        let watch = Arc::new(Watch { callback });
        let mut slot = self.inner.ordinary_commit_observation.lock().unwrap_or_else(|e| e.into_inner());
        assert!(slot.is_none(), "only one publication observation may be armed");
        *slot = Some(watch.clone());
        PublicationObservationGuard { plane: Arc::downgrade(&self.inner), watch }
    }
}

pub(super) fn observe(adapter: &MarmotRelayPlaneAccountAdapter, request: &TransportPublishRequest) {
    let watch = adapter.relay_plane.inner.ordinary_commit_observation.lock()
        .unwrap_or_else(|e| e.into_inner()).as_ref().cloned();
    let Some(watch) = watch else { return };
    if !(watch.callback)(request) { return; }
    let mut slot = adapter.relay_plane.inner.ordinary_commit_observation.lock()
        .unwrap_or_else(|e| e.into_inner());
    if slot.as_ref().is_some_and(|current| Arc::ptr_eq(current, &watch)) {
        slot.take();
    }
}
