//! Test-only hold of a real durable ordinary group evolution publication.
use super::*;
use cgka_traits::storage::OutboundFanoutStorage;
use cgka_traits::{FanoutPendingKind, GroupId};

type FanoutPredicate =
    dyn Fn(&TransportPublishRequest) -> Result<bool, TransportAdapterError> + Send + Sync;

pub(super) struct Gate {
    account: MemberId,
    matches_fanout: Box<FanoutPredicate>,
    observed: tokio::sync::oneshot::Sender<cgka_traits::TransportMessage>,
    release: Arc<Notify>,
}

pub struct Release {
    plane: Weak<MarmotRelayPlaneInner>,
    release: Arc<Notify>,
}
impl Drop for Release {
    fn drop(&mut self) {
        if let Some(plane) = self.plane.upgrade() {
            let mut gate = plane
                .ordinary_commit_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if gate
                .as_ref()
                .is_some_and(|gate| Arc::ptr_eq(&gate.release, &self.release))
            {
                gate.take();
            }
        }
        self.release.notify_waiters();
        self.release.notify_one();
    }
}
impl MarmotRelayPlane {
    #[doc(hidden)]
    pub fn hold_next_ordinary_group_commit<S: OutboundFanoutStorage + Send + Sync + 'static>(
        &self,
        account: MemberId,
        group: GroupId,
        storage: S,
    ) -> (
        tokio::sync::oneshot::Receiver<cgka_traits::TransportMessage>,
        Release,
    ) {
        let (observed, receiver) = tokio::sync::oneshot::channel();
        let release = Arc::new(Notify::new());
        let mut slot = self.inner.ordinary_commit_gate.lock().unwrap();
        assert!(
            slot.is_none(),
            "only one actual ordinary publication may be held"
        );
        *slot = Some(Gate {
            account,
            matches_fanout: Box::new(move |request| {
                let fanout = storage.outbound_fanout(&request.message.id).map_err(|_| {
                    TransportAdapterError::Other("fixture durable publication unavailable".into())
                })?;
                Ok(fanout.is_some_and(|fanout| {
                    fanout.group_id() == Some(&group)
                        && fanout.pending_kind() == Some(FanoutPendingKind::GroupEvolution)
                }))
            }),
            observed,
            release: release.clone(),
        });
        (
            receiver,
            Release {
                plane: Arc::downgrade(&self.inner),
                release,
            },
        )
    }
}

pub(super) async fn hold(
    adapter: &MarmotRelayPlaneAccountAdapter,
    request: &TransportPublishRequest,
) -> Result<(), TransportAdapterError> {
    let gate = {
        let mut slot = adapter
            .relay_plane
            .inner
            .ordinary_commit_gate
            .lock()
            .unwrap();
        let matches = if let Some(gate) = slot.as_ref() {
            if gate.account != request.account_id
                || !matches!(
                    request.target,
                    cgka_traits::TransportPublishTarget::Group { .. }
                )
            {
                false
            } else {
                (gate.matches_fanout)(request)?
            }
        } else {
            false
        };
        if matches { slot.take() } else { None }
    };
    if let Some(gate) = gate {
        let release = gate.release.notified();
        tokio::pin!(release);
        release.as_mut().enable();
        let _ = gate.observed.send(request.message.clone());
        release.await;
    }
    Ok(())
}
