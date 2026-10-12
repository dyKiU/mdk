//! Test-only hold of a real durable ordinary group evolution publication.
use super::*;
use cgka_traits::storage::OutboundFanoutStorage;
use cgka_traits::{FanoutPendingKind, GroupId};

pub(super) struct Gate {
    account: MemberId,
    group: GroupId,
    storage: storage_sqlite::SqliteAccountStorage,
    observed: tokio::sync::oneshot::Sender<cgka_traits::TransportMessage>,
    release: Arc<Notify>,
}

pub(crate) struct Release {
    plane: Weak<MarmotRelayPlaneInner>,
    release: Arc<Notify>,
}
impl Drop for Release {
    fn drop(&mut self) {
        if let Some(plane) = self.plane.upgrade() {
            let mut gate = plane.ordinary_commit_gate.lock().unwrap();
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
    pub(crate) fn hold_next_ordinary_group_commit(
        &self,
        account: MemberId,
        group: GroupId,
        storage: storage_sqlite::SqliteAccountStorage,
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
            group,
            storage,
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
            if gate.account != request.account_id {
                false
            } else {
                let fanout = gate
                    .storage
                    .outbound_fanout(&request.message.id)
                    .map_err(|_| {
                        TransportAdapterError::Other(
                            "fixture durable publication unavailable".into(),
                        )
                    })?;
                fanout.is_some_and(|fanout| {
                    fanout.group_id() == Some(&gate.group)
                        && fanout.pending_kind() == Some(FanoutPendingKind::GroupEvolution)
                })
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
