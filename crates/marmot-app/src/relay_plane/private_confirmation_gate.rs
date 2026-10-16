//! Test-only ordering of one real private confirmation before relay publication.
use super::*;
use cgka_traits::GroupId;
pub(super) struct Gate {
    account: MemberId,
    group: GroupId,
    observed: Option<tokio::sync::oneshot::Sender<cgka_traits::TransportMessage>>,
    reject: bool,
    release: Arc<Notify>,
}
pub(crate) struct Release {
    plane: Weak<MarmotRelayPlaneInner>,
    release: Arc<Notify>,
}
impl Drop for Release {
    fn drop(&mut self) {
        if let Some(plane) = self.plane.upgrade() {
            let mut slot = plane
                .private_confirmation_gate
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if slot
                .as_ref()
                .is_some_and(|g| Arc::ptr_eq(&g.release, &self.release))
            {
                slot.take();
            }
        }
        self.release.notify_one();
    }
}
impl MarmotRelayPlane {
    pub(crate) fn hold_next_private_confirmation(
        &self,
        account: MemberId,
        group: GroupId,
    ) -> (
        tokio::sync::oneshot::Receiver<cgka_traits::TransportMessage>,
        Release,
    ) {
        self.intercept_private_confirmation(account, group, false)
    }
    /// Reject actual confirmation sends while allowing the worker to deliver Welcome.
    pub(crate) fn reject_private_confirmations(
        &self,
        account: MemberId,
        group: GroupId,
    ) -> (
        tokio::sync::oneshot::Receiver<cgka_traits::TransportMessage>,
        Release,
    ) {
        self.intercept_private_confirmation(account, group, true)
    }
    fn intercept_private_confirmation(
        &self,
        account: MemberId,
        group: GroupId,
        reject: bool,
    ) -> (
        tokio::sync::oneshot::Receiver<cgka_traits::TransportMessage>,
        Release,
    ) {
        let (observed, receiver) = tokio::sync::oneshot::channel();
        let release = Arc::new(Notify::new());
        let mut slot = self.inner.private_confirmation_gate.lock().unwrap();
        assert!(
            slot.is_none(),
            "one actual private confirmation may be held"
        );
        *slot = Some(Gate {
            account,
            group,
            observed: Some(observed),
            reject,
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
            .private_confirmation_gate
            .lock()
            .unwrap();
        if slot.as_ref().is_some_and(|gate| {
            matches_scope(
                &gate.account,
                &gate.group,
                &request.account_id,
                &request.target,
            )
        }) {
            if slot.as_ref().unwrap().reject {
                if let Some(observed) = slot.as_mut().unwrap().observed.take() {
                    let _ = observed.send(request.message.clone());
                }
                return Err(TransportAdapterError::Publish(
                    "injected private confirmation rejection".into(),
                ));
            }
            slot.take()
        } else {
            None
        }
    };
    if let Some(gate) = gate {
        if let Some(observed) = gate.observed {
            let _ = observed.send(request.message.clone());
        }
        gate.release.notified().await;
    }
    Ok(())
}

fn matches_scope(
    account: &MemberId,
    group: &GroupId,
    actual_account: &MemberId,
    target: &cgka_traits::TransportPublishTarget,
) -> bool {
    account == actual_account
        && matches!(target, cgka_traits::TransportPublishTarget::Group { group_id, .. } if group_id == group)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn release_before_wait_retains_notification() {
        let notify = Arc::new(Notify::new());
        let release = Release {
            plane: Weak::new(),
            release: notify.clone(),
        };
        drop(release);
        tokio::time::timeout(std::time::Duration::from_millis(100), notify.notified())
            .await
            .expect("a release before await must not strand the real publisher");
    }
    #[test]
    fn exact_account_and_group_are_required() {
        let account = MemberId::new(vec![1; 32]);
        let other = MemberId::new(vec![2; 32]);
        let group = GroupId::new(vec![3; 16]);
        let different = GroupId::new(vec![4; 16]);
        let target = cgka_traits::TransportPublishTarget::Group {
            group_id: group.clone(),
            transport_group_id: vec![5; 32],
            endpoints: vec![],
        };
        assert!(matches_scope(&account, &group, &account, &target));
        assert!(!matches_scope(&account, &group, &other, &target));
        assert!(!matches_scope(&account, &different, &account, &target));
        assert!(!matches_scope(
            &account,
            &group,
            &account,
            &cgka_traits::TransportPublishTarget::Inbox {
                recipient: account.clone(),
                endpoints: vec![]
            }
        ));
    }
}
