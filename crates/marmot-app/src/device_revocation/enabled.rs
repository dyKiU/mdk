//! Bounded original administrator review ownership; no persisted approval.
use super::{GroupDeviceRevocationError, GroupDeviceRevocationSnapshot};
use cgka_engine::device_leaf_revocation::DeviceLeafRevocationSelection;
use std::{
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
const MAX_REVOCATION_ORIGINALS: u32 = 128;
const REVOCATION_ORIGINAL_LIFETIME: Duration = Duration::from_secs(600);

pub(crate) struct State {
    pub(crate) selection: DeviceLeafRevocationSelection,
    pub(crate) remaining: Vec<DeviceLeafRevocationSelection>,
    pub(crate) whole_device: bool,
    owner: Weak<AtomicBool>,
    deadline: Instant,
    cancelled: AtomicBool,
    revoked: tokio::sync::Notify,
    pub(crate) progress: Mutex<Progress>,
}
impl State {
    pub(crate) fn selections(&self) -> impl Iterator<Item = &DeviceLeafRevocationSelection> {
        std::iter::once(&self.selection).chain(&self.remaining)
    }
    pub(crate) fn current_selection(&self) -> &DeviceLeafRevocationSelection {
        self.selections()
            .nth(self.progress.lock().expect("revocation progress").index)
            .expect("bounded captured revocation scope")
    }
    pub(crate) fn device_snapshot(
        &self,
    ) -> Result<super::DeviceRevocationSnapshot, GroupDeviceRevocationError> {
        self.check()?;
        let protected = self
            .selections()
            .last()
            .ok_or(GroupDeviceRevocationError::InvalidSelection)?;
        if !self.whole_device || !protected.is_protected_group() {
            return Err(GroupDeviceRevocationError::InvalidSelection);
        }
        let progress = self.progress.lock().expect("revocation progress");
        Ok(super::DeviceRevocationSnapshot {
            revision: if progress.complete { 2 } else { 1 },
            complete: progress.complete,
            protected_group: protected.review().group.clone(),
            ordinary_groups: self
                .selections()
                .filter(|s| !s.is_protected_group())
                .map(|s| s.review().group.clone())
                .collect(),
            completed_groups: self
                .selections()
                .take(progress.index)
                .map(|s| s.review().group.clone())
                .collect(),
            target_device: protected.review().target_device.clone(),
        })
    }
    pub(crate) fn check(&self) -> Result<(), GroupDeviceRevocationError> {
        if self.cancelled.load(Ordering::Acquire)
            || Instant::now() >= self.deadline
            || !self
                .owner
                .upgrade()
                .is_some_and(|owner| owner.load(Ordering::Acquire))
        {
            return Err(GroupDeviceRevocationError::Closed);
        }
        Ok(())
    }
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.revoked.notify_waiters();
    }
    pub(crate) async fn revoked(&self) {
        loop {
            let notified = self.revoked.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.check().is_err() {
                return;
            }
            tokio::select! {
                _ = &mut notified => {},
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(self.deadline)) => return,
            }
        }
    }
    pub(crate) fn check_revision(&self, revision: u64) -> Result<(), GroupDeviceRevocationError> {
        self.check()?;
        if revision != self.snapshot()?.revision {
            return Err(GroupDeviceRevocationError::StaleRevision);
        }
        Ok(())
    }
    pub(crate) fn snapshot(
        &self,
    ) -> Result<GroupDeviceRevocationSnapshot, GroupDeviceRevocationError> {
        self.check()?;
        let review = self.selection.review();
        Ok(GroupDeviceRevocationSnapshot {
            revision: if self.progress.lock().expect("revocation progress").complete {
                2
            } else {
                1
            },
            complete: self.progress.lock().expect("revocation progress").complete,
            group: review.group.clone(),
            epoch: review.epoch,
            target_leaf_index: review.target_leaf_index,
            target_device: review.target_device.clone(),
            surviving_same_account_leaves: review.surviving_same_account_leaves,
        })
    }
}
pub(crate) struct AccountRevocationOwner {
    lifetime: Arc<AtomicBool>,
    current: Option<Weak<State>>,
    created: u32,
    cleanup: Option<(
        cgka_traits::PendingStateRef,
        cgka_traits::MessageId,
        cgka_traits::GroupId,
        Weak<State>,
    )>,
}
impl Default for AccountRevocationOwner {
    fn default() -> Self {
        Self {
            lifetime: Arc::new(AtomicBool::new(true)),
            current: None,
            created: 0,
            cleanup: None,
        }
    }
}
impl AccountRevocationOwner {
    pub(crate) fn reserve(
        &mut self,
        selection: DeviceLeafRevocationSelection,
    ) -> Result<Arc<State>, GroupDeviceRevocationError> {
        self.reserve_selections(vec![selection], false)
    }
    pub(crate) fn reserve_selections(
        &mut self,
        mut selections: Vec<DeviceLeafRevocationSelection>,
        whole_device: bool,
    ) -> Result<Arc<State>, GroupDeviceRevocationError> {
        if selections.is_empty() || selections.len() > 128 {
            return Err(GroupDeviceRevocationError::InvalidSelection);
        }
        if self.cleanup.is_some()
            || self.created >= MAX_REVOCATION_ORIGINALS
            || self
                .current
                .as_ref()
                .and_then(Weak::upgrade)
                .is_some_and(|original| original.check().is_ok())
        {
            return Err(GroupDeviceRevocationError::Busy);
        }
        let original = Arc::new(State {
            selection: selections.remove(0),
            remaining: selections,
            whole_device,
            owner: Arc::downgrade(&self.lifetime),
            deadline: Instant::now() + REVOCATION_ORIGINAL_LIFETIME,
            cancelled: AtomicBool::new(false),
            revoked: tokio::sync::Notify::new(),
            progress: Mutex::new(Progress::default()),
        });
        self.current = Some(Arc::downgrade(&original));
        self.created += 1;
        Ok(original)
    }
    pub(crate) fn register_pending(
        &mut self,
        original: &Arc<State>,
        pending: cgka_traits::PendingStateRef,
        origin: cgka_traits::MessageId,
        group: cgka_traits::GroupId,
    ) {
        self.cleanup = Some((pending, origin, group, Arc::downgrade(original)));
    }
    pub(crate) fn pending_to_retire(
        &self,
    ) -> Option<(
        cgka_traits::PendingStateRef,
        cgka_traits::MessageId,
        cgka_traits::GroupId,
    )> {
        self.cleanup
            .as_ref()
            .filter(|(_, _, _, original)| {
                original
                    .upgrade()
                    .is_none_or(|original| original.check().is_err())
            })
            .map(|(pending, origin, group, _)| (*pending, origin.clone(), group.clone()))
    }
    pub(crate) fn clear_pending(&mut self, pending: cgka_traits::PendingStateRef) {
        if self
            .cleanup
            .as_ref()
            .is_some_and(|(stored, _, _, _)| *stored == pending)
        {
            self.cleanup = None;
        }
    }
    pub(crate) fn owns(&self, original: &Arc<State>) -> bool {
        self.current
            .as_ref()
            .is_some_and(|current| Weak::ptr_eq(current, &Arc::downgrade(original)))
    }
}
impl Drop for AccountRevocationOwner {
    fn drop(&mut self) {
        self.lifetime.store(false, Ordering::Release);
    }
}

#[derive(Default)]
pub(crate) struct Progress {
    pub(crate) index: usize,
    pub(crate) prepared: Option<Prepared>,
    pub(crate) complete: bool,
}
pub(crate) struct Prepared {
    pub(crate) pending: cgka_traits::PendingStateRef,
    pub(crate) origin: cgka_traits::MessageId,
    pub(crate) message: cgka_traits::TransportMessage,
    pub(crate) report: Option<cgka_traits::TransportPublishReport>,
    pub(crate) effects: Option<cgka_session::SessionEffects>,
    pub(crate) confirmed: bool,
}
