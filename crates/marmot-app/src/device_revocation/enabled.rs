//! Bounded original administrator review ownership; no persisted approval.
use super::{GroupDeviceRevocationError, GroupDeviceRevocationSnapshot};
use cgka_engine::device_leaf_revocation::DeviceLeafRevocationSelection;
use std::{
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
const MAX_REVOCATION_ORIGINALS: u32 = 128;
const REVOCATION_ORIGINAL_LIFETIME: Duration = Duration::from_secs(600);

pub(crate) struct State {
    pub(crate) selection: DeviceLeafRevocationSelection,
    owner: Weak<AtomicBool>,
    deadline: Instant,
    cancelled: AtomicBool,
}
impl State {
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
    }
    pub(crate) fn snapshot(
        &self,
    ) -> Result<GroupDeviceRevocationSnapshot, GroupDeviceRevocationError> {
        self.check()?;
        let review = self.selection.review();
        Ok(GroupDeviceRevocationSnapshot {
            revision: 1,
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
}
impl Default for AccountRevocationOwner {
    fn default() -> Self {
        Self {
            lifetime: Arc::new(AtomicBool::new(true)),
            current: None,
            created: 0,
        }
    }
}
impl AccountRevocationOwner {
    pub(crate) fn reserve(
        &mut self,
        selection: DeviceLeafRevocationSelection,
    ) -> Result<Arc<State>, GroupDeviceRevocationError> {
        if self.created >= MAX_REVOCATION_ORIGINALS
            || self
                .current
                .as_ref()
                .and_then(Weak::upgrade)
                .is_some_and(|original| original.check().is_ok())
        {
            return Err(GroupDeviceRevocationError::Busy);
        }
        let original = Arc::new(State {
            selection,
            owner: Arc::downgrade(&self.lifetime),
            deadline: Instant::now() + REVOCATION_ORIGINAL_LIFETIME,
            cancelled: AtomicBool::new(false),
        });
        self.current = Some(Arc::downgrade(&original));
        self.created += 1;
        Ok(original)
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
