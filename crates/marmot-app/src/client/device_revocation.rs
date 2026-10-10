//! Serial fresh authenticated selection; imported review data grants nothing.
use super::AppClient;
use crate::device_revocation::{
    GroupDeviceRevocationError, GroupDeviceRevocationSnapshot, enabled::State,
};
use cgka_traits::GroupId;
use std::sync::Arc;

impl AppClient {
    pub(crate) fn begin_original_group_device_revocation(
        &mut self,
        group: &GroupId,
        target: &[u8],
    ) -> Result<Arc<State>, GroupDeviceRevocationError> {
        self.ensure_group(group)
            .map_err(|_| GroupDeviceRevocationError::InvalidSelection)?;
        self.runtime
            .session_mut()
            .ensure_group_hydrated(group)
            .map_err(|_| GroupDeviceRevocationError::InvalidSelection)?;
        let selection = self
            .runtime
            .session()
            .capture_device_leaf_revocation_selection(group, target)
            .map_err(|_| GroupDeviceRevocationError::InvalidSelection)?;
        self.device_revocation_owner.reserve(selection)
    }
    pub(crate) fn observe_original_group_device_revocation(
        &self,
        original: &Arc<State>,
    ) -> Result<GroupDeviceRevocationSnapshot, GroupDeviceRevocationError> {
        original.check()?;
        if !self.device_revocation_owner.owns(original) {
            return Err(GroupDeviceRevocationError::Closed);
        }
        self.runtime
            .session()
            .validate_device_leaf_revocation_selection(&original.selection)
            .map_err(|_| GroupDeviceRevocationError::InvalidSelection)?;
        original.snapshot()
    }
}
