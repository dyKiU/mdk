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
        if original
            .progress
            .lock()
            .expect("revocation progress")
            .complete
        {
            self.runtime
                .session()
                .confirmed_device_leaf_revocation(&original.selection)
                .map_err(|_| GroupDeviceRevocationError::InvalidSelection)?;
        } else {
            self.runtime
                .session()
                .validate_device_leaf_revocation_selection(&original.selection)
                .map_err(|_| GroupDeviceRevocationError::InvalidSelection)?;
        }
        original.snapshot()
    }
}

struct OriginalRemovalLease {
    original: Arc<State>,
    revision: u64,
}
impl cgka_engine::device_leaf_revocation::DeviceLeafRevocationLease for OriginalRemovalLease {
    fn check_original(
        &mut self,
        selection: &cgka_engine::device_leaf_revocation::DeviceLeafRevocationSelection,
    ) -> Result<(), cgka_traits::EngineError> {
        if !std::ptr::eq(selection, &self.original.selection) {
            return Err(cgka_traits::EngineError::Other(
                "device revocation original unavailable".into(),
            ));
        }
        self.original.check_revision(self.revision).map_err(|_| {
            cgka_traits::EngineError::Other("device revocation original unavailable".into())
        })
    }
}
impl AppClient {
    pub(crate) async fn maintain_device_leaf_revocation_pending(
        &mut self,
    ) -> Result<(), cgka_session::SessionError> {
        if let Some((pending, origin, group)) = self.device_revocation_owner.pending_to_retire() {
            self.runtime
                .session_mut()
                .retire_device_leaf_revocation_pending(pending, &origin, &group)
                .await?;
            self.device_revocation_owner.clear_pending(pending);
        }
        Ok(())
    }
    pub(crate) async fn approve_original_group_device_revocation(
        &mut self,
        original: &Arc<State>,
        revision: u64,
    ) -> Result<(), GroupDeviceRevocationError> {
        use cgka_engine::device_leaf_revocation::DeviceLeafRevocationLease;
        use cgka_traits::{SendResult, TransportPublishRequest, TransportPublishTarget};
        let unavailable = |_| GroupDeviceRevocationError::RuntimeUnavailable;
        if !self.device_revocation_owner.owns(original) {
            return Err(GroupDeviceRevocationError::Closed);
        }
        original.check_revision(revision)?;
        if original
            .progress
            .lock()
            .expect("revocation progress")
            .complete
        {
            return Ok(());
        }
        let group = original.selection.review().group.clone();
        let component = self
            .runtime
            .session()
            .app_component(&group, crate::NOSTR_ROUTING_COMPONENT_ID)
            .map_err(|_| GroupDeviceRevocationError::InvalidSelection)?
            .ok_or(GroupDeviceRevocationError::InvalidSelection)?;
        let route = cgka_traits::app_components::decode_nostr_routing_v1(&component)
            .map_err(|_| GroupDeviceRevocationError::InvalidSelection)?;
        let mut lease = OriginalRemovalLease {
            original: original.clone(),
            revision,
        };
        if original
            .progress
            .lock()
            .expect("revocation progress")
            .prepared
            .is_none()
        {
            self.observe_original_group_device_revocation(original)?;
            let result = self
                .runtime
                .session_mut()
                .prepare_device_leaf_revocation(&original.selection, &mut lease)
                .await
                .map_err(unavailable)?;
            let SendResult::GroupEvolution {
                msg,
                pending,
                welcomes,
            } = result
            else {
                return Err(GroupDeviceRevocationError::NotReady);
            };
            // Register exact negative cleanup synchronously before any await/read.
            self.device_revocation_owner.register_pending(
                original,
                pending,
                msg.id.clone(),
                group.clone(),
            );
            original
                .progress
                .lock()
                .expect("revocation prepared")
                .prepared = Some(crate::device_revocation::enabled::Prepared {
                pending,
                origin: msg.id.clone(),
                message: msg,
                report: None,
                effects: None,
                confirmed: false,
            });
            if !welcomes.is_empty() {
                original.cancel();
                return Err(GroupDeviceRevocationError::NotReady);
            }
        }
        let (pending, origin, message, acknowledged, confirmed) = {
            let p = original.progress.lock().expect("revocation prepared");
            let prepared = p.prepared.as_ref().unwrap();
            (
                prepared.pending,
                prepared.origin.clone(),
                prepared.message.clone(),
                prepared.report.is_some(),
                prepared.confirmed,
            )
        };
        if !confirmed {
            self.runtime
                .session()
                .validate_prepared_device_leaf_revocation(&original.selection, pending, &origin)
                .map_err(unavailable)?;
            lease
                .check_original(&original.selection)
                .map_err(unavailable)?;
            if !acknowledged {
                let report = self
                    .adapter
                    .publish_selected_chat(TransportPublishRequest {
                        account_id: self.runtime.session().self_id(),
                        message,
                        target: TransportPublishTarget::Group {
                            group_id: group.clone(),
                            transport_group_id: route.nostr_group_id.to_vec(),
                            endpoints: route
                                .relays
                                .into_iter()
                                .map(cgka_traits::TransportEndpoint)
                                .collect(),
                        },
                        required_acks: 1,
                    })
                    .await
                    .map_err(|_| GroupDeviceRevocationError::RuntimeUnavailable)?;
                lease
                    .check_original(&original.selection)
                    .map_err(unavailable)?;
                if !report.met_required_acks() {
                    return Err(GroupDeviceRevocationError::RuntimeUnavailable);
                }
                original
                    .progress
                    .lock()
                    .expect("revocation ack")
                    .prepared
                    .as_mut()
                    .unwrap()
                    .report = Some(report);
            }
            self.runtime
                .session()
                .validate_prepared_device_leaf_revocation(&original.selection, pending, &origin)
                .map_err(unavailable)?;
            lease
                .check_original(&original.selection)
                .map_err(unavailable)?;
            let effects = self
                .runtime
                .session_mut()
                .confirm_published(pending)
                .await
                .map_err(|_| GroupDeviceRevocationError::RuntimeUnavailable)?;
            // Store the committed outcome before any fallible subsequent check.
            {
                let mut p = original.progress.lock().expect("revocation confirmed");
                let prepared = p.prepared.as_mut().unwrap();
                prepared.confirmed = true;
                prepared.effects = Some(effects);
            }
            self.device_revocation_owner.clear_pending(pending);
        }
        original.check()?;
        self.runtime
            .session()
            .confirmed_device_leaf_revocation(&original.selection)
            .map_err(unavailable)?;
        let effects = {
            let p = original.progress.lock().expect("revocation effects");
            let prepared = p.prepared.as_ref().unwrap();
            prepared
                .effects
                .clone()
                .map(|effects| (effects, prepared.report.clone()))
        };
        if let Some((effects, report)) = effects {
            if !effects.publish.is_empty() {
                return Err(GroupDeviceRevocationError::NotReady);
            }
            let effects = marmot_account::AccountDeviceEffects {
                events: effects.events,
                queued: effects.queued,
                pending_convergence: effects.pending_convergence,
                reports: vec![report.ok_or(GroupDeviceRevocationError::NotReady)?],
                ..Default::default()
            };
            self.observe_send_applied_effects(&effects)
                .await
                .map_err(|_| GroupDeviceRevocationError::RuntimeUnavailable)?;
            self.save_state_with_pending_local_group_deletion_frontier_clears()
                .map_err(|_| GroupDeviceRevocationError::RuntimeUnavailable)?;
            original
                .progress
                .lock()
                .expect("revocation effects")
                .prepared
                .as_mut()
                .unwrap()
                .effects = None;
        }
        original.check()?;
        original
            .progress
            .lock()
            .expect("revocation complete")
            .complete = true;
        Ok(())
    }
}
