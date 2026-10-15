//! One hidden private subscription; never an ordinary conversation projection.
use super::AppClient;
use crate::AppError;
use cgka_traits::{TransportEndpoint, TransportGroupSubscription};

impl AppClient {
    /// Exercise the production route and subscription refresh under the real
    /// actor owner. The selector and returned booleans never grant authority.
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) async fn refresh_revocation_receive_route_for_test(
        &mut self,
        group: &cgka_traits::GroupId,
    ) -> Result<(bool, bool, bool), AppError> {
        let original_retry = self
            .runtime
            .session()
            .device_revocation_storage_retry_groups()
            .map_err(cgka_session::SessionError::from)?
            .contains(group);
        let evidence_absent = self
            .runtime
            .session()
            .private_transport_evidence(crate::NOSTR_ROUTING_COMPONENT_ID)
            .map_err(cgka_session::SessionError::from)?
            .is_none();
        self.refresh_private_transport_route()?;
        // Complete the actual adapter subscription replacement before the
        // fixture releases its original held source Challenge.
        self.sync_runtime_groups().await?;
        let retained_route = self.linking_owner.hidden_transport_group.as_ref() == Some(group)
            && self
                .routing
                .snapshot()
                .group_routes
                .iter()
                .any(|route| &route.group_id == group);
        Ok((original_retry, evidence_absent, retained_route))
    }

    pub(super) fn private_event_must_remain_hidden(
        &self,
        event: &cgka_traits::GroupEvent,
    ) -> Result<bool, AppError> {
        let Some(group) = crate::groups::event_group_id(event) else {
            return Ok(false);
        };
        self.runtime
            .session()
            .exclude_private_group_from_chat(group)
            .map_err(cgka_session::SessionError::from)
            .map_err(AppError::from)
    }

    /// Refresh only protected selected crypto metadata, with no full group sweep.
    pub(super) fn refresh_private_transport_route(&mut self) -> Result<bool, AppError> {
        let evidence = self
            .runtime
            .session()
            .private_transport_evidence(crate::NOSTR_ROUTING_COMPONENT_ID)
            .map_err(cgka_session::SessionError::from)?;
        if evidence.is_none()
            && let Some(previous) = &self.linking_owner.hidden_transport_group
        {
            let retry_groups = self
                .runtime
                .session()
                .device_revocation_storage_retry_groups()
                .map_err(cgka_session::SessionError::from)?;
            if retry_groups.contains(previous) {
                // Keep only this already-selected receive route while Core
                // retains the actual live rollback original. No new crypto
                // evidence or permission is reconstructed from its metadata.
                return Ok(false);
            }
        }
        let selected = evidence
            .as_ref()
            .map(|evidence| evidence.group_id().clone());
        // A failed protected read above cannot downgrade the existing source
        // fence. This stores classification metadata only, before any REQ.
        self.adapter
            .set_private_observation_group(selected.clone())?;
        let mut changed = false;
        if let Some(previous) = &self.linking_owner.hidden_transport_group
            && selected.as_ref() != Some(previous)
        {
            changed |= self.routing.replace_group_routes(previous, Vec::new());
        }
        if let Some(evidence) = evidence {
            let route = cgka_traits::app_components::decode_nostr_routing_v1(evidence.component())
                .map_err(|_| {
                    AppError::InvalidAppMessagePayload("invalid private route component".into())
                })?;
            changed |= self.routing.replace_group_routes(
                evidence.group_id(),
                vec![TransportGroupSubscription {
                    group_id: evidence.group_id().clone(),
                    transport_group_id: route.nostr_group_id.to_vec(),
                    endpoints: route.relays.into_iter().map(TransportEndpoint).collect(),
                    retained_since: None,
                }],
            );
        }
        self.linking_owner.hidden_transport_group = selected;
        if changed {
            self.pending_runtime_group_subscription_refresh = true;
        }

        Ok(changed)
    }
}
