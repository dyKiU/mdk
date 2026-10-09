//! Publication remains on the original explicit B action and private route.
use super::{AppClient, ClientLinkingError, rejected};

impl AppClient {
    pub(crate) fn enrollment_endorsement_control(
        &self,
        binding: &[u8; 32],
    ) -> Result<
        (
            std::time::Instant,
            cgka_engine::private_enrollment_endorsement::EnrollmentEndorsementCancellation,
        ),
        ClientLinkingError,
    > {
        let attempt = self
            .linking_owner
            .received_endorsement
            .as_ref()
            .filter(|attempt| attempt.binding == *binding && !attempt.cancelled)
            .ok_or_else(rejected)?;
        self.runtime
            .session()
            .validate_owned_private_enrollment_endorsement(&attempt.owned)
            .map_err(ClientLinkingError::Engine)?;
        attempt.owned.wire().map_err(ClientLinkingError::Engine)?;
        Ok((attempt.deadline, attempt.owned.cancellation_handle()))
    }

    pub(crate) async fn dispatch_received_enrollment_endorsement(
        &mut self,
        binding: &[u8; 32],
    ) -> Result<(), ClientLinkingError> {
        self.enrollment_endorsement_control(binding)?;
        self.refresh_private_transport_route()
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        self.sync_runtime_groups()
            .await
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        let attempt = self.linking_owner.received_endorsement.as_mut().unwrap();
        let message = self
            .runtime
            .session_mut()
            .wrap_private_enrollment_endorsement(&mut attempt.owned)
            .await
            .map_err(ClientLinkingError::Engine)?;
        let component = self
            .runtime
            .session()
            .app_component(&attempt.group, crate::NOSTR_ROUTING_COMPONENT_ID)
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error.into())))?
            .ok_or_else(rejected)?;
        let route = cgka_traits::app_components::decode_nostr_routing_v1(&component)
            .map_err(|_| rejected())?;
        self.runtime
            .session()
            .validate_owned_private_enrollment_endorsement(&attempt.owned)
            .map_err(ClientLinkingError::Engine)?;
        let report = self
            .adapter
            .publish_private_enrollment_proposal(
                cgka_traits::transport_adapter::TransportPublishRequest {
                    account_id: self.runtime.session().self_id(),
                    message,
                    target: cgka_traits::TransportPublishTarget::Group {
                        group_id: attempt.group.clone(),
                        transport_group_id: route.nostr_group_id.to_vec(),
                        endpoints: route
                            .relays
                            .into_iter()
                            .map(cgka_traits::TransportEndpoint)
                            .collect(),
                    },
                    required_acks: 1,
                },
            )
            .await
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error.into())))?;
        self.runtime
            .session()
            .validate_owned_private_enrollment_endorsement(&attempt.owned)
            .map_err(ClientLinkingError::Engine)?;
        if !report.met_required_acks() {
            return Err(ClientLinkingError::Engine(cgka_traits::EngineError::Other(
                "private endorsement publication uncertain".into(),
            )));
        }
        Ok(())
    }
}
