//! Account-worker ownership and transport of exact encrypted confirmations.
use super::AppClient;
use super::device_linking::ClientLinkingError;
use crate::device_linking::settlement::SettlementGuard;
use cgka_traits::device_linking_key_package::{LinkingWelcomeDenied, PurposeAttemptScope};
use std::sync::Arc;

pub(super) struct OwnedSettlementAttempt {
    pub(super) guard: Arc<SettlementGuard>,
    selected: bool,
    published: bool,
}
impl OwnedSettlementAttempt {
    pub(super) fn new(guard: Arc<SettlementGuard>) -> Self {
        Self {
            guard,
            selected: false,
            published: false,
        }
    }
}
impl AppClient {
    pub(super) fn select_owned_private_settlement(&mut self) -> Result<(), ClientLinkingError> {
        let Some(attempt) = self.linking_owner.settlement_attempt.as_mut() else {
            return Ok(());
        };
        if !attempt.guard.is_live() {
            return Err(denied());
        }
        if !attempt.selected {
            self.runtime
                .session()
                .select_owned_private_roster_settlement(
                    &attempt.guard.group(),
                    attempt.guard.clone(),
                )
                .map_err(ClientLinkingError::Engine)?;
            attempt.selected = true;
        }
        Ok(())
    }
    pub(crate) fn pending_private_settlement(
        &mut self,
    ) -> Result<Option<PurposeAttemptScope>, ClientLinkingError> {
        let Some(attempt) = self.linking_owner.settlement_attempt.as_ref() else {
            return Ok(None);
        };
        if !attempt.guard.is_live() {
            self.revoke_owned_private_settlement()?;
            return Ok(None);
        }
        if attempt.published {
            return Ok(None);
        }
        self.select_owned_private_settlement()?;
        let attempt = self.linking_owner.settlement_attempt.as_ref().unwrap();
        Ok(self
            .runtime
            .session()
            .private_roster_settlement_publication_ready(&attempt.guard.group())
            .map_err(ClientLinkingError::Engine)?
            .then(|| attempt.guard.scope().clone()))
    }
    pub(crate) fn private_settlement_control(
        &self,
        scope: &PurposeAttemptScope,
    ) -> Result<Arc<SettlementGuard>, ClientLinkingError> {
        self.linking_owner
            .settlement_attempt
            .as_ref()
            .filter(|attempt| attempt.guard.scope() == scope && attempt.guard.is_live())
            .map(|attempt| attempt.guard.clone())
            .ok_or_else(denied)
    }
    pub(crate) fn revoke_owned_private_settlement(&mut self) -> Result<(), ClientLinkingError> {
        if let Some(attempt) = self.linking_owner.settlement_attempt.as_ref() {
            attempt.guard.revoke();
            self.runtime
                .session()
                .cancel_private_roster_settlement(&attempt.guard.group())
                .map_err(ClientLinkingError::Engine)?;
            self.linking_owner.settlement_attempt = None;
        }
        Ok(())
    }
    pub(crate) async fn dispatch_owned_private_settlement(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        let guard = self.private_settlement_control(scope)?;
        let group = guard.group();
        self.refresh_private_transport_route()
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        self.sync_runtime_groups()
            .await
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        let component = self
            .runtime
            .session()
            .app_component(&group, crate::NOSTR_ROUTING_COMPONENT_ID)
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error.into())))?
            .ok_or_else(denied)?;
        let route = cgka_traits::app_components::decode_nostr_routing_v1(&component)
            .map_err(|_| denied())?;
        let publisher = SettlementPublisher {
            adapter: self.adapter.clone(),
            account: self.runtime.session().self_id(),
            target: cgka_traits::TransportPublishTarget::Group {
                group_id: group.clone(),
                transport_group_id: route.nostr_group_id.to_vec(),
                endpoints: route
                    .relays
                    .into_iter()
                    .map(cgka_traits::TransportEndpoint)
                    .collect(),
            },
        };
        self.runtime
            .session_mut()
            .dispatch_private_roster_settlement(&group, &publisher)
            .await
            .map_err(ClientLinkingError::Engine)?;
        let attempt = self
            .linking_owner
            .settlement_attempt
            .as_mut()
            .filter(|attempt| attempt.guard.scope() == scope)
            .ok_or_else(denied)?;
        if !guard.is_live() {
            return Err(denied());
        }
        // Relay acceptance is only a publication result, never peer/common knowledge.
        attempt.published = true;
        Ok(())
    }
}
fn denied() -> ClientLinkingError {
    ClientLinkingError::Gate(LinkingWelcomeDenied::NoLiveVerifier)
}
struct SettlementPublisher {
    adapter: crate::relay_plane::MarmotRelayPlaneAccountAdapter,
    account: cgka_traits::MemberId,
    target: cgka_traits::TransportPublishTarget,
}
#[async_trait::async_trait]
impl cgka_engine::private_roster_settlement::TrustedPrivateSettlementPublisher
    for SettlementPublisher
{
    async fn publish_confirmation(
        &self,
        message: &cgka_traits::TransportMessage,
    ) -> Result<(), cgka_traits::EngineError> {
        let report = self
            .adapter
            .publish_private_confirmation(cgka_traits::transport_adapter::TransportPublishRequest {
                account_id: self.account.clone(),
                message: message.clone(),
                target: self.target.clone(),
                required_acks: 1,
            })
            .await
            .map_err(|_| {
                cgka_traits::EngineError::Other("private confirmation publication uncertain".into())
            })?;
        if !report.met_required_acks() {
            return Err(cgka_traits::EngineError::Other(
                "private confirmation publication uncertain".into(),
            ));
        }
        Ok(())
    }
}
