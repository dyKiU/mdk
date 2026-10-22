//! Bounded acquisition metadata for one uncertain private commit. No consent.
use super::AppClient;
use crate::AppError;
use cgka_traits::private_device_invite::{
    PrivateInviteBinding, PrivateInvitePhase, PrivateInviteScope,
};
use cgka_traits::storage::{AccountDeviceSignerStorage, StorageError};
use cgka_traits::{
    GroupId, MemberId, StorageProvider, TransportEndpoint, TransportEnvelope, TransportMessage,
};
use std::time::{Duration, Instant};
use transport_nostr_adapter::{
    NostrAcquisitionCancellation, NostrAcquisitionLimits, NostrAcquisitionRequest,
    NostrAcquisitionResult, NostrAcquisitionScope, NostrRelayEvent,
};
use transport_nostr_peeler::NostrTransportEvent;

pub(crate) enum PrivateEchoError {
    App(AppError),
    Protected(cgka_traits::private_device_invite::PrivateInviteStorageError),
}
impl From<AppError> for PrivateEchoError {
    fn from(error: AppError) -> Self {
        Self::App(error)
    }
}
impl From<StorageError> for PrivateEchoError {
    fn from(error: StorageError) -> Self {
        Self::App(error.into())
    }
}
impl From<cgka_session::SessionError> for PrivateEchoError {
    fn from(error: cgka_session::SessionError) -> Self {
        Self::App(error.into())
    }
}
impl From<cgka_traits::TransportAdapterError> for PrivateEchoError {
    fn from(error: cgka_traits::TransportAdapterError) -> Self {
        Self::App(error.into())
    }
}
impl From<cgka_traits::private_device_invite::PrivateInviteStorageError> for PrivateEchoError {
    fn from(error: cgka_traits::private_device_invite::PrivateInviteStorageError) -> Self {
        Self::Protected(error)
    }
}
impl PrivateEchoError {
    pub(crate) fn into_app(self) -> AppError {
        match self {
            Self::App(error) => error,
            Self::Protected(
                cgka_traits::private_device_invite::PrivateInviteStorageError::Storage(error),
            ) => error.into(),
            Self::Protected(_) => {
                StorageError::Serialization("invalid protected private comparison metadata".into())
                    .into()
            }
        }
    }
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::App(error) => error.privacy_safe_kind(),
            Self::Protected(error) => match error {
                cgka_traits::private_device_invite::PrivateInviteStorageError::Storage(_) => {
                    "storage"
                }
                _ => "protected_metadata",
            },
        }
    }
}

const RETRY: Duration = Duration::from_secs(5);
const MAX_ENDPOINTS: usize = 4;
const MAX_BYTES: usize = 1024 * 1024;

/// Only the account actor derives this plan from protected storage AND current
/// crypto evidence. It is neither serializable nor membership/delivery authority.
#[derive(PartialEq, Eq)]
pub(crate) struct PrivateEchoPlan {
    scope: PrivateInviteScope,
    binding: PrivateInviteBinding,
    group: GroupId,
    route: [u8; 32],
    commit: TransportMessage,
    id: [u8; 32],
    account: MemberId,
    endpoints: Vec<TransportEndpoint>,
}

pub(crate) struct PrivateEchoTask {
    pub(crate) plan: PrivateEchoPlan,
    handle: tokio::task::JoinHandle<
        Result<NostrAcquisitionResult, transport_nostr_adapter::NostrAcquisitionError>,
    >,
    cancellation: NostrAcquisitionCancellation,
    // Share the existing process-wide recovery backpressure. Never overlap this
    // task with the account's ordinary comparison job.
    _credit: tokio::sync::OwnedSemaphorePermit,
}
impl Drop for PrivateEchoTask {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.handle.abort();
    }
}
impl PrivateEchoTask {
    pub(crate) async fn wait(
        &mut self,
    ) -> Result<
        Result<NostrAcquisitionResult, transport_nostr_adapter::NostrAcquisitionError>,
        tokio::task::JoinError,
    > {
        (&mut self.handle).await
    }
}

impl AppClient {
    fn read_private_echo_plan(&self) -> Result<Option<PrivateEchoPlan>, PrivateEchoError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let Some(capability) = storage.private_device_invite_storage() else {
            return Ok(None);
        };
        let Some(fact) = capability.private_invite()? else {
            return Ok(None);
        };
        // An interrupted invocation may retain Dispatching without a live
        // publisher/SDK lease. Both uncertain phases need exact-byte acquisition;
        // this does not permit redispatch or reconstruct publication consent.
        if !matches!(
            fact.phase,
            PrivateInvitePhase::Dispatching | PrivateInvitePhase::PublicationUnknown
        ) {
            return Ok(None);
        }
        let Some(evidence) = self
            .runtime
            .session()
            .private_transport_evidence(crate::NOSTR_ROUTING_COMPONENT_ID)
            .map_err(cgka_session::SessionError::from)?
        else {
            return Ok(None);
        };
        let invalid =
            || StorageError::Serialization("invalid protected private acquisition metadata".into());
        let account = self.runtime.session().self_id();
        let device = storage
            .account_device_signer(&account)?
            .ok_or_else(invalid)?;
        if device.marmot_identity != account
            || account.as_slice() != fact.scope.account
            || device.mls_signature_public_key.as_slice() != fact.scope.local_device
            || fact.raw.binding.approver_scope.account != fact.scope.account
            || fact.raw.binding.approver_scope.local_device != fact.scope.local_device
            || evidence.group_id() != &fact.raw.binding.group_id
        {
            return Err(invalid().into());
        }
        let route = cgka_traits::app_components::decode_nostr_routing_v1(evidence.component())
            .map_err(|_| invalid())?;
        let commit = fact.transport.ok_or_else(invalid)?.commit;
        if commit.payload.len() > MAX_BYTES {
            return Err(invalid().into());
        }
        let event = NostrTransportEvent::from_transport_message(&commit).map_err(|_| invalid())?;
        event.to_verified_nostr_event().map_err(|_| invalid())?;
        let validated = event.to_transport_message().map_err(|_| invalid())?;
        if validated != commit
            || !matches!(&validated.envelope, TransportEnvelope::GroupMessage { transport_group_id } if transport_group_id.as_slice() == route.nostr_group_id)
        {
            return Err(invalid().into());
        }
        let id = commit.id.as_slice().try_into().map_err(|_| invalid())?;
        let mut endpoints = self
            .relay_plane
            .sanitize_relay_endpoints(
                route.relays.into_iter().map(TransportEndpoint).collect(),
                "private exact event recovery",
            )
            .map_err(|_| invalid())?;
        endpoints.sort_by(|left, right| left.0.cmp(&right.0));
        endpoints.dedup();
        endpoints.truncate(MAX_ENDPOINTS);
        if endpoints.is_empty() {
            return Ok(None);
        }
        Ok(Some(PrivateEchoPlan {
            scope: fact.scope,
            group: evidence.group_id().clone(),
            route: route.nostr_group_id,
            binding: fact.raw.binding,
            commit,
            id,
            account,
            endpoints,
        }))
    }

    pub(crate) fn note_private_echo_comparison(
        &mut self,
        network: &super::sync::comparison_job::ComparisonNetworkResult,
    ) -> Result<(), PrivateEchoError> {
        if let Some(plan) = self.read_private_echo_plan()?
            && network.attempted_group(&plan.route)
        {
            self.linking_owner.private_echo_compared_route = Some((plan.scope, plan.route));
        }
        Ok(())
    }

    pub(crate) fn start_private_echo_recovery(
        &mut self,
        credit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<Option<PrivateEchoTask>, PrivateEchoError> {
        let now = Instant::now();
        if self
            .linking_owner
            .private_echo_retry
            .is_some_and(|retry| now < retry)
        {
            return Ok(None);
        }
        let Some(plan) = self.read_private_echo_plan()? else {
            return Ok(None);
        };
        if self.linking_owner.private_echo_compared_route.as_ref()
            != Some(&(plan.scope.clone(), plan.route))
        {
            return Ok(None);
        }
        self.linking_owner.private_echo_retry = Some(now + RETRY);
        let request = NostrAcquisitionRequest {
            account_id: plan.account.clone(),
            scope: NostrAcquisitionScope::KnownEventIds(vec![plan.id]),
            endpoints: plan.endpoints.clone(),
            limits: NostrAcquisitionLimits {
                max_endpoints: MAX_ENDPOINTS,
                max_requested_event_ids: 1,
                max_received_items_per_endpoint: 2,
                max_serialized_event_bytes_per_endpoint: MAX_BYTES,
                max_duration: Duration::from_secs(2),
            },
        };
        let plane = self.relay_plane.clone();
        let cancellation = NostrAcquisitionCancellation::new();
        let token = cancellation.clone();
        let handle = tokio::spawn(async move { plane.acquire_history(request, token).await });
        Ok(Some(PrivateEchoTask {
            plan,
            handle,
            cancellation,
            _credit: credit,
        }))
    }

    pub(crate) async fn admit_private_echo_recovery(
        &mut self,
        plan: &PrivateEchoPlan,
        result: NostrAcquisitionResult,
    ) -> Result<(), PrivateEchoError> {
        for endpoint in result.endpoints {
            if !plan.endpoints.contains(&endpoint.endpoint) {
                return Err(StorageError::Serialization(
                    "unexpected private acquisition endpoint".into(),
                )
                .into());
            }
            for event in endpoint.events {
                if self.read_private_echo_plan()?.as_ref() != Some(plan) {
                    return Ok(());
                }
                // Acquisition is only bytes. Both canonical signature and exact
                // frozen transport are checked before the normal account inlet.
                let verified = event.to_transport_message().map_err(|_| {
                    StorageError::Serialization("invalid private acquisition event".into())
                })?;
                if event.to_verified_nostr_event().is_err() || verified != plan.commit {
                    return Err(StorageError::Serialization(
                        "private acquisition event mismatch".into(),
                    )
                    .into());
                }
                let deliveries = self
                    .adapter
                    .recovered_deliveries(NostrRelayEvent {
                        endpoint: endpoint.endpoint.clone(),
                        subscription_id: None,
                        event,
                    })
                    .await?;
                for delivery in deliveries {
                    // The routing await may have raced an account control. Never
                    // infer permission/currentness from the network result.
                    if self.read_private_echo_plan()?.as_ref() != Some(plan) {
                        return Ok(());
                    }
                    self.admit_recovered_delivery(&delivery, super::sync::InventoryWrite::Immediate)
                        .await?;
                }
            }
        }
        Ok(())
    }
}
