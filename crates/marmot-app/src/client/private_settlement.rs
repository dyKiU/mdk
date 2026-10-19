//! Account-worker ownership and transport of exact encrypted confirmations.
use super::AppClient;
use super::device_linking::ClientLinkingError;
use crate::device_linking::settlement::SettlementGuard;
use cgka_traits::device_linking_key_package::{LinkingWelcomeDenied, PurposeAttemptScope};
use cgka_traits::storage::StorageProvider;
use std::sync::Arc;

pub(super) struct OwnedSettlementAttempt {
    pub(super) guard: Arc<SettlementGuard>,
    selected: bool,
    published: bool,
}
impl OwnedSettlementAttempt {
    /// Actual original selection custody, not a reconstructed durable fact.
    pub(super) fn has_selected_admission(&self) -> bool {
        self.selected
    }
    pub(super) fn new(guard: Arc<SettlementGuard>) -> Self {
        Self {
            guard,
            selected: false,
            published: false,
        }
    }
}
pub(super) struct OwnedExistingSettlementAttempt {
    pub(super) guard:
        Arc<cgka_engine::private_enrollment_endorsement::OwnedExistingEnrollmentTransition>,
    selected: bool,
    published: bool,
}
impl OwnedExistingSettlementAttempt {
    pub(super) fn new(
        guard: Arc<cgka_engine::private_enrollment_endorsement::OwnedExistingEnrollmentTransition>,
    ) -> Self {
        Self {
            guard,
            selected: false,
            published: false,
        }
    }
}
impl AppClient {
    /// Observe the existing actor-owned original binding; this cannot create
    /// revocation admission, restore a guard or schedule a retry.
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn live_revocation_settlement_binding_for_test(
        &self,
        group: &cgka_traits::GroupId,
    ) -> crate::client::device_linking::RevocationBindingObservationForTest {
        Ok((
            self.runtime
                .session()
                .device_revocation_settlement_control()
                .map_err(cgka_session::SessionError::from)?
                .filter(|control| control.is_live() && control.group() == group)
                .map(|control| control.binding()),
            self.linking_owner.revocation_retry_custody.clone(),
        ))
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn record_actual_revocation_retry_custody_for_test(
        &self,
        control: &cgka_engine::device_leaf_revocation::DeviceRevocationSettlementControl,
    ) {
        let mut observed = self.linking_owner.revocation_retry_custody.lock().unwrap();
        if observed.entries.len() < 128 {
            observed
                .entries
                .push((control.group().clone(), control.binding()));
        } else {
            observed.overflow = true;
        }
    }
    /// A failed atomic apply must retain the exact live B action. Reopening
    /// destroys that original owner and cannot reconstruct it from stored rows.
    pub(crate) fn existing_enrollment_storage_retry_group(
        &self,
        error: &crate::AppError,
    ) -> Option<cgka_traits::GroupId> {
        if !matches!(
            error.as_engine_error(),
            Some(cgka_traits::EngineError::Storage(_))
        ) {
            return None;
        }
        self.linking_owner
            .existing_settlement_attempt
            .as_ref()
            .filter(|attempt| attempt.guard.is_live())
            .map(|attempt| attempt.guard.group().clone())
    }

    pub(crate) fn device_revocation_storage_retry_groups(
        &self,
        error: &crate::AppError,
    ) -> Option<Vec<cgka_traits::GroupId>> {
        if !revoked_retry_is_engine_storage(error) {
            return None;
        }
        let groups = self
            .runtime
            .session()
            .device_revocation_storage_retry_groups()
            .ok()?;
        (!groups.is_empty()).then_some(groups)
    }

    /// Keep only the exact live-group delivery whose atomic ingest failed.
    pub(crate) fn revoked_confirmation_storage_retry(
        &self,
        error: &crate::AppError,
        delivery: &cgka_traits::TransportDelivery,
    ) -> Option<Arc<cgka_engine::device_leaf_revocation::DeviceRevocationSettlementControl>> {
        if delivery.message.payload.len() > 512 * 1024 {
            return None;
        }
        let groups = self.device_revocation_storage_retry_groups(error)?;
        let control = self
            .runtime
            .session()
            .device_revocation_settlement_control()
            .ok()??;
        use cgka_traits::private_roster_settlement::PrivateSettlementPhase;
        let storage = self.app.account_storage(&self.state.label).ok()?;
        let round = storage
            .private_roster_settlement_storage()?
            .read_round()
            .ok()??;
        // A rolled-back Remove still owns its retry intent, but has not
        // committed this successor. Route it through convergence so newer
        // settlement input can arrive; only failed successor confirmations
        // belong in the exact-delivery retry slot.
        (control.is_live()
            && delivery.group_id_hint.as_ref() == Some(control.group())
            && groups.contains(control.group())
            && round.phase == PrivateSettlementPhase::Pending
            && round.anchor.group_id == *control.group()
            && round.anchor.context_digest == control.binding())
        .then_some(control)
    }

    pub(crate) fn pending_existing_private_settlement(
        &mut self,
    ) -> Result<Option<[u8; 32]>, ClientLinkingError> {
        let Some(attempt) = self.linking_owner.existing_settlement_attempt.as_mut() else {
            return Ok(None);
        };
        if !attempt.guard.is_live() {
            return Ok(None);
        }
        if !attempt.selected {
            self.runtime
                .session()
                .select_owned_private_roster_settlement(
                    attempt.guard.group(),
                    attempt.guard.clone(),
                )
                .map_err(ClientLinkingError::Engine)?;
            attempt.selected = true;
        }
        if attempt.published {
            return Ok(None);
        }
        Ok(self
            .runtime
            .session()
            .private_roster_settlement_publication_ready(attempt.guard.group())
            .map_err(ClientLinkingError::Engine)?
            .then(|| *attempt.guard.binding()))
    }
    pub(crate) fn existing_settlement_control(
        &self,
        binding: &[u8; 32],
    ) -> Result<
        Arc<cgka_engine::private_enrollment_endorsement::OwnedExistingEnrollmentTransition>,
        ClientLinkingError,
    > {
        self.linking_owner
            .existing_settlement_attempt
            .as_ref()
            .filter(|attempt| attempt.guard.binding() == binding && attempt.guard.is_live())
            .map(|attempt| attempt.guard.clone())
            .ok_or_else(denied)
    }
    pub(crate) async fn dispatch_existing_private_settlement(
        &mut self,
        binding: &[u8; 32],
    ) -> Result<(), ClientLinkingError> {
        let guard = self.existing_settlement_control(binding)?;
        let group = guard.group().clone();
        self.dispatch_private_settlement_group(&group).await?;
        if !guard.is_live() {
            return Err(denied());
        }
        let attempt = self
            .linking_owner
            .existing_settlement_attempt
            .as_mut()
            .filter(|attempt| attempt.guard.binding() == binding)
            .ok_or_else(denied)?;
        attempt.published = true;
        self.note_owned_sibling_source_readiness();
        Ok(())
    }
    /// Real SDK-owned admission only. Never installs a test guard or grants permission.
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn reject_foreign_guard_against_real_settlement_for_test(
        &self,
    ) -> Result<(), ClientLinkingError> {
        use cgka_engine::private_roster_settlement::TrustedPrivateSettlementGuard;
        use cgka_traits::private_roster_settlement::PrivateSettlementAnchor;
        struct NeverAuthorizes;
        impl TrustedPrivateSettlementGuard for NeverAuthorizes {
            fn validate(&self, _: &PrivateSettlementAnchor) -> Result<std::time::Instant, cgka_traits::EngineError> {
                Err(cgka_traits::EngineError::Other("negative guard has no permission".into()))
            }
        }
        let attempt = self.linking_owner.settlement_attempt.as_ref().ok_or_else(denied)?;
        if !attempt.selected || !attempt.guard.is_live() { return Err(denied()); }
        let own: Arc<dyn TrustedPrivateSettlementGuard> = attempt.guard.clone();
        let group = attempt.guard.group();
        let session = self.runtime.session();
        if !session.owned_settlement_guard_is_current_and_live_for_test(&group, &own)
            .map_err(ClientLinkingError::Engine)? { return Err(denied()); }
        let storage = self.app.account_storage(&self.state.label)
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        let store = storage.private_roster_settlement_storage().ok_or_else(denied)?;
        let before = store.read_round().map_err(|error| ClientLinkingError::Engine(error.into()))?
            .ok_or_else(denied)?;
        if before.phase != cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed {
            return Err(denied());
        }
        eprintln!("cancel-real-guard-control {{\"selected_original\":true,\"current_guard_pointer\":true,\"original_live\":true,\"actual_round_present\":true}}");
        let foreign: Arc<dyn TrustedPrivateSettlementGuard> = Arc::new(NeverAuthorizes);
        // Both operations target exactly the SAME actual group. The foreign
        // guard never authorizes anything and is never installed in the Engine.
        let foreign_result = session.cancel_owned_private_roster_settlement(&group, &foreign);
        eprintln!("cancel-real-guard-result {{\"foreign_cancel_returned_ok\":{}}}", foreign_result.is_ok());
        if foreign_result.is_ok()
            || !attempt.guard.is_live()
            || !session.owned_settlement_guard_is_current_and_live_for_test(&group, &own)
                .map_err(ClientLinkingError::Engine)?
            || store.read_round().map_err(|error| ClientLinkingError::Engine(error.into()))?.as_ref() != Some(&before)
        { return Err(denied()); }
        // Intentional negative control on this SAME real original guard. A
        // completed round must remain valid durable provenance after memory
        // publication admission is withdrawn; no guard is reconstructed.
        session.cancel_owned_private_roster_settlement(&group, &own)
            .map_err(ClientLinkingError::Engine)?;
        if session.owned_settlement_guard_is_current_and_live_for_test(&group, &own)
                .map_err(ClientLinkingError::Engine)?
            || store.read_round().map_err(|error| ClientLinkingError::Engine(error.into()))?.as_ref() != Some(&before)
            || session.validated_settled_device_roster(&group)
                .map_err(ClientLinkingError::Engine)?.is_none()
        { return Err(denied()); }
        Ok(())
    }

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
        self.dispatch_private_settlement_group(&group).await?;
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
    pub(crate) async fn dispatch_private_settlement_group(
        &mut self,
        group: &cgka_traits::GroupId,
    ) -> Result<(), ClientLinkingError> {
        self.refresh_private_transport_route()
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        self.sync_runtime_groups()
            .await
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        let component = self
            .runtime
            .session()
            .app_component(group, crate::NOSTR_ROUTING_COMPONENT_ID)
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
            .dispatch_private_roster_settlement(group, &publisher)
            .await
            .map_err(ClientLinkingError::Engine)?;
        Ok(())
    }
}
fn denied() -> ClientLinkingError {
    ClientLinkingError::Gate(LinkingWelcomeDenied::NoLiveVerifier)
}
struct SettlementPublisher {
    adapter: transport_nostr::MarmotRelayPlaneAccountAdapter,
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

fn revoked_retry_is_engine_storage(error: &crate::AppError) -> bool {
    matches!(
        error.as_engine_error(),
        Some(cgka_traits::EngineError::Storage(_))
    )
}
#[cfg(test)]
mod revoked_retry_error_tests {
    use super::*;
    #[test]
    fn only_atomic_engine_storage_failures_can_retain_the_revoked_owner() {
        let engine_storage = crate::AppError::Session(cgka_session::SessionError::Engine(
            cgka_traits::EngineError::Storage(cgka_traits::storage::StorageError::NotFound),
        ));
        assert!(revoked_retry_is_engine_storage(&engine_storage));
        let other = crate::AppError::Session(cgka_session::SessionError::Engine(
            cgka_traits::EngineError::Other("test refusal".into()),
        ));
        assert!(!revoked_retry_is_engine_storage(&other));
        assert!(!revoked_retry_is_engine_storage(&crate::AppError::Storage(
            cgka_traits::storage::StorageError::NotFound
        )));
    }
}
