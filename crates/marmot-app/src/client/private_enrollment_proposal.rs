//! Received proposal authentication metadata only; no endorsement or SDK grant.
use super::AppClient;
use super::device_linking::ClientLinkingError;
use crate::device_linking::{LinkError, LinkingContext, OwnerError, PredecessorRoster};
use base64::Engine as _;
use cgka_engine::private_enrollment_request::AuthenticatedEnrollmentRequest;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::{GroupId, KeyPackage, MemberId};
use sha2::{Digest, Sha256};
use std::sync::Arc;

mod publication;
mod sibling_sharing;

const MAX_PART_BYTES: usize = 16 * 1024;
pub(super) struct ValidatedProposalParts {
    artifact: Vec<u8>,
    package: KeyPackage,
    context_digest: [u8; 32],
}
pub(super) struct OwnedReceivedEndorsement {
    binding: [u8; 32],
    deadline: std::time::Instant,
    group: GroupId,
    owned: cgka_engine::private_enrollment_endorsement::OwnedEnrollmentEndorsement,
    cancelled: bool,
    sharing: Option<Arc<OriginalSiblingSharingApproval>>,
}

/// Negative control for the actual original B choice, never a portable grant.
/// Native aliases can revoke blocked work without waiting for the worker RPC.
pub(crate) struct OriginalSiblingSharingApproval {
    pub(super) state: Arc<crate::account_chat_sharing::enabled::State>,
    cancellation: cgka_engine::private_enrollment_endorsement::EnrollmentEndorsementCancellation,
}
impl OriginalSiblingSharingApproval {
    pub(crate) fn cancel(&self) {
        self.state.cancel();
        self.cancellation.cancel();
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn channel_diagnostics_for_test(
        &self,
    ) -> crate::account_chat_sharing::enabled::SiblingMaintenanceSnapshot {
        self.state
            .sibling_diagnostics
            .lock()
            .expect("sibling diagnostics")
            .snapshot()
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn publication_for_test(&self) -> Option<cgka_traits::MessageId> {
        self.state
            .sibling_diagnostics
            .lock()
            .expect("sibling diagnostics")
            .last_publication
            .clone()
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    fn record_readiness_for_test(&self, category: u64) {
        let now = crate::account_chat_sharing::enabled::sibling_clock_ms_for_test();
        let mut diagnostic = self.state.sibling_diagnostics.lock().expect("sibling diagnostics");
        let readiness = &mut diagnostic.readiness;
        if category == 0 {
            readiness[0] += 1;
            if readiness[6] == 0 { readiness[6] = now; }
        }
        readiness[1] = category;
        readiness[2] = now;
        if category == 5 && readiness[3] == 0 { readiness[3] = now; }
        if category == 7 && readiness[4] == 0 { readiness[4] = now; }
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn status_for_test(&self) -> (bool, bool) {
        (self.state.live(), self.complete())
    }
    fn complete(&self) -> bool {
        self.state
            .progress
            .lock()
            .expect("sharing progress")
            .complete
    }
}
impl Drop for OriginalSiblingSharingApproval {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn rejected() -> ClientLinkingError {
    ClientLinkingError::Owner(OwnerError::Verifier(LinkError::InvalidContext))
}
impl AppClient {
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn publication_source_state_for_test(&self) -> Option<std::sync::Weak<crate::account_chat_sharing::enabled::State>> {
        self.linking_owner.received_endorsement.as_ref()
            .and_then(|action| action.sharing.as_ref())
            .map(|original| Arc::downgrade(&original.state))
    }
    /// Read-only correlation of actual retained observations; not approval.
    pub(crate) fn received_enrollment_proposal_bindings(
        &mut self,
    ) -> Result<Vec<[u8; 32]>, ClientLinkingError> {
        self.retain_received_enrollment_proposals()?;
        self.linking_owner
            .received_enrollment_proposals
            .iter()
            .map(|request| request.binding_digest().map_err(ClientLinkingError::Engine))
            .collect::<Result<Vec<_>, _>>()
            .map(|bindings| {
                bindings
                    .into_iter()
                    .filter(|binding| {
                        !self
                            .linking_owner
                            .cancelled_endorsements
                            .iter()
                            .any(|(b, _)| b == binding)
                    })
                    .collect()
            })
    }

    pub(crate) fn native_authenticated_received_bindings(
        &mut self,
    ) -> Result<Vec<([u8; 32], std::time::Instant)>, ClientLinkingError> {
        self.retain_received_enrollment_proposals()?;
        self.linking_owner
            .received_enrollment_proposals
            .iter()
            .filter(|request| {
                self.authenticate_received_enrollment_proposal(request)
                    .is_ok()
            })
            .map(|request| {
                request
                    .binding_digest()
                    .map(|binding| (binding, request.observed_deadline()))
                    .map_err(ClientLinkingError::Engine)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|observations| {
                observations
                    .into_iter()
                    .filter(|(binding, _)| {
                        !self
                            .linking_owner
                            .cancelled_endorsements
                            .iter()
                            .any(|(b, _)| b == binding)
                    })
                    .collect()
            })
    }

    pub(crate) fn native_received_approval_phase(
        &mut self,
        binding: &[u8; 32],
    ) -> Result<crate::DeviceLinkingApprovalPhase, ClientLinkingError> {
        use crate::DeviceLinkingApprovalPhase as Phase;
        use cgka_engine::private_roster_settlement::TrustedPrivateSettlementGuard;
        use cgka_traits::StorageProvider;
        if self
            .linking_owner
            .cancelled_endorsements
            .iter()
            .any(|(b, _)| b == binding)
        {
            return Ok(Phase::Cancelled);
        }
        if let Some(action) = self
            .linking_owner
            .received_endorsement
            .as_ref()
            .filter(|a| a.binding == *binding)
        {
            if action.cancelled {
                return Ok(Phase::Cancelled);
            }
            if std::time::Instant::now() >= action.deadline {
                return Ok(Phase::Expired);
            }
            if let Some(attempt) = self
                .linking_owner
                .existing_settlement_attempt
                .as_ref()
                .filter(|a| a.guard.binding() == binding && a.guard.is_live())
            {
                let storage = self
                    .app
                    .account_storage(&self.state.label)
                    .map_err(|e| ClientLinkingError::Runtime(Box::new(e)))?;
                if let Some(round) = storage
                    .private_roster_settlement_storage()
                    .ok_or_else(rejected)?
                    .read_round()
                    .map_err(|e| ClientLinkingError::Engine(e.into()))?
                    && attempt.guard.validate(&round.anchor).is_ok()
                    && self
                        .runtime
                        .session()
                        .validated_settled_device_roster(attempt.guard.group())
                        .map_err(ClientLinkingError::Engine)?
                        .is_some()
                {
                    if action
                        .sharing
                        .as_ref()
                        .is_some_and(|original| !original.complete())
                    {
                        return Ok(Phase::AwaitingSettlement);
                    }
                    return Ok(Phase::Settled);
                }
                return Ok(Phase::AwaitingSettlement);
            }
            self.enrollment_endorsement_control(binding)?;
            return Ok(Phase::ApprovedAwaitingPacket);
        }
        if self
            .received_enrollment_proposal_bindings()?
            .contains(binding)
        {
            Ok(Phase::AwaitingApproval)
        } else {
            Err(rejected())
        }
    }

    pub(crate) fn native_received_approval_review(
        &mut self,
        binding: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32], u32), ClientLinkingError> {
        if self.native_received_approval_phase(binding)?
            != crate::DeviceLinkingApprovalPhase::AwaitingApproval
        {
            return Err(rejected());
        }
        for request in &self.linking_owner.received_enrollment_proposals {
            if request
                .binding_digest()
                .map_err(ClientLinkingError::Engine)?
                == *binding
            {
                self.authenticate_received_enrollment_proposal(request)?;
                let count =
                    u32::try_from(request.predecessor().leaves.len()).map_err(|_| rejected())?;
                return Ok((*request.source_signer(), *request.recipient(), count));
            }
        }
        Err(rejected())
    }

    /// Explicit action on the exact retained, source-authenticated observation.
    /// Neither the selector nor the signed packet is SDK or Add permission.
    pub(crate) fn endorse_received_enrollment_proposal(
        &mut self,
        binding: &[u8; 32],
    ) -> Result<(), ClientLinkingError> {
        self.endorse_received_enrollment_proposal_choice(binding, false)
            .map(|_| ())
    }

    pub(crate) fn endorse_received_enrollment_proposal_and_share_chats(
        &mut self,
        binding: &[u8; 32],
    ) -> Result<Arc<OriginalSiblingSharingApproval>, ClientLinkingError> {
        self.endorse_received_enrollment_proposal_choice(binding, true)?
            .ok_or_else(rejected)
    }

    fn endorse_received_enrollment_proposal_choice(
        &mut self,
        binding: &[u8; 32],
        share_chats: bool,
    ) -> Result<Option<Arc<OriginalSiblingSharingApproval>>, ClientLinkingError> {
        let now = std::time::Instant::now();
        self.linking_owner
            .cancelled_endorsements
            .retain(|(_, deadline)| now < *deadline);
        if self
            .linking_owner
            .cancelled_endorsements
            .iter()
            .any(|(cancelled, _)| cancelled == binding)
        {
            return Err(rejected());
        }
        if let Some(attempt) = self.linking_owner.received_endorsement.as_ref() {
            if attempt.binding != *binding
                || attempt.cancelled
                || now >= attempt.deadline
                || attempt.sharing.is_some() != share_chats
                || attempt
                    .sharing
                    .as_ref()
                    .is_some_and(|original| !original.state.live())
            {
                return Err(rejected());
            }
            self.runtime
                .session()
                .validate_owned_private_enrollment_endorsement(&attempt.owned)
                .map_err(ClientLinkingError::Engine)?;
            attempt.owned.wire().map_err(ClientLinkingError::Engine)?;
            return Ok(attempt.sharing.clone());
        }
        self.retain_received_enrollment_proposals()?;
        let mut selected = None;
        for request in &self.linking_owner.received_enrollment_proposals {
            if request
                .binding_digest()
                .map_err(ClientLinkingError::Engine)?
                == *binding
            {
                selected = Some(request);
                break;
            }
        }
        let request = selected.ok_or_else(rejected)?;
        let parts = self.authenticate_received_enrollment_proposal(request)?;
        let deadline = request.observed_deadline();
        let mut owned = if share_chats {
            self.runtime
                .session()
                .endorse_private_enrollment_request_and_share_chats(
                    request,
                    &parts.artifact,
                    &parts.package,
                    &parts.context_digest,
                )
        } else {
            self.runtime.session().endorse_private_enrollment_request(
                request,
                &parts.artifact,
                &parts.package,
                &parts.context_digest,
            )
        }
        .map_err(ClientLinkingError::Engine)?;
        if let Some((owner, tags)) = &self.linking_owner.approval_pairing_metadata
            && owner == binding
        {
            self.runtime
                .session()
                .set_owned_enrollment_metadata(&mut owned, tags.clone())
                .map_err(ClientLinkingError::Engine)?;
        }
        self.runtime
            .session()
            .validate_owned_private_enrollment_endorsement(&owned)
            .map_err(ClientLinkingError::Engine)?;
        owned.wire().map_err(ClientLinkingError::Engine)?;
        let sharing = if share_chats {
            let original = Arc::new(OriginalSiblingSharingApproval {
                state: crate::account_chat_sharing::enabled::State::new_until(
                    &self.account_sharing_owner.lifetime,
                    parts.context_digest,
                    deadline,
                ),
                cancellation: owned.cancellation_handle(),
            });
            let capture = self
                .capture_legacy_chats(&|| {
                    if !original.state.live() {
                        return Err(cgka_traits::storage::StorageError::Serialization(
                            "sibling approval original unavailable".into(),
                        ));
                    }
                    self.runtime
                        .session()
                        .validate_owned_private_enrollment_endorsement(&owned)
                        .map_err(|_| {
                            cgka_traits::storage::StorageError::Serialization(
                                "sibling endorsement original changed".into(),
                            )
                        })
                })
                .map_err(|error| ClientLinkingError::Engine(error.into()))?;
            *original
                .state
                .legacy_capture
                .lock()
                .expect("legacy capture") = Some(capture);
            Some(original)
        } else {
            None
        };
        self.linking_owner.received_endorsement = Some(OwnedReceivedEndorsement {
            binding: *binding,
            deadline,
            group: GroupId::new(request.group_id().to_vec()),
            owned,
            cancelled: false,
            sharing: sharing.clone(),
        });
        Ok(sharing)
    }

    pub(crate) fn arm_existing_member_enrollment(
        &mut self,
        binding: &[u8; 32],
        packet: &[u8],
    ) -> Result<(), ClientLinkingError> {
        if packet.is_empty() || packet.len() > MAX_PART_BYTES {
            return Err(rejected());
        }
        let action = self
            .linking_owner
            .received_endorsement
            .as_ref()
            .filter(|attempt| {
                attempt.binding == *binding
                    && !attempt.cancelled
                    && std::time::Instant::now() < attempt.deadline
            })
            .ok_or_else(rejected)?;
        let guard = self
            .runtime
            .session()
            .arm_original_existing_enrollment_transition(&action.owned, packet)
            .map_err(ClientLinkingError::Engine)?;
        if self.linking_owner.existing_settlement_attempt.is_none() {
            self.linking_owner.existing_settlement_attempt =
                Some(super::private_settlement::OwnedExistingSettlementAttempt::new(guard));
        }
        Ok(())
    }

    /// Only negative control over the actual already-owned original. Never
    /// reconstruct an action from its binding, packet or retained observation.
    pub(crate) fn native_approval_cancellation(
        &self,
        binding: &[u8; 32],
    ) -> Result<
        cgka_engine::private_enrollment_endorsement::EnrollmentEndorsementCancellation,
        ClientLinkingError,
    > {
        let attempt = self
            .linking_owner
            .received_endorsement
            .as_ref()
            .ok_or_else(rejected)?;
        if attempt.binding != *binding
            || attempt.cancelled
            || std::time::Instant::now() >= attempt.deadline
        {
            return Err(rejected());
        }
        self.runtime
            .session()
            .validate_owned_private_enrollment_endorsement(&attempt.owned)
            .map_err(ClientLinkingError::Engine)?;
        Ok(attempt.owned.cancellation_handle())
    }

    pub(crate) fn cancel_received_enrollment_endorsement(
        &mut self,
        binding: &[u8; 32],
    ) -> Result<(), ClientLinkingError> {
        if !self
            .linking_owner
            .received_endorsement
            .as_ref()
            .is_some_and(|attempt| &attempt.binding == binding)
        {
            if self
                .linking_owner
                .cancelled_endorsements
                .iter()
                .any(|(cancelled, deadline)| {
                    cancelled == binding && std::time::Instant::now() < *deadline
                })
            {
                return Ok(());
            }
            // Unapproved cancellation fences the exact retained observation;
            // its original acquisition deadline bounds this negative tombstone.
            if let Some(request) = self
                .linking_owner
                .received_enrollment_proposals
                .iter()
                .find(|r| r.binding_digest().is_ok_and(|b| &b == binding))
            {
                if self.linking_owner.cancelled_endorsements.len() >= 128 {
                    return Err(rejected());
                }
                self.linking_owner
                    .cancelled_endorsements
                    .push((*binding, request.observed_deadline()));
                return Ok(());
            }
            // The bounded dispatcher may already have performed this exact
            // negative cleanup before the queued cancellation reply is served.
            if self
                .linking_owner
                .cancelled_endorsements
                .iter()
                .any(|(cancelled, deadline)| {
                    cancelled == binding && std::time::Instant::now() < *deadline
                })
            {
                return Ok(());
            }
            return Err(rejected());
        }
        self.cancel_owned_enrollment_endorsement()
    }

    pub(super) fn maintain_received_enrollment_endorsement(
        &mut self,
        now: std::time::Instant,
    ) -> Result<(), ClientLinkingError> {
        self.linking_owner
            .cancelled_endorsements
            .retain(|(_, deadline)| now < *deadline);
        if self
            .linking_owner
            .received_endorsement
            .as_ref()
            .is_some_and(|attempt| now >= attempt.deadline)
        {
            self.cancel_owned_enrollment_endorsement()?;
        }
        Ok(())
    }

    pub(super) fn cancel_owned_enrollment_endorsement(&mut self) -> Result<(), ClientLinkingError> {
        let now = std::time::Instant::now();
        self.linking_owner
            .cancelled_endorsements
            .retain(|(_, deadline)| now < *deadline);
        let Some(attempt) = self.linking_owner.received_endorsement.as_mut() else {
            return Ok(());
        };
        // Negative fence first, even if the Core cleanup subsequently fails.
        attempt.cancelled = true;
        if let Some(original) = &attempt.sharing {
            original.cancel();
        }
        if let Some(settlement) = self.linking_owner.existing_settlement_attempt.as_ref() {
            settlement.guard.cancellation_handle().cancel();
        }

        if now < attempt.deadline
            && !self
                .linking_owner
                .cancelled_endorsements
                .iter()
                .any(|(binding, _)| binding == &attempt.binding)
        {
            if self.linking_owner.cancelled_endorsements.len() >= 128 {
                return Err(rejected());
            }
            self.linking_owner
                .cancelled_endorsements
                .push((attempt.binding, attempt.deadline));
        }
        self.runtime
            .session()
            .cancel_private_enrollment_endorsements()
            .map_err(ClientLinkingError::Engine)?;
        if let Some(settlement) = self.linking_owner.existing_settlement_attempt.as_ref() {
            self.runtime
                .session()
                .cancel_private_roster_settlement(settlement.guard.group())
                .map_err(ClientLinkingError::Engine)?;
        }
        self.linking_owner.existing_settlement_attempt = None;
        self.linking_owner.received_endorsement = None;
        Ok(())
    }

    /// Internal serial-account intake. Retain only the actual opaque request and
    /// its original acquisition lifetime; this never creates approval or consent.
    fn retain_received_enrollment_proposals(&mut self) -> Result<(), ClientLinkingError> {
        self.linking_owner
            .received_enrollment_proposals
            .retain(|request| std::time::Instant::now() < request.observed_deadline());
        // Retaining an earlier observation must not hide later arrivals. Move
        // only the remaining App slots; leave excess proofs in Core unchanged.
        // App retention and Core's shared request/endorsement queue each cap at
        // 128, giving an explicit aggregate maximum of 256 opaque observations.
        let available = 128usize
            .saturating_sub(self.linking_owner.received_enrollment_proposals.len())
            .saturating_sub(self.retained_enrollment_endorsement_count());
        if available > 0 {
            let received = self
                .runtime
                .session_mut()
                .drain_authenticated_enrollment_requests_up_to(available)
                .map_err(ClientLinkingError::Engine)?
                .into_iter()
                .filter(|request| request.proposal_parts().is_some())
                .collect::<Vec<_>>();
            self.linking_owner
                .received_enrollment_proposals
                .extend(received);
        }
        Ok(())
    }

    pub(crate) fn validate_received_enrollment_proposals(
        &mut self,
    ) -> Result<usize, ClientLinkingError> {
        self.retain_received_enrollment_proposals()?;
        for request in &self.linking_owner.received_enrollment_proposals {
            self.authenticate_received_enrollment_proposal(request)?;
        }
        Ok(self.linking_owner.received_enrollment_proposals.len())
    }

    pub(super) fn authenticate_received_enrollment_proposal(
        &self,
        request: &AuthenticatedEnrollmentRequest,
    ) -> Result<ValidatedProposalParts, ClientLinkingError> {
        let (encoded, json) = request.proposal_parts().ok_or_else(rejected)?;
        if encoded.len() > MAX_PART_BYTES
            || json.len() > MAX_PART_BYTES
            || std::time::Instant::now() >= request.observed_deadline()
        {
            return Err(rejected());
        }
        let artifact = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| rejected())?;
        if artifact.is_empty()
            || base64::engine::general_purpose::STANDARD.encode(&artifact) != encoded
        {
            return Err(rejected());
        }
        let context: LinkingContext = serde_json::from_str(json).map_err(|_| rejected())?;
        if serde_json::to_vec(&context).map_err(|_| rejected())? != json.as_bytes()
            || context.version != 2
            || context.digest().map_err(|_| rejected())? != *request.context_digest()
            || context.account != *request.account()
            || context.device_group != request.group_id()
            || context.approver != *request.source_signer()
            || context.recipient != *request.recipient()
            || context.nonce != *request.enrollment_nonce()
            || context.approver_generation != request.approver_generation()
            || context.new_device_generation != request.recipient_generation()
            || context.key_package_reference.as_slice() != request.key_package_reference()
            || context.predecessor.artifact_digest != Some(*request.artifact_digest())
            || <[u8; 32]>::from(Sha256::digest(&artifact)) != *request.artifact_digest()
            || <[u8; 32]>::from(Sha256::digest(&context.exact_key_package))
                != *request.key_package_digest()
        {
            return Err(rejected());
        }
        let predecessor = request.predecessor();
        if context.predecessor.epoch != predecessor.epoch.0
            || context.predecessor.epoch_authenticator_digest
                != predecessor.epoch_authenticator_digest
            || context.predecessor.leaves.len() != predecessor.leaves.len()
            || !context
                .predecessor
                .leaves
                .iter()
                .zip(&predecessor.leaves)
                .all(|(a, b)| {
                    a.leaf_index == b.leaf_index && a.signature_public_key == b.signature_public_key
                })
            || !predecessor.leaves.iter().any(|leaf| {
                leaf.leaf_index == request.source_index()
                    && &leaf.signature_public_key == request.source_signer()
            })
        {
            return Err(rejected());
        }
        let account = MemberId::new(context.account.to_vec());
        if self.runtime.session().self_id() != account {
            return Err(rejected());
        }
        let group = GroupId::new(context.device_group.clone());
        let protected = self
            .runtime
            .session()
            .validated_settled_device_roster(&group)
            .map_err(ClientLinkingError::Engine)?
            .ok_or_else(rejected)?;
        let actual = protected.candidate();
        let mut actual_roster =
            PredecessorRoster::from_candidate(actual).map_err(|_| rejected())?;
        actual_roster.artifact_digest = context.predecessor.artifact_digest;
        if actual.account != account
            || actual.group_id != group
            || actual_roster != context.predecessor
        {
            return Err(rejected());
        }
        let authenticated = self
            .runtime
            .session()
            .validate_private_enrollment_request_predecessor(request, &artifact)
            .map_err(ClientLinkingError::Engine)?;
        if authenticated.artifact_digest() != request.artifact_digest() {
            return Err(rejected());
        }
        let package = KeyPackage::new(context.exact_key_package)
            .with_protocol_profile(ProtocolProfile::Current);
        let metadata =
            cgka_engine::key_package::key_package_metadata(&package).map_err(|_| rejected())?;
        if metadata.protocol_profile != ProtocolProfile::Current
            || hex::decode(metadata.credential_identity_hex).map_err(|_| rejected())?
                != context.account
            || hex::decode(metadata.signature_public_key_hex).map_err(|_| rejected())?
                != context.recipient
            || hex::decode(metadata.key_package_ref_hex).map_err(|_| rejected())?
                != context.key_package_reference
            || !metadata
                .app_components
                .contains(&cgka_traits::device_group_genesis::PRIVATE_DEVICE_GROUP_COMPONENT_ID)
            || std::time::Instant::now() >= request.observed_deadline()
        {
            return Err(rejected());
        }
        // No await, mutation or admission occurs between the fresh protected
        // tree reads and this original-deadline check. The account actor owns
        // group mutation exclusively; the opaque request stays in this owner.
        Ok(ValidatedProposalParts {
            artifact,
            package,
            context_digest: *request.context_digest(),
        })
    }
}
