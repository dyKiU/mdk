//! Received proposal authentication metadata only; no endorsement or SDK grant.
use super::AppClient;
use super::device_linking::ClientLinkingError;
use crate::device_linking::{LinkError, LinkingContext, OwnerError, PredecessorRoster};
use base64::Engine as _;
use cgka_engine::private_enrollment_request::AuthenticatedEnrollmentRequest;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::{GroupId, KeyPackage, MemberId};
use sha2::{Digest, Sha256};

mod publication;

const MAX_PART_BYTES: usize = 16 * 1024;
struct ValidatedProposalParts {
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
}

fn rejected() -> ClientLinkingError {
    ClientLinkingError::Owner(OwnerError::Verifier(LinkError::InvalidContext))
}
impl AppClient {
    /// Read-only correlation of actual retained observations; not approval.
    pub(crate) fn received_enrollment_proposal_bindings(
        &mut self,
    ) -> Result<Vec<[u8; 32]>, ClientLinkingError> {
        self.retain_received_enrollment_proposals()?;
        self.linking_owner
            .received_enrollment_proposals
            .iter()
            .map(|request| request.binding_digest().map_err(ClientLinkingError::Engine))
            .collect()
    }

    /// Explicit action on the exact retained, source-authenticated observation.
    /// Neither the selector nor the signed packet is SDK or Add permission.
    pub(crate) fn endorse_received_enrollment_proposal(
        &mut self,
        binding: &[u8; 32],
    ) -> Result<(), ClientLinkingError> {
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
            if attempt.binding != *binding || attempt.cancelled || now >= attempt.deadline {
                return Err(rejected());
            }
            self.runtime
                .session()
                .validate_owned_private_enrollment_endorsement(&attempt.owned)
                .map_err(ClientLinkingError::Engine)?;
            attempt.owned.wire().map_err(ClientLinkingError::Engine)?;
            return Ok(());
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
        let owned = self
            .runtime
            .session()
            .endorse_private_enrollment_request(
                request,
                &parts.artifact,
                &parts.package,
                &parts.context_digest,
            )
            .map_err(ClientLinkingError::Engine)?;
        self.runtime
            .session()
            .validate_owned_private_enrollment_endorsement(&owned)
            .map_err(ClientLinkingError::Engine)?;
        owned.wire().map_err(ClientLinkingError::Engine)?;
        self.linking_owner.received_endorsement = Some(OwnedReceivedEndorsement {
            binding: *binding,
            deadline,
            group: GroupId::new(request.group_id().to_vec()),
            owned,
            cancelled: false,
        });
        Ok(())
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

    fn authenticate_received_enrollment_proposal(
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
