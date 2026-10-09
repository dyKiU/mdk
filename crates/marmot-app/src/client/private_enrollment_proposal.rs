//! Received proposal authentication metadata only; no endorsement or SDK grant.
use super::AppClient;
use super::device_linking::ClientLinkingError;
use crate::device_linking::{LinkError, LinkingContext, OwnerError, PredecessorRoster};
use base64::Engine as _;
use cgka_engine::private_enrollment_request::AuthenticatedEnrollmentRequest;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::{GroupId, KeyPackage, MemberId};
use sha2::{Digest, Sha256};

const MAX_PART_BYTES: usize = 16 * 1024;
fn rejected() -> ClientLinkingError {
    ClientLinkingError::Owner(OwnerError::Verifier(LinkError::InvalidContext))
}
impl AppClient {
    /// Internal serial-account intake. Retain only the actual opaque request and
    /// its original acquisition lifetime; this never creates approval or consent.
    pub(crate) fn validate_received_enrollment_proposals(
        &mut self,
    ) -> Result<usize, ClientLinkingError> {
        self.linking_owner
            .received_enrollment_proposals
            .retain(|request| std::time::Instant::now() < request.observed_deadline());
        // Do not drain another bounded Core batch while this owner still holds
        // one: retaining original proofs must not silently overflow or discard
        // observations. Core's typed capacity/retry remains independent.
        if self.linking_owner.received_enrollment_proposals.is_empty() {
            self.linking_owner.received_enrollment_proposals = self
                .runtime
                .session_mut()
                .drain_authenticated_enrollment_requests()
                .map_err(ClientLinkingError::Engine)?
                .into_iter()
                .filter(|request| request.proposal_parts().is_some())
                .collect();
        }
        for request in &self.linking_owner.received_enrollment_proposals {
            self.authenticate_received_enrollment_proposal(request)?;
        }
        Ok(self.linking_owner.received_enrollment_proposals.len())
    }

    fn authenticate_received_enrollment_proposal(
        &self,
        request: &AuthenticatedEnrollmentRequest,
    ) -> Result<(), ClientLinkingError> {
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
            .validate_private_device_predecessor(
                &artifact,
                &account,
                &group,
                actual.epoch,
                &actual.leaves,
            )
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
        Ok(())
    }
}
