//! Original Approver-owned request, distinct from received source observations.
use super::{
    PAYLOAD_LIMIT, PROPOSAL_PROTOCOL, REQUEST_KIND, RequestFrame, RequestLeaf, RequestProposal,
    unavailable,
};
use crate::Engine;
use crate::device_group_snapshot::CandidateDeviceGroupSnapshot;
use crate::private_device_invite::{PrivateInviteLease, TrustedPrivateInvitePolicy};
use crate::private_enrollment_endorsement::Lifetime;
use base64::Engine as _;
use cgka_traits::{EngineError, GroupId, KeyPackage, TransportMessage, storage::StorageProvider};
use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Weak};
use tls_codec::Serialize;
use web_time::Instant;

/// Original owned policy lease; no public constructor, cloning or serialization.
/// Its local declaration cannot masquerade as an authenticated received message.
pub struct OwnedLocalEnrollmentProposal {
    owner: Weak<Lifetime>,
    policy: Arc<dyn TrustedPrivateInvitePolicy>,
    lease: Box<dyn PrivateInviteLease>,
    frame: RequestFrame,
    predecessor: CandidateDeviceGroupSnapshot,
    selection_generation: u64,
    package: KeyPackage,
    deadline: Instant,
    payload: Vec<u8>,
    ciphertext: Option<Vec<u8>>,
    wrapped: Option<TransportMessage>,
    own_endorsement: Option<Vec<u8>>,
}
impl OwnedLocalEnrollmentProposal {
    pub fn binding_digest(&mut self) -> Result<[u8; 32], EngineError> {
        self.check_live()?;
        super::request_binding_digest(&self.frame)
    }
    pub fn original_deadline(&self) -> Instant {
        self.deadline
    }
    fn check_live(&mut self) -> Result<(), EngineError> {
        if !self.owner.upgrade().is_some_and(|owner| owner.is_open())
            || Instant::now() >= self.deadline
        {
            return Err(unavailable());
        }
        self.lease
            .check_live_before_commit()
            .map_err(|_| unavailable())
    }
}
impl<S: StorageProvider> Engine<S> {
    /// Derive a proposal solely from fresh crypto inputs and the original trusted
    /// owner lease. No context, deadline or consent DTO is accepted from a caller.
    /// No Add, invitation ledger, ordinary Sent row or SDK admission is created.
    pub fn prepare_private_enrollment_proposal(
        &mut self,
        group: &GroupId,
        package: KeyPackage,
    ) -> Result<OwnedLocalEnrollmentProposal, EngineError> {
        self.ensure_group_live(group)?;
        let policy = self.private_invite_policy.clone().ok_or_else(unavailable)?;
        let (input, origin, selection_generation, artifact) =
            self.storage.with_read_snapshot(|_| {
                let settled = self
                    .validated_settled_device_roster(group)?
                    .ok_or_else(unavailable)?;
                let input = self.validate_private_invite_input(group, &package)?;
                if settled.candidate() != &input.predecessor {
                    return Err(unavailable());
                }
                let selected = self
                    .with_mls_group(group, |mls| {
                        crate::private_roster_settlement::completed_round_for_tree(
                            &self.storage,
                            group,
                            mls,
                        )
                    })?
                    .ok_or_else(unavailable)?;
                let artifact = self
                    .export_settled_device_predecessor(group)?
                    .ok_or_else(unavailable)?;
                Ok::<_, EngineError>((
                    input,
                    settled.origin().clone(),
                    selected.generation,
                    artifact,
                ))
            })?;
        let mut lease = policy.begin_prepare(&input).map_err(|_| unavailable())?;
        lease
            .check_live_before_commit()
            .map_err(|_| unavailable())?;
        let metadata = lease
            .enrollment_proposal_metadata()
            .map_err(|_| unavailable())?;
        let consent = lease.consent();
        let account: [u8; 32] = self
            .identity
            .self_id()
            .as_slice()
            .try_into()
            .map_err(|_| unavailable())?;
        let approver: [u8; 32] = self
            .identity
            .signer
            .public()
            .try_into()
            .map_err(|_| unavailable())?;
        let artifact_digest: [u8; 32] = Sha256::digest(&artifact).into();
        if consent.approver_scope.account != account
            || consent.approver_scope.local_device != approver
            || consent.approver_scope.generation == 0
            || consent.recipient_generation == 0
            || consent.origin != origin
            || consent.context_digest == [0; 32]
            || consent.nonce == [0; 32]
            || metadata.artifact_digest != artifact_digest
            || metadata.context_json.is_empty()
            || metadata.context_json.len() > PAYLOAD_LIMIT
            || Instant::now() >= metadata.original_deadline
        {
            return Err(unavailable());
        }
        // Deterministic correlation within the original SDK attempt: restoring
        // the same uncommitted lease cannot mint a new request identity or clock.
        // This domain-separated metadata nonce supplies no enrollment authority.
        let mut nonce = Sha256::new();
        nonce.update(b"whitenoise-private-local-enrollment-correlation-v2\0");
        nonce.update(consent.context_digest);
        nonce.update(consent.approver_scope.generation.to_be_bytes());
        nonce.update(consent.recipient_generation.to_be_bytes());
        nonce.update(selection_generation.to_be_bytes());
        nonce.update(input.key_package_reference);
        let frame = RequestFrame {
            protocol: PROPOSAL_PROTOCOL.into(),
            account,
            group_id: group.as_slice().to_vec(),
            epoch: input.predecessor.epoch.0,
            epoch_authenticator_digest: input.predecessor.epoch_authenticator_digest,
            leaves: input
                .predecessor
                .leaves
                .iter()
                .map(|leaf| {
                    Ok(RequestLeaf {
                        leaf_index: leaf.leaf_index,
                        signature_public_key: leaf
                            .signature_public_key
                            .as_slice()
                            .try_into()
                            .map_err(|_| unavailable())?,
                    })
                })
                .collect::<Result<_, EngineError>>()?,
            artifact_digest,
            context_digest: consent.context_digest,
            enrollment_nonce: consent.nonce,
            request_nonce: nonce.finalize().into(),
            approver,
            recipient: input.recipient_signature_public_key,
            approver_generation: consent.approver_scope.generation,
            recipient_generation: consent.recipient_generation,
            key_package_reference: input.key_package_reference.to_vec(),
            key_package_digest: Sha256::digest(package.bytes()).into(),
            proposal: Some(RequestProposal {
                artifact_base64: base64::engine::general_purpose::STANDARD.encode(artifact),
                context_json: metadata.context_json,
            }),
        };
        let event = cgka_traits::app_event::MarmotAppEvent::new(
            hex::encode(account),
            0,
            REQUEST_KIND,
            vec![],
            serde_json::to_string(&frame).map_err(|_| unavailable())?,
        );
        let payload = event.encode().map_err(|_| unavailable())?;
        if payload.len() > PAYLOAD_LIMIT {
            return Err(unavailable());
        }
        lease
            .check_live_before_commit()
            .map_err(|_| unavailable())?;
        Ok(OwnedLocalEnrollmentProposal {
            owner: self.enrollment_endorsements.owner_lifetime(),
            policy,
            lease,
            frame,
            predecessor: input.predecessor,
            selection_generation,
            package,
            deadline: metadata.original_deadline,
            payload,
            ciphertext: None,
            wrapped: None,
            own_endorsement: None,
        })
    }

    pub(crate) fn check_local_enrollment_proposal(
        &self,
        proposal: &mut OwnedLocalEnrollmentProposal,
    ) -> Result<(), EngineError> {
        if !self.enrollment_endorsements.owns_lifetime(&proposal.owner) {
            return Err(unavailable());
        }
        proposal.check_live()?;
        let policy = self
            .private_invite_policy
            .as_ref()
            .ok_or_else(unavailable)?;
        if !Arc::ptr_eq(policy, &proposal.policy) {
            return Err(unavailable());
        }
        self.storage.with_read_snapshot(|_| {
            let group = &proposal.predecessor.group_id;
            let settled = self
                .validated_settled_device_roster(group)?
                .ok_or_else(unavailable)?;
            let input = self.validate_private_invite_input(group, &proposal.package)?;
            let selected = self
                .with_mls_group(group, |mls| {
                    crate::private_roster_settlement::completed_round_for_tree(
                        &self.storage,
                        group,
                        mls,
                    )
                })?
                .ok_or_else(unavailable)?;
            if settled.candidate() != &proposal.predecessor
                || input.predecessor != proposal.predecessor
                || selected.generation != proposal.selection_generation
                || settled.origin() != &proposal.lease.consent().origin
            {
                return Err(unavailable());
            }
            Ok(())
        })?;
        proposal.check_live()
    }

    /// The local signature comes only from the original trusted SDK lease.
    /// Own MLS echoes and remote received-request objects cannot issue it.
    pub fn endorse_owned_local_enrollment_proposal(
        &self,
        proposal: &mut OwnedLocalEnrollmentProposal,
    ) -> Result<Vec<u8>, EngineError> {
        self.check_local_enrollment_proposal(proposal)?;
        if let Some(wire) = &proposal.own_endorsement {
            return Ok(wire.clone());
        }
        let binding = proposal.binding_digest()?;
        let wire = crate::private_enrollment_endorsement::sign_packet(
            self,
            &proposal.predecessor,
            binding,
        )?;
        self.check_local_enrollment_proposal(proposal)?;
        proposal.own_endorsement = Some(wire.clone());
        Ok(wire)
    }
    /// Validate one actual receipt under the original local SDK-owned proposal.
    /// Returned occupied-leaf index is metadata, never admission authority.
    pub fn authenticate_owned_local_enrollment_endorsement(
        &self,
        proposal: &mut OwnedLocalEnrollmentProposal,
        receipt: &crate::private_enrollment_endorsement::AuthenticatedEnrollmentEndorsement,
    ) -> Result<Option<u32>, EngineError> {
        self.check_local_enrollment_proposal(proposal)?;
        let settled = self
            .validated_settled_device_roster(&proposal.predecessor.group_id)?
            .ok_or_else(unavailable)?;
        if Instant::now() >= receipt.deadline
            || receipt.origin != *settled.origin()
            || receipt.settlement_generation != proposal.selection_generation
            || receipt.predecessor.epoch != proposal.predecessor.epoch
            || receipt.predecessor.epoch_authenticator_digest
                != proposal.predecessor.epoch_authenticator_digest
            || receipt.predecessor.leaves.len() != proposal.predecessor.leaves.len()
            || !receipt
                .predecessor
                .leaves
                .iter()
                .zip(&proposal.predecessor.leaves)
                .all(|(a, b)| {
                    a.leaf_index == b.leaf_index
                        && a.signature_public_key.as_slice() == b.signature_public_key
                })
            || receipt.source_signer == proposal.frame.approver
        {
            return Ok(None);
        }
        let encoded = &proposal
            .frame
            .proposal
            .as_ref()
            .ok_or_else(unavailable)?
            .artifact_base64;
        let artifact = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| unavailable())?;
        let authenticated = self.validate_private_device_predecessor(
            &artifact,
            &proposal.predecessor.account,
            &proposal.predecessor.group_id,
            proposal.predecessor.epoch,
            &proposal.predecessor.leaves,
        )?;
        if authenticated.artifact_digest() != &proposal.frame.artifact_digest {
            return Err(unavailable());
        }
        let binding = proposal.binding_digest()?;
        let Ok((index, signer)) =
            self.authenticate_private_enrollment_packet(&authenticated, &binding, &receipt.wire)
        else {
            return Ok(None);
        };
        if index != receipt.source_index || signer != receipt.source_signer {
            return Ok(None);
        }
        self.check_local_enrollment_proposal(proposal)?;
        Ok(Some(index))
    }

    /// All-current-leaf authentication under the live original local proposal.
    /// The result is metadata; it cannot construct Add, recipient or B authority.
    pub fn authenticate_owned_local_enrollment_endorsements(
        &self,
        proposal: &mut OwnedLocalEnrollmentProposal,
        received: &[&crate::private_enrollment_endorsement::AuthenticatedEnrollmentEndorsement],
    ) -> Result<crate::private_enrollment_endorsement::AuthenticatedAllLeafEndorsements, EngineError>
    {
        self.check_local_enrollment_proposal(proposal)?;
        if received.len().checked_add(1) != Some(proposal.predecessor.leaves.len()) {
            return Err(unavailable());
        }
        let own = self.endorse_owned_local_enrollment_proposal(proposal)?;
        let settled = self
            .validated_settled_device_roster(&proposal.predecessor.group_id)?
            .ok_or_else(unavailable)?;
        for receipt in received {
            if Instant::now() >= receipt.deadline
                || receipt.origin != *settled.origin()
                || receipt.settlement_generation != proposal.selection_generation
                || receipt.predecessor.epoch != proposal.predecessor.epoch
                || receipt.predecessor.epoch_authenticator_digest
                    != proposal.predecessor.epoch_authenticator_digest
                || receipt.predecessor.leaves.len() != proposal.predecessor.leaves.len()
                || !receipt
                    .predecessor
                    .leaves
                    .iter()
                    .zip(&proposal.predecessor.leaves)
                    .all(|(a, b)| {
                        a.leaf_index == b.leaf_index
                            && a.signature_public_key.as_slice() == b.signature_public_key
                    })
                || receipt.source_signer == proposal.frame.approver
                || !proposal.predecessor.leaves.iter().any(|leaf| {
                    leaf.leaf_index == receipt.source_index
                        && leaf.signature_public_key.as_slice() == receipt.source_signer
                })
            {
                return Err(unavailable());
            }
        }
        let encoded = &proposal
            .frame
            .proposal
            .as_ref()
            .ok_or_else(unavailable)?
            .artifact_base64;
        let artifact = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| unavailable())?;
        let authenticated = self.validate_private_device_predecessor(
            &artifact,
            &proposal.predecessor.account,
            &proposal.predecessor.group_id,
            proposal.predecessor.epoch,
            &proposal.predecessor.leaves,
        )?;
        if authenticated.artifact_digest() != &proposal.frame.artifact_digest {
            return Err(unavailable());
        }
        let mut packets = Vec::with_capacity(received.len() + 1);
        packets.push(own.as_slice());
        packets.extend(received.iter().map(|receipt| receipt.wire.as_slice()));
        let binding = proposal.binding_digest()?;
        let result = self.authenticate_all_private_enrollment_endorsements(
            &authenticated,
            &binding,
            &packets,
        )?;
        self.check_local_enrollment_proposal(proposal)?;
        Ok(result)
    }
    /// Commit the actual send ratchet once and retain exact ciphertext across
    /// transient wrapping retries. Successful wrapping remains control metadata;
    /// publication and any later Add require their own original-owner checks.
    pub async fn wrap_private_enrollment_proposal(
        &mut self,
        proposal: &mut OwnedLocalEnrollmentProposal,
    ) -> Result<TransportMessage, EngineError> {
        self.check_local_enrollment_proposal(proposal)?;
        if let Some(wrapped) = &proposal.wrapped {
            return Ok(wrapped.clone());
        }
        let group_id = proposal.predecessor.group_id.clone();
        let ctx = self.storage.with_read_snapshot(|storage| {
            let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
                &self.crypto,
                storage.mls_storage(),
            );
            self.with_mls_group(&group_id, |mls| {
                crate::group_lifecycle::build_group_context_snapshot(mls, &provider)
            })
        })?;
        if proposal.ciphertext.is_none() {
            let encrypted = self.storage.with_transaction(|storage| {
                self.check_local_enrollment_proposal(proposal)?;
                let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
                    &self.crypto,
                    storage.mls_storage(),
                );
                let mut group = MlsGroup::load(
                    provider.storage(),
                    &openmls::group::GroupId::from_slice(group_id.as_slice()),
                )
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
                let selected = crate::private_roster_settlement::completed_round_for_tree(
                    storage, &group_id, &group,
                )?
                .ok_or_else(unavailable)?;
                if selected.generation != proposal.selection_generation {
                    return Err(unavailable());
                }
                let ciphertext = group
                    .create_message(&provider, &self.identity.signer, &proposal.payload)
                    .map_err(|_| unavailable())?
                    .tls_serialize_detached()
                    .map_err(|_| unavailable())?;
                proposal.check_live()?;
                Ok::<_, EngineError>(ciphertext)
            });
            // This path loads a scratch object. Invalidate any cached group on
            // both outcomes; SQL rollback restores durable state on an error.
            self.mls_group_cache.forget_group(&group_id);
            proposal.ciphertext = Some(encrypted?);
        }
        let payload = cgka_traits::EncryptedPayload {
            ciphertext: proposal
                .ciphertext
                .as_ref()
                .ok_or_else(unavailable)?
                .clone(),
            aad: vec![],
        };
        let remaining = proposal.deadline.saturating_duration_since(Instant::now());
        let mut operation = self.peeler.wrap_group_message(&payload, &ctx);
        let wrapping = std::future::poll_fn(|cx| {
            if let Err(error) = proposal.check_live() {
                return std::task::Poll::Ready(Err(error));
            }
            operation
                .as_mut()
                .poll(cx)
                .map(|result| result.map_err(EngineError::Peeler))
        });
        let wrapped = crate::deadline::timeout(remaining, wrapping)
            .await
            .map_err(|_| unavailable())??;
        self.check_local_enrollment_proposal(proposal)?;
        let wrapped = crate::message_processor::route_wrapped_group_message(wrapped, &ctx);
        proposal.wrapped = Some(wrapped.clone());
        Ok(wrapped)
    }
}
