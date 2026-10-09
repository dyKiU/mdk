//! Bounded signed metadata for a separately SDK-owned original recipient.
//! Neither portable signatures nor this owner can replace the live join lease.
use super::{PAYLOAD_LIMIT, PROPOSAL_PROTOCOL, RequestFrame, request_binding_digest, unavailable};
use crate::Engine;
use crate::private_enrollment_endorsement::Lifetime;
use crate::private_enrollment_predecessor::AuthenticatedPrivatePredecessor;
use base64::Engine as _;
use cgka_traits::device_linking_key_package::{PurposeAttemptScope, PurposeKeyPackage};
use cgka_traits::storage::StorageProvider;
use cgka_traits::{EngineError, GroupId, MemberId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Weak;
use std::time::Duration;
use web_time::Instant;
const PROTOCOL: &str = "whitenoise.experimental.enrollment-recipient-evidence.v1";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    protocol: String,
    request: RequestFrame,
    endorsements: Vec<String>,
}
#[derive(Serialize)]
struct ExportPacket<'a> {
    protocol: &'static str,
    request: &'a RequestFrame,
    endorsements: Vec<String>,
}
/// Process-local metadata tied to the actual original purpose and Core lifetime.
/// No constructor/Clone/Serde. Joining additionally requires the original SDK lease.
pub struct OwnedEnrollmentRecipientEvidence {
    owner: Weak<Lifetime>,
    scope: PurposeAttemptScope,
    deadline: Instant,
    packet: Packet,
    context_json: String,
    artifact: AuthenticatedPrivatePredecessor,
    binding: [u8; 32],
    signed_packets: Vec<Vec<u8>>,
}
impl OwnedEnrollmentRecipientEvidence {
    pub fn context_json(&self) -> &str {
        &self.context_json
    }
    pub fn original_scope(&self) -> &PurposeAttemptScope {
        &self.scope
    }
    pub fn context_digest(&self) -> &[u8; 32] {
        &self.packet.request.context_digest
    }
    pub fn predecessor(&self) -> &AuthenticatedPrivatePredecessor {
        &self.artifact
    }
    pub(crate) fn check_current<S: StorageProvider>(
        &self,
        engine: &Engine<S>,
        context: &cgka_traits::peeler::PrivateLinkingWelcomeContext,
    ) -> Result<(), EngineError> {
        let purpose = engine
            .storage
            .device_linking_key_package_storage()
            .ok_or_else(unavailable)?
            .purpose_key_package()?
            .ok_or_else(unavailable)?;
        self.check(engine, &purpose)?;
        self.check_transport(context)
    }
    pub(crate) fn check_transport(
        &self,
        context: &cgka_traits::peeler::PrivateLinkingWelcomeContext,
    ) -> Result<(), EngineError> {
        let frame = &self.packet.request;
        if context.account != frame.account
            || context.approver != frame.approver
            || context.recipient != frame.recipient
            || context.approver_generation != frame.approver_generation
            || context.recipient_generation != frame.recipient_generation
            || context.group_id.as_slice() != frame.group_id
            || context.nonce != frame.enrollment_nonce
            || context.context_digest != frame.context_digest
            || context.key_package_reference.as_slice() != frame.key_package_reference
            || context.key_package_digest != frame.key_package_digest
        {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(crate) fn check_predecessor(
        &self,
        roster: &cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster,
    ) -> Result<(), EngineError> {
        let frame = &self.packet.request;
        if roster.epoch.0 != frame.epoch
            || roster.epoch_authenticator_digest != frame.epoch_authenticator_digest
            || roster.leaves.len() != frame.leaves.len()
            || !roster.leaves.iter().zip(&frame.leaves).all(|(a, b)| {
                a.account == frame.account
                    && a.leaf_index == b.leaf_index
                    && a.signature_public_key == b.signature_public_key
            })
        {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(crate) fn check<S: StorageProvider>(
        &self,
        engine: &Engine<S>,
        purpose: &PurposeKeyPackage,
    ) -> Result<(), EngineError> {
        if !engine.enrollment_endorsements.owns_lifetime(&self.owner)
            || !self.owner.upgrade().is_some_and(|owner| owner.is_open())
            || Instant::now() >= self.deadline
            || purpose.scope != self.scope
        {
            return Err(unavailable());
        }
        check_purpose(engine, purpose, &self.packet.request)?;
        let packets = self
            .signed_packets
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        engine.authenticate_all_private_enrollment_endorsements(
            &self.artifact,
            &self.binding,
            &packets,
        )?;
        Ok(())
    }
}
fn check_purpose<S: StorageProvider>(
    engine: &Engine<S>,
    purpose: &PurposeKeyPackage,
    frame: &RequestFrame,
) -> Result<(), EngineError> {
    let context = purpose.context.as_ref().ok_or_else(unavailable)?;
    if purpose.consumed
        || engine.identity.self_id().as_slice() != frame.account
        || engine.identity.signer.public() != frame.recipient
        || purpose.scope.account != frame.account
        || purpose.scope.local_device != frame.recipient
        || purpose.scope.generation != frame.recipient_generation
        || purpose.signature_public_key != frame.recipient
        || purpose.reference.as_slice() != frame.key_package_reference
        || <[u8; 32]>::from(Sha256::digest(&purpose.public_bytes)) != frame.key_package_digest
        || context.nonce != frame.enrollment_nonce
        || context.context_digest != frame.context_digest
    {
        return Err(unavailable());
    }
    Ok(())
}
pub(super) fn encode_packet(
    frame: &RequestFrame,
    packets: Vec<&[u8]>,
) -> Result<Vec<u8>, EngineError> {
    let bytes = serde_json::to_vec(&ExportPacket {
        protocol: PROTOCOL,
        request: frame,
        endorsements: packets
            .iter()
            .map(|wire| base64::engine::general_purpose::STANDARD.encode(wire))
            .collect(),
    })
    .map_err(|_| unavailable())?;
    if bytes.len() > PAYLOAD_LIMIT {
        return Err(unavailable());
    }
    Ok(bytes)
}
impl<S: StorageProvider> Engine<S> {
    /// Negative metadata comparison only. Actual joining still requires the live SDK lease.
    pub fn validate_owned_recipient_evidence(
        &self,
        evidence: &OwnedEnrollmentRecipientEvidence,
        context: &cgka_traits::peeler::PrivateLinkingWelcomeContext,
        predecessor: &cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster,
    ) -> Result<(), EngineError> {
        evidence.check_current(self, context)?;
        evidence.check_predecessor(predecessor)
    }

    /// Authenticity metadata bound to the actual saved purpose. No SDK grant:
    /// the account actor must independently match its original owned context.
    pub fn authenticate_original_recipient_enrollment_evidence(
        &self,
        scope: &PurposeAttemptScope,
        bytes: &[u8],
    ) -> Result<OwnedEnrollmentRecipientEvidence, EngineError> {
        let AuthenticatedPacket {
            packet,
            artifact,
            binding,
            signed_packets,
        } = decode_packet(self, bytes)?;
        let frame = &packet.request;
        let purpose = self
            .storage
            .device_linking_key_package_storage()
            .ok_or_else(unavailable)?
            .purpose_key_package()?
            .ok_or_else(unavailable)?;
        if &purpose.scope != scope {
            return Err(unavailable());
        }
        check_purpose(self, &purpose, frame)?;
        let evidence = OwnedEnrollmentRecipientEvidence {
            owner: self.enrollment_endorsements.owner_lifetime(),
            scope: scope.clone(),
            deadline: Instant::now() + Duration::from_secs(600),
            context_json: frame
                .proposal
                .as_ref()
                .ok_or_else(unavailable)?
                .context_json
                .clone(),
            packet,
            artifact,
            binding,
            signed_packets,
        };
        evidence.check(self, &purpose)?;
        Ok(evidence)
    }
}

pub(crate) struct ExistingEnrollmentMetadata {
    pub(crate) account: [u8; 32],
    pub(crate) group: GroupId,
    pub(crate) predecessor: cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster,
    pub(crate) binding: [u8; 32],
    pub(crate) nonce: [u8; 32],
    pub(crate) context_digest: [u8; 32],
    pub(crate) coordinator: [u8; 32],
    pub(crate) recipient: [u8; 32],
    pub(crate) key_package_reference: [u8; 32],
    pub(crate) key_package_digest: [u8; 32],
    pub(crate) signed_packets: Vec<Vec<u8>>,
}
pub(crate) fn authenticate_existing_packet<S: StorageProvider>(
    engine: &Engine<S>,
    bytes: &[u8],
) -> Result<ExistingEnrollmentMetadata, EngineError> {
    let AuthenticatedPacket {
        packet,
        artifact,
        binding,
        signed_packets,
    } = decode_packet(engine, bytes)?;
    let frame = packet.request;
    let predecessor = cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster {
        epoch: cgka_traits::EpochId(frame.epoch),
        epoch_authenticator_digest: frame.epoch_authenticator_digest,
        leaves: artifact
            .leaves()
            .iter()
            .map(|leaf| {
                Ok(cgka_traits::device_group_genesis::GenesisLeaf {
                    account: frame.account,
                    leaf_index: leaf.leaf_index,
                    signature_public_key: leaf
                        .signature_public_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| unavailable())?,
                })
            })
            .collect::<Result<Vec<_>, EngineError>>()?,
    };
    Ok(ExistingEnrollmentMetadata {
        account: frame.account,
        group: GroupId::new(frame.group_id),
        predecessor,
        binding,
        nonce: frame.enrollment_nonce,
        context_digest: frame.context_digest,
        coordinator: frame.approver,
        recipient: frame.recipient,
        key_package_reference: frame
            .key_package_reference
            .try_into()
            .map_err(|_| unavailable())?,
        key_package_digest: frame.key_package_digest,
        signed_packets,
    })
}
struct AuthenticatedPacket {
    packet: Packet,
    artifact: AuthenticatedPrivatePredecessor,
    binding: [u8; 32],
    signed_packets: Vec<Vec<u8>>,
}
fn decode_packet<S: StorageProvider>(
    engine: &Engine<S>,
    bytes: &[u8],
) -> Result<AuthenticatedPacket, EngineError> {
    if bytes.is_empty() || bytes.len() > PAYLOAD_LIMIT {
        return Err(unavailable());
    }
    let packet: Packet = serde_json::from_slice(bytes).map_err(|_| unavailable())?;
    let frame = &packet.request;
    if serde_json::to_vec(&packet).map_err(|_| unavailable())? != bytes
        || packet.protocol != PROTOCOL
        || frame.protocol != PROPOSAL_PROTOCOL
        || packet.endorsements.is_empty()
        || packet.endorsements.len() > 128
        || frame.leaves.len() < 2
        || frame.leaves.len() > 127
        || frame.epoch == 0
        || frame.group_id.is_empty()
        || frame.group_id.len() > 255
        || frame.approver_generation == 0
        || frame.request_nonce == [0; 32]
        || frame.artifact_digest == [0; 32]
        || frame.context_digest == [0; 32]
        || frame.recipient == frame.approver
        || frame
            .leaves
            .iter()
            .any(|leaf| leaf.signature_public_key == frame.recipient)
        || !frame
            .leaves
            .iter()
            .any(|leaf| leaf.signature_public_key == frame.approver)
    {
        return Err(unavailable());
    }
    let proposal = frame
        .proposal
        .as_ref()
        .filter(|proposal| proposal.bounded())
        .ok_or_else(unavailable)?;
    let artifact_bytes = base64::engine::general_purpose::STANDARD
        .decode(&proposal.artifact_base64)
        .map_err(|_| unavailable())?;
    if base64::engine::general_purpose::STANDARD.encode(&artifact_bytes) != proposal.artifact_base64
        || <[u8; 32]>::from(Sha256::digest(&artifact_bytes)) != frame.artifact_digest
    {
        return Err(unavailable());
    }
    let leaves = frame
        .leaves
        .iter()
        .map(|leaf| crate::device_group_snapshot::CandidateDeviceLeaf {
            leaf_index: leaf.leaf_index,
            signature_public_key: leaf.signature_public_key.to_vec(),
        })
        .collect::<Vec<_>>();
    let artifact = engine.validate_private_device_predecessor(
        &artifact_bytes,
        &MemberId::new(frame.account.to_vec()),
        &GroupId::new(frame.group_id.clone()),
        cgka_traits::EpochId(frame.epoch),
        &leaves,
    )?;
    let binding = request_binding_digest(frame)?;
    let signed_packets = packet
        .endorsements
        .iter()
        .map(|encoded| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| unavailable())?;
            if base64::engine::general_purpose::STANDARD.encode(&bytes) != *encoded {
                return Err(unavailable());
            }
            Ok(bytes)
        })
        .collect::<Result<Vec<_>, EngineError>>()?;
    let packets = signed_packets.iter().map(Vec::as_slice).collect::<Vec<_>>();
    engine.authenticate_all_private_enrollment_endorsements(&artifact, &binding, &packets)?;
    Ok(AuthenticatedPacket {
        packet,
        artifact,
        binding,
        signed_packets,
    })
}
