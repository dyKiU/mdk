//! Explicit current-leaf endorsements for the default-off private profile.
//! Signed packets are observations, not SDK consent or portable join permission.
//! Existing-member transition additionally requires its original owned continuation.
use crate::private_enrollment_predecessor::AuthenticatedPrivatePredecessor;
use crate::private_enrollment_request::AuthenticatedEnrollmentRequest;
use crate::{Engine, device_group_snapshot::CandidateDeviceGroupSnapshot};
use cgka_traits::{EngineError, GroupId, KeyPackage, storage::StorageProvider};
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, types::SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use web_time::Instant;

const PROTOCOL: &str = "whitenoise.experimental.enrollment-endorsement.v1";
const DOMAIN: &[u8] = b"whitenoise-private-enrollment-endorsement-v1\0";
const MAX_PACKET_BYTES: usize = 2048;

fn denied() -> EngineError {
    EngineError::Other("private enrollment endorsement denied".into())
}
#[derive(Default)]
pub(crate) struct Lifetime {
    generation: AtomicU64,
    closed: AtomicBool,
}
#[derive(Default)]
pub(crate) struct EndorsementState {
    lifetime: Arc<Lifetime>,
    active: Mutex<Option<[u8; 32]>>,
}
impl Lifetime {
    pub(crate) fn is_open(&self) -> bool {
        !self.closed.load(Ordering::SeqCst)
    }
}
impl EndorsementState {
    /// Shared exact Engine identity only; no endorsement or SDK consent.
    pub(crate) fn owner_lifetime(&self) -> Weak<Lifetime> {
        Arc::downgrade(&self.lifetime)
    }
    pub(crate) fn owns_lifetime(&self, owner: &Weak<Lifetime>) -> bool {
        Weak::ptr_eq(owner, &self.owner_lifetime())
    }
}
impl Drop for EndorsementState {
    fn drop(&mut self) {
        self.lifetime.closed.store(true, Ordering::SeqCst);
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    protocol: String,
    source_index: u32,
    source_signer: [u8; 32],
    binding_digest: [u8; 32],
    signature: Vec<u8>,
}
fn signing_input(packet: &Packet) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 68);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&packet.source_index.to_be_bytes());
    bytes.extend_from_slice(&packet.source_signer);
    bytes.extend_from_slice(&packet.binding_digest);
    bytes
}
/// One current engine's bounded explicit action. No Clone, Serde or constructor.
/// A copied wire packet cannot reconstruct this existing-member continuation.
pub struct OwnedEnrollmentEndorsement {
    owner: Weak<Lifetime>,
    generation: u64,
    deadline: Instant,
    predecessor: CandidateDeviceGroupSnapshot,
    origin: cgka_traits::private_device_invite::PrivateInviteOrigin,
    settlement_generation: u64,
    wire: Vec<u8>,
}
impl OwnedEnrollmentEndorsement {
    fn live(&self) -> Result<Arc<Lifetime>, EngineError> {
        let owner = self.owner.upgrade().ok_or_else(denied)?;
        if owner.closed.load(Ordering::SeqCst)
            || owner.generation.load(Ordering::SeqCst) != self.generation
            || Instant::now() >= self.deadline
        {
            return Err(denied());
        }
        Ok(owner)
    }
    /// Public signed correlation only, while the original local action is live.
    pub fn wire(&self) -> Result<&[u8], EngineError> {
        self.live()?;
        Ok(&self.wire)
    }
}
/// Portable all-leaf signature metadata, never an owner/SAS/admission constructor.
pub struct AuthenticatedAllLeafEndorsements {
    binding_digest: [u8; 32],
    artifact_digest: [u8; 32],
    leaf_count: usize,
}
impl AuthenticatedAllLeafEndorsements {
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }
    pub fn binding_digest(&self) -> &[u8; 32] {
        &self.binding_digest
    }
    pub fn artifact_digest(&self) -> &[u8; 32] {
        &self.artifact_digest
    }
}
pub(crate) fn matches_current(
    request: &AuthenticatedEnrollmentRequest,
    current: &CandidateDeviceGroupSnapshot,
) -> bool {
    let predecessor = request.predecessor();
    request.account().as_slice() == current.account.as_slice()
        && request.group_id() == current.group_id.as_slice()
        && predecessor.epoch == current.epoch
        && predecessor.epoch_authenticator_digest == current.epoch_authenticator_digest
        && predecessor.leaves.len() == current.leaves.len()
        && predecessor
            .leaves
            .iter()
            .zip(&current.leaves)
            .all(|(left, right)| {
                left.account == *request.account()
                    && left.leaf_index == right.leaf_index
                    && left.signature_public_key.as_slice() == right.signature_public_key
            })
}
impl<S: StorageProvider> Engine<S> {
    /// Explicit action on an actually received request. SDK context agreement is
    /// a separate App-owner check; neither caller digest nor this packet grants Add.
    pub fn endorse_private_enrollment_request(
        &self,
        request: &AuthenticatedEnrollmentRequest,
        artifact: &[u8],
        package: &KeyPackage,
        context_digest: &[u8; 32],
    ) -> Result<OwnedEnrollmentEndorsement, EngineError> {
        let state = &self.enrollment_endorsements;
        let generation = state.lifetime.generation.load(Ordering::SeqCst);
        if state.lifetime.closed.load(Ordering::SeqCst) {
            return Err(denied());
        }
        let deadline = request.observed_deadline();
        if Instant::now() >= deadline
            || request.context_digest() != context_digest
            || context_digest == &[0; 32]
            || artifact.is_empty()
            || artifact.len() > 256 * 1024
            || package.bytes().is_empty()
            || package.bytes().len() > 16 * 1024
        {
            return Err(denied());
        }
        let group = GroupId::new(request.group_id().to_vec());
        let current = self.storage.with_read_snapshot(|_| {
            let current = self
                .validated_settled_device_roster(&group)?
                .ok_or_else(denied)?;
            let candidate = current.candidate();
            if !request
                .matches_protected_selection(current.origin(), current.settlement_generation())
                || !matches_current(request, candidate)
            {
                return Err(denied());
            }
            let proof = self.validate_private_enrollment_request_predecessor(request, artifact)?;
            if proof.artifact_digest() != request.artifact_digest() {
                return Err(denied());
            }
            let input = self.validate_private_invite_input(&group, package)?;
            let package_digest: [u8; 32] = Sha256::digest(package.bytes()).into();
            if input.predecessor != *candidate
                || input.recipient_signature_public_key != *request.recipient()
                || input.key_package_reference.as_slice() != request.key_package_reference()
                || package_digest != *request.key_package_digest()
            {
                return Err(denied());
            }
            Ok((
                candidate.clone(),
                current.origin().clone(),
                current.settlement_generation(),
            ))
        })?;
        let (current, origin, settlement_generation) = current;
        let source_signer: [u8; 32] = self
            .identity
            .signer
            .public()
            .try_into()
            .map_err(|_| denied())?;
        let own = current
            .leaves
            .iter()
            .find(|leaf| leaf.signature_public_key.as_slice() == source_signer)
            .ok_or_else(denied)?;
        let binding_digest = request.binding_digest()?;
        let mut packet = Packet {
            protocol: PROTOCOL.into(),
            source_index: own.leaf_index,
            source_signer,
            binding_digest,
            signature: Vec::new(),
        };
        packet.signature = self
            .identity
            .signer
            .sign(&signing_input(&packet))
            .map_err(|_| denied())?;
        let wire = serde_json::to_vec(&packet).map_err(|_| denied())?;
        if wire.len() > MAX_PACKET_BYTES || Instant::now() >= deadline {
            return Err(denied());
        }
        let mut active = state.active.lock().map_err(|_| denied())?;
        if state.lifetime.closed.load(Ordering::SeqCst)
            || state.lifetime.generation.load(Ordering::SeqCst) != generation
            || Instant::now() >= deadline
            || active.is_some()
        {
            return Err(denied());
        }
        *active = Some(binding_digest);
        Ok(OwnedEnrollmentEndorsement {
            owner: Arc::downgrade(&state.lifetime),
            generation,
            deadline,
            predecessor: current,
            origin,
            settlement_generation,
            wire,
        })
    }
    /// Fresh local validation for later existing-member handoff, never wire restore.
    pub fn validate_owned_private_enrollment_endorsement(
        &self,
        endorsement: &OwnedEnrollmentEndorsement,
    ) -> Result<(), EngineError> {
        let owner = endorsement.live()?;
        if !Arc::ptr_eq(&owner, &self.enrollment_endorsements.lifetime) {
            return Err(denied());
        }
        let settled = self
            .validated_settled_device_roster(&endorsement.predecessor.group_id)?
            .ok_or_else(denied)?;
        if settled.candidate() != &endorsement.predecessor
            || settled.origin() != &endorsement.origin
            || settled.settlement_generation() != endorsement.settlement_generation
        {
            return Err(denied());
        }
        Ok(())
    }
    /// Cancellation burns the local generation; reopening has a different owner.
    pub fn cancel_private_enrollment_endorsements(&self) -> Result<(), EngineError> {
        let state = &self.enrollment_endorsements;
        let mut active = state.active.lock().map_err(|_| denied())?;
        if state
            .lifetime
            .generation
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |generation| {
                generation.checked_add(1)
            })
            .is_err()
        {
            state.lifetime.closed.store(true, Ordering::SeqCst);
            return Err(denied());
        }
        *active = None;
        Ok(())
    }
    /// Verify every occupied predecessor leaf once against actual authenticated
    /// public-tree keys. Completeness does not restore a live owner's approval.
    pub fn authenticate_all_private_enrollment_endorsements(
        &self,
        artifact: &AuthenticatedPrivatePredecessor,
        binding: &[u8; 32],
        endorsements: &[&[u8]],
    ) -> Result<AuthenticatedAllLeafEndorsements, EngineError> {
        if binding == &[0; 32]
            || endorsements.len() != artifact.leaves().len()
            || endorsements.is_empty()
            || endorsements.len() > 128
        {
            return Err(denied());
        }
        let mut indices = HashSet::new();
        for wire in endorsements {
            if wire.is_empty() || wire.len() > MAX_PACKET_BYTES {
                return Err(denied());
            }
            let packet: Packet = serde_json::from_slice(wire).map_err(|_| denied())?;
            if packet.protocol != PROTOCOL
                || packet.binding_digest != *binding
                || packet.signature.len() != 64
                || !indices.insert(packet.source_index)
                || !artifact.leaves().iter().any(|leaf| {
                    leaf.leaf_index == packet.source_index
                        && leaf.signature_public_key.as_slice() == packet.source_signer
                })
            {
                return Err(denied());
            }
            self.crypto
                .verify_signature(
                    SignatureScheme::ED25519,
                    &signing_input(&packet),
                    &packet.source_signer,
                    &packet.signature,
                )
                .map_err(|_| denied())?;
        }
        Ok(AuthenticatedAllLeafEndorsements {
            binding_digest: *binding,
            artifact_digest: *artifact.artifact_digest(),
            leaf_count: indices.len(),
        })
    }
}

/// Portable signature fixture only: no owned action, consent, or live authority.
#[cfg(test)]
pub(crate) fn sign_public_packet_for_test<S: StorageProvider + 'static>(
    engine: &Engine<S>,
    group: &GroupId,
    binding: [u8; 32],
) -> Result<Vec<u8>, EngineError> {
    let settled = engine
        .validated_settled_device_roster(group)?
        .ok_or_else(denied)?;
    let source_signer: [u8; 32] = engine
        .identity
        .signer
        .public()
        .try_into()
        .map_err(|_| denied())?;
    let own = settled
        .candidate()
        .leaves
        .iter()
        .find(|leaf| leaf.signature_public_key.as_slice() == source_signer)
        .ok_or_else(denied)?;
    let mut packet = Packet {
        protocol: PROTOCOL.into(),
        source_index: own.leaf_index,
        source_signer,
        binding_digest: binding,
        signature: Vec::new(),
    };
    packet.signature = engine
        .identity
        .signer
        .sign(&signing_input(&packet))
        .map_err(|_| denied())?;
    serde_json::to_vec(&packet).map_err(|_| denied())
}
