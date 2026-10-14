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

pub(crate) const ENDORSEMENT_KIND: u64 = 38176;
pub(crate) const PROTOCOL: &str = "whitenoise.experimental.enrollment-endorsement.v1";
const DOMAIN: &[u8] = b"whitenoise-private-enrollment-endorsement-v1\0";
pub(crate) const SHARING_PROTOCOL: &str =
    "whitenoise.experimental.enrollment-sharing-endorsement.v1";
const SHARING_DOMAIN: &[u8] = b"whitenoise-private-enrollment-account-chat-sharing-v1\0";
const MAX_PACKET_BYTES: usize = 2048;

fn denied() -> EngineError {
    EngineError::Other("private enrollment endorsement denied".into())
}
#[derive(Default)]
pub(crate) struct Lifetime {
    generation: AtomicU64,
    closed: AtomicBool,
    wake: Mutex<Option<std::task::Waker>>,
}
#[derive(Default)]
pub(crate) struct EndorsementState {
    lifetime: Arc<Lifetime>,
    active: Mutex<Option<[u8; 32]>>,
    existing: Mutex<Option<Arc<OwnedExistingEnrollmentTransition>>>,
}
impl Lifetime {
    fn register_waker(&self, waker: &std::task::Waker) {
        *self.wake.lock().unwrap_or_else(|error| error.into_inner()) = Some(waker.clone());
    }
    fn wake(&self) {
        let waker = self
            .wake
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
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
        self.lifetime.wake();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    protocol: String,
    source_index: u32,
    source_signer: [u8; 32],
    binding_digest: [u8; 32],
    #[serde(default, skip_serializing_if = "is_false")]
    share_chats: bool,
    signature: Vec<u8>,
}
fn is_false(value: &bool) -> bool {
    !*value
}
fn valid_protocol(packet: &Packet) -> bool {
    (packet.protocol == PROTOCOL && !packet.share_chats)
        || (packet.protocol == SHARING_PROTOCOL && packet.share_chats)
}
fn signing_input(packet: &Packet) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 68);
    if packet.share_chats {
        bytes.extend_from_slice(SHARING_DOMAIN);
        bytes.extend_from_slice(
            &cgka_traits::approved_account_sharing_policy::ACCOUNT_SHARING_POLICY_VERSION
                .to_be_bytes(),
        );
        bytes.push(cgka_traits::approved_account_sharing_policy::ACCOUNT_SHARING_CAPABILITIES);
    } else {
        bytes.extend_from_slice(DOMAIN);
    }
    bytes.extend_from_slice(&packet.source_index.to_be_bytes());
    bytes.extend_from_slice(&packet.source_signer);
    bytes.extend_from_slice(&packet.binding_digest);
    bytes
}
/// Exact original-generation negative control. It can revoke, never restore.
#[derive(Clone)]
pub struct EnrollmentEndorsementCancellation {
    owner: Weak<Lifetime>,
    generation: u64,
}
impl EnrollmentEndorsementCancellation {
    pub fn cancel(&self) {
        if let Some(owner) = self.owner.upgrade() {
            if let Some(next) = self.generation.checked_add(1) {
                let _ = owner.generation.compare_exchange(
                    self.generation,
                    next,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
            } else {
                owner.closed.store(true, Ordering::SeqCst);
            }
            owner.wake();
        }
    }
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
    ciphertext: Option<Vec<u8>>,
    wrapped: Option<cgka_traits::TransportMessage>,
    metadata_tags: Option<Vec<Vec<String>>>,
}
impl OwnedEnrollmentEndorsement {
    pub fn cancellation_handle(&self) -> EnrollmentEndorsementCancellation {
        EnrollmentEndorsementCancellation {
            owner: self.owner.clone(),
            generation: self.generation,
        }
    }
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
/// Actual private MLS receipt; no Clone/Serde/constructor or enrollment authority.
pub struct AuthenticatedEnrollmentEndorsement {
    pub(crate) predecessor: cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster,
    pub(crate) origin: cgka_traits::private_device_invite::PrivateInviteOrigin,
    pub(crate) settlement_generation: u64,
    pub(crate) deadline: Instant,
    pub(crate) source_index: u32,
    pub(crate) source_signer: [u8; 32],
    pub(crate) wire: Vec<u8>,
    metadata_tags: Vec<Vec<String>>,
}
impl AuthenticatedEnrollmentEndorsement {
    /// Actual outer MLS source metadata; not part of a portable signature grant.
    pub fn metadata_tags(&self) -> &[Vec<String>] {
        &self.metadata_tags
    }
    pub fn observed_deadline(&self) -> Instant {
        self.deadline
    }
    pub fn source_index(&self) -> u32 {
        self.source_index
    }
}
pub(crate) fn received_observation(
    content: &str,
    metadata_tags: &[Vec<String>],
    index: u32,
    signer: [u8; 32],
    state: &cgka_traits::private_roster_settlement::PrivateSettlementState,
    deadline: Instant,
) -> Option<AuthenticatedEnrollmentEndorsement> {
    if content.len() > MAX_PACKET_BYTES
        || Instant::now() >= deadline
        || !crate::private_enrollment_request::bounded_enrollment_metadata(metadata_tags)
    {
        return None;
    }
    let packet: Packet = serde_json::from_str(content).ok()?;
    if !valid_protocol(&packet)
        || packet.source_index != index
        || packet.source_signer != signer
        || packet.binding_digest == [0; 32]
        || packet.signature.len() != 64
        || serde_json::to_string(&packet).ok()?.as_str() != content
    {
        return None;
    }
    Some(AuthenticatedEnrollmentEndorsement {
        predecessor: state.anchor.successor.clone(),
        origin: state.anchor.origin.clone(),
        settlement_generation: state.generation,
        deadline,
        source_index: index,
        source_signer: signer,
        wire: content.as_bytes().to_vec(),
        metadata_tags: metadata_tags.to_vec(),
    })
}
pub(crate) fn sign_packet<S: StorageProvider>(
    engine: &Engine<S>,
    current: &CandidateDeviceGroupSnapshot,
    binding: [u8; 32],
) -> Result<Vec<u8>, EngineError> {
    let source_signer: [u8; 32] = engine
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
    let mut packet = Packet {
        protocol: PROTOCOL.into(),
        source_index: own.leaf_index,
        source_signer,
        binding_digest: binding,
        share_chats: false,
        signature: Vec::new(),
    };
    packet.signature = engine
        .identity
        .signer
        .sign(&signing_input(&packet))
        .map_err(|_| denied())?;
    let wire = serde_json::to_vec(&packet).map_err(|_| denied())?;
    if wire.len() > MAX_PACKET_BYTES {
        return Err(denied());
    }
    Ok(wire)
}
/// Portable all-leaf signature metadata, never an owner/SAS/admission constructor.
pub struct AuthenticatedAllLeafEndorsements {
    binding_digest: [u8; 32],
    artifact_digest: [u8; 32],
    leaf_count: usize,
    sharing_devices: Vec<[u8; 32]>,
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
    /// Authenticated terms observations only; no bilateral policy or live grant.
    pub fn sharing_devices(&self) -> &[[u8; 32]] {
        &self.sharing_devices
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
        self.endorse_private_enrollment_request_with_sharing(
            request,
            artifact,
            package,
            context_digest,
            false,
        )
    }
    /// Sign the explicit broader choice with the same original received action.
    /// The marker identifies requested terms; it is not a policy or join grant.
    pub fn endorse_private_enrollment_request_and_share_chats(
        &self,
        request: &AuthenticatedEnrollmentRequest,
        artifact: &[u8],
        package: &KeyPackage,
        context_digest: &[u8; 32],
    ) -> Result<OwnedEnrollmentEndorsement, EngineError> {
        self.endorse_private_enrollment_request_with_sharing(
            request,
            artifact,
            package,
            context_digest,
            true,
        )
    }
    fn endorse_private_enrollment_request_with_sharing(
        &self,
        request: &AuthenticatedEnrollmentRequest,
        artifact: &[u8],
        package: &KeyPackage,
        context_digest: &[u8; 32],
        share_chats: bool,
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
            protocol: if share_chats {
                SHARING_PROTOCOL
            } else {
                PROTOCOL
            }
            .into(),
            source_index: own.leaf_index,
            source_signer,
            binding_digest,
            share_chats,
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
            ciphertext: None,
            wrapped: None,
            metadata_tags: None,
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
        *state.existing.lock().map_err(|_| denied())? = None;
        state.lifetime.wake();
        Ok(())
    }
    /// Attach immutable bounded outer MLS metadata to the same live B action.
    /// Signed endorsement terms and binding are unchanged; no authority is added.
    pub fn set_owned_enrollment_metadata(
        &self,
        endorsement: &mut OwnedEnrollmentEndorsement,
        tags: Vec<Vec<String>>,
    ) -> Result<(), EngineError> {
        self.validate_owned_private_enrollment_endorsement(endorsement)?;
        if tags.is_empty() || !crate::private_enrollment_request::bounded_enrollment_metadata(&tags)
        {
            return Err(denied());
        }
        if let Some(previous) = &endorsement.metadata_tags {
            return if previous == &tags {
                Ok(())
            } else {
                Err(denied())
            };
        }
        if endorsement.ciphertext.is_some() || endorsement.wrapped.is_some() {
            return Err(denied());
        }
        endorsement.metadata_tags = Some(tags);
        Ok(())
    }
    /// Encrypt the original B action once. A failed wrap retains exact cipher;
    /// failed SQL rolls back the send ratchet. Cached retries recheck selection.
    pub async fn wrap_private_enrollment_endorsement(
        &mut self,
        endorsement: &mut OwnedEnrollmentEndorsement,
    ) -> Result<cgka_traits::TransportMessage, EngineError> {
        use openmls::group::MlsGroup;
        use openmls_traits::OpenMlsProvider;
        use tls_codec::Serialize;
        self.validate_owned_private_enrollment_endorsement(endorsement)?;
        if let Some(wrapped) = &endorsement.wrapped {
            return Ok(wrapped.clone());
        }
        let group_id = endorsement.predecessor.group_id.clone();
        let ctx = self.storage.with_read_snapshot(|storage| {
            let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
                &self.crypto,
                storage.mls_storage(),
            );
            self.with_mls_group(&group_id, |mls| {
                crate::group_lifecycle::build_group_context_snapshot(mls, &provider)
            })
        })?;
        if endorsement.ciphertext.is_none() {
            let payload = cgka_traits::app_event::MarmotAppEvent::new(
                hex::encode(self.identity.self_id().as_slice()),
                0,
                ENDORSEMENT_KIND,
                endorsement.metadata_tags.clone().unwrap_or_default(),
                String::from_utf8(endorsement.wire.clone()).map_err(|_| denied())?,
            )
            .encode()
            .map_err(|_| denied())?;
            if payload.len() > 16 * 1024 {
                return Err(denied());
            }
            let encrypted = self.storage.with_transaction(|storage| {
                self.validate_owned_private_enrollment_endorsement(endorsement)?;
                let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
                    &self.crypto,
                    storage.mls_storage(),
                );
                let mut group = MlsGroup::load(
                    provider.storage(),
                    &openmls::group::GroupId::from_slice(group_id.as_slice()),
                )
                .map_err(|_| denied())?
                .ok_or_else(denied)?;
                let cipher = group
                    .create_message(&provider, &self.identity.signer, &payload)
                    .map_err(|_| denied())?
                    .tls_serialize_detached()
                    .map_err(|_| denied())?;
                endorsement.live()?;
                Ok::<_, EngineError>(cipher)
            });
            self.mls_group_cache.forget_group(&group_id);
            endorsement.ciphertext = Some(encrypted?);
        }
        let payload = cgka_traits::EncryptedPayload {
            ciphertext: endorsement.ciphertext.as_ref().ok_or_else(denied)?.clone(),
            aad: vec![],
        };
        let remaining = endorsement
            .deadline
            .saturating_duration_since(Instant::now());
        let mut operation = self.peeler.wrap_group_message(&payload, &ctx);
        let wrapping = std::future::poll_fn(|cx| {
            if let Some(owner) = endorsement.owner.upgrade() {
                owner.register_waker(cx.waker());
            }
            if let Err(error) = endorsement.live() {
                return std::task::Poll::Ready(Err(error));
            }
            operation
                .as_mut()
                .poll(cx)
                .map(|result| result.map_err(EngineError::Peeler))
        });
        let wrapped = crate::deadline::timeout(remaining, wrapping)
            .await
            .map_err(|_| denied())??;
        self.validate_owned_private_enrollment_endorsement(endorsement)?;
        let wrapped = crate::message_processor::route_wrapped_group_message(wrapped, &ctx);
        endorsement.wrapped = Some(wrapped.clone());
        Ok(wrapped)
    }
    pub(crate) fn authenticate_private_enrollment_packet(
        &self,
        artifact: &AuthenticatedPrivatePredecessor,
        binding: &[u8; 32],
        wire: &[u8],
    ) -> Result<(u32, [u8; 32]), EngineError> {
        if binding == &[0; 32] || wire.is_empty() || wire.len() > MAX_PACKET_BYTES {
            return Err(denied());
        }
        let packet: Packet = serde_json::from_slice(wire).map_err(|_| denied())?;
        if !valid_protocol(&packet)
            || packet.binding_digest != *binding
            || packet.signature.len() != 64
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
        Ok((packet.source_index, packet.source_signer))
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
        let mut sharing_devices = Vec::new();
        for wire in endorsements {
            let (index, _) =
                self.authenticate_private_enrollment_packet(artifact, binding, wire)?;
            if !indices.insert(index) {
                return Err(denied());
            }
            let packet: Packet = serde_json::from_slice(wire).map_err(|_| denied())?;
            if packet.share_chats {
                sharing_devices.push(packet.source_signer);
            }
        }
        sharing_devices.sort();
        Ok(AuthenticatedAllLeafEndorsements {
            binding_digest: *binding,
            artifact_digest: *artifact.artifact_digest(),
            leaf_count: indices.len(),
            sharing_devices,
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
        share_chats: false,
        signature: Vec::new(),
    };
    packet.signature = engine
        .identity
        .signer
        .sign(&signing_input(&packet))
        .map_err(|_| denied())?;
    serde_json::to_vec(&packet).map_err(|_| denied())
}

mod existing;
pub use existing::OwnedExistingEnrollmentTransition;
