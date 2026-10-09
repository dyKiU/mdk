//! Private source-authenticated request metadata. These declarations are not
//! validated SDK context/artifact proofs, approval, or enrollment permission.
use crate::Engine;
use cgka_traits::private_roster_settlement::PrivateSettlementState;
use cgka_traits::{EngineError, GroupId, MemberId, MessageId, storage::StorageProvider};
use openmls::group::MlsGroup;
use openmls::prelude::{ProcessedMessage, ProcessedMessageContent, Sender};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
};
use web_time::Instant;

pub(crate) const REQUEST_KIND: u64 = 38175;
pub(crate) const REQUEST_PROTOCOL: &str = "whitenoise.experimental.enrollment-request.v1";
pub(crate) const PROPOSAL_PROTOCOL: &str = "whitenoise.experimental.enrollment-request.v2";
const LIMIT: usize = 128;
const PAYLOAD_LIMIT: usize = 16 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestLeaf {
    leaf_index: u32,
    signature_public_key: [u8; 32],
}
/// Source-authenticated opaque declarations. App must separately decode,
/// canonicalize and authenticate these before any explicit owner action.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestProposal {
    artifact_base64: String,
    context_json: String,
}
impl RequestProposal {
    fn bounded(&self) -> bool {
        !self.artifact_base64.is_empty()
            && !self.context_json.is_empty()
            && self.artifact_base64.len() <= PAYLOAD_LIMIT
            && self.context_json.len() <= PAYLOAD_LIMIT
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestFrame {
    protocol: String,
    account: [u8; 32],
    group_id: Vec<u8>,
    epoch: u64,
    epoch_authenticator_digest: [u8; 32],
    leaves: Vec<RequestLeaf>,
    artifact_digest: [u8; 32],
    context_digest: [u8; 32],
    enrollment_nonce: [u8; 32],
    request_nonce: [u8; 32],
    approver: [u8; 32],
    recipient: [u8; 32],
    approver_generation: u64,
    recipient_generation: u64,
    key_package_reference: Vec<u8>,
    key_package_digest: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proposal: Option<RequestProposal>,
}
/// Source-authenticated declarations with actual private MLS predecessor evidence.
/// No constructor, serialization, cloning, SDK consent, or admission authority.
pub struct AuthenticatedEnrollmentRequest {
    source_index: u32,
    source_signer: [u8; 32],
    message_id: MessageId,
    predecessor: cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster,
    frame: RequestFrame,
    observed_deadline: Instant,
    protected_origin: cgka_traits::private_device_invite::PrivateInviteOrigin,
    settlement_generation: u64,
}
impl AuthenticatedEnrollmentRequest {
    pub(crate) fn matches_protected_selection(
        &self,
        origin: &cgka_traits::private_device_invite::PrivateInviteOrigin,
        generation: u64,
    ) -> bool {
        &self.protected_origin == origin && self.settlement_generation == generation
    }
    /// Canonical request correlation only; no approval or SDK authority.
    pub fn binding_digest(&self) -> Result<[u8; 32], EngineError> {
        request_binding_digest(&self.frame)
    }
    /// Original bounded observation lifetime, never SDK enrollment consent.
    pub fn observed_deadline(&self) -> Instant {
        self.observed_deadline
    }
    pub fn source_index(&self) -> u32 {
        self.source_index
    }
    pub fn source_signer(&self) -> &[u8; 32] {
        &self.source_signer
    }
    pub fn account(&self) -> &[u8; 32] {
        &self.frame.account
    }
    pub fn group_id(&self) -> &[u8] {
        &self.frame.group_id
    }
    pub fn predecessor(
        &self,
    ) -> &cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster {
        &self.predecessor
    }
    pub fn artifact_digest(&self) -> &[u8; 32] {
        &self.frame.artifact_digest
    }
    pub fn context_digest(&self) -> &[u8; 32] {
        &self.frame.context_digest
    }
    pub fn enrollment_nonce(&self) -> &[u8; 32] {
        &self.frame.enrollment_nonce
    }
    /// Correlation metadata only, never a second enrollment authority nonce.
    pub fn request_nonce(&self) -> &[u8; 32] {
        &self.frame.request_nonce
    }
    pub fn recipient(&self) -> &[u8; 32] {
        &self.frame.recipient
    }
    pub fn approver_generation(&self) -> u64 {
        self.frame.approver_generation
    }
    pub fn recipient_generation(&self) -> u64 {
        self.frame.recipient_generation
    }
    pub fn key_package_reference(&self) -> &[u8] {
        &self.frame.key_package_reference
    }
    pub fn key_package_digest(&self) -> &[u8; 32] {
        &self.frame.key_package_digest
    }
    /// Bounded received proposal declarations only, never approval permission.
    /// App must validate canonical encoding, exact context and portable artifact.
    /// Version 1 always supplies no parts. The original intake clock is unchanged.
    pub fn proposal_parts(&self) -> Option<(&str, &str)> {
        self.frame.proposal.as_ref().map(|proposal| {
            (
                proposal.artifact_base64.as_str(),
                proposal.context_json.as_str(),
            )
        })
    }
    pub fn message_id(&self) -> &MessageId {
        &self.message_id
    }
}
/// In-process acquisition metadata, never SDK permission or persisted state.
pub(crate) struct LiveEnrollmentDelivery {
    pub(crate) id: MessageId,
    pub(crate) deadline: Instant,
}

struct Delivery {
    group: GroupId,
    state: PrivateSettlementState,
    deadline: Instant,
    content_id: Option<MessageId>,
}
#[derive(Default)]
struct IntakeState {
    deliveries: HashMap<MessageId, Delivery>,
}
#[derive(Default)]
pub(crate) struct EnrollmentIntake {
    state: Mutex<IntakeState>,
    observations: Mutex<VecDeque<AuthenticatedEnrollmentRequest>>,
}
pub(crate) struct EnrollmentEffect {
    pub(crate) message_id: MessageId,
    delivery_id: Option<MessageId>,
    generation: u64,
    observation: Option<AuthenticatedEnrollmentRequest>,
}
fn unavailable() -> EngineError {
    EngineError::Backend("private enrollment metadata intake unavailable".into())
}
impl EnrollmentIntake {
    /// Negative-only intersection before durable dedup can return early.
    pub(crate) fn shorten_existing_deadline(
        &self,
        id: &MessageId,
        deadline: Instant,
    ) -> Result<(), EngineError> {
        let mut slot = self.state.lock().map_err(|_| unavailable())?;
        let Some(existing) = slot.deliveries.get_mut(id) else {
            return Ok(());
        };
        existing.deadline = existing.deadline.min(deadline);
        let content = existing.content_id.clone();
        let group = existing.group.clone();
        let state = existing.state.clone();
        let earliest = existing.deadline;
        if let Some(content) = content {
            for delivery in slot.deliveries.values_mut().filter(|d| {
                d.content_id.as_ref() == Some(&content)
                    && d.group == group
                    && d.state.generation == state.generation
                    && d.state.anchor == state.anchor
            }) {
                delivery.deadline = delivery.deadline.min(earliest);
            }
        }
        Ok(())
    }

    pub(crate) fn admit<S: StorageProvider>(
        &self,
        storage: &S,
        id: &MessageId,
        group: &GroupId,
        state: PrivateSettlementState,
        acquisition_deadline: Instant,
    ) -> Result<(), EngineError> {
        let mut slot = self.state.lock().map_err(|_| unavailable())?;
        // An obsolete protected generation can never become current again.
        slot.deliveries.retain(|_, d| {
            d.state.generation == state.generation && d.state.anchor == state.anchor
        });
        let mut retired = Vec::new();
        for (id, d) in &slot.deliveries {
            if Instant::now() >= d.deadline {
                // Created/retryable content is not terminal: it may still be
                // replayed with this exact original ephemeral identity. Keep its
                // expired clock to prevent a fresh wrapper renewing that work.
                let durable = match storage.get_message(d.content_id.as_ref().unwrap_or(id)) {
                    Ok(row) => matches!(
                        row.state,
                        cgka_traits::message::MessageState::Processed
                            | cgka_traits::message::MessageState::Failed
                            | cgka_traits::message::MessageState::EpochInvalidated
                    ),
                    Err(cgka_traits::StorageError::NotFound) => {
                        storage.has_processed_transport_id(id)?
                            || storage.has_ingress_dedup_marker(id)?
                    }
                    Err(e) => return Err(e.into()),
                };
                if durable {
                    retired.push(id.clone());
                }
            }
        }
        for id in retired {
            slot.deliveries.remove(&id);
        }
        let deadline = acquisition_deadline.min(Instant::now() + Duration::from_secs(600));
        if let Some(existing) = slot.deliveries.get_mut(id) {
            if existing.group != *group
                || existing.state.generation != state.generation
                || existing.state.anchor != state.anchor
            {
                return Err(unavailable());
            }
            existing.deadline = existing.deadline.min(deadline);
            return Ok(());
        }
        if slot.deliveries.len() >= LIMIT {
            return Err(EngineError::PrivateEnrollmentIntakeAtCapacity);
        }
        slot.deliveries.insert(
            id.clone(),
            Delivery {
                group: group.clone(),
                state,
                deadline,
                content_id: None,
            },
        );
        Ok(())
    }
    // Test-only clock adjustment of an existing genuine admitted delivery.
    // This cannot create an identity, proof, or admission.
    #[cfg(test)]
    pub(crate) fn expire_existing_delivery_for_test(&self, raw: &MessageId) {
        let mut slot = self.state.lock().unwrap();
        let delivery = slot
            .deliveries
            .get_mut(raw)
            .expect("existing live delivery");
        delivery.deadline = Instant::now() - Duration::from_secs(1);
    }

    #[cfg(test)]
    pub(crate) fn existing_delivery_deadline_for_test(
        &self,
        raw: &MessageId,
    ) -> Option<(Instant, Option<MessageId>)> {
        self.state
            .lock()
            .unwrap()
            .deliveries
            .get(raw)
            .map(|d| (d.deadline, d.content_id.clone()))
    }

    pub(crate) fn reserve(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, VecDeque<AuthenticatedEnrollmentRequest>>, EngineError>
    {
        self.observations.lock().map_err(|_| unavailable())
    }
    pub(crate) fn check_capacity(
        reservation: &VecDeque<AuthenticatedEnrollmentRequest>,
        effects: &[EnrollmentEffect],
    ) -> Result<(), EngineError> {
        if reservation
            .len()
            .checked_add(effects.iter().filter(|e| e.observation.is_some()).count())
            .is_none_or(|n| n > LIMIT)
        {
            return Err(EngineError::PrivateEnrollmentIntakeAtCapacity);
        }
        Ok(())
    }
    pub(crate) fn bind(&self, raw: &MessageId, content: &MessageId) -> Result<(), EngineError> {
        let mut slot = self.state.lock().map_err(|_| unavailable())?;
        let Some(delivery) = slot.deliveries.get(raw) else {
            return Ok(());
        };
        if delivery
            .content_id
            .as_ref()
            .is_some_and(|existing| existing != content)
        {
            return Err(unavailable());
        }
        // Transport wrappers cannot create a new observation clock for the
        // same decrypted MLS request. Correlation remains exact owner/group/
        // protected-generation metadata, never admission reconstructed from SQL.
        let mut earliest = delivery.deadline;
        for bound in slot
            .deliveries
            .values()
            .filter(|d| d.content_id.as_ref() == Some(content))
        {
            if bound.group != delivery.group
                || bound.state.generation != delivery.state.generation
                || bound.state.anchor != delivery.state.anchor
            {
                return Err(unavailable());
            }
            earliest = earliest.min(bound.deadline);
        }
        slot.deliveries
            .get_mut(raw)
            .expect("existing delivery under same lock")
            .content_id = Some(content.clone());
        for bound in slot
            .deliveries
            .values_mut()
            .filter(|d| d.content_id.as_ref() == Some(content))
        {
            bound.deadline = earliest;
        }
        Ok(())
    }
    pub(crate) fn classify_nonrequest(&self, content: &MessageId) -> Result<(), EngineError> {
        self.state
            .lock()
            .map_err(|_| unavailable())?
            .deliveries
            .retain(|_, d| d.content_id.as_ref() != Some(content));
        Ok(())
    }
    /// Infallible publication under the queue guard reserved before SQL.
    /// A poisoned delivery map is cleared negatively; it cannot lose committed
    /// observations or reconstruct any future live-delivery identity.
    pub(crate) fn finish(
        &self,
        reservation: &mut VecDeque<AuthenticatedEnrollmentRequest>,
        effects: Vec<EnrollmentEffect>,
    ) {
        let mut slot = match self.state.lock() {
            Ok(slot) => slot,
            Err(poisoned) => {
                let mut slot = poisoned.into_inner();
                slot.deliveries.clear();
                slot
            }
        };
        for effect in effects {
            if let Some(id) = effect.delivery_id {
                slot.deliveries.remove(&id);
            }
            if let Some(observation) = effect.observation {
                reservation.push_back(observation);
            }
        }
    }
    pub(crate) fn validate_tail<S: StorageProvider>(
        &self,
        storage: &S,
        group: &GroupId,
        effects: &mut [EnrollmentEffect],
    ) -> Result<(), EngineError> {
        let slot = self.state.lock().map_err(|_| unavailable())?;
        let positive = effects.iter().filter(|e| e.observation.is_some()).count();
        if positive == 0 {
            return Ok(());
        }
        let actual = MlsGroup::load(
            storage.mls_storage(),
            &openmls::group::GroupId::from_slice(group.as_slice()),
        )
        .map_err(|_| unavailable())?;
        let state = match actual {
            Some(actual) => {
                crate::private_roster_settlement::completed_round_for_tree(storage, group, &actual)?
            }
            None => None,
        };
        for effect in effects.iter_mut().filter(|e| e.observation.is_some()) {
            let valid = state.as_ref().is_some_and(|state| {
                effect
                    .delivery_id
                    .as_ref()
                    .and_then(|id| slot.deliveries.get(id))
                    .is_some_and(|delivery| {
                        Instant::now() < delivery.deadline
                            && delivery.group == *group
                            && delivery.state.anchor == state.anchor
                            && state.generation == effect.generation
                            && delivery.state.generation == state.generation
                    })
            });
            if !valid {
                effect.observation = None;
            }
        }
        Ok(())
    }
}
/// Called only at actual ProcessedMessage processing; probes never supply intake.
pub(crate) struct SealedEnrollmentSource {
    delivery_id: MessageId,
    generation: u64,
    index: u32,
    signer: [u8; 32],
    state: PrivateSettlementState,
    observed_deadline: Instant,
}
pub(crate) fn seal<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    processed: &ProcessedMessage,
    group: &MlsGroup,
    intake: Option<&EnrollmentIntake>,
    message_id: &MessageId,
) -> Result<Option<SealedEnrollmentSource>, EngineError> {
    let Some(intake) = intake else {
        return Ok(None);
    };
    if group.pending_commit().is_some()
        || processed.epoch() != group.epoch()
        || !matches!(
            processed.content(),
            ProcessedMessageContent::ApplicationMessage(_)
        )
    {
        return Ok(None);
    }
    let Some(state) =
        crate::private_roster_settlement::completed_round_for_tree(storage, group_id, group)?
    else {
        return Ok(None);
    };
    if state.anchor.successor.epoch.0 < 1 || state.anchor.successor.leaves.len() < 2 {
        return Ok(None);
    }
    let Sender::Member(index) = processed.sender() else {
        return Ok(None);
    };
    let Some(member) = group.member_at(*index) else {
        return Ok(None);
    };
    let account = crate::identity::validated_member_id(processed.credential())?;
    if account.as_slice() != state.anchor.account
        || crate::identity::validated_member_id(&member.credential)? != account
    {
        return Ok(None);
    }
    let Ok(signer) = member.signature_key.as_slice().try_into() else {
        return Ok(None);
    };
    let slot = intake.state.lock().map_err(|_| unavailable())?;
    let Some((id, d)) = slot
        .deliveries
        .iter()
        .find(|(_, d)| d.content_id.as_ref() == Some(message_id))
    else {
        return Ok(None);
    };
    if d.group != *group_id
        || d.state.generation != state.generation
        || d.state.anchor != state.anchor
        || Instant::now() >= d.deadline
    {
        return Ok(None);
    }
    Ok(Some(SealedEnrollmentSource {
        delivery_id: id.clone(),
        generation: state.generation,
        index: index.u32(),
        signer,
        state,
        observed_deadline: d.deadline,
    }))
}
pub(crate) fn is_request_payload(payload: &[u8], sender: Option<&MemberId>) -> bool {
    let Some(sender) = sender else { return false };
    if let Ok(event) = crate::app_payload::validate_app_payload_for_sender(payload, sender)
        && event.kind == REQUEST_KIND
    {
        return true;
    }
    {
        #[derive(Deserialize)]
        struct Hint {
            protocol: Option<String>,
        }
        crate::app_payload::validate_app_payload_for_sender(payload, sender)
            .ok()
            .is_some_and(|event| {
                serde_json::from_str::<Hint>(&event.content)
                    .is_ok_and(|hint| hint.protocol.as_deref() == Some(REQUEST_PROTOCOL))
            })
    }
}
pub(crate) fn stage(
    sealed: Option<SealedEnrollmentSource>,
    payload: &[u8],
    sender: Option<&MemberId>,
    message_id: &MessageId,
) -> EnrollmentEffect {
    let mut effect = EnrollmentEffect {
        message_id: message_id.clone(),
        delivery_id: None,
        generation: 0,
        observation: None,
    };
    let Some(SealedEnrollmentSource {
        delivery_id,
        generation,
        index,
        signer,
        state,
        observed_deadline,
    }) = sealed
    else {
        return effect;
    };
    effect.delivery_id = Some(delivery_id);
    effect.generation = generation;
    if payload.len() > PAYLOAD_LIMIT {
        return effect;
    }
    let Some(sender) = sender else { return effect };
    let Ok(event) = crate::app_payload::validate_app_payload_for_sender(payload, sender) else {
        return effect;
    };
    if event.kind != REQUEST_KIND {
        return effect;
    }
    let Ok(frame) = serde_json::from_str::<RequestFrame>(&event.content) else {
        return effect;
    };
    let tree = &state.anchor.successor;
    let valid_protocol = match (frame.protocol.as_str(), frame.proposal.as_ref()) {
        (REQUEST_PROTOCOL, None) => true,
        (PROPOSAL_PROTOCOL, Some(proposal)) => proposal.bounded(),
        _ => false,
    };
    if !valid_protocol
        || frame.account != state.anchor.account
        || frame.group_id != state.anchor.group_id.as_slice()
        || frame.group_id.is_empty()
        || frame.group_id.len() > 1024
        || frame.epoch != tree.epoch.0
        || frame.epoch_authenticator_digest != tree.epoch_authenticator_digest
        || frame.leaves.len() != tree.leaves.len()
        || !frame.leaves.iter().zip(&tree.leaves).all(|(a, b)| {
            a.leaf_index == b.leaf_index && a.signature_public_key == b.signature_public_key
        })
        || frame.approver != signer
        || frame.recipient == [0; 32]
        || tree
            .leaves
            .iter()
            .any(|l| l.signature_public_key == frame.recipient)
        || frame.artifact_digest == [0; 32]
        || frame.context_digest == [0; 32]
        || frame.enrollment_nonce == [0; 32]
        || frame.request_nonce == [0; 32]
        || frame.key_package_digest == [0; 32]
        || frame.approver_generation == 0
        || frame.approver_generation > i64::MAX as u64
        || frame.recipient_generation > i64::MAX as u64
        || frame.recipient_generation == 0
        || frame.key_package_reference.is_empty()
        || frame.key_package_reference.len() > 128
    {
        return effect;
    }
    effect.observation = Some(AuthenticatedEnrollmentRequest {
        source_index: index,
        source_signer: signer,
        message_id: message_id.clone(),
        predecessor: tree.clone(),
        protected_origin: state.anchor.origin.clone(),
        settlement_generation: generation,
        frame,
        observed_deadline,
    });
    effect
}
impl<S: StorageProvider + 'static> Engine<S> {
    /// Real newly delivered encrypted input through the same audited ingest
    /// pipeline. The account owner must never call this for history acquisition
    /// or reconstructed rows. This enables observation, never permission.
    pub async fn ingest_private_enrollment_delivery(
        &mut self,
        message: cgka_traits::TransportMessage,
    ) -> Result<cgka_traits::IngestOutcome, EngineError> {
        self.ingest_private_enrollment_delivery_with_audit_context_until(
            message,
            None,
            Instant::now() + Duration::from_secs(600),
        )
        .await
    }

    /// Limit live observation by its original acquisition clock; no permission.
    pub async fn ingest_private_enrollment_delivery_until(
        &mut self,
        message: cgka_traits::TransportMessage,
        deadline: Instant,
    ) -> Result<cgka_traits::IngestOutcome, EngineError> {
        self.ingest_private_enrollment_delivery_with_audit_context_until(message, None, deadline)
            .await
    }

    /// Acquisition deadline is metadata only, cannot extend an existing clock,
    /// and must originate from the caller's actual in-process live receipt.
    pub async fn ingest_private_enrollment_delivery_with_audit_context_until(
        &mut self,
        message: cgka_traits::TransportMessage,
        transport_context: Option<marmot_forensics::AuditTransportContext>,
        acquisition_deadline: Instant,
    ) -> Result<cgka_traits::IngestOutcome, EngineError> {
        let origin = LiveEnrollmentDelivery {
            id: message.id.clone(),
            deadline: acquisition_deadline.min(Instant::now() + Duration::from_secs(600)),
        };
        self.ingest_with_delivery_origin(message, transport_context, Some(origin))
            .await
    }

    pub fn drain_authenticated_enrollment_requests(
        &mut self,
    ) -> Result<Vec<AuthenticatedEnrollmentRequest>, EngineError> {
        Ok(self
            .enrollment_intake
            .observations
            .lock()
            .map_err(|_| unavailable())?
            .drain(..)
            .collect())
    }
}

mod producer;
pub use producer::OwnedLocalEnrollmentProposal;

fn request_binding_digest(frame: &RequestFrame) -> Result<[u8; 32], EngineError> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(frame).map_err(|_| unavailable())?;
    let mut hash = Sha256::new();
    let domain: &[u8] = match frame.protocol.as_str() {
        REQUEST_PROTOCOL => b"whitenoise-private-enrollment-request-binding-v1\0",
        PROPOSAL_PROTOCOL => b"whitenoise-private-enrollment-request-binding-v2\0",
        _ => return Err(unavailable()),
    };
    hash.update(domain);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    Ok(hash.finalize().into())
}
