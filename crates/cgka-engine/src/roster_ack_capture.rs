//! Private experimental fact capture. No approved-roster anchor or grants.
use crate::{Engine, device_group_snapshot::CandidateDeviceGroupSnapshot};
use cgka_traits::engine::SendResult;
use cgka_traits::error::EngineError;
use cgka_traits::roster_ack_capture::{
    RosterAckCaptureFact, RosterAckCaptureLeaf, RosterAckCaptureState, RosterAckCaptureStorage,
};
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::GroupId;
use rand::RngCore;
use serde::{Deserialize, Serialize};

// Private transport framing, not a normative Marmot identifier/profile.
pub(crate) const PRIVATE_KIND: u64 = 38_173;
pub(crate) const PRIVATE_PROTOCOL: &str = "whitenoise.experimental.roster-capture.v1";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureFrame {
    pub protocol: String,
    pub phase: String,
    pub round_nonce: [u8; 32],
    pub roster_commitment: [u8; 32],
    pub epoch: u64,
}
fn refused() -> EngineError {
    EngineError::InvalidTransition(cgka_traits::engine_state::InvalidTransition {
        from: "LocalDeviceScope",
        to: "RosterCapture",
        reason: "roster capture scope unavailable",
    })
}
impl<S: StorageProvider> Engine<S> {
    pub(crate) fn capture_store(&self) -> Result<&dyn RosterAckCaptureStorage, EngineError> {
        self.storage
            .roster_ack_capture_storage()
            .ok_or_else(refused)
    }
    fn capture_candidate(
        &self,
        group: &GroupId,
    ) -> Result<CandidateDeviceGroupSnapshot, EngineError> {
        self.candidate_device_group_snapshot(group)?
            .ok_or_else(refused)
    }
    fn scope_from_candidate(
        &self,
        candidate: CandidateDeviceGroupSnapshot,
        nonce: Option<[u8; 32]>,
    ) -> RosterAckCaptureState {
        RosterAckCaptureState {
            format_version: 1,
            generation: 1,
            invalidated: false,
            account: candidate.account,
            local_device: self.identity.signer.public().to_vec(),
            group_id: candidate.group_id,
            epoch: candidate.epoch,
            epoch_authenticator_digest: candidate.epoch_authenticator_digest,
            roster_commitment: candidate.roster_commitment,
            leaves: candidate
                .leaves
                .into_iter()
                .map(|leaf| RosterAckCaptureLeaf {
                    leaf_index: leaf.leaf_index,
                    signature_public_key: leaf.signature_public_key,
                })
                .collect(),
            round_nonce: nonce,
            challenge_source: None,
            outbound: None,
            prepared_ciphertext: None,
        }
    }
    /// Explicit local selection only. Unsolicited remote input cannot select it.
    pub fn select_roster_ack_capture(&self, group: &GroupId) -> Result<(), EngineError> {
        let candidate = self.capture_candidate(group)?;
        self.capture_store()?
            .select_capture(&self.scope_from_candidate(candidate, None))?;
        Ok(())
    }
    /// Read-only facts are not settlement, approval, or membership permissions.
    pub fn roster_ack_capture_facts(
        &self,
        group: &GroupId,
    ) -> Result<Vec<RosterAckCaptureFact>, EngineError> {
        let candidate = self.capture_candidate(group)?;
        let store = self.capture_store()?;
        let Some(state) = store.capture_state()? else {
            return Ok(vec![]);
        };
        if state.invalidated
            || !same_tuple(&state, &candidate)
            || state.epoch != candidate.epoch
            || state.epoch_authenticator_digest != candidate.epoch_authenticator_digest
        {
            return Ok(vec![]);
        }
        Ok(store.capture_facts()?)
    }
}
impl<S: StorageProvider + 'static> Engine<S> {
    /// Select one fresh round and prepare a genuine encrypted private challenge.
    /// The current local candidate is not an approved roster. Zero grants result.
    pub async fn start_roster_ack_capture(
        &mut self,
        group: &GroupId,
    ) -> Result<SendResult, EngineError> {
        let candidate = self.capture_candidate(group)?;
        if let Some(state) = self.capture_store()?.capture_state()?
            && !state.invalidated
            && same_tuple(&state, &candidate)
            && state.challenge_source.is_none()
            && state.round_nonce.is_some()
        {
            if let Some(bytes) = state.outbound {
                return serde_json::from_slice(&bytes).map_err(|_| refused());
            }
            return self.capture_publication(state, "challenge").await;
        }
        let mut nonce = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        if nonce == [0; 32] {
            return Err(refused());
        }
        let state = self.scope_from_candidate(candidate, Some(nonce));
        let state = self.capture_store()?.select_capture(&state)?;
        self.capture_publication(state, "challenge").await
    }
    /// Responder must have explicitly selected this scope before crypto ingest.
    pub async fn prepare_roster_ack(&mut self, group: &GroupId) -> Result<SendResult, EngineError> {
        let candidate = self.capture_candidate(group)?;
        let state = self.capture_store()?.capture_state()?.ok_or_else(refused)?;
        if state.invalidated || !same_tuple(&state, &candidate) || state.challenge_source.is_none()
        {
            return Err(refused());
        }
        if let Some(bytes) = &state.outbound {
            return serde_json::from_slice(bytes).map_err(|_| refused());
        }
        self.capture_publication(state, "ack").await
    }
    async fn capture_publication(
        &mut self,
        state: RosterAckCaptureState,
        phase: &str,
    ) -> Result<SendResult, EngineError> {
        use cgka_traits::message::OwnApplicationConvergenceStamp;
        use cgka_traits::peeler::GroupMessageMetadata;
        use cgka_traits::transport::EncryptedPayload;
        use openmls::prelude::MlsMessageOut;
        use sha2::{Digest, Sha256};
        use tls_codec::Serialize as _;
        let candidate = self.capture_candidate(&state.group_id)?;
        if state.invalidated || !same_tuple(&state, &candidate) {
            return Err(refused());
        }
        let frame = CaptureFrame {
            protocol: PRIVATE_PROTOCOL.into(),
            phase: phase.into(),
            round_nonce: state.round_nonce.ok_or_else(refused)?,
            roster_commitment: state.roster_commitment,
            epoch: state.epoch.0,
        };
        let content = serde_json::to_string(&frame).map_err(|_| refused())?;
        let event = cgka_traits::app_event::MarmotAppEvent::new(
            hex::encode(self.identity.self_id().as_slice()),
            0,
            PRIVATE_KIND,
            vec![],
            content,
        );
        let payload = event.encode().map_err(|_| refused())?;
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mut group = self.take_mls_group(&state.group_id)?.ok_or_else(refused)?;
        if group.epoch().as_u64() != state.epoch.0
            || <[u8; 32]>::from(Sha256::digest(group.epoch_authenticator().as_slice()))
                != state.epoch_authenticator_digest
        {
            self.return_unmodified_mls_group(&state.group_id, group);
            return Err(refused());
        }
        let ctx = crate::group_lifecycle::build_group_context_snapshot(&group, &provider)?;
        let retention_seconds = crate::app_components::message_retention_seconds_of_group(&group)?;
        let stamp = OwnApplicationConvergenceStamp {
            sender: self.identity.self_id().clone(),
            source_epoch_authenticator: hex::encode(group.epoch_authenticator().as_slice()),
        };
        let ciphertext = if let Some(bytes) = &state.prepared_ciphertext {
            self.return_unmodified_mls_group(&state.group_id, group);
            bytes.clone()
        } else {
            let bytes = self.storage.with_transaction(|storage| {
                let out: MlsMessageOut = group
                    .create_message(&provider, &self.identity.signer, &payload)
                    .map_err(|_| EngineError::Backend("capture encryption failed".into()))?;
                let bytes = out
                    .tls_serialize_detached()
                    .map_err(|_| EngineError::Serialize("capture encryption failed".into()))?;
                storage
                    .roster_ack_capture_storage()
                    .ok_or_else(refused)?
                    .put_prepared_capture_ciphertext(state.generation, &bytes)?;
                Ok::<_, EngineError>(bytes)
            })?;
            self.return_mls_group(&state.group_id, group);
            bytes
        };
        // Wrapping is async and transport-generic. The committed MLS ciphertext
        // is recovered after a failure/restart; encryption is never repeated.
        let metadata = GroupMessageMetadata::application(event.created_at, retention_seconds);
        let wrapped = self
            .peeler
            .wrap_group_message_with_metadata(
                &EncryptedPayload {
                    ciphertext: ciphertext.clone(),
                    aad: vec![],
                },
                &ctx,
                &metadata,
            )
            .await
            .map_err(EngineError::Peeler)?;
        let candidate = self.capture_candidate(&state.group_id)?;
        if state.invalidated || !same_tuple(&state, &candidate) {
            return Err(refused());
        }
        let wrapped = crate::message_processor::route_wrapped_group_message(wrapped, &ctx);
        let result = SendResult::ApplicationMessage {
            msg: wrapped.clone(),
            group_id: state.group_id.clone(),
            app_event_id: event.id,
            source_epoch: state.epoch,
            retention: cgka_traits::app_event::AppMessageRetentionDecision::new(
                event.created_at,
                retention_seconds.unwrap_or(0),
            ),
            authority: None,
        };
        let bytes = serde_json::to_vec(&result).map_err(|_| refused())?;
        let content_id =
            self.persist_roster_capture_outbound(&wrapped, &ciphertext, &state, stamp, &bytes)?;
        self.sent_message_ids.insert(wrapped.id);
        self.sent_message_ids.insert(content_id);
        Ok(result)
    }
}

// This type has no public constructor, serialization or public proof inlet.
// It can only be minted while the actual authenticated ProcessedMessage and
// its matching live source-epoch tree are held by the crypto receiver.
pub(crate) struct AuthenticatedCaptureSource {
    generation: u64,
    leaf_index: u32,
    signature_public_key: Vec<u8>,
}

/// Receiver-private effects, never serialized or accepted from observations.
pub(crate) struct CaptureEffect {
    source: Option<AuthenticatedCaptureSource>,
    payload: Option<Vec<u8>>,
    sender: Option<cgka_traits::types::MemberId>,
    pub(crate) message_id: cgka_traits::types::MessageId,
}

pub(crate) fn is_capture_payload(
    payload: &[u8],
    sender: Option<&cgka_traits::types::MemberId>,
) -> bool {
    let Some(sender) = sender else {
        return false;
    };
    let Ok(event) = crate::app_payload::validate_app_payload_for_sender(payload, sender) else {
        return false;
    };
    if event.kind == PRIVATE_KIND {
        return true;
    }
    #[derive(Deserialize)]
    struct ProtocolHint {
        protocol: Option<String>,
    }
    serde_json::from_str::<ProtocolHint>(&event.content)
        .is_ok_and(|hint| hint.protocol.as_deref() == Some(PRIVATE_PROTOCOL))
}

pub(crate) fn stage_capture_effect(
    source: Option<AuthenticatedCaptureSource>,
    payload: &[u8],
    sender: Option<&cgka_traits::types::MemberId>,
    message_id: &cgka_traits::types::MessageId,
) -> CaptureEffect {
    CaptureEffect {
        source,
        payload: (payload.len() <= 16384).then(|| payload.to_vec()),
        sender: sender.cloned(),
        message_id: message_id.clone(),
    }
}

/// Apply only after actual selected processing, within its ratchet SQL unit.
pub(crate) fn apply_capture_effect<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    effect: CaptureEffect,
) -> Result<(), EngineError> {
    let Some(store) = storage.roster_ack_capture_storage() else {
        return Ok(());
    };
    let Some(state) = store.capture_state()? else {
        return Ok(());
    };
    let record = storage.get_group(group_id)?;
    if state.invalidated
        || state.group_id != *group_id
        || record.removed
        || record.unrecoverable
        || record.disbanded.is_some()
        || record.protocol_profile != cgka_traits::group::ProtocolProfile::Current
        || record.epoch != state.epoch
    {
        return Ok(());
    }
    let Some(group) = openmls::group::MlsGroup::load(
        storage.mls_storage(),
        &openmls::group::GroupId::from_slice(group_id.as_slice()),
    )
    .map_err(|_| refused())?
    else {
        return Ok(());
    };
    use sha2::{Digest, Sha256};
    if !group.is_active()
        || group.pending_commit().is_some()
        || group.epoch().as_u64() != state.epoch.0
        || <[u8; 32]>::from(Sha256::digest(group.epoch_authenticator().as_slice()))
            != state.epoch_authenticator_digest
        || crate::account_identity_proof::protocol_profile_of_group(&group)?
            != cgka_traits::group::ProtocolProfile::Current
    {
        return Ok(());
    }
    if let Some(payload) = effect.payload {
        apply_capture_payload(
            storage,
            effect.source,
            &payload,
            effect.sender.as_ref(),
            &effect.message_id,
        )?;
    }
    Ok(())
}
impl<S: StorageProvider> Engine<S> {
    pub(crate) fn authenticated_capture_source(
        &self,
        processed: &openmls::prelude::ProcessedMessage,
        group: &openmls::group::MlsGroup,
        group_id: &GroupId,
    ) -> Result<Option<AuthenticatedCaptureSource>, EngineError> {
        let locally_stable = matches!(self.epoch_manager.state(group_id), Some(cgka_traits::engine_state::EpochState::Stable { epoch }) if epoch.0 == group.epoch().as_u64());
        let record = self.storage.get_group(group_id)?;
        if !locally_stable
            || self.pending_convergence_groups.contains(group_id)
            || record.protocol_profile != cgka_traits::group::ProtocolProfile::Current
            || record.epoch.0 != group.epoch().as_u64()
            || record.removed
            || record.unrecoverable
            || record.disbanded.is_some()
            || self
                .storage
                .convergence_pass(group_id)?
                .is_some_and(|pass| pass.is_active())
            || !self
                .storage
                .list_queued_outbound_intents(group_id)?
                .is_empty()
        {
            return Ok(None);
        }
        capture_source_of_processed_message(&self.storage, processed, group, group_id)
    }
    /// Only the crypto ingress calls this with its sealed source. A recognized
    /// private frame is consumed even when invalid, never emitted as app evidence.
    pub(crate) fn capture_authenticated_payload(
        &self,
        source: Option<AuthenticatedCaptureSource>,
        payload: &[u8],
        sender: Option<&cgka_traits::types::MemberId>,
        message_id: &cgka_traits::types::MessageId,
    ) -> Result<Option<bool>, EngineError> {
        apply_capture_payload(&self.storage, source, payload, sender, message_id)
    }
}

/// Pure cryptographic seal, never grants and never accepts public metadata.
pub(crate) fn capture_source_of_processed_message<S: StorageProvider>(
    storage: &S,
    processed: &openmls::prelude::ProcessedMessage,
    group: &openmls::group::MlsGroup,
    group_id: &GroupId,
) -> Result<Option<AuthenticatedCaptureSource>, EngineError> {
    use openmls::prelude::ProcessedMessageContent;
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;
    if !matches!(
        processed.content(),
        ProcessedMessageContent::ApplicationMessage(_)
    ) || processed.epoch() != group.epoch()
        || !group.is_active()
        || group.pending_commit().is_some()
        || crate::account_identity_proof::protocol_profile_of_group(group)?
            != cgka_traits::group::ProtocolProfile::Current
    {
        return Ok(None);
    }
    let Some(store) = storage.roster_ack_capture_storage() else {
        return Ok(None);
    };
    let Some(state) = store.capture_state()? else {
        return Ok(None);
    };
    if state.invalidated
        || state.group_id != *group_id
        || state.epoch.0 != group.epoch().as_u64()
        || crate::identity::validated_member_id(
            &group
                .own_leaf_node()
                .ok_or_else(refused)?
                .credential()
                .clone(),
        )? != state.account
        || state.local_device
            != group
                .own_leaf_node()
                .ok_or_else(refused)?
                .signature_key()
                .as_slice()
    {
        return Ok(None);
    }
    let openmls::prelude::Sender::Member(index) = processed.sender() else {
        return Ok(None);
    };
    let Some(member) = group.member_at(*index) else {
        return Ok(None);
    };
    if crate::identity::validated_member_id(processed.credential())? != state.account
        || crate::identity::validated_member_id(&member.credential)? != state.account
    {
        return Ok(None);
    }
    let mut keys = HashSet::new();
    let mut leaves = Vec::new();
    for leaf in group.members() {
        if leaves.len() == 128
            || leaf.signature_key.len() != 32
            || !keys.insert(leaf.signature_key.clone())
            || crate::identity::validated_member_id(&leaf.credential)? != state.account
        {
            return Ok(None);
        }
        leaves.push(crate::device_group_snapshot::CandidateDeviceLeaf {
            leaf_index: leaf.index.u32(),
            signature_public_key: leaf.signature_key,
        });
    }
    leaves.sort_unstable_by_key(|v| v.leaf_index);
    let snapshot = CandidateDeviceGroupSnapshot {
        account: state.account.clone(),
        group_id: group_id.clone(),
        epoch: state.epoch,
        epoch_authenticator_digest: Sha256::digest(group.epoch_authenticator().as_slice()).into(),
        leaves,
        roster_commitment: [0; 32],
    };
    if state.epoch_authenticator_digest != snapshot.epoch_authenticator_digest
        || state.roster_commitment != crate::device_group_snapshot::commitment(&snapshot)
        || !state
            .leaves
            .iter()
            .any(|v| v.leaf_index == index.u32() && v.signature_public_key == member.signature_key)
    {
        return Ok(None);
    }
    Ok(Some(AuthenticatedCaptureSource {
        generation: state.generation,
        leaf_index: index.u32(),
        signature_public_key: member.signature_key,
    }))
}

fn apply_capture_payload<S: StorageProvider>(
    storage: &S,
    source: Option<AuthenticatedCaptureSource>,
    payload: &[u8],
    sender: Option<&cgka_traits::types::MemberId>,
    message_id: &cgka_traits::types::MessageId,
) -> Result<Option<bool>, EngineError> {
    let Some(sender) = sender else {
        return Ok(None);
    };
    let Ok(event) = crate::app_payload::validate_app_payload_for_sender(payload, sender) else {
        return Ok(None);
    };
    // Classification alone never authenticates a frame. A private protocol
    // body hidden under an ordinary app kind must not reach chat/history.
    #[derive(Deserialize)]
    struct ProtocolHint {
        protocol: Option<String>,
    }
    let private_body = serde_json::from_str::<ProtocolHint>(&event.content)
        .is_ok_and(|hint| hint.protocol.as_deref() == Some(PRIVATE_PROTOCOL));
    if event.kind != PRIVATE_KIND {
        return Ok(private_body.then_some(false));
    }
    if event.content.len() > 4096 {
        return Ok(Some(false));
    }
    let Ok(frame) = serde_json::from_str::<CaptureFrame>(&event.content) else {
        return Ok(Some(false));
    };
    if frame.protocol != PRIVATE_PROTOCOL || frame.round_nonce == [0; 32] {
        return Ok(Some(false));
    }
    let Some(source) = source else {
        return Ok(Some(false));
    };
    let store = storage.roster_ack_capture_storage().ok_or_else(refused)?;
    let Some(state) = store.capture_state()? else {
        return Ok(Some(false));
    };
    if state.invalidated
        || state.generation != source.generation
        || state.roster_commitment != frame.roster_commitment
        || state.epoch.0 != frame.epoch
    {
        return Ok(Some(false));
    }
    match frame.phase.as_str() {
        "challenge" => {
            if state.round_nonce.is_some()
                && (state.round_nonce != Some(frame.round_nonce)
                    || state.challenge_source != Some(source.leaf_index))
            {
                return Ok(Some(false));
            }
            store.accept_capture_challenge(
                source.generation,
                frame.round_nonce,
                source.leaf_index,
            )?;
        }
        "ack" => {
            if state.round_nonce != Some(frame.round_nonce) || state.challenge_source.is_some() {
                return Ok(Some(false));
            }
            store.put_capture_fact(&RosterAckCaptureFact {
                format_version: 1,
                generation: source.generation,
                leaf_index: source.leaf_index,
                signature_public_key: source.signature_public_key,
                message_id: message_id.clone(),
            })?;
        }
        _ => return Ok(Some(false)),
    }
    Ok(Some(true))
}

fn same_tuple(state: &RosterAckCaptureState, candidate: &CandidateDeviceGroupSnapshot) -> bool {
    state.account == candidate.account
        && state.group_id == candidate.group_id
        && state.epoch == candidate.epoch
        && state.epoch_authenticator_digest == candidate.epoch_authenticator_digest
        && state.roster_commitment == candidate.roster_commitment
        && state.leaves.len() == candidate.leaves.len()
        && state.leaves.iter().zip(&candidate.leaves).all(|(a, b)| {
            a.leaf_index == b.leaf_index && a.signature_public_key == b.signature_public_key
        })
}

/// A denial fact from an actual adopted MLS tree, called only in its SQL unit.
/// Temporary probes must never invoke this function.
pub(crate) fn invalidate_capture_for_tree<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    group: &openmls::group::MlsGroup,
) -> Result<(), EngineError> {
    use sha2::{Digest, Sha256};
    crate::device_group_genesis::deny_changed_birth_for_tree(storage, group_id, group)?;
    let Some(store) = storage.roster_ack_capture_storage() else {
        return Ok(());
    };
    let Some(state) = store.capture_state()? else {
        return Ok(());
    };
    if state.group_id != *group_id || state.invalidated {
        return Ok(());
    }
    let digest: [u8; 32] = Sha256::digest(group.epoch_authenticator().as_slice()).into();
    if !group.is_active()
        || group.epoch().as_u64() != state.epoch.0
        || digest != state.epoch_authenticator_digest
        || crate::account_identity_proof::protocol_profile_of_group(group)?
            != cgka_traits::group::ProtocolProfile::Current
    {
        store.invalidate_capture(state.generation)?;
    }
    Ok(())
}
