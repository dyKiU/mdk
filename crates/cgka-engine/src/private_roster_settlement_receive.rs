//! Private crypto-sealed settlement intake. Public source metadata never enters.
use crate::private_roster_settlement::{LiveSettlementAdmission, SettlementFrame, SettlementPhase};
use crate::private_roster_settlement::{
    PRIVATE_SETTLEMENT_KIND as PRIVATE_KIND, PRIVATE_SETTLEMENT_PROTOCOL as PRIVATE_PROTOCOL,
};
use cgka_traits::private_roster_settlement::{PrivateSettlementFact, PrivateSettlementPhase};
use cgka_traits::{EngineError, GroupId, MemberId, MessageId, storage::StorageProvider};
use openmls::prelude::{MlsGroup, ProcessedMessage, ProcessedMessageContent, Sender};
use std::sync::Arc;
pub(crate) struct SealedSettlementSource {
    leaf_index: u32,
    signer: [u8; 32],
}
pub(crate) struct SettlementEffect {
    source: Option<SealedSettlementSource>,
    admission: Option<Arc<LiveSettlementAdmission>>,
    frame: Option<SettlementFrame>,
    pub(crate) message_id: MessageId,
}
fn refused() -> EngineError {
    EngineError::Other("private settlement admission expired".into())
}
pub(crate) fn ensure_live(
    admission: Option<&Arc<LiveSettlementAdmission>>,
    positive: bool,
) -> Result<(), EngineError> {
    if positive && !admission.is_some_and(|a| a.is_live()) {
        return Err(refused());
    }
    Ok(())
}
pub(crate) fn is_settlement_payload(payload: &[u8], sender: Option<&MemberId>) -> bool {
    let Some(sender) = sender else {
        return false;
    };
    let Ok(event) = crate::app_payload::validate_app_payload_for_sender(payload, sender) else {
        return false;
    };
    if event.kind == PRIVATE_KIND {
        return true;
    }
    #[derive(serde::Deserialize)]
    struct Hint {
        protocol: Option<String>,
    }
    serde_json::from_str::<Hint>(&event.content)
        .is_ok_and(|v| v.protocol.as_deref() == Some(PRIVATE_PROTOCOL))
}
pub(crate) fn seal_settlement_source<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    processed: &ProcessedMessage,
    group: &MlsGroup,
    admission: Option<&Arc<LiveSettlementAdmission>>,
) -> Result<Option<SealedSettlementSource>, EngineError> {
    let mut source = None;
    if let Some(live) = admission
        && live.is_live()
        && group.pending_commit().is_none()
        && processed.epoch() == group.epoch()
        && matches!(
            processed.content(),
            ProcessedMessageContent::ApplicationMessage(_)
        )
        && crate::private_successor::anchor_matches_actual_tree(
            storage,
            group_id,
            group,
            &live.anchor,
        )?
        && let Sender::Member(index) = processed.sender()
        && let Some(member) = group.member_at(*index)
        && crate::identity::validated_member_id(processed.credential())?.as_slice()
            == live.anchor.account
        && crate::identity::validated_member_id(&member.credential)?.as_slice()
            == live.anchor.account
        && let Ok(signer) = member.signature_key.as_slice().try_into()
        && live
            .anchor
            .successor
            .leaves
            .iter()
            .any(|leaf| leaf.leaf_index == index.u32() && leaf.signature_public_key == signer)
    {
        source = Some(SealedSettlementSource {
            leaf_index: index.u32(),
            signer,
        });
    }
    Ok(source)
}
pub(crate) fn stage_settlement_effect(
    source: Option<SealedSettlementSource>,
    admission: Option<&Arc<LiveSettlementAdmission>>,
    payload: &[u8],
    sender: Option<&MemberId>,
    message_id: &MessageId,
) -> SettlementEffect {
    let frame = (payload.len() <= 16 * 1024)
        .then_some(sender)
        .flatten()
        .and_then(|s| crate::app_payload::validate_app_payload_for_sender(payload, s).ok())
        .filter(|event| event.kind == PRIVATE_KIND && event.content.len() <= 4096)
        .and_then(|event| serde_json::from_str::<SettlementFrame>(&event.content).ok())
        .filter(|frame| frame.protocol == PRIVATE_PROTOCOL && frame.round_nonce != [0; 32]);
    SettlementEffect {
        source,
        admission: admission.cloned(),
        frame,
        message_id: message_id.clone(),
    }
}

pub(crate) fn apply_settlement_effect<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    effect: SettlementEffect,
) -> Result<bool, EngineError> {
    let (Some(source), Some(live), Some(frame)) = (effect.source, effect.admission, effect.frame)
    else {
        return Ok(false);
    };
    if !live.is_live() {
        return Ok(false);
    }
    let Some(store) = storage.private_roster_settlement_storage() else {
        return Ok(false);
    };
    let Some(round) = store.read_round()? else {
        return Ok(false);
    };
    if round.generation != live.generation
        || round.anchor != live.anchor
        || round.phase == PrivateSettlementPhase::Denied
        || round.anchor.group_id != *group_id
        || frame.roster_commitment != round.anchor.roster_commitment
        || frame.epoch != round.anchor.successor.epoch.0
        || frame.enrollment_nonce != round.anchor.enrollment_nonce
        || frame.context_digest != round.anchor.context_digest
        || frame.coordinator != round.anchor.coordinator
    {
        return Ok(false);
    }
    let record = storage.get_group(group_id)?;
    if record.removed
        || record.unrecoverable
        || record.disbanded.is_some()
        || record.epoch != round.anchor.successor.epoch
    {
        return Ok(false);
    }
    let Some(group) = MlsGroup::load(
        storage.mls_storage(),
        &openmls::group::GroupId::from_slice(group_id.as_slice()),
    )
    .map_err(|_| EngineError::Backend("private settlement tree read failed".into()))?
    else {
        return Ok(false);
    };
    if !crate::private_successor::anchor_matches_actual_tree(
        storage,
        group_id,
        &group,
        &round.anchor,
    )? {
        return Ok(false);
    }
    if source.signer == round.anchor.local_device {
        return Ok(false);
    }
    // A second authenticated but different statement for an occupied slot is
    // handled negatively. Actual backend failures still abort the crypto unit.
    if store.read_facts()?.iter().any(|fact| {
        fact.leaf_index == source.leaf_index
            && (fact.signature_public_key != source.signer || fact.message_id != effect.message_id)
    }) {
        return Ok(false);
    }
    match frame.phase {
        SettlementPhase::Challenge => {
            if source.signer != round.anchor.coordinator
                || round
                    .coordinator_leaf_index
                    .is_some_and(|index| index != source.leaf_index)
                || round
                    .round_nonce
                    .is_some_and(|nonce| nonce != frame.round_nonce)
            {
                return Ok(false);
            }
            store.bind_round_nonce(round.generation, frame.round_nonce, source.leaf_index)?;
        }
        SettlementPhase::Ack => {
            if round.round_nonce != Some(frame.round_nonce) {
                return Ok(false);
            }
        }
    }
    store.record_remote_confirmation(&PrivateSettlementFact {
        format_version: 1,
        generation: round.generation,
        leaf_index: source.leaf_index,
        signature_public_key: source.signer,
        message_id: effect.message_id,
    })?;
    ensure_live(Some(&live), true)?;
    Ok(true)
}
/// Actual adopted tree denial, never called by probes or public observations.
pub(crate) fn deny_settlement_for_tree<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    group: &MlsGroup,
) -> Result<(), EngineError> {
    let Some(store) = storage.private_roster_settlement_storage() else {
        return Ok(());
    };
    let Some(round) = store.read_round()? else {
        return Ok(());
    };
    if round.anchor.group_id == *group_id
        && round.phase != PrivateSettlementPhase::Denied
        && !crate::private_successor::anchor_matches_actual_tree(
            storage,
            group_id,
            group,
            &round.anchor,
        )?
    {
        store.deny_round(round.generation)?;
    }
    Ok(())
}

/// Explicit authoritative removal/deletion denial inside its existing SQL unit.
pub(crate) fn deny_settlement_for_group<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
) -> Result<(), EngineError> {
    if let Some(store) = storage.private_roster_settlement_storage()
        && let Some(round) = store.read_round()?
        && round.anchor.group_id == *group_id
        && round.phase != PrivateSettlementPhase::Denied
    {
        store.deny_round(round.generation)?;
    }
    Ok(())
}
