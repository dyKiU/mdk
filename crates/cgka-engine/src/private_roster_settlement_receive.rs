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
    #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
    diagnostic_recipient: Option<[u8; 32]>,
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
    #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
    diagnostic_recipient: Option<[u8; 32]>,
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
        #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
        diagnostic_recipient,
    }
}

pub(crate) fn apply_settlement_effect<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    effect: SettlementEffect,
) -> Result<bool, EngineError> {
    #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
    use crate::private_settlement_test_observation::Category;
    #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
    let diagnostic_id = effect.message_id.clone();
    #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
    let observe = |category| {
        crate::private_settlement_test_observation::record(
            group_id,
            effect.diagnostic_recipient,
            &diagnostic_id,
            category,
        )
    };
    #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
    observe(Category::Attempt);
    #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
    let missing = if effect.admission.is_none() {
        Category::MissingAdmission
    } else if effect.source.is_none() {
        Category::MissingSource
    } else {
        Category::InvalidFrame
    };
    let (Some(source), Some(live), Some(frame)) = (effect.source, effect.admission, effect.frame)
    else {
        #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
        observe(missing);
        return Ok(false);
    };
    if !live.is_live() {
        #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
        observe(Category::Expired);
        return Ok(false);
    }
    let Some(store) = storage.private_roster_settlement_storage() else {
        #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
        observe(Category::MissingRound);
        return Ok(false);
    };
    let Some(round) = store.read_round()? else {
        #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
        observe(Category::MissingRound);
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
        #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
        observe(Category::RoundScope);
        return Ok(false);
    }
    let record = storage.get_group(group_id)?;
    if record.removed
        || record.unrecoverable
        || record.disbanded.is_some()
        || record.epoch != round.anchor.successor.epoch
    {
        #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
        observe(Category::TreeScope);
        return Ok(false);
    }
    let Some(group) = MlsGroup::load(
        storage.mls_storage(),
        &openmls::group::GroupId::from_slice(group_id.as_slice()),
    )
    .map_err(|_| EngineError::Backend("private settlement tree read failed".into()))?
    else {
        #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
        observe(Category::TreeScope);
        return Ok(false);
    };
    if !crate::private_successor::anchor_matches_actual_tree(
        storage,
        group_id,
        &group,
        &round.anchor,
    )? {
        #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
        observe(Category::TreeScope);
        return Ok(false);
    }
    if source.signer == round.anchor.local_device {
        #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
        observe(Category::LocalSource);
        return Ok(false);
    }
    // A second authenticated but different statement for an occupied slot is
    // handled negatively. Actual backend failures still abort the crypto unit.
    if store.read_facts()?.iter().any(|fact| {
        fact.leaf_index == source.leaf_index
            && (fact.signature_public_key != source.signer || fact.message_id != effect.message_id)
    }) {
        #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
        observe(Category::ConflictingFact);
        return Ok(false);
    }
    let confirmation = PrivateSettlementFact {
        format_version: 1,
        generation: round.generation,
        leaf_index: source.leaf_index,
        signature_public_key: source.signer,
        message_id: effect.message_id,
    };
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
                #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
                observe(Category::ChallengeBinding);
                return Ok(false);
            }
            store.bind_round_nonce(round.generation, frame.round_nonce, source.leaf_index)?;
        }
        SettlementPhase::Ack => {
            if round.round_nonce.is_none() {
                if source.signer == round.anchor.coordinator {
                    #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
                    observe(Category::AckBinding);
                    return Ok(false);
                }
                store.defer_remote_ack(
                    &cgka_traits::private_roster_settlement::PrivateSettlementDeferredAck {
                        fact: confirmation,
                        round_nonce: frame.round_nonce,
                    },
                )?;
                ensure_live(Some(&live), true)?;
                #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
                observe(Category::Accepted);
                return Ok(true);
            }
            if round.round_nonce != Some(frame.round_nonce) {
                #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
                observe(Category::AckBinding);
                return Ok(false);
            }
        }
    }
    #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
    let confirmation_result = store
        .record_remote_confirmation(&confirmation)
        .inspect_err(|_| {
            observe(Category::ConfirmationWriteError);
        });
    #[cfg(not(any(test, all(feature = "test-crash-hooks", debug_assertions))))]
    let confirmation_result = store.record_remote_confirmation(&confirmation);
    confirmation_result?;
    if matches!(frame.phase, SettlementPhase::Challenge) {
        // Only the actual coordinator's sealed Challenge binds the nonce.
        // Promote matching earlier receipts inside this same crypto SQL unit;
        // rollback retains both the ciphertext ratchet and deferred metadata.
        for ack in &round.deferred_acks {
            if ack.round_nonce == frame.round_nonce
                && !store
                    .read_facts()?
                    .iter()
                    .any(|fact| fact.leaf_index == ack.fact.leaf_index && fact != &ack.fact)
            {
                store.record_remote_confirmation(&ack.fact)?;
            }
        }
        store.clear_deferred_acks(round.generation)?;
    }
    ensure_live(Some(&live), true)?;
    #[cfg(any(test, all(feature = "test-crash-hooks", debug_assertions)))]
    observe(Category::Accepted);
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
