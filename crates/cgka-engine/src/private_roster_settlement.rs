//! Protected all-leaf settlement boundary under construction. No permissions.
use crate::{Engine, device_group_snapshot::CandidateDeviceGroupSnapshot};
use cgka_traits::private_roster_settlement::{
    PrivateSettlementAnchor, PrivateSettlementFact, PrivateSettlementPhase, PrivateSettlementState,
};
use serde::{Deserialize, Serialize};

pub(crate) const PRIVATE_SETTLEMENT_KIND: u64 = 38_174;
pub(crate) const PRIVATE_SETTLEMENT_PROTOCOL: &str = "whitenoise.experimental.roster-settlement.v1";
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SettlementPhase {
    Challenge,
    Ack,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SettlementFrame {
    pub(crate) protocol: String,
    pub(crate) phase: SettlementPhase,
    pub(crate) round_nonce: [u8; 32],
    pub(crate) roster_commitment: [u8; 32],
    pub(crate) epoch: u64,
    pub(crate) enrollment_nonce: [u8; 32],
    pub(crate) context_digest: [u8; 32],
    pub(crate) coordinator: [u8; 32],
}
use cgka_traits::{EngineError, GroupId, engine::SendResult, storage::StorageProvider};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[cfg(test)]
use std::time::Duration;
use web_time::Instant;

/// Trusted account-owner continuation from the original verified SDK attempt.
/// No implementation may restore admission or extend its deadline from SQL.
pub trait TrustedPrivateSettlementGuard: Send + Sync {
    fn validate(&self, anchor: &PrivateSettlementAnchor) -> Result<Instant, EngineError>;
}

/// Publishes only the exact prepared private control through the account adapter.
#[async_trait::async_trait]
pub trait TrustedPrivateSettlementPublisher: Send + Sync {
    async fn publish_confirmation(
        &self,
        message: &cgka_traits::TransportMessage,
    ) -> Result<(), EngineError>;
}

// Engine-owned, nonserialized admission. Durable facts never construct this.
pub(crate) struct LiveSettlementAdmission {
    pub(crate) anchor: PrivateSettlementAnchor,
    pub(crate) generation: u64,
    deadline: Instant,
    cancelled: AtomicBool,
    guard: Option<Arc<dyn TrustedPrivateSettlementGuard>>,
}
impl LiveSettlementAdmission {
    pub(crate) fn select_applied_existing<S: StorageProvider>(
        storage: &S,
        group_id: &GroupId,
        group: &openmls::group::MlsGroup,
        guard: Arc<crate::private_enrollment_endorsement::OwnedExistingEnrollmentTransition>,
    ) -> Result<Arc<Self>, EngineError> {
        let anchor = guard.applied_settlement_anchor(storage, group_id, group)?;
        let deadline = guard.validate(&anchor)?;
        let state = storage
            .private_roster_settlement_storage()
            .ok_or_else(unavailable)?
            .select_round(&anchor)?;
        if guard.validate(&anchor)? != deadline || Instant::now() >= deadline {
            return Err(unavailable());
        }
        Ok(Arc::new(Self {
            anchor,
            generation: state.generation,
            deadline,
            cancelled: AtomicBool::new(false),
            guard: Some(guard),
        }))
    }
    pub(crate) fn select_applied_revoked<S: StorageProvider>(
        storage: &S,
        group_id: &GroupId,
        group: &openmls::group::MlsGroup,
        guard: Arc<crate::device_leaf_revocation::transition::OwnedDeviceRevocationTransition>,
    ) -> Result<Arc<Self>, EngineError> {
        let anchor = guard.applied_settlement_anchor(storage, group_id, group)?;
        let deadline = guard.validate(&anchor)?;
        let state = storage
            .private_roster_settlement_storage()
            .ok_or_else(unavailable)?
            .select_round(&anchor)?;
        if guard.validate(&anchor)? != deadline || Instant::now() >= deadline {
            return Err(unavailable());
        }
        Ok(Arc::new(Self {
            anchor,
            generation: state.generation,
            deadline,
            cancelled: AtomicBool::new(false),
            guard: Some(guard),
        }))
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
    pub(crate) fn is_live(&self) -> bool {
        !self.cancelled.load(Ordering::SeqCst)
            && Instant::now() < self.deadline
            // A failed owner check revokes positive admission; it never falls
            // back to durable facts or the test-only unguarded route.
            && self.guard.as_ref().is_none_or(|guard| {
                guard.validate(&self.anchor).is_ok_and(|deadline| {
                    deadline == self.deadline && Instant::now() < deadline
                })
            })
    }
}

/// Opaque fresh protected lineage and all-leaf settlement observation.
/// No constructor, Clone or serde; neither metadata accessor supplies SDK consent.
pub struct ValidatedSettledDeviceRoster {
    settlement_generation: u64,
    candidate: CandidateDeviceGroupSnapshot,
    origin: cgka_traits::private_device_invite::PrivateInviteOrigin,
}
impl ValidatedSettledDeviceRoster {
    /// Protected completed-round identity only; never admission or consent.
    pub fn settlement_generation(&self) -> u64 {
        self.settlement_generation
    }

    pub fn candidate(&self) -> &CandidateDeviceGroupSnapshot {
        &self.candidate
    }
    /// Read-only protected source kind/generation, inseparable from this proof.
    /// Arming still requires the original SDK token and fresh Engine validation.
    pub fn origin(&self) -> &cgka_traits::private_device_invite::PrivateInviteOrigin {
        &self.origin
    }
}
pub(crate) fn unavailable() -> EngineError {
    EngineError::Other("protected private roster settlement unavailable".into())
}
impl<S: StorageProvider> Engine<S> {
    pub fn validated_settled_device_roster(
        &self,
        group: &GroupId,
    ) -> Result<Option<ValidatedSettledDeviceRoster>, EngineError> {
        self.ensure_group_live(group)?;
        self.storage.with_read_snapshot(|storage| {
            let Some(evidence) = self.validated_private_successor(group)? else {
                return Ok(None);
            };
            // Reuse only the existing generation-validated parsed MLS object.
            // The successor, round, facts and exact anchor remain fresh reads in
            // this pinned snapshot; parsed state never carries authorization.
            let Some(actual) = self
                .take_mls_group(group)
                .map_err(|_| EngineError::Backend("private settled tree read failed".into()))?
            else {
                return Ok(None);
            };
            let result = (|| {
                let Some(state) = completed_round_for_tree(storage, group, &actual)? else {
                    return Ok(None);
                };
                if &state.anchor != evidence.settlement_anchor() {
                    return Ok(None);
                }
                Ok(Some(ValidatedSettledDeviceRoster {
                    settlement_generation: state.generation,
                    candidate: evidence.candidate().clone(),
                    origin: evidence.settlement_anchor().origin.clone(),
                }))
            })();
            self.return_unmodified_mls_group(group, actual);
            result
        })
    }
    #[cfg(test)]
    pub(crate) fn select_private_roster_settlement(
        &self,
        group: &GroupId,
    ) -> Result<(), EngineError> {
        self.select_settlement_round(group, Instant::now() + Duration::from_secs(600), None)
    }

    /// Select only fresh protected successor evidence under an original owner
    /// continuation. This is not a native permission or serialized proof inlet.
    pub fn select_owned_private_roster_settlement(
        &self,
        group: &GroupId,
        guard: Arc<dyn TrustedPrivateSettlementGuard>,
    ) -> Result<(), EngineError> {
        let evidence = self
            .validated_private_successor(group)?
            .ok_or_else(unavailable)?;
        let deadline = guard.validate(evidence.settlement_anchor())?;
        self.select_settlement_round(group, deadline, Some(guard))
    }

    fn select_settlement_round(
        &self,
        group: &GroupId,
        deadline: Instant,
        guard: Option<Arc<dyn TrustedPrivateSettlementGuard>>,
    ) -> Result<(), EngineError> {
        let mut slot = self
            .settlement_admission
            .lock()
            .map_err(|_| unavailable())?;
        let evidence = self
            .validated_private_successor(group)?
            .ok_or_else(unavailable)?;
        let anchor = evidence.settlement_anchor().clone();
        let state = self.storage.with_transaction(|storage| {
            // The selection and fresh protected-origin check share the SQL unit.
            let current = self
                .validated_private_successor(group)?
                .ok_or_else(unavailable)?;
            if current.settlement_anchor() != &anchor {
                return Err(unavailable());
            }
            if Instant::now() >= deadline
                || guard.as_ref().is_some_and(|guard| {
                    guard
                        .validate(&anchor)
                        .map_or(true, |current| current != deadline)
                })
            {
                return Err(unavailable());
            }
            // Maintenance can reach this same original owner after selected
            // crypto apply already admitted and received its first Challenge.
            // Reuse only that live in-memory continuation; a matching SQL row
            // without the identical original guard never grants admission.
            if let (Some(previous), Some(requested)) = (slot.as_ref(), guard.as_ref())
                && previous.anchor == anchor
                && previous.deadline == deadline
                && previous.is_live()
                && previous
                    .guard
                    .as_ref()
                    .is_some_and(|original| Arc::ptr_eq(original, requested))
                && storage
                    .private_roster_settlement_storage()
                    .ok_or_else(unavailable)?
                    .read_round()?
                    .is_some_and(|round| {
                        round.generation == previous.generation
                            && round.anchor == anchor
                            && round.phase != PrivateSettlementPhase::Denied
                    })
            {
                return Ok(None);
            }
            let state = storage
                .private_roster_settlement_storage()
                .ok_or_else(unavailable)?
                .select_round(&anchor)?;
            if Instant::now() >= deadline
                || guard.as_ref().is_some_and(|guard| {
                    guard
                        .validate(&anchor)
                        .map_or(true, |current| current != deadline)
                })
            {
                return Err(unavailable());
            }
            Ok::<_, EngineError>(Some(state))
        })?;
        let Some(state) = state else {
            return Ok(());
        };
        let admission = Arc::new(LiveSettlementAdmission {
            anchor,
            generation: state.generation,
            deadline,
            cancelled: AtomicBool::new(false),
            guard,
        });
        if let Some(previous) = slot.replace(admission) {
            previous.cancel();
        }
        Ok(())
    }
}
impl<S: StorageProvider> Engine<S> {
    pub fn cancel_private_roster_settlement(&self, group: &GroupId) -> Result<(), EngineError> {
        let admission = self
            .settlement_admission
            .lock()
            .map_err(|_| unavailable())?
            .clone();
        let Some(admission) = admission.filter(|value| value.anchor.group_id == *group) else {
            return Ok(());
        };
        // Cancellation withdraws memory authority immediately, even if the
        // durable negative fence encounters a recoverable storage failure.
        admission.cancel();
        let store = self
            .storage
            .private_roster_settlement_storage()
            .ok_or_else(unavailable)?;
        if let Some(state) = store.read_round()?
            && state.generation == admission.generation
            && state.phase == PrivateSettlementPhase::Pending
        {
            store.deny_round(state.generation)?;
        }
        Ok(())
    }
    pub(crate) fn settlement_admission_for(
        &self,
        group: &GroupId,
    ) -> Result<Option<Arc<LiveSettlementAdmission>>, EngineError> {
        let admission = self
            .settlement_admission
            .lock()
            .map_err(|_| unavailable())?
            .clone();
        let Some(admission) = admission.filter(|value| value.anchor.group_id == *group) else {
            return Ok(None);
        };
        if !admission.is_live() {
            admission.cancel();
            if let Some(store) = self.storage.private_roster_settlement_storage()
                && let Some(state) = store.read_round()?
                && state.generation == admission.generation
                && state.phase == PrivateSettlementPhase::Pending
            {
                store.deny_round(state.generation)?;
            }
            return Ok(None);
        }
        let Some(state) = self
            .storage
            .private_roster_settlement_storage()
            .ok_or_else(unavailable)?
            .read_round()?
        else {
            return Ok(None);
        };
        if state.generation != admission.generation
            || state.anchor != admission.anchor
            || state.phase == PrivateSettlementPhase::Denied
        {
            return Ok(None);
        }
        // Tree freshness is checked by each crypto seam, including selected
        // apply while its convergence pass is still active.
        Ok(Some(admission))
    }
    pub(crate) fn commit_applied_settlement_admission(
        &self,
        admission: Arc<LiveSettlementAdmission>,
    ) -> Result<(), EngineError> {
        if !admission.is_live() {
            return Err(unavailable());
        }
        let mut slot = self
            .settlement_admission
            .lock()
            .map_err(|_| unavailable())?;
        if let Some(previous) = slot.replace(admission) {
            previous.cancel();
        }
        Ok(())
    }
    pub(crate) fn checked_settlement_round(
        &self,
        admission: &LiveSettlementAdmission,
    ) -> Result<PrivateSettlementState, EngineError> {
        if !admission.is_live() {
            return Err(unavailable());
        }
        let evidence = self
            .validated_private_successor(&admission.anchor.group_id)?
            .ok_or_else(unavailable)?;
        if evidence.settlement_anchor() != &admission.anchor {
            return Err(unavailable());
        }
        let state = self
            .storage
            .private_roster_settlement_storage()
            .ok_or_else(unavailable)?
            .read_round()?
            .ok_or_else(unavailable)?;
        if state.generation != admission.generation
            || state.anchor != admission.anchor
            || state.phase == PrivateSettlementPhase::Denied
        {
            return Err(unavailable());
        }
        Ok(state)
    }
}
impl<S: StorageProvider + 'static> Engine<S> {
    /// Scheduling observation under an already-live selection; never consent.
    pub fn private_roster_settlement_publication_ready(
        &self,
        group: &GroupId,
    ) -> Result<bool, EngineError> {
        let Some(admission) = self.settlement_admission_for(group)? else {
            return Ok(false);
        };
        let state = self.checked_settlement_round(&admission)?;
        if state.anchor.local_device == state.anchor.coordinator {
            return Ok(true);
        }
        let Some(index) = state.coordinator_leaf_index else {
            return Ok(false);
        };
        Ok(state.round_nonce.is_some()
            && self
                .storage
                .private_roster_settlement_storage()
                .ok_or_else(unavailable)?
                .read_facts()?
                .iter()
                .any(|fact| {
                    fact.generation == state.generation
                        && fact.leaf_index == index
                        && fact.signature_public_key == state.anchor.coordinator
                }))
    }

    /// Fresh scope and original monotonic owner admission are checked before
    /// every publication poll. Retries retain the cached MLS ciphertext/wrapper.
    pub async fn dispatch_private_roster_settlement(
        &mut self,
        group: &GroupId,
        publisher: &dyn TrustedPrivateSettlementPublisher,
    ) -> Result<(), EngineError> {
        let admission = self
            .settlement_admission_for(group)?
            .ok_or_else(unavailable)?;
        let round = self.checked_settlement_round(&admission)?;
        let result = if round.anchor.local_device == round.anchor.coordinator {
            self.start_private_roster_settlement(group).await?
        } else {
            self.prepare_private_roster_ack(group).await?
        };
        let SendResult::ApplicationMessage { msg, .. } = result else {
            return Err(unavailable());
        };
        let mut future = Box::pin(publisher.publish_confirmation(&msg));
        let remaining = admission
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(unavailable)?;
        crate::deadline::timeout(
            remaining,
            std::future::poll_fn(|cx| {
                if let Err(error) = self.checked_settlement_round(&admission) {
                    return std::task::Poll::Ready(Err(error));
                }
                std::future::Future::poll(future.as_mut(), cx)
            }),
        )
        .await
        .map_err(|_| unavailable())?
    }

    pub(crate) async fn start_private_roster_settlement(
        &mut self,
        group: &GroupId,
    ) -> Result<SendResult, EngineError> {
        let evidence = self
            .validated_private_successor(group)?
            .ok_or_else(unavailable)?;
        if evidence.settlement_anchor().coordinator != evidence.settlement_anchor().local_device {
            return Err(unavailable());
        }
        // First explicit start may select. An existing expired admission is
        // terminal: a retry cannot allocate a replacement or extend its clock.
        let has_admission = self
            .settlement_admission
            .lock()
            .map_err(|_| unavailable())?
            .is_some();
        if !has_admission {
            #[cfg(test)]
            self.select_private_roster_settlement(group)?;
            #[cfg(not(test))]
            return Err(unavailable());
        }
        let admission = self
            .settlement_admission_for(group)?
            .ok_or_else(unavailable)?;
        let state = self.checked_settlement_round(&admission)?;
        if state.round_nonce.is_none() {
            use rand::RngCore;
            let mut nonce = [0; 32];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            if nonce == [0; 32] {
                return Err(unavailable());
            }
            let index = state
                .anchor
                .successor
                .leaves
                .iter()
                .find(|leaf| leaf.signature_public_key == state.anchor.coordinator)
                .ok_or_else(unavailable)?
                .leaf_index;
            self.storage.with_transaction(|storage| {
                self.checked_settlement_round(&admission)?;
                storage
                    .private_roster_settlement_storage()
                    .ok_or_else(unavailable)?
                    .bind_round_nonce(state.generation, nonce, index)?;
                if !admission.is_live() {
                    return Err(unavailable());
                }
                Ok::<_, EngineError>(())
            })?;
        }
        self.prepare_settlement_publication(admission, SettlementPhase::Challenge)
            .await
    }
    pub(crate) async fn prepare_private_roster_ack(
        &mut self,
        group: &GroupId,
    ) -> Result<SendResult, EngineError> {
        let admission = self
            .settlement_admission_for(group)?
            .ok_or_else(unavailable)?;
        let state = self.checked_settlement_round(&admission)?;
        if state.anchor.local_device == state.anchor.coordinator || state.round_nonce.is_none() {
            return Err(unavailable());
        }
        // A bound nonce is not a coordinator confirmation. Require the exact
        // sealed cryptographic coordinator slot before releasing a local ACK.
        let coordinator_index = state.coordinator_leaf_index.ok_or_else(unavailable)?;
        let facts = self
            .storage
            .private_roster_settlement_storage()
            .ok_or_else(unavailable)?
            .read_facts()?;
        if !facts.iter().any(|fact| {
            fact.generation == state.generation
                && fact.leaf_index == coordinator_index
                && fact.signature_public_key == state.anchor.coordinator
        }) {
            return Err(unavailable());
        }
        self.prepare_settlement_publication(admission, SettlementPhase::Ack)
            .await
    }
    async fn prepare_settlement_publication(
        &mut self,
        admission: Arc<LiveSettlementAdmission>,
        phase: SettlementPhase,
    ) -> Result<SendResult, EngineError> {
        use cgka_traits::transport::EncryptedPayload;
        use openmls::prelude::MlsMessageOut;
        use tls_codec::Serialize as _;
        let state = self.checked_settlement_round(&admission)?;
        let frame = SettlementFrame {
            protocol: PRIVATE_SETTLEMENT_PROTOCOL.into(),
            phase,
            round_nonce: state.round_nonce.ok_or_else(unavailable)?,
            roster_commitment: state.anchor.roster_commitment,
            epoch: state.anchor.successor.epoch.0,
            enrollment_nonce: state.anchor.enrollment_nonce,
            context_digest: state.anchor.context_digest,
            coordinator: state.anchor.coordinator,
        };
        let event = cgka_traits::app_event::MarmotAppEvent::new(
            hex::encode(self.identity.self_id().as_slice()),
            0,
            PRIVATE_SETTLEMENT_KIND,
            vec![],
            serde_json::to_string(&frame).map_err(|_| unavailable())?,
        );
        if let Some(bytes) = &state.outbound {
            let result: SendResult = serde_json::from_slice(bytes).map_err(|_| unavailable())?;
            if !matches!(&result, SendResult::ApplicationMessage {
                group_id, source_epoch, app_event_id, ..
            } if group_id == &state.anchor.group_id
                && source_epoch == &state.anchor.successor.epoch && app_event_id == &event.id)
            {
                return Err(unavailable());
            }
            self.checked_settlement_round(&admission)?;
            return Ok(result);
        }
        let payload = event.encode().map_err(|_| unavailable())?;
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let (ctx, stamp) = self.with_mls_group(&state.anchor.group_id, |group| {
            Ok::<_, EngineError>((
                crate::group_lifecycle::build_group_context_snapshot(group, &provider)?,
                cgka_traits::message::OwnApplicationConvergenceStamp {
                    sender: self.identity.self_id().clone(),
                    source_epoch_authenticator: hex::encode(group.epoch_authenticator().as_slice()),
                },
            ))
        })?;
        let ciphertext = if let Some(bytes) = &state.prepared_ciphertext {
            bytes.clone()
        } else {
            let mut group = self
                .take_mls_group(&state.anchor.group_id)?
                .ok_or_else(unavailable)?;
            let result = self.storage.with_transaction(|storage| {
                self.checked_settlement_round(&admission)?;
                let message: MlsMessageOut = group
                    .create_message(&provider, &self.identity.signer, &payload)
                    .map_err(|_| {
                        EngineError::Backend("private settlement encryption failed".into())
                    })?;
                let bytes = message.tls_serialize_detached().map_err(|_| {
                    EngineError::Serialize("private settlement encryption failed".into())
                })?;
                let own = state
                    .anchor
                    .successor
                    .leaves
                    .iter()
                    .find(|leaf| leaf.signature_public_key == state.anchor.local_device)
                    .ok_or_else(unavailable)?;
                storage
                    .private_roster_settlement_storage()
                    .ok_or_else(unavailable)?
                    .record_local_confirmation(
                        &PrivateSettlementFact {
                            format_version: 1,
                            generation: state.generation,
                            leaf_index: own.leaf_index,
                            signature_public_key: own.signature_public_key,
                            message_id: crate::message_processor::content_dedup_id(&bytes),
                        },
                        &bytes,
                    )?;
                self.checked_settlement_round(&admission)?;
                Ok::<_, EngineError>(bytes)
            });
            match result {
                Ok(bytes) => {
                    self.return_mls_group(&state.anchor.group_id, group);
                    bytes
                }
                // SQL rolled back the ratchet. Discard the mutated scratch MLS
                // object; the next attempt loads the original durable state.
                Err(error) => {
                    self.mls_group_cache.forget_group(&state.anchor.group_id);
                    return Err(error);
                }
            }
        };
        // Private confirmation is control traffic, outside chat retention.
        // Use transport-default wrap time and no chat expiration metadata.
        let remaining = admission.deadline.saturating_duration_since(Instant::now());
        let wrapped = crate::deadline::timeout(
            remaining,
            self.peeler.wrap_group_message(
                &EncryptedPayload {
                    ciphertext: ciphertext.clone(),
                    aad: vec![],
                },
                &ctx,
            ),
        )
        .await;
        let wrapped = match wrapped {
            Ok(result) => result.map_err(EngineError::Peeler)?,
            Err(_) => {
                // Expiry is terminal for unfinished work; transient wrapping
                // errors above retain the original admission and ciphertext.
                self.settlement_admission_for(&state.anchor.group_id)?;
                return Err(unavailable());
            }
        };
        self.checked_settlement_round(&admission)?;
        let wrapped = crate::message_processor::route_wrapped_group_message(wrapped, &ctx);
        let result = SendResult::ApplicationMessage {
            msg: wrapped.clone(),
            group_id: state.anchor.group_id.clone(),
            app_event_id: event.id,
            source_epoch: state.anchor.successor.epoch,
            retention: cgka_traits::app_event::AppMessageRetentionDecision::new(
                event.created_at,
                0,
            ),
            authority: None,
        };
        let bytes = serde_json::to_vec(&result).map_err(|_| unavailable())?;
        let content_id = self.persist_private_settlement_outbound(
            &wrapped,
            &ciphertext,
            &admission,
            stamp,
            &bytes,
        )?;
        self.sent_message_ids.insert(wrapped.id);
        self.sent_message_ids.insert(content_id);
        Ok(result)
    }
}

#[cfg(test)]
#[path = "private_roster_settlement_tests.rs"]
pub(crate) mod tests;

/// Shared fresh crypto-tree plus completed-facts validation. Never admission.
pub(crate) fn completed_round_for_tree<S: StorageProvider>(
    storage: &S,
    group: &GroupId,
    actual: &openmls::group::MlsGroup,
) -> Result<Option<PrivateSettlementState>, EngineError> {
    if actual.pending_commit().is_some() {
        return Ok(None);
    }
    completed_round_for_predecessor_tree(storage, group, actual)
}

/// Protected predecessor metadata only. Pending Add callers must separately
/// hold the original SDK lease and validate their exact memory-owned raw scope;
/// public settled-roster/candidate APIs continue to reject all pending commits.
pub(crate) fn completed_round_for_predecessor_tree<S: StorageProvider>(
    storage: &S,
    group: &GroupId,
    actual: &openmls::group::MlsGroup,
) -> Result<Option<PrivateSettlementState>, EngineError> {
    let Some(store) = storage.private_roster_settlement_storage() else {
        return Ok(None);
    };
    let Some(state) = store.read_round()? else {
        return Ok(None);
    };
    if state.phase != PrivateSettlementPhase::Completed
        || state.anchor.group_id != *group
        || state.round_nonce.is_none()
        || state.coordinator_leaf_index.is_none()
        || state.prepared_ciphertext.is_none()
    {
        return Ok(None);
    }
    let record = storage.get_group(group)?;
    if record.removed
        || record.unrecoverable
        || record.disbanded.is_some()
        || record.epoch != state.anchor.successor.epoch
    {
        return Ok(None);
    }
    let facts = store.read_facts()?;
    if facts.len() != state.anchor.successor.leaves.len()
        || !state.anchor.successor.leaves.iter().all(|leaf| {
            facts.iter().any(|fact| {
                fact.generation == state.generation
                    && fact.leaf_index == leaf.leaf_index
                    && fact.signature_public_key == leaf.signature_public_key
            })
        })
    {
        return Ok(None);
    }
    if !crate::private_successor::anchor_matches_actual_tree(storage, group, actual, &state.anchor)?
    {
        return Ok(None);
    }
    let account = cgka_traits::MemberId::new(state.anchor.account.to_vec());
    for leaf in actual.export_ratchet_tree().leaves() {
        if crate::account_identity_proof::validate_leaf_account_identity_proof_for_member(
            leaf,
            actual.ciphersuite(),
            &account,
            "private completed predecessor",
        )
        .map_err(|_| {
            EngineError::Other("private completed predecessor leaf proof invalid".into())
        })? != cgka_traits::group::ProtocolProfile::Current
        {
            return Ok(None);
        }
    }
    Ok(Some(state))
}
