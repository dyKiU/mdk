//! Original authenticated Remove continuation. Stored facts never construct it.
use super::{DeviceLeafRevocationSelection, unavailable};
use crate::private_roster_settlement::TrustedPrivateSettlementGuard;
use cgka_traits::EngineError;
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::private_roster_settlement::PrivateSettlementAnchor;
use cgka_traits::revoked_device_group_anchor::RevokedDeviceGroupDraft;
use std::sync::{Arc, Weak};
use web_time::Instant;

/// Trusted actor lease of the exact displayed, explicitly approved original.
/// Implementations may not restore a lease or extend its deadline from SQL.
pub trait TrustedDeviceRevocationTransitionLease: Send + Sync {
    fn check_original(
        &self,
        original: &DeviceLeafRevocationSelection,
    ) -> Result<Instant, EngineError>;
    fn check_live(&self) -> Result<Instant, EngineError>;
}

// Construct only from the actual applied successor draft. A separate original
// preparation intent must retain its predecessor/commit identity across rollback;
// this applied continuation is staged until the outer SQL commit succeeds.
pub(crate) struct OwnedDeviceRevocationTransition {
    pub(crate) owner: Weak<crate::private_enrollment_endorsement::Lifetime>,
    pub(crate) deadline: Instant,
    pub(crate) draft: RevokedDeviceGroupDraft,
    pub(crate) source: Option<Arc<dyn TrustedDeviceRevocationTransitionLease>>,
}
impl OwnedDeviceRevocationTransition {
    pub(crate) fn check_live(&self) -> Result<(), EngineError> {
        if Instant::now() >= self.deadline
            || !self.owner.upgrade().is_some_and(|owner| owner.is_open())
        {
            return Err(unavailable());
        }
        if let Some(lease) = &self.source
            && lease.check_live()? != self.deadline
        {
            return Err(unavailable());
        }
        Ok(())
    }
    pub(crate) fn applied_settlement_anchor<S: cgka_traits::storage::StorageProvider>(
        &self,
        storage: &S,
        group: &cgka_traits::GroupId,
        actual: &openmls::group::MlsGroup,
    ) -> Result<PrivateSettlementAnchor, EngineError> {
        self.check_live()?;
        let fact = storage
            .revoked_device_group_anchor_storage()
            .ok_or_else(unavailable)?
            .revoked_anchor()?
            .ok_or_else(unavailable)?;
        if fact.denied
            || fact.generation == 0
            || fact.draft != self.draft
            || group != &self.draft.group_id
            || !crate::device_group_lineage::AppliedPrivateTree::read(group, actual)?.is_some_and(
                |tree| {
                    tree.matches(
                        &self.draft.account,
                        &self.draft.local_device,
                        &self.draft.successor,
                    )
                },
            )
        {
            return Err(unavailable());
        }
        let draft = &self.draft;
        let mut candidate = crate::device_group_snapshot::CandidateDeviceGroupSnapshot {
            account: cgka_traits::MemberId::new(draft.account.to_vec()),
            group_id: group.clone(),
            epoch: draft.successor.epoch,
            epoch_authenticator_digest: draft.successor.epoch_authenticator_digest,
            leaves: draft
                .successor
                .leaves
                .iter()
                .map(|leaf| crate::device_group_snapshot::CandidateDeviceLeaf {
                    leaf_index: leaf.leaf_index,
                    signature_public_key: leaf.signature_public_key.to_vec(),
                })
                .collect(),
            roster_commitment: [0; 32],
        };
        candidate.roster_commitment = crate::device_group_snapshot::commitment(&candidate);
        let anchor = PrivateSettlementAnchor {
            origin: cgka_traits::private_device_invite::PrivateInviteOrigin::Revoked(
                fact.generation,
            ),
            account: draft.account,
            local_device: draft.local_device,
            group_id: group.clone(),
            successor: draft.successor.clone(),
            roster_commitment: candidate.roster_commitment,
            enrollment_nonce: draft.nonce,
            context_digest: draft.context_digest,
            coordinator: draft.source_device,
        };
        self.validate(&anchor)?;
        Ok(anchor)
    }
    pub(crate) fn matches_successor(&self, successor: &DeviceGroupAnchorRoster) -> bool {
        successor == &self.draft.successor
            && Some(successor.epoch.0) == self.draft.predecessor.epoch.0.checked_add(1)
            && successor.leaves.len() + 1 == self.draft.predecessor.leaves.len()
            && !successor.leaves.iter().any(|leaf| {
                leaf.leaf_index == self.draft.removed_leaf_index
                    || leaf.signature_public_key == self.draft.removed_device
            })
            && self
                .draft
                .predecessor
                .leaves
                .iter()
                .filter(|leaf| leaf.leaf_index != self.draft.removed_leaf_index)
                .all(|leaf| successor.leaves.contains(leaf))
    }
}
impl TrustedPrivateSettlementGuard for OwnedDeviceRevocationTransition {
    fn validate(&self, anchor: &PrivateSettlementAnchor) -> Result<Instant, EngineError> {
        self.check_live()?;
        let draft = &self.draft;
        if !matches!(anchor.origin, cgka_traits::private_device_invite::PrivateInviteOrigin::Revoked(generation) if generation != 0)
            || anchor.account != draft.account
            || anchor.local_device != draft.local_device
            || anchor.group_id != draft.group_id
            || anchor.enrollment_nonce != draft.nonce
            || anchor.context_digest != draft.context_digest
            || anchor.coordinator != draft.source_device
            || !self.matches_successor(&anchor.successor)
        {
            return Err(unavailable());
        }
        Ok(self.deadline)
    }
}

/// Fixed first-observation intent. Retain this exact value across failed SQL
/// apply; constructing another value from a stored draft cannot renew it.
pub(crate) struct DeviceRevocationTransitionIntent {
    pub(crate) owner: Weak<crate::private_enrollment_endorsement::Lifetime>,
    pub(crate) deadline: Instant,
    pub(crate) source: Option<Arc<dyn TrustedDeviceRevocationTransitionLease>>,
    pub(crate) predecessor: DeviceGroupAnchorRoster,
    pub(crate) predecessor_origin: cgka_traits::private_device_invite::PrivateInviteOrigin,
    pub(crate) predecessor_generation: u64,
    pub(crate) group: cgka_traits::GroupId,
    pub(crate) account: [u8; 32],
    pub(crate) local_device: [u8; 32],
    pub(crate) source_index: u32,
    pub(crate) source_device: [u8; 32],
    pub(crate) removed_index: u32,
    pub(crate) removed_device: [u8; 32],
    pub(crate) commit_digest: [u8; 32],
}
impl DeviceRevocationTransitionIntent {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture<S: cgka_traits::storage::StorageProvider>(
        storage: &S,
        group_id: &cgka_traits::GroupId,
        group: &openmls::group::MlsGroup,
        staged: &openmls::group::StagedCommit,
        committer: openmls::prelude::LeafNodeIndex,
        digest: [u8; 32],
        owner: Weak<crate::private_enrollment_endorsement::Lifetime>,
        source: Option<Arc<dyn TrustedDeviceRevocationTransitionLease>>,
        deadline: Instant,
    ) -> Result<Option<Self>, EngineError> {
        if digest == [0; 32]
            || Instant::now() >= deadline
            || !owner.upgrade().is_some_and(|owner| owner.is_open())
        {
            return Err(unavailable());
        }
        let Some(round) = crate::private_roster_settlement::completed_round_for_predecessor_tree(
            storage, group_id, group,
        )?
        else {
            return Ok(None);
        };
        let mut proposals = staged.queued_proposals();
        let removed = match proposals.next().map(|queued| queued.proposal()) {
            Some(openmls::prelude::Proposal::Remove(remove)) => remove.removed(),
            _ => return Ok(None),
        };
        if proposals.next().is_some() || removed == committer || removed == group.own_leaf_index() {
            return Ok(None);
        }
        let Some(sender) = group.member_at(committer) else {
            return Ok(None);
        };
        let Some(target) = group.member_at(removed) else {
            return Ok(None);
        };
        let Some(local) = group.member_at(group.own_leaf_index()) else {
            return Ok(None);
        };
        let account = crate::identity::validated_member_id(&sender.credential)?;
        if account.as_slice() != round.anchor.account
            || crate::identity::validated_member_id(&target.credential)? != account
            || crate::identity::validated_member_id(&local.credential)? != account
            || !crate::app_components::admins_of_group(group)?
                .iter()
                .any(|admin| admin.as_slice() == account.as_slice())
        {
            return Ok(None);
        }
        if let Some(source) = &source
            && source.check_live()? != deadline
        {
            return Err(unavailable());
        }
        Ok(Some(Self {
            owner,
            deadline,
            source,
            predecessor: round.anchor.successor,
            predecessor_origin: round.anchor.origin,
            predecessor_generation: round.generation,
            group: group_id.clone(),
            account: account.as_slice().try_into().map_err(|_| unavailable())?,
            local_device: local
                .signature_key
                .as_slice()
                .try_into()
                .map_err(|_| unavailable())?,
            source_index: committer.u32(),
            source_device: sender
                .signature_key
                .as_slice()
                .try_into()
                .map_err(|_| unavailable())?,
            removed_index: removed.u32(),
            removed_device: target
                .signature_key
                .as_slice()
                .try_into()
                .map_err(|_| unavailable())?,
            commit_digest: digest,
        }))
    }
}

impl DeviceRevocationTransitionIntent {
    fn check_live(&self) -> Result<(), EngineError> {
        if Instant::now() >= self.deadline
            || !self.owner.upgrade().is_some_and(|owner| owner.is_open())
            || self.source.as_ref().is_some_and(|source| {
                !source
                    .check_live()
                    .is_ok_and(|deadline| deadline == self.deadline)
            })
        {
            return Err(unavailable());
        }
        Ok(())
    }

    /// Called inside the adopting SQL unit after the genuine Remove merge,
    /// before retiring the old lineage. The returned guard is not installed in
    /// Engine memory until that outer transaction commits.
    pub(crate) fn install_applied<S: cgka_traits::storage::StorageProvider>(
        &self,
        storage: &S,
        group_id: &cgka_traits::GroupId,
        group: &openmls::group::MlsGroup,
    ) -> Result<Arc<OwnedDeviceRevocationTransition>, EngineError> {
        use sha2::{Digest, Sha256};
        self.check_live()?;
        let actual = crate::device_group_lineage::AppliedPrivateTree::read(group_id, group)?
            .ok_or_else(unavailable)?;
        let successor = actual.roster().clone();
        if group_id != &self.group {
            return Err(unavailable());
        }
        // All surviving actors derive the same transcript from authenticated
        // MLS evidence. Local storage generations are deliberately not shared.
        let mut transcript = Sha256::new();
        transcript.update(b"whitenoise.revoked-device-transition.v1");
        transcript.update((group_id.as_slice().len() as u64).to_be_bytes());
        transcript.update(group_id.as_slice());
        transcript.update(self.account);
        transcript.update(self.predecessor.epoch.0.to_be_bytes());
        transcript.update(self.predecessor.epoch_authenticator_digest);
        transcript.update(self.commit_digest);
        transcript.update(self.source_index.to_be_bytes());
        transcript.update(self.source_device);
        transcript.update(self.removed_index.to_be_bytes());
        transcript.update(self.removed_device);
        transcript.update(successor.epoch.0.to_be_bytes());
        transcript.update(successor.epoch_authenticator_digest);
        let action_binding: [u8; 32] = transcript.finalize().into();
        let derive = |domain: &[u8]| -> [u8; 32] {
            let mut hash = Sha256::new();
            hash.update(domain);
            hash.update(action_binding);
            hash.finalize().into()
        };
        let guard = Arc::new(OwnedDeviceRevocationTransition {
            owner: self.owner.clone(),
            deadline: self.deadline,
            source: self.source.clone(),
            draft: RevokedDeviceGroupDraft {
                account: self.account,
                local_device: self.local_device,
                group_id: self.group.clone(),
                predecessor: self.predecessor.clone(),
                predecessor_origin: self.predecessor_origin.clone(),
                predecessor_settlement_generation: self.predecessor_generation,
                source_leaf_index: self.source_index,
                source_device: self.source_device,
                removed_leaf_index: self.removed_index,
                removed_device: self.removed_device,
                actual_commit_digest: self.commit_digest,
                action_binding,
                nonce: derive(b"whitenoise.revoked-device-nonce.v1"),
                context_digest: derive(b"whitenoise.revoked-device-context.v1"),
                successor,
            },
        });
        if !guard.matches_successor(&guard.draft.successor)
            || !actual.matches(&self.account, &self.local_device, &guard.draft.successor)
        {
            return Err(unavailable());
        }
        storage
            .revoked_device_group_anchor_storage()
            .ok_or_else(unavailable)?
            .install_revoked_anchor(&guard.draft)?;
        guard.check_live()?;
        Ok(guard)
    }
}

/// At most 128 first-observation intents per originating Engine, including
/// terminal intents. A failed transaction
/// retains its original deadline; a different commit cannot replace it.
pub(crate) struct DeviceRevocationTransitionState {
    owner: Weak<crate::private_enrollment_endorsement::Lifetime>,
    intents: std::sync::Mutex<Vec<Arc<DeviceRevocationTransitionIntent>>>,
    receipts: std::sync::Mutex<Vec<(cgka_traits::GroupId, [u8; 32], Instant)>>,
}
impl DeviceRevocationTransitionState {
    pub(crate) fn new(owner: Weak<crate::private_enrollment_endorsement::Lifetime>) -> Self {
        Self {
            owner,
            intents: std::sync::Mutex::new(Vec::new()),
            receipts: std::sync::Mutex::new(Vec::new()),
        }
    }
    /// Acquired only after actual live transport peeling and durable content
    /// dedup. Retained records and rewrapped stored ciphertext cannot renew it.
    pub(crate) fn observe_live_receipt(
        &self,
        group: &cgka_traits::GroupId,
        digest: [u8; 32],
        deadline: Instant,
    ) -> Result<(), EngineError> {
        if digest == [0; 32] || Instant::now() >= deadline {
            return Ok(());
        }
        let intents = self.intents.lock().map_err(|_| unavailable())?;
        let mut receipts = self.receipts.lock().map_err(|_| unavailable())?;
        if let Some(original) = receipts
            .iter_mut()
            .find(|(g, d, _)| g == group && *d == digest)
        {
            original.2 = original.2.min(deadline);
            return Ok(());
        }
        let retained = receipts.len()
            + intents
                .iter()
                .filter(|intent| {
                    !receipts
                        .iter()
                        .any(|(g, d, _)| *g == intent.group && *d == intent.commit_digest)
                })
                .count();
        let same_intent = intents
            .iter()
            .any(|intent| intent.group == *group && intent.commit_digest == digest);
        if retained >= 128 && !same_intent {
            return Err(unavailable());
        }
        receipts.push((group.clone(), digest, deadline));
        Ok(())
    }
    fn live_received_intents(
        &self,
    ) -> Result<Vec<Arc<DeviceRevocationTransitionIntent>>, EngineError> {
        let intents = self.intents.lock().map_err(|_| unavailable())?;
        let receipts = self.receipts.lock().map_err(|_| unavailable())?;
        Ok(intents
            .iter()
            .filter(|intent| {
                intent.source.is_none()
                    && intent.check_live().is_ok()
                    && receipts.iter().any(|(group, digest, deadline)| {
                        *group == intent.group
                            && *digest == intent.commit_digest
                            && *deadline == intent.deadline
                    })
            })
            .cloned()
            .collect())
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture<S: cgka_traits::storage::StorageProvider>(
        &self,
        storage: &S,
        group_id: &cgka_traits::GroupId,
        group: &openmls::group::MlsGroup,
        staged: &openmls::group::StagedCommit,
        committer: openmls::prelude::LeafNodeIndex,
        digest: [u8; 32],
        source: Option<Arc<dyn TrustedDeviceRevocationTransitionLease>>,
    ) -> Result<Option<Arc<DeviceRevocationTransitionIntent>>, EngineError> {
        let mut slot = self.intents.lock().map_err(|_| unavailable())?;
        if let Some(original) = slot
            .iter()
            .find(|intent| intent.group == *group_id && intent.commit_digest == digest)
        {
            if source.is_none() && original.check_live().is_err() {
                return Ok(None);
            }
            original.check_live()?;
            return Ok(Some(original.clone()));
        }
        let deadline = match &source {
            Some(source) => source.check_live()?,
            None => {
                let receipts = self.receipts.lock().map_err(|_| unavailable())?;
                let Some((_, _, deadline)) = receipts.iter().find(|(g, d, deadline)| {
                    g == group_id && *d == digest && Instant::now() < *deadline
                }) else {
                    return Ok(None);
                };
                *deadline
            }
        };
        let intent = DeviceRevocationTransitionIntent::capture(
            storage,
            group_id,
            group,
            staged,
            committer,
            digest,
            self.owner.clone(),
            source,
            deadline,
        )?
        .map(Arc::new);
        if let Some(intent) = &intent {
            let receipts = self.receipts.lock().map_err(|_| unavailable())?;
            let retained = slot.len()
                + receipts
                    .iter()
                    .filter(|(g, d, _)| {
                        !slot
                            .iter()
                            .any(|old| old.group == *g && old.commit_digest == *d)
                    })
                    .count();
            let same_receipt = receipts
                .iter()
                .any(|(g, d, _)| *g == intent.group && *d == intent.commit_digest);
            if retained >= 128 && !same_receipt {
                return Err(unavailable());
            }
            slot.push(intent.clone());
        }
        Ok(intent)
    }
    pub(crate) fn own_intent(
        &self,
        group: &cgka_traits::GroupId,
        digest: [u8; 32],
    ) -> Result<Option<Arc<DeviceRevocationTransitionIntent>>, EngineError> {
        let slot = self.intents.lock().map_err(|_| unavailable())?;
        let Some(intent) = slot.iter().find(|intent| {
            intent.group == *group && intent.commit_digest == digest && intent.source.is_some()
        }) else {
            return Ok(None);
        };
        intent.check_live()?;
        Ok(Some(intent.clone()))
    }
}

/// Negative control of the actual original applied Remove admission. No public
/// constructor or serialization; neither fields nor retained SQL can mint it.
pub struct DeviceRevocationSettlementControl {
    admission: Arc<crate::private_roster_settlement::LiveSettlementAdmission>,
}
impl DeviceRevocationSettlementControl {
    pub fn deadline(&self) -> Instant {
        self.admission.deadline()
    }
    pub fn is_live(&self) -> bool {
        self.admission.is_live()
    }
    pub fn cancel(&self) {
        self.admission.cancel();
    }
    pub fn group(&self) -> &cgka_traits::GroupId {
        &self.admission.anchor.group_id
    }
    pub fn binding(&self) -> [u8; 32] {
        self.admission.anchor.context_digest
    }
}
impl<S: cgka_traits::storage::StorageProvider> crate::Engine<S> {
    /// Negative retry observation of an already-captured original receipt.
    /// This does not construct an intent, renew a deadline or grant settlement.
    pub fn device_revocation_storage_retry_groups(
        &self,
    ) -> Result<Vec<cgka_traits::GroupId>, EngineError> {
        let mut groups = Vec::new();
        for intent in self.revocation_transition.live_received_intents()? {
            if !self.has_pending_convergence_inputs(&intent.group)? {
                continue;
            }
            let Some(actual) = openmls::group::MlsGroup::load(
                self.storage.mls_storage(),
                &openmls::group::GroupId::from_slice(intent.group.as_slice()),
            )
            .map_err(|_| unavailable())?
            else {
                continue;
            };
            let Some(round) =
                crate::private_roster_settlement::completed_round_for_predecessor_tree(
                    &self.storage,
                    &intent.group,
                    &actual,
                )?
            else {
                continue;
            };
            if round.generation == intent.predecessor_generation
                && round.anchor.origin == intent.predecessor_origin
                && round.anchor.account == intent.account
                && round.anchor.local_device == intent.local_device
                && round.anchor.successor == intent.predecessor
            {
                intent.check_live()?;
                groups.push(intent.group.clone());
            }
        }
        Ok(groups)
    }
    pub fn device_revocation_settlement_control(
        &self,
    ) -> Result<Option<Arc<DeviceRevocationSettlementControl>>, EngineError> {
        let slot = self
            .settlement_admission
            .lock()
            .map_err(|_| unavailable())?;
        Ok(slot
            .as_ref()
            .filter(|admission| {
                admission.is_live()
                    && matches!(
                        admission.anchor.origin,
                        cgka_traits::private_device_invite::PrivateInviteOrigin::Revoked(_)
                    )
            })
            .map(|admission| {
                Arc::new(DeviceRevocationSettlementControl {
                    admission: admission.clone(),
                })
            }))
    }
}
