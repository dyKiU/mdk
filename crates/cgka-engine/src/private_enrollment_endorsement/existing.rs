//! The original local B action bridges only an exact authenticated single Add.
//! Protected facts record actual SQL application; they cannot restore this owner.
use super::*;
use crate::private_enrollment_request::recipient::{
    ExistingEnrollmentMetadata, authenticate_existing_packet,
};
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::existing_device_group_anchor::ExistingDeviceGroupDraft;
use cgka_traits::private_roster_settlement::PrivateSettlementAnchor;
use openmls::prelude::{LeafNodeIndex, MlsGroup, Proposal, StagedCommit};
use tls_codec::Serialize;

/// A sealed continuation of the original explicit received-request action.
/// Arc aliases share cancellation/expiry; packets and rows cannot construct it.
pub struct OwnedExistingEnrollmentTransition {
    owner: Weak<Lifetime>,
    generation: u64,
    deadline: Instant,
    local_device: [u8; 32],
    origin: cgka_traits::private_device_invite::PrivateInviteOrigin,
    settlement_generation: u64,
    metadata: ExistingEnrollmentMetadata,
}
impl OwnedExistingEnrollmentTransition {
    pub fn binding(&self) -> &[u8; 32] {
        &self.metadata.binding
    }
    pub fn group(&self) -> &GroupId {
        &self.metadata.group
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn cancellation_handle(&self) -> EnrollmentEndorsementCancellation {
        EnrollmentEndorsementCancellation {
            owner: self.owner.clone(),
            generation: self.generation,
        }
    }
    pub fn is_live(&self) -> bool {
        self.check_live().is_ok()
    }
    fn check_live(&self) -> Result<(), EngineError> {
        let owner = self.owner.upgrade().ok_or_else(denied)?;
        if owner.closed.load(Ordering::SeqCst)
            || owner.generation.load(Ordering::SeqCst) != self.generation
            || Instant::now() >= self.deadline
        {
            return Err(denied());
        }
        Ok(())
    }
    fn matches_successor(&self, roster: &DeviceGroupAnchorRoster) -> bool {
        let old = &self.metadata.predecessor;
        roster.epoch.0 == old.epoch.0 + 1
            && roster.leaves.len() == old.leaves.len() + 1
            && roster.epoch_authenticator_digest != [0; 32]
            && old.leaves.iter().all(|leaf| roster.leaves.contains(leaf))
            && roster
                .leaves
                .iter()
                .filter(|leaf| !old.leaves.contains(leaf))
                .all(|leaf| {
                    leaf.account == self.metadata.account
                        && leaf.signature_public_key == self.metadata.recipient
                })
    }
    /// Called only for actual canonical apply, before merging the staged commit.
    pub(crate) fn approves_commit<S: StorageProvider>(
        &self,
        storage: &S,
        group_id: &GroupId,
        group: &MlsGroup,
        staged: &StagedCommit,
        committer: LeafNodeIndex,
        crypto: &openmls_rust_crypto::RustCrypto,
    ) -> Result<bool, EngineError> {
        if self.group() != group_id || !self.is_live() {
            return Ok(false);
        }
        let Some(actual) = crate::device_group_lineage::AppliedPrivateTree::read(group_id, group)?
        else {
            return Ok(false);
        };
        if !actual.matches(
            &self.metadata.account,
            &self.local_device,
            &self.metadata.predecessor,
        ) {
            return Ok(false);
        }
        let Some(round) =
            crate::private_roster_settlement::completed_round_for_tree(storage, group_id, group)?
        else {
            return Ok(false);
        };
        if round.anchor.origin != self.origin
            || round.generation != self.settlement_generation
            || !group
                .member_at(committer)
                .is_some_and(|member| member.signature_key.as_slice() == self.metadata.coordinator)
        {
            return Ok(false);
        }
        let mut proposals = staged.queued_proposals();
        let package = match proposals.next().map(|queued| queued.proposal()) {
            Some(Proposal::Add(add)) => add.key_package(),
            _ => return Ok(false),
        };
        if proposals.next().is_some()
            || package.last_resort()
            || package.hash_ref(crypto).map_err(|_| denied())?.as_slice()
                != self.metadata.key_package_reference
            || package.leaf_node().signature_key().as_slice() != self.metadata.recipient
            || crate::identity::validated_member_id_of_leaf(package.leaf_node())?.as_slice()
                != self.metadata.account
            || <[u8; 32]>::from(Sha256::digest(
                openmls::prelude::MlsMessageOut::from(package.clone())
                    .tls_serialize_detached()
                    .map_err(|_| denied())?,
            )) != self.metadata.key_package_digest
        {
            return Ok(false);
        }
        self.check_live()?;
        Ok(true)
    }
    pub(crate) fn install<S: StorageProvider>(
        &self,
        storage: &S,
        group_id: &GroupId,
        group: &MlsGroup,
        commit_digest: [u8; 32],
    ) -> Result<(), EngineError> {
        self.check_live()?;
        let successor = DeviceGroupAnchorRoster {
            epoch: cgka_traits::EpochId(group.epoch().as_u64()),
            epoch_authenticator_digest: Sha256::digest(group.epoch_authenticator().as_slice())
                .into(),
            leaves: group
                .members()
                .map(|member| {
                    Ok(cgka_traits::device_group_genesis::GenesisLeaf {
                        account: crate::identity::validated_member_id(&member.credential)?
                            .as_slice()
                            .try_into()
                            .map_err(|_| denied())?,
                        leaf_index: member.index.u32(),
                        signature_public_key: member
                            .signature_key
                            .as_slice()
                            .try_into()
                            .map_err(|_| denied())?,
                    })
                })
                .collect::<Result<Vec<_>, EngineError>>()?,
        };
        if group_id != self.group() || !self.matches_successor(&successor) {
            return Err(denied());
        }
        let m = &self.metadata;
        let draft = ExistingDeviceGroupDraft {
            account: m.account,
            local_device: self.local_device,
            group_id: group_id.clone(),
            predecessor: m.predecessor.clone(),
            predecessor_origin: self.origin.clone(),
            predecessor_settlement_generation: self.settlement_generation,
            action_binding: m.binding,
            nonce: m.nonce,
            context_digest: m.context_digest,
            coordinator: m.coordinator,
            recipient: m.recipient,
            key_package_reference: m.key_package_reference,
            key_package_digest: m.key_package_digest,
            commit_digest,
            successor,
        };
        storage
            .existing_device_group_anchor_storage()
            .ok_or_else(denied)?
            .install_existing_anchor(&draft)
            .map_err(EngineError::Storage)?;
        self.check_live()
    }
    pub(crate) fn check_applied<S: StorageProvider>(
        &self,
        storage: &S,
        group: &GroupId,
    ) -> Result<(), EngineError> {
        if group == self.group()
            && storage
                .existing_device_group_anchor_storage()
                .map(|store| store.existing_anchor())
                .transpose()?
                .flatten()
                .is_some_and(|fact| {
                    !fact.denied
                        && fact.draft.action_binding == self.metadata.binding
                        && fact.draft.group_id == *group
                })
        {
            self.check_live()?;
        }
        Ok(())
    }
}
impl crate::private_roster_settlement::TrustedPrivateSettlementGuard
    for OwnedExistingEnrollmentTransition
{
    fn validate(&self, anchor: &PrivateSettlementAnchor) -> Result<Instant, EngineError> {
        self.check_live()?;
        let m = &self.metadata;
        if !matches!(anchor.origin, cgka_traits::private_device_invite::PrivateInviteOrigin::Existing(generation) if generation != 0)
            || anchor.account != m.account
            || anchor.local_device != self.local_device
            || anchor.group_id != m.group
            || anchor.enrollment_nonce != m.nonce
            || anchor.context_digest != m.context_digest
            || anchor.coordinator != m.coordinator
            || !self.matches_successor(&anchor.successor)
        {
            return Err(denied());
        }
        Ok(self.deadline)
    }
}
impl EndorsementState {
    pub(crate) fn existing_transition(
        &self,
    ) -> Result<Option<Arc<OwnedExistingEnrollmentTransition>>, EngineError> {
        let slot = self.existing.lock().map_err(|_| denied())?;
        Ok(slot.as_ref().filter(|guard| guard.is_live()).cloned())
    }
}
impl<S: StorageProvider> Engine<S> {
    pub fn arm_original_existing_enrollment_transition(
        &self,
        action: &OwnedEnrollmentEndorsement,
        bytes: &[u8],
    ) -> Result<Arc<OwnedExistingEnrollmentTransition>, EngineError> {
        self.validate_owned_private_enrollment_endorsement(action)?;
        let metadata = authenticate_existing_packet(self, bytes)?;
        let packet: Packet = serde_json::from_slice(action.wire()?).map_err(|_| denied())?;
        if metadata.binding != packet.binding_digest
            || metadata.group != action.predecessor.group_id
            || metadata.account.as_slice() != action.predecessor.account.as_slice()
            || metadata.predecessor.epoch != action.predecessor.epoch
            || metadata.predecessor.epoch_authenticator_digest
                != action.predecessor.epoch_authenticator_digest
            || metadata.predecessor.leaves.len() != action.predecessor.leaves.len()
            || !metadata
                .predecessor
                .leaves
                .iter()
                .zip(&action.predecessor.leaves)
                .all(|(a, b)| {
                    a.leaf_index == b.leaf_index
                        && a.signature_public_key.as_slice() == b.signature_public_key
                })
            || !metadata
                .signed_packets
                .iter()
                .any(|wire| wire == &action.wire)
        {
            return Err(denied());
        }
        let mut slot = self
            .enrollment_endorsements
            .existing
            .lock()
            .map_err(|_| denied())?;
        if let Some(existing) = slot.as_ref() {
            if existing.binding() != &metadata.binding || !existing.is_live() {
                return Err(denied());
            }
            return Ok(existing.clone());
        }
        let guard = Arc::new(OwnedExistingEnrollmentTransition {
            owner: action.owner.clone(),
            generation: action.generation,
            deadline: action.deadline,
            local_device: packet.source_signer,
            origin: action.origin.clone(),
            settlement_generation: action.settlement_generation,
            metadata,
        });
        self.validate_owned_private_enrollment_endorsement(action)?;
        *slot = Some(guard.clone());
        Ok(guard)
    }
}
