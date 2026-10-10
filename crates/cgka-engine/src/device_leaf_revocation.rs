//! Fresh exact occupied-leaf selection. Observations do not authorize a Remove.
use crate::{Engine, device_group_snapshot::CandidateDeviceGroupSnapshot};
use cgka_traits::{
    EngineError, GroupId, GroupLifecycleState, group::ProtocolProfile, storage::StorageProvider,
};
use sha2::{Digest, Sha256};
use std::sync::Weak;

pub(crate) mod transition;
pub use transition::{DeviceRevocationSettlementControl, TrustedDeviceRevocationTransitionLease};

fn unavailable() -> EngineError {
    EngineError::Other("original device leaf selection unavailable".into())
}

/// Read-only authenticated administrator review, never a serialized grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceLeafRevocationReview {
    pub group: GroupId,
    pub epoch: u64,
    pub target_leaf_index: u32,
    pub target_device: Vec<u8>,
    pub surviving_same_account_leaves: u32,
}

/// Core-captured metadata tied to one originating Engine. No constructor or serde.
pub struct DeviceLeafRevocationSelection {
    owner: Weak<crate::private_enrollment_endorsement::Lifetime>,
    protected: CandidateDeviceGroupSnapshot,
    protected_generation: u64,
    authenticator: [u8; 32],
    leaves: Vec<crate::selected_chat_consent::IndexedOrdinaryLeaf>,
    review: DeviceLeafRevocationReview,
    protected_remove: bool,
}
impl DeviceLeafRevocationSelection {
    pub fn review(&self) -> &DeviceLeafRevocationReview {
        &self.review
    }
    pub fn is_protected_group(&self) -> bool {
        self.protected_remove
    }
}

/// Bounded fresh roster observations, never a captured removal action.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceRevocationTarget {
    pub leaf_index: u32,
    pub device: Vec<u8>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceRevocationTargets {
    pub protected_group: GroupId,
    pub protected_epoch: u64,
    pub targets: Vec<DeviceRevocationTarget>,
}
impl std::fmt::Debug for DeviceRevocationTargets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRevocationTargets")
            .field("targets", &self.targets.len())
            .finish_non_exhaustive()
    }
}

impl<S: StorageProvider> Engine<S> {
    /// Observe current protected devices independently of ordinary chat admission.
    pub fn device_revocation_targets(&self) -> Result<DeviceRevocationTargets, EngineError> {
        self.storage.with_read_snapshot(|storage| {
            let round = storage
                .private_roster_settlement_storage()
                .ok_or_else(unavailable)?
                .read_round()?
                .ok_or_else(unavailable)?;
            let actual = self
                .validated_settled_device_roster(&round.anchor.group_id)?
                .ok_or_else(unavailable)?;
            let protected = actual.candidate();
            self.ensure_group_live(&protected.group_id)?;
            let record = self.group_record(&protected.group_id)?;
            let authority = self.group_authority(&protected.group_id)?;
            let signer = self.identity.signer.public();
            if protected.account != *self.identity.self_id()
                || protected.leaves.len() > 128
                || record.protocol_profile != ProtocolProfile::Current
                || record.removed
                || record.unrecoverable
                || record.disbanded.is_some()
                || authority.lifecycle != GroupLifecycleState::Stable
                || authority.disbanding
                || !authority.facts.is_admin
                || !authority.facts.is_member
                || !protected
                    .leaves
                    .iter()
                    .any(|leaf| leaf.signature_public_key == signer)
            {
                return Err(unavailable());
            }
            let mut targets: Vec<_> = protected
                .leaves
                .iter()
                .filter(|leaf| leaf.signature_public_key != signer)
                .map(|leaf| DeviceRevocationTarget {
                    leaf_index: leaf.leaf_index,
                    device: leaf.signature_public_key.clone(),
                })
                .collect();
            targets.sort_unstable_by_key(|target| target.leaf_index);
            Ok(DeviceRevocationTargets {
                protected_group: protected.group_id.clone(),
                protected_epoch: protected.epoch.0,
                targets,
            })
        })
    }

    pub fn capture_device_leaf_revocation_selection(
        &self,
        group: &GroupId,
        target_device: &[u8],
    ) -> Result<DeviceLeafRevocationSelection, EngineError> {
        self.capture_device_leaf_revocation_selection_for_role(group, target_device, false)
    }

    /// Capture the complete locally authenticated scope, with protected removal
    /// last. No caller supplies a group list or reconstructs a selection.
    pub fn capture_device_revocation_selections(
        &self,
        target_device: &[u8],
    ) -> Result<Vec<DeviceLeafRevocationSelection>, EngineError> {
        self.storage.with_read_snapshot(|storage| {
            let round = storage
                .private_roster_settlement_storage()
                .ok_or_else(unavailable)?
                .read_round()?
                .ok_or_else(unavailable)?;
            let protected = self.capture_device_leaf_revocation_selection_for_role(
                &round.anchor.group_id,
                target_device,
                true,
            )?;
            let groups = storage.list_groups()?;
            if groups.len() > 128 {
                return Err(unavailable());
            }
            let mut selections = Vec::new();
            for group in groups {
                if group == protected.review.group {
                    continue;
                }
                let record = self.group_record(&group)?;
                if record.removed || record.disbanded.is_some() {
                    continue;
                }
                let leaves = self.selected_indexed_ordinary_leaves(&group)?;
                if leaves.iter().any(|leaf| leaf.signer == target_device) {
                    selections.push(
                        self.capture_device_leaf_revocation_selection(&group, target_device)?,
                    );
                }
            }
            selections.sort_by(|a, b| a.review.group.as_slice().cmp(b.review.group.as_slice()));
            selections.push(protected);
            Ok(selections)
        })
    }

    fn capture_device_leaf_revocation_selection_for_role(
        &self,
        group: &GroupId,
        target_device: &[u8],
        protected_remove: bool,
    ) -> Result<DeviceLeafRevocationSelection, EngineError> {
        self.ensure_group_live(group)?;
        if group.as_slice().is_empty() || group.as_slice().len() > 256 || target_device.len() != 32
        {
            return Err(unavailable());
        }
        self.storage.with_read_snapshot(|storage| {
            // A retained round identifies where to read actual protected state;
            // its fields cannot substitute for fresh lineage/full-tree validation.
            let round = storage
                .private_roster_settlement_storage()
                .ok_or_else(unavailable)?
                .read_round()?
                .ok_or_else(unavailable)?;
            let settled = self
                .validated_settled_device_roster(&round.anchor.group_id)?
                .ok_or_else(unavailable)?;
            let protected = settled.candidate();
            let signer = self.identity.signer.public();
            if protected.account != *self.identity.self_id()
                || !protected
                    .leaves
                    .iter()
                    .any(|leaf| leaf.signature_public_key == signer)
                || !protected
                    .leaves
                    .iter()
                    .any(|leaf| leaf.signature_public_key == target_device)
                || signer == target_device
                || (group == &protected.group_id) != protected_remove
            {
                return Err(unavailable());
            }
            let record = self.group_record(group)?;
            let authority = self.group_authority(group)?;
            if record.protocol_profile != ProtocolProfile::Current
                || authority.lifecycle != GroupLifecycleState::Stable
                || authority.disbanding
                || !authority.facts.is_admin
                || !authority.facts.is_member
                || record.removed
                || record.unrecoverable
                || record.disbanded.is_some()
                || self.pending_convergence_groups.contains(group)
                || storage
                    .convergence_pass(group)?
                    .is_some_and(|pass| pass.is_active())
                || !storage.list_queued_outbound_intents(group)?.is_empty()
            {
                return Err(unavailable());
            }
            let own_index = self.do_own_leaf_index(group)?;
            let leaves = self.selected_indexed_ordinary_leaves(group)?;
            if !leaves.iter().any(|leaf| {
                leaf.index == own_index
                    && leaf.account == self.identity.self_id().as_slice()
                    && leaf.signer == signer
            }) {
                return Err(unavailable());
            }
            let target = leaves
                .iter()
                .find(|leaf| leaf.signer == target_device)
                .ok_or_else(unavailable)?;
            if target.index == own_index || target.account != self.identity.self_id().as_slice() {
                return Err(unavailable());
            }
            let surviving_same_account_leaves = u32::try_from(
                leaves
                    .iter()
                    .filter(|leaf| leaf.account == target.account && leaf.index != target.index)
                    .count(),
            )
            .map_err(|_| unavailable())?;
            let authenticator = self.with_mls_group(group, |actual| {
                if !actual.is_active()
                    || actual.pending_commit().is_some()
                    || actual.epoch().as_u64() != authority.facts.epoch.0
                    || crate::account_identity_proof::protocol_profile_of_group(actual)?
                        != ProtocolProfile::Current
                    || crate::device_group_genesis::has_private_component(actual)?
                        != protected_remove
                {
                    return Err(unavailable());
                }
                crate::app_components::require_admin(actual, group, self.identity.self_id())?;
                Ok::<_, EngineError>(Sha256::digest(actual.epoch_authenticator().as_slice()).into())
            })?;
            Ok(DeviceLeafRevocationSelection {
                owner: self.enrollment_endorsements.owner_lifetime(),
                protected: protected.clone(),
                protected_generation: settled.settlement_generation(),
                authenticator,
                review: DeviceLeafRevocationReview {
                    group: group.clone(),
                    epoch: authority.facts.epoch.0,
                    target_leaf_index: target.index,
                    target_device: target.signer.clone(),
                    surviving_same_account_leaves,
                },
                leaves,
                protected_remove,
            })
        })
    }

    pub fn validate_device_leaf_revocation_selection(
        &self,
        original: &DeviceLeafRevocationSelection,
    ) -> Result<(), EngineError> {
        if !self.enrollment_endorsements.owns_lifetime(&original.owner)
            || !original
                .owner
                .upgrade()
                .is_some_and(|owner| owner.is_open())
        {
            return Err(unavailable());
        }
        let fresh = self.capture_device_leaf_revocation_selection_for_role(
            &original.review.group,
            &original.review.target_device,
            original.protected_remove,
        )?;
        if fresh.protected != original.protected
            || fresh.protected_generation != original.protected_generation
            || fresh.authenticator != original.authenticator
            || fresh.leaves != original.leaves
            || fresh.review != original.review
        {
            return Err(unavailable());
        }
        Ok(())
    }
}

/// Trusted process owner checks the original review, fixed deadline and explicit
/// displayed revision. Neither a target signer nor a stored review supplies it.
pub trait DeviceLeafRevocationLease: Send {
    fn transition_lease(
        &self,
    ) -> Option<std::sync::Arc<dyn TrustedDeviceRevocationTransitionLease>> {
        None
    }
    fn check_original(
        &mut self,
        original: &DeviceLeafRevocationSelection,
    ) -> Result<(), EngineError>;
}

impl<S: StorageProvider> Engine<S> {
    fn check_device_leaf_revocation_context(
        &self,
        original: &DeviceLeafRevocationSelection,
    ) -> Result<(), EngineError> {
        self.ensure_group_live(&original.review.group)?;
        if !self.enrollment_endorsements.owns_lifetime(&original.owner)
            || !original
                .owner
                .upgrade()
                .is_some_and(|owner| owner.is_open())
        {
            return Err(unavailable());
        }
        if original.protected_remove {
            // A pending protected Remove still has the exact predecessor tree.
            // Only this original memory-owned action may use its completed
            // predecessor facts; public settled/capture APIs remain unchanged.
            self.with_mls_group(&original.review.group, |actual| {
                let round = crate::private_roster_settlement::completed_round_for_predecessor_tree(
                    &self.storage,
                    &original.review.group,
                    actual,
                )?
                .ok_or_else(unavailable)?;
                if round.generation != original.protected_generation {
                    return Err(unavailable());
                }
                Ok(())
            })?;
        } else {
            let settled = self
                .validated_settled_device_roster(&original.protected.group_id)?
                .ok_or_else(unavailable)?;
            if settled.candidate() != &original.protected
                || settled.settlement_generation() != original.protected_generation
            {
                return Err(unavailable());
            }
        }
        let group = &original.review.group;
        let record = self.group_record(group)?;
        if record.removed
            || record.unrecoverable
            || record.disbanded.is_some()
            || record.protocol_profile != ProtocolProfile::Current
            || self.pending_convergence_groups.contains(group)
            || self
                .storage
                .convergence_pass(group)?
                .is_some_and(|pass| pass.is_active())
            || !self.storage.list_queued_outbound_intents(group)?.is_empty()
            || self.selected_indexed_ordinary_leaves(group)? != original.leaves
        {
            return Err(unavailable());
        }
        self.with_mls_group(group, |actual| {
            crate::app_components::require_admin(actual, group, self.identity.self_id())?;
            let authenticator: [u8; 32] =
                Sha256::digest(actual.epoch_authenticator().as_slice()).into();
            if !actual.is_active()
                || actual.epoch().as_u64() != original.review.epoch
                || authenticator != original.authenticator
                || crate::account_identity_proof::protocol_profile_of_group(actual)?
                    != ProtocolProfile::Current
                || crate::device_group_genesis::has_private_component(actual)?
                    != original.protected_remove
            {
                return Err(unavailable());
            }
            Ok(())
        })
    }

    fn check_device_leaf_revocation_successor(
        &self,
        original: &DeviceLeafRevocationSelection,
        actual: &[crate::selected_chat_consent::IndexedOrdinaryLeaf],
        epoch: u64,
    ) -> Result<(), EngineError> {
        if original.review.epoch.checked_add(1) != Some(epoch)
            || actual.len().checked_add(1) != Some(original.leaves.len())
            || actual.iter().any(|leaf| {
                leaf.index == original.review.target_leaf_index
                    || leaf.signer == original.review.target_device
            })
        {
            return Err(unavailable());
        }
        let source = self.identity.signer.public();
        for old in &original.leaves {
            if old.index == original.review.target_leaf_index {
                continue;
            }
            let new = actual
                .iter()
                .find(|leaf| leaf.index == old.index)
                .ok_or_else(unavailable)?;
            if new.account != old.account
                || new.signer != old.signer
                || (old.signer != source && new.hash != old.hash)
            {
                return Err(unavailable());
            }
        }
        Ok(())
    }

    pub async fn prepare_device_leaf_revocation(
        &mut self,
        original: &DeviceLeafRevocationSelection,
        lease: &mut dyn DeviceLeafRevocationLease,
    ) -> Result<cgka_traits::SendResult, EngineError> {
        self.validate_device_leaf_revocation_selection(original)?;
        lease.check_original(original)?;
        let mut check = |engine: &Self| {
            engine.check_device_leaf_revocation_context(original)?;
            lease.check_original(original)
        };
        let result = self
            .do_send_remove_members_with_guard(
                original.review.group.clone(),
                vec![self.identity.self_id().clone()],
                Some(original.review.target_leaf_index),
                Some(&mut check),
            )
            .await?;
        let cgka_traits::SendResult::GroupEvolution {
            pending,
            msg,
            welcomes,
        } = &result
        else {
            return Err(unavailable());
        };
        let verified = if welcomes.is_empty() {
            self.validate_prepared_device_leaf_revocation(original, *pending, &msg.id)
                .and_then(|()| lease.check_original(original))
        } else {
            Err(unavailable())
        };
        if let Err(error) = verified {
            self.do_publish_failed(*pending).await?;
            return Err(error);
        }
        let transition_capture = (|| -> Result<(), EngineError> {
            if original.protected_remove {
                let transition = lease.transition_lease().ok_or_else(unavailable)?;
                transition.check_original(original)?;
                let group = openmls::group::MlsGroup::load(
                    self.storage.mls_storage(),
                    &openmls::group::GroupId::from_slice(original.review.group.as_slice()),
                )
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
                let digest =
                    crate::openmls_projection::own_commit_message_digest(&self.storage, &msg.id)?;
                self.revocation_transition
                    .capture(
                        &self.storage,
                        &original.review.group,
                        &group,
                        group.pending_commit().ok_or_else(unavailable)?,
                        group.own_leaf_index(),
                        digest,
                        Some(transition),
                    )?
                    .ok_or_else(unavailable)?;
            }
            Ok(())
        })();
        if let Err(error) = transition_capture {
            self.do_publish_failed(*pending).await?;
            return Err(error);
        }
        Ok(result)
    }

    pub fn validate_prepared_device_leaf_revocation(
        &self,
        original: &DeviceLeafRevocationSelection,
        pending: cgka_traits::PendingStateRef,
        origin: &cgka_traits::MessageId,
    ) -> Result<(), EngineError> {
        self.check_device_leaf_revocation_context(original)?;
        if self.pending_origin_message_id(pending)? != *origin {
            return Err(unavailable());
        }
        let group = openmls::group::MlsGroup::load(
            self.storage.mls_storage(),
            &openmls::group::GroupId::from_slice(original.review.group.as_slice()),
        )
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
        let staged = group.pending_commit().ok_or_else(unavailable)?;
        let proposals = staged.queued_proposals().collect::<Vec<_>>();
        if proposals.len() != 1
            || !matches!(proposals[0].proposal(),
            openmls::prelude::Proposal::Remove(remove) if remove.removed().u32() == original.review.target_leaf_index)
        {
            return Err(unavailable());
        }
        let tree = staged
            .export_ratchet_tree(&self.crypto, group.export_ratchet_tree())
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        self.check_device_leaf_revocation_successor(
            original,
            &crate::selected_chat_consent::invite::indexed_tree(tree)?,
            staged.epoch().as_u64(),
        )
    }

    /// Negative pending retirement shares only the purpose-neutral exact own
    /// origin classifier. It cannot authorize a selected Invite or any Remove.
    pub async fn retire_device_leaf_revocation_pending(
        &mut self,
        pending: cgka_traits::PendingStateRef,
        origin: &cgka_traits::MessageId,
        group: &GroupId,
    ) -> Result<(), EngineError> {
        self.retire_selected_chat_pending(pending, origin, group)
            .await
    }
    pub fn confirmed_device_leaf_revocation(
        &self,
        original: &DeviceLeafRevocationSelection,
    ) -> Result<(), EngineError> {
        self.ensure_group_live(&original.review.group)?;
        if !self.enrollment_endorsements.owns_lifetime(&original.owner)
            || !original
                .owner
                .upgrade()
                .is_some_and(|owner| owner.is_open())
        {
            return Err(unavailable());
        }
        if !original.protected_remove {
            let settled = self
                .validated_settled_device_roster(&original.protected.group_id)?
                .ok_or_else(unavailable)?;
            if settled.candidate() != &original.protected
                || settled.settlement_generation() != original.protected_generation
            {
                return Err(unavailable());
            }
        } else {
            self.check_retired_device_revocation_roster(original)?;
        }
        self.check_confirmed_device_leaf_tree(original)
    }

    fn check_retired_device_revocation_roster(
        &self,
        original: &DeviceLeafRevocationSelection,
    ) -> Result<(), EngineError> {
        let round = self
            .storage
            .private_roster_settlement_storage()
            .ok_or_else(unavailable)?
            .read_round()?
            .ok_or_else(unavailable)?;
        if original.protected_remove
            && round.generation > original.protected_generation
            && round.anchor.group_id == original.protected.group_id
            && round.phase != cgka_traits::private_roster_settlement::PrivateSettlementPhase::Denied
        {
            let fact = self
                .storage
                .revoked_device_group_anchor_storage()
                .ok_or_else(unavailable)?
                .revoked_anchor()?
                .ok_or_else(unavailable)?;
            if !fact.denied
                && round.anchor.origin
                    == cgka_traits::private_device_invite::PrivateInviteOrigin::Revoked(
                        fact.generation,
                    )
                && fact.draft.predecessor_settlement_generation == original.protected_generation
                && fact.draft.group_id == original.review.group
                && fact.draft.removed_leaf_index == original.review.target_leaf_index
                && fact.draft.removed_device.as_slice() == original.review.target_device
                && fact.draft.predecessor.epoch == original.protected.epoch
                && fact.draft.predecessor.epoch_authenticator_digest
                    == original.protected.epoch_authenticator_digest
                && round.anchor.successor == fact.draft.successor
            {
                self.check_confirmed_device_leaf_tree(original)?;
                return Ok(());
            }
        }
        if !original.protected_remove
            || round.generation != original.protected_generation
            || round.anchor.group_id != original.protected.group_id
            || round.phase != cgka_traits::private_roster_settlement::PrivateSettlementPhase::Denied
        {
            return Err(unavailable());
        }
        Ok(())
    }

    /// Completion is an observation of exact committed successor trees and
    /// retired old protected authority. It cannot authorize later enrollment.
    pub fn confirmed_device_revocation_scope(
        &self,
        originals: &[&DeviceLeafRevocationSelection],
    ) -> Result<(), EngineError> {
        let protected = originals.last().ok_or_else(unavailable)?;
        self.check_retired_device_revocation_roster(protected)?;
        for original in originals {
            if !self.enrollment_endorsements.owns_lifetime(&original.owner)
                || !original
                    .owner
                    .upgrade()
                    .is_some_and(|owner| owner.is_open())
                || original.protected != protected.protected
                || original.protected_generation != protected.protected_generation
            {
                return Err(unavailable());
            }
            self.check_confirmed_device_leaf_tree(original)?;
        }
        Ok(())
    }

    fn check_confirmed_device_leaf_tree(
        &self,
        original: &DeviceLeafRevocationSelection,
    ) -> Result<(), EngineError> {
        let epoch = self.with_mls_group(&original.review.group, |group| {
            crate::app_components::require_admin(
                group,
                &original.review.group,
                self.identity.self_id(),
            )?;
            if !group.is_active()
                || group.pending_commit().is_some()
                || crate::account_identity_proof::protocol_profile_of_group(group)?
                    != ProtocolProfile::Current
                || crate::device_group_genesis::has_private_component(group)?
                    != original.protected_remove
            {
                return Err(unavailable());
            }
            Ok(group.epoch().as_u64())
        })?;
        self.check_device_leaf_revocation_successor(
            original,
            &self.selected_indexed_ordinary_leaves(&original.review.group)?,
            epoch,
        )
    }
}
