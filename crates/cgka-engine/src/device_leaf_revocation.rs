//! Fresh exact occupied-leaf selection. Observations do not authorize a Remove.
use crate::{Engine, device_group_snapshot::CandidateDeviceGroupSnapshot};
use cgka_traits::{
    EngineError, GroupId, GroupLifecycleState, group::ProtocolProfile, storage::StorageProvider,
};
use sha2::{Digest, Sha256};
use std::sync::Weak;

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
}
impl DeviceLeafRevocationSelection {
    pub fn review(&self) -> &DeviceLeafRevocationReview {
        &self.review
    }
}

impl<S: StorageProvider> Engine<S> {
    pub fn capture_device_leaf_revocation_selection(
        &self,
        group: &GroupId,
        target_device: &[u8],
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
                || group == &protected.group_id
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
        let fresh = self.capture_device_leaf_revocation_selection(
            &original.review.group,
            &original.review.target_device,
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
