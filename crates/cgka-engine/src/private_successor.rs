//! Fresh protected private successor evidence; never SDK consent or settlement.
use crate::{Engine, device_group_snapshot::CandidateDeviceGroupSnapshot};
use cgka_traits::private_device_invite::{ConfirmedPrivateInviteFact, PrivateInviteOrigin};
use cgka_traits::private_roster_settlement::PrivateSettlementAnchor;
use cgka_traits::{EngineError, GroupId, storage::StorageProvider};

pub(crate) struct ValidatedPrivateSuccessor {
    candidate: CandidateDeviceGroupSnapshot,
    origin: PrivateInviteOrigin,
    nonce: [u8; 32],
    context_digest: [u8; 32],
    anchor: PrivateSettlementAnchor,
}
impl ValidatedPrivateSuccessor {
    pub(crate) fn settlement_anchor(&self) -> &PrivateSettlementAnchor {
        &self.anchor
    }
    pub(crate) fn candidate(&self) -> &CandidateDeviceGroupSnapshot {
        &self.candidate
    }
    pub(crate) fn matches_confirmed(&self, fact: &ConfirmedPrivateInviteFact) -> bool {
        self.origin == PrivateInviteOrigin::Confirmed(fact.scope.staging_generation)
            && self.nonce == fact.binding.nonce
            && self.context_digest == fact.binding.context_digest
            && self.candidate.group_id == fact.binding.group_id
    }
}
impl<S: StorageProvider> Engine<S> {
    pub(crate) fn validated_private_successor(
        &self,
        group: &GroupId,
    ) -> Result<Option<ValidatedPrivateSuccessor>, EngineError> {
        self.ensure_group_live(group)?;
        self.storage.with_read_snapshot(|storage| {
            let Some(candidate) = self.candidate_device_group_snapshot(group)? else {
                return Ok(None);
            };
            let actual = self.with_mls_group(group, |mls| {
                crate::device_group_lineage::AppliedPrivateTree::read(group, mls)
            })?;
            let Some(actual) = actual else {
                return Ok(None);
            };
            let accepted = storage
                .accepted_device_group_anchor_storage()
                .map(|store| store.accepted_anchor())
                .transpose()
                .map_err(|error| match error {
                    cgka_traits::accepted_device_group_anchor::AnchorError::Storage(error) => {
                        EngineError::Storage(error)
                    }
                    _ => EngineError::Other("private successor anchor read failed".into()),
                })?
                .flatten()
                .filter(|fact| {
                    !fact.denied
                        && fact.scope.selection_generation != 0
                        && fact.draft.group_id == *group
                        && actual.matches(
                            &fact.scope.account,
                            &fact.scope.local_device,
                            &fact.draft.successor,
                        )
                });
            let confirmed = storage
                .private_device_invite_storage()
                .map(|store| store.confirmed_private_invite())
                .transpose()
                .map_err(|error| match error {
                    cgka_traits::private_device_invite::PrivateInviteStorageError::Storage(
                        error,
                    ) => EngineError::Storage(error),
                    _ => EngineError::Other("private successor confirmation read failed".into()),
                })?
                .flatten()
                .filter(|fact| {
                    !fact.denied
                        && fact.scope.staging_generation != 0
                        && fact.binding.group_id == *group
                        && actual.matches(
                            &fact.scope.account,
                            &fact.scope.local_device,
                            &fact.binding.successor,
                        )
                });
            // Each genuine successor has one protected local origin. Conflicting
            // matching origins cannot choose their authority by precedence.
            let anchor = match (accepted, confirmed) {
                (Some(fact), None) => PrivateSettlementAnchor {
                    origin: PrivateInviteOrigin::Accepted(fact.scope.selection_generation),
                    account: fact.scope.account,
                    local_device: fact.scope.local_device,
                    group_id: group.clone(),
                    successor: fact.draft.successor,
                    roster_commitment: candidate.roster_commitment,
                    enrollment_nonce: fact.draft.nonce,
                    context_digest: fact.draft.context_digest,
                    coordinator: fact.draft.approver,
                },
                (None, Some(fact)) => PrivateSettlementAnchor {
                    origin: PrivateInviteOrigin::Confirmed(fact.scope.staging_generation),
                    account: fact.scope.account,
                    local_device: fact.scope.local_device,
                    group_id: group.clone(),
                    successor: fact.binding.successor,
                    roster_commitment: candidate.roster_commitment,
                    enrollment_nonce: fact.binding.nonce,
                    context_digest: fact.binding.context_digest,
                    coordinator: fact.binding.approver_scope.local_device,
                },
                _ => return Ok(None),
            };
            Ok(Some(ValidatedPrivateSuccessor {
                candidate,
                origin: anchor.origin.clone(),
                nonce: anchor.enrollment_nonce,
                context_digest: anchor.context_digest,
                anchor,
            }))
        })
    }
}

/// Protected origin and full actual-tree check for selected apply. This does
/// not depend on candidate stability: canonical apply owns its convergence SQL
/// unit and validates local stability before exposing a completed roster.
pub(crate) fn anchor_matches_actual_tree<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    group: &openmls::group::MlsGroup,
    anchor: &PrivateSettlementAnchor,
) -> Result<bool, EngineError> {
    if anchor.group_id != *group_id {
        return Ok(false);
    }
    let Some(actual) = crate::device_group_lineage::AppliedPrivateTree::read(group_id, group)?
    else {
        return Ok(false);
    };
    if !actual.matches(&anchor.account, &anchor.local_device, &anchor.successor) {
        return Ok(false);
    }
    let accepted = storage
        .accepted_device_group_anchor_storage()
        .map(|store| store.accepted_anchor())
        .transpose()
        .map_err(|error| match error {
            cgka_traits::accepted_device_group_anchor::AnchorError::Storage(error) => {
                EngineError::Storage(error)
            }
            _ => EngineError::Other("private successor anchor read failed".into()),
        })?
        .flatten()
        .filter(|fact| {
            !fact.denied
                && fact.scope.selection_generation != 0
                && fact.draft.group_id == *group_id
                && actual.matches(
                    &fact.scope.account,
                    &fact.scope.local_device,
                    &fact.draft.successor,
                )
        });
    let confirmed = storage
        .private_device_invite_storage()
        .map(|store| store.confirmed_private_invite())
        .transpose()
        .map_err(|error| match error {
            cgka_traits::private_device_invite::PrivateInviteStorageError::Storage(error) => {
                EngineError::Storage(error)
            }
            _ => EngineError::Other("private successor confirmation read failed".into()),
        })?
        .flatten()
        .filter(|fact| {
            !fact.denied
                && fact.scope.staging_generation != 0
                && fact.binding.group_id == *group_id
                && actual.matches(
                    &fact.scope.account,
                    &fact.scope.local_device,
                    &fact.binding.successor,
                )
        });
    // The same ambiguity rule as fresh Engine evidence: no precedence grant.
    let matches = match (accepted, confirmed) {
        (Some(fact), None) => {
            anchor.origin == PrivateInviteOrigin::Accepted(fact.scope.selection_generation)
                && anchor.account == fact.scope.account
                && anchor.local_device == fact.scope.local_device
                && anchor.successor == fact.draft.successor
                && anchor.enrollment_nonce == fact.draft.nonce
                && anchor.context_digest == fact.draft.context_digest
                && anchor.coordinator == fact.draft.approver
        }
        (None, Some(fact)) => {
            anchor.origin == PrivateInviteOrigin::Confirmed(fact.scope.staging_generation)
                && anchor.account == fact.scope.account
                && anchor.local_device == fact.scope.local_device
                && anchor.successor == fact.binding.successor
                && anchor.enrollment_nonce == fact.binding.nonce
                && anchor.context_digest == fact.binding.context_digest
                && anchor.coordinator == fact.binding.approver_scope.local_device
        }
        _ => false,
    };
    if !matches {
        return Ok(false);
    }
    let candidate = crate::device_group_snapshot::CandidateDeviceGroupSnapshot {
        account: cgka_traits::MemberId::new(anchor.account.to_vec()),
        group_id: group_id.clone(),
        epoch: anchor.successor.epoch,
        epoch_authenticator_digest: anchor.successor.epoch_authenticator_digest,
        leaves: anchor
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
    Ok(crate::device_group_snapshot::commitment(&candidate) == anchor.roster_commitment)
}

#[cfg(test)]
#[path = "private_successor_tests.rs"]
pub(crate) mod tests;
