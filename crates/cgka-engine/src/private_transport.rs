//! Protected current-group metadata for one hidden transport subscription.
//! This is neither consent nor settled roster evidence. Pending publication may
//! retain a subscription only to reconcile its actual authenticated own echo.
use crate::{Engine, device_group_lineage::AppliedPrivateTree};
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::private_device_invite::{PrivateInviteOrigin, PrivateInvitePhase};
use cgka_traits::{AppComponentId, EngineError, GroupId, storage::StorageProvider};

/// Fresh protected crypto metadata. Never a publishing or enrollment grant.
pub struct PrivateTransportEvidence {
    group: GroupId,
    component: Vec<u8>,
}
impl PrivateTransportEvidence {
    pub fn group_id(&self) -> &GroupId {
        &self.group
    }
    pub fn component(&self) -> &[u8] {
        &self.component
    }
}

impl<S: StorageProvider> Engine<S> {
    /// Negative presentation classification only. Historical private provenance
    /// suppresses projection after removal/invalidation; it never admits a leaf,
    /// selects a route or restores consent. Backend errors must remain retryable.
    pub fn exclude_private_group_from_chat(&self, group_id: &GroupId) -> Result<bool, EngineError> {
        self.storage.with_read_snapshot(|storage| {
            if let Some(store) = storage.private_group_privacy_storage() {
                let account: [u8; 32] =
                    self.identity.self_id().as_slice().try_into().map_err(|_| {
                        EngineError::Other("private presentation identity unavailable".into())
                    })?;
                let device: [u8; 32] = self.identity.signer.public().try_into().map_err(|_| {
                    EngineError::Other("private presentation identity unavailable".into())
                })?;
                if store.private_group_chat_excluded(&account, &device, group_id)? {
                    return Ok(true);
                }
            }
            if let Some(store) = storage.device_group_genesis_storage()
                && store
                    .genesis_selection()
                    .map_err(|error| match error {
                        cgka_traits::device_group_genesis::GenesisError::Storage(error) => {
                            EngineError::Storage(error)
                        }
                        _ => EngineError::Other(
                            "private presentation classification unavailable".into(),
                        ),
                    })?
                    .is_some_and(|row| row.fact.birth.group_id == *group_id)
            {
                return Ok(true);
            }
            if let Some(store) = storage.accepted_device_group_anchor_storage()
                && store
                    .accepted_anchor()
                    .map_err(|error| match error {
                        cgka_traits::accepted_device_group_anchor::AnchorError::Storage(error) => {
                            EngineError::Storage(error)
                        }
                        _ => EngineError::Other(
                            "private presentation classification unavailable".into(),
                        ),
                    })?
                    .is_some_and(|row| row.draft.group_id == *group_id)
            {
                return Ok(true);
            }
            if let Some(store) = storage.existing_device_group_anchor_storage()
                && store
                    .existing_anchor()?
                    .is_some_and(|row| row.draft.group_id == *group_id)
            {
                return Ok(true);
            }
            if let Some(store) = storage.private_device_invite_storage() {
                let convert = |error| match error {
                    cgka_traits::private_device_invite::PrivateInviteStorageError::Storage(
                        error,
                    ) => EngineError::Storage(error),
                    _ => {
                        EngineError::Other("private presentation classification unavailable".into())
                    }
                };
                if store
                    .private_invite()
                    .map_err(convert)?
                    .is_some_and(|row| row.raw.binding.group_id == *group_id)
                    || store
                        .confirmed_private_invite()
                        .map_err(convert)?
                        .is_some_and(|row| row.binding.group_id == *group_id)
                {
                    return Ok(true);
                }
            }
            match self.with_mls_group(group_id, crate::device_group_genesis::exact_profile) {
                Err(error @ EngineError::UnknownGroup(_)) => match storage.get_group(group_id) {
                    // Disband deletes MLS but retains its authenticated canonical
                    // capabilities. Historical privacy fences above still win,
                    // including a private marker removed before termination.
                    Ok(record) if record.disbanded.is_some() => {
                        Ok(record.required_capabilities.app_components.contains(
                            cgka_traits::device_group_genesis::PRIVATE_DEVICE_GROUP_COMPONENT_ID,
                        ))
                    }
                    Ok(_) | Err(cgka_traits::storage::StorageError::NotFound) => Err(error),
                    Err(error) => Err(EngineError::Storage(error)),
                },
                result => result,
            }
        })
    }

    /// Validate one selected private tree and component in a single read unit.
    /// Denial rows never authorize a route. Unknown pending work retains only
    /// the subscription needed for authenticated reconciliation, not consent.
    pub fn private_transport_evidence(
        &self,
        component: AppComponentId,
    ) -> Result<Option<PrivateTransportEvidence>, EngineError> {
        self.storage.with_read_snapshot(|storage| {
            let Some(genesis_store) = storage.device_group_genesis_storage() else {
                return Ok(None);
            };
            let Some(accepted_store) = storage.accepted_device_group_anchor_storage() else {
                return Ok(None);
            };
            let Some(invite_store) = storage.private_device_invite_storage() else {
                return Ok(None);
            };
            let genesis = genesis_store
                .genesis_selection()
                .map_err(|error| match error {
                    cgka_traits::device_group_genesis::GenesisError::Storage(error) => {
                        EngineError::Storage(error)
                    }
                    _ => EngineError::Other("private route provenance unavailable".into()),
                })?;
            let accepted = accepted_store
                .accepted_anchor()
                .map_err(|error| match error {
                    cgka_traits::accepted_device_group_anchor::AnchorError::Storage(error) => {
                        EngineError::Storage(error)
                    }
                    _ => EngineError::Other("private route provenance unavailable".into()),
                })?;
            let ledger_error = |error| match error {
                cgka_traits::private_device_invite::PrivateInviteStorageError::Storage(error) => {
                    EngineError::Storage(error)
                }
                _ => EngineError::Other("private route provenance unavailable".into()),
            };
            let confirmed = invite_store
                .confirmed_private_invite()
                .map_err(ledger_error)?;
            let pending = invite_store.private_invite().map_err(ledger_error)?;
            let existing = storage
                .existing_device_group_anchor_storage()
                .map(|store| store.existing_anchor())
                .transpose()?
                .flatten();
            let birth_roster = |birth: &cgka_traits::device_group_genesis::GenesisBirthDraft| {
                DeviceGroupAnchorRoster {
                    epoch: birth.epoch,
                    epoch_authenticator_digest: birth.epoch_authenticator_digest,
                    leaves: birth.leaves.clone(),
                }
            };
            let active_pending = pending.as_ref().filter(|fact| {
                matches!(
                    fact.phase,
                    PrivateInvitePhase::RawStaged
                        | PrivateInvitePhase::Wrapped
                        | PrivateInvitePhase::Dispatching
                        | PrivateInvitePhase::PublicationUnknown
                )
            });
            let (group_id, account, signer, roster) = if let Some(fact) = active_pending {
                let binding = &fact.raw.binding;
                let protected = match binding.origin {
                    PrivateInviteOrigin::Genesis(generation) => {
                        genesis.as_ref().is_some_and(|row| {
                            !row.active_denied
                                && row.fact.scope.selection_generation == generation
                                && row.fact.scope.account == fact.scope.account
                                && row.fact.scope.local_device == fact.scope.local_device
                                && row.fact.birth.group_id == binding.group_id
                                && birth_roster(&row.fact.birth) == binding.predecessor
                        })
                    }
                    PrivateInviteOrigin::Accepted(generation) => {
                        accepted.as_ref().is_some_and(|row| {
                            !row.denied
                                && row.scope.selection_generation == generation
                                && row.scope.account == fact.scope.account
                                && row.scope.local_device == fact.scope.local_device
                                && row.draft.group_id == binding.group_id
                                && row.draft.successor == binding.predecessor
                        })
                    }
                    PrivateInviteOrigin::Confirmed(generation) => {
                        confirmed.as_ref().is_some_and(|row| {
                            !row.denied
                                && row.scope.staging_generation == generation
                                && row.scope.account == fact.scope.account
                                && row.scope.local_device == fact.scope.local_device
                                && row.binding.group_id == binding.group_id
                                && row.binding.successor == binding.predecessor
                        })
                    }
                    PrivateInviteOrigin::Existing(generation) => {
                        existing.as_ref().is_some_and(|row| {
                            !row.denied
                                && row.generation == generation
                                && row.draft.account == fact.scope.account
                                && row.draft.local_device == fact.scope.local_device
                                && row.draft.group_id == binding.group_id
                                && row.draft.successor == binding.predecessor
                        })
                    }
                };
                if !protected {
                    return Ok(None);
                }
                (
                    binding.group_id.clone(),
                    fact.scope.account,
                    fact.scope.local_device,
                    binding.predecessor.clone(),
                )
            } else if let Some(row) = existing.as_ref().filter(|row| !row.denied) {
                // Conflicting live origins cannot choose a route by precedence.
                if confirmed.as_ref().is_some_and(|v| !v.denied)
                    || accepted.as_ref().is_some_and(|v| !v.denied)
                    || genesis.as_ref().is_some_and(|v| !v.active_denied)
                {
                    return Ok(None);
                }
                (
                    row.draft.group_id.clone(),
                    row.draft.account,
                    row.draft.local_device,
                    row.draft.successor.clone(),
                )
            } else if let Some(row) = confirmed.as_ref().filter(|row| !row.denied) {
                (
                    row.binding.group_id.clone(),
                    row.scope.account,
                    row.scope.local_device,
                    row.binding.successor.clone(),
                )
            } else if let Some(row) = accepted.as_ref().filter(|row| !row.denied) {
                (
                    row.draft.group_id.clone(),
                    row.scope.account,
                    row.scope.local_device,
                    row.draft.successor.clone(),
                )
            } else if let Some(row) = genesis.as_ref().filter(|row| !row.active_denied) {
                (
                    row.fact.birth.group_id.clone(),
                    row.fact.scope.account,
                    row.fact.scope.local_device,
                    birth_roster(&row.fact.birth),
                )
            } else {
                return Ok(None);
            };
            if account.as_slice() != self.identity.self_id().as_slice()
                || signer.as_slice() != self.identity.signer.public()
                || self.pending_convergence_groups.contains(&group_id)
                || !matches!(
                    self.epoch_manager.state(&group_id),
                    Some(
                        cgka_traits::EpochState::Stable { .. }
                            | cgka_traits::EpochState::PendingPublish(_)
                    )
                )
            {
                return Ok(None);
            }
            self.ensure_group_live(&group_id)?;
            let record = storage.get_group(&group_id)?;
            if record.removed
                || record.unrecoverable
                || record.disbanded.is_some()
                || record.epoch != roster.epoch
                || storage
                    .convergence_pass(&group_id)?
                    .is_some_and(|pass| pass.is_active())
            {
                return Ok(None);
            }
            self.with_mls_group(&group_id, |group| {
                if !AppliedPrivateTree::read(&group_id, group)?
                    .is_some_and(|actual| actual.matches(&account, &signer, &roster))
                {
                    return Ok(None);
                }
                if let Some(fact) = active_pending {
                    // Reauthenticate the actual retained pending Add, exact package and tree.
                    self.retained_private_add(group, fact)?;
                } else if group.pending_commit().is_some() {
                    return Ok(None);
                }
                Ok(
                    crate::app_components::app_component_data_of_group(group, component).map(
                        |component| PrivateTransportEvidence {
                            group: group_id.clone(),
                            component,
                        },
                    ),
                )
            })
        })
    }
}
