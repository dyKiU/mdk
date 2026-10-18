//! Permanent negative fences from an actually applied MLS tree. Never consent.
//! Call only inside the adopting crypto/SQL unit, never from scratch probes.
use cgka_traits::accepted_device_group_anchor::{AnchorError, DeviceGroupAnchorRoster};
use cgka_traits::device_group_genesis::GenesisLeaf;
use cgka_traits::private_device_invite::PrivateInviteStorageError;
use cgka_traits::{EngineError, EpochId, GroupId, storage::StorageProvider};
use openmls::group::MlsGroup;
use sha2::{Digest, Sha256};

pub(crate) struct AppliedPrivateTree {
    owner_account: [u8; 32],
    owner_signer: [u8; 32],
    roster: DeviceGroupAnchorRoster,
}
impl AppliedPrivateTree {
    pub(crate) fn roster(&self) -> &DeviceGroupAnchorRoster {
        &self.roster
    }

    pub(crate) fn read(group_id: &GroupId, group: &MlsGroup) -> Result<Option<Self>, EngineError> {
        if !group.is_active()
            || group.group_id().as_slice() != group_id.as_slice()
            || !crate::device_group_genesis::exact_profile(group)?
        {
            return Ok(None);
        }
        let Some(own) = group.member_at(group.own_leaf_index()) else {
            return Ok(None);
        };
        let owner_account = crate::identity::validated_member_id(&own.credential)?
            .as_slice()
            .try_into()
            .map_err(|_| EngineError::Other("invalid private lineage owner".into()))?;
        let Ok(owner_signer) = own.signature_key.as_slice().try_into() else {
            return Ok(None);
        };
        let mut leaves = Vec::new();
        for member in group.members().take(129) {
            let account = crate::identity::validated_member_id(&member.credential)?;
            let Ok(signature_public_key) = member.signature_key.as_slice().try_into() else {
                return Ok(None);
            };
            if account.as_slice() != owner_account {
                return Ok(None);
            }
            leaves.push(GenesisLeaf {
                account: owner_account,
                leaf_index: member.index.u32(),
                signature_public_key,
            });
        }
        if leaves.is_empty() || leaves.len() > 128 {
            return Ok(None);
        }
        leaves.sort_unstable_by_key(|leaf| leaf.leaf_index);
        Ok(Some(Self {
            owner_account,
            owner_signer,
            roster: DeviceGroupAnchorRoster {
                epoch: EpochId(group.epoch().as_u64()),
                epoch_authenticator_digest: Sha256::digest(group.epoch_authenticator().as_slice())
                    .into(),
                leaves,
            },
        }))
    }
    pub(crate) fn matches(
        &self,
        account: &[u8; 32],
        signer: &[u8; 32],
        roster: &DeviceGroupAnchorRoster,
    ) -> bool {
        self.owner_account == *account && self.owner_signer == *signer && self.roster == *roster
    }
}

pub(crate) fn deny_changed_lineage_for_tree<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    group: &MlsGroup,
) -> Result<(), EngineError> {
    let accepted_store = storage.accepted_device_group_anchor_storage();
    let accepted = accepted_store
        .map(|store| store.accepted_anchor())
        .transpose()
        .map_err(anchor_error)?
        .flatten()
        .filter(|fact| !fact.denied && fact.draft.group_id == *group_id);
    let confirmed_store = storage.private_device_invite_storage();
    let confirmed = confirmed_store
        .map(|store| store.confirmed_private_invite())
        .transpose()
        .map_err(invite_error)?
        .flatten()
        .filter(|fact| !fact.denied && fact.binding.group_id == *group_id);
    let existing_store = storage.existing_device_group_anchor_storage();
    let existing = existing_store
        .map(|store| store.existing_anchor())
        .transpose()?
        .flatten()
        .filter(|fact| !fact.denied && fact.draft.group_id == *group_id);
    let revoked_store = storage.revoked_device_group_anchor_storage();
    let revoked = revoked_store
        .map(|store| store.revoked_anchor())
        .transpose()?
        .flatten()
        .filter(|fact| !fact.denied && fact.draft.group_id == *group_id);
    if accepted.is_none() && confirmed.is_none() && existing.is_none() && revoked.is_none() {
        return Ok(());
    }
    let actual = AppliedPrivateTree::read(group_id, group)?;
    if let Some(fact) = accepted
        && !actual.as_ref().is_some_and(|tree| {
            tree.matches(
                &fact.scope.account,
                &fact.scope.local_device,
                &fact.draft.successor,
            )
        })
    {
        accepted_store
            .ok_or_else(|| {
                EngineError::Other("private accepted lineage storage unavailable".into())
            })?
            .deny_accepted_anchor(&fact.scope, group_id)
            .map_err(anchor_error)?;
    }
    if let Some(fact) = confirmed
        && !actual.as_ref().is_some_and(|tree| {
            tree.matches(
                &fact.scope.account,
                &fact.scope.local_device,
                &fact.binding.successor,
            )
        })
    {
        confirmed_store
            .ok_or_else(|| {
                EngineError::Other("private confirmed lineage storage unavailable".into())
            })?
            .deny_confirmed_private_invite(&fact.scope, group_id)
            .map_err(invite_error)?;
    }
    if let Some(fact) = existing
        && !actual.as_ref().is_some_and(|tree| {
            tree.matches(
                &fact.draft.account,
                &fact.draft.local_device,
                &fact.draft.successor,
            )
        })
    {
        existing_store
            .ok_or_else(|| {
                EngineError::Other("private existing lineage storage unavailable".into())
            })?
            .deny_existing_anchor(fact.generation, group_id)?;
    }
    if let Some(fact) = revoked
        && !actual.as_ref().is_some_and(|tree| {
            tree.matches(
                &fact.draft.account,
                &fact.draft.local_device,
                &fact.draft.successor,
            )
        })
    {
        revoked_store
            .ok_or_else(|| {
                EngineError::Other("private revoked lineage storage unavailable".into())
            })?
            .deny_revoked_anchor(fact.generation, group_id)?;
    }
    Ok(())
}
fn anchor_error(error: AnchorError) -> EngineError {
    match error {
        AnchorError::Storage(error) => EngineError::Storage(error),
        _ => EngineError::Other("private accepted lineage denial failed".into()),
    }
}
fn invite_error(error: PrivateInviteStorageError) -> EngineError {
    match error {
        PrivateInviteStorageError::Storage(error) => EngineError::Storage(error),
        _ => EngineError::Other("private confirmed lineage denial failed".into()),
    }
}
