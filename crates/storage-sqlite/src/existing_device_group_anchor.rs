//! Bounded original-existing-member metadata, never live consent reconstruction.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::GroupId;
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::existing_device_group_anchor::*;
use cgka_traits::private_device_invite::PrivateInviteOrigin;
use cgka_traits::private_roster_settlement::PrivateSettlementPhase;
use cgka_traits::storage::{StorageError, StorageProvider, StorageResult};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashSet;
const MAX_BYTES: usize = 131072;
fn invalid() -> StorageError {
    StorageError::Serialization("invalid existing-member successor metadata".into())
}
fn generation(value: u64) -> StorageResult<i64> {
    i64::try_from(value)
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(invalid)
}
fn validate_roster(roster: &DeviceGroupAnchorRoster, account: &[u8; 32]) -> StorageResult<()> {
    if roster.epoch.0 > i64::MAX as u64 || roster.leaves.is_empty() || roster.leaves.len() > 128 {
        return Err(invalid());
    }
    let mut previous = None;
    let mut keys = HashSet::new();
    for leaf in &roster.leaves {
        if leaf.account != *account
            || previous.is_some_and(|v| v >= leaf.leaf_index)
            || !keys.insert(leaf.signature_public_key)
        {
            return Err(invalid());
        }
        previous = Some(leaf.leaf_index);
    }
    Ok(())
}
fn validate(draft: &ExistingDeviceGroupDraft) -> StorageResult<()> {
    let origin_generation = match draft.predecessor_origin {
        PrivateInviteOrigin::Genesis(v)
        | PrivateInviteOrigin::Accepted(v)
        | PrivateInviteOrigin::Confirmed(v)
        | PrivateInviteOrigin::Existing(v) => v,
    };
    generation(origin_generation)?;
    generation(draft.predecessor_settlement_generation)?;
    validate_roster(&draft.predecessor, &draft.account)?;
    validate_roster(&draft.successor, &draft.account)?;
    if draft.group_id.as_slice().is_empty()
        || draft.group_id.as_slice().len() > 255
        || [
            draft.action_binding,
            draft.nonce,
            draft.context_digest,
            draft.key_package_reference,
            draft.key_package_digest,
            draft.commit_digest,
        ]
        .contains(&[0; 32])
        || draft.local_device == draft.recipient
        || draft.coordinator == draft.recipient
        || draft.predecessor.leaves.len() >= 128
        || Some(draft.successor.epoch.0) != draft.predecessor.epoch.0.checked_add(1)
        || draft.successor.leaves.len() != draft.predecessor.leaves.len() + 1
        || ![draft.local_device, draft.coordinator].iter().all(|key| {
            draft
                .predecessor
                .leaves
                .iter()
                .any(|leaf| leaf.signature_public_key == *key)
        })
        || draft
            .predecessor
            .leaves
            .iter()
            .any(|leaf| leaf.signature_public_key == draft.recipient)
        || !draft
            .successor
            .leaves
            .iter()
            .any(|leaf| leaf.signature_public_key == draft.recipient)
        || !draft
            .predecessor
            .leaves
            .iter()
            .all(|leaf| draft.successor.leaves.contains(leaf))
    {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn read(conn: &Connection) -> StorageResult<Option<ExistingDeviceGroupFact>> {
    type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, bool);
    let row: Option<Row> = conn.query_row(
        "SELECT generation,account,local_device,group_id,draft,denied FROM existing_device_group_anchor WHERE singleton=1",
        [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
    ).optional().storage()?;
    row.map(|(counter, account, device, group, bytes, denied)| {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        let draft: ExistingDeviceGroupDraft =
            serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        validate(&draft)?;
        let value = u64::try_from(counter).map_err(|_| invalid())?;
        generation(value)?;
        if account != draft.account
            || device != draft.local_device
            || group != draft.group_id.as_slice()
        {
            return Err(invalid());
        }
        Ok(ExistingDeviceGroupFact {
            generation: value,
            draft,
            denied,
        })
    })
    .transpose()
}
fn check_predecessor(
    storage: &SqliteAccountStorage,
    draft: &ExistingDeviceGroupDraft,
) -> StorageResult<()> {
    // These are negative exact-selection fences. The original live action and
    // authenticated actual MLS tree remain required by the caller's apply unit.
    let roster = match draft.predecessor_origin {
        PrivateInviteOrigin::Accepted(n) => {
            let fact = storage
                .accepted_device_group_anchor_storage()
                .ok_or_else(invalid)?
                .accepted_anchor()
                .map_err(|error| match error {
                    cgka_traits::accepted_device_group_anchor::AnchorError::Storage(error) => error,
                    _ => invalid(),
                })?
                .ok_or_else(invalid)?;
            if fact.denied
                || fact.scope.selection_generation != n
                || fact.scope.account != draft.account
                || fact.scope.local_device != draft.local_device
                || fact.draft.group_id != draft.group_id
            {
                return Err(invalid());
            }
            fact.draft.successor
        }
        PrivateInviteOrigin::Confirmed(n) => {
            let fact = storage
                .private_device_invite_storage()
                .ok_or_else(invalid)?
                .confirmed_private_invite()
                .map_err(|error| match error {
                    cgka_traits::private_device_invite::PrivateInviteStorageError::Storage(
                        error,
                    ) => error,
                    _ => invalid(),
                })?
                .ok_or_else(invalid)?;
            if fact.denied
                || fact.scope.staging_generation != n
                || fact.scope.account != draft.account
                || fact.scope.local_device != draft.local_device
                || fact.binding.group_id != draft.group_id
            {
                return Err(invalid());
            }
            fact.binding.successor
        }
        PrivateInviteOrigin::Existing(n) => {
            let fact = storage.existing_anchor()?.ok_or_else(invalid)?;
            if fact.denied
                || fact.generation != n
                || fact.draft.account != draft.account
                || fact.draft.local_device != draft.local_device
                || fact.draft.group_id != draft.group_id
            {
                return Err(invalid());
            }
            fact.draft.successor
        }
        // Genesis has no completed predecessor enrollment round.
        PrivateInviteOrigin::Genesis(_) => return Err(invalid()),
    };
    let state = storage
        .private_roster_settlement_storage()
        .ok_or_else(invalid)?
        .read_round()?
        .ok_or_else(invalid)?;
    if roster != draft.predecessor
        || state.phase != PrivateSettlementPhase::Completed
        || state.generation != draft.predecessor_settlement_generation
        || state.anchor.origin != draft.predecessor_origin
        || state.anchor.account != draft.account
        || state.anchor.local_device != draft.local_device
        || state.anchor.group_id != draft.group_id
        || state.anchor.successor != draft.predecessor
    {
        return Err(invalid());
    }
    Ok(())
}
impl ExistingDeviceGroupStorage for SqliteAccountStorage {
    fn existing_anchor(&self) -> StorageResult<Option<ExistingDeviceGroupFact>> {
        let conn = self.lock()?;
        read(&conn)
    }
    fn install_existing_anchor(
        &self,
        draft: &ExistingDeviceGroupDraft,
    ) -> StorageResult<ExistingDeviceGroupFact> {
        validate(draft)?;
        let bytes = serde_json::to_vec(draft).map_err(|_| invalid())?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        self.with_transaction(|storage| {
            let old = storage.existing_anchor()?;
            if let Some(old) = &old {
                if old.draft == *draft { return if old.denied { Err(invalid()) } else { Ok(old.clone()) }; }
                if old.draft.account != draft.account || old.draft.local_device != draft.local_device
                    || (!old.denied && draft.predecessor_origin != PrivateInviteOrigin::Existing(old.generation))
                    || (old.draft.group_id == draft.group_id && draft.predecessor.epoch.0 < old.draft.successor.epoch.0)
                    || old.draft.action_binding == draft.action_binding {
                    return Err(invalid());
                }
            }
            check_predecessor(storage, draft)?;
            let conn = storage.lock()?;
            let wrong: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM account_state WHERE local_account_id_hex IS NULL OR local_account_id_hex<>?1)",
                [hex::encode(draft.account)], |r| r.get(0)).storage()?;
            if wrong { return Err(invalid()); }
            let next = old.map_or(Some(1), |v| v.generation.checked_add(1)).ok_or_else(invalid)?;
            conn.execute("INSERT INTO existing_device_group_anchor VALUES(1,?1,?2,?3,?4,?5,0)
                ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation,group_id=excluded.group_id,draft=excluded.draft,denied=0",
                params![generation(next)?,draft.account.as_slice(),draft.local_device.as_slice(),draft.group_id.as_slice(),bytes]).storage()?;
            Ok(ExistingDeviceGroupFact { generation: next, draft: draft.clone(), denied: false })
        })
    }
    fn deny_existing_anchor(&self, expected: u64, group: &GroupId) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let fact = read(&conn)?.ok_or_else(invalid)?;
            if fact.generation != expected || fact.draft.group_id != *group { return Err(invalid()); }
            conn.execute("UPDATE existing_device_group_anchor SET denied=1 WHERE singleton=1 AND generation=?1 AND group_id=?2",
                params![generation(expected)?,group.as_slice()]).storage()?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
