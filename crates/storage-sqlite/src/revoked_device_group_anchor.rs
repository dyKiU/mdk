//! Bounded authenticated single-Remove metadata, never live consent reconstruction.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::private_device_invite::PrivateInviteOrigin;
use cgka_traits::revoked_device_group_anchor::*;
use cgka_traits::storage::{
    AccountDeviceSignerStorage, StorageError, StorageProvider, StorageResult,
};
use cgka_traits::{GroupId, MemberId};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashSet;
const MAX_BYTES: usize = 131072;
fn invalid() -> StorageError {
    StorageError::Serialization("invalid revoked-device successor metadata".into())
}
fn generation(value: u64) -> StorageResult<i64> {
    i64::try_from(value)
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(invalid)
}
fn validate_roster(roster: &DeviceGroupAnchorRoster, account: &[u8; 32]) -> StorageResult<()> {
    if roster.epoch.0 > i64::MAX as u64
        || roster.epoch_authenticator_digest == [0; 32]
        || roster.leaves.is_empty()
        || roster.leaves.len() > 128
    {
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
fn validate(draft: &RevokedDeviceGroupDraft) -> StorageResult<()> {
    let n = match draft.predecessor_origin {
        PrivateInviteOrigin::Genesis(v)
        | PrivateInviteOrigin::Accepted(v)
        | PrivateInviteOrigin::Confirmed(v)
        | PrivateInviteOrigin::Existing(v)
        | PrivateInviteOrigin::Revoked(v) => v,
    };
    generation(n)?;
    generation(draft.predecessor_settlement_generation)?;
    validate_roster(&draft.predecessor, &draft.account)?;
    validate_roster(&draft.successor, &draft.account)?;
    let has_leaf = |index, key| {
        draft
            .predecessor
            .leaves
            .iter()
            .any(|leaf| leaf.leaf_index == index && leaf.signature_public_key == key)
    };
    if draft.group_id.as_slice().is_empty()
        || draft.group_id.as_slice().len() > 255
        || [
            draft.actual_commit_digest,
            draft.action_binding,
            draft.nonce,
            draft.context_digest,
        ]
        .contains(&[0; 32])
        || draft.source_device == draft.removed_device
        || draft.local_device == draft.removed_device
        || !has_leaf(draft.source_leaf_index, draft.source_device)
        || !has_leaf(draft.removed_leaf_index, draft.removed_device)
        || !draft
            .successor
            .leaves
            .iter()
            .any(|leaf| leaf.signature_public_key == draft.local_device)
        || Some(draft.successor.epoch.0) != draft.predecessor.epoch.0.checked_add(1)
        || draft.successor.leaves.len() + 1 != draft.predecessor.leaves.len()
        || draft
            .successor
            .leaves
            .iter()
            .any(|leaf| leaf.signature_public_key == draft.removed_device)
        || !draft
            .predecessor
            .leaves
            .iter()
            .filter(|leaf| leaf.signature_public_key != draft.removed_device)
            .eq(draft.successor.leaves.iter())
    {
        return Err(invalid());
    }
    Ok(())
}
fn read_generation(
    conn: &Connection,
    expected: Option<u64>,
) -> StorageResult<Option<RevokedDeviceGroupFact>> {
    type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, bool);
    let expected = expected.map(generation).transpose()?;
    let row: Option<Row> = conn.query_row(
        "SELECT generation,account,local_device,group_id,draft,denied FROM revoked_device_group_anchor
         WHERE generation=COALESCE(?1,(SELECT max(generation) FROM revoked_device_group_anchor))",
        [expected], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
    ).optional().storage()?;
    row.map(|(counter, account, device, group, bytes, denied)| {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        let draft: RevokedDeviceGroupDraft =
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
        Ok(RevokedDeviceGroupFact {
            generation: value,
            draft,
            denied,
        })
    })
    .transpose()
}
pub(crate) fn read(conn: &Connection) -> StorageResult<Option<RevokedDeviceGroupFact>> {
    read_generation(conn, None)
}
fn check_owner(
    storage: &SqliteAccountStorage,
    draft: &RevokedDeviceGroupDraft,
) -> StorageResult<()> {
    let wrong: bool = storage.lock()?.query_row(
        "SELECT EXISTS(SELECT 1 FROM account_state WHERE local_account_id_hex IS NULL OR local_account_id_hex<>?1)",
        [hex::encode(draft.account)], |r| r.get(0)).storage()?;
    if wrong {
        return Err(invalid());
    }
    if let Some(binding) = storage.account_device_signer(&MemberId::new(draft.account.to_vec()))?
        && binding.mls_signature_public_key != draft.local_device
    {
        return Err(invalid());
    }
    Ok(())
}
impl RevokedDeviceGroupStorage for SqliteAccountStorage {
    fn revoked_anchors(&self) -> StorageResult<Vec<RevokedDeviceGroupFact>> {
        let conn = self.lock()?;
        let mut query = conn
            .prepare(
                "SELECT generation FROM revoked_device_group_anchor ORDER BY generation LIMIT 129",
            )
            .storage()?;
        let counters = query.query_map([], |r| r.get::<_, i64>(0)).storage()?;
        let mut facts = Vec::new();
        for n in counters {
            if facts.len() == 128 {
                return Err(invalid());
            }
            facts.push(
                read_generation(
                    &conn,
                    Some(u64::try_from(n.storage()?).map_err(|_| invalid())?),
                )?
                .ok_or_else(invalid)?,
            );
        }
        Ok(facts)
    }
    fn revoked_anchor(&self) -> StorageResult<Option<RevokedDeviceGroupFact>> {
        let conn = self.lock()?;
        read(&conn)
    }
    fn install_revoked_anchor(
        &self,
        draft: &RevokedDeviceGroupDraft,
    ) -> StorageResult<RevokedDeviceGroupFact> {
        validate(draft)?;
        let bytes = serde_json::to_vec(draft).map_err(|_| invalid())?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        self.with_transaction(|storage| {
            check_owner(storage, draft)?;
            let old = storage.revoked_anchor()?;
            if let Some(old) = &old {
                if old.draft == *draft {
                    return if old.denied {
                        Err(invalid())
                    } else {
                        Ok(old.clone())
                    };
                }
                if old.draft.account != draft.account
                    || old.draft.local_device != draft.local_device
                    || (!old.denied
                        && draft.predecessor_origin != PrivateInviteOrigin::Revoked(old.generation))
                    || (old.draft.group_id == draft.group_id
                        && draft.predecessor.epoch.0 < old.draft.successor.epoch.0)
                    || old.draft.action_binding == draft.action_binding
                {
                    return Err(invalid());
                }
            }
            crate::existing_device_group_anchor::check_selected_predecessor(
                storage,
                &draft.predecessor_origin,
                &draft.account,
                &draft.local_device,
                &draft.group_id,
                &draft.predecessor,
                draft.predecessor_settlement_generation,
            )?;
            let conn = storage.lock()?;
            let count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM revoked_device_group_anchor",
                    [],
                    |r| r.get(0),
                )
                .storage()?;
            if count >= 128 {
                return Err(invalid());
            }
            let next = old
                .as_ref()
                .map_or(Some(1), |v| v.generation.checked_add(1))
                .ok_or_else(invalid)?;
            if let Some(old) = &old {
                conn.execute(
                    "UPDATE revoked_device_group_anchor SET denied=1 WHERE generation=?1",
                    [generation(old.generation)?],
                )
                .storage()?;
            }
            conn.execute(
                "INSERT INTO revoked_device_group_anchor VALUES(?1,?2,?3,?4,?5,0)",
                params![
                    generation(next)?,
                    draft.account.as_slice(),
                    draft.local_device.as_slice(),
                    draft.group_id.as_slice(),
                    bytes
                ],
            )
            .storage()?;
            Ok(RevokedDeviceGroupFact {
                generation: next,
                draft: draft.clone(),
                denied: false,
            })
        })
    }
    fn deny_revoked_anchor(&self, expected: u64, group: &GroupId) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let fact = read_generation(&conn, Some(expected))?.ok_or_else(invalid)?;
            if fact.draft.group_id != *group { return Err(invalid()); }
            conn.execute("UPDATE revoked_device_group_anchor SET denied=1 WHERE generation=?1 AND group_id=?2",
                params![generation(expected)?, group.as_slice()]).storage()?;
            Ok(())
        })
    }
}
#[cfg(test)]
mod tests;
