//! Trusted-core accepted successor persistence, never verifier/settlement permission.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::accepted_device_group_anchor::*;
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::GroupId;
use rusqlite::{OptionalExtension, params};
use std::collections::HashSet;
const MAX_DRAFT_BYTES: usize = 131072;
const SELECT: &str = "SELECT generation,account,local_device,group_id,draft,denied
    FROM accepted_device_group_anchor WHERE singleton=1";
fn generation(value: u64) -> AnchorResult<i64> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(AnchorError::GenerationExhausted)
}
fn validate_roster(roster: &DeviceGroupAnchorRoster, account: &[u8; 32]) -> AnchorResult<()> {
    if roster.epoch.0 > i64::MAX as u64 || roster.leaves.is_empty() || roster.leaves.len() > 128 {
        return Err(AnchorError::InvalidFact);
    }
    let mut previous = None;
    let mut signers = HashSet::new();
    for leaf in &roster.leaves {
        if leaf.account != *account
            || previous.is_some_and(|index| index >= leaf.leaf_index)
            || !signers.insert(leaf.signature_public_key)
        {
            return Err(AnchorError::InvalidFact);
        }
        previous = Some(leaf.leaf_index);
    }
    Ok(())
}
fn validate(draft: &AcceptedDeviceGroupAnchorDraft) -> AnchorResult<()> {
    if draft.format_version != 1
        || draft.group_id.as_slice().is_empty()
        || draft.group_id.as_slice().len() > 255
        || generation(draft.purpose.generation).is_err()
        || draft.nonce == [0; 32]
        || draft.approver == draft.recipient
        || draft.purpose.local_device != draft.recipient
    {
        return Err(AnchorError::InvalidFact);
    }
    validate_roster(&draft.predecessor, &draft.purpose.account)?;
    validate_roster(&draft.successor, &draft.purpose.account)?;
    if draft.predecessor.leaves.len() >= 128
        || Some(draft.successor.epoch.0) != draft.predecessor.epoch.0.checked_add(1)
        || draft.successor.leaves.len() != draft.predecessor.leaves.len() + 1
        || !draft
            .predecessor
            .leaves
            .iter()
            .any(|leaf| leaf.signature_public_key == draft.approver)
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
        return Err(AnchorError::InvalidFact);
    }
    Ok(())
}
fn read(connection: &rusqlite::Connection) -> AnchorResult<Option<AcceptedDeviceGroupAnchorFact>> {
    type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, bool);
    let row: Option<Row> = connection
        .query_row(SELECT, [], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .optional()
        .storage()?;
    row.map(|(counter, account, device, group, bytes, denied)| {
        if bytes.len() > MAX_DRAFT_BYTES {
            return Err(AnchorError::InvalidFact);
        }
        let account: [u8; 32] = account.try_into().map_err(|_| AnchorError::InvalidFact)?;
        let local_device: [u8; 32] = device.try_into().map_err(|_| AnchorError::InvalidFact)?;
        let selection_generation = u64::try_from(counter).map_err(|_| AnchorError::InvalidFact)?;
        generation(selection_generation)?;
        let draft: AcceptedDeviceGroupAnchorDraft =
            serde_json::from_slice(&bytes).map_err(|_| AnchorError::InvalidFact)?;
        validate(&draft)?;
        if draft.purpose.account != account
            || draft.purpose.local_device != local_device
            || draft.group_id.as_slice() != group
        {
            return Err(AnchorError::InvalidFact);
        }
        Ok(AcceptedDeviceGroupAnchorFact {
            scope: DeviceGroupAnchorScope {
                account,
                local_device,
                selection_generation,
            },
            draft,
            denied,
        })
    })
    .transpose()
}
impl AcceptedDeviceGroupAnchorStorage for SqliteAccountStorage {
    fn accepted_anchor(&self) -> AnchorResult<Option<AcceptedDeviceGroupAnchorFact>> {
        let connection = self.lock()?;
        read(&connection)
    }
    fn install_accepted_anchor(
        &self,
        draft: &AcceptedDeviceGroupAnchorDraft,
    ) -> AnchorResult<AcceptedDeviceGroupAnchorFact> {
        validate(draft)?;
        let bytes = serde_json::to_vec(draft).map_err(|_| AnchorError::InvalidFact)?;
        if bytes.len() > MAX_DRAFT_BYTES {
            return Err(AnchorError::InvalidFact);
        }
        self.with_transaction(|storage| {
            let connection = storage.lock()?;
            // Negative allocation fence only. A retained birth is never consent
            // or an accepted-successor anchor; one account-device selects at
            // most one active private group across both origin paths.
            let genesis: Option<(Vec<u8>, Vec<u8>, bool)> = connection
                .query_row(
                    "SELECT account,local_device,active_denied FROM device_group_genesis_selection WHERE singleton=1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .storage()?;
            if let Some((account, device, denied)) = genesis {
                if account.as_slice() != draft.purpose.account
                    || device.as_slice() != draft.purpose.local_device
                {
                    return Err(AnchorError::ScopeMismatch);
                }
                if !denied {
                    return Err(AnchorError::SelectionBusy);
                }
            }
            let old = read(&connection)?;
            if let Some(old) = &old {
                if old.scope.account != draft.purpose.account || old.scope.local_device != draft.purpose.local_device {
                    return Err(AnchorError::ScopeMismatch);
                }
                if !old.denied {
                    if old.draft == *draft { return Ok(old.clone()); }
                    return Err(AnchorError::SelectionBusy);
                }
                if draft.purpose.generation <= old.draft.purpose.generation { return Err(AnchorError::ScopeMismatch); }
            }
            // Exact existing fact retries above do not allocate a selection.
            crate::private_device_invite::check_selection_allocation(
                &connection, &draft.purpose.account, &draft.purpose.local_device,
            ).map_err(|error| match error {
                cgka_traits::private_device_invite::PrivateInviteStorageError::Storage(error) => AnchorError::Storage(error),
                cgka_traits::private_device_invite::PrivateInviteStorageError::ScopeMismatch => AnchorError::ScopeMismatch,
                cgka_traits::private_device_invite::PrivateInviteStorageError::Busy => AnchorError::SelectionBusy,
                _ => AnchorError::InvalidFact,
            })?;
            let projection_matches: bool = connection.query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM account_state WHERE local_account_id_hex<>?1 OR local_account_id_hex IS NULL)",
                [hex::encode(draft.purpose.account)], |row| row.get(0)
            ).storage()?;
            if !projection_matches { return Err(AnchorError::ScopeMismatch); }
            let selection_generation = old.map_or(Some(1),|old|old.scope.selection_generation.checked_add(1))
                .ok_or(AnchorError::GenerationExhausted)?;
            connection.execute(
                "INSERT INTO accepted_device_group_anchor(singleton,generation,account,local_device,group_id,draft,denied)
                VALUES(1,?1,?2,?3,?4,?5,0) ON CONFLICT(singleton) DO UPDATE SET
                generation=excluded.generation,group_id=excluded.group_id,draft=excluded.draft,denied=0",
                params![generation(selection_generation)?,draft.purpose.account.as_slice(),draft.purpose.local_device.as_slice(),draft.group_id.as_slice(),bytes]
            ).storage()?;
            Ok(AcceptedDeviceGroupAnchorFact {
                scope: DeviceGroupAnchorScope { account:draft.purpose.account,local_device:draft.purpose.local_device,selection_generation },
                draft:draft.clone(),denied:false
            })
        })
    }
    fn deny_accepted_anchor(
        &self,
        scope: &DeviceGroupAnchorScope,
        group_id: &GroupId,
    ) -> AnchorResult<()> {
        self.with_transaction(|storage| {
            let connection=storage.lock()?;
            let current=read(&connection)?.ok_or(AnchorError::ScopeMismatch)?;
            if current.scope != *scope || current.draft.group_id != *group_id { return Err(AnchorError::ScopeMismatch); }
            if connection.execute(
                "UPDATE accepted_device_group_anchor SET denied=1 WHERE singleton=1 AND generation=?1 AND account=?2 AND local_device=?3 AND group_id=?4",
                params![generation(scope.selection_generation)?,scope.account.as_slice(),scope.local_device.as_slice(),group_id.as_slice()]
            ).storage()? != 1 { return Err(AnchorError::ScopeMismatch); }
            Ok(())
        })
    }
}
