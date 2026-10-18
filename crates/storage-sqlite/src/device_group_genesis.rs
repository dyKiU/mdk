//! Trusted core fact persistence only. Neither birth nor active state grants permission.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::device_group_genesis::{
    DeviceGroupGenesisFact, DeviceGroupGenesisSelection, DeviceGroupGenesisStorage,
    GenesisBirthDraft, GenesisError, GenesisResult, GenesisScope,
};
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::GroupId;
use rusqlite::{OptionalExtension, params};
const SELECT: &str = "SELECT generation,account,local_device,group_id,birth,active_denied
    FROM device_group_genesis_selection WHERE singleton=1";
const INSTALL: &str = "INSERT INTO device_group_genesis_selection
    (singleton,generation,account,local_device,group_id,birth,active_denied)
    VALUES(1,?1,?2,?3,?4,?5,0) ON CONFLICT(singleton) DO UPDATE SET
    generation=excluded.generation,group_id=excluded.group_id,birth=excluded.birth,active_denied=0";
const DENY: &str = "UPDATE device_group_genesis_selection SET active_denied=1
    WHERE singleton=1 AND generation=?1 AND account=?2 AND local_device=?3 AND group_id=?4";
fn generation(value: u64) -> GenesisResult<i64> {
    i64::try_from(value)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(GenesisError::GenerationExhausted)
}
fn validate(account: &[u8; 32], device: &[u8; 32], birth: &GenesisBirthDraft) -> GenesisResult<()> {
    if birth.format_version != 1
        || birth.group_id.as_slice().is_empty()
        || birth.group_id.as_slice().len() > 255
        || birth.epoch.0 != 0
        || birth.leaves.len() != 1
        || birth.leaves[0].leaf_index != 0
        || birth.leaves[0].account != *account
        || birth.leaves[0].signature_public_key != *device
    {
        return Err(GenesisError::InvalidFact);
    }
    Ok(())
}
fn read(connection: &rusqlite::Connection) -> GenesisResult<Option<DeviceGroupGenesisSelection>> {
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
    row.map(|(counter, account, device, group, bytes, active_denied)| {
        let account: [u8; 32] = account.try_into().map_err(|_| GenesisError::InvalidFact)?;
        let local_device: [u8; 32] = device.try_into().map_err(|_| GenesisError::InvalidFact)?;
        let selection_generation = u64::try_from(counter).map_err(|_| GenesisError::InvalidFact)?;
        generation(selection_generation)?;
        let birth: GenesisBirthDraft =
            serde_json::from_slice(&bytes).map_err(|_| GenesisError::InvalidFact)?;
        validate(&account, &local_device, &birth)?;
        if bytes.len() > 4096 || birth.group_id.as_slice() != group {
            return Err(GenesisError::InvalidFact);
        }
        Ok(DeviceGroupGenesisSelection {
            fact: DeviceGroupGenesisFact {
                scope: GenesisScope {
                    account,
                    local_device,
                    selection_generation,
                },
                birth,
            },
            active_denied,
        })
    })
    .transpose()
}
impl DeviceGroupGenesisStorage for SqliteAccountStorage {
    fn genesis_selection(&self) -> GenesisResult<Option<DeviceGroupGenesisSelection>> {
        let connection = self.lock()?;
        read(&connection)
    }
    fn store_genesis_birth(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        birth: &GenesisBirthDraft,
    ) -> GenesisResult<DeviceGroupGenesisSelection> {
        validate(account, local_device, birth)?;
        let bytes = serde_json::to_vec(birth).map_err(|_| GenesisError::InvalidFact)?;
        if bytes.len() > 4096 {
            return Err(GenesisError::InvalidFact);
        }
        self.with_transaction(|storage| {
            let connection = storage.lock()?;
            crate::private_device_invite::check_selection_allocation(
                &connection,
                account,
                local_device,
            )
            .map_err(|error| match error {
                cgka_traits::private_device_invite::PrivateInviteStorageError::Storage(error) => {
                    GenesisError::Storage(error)
                }
                cgka_traits::private_device_invite::PrivateInviteStorageError::ScopeMismatch => {
                    GenesisError::ScopeMismatch
                }
                cgka_traits::private_device_invite::PrivateInviteStorageError::Busy => {
                    GenesisError::SelectionBusy
                }
                _ => GenesisError::InvalidFact,
            })?;
            let old = read(&connection)?;
            if let Some(old) = &old {
                if old.fact.scope.account != *account
                    || old.fact.scope.local_device != *local_device
                {
                    return Err(GenesisError::ScopeMismatch);
                }
                if !old.active_denied {
                    return Err(GenesisError::SelectionBusy);
                }
                if old.fact.birth.group_id == birth.group_id {
                    return Err(GenesisError::InvalidFact);
                }
            }
            let projected: i64 = connection
                .query_row("SELECT count(*) FROM account_state", [], |row| row.get(0))
                .storage()?;
            if projected != 0 {
                let matches: bool = connection
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM account_state WHERE local_account_id_hex=?1)",
                        params![hex::encode(account)],
                        |row| row.get(0),
                    )
                    .storage()?;
                if !matches {
                    return Err(GenesisError::ScopeMismatch);
                }
            }
            let selection_generation = old
                .map_or(Some(1), |old| {
                    old.fact.scope.selection_generation.checked_add(1)
                })
                .ok_or(GenesisError::GenerationExhausted)?;
            connection
                .execute(
                    INSTALL,
                    params![
                        generation(selection_generation)?,
                        account.as_slice(),
                        local_device.as_slice(),
                        birth.group_id.as_slice(),
                        bytes
                    ],
                )
                .storage()?;
            Ok(DeviceGroupGenesisSelection {
                fact: DeviceGroupGenesisFact {
                    scope: GenesisScope {
                        account: *account,
                        local_device: *local_device,
                        selection_generation,
                    },
                    birth: birth.clone(),
                },
                active_denied: false,
            })
        })
    }
    fn deny_genesis_selection(
        &self,
        scope: &GenesisScope,
        group_id: &GroupId,
    ) -> GenesisResult<()> {
        self.with_transaction(|storage| {
            let connection = storage.lock()?;
            let row = read(&connection)?.ok_or(GenesisError::ScopeMismatch)?;
            if row.fact.scope != *scope || row.fact.birth.group_id != *group_id {
                return Err(GenesisError::ScopeMismatch);
            }
            if connection
                .execute(
                    DENY,
                    params![
                        generation(scope.selection_generation)?,
                        scope.account.as_slice(),
                        scope.local_device.as_slice(),
                        group_id.as_slice()
                    ],
                )
                .storage()?
                != 1
            {
                return Err(GenesisError::ScopeMismatch);
            }
            Ok(())
        })
    }
}
