//! Atomic selected-chat recipient facts. Rows and terminal references never grant joins.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::selected_chat_key_package::*;
use cgka_traits::storage::{
    AccountDeviceSignerBinding, StorageError, StorageProvider, StorageResult,
};
use rusqlite::{Connection, params};
use std::collections::HashSet;

const MAX_RECORD_BYTES: usize = 262_144;

fn invalid() -> StorageError {
    StorageError::Serialization("invalid selected-chat recipient ownership".into())
}

fn validate_scope(scope: &SelectedChatPurposeScope) -> StorageResult<()> {
    if scope.account == [0; 32]
        || scope.local_device == [0; 32]
        || scope.request_binding == [0; 32]
        || scope.generation == 0
        || scope.generation > i64::MAX as u64
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate(package: &SelectedChatPurposeKeyPackage) -> StorageResult<()> {
    validate_scope(&package.scope)?;
    let context = &package.context;
    let group_valid = |group: &cgka_traits::types::GroupId| {
        !group.as_slice().is_empty() && group.as_slice().len() <= MAX_SELECTED_CHAT_GROUP_ID_BYTES
    };
    if package.public_bytes.is_empty()
        || package.public_bytes.len() > MAX_SELECTED_CHAT_KEY_PACKAGE_BYTES
        || package.reference == [0; 32]
        || package.signature_public_key != package.scope.local_device
        || context.approved_response_digest == [0; 32]
        || !group_valid(&context.protected_group)
        || !group_valid(&context.ordinary_group)
        || context.protected_group == context.ordinary_group
        || context.protected_settlement_generation == 0
        || context.protected_settlement_generation > i64::MAX as u64
        || context.protected_anchor.epoch_authenticator_digest == [0; 32]
        || !(2..=128).contains(&context.protected_anchor.leaves.len())
        || context.ordinary_own_leaf_hash.is_empty()
        || context.ordinary_own_leaf_hash.len() > MAX_SELECTED_CHAT_LEAF_HASH_BYTES
        || context.ordinary_roster_digest == [0; 32]
    {
        return Err(invalid());
    }
    let mut indices = HashSet::new();
    let mut keys = HashSet::new();
    let mut previous_index = None;
    for leaf in &context.protected_anchor.leaves {
        if leaf.account != package.scope.account
            || leaf.signature_public_key == [0; 32]
            || !indices.insert(leaf.leaf_index)
            || !keys.insert(leaf.signature_public_key)
            || previous_index.is_some_and(|previous| previous >= leaf.leaf_index)
        {
            return Err(invalid());
        }
        previous_index = Some(leaf.leaf_index);
    }
    if !keys.contains(&package.scope.local_device)
        || crate::serialize(context)?.len() > MAX_SELECTED_CHAT_PURPOSE_CONTEXT_BYTES
    {
        return Err(invalid());
    }
    Ok(())
}

fn rows(connection: &Connection) -> StorageResult<Vec<SelectedChatPurposeKeyPackage>> {
    let mut statement = connection
        .prepare(
            "SELECT reference,account,local_device,generation,request_binding,record,state
         FROM selected_chat_key_packages ORDER BY rowid LIMIT 129",
        )
        .storage()?;
    let records = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .storage()?;
    let mut packages = Vec::new();
    for record in records {
        let (reference, account, device, generation, binding, bytes, state) = record.storage()?;
        if packages.len() == MAX_SELECTED_CHAT_PURPOSE_ROWS || bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid());
        }
        let mut package: SelectedChatPurposeKeyPackage =
            serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        validate(&package)?;
        if package.state != SelectedChatPurposeState::Pending
            || package.reference.as_slice() != reference
            || package.scope.account.as_slice() != account
            || package.scope.local_device.as_slice() != device
            || package.scope.generation != generation as u64
            || package.scope.request_binding.as_slice() != binding
        {
            return Err(invalid());
        }
        package.state = match state {
            0 => SelectedChatPurposeState::Pending,
            1 => SelectedChatPurposeState::Consumed,
            2 => SelectedChatPurposeState::Denied,
            _ => return Err(invalid()),
        };
        packages.push(package);
    }
    Ok(packages)
}

fn check_owner(
    connection: &Connection,
    scope: &SelectedChatPurposeScope,
    retained: &[SelectedChatPurposeKeyPackage],
) -> StorageResult<()> {
    validate_scope(scope)?;
    if retained.iter().any(|row| {
        row.scope.account != scope.account || row.scope.local_device != scope.local_device
    }) {
        return Err(invalid());
    }
    let mut statement = connection
        .prepare(
            "SELECT local_account_id_hex FROM account_state WHERE local_account_id_hex IS NOT NULL",
        )
        .storage()?;
    let accounts = statement
        .query_map([], |row| row.get::<_, String>(0))
        .storage()?;
    let mut found = false;
    for account in accounts {
        if hex::decode(account.storage()?).map_err(|_| invalid())? != scope.account {
            return Err(invalid());
        }
        found = true;
    }
    if !found {
        return Err(invalid());
    }
    let bytes: Vec<u8> = connection
        .query_row(
            "SELECT record FROM cgka_account_device_signers WHERE marmot_identity=?1",
            params![scope.account.as_slice()],
            |row| row.get(0),
        )
        .storage()?;
    let signer: AccountDeviceSignerBinding =
        serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if signer.marmot_identity.as_slice() != scope.account
        || signer.mls_signature_public_key != scope.local_device
    {
        return Err(invalid());
    }
    Ok(())
}

impl SelectedChatKeyPackageStorage for SqliteAccountStorage {
    fn selected_chat_key_packages(&self) -> StorageResult<Vec<SelectedChatPurposeKeyPackage>> {
        let connection = self.lock()?;
        rows(&connection)
    }

    fn selected_chat_key_package_by_ref(
        &self,
        reference: &[u8; 32],
    ) -> StorageResult<Option<SelectedChatPurposeKeyPackage>> {
        let connection = self.lock()?;
        Ok(rows(&connection)?
            .into_iter()
            .find(|row| row.reference == *reference))
    }

    fn selected_chat_key_package(
        &self,
        scope: &SelectedChatPurposeScope,
    ) -> StorageResult<Option<SelectedChatPurposeKeyPackage>> {
        validate_scope(scope)?;
        let connection = self.lock()?;
        Ok(rows(&connection)?
            .into_iter()
            .find(|row| row.scope == *scope))
    }

    fn put_selected_chat_key_package(
        &self,
        package: &SelectedChatPurposeKeyPackage,
    ) -> StorageResult<()> {
        validate(package)?;
        if package.state != SelectedChatPurposeState::Pending {
            return Err(invalid());
        }
        let bytes = crate::serialize(package)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid());
        }
        self.with_transaction(|storage| {
            let connection = storage.lock()?;
            let retained = rows(&connection)?;
            check_owner(&connection, &package.scope, &retained)?;
            if let Some(existing) = retained.iter().find(|row| row.reference == package.reference || row.scope.request_binding == package.scope.request_binding) {
                return if existing == package { Ok(()) } else { Err(StorageError::AlreadyExists) };
            }
            if retained.len() == MAX_SELECTED_CHAT_PURPOSE_ROWS || retained.iter().any(|row| row.state == SelectedChatPurposeState::Pending) {
                return Err(StorageError::AlreadyExists);
            }
            connection.execute(
                "INSERT INTO selected_chat_key_packages(reference,account,local_device,generation,request_binding,record,state)
                 VALUES(?1,?2,?3,?4,?5,?6,0)",
                params![package.reference.as_slice(), package.scope.account.as_slice(), package.scope.local_device.as_slice(), package.scope.generation as i64, package.scope.request_binding.as_slice(), bytes],
            ).storage()?;
            Ok(())
        })
    }

    fn consume_selected_chat_key_package(
        &self,
        scope: &SelectedChatPurposeScope,
        reference: &[u8; 32],
    ) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let connection = storage.lock()?;
            let retained = rows(&connection)?;
            check_owner(&connection, scope, &retained)?;
            let row = retained
                .iter()
                .find(|row| row.scope == *scope && row.reference == *reference)
                .ok_or(StorageError::NotFound)?;
            if row.state == SelectedChatPurposeState::Denied {
                return Err(invalid());
            }
            connection
                .execute(
                    "UPDATE selected_chat_key_packages SET state=1 WHERE reference=?1 AND state=0",
                    params![reference.as_slice()],
                )
                .storage()?;
            Ok(())
        })
    }

    fn deny_selected_chat_key_package(
        &self,
        scope: &SelectedChatPurposeScope,
        reference: &[u8; 32],
    ) -> StorageResult<()> {
        validate_scope(scope)?;
        self.with_transaction(|storage| {
            let connection = storage.lock()?;
            if !rows(&connection)?
                .iter()
                .any(|row| row.scope == *scope && row.reference == *reference)
            {
                return Err(StorageError::NotFound);
            }
            connection
                .execute(
                    "UPDATE selected_chat_key_packages SET state=2 WHERE reference=?1 AND state=0",
                    params![reference.as_slice()],
                )
                .storage()?;
            Ok(())
        })
    }

    fn deny_pending_selected_chat_key_packages(&self) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let connection = storage.lock()?;
            rows(&connection)?;
            connection
                .execute(
                    "UPDATE selected_chat_key_packages SET state=2 WHERE state=0",
                    [],
                )
                .storage()?;
            Ok(())
        })
    }
}
