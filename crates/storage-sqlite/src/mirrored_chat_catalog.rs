//! Account-private source-attested catalog. No live Group or MLS mutations.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::{
    GroupId,
    mirrored_chat_catalog::*,
    storage::{StorageError, StorageResult},
};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashSet;

fn invalid() -> StorageError {
    StorageError::Serialization("invalid mirrored chat observation".into())
}

fn conflict() -> StorageError {
    StorageError::Serialization("conflicting mirrored chat observation".into())
}

fn group_valid(group: &GroupId) -> bool {
    (1..=255).contains(&group.as_slice().len())
}

pub(crate) fn scope_bytes(scope: &MirroredChatScope) -> StorageResult<Vec<u8>> {
    if scope.account == [0; 32]
        || scope.local_device == [0; 32]
        || scope.source_device == [0; 32]
        || scope.source_device == scope.local_device
        || scope.policy_digest == [0; 32]
        || !group_valid(&scope.protected_group)
        || scope.protected_generation == 0
        || scope.protected_generation > i64::MAX as u64
    {
        return Err(invalid());
    }
    let bytes = crate::serialize(scope)?;
    if bytes.len() > 2048 {
        return Err(invalid());
    }
    Ok(bytes)
}

fn entry_bytes(scope: &MirroredChatScope, entry: &MirroredChatEntry) -> StorageResult<Vec<u8>> {
    if !group_valid(&entry.group_id)
        || entry.group_id == scope.protected_group
        || entry.source_epoch > i64::MAX as u64
        || entry.source_sequence == 0
        || entry.source_sequence > i64::MAX as u64
        || entry.source_digest == [0; 32]
        || entry.name.len() > 1024
        || entry.description.len() > 8192
        || (entry.state != MirroredChatState::Active
            && (!entry.name.is_empty() || !entry.description.is_empty()))
    {
        return Err(invalid());
    }
    let bytes = crate::serialize(entry)?;
    if bytes.len() > 32768 {
        return Err(invalid());
    }
    Ok(bytes)
}

fn state_value(state: MirroredChatState) -> i64 {
    match state {
        MirroredChatState::Active => 0,
        MirroredChatState::Left => 1,
        MirroredChatState::Deleted => 2,
    }
}

pub(crate) fn check_owner(conn: &Connection, scope: &MirroredChatScope) -> StorageResult<()> {
    crate::approved_account_sharing_policy::check_configured_owner(
        conn,
        &scope.account,
        &scope.local_device,
    )?;
    let mismatched: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM mirrored_chat_scopes WHERE account!=?1 OR local_device!=?2)", params![scope.account.as_slice(),scope.local_device.as_slice()], |r|r.get(0)).storage()?;
    if mismatched {
        return Err(invalid());
    }
    Ok(())
}

fn decode_entry(
    scope: &MirroredChatScope,
    group: Vec<u8>,
    sequence: i64,
    state: i64,
    bytes: Vec<u8>,
) -> StorageResult<MirroredChatEntry> {
    if bytes.len() > 32768 {
        return Err(invalid());
    }
    let entry: MirroredChatEntry = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    entry_bytes(scope, &entry)?;
    if entry.group_id.as_slice() != group
        || entry.source_sequence != sequence as u64
        || state_value(entry.state) != state
    {
        return Err(invalid());
    }
    Ok(entry)
}

impl MirroredChatCatalogStorage for SqliteAccountStorage {
    fn apply_mirrored_chat_catalog(
        &self,
        scope: &MirroredChatScope,
        entries: &[MirroredChatEntry],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<usize> {
        let scope_key = scope_bytes(scope)?;
        if !(1..=MAX_MIRRORED_CHAT_PAGE).contains(&entries.len()) {
            return Err(invalid());
        }
        let mut ids = HashSet::new();
        let bodies = entries
            .iter()
            .map(|entry| {
                if !ids.insert(entry.group_id.clone()) {
                    return Err(invalid());
                }
                entry_bytes(scope, entry)
            })
            .collect::<StorageResult<Vec<_>>>()?;
        self.connection.with_transaction(|| {
            validate_original()?;
            let conn=self.lock()?;
            check_owner(&conn,scope)?;
            let exists:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM mirrored_chat_scopes WHERE scope=?1)",[&scope_key],|r|r.get(0)).storage()?;
            if !exists {
                conn.execute("INSERT INTO mirrored_chat_scopes(scope,account,local_device,source_device) VALUES(?1,?2,?3,?4)",params![scope_key,scope.account.as_slice(),scope.local_device.as_slice(),scope.source_device.as_slice()]).storage()?;
            }
            let mut changed=0;
            for (entry,body) in entries.iter().zip(&bodies) {
                let previous:Option<(Vec<u8>,i64,i64,Vec<u8>)>=conn.query_row("SELECT group_id,source_sequence,state,record FROM mirrored_chat_catalog WHERE scope=?1 AND group_id=?2",params![scope_key,entry.group_id.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().storage()?;
                if let Some((group,sequence,state,bytes))=previous {
                    let old=decode_entry(scope,group,sequence,state,bytes)?;
                    if entry.source_sequence<old.source_sequence { continue; }
                    if entry.source_sequence==old.source_sequence {
                        if *entry!=old { return Err(conflict()); }
                        continue;
                    }
                    if old.state!=MirroredChatState::Active && entry.state!=old.state { return Err(conflict()); }
                    if entry.source_epoch<old.source_epoch { return Err(conflict()); }
                    conn.execute("UPDATE mirrored_chat_catalog SET source_sequence=?3,state=?4,record=?5 WHERE scope=?1 AND group_id=?2",params![scope_key,entry.group_id.as_slice(),entry.source_sequence as i64,state_value(entry.state),body]).storage()?;
                } else {
                    conn.execute("INSERT INTO mirrored_chat_catalog(scope,group_id,source_sequence,state,record) VALUES(?1,?2,?3,?4,?5)",params![scope_key,entry.group_id.as_slice(),entry.source_sequence as i64,state_value(entry.state),body]).storage()?;
                }
                changed+=1;
            }
            // Release the connection guard before a fresh Core check on this
            // same transaction. The original callback never becomes a row.
            drop(conn);
            validate_original()?;
            Ok(changed)
        })
    }

    fn mirrored_chat_catalog_page(
        &self,
        scope: &MirroredChatScope,
        after: Option<&GroupId>,
        limit: usize,
    ) -> StorageResult<Vec<MirroredChatEntry>> {
        let key = scope_bytes(scope)?;
        if !(1..=MAX_MIRRORED_CHAT_PAGE).contains(&limit)
            || after.is_some_and(|group| !group_valid(group))
        {
            return Err(invalid());
        }
        let conn = self.lock()?;
        check_owner(&conn, scope)?;
        let mut statement = conn
            .prepare(
                "SELECT c.group_id,c.source_sequence,c.state,c.record FROM mirrored_chat_catalog c
            WHERE c.scope=?1 AND c.group_id>?2 AND (c.state!=0 OR NOT EXISTS(
              SELECT 1 FROM mirrored_chat_catalog terminal
              JOIN mirrored_chat_scopes s ON s.scope=terminal.scope
              WHERE terminal.group_id=c.group_id AND terminal.state!=0 AND s.source_device=?4))
            ORDER BY c.group_id LIMIT ?3",
            )
            .storage()?;
        let records = statement
            .query_map(
                params![
                    key,
                    after.map(GroupId::as_slice).unwrap_or(&[]),
                    limit as i64,
                    scope.source_device.as_slice()
                ],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .storage()?;
        records
            .map(|row| {
                let (group, sequence, state, body) = row.storage()?;
                decode_entry(scope, group, sequence, state, body)
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "mirrored_chat_catalog/tests.rs"]
mod tests;
