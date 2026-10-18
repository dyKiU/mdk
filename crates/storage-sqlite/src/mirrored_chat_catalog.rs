//! Account-private source-attested catalog. No live Group or MLS mutations.
use crate::{SqliteAppStorage, SqliteResultExt};
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

pub(crate) fn validate_origin(origin: Option<AcceptedChatOrigin>) -> StorageResult<()> {
    if origin.is_some_and(|o| o.id == [0; 32] || !(1..=8192).contains(&o.order)) {
        return Err(invalid());
    }
    Ok(())
}

// Metadata only; the outer transaction still revalidates the real original.
fn prepare_lineage(
    conn: &Connection,
    scope: &MirroredChatScope,
    entry: &MirroredChatEntry,
) -> StorageResult<bool> {
    validate_origin(entry.accepted_origin)?;
    let current: Option<(Vec<u8>,i64,i64)> = conn.query_row("SELECT origin_id,origin_order,epoch FROM mirrored_chat_origin_current WHERE account=?1 AND local_device=?2 AND source_device=?3 AND group_id=?4",params![scope.account.as_slice(),scope.local_device.as_slice(),scope.source_device.as_slice(),entry.group_id.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().storage()?;
    if entry.state != MirroredChatState::Active {
        if entry.accepted_origin.is_none() && current.is_some() {
            return Ok(false);
        }
        let (id, order) = entry
            .accepted_origin
            .map(|o| (o.id, o.order))
            .unwrap_or(([0; 32], 0));
        let prior: Option<(i64,i64,i64)>=conn.query_row("SELECT origin_order,epoch,state FROM mirrored_chat_origin_fences WHERE account=?1 AND local_device=?2 AND source_device=?3 AND group_id=?4 AND origin_id=?5",params![scope.account.as_slice(),scope.local_device.as_slice(),scope.source_device.as_slice(),entry.group_id.as_slice(),id.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().storage()?;
        if let Some((old_order, epoch, state)) = prior {
            if old_order != order as i64 {
                return Err(conflict());
            }
            conn.execute("UPDATE mirrored_chat_origin_fences SET epoch=?6,state=?7 WHERE account=?1 AND local_device=?2 AND source_device=?3 AND group_id=?4 AND origin_id=?5",params![scope.account.as_slice(),scope.local_device.as_slice(),scope.source_device.as_slice(),entry.group_id.as_slice(),id.as_slice(),epoch.max(entry.source_epoch as i64),state.max(state_value(entry.state))]).storage()?;
        } else {
            conn.execute(
                "INSERT INTO mirrored_chat_origin_fences VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    scope.account.as_slice(),
                    scope.local_device.as_slice(),
                    scope.source_device.as_slice(),
                    entry.group_id.as_slice(),
                    id.as_slice(),
                    order as i64,
                    entry.source_epoch as i64,
                    state_value(entry.state)
                ],
            )
            .storage()?;
        }
        return Ok(
            current.is_none_or(|(old_id, old_order, _)| old_id == id && old_order == order as i64)
        );
    }
    let blocked:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM mirrored_chat_origin_fences WHERE account=?1 AND local_device=?2 AND source_device=?3 AND group_id=?4 AND (state=2 OR origin_id=?5 OR (origin_order=0 AND (?6=0 OR epoch>=?7)) OR (origin_order>0 AND (origin_order>=?6 OR epoch>?7))))",params![scope.account.as_slice(),scope.local_device.as_slice(),scope.source_device.as_slice(),entry.group_id.as_slice(),entry.accepted_origin.map(|o|o.id.to_vec()).unwrap_or_default(),entry.accepted_origin.map(|o|o.order as i64).unwrap_or(0),entry.source_epoch as i64],|r|r.get(0)).storage()?;
    if blocked {
        return Err(conflict());
    }
    let Some(origin) = entry.accepted_origin else {
        return if current.is_none() {
            Ok(true)
        } else {
            Err(conflict())
        };
    };
    if let Some((id, order, epoch)) = current {
        if origin.order < (order as u64)
            || (origin.order == order as u64 && id != origin.id)
            || entry.source_epoch < (epoch as u64)
        {
            return Err(conflict());
        }
        conn.execute("UPDATE mirrored_chat_origin_current SET origin_id=?5,origin_order=?6,epoch=?7 WHERE account=?1 AND local_device=?2 AND source_device=?3 AND group_id=?4",params![scope.account.as_slice(),scope.local_device.as_slice(),scope.source_device.as_slice(),entry.group_id.as_slice(),origin.id.as_slice(),origin.order as i64,entry.source_epoch as i64]).storage()?;
    } else {
        conn.execute(
            "INSERT INTO mirrored_chat_origin_current VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                scope.account.as_slice(),
                scope.local_device.as_slice(),
                scope.source_device.as_slice(),
                entry.group_id.as_slice(),
                origin.id.as_slice(),
                origin.order as i64,
                entry.source_epoch as i64
            ],
        )
        .storage()?;
    }
    Ok(true)
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
    validate_origin(entry.accepted_origin)?;
    if entry.direct_peer_account.is_some_and(|peer| {
        peer == [0; 32] || peer == scope.account || entry.state != MirroredChatState::Active
    }) {
        return Err(invalid());
    }
    if entry
        .same_account_source_count
        .is_some_and(|n| !(1..=128).contains(&n))
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

pub(crate) fn decode_entry(
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

impl MirroredChatCatalogStorage for SqliteAppStorage {
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
                let previous=previous.map(|(group,sequence,state,bytes)|decode_entry(scope,group,sequence,state,bytes)).transpose()?;
                if let Some(old)=&previous {
                    if entry.source_sequence<old.source_sequence && entry.state==MirroredChatState::Active {continue;}
                    if entry.source_sequence==old.source_sequence {
                        if *entry!=*old {return Err(conflict());}
                        continue;
                    }
                }
                if entry.state==MirroredChatState::Active && crate::account_chat_departure::account_chat_departure_denies_source_on_connection(&conn,&scope.account,&scope.local_device,&entry.group_id,&scope.source_device,entry.accepted_origin)? {continue;}
                if !prepare_lineage(&conn,scope,entry)? {continue;}
                if let Some(old)=previous {
                    if entry.source_sequence<old.source_sequence {continue;}
                    if old.state!=MirroredChatState::Active && entry.state!=old.state && !(old.state==MirroredChatState::Left && entry.state==MirroredChatState::Active && entry.accepted_origin.is_some_and(|b| old.accepted_origin.map_or(entry.source_epoch>old.source_epoch, |a| a.id!=b.id && b.order>a.order))) { return Err(conflict()); }
                    if entry.source_epoch<old.source_epoch { return Err(conflict()); }
                    conn.execute("UPDATE mirrored_chat_catalog SET source_sequence=?3,state=?4,record=?5,origin_id=?6,origin_order=?7,direct_peer=?8 WHERE scope=?1 AND group_id=?2",params![scope_key,entry.group_id.as_slice(),entry.source_sequence as i64,state_value(entry.state),body,entry.accepted_origin.map(|o|o.id.to_vec()),entry.accepted_origin.map(|o|o.order as i64),entry.direct_peer_account.map(|peer|peer.to_vec())]).storage()?;
                } else {
                    conn.execute("INSERT INTO mirrored_chat_catalog(scope,group_id,source_sequence,state,record,origin_id,origin_order,direct_peer) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![scope_key,entry.group_id.as_slice(),entry.source_sequence as i64,state_value(entry.state),body,entry.accepted_origin.map(|o|o.id.to_vec()),entry.accepted_origin.map(|o|o.order as i64),entry.direct_peer_account.map(|peer|peer.to_vec())]).storage()?;
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
            WHERE c.scope=?1 AND c.group_id>?2 AND (c.state!=0 OR EXISTS(SELECT 1 FROM mirrored_chat_live_catalog live WHERE live.scope=c.scope AND live.group_id=c.group_id)) AND ?4 IS NOT NULL
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
