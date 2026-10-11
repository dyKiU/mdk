//! Bounded read-only union of caller-validated source scopes. No permission or MLS writes.
use crate::{SqliteAccountStorage, SqliteResultExt, mirrored_chat_catalog, mirrored_chat_messages};
use cgka_traits::{
    GroupId,
    mirrored_chat_catalog::{MAX_MIRRORED_CHAT_SCOPES, MirroredChatEntry, MirroredChatScope},
    mirrored_chat_messages::{MAX_MIRRORED_MESSAGE_PAGE, MirroredChatCursor, MirroredChatRecord},
    storage::{StorageError, StorageResult},
};
use rusqlite::{params_from_iter, types::Value};
use std::collections::HashSet;

#[derive(Clone, PartialEq, Eq)]
pub struct MirroredCatalogObservation {
    pub scope: MirroredChatScope,
    pub entry: MirroredChatEntry,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MirroredMessageObservation {
    pub scope: MirroredChatScope,
    pub record: MirroredChatRecord,
}

fn invalid() -> StorageError {
    StorageError::Serialization("invalid mirrored presentation read".into())
}

fn eligible(scopes: &[MirroredChatScope], limit: usize) -> StorageResult<Vec<Vec<u8>>> {
    if scopes.len() > MAX_MIRRORED_CHAT_SCOPES || !(1..=MAX_MIRRORED_MESSAGE_PAGE).contains(&limit)
    {
        return Err(invalid());
    }
    let keys = scopes
        .iter()
        .map(mirrored_chat_catalog::scope_bytes)
        .collect::<StorageResult<Vec<_>>>()?;
    let mut unique = HashSet::new();
    for (scope, key) in scopes.iter().zip(&keys) {
        if !unique.insert(key)
            || scopes.first().is_some_and(|first| {
                first.account != scope.account || first.local_device != scope.local_device
            })
        {
            return Err(invalid());
        }
    }
    Ok(keys)
}

fn selection(keys: &[Vec<u8>]) -> (String, Vec<Value>) {
    let values = keys
        .iter()
        .enumerate()
        .map(|(index, _)| format!("({},?)", index))
        .collect::<Vec<_>>()
        .join(",");
    (
        format!("WITH eligible(position,scope) AS (VALUES {values})"),
        keys.iter().cloned().map(Value::Blob).collect(),
    )
}

impl SqliteAccountStorage {
    /// Scope inputs are observations supplied by a freshly validating App worker.
    /// One total bound applies across all scopes. Existing ordinary groups win.
    pub fn mirrored_catalog_observation_page(
        &self,
        scopes: &[MirroredChatScope],
        after: Option<&GroupId>,
        limit: usize,
    ) -> StorageResult<Vec<MirroredCatalogObservation>> {
        let keys = eligible(scopes, limit)?;
        if after.is_some_and(|group| !(1..=255).contains(&group.as_slice().len())) {
            return Err(invalid());
        }
        let conn = self.lock()?;
        for scope in scopes {
            mirrored_chat_catalog::check_owner(&conn, scope)?;
        }
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let (prefix, mut arguments) = selection(&keys);
        arguments.push(Value::Blob(
            after.map(GroupId::as_slice).unwrap_or(&[]).to_vec(),
        ));
        arguments.push(Value::Integer(limit as i64));
        let sql = format!("{prefix}, ranked AS (
            SELECT e.position,c.group_id,c.source_sequence,c.state,c.record,
                row_number() OVER(PARTITION BY c.group_id ORDER BY c.scope) AS rank
            FROM eligible e JOIN mirrored_chat_catalog c ON c.scope=e.scope
            JOIN mirrored_chat_scopes s ON s.scope=c.scope
            WHERE c.state=0 AND c.group_id>?
            AND NOT EXISTS(SELECT 1 FROM cgka_groups g WHERE g.id=c.group_id)
            AND NOT EXISTS(SELECT 1 FROM mirrored_chat_catalog terminal
                JOIN mirrored_chat_scopes ts ON ts.scope=terminal.scope
                WHERE terminal.group_id=c.group_id AND terminal.state!=0 AND ts.source_device=s.source_device)
        ) SELECT position,group_id,source_sequence,state,record FROM ranked WHERE rank=1 ORDER BY group_id LIMIT ?");
        let mut statement = conn.prepare(&sql).storage()?;
        let rows = statement
            .query_map(params_from_iter(arguments), |row| {
                Ok((
                    row.get::<_, i64>(0)? as usize,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .storage()?;
        rows.map(|row| {
            let (position, group, sequence, state, bytes) = row.storage()?;
            let scope = scopes.get(position).ok_or_else(invalid)?;
            Ok(MirroredCatalogObservation {
                scope: scope.clone(),
                entry: mirrored_chat_catalog::decode_entry(scope, group, sequence, state, bytes)?,
            })
        })
        .collect()
    }

    /// Canonical event-time order, not local replay insert order. Ordinary live
    /// identities always suppress a mirror, including invalidated ordinary rows.
    pub fn mirrored_message_observation_page(
        &self,
        scopes: &[MirroredChatScope],
        group: &GroupId,
        after: Option<&MirroredChatCursor>,
        limit: usize,
        now: u64,
    ) -> StorageResult<Vec<MirroredMessageObservation>> {
        let keys = eligible(scopes, limit)?;
        if !(1..=255).contains(&group.as_slice().len())
            || now > i64::MAX as u64
            || after.is_some_and(|cursor| {
                cursor.created_at > i64::MAX as u64 || cursor.event_id == [0; 32]
            })
        {
            return Err(invalid());
        }
        let conn = self.lock()?;
        for scope in scopes {
            mirrored_chat_catalog::check_owner(&conn, scope)?;
        }
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let (prefix, mut arguments) = selection(&keys);
        arguments.extend([
            Value::Blob(group.as_slice().to_vec()),
            Value::Integer(after.is_some() as i64),
            Value::Integer(after.map(|cursor| cursor.created_at as i64).unwrap_or(0)),
            Value::Blob(
                after
                    .map(|cursor| cursor.event_id.to_vec())
                    .unwrap_or_default(),
            ),
            Value::Text(hex::encode(group.as_slice())),
            Value::Integer(limit as i64),
        ]);
        let sql = format!("{prefix}, ranked AS (
          SELECT m.*,e.position,row_number() OVER(PARTITION BY m.event_id ORDER BY m.scope) AS rank
          FROM eligible e JOIN mirrored_chat_messages m ON m.scope=e.scope
          JOIN mirrored_chat_catalog c ON c.scope=m.scope AND c.group_id=m.group_id
          JOIN mirrored_chat_scopes s ON s.scope=m.scope
          WHERE m.group_id=? AND (?=0 OR (m.created_at,m.event_id)>(?,?)) AND c.state=0
          AND NOT EXISTS(SELECT 1 FROM mirrored_chat_catalog terminal JOIN mirrored_chat_scopes ts ON ts.scope=terminal.scope WHERE terminal.group_id=c.group_id AND terminal.state!=0 AND ts.source_device=s.source_device)
          AND NOT EXISTS(SELECT 1 FROM user_blocks blocked WHERE blocked.public_key=lower(hex(m.author)))
          AND NOT EXISTS(SELECT 1 FROM app_events live WHERE live.group_id_hex=? AND live.message_id_hex=lower(hex(m.event_id)))
          AND (m.deleted=1 OR NOT EXISTS(SELECT 1 FROM mirrored_chat_messages terminal WHERE terminal.group_id=m.group_id AND terminal.event_id=m.event_id AND terminal.deleted=1))
        ) SELECT event_id,author,created_at,kind,payload,expires_at,content_digest,deleted,source_epoch,source_sequence,source_digest,position,
          (SELECT min(expiry.expires_at) FROM mirrored_chat_messages expiry WHERE expiry.group_id=ranked.group_id AND expiry.event_id=ranked.event_id)
          FROM ranked WHERE rank=1 ORDER BY created_at,event_id LIMIT ?");
        let mut statement = conn.prepare(&sql).storage()?;
        let rows = statement
            .query_map(params_from_iter(arguments), |row| {
                Ok((
                    mirrored_chat_messages::read_record(row)?,
                    row.get::<_, i64>(11)? as usize,
                    row.get::<_, Option<i64>>(12)?,
                ))
            })
            .storage()?;
        rows.map(|row| {
            let (mut record, position, expiry) = row.storage()?;
            mirrored_chat_messages::validate(&record)?;
            record.expires_at = expiry.map(|value| value as u64);
            if record.expires_at.is_some_and(|expiry| expiry <= now) {
                record.deleted = true;
                record.payload.clear();
            }
            let scope = scopes.get(position).ok_or_else(invalid)?;
            Ok(MirroredMessageObservation {
                scope: scope.clone(),
                record,
            })
        })
        .collect()
    }
}

#[cfg(test)]
#[path = "mirrored_chat_presentation/tests.rs"]
mod tests;
