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

#[path = "mirrored_chat_presentation/activity.rs"]
mod activity;
pub use activity::MirroredChatActivityObservation;

#[derive(Clone, PartialEq, Eq)]
pub struct MirroredCatalogObservation {
    pub scope: MirroredChatScope,
    pub entry: MirroredChatEntry,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MirroredMessageObservation {
    pub scope: MirroredChatScope,
    pub record: MirroredChatRecord,
    pub edit: Option<crate::MirroredMessageEdit>,
}

/// Ordinary materialized rows keep their authenticated local provenance.
#[derive(Clone)]
pub enum AccountConversationObservation {
    LocalMls(Box<crate::TimelineMessageRecord>),
    PairedSource(Box<MirroredMessageObservation>),
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
            FROM eligible e JOIN mirrored_chat_live_catalog c ON c.scope=e.scope
            JOIN mirrored_chat_scopes s ON s.scope=c.scope
            WHERE c.state=0 AND c.group_id>?
            AND NOT EXISTS(SELECT 1 FROM cgka_groups g WHERE g.id=c.group_id)
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

    /// Resolve a source-attested direct peer through the bounded current scope
    /// set and peer index. This is a presentation route, never MLS membership.
    pub fn mirrored_direct_conversation_observation(
        &self,
        scopes: &[MirroredChatScope],
        peer: &[u8; 32],
    ) -> StorageResult<Option<MirroredCatalogObservation>> {
        let keys = eligible(scopes, 1)?;
        if *peer == [0; 32] || scopes.first().is_some_and(|scope| scope.account == *peer) {
            return Err(invalid());
        }
        let conn = self.lock()?;
        for scope in scopes {
            mirrored_chat_catalog::check_owner(&conn, scope)?;
        }
        if keys.is_empty() {
            return Ok(None);
        }
        let (prefix, mut arguments) = selection(&keys);
        arguments.push(Value::Blob(peer.to_vec()));
        let sql = format!(
            "{prefix} SELECT e.position,c.group_id,c.source_sequence,c.state,c.record
             FROM eligible e JOIN mirrored_chat_catalog c INDEXED BY mirrored_catalog_direct_peer
               ON c.scope=e.scope
             WHERE c.direct_peer=? AND c.state=0
               AND EXISTS(SELECT 1 FROM mirrored_chat_live_catalog live
                 WHERE live.scope=c.scope AND live.group_id=c.group_id)
               AND NOT EXISTS(SELECT 1 FROM cgka_groups g WHERE g.id=c.group_id)
             ORDER BY c.group_id,c.scope LIMIT 1"
        );
        let mut statement = conn.prepare(&sql).storage()?;
        let mut rows = statement.query(params_from_iter(arguments)).storage()?;
        let Some(row) = rows.next().storage()? else {
            return Ok(None);
        };
        let scope = scopes
            .get(row.get::<_, i64>(0).storage()? as usize)
            .ok_or_else(invalid)?;
        let entry = mirrored_chat_catalog::decode_entry(
            scope,
            row.get(1).storage()?,
            row.get(2).storage()?,
            row.get(3).storage()?,
            row.get(4).storage()?,
        )?;
        if entry.direct_peer_account != Some(*peer) {
            return Err(invalid());
        }
        Ok(Some(MirroredCatalogObservation {
            scope: scope.clone(),
            entry,
        }))
    }

    /// Resolve one mirrored header without walking preceding catalogue pages.
    pub fn mirrored_catalog_observation(
        &self,
        scopes: &[MirroredChatScope],
        group: &GroupId,
    ) -> StorageResult<Option<MirroredCatalogObservation>> {
        let keys = eligible(scopes, 1)?;
        if !(1..=255).contains(&group.as_slice().len()) {
            return Err(invalid());
        }
        let conn = self.lock()?;
        for scope in scopes {
            mirrored_chat_catalog::check_owner(&conn, scope)?;
        }
        if keys.is_empty() {
            return Ok(None);
        }
        let (prefix, mut arguments) = selection(&keys);
        arguments.push(Value::Blob(group.as_slice().to_vec()));
        let sql = format!(
            "{prefix} SELECT e.position,c.group_id,c.source_sequence,c.state,c.record
          FROM eligible e JOIN mirrored_chat_live_catalog c ON c.scope=e.scope
          JOIN mirrored_chat_scopes s ON s.scope=c.scope
          WHERE c.group_id=? AND c.state=0
          ORDER BY c.scope LIMIT 1"
        );
        let mut statement = conn.prepare(&sql).storage()?;
        let mut rows = statement.query(params_from_iter(arguments)).storage()?;
        let Some(row) = rows.next().storage()? else {
            return Ok(None);
        };
        let scope = scopes
            .get(row.get::<_, i64>(0).storage()? as usize)
            .ok_or_else(invalid)?;
        Ok(Some(MirroredCatalogObservation {
            scope: scope.clone(),
            entry: mirrored_chat_catalog::decode_entry(
                scope,
                row.get(1).storage()?,
                row.get(2).storage()?,
                row.get(3).storage()?,
                row.get(4).storage()?,
            )?,
        }))
    }

    /// A single total SQL limit over genuine ordinary and eligible mirrored rows.
    /// The exclusive cursor uses original event time/id, never local replay order.
    pub fn account_conversation_observation_window(
        &self,
        scopes: &[MirroredChatScope],
        group: &GroupId,
        before: Option<&MirroredChatCursor>,
        limit: usize,
        now: u64,
    ) -> StorageResult<Vec<AccountConversationObservation>> {
        let keys = eligible(scopes, limit)?;
        if !(1..=255).contains(&group.as_slice().len())
            || now > i64::MAX as u64
            || before.is_some_and(|v| v.created_at > i64::MAX as u64 || v.event_id == [0; 32])
        {
            return Err(invalid());
        }
        cgka_traits::StorageProvider::with_read_snapshot(self, |store| {
            let selected = {
                let conn = store.lock()?;
                for scope in scopes {
                    mirrored_chat_catalog::check_owner(&conn, scope)?;
                }
                let (prefix, mut arguments) = if keys.is_empty() {
                    (
                        "WITH eligible(position,scope) AS (SELECT 0,NULL WHERE 0)".to_owned(),
                        Vec::new(),
                    )
                } else {
                    selection(&keys)
                };
                arguments.extend([
                    Value::Blob(group.as_slice().to_vec()),
                    Value::Text(hex::encode(group.as_slice())),
                    Value::Text(hex::encode(group.as_slice())),
                    Value::Integer(before.is_some() as i64),
                    Value::Integer(before.map(|v| v.created_at as i64).unwrap_or(0)),
                    Value::Text(before.map(|v| hex::encode(v.event_id)).unwrap_or_default()),
                    Value::Integer(limit as i64),
                ]);
                let sql = format!("{prefix}, ranked AS (
              SELECT m.*,e.position,row_number() OVER(PARTITION BY m.event_id ORDER BY m.scope) AS rank
              FROM eligible e JOIN mirrored_chat_messages m ON m.scope=e.scope
              JOIN mirrored_chat_live_catalog c ON c.scope=m.scope AND c.group_id=m.group_id
              JOIN mirrored_chat_scopes s ON s.scope=m.scope
              WHERE m.kind<>1009 AND m.group_id=? AND c.state=0 AND m.origin_id IS c.origin_id AND m.origin_order IS c.origin_order
              AND NOT EXISTS(SELECT 1 FROM user_blocks blocked WHERE blocked.public_key=lower(hex(m.author)))
              AND NOT EXISTS(SELECT 1 FROM app_events live WHERE live.group_id_hex=? AND live.message_id_hex=lower(hex(m.event_id)))
              AND (m.deleted=1 OR NOT EXISTS(SELECT 1 FROM mirrored_chat_messages terminal WHERE terminal.group_id=m.group_id AND terminal.event_id=m.event_id AND terminal.deleted=1))
            ), united AS (
              SELECT 1 AS paired,position,created_at AS event_time,lower(hex(event_id)) AS event_id FROM ranked WHERE rank=1
              UNION ALL SELECT 0,0,timeline_at,message_id_hex FROM visible_message_timeline WHERE group_id_hex=?
            ) SELECT paired,position,event_time,event_id FROM united WHERE (?=0 OR (event_time,event_id)<(?,?))
              ORDER BY event_time DESC,event_id DESC LIMIT ?");
                let mut statement = conn.prepare(&sql).storage()?;
                statement
                    .query_map(params_from_iter(arguments), |row| {
                        Ok((
                            row.get::<_, bool>(0)?,
                            row.get::<_, i64>(1)? as usize,
                            row.get::<_, String>(3)?,
                        ))
                    })
                    .storage()?
                    .map(|row| row.storage())
                    .collect::<StorageResult<Vec<_>>>()?
            };
            let mut observed = Vec::with_capacity(selected.len());
            for (paired, position, event) in selected {
                if !paired {
                    let row = store
                        .timeline_message(&hex::encode(group.as_slice()), &event)?
                        .ok_or_else(invalid)?;
                    observed.push(AccountConversationObservation::LocalMls(Box::new(
                        store.scrub_paired_timeline_record(row, now)?,
                    )));
                } else {
                    let scope = scopes.get(position).ok_or_else(invalid)?;
                    let conn = store.lock()?;
                    let scope_key = mirrored_chat_catalog::scope_bytes(scope)?;
                    let event_bytes = hex::decode(&event).map_err(|_| invalid())?;
                    let (mut record,expiry)=conn.query_row("SELECT event_id,author,created_at,kind,payload,expires_at,content_digest,deleted,source_epoch,source_sequence,source_digest,origin_id,origin_order,
                (SELECT min(expires_at) FROM mirrored_chat_messages expiry WHERE expiry.group_id=m.group_id AND expiry.event_id=m.event_id)
                FROM mirrored_chat_messages m WHERE m.scope=? AND m.group_id=? AND m.event_id=?",rusqlite::params![scope_key,group.as_slice(),event_bytes],
                |row|Ok((mirrored_chat_messages::read_record(row)?,row.get::<_,Option<i64>>(13)?))).storage()?;
                    mirrored_chat_messages::validate(&record)?;
                    record.expires_at = expiry.map(|v| v as u64);
                    if record.expires_at.is_some_and(|v| v <= now) {
                        record.deleted = true;
                        record.payload.clear();
                    }
                    observed.push(AccountConversationObservation::PairedSource(Box::new(
                        MirroredMessageObservation {
                            scope: scope.clone(),
                            edit: crate::mirrored_chat_edits::resolve(
                                &conn, scopes, group, &record, now,
                            )?,
                            record,
                        },
                    )));
                }
            }
            observed.reverse();
            Ok(observed)
        })
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
        self.mirrored_message_observation_read(scopes, group, after, limit, now, false)
    }

    /// Latest bounded window or exclusive earlier canonical cursor. Returned
    /// rows remain ascending; the descending SQL limit never scans all records.
    pub fn mirrored_message_observation_window(
        &self,
        scopes: &[MirroredChatScope],
        group: &GroupId,
        before: Option<&MirroredChatCursor>,
        limit: usize,
        now: u64,
    ) -> StorageResult<Vec<MirroredMessageObservation>> {
        self.mirrored_message_observation_read(scopes, group, before, limit, now, true)
    }

    fn mirrored_message_observation_read(
        &self,
        scopes: &[MirroredChatScope],
        group: &GroupId,
        after: Option<&MirroredChatCursor>,
        limit: usize,
        now: u64,
        newest: bool,
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
        let comparison = if newest { "<" } else { ">" };
        let ordering = if newest {
            "created_at DESC,event_id DESC"
        } else {
            "created_at,event_id"
        };
        let sql = format!("{prefix}, ranked AS (
          SELECT m.*,e.position,row_number() OVER(PARTITION BY m.event_id ORDER BY m.scope) AS rank
          FROM eligible e JOIN mirrored_chat_messages m ON m.scope=e.scope
          JOIN mirrored_chat_live_catalog c ON c.scope=m.scope AND c.group_id=m.group_id
          JOIN mirrored_chat_scopes s ON s.scope=m.scope
          WHERE m.kind<>1009 AND m.group_id=? AND (?=0 OR (m.created_at,m.event_id){comparison}(?,?)) AND c.state=0 AND m.origin_id IS c.origin_id AND m.origin_order IS c.origin_order
          AND NOT EXISTS(SELECT 1 FROM user_blocks blocked WHERE blocked.public_key=lower(hex(m.author)))
          AND NOT EXISTS(SELECT 1 FROM app_events live WHERE live.group_id_hex=? AND live.message_id_hex=lower(hex(m.event_id)))
          AND (m.deleted=1 OR NOT EXISTS(SELECT 1 FROM mirrored_chat_messages terminal WHERE terminal.group_id=m.group_id AND terminal.event_id=m.event_id AND terminal.deleted=1))
        ) SELECT event_id,author,created_at,kind,payload,expires_at,content_digest,deleted,source_epoch,source_sequence,source_digest,origin_id,origin_order,position,
          (SELECT min(expiry.expires_at) FROM mirrored_chat_messages expiry WHERE expiry.group_id=ranked.group_id AND expiry.event_id=ranked.event_id)
          FROM ranked WHERE rank=1 ORDER BY {ordering} LIMIT ?");
        let mut statement = conn.prepare(&sql).storage()?;
        let rows = statement
            .query_map(params_from_iter(arguments), |row| {
                Ok((
                    mirrored_chat_messages::read_record(row)?,
                    row.get::<_, i64>(13)? as usize,
                    row.get::<_, Option<i64>>(14)?,
                ))
            })
            .storage()?;
        let mut observed = rows
            .map(|row| {
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
                    edit: crate::mirrored_chat_edits::resolve(&conn, scopes, group, &record, now)?,
                    record,
                })
            })
            .collect::<StorageResult<Vec<_>>>()?;
        if newest {
            observed.reverse();
        }
        Ok(observed)
    }
}

#[cfg(test)]
#[path = "mirrored_chat_presentation/tests.rs"]
mod tests;
