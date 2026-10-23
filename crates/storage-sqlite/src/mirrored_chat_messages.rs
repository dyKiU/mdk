//! Bounded source-attested records; no app_events, Group rows or MLS writes.
use crate::{
    SqliteAppStorage, SqliteResultExt,
    mirrored_chat_catalog::{check_owner, scope_bytes},
};
use cgka_traits::{
    GroupId,
    mirrored_chat_catalog::MirroredChatScope,
    mirrored_chat_messages::{
        MAX_MIRRORED_MESSAGE_BYTES, MAX_MIRRORED_MESSAGE_PAGE, MAX_MIRRORED_MESSAGE_PAYLOAD,
        MirroredChatCursor, MirroredChatMessageStorage, MirroredChatRecord,
    },
    storage::{StorageError, StorageResult},
};
use rusqlite::{Connection, OptionalExtension, Row, params};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

fn invalid() -> StorageError {
    StorageError::Serialization("invalid mirrored message observation".into())
}
fn group_valid(group: &GroupId) -> bool {
    (1..=255).contains(&group.as_slice().len())
}
pub(crate) fn validate(record: &MirroredChatRecord) -> StorageResult<()> {
    if record.event_id == [0; 32]
        || record.author == [0; 32]
        || record.source_digest == [0; 32]
        || record.created_at > i64::MAX as u64
        || record.source_epoch > i64::MAX as u64
        || record.source_sequence == 0
        || record.source_sequence > i64::MAX as u64
        || record.expires_at.is_some_and(|t| t > i64::MAX as u64)
        || record.content_digest == Some([0; 32])
        || record.payload.len() > MAX_MIRRORED_MESSAGE_PAYLOAD
        || (record.deleted && !record.payload.is_empty())
        || (!record.deleted
            && (record.payload.is_empty()
                || record.content_digest != Some(Sha256::digest(&record.payload).into())))
    {
        return Err(invalid());
    }
    crate::mirrored_chat_catalog::validate_origin(record.accepted_origin)?;
    Ok(())
}
pub(crate) fn check_catalog(
    conn: &Connection,
    scope: &MirroredChatScope,
    key: &[u8],
    group: &GroupId,
) -> StorageResult<()> {
    if !group_valid(group) || group == &scope.protected_group {
        return Err(invalid());
    }
    check_owner(conn, scope)?;
    let active:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM mirrored_chat_live_catalog WHERE scope=?1 AND group_id=?2 AND ?3 IS NOT NULL)",params![key,group.as_slice(),scope.source_device.as_slice()],|r|r.get(0)).storage()?;
    if !active {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn read_record(row: &Row<'_>) -> rusqlite::Result<MirroredChatRecord> {
    fn fixed(row: &Row<'_>, column: usize) -> rusqlite::Result<[u8; 32]> {
        let bytes: Vec<u8> = row.get(column)?;
        bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
    }
    let digest: Option<Vec<u8>> = row.get(6)?;
    let origin_id: Option<Vec<u8>> = row.get(11)?;
    let origin_order: Option<i64> = row.get(12)?;
    let accepted_origin = match (origin_id, origin_order) {
        (None, None) => None,
        (Some(bytes), Some(order)) if (1..=8192).contains(&order) => {
            let id: [u8; 32] = bytes
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            if id == [0; 32] {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Some(cgka_traits::mirrored_chat_catalog::AcceptedChatOrigin {
                id,
                order: order as u64,
            })
        }
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    Ok(MirroredChatRecord {
        event_id: fixed(row, 0)?,
        author: fixed(row, 1)?,
        created_at: row.get::<_, i64>(2)? as u64,
        kind: row.get(3)?,
        payload: row.get(4)?,
        expires_at: row.get::<_, Option<i64>>(5)?.map(|n| n as u64),
        content_digest: digest
            .map(|b| b.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        deleted: row.get(7)?,
        source_epoch: row.get::<_, i64>(8)? as u64,
        source_sequence: row.get::<_, i64>(9)? as u64,
        source_digest: fixed(row, 10)?,

        accepted_origin,
    })
}
const COLUMNS: &str = "event_id,author,created_at,kind,payload,expires_at,content_digest,deleted,source_epoch,source_sequence,source_digest,origin_id,origin_order";
fn load(
    conn: &Connection,
    key: &[u8],
    group: &GroupId,
    id: &[u8; 32],
) -> StorageResult<Option<MirroredChatRecord>> {
    let record=conn.query_row(&format!("SELECT {COLUMNS} FROM mirrored_chat_messages WHERE scope=?1 AND group_id=?2 AND event_id=?3"),
      params![key,group.as_slice(),id.as_slice()],read_record).optional().storage()?;
    if let Some(r) = &record {
        validate(r)?;
    }
    Ok(record)
}
fn restrictive_expiry(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}
fn global_expiry(conn: &Connection, group: &GroupId, id: &[u8; 32]) -> StorageResult<Option<u64>> {
    conn.query_row(
        "SELECT min(expires_at) FROM mirrored_chat_messages WHERE group_id=?1 AND event_id=?2",
        params![group.as_slice(), id.as_slice()],
        |r| r.get::<_, Option<i64>>(0),
    )
    .storage()
    .map(|t| t.map(|n| n as u64))
}
fn write(
    conn: &Connection,
    key: &[u8],
    group: &GroupId,
    record: &MirroredChatRecord,
    exists: bool,
) -> StorageResult<()> {
    let sql = if exists {
        "UPDATE mirrored_chat_messages SET author=?4,created_at=?5,kind=?6,payload=?7,content_digest=?8,expires_at=?9,deleted=?10,source_epoch=?11,source_sequence=?12,source_digest=?13,origin_id=?14,origin_order=?15 WHERE scope=?1 AND group_id=?2 AND event_id=?3"
    } else {
        "INSERT INTO mirrored_chat_messages(scope,group_id,event_id,author,created_at,kind,payload,content_digest,expires_at,deleted,source_epoch,source_sequence,source_digest,origin_id,origin_order) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)"
    };
    conn.execute(
        sql,
        params![
            key,
            group.as_slice(),
            record.event_id.as_slice(),
            record.author.as_slice(),
            record.created_at as i64,
            record.kind,
            record.payload,
            record.content_digest.as_ref().map(|d| d.as_slice()),
            record.expires_at.map(|t| t as i64),
            record.deleted,
            record.source_epoch as i64,
            record.source_sequence as i64,
            record.source_digest.as_slice(),
            record.accepted_origin.map(|o| o.id.to_vec()),
            record.accepted_origin.map(|o| o.order as i64),
        ],
    )
    .storage()?;
    if record.kind == 1009
        && let Some(target) = crate::mirrored_chat_edits::target(&record.payload)
    {
        conn.execute(
            "INSERT OR IGNORE INTO mirrored_chat_edit_targets VALUES(?1,?2,?3,?4)",
            params![
                key,
                group.as_slice(),
                record.event_id.as_slice(),
                target.as_slice()
            ],
        )
        .storage()?;
    }
    Ok(())
}

impl MirroredChatMessageStorage for SqliteAppStorage {
    fn apply_mirrored_chat_messages(
        &self,
        scope: &MirroredChatScope,
        group: &GroupId,
        records: &[MirroredChatRecord],
        now: u64,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<usize> {
        let key = scope_bytes(scope)?;
        if !(1..=MAX_MIRRORED_MESSAGE_PAGE).contains(&records.len()) || now > i64::MAX as u64 {
            return Err(invalid());
        }
        let mut ids = HashSet::new();
        for record in records {
            validate(record)?;
            if !ids.insert(record.event_id) {
                return Err(invalid());
            }
        }
        self.connection.with_transaction(|| {
            validate_original()?;
            let conn = self.lock()?;
            check_catalog(&conn, scope, &key, group)?;
            let mut changed = 0;
            for original in records {
                if crate::account_chat_departure::account_chat_departure_denies_source_on_connection(&conn,&scope.account,&scope.local_device,group,&scope.source_device,original.accepted_origin)? {return Err(invalid());}
                let matches: bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM mirrored_chat_live_catalog WHERE scope=?1 AND group_id=?2 AND origin_id IS ?3 AND origin_order IS ?4)",params![key,group.as_slice(),original.accepted_origin.map(|o|o.id.to_vec()),original.accepted_origin.map(|o|o.order as i64)],|r|r.get(0)).storage()?;
                if !matches {return Err(invalid());}
                let old = load(&conn, &key, group, &original.event_id)?;
                if old
                    .as_ref()
                    .is_some_and(|r| original.source_sequence < r.source_sequence)
                {
                    continue;
                }
                let mut record = original.clone();
                record.expires_at = restrictive_expiry(
                    record.expires_at,
                    global_expiry(&conn, group, &record.event_id)?,
                );
                if record.expires_at.is_some_and(|t| t <= now) {
                    record.deleted = true;
                    record.payload.clear();
                }
                if let Some(previous) = &old {
                    if previous.deleted && !record.deleted {
                        return Err(invalid());
                    }
                    if record.content_digest.is_none() {
                        record.content_digest = previous.content_digest;
                    }
                    if record.source_sequence == previous.source_sequence {
                        if record == *previous {
                            continue;
                        }
                        // Only local expiry may change an otherwise exact source observation.
                        let mut expired = previous.clone();
                        expired.deleted = true;
                        expired.payload.clear();
                        expired.expires_at = record.expires_at;
                        if !record.deleted
                            || !record.expires_at.is_some_and(|t| t <= now)
                            || record != expired
                        {
                            return Err(invalid());
                        }
                    }
                }
                write(&conn, &key, group, &record, old.is_some())?;
                changed += 1;
            }
            let bytes: i64 = conn
                .query_row(
                    "SELECT coalesce(sum(length(payload)),0) FROM mirrored_chat_messages",
                    [],
                    |r| r.get(0),
                )
                .storage()?;
            if bytes > MAX_MIRRORED_MESSAGE_BYTES as i64 {
                return Err(invalid());
            }
            drop(conn);
            validate_original()?;
            Ok(changed)
        })
    }
    fn mirrored_chat_message_page(
        &self,
        scope: &MirroredChatScope,
        group: &GroupId,
        after: Option<&MirroredChatCursor>,
        limit: usize,
        now: u64,
    ) -> StorageResult<Vec<MirroredChatRecord>> {
        let key = scope_bytes(scope)?;
        if !(1..=MAX_MIRRORED_MESSAGE_PAGE).contains(&limit)
            || now > i64::MAX as u64
            || after.is_some_and(|c| c.created_at > i64::MAX as u64 || c.event_id == [0; 32])
        {
            return Err(invalid());
        }
        let conn = self.lock()?;
        check_catalog(&conn, scope, &key, group)?;
        let mut statement=conn.prepare(&format!("SELECT {COLUMNS} FROM mirrored_chat_messages own WHERE scope=?1 AND group_id=?2
          AND (?3=0 OR (created_at,event_id)>(?4,?5))
          AND EXISTS(SELECT 1 FROM mirrored_chat_live_catalog c WHERE c.scope=own.scope AND c.group_id=own.group_id AND c.origin_id IS own.origin_id AND c.origin_order IS own.origin_order)
          AND (deleted=1 OR NOT EXISTS(SELECT 1 FROM mirrored_chat_messages terminal WHERE terminal.group_id=own.group_id AND terminal.event_id=own.event_id AND terminal.deleted=1))
          ORDER BY created_at,event_id LIMIT ?6")).storage()?;
        let rows = statement
            .query_map(
                params![
                    key,
                    group.as_slice(),
                    after.is_some(),
                    after.map(|c| c.created_at as i64).unwrap_or(0),
                    after.map(|c| c.event_id.as_slice()).unwrap_or(&[]),
                    limit as i64
                ],
                read_record,
            )
            .storage()?;
        let mut records = Vec::new();
        for row in rows {
            let mut record = row.storage()?;
            validate(&record)?;
            record.expires_at = restrictive_expiry(
                record.expires_at,
                global_expiry(&conn, group, &record.event_id)?,
            );
            if record.expires_at.is_some_and(|t| t <= now) {
                record.deleted = true;
                record.payload.clear();
            }
            records.push(record);
        }
        Ok(records)
    }
    fn purge_expired_mirrored_chat_messages(
        &self,
        scope: &MirroredChatScope,
        group: &GroupId,
        now: u64,
        limit: usize,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<usize> {
        let key = scope_bytes(scope)?;
        if !(1..=MAX_MIRRORED_MESSAGE_PAGE).contains(&limit) || now > i64::MAX as u64 {
            return Err(invalid());
        }
        self.connection.with_transaction(|| {
            validate_original()?;let conn=self.lock()?;check_owner(&conn,scope)?;
            if !group_valid(group) || group==&scope.protected_group {return Err(invalid());}
            let mut statement=conn.prepare(&format!("SELECT {COLUMNS} FROM mirrored_chat_messages own WHERE scope=?1 AND group_id=?2 AND deleted=0
              AND EXISTS(SELECT 1 FROM mirrored_chat_messages expired WHERE expired.group_id=own.group_id AND expired.event_id=own.event_id AND expired.expires_at<=?3)
              ORDER BY created_at,event_id LIMIT ?4")).storage()?;
            let rows=statement.query_map(params![key,group.as_slice(),now as i64,limit as i64],read_record).storage()?;
            let mut records=Vec::new();for row in rows {records.push(row.storage()?);}drop(statement);
            for record in &mut records {validate(record)?;record.expires_at=restrictive_expiry(record.expires_at,global_expiry(&conn,group,&record.event_id)?);record.deleted=true;record.payload.clear();write(&conn,&key,group,record,true)?;}
            drop(conn);validate_original()?;Ok(records.len())
        })
    }
}

#[cfg(test)]
#[path = "mirrored_chat_messages/tests.rs"]
mod tests;
