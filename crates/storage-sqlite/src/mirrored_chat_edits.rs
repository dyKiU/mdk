//! Edit relationships index immutable logical events; no MLS or send authority.
use cgka_traits::mirrored_chat_messages::MAX_MIRRORED_MESSAGE_PAYLOAD;

pub(crate) fn target(payload: &[u8]) -> Option<[u8; 32]> {
    if payload.len() > MAX_MIRRORED_MESSAGE_PAYLOAD {
        return None;
    }
    let logical: (String, Vec<Vec<String>>) = serde_json::from_slice(payload).ok()?;
    if serde_json::to_vec(&logical).ok()?.as_slice() != payload {
        return None;
    }
    let mut refs = logical
        .1
        .iter()
        .filter(|tag| tag.first().is_some_and(|v| v == "e"));
    let id = refs.next()?.get(1)?;
    if refs.next().is_some() || id.len() != 64 {
        return None;
    }
    let bytes: [u8; 32] = hex::decode(id).ok()?.try_into().ok()?;
    (bytes != [0; 32] && hex::encode(bytes) == *id).then_some(bytes)
}

#[cfg(feature = "experimental-device-sync")]
#[derive(Clone, PartialEq, Eq)]
pub struct MirroredMessageEdit {
    pub summary: crate::TimelineEditSummary,
    pub plaintext: String,
    /// Earliest retained edit expiry, for the live projection refresh timer.
    pub next_expiry: Option<u64>,
}

#[cfg(feature = "experimental-device-sync")]
pub(crate) fn resolve(
    conn: &rusqlite::Connection,
    scopes: &[cgka_traits::mirrored_chat_catalog::MirroredChatScope],
    group: &cgka_traits::GroupId,
    record: &cgka_traits::mirrored_chat_messages::MirroredChatRecord,
    now: u64,
) -> cgka_traits::storage::StorageResult<Option<MirroredMessageEdit>> {
    use crate::SqliteResultExt;
    use rusqlite::{OptionalExtension, params_from_iter, types::Value};
    if record.kind != 9
        || record.deleted
        || record.expires_at.is_some_and(|v| v <= now)
        || scopes.is_empty()
    {
        return Ok(None);
    }
    let mut values = scopes
        .iter()
        .map(|scope| crate::mirrored_chat_catalog::scope_bytes(scope).map(Value::Blob))
        .collect::<cgka_traits::storage::StorageResult<Vec<_>>>()?;
    let slots = vec!["?"; values.len()].join(",");
    values.extend([
        Value::Blob(group.as_slice().to_vec()),
        Value::Blob(record.event_id.to_vec()),
        Value::Blob(record.author.to_vec()),
        Value::Integer(now as i64),
    ]);
    let sql = format!("WITH ranked AS (
        SELECT m.*,(SELECT min(expiry.expires_at) FROM mirrored_chat_messages expiry WHERE expiry.group_id=m.group_id AND expiry.event_id=m.event_id) AS edit_expiry,row_number() OVER(PARTITION BY m.event_id ORDER BY m.scope) AS source_rank
        FROM mirrored_chat_messages m
        JOIN mirrored_chat_edit_targets t ON t.scope=m.scope AND t.group_id=m.group_id AND t.event_id=m.event_id
        JOIN mirrored_chat_live_catalog c ON c.scope=m.scope AND c.group_id=m.group_id
        JOIN mirrored_chat_scopes s ON s.scope=m.scope
        WHERE m.scope IN ({slots}) AND m.group_id=? AND t.target_id=? AND m.author=?
        AND m.kind=1009 AND m.deleted=0 AND c.state=0
        AND m.origin_id IS c.origin_id AND m.origin_order IS c.origin_order
        AND NOT EXISTS(SELECT 1 FROM mirrored_chat_messages terminal WHERE terminal.group_id=m.group_id AND terminal.event_id=m.event_id AND terminal.deleted=1)
        AND NOT EXISTS(SELECT 1 FROM mirrored_chat_messages expired WHERE expired.group_id=m.group_id AND expired.event_id=m.event_id AND expired.expires_at<=?)
    ) SELECT event_id,created_at,payload,count(*) OVER(),min(edit_expiry) OVER() FROM ranked WHERE source_rank=1
      ORDER BY created_at DESC,event_id DESC LIMIT 1");
    let row = conn
        .query_row(&sql, params_from_iter(values), |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })
        .optional()
        .storage()?;
    row.map(|(id, at, payload, count, next_expiry)| {
        let logical: (String, Vec<Vec<String>>) =
            serde_json::from_slice(&payload).map_err(|_| {
                cgka_traits::storage::StorageError::Serialization("invalid mirrored edit".into())
            })?;
        Ok(MirroredMessageEdit {
            summary: crate::TimelineEditSummary {
                edit_count: count as u64,
                latest_edit_message_id_hex: hex::encode(id),
                edited_at: at as u64,
            },
            plaintext: logical.0,
            next_expiry: next_expiry.map(|value| value as u64),
        })
    })
    .transpose()
}
