//! One snapshot of catalog headers and their latest source-qualified messages.
use super::*;

#[derive(Clone)]
pub struct MirroredChatActivityObservation {
    pub catalog: MirroredCatalogObservation,
    pub latest_message: Option<MirroredMessageObservation>,
}

impl SqliteAppStorage {
    /// Preserve catalog cursor order and the total page bound. The latest
    /// record is an observation, including a scrubbed deletion/expiry marker;
    /// it does not create local membership or initialize unread state.
    pub fn mirrored_catalog_activity_page(
        &self,
        scopes: &[MirroredChatScope],
        after: Option<&GroupId>,
        limit: usize,
        now: u64,
    ) -> StorageResult<Vec<MirroredChatActivityObservation>> {
        let keys = eligible(scopes, limit)?;
        if now > i64::MAX as u64 {
            return Err(invalid());
        }
        self.with_read_snapshot(|store| {
            let mut page = store
                .mirrored_catalog_observation_page(scopes, after, limit)?
                .into_iter()
                .map(|catalog| MirroredChatActivityObservation {
                    catalog,
                    latest_message: None,
                })
                .collect::<Vec<_>>();
            if page.is_empty() {
                return Ok(page);
            }
            let (prefix, mut arguments) = selection(&keys);
            let groups = page
                .iter()
                .enumerate()
                .map(|(index, row)| {
                    arguments.push(Value::Blob(row.catalog.entry.group_id.as_slice().to_vec()));
                    format!("({index},?)")
                })
                .collect::<Vec<_>>()
                .join(",");
            // Rank source duplicates before taking each group's tail. Keep the
            // same owner/origin/block/live-identity/terminal fences as the
            // source-qualified conversation window, before the per-group limit.
            let sql = format!("{prefix}, page(group_position,group_id) AS (VALUES {groups}), ranked AS (
                SELECT m.scope,m.group_id,m.event_id,m.created_at,e.position AS source_position,p.group_position,
                    row_number() OVER(PARTITION BY m.group_id,m.event_id ORDER BY m.scope) AS source_rank
                FROM eligible e JOIN mirrored_chat_messages m ON m.scope=e.scope
                JOIN page p ON p.group_id=m.group_id
                JOIN mirrored_chat_live_catalog c ON c.scope=m.scope AND c.group_id=m.group_id
                JOIN mirrored_chat_scopes s ON s.scope=m.scope
                WHERE m.kind<>1009 AND c.state=0 AND m.origin_id IS c.origin_id AND m.origin_order IS c.origin_order
                AND NOT EXISTS(SELECT 1 FROM user_blocks blocked WHERE blocked.public_key=lower(hex(m.author)))
                AND NOT EXISTS(SELECT 1 FROM app_events live WHERE live.group_id_hex=lower(hex(m.group_id)) AND live.message_id_hex=lower(hex(m.event_id)))
                AND (m.deleted=1 OR NOT EXISTS(SELECT 1 FROM mirrored_chat_messages terminal WHERE terminal.group_id=m.group_id AND terminal.event_id=m.event_id AND terminal.deleted=1))
            ), latest AS (
                SELECT *,row_number() OVER(PARTITION BY group_id ORDER BY created_at DESC,event_id DESC) AS activity_rank
                FROM ranked WHERE source_rank=1
            ) SELECT m.event_id,m.author,m.created_at,m.kind,m.payload,m.expires_at,m.content_digest,m.deleted,
                m.source_epoch,m.source_sequence,m.source_digest,m.origin_id,m.origin_order,latest.source_position,latest.group_position,
                (SELECT min(expiry.expires_at) FROM mirrored_chat_messages expiry WHERE expiry.group_id=latest.group_id AND expiry.event_id=latest.event_id)
                FROM latest JOIN mirrored_chat_messages m ON m.scope=latest.scope AND m.group_id=latest.group_id AND m.event_id=latest.event_id
                WHERE activity_rank=1 ORDER BY latest.group_position");
            let conn = store.lock()?;
            let mut statement = conn.prepare(&sql).storage()?;
            let rows = statement
                .query_map(params_from_iter(arguments), |row| {
                    Ok((
                        mirrored_chat_messages::read_record(row)?,
                        row.get::<_, i64>(13)? as usize,
                        row.get::<_, i64>(14)? as usize,
                        row.get::<_, Option<i64>>(15)?,
                    ))
                })
                .storage()?;
            for row in rows {
                let (mut record, source, group, expiry) = row.storage()?;
                mirrored_chat_messages::validate(&record)?;
                record.expires_at = expiry.map(|value| value as u64);
                if record.expires_at.is_some_and(|value| value <= now) {
                    record.deleted = true;
                    record.payload.clear();
                }
                let entry = page.get_mut(group).ok_or_else(invalid)?;
                if entry.latest_message.is_some() {
                    return Err(invalid());
                }
                entry.latest_message = Some(MirroredMessageObservation {
                    scope: scopes.get(source).ok_or_else(invalid)?.clone(),
                    edit: crate::mirrored_chat_edits::resolve(
                        &conn,
                        scopes,
                        &entry.catalog.entry.group_id,
                        &record,
                        now,
                    )?,
                    record,
                });
            }
            Ok(page)
        })
    }
}
