//! Derived edit relationships leave immutable original event bytes untouched.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::{Transaction, params};

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE TABLE mirrored_chat_edit_targets (
        scope BLOB NOT NULL, group_id BLOB NOT NULL, event_id BLOB NOT NULL,
        target_id BLOB NOT NULL CHECK(length(target_id)=32),
        PRIMARY KEY(scope,group_id,event_id),
        FOREIGN KEY(scope,group_id,event_id) REFERENCES mirrored_chat_messages(scope,group_id,event_id));
        CREATE INDEX mirrored_chat_edit_target ON mirrored_chat_edit_targets(group_id,target_id);
        CREATE TRIGGER mirrored_edit_target_keep BEFORE DELETE ON mirrored_chat_edit_targets
        BEGIN SELECT RAISE(ABORT,'immutable edit relationship'); END;
        CREATE TRIGGER mirrored_edit_target_immutable BEFORE UPDATE ON mirrored_chat_edit_targets
        BEGIN SELECT RAISE(ABORT,'immutable edit relationship'); END;").storage()?;
    let mut after = 0_i64;
    loop {
        let mut statement = tx.prepare("SELECT rowid,scope,group_id,event_id,payload FROM mirrored_chat_messages WHERE kind=1009 AND rowid>? ORDER BY rowid LIMIT 128").storage()?;
        let rows = statement
            .query_map([after], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        for (id, scope, group, event, payload) in &rows {
            if let Some(target) = crate::mirrored_chat_edits::target(payload) {
                tx.execute(
                    "INSERT INTO mirrored_chat_edit_targets VALUES(?1,?2,?3,?4)",
                    params![scope, group, event, target.as_slice()],
                )
                .storage()?;
            }
            after = *id;
        }
        if rows.is_empty() {
            break;
        }
    }
    Ok(())
}
