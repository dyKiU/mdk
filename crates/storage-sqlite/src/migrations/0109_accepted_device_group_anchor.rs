//! Bounded accepted-successor facts, separate from immutable local genesis.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;
pub(crate) fn apply(transaction: &Transaction<'_>) -> StorageResult<()> {
    transaction
        .execute_batch(
            "CREATE TABLE accepted_device_group_anchor (
            singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
            generation INTEGER NOT NULL CHECK(generation>0),
            account BLOB NOT NULL CHECK(length(account)=32),
            local_device BLOB NOT NULL CHECK(length(local_device)=32),
            group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
            draft BLOB NOT NULL CHECK(length(draft) BETWEEN 1 AND 131072),
            denied INTEGER NOT NULL DEFAULT 0 CHECK(denied IN(0,1))
        );
        CREATE TRIGGER accepted_device_group_anchor_group_deleted AFTER DELETE ON cgka_groups
        BEGIN
            UPDATE accepted_device_group_anchor SET denied=1 WHERE group_id=OLD.id;
        END;",
        )
        .storage()?;
    Ok(())
}
