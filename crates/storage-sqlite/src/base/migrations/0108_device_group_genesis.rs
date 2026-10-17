//! Bounded immutable birth metadata and independent permanent active-lineage denial.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;
pub(crate) fn apply(transaction: &Transaction<'_>) -> StorageResult<()> {
    transaction
        .execute_batch(
            "CREATE TABLE device_group_genesis_selection (
            singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
            generation INTEGER NOT NULL CHECK(generation>0),
            account BLOB NOT NULL CHECK(length(account)=32),
            local_device BLOB NOT NULL CHECK(length(local_device)=32),
            group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
            birth BLOB NOT NULL CHECK(length(birth) BETWEEN 1 AND 4096),
            active_denied INTEGER NOT NULL DEFAULT 0 CHECK(active_denied IN(0,1))
        );
        CREATE TRIGGER device_group_genesis_group_deleted AFTER DELETE ON cgka_groups
        BEGIN
            UPDATE device_group_genesis_selection SET active_denied=1 WHERE group_id=OLD.id;
        END;",
        )
        .storage()?;
    Ok(())
}
