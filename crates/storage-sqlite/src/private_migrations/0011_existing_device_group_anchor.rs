//! Private ledger revision11; no upstream core schema allocation.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE existing_device_group_anchor (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        generation INTEGER NOT NULL CHECK(generation>0),
        account BLOB NOT NULL CHECK(length(account)=32),
        local_device BLOB NOT NULL CHECK(length(local_device)=32),
        group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
        draft BLOB NOT NULL CHECK(length(draft) BETWEEN 1 AND 131072),
        denied INTEGER NOT NULL CHECK(denied IN (0,1))
    );",
    )
    .storage()?;
    Ok(())
}
