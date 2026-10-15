//! Separate experimental ledger revision10; no upstream schema allocation.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE private_roster_settlement (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        generation INTEGER NOT NULL CHECK(generation>0),
        account BLOB NOT NULL CHECK(length(account)=32),
        local_device BLOB NOT NULL CHECK(length(local_device)=32),
        group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
        state BLOB NOT NULL CHECK(length(state) BETWEEN 1 AND 262144)
    );
    CREATE TABLE private_roster_settlement_facts (
        leaf_index INTEGER PRIMARY KEY CHECK(leaf_index BETWEEN 0 AND 4294967295),
        record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 4096)
    );",
    )
    .storage()?;
    Ok(())
}
