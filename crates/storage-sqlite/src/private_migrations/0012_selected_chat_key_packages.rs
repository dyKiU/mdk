//! Private revision12; independent recipient facts, not an upstream schema allocation.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE selected_chat_key_packages (
            reference BLOB PRIMARY KEY CHECK(length(reference)=32),
            account BLOB NOT NULL CHECK(length(account)=32),
            local_device BLOB NOT NULL CHECK(length(local_device)=32),
            generation INTEGER NOT NULL CHECK(generation>0),
            request_binding BLOB NOT NULL CHECK(length(request_binding)=32),
            record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 262144),
            state INTEGER NOT NULL CHECK(state IN (0,1,2)),
            UNIQUE(account,local_device,request_binding)
        );",
    )
    .storage()
}
