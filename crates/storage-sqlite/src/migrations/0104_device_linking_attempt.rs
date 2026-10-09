//! Device-local verification fencing, separate from enrollment and MLS evidence.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE device_linking_attempt (
            singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
            account_id BLOB NOT NULL CHECK(length(account_id)=32),
            local_device BLOB NOT NULL CHECK(length(local_device)=32),
            generation INTEGER NOT NULL CHECK(generation>0),
            state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 9),
            nonce BLOB CHECK(nonce IS NULL OR length(nonce)=32),
            context_digest BLOB CHECK(context_digest IS NULL OR length(context_digest)=32),
            flow TEXT CHECK(flow IS NULL OR length(CAST(flow AS BLOB)) BETWEEN 1 AND 128),
            CHECK(state!=0 OR (nonce IS NULL AND context_digest IS NULL AND flow IS NULL)),
            CHECK(state NOT IN (1,2,3) OR (nonce IS NOT NULL AND context_digest IS NOT NULL)),
            CHECK(state NOT IN (2,3) OR flow IS NOT NULL)
        );",
    )
    .storage()?;
    Ok(())
}
