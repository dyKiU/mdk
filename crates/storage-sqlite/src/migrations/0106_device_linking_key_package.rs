//! One purpose-owned package, separate from public rotation/publication slots.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE device_linking_key_package (
            singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
            generation INTEGER NOT NULL CHECK(generation>0),
            account_id BLOB NOT NULL CHECK(length(account_id)=32),
            local_device BLOB NOT NULL CHECK(length(local_device)=32),
            public_bytes BLOB NOT NULL CHECK(length(public_bytes) BETWEEN 1 AND 16384),
            key_package_ref BLOB NOT NULL CHECK(length(key_package_ref) BETWEEN 1 AND 256),
            signature_key BLOB NOT NULL CHECK(length(signature_key) BETWEEN 1 AND 256),
            nonce BLOB CHECK(nonce IS NULL OR length(nonce)=32),
            context_digest BLOB CHECK(context_digest IS NULL OR length(context_digest)=32),
            consumed INTEGER NOT NULL CHECK(consumed IN (0,1)),
            CHECK((nonce IS NULL) = (context_digest IS NULL)),
            CHECK(consumed=0 OR nonce IS NOT NULL)
        );",
    )
    .storage()?;
    Ok(())
}
