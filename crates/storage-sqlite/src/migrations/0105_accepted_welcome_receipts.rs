//! Additive device-local accepted-join evidence, distinct from pairing facts.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE accepted_welcome_receipts (
            welcome_id BLOB PRIMARY KEY NOT NULL CHECK(length(welcome_id) BETWEEN 1 AND 512),
            content_id BLOB NOT NULL CHECK(length(content_id) BETWEEN 1 AND 512),
            group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
            key_package_ref BLOB NOT NULL CHECK(length(key_package_ref) BETWEEN 1 AND 256),
            own_account BLOB NOT NULL CHECK(length(own_account)=32),
            own_signature_key BLOB NOT NULL CHECK(length(own_signature_key) BETWEEN 1 AND 256),
            welcomer_account BLOB NOT NULL CHECK(length(welcomer_account)=32),
            welcomer_signature_key BLOB NOT NULL CHECK(length(welcomer_signature_key) BETWEEN 1 AND 256),
            joined_epoch INTEGER NOT NULL CHECK(joined_epoch>=0),
            authenticator_digest BLOB NOT NULL CHECK(length(authenticator_digest)=32)
        );
        CREATE INDEX accepted_welcome_receipts_group ON accepted_welcome_receipts(group_id);",
    ).storage()?;
    Ok(())
}
