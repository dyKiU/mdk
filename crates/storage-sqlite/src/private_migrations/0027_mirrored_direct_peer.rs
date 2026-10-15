//! Indexed source-attested direct peers; legacy observations remain unknown.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE mirrored_chat_catalog ADD COLUMN direct_peer BLOB
          CHECK(direct_peer IS NULL OR length(direct_peer)=32);
         CREATE INDEX mirrored_catalog_direct_peer
          ON mirrored_chat_catalog(direct_peer,scope,group_id) WHERE state=0;",
    )
    .storage()
}
