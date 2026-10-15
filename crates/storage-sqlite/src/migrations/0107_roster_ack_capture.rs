//! One locally selected capture scope and bounded per-leaf facts, never grants.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE roster_ack_capture (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        generation INTEGER NOT NULL CHECK(generation>0),
        group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
        state BLOB NOT NULL CHECK(length(state) BETWEEN 1 AND 65536)
    );
    CREATE TABLE roster_ack_capture_facts (
        leaf_index INTEGER PRIMARY KEY NOT NULL CHECK(leaf_index BETWEEN 0 AND 4294967295),
        record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 4096)
    );
    CREATE TRIGGER roster_ack_capture_group_deleted AFTER DELETE ON cgka_groups
    WHEN EXISTS(SELECT 1 FROM roster_ack_capture WHERE group_id=OLD.id)
    BEGIN
        UPDATE roster_ack_capture SET state=CAST(json_set(CAST(state AS TEXT),
            '$.invalidated',json('true'),'$.prepared_ciphertext',NULL,'$.outbound',NULL) AS BLOB)
        WHERE group_id=OLD.id;
        DELETE FROM roster_ack_capture_facts;
    END;
    CREATE TRIGGER roster_ack_capture_slot_bound BEFORE INSERT ON roster_ack_capture_facts
    WHEN (SELECT count(*) FROM roster_ack_capture_facts)>=128
    BEGIN SELECT RAISE(ABORT,'capture capacity'); END;",
    )
    .storage()?;
    Ok(())
}
