//! Separate bounded outgoing staging and retained confirmed lineage facts.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(transaction: &Transaction<'_>) -> StorageResult<()> {
    transaction
        .execute_batch(
            "CREATE TABLE private_device_invite_counter (
            singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
            generation INTEGER NOT NULL CHECK(generation>=0)
        );
        CREATE TABLE private_device_invite_staging (
            singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
            generation INTEGER NOT NULL CHECK(generation>0),
            account BLOB NOT NULL CHECK(length(account)=32),
            local_device BLOB NOT NULL CHECK(length(local_device)=32),
            group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
            binding BLOB NOT NULL CHECK(length(binding) BETWEEN 1 AND 131072),
            raw_commit BLOB NOT NULL CHECK(length(raw_commit) BETWEEN 1 AND 262144),
            raw_welcome BLOB NOT NULL CHECK(length(raw_welcome) BETWEEN 1 AND 2097152),
            transport BLOB CHECK(transport IS NULL OR length(transport) BETWEEN 1 AND 16777216),
            phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 5),
            CHECK((phase=0 AND transport IS NULL) OR
                  (phase IN(1,2,3,5) AND transport IS NOT NULL) OR phase=4)
        );
        CREATE TABLE private_device_invite_confirmed (
            singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
            generation INTEGER NOT NULL CHECK(generation>0),
            account BLOB NOT NULL CHECK(length(account)=32),
            local_device BLOB NOT NULL CHECK(length(local_device)=32),
            group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
            binding BLOB NOT NULL CHECK(length(binding) BETWEEN 1 AND 131072),
            denied INTEGER NOT NULL DEFAULT 0 CHECK(denied IN(0,1))
        );
        CREATE TRIGGER private_device_invite_group_deleted AFTER DELETE ON cgka_groups
        BEGIN
            UPDATE private_device_invite_staging SET phase=4
                WHERE group_id=OLD.id AND phase NOT IN(2,3);
            UPDATE private_device_invite_confirmed SET denied=1 WHERE group_id=OLD.id;
        END;",
        )
        .storage()?;
    Ok(())
}
