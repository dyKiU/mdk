//! Private ledger revision9; no upstream core migration allocation.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE TABLE private_group_chat_exclusion (
        group_id BLOB PRIMARY KEY NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
        account BLOB NOT NULL CHECK(length(account)=32),
        local_device BLOB NOT NULL CHECK(length(local_device)=32)
    );
    CREATE TRIGGER private_group_chat_exclusion_no_update BEFORE UPDATE ON private_group_chat_exclusion
    BEGIN SELECT RAISE(ABORT,'private presentation fence is immutable'); END;
    CREATE TRIGGER private_group_chat_exclusion_no_delete BEFORE DELETE ON private_group_chat_exclusion
    BEGIN SELECT RAISE(ABORT,'private presentation fence is immutable'); END;
    CREATE TRIGGER private_group_chat_exclusion_no_replace BEFORE INSERT ON private_group_chat_exclusion
    WHEN EXISTS(SELECT 1 FROM private_group_chat_exclusion WHERE group_id=NEW.group_id)
    BEGIN SELECT RAISE(ABORT,'private presentation fence is immutable'); END;
    INSERT INTO private_group_chat_exclusion(group_id,account,local_device)
    SELECT group_id,account,local_device FROM device_group_genesis_selection
    UNION SELECT group_id,account,local_device FROM accepted_device_group_anchor
    UNION SELECT group_id,account,local_device FROM private_device_invite_staging
    UNION SELECT group_id,account,local_device FROM private_device_invite_confirmed;")
        .storage()?;
    Ok(())
}
