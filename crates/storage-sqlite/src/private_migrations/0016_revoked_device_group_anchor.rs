//! Immutable bounded authenticated Remove lineage; never admission reconstruction.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE TABLE revoked_device_group_anchor (
        generation INTEGER PRIMARY KEY NOT NULL CHECK(generation>0),
        account BLOB NOT NULL CHECK(length(account)=32),
        local_device BLOB NOT NULL CHECK(length(local_device)=32),
        group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
        draft BLOB NOT NULL CHECK(length(draft) BETWEEN 1 AND 131072),
        denied INTEGER NOT NULL CHECK(denied IN (0,1)));
        CREATE TRIGGER revoked_anchor_keep_reference BEFORE DELETE ON revoked_device_group_anchor
        BEGIN SELECT RAISE(ABORT,'revoked anchor reference is retained'); END;
        CREATE TRIGGER revoked_anchor_keep_identity BEFORE UPDATE ON revoked_device_group_anchor
        WHEN NEW.generation!=OLD.generation OR NEW.account!=OLD.account OR NEW.local_device!=OLD.local_device
          OR NEW.group_id!=OLD.group_id OR NEW.draft!=OLD.draft OR NEW.denied<OLD.denied
        BEGIN SELECT RAISE(ABORT,'revoked anchor identity is immutable'); END;
        CREATE TRIGGER revoked_anchor_insert_fence BEFORE INSERT ON revoked_device_group_anchor
        WHEN (SELECT count(*) FROM revoked_device_group_anchor)>=128
          OR EXISTS(SELECT 1 FROM revoked_device_group_anchor WHERE generation=NEW.generation OR denied=0
             OR account!=NEW.account OR local_device!=NEW.local_device)
          OR NEW.generation!=COALESCE((SELECT max(generation)+1 FROM revoked_device_group_anchor),1)
        BEGIN SELECT RAISE(ABORT,'revoked anchor reservation conflicts'); END;") .storage()
}
