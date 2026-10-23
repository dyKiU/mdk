//! Permanent negative request identities; never original consent or authority.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE TABLE history_request_observations (
        transfer_id BLOB PRIMARY KEY NOT NULL CHECK(length(transfer_id)=32),
        account BLOB NOT NULL CHECK(length(account)=32),
        local_device BLOB NOT NULL CHECK(length(local_device)=32),
        request_digest BLOB NOT NULL CHECK(length(request_digest)=32));
        CREATE TRIGGER history_request_keep_identity BEFORE UPDATE ON history_request_observations
        BEGIN SELECT RAISE(ABORT,'history request identity is immutable'); END;
        CREATE TRIGGER history_request_keep_reference BEFORE DELETE ON history_request_observations
        BEGIN SELECT RAISE(ABORT,'history request reference is retained'); END;
        CREATE TRIGGER history_request_insert_fence BEFORE INSERT ON history_request_observations
        WHEN (SELECT count(*) FROM history_request_observations)>=128
          OR EXISTS(SELECT 1 FROM history_request_observations WHERE transfer_id=NEW.transfer_id)
          OR EXISTS(SELECT 1 FROM history_request_observations WHERE account!=NEW.account OR local_device!=NEW.local_device)
        BEGIN SELECT RAISE(ABORT,'history request reservation conflicts'); END;") .storage()
}
