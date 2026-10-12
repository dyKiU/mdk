//! Immutable peer-generation acknowledgment metadata; no payload or live owner.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_chat_record_generation_receipts (
          policy_id BLOB NOT NULL,
          group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
          digest BLOB NOT NULL CHECK(length(digest)=32),
          peer_generation INTEGER NOT NULL CHECK(peer_generation>=0),
          record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 4096),
          PRIMARY KEY(policy_id,group_id,digest,peer_generation),
          FOREIGN KEY(policy_id,group_id,digest)
            REFERENCES account_chat_record_outbox(policy_id,group_id,digest));
        CREATE TRIGGER chat_record_generation_receipt_insert
        BEFORE INSERT ON account_chat_record_generation_receipts
        WHEN (SELECT count(*) FROM account_chat_record_generation_receipts)>=8192
          OR EXISTS(SELECT 1 FROM account_chat_record_generation_receipts
            WHERE policy_id=NEW.policy_id AND group_id=NEW.group_id
              AND digest=NEW.digest AND peer_generation=NEW.peer_generation)
          OR NOT EXISTS(SELECT 1 FROM account_chat_record_outbox o
            JOIN approved_account_sharing_policies p USING(policy_id)
            WHERE o.policy_id=NEW.policy_id AND o.group_id=NEW.group_id
              AND o.digest=NEW.digest AND o.state=1 AND o.receipt=NEW.record
              AND p.revoked=0)
        BEGIN SELECT RAISE(ABORT,'invalid record generation receipt'); END;
        CREATE TRIGGER chat_record_generation_receipt_update
        BEFORE UPDATE ON account_chat_record_generation_receipts
        BEGIN SELECT RAISE(ABORT,'record generation receipt is immutable'); END;
        CREATE TRIGGER chat_record_generation_receipt_keep
        BEFORE DELETE ON account_chat_record_generation_receipts
        BEGIN SELECT RAISE(ABORT,'record generation receipt retained'); END;",
    )
    .storage()
}
