//! Durable approval metadata and bounded local-source sequence reservations.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE TABLE approved_account_sharing_policies (
        policy_id BLOB PRIMARY KEY NOT NULL CHECK(length(policy_id)=32),
        account BLOB NOT NULL CHECK(length(account)=32),
        local_device BLOB NOT NULL CHECK(length(local_device)=32),
        record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 4096),
        revoked INTEGER NOT NULL CHECK(revoked IN (0,1)));
    CREATE TABLE account_sharing_source_counters (
        policy_id BLOB PRIMARY KEY NOT NULL REFERENCES approved_account_sharing_policies(policy_id),
        sequence INTEGER NOT NULL CHECK(sequence>=0));
    CREATE TABLE account_sharing_source_journal (
        policy_id BLOB NOT NULL REFERENCES approved_account_sharing_policies(policy_id),
        group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
        digest BLOB NOT NULL CHECK(length(digest)=32),
        sequence INTEGER NOT NULL CHECK(sequence>0),
        PRIMARY KEY(policy_id,group_id));
    CREATE TRIGGER approved_sharing_policy_bound BEFORE INSERT ON approved_account_sharing_policies
    WHEN NEW.revoked!=0 OR (SELECT count(*) FROM approved_account_sharing_policies)>=128
      OR EXISTS(SELECT 1 FROM approved_account_sharing_policies WHERE policy_id=NEW.policy_id
        OR account!=NEW.account OR local_device!=NEW.local_device)
    BEGIN SELECT RAISE(ABORT,'sharing approval capacity or identity conflict'); END;
    CREATE TRIGGER approved_sharing_policy_fence BEFORE UPDATE ON approved_account_sharing_policies
    WHEN NEW.policy_id!=OLD.policy_id OR NEW.account!=OLD.account OR NEW.local_device!=OLD.local_device
      OR NEW.record!=OLD.record OR OLD.revoked!=0 OR NEW.revoked!=1
    BEGIN SELECT RAISE(ABORT,'sharing approval is immutable'); END;
    CREATE TRIGGER approved_sharing_policy_keep BEFORE DELETE ON approved_account_sharing_policies
    BEGIN SELECT RAISE(ABORT,'sharing approval is retained'); END;
    CREATE TRIGGER sharing_counter_insert BEFORE INSERT ON account_sharing_source_counters
    WHEN NEW.sequence!=0 OR EXISTS(SELECT 1 FROM account_sharing_source_counters WHERE policy_id=NEW.policy_id)
      OR NOT EXISTS(SELECT 1 FROM approved_account_sharing_policies WHERE policy_id=NEW.policy_id AND revoked=0)
    BEGIN SELECT RAISE(ABORT,'invalid sharing counter'); END;
    CREATE TRIGGER sharing_counter_update BEFORE UPDATE ON account_sharing_source_counters
    WHEN NEW.policy_id!=OLD.policy_id OR NEW.sequence!=OLD.sequence+1 OR OLD.sequence=9223372036854775807
      OR NOT EXISTS(SELECT 1 FROM approved_account_sharing_policies WHERE policy_id=NEW.policy_id AND revoked=0)
    BEGIN SELECT RAISE(ABORT,'sharing sequence regression'); END;
    CREATE TRIGGER sharing_counter_keep BEFORE DELETE ON account_sharing_source_counters
    BEGIN SELECT RAISE(ABORT,'sharing counter is retained'); END;
    CREATE TRIGGER sharing_journal_bound BEFORE INSERT ON account_sharing_source_journal
    WHEN (SELECT count(*) FROM account_sharing_source_journal)>=8192
      OR EXISTS(SELECT 1 FROM account_sharing_source_journal WHERE policy_id=NEW.policy_id AND group_id=NEW.group_id)
      OR NOT EXISTS(SELECT 1 FROM account_sharing_source_counters c JOIN approved_account_sharing_policies p USING(policy_id)
         WHERE c.policy_id=NEW.policy_id AND c.sequence=NEW.sequence AND p.revoked=0)
    BEGIN SELECT RAISE(ABORT,'sharing journal capacity or sequence conflict'); END;
    CREATE TRIGGER sharing_journal_update BEFORE UPDATE ON account_sharing_source_journal
    WHEN NEW.policy_id!=OLD.policy_id OR NEW.group_id!=OLD.group_id OR NEW.sequence<=OLD.sequence OR NEW.digest=OLD.digest
      OR NOT EXISTS(SELECT 1 FROM account_sharing_source_counters c JOIN approved_account_sharing_policies p USING(policy_id)
         WHERE c.policy_id=NEW.policy_id AND c.sequence=NEW.sequence AND p.revoked=0)
    BEGIN SELECT RAISE(ABORT,'sharing journal regression'); END;
    CREATE TRIGGER sharing_journal_keep BEFORE DELETE ON account_sharing_source_journal
    BEGIN SELECT RAISE(ABORT,'sharing journal is retained'); END;").storage()
}
