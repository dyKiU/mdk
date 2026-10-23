//! Independent logical-record journal and atomic delivery receipts.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE TABLE account_chat_record_counters (
      policy_id BLOB PRIMARY KEY NOT NULL REFERENCES approved_account_sharing_policies(policy_id),
      sequence INTEGER NOT NULL CHECK(sequence>=0));
    CREATE TABLE account_chat_record_journal (
      policy_id BLOB NOT NULL REFERENCES account_chat_record_counters(policy_id),
      group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
      event_id BLOB NOT NULL CHECK(length(event_id)=32),
      digest BLOB NOT NULL CHECK(length(digest)=32),
      sequence INTEGER NOT NULL CHECK(sequence>0),
      PRIMARY KEY(policy_id,group_id,event_id));
    CREATE TABLE account_chat_record_outbox (
      policy_id BLOB NOT NULL REFERENCES approved_account_sharing_policies(policy_id),
      group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
      digest BLOB NOT NULL CHECK(length(digest)=32),
      first_sequence INTEGER NOT NULL CHECK(first_sequence>0),
      last_sequence INTEGER NOT NULL CHECK(last_sequence>=first_sequence),
      record_count INTEGER NOT NULL CHECK(record_count BETWEEN 1 AND 128),
      payload BLOB NOT NULL CHECK(length(payload)<=1048576),
      receipt BLOB CHECK(receipt IS NULL OR length(receipt) BETWEEN 1 AND 4096),
      state INTEGER NOT NULL CHECK(state IN (0,1,2)),
      PRIMARY KEY(policy_id,group_id,digest),
      CHECK((state=0 AND receipt IS NULL AND length(payload)>0) OR (state=1 AND receipt IS NOT NULL AND length(payload)=0) OR (state=2 AND receipt IS NULL AND length(payload)=0)));
    CREATE TABLE account_chat_record_receipts (
      policy_id BLOB NOT NULL REFERENCES approved_account_sharing_policies(policy_id),
      group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
      digest BLOB NOT NULL CHECK(length(digest)=32),
      record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 4096),
      PRIMARY KEY(policy_id,group_id,digest));
    CREATE TABLE account_chat_record_progress (
      policy_id BLOB NOT NULL REFERENCES approved_account_sharing_policies(policy_id),
      group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
      sequence INTEGER NOT NULL CHECK(sequence>0),
      PRIMARY KEY(policy_id,group_id));
    CREATE TRIGGER chat_record_counter_insert BEFORE INSERT ON account_chat_record_counters
    WHEN NEW.sequence!=0 OR EXISTS(SELECT 1 FROM account_chat_record_counters WHERE policy_id=NEW.policy_id)
      OR NOT EXISTS(SELECT 1 FROM approved_account_sharing_policies WHERE policy_id=NEW.policy_id AND revoked=0)
    BEGIN SELECT RAISE(ABORT,'invalid record counter'); END;
    CREATE TRIGGER chat_record_counter_update BEFORE UPDATE ON account_chat_record_counters
    WHEN NEW.policy_id!=OLD.policy_id OR OLD.sequence=9223372036854775807 OR NEW.sequence!=OLD.sequence+1
      OR NOT EXISTS(SELECT 1 FROM approved_account_sharing_policies WHERE policy_id=NEW.policy_id AND revoked=0)
    BEGIN SELECT RAISE(ABORT,'record counter regression'); END;
    CREATE TRIGGER chat_record_counter_keep BEFORE DELETE ON account_chat_record_counters
    BEGIN SELECT RAISE(ABORT,'record counter retained'); END;
    CREATE TRIGGER chat_record_journal_insert BEFORE INSERT ON account_chat_record_journal
    WHEN (SELECT count(*) FROM account_chat_record_journal)>=100000
      OR EXISTS(SELECT 1 FROM account_chat_record_journal WHERE policy_id=NEW.policy_id AND group_id=NEW.group_id AND event_id=NEW.event_id)
      OR NOT EXISTS(SELECT 1 FROM account_chat_record_counters c JOIN approved_account_sharing_policies p USING(policy_id)
        WHERE c.policy_id=NEW.policy_id AND c.sequence=NEW.sequence AND p.revoked=0)
    BEGIN SELECT RAISE(ABORT,'record journal capacity or sequence conflict'); END;
    CREATE TRIGGER chat_record_journal_update BEFORE UPDATE ON account_chat_record_journal
    WHEN NEW.policy_id!=OLD.policy_id OR NEW.group_id!=OLD.group_id OR NEW.event_id!=OLD.event_id
      OR NEW.digest=OLD.digest OR NEW.sequence<=OLD.sequence
      OR NOT EXISTS(SELECT 1 FROM account_chat_record_counters c JOIN approved_account_sharing_policies p USING(policy_id)
        WHERE c.policy_id=NEW.policy_id AND c.sequence=NEW.sequence AND p.revoked=0)
    BEGIN SELECT RAISE(ABORT,'record journal regression'); END;
    CREATE TRIGGER chat_record_journal_keep BEFORE DELETE ON account_chat_record_journal
    BEGIN SELECT RAISE(ABORT,'record journal retained'); END;
    CREATE TRIGGER chat_record_outbox_insert BEFORE INSERT ON account_chat_record_outbox
    WHEN NEW.state!=0 OR NEW.receipt IS NOT NULL OR (SELECT count(*) FROM account_chat_record_outbox)>=4096
      OR (SELECT coalesce(sum(length(payload)),0) FROM account_chat_record_outbox)+length(NEW.payload)>67108864
      OR EXISTS(SELECT 1 FROM account_chat_record_outbox WHERE policy_id=NEW.policy_id AND group_id=NEW.group_id AND digest=NEW.digest)
      OR NOT EXISTS(SELECT 1 FROM approved_account_sharing_policies WHERE policy_id=NEW.policy_id AND revoked=0)
    BEGIN SELECT RAISE(ABORT,'record outbox capacity or scope conflict'); END;
    CREATE TRIGGER chat_record_outbox_update BEFORE UPDATE ON account_chat_record_outbox
    WHEN NEW.policy_id!=OLD.policy_id OR NEW.group_id!=OLD.group_id OR NEW.digest!=OLD.digest
      OR NEW.first_sequence!=OLD.first_sequence OR NEW.last_sequence!=OLD.last_sequence OR NEW.record_count!=OLD.record_count
      OR OLD.state!=0 OR NEW.state NOT IN (1,2) OR length(NEW.payload)!=0
    BEGIN SELECT RAISE(ABORT,'record outbox is immutable or terminal'); END;
    CREATE TRIGGER chat_record_outbox_keep BEFORE DELETE ON account_chat_record_outbox
    BEGIN SELECT RAISE(ABORT,'record outbox identity retained'); END;
    CREATE TRIGGER chat_record_receipt_insert BEFORE INSERT ON account_chat_record_receipts
    WHEN (SELECT count(*) FROM account_chat_record_receipts)>=8192
      OR EXISTS(SELECT 1 FROM account_chat_record_receipts WHERE policy_id=NEW.policy_id AND group_id=NEW.group_id AND digest=NEW.digest)
    BEGIN SELECT RAISE(ABORT,'record receipt capacity or identity conflict'); END;
    CREATE TRIGGER chat_record_receipt_update BEFORE UPDATE ON account_chat_record_receipts
    BEGIN SELECT RAISE(ABORT,'record receipt is immutable'); END;
    CREATE TRIGGER chat_record_receipt_keep BEFORE DELETE ON account_chat_record_receipts
    BEGIN SELECT RAISE(ABORT,'record receipt retained'); END;
    CREATE TRIGGER chat_record_progress_insert BEFORE INSERT ON account_chat_record_progress
    WHEN (SELECT count(*) FROM account_chat_record_progress)>=8192
      OR EXISTS(SELECT 1 FROM account_chat_record_progress WHERE policy_id=NEW.policy_id AND group_id=NEW.group_id)
    BEGIN SELECT RAISE(ABORT,'record progress capacity or identity conflict'); END;
    CREATE TRIGGER chat_record_progress_update BEFORE UPDATE ON account_chat_record_progress
    WHEN NEW.policy_id!=OLD.policy_id OR NEW.group_id!=OLD.group_id OR NEW.sequence<=OLD.sequence
    BEGIN SELECT RAISE(ABORT,'record progress regression'); END;
    CREATE TRIGGER chat_record_progress_keep BEFORE DELETE ON account_chat_record_progress
    BEGIN SELECT RAISE(ABORT,'record progress retained'); END;").storage()
}
