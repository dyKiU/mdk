//! User acceptance lineage, separate from MLS membership and broad policy facts.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_chat_source_origins (
          origin_id BLOB PRIMARY KEY CHECK(length(origin_id)=32),
          account BLOB NOT NULL CHECK(length(account)=32),
          local_device BLOB NOT NULL CHECK(length(local_device)=32),
          group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
          origin_order INTEGER NOT NULL UNIQUE CHECK(origin_order BETWEEN 1 AND 8192),
          origin BLOB NOT NULL CHECK(length(origin) BETWEEN 1 AND 257),
          verdict INTEGER NOT NULL CHECK(verdict BETWEEN 0 AND 2));
        CREATE TABLE account_chat_source_current (
          group_id BLOB PRIMARY KEY CHECK(length(group_id) BETWEEN 1 AND 255),
          origin_id BLOB NOT NULL REFERENCES account_chat_source_origins(origin_id));
        CREATE TRIGGER chat_source_insert BEFORE INSERT ON account_chat_source_origins
        WHEN (SELECT count(*) FROM account_chat_source_origins)>=8192
          OR NEW.origin_order!=(SELECT count(*)+1 FROM account_chat_source_origins)
          OR EXISTS(SELECT 1 FROM account_chat_source_origins WHERE origin_id=NEW.origin_id)
          OR EXISTS(SELECT 1 FROM account_chat_source_origins
            WHERE account!=NEW.account OR local_device!=NEW.local_device)
        BEGIN SELECT RAISE(ABORT,'invalid chat acceptance observation'); END;
        CREATE TRIGGER chat_source_update BEFORE UPDATE ON account_chat_source_origins
        WHEN NEW.origin_id!=OLD.origin_id OR NEW.account!=OLD.account
          OR NEW.local_device!=OLD.local_device OR NEW.group_id!=OLD.group_id
          OR NEW.origin!=OLD.origin OR NEW.verdict<OLD.verdict
          OR NEW.origin_order!=OLD.origin_order
        BEGIN SELECT RAISE(ABORT,'chat acceptance lineage is immutable'); END;
        CREATE TRIGGER chat_source_keep BEFORE DELETE ON account_chat_source_origins
        BEGIN SELECT RAISE(ABORT,'chat acceptance lineage retained'); END;
        CREATE TRIGGER chat_source_current_insert BEFORE INSERT ON account_chat_source_current
        WHEN EXISTS(SELECT 1 FROM account_chat_source_current WHERE group_id=NEW.group_id)
          OR NOT EXISTS(SELECT 1 FROM account_chat_source_origins
            WHERE origin_id=NEW.origin_id AND group_id=NEW.group_id)
        BEGIN SELECT RAISE(ABORT,'invalid current chat acceptance lineage'); END;
        CREATE TRIGGER chat_source_current_update BEFORE UPDATE ON account_chat_source_current
        WHEN NEW.group_id!=OLD.group_id OR NOT EXISTS(
          SELECT 1 FROM account_chat_source_origins
          WHERE origin_id=NEW.origin_id AND group_id=NEW.group_id)
          OR (SELECT origin_order FROM account_chat_source_origins WHERE origin_id=NEW.origin_id)
            <(SELECT origin_order FROM account_chat_source_origins WHERE origin_id=OLD.origin_id)
        BEGIN SELECT RAISE(ABORT,'invalid current chat acceptance lineage'); END;
        CREATE TRIGGER chat_source_current_keep BEFORE DELETE ON account_chat_source_current
        BEGIN SELECT RAISE(ABORT,'current chat acceptance lineage retained'); END;",
    )
    .storage()
}
