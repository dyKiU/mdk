//! Separate paired-source observations. No foreign key to live MLS group rows.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE mirrored_chat_scopes (
            scope BLOB PRIMARY KEY NOT NULL CHECK(length(scope) BETWEEN 1 AND 2048),
            account BLOB NOT NULL CHECK(length(account)=32),
            local_device BLOB NOT NULL CHECK(length(local_device)=32),
            source_device BLOB NOT NULL CHECK(length(source_device)=32));
         CREATE TABLE mirrored_chat_catalog (
            scope BLOB NOT NULL REFERENCES mirrored_chat_scopes(scope),
            group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
            source_sequence INTEGER NOT NULL CHECK(source_sequence>0),
            state INTEGER NOT NULL CHECK(state IN (0,1,2)),
            record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 32768),
            PRIMARY KEY(scope,group_id));
         CREATE INDEX mirrored_catalog_terminals ON mirrored_chat_catalog(group_id,state,scope);
         CREATE TRIGGER mirrored_scope_keep_identity BEFORE UPDATE ON mirrored_chat_scopes
         BEGIN SELECT RAISE(ABORT,'mirrored scope is immutable'); END;
         CREATE TRIGGER mirrored_scope_keep_reference BEFORE DELETE ON mirrored_chat_scopes
         BEGIN SELECT RAISE(ABORT,'mirrored scope is retained'); END;
         CREATE TRIGGER mirrored_scope_bound BEFORE INSERT ON mirrored_chat_scopes
         WHEN (SELECT count(*) FROM mirrored_chat_scopes)>=128
           OR EXISTS(SELECT 1 FROM mirrored_chat_scopes WHERE scope=NEW.scope)
           OR EXISTS(SELECT 1 FROM mirrored_chat_scopes WHERE account!=NEW.account OR local_device!=NEW.local_device)
         BEGIN SELECT RAISE(ABORT,'mirrored scope capacity or owner conflict'); END;
         CREATE TRIGGER mirrored_catalog_bound BEFORE INSERT ON mirrored_chat_catalog
         WHEN (SELECT count(*) FROM mirrored_chat_catalog)>=8192
           OR EXISTS(SELECT 1 FROM mirrored_chat_catalog WHERE scope=NEW.scope AND group_id=NEW.group_id)
           OR (NEW.state=0 AND EXISTS(
             SELECT 1 FROM mirrored_chat_catalog old
             JOIN mirrored_chat_scopes old_scope ON old_scope.scope=old.scope
             JOIN mirrored_chat_scopes new_scope ON new_scope.scope=NEW.scope
             WHERE old.group_id=NEW.group_id AND old.state!=0
               AND old_scope.source_device=new_scope.source_device))
         BEGIN SELECT RAISE(ABORT,'mirrored catalog capacity exceeded'); END;
         CREATE TRIGGER mirrored_catalog_keep_reference BEFORE DELETE ON mirrored_chat_catalog
         BEGIN SELECT RAISE(ABORT,'mirrored terminal reference is retained'); END;
         CREATE TRIGGER mirrored_catalog_fence BEFORE UPDATE ON mirrored_chat_catalog
         WHEN NEW.scope!=OLD.scope OR NEW.group_id!=OLD.group_id
           OR NEW.source_sequence<=OLD.source_sequence
           OR (OLD.state!=0 AND NEW.state!=OLD.state)
           OR (NEW.state=0 AND EXISTS(
             SELECT 1 FROM mirrored_chat_catalog old
             JOIN mirrored_chat_scopes old_scope ON old_scope.scope=old.scope
             JOIN mirrored_chat_scopes new_scope ON new_scope.scope=NEW.scope
             WHERE old.group_id=NEW.group_id AND old.state!=0
               AND old_scope.source_device=new_scope.source_device))
         BEGIN SELECT RAISE(ABORT,'mirrored catalog regression'); END;",
    ).storage()
}
