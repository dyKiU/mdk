//! Private revision14: opaque archive fragments, never original authorization.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE history_archive_staging (
            transfer_id BLOB PRIMARY KEY NOT NULL CHECK(length(transfer_id)=32),
            scope BLOB NOT NULL CHECK(length(scope) BETWEEN 1 AND 32768),
            next_fragment INTEGER NOT NULL DEFAULT 0 CHECK(next_fragment BETWEEN 0 AND 128),
            state INTEGER NOT NULL DEFAULT 0 CHECK(state IN (0,1,2))
        );
        CREATE TABLE history_archive_fragments (
            transfer_id BLOB NOT NULL REFERENCES history_archive_staging(transfer_id),
            ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 127),
            body BLOB CHECK(body IS NULL OR length(body) BETWEEN 1 AND 1536),
            receipt BLOB NOT NULL CHECK(length(receipt) BETWEEN 1 AND 4096),
            PRIMARY KEY(transfer_id,ordinal)
        );
        CREATE TRIGGER history_archive_keep_reference BEFORE DELETE ON history_archive_staging
        BEGIN SELECT RAISE(ABORT,'archive reference is retained'); END;
        CREATE TRIGGER history_archive_keep_scope BEFORE UPDATE OF transfer_id,scope ON history_archive_staging
        BEGIN SELECT RAISE(ABORT,'archive scope is immutable'); END;
        CREATE TRIGGER history_archive_keep_terminal BEFORE UPDATE ON history_archive_staging
        WHEN OLD.state!=0 AND (NEW.state!=OLD.state OR NEW.next_fragment!=OLD.next_fragment)
        BEGIN SELECT RAISE(ABORT,'archive terminal state is immutable'); END;
        CREATE TRIGGER history_archive_insert_fence BEFORE INSERT ON history_archive_staging
        WHEN NEW.state!=0 OR NEW.next_fragment!=0
          OR (SELECT count(*) FROM history_archive_staging)>=128
          OR EXISTS(SELECT 1 FROM history_archive_staging WHERE transfer_id=NEW.transfer_id)
        BEGIN SELECT RAISE(ABORT,'archive reservation conflicts'); END;
        CREATE TRIGGER history_archive_fragment_keep_receipt
        BEFORE UPDATE OF transfer_id,ordinal,receipt ON history_archive_fragments
        BEGIN SELECT RAISE(ABORT,'archive receipt is immutable'); END;
        CREATE TRIGGER history_archive_fragment_keep_reference BEFORE DELETE ON history_archive_fragments
        BEGIN SELECT RAISE(ABORT,'archive receipt is retained'); END;
        CREATE TRIGGER history_archive_fragment_clear_only BEFORE UPDATE OF body ON history_archive_fragments
        WHEN NEW.body IS NOT NULL OR NOT EXISTS(SELECT 1 FROM history_archive_staging
            WHERE transfer_id=OLD.transfer_id AND state!=0)
        BEGIN SELECT RAISE(ABORT,'archive payload is immutable'); END;
        CREATE TRIGGER history_archive_fragment_insert_fence BEFORE INSERT ON history_archive_fragments
        WHEN NEW.body IS NULL OR NOT EXISTS(SELECT 1 FROM history_archive_staging
            WHERE transfer_id=NEW.transfer_id AND state=0 AND next_fragment=NEW.ordinal)
          OR EXISTS(SELECT 1 FROM history_archive_fragments
            WHERE transfer_id=NEW.transfer_id AND ordinal=NEW.ordinal)
        BEGIN SELECT RAISE(ABORT,'archive fragment conflicts'); END;",
    ).storage()
}
