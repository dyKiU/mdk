//! Private revision13; preserve revision12 schema while fencing terminal references.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TRIGGER selected_chat_key_packages_keep_reference
        BEFORE DELETE ON selected_chat_key_packages
        BEGIN SELECT RAISE(ABORT,'selected chat reference is retained'); END;
        CREATE TRIGGER selected_chat_key_packages_keep_context
        BEFORE UPDATE OF reference,account,local_device,generation,request_binding,record
        ON selected_chat_key_packages
        BEGIN SELECT RAISE(ABORT,'selected chat context is immutable'); END;
        CREATE TRIGGER selected_chat_key_packages_keep_terminal
        BEFORE UPDATE OF state ON selected_chat_key_packages
        WHEN OLD.state!=0 AND NEW.state!=OLD.state
        BEGIN SELECT RAISE(ABORT,'selected chat terminal state is immutable'); END;
        CREATE TRIGGER selected_chat_key_packages_insert_fence
        BEFORE INSERT ON selected_chat_key_packages
        WHEN NEW.reference IS NULL OR NEW.state!=0
          OR (SELECT count(*) FROM selected_chat_key_packages)>=128
          OR EXISTS(SELECT 1 FROM selected_chat_key_packages
              WHERE reference=NEW.reference OR request_binding=NEW.request_binding
                 OR account!=NEW.account OR local_device!=NEW.local_device OR state=0)
        BEGIN SELECT RAISE(ABORT,'selected chat recipient reservation conflicts'); END;",
    )
    .storage()
}
