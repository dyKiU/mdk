//! Logical payloads and permanent identity/retention fences, outside live MLS.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE TABLE mirrored_chat_messages (
      scope BLOB NOT NULL REFERENCES mirrored_chat_scopes(scope),
      group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
      event_id BLOB NOT NULL CHECK(length(event_id)=32),
      author BLOB NOT NULL CHECK(length(author)=32),
      created_at INTEGER NOT NULL CHECK(created_at>=0),
      kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 65535),
      payload BLOB NOT NULL CHECK(length(payload)<=65536),
      content_digest BLOB CHECK(content_digest IS NULL OR length(content_digest)=32),
      expires_at INTEGER CHECK(expires_at IS NULL OR expires_at>=0),
      deleted INTEGER NOT NULL CHECK(deleted IN (0,1)),
      source_epoch INTEGER NOT NULL CHECK(source_epoch>=0),
      source_sequence INTEGER NOT NULL CHECK(source_sequence>0),
      source_digest BLOB NOT NULL CHECK(length(source_digest)=32),
      PRIMARY KEY(scope,group_id,event_id),
      CHECK((deleted=1 AND length(payload)=0) OR (deleted=0 AND length(payload)>0 AND content_digest IS NOT NULL)));
    CREATE INDEX mirrored_message_page ON mirrored_chat_messages(scope,group_id,created_at,event_id);
    CREATE INDEX mirrored_message_identity ON mirrored_chat_messages(group_id,event_id,deleted);
    CREATE TRIGGER mirrored_message_bound BEFORE INSERT ON mirrored_chat_messages
    WHEN (SELECT count(*) FROM mirrored_chat_messages)>=100000
      OR EXISTS(SELECT 1 FROM mirrored_chat_messages WHERE scope=NEW.scope AND group_id=NEW.group_id AND event_id=NEW.event_id)
      OR EXISTS(SELECT 1 FROM mirrored_chat_messages old WHERE old.group_id=NEW.group_id AND old.event_id=NEW.event_id AND
        (old.author!=NEW.author OR old.created_at!=NEW.created_at OR old.kind!=NEW.kind
         OR (NEW.deleted=0 AND old.deleted=1)
         OR (old.deleted=0 AND NEW.deleted=0 AND old.payload!=NEW.payload)
         OR (old.content_digest IS NOT NULL AND NEW.content_digest IS NOT NULL AND old.content_digest!=NEW.content_digest)))
    BEGIN SELECT RAISE(ABORT,'mirrored message capacity or identity conflict'); END;
    CREATE TRIGGER mirrored_message_keep BEFORE DELETE ON mirrored_chat_messages
    BEGIN SELECT RAISE(ABORT,'mirrored message identity is retained'); END;
    CREATE TRIGGER mirrored_message_fence BEFORE UPDATE ON mirrored_chat_messages
    WHEN NEW.scope!=OLD.scope OR NEW.group_id!=OLD.group_id OR NEW.event_id!=OLD.event_id
      OR NEW.author!=OLD.author OR NEW.created_at!=OLD.created_at OR NEW.kind!=OLD.kind
      OR (OLD.deleted=0 AND NEW.deleted=0 AND NEW.payload!=OLD.payload)
      OR NEW.source_epoch<OLD.source_epoch OR NEW.source_sequence<OLD.source_sequence
      OR (OLD.content_digest IS NOT NULL AND (NEW.content_digest IS NULL OR NEW.content_digest!=OLD.content_digest))
      OR (OLD.deleted=1 AND NEW.deleted!=1)
      OR (OLD.expires_at IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at>OLD.expires_at))
      OR (NEW.source_sequence=OLD.source_sequence AND NOT (
          OLD.deleted=0 AND NEW.deleted=1 AND length(NEW.payload)=0
          AND NEW.source_digest=OLD.source_digest AND NEW.source_epoch=OLD.source_epoch))
      OR EXISTS(SELECT 1 FROM mirrored_chat_messages other WHERE other.group_id=NEW.group_id AND other.event_id=NEW.event_id AND
        (other.author!=NEW.author OR other.created_at!=NEW.created_at OR other.kind!=NEW.kind
          OR (NEW.deleted=0 AND other.deleted=1)
          OR (other.deleted=0 AND NEW.deleted=0 AND other.payload!=NEW.payload)
          OR (other.content_digest IS NOT NULL AND NEW.content_digest IS NOT NULL AND other.content_digest!=NEW.content_digest)))
    BEGIN SELECT RAISE(ABORT,'mirrored message identity or retention regression'); END;").storage()
}
