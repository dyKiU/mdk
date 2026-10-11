//! Immutable logical intents, independent routes and durable receipt outbox.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE TABLE account_chat_send_intents (
      intent_id BLOB PRIMARY KEY NOT NULL CHECK(length(intent_id)=32),
      account BLOB NOT NULL CHECK(length(account)=32),
      origin BLOB NOT NULL CHECK(length(origin)=32),
      group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
      event_id BLOB NOT NULL CHECK(length(event_id)=32),
      payload BLOB NOT NULL CHECK(length(payload)<=65536),
      digest BLOB NOT NULL CHECK(length(digest)=32),
      created_at INTEGER NOT NULL CHECK(created_at>=0),
      state INTEGER NOT NULL CHECK(state IN (0,2,3)),
      CHECK((state=0 AND length(payload)>0) OR (state!=0 AND length(payload)=0)));
    CREATE TABLE account_chat_send_routes (
      intent_id BLOB NOT NULL REFERENCES account_chat_send_intents(intent_id),
      policy_id BLOB NOT NULL REFERENCES approved_account_sharing_policies(policy_id),
      local_device BLOB NOT NULL CHECK(length(local_device)=32),
      peer_device BLOB NOT NULL CHECK(length(peer_device)=32 AND peer_device!=local_device),
      state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 3),
      member BLOB CHECK(member IS NULL OR length(member)=32),
      PRIMARY KEY(intent_id,policy_id));
    CREATE TABLE account_chat_send_receipts (
      digest BLOB PRIMARY KEY NOT NULL CHECK(length(digest)=32),
      intent_id BLOB NOT NULL,
      policy_id BLOB NOT NULL,
      record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 2048),
      acknowledged INTEGER NOT NULL CHECK(acknowledged IN (0,1)),
      FOREIGN KEY(intent_id,policy_id) REFERENCES account_chat_send_routes(intent_id,policy_id));
    CREATE TRIGGER chat_send_intent_insert BEFORE INSERT ON account_chat_send_intents
    WHEN NEW.state!=0 OR (SELECT count(*) FROM account_chat_send_intents)>=4096
      OR EXISTS(SELECT 1 FROM account_chat_send_intents WHERE intent_id=NEW.intent_id)
      OR (SELECT coalesce(sum(length(payload)),0) FROM account_chat_send_intents)+length(NEW.payload)>16777216
    BEGIN SELECT RAISE(ABORT,'chat send intent capacity or identity conflict'); END;
    CREATE TRIGGER chat_send_intent_update BEFORE UPDATE ON account_chat_send_intents
    WHEN NEW.intent_id!=OLD.intent_id OR NEW.account!=OLD.account OR NEW.origin!=OLD.origin
      OR NEW.group_id!=OLD.group_id OR NEW.event_id!=OLD.event_id OR NEW.digest!=OLD.digest
      OR NEW.created_at!=OLD.created_at OR OLD.state!=0 OR NEW.state=0
    BEGIN SELECT RAISE(ABORT,'chat send intent is immutable or terminal'); END;
    CREATE TRIGGER chat_send_intent_keep BEFORE DELETE ON account_chat_send_intents
    BEGIN SELECT RAISE(ABORT,'chat send intent identity retained'); END;
    CREATE TRIGGER chat_send_route_insert BEFORE INSERT ON account_chat_send_routes
    WHEN NEW.state!=0 OR NEW.member IS NOT NULL OR (SELECT count(*) FROM account_chat_send_routes)>=8192
      OR EXISTS(SELECT 1 FROM account_chat_send_routes WHERE intent_id=NEW.intent_id AND policy_id=NEW.policy_id)
      OR EXISTS(SELECT 1 FROM account_chat_send_routes old JOIN approved_account_sharing_policies p ON p.policy_id=old.policy_id WHERE old.intent_id=NEW.intent_id AND p.revoked=1)
      OR NOT EXISTS(SELECT 1 FROM account_chat_send_intents WHERE intent_id=NEW.intent_id AND state=0)
      OR NOT EXISTS(SELECT 1 FROM approved_account_sharing_policies WHERE policy_id=NEW.policy_id AND revoked=0 AND local_device=NEW.local_device)
    BEGIN SELECT RAISE(ABORT,'chat send route capacity or scope conflict'); END;
    CREATE TRIGGER chat_send_route_update BEFORE UPDATE ON account_chat_send_routes
    WHEN NEW.intent_id!=OLD.intent_id OR NEW.policy_id!=OLD.policy_id
      OR NEW.local_device!=OLD.local_device OR NEW.peer_device!=OLD.peer_device
      OR OLD.state IN (2,3) OR NEW.state<=OLD.state
      OR (OLD.member IS NOT NULL AND (NEW.member IS NULL OR NEW.member!=OLD.member))
    BEGIN SELECT RAISE(ABORT,'chat send route regression'); END;
    CREATE TRIGGER chat_send_route_keep BEFORE DELETE ON account_chat_send_routes
    BEGIN SELECT RAISE(ABORT,'chat send route retained'); END;
    CREATE TRIGGER chat_send_receipt_insert BEFORE INSERT ON account_chat_send_receipts
    WHEN NEW.acknowledged!=0 OR (SELECT count(*) FROM account_chat_send_receipts)>=32768
      OR EXISTS(SELECT 1 FROM account_chat_send_receipts WHERE digest=NEW.digest)
    BEGIN SELECT RAISE(ABORT,'chat send receipt capacity or identity conflict'); END;
    CREATE TRIGGER chat_send_receipt_update BEFORE UPDATE ON account_chat_send_receipts
    WHEN NEW.digest!=OLD.digest OR NEW.intent_id!=OLD.intent_id OR NEW.policy_id!=OLD.policy_id
      OR NEW.record!=OLD.record OR OLD.acknowledged!=0 OR NEW.acknowledged!=1
    BEGIN SELECT RAISE(ABORT,'chat send receipt is immutable'); END;
    CREATE TRIGGER chat_send_receipt_keep BEFORE DELETE ON account_chat_send_receipts
    BEGIN SELECT RAISE(ABORT,'chat send receipt retained'); END;").storage()
}
