//! Durable negative account departure intent, exact source cuts and transport receipts.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_chat_departures (
          action_id BLOB PRIMARY KEY CHECK(length(action_id)=32),
          account BLOB NOT NULL CHECK(length(account)=32),
          local_device BLOB NOT NULL CHECK(length(local_device)=32),
          initiator BLOB NOT NULL CHECK(length(initiator)=32),
          group_id BLOB NOT NULL CHECK(length(group_id) BETWEEN 1 AND 255),
          record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 65536),
          local_state INTEGER NOT NULL DEFAULT 0 CHECK(local_state BETWEEN 0 AND 2),
          needs_administrator INTEGER NOT NULL DEFAULT 0 CHECK(needs_administrator IN(0,1)),
          awaiting_sources INTEGER NOT NULL DEFAULT 0 CHECK(awaiting_sources IN(0,1)),
          global_complete INTEGER NOT NULL DEFAULT 0 CHECK(global_complete IN(0,1)),
          reply_pending INTEGER NOT NULL DEFAULT 1 CHECK(reply_pending IN(0,1)));
         CREATE TABLE account_chat_departure_cuts (
          action_id BLOB NOT NULL REFERENCES account_chat_departures(action_id),
          source_device BLOB NOT NULL CHECK(length(source_device)=32),
          origin_id BLOB NOT NULL CHECK(length(origin_id)=32),
          origin_order INTEGER NOT NULL CHECK(origin_order BETWEEN 1 AND 8192),
          PRIMARY KEY(action_id,source_device));
         CREATE TABLE account_chat_departure_routes (
          action_id BLOB NOT NULL REFERENCES account_chat_departures(action_id),
          peer_device BLOB NOT NULL CHECK(length(peer_device)=32),
          acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN(0,1)),
          complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN(0,1)),
          needs_administrator INTEGER NOT NULL DEFAULT 0 CHECK(needs_administrator IN(0,1)),
          awaiting_sources INTEGER NOT NULL DEFAULT 0 CHECK(awaiting_sources IN(0,1)),
          final_acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(final_acknowledged IN(0,1)),
          PRIMARY KEY(action_id,peer_device));
         CREATE TRIGGER account_departure_keep BEFORE DELETE ON account_chat_departures
          BEGIN SELECT RAISE(ABORT,'account departure intent retained'); END;
         CREATE TRIGGER account_departure_immutable BEFORE UPDATE ON account_chat_departures
          WHEN NEW.action_id!=OLD.action_id OR NEW.account!=OLD.account
           OR NEW.local_device!=OLD.local_device OR NEW.initiator!=OLD.initiator
           OR NEW.group_id!=OLD.group_id OR NEW.record!=OLD.record
           OR NEW.local_state<OLD.local_state
          BEGIN SELECT RAISE(ABORT,'account departure intent immutable'); END;
         CREATE TRIGGER account_departure_cut_keep BEFORE DELETE ON account_chat_departure_cuts
          BEGIN SELECT RAISE(ABORT,'account departure cut retained'); END;
         CREATE TRIGGER account_departure_cut_immutable BEFORE UPDATE ON account_chat_departure_cuts
          BEGIN SELECT RAISE(ABORT,'account departure cut immutable'); END;
         DROP VIEW mirrored_chat_live_catalog;
         CREATE VIEW mirrored_chat_live_catalog AS SELECT c.* FROM mirrored_chat_catalog c JOIN mirrored_chat_scopes s USING(scope) WHERE c.state=0
 AND NOT EXISTS(SELECT 1 FROM mirrored_chat_origin_fences f WHERE f.account=s.account AND f.local_device=s.local_device AND f.source_device=s.source_device AND f.group_id=c.group_id AND (f.state=2 OR f.origin_id=c.origin_id OR (f.origin_order=0 AND (c.origin_id IS NULL OR f.epoch>=json_extract(c.record,'$.source_epoch')))))
 AND ((c.origin_id IS NULL AND NOT EXISTS(SELECT 1 FROM mirrored_chat_origin_current o WHERE o.account=s.account AND o.local_device=s.local_device AND o.source_device=s.source_device AND o.group_id=c.group_id)) OR EXISTS(SELECT 1 FROM mirrored_chat_origin_current o WHERE o.account=s.account AND o.local_device=s.local_device AND o.source_device=s.source_device AND o.group_id=c.group_id AND o.origin_id=c.origin_id AND o.origin_order=c.origin_order))
 AND NOT EXISTS(SELECT 1 FROM account_chat_departures departure
   JOIN account_chat_departure_cuts cut USING(action_id)
   WHERE departure.account=s.account AND departure.local_device=s.local_device
     AND departure.group_id=c.group_id AND cut.source_device=s.source_device
     AND (c.origin_id IS NULL OR cut.origin_id=c.origin_id OR cut.origin_order>=c.origin_order));",
    )
    .storage()
}
