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
          BEGIN SELECT RAISE(ABORT,'account departure cut immutable'); END;",
    )
    .storage()
}
