//! Separate experimental archive records from authenticated engine evidence.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE TABLE synchronized_history_transfers (
        transfer_id BLOB PRIMARY KEY NOT NULL CHECK(length(transfer_id)=32),
        group_id_hex TEXT NOT NULL,
        source_device BLOB NOT NULL CHECK(length(source_device)=32),
        manifest_digest BLOB NOT NULL CHECK(length(manifest_digest)=32),
        manifest_json BLOB NOT NULL CHECK(length(manifest_json)<=32768),
        next_chunk INTEGER NOT NULL DEFAULT 0 CHECK(next_chunk BETWEEN 0 AND 128),
        complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0,1)),
        cancelled INTEGER NOT NULL DEFAULT 0 CHECK(cancelled IN (0,1)),
        charged_bytes INTEGER NOT NULL DEFAULT 0 CHECK(charged_bytes>=0)
    );
    CREATE INDEX idx_synchronized_history_transfers_group ON synchronized_history_transfers(group_id_hex,complete);
    CREATE TABLE synchronized_history_chunks (
        transfer_id BLOB NOT NULL REFERENCES synchronized_history_transfers(transfer_id) ON DELETE CASCADE,
        chunk_index INTEGER NOT NULL CHECK(chunk_index BETWEEN 0 AND 127),
        chunk_digest BLOB NOT NULL CHECK(length(chunk_digest)=32),
        imported_records INTEGER NOT NULL CHECK(imported_records BETWEEN 0 AND 200),
        skipped_records INTEGER NOT NULL CHECK(skipped_records BETWEEN 0 AND 200),
        PRIMARY KEY(transfer_id,chunk_index)
    );
    CREATE TABLE synchronized_history_records (
        transfer_id BLOB NOT NULL REFERENCES synchronized_history_transfers(transfer_id) ON DELETE CASCADE,
        message_id_hex TEXT NOT NULL CHECK(length(message_id_hex)=64),
        record_json BLOB NOT NULL CHECK(length(record_json)<=1048576),
        deleted INTEGER NOT NULL CHECK(deleted IN (0,1)),
        identity_digest BLOB NOT NULL CHECK(length(identity_digest)=32),
        created_at INTEGER NOT NULL CHECK(created_at>=0),
        expires_at INTEGER CHECK(expires_at>=0),
        PRIMARY KEY(transfer_id,message_id_hex)
    );
    CREATE INDEX idx_synchronized_history_records_id ON synchronized_history_records(message_id_hex,deleted,transfer_id);
    CREATE TABLE synchronized_history_retention_intents (
        transfer_id BLOB NOT NULL REFERENCES synchronized_history_transfers(transfer_id) ON DELETE CASCADE,
        message_id_hex TEXT NOT NULL CHECK(length(message_id_hex)=64),
        PRIMARY KEY(transfer_id,message_id_hex)
    );
    CREATE TABLE synchronized_history_retention_fences (
        group_id_hex TEXT NOT NULL,
        message_id_hex TEXT NOT NULL CHECK(length(message_id_hex)=64),
        PRIMARY KEY(group_id_hex,message_id_hex)
    );").storage()?;
    Ok(())
}
