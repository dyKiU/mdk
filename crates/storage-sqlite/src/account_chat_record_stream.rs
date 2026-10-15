//! Durable canonical batches and committed receipts, without channel restoration.
use crate::{SqliteAccountStorage, SqliteResultExt, approved_account_sharing_policy::load};
use cgka_traits::{
    GroupId,
    account_chat_record_stream::*,
    mirrored_chat_catalog::MirroredChatScope,
    mirrored_chat_messages::{
        MAX_MIRRORED_MESSAGE_PAGE, MirroredChatMessageStorage, MirroredChatRecord,
    },
    storage::{StorageError, StorageResult},
};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
fn invalid() -> StorageError {
    StorageError::Serialization("invalid paired chat record delivery".into())
}
fn capacity() -> StorageError {
    StorageError::Capacity("paired chat record delivery limit reached".into())
}
fn policy(conn: &Connection, id: &[u8; 32], group: &GroupId) -> StorageResult<()> {
    let fact = load(conn, id)?;
    if fact.revoked
        || group == &fact.protected_group
        || !(1..=255).contains(&group.as_slice().len())
    {
        return Err(invalid());
    }
    Ok(())
}
fn decode(batch: &AccountChatRecordBatch) -> StorageResult<Vec<MirroredChatRecord>> {
    if batch.batch_digest == [0; 32]
        || batch.encoded_records.is_empty()
        || batch.encoded_records.len() > MAX_ACCOUNT_CHAT_RECORD_BATCH_BYTES
        || batch.first_sequence == 0
        || batch.last_sequence > i64::MAX as u64
        || batch.last_sequence < batch.first_sequence
        || !(1..=MAX_MIRRORED_MESSAGE_PAGE as u32).contains(&batch.record_count)
        || <[u8; 32]>::from(Sha256::digest(&batch.encoded_records)) != batch.batch_digest
    {
        return Err(invalid());
    }
    let records: Vec<MirroredChatRecord> =
        serde_json::from_slice(&batch.encoded_records).map_err(|_| invalid())?;
    if records.len() != batch.record_count as usize
        || records.first().map(|r| r.source_sequence) != Some(batch.first_sequence)
        || records.last().map(|r| r.source_sequence) != Some(batch.last_sequence)
        || serde_json::to_vec(&records).map_err(|_| invalid())? != batch.encoded_records
        || records
            .windows(2)
            .any(|w| w[0].source_sequence >= w[1].source_sequence)
    {
        return Err(invalid());
    }
    let mut ids = HashSet::new();
    for record in &records {
        crate::mirrored_chat_messages::validate(record)?;
        if !ids.insert(record.event_id) {
            return Err(invalid());
        }
    }
    Ok(records)
}
fn matches(receipt: &AccountChatRecordReceipt, batch: &AccountChatRecordBatch) -> bool {
    receipt.batch_digest == batch.batch_digest
        && receipt.first_sequence == batch.first_sequence
        && receipt.last_sequence == batch.last_sequence
        && receipt.record_count == batch.record_count
        && receipt.imported_count <= receipt.record_count
}
type OutboxRow = (i64, i64, u32, Vec<u8>, Option<Vec<u8>>, u8);
type StoredBatch = (AccountChatRecordBatch, Option<AccountChatRecordReceipt>, u8);
fn stored_batch(
    conn: &Connection,
    id: &[u8; 32],
    group: &GroupId,
    digest: &[u8; 32],
) -> StorageResult<Option<StoredBatch>> {
    let row: Option<OutboxRow> = conn
        .query_row(
            "SELECT first_sequence,last_sequence,record_count,payload,receipt,state
FROM account_chat_record_outbox WHERE policy_id=?1 AND group_id=?2 AND
digest=?3",
            params![id.as_slice(), group.as_slice(), digest.as_slice()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()
        .storage()?;
    row.map(|(first, last, count, payload, receipt, state)| {
        let batch = AccountChatRecordBatch {
            batch_digest: *digest,
            first_sequence: first as u64,
            last_sequence: last as u64,
            record_count: count,
            encoded_records: payload,
        };
        let receipt: Option<AccountChatRecordReceipt> = receipt
            .map(|r| serde_json::from_slice(&r).map_err(|_| invalid()))
            .transpose()?;
        if state == 2 {
            if receipt.is_some() || !batch.encoded_records.is_empty() {
                return Err(invalid());
            }
        } else if let Some(r) = &receipt {
            if !matches(r, &batch) || !batch.encoded_records.is_empty() {
                return Err(invalid());
            }
        } else {
            decode(&batch)?;
        }
        Ok((batch, receipt, state))
    })
    .transpose()
}
fn acknowledge_global_batch(
    conn: &Connection,
    id: &[u8; 32],
    group: &GroupId,
    receipt: &AccountChatRecordReceipt,
) -> StorageResult<()> {
    let (batch, previous, state) =
        stored_batch(conn, id, group, &receipt.batch_digest)?.ok_or_else(invalid)?;
    if state == 2 || !matches(receipt, &batch) {
        return Err(invalid());
    }
    if let Some(old) = previous {
        if old != *receipt {
            return Err(invalid());
        }
    } else {
        conn.execute(
            "UPDATE account_chat_record_outbox SET payload=X'',receipt=?4,state=1 WHERE
policy_id=?1 AND group_id=?2 AND digest=?3",
            params![
                id.as_slice(),
                group.as_slice(),
                receipt.batch_digest.as_slice(),
                serde_json::to_vec(receipt).map_err(|_| invalid())?
            ],
        )
        .storage()?;
    }
    Ok(())
}

fn generation_receipt(
    conn: &Connection,
    id: &[u8; 32],
    group: &GroupId,
    digest: &[u8; 32],
    generation: u64,
) -> StorageResult<Option<AccountChatRecordReceipt>> {
    if generation > i64::MAX as u64 {
        return Err(invalid());
    }
    let (batch, global, state) = stored_batch(conn, id, group, digest)?.ok_or_else(invalid)?;
    if state == 2 {
        return Err(invalid());
    }
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT record FROM account_chat_record_generation_receipts
WHERE policy_id=?1 AND group_id=?2 AND digest=?3 AND peer_generation=?4",
            params![
                id.as_slice(),
                group.as_slice(),
                digest.as_slice(),
                generation as i64
            ],
            |row| row.get(0),
        )
        .optional()
        .storage()?;
    bytes
        .map(|bytes| {
            let receipt: AccountChatRecordReceipt =
                serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            if state != 1 || global.as_ref() != Some(&receipt) || !matches(&receipt, &batch) {
                return Err(invalid());
            }
            Ok(receipt)
        })
        .transpose()
}

impl AccountChatRecordStreamStorage for SqliteAccountStorage {
    fn reserve_account_chat_record_sequence(
        &self,
        id: &[u8; 32],
        group: &GroupId,
        event: &[u8; 32],
        digest: &[u8; 32],
        validator: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<u64> {
        if *event == [0; 32] || *digest == [0; 32] {
            return Err(invalid());
        }
        self.connection.with_transaction(|| {
            validator()?;
            let conn = self.lock()?;
            policy(&conn, id, group)?;
            let previous: Option<(Vec<u8>, i64)> = conn
                .query_row(
                    "SELECT digest,sequence FROM account_chat_record_journal WHERE policy_id=?1
AND group_id=?2 AND event_id=?3",
                    params![id.as_slice(), group.as_slice(), event.as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .storage()?;
            let sequence = if let Some((_, sequence)) = previous
                .as_ref()
                .filter(|(old, _)| old.as_slice() == digest)
            {
                *sequence
            } else {
                if previous.is_none() {
                    let count: i64 = conn
                        .query_row(
                            "SELECT count(*) FROM account_chat_record_journal",
                            [],
                            |r| r.get(0),
                        )
                        .storage()?;
                    if count >= MAX_ACCOUNT_CHAT_RECORD_JOURNAL as i64 {
                        return Err(capacity());
                    }
                }
                let counter: Option<i64> = conn
                    .query_row(
                        "SELECT sequence FROM account_chat_record_counters WHERE policy_id=?1",
                        [id.as_slice()],
                        |r| r.get(0),
                    )
                    .optional()
                    .storage()?;
                if counter.is_none() {
                    conn.execute(
                        "INSERT INTO account_chat_record_counters VALUES(?1,0)",
                        [id.as_slice()],
                    )
                    .storage()?;
                }
                let next = counter
                    .unwrap_or(0)
                    .checked_add(1)
                    .filter(|n| *n > 0)
                    .ok_or_else(capacity)?;
                conn.execute(
                    "UPDATE account_chat_record_counters SET sequence=?2 WHERE policy_id=?1",
                    params![id.as_slice(), next],
                )
                .storage()?;
                if previous.is_some() {
                    conn.execute(
                        "UPDATE account_chat_record_journal SET digest=?4,sequence=?5 WHERE
policy_id=?1 AND group_id=?2 AND event_id=?3",
                        params![
                            id.as_slice(),
                            group.as_slice(),
                            event.as_slice(),
                            digest.as_slice(),
                            next
                        ],
                    )
                    .storage()?;
                } else {
                    conn.execute(
                        "INSERT INTO account_chat_record_journal VALUES(?1,?2,?3,?4,?5)",
                        params![
                            id.as_slice(),
                            group.as_slice(),
                            event.as_slice(),
                            digest.as_slice(),
                            next
                        ],
                    )
                    .storage()?;
                }
                next
            };
            drop(conn);
            validator()?;
            Ok(sequence as u64)
        })
    }
    fn stage_account_chat_record_batch(
        &self,
        id: &[u8; 32],
        group: &GroupId,
        batch: &AccountChatRecordBatch,
        validator: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        let records = decode(batch)?;
        self.connection.with_transaction(|| {
            validator()?;
let conn=self.lock()?;
policy(&conn,id,group)?;
            if let Some((old,receipt,state))=stored_batch(&conn,id,group,&batch.batch_digest)? {
                if state==2 {
return Err(invalid());
}
                if old.first_sequence!=batch.first_sequence || old.last_sequence!=batch.last_sequence || old.record_count!=batch.record_count || (receipt.is_none() && old!=*batch) {
return Err(invalid());
}
            }
 else {
                let (count,bytes):(i64,i64)=conn.query_row("SELECT count(*),coalesce(sum(length(payload)),0) FROM account_chat_record_outbox",[],|r|Ok((r.get(0)?,r.get(1)?))).storage()?;
                if count>=MAX_ACCOUNT_CHAT_RECORD_OUTBOX as i64 || bytes+batch.encoded_records.len() as i64>MAX_ACCOUNT_CHAT_RECORD_OUTBOX_BYTES as i64 {
return Err(capacity());
}
                for record in &records {
                    let current:Option<(Vec<u8>,i64)>=conn.query_row("SELECT digest,sequence FROM account_chat_record_journal WHERE policy_id=?1
AND group_id=?2 AND event_id=?3",params![id.as_slice(),group.as_slice(),record.event_id.as_slice()],|r|Ok((r.get(0)?,r.get(1)?))).optional().storage()?;
                    if !current.is_some_and(|(digest,sequence)|digest.as_slice()==record.source_digest && sequence as u64==record.source_sequence) {
return Err(invalid());
}
                }
                conn.execute("INSERT INTO account_chat_record_outbox VALUES(?1,?2,?3,?4,?5,?6,?7,NULL,0)",params![id.as_slice(),group.as_slice(),batch.batch_digest.as_slice(),batch.first_sequence as i64,batch.last_sequence as i64,batch.record_count,batch.encoded_records]).storage()?;
            }
            drop(conn);
validator()
        }
)
    }
    fn pending_account_chat_record_batches(
        &self,
        id: &[u8; 32],
        group: &GroupId,
        after: Option<&[u8; 32]>,
        limit: usize,
    ) -> StorageResult<Vec<AccountChatRecordBatch>> {
        if !(1..=MAX_MIRRORED_MESSAGE_PAGE).contains(&limit) {
            return Err(invalid());
        }
        let conn = self.lock()?;
        policy(&conn, id, group)?;
        let mut statement = conn
            .prepare(
                "SELECT digest FROM account_chat_record_outbox WHERE policy_id=?1 AND
group_id=?2 AND state=0 AND (?3 IS NULL OR digest>?3) ORDER BY digest
LIMIT ?4",
            )
            .storage()?;
        let rows = statement
            .query_map(
                params![
                    id.as_slice(),
                    group.as_slice(),
                    after.map(|d| d.as_slice()),
                    limit as i64
                ],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .storage()?;
        let mut batches = Vec::new();
        for row in rows {
            let digest: [u8; 32] = row.storage()?.try_into().map_err(|_| invalid())?;
            batches.push(
                stored_batch(&conn, id, group, &digest)?
                    .ok_or_else(invalid)?
                    .0,
            );
        }
        Ok(batches)
    }
    fn acknowledge_account_chat_record_batch(
        &self,
        id: &[u8; 32],
        group: &GroupId,
        receipt: &AccountChatRecordReceipt,
        validator: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            validator()?;
            let conn = self.lock()?;
            policy(&conn, id, group)?;
            acknowledge_global_batch(&conn, id, group, receipt)?;
            drop(conn);
            validator()
        })
    }
    fn account_chat_record_generation_receipt(
        &self,
        id: &[u8; 32],
        group: &GroupId,
        digest: &[u8; 32],
        peer_generation: u64,
        validator: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<Option<AccountChatRecordReceipt>> {
        self.connection.with_transaction(|| {
            validator()?;
            let conn = self.lock()?;
            policy(&conn, id, group)?;
            let result = generation_receipt(&conn, id, group, digest, peer_generation)?;
            drop(conn);
            validator()?;
            Ok(result)
        })
    }
    fn acknowledge_account_chat_record_batch_for_generation(
        &self,
        id: &[u8; 32],
        group: &GroupId,
        receipt: &AccountChatRecordReceipt,
        peer_generation: u64,
        validator: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        if peer_generation > i64::MAX as u64 {
            return Err(invalid());
        }
        self.connection.with_transaction(|| {
            validator()?;
            let conn = self.lock()?;
            policy(&conn, id, group)?;
            acknowledge_global_batch(&conn, id, group, receipt)?;
            if let Some(previous) =
                generation_receipt(&conn, id, group, &receipt.batch_digest, peer_generation)?
            {
                if previous != *receipt {
                    return Err(invalid());
                }
            } else {
                let count: i64 = conn
                    .query_row(
                        "SELECT count(*) FROM account_chat_record_generation_receipts",
                        [],
                        |row| row.get(0),
                    )
                    .storage()?;
                if count >= MAX_ACCOUNT_CHAT_RECORD_GENERATION_RECEIPTS as i64 {
                    return Err(capacity());
                }
                conn.execute(
                    "INSERT INTO account_chat_record_generation_receipts VALUES(?1,?2,?3,?4,?5)",
                    params![
                        id.as_slice(),
                        group.as_slice(),
                        receipt.batch_digest.as_slice(),
                        peer_generation as i64,
                        serde_json::to_vec(receipt).map_err(|_| invalid())?
                    ],
                )
                .storage()?;
            }
            drop(conn);
            validator()
        })
    }
    fn deny_account_chat_record_batch(
        &self,
        id: &[u8; 32],
        group: &GroupId,
        digest: &[u8; 32],
        validator: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            validator()?;
            let conn = self.lock()?;
            let fact = load(&conn, id)?;
            if group == &fact.protected_group || !(1..=255).contains(&group.as_slice().len()) {
                return Err(invalid());
            }
            let (_, _, state) = stored_batch(&conn, id, group, digest)?.ok_or_else(invalid)?;
            if state == 1 {
                return Err(invalid());
            }
            if state == 0 {
                conn.execute(
                    "UPDATE account_chat_record_outbox SET payload=X'',state=2 WHERE
policy_id=?1 AND group_id=?2 AND digest=?3",
                    params![id.as_slice(), group.as_slice(), digest.as_slice()],
                )
                .storage()?;
            }
            drop(conn);
            validator()
        })
    }
    fn apply_account_chat_record_batch(
        &self,
        scope: &MirroredChatScope,
        group: &GroupId,
        batch: &AccountChatRecordBatch,
        now: u64,
        validator: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<AccountChatRecordReceipt> {
        if now > i64::MAX as u64 {
            return Err(invalid());
        }
        let records = decode(batch)?;
        let key = crate::mirrored_chat_catalog::scope_bytes(scope)?;
        self.connection.with_transaction(|| {
            validator()?;
            let conn = self.lock()?;
            policy(&conn, &scope.policy_digest, group)?;
            let fact = load(&conn, &scope.policy_digest)?;
            if fact.account != scope.account
                || fact.local_device != scope.local_device
                || fact.peer_device != scope.source_device
                || fact.protected_group != scope.protected_group
            {
                return Err(invalid());
            }
            crate::mirrored_chat_catalog::check_owner(&conn, scope)?;
            for record in &records {
                if crate::account_chat_departure::account_chat_departure_denies_source_on_connection(
                    &conn, &scope.account, &scope.local_device, group,
                    &scope.source_device, record.accepted_origin,
                )? {
                    return Err(StorageError::MirroredRecordDeniedByDeparture);
                }
            }
            crate::mirrored_chat_messages::check_catalog(&conn, scope, &key, group)?;
            let old: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT record FROM account_chat_record_receipts WHERE policy_id=?1
AND group_id=?2 AND digest=?3",
                    params![
                        scope.policy_digest.as_slice(),
                        group.as_slice(),
                        batch.batch_digest.as_slice()
                    ],
                    |r| r.get(0),
                )
                .optional()
                .storage()?;
            if let Some(bytes) = old {
                let receipt: AccountChatRecordReceipt =
                    serde_json::from_slice(&bytes).map_err(|_| invalid())?;
                if !matches(&receipt, batch) {
                    return Err(invalid());
                }
                drop(conn);
                // Renewed scope projections receive the exact observations,
                // while the committed acknowledgment remains unchanged.
                self.apply_mirrored_chat_messages(scope, group, &records, now, &|| Ok(()))?;
                validator()?;
                return Ok(receipt);
            }
            let count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM account_chat_record_receipts",
                    [],
                    |r| r.get(0),
                )
                .storage()?;
            if count >= MAX_ACCOUNT_CHAT_RECORD_RECEIPTS as i64 {
                return Err(capacity());
            }
            let previous: Option<i64> = conn
                .query_row(
                    "SELECT sequence FROM account_chat_record_progress WHERE policy_id=?1
AND group_id=?2",
                    params![scope.policy_digest.as_slice(), group.as_slice()],
                    |r| r.get(0),
                )
                .optional()
                .storage()?;
            if previous.is_none() {
                let count: i64 = conn
                    .query_row(
                        "SELECT count(*) FROM account_chat_record_progress",
                        [],
                        |r| r.get(0),
                    )
                    .storage()?;
                if count >= 8192 {
                    return Err(capacity());
                }
            }
            drop(conn);
            // Nested same-thread transaction shares the outer SQL commit/rollback.
            // Only the outer before/tail callbacks own the fresh original check.
            let imported =
                self.apply_mirrored_chat_messages(scope, group, &records, now, &|| Ok(()))?;
            let receipt = AccountChatRecordReceipt {
                batch_digest: batch.batch_digest,
                first_sequence: batch.first_sequence,
                last_sequence: batch.last_sequence,
                record_count: batch.record_count,
                imported_count: imported as u32,
            };
            let conn = self.lock()?;
            conn.execute(
                "INSERT INTO account_chat_record_receipts VALUES(?1,?2,?3,?4)",
                params![
                    scope.policy_digest.as_slice(),
                    group.as_slice(),
                    batch.batch_digest.as_slice(),
                    serde_json::to_vec(&receipt).map_err(|_| invalid())?
                ],
            )
            .storage()?;
            if previous.is_none() {
                conn.execute(
                    "INSERT INTO account_chat_record_progress VALUES(?1,?2,?3)",
                    params![
                        scope.policy_digest.as_slice(),
                        group.as_slice(),
                        batch.last_sequence as i64
                    ],
                )
                .storage()?;
            } else if previous.is_some_and(|old| old < batch.last_sequence as i64) {
                conn.execute(
                    "UPDATE account_chat_record_progress SET sequence=?3 WHERE policy_id=?1
AND group_id=?2",
                    params![
                        scope.policy_digest.as_slice(),
                        group.as_slice(),
                        batch.last_sequence as i64
                    ],
                )
                .storage()?;
            }
            drop(conn);
            validator()?;
            Ok(receipt)
        })
    }
}
#[cfg(test)]
#[path = "account_chat_record_stream/tests.rs"]
mod tests;
