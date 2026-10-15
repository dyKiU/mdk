//! Bounded metadata only. Engine owns live admission and authenticated fact creation.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::private_device_invite::PrivateInviteOrigin;
use cgka_traits::private_roster_settlement::*;
use cgka_traits::storage::{StorageError, StorageProvider, StorageResult};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashSet;
const SELECT: &str = "SELECT generation,account,local_device,group_id,state FROM private_roster_settlement WHERE singleton=1";
const UPDATE: &str =
    "UPDATE private_roster_settlement SET state=?1 WHERE singleton=1 AND generation=?2";
fn invalid() -> StorageError {
    StorageError::Serialization("invalid private settlement facts".into())
}
fn generation(value: u64) -> StorageResult<i64> {
    i64::try_from(value)
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(invalid)
}
fn encode<T: serde::Serialize>(value: &T, max: usize) -> StorageResult<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    if bytes.is_empty() || bytes.len() > max {
        return Err(invalid());
    }
    Ok(bytes)
}
fn validate_anchor(anchor: &PrivateSettlementAnchor) -> StorageResult<()> {
    match anchor.origin {
        PrivateInviteOrigin::Accepted(n)
        | PrivateInviteOrigin::Confirmed(n)
        | PrivateInviteOrigin::Existing(n)
        | PrivateInviteOrigin::Revoked(n) => {
            generation(n)?;
        }
        _ => return Err(invalid()),
    }
    if anchor.group_id.as_slice().is_empty()
        || anchor.group_id.as_slice().len() > 255
        || anchor.successor.epoch.0 > i64::MAX as u64
        || anchor.successor.leaves.is_empty()
        || anchor.successor.leaves.len() > 128
        || anchor.enrollment_nonce == [0; 32]
        || anchor.context_digest == [0; 32]
        || anchor.roster_commitment == [0; 32]
    {
        return Err(invalid());
    }
    let mut previous = None;
    let mut keys = HashSet::new();
    for leaf in &anchor.successor.leaves {
        if leaf.account != anchor.account
            || previous.is_some_and(|index| index >= leaf.leaf_index)
            || !keys.insert(leaf.signature_public_key)
        {
            return Err(invalid());
        }
        previous = Some(leaf.leaf_index);
    }
    if !keys.contains(&anchor.local_device) || !keys.contains(&anchor.coordinator) {
        return Err(invalid());
    }
    Ok(())
}
fn validate_state(state: &PrivateSettlementState) -> StorageResult<()> {
    validate_anchor(&state.anchor)?;
    generation(state.generation)?;
    if state.format_version != 1
        || state.round_nonce == Some([0; 32])
        || state.round_nonce.is_some() != state.coordinator_leaf_index.is_some()
        || state
            .prepared_ciphertext
            .as_ref()
            .is_some_and(|b| b.is_empty() || b.len() > 16384)
        || state
            .outbound
            .as_ref()
            .is_some_and(|b| b.is_empty() || b.len() > 32768)
        || ((state.prepared_ciphertext.is_some() || state.outbound.is_some())
            && state.round_nonce.is_none())
    {
        return Err(invalid());
    }
    if let Some(index) = state.coordinator_leaf_index
        && !state
            .anchor
            .successor
            .leaves
            .iter()
            .any(|v| v.leaf_index == index && v.signature_public_key == state.anchor.coordinator)
    {
        return Err(invalid());
    }
    let mut pending_slots = HashSet::new();
    if state.deferred_acks.len() > state.anchor.successor.leaves.len() {
        return Err(invalid());
    }
    for ack in &state.deferred_acks {
        validate_fact(state, &ack.fact)?;
        if ack.round_nonce == [0; 32]
            || ack.fact.signature_public_key == state.anchor.local_device
            || ack.fact.signature_public_key == state.anchor.coordinator
            || !pending_slots.insert(ack.fact.leaf_index)
        {
            return Err(invalid());
        }
    }
    if state.phase == PrivateSettlementPhase::Denied
        && (state.prepared_ciphertext.is_some()
            || state.outbound.is_some()
            || !state.deferred_acks.is_empty())
    {
        return Err(invalid());
    }
    Ok(())
}
fn validate_fact(
    state: &PrivateSettlementState,
    fact: &PrivateSettlementFact,
) -> StorageResult<()> {
    if fact.format_version != 1
        || fact.generation != state.generation
        || fact.message_id.as_slice().is_empty()
        || fact.message_id.as_slice().len() > 256
        || !state.anchor.successor.leaves.iter().any(|leaf| {
            leaf.leaf_index == fact.leaf_index
                && leaf.signature_public_key == fact.signature_public_key
        })
    {
        return Err(invalid());
    }
    Ok(())
}
fn facts(
    conn: &Connection,
    state: &PrivateSettlementState,
) -> StorageResult<Vec<PrivateSettlementFact>> {
    #[cfg(all(feature = "test-support", feature = "experimental-device-sync"))]
    let _sync_cost_facts_whole = cgka_traits::enrollment_sync_cost::Probe::start(
        cgka_traits::enrollment_sync_cost::Bucket::SqlFactsWhole,
    );
    #[cfg(all(feature = "test-support", feature = "experimental-device-sync"))]
    let _sync_cost_facts_query = cgka_traits::enrollment_sync_cost::Probe::start(
        cgka_traits::enrollment_sync_cost::Bucket::SqlFactsQuerySetup,
    );
    let mut query=conn.prepare("SELECT leaf_index,record FROM private_roster_settlement_facts ORDER BY leaf_index LIMIT 129").storage()?;
    let rows = query
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .storage()?;
    #[cfg(all(feature = "test-support", feature = "experimental-device-sync"))]
    drop(_sync_cost_facts_query);
    let mut result = Vec::new();
    for row in rows {
        let (index, bytes) = row.storage()?;
        #[cfg(all(feature = "test-support", feature = "experimental-device-sync"))]
        cgka_traits::enrollment_sync_cost::record_bytes(
            cgka_traits::enrollment_sync_cost::Bucket::SqlFactDecode,
            bytes.len(),
        );
        #[cfg(all(feature = "test-support", feature = "experimental-device-sync"))]
        let _sync_cost_fact_decode = cgka_traits::enrollment_sync_cost::Probe::start(
            cgka_traits::enrollment_sync_cost::Bucket::SqlFactDecode,
        );
        let fact: PrivateSettlementFact = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        #[cfg(all(feature = "test-support", feature = "experimental-device-sync"))]
        drop(_sync_cost_fact_decode);
        #[cfg(all(feature = "test-support", feature = "experimental-device-sync"))]
        let _sync_cost_fact_validate = cgka_traits::enrollment_sync_cost::Probe::start(
            cgka_traits::enrollment_sync_cost::Bucket::SqlFactValidate,
        );
        validate_fact(state, &fact)?;
        if i64::from(fact.leaf_index) != index {
            return Err(invalid());
        }
        result.push(fact);
    }
    if result.len() > 128
        || (!result.is_empty() && state.round_nonce.is_none())
        || (state.phase == PrivateSettlementPhase::Denied && !result.is_empty())
    {
        return Err(invalid());
    }
    Ok(result)
}
fn read(conn: &Connection) -> StorageResult<Option<PrivateSettlementState>> {
    #[cfg(all(feature = "test-support", feature = "experimental-device-sync"))]
    let _sync_cost_state_query = cgka_traits::enrollment_sync_cost::Probe::start(
        cgka_traits::enrollment_sync_cost::Bucket::SqlStateQuery,
    );
    let row = conn
        .query_row(SELECT, [], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        })
        .optional()
        .storage()?;
    #[cfg(all(feature = "test-support", feature = "experimental-device-sync"))]
    drop(_sync_cost_state_query);
    let Some((counter, account, device, group, bytes)) = row else {
        return Ok(None);
    };
    #[cfg(all(feature = "test-support", feature = "experimental-device-sync"))]
    cgka_traits::enrollment_sync_cost::record_bytes(
        cgka_traits::enrollment_sync_cost::Bucket::SqlStateDecode,
        bytes.len(),
    );
    #[cfg(all(feature = "test-support", feature = "experimental-device-sync"))]
    let _sync_cost_state_decode = cgka_traits::enrollment_sync_cost::Probe::start(
        cgka_traits::enrollment_sync_cost::Bucket::SqlStateDecode,
    );
    let state: PrivateSettlementState = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    #[cfg(all(feature = "test-support", feature = "experimental-device-sync"))]
    drop(_sync_cost_state_decode);
    #[cfg(all(feature = "test-support", feature = "experimental-device-sync"))]
    let _sync_cost_state_validate = cgka_traits::enrollment_sync_cost::Probe::start(
        cgka_traits::enrollment_sync_cost::Bucket::SqlStateValidate,
    );
    validate_state(&state)?;
    if generation(state.generation)? != counter
        || account != state.anchor.account
        || device != state.anchor.local_device
        || group != state.anchor.group_id.as_slice()
    {
        return Err(invalid());
    }
    #[cfg(all(feature = "test-support", feature = "experimental-device-sync"))]
    drop(_sync_cost_state_validate);
    let slots = facts(conn, &state)?;
    #[cfg(all(feature = "test-support", feature = "experimental-device-sync"))]
    let _sync_cost_consistency = cgka_traits::enrollment_sync_cost::Probe::start(
        cgka_traits::enrollment_sync_cost::Bucket::SqlReadConsistency,
    );
    let has_local = slots
        .iter()
        .any(|fact| fact.signature_public_key == state.anchor.local_device);
    if has_local != state.prepared_ciphertext.is_some() || (state.outbound.is_some() && !has_local)
    {
        return Err(invalid());
    }
    let complete = slots.len() == state.anchor.successor.leaves.len();
    if (state.phase == PrivateSettlementPhase::Completed) != complete
        || (complete && state.prepared_ciphertext.is_none())
    {
        return Err(invalid());
    }
    Ok(Some(state))
}
fn write(conn: &Connection, state: &PrivateSettlementState) -> StorageResult<()> {
    validate_state(state)?;
    let bytes = encode(state, 262144)?;
    if conn
        .execute(UPDATE, params![bytes, generation(state.generation)?])
        .storage()?
        != 1
    {
        return Err(invalid());
    }
    Ok(())
}
fn insert_fact(
    conn: &Connection,
    state: &mut PrivateSettlementState,
    fact: &PrivateSettlementFact,
) -> StorageResult<()> {
    validate_fact(state, fact)?;
    if state.phase == PrivateSettlementPhase::Denied || state.round_nonce.is_none() {
        return Err(invalid());
    }
    let old: Option<Vec<u8>> = conn
        .query_row(
            "SELECT record FROM private_roster_settlement_facts WHERE leaf_index=?1",
            [i64::from(fact.leaf_index)],
            |r| r.get(0),
        )
        .optional()
        .storage()?;
    if let Some(bytes) = old {
        let prior: PrivateSettlementFact = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        return if prior == *fact {
            Ok(())
        } else {
            Err(invalid())
        };
    }
    if state.phase != PrivateSettlementPhase::Pending {
        return Err(invalid());
    }
    conn.execute(
        "INSERT INTO private_roster_settlement_facts(leaf_index,record) VALUES(?1,?2)",
        params![i64::from(fact.leaf_index), encode(fact, 4096)?],
    )
    .storage()?;
    let slots = facts(conn, state)?;
    if slots.len() == state.anchor.successor.leaves.len() {
        if state.prepared_ciphertext.is_none() {
            return Err(invalid());
        }
        state.phase = PrivateSettlementPhase::Completed;
    }
    Ok(())
}
/// Permanent fence in the backend's actual group-delete transaction. Never
/// invoked during scratch snapshot restoration or projection-only erasure.
pub(crate) fn deny_for_group_tx(
    conn: &Connection,
    group_id: &cgka_traits::GroupId,
) -> StorageResult<()> {
    let Some(mut state) = read(conn)? else {
        return Ok(());
    };
    if state.anchor.group_id != *group_id || state.phase == PrivateSettlementPhase::Denied {
        return Ok(());
    }
    state.phase = PrivateSettlementPhase::Denied;
    state.prepared_ciphertext = None;
    state.outbound = None;
    conn.execute("DELETE FROM private_roster_settlement_facts", [])
        .storage()?;
    write(conn, &state)
}

impl PrivateRosterSettlementStorage for SqliteAccountStorage {
    fn read_round(&self) -> StorageResult<Option<PrivateSettlementState>> {
        {
            let conn = self.lock()?;
            read(&conn)
        }
    }
    fn select_round(
        &self,
        anchor: &PrivateSettlementAnchor,
    ) -> StorageResult<PrivateSettlementState> {
        validate_anchor(anchor)?;
        self.with_transaction(|storage| {
            let conn=storage.lock()?;
            let old=read(&conn)?;
            if old.as_ref().is_some_and(|s|s.anchor.account!=anchor.account||s.anchor.local_device!=anchor.local_device) {return Err(invalid());}
            let wrong:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM account_state WHERE local_account_id_hex IS NULL OR local_account_id_hex<>?1)",[hex::encode(anchor.account)],|r|r.get(0)).storage()?;
            if wrong {return Err(invalid());}
            let state=PrivateSettlementState {format_version:1,generation:old.map_or(Some(1),|s|s.generation.checked_add(1)).ok_or_else(invalid)?,phase:PrivateSettlementPhase::Pending,anchor:anchor.clone(),round_nonce:None,coordinator_leaf_index:None,prepared_ciphertext:None,outbound:None,deferred_acks:vec![]};
            let bytes=encode(&state,262144)?;generation(state.generation)?;
            conn.execute("DELETE FROM private_roster_settlement_facts",[]).storage()?;
            conn.execute("INSERT INTO private_roster_settlement VALUES(1,?1,?2,?3,?4,?5) ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation,account=excluded.account,local_device=excluded.local_device,group_id=excluded.group_id,state=excluded.state",params![generation(state.generation)?,anchor.account.as_slice(),anchor.local_device.as_slice(),anchor.group_id.as_slice(),bytes]).storage()?;
            Ok(state)
        })
    }
    fn bind_round_nonce(&self, expected: u64, nonce: [u8; 32], index: u32) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let mut state = read(&conn)?.ok_or(StorageError::NotFound)?;
            if state.generation != expected
                || state.phase == PrivateSettlementPhase::Denied
                || nonce == [0; 32]
                || !state.anchor.successor.leaves.iter().any(|v| {
                    v.leaf_index == index && v.signature_public_key == state.anchor.coordinator
                })
            {
                return Err(invalid());
            }
            if let Some(old) = state.round_nonce {
                return if old == nonce && state.coordinator_leaf_index == Some(index) {
                    Ok(())
                } else {
                    Err(invalid())
                };
            }
            if state.phase != PrivateSettlementPhase::Pending {
                return Err(invalid());
            }
            state.round_nonce = Some(nonce);
            state.coordinator_leaf_index = Some(index);
            write(&conn, &state)
        })
    }
    fn record_local_confirmation(
        &self,
        fact: &PrivateSettlementFact,
        cipher: &[u8],
    ) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let mut state = read(&conn)?.ok_or(StorageError::NotFound)?;
            if fact.signature_public_key != state.anchor.local_device
                || cipher.is_empty()
                || cipher.len() > 16384
                || state.phase == PrivateSettlementPhase::Denied
            {
                return Err(invalid());
            }
            if let Some(old) = &state.prepared_ciphertext {
                if old != cipher {
                    return Err(invalid());
                }
            } else {
                if state.phase != PrivateSettlementPhase::Pending {
                    return Err(invalid());
                }
                state.prepared_ciphertext = Some(cipher.to_vec());
            }
            insert_fact(&conn, &mut state, fact)?;
            write(&conn, &state)
        })
    }
    fn record_remote_confirmation(&self, fact: &PrivateSettlementFact) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let mut state = read(&conn)?.ok_or(StorageError::NotFound)?;
            if fact.signature_public_key == state.anchor.local_device {
                return Err(invalid());
            }
            insert_fact(&conn, &mut state, fact)?;
            write(&conn, &state)
        })
    }
    fn defer_remote_ack(&self, ack: &PrivateSettlementDeferredAck) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let mut state = read(&conn)?.ok_or(StorageError::NotFound)?;
            validate_fact(&state, &ack.fact)?;
            if state.phase != PrivateSettlementPhase::Pending
                || state.round_nonce.is_some()
                || ack.round_nonce == [0; 32]
                || ack.fact.signature_public_key == state.anchor.local_device
                || ack.fact.signature_public_key == state.anchor.coordinator
            {
                return Err(invalid());
            }
            // One bounded receipt per actual remote leaf. A conflicting claim
            // never replaces the first receipt or establishes coordinator nonce.
            if state
                .deferred_acks
                .iter()
                .any(|old| old.fact.leaf_index == ack.fact.leaf_index)
            {
                return Ok(());
            }
            state.deferred_acks.push(ack.clone());
            write(&conn, &state)
        })
    }
    fn clear_deferred_acks(&self, expected: u64) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let mut state = read(&conn)?.ok_or(StorageError::NotFound)?;
            if state.generation != expected
                || state.phase == PrivateSettlementPhase::Denied
                || state.round_nonce.is_none()
            {
                return Err(invalid());
            }
            state.deferred_acks.clear();
            write(&conn, &state)
        })
    }
    fn put_outbound(&self, expected: u64, bytes: &[u8]) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let mut state = read(&conn)?.ok_or(StorageError::NotFound)?;
            if state.generation != expected
                || state.phase == PrivateSettlementPhase::Denied
                || state.prepared_ciphertext.is_none()
                || bytes.is_empty()
                || bytes.len() > 32768
            {
                return Err(invalid());
            }
            if let Some(old) = &state.outbound {
                return if old == bytes { Ok(()) } else { Err(invalid()) };
            }
            state.outbound = Some(bytes.to_vec());
            write(&conn, &state)
        })
    }
    fn deny_round(&self, expected: u64) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let mut state = read(&conn)?.ok_or(StorageError::NotFound)?;
            if state.generation != expected {
                return Err(invalid());
            }
            state.phase = PrivateSettlementPhase::Denied;
            state.prepared_ciphertext = None;
            state.outbound = None;
            state.deferred_acks.clear();
            conn.execute("DELETE FROM private_roster_settlement_facts", [])
                .storage()?;
            write(&conn, &state)
        })
    }
    fn abandon_pending_on_startup(&self) -> StorageResult<bool> {
        self.with_transaction(|storage| {
            let state = {
                let conn = storage.lock()?;
                read(&conn)?
            };
            if let Some(state) = state
                && state.phase == PrivateSettlementPhase::Pending
            {
                storage.deny_round(state.generation)?;
                return Ok(true);
            }
            Ok(false)
        })
    }
    fn read_facts(&self) -> StorageResult<Vec<PrivateSettlementFact>> {
        let conn = self.lock()?;
        match read(&conn)? {
            Some(s) => facts(&conn, &s),
            None => Ok(vec![]),
        }
    }
}
#[cfg(test)]
mod tests;
