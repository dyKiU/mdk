//! Locally selected bounded facts. Callers cannot derive permissions from them.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::roster_ack_capture::{
    RosterAckCaptureFact, RosterAckCaptureState, RosterAckCaptureStorage,
};
use cgka_traits::storage::{StorageError, StorageProvider, StorageResult};
use rusqlite::{OptionalExtension, params};
use std::collections::HashSet;
const SELECT: &str = "SELECT generation,state,group_id FROM roster_ack_capture WHERE singleton=1";
const UPDATE: &str = "UPDATE roster_ack_capture SET state=?1 WHERE singleton=1 AND generation=?2";
fn invalid() -> StorageError {
    StorageError::Serialization("invalid roster capture scope".into())
}
fn generation(value: u64) -> StorageResult<i64> {
    i64::try_from(value)
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(invalid)
}
fn encode<T: serde::Serialize>(value: &T, limit: usize) -> StorageResult<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    if bytes.len() > limit {
        return Err(invalid());
    }
    Ok(bytes)
}
fn validate(state: &RosterAckCaptureState) -> StorageResult<()> {
    generation(state.generation)?;
    if state.format_version != 1
        || state
            .prepared_ciphertext
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 16384)
        || (state.prepared_ciphertext.is_some() && state.round_nonce.is_none())
        || state.account.as_slice().len() != 32
        || state.local_device.len() != 32
        || state.group_id.as_slice().is_empty()
        || state.group_id.as_slice().len() > 255
        || state.leaves.is_empty()
        || state.leaves.len() > 128
        || state.round_nonce == Some([0; 32])
        || state
            .outbound
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 32768)
    {
        return Err(invalid());
    }
    let mut indices = HashSet::new();
    let mut keys = HashSet::new();
    for leaf in &state.leaves {
        if leaf.signature_public_key.len() != 32
            || !indices.insert(leaf.leaf_index)
            || !keys.insert(leaf.signature_public_key.clone())
        {
            return Err(invalid());
        }
    }
    if !keys.contains(&state.local_device)
        || state
            .challenge_source
            .is_some_and(|v| !indices.contains(&v))
        || (state.challenge_source.is_some() && state.round_nonce.is_none())
    {
        return Err(invalid());
    }
    Ok(())
}
fn read(conn: &rusqlite::Connection) -> StorageResult<Option<RosterAckCaptureState>> {
    let row: Option<(i64, Vec<u8>, Vec<u8>)> = conn
        .query_row(SELECT, [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .optional()
        .storage()?;
    row.map(|(expected_generation, bytes, group_id)| {
        let state: RosterAckCaptureState = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        validate(&state)?;
        if generation(state.generation)? != expected_generation
            || state.group_id.as_slice() != group_id
        {
            return Err(invalid());
        }
        Ok(state)
    })
    .transpose()
}
fn update(conn: &rusqlite::Connection, state: &RosterAckCaptureState) -> StorageResult<()> {
    validate(state)?;
    let bytes = encode(state, 65536)?;
    if conn
        .execute(UPDATE, params![bytes, generation(state.generation)?])
        .storage()?
        != 1
    {
        return Err(StorageError::NotFound);
    }
    Ok(())
}
impl RosterAckCaptureStorage for SqliteAccountStorage {
    fn capture_state(&self) -> StorageResult<Option<RosterAckCaptureState>> {
        {
            let conn = self.lock()?;
            read(&conn)
        }
    }
    fn select_capture(
        &self,
        input: &RosterAckCaptureState,
    ) -> StorageResult<RosterAckCaptureState> {
        if input.invalidated {
            return Err(invalid());
        }
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let old = read(&conn)?;
            if old.as_ref().is_some_and(|old| old.account != input.account || old.local_device != input.local_device) {
                return Err(invalid());
            }
            let projected: i64 = conn.query_row(
                "SELECT count(*) FROM account_state", [], |row| row.get(0),
            ).storage()?;
            if projected != 0 {
                let matches: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM account_state WHERE local_account_id_hex=?1)",
                    params![hex::encode(input.account.as_slice())], |row| row.get(0),
                ).storage()?;
                if !matches { return Err(invalid()); }
            }
            let mut state = input.clone();
            state.generation = old.map_or(Some(1), |old| old.generation.checked_add(1)).ok_or_else(invalid)?;
            validate(&state)?;
            let bytes = encode(&state, 65536)?;
            conn.execute("DELETE FROM roster_ack_capture_facts", []).storage()?;
            const REPLACE_SCOPE: &str = "INSERT INTO roster_ack_capture(singleton,generation,group_id,state) VALUES(1,?1,?2,?3) ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation,group_id=excluded.group_id,state=excluded.state";
            conn.execute(REPLACE_SCOPE, params![generation(state.generation)?, state.group_id.as_slice(), bytes]).storage()?;
            Ok(state)
        })
    }
    fn invalidate_capture(&self, expected_generation: u64) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let mut state = read(&conn)?.ok_or(StorageError::NotFound)?;
            if state.generation != expected_generation {
                return Err(invalid());
            }
            if state.invalidated {
                return Ok(());
            }
            state.invalidated = true;
            state.prepared_ciphertext = None;
            state.outbound = None;
            update(&conn, &state)?;
            conn.execute("DELETE FROM roster_ack_capture_facts", [])
                .storage()?;
            Ok(())
        })
    }
    fn accept_capture_challenge(
        &self,
        expected_generation: u64,
        nonce: [u8; 32],
        source: u32,
    ) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let mut state = read(&conn)?.ok_or(StorageError::NotFound)?;
            if state.invalidated
                || state.generation != expected_generation
                || nonce == [0; 32]
                || !state.leaves.iter().any(|v| v.leaf_index == source)
            {
                return Err(invalid());
            }
            if state.round_nonce.is_some() {
                if state.round_nonce == Some(nonce) && state.challenge_source == Some(source) {
                    return Ok(());
                }
                return Err(StorageError::AlreadyExists);
            }
            state.round_nonce = Some(nonce);
            state.challenge_source = Some(source);
            update(&conn, &state)
        })
    }
    fn put_prepared_capture_ciphertext(
        &self,
        expected_generation: u64,
        bytes: &[u8],
    ) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let mut state = read(&conn)?.ok_or(StorageError::NotFound)?;
            if state.invalidated
                || state.generation != expected_generation
                || state.round_nonce.is_none()
                || state.outbound.is_some()
                || bytes.is_empty()
                || bytes.len() > 16384
            {
                return Err(invalid());
            }
            if let Some(old) = &state.prepared_ciphertext {
                return if old == bytes {
                    Ok(())
                } else {
                    Err(StorageError::AlreadyExists)
                };
            }
            state.prepared_ciphertext = Some(bytes.to_vec());
            update(&conn, &state)
        })
    }
    fn put_capture_outbound(&self, expected_generation: u64, bytes: &[u8]) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let mut state = read(&conn)?.ok_or(StorageError::NotFound)?;
            if state.invalidated
                || state.generation != expected_generation
                || bytes.is_empty()
                || bytes.len() > 32768
                || state.round_nonce.is_none()
            {
                return Err(invalid());
            }
            if let Some(old) = &state.outbound {
                if old == bytes {
                    return Ok(());
                }
                return Err(StorageError::AlreadyExists);
            }
            state.outbound = Some(bytes.to_vec());
            state.prepared_ciphertext = None;
            update(&conn, &state)
        })
    }
    fn put_capture_fact(&self, fact: &RosterAckCaptureFact) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let state = read(&conn)?.ok_or(StorageError::NotFound)?;
            if state.invalidated
                || fact.format_version != 1
                || state.generation != fact.generation
                || state.round_nonce.is_none()
                || fact.message_id.as_slice().is_empty()
                || fact.message_id.as_slice().len() > 256
                || !state.leaves.iter().any(|v| {
                    v.leaf_index == fact.leaf_index
                        && v.signature_public_key == fact.signature_public_key
                })
            {
                return Err(invalid());
            }
            let bytes = encode(fact, 4096)?;
            let old: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT record FROM roster_ack_capture_facts WHERE leaf_index=?1",
                    params![i64::from(fact.leaf_index)],
                    |row| row.get(0),
                )
                .optional()
                .storage()?;
            if let Some(old) = old {
                let prior: RosterAckCaptureFact =
                    serde_json::from_slice(&old).map_err(|_| invalid())?;
                if prior.generation == fact.generation
                    && prior.signature_public_key == fact.signature_public_key
                {
                    return Ok(());
                }
                return Err(invalid());
            }
            conn.execute(
                "INSERT INTO roster_ack_capture_facts(leaf_index,record) VALUES(?1,?2)",
                params![i64::from(fact.leaf_index), bytes],
            )
            .storage()?;
            Ok(())
        })
    }
    fn capture_facts(&self) -> StorageResult<Vec<RosterAckCaptureFact>> {
        let conn = self.lock()?;
        let Some(state) = read(&conn)? else {
            return Ok(vec![]);
        };
        let mut query = conn
            .prepare("SELECT record FROM roster_ack_capture_facts ORDER BY leaf_index LIMIT 129")
            .storage()?;
        let rows = query
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .storage()?;
        let mut facts = Vec::new();
        for row in rows {
            let fact: RosterAckCaptureFact =
                serde_json::from_slice(&row.storage()?).map_err(|_| invalid())?;
            if fact.format_version != 1
                || fact.generation != state.generation
                || !state.leaves.iter().any(|v| {
                    v.leaf_index == fact.leaf_index
                        && v.signature_public_key == fact.signature_public_key
                })
            {
                return Err(invalid());
            }
            facts.push(fact);
        }
        if facts.len() > 128 {
            return Err(invalid());
        }
        Ok(facts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::roster_ack_capture::RosterAckCaptureLeaf;
    use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
    fn scope() -> RosterAckCaptureState {
        RosterAckCaptureState {
            format_version: 1,
            generation: 1,
            invalidated: false,
            account: MemberId::new(vec![1; 32]),
            local_device: vec![2; 32],
            group_id: GroupId::new(vec![3, 4, 5]),
            epoch: EpochId(6),
            epoch_authenticator_digest: [7; 32],
            roster_commitment: [8; 32],
            leaves: (0..128u32)
                .map(|index| RosterAckCaptureLeaf {
                    leaf_index: index * 2,
                    signature_public_key: vec![(index + 1) as u8; 32],
                })
                .collect(),
            round_nonce: Some([9; 32]),
            challenge_source: None,
            outbound: None,
            prepared_ciphertext: None,
        }
    }
    #[test]
    fn roster_ack_capture_is_bounded_idempotent_and_has_no_lifetime_attempt_cap() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let selected = storage.select_capture(&scope()).unwrap();
        for leaf in &selected.leaves {
            let fact = RosterAckCaptureFact {
                format_version: 1,
                generation: selected.generation,
                leaf_index: leaf.leaf_index,
                signature_public_key: leaf.signature_public_key.clone(),
                message_id: MessageId::new(vec![10]),
            };
            storage.put_capture_fact(&fact).unwrap();
            storage.put_capture_fact(&fact).unwrap();
        }
        assert_eq!(storage.capture_facts().unwrap().len(), 128);
        let mut wrong = scope();
        wrong.account = MemberId::new(vec![11; 32]);
        assert!(storage.select_capture(&wrong).is_err());
        let mut oversize = scope();
        oversize.leaves.push(RosterAckCaptureLeaf {
            leaf_index: 300,
            signature_public_key: vec![200; 32],
        });
        assert!(storage.select_capture(&oversize).is_err());
        assert_eq!(storage.capture_facts().unwrap().len(), 128);
        for _ in 0..300 {
            storage.select_capture(&scope()).unwrap();
        }
        assert_eq!(storage.capture_state().unwrap().unwrap().generation, 301);
        assert!(storage.capture_facts().unwrap().is_empty());
        let conn = storage.lock().unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM roster_ack_capture", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn roster_ack_capture_scope_replacement_rollback_keeps_old_round_facts() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let selected = storage.select_capture(&scope()).unwrap();
        let leaf = &selected.leaves[0];
        storage
            .put_capture_fact(&RosterAckCaptureFact {
                format_version: 1,
                generation: selected.generation,
                leaf_index: leaf.leaf_index,
                signature_public_key: leaf.signature_public_key.clone(),
                message_id: MessageId::new(vec![10]),
            })
            .unwrap();
        storage.lock().unwrap().execute_batch("CREATE TRIGGER reject_scope_replace BEFORE UPDATE ON roster_ack_capture BEGIN SELECT RAISE(ABORT,'injected scope failure'); END;").unwrap();
        assert!(storage.select_capture(&scope()).is_err());
        assert_eq!(
            storage.capture_state().unwrap().unwrap().generation,
            selected.generation
        );
        assert_eq!(storage.capture_facts().unwrap().len(), 1);
    }

    #[test]
    fn roster_ack_capture_invalidation_refuses_all_old_round_writes() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let selected = storage.select_capture(&scope()).unwrap();
        let fact = RosterAckCaptureFact {
            format_version: 1,
            generation: selected.generation,
            leaf_index: selected.leaves[0].leaf_index,
            signature_public_key: selected.leaves[0].signature_public_key.clone(),
            message_id: MessageId::new(vec![10]),
        };
        storage.put_capture_fact(&fact).unwrap();
        storage.invalidate_capture(selected.generation).unwrap();
        assert!(storage.capture_facts().unwrap().is_empty());
        assert!(storage.put_capture_fact(&fact).is_err());
        assert!(
            storage
                .accept_capture_challenge(selected.generation, [9; 32], fact.leaf_index)
                .is_err()
        );
        assert!(
            storage
                .put_prepared_capture_ciphertext(selected.generation, &[1])
                .is_err()
        );
        assert!(
            storage
                .put_capture_outbound(selected.generation, &[1])
                .is_err()
        );
        assert!(storage.capture_facts().unwrap().is_empty());
        storage.close().unwrap();
    }
}
