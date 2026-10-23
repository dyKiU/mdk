//! Synthetic bounded persistence tests, never Engine/MLS or SDK authority.
use super::*;
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::device_group_genesis::GenesisLeaf;
use cgka_traits::{EpochId, GroupId, MessageId};

fn deferred_anchor() -> PrivateSettlementAnchor {
    let mut value = anchor();
    value.successor.leaves.push(GenesisLeaf {
        account: value.account,
        leaf_index: 8,
        signature_public_key: [12; 32],
    });
    value
}

fn deferred_ack(generation: u64) -> PrivateSettlementDeferredAck {
    PrivateSettlementDeferredAck {
        fact: PrivateSettlementFact {
            format_version: 1,
            generation,
            leaf_index: 8,
            signature_public_key: [12; 32],
            message_id: MessageId::new(vec![13; 32]),
        },
        round_nonce: [7; 32],
    }
}

#[test]
fn private_settlement_deferred_ack_does_not_bind_nonce_or_count_confirmation() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let generation = storage.select_round(&deferred_anchor()).unwrap().generation;
    let ack = deferred_ack(generation);
    storage.defer_remote_ack(&ack).unwrap();
    storage.defer_remote_ack(&ack).unwrap();
    let round = storage.read_round().unwrap().unwrap();
    assert!(round.phase == PrivateSettlementPhase::Pending);
    assert!(round.round_nonce.is_none());
    assert!(round.coordinator_leaf_index.is_none());
    assert!(round.prepared_ciphertext.is_none());
    assert!(round.deferred_acks == vec![ack.clone()]);
    assert!(storage.read_facts().unwrap().is_empty());
    let mut conflict = ack.clone();
    conflict.round_nonce = [14; 32];
    storage.defer_remote_ack(&conflict).unwrap();
    conflict = ack.clone();
    conflict.fact.message_id = MessageId::new(vec![14; 32]);
    storage.defer_remote_ack(&conflict).unwrap();
    assert!(storage.read_round().unwrap().unwrap().deferred_acks == vec![ack]);
    assert!(storage.clear_deferred_acks(generation + 1).is_err());
    assert!(storage.clear_deferred_acks(generation).is_err());
    storage.bind_round_nonce(generation, [7; 32], 0).unwrap();
    storage.clear_deferred_acks(generation).unwrap();
    storage.clear_deferred_acks(generation).unwrap();
    assert!(
        storage
            .read_round()
            .unwrap()
            .unwrap()
            .deferred_acks
            .is_empty()
    );
    assert!(storage.read_facts().unwrap().is_empty());
}

#[test]
fn private_settlement_deferred_ack_rejects_wrong_generation_role_and_roster() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let generation = storage.select_round(&deferred_anchor()).unwrap().generation;
    let valid = deferred_ack(generation);
    let mut invalids = Vec::new();
    let mut ack = valid.clone();
    ack.fact.generation += 1;
    invalids.push(ack);
    let mut ack = valid.clone();
    ack.round_nonce = [0; 32];
    invalids.push(ack);
    let mut ack = valid.clone();
    ack.fact = fact(generation, true);
    invalids.push(ack);
    let mut ack = valid.clone();
    ack.fact = fact(generation, false);
    invalids.push(ack);
    let mut ack = valid.clone();
    ack.fact.leaf_index = 9;
    invalids.push(ack);
    let mut ack = valid.clone();
    ack.fact.signature_public_key = [15; 32];
    invalids.push(ack);
    let mut ack = valid.clone();
    ack.fact.message_id = MessageId::new(vec![13; 257]);
    invalids.push(ack);
    for ack in invalids {
        assert!(storage.defer_remote_ack(&ack).is_err());
    }
    assert!(
        storage
            .read_round()
            .unwrap()
            .unwrap()
            .deferred_acks
            .is_empty()
    );
    storage.defer_remote_ack(&valid).unwrap();
}

#[test]
fn private_settlement_deferred_ack_rollback_retirement_and_replacement() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let first = storage.select_round(&deferred_anchor()).unwrap().generation;
    let ack = deferred_ack(first);
    let rollback: StorageResult<()> = storage.with_transaction(|storage| {
        storage.defer_remote_ack(&ack)?;
        Err(StorageError::Serialization(
            "injected deferred receipt rollback".into(),
        ))
    });
    assert!(rollback.is_err());
    assert!(
        storage
            .read_round()
            .unwrap()
            .unwrap()
            .deferred_acks
            .is_empty()
    );
    storage.defer_remote_ack(&ack).unwrap();
    storage.bind_round_nonce(first, [7; 32], 0).unwrap();
    let rollback: StorageResult<()> = storage.with_transaction(|storage| {
        storage.clear_deferred_acks(first)?;
        Err(StorageError::Serialization(
            "injected deferred retirement rollback".into(),
        ))
    });
    assert!(rollback.is_err());
    assert!(storage.read_round().unwrap().unwrap().deferred_acks == vec![ack.clone()]);
    storage.deny_round(first).unwrap();
    assert!(
        storage
            .read_round()
            .unwrap()
            .unwrap()
            .deferred_acks
            .is_empty()
    );
    assert!(storage.defer_remote_ack(&ack).is_err());
    let second = storage.select_round(&deferred_anchor()).unwrap().generation;
    storage.defer_remote_ack(&deferred_ack(second)).unwrap();
    assert!(storage.abandon_pending_on_startup().unwrap());
    assert!(
        storage
            .read_round()
            .unwrap()
            .unwrap()
            .deferred_acks
            .is_empty()
    );
    let third = storage.select_round(&deferred_anchor()).unwrap().generation;
    storage.defer_remote_ack(&deferred_ack(third)).unwrap();
    let fourth = storage.select_round(&deferred_anchor()).unwrap().generation;
    assert!(fourth > third);
    assert!(
        storage
            .read_round()
            .unwrap()
            .unwrap()
            .deferred_acks
            .is_empty()
    );
    assert!(storage.defer_remote_ack(&deferred_ack(third)).is_err());
}

#[test]
fn private_settlement_legacy_json_without_deferred_ack_field_remains_readable() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let generation = selected(&storage);
    let state = storage.read_round().unwrap().unwrap();
    let mut legacy = serde_json::to_value(&state).unwrap();
    legacy.as_object_mut().unwrap().remove("deferred_acks");
    {
        let conn = storage.lock().unwrap();
        conn.execute(
            "UPDATE private_roster_settlement SET state=?1 WHERE singleton=1",
            [serde_json::to_vec(&legacy).unwrap()],
        )
        .unwrap();
    }
    let reopened = storage.read_round().unwrap().unwrap();
    assert!(reopened.deferred_acks.is_empty());
    assert_eq!(reopened.generation, generation);
    assert!(reopened.round_nonce == state.round_nonce);
    storage
        .record_remote_confirmation(&fact(generation, false))
        .unwrap();
    storage
        .record_local_confirmation(&fact(generation, true), b"legacy-compatible-cipher")
        .unwrap();
    assert!(storage.read_round().unwrap().unwrap().phase == PrivateSettlementPhase::Completed);
}

#[test]
fn private_settlement_deferred_ack_storage_is_bounded_by_actual_remote_slots() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut roster = deferred_anchor();
    for index in 9..134u32 {
        let mut signer = [0; 32];
        signer[..4].copy_from_slice(&index.to_be_bytes());
        roster.successor.leaves.push(GenesisLeaf {
            account: roster.account,
            leaf_index: index,
            signature_public_key: signer,
        });
    }
    assert_eq!(roster.successor.leaves.len(), 128);
    let generation = storage.select_round(&roster).unwrap().generation;
    for leaf in roster.successor.leaves.iter().filter(|leaf| {
        leaf.signature_public_key != roster.local_device
            && leaf.signature_public_key != roster.coordinator
    }) {
        storage
            .defer_remote_ack(&PrivateSettlementDeferredAck {
                fact: PrivateSettlementFact {
                    format_version: 1,
                    generation,
                    leaf_index: leaf.leaf_index,
                    signature_public_key: leaf.signature_public_key,
                    message_id: MessageId::new(leaf.leaf_index.to_be_bytes().to_vec()),
                },
                round_nonce: [7; 32],
            })
            .unwrap();
    }
    let state = storage.read_round().unwrap().unwrap();
    assert_eq!(state.deferred_acks.len(), 126);
    assert!(storage.read_facts().unwrap().is_empty());
    assert!(state.round_nonce.is_none());
    let mut corrupt = serde_json::to_value(&state).unwrap();
    let duplicates = vec![serde_json::to_value(&state.deferred_acks[0]).unwrap(); 129];
    corrupt["deferred_acks"] = serde_json::Value::Array(duplicates);
    {
        let conn = storage.lock().unwrap();
        conn.execute(
            "UPDATE private_roster_settlement SET state=?1 WHERE singleton=1",
            [serde_json::to_vec(&corrupt).unwrap()],
        )
        .unwrap();
    }
    assert!(storage.read_round().is_err());
}
fn anchor() -> PrivateSettlementAnchor {
    PrivateSettlementAnchor {
        origin: PrivateInviteOrigin::Accepted(1),
        account: [1; 32],
        local_device: [2; 32],
        group_id: GroupId::new(vec![8; 19]),
        successor: DeviceGroupAnchorRoster {
            epoch: EpochId(1),
            epoch_authenticator_digest: [9; 32],
            leaves: vec![
                GenesisLeaf {
                    account: [1; 32],
                    leaf_index: 0,
                    signature_public_key: [3; 32],
                },
                GenesisLeaf {
                    account: [1; 32],
                    leaf_index: 4,
                    signature_public_key: [2; 32],
                },
            ],
        },
        roster_commitment: [4; 32],
        enrollment_nonce: [5; 32],
        context_digest: [6; 32],
        coordinator: [3; 32],
    }
}
fn fact(generation: u64, local: bool) -> PrivateSettlementFact {
    PrivateSettlementFact {
        format_version: 1,
        generation,
        leaf_index: if local { 4 } else { 0 },
        signature_public_key: if local { [2; 32] } else { [3; 32] },
        message_id: MessageId::new(vec![if local { 10 } else { 11 }; 32]),
    }
}
fn selected(storage: &SqliteAccountStorage) -> u64 {
    let state = storage.select_round(&anchor()).unwrap();
    storage
        .bind_round_nonce(state.generation, [7; 32], 0)
        .unwrap();
    state.generation
}
fn complete(storage: &SqliteAccountStorage) -> u64 {
    let generation = selected(storage);
    storage
        .record_remote_confirmation(&fact(generation, false))
        .unwrap();
    storage
        .record_local_confirmation(&fact(generation, true), b"opaque-cipher")
        .unwrap();
    generation
}
#[test]
fn private_settlement_all_leaf_completion_and_exact_completed_retries() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let generation = selected(&storage);
    storage
        .record_remote_confirmation(&fact(generation, false))
        .unwrap();
    assert!(storage.read_round().unwrap().unwrap().phase == PrivateSettlementPhase::Pending);
    storage
        .record_local_confirmation(&fact(generation, true), b"opaque-cipher")
        .unwrap();
    assert!(storage.read_round().unwrap().unwrap().phase == PrivateSettlementPhase::Completed);
    storage
        .record_remote_confirmation(&fact(generation, false))
        .unwrap();
    storage
        .record_local_confirmation(&fact(generation, true), b"opaque-cipher")
        .unwrap();
    storage.bind_round_nonce(generation, [7; 32], 0).unwrap();
    storage.put_outbound(generation, b"exact-wrapped").unwrap();
    storage.put_outbound(generation, b"exact-wrapped").unwrap();
    assert!(storage.put_outbound(generation, b"substitute").is_err());
    assert!(
        storage
            .record_local_confirmation(&fact(generation, true), b"wrong-cipher")
            .is_err()
    );
    let mut wrong = fact(generation, false);
    wrong.message_id = MessageId::new(vec![12; 32]);
    assert!(storage.record_remote_confirmation(&wrong).is_err());
    assert_eq!(storage.read_facts().unwrap().len(), 2);
    let conn = storage.lock().unwrap();
    let evidence: i64 = conn
        .query_row("SELECT count(*) FROM cgka_messages", [], |r| r.get(0))
        .unwrap();
    assert_eq!(evidence, 0);
}
#[test]
fn private_settlement_nonce_role_and_generation_fences() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let g = storage.select_round(&anchor()).unwrap().generation;
    assert!(
        storage
            .record_local_confirmation(&fact(g, true), b"cipher")
            .is_err()
    );
    assert!(storage.bind_round_nonce(g, [0; 32], 0).is_err());
    assert!(storage.bind_round_nonce(g, [7; 32], 4).is_err());
    storage.bind_round_nonce(g, [7; 32], 0).unwrap();
    assert!(storage.bind_round_nonce(g, [8; 32], 0).is_err());
    assert!(storage.record_remote_confirmation(&fact(g, true)).is_err());
    assert!(
        storage
            .record_local_confirmation(&fact(g, false), b"cipher")
            .is_err()
    );
    assert!(
        storage
            .record_remote_confirmation(&fact(g + 1, false))
            .is_err()
    );
    let mut wrong = fact(g, false);
    wrong.signature_public_key = [5; 32];
    assert!(storage.record_remote_confirmation(&wrong).is_err());
    assert!(storage.read_facts().unwrap().is_empty());
}
#[test]
fn private_settlement_denial_blocks_all_positive_data_and_restart_preserves_completed() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let g = complete(&storage);
    assert!(!storage.abandon_pending_on_startup().unwrap());
    storage.deny_round(g).unwrap();
    storage.deny_round(g).unwrap();
    assert!(storage.read_round().unwrap().unwrap().phase == PrivateSettlementPhase::Denied);
    assert!(storage.read_facts().unwrap().is_empty());
    assert!(storage.record_remote_confirmation(&fact(g, false)).is_err());
    assert!(
        storage
            .record_local_confirmation(&fact(g, true), b"cipher")
            .is_err()
    );
    assert!(storage.bind_round_nonce(g, [7; 32], 0).is_err());
    assert!(storage.put_outbound(g, b"wrapped").is_err());
    assert!(storage.deny_round(g + 1).is_err());
    let newer = selected(&storage);
    assert!(newer > g);
    assert!(storage.abandon_pending_on_startup().unwrap());
    assert!(!storage.abandon_pending_on_startup().unwrap());
    assert!(storage.bind_round_nonce(g, [7; 32], 0).is_err());
}
#[test]
fn private_settlement_canonical_owner_and_origin_bounds() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut invalids = vec![];
    let mut a = anchor();
    a.origin = PrivateInviteOrigin::Genesis(1);
    invalids.push(a);
    let mut a = anchor();
    a.origin = PrivateInviteOrigin::Accepted(0);
    invalids.push(a);
    let mut a = anchor();
    a.successor.leaves.swap(0, 1);
    invalids.push(a);
    let mut a = anchor();
    a.successor.leaves[1].signature_public_key = [3; 32];
    invalids.push(a);
    let mut a = anchor();
    a.successor.leaves[1].account = [9; 32];
    invalids.push(a);
    let mut a = anchor();
    a.local_device = [9; 32];
    invalids.push(a);
    let mut a = anchor();
    a.coordinator = [9; 32];
    invalids.push(a);
    let mut a = anchor();
    a.group_id = GroupId::new(vec![]);
    invalids.push(a);
    let mut a = anchor();
    a.group_id = GroupId::new(vec![1; 256]);
    invalids.push(a);
    let mut a = anchor();
    a.enrollment_nonce = [0; 32];
    invalids.push(a);
    for a in invalids {
        assert!(storage.select_round(&a).is_err());
    }
    selected(&storage);
    let mut other = anchor();
    other.account = [9; 32];
    for l in &mut other.successor.leaves {
        l.account = other.account;
    }
    assert!(storage.select_round(&other).is_err());
    let mut other = anchor();
    other.local_device = [3; 32];
    assert!(storage.select_round(&other).is_err());
    let isolated = SqliteAccountStorage::in_memory().unwrap();
    isolated
        .app_storage()
        .ensure_account_projection_with_identity("other", &hex::encode([9; 32]))
        .unwrap();
    assert!(isolated.select_round(&anchor()).is_err());
}
#[test]
fn private_settlement_limits_and_checked_replacement_do_not_have_lifetime_cap() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    for _ in 0..140 {
        selected(&storage);
    }
    let state = storage.read_round().unwrap().unwrap();
    let g = state.generation;
    assert_eq!(g, 140);
    assert!(
        storage
            .record_local_confirmation(&fact(g, true), &vec![0; 16385])
            .is_err()
    );
    storage
        .record_local_confirmation(&fact(g, true), &vec![0; 16384])
        .unwrap();
    assert!(storage.put_outbound(g, &vec![0; 32769]).is_err());
    storage.put_outbound(g, &vec![0; 32768]).unwrap();
    let mut a = anchor();
    a.successor.leaves = (0..129u32)
        .map(|i| {
            let mut key = [0; 32];
            key[..4].copy_from_slice(&i.to_be_bytes());
            GenesisLeaf {
                account: a.account,
                leaf_index: i,
                signature_public_key: key,
            }
        })
        .collect();
    assert!(storage.select_round(&a).is_err());
    let counter_storage = SqliteAccountStorage::in_memory().unwrap();
    let mut exhausted = counter_storage.select_round(&anchor()).unwrap();
    exhausted.generation = i64::MAX as u64;
    let conn = counter_storage.lock().unwrap();
    conn.execute(
        "UPDATE private_roster_settlement SET generation=?1,state=?2",
        params![i64::MAX, serde_json::to_vec(&exhausted).unwrap()],
    )
    .unwrap();
    drop(conn);
    assert_eq!(
        counter_storage.read_round().unwrap().unwrap().generation,
        i64::MAX as u64
    );
    assert!(counter_storage.select_round(&anchor()).is_err());
}
#[test]
fn private_settlement_last_fact_write_failure_rolls_back_and_reopens_exact_retry() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("isolated.sqlite");
    let key = crate::SqlCipherKey::new("11".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let g = selected(&storage);
    storage
        .record_local_confirmation(&fact(g, true), b"cipher")
        .unwrap();
    storage.lock().unwrap().execute_batch("CREATE TEMP TRIGGER fail_completion BEFORE UPDATE ON private_roster_settlement BEGIN SELECT RAISE(ABORT,'injected settlement write fault'); END;").unwrap();
    assert!(matches!(
        storage.record_remote_confirmation(&fact(g, false)),
        Err(StorageError::Backend(_))
    ));
    assert_eq!(storage.read_facts().unwrap().len(), 1);
    assert!(storage.read_round().unwrap().unwrap().phase == PrivateSettlementPhase::Pending);
    drop(storage);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    storage.record_remote_confirmation(&fact(g, false)).unwrap();
    assert!(storage.read_round().unwrap().unwrap().phase == PrivateSettlementPhase::Completed);
    assert!(!storage.abandon_pending_on_startup().unwrap());
    drop(storage);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(storage.read_round().unwrap().unwrap().phase == PrivateSettlementPhase::Completed);
    assert_eq!(storage.read_facts().unwrap().len(), 2);
}
#[test]
fn private_settlement_outer_crypto_unit_rollback_and_replacement_are_atomic() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let g = selected(&storage);
    storage.record_remote_confirmation(&fact(g, false)).unwrap();
    let result: StorageResult<()> = storage.with_transaction(|s| {
        s.record_local_confirmation(&fact(g, true), b"cipher")?;
        Err(StorageError::Backend("injected outer rollback".into()))
    });
    assert!(result.is_err());
    assert_eq!(storage.read_facts().unwrap().len(), 1);
    assert!(
        storage
            .read_round()
            .unwrap()
            .unwrap()
            .prepared_ciphertext
            .is_none()
    );
    let result: StorageResult<()> = storage.with_transaction(|s| {
        s.select_round(&anchor())?;
        Err(StorageError::Backend("injected outer rollback".into()))
    });
    assert!(result.is_err());
    assert_eq!(storage.read_round().unwrap().unwrap().generation, g);
    assert_eq!(storage.read_facts().unwrap().len(), 1);
}
#[test]
fn private_settlement_encrypted_pending_restart_denial_survives_reopen() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("isolated.sqlite");
    let k = crate::SqlCipherKey::new("22".repeat(32)).unwrap();
    let s = SqliteAccountStorage::open_encrypted(&p, &k).unwrap();
    let g = selected(&s);
    s.record_remote_confirmation(&fact(g, false)).unwrap();
    drop(s);
    let s = SqliteAccountStorage::open_encrypted(&p, &k).unwrap();
    assert!(s.abandon_pending_on_startup().unwrap());
    drop(s);
    let s = SqliteAccountStorage::open_encrypted(&p, &k).unwrap();
    assert!(s.read_round().unwrap().unwrap().phase == PrivateSettlementPhase::Denied);
    assert!(
        s.record_local_confirmation(&fact(g, true), b"cipher")
            .is_err()
    );
    assert!(s.read_facts().unwrap().is_empty());
}
#[test]
fn private_settlement_all_128_occupied_slots_complete_without_account_deduplication() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut a = anchor();
    for index in 5..131u32 {
        let mut signer = [0; 32];
        signer[..4].copy_from_slice(&index.to_be_bytes());
        a.successor.leaves.push(GenesisLeaf {
            account: a.account,
            leaf_index: index,
            signature_public_key: signer,
        });
    }
    assert_eq!(a.successor.leaves.len(), 128);
    let g = storage.select_round(&a).unwrap().generation;
    storage.bind_round_nonce(g, [7; 32], 0).unwrap();
    storage
        .record_local_confirmation(&fact(g, true), b"cipher")
        .unwrap();
    for leaf in a
        .successor
        .leaves
        .iter()
        .filter(|l| l.signature_public_key != a.local_device)
    {
        storage
            .record_remote_confirmation(&PrivateSettlementFact {
                format_version: 1,
                generation: g,
                leaf_index: leaf.leaf_index,
                signature_public_key: leaf.signature_public_key,
                message_id: MessageId::new(leaf.leaf_index.to_be_bytes().to_vec()),
            })
            .unwrap();
    }
    assert_eq!(storage.read_facts().unwrap().len(), 128);
    assert!(storage.read_round().unwrap().unwrap().phase == PrivateSettlementPhase::Completed);
}

// Synthetic SQL consistency only; no Engine/MLS or SDK authority is constructed.
#[derive(Clone, Copy)]
enum ForeignSettlementRead {
    Round,
    Facts,
}

enum ForeignSettlementView {
    Round(Box<PrivateSettlementState>),
    Facts(Vec<PrivateSettlementFact>),
}

struct ForeignSettlementTraceGate {
    target_facts_statement: usize,
    seen_facts_statements: usize,
    reached: std::sync::mpsc::SyncSender<()>,
    resume: std::sync::mpsc::Receiver<()>,
    writer_committed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    callback_completed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

std::thread_local! {
    static FOREIGN_SETTLEMENT_TRACE_GATE: std::cell::RefCell<Option<ForeignSettlementTraceGate>> =
        const { std::cell::RefCell::new(None) };
}

fn pause_foreign_settlement_facts(event: rusqlite::trace::TraceEvent<'_>) {
    let rusqlite::trace::TraceEvent::Stmt(statement, _) = event else {
        return;
    };
    if statement.sql()
        != "SELECT leaf_index,record FROM private_roster_settlement_facts ORDER BY leaf_index LIMIT 129"
    {
        return;
    }
    FOREIGN_SETTLEMENT_TRACE_GATE.with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else {
            return;
        };
        let Some(gate) = slot.as_mut() else {
            return;
        };
        gate.seen_facts_statements += 1;
        if gate.seen_facts_statements != gate.target_facts_statement {
            return;
        }
        // Only bounded channels here: never call SQLite or print SQL/values from its callback.
        let signalled = gate.reached.send(()).is_ok();
        let resumed = gate
            .resume
            .recv_timeout(std::time::Duration::from_secs(10))
            .is_ok();
        gate.callback_completed.store(
            signalled
                && resumed
                && gate
                    .writer_committed
                    .load(std::sync::atomic::Ordering::Acquire),
            std::sync::atomic::Ordering::Release,
        );
    });
}

fn exercise_foreign_settlement_snapshot(mode: ForeignSettlementRead) {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::Duration;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("foreign-settlement-snapshot.sqlite");
    let key = crate::SqlCipherKey::new("63".repeat(32)).unwrap();
    let writer = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let reader = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(!reader.shares_connection_with(&writer));
    let journal: String = reader
        .lock()
        .unwrap()
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert!(journal.eq_ignore_ascii_case("wal"));
    let old_generation = complete(&writer);
    let old_state = writer.read_round().unwrap().unwrap();
    let old_facts = writer.read_facts().unwrap();
    assert!(old_state.phase == PrivateSettlementPhase::Completed && old_facts.len() == 2);
    let (reached_tx, reached_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let writer_committed = Arc::new(AtomicBool::new(false));
    let callback_completed = Arc::new(AtomicBool::new(false));
    let callback_copy = callback_completed.clone();
    let writer_copy = writer_committed.clone();
    let target = match mode {
        ForeignSettlementRead::Round => 1,
        ForeignSettlementRead::Facts => 2,
    };
    let reader_thread = std::thread::spawn(move || {
        FOREIGN_SETTLEMENT_TRACE_GATE.with(|slot| {
            *slot.borrow_mut() = Some(ForeignSettlementTraceGate {
                target_facts_statement: target,
                seen_facts_statements: 0,
                reached: reached_tx,
                resume: resume_rx,
                writer_committed: writer_copy,
                callback_completed: callback_copy,
            });
        });
        reader.lock().unwrap().trace_v2(
            rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
            Some(pause_foreign_settlement_facts),
        );
        let result = match mode {
            ForeignSettlementRead::Round => reader.read_round().and_then(|value| {
                value
                    .map(|state| ForeignSettlementView::Round(Box::new(state)))
                    .ok_or(StorageError::NotFound)
            }),
            ForeignSettlementRead::Facts => reader.read_facts().map(ForeignSettlementView::Facts),
        };
        reader
            .lock()
            .unwrap()
            .trace_v2(rusqlite::trace::TraceEventCodes::empty(), None);
        let seen = FOREIGN_SETTLEMENT_TRACE_GATE.with(|slot| {
            slot.borrow_mut()
                .take()
                .map_or(0, |gate| gate.seen_facts_statements)
        });
        (result, seen, reader)
    });
    let boundary_seen = reached_rx.recv_timeout(Duration::from_secs(10)).is_ok();
    let replacement = if boundary_seen {
        writer.select_round(&anchor())
    } else {
        Err(StorageError::NotFound)
    };
    let committed = replacement.as_ref().is_ok_and(|state| {
        state.generation == old_generation + 1 && state.phase == PrivateSettlementPhase::Pending
    });
    writer_committed.store(committed, Ordering::Release);
    let release_sent = resume_tx.send(()).is_ok();
    let (result, observed_statements, reader) = reader_thread.join().unwrap();
    let callback_ok = callback_completed.load(Ordering::Acquire);
    assert!(
        boundary_seen && committed && release_sent && callback_ok && observed_statements == target,
        "actual independent WAL commit must occur inside the selected public read boundary"
    );
    let mut typed_serialization = false;
    let mut returned_facts = false;
    let coherent = match result {
        Ok(ForeignSettlementView::Round(state)) => *state == old_state,
        Ok(ForeignSettlementView::Facts(facts)) => {
            returned_facts = true;
            facts == old_facts
        }
        Err(StorageError::Serialization(detail)) => {
            typed_serialization = detail == "invalid private settlement facts";
            false
        }
        Err(_) => false,
    };
    // A new independent observation must see the committed replacement, not the pinned old view.
    let fresh = reader.read_round().unwrap().unwrap();
    let fresh_facts = reader.read_facts().unwrap();
    let fresh_new_view = fresh.generation == old_generation + 1
        && fresh.phase == PrivateSettlementPhase::Pending
        && fresh_facts.is_empty();
    assert!(
        fresh_new_view,
        "fresh public reads must see the actual committed replacement"
    );
    let mode_name = match mode {
        ForeignSettlementRead::Round => "round",
        ForeignSettlementRead::Facts => "facts",
    };
    eprintln!(
        "private_settlement_read_snapshot mode={mode_name} boundary_seen={boundary_seen} writer_committed={committed} callback_completed={callback_ok} independent_handles=true observed_statements={observed_statements} coherent_old_view={coherent} fresh_new_view={fresh_new_view} typed_serialization={typed_serialization} returned_facts={returned_facts}"
    );
    match mode {
        ForeignSettlementRead::Round => assert!(
            coherent,
            "public settlement round snapshot must preserve coherent committed state and facts"
        ),
        ForeignSettlementRead::Facts => assert!(
            coherent,
            "public settlement facts snapshot must preserve coherent committed state and facts"
        ),
    }
    reader.close().unwrap();
    writer.close().unwrap();
}

#[test]
fn private_settlement_read_round_pins_foreign_wal_replacement() {
    exercise_foreign_settlement_snapshot(ForeignSettlementRead::Round);
}

#[test]
fn private_settlement_read_facts_pins_foreign_wal_replacement() {
    exercise_foreign_settlement_snapshot(ForeignSettlementRead::Facts);
}

#[test]
fn private_settlement_snapshot_reads_reject_persisted_foreign_generation_fact() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let generation = complete(&storage);
    let mut corrupt = fact(generation, false);
    corrupt.generation += 1;
    storage
        .lock()
        .unwrap()
        .execute(
            "UPDATE private_roster_settlement_facts SET record=?1 WHERE leaf_index=?2",
            rusqlite::params![
                serde_json::to_vec(&corrupt).unwrap(),
                i64::from(corrupt.leaf_index)
            ],
        )
        .unwrap();
    let round_rejected = matches!(storage.read_round(),
        Err(StorageError::Serialization(detail)) if detail == "invalid private settlement facts");
    let facts_rejected = matches!(storage.read_facts(),
        Err(StorageError::Serialization(detail)) if detail == "invalid private settlement facts");
    assert!(
        round_rejected && facts_rejected,
        "consistent snapshots must not accept persisted foreign-generation facts"
    );
}
