//! Synthetic bounded persistence tests, never Engine/MLS or SDK authority.
use super::*;
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::device_group_genesis::GenesisLeaf;
use cgka_traits::{EpochId, GroupId, MessageId};
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
