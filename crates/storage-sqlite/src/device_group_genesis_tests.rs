//! Storage capability regression; synthetic fixtures only.
use crate::SqliteAccountStorage;
use cgka_traits::storage::StorageProvider;
#[test]
fn private_device_group_genesis_storage_capability_is_available() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    assert!(storage.device_group_genesis_storage().is_some());
}

use cgka_traits::device_group_genesis::{GenesisBirthDraft, GenesisError, GenesisLeaf};
use cgka_traits::types::{EpochId, GroupId};
fn birth(group: Vec<u8>) -> GenesisBirthDraft {
    GenesisBirthDraft {
        format_version: 1,
        group_id: GroupId::new(group),
        epoch: EpochId(0),
        epoch_authenticator_digest: [4; 32],
        leaves: vec![GenesisLeaf {
            leaf_index: 0,
            account: [1; 32],
            signature_public_key: [2; 32],
        }],
        roster_commitment: [5; 32],
    }
}
#[test]
fn private_device_group_genesis_denial_retains_birth_and_fences_old_generations() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let cap = storage.device_group_genesis_storage().unwrap();
    let first = cap
        .store_genesis_birth(&[1; 32], &[2; 32], &birth(vec![7; 19]))
        .unwrap();
    assert!(matches!(
        cap.store_genesis_birth(&[1; 32], &[2; 32], &birth(vec![8; 23])),
        Err(GenesisError::SelectionBusy)
    ));
    let mut wrong_scope = first.fact.scope.clone();
    wrong_scope.selection_generation += 1;
    assert!(matches!(
        cap.deny_genesis_selection(&wrong_scope, &first.fact.birth.group_id),
        Err(GenesisError::ScopeMismatch)
    ));
    assert!(matches!(
        cap.deny_genesis_selection(&first.fact.scope, &GroupId::new(vec![9])),
        Err(GenesisError::ScopeMismatch)
    ));
    cap.deny_genesis_selection(&first.fact.scope, &first.fact.birth.group_id)
        .unwrap();
    cap.deny_genesis_selection(&first.fact.scope, &first.fact.birth.group_id)
        .unwrap();
    let denied = cap.genesis_selection().unwrap().unwrap();
    assert!(denied.active_denied && denied.fact == first.fact);
    assert!(matches!(
        cap.store_genesis_birth(&[1; 32], &[2; 32], &first.fact.birth),
        Err(GenesisError::InvalidFact)
    ));
    let next = cap
        .store_genesis_birth(&[1; 32], &[2; 32], &birth(vec![8; 255]))
        .unwrap();
    assert_eq!(next.fact.scope.selection_generation, 2);
    assert!(!next.active_denied);
    assert!(matches!(
        cap.deny_genesis_selection(&first.fact.scope, &first.fact.birth.group_id),
        Err(GenesisError::ScopeMismatch)
    ));
    assert!(cap.genesis_selection().unwrap().unwrap().fact == next.fact);
}
#[test]
fn private_device_group_genesis_scope_and_projection_identity_are_immutable() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    storage
        .ensure_account_projection_with_identity("synthetic-genesis", &hex::encode([1; 32]))
        .unwrap();
    let cap = storage.device_group_genesis_storage().unwrap();
    let first = cap
        .store_genesis_birth(&[1; 32], &[2; 32], &birth(vec![7]))
        .unwrap();
    cap.deny_genesis_selection(&first.fact.scope, &first.fact.birth.group_id)
        .unwrap();
    for change_account in [true, false] {
        let account = if change_account { [3; 32] } else { [1; 32] };
        let device = if change_account { [2; 32] } else { [3; 32] };
        let mut draft = birth(vec![8]);
        draft.leaves[0].account = account;
        draft.leaves[0].signature_public_key = device;
        assert!(matches!(
            cap.store_genesis_birth(&account, &device, &draft),
            Err(GenesisError::ScopeMismatch)
        ));
    }
    assert!(cap.genesis_selection().unwrap().unwrap().fact == first.fact);
}
#[test]
fn private_device_group_genesis_invalid_births_never_allocate_selection() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let cap = storage.device_group_genesis_storage().unwrap();
    let mut cases = vec![birth(vec![]), birth(vec![7; 256])];
    let mut wrong = birth(vec![7]);
    wrong.epoch = EpochId(1);
    cases.push(wrong);
    let mut wrong = birth(vec![7]);
    wrong.leaves[0].leaf_index = 1;
    cases.push(wrong);
    let mut wrong = birth(vec![7]);
    wrong.leaves[0].account = [3; 32];
    cases.push(wrong);
    let mut wrong = birth(vec![7]);
    wrong.leaves.clear();
    cases.push(wrong);
    let mut wrong = birth(vec![7]);
    wrong.leaves.push(wrong.leaves[0].clone());
    cases.push(wrong);
    for draft in cases {
        assert!(matches!(
            cap.store_genesis_birth(&[1; 32], &[2; 32], &draft),
            Err(GenesisError::InvalidFact)
        ));
        assert!(cap.genesis_selection().unwrap().is_none());
    }
}
#[test]
fn private_device_group_genesis_outer_rollback_preserves_counter_and_admission() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let result: Result<(), GenesisError> = storage.with_transaction(|backend| {
        backend
            .device_group_genesis_storage()
            .unwrap()
            .store_genesis_birth(&[1; 32], &[2; 32], &birth(vec![7]))?;
        Err(GenesisError::InvalidFact)
    });
    assert!(result.is_err());
    let cap = storage.device_group_genesis_storage().unwrap();
    assert!(cap.genesis_selection().unwrap().is_none());
    assert_eq!(
        cap.store_genesis_birth(&[1; 32], &[2; 32], &birth(vec![8]))
            .unwrap()
            .fact
            .scope
            .selection_generation,
        1
    );
}
#[test]
fn private_device_group_genesis_monotonic_selection_is_bounded_without_lifetime_cap() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let cap = storage.device_group_genesis_storage().unwrap();
    for count in 1u64..=300 {
        let selected = cap
            .store_genesis_birth(&[1; 32], &[2; 32], &birth(count.to_be_bytes().to_vec()))
            .unwrap();
        assert_eq!(selected.fact.scope.selection_generation, count);
        cap.deny_genesis_selection(&selected.fact.scope, &selected.fact.birth.group_id)
            .unwrap();
    }
    let connection = storage.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM device_group_genesis_selection",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    connection
        .execute(
            "UPDATE device_group_genesis_selection SET generation=?1",
            [i64::MAX],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        cap.store_genesis_birth(&[1; 32], &[2; 32], &birth(vec![9])),
        Err(GenesisError::GenerationExhausted)
    ));
}
