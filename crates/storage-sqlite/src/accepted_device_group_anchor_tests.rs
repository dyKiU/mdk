//! Fact-store contracts with synthetic data, never verifier permission.
use crate::SqliteAccountStorage;
use cgka_traits::accepted_device_group_anchor::*;
use cgka_traits::device_group_genesis::GenesisLeaf;
use cgka_traits::device_linking_key_package::PurposeAttemptScope;
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::{EpochId, GroupId};
fn draft(generation: u64, group: u8) -> AcceptedDeviceGroupAnchorDraft {
    let approver = GenesisLeaf {
        leaf_index: 0,
        account: [1; 32],
        signature_public_key: [3; 32],
    };
    let recipient = GenesisLeaf {
        leaf_index: 4,
        account: [1; 32],
        signature_public_key: [2; 32],
    };
    AcceptedDeviceGroupAnchorDraft {
        format_version: 1,
        purpose: PurposeAttemptScope {
            account: [1; 32],
            local_device: [2; 32],
            generation,
        },
        group_id: GroupId::new(vec![group; 19]),
        nonce: [4; 32],
        context_digest: [5; 32],
        key_package_reference: [6; 32],
        welcome_digest: [7; 32],
        approver: [3; 32],
        recipient: [2; 32],
        predecessor: DeviceGroupAnchorRoster {
            epoch: EpochId(1),
            epoch_authenticator_digest: [8; 32],
            leaves: vec![approver.clone()],
        },
        successor: DeviceGroupAnchorRoster {
            epoch: EpochId(2),
            epoch_authenticator_digest: [9; 32],
            leaves: vec![approver, recipient],
        },
    }
}
#[test]
fn accepted_device_group_anchor_exact_retry_and_denial_never_restore_an_old_selection() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let cap = storage.accepted_device_group_anchor_storage().unwrap();
    let original = draft(1, 10);
    let first = cap.install_accepted_anchor(&original).unwrap();
    assert!(cap.install_accepted_anchor(&original).unwrap() == first);
    assert!(matches!(
        cap.install_accepted_anchor(&draft(2, 11)),
        Err(AnchorError::SelectionBusy)
    ));
    let mut wrong = first.scope.clone();
    wrong.selection_generation += 1;
    assert!(matches!(
        cap.deny_accepted_anchor(&wrong, &original.group_id),
        Err(AnchorError::ScopeMismatch)
    ));
    cap.deny_accepted_anchor(&first.scope, &original.group_id)
        .unwrap();
    assert!(matches!(
        cap.install_accepted_anchor(&original),
        Err(AnchorError::ScopeMismatch)
    ));
    let denied = cap.accepted_anchor().unwrap().unwrap();
    assert!(denied.denied && denied.draft == original);
    let second = cap.install_accepted_anchor(&draft(2, 11)).unwrap();
    assert_eq!(second.scope.selection_generation, 2);
    assert!(matches!(
        cap.deny_accepted_anchor(&first.scope, &original.group_id),
        Err(AnchorError::ScopeMismatch)
    ));
}
#[test]
fn accepted_device_group_anchor_invalid_successor_and_identity_never_allocate() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let cap = storage.accepted_device_group_anchor_storage().unwrap();
    for field in 0..10 {
        let mut wrong = draft(1, 10);
        match field {
            0 => wrong.successor.epoch = EpochId(1),
            1 => wrong.successor.leaves[0].signature_public_key = [11; 32],
            2 => wrong.successor.leaves[1].account = [11; 32],
            3 => wrong.successor.leaves.reverse(),
            4 => wrong.predecessor.leaves.clear(),
            5 => wrong.recipient = wrong.approver,
            6 => wrong.purpose.generation = 0,
            7 => wrong.purpose.local_device = [11; 32],
            8 => wrong.group_id = GroupId::new(vec![0; 256]),
            _ => wrong
                .successor
                .leaves
                .push(wrong.successor.leaves[1].clone()),
        }
        assert!(matches!(
            cap.install_accepted_anchor(&wrong),
            Err(AnchorError::InvalidFact)
        ));
        assert!(cap.accepted_anchor().unwrap().is_none());
    }
}
#[test]
fn accepted_device_group_anchor_outer_transaction_rolls_back_selection_and_counter() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let result: Result<(), AnchorError> = storage.with_transaction(|backend| {
        backend
            .accepted_device_group_anchor_storage()
            .unwrap()
            .install_accepted_anchor(&draft(1, 10))?;
        Err(AnchorError::InvalidFact)
    });
    assert!(result.is_err());
    let cap = storage.accepted_device_group_anchor_storage().unwrap();
    assert!(cap.accepted_anchor().unwrap().is_none());
    assert_eq!(
        cap.install_accepted_anchor(&draft(2, 11))
            .unwrap()
            .scope
            .selection_generation,
        1
    );
}
#[test]
fn accepted_device_group_anchor_identity_is_immutable_and_selection_counter_is_bounded() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let cap = storage.accepted_device_group_anchor_storage().unwrap();
    for generation in 1..=300 {
        let fact = cap
            .install_accepted_anchor(&draft(generation, (generation % 255) as u8))
            .unwrap();
        assert_eq!(fact.scope.selection_generation, generation);
        cap.deny_accepted_anchor(&fact.scope, &fact.draft.group_id)
            .unwrap();
    }
    let mut other = draft(301, 12);
    other.purpose.local_device = [12; 32];
    other.recipient = [12; 32];
    other.successor.leaves[1].signature_public_key = [12; 32];
    assert!(matches!(
        cap.install_accepted_anchor(&other),
        Err(AnchorError::ScopeMismatch)
    ));
    let connection = storage.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM accepted_device_group_anchor",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    connection
        .execute(
            "UPDATE accepted_device_group_anchor SET generation=?1",
            [i64::MAX],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        cap.install_accepted_anchor(&draft(301, 12)),
        Err(AnchorError::GenerationExhausted)
    ));
}

#[test]
fn accepted_device_group_anchor_group_deletion_permanently_denies_retained_fact() {
    use cgka_traits::storage::GroupStorage;
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let original = draft(1, 10);
    storage
        .put_group(&crate::base::test_support::sample_group(
            original.group_id.clone(),
            2,
            2,
        ))
        .unwrap();
    let cap = storage.accepted_device_group_anchor_storage().unwrap();
    let selected = cap.install_accepted_anchor(&original).unwrap();
    storage.delete_group(&original.group_id).unwrap();
    let after = cap.accepted_anchor().unwrap().unwrap();
    assert!(after.denied && after.scope == selected.scope && after.draft == original);
    assert!(matches!(
        cap.install_accepted_anchor(&original),
        Err(AnchorError::ScopeMismatch)
    ));
}

#[test]
fn accepted_device_group_anchor_encrypted_reopen_retains_exact_denial_without_messages() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("synthetic-anchor.db");
    let key = crate::SqlCipherKey::new("06".repeat(32)).unwrap();
    let original = draft(1, 10);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let cap = storage.accepted_device_group_anchor_storage().unwrap();
    let selected = cap.install_accepted_anchor(&original).unwrap();
    cap.deny_accepted_anchor(&selected.scope, &original.group_id)
        .unwrap();
    storage.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let after = reopened
        .accepted_device_group_anchor_storage()
        .unwrap()
        .accepted_anchor()
        .unwrap()
        .unwrap();
    assert!(after.denied && after.scope == selected.scope && after.draft == original);
    assert_eq!(
        reopened
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM cgka_messages", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn accepted_device_group_anchor_projection_mismatch_and_insert_failure_allocate_nothing() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    storage
        .ensure_account_projection_with_identity("synthetic-anchor", &hex::encode([12; 32]))
        .unwrap();
    let cap = storage.accepted_device_group_anchor_storage().unwrap();
    assert!(matches!(
        cap.install_accepted_anchor(&draft(1, 10)),
        Err(AnchorError::ScopeMismatch)
    ));
    assert!(cap.accepted_anchor().unwrap().is_none());
    let storage = SqliteAccountStorage::in_memory().unwrap();
    storage.lock().unwrap().execute_batch("CREATE TRIGGER reject_synthetic_anchor BEFORE INSERT ON accepted_device_group_anchor BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;").unwrap();
    let cap = storage.accepted_device_group_anchor_storage().unwrap();
    assert!(matches!(
        cap.install_accepted_anchor(&draft(1, 10)),
        Err(AnchorError::Storage(_))
    ));
    assert!(cap.accepted_anchor().unwrap().is_none());
    storage
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_synthetic_anchor")
        .unwrap();
    assert_eq!(
        cap.install_accepted_anchor(&draft(1, 10))
            .unwrap()
            .scope
            .selection_generation,
        1
    );
}

#[test]
fn accepted_device_group_anchor_and_local_genesis_cannot_select_two_active_groups() {
    use cgka_traits::device_group_genesis::GenesisBirthDraft;
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let birth = GenesisBirthDraft {
        format_version: 1,
        group_id: GroupId::new(vec![13; 19]),
        epoch: EpochId(0),
        epoch_authenticator_digest: [14; 32],
        roster_commitment: [15; 32],
        leaves: vec![GenesisLeaf {
            leaf_index: 0,
            account: [1; 32],
            signature_public_key: [2; 32],
        }],
    };
    let genesis = storage
        .device_group_genesis_storage()
        .unwrap()
        .store_genesis_birth(&[1; 32], &[2; 32], &birth)
        .unwrap();
    let cap = storage.accepted_device_group_anchor_storage().unwrap();
    assert!(matches!(
        cap.install_accepted_anchor(&draft(1, 10)),
        Err(AnchorError::SelectionBusy)
    ));
    assert!(cap.accepted_anchor().unwrap().is_none());
    storage
        .device_group_genesis_storage()
        .unwrap()
        .deny_genesis_selection(&genesis.fact.scope, &birth.group_id)
        .unwrap();
    assert!(cap.install_accepted_anchor(&draft(1, 10)).is_ok());
}
