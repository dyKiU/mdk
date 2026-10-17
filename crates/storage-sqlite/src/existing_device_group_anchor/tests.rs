//! Synthetic persistence contracts, deliberately separate from genuine SDK proof.
use super::*;
use cgka_traits::accepted_device_group_anchor::*;
use cgka_traits::device_group_genesis::GenesisLeaf;
use cgka_traits::device_linking_key_package::PurposeAttemptScope;
use cgka_traits::private_roster_settlement::*;
use cgka_traits::{EpochId, MessageId};

fn setup(storage: &SqliteAccountStorage) -> ExistingDeviceGroupDraft {
    let a = GenesisLeaf {
        account: [1; 32],
        leaf_index: 0,
        signature_public_key: [2; 32],
    };
    let b = GenesisLeaf {
        account: [1; 32],
        leaf_index: 4,
        signature_public_key: [3; 32],
    };
    let roster = DeviceGroupAnchorRoster {
        epoch: EpochId(1),
        epoch_authenticator_digest: [4; 32],
        leaves: vec![a.clone(), b.clone()],
    };
    let accepted = AcceptedDeviceGroupAnchorDraft {
        format_version: 1,
        purpose: PurposeAttemptScope {
            account: [1; 32],
            local_device: [3; 32],
            generation: 1,
        },
        group_id: GroupId::new(vec![5; 19]),
        nonce: [6; 32],
        context_digest: [7; 32],
        key_package_reference: [8; 32],
        welcome_digest: [9; 32],
        approver: [2; 32],
        recipient: [3; 32],
        predecessor: DeviceGroupAnchorRoster {
            epoch: EpochId(0),
            epoch_authenticator_digest: [10; 32],
            leaves: vec![a],
        },
        successor: roster.clone(),
    };
    let fact = storage
        .accepted_device_group_anchor_storage()
        .unwrap()
        .install_accepted_anchor(&accepted)
        .unwrap();
    let round = storage.private_roster_settlement_storage().unwrap();
    let state = round
        .select_round(&PrivateSettlementAnchor {
            origin: PrivateInviteOrigin::Accepted(fact.scope.selection_generation),
            account: [1; 32],
            local_device: [3; 32],
            group_id: accepted.group_id.clone(),
            successor: roster.clone(),
            roster_commitment: [11; 32],
            enrollment_nonce: accepted.nonce,
            context_digest: accepted.context_digest,
            coordinator: [2; 32],
        })
        .unwrap();
    round
        .bind_round_nonce(state.generation, [12; 32], 0)
        .unwrap();
    round
        .record_local_confirmation(
            &PrivateSettlementFact {
                format_version: 1,
                generation: state.generation,
                leaf_index: 4,
                signature_public_key: [3; 32],
                message_id: MessageId::new(vec![13; 32]),
            },
            &[14],
        )
        .unwrap();
    round
        .record_remote_confirmation(&PrivateSettlementFact {
            format_version: 1,
            generation: state.generation,
            leaf_index: 0,
            signature_public_key: [2; 32],
            message_id: MessageId::new(vec![15; 32]),
        })
        .unwrap();
    let mut successor = roster.clone();
    successor.epoch = EpochId(2);
    successor.epoch_authenticator_digest = [16; 32];
    successor.leaves.push(GenesisLeaf {
        account: [1; 32],
        leaf_index: 7,
        signature_public_key: [17; 32],
    });
    ExistingDeviceGroupDraft {
        account: [1; 32],
        local_device: [3; 32],
        group_id: accepted.group_id,
        predecessor: roster,
        predecessor_origin: state.anchor.origin,
        predecessor_settlement_generation: state.generation,
        action_binding: [18; 32],
        nonce: [19; 32],
        context_digest: [20; 32],
        coordinator: [2; 32],
        recipient: [17; 32],
        key_package_reference: [21; 32],
        key_package_digest: [22; 32],
        commit_digest: [23; 32],
        successor,
    }
}

#[test]
fn existing_anchor_exact_retry_denial_and_stale_scope_are_permanent() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let draft = setup(&storage);
    let fact = storage.install_existing_anchor(&draft).unwrap();
    assert!(storage.install_existing_anchor(&draft).unwrap() == fact);
    assert!(
        storage
            .deny_existing_anchor(fact.generation + 1, &draft.group_id)
            .is_err()
    );
    storage
        .deny_existing_anchor(fact.generation, &draft.group_id)
        .unwrap();
    assert!(storage.install_existing_anchor(&draft).is_err());
    let mut changed_binding = draft.clone();
    changed_binding.action_binding = [27; 32];
    assert!(storage.install_existing_anchor(&changed_binding).is_err());
    assert!(storage.existing_anchor().unwrap().unwrap().denied);
    assert_eq!(
        storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM existing_device_group_anchor",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
}

#[test]
fn existing_anchor_group_delete_denies_metadata_in_the_same_transaction() {
    use cgka_traits::storage::GroupStorage;
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let draft = setup(&storage);
    storage
        .put_group(&crate::base::test_support::sample_group(
            draft.group_id.clone(),
            2,
            3,
        ))
        .unwrap();
    let fact = storage.install_existing_anchor(&draft).unwrap();
    storage.delete_group(&draft.group_id).unwrap();
    let retained = storage.existing_anchor().unwrap().unwrap();
    assert!(retained.denied && retained.generation == fact.generation && retained.draft == draft);
    assert!(storage.install_existing_anchor(&draft).is_err());
}

#[test]
fn existing_anchor_projection_mismatch_and_new_selection_cannot_orphan_live_origin() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let draft = setup(&storage);
    storage
        .app_storage()
        .ensure_account_projection_with_identity("synthetic-existing", &hex::encode([27; 32]))
        .unwrap();
    assert!(storage.install_existing_anchor(&draft).is_err());
    assert!(storage.existing_anchor().unwrap().is_none());
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let draft = setup(&storage);
    storage.install_existing_anchor(&draft).unwrap();
    let connection = storage.lock().unwrap();
    assert!(matches!(
        crate::private_device_invite::check_selection_allocation(
            &connection,
            &draft.account,
            &draft.local_device
        ),
        Err(cgka_traits::private_device_invite::PrivateInviteStorageError::Busy)
    ));
    assert!(matches!(
        crate::private_device_invite::check_selection_allocation(
            &connection,
            &draft.account,
            &[27; 32]
        ),
        Err(cgka_traits::private_device_invite::PrivateInviteStorageError::ScopeMismatch)
    ));
}

#[test]
fn existing_anchor_rejects_changed_owner_roster_binding_and_generation_without_allocating() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let draft = setup(&storage);
    for field in 0..14 {
        let mut wrong = draft.clone();
        match field {
            0 => wrong.account = [24; 32],
            1 => wrong.local_device = wrong.recipient,
            2 => wrong.predecessor_origin = PrivateInviteOrigin::Accepted(2),
            3 => wrong.predecessor_settlement_generation += 1,
            4 => wrong.action_binding = [0; 32],
            5 => wrong.commit_digest = [0; 32],
            6 => wrong.successor.epoch = wrong.predecessor.epoch,
            7 => wrong.successor.leaves.reverse(),
            8 => wrong.successor.leaves[0].signature_public_key = [24; 32],
            9 => wrong.predecessor.epoch_authenticator_digest = [24; 32],
            10 => wrong.coordinator = wrong.recipient,
            11 => wrong.key_package_digest = [0; 32],
            12 => wrong.successor.leaves[2].account = [24; 32],
            _ => wrong.group_id = GroupId::new(vec![24; 256]),
        }
        assert!(storage.install_existing_anchor(&wrong).is_err());
        assert!(storage.existing_anchor().unwrap().is_none());
    }
}

#[test]
fn existing_anchor_requires_completed_active_predecessor() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let draft = setup(&storage);
    storage
        .private_roster_settlement_storage()
        .unwrap()
        .deny_round(draft.predecessor_settlement_generation)
        .unwrap();
    assert!(storage.install_existing_anchor(&draft).is_err());
    assert!(storage.existing_anchor().unwrap().is_none());
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let draft = setup(&storage);
    let cap = storage.accepted_device_group_anchor_storage().unwrap();
    let old = cap.accepted_anchor().unwrap().unwrap();
    cap.deny_accepted_anchor(&old.scope, &draft.group_id)
        .unwrap();
    assert!(storage.install_existing_anchor(&draft).is_err());
}

#[test]
fn existing_anchor_outer_failure_rolls_back_row_and_generation() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let draft = setup(&storage);
    let result: StorageResult<()> = storage.with_transaction(|backend| {
        backend.install_existing_anchor(&draft)?;
        Err(StorageError::Backend("injected post-apply failure".into()))
    });
    assert!(result.is_err());
    assert!(storage.existing_anchor().unwrap().is_none());
    storage.lock().unwrap().execute_batch("CREATE TRIGGER reject_existing BEFORE INSERT ON existing_device_group_anchor BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(storage.install_existing_anchor(&draft).is_err());
    storage
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_existing;")
        .unwrap();
    assert_eq!(
        storage.install_existing_anchor(&draft).unwrap().generation,
        1
    );
}

#[test]
fn existing_anchor_encrypted_reopen_preserves_denial_and_original_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("existing-anchor.db");
    let key = crate::SqlCipherKey::new("26".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let draft = setup(&storage);
    let fact = storage.install_existing_anchor(&draft).unwrap();
    storage
        .deny_existing_anchor(fact.generation, &draft.group_id)
        .unwrap();
    storage.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let retained = reopened.existing_anchor().unwrap().unwrap();
    assert!(retained.denied && retained.generation == fact.generation && retained.draft == draft);
    assert!(reopened.install_existing_anchor(&draft).is_err());
    assert_eq!(
        reopened
            .lock()
            .unwrap()
            .query_row("SELECT max(version) FROM cgka_schema_migrations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        109
    );
    assert_eq!(
        reopened
            .lock()
            .unwrap()
            .query_row(
                "SELECT max(version) FROM cgka_experimental_device_sync_schema_migrations",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        crate::migrations::latest_private_migration_version()
    );
}
