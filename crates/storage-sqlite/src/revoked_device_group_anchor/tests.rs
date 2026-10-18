//! Synthetic SQL contracts; these fixtures grant no genuine Core authority.
use super::*;
use cgka_traits::accepted_device_group_anchor::*;
use cgka_traits::device_group_genesis::GenesisLeaf;
use cgka_traits::device_linking_key_package::PurposeAttemptScope;
use cgka_traits::existing_device_group_anchor::*;
use cgka_traits::private_device_invite::PrivateInviteOrigin;
use cgka_traits::private_roster_settlement::*;
use cgka_traits::storage::StorageProvider;
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

fn draft(storage: &SqliteAccountStorage) -> RevokedDeviceGroupDraft {
    let add = setup(storage);
    let fact = storage.install_existing_anchor(&add).unwrap();
    let rounds = storage.private_roster_settlement_storage().unwrap();
    let state = rounds
        .select_round(&PrivateSettlementAnchor {
            origin: PrivateInviteOrigin::Existing(fact.generation),
            account: add.account,
            local_device: add.local_device,
            group_id: add.group_id.clone(),
            successor: add.successor.clone(),
            roster_commitment: [24; 32],
            enrollment_nonce: add.nonce,
            context_digest: add.context_digest,
            coordinator: add.coordinator,
        })
        .unwrap();
    rounds
        .bind_round_nonce(state.generation, [25; 32], 0)
        .unwrap();
    for leaf in &add.successor.leaves {
        let f = PrivateSettlementFact {
            format_version: 1,
            generation: state.generation,
            leaf_index: leaf.leaf_index,
            signature_public_key: leaf.signature_public_key,
            message_id: MessageId::new(vec![leaf.leaf_index as u8 + 30; 32]),
        };
        if leaf.signature_public_key == add.local_device {
            rounds.record_local_confirmation(&f, &[26]).unwrap();
        } else {
            rounds.record_remote_confirmation(&f).unwrap();
        }
    }
    let mut successor = add.successor.clone();
    successor.epoch = EpochId(3);
    successor.epoch_authenticator_digest = [27; 32];
    successor
        .leaves
        .retain(|leaf| leaf.signature_public_key != add.recipient);
    RevokedDeviceGroupDraft {
        account: add.account,
        local_device: add.local_device,
        group_id: add.group_id,
        predecessor: add.successor,
        predecessor_origin: state.anchor.origin,
        predecessor_settlement_generation: state.generation,
        source_leaf_index: 0,
        source_device: add.coordinator,
        removed_leaf_index: 7,
        removed_device: add.recipient,
        actual_commit_digest: [28; 32],
        action_binding: [29; 32],
        nonce: [30; 32],
        context_digest: [31; 32],
        successor,
    }
}
#[test]
fn revoked_anchor_retains_exact_successor_and_permanent_denial() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let draft = draft(&storage);
    let fact = storage.install_revoked_anchor(&draft).unwrap();
    assert_eq!(fact.generation, 1);
    assert!(!fact.denied && fact.draft == draft);
    assert!(storage.install_revoked_anchor(&draft).unwrap() == fact);
    storage
        .deny_revoked_anchor(fact.generation, &draft.group_id)
        .unwrap();
    assert!(storage.revoked_anchor().unwrap().unwrap().denied);
    assert!(storage.install_revoked_anchor(&draft).is_err());
    let mut changed = draft.clone();
    changed.action_binding = [32; 32];
    assert!(storage.install_revoked_anchor(&changed).is_err());
}

fn settle_successor(storage: &SqliteAccountStorage, fact: &RevokedDeviceGroupFact) -> u64 {
    let rounds = storage.private_roster_settlement_storage().unwrap();
    let state = rounds
        .select_round(&PrivateSettlementAnchor {
            origin: PrivateInviteOrigin::Revoked(fact.generation),
            account: fact.draft.account,
            local_device: fact.draft.local_device,
            group_id: fact.draft.group_id.clone(),
            successor: fact.draft.successor.clone(),
            roster_commitment: [40; 32],
            enrollment_nonce: fact.draft.nonce,
            context_digest: fact.draft.context_digest,
            coordinator: fact.draft.source_device,
        })
        .unwrap();
    rounds
        .bind_round_nonce(state.generation, [41; 32], fact.draft.source_leaf_index)
        .unwrap();
    for leaf in &fact.draft.successor.leaves {
        let f = PrivateSettlementFact {
            format_version: 1,
            generation: state.generation,
            leaf_index: leaf.leaf_index,
            signature_public_key: leaf.signature_public_key,
            message_id: MessageId::new(vec![leaf.leaf_index as u8 + 50; 32]),
        };
        if leaf.signature_public_key == fact.draft.local_device {
            rounds.record_local_confirmation(&f, &[42]).unwrap();
        } else {
            rounds.record_remote_confirmation(&f).unwrap();
        }
    }
    state.generation
}
fn next_draft(
    storage: &SqliteAccountStorage,
    fact: &RevokedDeviceGroupFact,
) -> RevokedDeviceGroupDraft {
    let generation = settle_successor(storage, fact);
    let mut d = fact.draft.clone();
    d.predecessor = fact.draft.successor.clone();
    d.predecessor_origin = PrivateInviteOrigin::Revoked(fact.generation);
    d.predecessor_settlement_generation = generation;
    d.source_leaf_index = 4;
    d.source_device = d.local_device;
    d.removed_leaf_index = 0;
    d.removed_device = [2; 32];
    d.successor.epoch = EpochId(4);
    d.successor.epoch_authenticator_digest = [43; 32];
    d.successor
        .leaves
        .retain(|leaf| leaf.signature_public_key != d.removed_device);
    d.actual_commit_digest = [44; 32];
    d.action_binding = [45; 32];
    d.nonce = [46; 32];
    d.context_digest = [47; 32];
    d
}
#[test]
fn revoked_anchor_checks_exact_single_remove_full_roster_and_owner() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let original = draft(&storage);
    for field in 0..17 {
        let mut wrong = original.clone();
        match field {
            0 => wrong.source_leaf_index = 1,
            1 => wrong.removed_leaf_index = 6,
            2 => wrong.source_device = wrong.removed_device,
            3 => wrong.local_device = wrong.removed_device,
            4 => wrong.successor.leaves[0].signature_public_key = [60; 32],
            5 => wrong.successor.leaves[0].leaf_index = 1,
            6 => wrong.successor.leaves.reverse(),
            7 => wrong.successor.epoch = wrong.predecessor.epoch,
            8 => wrong.successor.epoch_authenticator_digest = [0; 32],
            9 => wrong.actual_commit_digest = [0; 32],
            10 => wrong.predecessor_origin = PrivateInviteOrigin::Existing(2),
            11 => wrong.predecessor_settlement_generation += 1,
            12 => wrong.predecessor.epoch_authenticator_digest = [60; 32],
            13 => wrong.account = [60; 32],
            14 => wrong.successor.leaves[0].account = [60; 32],
            15 => wrong.group_id = GroupId::new(vec![60; 256]),
            _ => wrong
                .successor
                .leaves
                .push(wrong.predecessor.leaves[2].clone()),
        }
        assert!(
            storage.install_revoked_anchor(&wrong).is_err(),
            "field {field}"
        );
        assert!(storage.revoked_anchor().unwrap().is_none());
    }
    storage
        .app_storage()
        .ensure_account_projection_with_identity("synthetic-revoked", &hex::encode([60; 32]))
        .unwrap();
    assert!(storage.install_revoked_anchor(&original).is_err());
    assert!(storage.revoked_anchor().unwrap().is_none());
}
#[test]
fn revoked_anchor_requires_completed_active_predecessor_and_exact_signer() {
    use cgka_traits::storage::{AccountDeviceSignerBinding, AccountDeviceSignerStorage};
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let d = draft(&storage);
    storage
        .put_account_device_signer(&AccountDeviceSignerBinding {
            marmot_identity: cgka_traits::MemberId::new(d.account.to_vec()),
            mls_signature_public_key: vec![60; 32],
        })
        .unwrap();
    assert!(storage.install_revoked_anchor(&d).is_err());
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let d = draft(&storage);
    storage
        .private_roster_settlement_storage()
        .unwrap()
        .deny_round(d.predecessor_settlement_generation)
        .unwrap();
    assert!(storage.install_revoked_anchor(&d).is_err());
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let d = draft(&storage);
    let old = storage.existing_anchor().unwrap().unwrap();
    storage
        .deny_existing_anchor(old.generation, &d.group_id)
        .unwrap();
    assert!(storage.install_revoked_anchor(&d).is_err());
}
#[test]
fn revoked_anchor_successor_retains_terminal_predecessor_and_fences_selection() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let d = draft(&storage);
    let first = storage.install_revoked_anchor(&d).unwrap();
    let next = next_draft(&storage, &first);
    let second = storage.install_revoked_anchor(&next).unwrap();
    assert_eq!(second.generation, 2);
    assert!(
        read_generation(&storage.lock().unwrap(), Some(1))
            .unwrap()
            .unwrap()
            .denied
    );
    assert!(storage.install_revoked_anchor(&d).is_err());
    assert!(storage.install_revoked_anchor(&next).unwrap() == second);
    storage.deny_revoked_anchor(1, &d.group_id).unwrap();
    assert!(!storage.revoked_anchor().unwrap().unwrap().denied);
    let old = storage.existing_anchor().unwrap().unwrap();
    storage
        .deny_existing_anchor(old.generation, &d.group_id)
        .unwrap();
    assert!(matches!(
        crate::private_device_invite::check_selection_allocation(
            &storage.lock().unwrap(),
            &d.account,
            &d.local_device
        ),
        Err(cgka_traits::private_device_invite::PrivateInviteStorageError::Busy)
    ));
    assert!(matches!(
        crate::private_device_invite::check_selection_allocation(
            &storage.lock().unwrap(),
            &d.account,
            &[60; 32]
        ),
        Err(cgka_traits::private_device_invite::PrivateInviteStorageError::ScopeMismatch)
    ));
}
#[test]
fn revoked_anchor_outer_failure_and_failed_successor_insert_restore_all_rows() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let d = draft(&storage);
    let result: StorageResult<()> = storage.with_transaction(|s| {
        s.install_revoked_anchor(&d)?;
        Err(StorageError::Backend("injected after insert".into()))
    });
    assert!(result.is_err() && storage.revoked_anchor().unwrap().is_none());
    let first = storage.install_revoked_anchor(&d).unwrap();
    let next = next_draft(&storage, &first);
    storage.lock().unwrap().execute_batch("CREATE TRIGGER fail_revoked_successor BEFORE INSERT ON revoked_device_group_anchor BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(storage.install_revoked_anchor(&next).is_err());
    assert!(storage.revoked_anchor().unwrap().unwrap() == first);
    storage
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_revoked_successor;")
        .unwrap();
    assert_eq!(storage.install_revoked_anchor(&next).unwrap().generation, 2);
}
#[test]
fn revoked_anchor_sql_cannot_delete_replace_mutate_or_reactivate_terminal_reference() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let d = draft(&storage);
    let fact = storage.install_revoked_anchor(&d).unwrap();
    storage
        .deny_revoked_anchor(fact.generation, &d.group_id)
        .unwrap();
    let conn = storage.lock().unwrap();
    for sql in [
        "DELETE FROM revoked_device_group_anchor",
        "UPDATE revoked_device_group_anchor SET denied=0",
        "UPDATE revoked_device_group_anchor SET generation=2",
        "UPDATE revoked_device_group_anchor SET draft=X'01'",
        "INSERT OR REPLACE INTO revoked_device_group_anchor SELECT * FROM revoked_device_group_anchor",
    ] {
        assert!(conn.execute_batch(sql).is_err());
    }
    assert!(read(&conn).unwrap().unwrap().denied);
}
#[test]
fn revoked_anchor_lifetime_budget_includes_all_denied_rows() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let d = draft(&storage);
    let bytes = serde_json::to_vec(&d).unwrap();
    let conn = storage.lock().unwrap();
    for n in 1..=128i64 {
        conn.execute(
            "INSERT INTO revoked_device_group_anchor VALUES(?1,?2,?3,?4,?5,1)",
            params![
                n,
                d.account.as_slice(),
                d.local_device.as_slice(),
                d.group_id.as_slice(),
                bytes
            ],
        )
        .unwrap();
    }
    assert!(
        conn.execute(
            "INSERT INTO revoked_device_group_anchor VALUES(129,?1,?2,?3,?4,1)",
            params![
                d.account.as_slice(),
                d.local_device.as_slice(),
                d.group_id.as_slice(),
                bytes
            ]
        )
        .is_err()
    );
    assert_eq!(read(&conn).unwrap().unwrap().generation, 128);
    drop(conn);
    assert!(storage.install_revoked_anchor(&d).is_err());
}
#[test]
fn revoked_anchor_encrypted_reopen_and_group_deletion_preserve_terminal_bytes() {
    use cgka_traits::storage::GroupStorage;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("revoked.db");
    let key = crate::SqlCipherKey::new("26".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let d = draft(&storage);
    let fact = storage.install_revoked_anchor(&d).unwrap();
    storage
        .put_group(&crate::base::test_support::sample_group(
            d.group_id.clone(),
            3,
            2,
        ))
        .unwrap();
    storage.delete_group(&d.group_id).unwrap();
    storage.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let retained = reopened.revoked_anchor().unwrap().unwrap();
    assert!(retained.denied && retained.generation == fact.generation && retained.draft == d);
    assert!(reopened.install_revoked_anchor(&d).is_err());
    assert_eq!(
        reopened
            .lock()
            .unwrap()
            .query_row("SELECT max(version) FROM cgka_schema_migrations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        113 // Core 0113_staged_media; private migration receipts use their own ledger.
    );
}

#[test]
fn revoked_anchor_settled_successor_is_an_exact_later_add_predecessor() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let d = draft(&storage);
    let fact = storage.install_revoked_anchor(&d).unwrap();
    let generation = settle_successor(&storage, &fact);
    let old = storage.existing_anchor().unwrap().unwrap();
    storage
        .deny_existing_anchor(old.generation, &d.group_id)
        .unwrap();
    let mut add = old.draft;
    add.predecessor_origin = PrivateInviteOrigin::Revoked(fact.generation);
    add.predecessor = d.successor.clone();
    add.predecessor_settlement_generation = generation;
    add.successor = d.successor;
    add.successor.epoch = EpochId(4);
    add.successor.epoch_authenticator_digest = [61; 32];
    add.recipient = [62; 32];
    add.successor.leaves.push(GenesisLeaf {
        account: d.account,
        leaf_index: 8,
        signature_public_key: add.recipient,
    });
    add.action_binding = [63; 32];
    add.commit_digest = [64; 32];
    let installed = storage.install_existing_anchor(&add).unwrap();
    assert!(installed.draft == add && !installed.denied);
    storage
        .deny_revoked_anchor(fact.generation, &d.group_id)
        .unwrap();
    assert!(storage.revoked_anchors().unwrap()[0].denied);
}
#[test]
fn revoked_anchor_group_snapshot_rollback_cannot_restore_positive_metadata() {
    use cgka_traits::storage::{GroupStorage, MessageStorage};
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let d = draft(&storage);
    let fact = storage.install_revoked_anchor(&d).unwrap();
    storage
        .put_group(&crate::base::test_support::sample_group(
            d.group_id.clone(),
            3,
            2,
        ))
        .unwrap();
    storage
        .create_group_snapshot(&d.group_id, "before-denial")
        .unwrap();
    storage
        .deny_revoked_anchor(fact.generation, &d.group_id)
        .unwrap();
    storage
        .rollback_group_to_snapshot(&d.group_id, "before-denial")
        .unwrap();
    assert!(storage.revoked_anchor().unwrap().unwrap().denied);
    assert!(storage.install_revoked_anchor(&d).is_err());
}
