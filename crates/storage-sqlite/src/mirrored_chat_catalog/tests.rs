//! Synthetic persistence acceptance; not pairing or transport qualification.
use crate::SqliteAccountStorage;
use super::*;
use cgka_traits::{
    MemberId,
    group::ProtocolProfile,
    storage::{AccountDeviceSignerBinding, AccountDeviceSignerStorage, GroupStorage},
};
use std::cell::Cell;

fn scope() -> MirroredChatScope {
    MirroredChatScope {
        account: [1; 32],
        local_device: [2; 32],
        source_device: [3; 32],
        policy_digest: [4; 32],
        protected_group: GroupId::new(vec![5; 16]),
        protected_generation: 1,
    }
}

fn configure(storage: &SqliteAccountStorage) {
    storage
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO account_state(label,updated_at,local_account_id_hex) VALUES('test',0,?1)",
            [hex::encode(scope().account)],
        )
        .unwrap();
    storage
        .put_account_device_signer(&AccountDeviceSignerBinding {
            marmot_identity: MemberId::new(scope().account.to_vec()),
            mls_signature_public_key: scope().local_device.to_vec(),
        })
        .unwrap();
}

fn entry(id: u8, sequence: u64) -> MirroredChatEntry {
    MirroredChatEntry {
        group_id: GroupId::new(vec![id; 16]),
        source_epoch: 0,
        source_sequence: sequence,
        source_digest: [id; 32],
        profile: ProtocolProfile::Current,
        name: "same title".into(),
        description: String::new(),
        state: MirroredChatState::Active,

        accepted_origin: None,

        same_account_source_count: None,

        direct_peer_account: None,
    }
}

#[test]
fn mirrored_catalog_pages_identity_and_retries_without_mls_membership() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    let records = vec![entry(8, 1), entry(7, 2)];
    let calls = Cell::new(0);
    let validate = || {
        calls.set(calls.get() + 1);
        Ok(())
    };
    assert_eq!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &records, &validate)
            .unwrap(),
        2
    );
    assert_eq!(calls.get(), 2);
    assert_eq!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &records, &validate)
            .unwrap(),
        0
    );
    let first = storage
        .mirrored_chat_catalog_page(&scope(), None, 1)
        .unwrap();
    assert!(first == vec![entry(7, 2)]);
    let second = storage
        .mirrored_chat_catalog_page(&scope(), Some(&first[0].group_id), 1)
        .unwrap();
    assert!(second == vec![entry(8, 1)]);
    assert!(
        storage
            .mirrored_chat_catalog_page(&scope(), Some(&second[0].group_id), 1)
            .unwrap()
            .is_empty()
    );
    assert!(storage.list_group_records().unwrap().is_empty());
    let mut conflict = records[0].clone();
    conflict.name = "different".into();
    assert!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[conflict], &validate)
            .is_err()
    );
    assert!(
        storage
            .mirrored_chat_catalog_page(&scope(), None, 128)
            .unwrap()
            == vec![entry(7, 2), entry(8, 1)]
    );
}

#[test]
fn mirrored_catalog_terminal_fence_and_original_cancellation_are_atomic() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    storage
        .apply_mirrored_chat_catalog(&scope(), &[entry(7, 2)], &|| Ok(()))
        .unwrap();
    let mut terminal = entry(7, 3);
    terminal.state = MirroredChatState::Left;
    terminal.name.clear();
    storage
        .apply_mirrored_chat_catalog(&scope(), &[terminal.clone()], &|| Ok(()))
        .unwrap();
    assert_eq!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[entry(7, 1)], &|| Ok(()))
            .unwrap(),
        0
    );
    assert!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[entry(7, 4)], &|| Ok(()))
            .is_err()
    );
    let calls = Cell::new(0);
    let cancelled = || {
        calls.set(calls.get() + 1);
        if calls.get() == 2 {
            Err(invalid())
        } else {
            Ok(())
        }
    };
    assert!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[entry(8, 4), entry(9, 5)], &cancelled)
            .is_err()
    );
    assert!(
        storage
            .mirrored_chat_catalog_page(&scope(), None, 128)
            .unwrap()
            == vec![terminal]
    );
    assert!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[entry(8, 4)], &|| Err(invalid()))
            .is_err()
    );
    assert!(storage.list_group_records().unwrap().is_empty());
}

#[test]
fn mirrored_catalog_refuses_wrong_owner_scope_bounds_and_duplicate_ids() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    assert!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[entry(7, 1)], &|| Ok(()))
            .is_err()
    );
    configure(&storage);
    let mut wrong = scope();
    wrong.account = [9; 32];
    assert!(
        storage
            .apply_mirrored_chat_catalog(&wrong, &[entry(7, 1)], &|| Ok(()))
            .is_err()
    );
    wrong = scope();
    wrong.local_device = [9; 32];
    assert!(
        storage
            .apply_mirrored_chat_catalog(&wrong, &[entry(7, 1)], &|| Ok(()))
            .is_err()
    );
    wrong = scope();
    wrong.source_device = wrong.local_device;
    assert!(
        storage
            .apply_mirrored_chat_catalog(&wrong, &[entry(7, 1)], &|| Ok(()))
            .is_err()
    );
    assert!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[], &|| Ok(()))
            .is_err()
    );
    assert!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[entry(7, 1), entry(7, 2)], &|| Ok(()))
            .is_err()
    );
    let mut invalid_entry = entry(7, 1);
    invalid_entry.name = "x".repeat(1025);
    assert!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[invalid_entry], &|| Ok(()))
            .is_err()
    );
    invalid_entry = entry(7, 1);
    invalid_entry.group_id = scope().protected_group;
    assert!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[invalid_entry], &|| Ok(()))
            .is_err()
    );
    assert!(
        storage
            .mirrored_chat_catalog_page(&scope(), None, 0)
            .is_err()
    );
    assert!(
        storage
            .mirrored_chat_catalog_page(&scope(), None, 129)
            .is_err()
    );
    assert!(
        storage
            .mirrored_chat_catalog_page(&scope(), Some(&GroupId::new(vec![])), 1)
            .is_err()
    );
    assert!(
        storage
            .mirrored_chat_catalog_page(&scope(), None, 128)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn mirrored_catalog_encrypted_reopen_preserves_terminal_fence_and_close_is_final() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catalog.db");
    let key = crate::SqlCipherKey::new("42".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    configure(&storage);
    let mut terminal = entry(7, 3);
    terminal.state = MirroredChatState::Deleted;
    terminal.name.clear();
    storage
        .apply_mirrored_chat_catalog(&scope(), &[terminal.clone()], &|| Ok(()))
        .unwrap();
    storage.close().unwrap();
    assert!(matches!(
        storage.mirrored_chat_catalog_page(&scope(), None, 128),
        Err(StorageError::Closed(_))
    ));
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(
        reopened
            .mirrored_chat_catalog_page(&scope(), None, 128)
            .unwrap()
            == vec![terminal]
    );
    assert!(
        reopened
            .apply_mirrored_chat_catalog(&scope(), &[entry(7, 4)], &|| Ok(()))
            .is_err()
    );
    assert!(reopened.list_group_records().unwrap().is_empty());
    assert_eq!(
        reopened
            .lock()
            .unwrap()
            .query_row("SELECT max(version) FROM cgka_schema_migrations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        102
    );
}

#[test]
fn mirrored_catalog_multirow_conflict_rolls_back_and_owner_change_cannot_adopt_rows() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    storage
        .apply_mirrored_chat_catalog(&scope(), &[entry(7, 1)], &|| Ok(()))
        .unwrap();
    let mut conflict = entry(7, 1);
    conflict.description = "conflicting update".into();
    assert!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[entry(8, 2), conflict], &|| Ok(()))
            .is_err()
    );
    assert!(
        storage
            .mirrored_chat_catalog_page(&scope(), None, 128)
            .unwrap()
            == vec![entry(7, 1)]
    );
    storage
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_state SET local_account_id_hex=?1",
            [hex::encode([9; 32])],
        )
        .unwrap();
    assert!(
        storage
            .mirrored_chat_catalog_page(&scope(), None, 128)
            .is_err()
    );
    let mut other = scope();
    other.account = [9; 32];
    storage
        .put_account_device_signer(&AccountDeviceSignerBinding {
            marmot_identity: MemberId::new(other.account.to_vec()),
            mls_signature_public_key: other.local_device.to_vec(),
        })
        .unwrap();
    assert!(
        storage
            .apply_mirrored_chat_catalog(&other, &[entry(8, 2)], &|| Ok(()))
            .is_err()
    );
}

#[test]
fn mirrored_catalog_sql_guards_preserve_scope_and_terminal_references() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    let mut terminal = entry(7, 3);
    terminal.state = MirroredChatState::Left;
    terminal.name.clear();
    storage
        .apply_mirrored_chat_catalog(&scope(), &[terminal], &|| Ok(()))
        .unwrap();
    let key = scope_bytes(&scope()).unwrap();
    let conn = storage.lock().unwrap();
    assert!(
        conn.execute("DELETE FROM mirrored_chat_catalog", [])
            .is_err()
    );
    assert!(
        conn.execute("DELETE FROM mirrored_chat_scopes", [])
            .is_err()
    );
    assert!(
        conn.execute(
            "UPDATE mirrored_chat_catalog SET state=0,source_sequence=4",
            []
        )
        .is_err()
    );
    assert!(
        conn.execute("UPDATE mirrored_chat_catalog SET source_sequence=2", [])
            .is_err()
    );
    assert!(
        conn.execute(
            "UPDATE mirrored_chat_scopes SET local_device=?1",
            [[9; 32].as_slice()]
        )
        .is_err()
    );
    assert!(conn.execute("INSERT OR REPLACE INTO mirrored_chat_scopes(scope,account,local_device,source_device) VALUES(?1,?2,?3,?4)", params![key,scope().account.as_slice(),scope().local_device.as_slice(),scope().source_device.as_slice()]).is_err());
    assert!(conn.execute("INSERT OR REPLACE INTO mirrored_chat_catalog(scope,group_id,source_sequence,state,record) VALUES(?1,?2,4,0,?3)",params![key,entry(7,4).group_id.as_slice(),crate::serialize(&entry(7,4)).unwrap()]).is_err());
}

#[test]
fn mirrored_catalog_terminal_fence_survives_policy_and_roster_renewal() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    let mut newer_scope = scope();
    newer_scope.protected_generation = 2;
    newer_scope.policy_digest = [6; 32];
    storage
        .apply_mirrored_chat_catalog(&newer_scope, &[entry(7, 1)], &|| Ok(()))
        .unwrap();
    let mut terminal = entry(7, 2);
    terminal.state = MirroredChatState::Left;
    terminal.name.clear();
    storage
        .apply_mirrored_chat_catalog(&scope(), &[terminal], &|| Ok(()))
        .unwrap();
    assert!(
        storage
            .mirrored_chat_catalog_page(&newer_scope, None, 128)
            .unwrap()
            .is_empty()
    );
    assert!(
        storage
            .apply_mirrored_chat_catalog(&newer_scope, &[entry(7, 3)], &|| Ok(()))
            .is_err()
    );
    let mut fresh_scope = newer_scope.clone();
    fresh_scope.protected_generation = 3;
    assert!(
        storage
            .apply_mirrored_chat_catalog(&fresh_scope, &[entry(7, 3)], &|| Ok(()))
            .is_err()
    );
    // Another actual member source has independent membership; a source leave
    // does not forge a global disband or delete that sibling's valid observation.
    fresh_scope.source_device = [8; 32];
    storage
        .apply_mirrored_chat_catalog(&fresh_scope, &[entry(7, 3)], &|| Ok(()))
        .unwrap();
    assert!(
        storage
            .mirrored_chat_catalog_page(&fresh_scope, None, 128)
            .unwrap()
            == vec![entry(7, 3)]
    );
}

#[test]
fn mirrored_catalog_fresh_origin_rejoin_preserves_retired_and_unbound_fences() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    let old_origin = AcceptedChatOrigin {
        id: [21; 32],
        order: 1,
    };
    let new_origin = AcceptedChatOrigin {
        id: [22; 32],
        order: 2,
    };
    let mut old = entry(7, 1);
    old.accepted_origin = Some(old_origin);
    storage
        .apply_mirrored_chat_catalog(&scope(), &[old.clone()], &|| Ok(()))
        .unwrap();
    let mut left = old.clone();
    left.source_sequence = 2;
    left.source_epoch = 1;
    left.state = MirroredChatState::Left;
    left.name.clear();
    storage
        .apply_mirrored_chat_catalog(&scope(), &[left.clone()], &|| Ok(()))
        .unwrap();
    let mut same = old.clone();
    same.source_sequence = 99;
    same.source_epoch = 4;
    assert!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[same], &|| Ok(()))
            .is_err()
    );
    let mut missing = entry(7, 100);
    missing.source_epoch = 4;
    assert!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[missing], &|| Ok(()))
            .is_err()
    );
    let mut renewed = scope();
    renewed.protected_generation = 2;
    renewed.policy_digest = [9; 32];
    let mut fresh = entry(7, 3);
    fresh.source_epoch = 2;
    fresh.accepted_origin = Some(new_origin);
    storage
        .apply_mirrored_chat_catalog(&renewed, &[fresh.clone()], &|| Ok(()))
        .unwrap();
    // A delayed old terminal cannot deny the genuinely new accepted lineage.
    left.source_sequence = 200;
    assert_eq!(
        storage
            .apply_mirrored_chat_catalog(&renewed, &[left], &|| Ok(()))
            .unwrap(),
        0
    );
    let mut unbound = entry(7, 201);
    unbound.state = MirroredChatState::Left;
    unbound.name.clear();
    assert_eq!(
        storage
            .apply_mirrored_chat_catalog(&renewed, &[unbound], &|| Ok(()))
            .unwrap(),
        0
    );
    assert!(
        storage
            .mirrored_chat_catalog_page(&renewed, None, 128)
            .unwrap()
            == vec![fresh]
    );
    let mut other = scope();
    other.source_device = [8; 32];
    storage
        .apply_mirrored_chat_catalog(&other, &[old], &|| Ok(()))
        .unwrap();
    assert_eq!(
        storage
            .mirrored_chat_catalog_page(&other, None, 128)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn mirrored_catalog_new_origin_cannot_reopen_legacy_or_deleted_terminal() {
    for state in [MirroredChatState::Left, MirroredChatState::Deleted] {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        configure(&storage);
        let mut dead = entry(7, 1);
        dead.state = state;
        dead.name.clear();
        if state == MirroredChatState::Deleted {
            dead.accepted_origin = Some(AcceptedChatOrigin {
                id: [21; 32],
                order: 1,
            });
        }
        storage
            .apply_mirrored_chat_catalog(&scope(), &[dead], &|| Ok(()))
            .unwrap();
        let mut fresh = entry(7, 2);
        fresh.accepted_origin = Some(AcceptedChatOrigin {
            id: [22; 32],
            order: 2,
        });
        assert!(
            storage
                .apply_mirrored_chat_catalog(&scope(), &[fresh], &|| Ok(()))
                .is_err()
        );
    }
}

#[test]
fn mirrored_catalog_stale_active_cannot_advance_current_origin_and_replace_cannot_erase_fences() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    let mut active = entry(7, 10);
    active.accepted_origin = Some(AcceptedChatOrigin {
        id: [21; 32],
        order: 1,
    });
    storage
        .apply_mirrored_chat_catalog(&scope(), &[active.clone()], &|| Ok(()))
        .unwrap();
    let mut stale = active.clone();
    stale.source_sequence = 9;
    stale.accepted_origin = Some(AcceptedChatOrigin {
        id: [22; 32],
        order: 2,
    });
    assert_eq!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[stale], &|| Ok(()))
            .unwrap(),
        0
    );
    assert!(
        storage
            .mirrored_chat_catalog_page(&scope(), None, 128)
            .unwrap()
            == vec![active.clone()]
    );
    let conn = storage.lock().unwrap();
    assert!(conn.execute("INSERT OR REPLACE INTO mirrored_chat_origin_current SELECT account,local_device,source_device,group_id,zeroblob(32),origin_order+1,epoch FROM mirrored_chat_origin_current",[]).is_err());
    drop(conn);
    active.source_sequence = 11;
    active.state = MirroredChatState::Left;
    active.name.clear();
    storage
        .apply_mirrored_chat_catalog(&scope(), &[active], &|| Ok(()))
        .unwrap();
    let conn = storage.lock().unwrap();
    assert!(conn.execute("INSERT OR REPLACE INTO mirrored_chat_origin_fences SELECT account,local_device,source_device,group_id,origin_id,origin_order,epoch,1 FROM mirrored_chat_origin_fences",[]).is_err());
    assert!(
        conn.execute("DELETE FROM mirrored_chat_origin_fences", [])
            .is_err()
    );
}

#[test]
fn direct_peer_lookup_requires_exact_current_scope_and_never_joins_mls() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    let peer = [42; 32];
    let mut direct = entry(7, 1);
    direct.direct_peer_account = Some(peer);
    storage
        .apply_mirrored_chat_catalog(&scope(), &[entry(6, 1), direct.clone()], &|| Ok(()))
        .unwrap();
    let found = storage
        .app_storage().mirrored_direct_conversation_observation(&[scope()], &peer)
        .unwrap()
        .unwrap();
    assert!(found.entry == direct && found.scope == scope());
    assert!(storage.list_group_records().unwrap().is_empty());
    assert!(
        storage
            .app_storage().mirrored_direct_conversation_observation(&[], &peer)
            .unwrap()
            .is_none()
    );
    let mut stale = scope();
    stale.policy_digest = [43; 32];
    assert!(
        storage
            .app_storage().mirrored_direct_conversation_observation(&[stale], &peer)
            .unwrap()
            .is_none()
    );
    assert!(
        storage
            .app_storage().mirrored_direct_conversation_observation(&[scope()], &[44; 32])
            .unwrap()
            .is_none()
    );
    assert!(
        storage
            .app_storage().mirrored_direct_conversation_observation(&[scope()], &[0; 32])
            .is_err()
    );
    assert!(
        storage
            .app_storage().mirrored_direct_conversation_observation(&[scope()], &scope().account)
            .is_err()
    );
}

#[test]
fn direct_peer_changes_and_terminal_fences_retire_the_old_lookup() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    let peer = [42; 32];
    let mut direct = entry(7, 1);
    direct.direct_peer_account = Some(peer);
    storage
        .apply_mirrored_chat_catalog(&scope(), &[direct.clone()], &|| Ok(()))
        .unwrap();
    direct.source_sequence = 2;
    direct.direct_peer_account = None;
    storage
        .apply_mirrored_chat_catalog(&scope(), &[direct.clone()], &|| Ok(()))
        .unwrap();
    assert!(
        storage
            .app_storage().mirrored_direct_conversation_observation(&[scope()], &peer)
            .unwrap()
            .is_none()
    );
    direct.source_sequence = 3;
    direct.direct_peer_account = Some(peer);
    storage
        .apply_mirrored_chat_catalog(&scope(), &[direct.clone()], &|| Ok(()))
        .unwrap();
    let mut terminal = entry(7, 4);
    terminal.state = MirroredChatState::Left;
    terminal.name.clear();
    storage
        .apply_mirrored_chat_catalog(&scope(), &[terminal], &|| Ok(()))
        .unwrap();
    assert!(
        storage
            .app_storage().mirrored_direct_conversation_observation(&[scope()], &peer)
            .unwrap()
            .is_none()
    );
    let mut renewed = scope();
    renewed.policy_digest = [43; 32];
    assert!(
        storage
            .apply_mirrored_chat_catalog(&renewed, &[direct], &|| Ok(()))
            .is_err()
    );
    assert!(
        storage
            .app_storage().mirrored_direct_conversation_observation(&[renewed], &peer)
            .unwrap()
            .is_none()
    );
}

#[test]
fn direct_peer_original_tail_failure_rolls_back_the_index_and_observation() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    let peer = [42; 32];
    let mut direct = entry(7, 1);
    direct.direct_peer_account = Some(peer);
    let checks = Cell::new(0);
    assert!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[direct.clone()], &|| {
                checks.set(checks.get() + 1);
                if checks.get() == 2 {
                    Err(invalid())
                } else {
                    Ok(())
                }
            })
            .is_err()
    );
    assert_eq!(checks.get(), 2);
    assert!(
        storage
            .app_storage().mirrored_direct_conversation_observation(&[scope()], &peer)
            .unwrap()
            .is_none()
    );
    storage
        .apply_mirrored_chat_catalog(&scope(), &[direct], &|| Ok(()))
        .unwrap();
    assert!(
        storage
            .app_storage().mirrored_direct_conversation_observation(&[scope()], &peer)
            .unwrap()
            .is_some()
    );
}

#[test]
fn direct_peer_metadata_rejects_self_zero_and_terminal_values() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    for peer in [[0; 32], scope().account] {
        let mut direct = entry(7, 1);
        direct.direct_peer_account = Some(peer);
        assert!(
            storage
                .apply_mirrored_chat_catalog(&scope(), &[direct], &|| Ok(()))
                .is_err()
        );
    }
    let mut terminal = entry(7, 1);
    terminal.state = MirroredChatState::Deleted;
    terminal.name.clear();
    terminal.direct_peer_account = Some([42; 32]);
    assert!(
        storage
            .apply_mirrored_chat_catalog(&scope(), &[terminal], &|| Ok(()))
            .is_err()
    );
    assert!(
        storage
            .mirrored_chat_catalog_page(&scope(), None, 128)
            .unwrap()
            .is_empty()
    );
}
