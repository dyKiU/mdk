//! Synthetic persistence controls, not original Core/SDK consent acceptance.
use super::*;
use crate::{SqliteResultExt, SqliteAppStorage};
use cgka_traits::{
    MemberId,
    approved_account_sharing_policy::{ACCOUNT_SHARING_POLICY_VERSION, ACCOUNT_SHARING_CAPABILITIES},
    storage::{StorageProvider, StorageError, AccountDeviceSignerStorage, AccountDeviceSignerBinding},
};
use std::cell::Cell;

fn configured() -> SqliteAccountStorage {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    storage.app_storage().ensure_account_projection_with_identity("test", &hex::encode([1; 32])).unwrap();
    storage.put_account_device_signer(&AccountDeviceSignerBinding {
        marmot_identity: MemberId::new(vec![1; 32]),
        mls_signature_public_key: vec![2; 32],
    }).unwrap();
    storage
}
fn policy() -> ApprovedAccountSharingPolicy {
    ApprovedAccountSharingPolicy {
        version: ACCOUNT_SHARING_POLICY_VERSION,
        capabilities: ACCOUNT_SHARING_CAPABILITIES,
        account: [1; 32], local_device: [2; 32], peer_device: [3; 32],
        protected_group: GroupId::new(vec![5; 16]), approval_id: [4; 32],
        created_at: 100, approved_protected_epoch: 2, revoked: false,
    }
}

#[test]
fn private_app_capability_keeps_protocol_outer_rollback_and_exact_callbacks() {
    let storage = configured();
    let app = storage.app_storage();
    assert!(app.shares_connection_with(&storage.app_storage()));
    let calls = Cell::new(0usize);
    let result: StorageResult<()> = storage.with_transaction(|outer| {
        let capability = outer.approved_account_sharing_policy_storage().unwrap();
        capability.put_approved_account_sharing_policy(&policy(), &|| {
            calls.set(calls.get() + 1); Ok(())
        })?;
        assert_eq!(app.approved_account_sharing_policies()?.len(), 1);
        Err(StorageError::Serialization("synthetic outer rollback".into()))
    });
    assert!(result.is_err());
    assert_eq!(calls.get(), 2, "the same callback must run before work and at tail");
    assert!(app.approved_account_sharing_policies().unwrap().is_empty(),
            "App capability writes must roll back with the original protocol transaction");
    storage.approved_account_sharing_policy_storage().unwrap()
        .put_approved_account_sharing_policy(&policy(), &|| Ok(())).unwrap();
    assert_eq!(app.approved_account_sharing_policies().unwrap().len(), 1);
}

#[test]
fn private_app_capability_preserves_tail_refusal_and_terminal_shared_close() {
    let storage = configured();
    let app = storage.app_storage();
    let calls = Cell::new(0usize);
    let result = storage.approved_account_sharing_policy_storage().unwrap()
        .put_approved_account_sharing_policy(&policy(), &|| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 { Err(StorageError::Serialization("synthetic tail refusal".into())) }
            else { Ok(()) }
        });
    assert!(result.is_err());
    assert_eq!(calls.get(), 2);
    assert!(app.approved_account_sharing_policies().unwrap().is_empty());
    storage.approved_account_sharing_policy_storage().unwrap()
        .put_approved_account_sharing_policy(&policy(), &|| Ok(())).unwrap();
    assert_eq!(app.approved_account_sharing_policies().unwrap().len(), 1);
    storage.close().unwrap();
    assert!(app.is_closed());
    assert!(matches!(app.approved_account_sharing_policies(), Err(StorageError::Closed(_))));
    assert!(matches!(storage.approved_account_sharing_policy_storage().unwrap()
        .approved_account_sharing_policies(), Err(StorageError::Closed(_))));
}

#[test]
fn private_app_read_snapshot_is_query_only_restores_mode_and_observes_close() {
    let storage = configured();
    let app: SqliteAppStorage = storage.app_storage();
    let write: StorageResult<()> = app.with_read_snapshot(|view| {
        view.lock()?.execute_batch("UPDATE account_state SET updated_at=updated_at+1").storage()
    });
    assert!(write.is_err(), "actual App read snapshots must reject writes");
    app.lock().unwrap().execute_batch("UPDATE account_state SET updated_at=updated_at+1").unwrap();
    let rows: StorageResult<i64> = app.with_read_snapshot(|view| {
        view.lock()?.query_row("SELECT count(*) FROM account_state", [], |row| row.get(0)).storage()
    });
    assert_eq!(rows.unwrap(), 1);
    storage.close().unwrap();
    let entered = Cell::new(false);
    let closed: StorageResult<()> = app.with_read_snapshot(|_| { entered.set(true); Ok(()) });
    assert!(matches!(closed, Err(StorageError::Closed(_))));
    assert!(!entered.get(), "a closed account cannot enter the App snapshot callback");
}
