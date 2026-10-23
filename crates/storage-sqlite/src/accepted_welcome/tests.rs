use super::*;
use crate::SqlCipherKey;
fn receipt() -> AcceptedWelcomeReceipt {
    AcceptedWelcomeReceipt {
        welcome_id: MessageId::new(vec![1; 17]),
        content_id: MessageId::new(vec![2; 31]),
        group_id: GroupId::new(vec![3; 19]),
        consumed_key_package_ref: vec![4; 27],
        own_account: MemberId::new(vec![5; 32]),
        own_signature_public_key: vec![6; 48],
        welcomer_account: MemberId::new(vec![7; 32]),
        welcomer_signature_public_key: vec![8; 64],
        joined_epoch: EpochId(9),
        joined_epoch_authenticator_digest: [10; 32],
    }
}
#[test]
fn exact_retry_is_idempotent_and_substituted_binding_never_replaces_receipt() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let original = receipt();
    storage.put_accepted_welcome_receipt(&original).unwrap();
    storage.put_accepted_welcome_receipt(&original).unwrap();
    for field in 0..9 {
        let mut changed = original.clone();
        match field {
            0 => changed.content_id = MessageId::new(vec![11]),
            1 => changed.group_id = GroupId::new(vec![11]),
            2 => changed.consumed_key_package_ref[0] ^= 1,
            3 => changed.own_account = MemberId::new(vec![11; 32]),
            4 => changed.own_signature_public_key[0] ^= 1,
            5 => changed.welcomer_account = MemberId::new(vec![11; 32]),
            6 => changed.welcomer_signature_public_key[0] ^= 1,
            7 => changed.joined_epoch.0 += 1,
            _ => changed.joined_epoch_authenticator_digest[0] ^= 1,
        }
        assert!(matches!(
            storage.put_accepted_welcome_receipt(&changed),
            Err(StorageError::AlreadyExists)
        ));
    }
    assert!(
        storage
            .accepted_welcome_receipt(&original.welcome_id)
            .unwrap()
            .unwrap()
            == original
    );
    assert!(
        storage
            .accepted_welcome_receipt(&MessageId::new(vec![99]))
            .unwrap()
            .is_none()
    );
}
#[test]
fn enclosing_join_transaction_rollback_leaves_no_receipt() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let original = receipt();
    let result: StorageResult<()> = storage.with_transaction(|storage| {
        storage.put_accepted_welcome_receipt(&original)?;
        Err(StorageError::Backend(
            "injected post-receipt failure".into(),
        ))
    });
    assert!(result.is_err());
    assert!(
        storage
            .accepted_welcome_receipt(&original.welcome_id)
            .unwrap()
            .is_none()
    );
}
#[test]
fn variable_ids_and_signature_sizes_are_preserved_with_explicit_bounds() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let original = receipt();
    storage.put_accepted_welcome_receipt(&original).unwrap();
    for field in 0..7 {
        let mut changed = original.clone();
        changed.welcome_id = MessageId::new(vec![22]);
        match field {
            0 => changed.welcome_id = MessageId::new(vec![]),
            1 => changed.group_id = GroupId::new(vec![1; 256]),
            2 => changed.consumed_key_package_ref = vec![1; 257],
            3 => changed.own_signature_public_key = vec![],
            4 => changed.welcomer_signature_public_key = vec![1; 257],
            5 => changed.own_account = MemberId::new(vec![1; 31]),
            _ => changed.joined_epoch = EpochId(i64::MAX as u64 + 1),
        }
        assert!(matches!(
            storage.put_accepted_welcome_receipt(&changed),
            Err(StorageError::Serialization(_))
        ));
    }
}
#[test]
fn encrypted_reopen_preserves_receipt_without_creating_engine_messages() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt.db");
    let key = SqlCipherKey::new("05".repeat(32)).unwrap();
    let original = receipt();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    storage.put_accepted_welcome_receipt(&original).unwrap();
    storage.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(
        reopened
            .accepted_welcome_receipt(&original.welcome_id)
            .unwrap()
            .unwrap()
            == original
    );
    let count: i64 = reopened
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM cgka_messages", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
    reopened.close().unwrap();
    assert!(matches!(
        reopened.accepted_welcome_receipt(&original.welcome_id),
        Err(StorageError::Closed(_))
    ));
}
