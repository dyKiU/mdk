//! Synthetic persistence acceptance; no stored fact creates a live owner.
use crate::SqliteAccountStorage;
use super::*;
use cgka_traits::{MemberId, storage::AccountDeviceSignerStorage};
use std::cell::Cell;

fn policy() -> ApprovedAccountSharingPolicy {
    ApprovedAccountSharingPolicy {
        account: [1; 32],
        local_device: [2; 32],
        peer_device: [3; 32],
        protected_group: GroupId::new(vec![5; 16]),
        approval_id: [4; 32],
        version: 1,
        capabilities: 0x0f,
        created_at: 100,
        approved_protected_epoch: 2,
        revoked: false,
    }
}
fn configure(storage: &SqliteAccountStorage) {
    storage
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO account_state(label,updated_at,local_account_id_hex) VALUES('test',0,?1)",
            [hex::encode([1; 32])],
        )
        .unwrap();
    storage
        .put_account_device_signer(&AccountDeviceSignerBinding {
            marmot_identity: MemberId::new(vec![1; 32]),
            mls_signature_public_key: vec![2; 32],
        })
        .unwrap();
}
fn stored() -> SqliteAccountStorage {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    storage
        .put_approved_account_sharing_policy(&policy(), &|| Ok(()))
        .unwrap();
    storage
}
fn group(n: u8) -> GroupId {
    GroupId::new(vec![n; 16])
}
fn fail_at_tail() -> impl Fn() -> StorageResult<()> {
    let calls = Cell::new(0);
    move || {
        calls.set(calls.get() + 1);
        if calls.get() == 2 {
            Err(invalid())
        } else {
            Ok(())
        }
    }
}
#[test]
fn sharing_policy_original_approval_is_immutable_and_revocation_permanent() {
    let storage = stored();
    let p = policy();
    let id = identity(&p).unwrap();
    storage
        .put_approved_account_sharing_policy(&p, &|| Ok(()))
        .unwrap();
    assert!(storage.approved_account_sharing_policies().unwrap() == vec![p.clone()]);
    let mut changed = p.clone();
    changed.created_at += 1;
    assert!(
        storage
            .put_approved_account_sharing_policy(&changed, &|| Ok(()))
            .is_err()
    );
    changed = p.clone();
    changed.approved_protected_epoch += 1;
    assert!(
        storage
            .put_approved_account_sharing_policy(&changed, &|| Ok(()))
            .is_err()
    );
    storage
        .revoke_account_sharing_policy(&id, &|| Ok(()))
        .unwrap();
    storage
        .revoke_account_sharing_policy(&id, &|| Ok(()))
        .unwrap();
    assert!(
        storage
            .put_approved_account_sharing_policy(&p, &|| Ok(()))
            .is_err()
    );
    assert!(
        storage
            .reserve_account_chat_sequence(&id, &group(8), &[8; 32], &|| Ok(()))
            .is_err()
    );
    let mut expected = p;
    expected.revoked = true;
    assert!(storage.approved_account_sharing_policies().unwrap() == vec![expected]);
}
#[test]
fn sharing_source_sequence_interleaves_groups_and_only_current_digest_retries() {
    let storage = stored();
    let id = identity(&policy()).unwrap();
    let reserve = |g, d| {
        storage
            .reserve_account_chat_sequence(&id, &group(g), &[d; 32], &|| Ok(()))
            .unwrap()
    };
    assert_eq!(reserve(8, 8), 1);
    assert_eq!(reserve(9, 9), 2);
    assert_eq!(reserve(8, 8), 1);
    assert_eq!(reserve(8, 7), 3);
    assert_eq!(reserve(8, 8), 4);
    assert_eq!(reserve(9, 9), 2);
    let mut another = policy();
    another.approval_id = [6; 32];
    storage
        .put_approved_account_sharing_policy(&another, &|| Ok(()))
        .unwrap();
    assert_eq!(
        storage
            .reserve_account_chat_sequence(
                &identity(&another).unwrap(),
                &group(8),
                &[8; 32],
                &|| Ok(())
            )
            .unwrap(),
        1
    );
}
#[test]
fn sharing_original_cancellation_rolls_back_approval_revocation_and_sequence() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    let id = identity(&policy()).unwrap();
    assert!(
        storage
            .put_approved_account_sharing_policy(&policy(), &fail_at_tail())
            .is_err()
    );
    assert!(
        storage
            .approved_account_sharing_policies()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM account_sharing_source_counters",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    storage
        .put_approved_account_sharing_policy(&policy(), &|| Ok(()))
        .unwrap();
    assert!(
        storage
            .reserve_account_chat_sequence(&id, &group(8), &[8; 32], &fail_at_tail())
            .is_err()
    );
    assert_eq!(
        storage
            .reserve_account_chat_sequence(&id, &group(8), &[9; 32], &|| Ok(()))
            .unwrap(),
        1
    );
    assert!(
        storage
            .revoke_account_sharing_policy(&id, &fail_at_tail())
            .is_err()
    );
    assert!(!storage.approved_account_sharing_policies().unwrap()[0].revoked);
    assert!(
        storage
            .reserve_account_chat_sequence(&id, &group(9), &[9; 32], &|| Err(invalid()))
            .is_err()
    );
    assert_eq!(
        storage
            .reserve_account_chat_sequence(&id, &group(9), &[9; 32], &|| Ok(()))
            .unwrap(),
        2
    );
}
#[test]
fn sharing_policy_encrypted_restart_retains_sequences_revocation_and_closed_owner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sharing.db");
    let key = crate::SqlCipherKey::new("42".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    configure(&storage);
    let id = identity(&policy()).unwrap();
    storage
        .put_approved_account_sharing_policy(&policy(), &|| Ok(()))
        .unwrap();
    assert_eq!(
        storage
            .reserve_account_chat_sequence(&id, &group(8), &[8; 32], &|| Ok(()))
            .unwrap(),
        1
    );
    storage.close().unwrap();
    assert!(matches!(
        storage.approved_account_sharing_policies(),
        Err(StorageError::Closed(_))
    ));
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(
        reopened
            .reserve_account_chat_sequence(&id, &group(8), &[8; 32], &|| Ok(()))
            .unwrap(),
        1
    );
    assert_eq!(
        reopened
            .reserve_account_chat_sequence(&id, &group(8), &[9; 32], &|| Ok(()))
            .unwrap(),
        2
    );
    reopened
        .revoke_account_sharing_policy(&id, &|| Ok(()))
        .unwrap();
    reopened.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(reopened.approved_account_sharing_policies().unwrap()[0].revoked);
    assert!(
        reopened
            .put_approved_account_sharing_policy(&policy(), &|| Ok(()))
            .is_err()
    );
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
fn sharing_policy_rejects_invalid_context_and_configured_owner_changes() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    assert!(
        storage
            .put_approved_account_sharing_policy(&policy(), &|| Ok(()))
            .is_err()
    );
    configure(&storage);
    for field in 0..7 {
        let mut p = policy();
        match field {
            0 => p.version = 2,
            1 => p.capabilities = 1,
            2 => p.created_at = u64::MAX,
            3 => p.approved_protected_epoch = u64::MAX,
            4 => p.revoked = true,
            5 => p.account = [7; 32],
            _ => p.local_device = [7; 32],
        };
        assert!(
            storage
                .put_approved_account_sharing_policy(&p, &|| Ok(()))
                .is_err()
        );
    }
    storage
        .put_approved_account_sharing_policy(&policy(), &|| Ok(()))
        .unwrap();
    let id = identity(&policy()).unwrap();
    assert!(
        storage
            .reserve_account_chat_sequence(&id, &group(5), &[9; 32], &|| Ok(()))
            .is_err()
    );
    assert!(
        storage
            .reserve_account_chat_sequence(&id, &group(8), &[0; 32], &|| Ok(()))
            .is_err()
    );
    assert!(
        storage
            .reserve_account_chat_sequence(&id, &GroupId::new(vec![]), &[9; 32], &|| Ok(()))
            .is_err()
    );
    storage
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_state SET local_account_id_hex=?1",
            [hex::encode([7; 32])],
        )
        .unwrap();
    assert!(storage.approved_account_sharing_policies().is_err());
    assert!(
        storage
            .revoke_account_sharing_policy(&id, &|| Ok(()))
            .is_err()
    );
    let mut other = policy();
    other.account = [7; 32];
    storage
        .put_account_device_signer(&AccountDeviceSignerBinding {
            marmot_identity: MemberId::new(vec![7; 32]),
            mls_signature_public_key: vec![2; 32],
        })
        .unwrap();
    assert!(
        storage
            .put_approved_account_sharing_policy(&other, &|| Ok(()))
            .is_err()
    );
}
#[test]
fn sharing_sql_guards_prevent_reset_replace_and_terminal_reactivation() {
    let storage = stored();
    let id = identity(&policy()).unwrap();
    storage
        .reserve_account_chat_sequence(&id, &group(8), &[8; 32], &|| Ok(()))
        .unwrap();
    let conn = storage.lock().unwrap();
    for sql in [
        "DELETE FROM approved_account_sharing_policies",
        "DELETE FROM account_sharing_source_counters",
        "DELETE FROM account_sharing_source_journal",
        "UPDATE account_sharing_source_counters SET sequence=0",
        "UPDATE account_sharing_source_journal SET sequence=2",
        "UPDATE approved_account_sharing_policies SET record=X'00'",
    ] {
        assert!(conn.execute(sql, []).is_err());
    }
    assert!(conn.execute("INSERT OR REPLACE INTO approved_account_sharing_policies(policy_id,account,local_device,record,revoked) VALUES(?1,?2,?3,?4,0)",params![id.as_slice(),[1u8;32].as_slice(),[2u8;32].as_slice(),crate::serialize(&policy()).unwrap()]).is_err());
    assert!(conn.execute("INSERT OR REPLACE INTO account_sharing_source_counters(policy_id,sequence) VALUES(?1,0)",[id.as_slice()]).is_err());
    assert!(conn.execute("INSERT OR REPLACE INTO account_sharing_source_journal(policy_id,group_id,digest,sequence) VALUES(?1,?2,?3,1)",params![id.as_slice(),group(8).as_slice(),[8u8;32].as_slice()]).is_err());
    drop(conn);
    storage
        .revoke_account_sharing_policy(&id, &|| Ok(()))
        .unwrap();
    assert!(
        storage
            .lock()
            .unwrap()
            .execute("UPDATE approved_account_sharing_policies SET revoked=0", [])
            .is_err()
    );
}
#[test]
fn sharing_policy_capacity_includes_revoked_and_sequence_overflow_is_atomic() {
    let storage = stored();
    let id = identity(&policy()).unwrap();
    storage
        .revoke_account_sharing_policy(&id, &|| Ok(()))
        .unwrap();
    for n in 1..MAX_ACCOUNT_SHARING_POLICIES {
        let mut p = policy();
        p.approval_id = [0; 32];
        p.approval_id[..2].copy_from_slice(&(n as u16).to_be_bytes());
        storage
            .put_approved_account_sharing_policy(&p, &|| Ok(()))
            .unwrap();
    }
    let mut excess = policy();
    excess.approval_id = [9; 32];
    assert!(
        storage
            .put_approved_account_sharing_policy(&excess, &|| Ok(()))
            .is_err()
    );
    assert_eq!(
        storage.approved_account_sharing_policies().unwrap().len(),
        128
    );
    let storage = stored();
    let conn = storage.lock().unwrap();
    // Fault fixture only: exercise checked overflow with no real sequence work.
    conn.execute_batch("DROP TRIGGER sharing_counter_update")
        .unwrap();
    conn.execute(
        "UPDATE account_sharing_source_counters SET sequence=9223372036854775807",
        [],
    )
    .unwrap();
    drop(conn);
    assert!(
        storage
            .reserve_account_chat_sequence(&id, &group(8), &[8; 32], &|| Ok(()))
            .is_err()
    );
    assert_eq!(
        storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM account_sharing_source_journal",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn sharing_source_journal_capacity_rolls_back_counter_and_preserves_retry() {
    let storage = stored();
    let id = identity(&policy()).unwrap();
    assert_eq!(
        storage
            .reserve_account_chat_sequence(&id, &group(8), &[8; 32], &|| Ok(()))
            .unwrap(),
        1
    );
    // Populate the remaining bounded observation references in one SQL unit;
    // no approval, counter, Group or MLS evidence is fabricated by this fixture.
    storage.connection.with_transaction(|| {
        storage.lock()?.execute("WITH RECURSIVE slots(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM slots WHERE n<8191)
          INSERT INTO account_sharing_source_journal(policy_id,group_id,digest,sequence)
          SELECT ?1,CAST(printf('%05d',n) AS BLOB),?2,1 FROM slots",
          params![id.as_slice(),[8u8;32].as_slice()]).storage()?;
        Ok::<(),StorageError>(())
    }).unwrap();
    assert!(
        storage
            .reserve_account_chat_sequence(&id, &group(9), &[9; 32], &|| Ok(()))
            .is_err()
    );
    assert_eq!(
        storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT sequence FROM account_sharing_source_counters",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        storage
            .reserve_account_chat_sequence(&id, &group(8), &[8; 32], &|| Ok(()))
            .unwrap(),
        1
    );
    assert_eq!(
        storage
            .reserve_account_chat_sequence(&id, &group(8), &[9; 32], &|| Ok(()))
            .unwrap(),
        2
    );
}
