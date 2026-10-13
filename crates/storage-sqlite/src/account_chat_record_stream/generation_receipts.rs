//! Metadata acceptance only; peer-generation authentication remains Core-owned.
use super::*;

fn staged(
    s: &SqliteAccountStorage,
    event: u8,
) -> (AccountChatRecordBatch, AccountChatRecordReceipt) {
    let b = batch(&[reserved(s, event)]);
    s.stage_account_chat_record_batch(&id(), &group(), &b, &|| Ok(()))
        .unwrap();
    let receipt = s
        .apply_account_chat_record_batch(&scope(), &group(), &b, 1, &|| Ok(()))
        .unwrap();
    (b, receipt)
}

#[test]
fn generation_receipts_do_not_promote_legacy_ack_or_restore_terminal_payload() {
    let s = stored();
    let (b, receipt) = staged(&s, 9);
    s.acknowledge_account_chat_record_batch(&id(), &group(), &receipt, &|| Ok(()))
        .unwrap();
    assert!(
        s.account_chat_record_generation_receipt(&id(), &group(), &b.batch_digest, 1, &|| Ok(()))
            .unwrap()
            .is_none()
    );
    let original = stored_batch(&s.lock().unwrap(), &id(), &group(), &b.batch_digest)
        .unwrap()
        .unwrap();
    for generation in [1, 2, 2] {
        s.acknowledge_account_chat_record_batch_for_generation(
            &id(),
            &group(),
            &receipt,
            generation,
            &|| Ok(()),
        )
        .unwrap();
        assert!(
            s.account_chat_record_generation_receipt(
                &id(),
                &group(),
                &b.batch_digest,
                generation,
                &|| Ok(())
            )
            .unwrap()
            .as_ref()
                == Some(&receipt)
        );
    }
    assert_eq!(rows(&s, "account_chat_record_generation_receipts"), 2);
    assert!(
        s.account_chat_record_generation_receipt(&id(), &group(), &b.batch_digest, 3, &|| Ok(()))
            .unwrap()
            .is_none()
    );
    let final_batch = stored_batch(&s.lock().unwrap(), &id(), &group(), &b.batch_digest)
        .unwrap()
        .unwrap();
    assert!(final_batch == original);
    assert!(final_batch.0.encoded_records.is_empty());
    assert!(
        s.pending_account_chat_record_batches(&id(), &group(), None, 128)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn generation_receipts_rollback_both_global_ack_and_metadata_at_original_tail() {
    let s = stored();
    let (b, receipt) = staged(&s, 9);
    assert!(
        s.acknowledge_account_chat_record_batch_for_generation(
            &id(),
            &group(),
            &receipt,
            1,
            &tail_failure()
        )
        .is_err()
    );
    assert_eq!(rows(&s, "account_chat_record_generation_receipts"), 0);
    assert_eq!(
        s.pending_account_chat_record_batches(&id(), &group(), None, 128)
            .unwrap()
            .len(),
        1
    );
    s.acknowledge_account_chat_record_batch_for_generation(
        &id(),
        &group(),
        &receipt,
        1,
        &|| Ok(()),
    )
    .unwrap();
    assert!(
        s.account_chat_record_generation_receipt(
            &id(),
            &group(),
            &b.batch_digest,
            1,
            &tail_failure()
        )
        .is_err()
    );
    assert!(
        s.account_chat_record_generation_receipt(&id(), &group(), &b.batch_digest, 1, &|| Err(
            invalid()
        ))
        .is_err()
    );
}

#[test]
fn generation_receipts_refuse_conflict_denial_unknown_batch_and_invalid_generation() {
    let s = stored();
    let (b, receipt) = staged(&s, 9);
    assert!(
        s.account_chat_record_generation_receipt(&id(), &group(), &[99; 32], 1, &|| Ok(()))
            .is_err()
    );
    for generation in [i64::MAX as u64 + 1, u64::MAX] {
        assert!(
            s.acknowledge_account_chat_record_batch_for_generation(
                &id(),
                &group(),
                &receipt,
                generation,
                &|| Ok(())
            )
            .is_err()
        );
        assert!(
            s.account_chat_record_generation_receipt(
                &id(),
                &group(),
                &b.batch_digest,
                generation,
                &|| Ok(())
            )
            .is_err()
        );
    }
    s.acknowledge_account_chat_record_batch_for_generation(
        &id(),
        &group(),
        &receipt,
        0,
        &|| Ok(()),
    )
    .unwrap();
    let mut conflicting = receipt.clone();
    conflicting.imported_count = 0;
    assert!(
        s.acknowledge_account_chat_record_batch_for_generation(
            &id(),
            &group(),
            &conflicting,
            1,
            &|| Ok(())
        )
        .is_err()
    );
    assert_eq!(rows(&s, "account_chat_record_generation_receipts"), 1);
    let (denied, denied_receipt) = staged(&s, 10);
    s.deny_account_chat_record_batch(&id(), &group(), &denied.batch_digest, &|| Ok(()))
        .unwrap();
    assert!(
        s.account_chat_record_generation_receipt(&id(), &group(), &denied.batch_digest, 1, &|| Ok(
            ()
        ))
        .is_err()
    );
    assert!(
        s.acknowledge_account_chat_record_batch_for_generation(
            &id(),
            &group(),
            &denied_receipt,
            1,
            &|| Ok(())
        )
        .is_err()
    );
}

#[test]
fn generation_receipts_preserve_sql_identity_against_update_delete_and_replace() {
    let s = stored();
    let (_, receipt) = staged(&s, 9);
    s.acknowledge_account_chat_record_batch_for_generation(
        &id(),
        &group(),
        &receipt,
        1,
        &|| Ok(()),
    )
    .unwrap();
    for sql in [
        "UPDATE account_chat_record_generation_receipts SET peer_generation=2",
        "DELETE FROM account_chat_record_generation_receipts",
        "INSERT OR REPLACE INTO account_chat_record_generation_receipts SELECT * FROM account_chat_record_generation_receipts",
    ] {
        assert!(s.lock().unwrap().execute(sql, []).is_err());
    }
    assert_eq!(rows(&s, "account_chat_record_generation_receipts"), 1);
}

#[test]
fn generation_receipts_check_configured_owner_and_revocation() {
    let s = stored();
    let (b, receipt) = staged(&s, 9);
    s.acknowledge_account_chat_record_batch_for_generation(
        &id(),
        &group(),
        &receipt,
        1,
        &|| Ok(()),
    )
    .unwrap();
    s.lock()
        .unwrap()
        .execute(
            "UPDATE account_state SET local_account_id_hex=?1",
            [hex::encode([99; 32])],
        )
        .unwrap();
    assert!(
        s.account_chat_record_generation_receipt(&id(), &group(), &b.batch_digest, 1, &|| Ok(()))
            .is_err()
    );
    assert!(
        s.acknowledge_account_chat_record_batch_for_generation(
            &id(),
            &group(),
            &receipt,
            2,
            &|| Ok(())
        )
        .is_err()
    );
    s.lock()
        .unwrap()
        .execute(
            "UPDATE account_state SET local_account_id_hex=?1",
            [hex::encode([1; 32])],
        )
        .unwrap();
    s.revoke_account_sharing_policy(&id(), &|| Ok(())).unwrap();
    assert!(
        s.account_chat_record_generation_receipt(&id(), &group(), &b.batch_digest, 1, &|| Ok(()))
            .is_err()
    );
    assert!(
        s.acknowledge_account_chat_record_batch_for_generation(
            &id(),
            &group(),
            &receipt,
            2,
            &|| Ok(())
        )
        .is_err()
    );
}

#[test]
fn generation_receipts_survive_encrypted_reopen_and_closed_storage_is_terminal() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("generation.sqlite");
    let key = crate::SqlCipherKey::new("24".repeat(32)).unwrap();
    let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    configure(&s);
    let (b, receipt) = staged(&s, 9);
    s.acknowledge_account_chat_record_batch_for_generation(
        &id(),
        &group(),
        &receipt,
        1,
        &|| Ok(()),
    )
    .unwrap();
    s.close().unwrap();
    assert!(matches!(
        s.account_chat_record_generation_receipt(&id(), &group(), &b.batch_digest, 1, &|| Ok(())),
        Err(StorageError::Closed(_))
    ));
    drop(s);
    let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(
        s.account_chat_record_generation_receipt(&id(), &group(), &b.batch_digest, 1, &|| Ok(()))
            .unwrap()
            .as_ref()
            == Some(&receipt)
    );
    assert!(
        s.account_chat_record_generation_receipt(&id(), &group(), &b.batch_digest, 2, &|| Ok(()))
            .unwrap()
            .is_none()
    );
    s.close().unwrap();
}

#[test]
fn generation_receipts_enforce_actual_lifetime_capacity_atomically() {
    let s = stored();
    let (_, receipt) = staged(&s, 9);
    for generation in 0..MAX_ACCOUNT_CHAT_RECORD_GENERATION_RECEIPTS as u64 {
        s.acknowledge_account_chat_record_batch_for_generation(
            &id(),
            &group(),
            &receipt,
            generation,
            &|| Ok(()),
        )
        .unwrap();
    }
    s.acknowledge_account_chat_record_batch_for_generation(
        &id(),
        &group(),
        &receipt,
        1,
        &|| Ok(()),
    )
    .unwrap();
    let (_, pending_receipt) = staged(&s, 10);
    assert!(matches!(
        s.acknowledge_account_chat_record_batch_for_generation(
            &id(),
            &group(),
            &pending_receipt,
            1,
            &|| Ok(())
        ),
        Err(StorageError::Capacity(_))
    ));
    assert_eq!(
        rows(&s, "account_chat_record_generation_receipts"),
        MAX_ACCOUNT_CHAT_RECORD_GENERATION_RECEIPTS as i64
    );
    assert_eq!(
        s.pending_account_chat_record_batches(&id(), &group(), None, 128)
            .unwrap()
            .len(),
        1
    );
    assert!(
        s.lock()
            .unwrap()
            .execute("DELETE FROM account_chat_record_generation_receipts", [])
            .is_err()
    );
}
