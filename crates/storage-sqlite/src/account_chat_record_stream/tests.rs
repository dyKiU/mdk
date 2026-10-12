//! Synthetic SQL acceptance; original channel authentication remains Core-owned.
#[path = "generation_receipts.rs"]
mod generation_receipts;
use super::*;
use cgka_traits::{
    MemberId,
    approved_account_sharing_policy::*,
    group::ProtocolProfile,
    mirrored_chat_catalog::{MirroredChatCatalogStorage, MirroredChatEntry, MirroredChatState},
    storage::{AccountDeviceSignerBinding, AccountDeviceSignerStorage, GroupStorage},
};
use std::cell::Cell;

fn group() -> GroupId {
    GroupId::new(vec![8; 16])
}
fn fact() -> ApprovedAccountSharingPolicy {
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
fn id() -> [u8; 32] {
    let p = fact();
    approved_account_sharing_identity(
        &p.account,
        &p.protected_group,
        &p.local_device,
        &p.peer_device,
        &p.approval_id,
    )
    .unwrap()
}
fn scope() -> MirroredChatScope {
    let p = fact();
    MirroredChatScope {
        account: p.account,
        local_device: p.local_device,
        source_device: p.peer_device,
        policy_digest: id(),
        protected_group: p.protected_group,
        protected_generation: 1,
    }
}
fn configure(s: &SqliteAccountStorage) {
    s.lock()
        .unwrap()
        .execute(
            "INSERT INTO account_state(label,updated_at,local_account_id_hex) VALUES('test',0,?1)",
            [hex::encode([1; 32])],
        )
        .unwrap();
    s.put_account_device_signer(&AccountDeviceSignerBinding {
        marmot_identity: MemberId::new(vec![1; 32]),
        mls_signature_public_key: vec![2; 32],
    })
    .unwrap();
    s.put_approved_account_sharing_policy(&fact(), &|| Ok(()))
        .unwrap();
    s.apply_mirrored_chat_catalog(
        &scope(),
        &[MirroredChatEntry {
            group_id: group(),
            source_epoch: 1,
            source_sequence: 1,
            source_digest: [8; 32],
            profile: ProtocolProfile::Current,
            name: "shared".into(),
            description: String::new(),
            state: MirroredChatState::Active,
        }],
        &|| Ok(()),
    )
    .unwrap();
}
fn stored() -> SqliteAccountStorage {
    let s = SqliteAccountStorage::in_memory().unwrap();
    configure(&s);
    s
}
fn record(event: u8, seq: u64) -> MirroredChatRecord {
    let payload = serde_json::to_vec(&("synthetic", Vec::<Vec<String>>::new())).unwrap();
    MirroredChatRecord {
        event_id: [event; 32],
        author: [7; 32],
        created_at: 10,
        kind: 9,
        content_digest: Some(Sha256::digest(&payload).into()),
        payload,
        expires_at: None,
        deleted: false,
        source_epoch: 1,
        source_sequence: seq,
        source_digest: [event; 32],
    }
}
fn batch(records: &[MirroredChatRecord]) -> AccountChatRecordBatch {
    let bytes = serde_json::to_vec(records).unwrap();
    AccountChatRecordBatch {
        batch_digest: Sha256::digest(&bytes).into(),
        first_sequence: records.first().unwrap().source_sequence,
        last_sequence: records.last().unwrap().source_sequence,
        record_count: records.len() as u32,
        encoded_records: bytes,
    }
}
fn reserved(s: &SqliteAccountStorage, event: u8) -> MirroredChatRecord {
    let seq = s
        .reserve_account_chat_record_sequence(&id(), &group(), &[event; 32], &[event; 32], &|| {
            Ok(())
        })
        .unwrap();
    record(event, seq)
}
fn tail_failure() -> impl Fn() -> StorageResult<()> {
    let n = Cell::new(0);
    move || {
        n.set(n.get() + 1);
        if n.get() == 2 { Err(invalid()) } else { Ok(()) }
    }
}
fn rows(s: &SqliteAccountStorage, table: &str) -> i64 {
    s.lock()
        .unwrap()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn record_stream_journal_is_independent_and_retries_only_current_attestation() {
    let s = stored();
    let event = [9; 32];
    assert_eq!(
        s.reserve_account_chat_sequence(&id(), &group(), &[8; 32], &|| Ok(()))
            .unwrap(),
        1
    );
    assert_eq!(
        s.reserve_account_chat_record_sequence(&id(), &group(), &event, &[8; 32], &|| Ok(()))
            .unwrap(),
        1
    );
    assert_eq!(
        s.reserve_account_chat_record_sequence(&id(), &group(), &event, &[8; 32], &|| Ok(()))
            .unwrap(),
        1
    );
    assert_eq!(
        s.reserve_account_chat_record_sequence(&id(), &group(), &event, &[7; 32], &|| Ok(()))
            .unwrap(),
        2
    );
    assert_eq!(
        s.reserve_account_chat_record_sequence(&id(), &group(), &event, &[8; 32], &|| Ok(()))
            .unwrap(),
        3
    );
    assert!(
        s.reserve_account_chat_record_sequence(
            &id(),
            &group(),
            &[10; 32],
            &[8; 32],
            &tail_failure()
        )
        .is_err()
    );
    assert_eq!(
        s.reserve_account_chat_record_sequence(&id(), &group(), &[10; 32], &[8; 32], &|| Ok(()))
            .unwrap(),
        4
    );
    assert_eq!(
        s.reserve_account_chat_sequence(&id(), &group(), &[7; 32], &|| Ok(()))
            .unwrap(),
        2
    );
}

#[test]
fn record_stream_outbox_retries_exact_bytes_until_matching_committed_receipt() {
    let s = stored();
    let b = batch(&[reserved(&s, 9)]);
    assert!(
        s.stage_account_chat_record_batch(&id(), &group(), &b, &tail_failure())
            .is_err()
    );
    assert_eq!(rows(&s, "account_chat_record_outbox"), 0);
    s.stage_account_chat_record_batch(&id(), &group(), &b, &|| Ok(()))
        .unwrap();
    s.stage_account_chat_record_batch(&id(), &group(), &b, &|| Ok(()))
        .unwrap();
    assert!(
        s.pending_account_chat_record_batches(&id(), &group(), None, 1)
            .unwrap()
            == vec![b.clone()]
    );
    let receipt = s
        .apply_account_chat_record_batch(&scope(), &group(), &b, 1, &|| Ok(()))
        .unwrap();
    let mut wrong = receipt.clone();
    wrong.last_sequence += 1;
    assert!(
        s.acknowledge_account_chat_record_batch(&id(), &group(), &wrong, &|| Ok(()))
            .is_err()
    );
    assert!(
        s.acknowledge_account_chat_record_batch(&id(), &group(), &receipt, &tail_failure())
            .is_err()
    );
    assert_eq!(
        s.pending_account_chat_record_batches(&id(), &group(), None, 1)
            .unwrap()
            .len(),
        1
    );
    s.acknowledge_account_chat_record_batch(&id(), &group(), &receipt, &|| Ok(()))
        .unwrap();
    s.acknowledge_account_chat_record_batch(&id(), &group(), &receipt, &|| Ok(()))
        .unwrap();
    s.stage_account_chat_record_batch(&id(), &group(), &b, &|| Ok(()))
        .unwrap();
    assert!(
        s.pending_account_chat_record_batches(&id(), &group(), None, 1)
            .unwrap()
            .is_empty()
    );
    let payload: i64 = s
        .lock()
        .unwrap()
        .query_row(
            "SELECT length(payload) FROM account_chat_record_outbox",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(payload, 0);
    wrong = receipt;
    wrong.imported_count = 0;
    assert!(
        s.acknowledge_account_chat_record_batch(&id(), &group(), &wrong, &|| Ok(()))
            .is_err()
    );
}

#[test]
fn record_stream_apply_receipt_and_progress_are_atomic_and_out_of_order_safe() {
    let s = stored();
    let late = batch(&[record(9, 20)]);
    let early = batch(&[record(8, 2)]);
    assert!(
        s.apply_account_chat_record_batch(&scope(), &group(), &late, 1, &tail_failure())
            .is_err()
    );
    for table in [
        "mirrored_chat_messages",
        "account_chat_record_receipts",
        "account_chat_record_progress",
    ] {
        assert_eq!(rows(&s, table), 0);
    }
    let first = s
        .apply_account_chat_record_batch(&scope(), &group(), &late, 1, &|| Ok(()))
        .unwrap();
    assert_eq!(first.imported_count, 1);
    assert!(
        s.apply_account_chat_record_batch(&scope(), &group(), &late, 1, &|| Ok(()))
            .unwrap()
            == first
    );
    assert_eq!(
        s.apply_account_chat_record_batch(&scope(), &group(), &early, 1, &|| Ok(()))
            .unwrap()
            .imported_count,
        1
    );
    let seq: i64 = s
        .lock()
        .unwrap()
        .query_row(
            "SELECT sequence FROM account_chat_record_progress",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(seq, 20);
    let mut renewed = scope();
    renewed.protected_generation += 1;
    s.apply_mirrored_chat_catalog(
        &renewed,
        &[MirroredChatEntry {
            group_id: group(),
            source_epoch: 1,
            source_sequence: 1,
            source_digest: [8; 32],
            profile: ProtocolProfile::Current,
            name: "shared".into(),
            description: String::new(),
            state: MirroredChatState::Active,
        }],
        &|| Ok(()),
    )
    .unwrap();
    assert!(
        s.apply_account_chat_record_batch(&renewed, &group(), &late, 1, &|| Ok(()))
            .unwrap()
            == first
    );
    assert_eq!(
        s.mirrored_chat_message_page(&renewed, &group(), None, 128, 1)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(rows(&s, "account_chat_record_receipts"), 2);
    assert_eq!(rows(&s, "mirrored_chat_messages"), 3);
    assert!(s.list_group_records().unwrap().is_empty());
    assert_eq!(rows(&s, "app_events"), 0);
    s.lock().unwrap().execute_batch("CREATE TRIGGER synthetic_receipt_failure BEFORE INSERT ON account_chat_record_receipts BEGIN SELECT RAISE(ABORT,'synthetic'); END;").unwrap();
    assert!(
        s.apply_account_chat_record_batch(&scope(), &group(), &batch(&[record(7, 30)]), 1, &|| Ok(
            ()
        ))
        .is_err()
    );
    assert_eq!(rows(&s, "mirrored_chat_messages"), 3);
}

#[test]
fn record_stream_canonical_bounds_and_unreserved_outbox_are_refused() {
    let s = stored();
    let b = batch(&[record(9, 1)]);
    assert!(
        s.stage_account_chat_record_batch(&id(), &group(), &b, &|| Ok(()))
            .is_err()
    );
    let mut noncanonical = b.clone();
    noncanonical.encoded_records.push(b' ');
    noncanonical.batch_digest = Sha256::digest(&noncanonical.encoded_records).into();
    assert!(
        s.apply_account_chat_record_batch(&scope(), &group(), &noncanonical, 1, &|| Ok(()))
            .is_err()
    );
    let mut bad = b.clone();
    bad.record_count = 2;
    assert!(
        s.apply_account_chat_record_batch(&scope(), &group(), &bad, 1, &|| Ok(()))
            .is_err()
    );
    bad = b.clone();
    bad.first_sequence = 0;
    assert!(
        s.apply_account_chat_record_batch(&scope(), &group(), &bad, 1, &|| Ok(()))
            .is_err()
    );
    bad = b;
    bad.batch_digest = [0; 32];
    assert!(
        s.apply_account_chat_record_batch(&scope(), &group(), &bad, 1, &|| Ok(()))
            .is_err()
    );
    assert!(
        s.apply_account_chat_record_batch(
            &scope(),
            &group(),
            &batch(&[record(8, 2), record(9, 1)]),
            1,
            &|| Ok(())
        )
        .is_err()
    );
    assert!(
        s.apply_account_chat_record_batch(
            &scope(),
            &group(),
            &batch(&[record(8, 1), record(8, 2)]),
            1,
            &|| Ok(())
        )
        .is_err()
    );
}

#[test]
fn record_stream_terminal_sql_fences_and_revoked_owner_survive() {
    let s = stored();
    let b = batch(&[reserved(&s, 9)]);
    s.stage_account_chat_record_batch(&id(), &group(), &b, &|| Ok(()))
        .unwrap();
    s.apply_account_chat_record_batch(&scope(), &group(), &b, 1, &|| Ok(()))
        .unwrap();
    for sql in [
        "DELETE FROM account_chat_record_journal",
        "DELETE FROM account_chat_record_outbox",
        "DELETE FROM account_chat_record_receipts",
        "DELETE FROM account_chat_record_progress",
        "UPDATE account_chat_record_receipts SET record=X'01'",
        "UPDATE account_chat_record_journal SET sequence=1",
        "UPDATE account_chat_record_progress SET sequence=1",
    ] {
        assert!(s.lock().unwrap().execute(sql, []).is_err());
    }
    let mut wrong = scope();
    wrong.source_device = [6; 32];
    assert!(
        s.apply_account_chat_record_batch(&wrong, &group(), &b, 1, &|| Ok(()))
            .is_err()
    );
    s.revoke_account_sharing_policy(&id(), &|| Ok(())).unwrap();
    assert!(
        s.pending_account_chat_record_batches(&id(), &group(), None, 1)
            .is_err()
    );
    assert!(
        s.apply_account_chat_record_batch(&scope(), &group(), &b, 1, &|| Ok(()))
            .is_err()
    );
    assert!(
        s.reserve_account_chat_record_sequence(&id(), &group(), &[8; 32], &[8; 32], &|| Ok(()))
            .is_err()
    );
}

#[test]
fn record_stream_encrypted_restart_retains_ack_and_close_is_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("records.db");
    let key = crate::SqlCipherKey::new("11".repeat(32)).unwrap();
    let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    configure(&s);
    let b = batch(&[reserved(&s, 9)]);
    s.stage_account_chat_record_batch(&id(), &group(), &b, &|| Ok(()))
        .unwrap();
    let receipt = s
        .apply_account_chat_record_batch(&scope(), &group(), &b, 1, &|| Ok(()))
        .unwrap();
    drop(s);
    let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(
        s.apply_account_chat_record_batch(&scope(), &group(), &b, 1, &|| Ok(()))
            .unwrap()
            == receipt
    );
    assert!(
        s.pending_account_chat_record_batches(&id(), &group(), None, 1)
            .unwrap()
            == vec![b]
    );
    s.acknowledge_account_chat_record_batch(&id(), &group(), &receipt, &|| Ok(()))
        .unwrap();
    drop(s);
    let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(
        s.pending_account_chat_record_batches(&id(), &group(), None, 1)
            .unwrap()
            .is_empty()
    );
    s.close().unwrap();
    assert!(matches!(
        s.pending_account_chat_record_batches(&id(), &group(), None, 1),
        Err(StorageError::Closed(_))
    ));
}

#[test]
fn record_stream_actual_lifetime_and_active_byte_limits_return_typed_capacity() {
    // Populate actual bounded SQL metadata, without pretending synthetic rows
    // are genuine channel attestations or running 100,000 network operations.
    let s = stored();
    let b = batch(&[reserved(&s, 9)]);
    s.lock().unwrap().execute(
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<99999)
         INSERT INTO account_chat_record_journal SELECT ?1,?2,CAST(printf('%032x',x) AS BLOB),?3,1 FROM n",
        params![id().as_slice(),group().as_slice(),[7u8;32].as_slice()],
    ).unwrap();
    assert_eq!(
        rows(&s, "account_chat_record_journal"),
        MAX_ACCOUNT_CHAT_RECORD_JOURNAL as i64
    );
    assert!(matches!(
        s.reserve_account_chat_record_sequence(&id(), &group(), &[10; 32], &[10; 32], &|| Ok(())),
        Err(StorageError::Capacity(_))
    ));

    let bytes = stored();
    let b_bytes = batch(&[reserved(&bytes, 9)]);
    bytes.lock().unwrap().execute(
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<64)
         INSERT INTO account_chat_record_outbox SELECT ?1,?2,CAST(printf('%032x',x) AS BLOB),1,1,1,zeroblob(1048576),NULL,0 FROM n",
        params![id().as_slice(),group().as_slice()],
    ).unwrap();
    let actual: i64 = bytes
        .lock()
        .unwrap()
        .query_row(
            "SELECT sum(length(payload)) FROM account_chat_record_outbox",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(actual, MAX_ACCOUNT_CHAT_RECORD_OUTBOX_BYTES as i64);
    assert!(matches!(
        bytes.stage_account_chat_record_batch(&id(), &group(), &b_bytes, &|| Ok(())),
        Err(StorageError::Capacity(_))
    ));

    let count = stored();
    let b_count = batch(&[reserved(&count, 9)]);
    count.lock().unwrap().execute(
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096)
         INSERT INTO account_chat_record_outbox SELECT ?1,?2,CAST(printf('%032x',x) AS BLOB),1,1,1,X'01',NULL,0 FROM n",
        params![id().as_slice(),group().as_slice()],
    ).unwrap();
    assert_eq!(
        rows(&count, "account_chat_record_outbox"),
        MAX_ACCOUNT_CHAT_RECORD_OUTBOX as i64
    );
    assert!(matches!(
        count.stage_account_chat_record_batch(&id(), &group(), &b_count, &|| Ok(())),
        Err(StorageError::Capacity(_))
    ));

    let key = id();
    s.lock().unwrap().execute(
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<8192)
         INSERT INTO account_chat_record_receipts SELECT ?1,?2,CAST(printf('%032x',x) AS BLOB),X'01' FROM n",
        params![key,group().as_slice()],
    ).unwrap();
    assert_eq!(
        rows(&s, "account_chat_record_receipts"),
        MAX_ACCOUNT_CHAT_RECORD_RECEIPTS as i64
    );
    assert!(matches!(
        s.apply_account_chat_record_batch(&scope(), &group(), &b, 1, &|| Ok(())),
        Err(StorageError::Capacity(_))
    ));
    assert_eq!(rows(&s, "mirrored_chat_messages"), 0);
}

#[test]
fn record_stream_source_denial_erases_bytes_without_claiming_delivery_or_reopening() {
    let s = stored();
    let original = reserved(&s, 9);
    let old = batch(std::slice::from_ref(&original));
    s.stage_account_chat_record_batch(&id(), &group(), &old, &|| Ok(()))
        .unwrap();
    assert!(
        s.deny_account_chat_record_batch(&id(), &group(), &old.batch_digest, &tail_failure())
            .is_err()
    );
    assert_eq!(
        s.pending_account_chat_record_batches(&id(), &group(), None, 1)
            .unwrap()
            .len(),
        1
    );
    s.deny_account_chat_record_batch(&id(), &group(), &old.batch_digest, &|| Ok(()))
        .unwrap();
    s.deny_account_chat_record_batch(&id(), &group(), &old.batch_digest, &|| Ok(()))
        .unwrap();
    assert!(
        s.stage_account_chat_record_batch(&id(), &group(), &old, &|| Ok(()))
            .is_err()
    );
    let late = AccountChatRecordReceipt {
        batch_digest: old.batch_digest,
        first_sequence: old.first_sequence,
        last_sequence: old.last_sequence,
        record_count: old.record_count,
        imported_count: 1,
    };
    assert!(
        s.acknowledge_account_chat_record_batch(&id(), &group(), &late, &|| Ok(()))
            .is_err()
    );
    let mut terminal = original;
    terminal.deleted = true;
    terminal.payload.clear();
    terminal.source_digest = [10; 32];
    terminal.source_sequence = s
        .reserve_account_chat_record_sequence(
            &id(),
            &group(),
            &terminal.event_id,
            &terminal.source_digest,
            &|| Ok(()),
        )
        .unwrap();
    let new = batch(&[terminal]);
    s.stage_account_chat_record_batch(&id(), &group(), &new, &|| Ok(()))
        .unwrap();
    assert!(
        s.pending_account_chat_record_batches(&id(), &group(), None, 1)
            .unwrap()
            == vec![new.clone()]
    );
    s.revoke_account_sharing_policy(&id(), &|| Ok(())).unwrap();
    s.deny_account_chat_record_batch(&id(), &group(), &new.batch_digest, &|| Ok(()))
        .unwrap();
    let (bytes, receipts): (i64, i64) = s
        .lock()
        .unwrap()
        .query_row(
            "SELECT sum(length(payload)),sum(receipt IS NOT NULL) FROM account_chat_record_outbox",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((bytes, receipts), (0, 0));
    assert_eq!(rows(&s, "account_chat_record_outbox"), 2);
}

#[test]
fn record_stream_outbox_digest_paging_reaches_every_pending_batch() {
    let s = stored();
    for event in 1..=130 {
        let b = batch(&[reserved(&s, event)]);
        s.stage_account_chat_record_batch(&id(), &group(), &b, &|| Ok(()))
            .unwrap();
    }
    let first = s
        .pending_account_chat_record_batches(&id(), &group(), None, 128)
        .unwrap();
    assert_eq!(first.len(), 128);
    let second = s
        .pending_account_chat_record_batches(
            &id(),
            &group(),
            Some(&first.last().unwrap().batch_digest),
            128,
        )
        .unwrap();
    assert_eq!(second.len(), 2);
    let mut ids = HashSet::new();
    for b in first.into_iter().chain(second) {
        assert!(ids.insert(b.batch_digest));
    }
    assert_eq!(ids.len(), 130);
}
