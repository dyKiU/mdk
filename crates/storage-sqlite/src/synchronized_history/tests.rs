use super::*;
use crate::{SqlCipherKey, StoredAppEvent};
use std::cell::Cell;

fn storage() -> SqliteAccountStorage {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    storage
        .ensure_account_projection_with_identity("test", &hex::encode([1; 32]))
        .unwrap();
    storage
}

fn record(id: u8) -> SynchronizedHistoryRecord {
    SynchronizedHistoryRecord {
        message_id: [id; 32],
        author: [7; 32],
        created_at: 100,
        kind: 9,
        payload: vec![0, 255, id],
        expires_at: None,
        deleted: false,
    }
}

fn manifest(id: u8, chunks: &[Vec<SynchronizedHistoryRecord>]) -> SynchronizedHistoryManifest {
    let binding = SynchronizedHistoryBinding {
        transfer_id: [id; 32],
        account_id: [1; 32],
        source_device: [2; 32],
        recipient_device: [3; 32],
        group_id_hex: "ab".repeat(16),
        snapshot_timestamp_ceiling: 200,
    };
    let chunk_digests = chunks
        .iter()
        .enumerate()
        .map(|(i, r)| synchronized_history_chunk_digest(&binding, i, r).unwrap())
        .collect();
    SynchronizedHistoryManifest {
        binding,
        chunk_digests,
        retain_since: 50,
        max_record_lifetime_seconds: None,
    }
}

fn import(storage: &SqliteAccountStorage, id: u8, records: Vec<SynchronizedHistoryRecord>) {
    let chunks = vec![records];
    let m = manifest(id, &chunks);
    storage.admit_synchronized_history(&m).unwrap();
    storage
        .import_synchronized_history_chunk(&m, 0, &chunks[0], 120, &|| false)
        .unwrap();
}

#[test]
fn history_import_is_atomic_idempotent_and_never_creates_mls_evidence() {
    let s = storage();
    let chunks = vec![vec![record(4), record(5)], vec![record(6)]];
    let m = manifest(9, &chunks);
    s.admit_synchronized_history(&m).unwrap();
    s.admit_synchronized_history(&m).unwrap();
    let calls = Cell::new(0);
    let cancelled = || {
        let n = calls.get() + 1;
        calls.set(n);
        n == 3
    };
    assert!(matches!(
        s.import_synchronized_history_chunk(&m, 0, &chunks[0], 120, &cancelled),
        Err(SynchronizedHistoryError::Cancelled)
    ));
    {
        let conn = s.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM synchronized_history_records",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 0,
            "cancel after the first write rolls the whole chunk back"
        );
    }
    let p = s
        .import_synchronized_history_chunk(&m, 0, &chunks[0], 120, &|| false)
        .unwrap();
    assert!(!p.complete);
    assert!(
        s.synchronized_history_page(&m.binding.group_id_hex, None, 200, 120)
            .unwrap()
            .is_empty()
    );
    let retry = s
        .import_synchronized_history_chunk(&m, 0, &chunks[0], 120, &|| false)
        .unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.next_chunk, 1);
    assert!(
        s.import_synchronized_history_chunk(&m, 1, &chunks[1], 120, &|| false)
            .unwrap()
            .complete
    );
    let rows = s
        .synchronized_history_page(&m.binding.group_id_hex, None, 200, 120)
        .unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].record.payload, vec![0, 255, 4]);
    assert_eq!(rows[0].source_device, [2; 32]);
    assert_eq!(rows[0].manifest_digest, m.digest().unwrap());
    let conn = s.lock().unwrap();
    for table in [
        "cgka_messages",
        "app_events",
        "message_timeline",
        "cgka_groups",
    ] {
        let count: i64 = conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            count, 0,
            "archive never becomes authenticated engine or projection evidence"
        );
    }
}

#[test]
fn integrity_account_recipient_order_and_total_are_bound() {
    let s = storage();
    let chunks = vec![vec![record(4)], vec![record(5)]];
    let m = manifest(9, &chunks);
    let mut wrong = m.clone();
    wrong.binding.account_id = [8; 32];
    assert!(matches!(
        s.admit_synchronized_history(&wrong),
        Err(SynchronizedHistoryError::WrongAccount)
    ));
    s.admit_synchronized_history(&m).unwrap();
    assert!(matches!(
        s.import_synchronized_history_chunk(&m, 1, &chunks[1], 120, &|| false),
        Err(SynchronizedHistoryError::OutOfOrder)
    ));
    let mut bad = chunks[0].clone();
    bad[0].payload.push(8);
    assert!(matches!(
        s.import_synchronized_history_chunk(&m, 0, &bad, 120, &|| false),
        Err(SynchronizedHistoryError::IntegrityMismatch)
    ));
    for field in 0..4 {
        let mut changed = m.clone();
        match field {
            0 => changed.binding.recipient_device = [8; 32],
            1 => changed.binding.group_id_hex = "ef".repeat(17),
            2 => changed.binding.snapshot_timestamp_ceiling = 201,
            _ => changed.chunk_digests.pop().map(|_| ()).unwrap(),
        }
        assert!(matches!(
            s.admit_synchronized_history(&changed),
            Err(SynchronizedHistoryError::TransferConflict)
        ));
    }
    let mut changed = m.clone();
    changed.chunk_digests.swap(0, 1);
    assert!(matches!(
        s.admit_synchronized_history(&changed),
        Err(SynchronizedHistoryError::TransferConflict)
    ));
    assert!(matches!(
        s.import_synchronized_history_chunk(&changed, 0, &chunks[1], 120, &|| false),
        Err(SynchronizedHistoryError::IntegrityMismatch)
    ));
}

#[test]
fn bounds_are_rejected_before_writes() {
    let s = storage();
    let chunks = vec![vec![record(4)]];
    let m = manifest(9, &chunks);
    for group in [
        String::new(),
        "ab".repeat(256),
        "AB".repeat(16),
        "z1".into(),
    ] {
        let mut bad = m.clone();
        bad.binding.group_id_hex = group;
        assert!(matches!(
            s.admit_synchronized_history(&bad),
            Err(SynchronizedHistoryError::InvalidManifest)
        ));
    }
    let mut bad = m.clone();
    bad.chunk_digests = vec![[0; 32]; 129];
    assert!(matches!(
        s.admit_synchronized_history(&bad),
        Err(SynchronizedHistoryError::LimitExceeded)
    ));
    assert!(matches!(
        synchronized_history_chunk_digest(&m.binding, 0, &vec![record(4); 201]),
        Err(SynchronizedHistoryError::LimitExceeded)
    ));
    let mut big = record(4);
    big.payload = vec![8; 65_537];
    assert!(matches!(
        synchronized_history_chunk_digest(&m.binding, 0, &[big]),
        Err(SynchronizedHistoryError::LimitExceeded)
    ));
    let mut total = record(4);
    total.payload = vec![8; 65_536];
    assert!(matches!(
        synchronized_history_chunk_digest(&m.binding, 0, &vec![total; 20]),
        Err(SynchronizedHistoryError::LimitExceeded)
    ));
    assert!(matches!(
        s.synchronized_history_page(&m.binding.group_id_hex, None, 201, 120),
        Err(SynchronizedHistoryError::LimitExceeded)
    ));
    s.admit_synchronized_history(&m).unwrap();
    assert!(matches!(
        s.import_synchronized_history_chunk(&m, 0, &chunks[0], i64::MAX as u64 + 1, &|| false),
        Err(SynchronizedHistoryError::InvalidManifest)
    ));
    assert!(
        s.synchronized_history_page(&m.binding.group_id_hex, None, 200, 120)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn live_authenticated_events_shadow_archive_in_both_arrival_orders() {
    let s = storage();
    let group = "ab".repeat(16);
    let event = |id: u8| StoredAppEvent {
        group_id_hex: group.clone(),
        message_id_hex: hex::encode([id; 32]),
        source_message_id_hex: None,
        source_epoch: None,
        direction: "received".into(),
        sender: hex::encode([7; 32]),
        plaintext: "live".into(),
        kind: 9,
        tags: vec![],
        recorded_at: 100,
        received_at: 100,
        origin_commit_id: None,
        moderation_grant: false,
    };
    s.record_app_event(&event(4)).unwrap();
    import(&s, 9, vec![record(4), record(5)]);
    let rows = s.synchronized_history_page(&group, None, 200, 120).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].record.message_id, [5; 32]);
    s.record_app_event(&event(5)).unwrap();
    assert!(
        s.synchronized_history_page(&group, None, 200, 120)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn tombstones_and_retention_never_resurrect_on_new_transfer_or_retry() {
    let s = storage();
    let group = "ab".repeat(16);
    import(&s, 9, vec![record(4)]);
    let mut dead = record(4);
    dead.deleted = true;
    dead.payload.clear();
    import(&s, 10, vec![dead]);
    import(&s, 11, vec![record(4)]);
    let rows = s.synchronized_history_page(&group, None, 200, 120).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].record.deleted);
    assert!(rows[0].record.payload.is_empty());
    let mut expires = record(5);
    expires.expires_at = Some(130);
    import(&s, 12, vec![expires]);
    assert_eq!(s.prune_synchronized_history(&group, 50, 131).unwrap(), 1);
    import(&s, 13, vec![record(5)]);
    assert_eq!(
        s.synchronized_history_page(&group, None, 200, 131)
            .unwrap()
            .len(),
        1
    );
    let mut old = record(6);
    old.created_at = 49;
    import(&s, 14, vec![old]);
    import(&s, 15, vec![record(6)]);
    assert_eq!(
        s.synchronized_history_page(&group, None, 200, 131)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn simultaneous_staging_cannot_publish_conflicting_archive_bodies() {
    let s = storage();
    let a = vec![vec![record(4)], vec![]];
    let mut forged = record(4);
    forged.payload = vec![10];
    let b = vec![vec![forged], vec![]];
    let ma = manifest(9, &a);
    let mb = manifest(10, &b);
    s.admit_synchronized_history(&ma).unwrap();
    s.admit_synchronized_history(&mb).unwrap();
    s.import_synchronized_history_chunk(&ma, 0, &a[0], 120, &|| false)
        .unwrap();
    s.import_synchronized_history_chunk(&mb, 0, &b[0], 120, &|| false)
        .unwrap();
    s.import_synchronized_history_chunk(&ma, 1, &a[1], 120, &|| false)
        .unwrap();
    assert!(matches!(
        s.import_synchronized_history_chunk(&mb, 1, &b[1], 120, &|| false),
        Err(SynchronizedHistoryError::RecordConflict)
    ));
    assert_eq!(
        s.synchronized_history_page(&ma.binding.group_id_hex, None, 200, 120)
            .unwrap()[0]
            .record
            .payload,
        vec![0, 255, 4]
    );
}

#[test]
fn progress_and_permanent_cancel_fence_survive_encrypted_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.sqlite3");
    let key = SqlCipherKey::new("11".repeat(32)).unwrap();
    let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    s.ensure_account_projection_with_identity("test", &hex::encode([1; 32]))
        .unwrap();
    let chunks = vec![vec![record(4)], vec![record(5)]];
    let m = manifest(9, &chunks);
    s.admit_synchronized_history(&m).unwrap();
    s.import_synchronized_history_chunk(&m, 0, &chunks[0], 120, &|| false)
        .unwrap();
    s.close().unwrap();
    drop(s);
    let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(
        s.import_synchronized_history_chunk(&m, 0, &chunks[0], 120, &|| false)
            .unwrap()
            .replayed
    );
    s.cancel_synchronized_history(&m.binding.transfer_id)
        .unwrap();
    s.close().unwrap();
    drop(s);
    let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(matches!(
        s.admit_synchronized_history(&m),
        Err(SynchronizedHistoryError::Cancelled)
    ));
    assert!(matches!(
        s.import_synchronized_history_chunk(&m, 1, &chunks[1], 120, &|| false),
        Err(SynchronizedHistoryError::Cancelled)
    ));
    assert!(
        s.synchronized_history_page(&m.binding.group_id_hex, None, 200, 120)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        s.lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM synchronized_history_records",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn interrupted_transfer_resumes_to_completion_after_encrypted_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.sqlite3");
    let key = SqlCipherKey::new("11".repeat(32)).unwrap();
    let chunks = vec![vec![record(4)], vec![record(5)]];
    let m = manifest(9, &chunks);
    {
        let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        s.ensure_account_projection_with_identity("test", &hex::encode([1; 32]))
            .unwrap();
        s.admit_synchronized_history(&m).unwrap();
        s.import_synchronized_history_chunk(&m, 0, &chunks[0], 120, &|| false)
            .unwrap();
        s.close().unwrap();
    }
    let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let p = s
        .import_synchronized_history_chunk(&m, 1, &chunks[1], 120, &|| false)
        .unwrap();
    assert!(p.complete);
    assert_eq!(p.next_chunk, 2);
    let first = s
        .synchronized_history_page(&m.binding.group_id_hex, None, 1, 120)
        .unwrap();
    assert_eq!(first[0].record.message_id, [4; 32]);
    let next = s
        .synchronized_history_page(
            &m.binding.group_id_hex,
            Some(&first[0].record.message_id),
            1,
            120,
        )
        .unwrap();
    assert_eq!(next[0].record.message_id, [5; 32]);
}

#[test]
fn receiving_retention_ceiling_does_not_trust_exporter_expiry() {
    let s = storage();
    let chunks = vec![vec![record(4)]];
    let mut m = manifest(9, &chunks);
    m.max_record_lifetime_seconds = Some(20);
    s.admit_synchronized_history(&m).unwrap();
    let p = s
        .import_synchronized_history_chunk(&m, 0, &chunks[0], 120, &|| false)
        .unwrap();
    assert_eq!(p.skipped_records, 1);
    import(&s, 10, vec![record(4)]);
    assert!(
        s.synchronized_history_page(&m.binding.group_id_hex, None, 200, 120)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn incomplete_retention_intents_cannot_erase_completed_history() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.sqlite3");
    let key = SqlCipherKey::new("11".repeat(32)).unwrap();
    let group = "ab".repeat(16);
    let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    s.ensure_account_projection_with_identity("test", &hex::encode([1; 32]))
        .unwrap();
    import(&s, 9, vec![record(4)]);
    let mut expired = record(4);
    expired.expires_at = Some(110);
    let chunks = vec![vec![expired.clone()], vec![]];
    let m = manifest(10, &chunks);
    s.admit_synchronized_history(&m).unwrap();
    s.import_synchronized_history_chunk(&m, 0, &chunks[0], 120, &|| false)
        .unwrap();
    assert_eq!(
        s.synchronized_history_page(&group, None, 200, 120)
            .unwrap()
            .len(),
        1
    );
    s.cancel_synchronized_history(&m.binding.transfer_id)
        .unwrap();
    s.close().unwrap();
    drop(s);
    let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(
        s.synchronized_history_page(&group, None, 200, 120)
            .unwrap()
            .len(),
        1
    );
    let done = manifest(11, &chunks);
    s.admit_synchronized_history(&done).unwrap();
    s.import_synchronized_history_chunk(&done, 0, &chunks[0], 120, &|| false)
        .unwrap();
    assert_eq!(
        s.synchronized_history_page(&group, None, 200, 120)
            .unwrap()
            .len(),
        1
    );
    s.import_synchronized_history_chunk(&done, 1, &chunks[1], 120, &|| false)
        .unwrap();
    assert!(
        s.synchronized_history_page(&group, None, 200, 120)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn overlapping_snapshot_retention_only_tightens_without_content_conflict() {
    let s = storage();
    let chunks = vec![vec![record(4)]];
    let group = "ab".repeat(16);
    import(&s, 9, chunks[0].clone());
    let mut shorter = manifest(10, &chunks);
    shorter.max_record_lifetime_seconds = Some(30);
    s.admit_synchronized_history(&shorter).unwrap();
    s.import_synchronized_history_chunk(&shorter, 0, &chunks[0], 120, &|| false)
        .unwrap();
    let rows = s.synchronized_history_page(&group, None, 200, 120).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].record.expires_at, Some(130));
    import(&s, 11, chunks[0].clone());
    assert_eq!(
        s.synchronized_history_page(&group, None, 200, 120).unwrap()[0]
            .record
            .expires_at,
        Some(130)
    );
    assert!(
        s.synchronized_history_page(&group, None, 200, 131)
            .unwrap()
            .is_empty()
    );
    let before: i64 = s
        .lock()
        .unwrap()
        .query_row(
            "SELECT sum(charged_bytes) FROM synchronized_history_transfers",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(before > 0);
    s.prune_synchronized_history(&group, 50, 131).unwrap();
    let after: i64 = s
        .lock()
        .unwrap()
        .query_row(
            "SELECT sum(charged_bytes) FROM synchronized_history_transfers",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(after, 0);
}

#[test]
fn retention_prune_cannot_publish_incomplete_expiry_policy() {
    let s = storage();
    let group = "ab".repeat(16);
    import(&s, 9, vec![record(4)]);
    let mut staged = record(4);
    staged.expires_at = Some(130);
    let chunks = vec![vec![staged], vec![]];
    let m = manifest(10, &chunks);
    s.admit_synchronized_history(&m).unwrap();
    s.import_synchronized_history_chunk(&m, 0, &chunks[0], 120, &|| false)
        .unwrap();
    assert_eq!(s.prune_synchronized_history(&group, 50, 140).unwrap(), 0);
    assert_eq!(
        s.synchronized_history_page(&group, None, 200, 140)
            .unwrap()
            .len(),
        1
    );
    s.cancel_synchronized_history(&m.binding.transfer_id)
        .unwrap();
    assert_eq!(
        s.synchronized_history_page(&group, None, 200, 140)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn capped_archive_admission_keeps_durable_cancel_receipts() {
    let s = storage();
    let chunks = vec![vec![]];
    for id in 0..128 {
        s.admit_synchronized_history(&manifest(id, &chunks))
            .unwrap();
    }
    s.cancel_synchronized_history(&[0; 32]).unwrap();
    assert!(matches!(
        s.admit_synchronized_history(&manifest(0, &chunks)),
        Err(SynchronizedHistoryError::Cancelled)
    ));
    assert!(matches!(
        s.admit_synchronized_history(&manifest(200, &chunks)),
        Err(SynchronizedHistoryError::LimitExceeded)
    ));
}
