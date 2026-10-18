//! Synthetic logical-store acceptance. Actual source authentication stays Core-owned.
use super::*;
use crate::SqliteAccountStorage;
use cgka_traits::{
    MemberId,
    group::ProtocolProfile,
    mirrored_chat_catalog::{MirroredChatCatalogStorage, MirroredChatEntry, MirroredChatState},
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
fn group() -> GroupId {
    GroupId::new(vec![8; 16])
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
fn catalog(storage: &SqliteAccountStorage, s: &MirroredChatScope) {
    storage
        .apply_mirrored_chat_catalog(
            s,
            &[MirroredChatEntry {
                group_id: group(),
                source_epoch: 1,
                source_sequence: 1,
                source_digest: [8; 32],
                profile: ProtocolProfile::Current,
                name: "shared".into(),
                description: String::new(),
                state: MirroredChatState::Active,

                accepted_origin: None,

                same_account_source_count: None,

                direct_peer_account: None,
            }],
            &|| Ok(()),
        )
        .unwrap();
}
fn stored() -> SqliteAccountStorage {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    catalog(&storage, &scope());
    storage
}
fn record(id: u8, sequence: u64) -> MirroredChatRecord {
    let payload = serde_json::to_vec(&("test", vec![vec!["p", "synthetic"]])).unwrap();
    MirroredChatRecord {
        event_id: [id; 32],
        author: [7; 32],
        created_at: 10,
        kind: 9,
        content_digest: Some(Sha256::digest(&payload).into()),
        payload,
        expires_at: None,
        deleted: false,
        source_epoch: 1,
        source_sequence: sequence,
        source_digest: [id; 32],

        accepted_origin: None,
    }
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
fn apply(storage: &SqliteAccountStorage, r: &[MirroredChatRecord]) -> StorageResult<usize> {
    storage.apply_mirrored_chat_messages(&scope(), &group(), r, 1, &|| Ok(()))
}
fn page(storage: &SqliteAccountStorage, now: u64) -> Vec<MirroredChatRecord> {
    storage
        .mirrored_chat_message_page(&scope(), &group(), None, 128, now)
        .unwrap()
}
#[test]
fn mirrored_messages_exact_retry_and_chronological_page_keep_logical_tags_only() {
    let storage = stored();
    let mut earlier = record(9, 1);
    earlier.created_at = 9;
    let records = [record(8, 2), record(7, 3), earlier.clone()];
    assert_eq!(apply(&storage, &records).unwrap(), 3);
    assert_eq!(apply(&storage, &records).unwrap(), 0);
    let first = storage
        .mirrored_chat_message_page(&scope(), &group(), None, 1, 1)
        .unwrap();
    assert!(first == vec![earlier]);
    let after = MirroredChatCursor {
        created_at: first[0].created_at,
        event_id: first[0].event_id,
    };
    assert!(
        storage
            .mirrored_chat_message_page(&scope(), &group(), Some(&after), 128, 1)
            .unwrap()
            == vec![record(7, 3), record(8, 2)]
    );
    assert!(storage.list_group_records().unwrap().is_empty());
    assert_eq!(
        storage
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM app_events", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(
        serde_json::from_slice::<(String, Vec<Vec<String>>)>(&first[0].payload)
            .unwrap()
            .1
            == vec![vec!["p", "synthetic"]]
    );
}
#[test]
fn mirrored_messages_body_conflicts_and_original_cancellation_roll_back_batch() {
    let storage = stored();
    apply(&storage, &[record(8, 1)]).unwrap();
    let mut conflict = record(8, 2);
    conflict.payload = serde_json::to_vec(&("changed", Vec::<Vec<String>>::new())).unwrap();
    conflict.content_digest = Some(Sha256::digest(&conflict.payload).into());
    assert!(apply(&storage, &[record(9, 3), conflict]).is_err());
    assert!(page(&storage, 1) == vec![record(8, 1)]);
    assert!(
        storage
            .apply_mirrored_chat_messages(&scope(), &group(), &[record(9, 3)], 1, &fail_at_tail())
            .is_err()
    );
    assert!(page(&storage, 1) == vec![record(8, 1)]);
    assert!(
        storage
            .apply_mirrored_chat_messages(
                &scope(),
                &group(),
                &[record(9, 3)],
                1,
                &|| Err(invalid())
            )
            .is_err()
    );
}
#[test]
fn mirrored_messages_terminal_before_body_fences_all_sources_policies_and_renewals() {
    let storage = stored();
    let mut terminal = record(8, 1);
    terminal.deleted = true;
    terminal.payload.clear();
    terminal.content_digest = None;
    apply(&storage, &[terminal.clone()]).unwrap();
    assert!(apply(&storage, &[record(8, 2)]).is_err());
    let mut renewed = scope();
    renewed.protected_generation = 2;
    renewed.policy_digest = [6; 32];
    catalog(&storage, &renewed);
    assert!(
        storage
            .apply_mirrored_chat_messages(&renewed, &group(), &[record(8, 3)], 1, &|| Ok(()))
            .is_err()
    );
    renewed.source_device = [9; 32];
    catalog(&storage, &renewed);
    assert!(
        storage
            .apply_mirrored_chat_messages(&renewed, &group(), &[record(8, 3)], 1, &|| Ok(()))
            .is_err()
    );
    assert!(page(&storage, 1) == vec![terminal]);
    // Independent source body imported before a deletion becomes invisible.
    storage
        .apply_mirrored_chat_messages(&renewed, &group(), &[record(9, 3)], 1, &|| Ok(()))
        .unwrap();
    let mut deleted = record(9, 4);
    deleted.deleted = true;
    deleted.payload.clear();
    apply(&storage, &[deleted]).unwrap();
    assert!(
        storage
            .mirrored_chat_message_page(&renewed, &group(), None, 128, 1)
            .unwrap()
            .is_empty()
    );
}
#[test]
fn mirrored_messages_retention_only_tightens_and_purge_keeps_replay_fence() {
    let storage = stored();
    let mut original = record(8, 1);
    original.expires_at = Some(20);
    apply(&storage, &[original.clone()]).unwrap();
    let mut renewed = original.clone();
    renewed.expires_at = None;
    renewed.source_sequence = 2;
    apply(&storage, &[renewed]).unwrap();
    assert_eq!(page(&storage, 1)[0].expires_at, Some(20));
    let view = page(&storage, 20);
    assert!(view[0].deleted && view[0].payload.is_empty());
    assert!(
        storage
            .purge_expired_mirrored_chat_messages(&scope(), &group(), 20, 1, &fail_at_tail())
            .is_err()
    );
    assert_eq!(
        storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT length(payload) FROM mirrored_chat_messages",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        original.payload.len() as i64
    );
    assert_eq!(
        storage
            .purge_expired_mirrored_chat_messages(&scope(), &group(), 20, 1, &|| Ok(()))
            .unwrap(),
        1
    );
    assert_eq!(
        storage
            .purge_expired_mirrored_chat_messages(&scope(), &group(), 20, 1, &|| Ok(()))
            .unwrap(),
        0
    );
    let tombstone = page(&storage, 1).remove(0);
    assert!(tombstone.deleted && tombstone.payload.is_empty());
    assert_eq!(tombstone.source_sequence, 2);
    assert_eq!(tombstone.content_digest, original.content_digest);
    let mut attempt = original;
    attempt.source_sequence = 3;
    attempt.expires_at = None;
    assert!(apply(&storage, &[attempt]).is_err());
}
#[test]
fn mirrored_messages_source_replays_epochs_and_cross_source_immutable_identity() {
    let storage = stored();
    let mut latest = record(8, 2);
    latest.source_epoch = 2;
    apply(&storage, &[latest.clone()]).unwrap();
    assert_eq!(apply(&storage, &[record(8, 1)]).unwrap(), 0);
    assert!(apply(&storage, &[record(8, 3)]).is_err());
    let mut conflict = latest.clone();
    conflict.author = [9; 32];
    assert!(apply(&storage, &[conflict]).is_err());
    let mut source = scope();
    source.source_device = [9; 32];
    catalog(&storage, &source);
    let mut copy = latest.clone();
    copy.source_sequence = 1;
    copy.source_epoch = 1;
    storage
        .apply_mirrored_chat_messages(&source, &group(), &[copy.clone()], 1, &|| Ok(()))
        .unwrap();
    copy.author = [6; 32];
    copy.source_sequence = 2;
    assert!(
        storage
            .apply_mirrored_chat_messages(&source, &group(), &[copy], 1, &|| Ok(()))
            .is_err()
    );
    assert!(page(&storage, 1) == vec![latest]);
}
#[test]
fn mirrored_messages_encrypted_restart_retains_body_and_terminal_close_is_final() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("messages.db");
    let key = crate::SqlCipherKey::new("42".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    configure(&storage);
    catalog(&storage, &scope());
    apply(&storage, &[record(8, 1)]).unwrap();
    storage.close().unwrap();
    assert!(matches!(
        storage.mirrored_chat_message_page(&scope(), &group(), None, 128, 1),
        Err(StorageError::Closed(_))
    ));
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(page(&reopened, 1) == vec![record(8, 1)]);
    let mut terminal = record(8, 2);
    terminal.deleted = true;
    terminal.payload.clear();
    apply(&reopened, &[terminal.clone()]).unwrap();
    reopened.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(page(&reopened, 1) == vec![terminal]);
    assert!(apply(&reopened, &[record(8, 3)]).is_err());
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
fn mirrored_messages_require_active_catalog_valid_body_and_configured_owner() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    assert!(apply(&storage, &[record(8, 1)]).is_err());
    catalog(&storage, &scope());
    for n in 0..6 {
        let mut r = record(8, 1);
        match n {
            0 => r.content_digest = None,
            1 => r.content_digest = Some([1; 32]),
            2 => r.payload.clear(),
            3 => r.created_at = u64::MAX,
            4 => r.source_sequence = 0,
            _ => r.deleted = true,
        };
        assert!(apply(&storage, &[r]).is_err());
    }
    assert!(apply(&storage, &[]).is_err());
    assert!(apply(&storage, &[record(8, 1), record(8, 2)]).is_err());
    assert!(apply(&storage, &vec![record(8, 1); 129]).is_err());
    assert!(
        storage
            .mirrored_chat_message_page(&scope(), &group(), None, 129, 1)
            .is_err()
    );
    apply(&storage, &[record(8, 1)]).unwrap();
    storage
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_state SET local_account_id_hex=?1",
            [hex::encode([9; 32])],
        )
        .unwrap();
    assert!(apply(&storage, &[record(9, 2)]).is_err());
    assert!(
        storage
            .mirrored_chat_message_page(&scope(), &group(), None, 128, 1)
            .is_err()
    );
}
#[test]
fn mirrored_messages_sql_guards_keep_identity_payload_and_terminal_references() {
    let storage = stored();
    apply(&storage, &[record(8, 1)]).unwrap();
    let conn = storage.lock().unwrap();
    for sql in [
        "DELETE FROM mirrored_chat_messages",
        "UPDATE mirrored_chat_messages SET source_sequence=0",
        "UPDATE mirrored_chat_messages SET payload=X'01',source_sequence=2",
        "UPDATE mirrored_chat_messages SET author=zeroblob(32),source_sequence=2",
        "UPDATE mirrored_chat_messages SET content_digest=NULL,source_sequence=2",
    ] {
        assert!(conn.execute(sql, []).is_err());
    }
    let key = scope_bytes(&scope()).unwrap();
    let r = record(8, 1);
    assert!(conn.execute("INSERT OR REPLACE INTO mirrored_chat_messages(scope,group_id,event_id,author,created_at,kind,payload,content_digest,deleted,source_epoch,source_sequence,source_digest) VALUES(?1,?2,?3,?4,10,9,?5,?6,0,1,1,?7)",params![key,group().as_slice(),r.event_id.as_slice(),r.author.as_slice(),r.payload,r.content_digest.unwrap().as_slice(),r.source_digest.as_slice()]).is_err());
    drop(conn);
    let mut terminal = record(8, 2);
    terminal.deleted = true;
    terminal.payload.clear();
    apply(&storage, &[terminal]).unwrap();
    assert!(
        storage
            .lock()
            .unwrap()
            .execute(
                "UPDATE mirrored_chat_messages SET deleted=0,payload=X'01',source_sequence=3",
                []
            )
            .is_err()
    );
}
#[test]
fn mirrored_messages_payload_budget_is_atomic_and_purge_reclaims_bytes_not_identity() {
    let storage = stored();
    let payload = serde_json::to_vec(&(
        "x".repeat(MAX_MIRRORED_MESSAGE_PAYLOAD - 7),
        Vec::<Vec<String>>::new(),
    ))
    .unwrap();
    assert_eq!(payload.len(), 65536);
    let records = |start: u64| {
        (start..start + 128)
            .map(|n| {
                let mut r = record(8, n);
                r.event_id = [0; 32];
                r.event_id[..8].copy_from_slice(&n.to_be_bytes());
                r.payload = payload.clone();
                r.content_digest = Some(Sha256::digest(&r.payload).into());
                r.expires_at = Some(100);
                r
            })
            .collect::<Vec<_>>()
    };
    for batch in 0..8 {
        assert_eq!(apply(&storage, &records(1 + batch * 128)).unwrap(), 128);
    }
    assert!(apply(&storage, &records(1025)).is_err());
    assert_eq!(
        storage
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM mirrored_chat_messages", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1024
    );
    assert_eq!(
        storage
            .purge_expired_mirrored_chat_messages(&scope(), &group(), 100, 128, &|| Ok(()))
            .unwrap(),
        128
    );
    assert_eq!(apply(&storage, &records(1025)).unwrap(), 128);
    assert_eq!(
        storage
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM mirrored_chat_messages", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1152
    );
    assert!(apply(&storage, &records(1)).is_err());
}

#[test]
fn mirrored_records_require_current_catalog_origin_and_hide_prior_lineage() {
    use cgka_traits::mirrored_chat_catalog::AcceptedChatOrigin;
    let storage = SqliteAccountStorage::in_memory().unwrap();
    configure(&storage);
    let a = AcceptedChatOrigin {
        id: [21; 32],
        order: 1,
    };
    let b = AcceptedChatOrigin {
        id: [22; 32],
        order: 2,
    };
    let mut active = MirroredChatEntry {
        group_id: group(),
        source_epoch: 1,
        source_sequence: 1,
        source_digest: [8; 32],
        profile: ProtocolProfile::Current,
        name: "shared".into(),
        description: String::new(),
        state: MirroredChatState::Active,
        accepted_origin: Some(a),
        same_account_source_count: Some(1),
        direct_peer_account: None,
    };
    storage
        .apply_mirrored_chat_catalog(&scope(), &[active.clone()], &|| Ok(()))
        .unwrap();
    let mut first = record(1, 1);
    first.accepted_origin = Some(a);
    storage
        .apply_mirrored_chat_messages(&scope(), &group(), &[first.clone()], 0, &|| Ok(()))
        .unwrap();
    let mut left = active.clone();
    left.source_sequence = 2;
    left.state = MirroredChatState::Left;
    left.name.clear();
    storage
        .apply_mirrored_chat_catalog(&scope(), &[left], &|| Ok(()))
        .unwrap();
    active.source_sequence = 3;
    active.source_epoch = 2;
    active.accepted_origin = Some(b);
    storage
        .apply_mirrored_chat_catalog(&scope(), &[active], &|| Ok(()))
        .unwrap();
    assert!(
        storage
            .mirrored_chat_message_page(&scope(), &group(), None, 128, 0)
            .unwrap()
            .is_empty()
    );
    first.source_sequence = 2;
    first.source_epoch = 2;
    assert!(
        storage
            .apply_mirrored_chat_messages(&scope(), &group(), &[first.clone()], 0, &|| Ok(()))
            .is_err()
    );
    first.accepted_origin = None;
    assert!(
        storage
            .apply_mirrored_chat_messages(&scope(), &group(), &[first.clone()], 0, &|| Ok(()))
            .is_err()
    );
    first.accepted_origin = Some(b);
    storage
        .apply_mirrored_chat_messages(&scope(), &group(), &[first], 0, &|| Ok(()))
        .unwrap();
    assert_eq!(
        storage
            .mirrored_chat_message_page(&scope(), &group(), None, 128, 0)
            .unwrap()
            .len(),
        1
    );
}

fn origin_bound_record(storage: &SqliteAccountStorage) -> MirroredChatRecord {
    use cgka_traits::mirrored_chat_catalog::AcceptedChatOrigin;
    configure(storage);
    let origin = AcceptedChatOrigin {
        id: [31; 32],
        order: 1,
    };
    storage
        .apply_mirrored_chat_catalog(
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
                accepted_origin: Some(origin),
                same_account_source_count: Some(1),
                direct_peer_account: None,
            }],
            &|| Ok(()),
        )
        .unwrap();
    let mut value = record(1, 1);
    value.accepted_origin = Some(origin);
    storage
        .apply_mirrored_chat_messages(&scope(), &group(), &[value.clone()], 0, &|| Ok(()))
        .unwrap();
    value
}

#[test]
fn mirrored_record_origin_roundtrip_survives_actual_encrypted_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bound-record.sqlite");
    let key = crate::SqlCipherKey::new("42".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let expected = origin_bound_record(&storage);
    storage.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let rows = reopened
        .mirrored_chat_message_page(&scope(), &group(), None, 128, 0)
        .unwrap();
    assert!(
        rows.len() == 1 && rows[0] == expected,
        "an encrypted read must retain exact source-origin metadata"
    );
    reopened.close().unwrap();
}

#[test]
fn mirrored_record_origin_roundtrip_exact_reimport_is_idempotent() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let expected = origin_bound_record(&storage);
    let duplicate =
        storage.apply_mirrored_chat_messages(&scope(), &group(), &[expected], 0, &|| Ok(()));
    assert!(
        matches!(duplicate, Ok(0)),
        "same-source exact replay must remain an unchanged import"
    );
}

#[test]
fn mirrored_record_origin_decoder_refuses_partial_or_malformed_pairs() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let original = record(1, 1);
    let decode = |id: Option<Vec<u8>>, order: Option<i64>| {
        conn.query_row(
            "SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13",
            params![
                original.event_id.as_slice(),
                original.author.as_slice(),
                original.created_at as i64,
                original.kind,
                original.payload,
                original.expires_at.map(|v| v as i64),
                original.content_digest.map(|v| v.to_vec()),
                original.deleted,
                original.source_epoch as i64,
                original.source_sequence as i64,
                original.source_digest.as_slice(),
                id,
                order
            ],
            read_record,
        )
    };
    assert!(
        decode(None, None).unwrap().accepted_origin.is_none(),
        "old paired NULL columns remain readable"
    );
    let valid = decode(Some(vec![31; 32]), Some(8192)).unwrap();
    assert!(
        valid
            .accepted_origin
            .is_some_and(|origin| origin.id == [31; 32] && origin.order == 8192)
    );
    for (id, order) in [
        (None, Some(1)),
        (Some(vec![31; 32]), None),
        (Some(vec![31; 31]), Some(1)),
        (Some(vec![0; 32]), Some(1)),
        (Some(vec![31; 32]), Some(0)),
        (Some(vec![31; 32]), Some(-1)),
        (Some(vec![31; 32]), Some(8193)),
    ] {
        assert!(
            decode(id, order).is_err(),
            "malformed origin pairs must fail closed"
        );
    }
}
