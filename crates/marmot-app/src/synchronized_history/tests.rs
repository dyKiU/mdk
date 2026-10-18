use super::*;
use storage_sqlite::{
    StoredAppEvent, SynchronizedHistoryBinding, SynchronizedHistoryManifest,
    SynchronizedHistoryRecord, synchronized_history_chunk_digest,
};

fn fixture() -> (tempfile::TempDir, MarmotApp, GroupId) {
    let dir = tempfile::tempdir().unwrap();
    marmot_account::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://history.example");
    app.ensure_account_state("alice").unwrap();
    (dir, app, GroupId::new(vec![8; 16]))
}
fn record(id: u8) -> SynchronizedHistoryRecord {
    SynchronizedHistoryRecord {
        message_id: [id; 32],
        author: [7; 32],
        created_at: 100,
        kind: 9,
        payload: serde_json::to_vec(&("source content", Vec::<Vec<String>>::new())).unwrap(),
        expires_at: None,
        deleted: false,
    }
}
/// Seed projection fixtures only; this does not manufacture an original actor.
fn import(
    app: &MarmotApp,
    group: &GroupId,
    id: u8,
    records: Vec<SynchronizedHistoryRecord>,
    complete: bool,
) {
    let account = app.account_home().account("alice").unwrap();
    let binding = SynchronizedHistoryBinding {
        transfer_id: [id; 32],
        account_id: hex::decode(account.account_id_hex)
            .unwrap()
            .try_into()
            .unwrap(),
        source_device: [2; 32],
        recipient_device: [3; 32],
        group_id_hex: hex::encode(group.as_slice()),
        snapshot_timestamp_ceiling: 200,
    };
    let mut chunks = vec![records];
    if !complete {
        chunks.push(Vec::new());
    }
    let manifest = SynchronizedHistoryManifest {
        chunk_digests: chunks
            .iter()
            .enumerate()
            .map(|(i, chunk)| synchronized_history_chunk_digest(&binding, i, chunk).unwrap())
            .collect(),
        binding,
        retain_since: 0,
        max_record_lifetime_seconds: None,
    };
    let storage = app.account_storage("alice").unwrap();
    storage.app_storage().admit_synchronized_history(&manifest).unwrap();
    assert_eq!(
        storage
            .app_storage().import_synchronized_history_chunk(&manifest, 0, &chunks[0], 120, &|| false)
            .unwrap()
            .complete,
        complete
    );
}

#[test]
fn query_bounds_refuse_before_unknown_account_storage_effects() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://history.example");
    for (group, limit) in [
        (GroupId::new(Vec::new()), 1),
        (GroupId::new(vec![0; 256]), 1),
        (GroupId::new(vec![0; 16]), 0),
        (GroupId::new(vec![0; 16]), 201),
    ] {
        assert!(matches!(
            app.synchronized_history_page("missing", &group, None, limit),
            Err(SynchronizedHistoryReadError::InvalidQuery)
        ));
    }
    assert!(!app.account_storage_cached_for_test("missing"));
    app.close_storage().unwrap();
}

#[test]
fn unfinished_import_is_invisible_and_live_events_shadow_completed_history() {
    let (_dir, app, group) = fixture();
    import(&app, &group, 9, vec![record(1)], false);
    assert!(
        app.synchronized_history_page("alice", &group, None, 200)
            .unwrap()
            .records
            .is_empty()
    );
    import(&app, &group, 10, vec![record(2)], true);
    assert_eq!(
        app.synchronized_history_page("alice", &group, None, 200)
            .unwrap()
            .records
            .len(),
        1
    );
    app.account_storage("alice")
        .unwrap()
        .app_storage()
        .record_app_event(&StoredAppEvent {
            group_id_hex: hex::encode(group.as_slice()),
            message_id_hex: hex::encode([2; 32]),
            source_message_id_hex: None,
            source_epoch: None,
            direction: "received".into(),
            sender: hex::encode([7; 32]),
            plaintext: "live content".into(),
            kind: 9,
            tags: vec![],
            recorded_at: 100,
            received_at: 100,
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
    assert!(
        app.synchronized_history_page("alice", &group, None, 200)
            .unwrap()
            .records
            .is_empty()
    );
    app.close_storage().unwrap();
}

#[test]
fn expiry_retention_fences_and_payload_free_tombstones_survive_reads() {
    let (_dir, app, group) = fixture();
    let mut expired = record(1);
    expired.expires_at = Some(150);
    let mut deleted = record(2);
    deleted.deleted = true;
    deleted.payload.clear();
    import(&app, &group, 9, vec![expired, deleted, record(3)], true);
    let page = app
        .synchronized_history_page("alice", &group, None, 200)
        .unwrap();
    assert_eq!(page.records.len(), 2);
    assert_eq!(page.records[0].message_id, [2; 32]);
    assert!(
        page.records[0].deleted
            && page.records[0].content.is_empty()
            && page.records[0].tags.is_empty()
            && page.records[0].media_attachments.is_empty()
    );
    app.account_storage("alice")
        .unwrap()
        .app_storage().prune_synchronized_history(&hex::encode(group.as_slice()), 101, 120)
        .unwrap();
    import(&app, &group, 10, vec![record(3)], true);
    let page = app
        .synchronized_history_page("alice", &group, None, 200)
        .unwrap();
    assert_eq!(page.records.len(), 1);
    assert!(page.records[0].deleted);
    app.close_storage().unwrap();
}

#[test]
fn malformed_logical_payload_fails_page_without_reclassifying_live_messages() {
    for payload in [
        b"not json".to_vec(),
        b"[\"text\",[],42]".to_vec(),
        b"[ \"text\", [] ]".to_vec(),
    ] {
        let (_dir, app, group) = fixture();
        let mut malformed = record(2);
        malformed.payload = payload;
        import(&app, &group, 9, vec![record(1), malformed], true);
        assert!(matches!(
            app.synchronized_history_page("alice", &group, None, 200),
            Err(SynchronizedHistoryReadError::InvalidRecord)
        ));
        assert!(app.messages("alice").unwrap().is_empty());
        app.close_storage().unwrap();
    }
}

#[test]
fn media_verdicts_keep_rejected_slots_and_valid_siblings_in_order() {
    let (_dir, app, group) = fixture();
    let tags = vec![
        vec!["imeta".into(), "v unsupported-version".into()],
        vec![
            "imeta".into(),
            "v encrypted-media-v1".into(),
            format!(
                "locator blossom-v1 https://media.example/{}.bin",
                "11".repeat(32)
            ),
            format!("ciphertext_sha256 {}", "11".repeat(32)),
            format!("plaintext_sha256 {}", "22".repeat(32)),
            "nonce 333333333333333333333333".into(),
            "m image/png".into(),
            "filename diagram.png".into(),
        ],
    ];
    let mut media = record(1);
    media.payload = serde_json::to_vec(&("source content", tags)).unwrap();
    import(&app, &group, 9, vec![media], true);
    let page = app
        .synchronized_history_page("alice", &group, None, 200)
        .unwrap();
    let outcomes = &page.records[0].media_attachments;
    assert_eq!(outcomes.len(), 2);
    assert!(matches!(
        outcomes[0],
        MediaAttachmentOutcome::Rejected {
            attachment_index: 0,
            ..
        }
    ));
    assert!(matches!(
        outcomes[1],
        MediaAttachmentOutcome::Accepted {
            attachment_index: 1,
            ..
        }
    ));
    let debug = format!("{page:?}");
    assert!(
        !debug.contains("source content")
            && !debug.contains("diagram.png")
            && !debug.contains(&hex::encode([7; 32]))
    );
    app.close_storage().unwrap();
}

#[test]
fn closed_storage_query_cannot_reopen_the_account_database() {
    let (_dir, app, group) = fixture();
    app.close_storage().unwrap();
    assert!(matches!(
        app.synchronized_history_page("alice", &group, None, 200),
        Err(SynchronizedHistoryReadError::Unavailable)
    ));
    assert!(app.storage_is_closed());
    assert!(!app.account_storage_cached_for_test("alice"));
}
