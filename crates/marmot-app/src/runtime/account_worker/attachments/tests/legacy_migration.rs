//! The maintenance tick's legacy body migration (mdk#2314 step 6): one batch
//! on the blocking pool, with the account's policy and free space, waking
//! attachment observers when it finishes.
use super::*;
use crate::media::attachment_resume::test_free_space;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_maintenance_batch_moves_a_legacy_body_and_wakes_observers() {
    let (dir, client, storage, _reference) = offline_fixture().await;
    test_free_space::set(dir.path(), 1 << 40);
    let plaintext = b"retained worker bytes";
    let now = crate::unix_now_seconds();
    admit_demands(&storage.app_storage(), now, false).unwrap();
    let asset = storage
        .app_storage()
        .due_attachment_acquisitions(now, 1)
        .unwrap()
        .remove(0);
    let job = storage
        .app_storage()
        .claim_attachment_acquisition(&asset, now, now + 60)
        .unwrap()
        .unwrap();
    assert_eq!(
        storage
            .app_storage()
            .complete_attachment_acquisition(&job, plaintext, now, u64::MAX / 2)
            .unwrap(),
        storage_sqlite::AttachmentPublishResult::Published
    );
    let shared = RuntimeSharedServices::default();
    let observer = shared.attachment_updates.subscribe();
    let mut admission = Admission::default();

    spawn_legacy_migration(&client, &shared, &mut admission);
    admission.legacy_migration.take().unwrap().await.unwrap();

    assert!(
        observer.has_changed().unwrap(),
        "completion wakes observers"
    );
    assert_eq!(storage.app_storage().legacy_attachment_bytes().unwrap(), 0);
    let read = read_retained(&storage, &client.app, "alice", &asset, now, 0, 1024)
        .unwrap()
        .unwrap();
    assert_eq!(read.as_slice(), plaintext);
    assert!(matches!(
        storage
            .app_storage()
            .retained_attachment_read(&asset, now, 0, 16)
            .unwrap(),
        Some(storage_sqlite::RetainedAttachmentRead::MediaFile(_))
    ));
    test_free_space::clear(dir.path());
}

/// Exercise the real account worker's broad maintenance arm, not the batch helper.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_account_worker_migrates_legacy_body_and_wakes_observers() {
    use sha2::{Digest, Sha256};

    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path()).create_account("alice").unwrap();
    // Seed with migration refused by the unchanged disk policy, then permit the
    // next ordinary fifteen-second maintenance tick to perform the actual move.
    test_free_space::set(dir.path(), 0);
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        MarmotAppConfig::white_noise()
            .with_allow_loopback_relay_endpoints(true)
            .with_attachment_acquisition_mode(crate::AttachmentAcquisitionMode::HostManaged),
    );
    let runtime = app.runtime();
    runtime.reconcile_accounts().await.unwrap();
    let group = runtime.create_group_with_options(
        "alice", "legacy maintenance", &[],
        crate::AppCreateGroupOptions { relays: Some(vec![url]), ..Default::default() },
    ).await.unwrap();
    tokio::time::timeout(Duration::from_secs(20), runtime.catch_up_accounts())
        .await.expect("real worker initial catch-up must finish").unwrap();
    let group_hex = hex::encode(group.as_slice());
    let storage = app.account_storage("alice").unwrap();
    let plaintext = b"retained worker bytes";
    let now = crate::unix_now_seconds();
    storage.app_storage().record_app_event(&StoredAppEvent {
        group_id_hex: group_hex.clone(),
        message_id_hex: "11".repeat(32),
        source_message_id_hex: Some("22".repeat(32)),
        source_epoch: Some(0),
        direction: "received".into(),
        sender: "33".repeat(32),
        plaintext: String::new(),
        kind: 9,
        tags: vec![vec!["imeta".into(), "m application/octet-stream".into(),
            format!("x {}", hex::encode(Sha256::digest(plaintext)))]],
        recorded_at: now, received_at: now,
        origin_commit_id: None, moderation_grant: false,
    }).unwrap();
    let entry = storage.app_storage().attachment_history_page(&group_hex, 64, None)
        .unwrap().entries.into_iter().find(|entry| entry.message_id_hex == "11".repeat(32)).unwrap();
    let storage_sqlite::AttachmentDemand::Requested(asset) = storage.app_storage()
        .request_attachment_acquisition(&group_hex, &entry, Sha256::digest(plaintext).into(), now).unwrap()
    else { panic!("real retained-body fixture must create one demand"); };
    let job = storage.app_storage().claim_attachment_acquisition(&asset, now, now + 60)
        .unwrap().unwrap();
    assert_eq!(storage.app_storage().complete_attachment_acquisition(&job, plaintext, now, u64::MAX / 2).unwrap(),
        storage_sqlite::AttachmentPublishResult::Published);
    assert!(storage.app_storage().legacy_attachment_bytes().unwrap() > 0,
        "fixture must retain actual legacy SQL bytes before maintenance");
    assert!(matches!(storage.app_storage().retained_attachment_read(&asset, now, 0, 1024).unwrap(),
        Some(storage_sqlite::RetainedAttachmentRead::Bytes(_))));
    let mut observer = runtime.shared.attachment_updates.subscribe();
    observer.borrow_and_update();
    test_free_space::set(dir.path(), 1 << 40);
    // Three normal maintenance periods are a finite fixture allowance; no
    // production interval, admission policy or original deadline is changed.
    let moved = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            observer.changed().await.unwrap();
            if storage.app_storage().legacy_attachment_bytes().unwrap() == 0 {
                assert!(matches!(storage.app_storage().retained_attachment_read(&asset, now, 0, 1024).unwrap(),
                    Some(storage_sqlite::RetainedAttachmentRead::MediaFile(_))),
                    "worker must publish a real media-store replacement");
                assert_eq!(read_retained(&storage, &app, "alice", &asset, now, 0, 1024)
                    .unwrap().unwrap().as_slice(), plaintext,
                    "worker migration must preserve authenticated bytes");
                break;
            }
        }
    }).await;
    let closed = runtime.shutdown_and_close().await;
    test_free_space::clear(dir.path());
    closed.unwrap();
    assert!(moved.is_ok(),
        "real account worker maintenance must migrate legacy bodies and wake observers");
}
