use super::*;

// A single-thread interleaving keeps SQL fault removal and observer snapshots ordered.
#[tokio::test(flavor = "current_thread")]
async fn authenticated_negative_sql_failure_retains_owned_body_until_commit_before_disposition() {
    use cgka_traits::StorageProvider;
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let apps = std::array::from_fn::<_, 2, _>(|index| {
        AccountHome::open(dirs[index].path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        MarmotApp::with_relay(dirs[index].path(), &url)
    });
    let runtimes = apps.clone().map(MarmotAppRuntime::new);
    for runtime in &runtimes {
        runtime.reconcile_accounts().await.unwrap();
    }
    let managers = runtimes.each_ref().map(|runtime| runtime.accounts());
    let old_chat = managers[0]
        .create_group("test", "Body responsiveness baseline", &[], None)
        .await
        .unwrap();
    let history = managers[0]
        .send_message(
            "test",
            &old_chat,
            b"Body responsiveness baseline history".to_vec(),
        )
        .await
        .unwrap();
    assert_eq!(history.message_ids.len(), 1);
    let recipient = managers[1]
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let source = managers[0]
        .approve_automatic_device_linking_session(
            "test",
            recipient.automatic_pairing_code().await.unwrap(),
            None,
        )
        .await
        .unwrap();
    source.automatic_pairing_code().await.unwrap();
    compare_and_confirm_pair(&source, &recipient).await;
    recipient
        .continue_automatic_linking(recipient.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    source
        .continue_automatic_linking(source.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    wait_for_automatic_phase(&source, &recipient, DeviceLinkingPhase::EnrollmentComplete).await;
    assert!(
        apps.iter().all(|app| {
            let policies = app
                .account_storage("test")
                .unwrap()
                .approved_account_sharing_policy_storage()
                .unwrap()
                .approved_account_sharing_policies()
                .unwrap();
            policies.len() == 1 && !policies[0].revoked
        }),
        "actual bilateral completed policies are required"
    );
    let history_id = hex::decode(&history.message_ids[0]).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let chats = managers[1]
                .paired_chat_list_page("test", None, 128)
                .await
                .unwrap();
            let messages = managers[1]
                .paired_chat_message_page("test", old_chat.clone(), None, 128)
                .await;
            if chats
                .chats
                .iter()
                .filter(|chat| chat.group_id == old_chat)
                .count()
                == 1
                && messages.is_ok_and(|page| {
                    page.messages
                        .iter()
                        .any(|message| message.event_id.as_slice() == history_id)
                })
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the real existing chat and history must be fully mirrored first");
    source.cancel().await.unwrap();
    recipient.cancel().await.unwrap();
    eprintln!("automatic-body-control stage=bilateral-pair-and-history-ready");

    let probe = crate::AppClient::test_capture_automatic_body_negative(
        apps[0].account_home().root(),
        apps[1].account_home().root(),
        &old_chat,
    );
    struct IntentRelease<F: Fn()>(F);
    impl<F: Fn()> Drop for IntentRelease<F> {
        fn drop(&mut self) {
            (self.0)();
        }
    }
    let peer_release_probe = probe.clone();
    let _intent_release = IntentRelease(move || peer_release_probe.release_peer_intent());
    let path = apps[0].account_storage_path("test");
    let signing = apps[0].account_home().load_signing_keys("test").unwrap();
    let sql_key = apps[0]
        .sqlcipher_key(
            "test",
            &signing,
            &path,
            crate::sqlcipher::SqlcipherDatabaseKind::Session,
        )
        .unwrap();
    fs_private::ensure_private_db_files(&path).unwrap();
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &sql_key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER reject_body_negative_cut BEFORE INSERT ON account_chat_departure_cuts BEGIN SELECT RAISE(ABORT,'isolated genuine negative cut rollback'); END;").unwrap();
    let pending = runtimes[1]
        .leave_account_chat("test", &old_chat)
        .await
        .unwrap();
    assert_eq!(pending.status, crate::AccountChatDepartureStatus::Pending);
    assert!(pending.operation_id.is_some());
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while !probe.peer_intent_is_held() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect(
        "real prepared peer DepartureIntent must be held inside its original publication select",
    );
    eprintln!("body-negative-control stage=actual-peer-intent-held");
    let (observed, release) = apps[0].relay_plane.hold_next_automatic_catalog_body_except(
        cgka_traits::MemberId::new(keys.public_key().to_bytes().to_vec()),
        old_chat.clone(),
    );
    struct Release(std::sync::Arc<tokio::sync::Notify>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.notify_one();
        }
    }
    let release = Release(release);
    let fresh_chat = managers[0]
        .create_group("test", "Negative assembly held new chat", &[], None)
        .await
        .unwrap();
    let (held_group, held_message) =
        tokio::time::timeout(std::time::Duration::from_secs(30), observed)
            .await
            .expect("real new-chat Body must reach the existing transport hold")
            .unwrap();
    assert!(
        held_group == fresh_chat,
        "actual held Catalog Body must belong to the fresh fixture chat"
    );
    assert!(!held_message.payload.is_empty());
    use sha2::Digest as _;
    let held_payload_digest: [u8; 32] = sha2::Sha256::digest(&held_message.payload).into();
    assert!(
        probe.matches_held_catalog(&held_group, held_payload_digest),
        "captured owned slot must match the actual held Catalog Body group and prepared payload"
    );
    eprintln!("body-negative-control stage=actual-owned-body-held");
    eprintln!("body-negative-control stage=actual-same-channel-binding-verified");
    probe.release_peer_intent();
    eprintln!("body-negative-control stage=actual-peer-intent-released");

    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while probe.snapshot().sql_failures == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect(
        "real complete authenticated peer negative must reach the actual encrypted SQL refusal",
    );
    eprintln!("body-negative-control stage=actual-authenticated-negative-sql-failure");

    // These are the behavior under test. Missing retention/commit/harvest is false,
    // never an early setup panic that prevents positive runtime cleanup.
    let barrier_seen = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let state = probe.snapshot();
            if state.barrier_observations > 0 && state.aborted_task_finished {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok();
    let failed = probe.snapshot();
    let rolled_back: i64 = injector
        .query_row(
            "SELECT count(*) FROM account_chat_departures WHERE group_id=?1",
            rusqlite::params![old_chat.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let retained = barrier_seen
        && failed.retained
        && failed.sql_failures > 0
        && failed.commit_at == 0
        && failed.harvest_at == 0
        && failed.retirement_at == 0
        && failed.body_effects == 0
        && rolled_back == 0;
    injector
        .execute_batch("DROP TRIGGER reject_body_negative_cut;")
        .unwrap();
    eprintln!("body-negative-control stage=persistent-sql-fault-removed");
    let ordered_recovery = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let state = probe.snapshot();
            if state.commit_at > 0 && (state.harvest_at > 0 || state.retirement_at > 0) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok();
    let recovered = probe.snapshot();
    let committed: i64 = injector
        .query_row(
            "SELECT count(*) FROM account_chat_departures WHERE group_id=?1",
            rusqlite::params![old_chat.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let commit_before_disposition = ordered_recovery
        && recovered.retained
        && committed == 1
        && [recovered.harvest_at, recovered.retirement_at]
            .into_iter()
            .filter(|ordinal| *ordinal > 0)
            .min()
            .is_some_and(|first_disposition| recovered.commit_at < first_disposition);
    release.0.notify_one();
    // The existing hold is BEFORE SDK publication. Its aborted release is not an ACK.
    // A separate actual post-EVENT/pre-OK gate is required for late-ACK coverage.
    let actor_progress = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        managers[0].device_linking_targets("test"),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    drop(injector);
    for (index, runtime) in runtimes.iter().enumerate() {
        runtime.shutdown_and_close().await.unwrap();
        assert!(
            runtime.storage_is_closed(),
            "real fixture runtime must positively close"
        );
        eprintln!("body-negative-control stage=positive-runtime-close index={index}");
    }
    let after_release = probe.snapshot();
    let no_old_body_effects = after_release.body_effects == 0;
    eprintln!(
        "body-negative-control retained={retained} commit_before_disposition={commit_before_disposition} no_old_body_effects={no_old_body_effects} actor_progress={actor_progress} sql_failures={} associated_sql_failures={} barrier_observations={} commit_at={} harvest_at={} retirement_at={} body_effects={} harvested_cancelled={} retired_task_finished={}",
        after_release.sql_failures,
        after_release.associated_sql_failures,
        after_release.barrier_observations,
        after_release.commit_at,
        after_release.harvest_at,
        after_release.retirement_at,
        after_release.body_effects,
        after_release.harvested_cancelled,
        after_release.retired_task_finished
    );
    assert!(
        after_release.associated_sql_failures > 0,
        "actual SQL-trigger failure must belong to the held original nonce and owned publication slot"
    );
    assert!(
        retained && commit_before_disposition && no_old_body_effects && actor_progress,
        "authenticated negative SQL rollback must retain the same owned Body until negative commit precedes owned-task harvest or channel retirement without old Body effects"
    );
}
