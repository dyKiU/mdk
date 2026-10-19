//! Real client-token send from a paired mirror through an actual member.
use super::*;
use cgka_traits::StorageProvider;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_forwarding_uses_original_client_token_and_real_ordinary_event() {
    actual::run_native_public_three_device_enrollment(
        actual::ApprovalScenario::AutomaticForwarding,
    )
    .await;
}

pub(super) async fn verify(
    apps: &[MarmotApp; 3],
    runtime: &MarmotAppRuntime,
    group: &crate::GroupId,
    scope: &cgka_traits::mirrored_chat_catalog::MirroredChatScope,
) -> String {
    let token = "paired-source-forwarding-original-token".to_owned();
    let text = "message from the paired mirror".to_owned();
    let accepted = runtime
        .submit_text("test", group, text.clone(), token.clone())
        .await
        .unwrap();
    let retry = runtime
        .submit_text("test", group, text.clone(), token.clone())
        .await
        .unwrap();
    assert!(
        accepted == retry,
        "same token must retain canonical event identity"
    );
    assert!(
        runtime
            .submit_text("test", group, "changed request".into(), token.clone())
            .await
            .is_err()
    );
    assert!(apps[2].load_state("test").unwrap().groups.is_empty());
    tokio::time::timeout(std::time::Duration::from_secs(90), async {
        loop {
            let state = runtime.local_send_status("test", group, &token).unwrap();
            if let Some(crate::LocalSendStatus::Completed(summary)) = state {
                assert_eq!(summary.published, 1);
                assert!(summary.message_ids == [accepted.message_id_hex.clone()]);
                let source = apps[0].account_storage("test").unwrap();
                let row = source
                    .app_storage()
                    .app_message(&hex::encode(group.as_slice()), &accepted.message_id_hex)
                    .unwrap();
                let receiver = apps[2].account_storage("test").unwrap();
                let rows = receiver
                    .mirrored_chat_message_storage()
                    .unwrap()
                    .mirrored_chat_message_page(scope, group, None, 128, crate::unix_now_seconds())
                    .unwrap();
                if let Some(row) = row
                    && rows
                        .iter()
                        .any(|r| hex::encode(r.event_id) == accepted.message_id_hex)
                {
                    assert!(row.plaintext == text);
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect(
        "actual member publish, authenticated receipt and automatic record import must complete",
    );
    assert!(
        apps[2].load_state("test").unwrap().groups.is_empty(),
        "forwarding never creates synthetic ordinary membership"
    );
    accepted.message_id_hex
}

/// A mirror-originated own message is edited on its actual ordinary source.
/// The original open mirror window must update from encrypted stream delivery.
pub(super) async fn verify_source_edit(
    source: &MarmotAppRuntime,
    mirror: &MarmotAppRuntime,
    group: &crate::GroupId,
    target: &str,
) {
    let mut window = mirror
        .open_account_conversation_window("test", group, 128)
        .await
        .unwrap();
    let original_time = window
        .snapshot
        .rows
        .iter()
        .find_map(|row| match row {
            crate::AccountConversationRow::PairedSource(row)
                if hex::encode(row.event_id) == target =>
            {
                Some(row.created_at)
            }
            _ => None,
        })
        .expect("forwarded original is in the mirror before edit");
    let result = source
        .edit_message("test", group, target, "corrected on the source device")
        .await
        .unwrap();
    assert_eq!(result.published, 1);
    let edit_id = result
        .message_ids
        .first()
        .expect("canonical edit event")
        .clone();
    tokio::time::timeout(std::time::Duration::from_secs(90), async {
        loop {
            let snapshot = window.recv().await.unwrap().expect("original mirror window remains live");
            if let Some(row) = snapshot.rows.iter().find_map(|row| match row {
                crate::AccountConversationRow::PairedSource(row) if hex::encode(row.event_id) == target && row.content == "corrected on the source device" => Some(row),
                _ => None,
            }) {
                assert_eq!(row.created_at, original_time);
                let edit = row.edit.as_ref().expect("edited marker accompanies the corrected text");
                assert_eq!(edit.latest_edit_message_id_hex, edit_id);
                assert_eq!(edit.edit_count, 1);
                assert!(!snapshot.rows.iter().any(|row| matches!(row, crate::AccountConversationRow::PairedSource(row) if hex::encode(row.event_id) == edit_id)));
                break;
            }
        }
    }).await.expect("canonical source edit must wake and update the existing mirror window");
    window.window_handle().cancel();
}

pub(super) async fn verify_cancelled_host_admission(
    apps: &[MarmotApp; 3],
    runtime: &MarmotAppRuntime,
    group: &crate::GroupId,
    scope: &cgka_traits::mirrored_chat_catalog::MirroredChatScope,
) {
    use cgka_traits::storage::GroupStorage;
    let storage = apps[2].account_storage("test").unwrap();
    assert!(matches!(
        storage.get_group(group),
        Err(cgka_traits::StorageError::NotFound)
    ));
    let account = apps[2].account_home().account("test").unwrap();
    let token = "forwarded-cancelled-host-token".to_owned();
    let text = "forwarded after host cancellation".to_owned();
    let classification_entered = runtime
        .shared_services()
        .arm_submission_classification_for_test(&account.account_id_hex, &token);
    let waiter = {
        let runtime = runtime.clone();
        let group = group.clone();
        let token = token.clone();
        let text = text.clone();
        tokio::spawn(async move { runtime.submit_text("test", &group, text, token).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !classification_entered.entered() {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the real forwarded caller must own blocking admission before cancellation");
    waiter.abort();
    match waiter.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(_) => panic!("the host waiter must be cancelled before releasing admission"),
    }
    classification_entered.release();
    tokio::time::timeout(std::time::Duration::from_secs(90), async {
        loop {
            if let Some(crate::LocalSendStatus::Completed(summary)) =
                runtime.local_send_status("test", group, &token).unwrap()
            {
                assert_eq!(summary.published, 1);
                assert_eq!(summary.message_ids.len(), 1);
                let id = &summary.message_ids[0];
                let source = apps[0].account_storage("test").unwrap();
                let row = source
                    .app_storage()
                    .app_message(&hex::encode(group.as_slice()), id)
                    .unwrap();
                let receiver = apps[2].account_storage("test").unwrap();
                let rows = receiver
                    .mirrored_chat_message_storage()
                    .unwrap()
                    .mirrored_chat_message_page(scope, group, None, 128, crate::unix_now_seconds())
                    .unwrap();
                if let Some(row) = row
                    && rows.iter().any(|row| hex::encode(row.event_id) == *id)
                {
                    assert!(row.plaintext == text);
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect(
        "cancelled host wait must retain actual source publication and canonical mirror import",
    );
    assert!(apps[2].load_state("test").unwrap().groups.is_empty());
    eprintln!("forwarded_cancelled_host_admission_body_executed=true");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_forwarding_preserves_actual_reply_reference_and_canonical_id() {
    actual::run_native_public_three_device_enrollment(
        actual::ApprovalScenario::AutomaticForwardingReply,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_forwarding_queues_without_members_and_reopens_both_independent_stores() {
    actual::run_native_public_three_device_enrollment(
        actual::ApprovalScenario::AutomaticForwardingOffline,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_forwarding_retries_unacknowledged_receipt_after_recipient_sql_rollback() {
    actual::run_native_public_three_device_enrollment(
        actual::ApprovalScenario::AutomaticForwardingReceiptRetry,
    )
    .await;
}

pub(super) async fn verify_receipt_sql_retry(
    apps: &[MarmotApp; 3],
    runtime: &MarmotAppRuntime,
    group: &crate::GroupId,
    scope: &cgka_traits::mirrored_chat_catalog::MirroredChatScope,
) {
    let path = apps[2].account_storage_path("test");
    let keys = apps[2].account_home().load_signing_keys("test").unwrap();
    let sql_key = apps[2]
        .sqlcipher_key(
            "test",
            &keys,
            &path,
            crate::sqlcipher::SqlcipherDatabaseKind::Session,
        )
        .unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &sql_key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection.execute_batch("CREATE TRIGGER hold_forwarded_receipt BEFORE UPDATE ON account_chat_send_intents WHEN NEW.state=2 BEGIN SELECT RAISE(ABORT,'isolated forwarded receipt rollback'); END;").unwrap();
    let mut errors = runtime.subscribe();
    let token = "receipt-rollback-original-client-token".to_owned();
    let accepted = runtime
        .submit_text("test", group, "receipt retry".into(), token.clone())
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(90), async {
        loop {
            if let crate::MarmotAppEvent::AccountError(error) = errors.recv().await.unwrap()
                && error.message.starts_with("runtime receive failed")
            {
                assert_eq!(
                    error.message,
                    "runtime receive failed: invalid_app_message_payload"
                );
                break;
            }
        }
    })
    .await
    .expect("actual encrypted receipt must reach recipient SQL refusal");
    assert!(matches!(
        runtime.local_send_status("test", group, &token).unwrap(),
        Some(crate::LocalSendStatus::Queued)
    ));
    let storage = apps[0].account_storage("test").unwrap();
    let policy = storage
        .approved_account_sharing_policy_storage()
        .unwrap()
        .approved_account_sharing_policies()
        .unwrap()
        .into_iter()
        .find(|p| p.peer_device == scope.local_device)
        .unwrap();
    let receipts = storage
        .account_chat_send_queue_storage()
        .unwrap()
        .pending_account_chat_send_receipts(&policy.account, &policy.local_device, None, 128)
        .unwrap();
    assert!(receipts.iter().any(|r| r.actual_member_device == policy.local_device
        && matches!(r.state, cgka_traits::account_chat_send_queue::AccountChatSendState::Published { event_id } if hex::encode(event_id) == accepted.message_id_hex)));
    assert!(
        storage
            .app_storage()
            .app_message(&hex::encode(group.as_slice()), &accepted.message_id_hex)
            .unwrap()
            .is_some()
    );
    let retried = runtime
        .submit_text("test", group, "receipt retry".into(), token.clone())
        .await
        .unwrap();
    assert!(retried == accepted);
    connection
        .execute_batch("DROP TRIGGER hold_forwarded_receipt;")
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(90), async {
        loop {
            if let Some(crate::LocalSendStatus::Completed(summary)) = runtime.local_send_status("test", group, &token).unwrap() {
                assert_eq!(summary.published, 1);
                assert!(summary.message_ids == [accepted.message_id_hex.clone()]);
                if storage.account_chat_send_queue_storage().unwrap()
                    .pending_account_chat_send_receipts(&policy.account, &policy.local_device, None, 128).unwrap().is_empty() {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }).await.expect("same published event must receive a committed recipient receipt and authenticated acknowledgement");
    assert!(apps[2].load_state("test").unwrap().groups.is_empty());
}

pub(super) async fn verify_reply(
    apps: &[MarmotApp; 3],
    runtime: &MarmotAppRuntime,
    group: &crate::GroupId,
    scope: &cgka_traits::mirrored_chat_catalog::MirroredChatScope,
    target: &str,
) {
    let token = "paired-reply-fixed-client-token".to_owned();
    let text = "reply from the paired mirror".to_owned();
    let accepted = runtime
        .submit_reply(
            "test",
            group,
            target.to_owned(),
            text.clone(),
            token.clone(),
        )
        .await
        .unwrap();
    let retry = runtime
        .submit_reply(
            "test",
            group,
            target.to_owned(),
            text.clone(),
            token.clone(),
        )
        .await
        .unwrap();
    assert!(accepted == retry);
    assert!(
        runtime
            .submit_text("test", group, text.clone(), token.clone())
            .await
            .is_err(),
        "reply tags are part of immutable client-token correlation"
    );
    tokio::time::timeout(std::time::Duration::from_secs(90), async {
        loop {
            if let Some(crate::LocalSendStatus::Completed(summary)) =
                runtime.local_send_status("test", group, &token).unwrap()
            {
                assert_eq!(summary.published, 1);
                assert!(summary.message_ids == [accepted.message_id_hex.clone()]);
                let source = apps[0].account_storage("test").unwrap();
                if let Some(row) = source
                    .app_storage()
                    .app_message(&hex::encode(group.as_slice()), &accepted.message_id_hex)
                    .unwrap()
                {
                    assert!(row.plaintext == text);
                    assert!(
                        row.tags
                            .iter()
                            .any(|tag| tag.first().is_some_and(|v| v == "e")
                                && tag.get(1).is_some_and(|v| v == target))
                    );
                    let storage = apps[2].account_storage("test").unwrap();
                    let records = storage
                        .mirrored_chat_message_storage()
                        .unwrap()
                        .mirrored_chat_message_page(
                            scope,
                            group,
                            None,
                            128,
                            crate::unix_now_seconds(),
                        )
                        .unwrap();
                    if let Some(record) = records
                        .iter()
                        .find(|r| hex::encode(r.event_id) == accepted.message_id_hex)
                    {
                        let logical: (String, Vec<Vec<String>>) =
                            serde_json::from_slice(&record.payload).unwrap();
                        assert!(logical.0 == text);
                        assert!(logical.1 == row.tags);
                        break;
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("real reply publication and source-attested exact tags must arrive");
    assert!(apps[2].load_state("test").unwrap().groups.is_empty());
}

pub(super) async fn verify_offline_reopen(
    apps: &[MarmotApp; 3],
    runtimes: &[MarmotAppRuntime; 3],
    roots: [&std::path::Path; 2],
    url: &str,
    group: &crate::GroupId,
    scope: &cgka_traits::mirrored_chat_catalog::MirroredChatScope,
) {
    // Only A has this ordinary membership; B/C retain no ordinary group.
    assert!(
        apps[0]
            .load_state("test")
            .unwrap()
            .groups
            .iter()
            .any(|g| g.group_id_hex == hex::encode(group.as_slice()))
    );
    assert!(apps[1].load_state("test").unwrap().groups.is_empty());
    assert!(apps[2].load_state("test").unwrap().groups.is_empty());
    runtimes[0].shutdown_and_close().await.unwrap();
    assert!(runtimes[0].storage_is_closed());
    let token = "offline-mirror-durable-client-token".to_owned();
    let text = "queued while all actual members are closed".to_owned();
    let accepted = runtimes[2]
        .submit_text("test", group, text.clone(), token.clone())
        .await
        .unwrap();
    assert!(matches!(
        runtimes[2]
            .local_send_status("test", group, &token)
            .unwrap(),
        Some(crate::LocalSendStatus::Queued)
    ));
    runtimes[2].shutdown_and_close().await.unwrap();
    assert!(runtimes[2].storage_is_closed());
    // Fresh clients reopen only their own encrypted roots. No old channel,
    // opaque consent or MLS database is copied into either new engine.
    let recipient_app = MarmotApp::with_relay(roots[1], url);
    let recipient = MarmotAppRuntime::new(recipient_app.clone());
    recipient.reconcile_accounts().await.unwrap();
    assert!(matches!(
        recipient.local_send_status("test", group, &token).unwrap(),
        Some(crate::LocalSendStatus::Queued)
    ));
    let retry = recipient
        .submit_text("test", group, text.clone(), token.clone())
        .await
        .unwrap();
    assert!(
        accepted == retry,
        "encrypted restart preserves exact original event identity"
    );
    assert!(
        recipient
            .submit_text("test", group, "changed after restart".into(), token.clone())
            .await
            .is_err()
    );
    let member_app = MarmotApp::with_relay(roots[0], url);
    let member = MarmotAppRuntime::new(member_app.clone());
    member.reconcile_accounts().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            if let Some(crate::LocalSendStatus::Completed(summary)) =
                recipient.local_send_status("test", group, &token).unwrap()
            {
                assert_eq!(summary.published, 1);
                assert!(summary.message_ids == [accepted.message_id_hex.clone()]);
                let source = member_app.account_storage("test").unwrap();
                let receiver = recipient_app.account_storage("test").unwrap();
                let records = receiver
                    .mirrored_chat_message_storage()
                    .unwrap()
                    .mirrored_chat_message_page(scope, group, None, 128, crate::unix_now_seconds())
                    .unwrap();
                if let Some(row) = source
                    .app_storage()
                    .app_message(&hex::encode(group.as_slice()), &accepted.message_id_hex)
                    .unwrap()
                    && records
                        .iter()
                        .any(|r| hex::encode(r.event_id) == accepted.message_id_hex)
                {
                    assert!(row.plaintext == text);
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("fresh approved channels must deliver original durable offline intent");
    assert!(recipient_app.load_state("test").unwrap().groups.is_empty());
    recipient.shutdown_and_close().await.unwrap();
    member.shutdown_and_close().await.unwrap();
    assert!(recipient.storage_is_closed() && member.storage_is_closed());
}
