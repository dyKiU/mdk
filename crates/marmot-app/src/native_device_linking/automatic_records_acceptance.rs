//! Actual independent-store source-attested records over the paired private relay.
use super::*;
use cgka_traits::StorageProvider;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_records_include_preapproval_and_future_messages_without_per_chat_actions() {
    actual::run_native_public_three_device_enrollment(actual::ApprovalScenario::AutomaticRecords)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_records_wake_the_original_open_conversation_after_committed_future_import() {
    actual::run_native_public_three_device_enrollment(
        actual::ApprovalScenario::AutomaticRecordsWindow,
    )
    .await;
}

pub(super) async fn seed(
    manager: &crate::runtime::AccountManager,
    group: &crate::GroupId,
) -> Vec<String> {
    let summary = manager
        .send_message("test", group, vec![b'x'; 4096])
        .await
        .unwrap();
    assert_eq!(summary.published, 1);
    assert_eq!(summary.message_ids.len(), 1);
    summary.message_ids
}

pub(super) async fn verify(
    apps: &[MarmotApp; 3],
    manager: &crate::runtime::AccountManager,
    group: &crate::GroupId,
    scope: &cgka_traits::mirrored_chat_catalog::MirroredChatScope,
    initial: &[String],
    window_runtime: Option<&MarmotAppRuntime>,
) {
    wait_for_records(apps, group, scope, initial).await;
    // Open the real approved C observation owner before the ordinary A send.
    // Catalog discovery and earlier record receipt are already complete; no
    // explicit page/reopen or fabricated wake may expose this later batch.
    let mut window = if let Some(runtime) = window_runtime {
        let window = runtime
            .open_account_conversation_window("test", group, 128)
            .await
            .unwrap();
        assert!(matches!(
            window.snapshot.header,
            crate::AccountConversationHeader::PairedSource(_)
        ));
        assert!(initial.iter().all(|id| has_record(&window.snapshot, id)));
        Some(window)
    } else {
        None
    };
    let future = manager
        .send_message("test", group, b"automatic future message".to_vec())
        .await
        .unwrap();
    assert_eq!(future.published, 1);
    assert_eq!(future.message_ids.len(), 1);
    let mut expected = initial.to_vec();
    expected.extend(future.message_ids.clone());
    wait_for_records(apps, group, scope, &expected).await;
    if let Some(window) = &mut window {
        let generation = window.snapshot.generation.clone();
        let sequence = window.snapshot.sequence;
        // The SQL and authenticated receipt witness above is deliberately
        // independent of the window. A stale subscription must fail even
        // though automatic transport/import succeeded.
        let visible = tokio::time::timeout(std::time::Duration::from_secs(8), async {
            loop {
                let update = window
                    .recv()
                    .await
                    .unwrap()
                    .expect("the original approved conversation must remain live");
                if future.message_ids.iter().all(|id| has_record(&update, id)) {
                    break update;
                }
            }
        })
        .await
        .expect("committed future record import must wake the original open conversation without paging or reopening");
        assert!(visible.generation == generation);
        assert!(visible.sequence > sequence);
        assert!(expected.iter().all(|id| has_record(&visible, id)));
        window.window_handle().cancel();
        assert!(window.recv().await.unwrap().is_none());
    }
    assert!(
        apps[2].load_state("test").unwrap().groups.is_empty(),
        "source-attested rows must not fabricate ordinary membership"
    );
    assert!(
        apps[1]
            .account_storage("test")
            .unwrap()
            .mirrored_chat_message_storage()
            .unwrap()
            .mirrored_chat_message_page(scope, group, None, 128, crate::unix_now_seconds())
            .is_err(),
        "unapproved B cannot read C-owned records"
    );
}

fn has_record(snapshot: &crate::AccountConversationWindowSnapshot, event_id: &str) -> bool {
    snapshot.rows.iter().any(|row| {
        matches!(row, crate::AccountConversationRow::PairedSource(record)
            if hex::encode(record.event_id) == event_id)
    })
}

async fn wait_for_records(
    apps: &[MarmotApp; 3],
    group: &crate::GroupId,
    scope: &cgka_traits::mirrored_chat_catalog::MirroredChatScope,
    expected: &[String],
) {
    tokio::time::timeout(std::time::Duration::from_secs(90), async {
        loop {
            let receiver = apps[2].account_storage("test").unwrap();
            let records = receiver.mirrored_chat_message_storage().unwrap().mirrored_chat_message_page(scope, group, None, 128, crate::unix_now_seconds()).unwrap();
            if expected.iter().all(|id| records.iter().any(|record| hex::encode(record.event_id) == *id)) {
                let source = apps[0].account_storage("test").unwrap();
                for id in expected {
                    let row = source.app_storage().app_message(&hex::encode(group.as_slice()), id).unwrap().unwrap();
                    let record = records.iter().find(|record| hex::encode(record.event_id) == *id).unwrap();
                    assert!(record.payload == serde_json::to_vec(&(&row.plaintext, &row.tags)).unwrap(), "canonical logical payload and tags must survive actual encrypted transport");
                    assert_eq!(hex::encode(record.author), row.sender);
                    assert_eq!(record.created_at, row.recorded_at);
                    assert_eq!(record.kind, 9);
                    assert!(!record.deleted);
                    assert!(record.source_sequence > 0);
                }
                let policy = apps[0].account_storage("test").unwrap().approved_account_sharing_policy_storage().unwrap().approved_account_sharing_policies().unwrap().into_iter().find(|policy| policy.peer_device == scope.local_device).unwrap();
                let policy_id = cgka_traits::approved_account_sharing_policy::approved_account_sharing_identity(&policy.account, &policy.protected_group, &policy.local_device, &policy.peer_device, &policy.approval_id).unwrap();
                if source.account_chat_record_stream_storage().unwrap().pending_account_chat_record_batches(&policy_id, group, None, 128).unwrap().is_empty() { break; }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }).await.expect("actual approved private carrier must commit records and return authenticated receipts");
}
