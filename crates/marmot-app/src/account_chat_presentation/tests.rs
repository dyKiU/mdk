use super::*;

#[cfg(not(feature = "experimental-device-sync"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paired_presentation_default_refuses_before_input_and_account_effects() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = crate::MarmotAppRuntime::new(crate::MarmotApp::with_relay(
        dir.path(),
        "wss://relay.example",
    ));
    let manager = runtime.accounts();
    assert!(matches!(
        manager
            .paired_chat_list_page("missing", Some(GroupId::new(Vec::new())), 0)
            .await,
        Err(AccountChatReadError::Unsupported)
    ));
    assert!(matches!(
        manager
            .paired_chat_message_page("missing", GroupId::new(Vec::new()), None, 0)
            .await,
        Err(AccountChatReadError::Unsupported)
    ));
    assert!(matches!(
        runtime.open_account_chat_list_window("missing", 0).await,
        Err(AccountChatReadError::Unsupported)
    ));
    assert!(matches!(
        manager
            .account_conversation_page("missing", GroupId::new(Vec::new()), None, 0)
            .await,
        Err(AccountChatReadError::Unsupported)
    ));
    assert!(matches!(
        runtime
            .open_account_conversation_window("missing", &GroupId::new(Vec::new()), 0)
            .await,
        Err(AccountChatReadError::Unsupported)
    ));
    assert!(manager.managed_accounts().unwrap().is_empty());
    runtime.shutdown_and_close().await.unwrap();
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn paired_presentation_canonical_decode_keeps_ordered_rejections_and_tombstone_privacy() {
    use cgka_traits::{
        mirrored_chat_catalog::MirroredChatScope, mirrored_chat_messages::MirroredChatRecord,
    };
    let scope = MirroredChatScope {
        account: [1; 32],
        local_device: [2; 32],
        source_device: [3; 32],
        policy_digest: [4; 32],
        protected_group: GroupId::new(vec![5]),
        protected_generation: 1,
    };
    let tags: Vec<Vec<String>> = vec![
        vec!["imeta".into(), "v unsupported".into()],
        vec!["imeta".into(), "url https://example.invalid/image".into()],
    ];
    let record = MirroredChatRecord {
        event_id: [6; 32],
        author: [7; 32],
        created_at: 10,
        kind: 9,
        payload: serde_json::to_vec(&("synthetic", tags.clone())).unwrap(),
        content_digest: Some([8; 32]),
        expires_at: None,
        deleted: false,
        source_epoch: 1,
        source_sequence: 2,
        source_digest: [9; 32],

        accepted_origin: None,
    };
    let row = storage_sqlite::MirroredMessageObservation {
        scope,
        record,
        edit: None,
    };
    let mut edited = row.clone();
    edited.edit = Some(storage_sqlite::MirroredMessageEdit {
        summary: crate::TimelineEditSummary {
            edit_count: 1,
            latest_edit_message_id_hex: hex::encode([10; 32]),
            edited_at: 20,
        },
        plaintext: "corrected".into(),
        next_expiry: Some(30),
    });
    let corrected = present_message(edited.clone(), false).unwrap();
    assert_eq!(corrected.content, "corrected");
    assert_eq!(corrected.event_id, row.record.event_id);
    assert_eq!(corrected.created_at, row.record.created_at);
    assert_eq!(corrected.edit.as_ref().unwrap().edit_count, 1);
    assert_eq!(corrected.next_edit_expiry, Some(30));
    edited.record.deleted = true;
    edited.record.payload.clear();
    let deleted_edit = present_message(edited, false).unwrap();
    assert!(
        deleted_edit.content.is_empty()
            && deleted_edit.edit.is_none()
            && deleted_edit.next_edit_expiry.is_none()
    );
    let presented = present_message(row.clone(), false).unwrap();
    assert!(presented.tags == tags);
    assert_eq!(presented.media_attachments.len(), 2);
    assert_eq!(presented.source.device, [3; 32]);
    let mut noncanonical = row.clone();
    noncanonical.record.payload.insert(0, b' ');
    assert!(matches!(
        present_message(noncanonical, false),
        Err(AccountChatReadError::InvalidRecord)
    ));
    let mut tombstone = row.clone();
    tombstone.record.deleted = true;
    assert!(matches!(
        present_message(tombstone.clone(), false),
        Err(AccountChatReadError::InvalidRecord)
    ));
    tombstone.record.payload.clear();
    let deleted = present_message(tombstone, false).unwrap();
    assert!(
        deleted.deleted
            && deleted.content.is_empty()
            && deleted.tags.is_empty()
            && deleted.media_attachments.is_empty()
    );
    let mut wrong = row;
    wrong.record.kind = 42;
    let unsupported = present_message(wrong, false).unwrap();
    assert_eq!(
        unsupported.content_kind,
        PairedChatContent::UnsupportedKind(42)
    );
    assert_eq!(unsupported.event_id, [6; 32]);
    assert_eq!(unsupported.source.device, [3; 32]);
    assert!(
        unsupported.content.is_empty()
            && unsupported.tags.is_empty()
            && unsupported.media_attachments.is_empty()
    );
}

#[cfg(all(
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paired_presentation_actual_original_approval_catalog_without_fake_mls_group() {
    use crate::{DeviceLinkingPhase, DeviceLinkingSession, MarmotApp, MarmotAppRuntime};
    use cgka_traits::storage::GroupStorage;
    let relay = nostr_relay_builder::LocalRelay::new(nostr_relay_builder::RelayBuilder::default());
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs: [tempfile::TempDir; 2] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
    let apps: [MarmotApp; 2] = std::array::from_fn(|i| {
        marmot_account::AccountHome::open(dirs[i].path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        MarmotApp::with_relay(dirs[i].path(), &url)
    });
    let runtimes = apps.clone().map(MarmotAppRuntime::new);
    for runtime in &runtimes {
        runtime.reconcile_accounts().await.unwrap();
    }
    let managers = runtimes.each_ref().map(|runtime| runtime.accounts());
    assert!(
        managers[1]
            .paired_chat_list_page("test", None, 128)
            .await
            .unwrap()
            .chats
            .is_empty()
    );
    let b = managers[1]
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let a = managers[0]
        .approve_device_linking_session("test", b.setup_packet(), None)
        .await
        .unwrap();
    async fn drain(from: &DeviceLinkingSession, to: &DeviceLinkingSession) {
        for packet in from.outgoing_packets().await.unwrap() {
            to.receive_packet(packet.bytes).await.unwrap();
            from.acknowledge_packet(packet.acknowledgement_id)
                .await
                .unwrap();
        }
    }
    b.receive_setup_packet(a.setup_packet()).await.unwrap();
    for _ in 0..8 {
        drain(&a, &b).await;
        drain(&b, &a).await;
    }
    let first = a.snapshot().await.unwrap();
    let second = b.snapshot().await.unwrap();
    assert_eq!(first.phase, DeviceLinkingPhase::ComparisonAvailable);
    assert_eq!(first.decimals, second.decimals);
    a.confirm_comparison(first.revision).await.unwrap();
    b.confirm_comparison(second.revision).await.unwrap();
    for _ in 0..8 {
        drain(&a, &b).await;
        drain(&b, &a).await;
    }
    b.continue_linking_and_share_chats(b.snapshot().await.unwrap().revision)
        .await
        .unwrap();
    a.continue_linking_and_share_chats(a.snapshot().await.unwrap().revision)
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            if a.snapshot().await.unwrap().phase == DeviceLinkingPhase::EnrollmentComplete
                && b.snapshot().await.unwrap().phase == DeviceLinkingPhase::EnrollmentComplete
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("actual original two-device protected settlement");
    a.cancel().await.unwrap();
    b.cancel().await.unwrap();
    let mut window = runtimes[1]
        .open_account_chat_list_window("test", 128)
        .await
        .unwrap();
    assert!(window.snapshot.rows.is_empty());
    let group = managers[0]
        .create_group("test", "synthetic paired conversation", &[], None)
        .await
        .unwrap();
    let page = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let page = managers[1]
                .paired_chat_list_page("test", None, 128)
                .await
                .unwrap();
            if page.chats.iter().any(|chat| chat.group_id == group) {
                break page;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("real encrypted original-approved catalogue must reach worker query");
    let row = page
        .chats
        .iter()
        .find(|chat| chat.group_id == group)
        .unwrap();
    assert_eq!(row.name, "synthetic paired conversation");
    assert_ne!(row.source.device, [0; 32]);
    let visible = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let update = window
                .recv()
                .await
                .unwrap()
                .expect("live source-qualified window");
            if update.rows.iter().any(|row| {
                matches!(row,
                crate::AccountChatRow::PairedSource(row) if row.group_id==group)
            }) {
                break update;
            }
        }
    })
    .await
    .expect("committed catalogue wake must make mirrored conversation visible");
    assert!(visible.rows.len() <= 128);
    assert!(visible.local.rows.is_empty());
    assert!(matches!(
        window
            .window_handle()
            .paired_page(visible.sequence + 1, None)
            .await,
        Err(AccountChatReadError::StaleWindow)
    ));

    assert!(
        matches!(
            apps[1].account_storage("test").unwrap().get_group(&group),
            Err(cgka_traits::StorageError::NotFound)
        ),
        "read presentation must not fabricate MLS membership"
    );
    assert!(
        managers[0]
            .paired_chat_list_page("test", None, 128)
            .await
            .unwrap()
            .chats
            .iter()
            .all(|chat| chat.group_id != group),
        "ordinary local group takes precedence"
    );
    assert!(
        managers[1]
            .paired_chat_message_page("test", group.clone(), None, 128)
            .await
            .unwrap()
            .messages
            .is_empty()
    );
    assert!(matches!(
        managers[1]
            .paired_chat_list_page("missing", None, 128)
            .await,
        Err(AccountChatReadError::RuntimeUnavailable)
    ));
    let mut local_conversation = runtimes[0]
        .open_account_conversation_window("test", &group, 128)
        .await
        .unwrap();
    assert!(matches!(
        local_conversation.snapshot.header,
        crate::AccountConversationHeader::LocalMls(_)
    ));
    local_conversation.window_handle().cancel();
    assert!(local_conversation.recv().await.unwrap().is_none());
    let mut conversation = runtimes[1]
        .open_account_conversation_window("test", &group, 128)
        .await
        .unwrap();
    assert!(matches!(
        conversation.snapshot.header,
        crate::AccountConversationHeader::PairedSource(_)
    ));
    assert!(conversation.snapshot.rows.is_empty());
    assert!(matches!(
        conversation
            .window_handle()
            .older_page(conversation.snapshot.sequence + 1, None)
            .await,
        Err(AccountChatReadError::StaleWindow)
    ));
    conversation.window_handle().cancel();
    assert!(conversation.recv().await.unwrap().is_none());
    assert!(matches!(
        conversation
            .window_handle()
            .older_page(conversation.snapshot.sequence, None)
            .await,
        Err(AccountChatReadError::Closed)
    ));
    let mut live_conversation = runtimes[1]
        .open_account_conversation_window("test", &group, 128)
        .await
        .unwrap();
    window.window_handle().cancel();
    assert!(window.recv().await.unwrap().is_none());
    assert!(matches!(
        window
            .window_handle()
            .paired_page(visible.sequence, None)
            .await,
        Err(AccountChatReadError::Closed)
    ));
    let mut live_window = runtimes[1]
        .open_account_chat_list_window("test", 128)
        .await
        .unwrap();
    assert!(live_window.snapshot.rows.iter().any(|row| matches!(row,
        crate::AccountChatRow::PairedSource(row) if row.group_id==group)));
    let sent = managers[0]
        .send_message("test", &group, b"Synthetic latest shared preview".to_vec())
        .await
        .unwrap();
    assert_eq!(sent.message_ids.len(), 1);
    let latest = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let update = live_window
                .recv()
                .await
                .unwrap()
                .expect("live activity window");
            if let Some(message) = update.rows.iter().find_map(|row| match row {
                crate::AccountChatRow::PairedSource(row) if row.group_id == group => {
                    row.latest_message.clone()
                }
                _ => None,
            }) {
                break message;
            }
        }
    })
    .await
    .expect("real received body must wake chat-list preview without navigation");
    assert_eq!(latest.content, "Synthetic latest shared preview");
    assert_eq!(hex::encode(latest.event_id), sent.message_ids[0]);
    assert!(latest.created_at > 0);
    assert!(!latest.deleted);
    assert!(matches!(
        apps[1].account_storage("test").unwrap().get_group(&group),
        Err(cgka_traits::StorageError::NotFound)
    ));
    for runtime in &runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
    assert!(live_conversation.recv().await.unwrap().is_none());
    assert!(live_window.recv().await.unwrap().is_none());
    assert!(window.recv().await.unwrap().is_none());
    assert!(matches!(
        window
            .window_handle()
            .paired_page(visible.sequence, None)
            .await,
        Err(AccountChatReadError::Closed)
    ));

    assert!(
        managers[1]
            .paired_chat_list_page("test", None, 128)
            .await
            .is_err()
    );
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn paired_summary_keeps_source_attested_peer_and_preserves_unknown_legacy_peer() {
    use cgka_traits::mirrored_chat_catalog::{
        MirroredChatEntry, MirroredChatScope, MirroredChatState,
    };
    for peer in [None, Some([9; 32])] {
        let observation = storage_sqlite::MirroredCatalogObservation {
            scope: MirroredChatScope {
                account: [1; 32],
                local_device: [2; 32],
                source_device: [3; 32],
                policy_digest: [4; 32],
                protected_group: GroupId::new(vec![5]),
                protected_generation: 6,
            },
            entry: MirroredChatEntry {
                group_id: GroupId::new(vec![7]),
                source_epoch: 8,
                source_sequence: 10,
                source_digest: [11; 32],
                profile: cgka_traits::group::ProtocolProfile::Current,
                name: String::new(),
                description: String::new(),
                state: MirroredChatState::Active,
                accepted_origin: None,
                same_account_source_count: Some(1),
                direct_peer_account: peer,
            },
        };
        let summary = PairedChatSummary::from(observation.clone());
        assert_eq!(summary.direct_peer_account, peer);
        assert!(summary.name.is_empty());
        assert_eq!(summary.source.device, [3; 32]);
        assert_eq!(summary.source.protected_generation, 6);
        assert_eq!(summary.source.source_sequence, 10);
        assert!(summary.latest_message.is_none());
        // Header and latest body can be selected from different approved sources.
        let mut body_scope = observation.scope.clone();
        body_scope.source_device = [12; 32];
        let record = cgka_traits::mirrored_chat_messages::MirroredChatRecord {
            event_id: [13; 32],
            author: [14; 32],
            created_at: 123,
            kind: 9,
            payload: serde_json::to_vec(&("synthetic preview", Vec::<Vec<String>>::new())).unwrap(),
            expires_at: Some(200),
            content_digest: Some([15; 32]),
            deleted: false,
            source_epoch: 9,
            source_sequence: 11,
            source_digest: [16; 32],
            accepted_origin: None,
        };
        let mut activity = storage_sqlite::MirroredChatActivityObservation {
            catalog: observation,
            latest_message: Some(storage_sqlite::MirroredMessageObservation {
                edit: None,
                scope: body_scope,
                record,
            }),
        };
        let shown = present_chat_activity(activity.clone(), false).unwrap();
        assert_eq!(shown.source.device, [3; 32]);
        let latest = shown.latest_message.unwrap();
        assert_eq!(latest.content, "synthetic preview");
        assert_eq!(latest.created_at, 123);
        assert_eq!(latest.expires_at, Some(200));
        assert_eq!(latest.source.device, [12; 32]);
        assert_eq!(latest.source.source_sequence, 11);
        let body = activity.latest_message.as_mut().unwrap();
        body.record.deleted = true;
        body.record.payload.clear();
        let shown = present_chat_activity(activity.clone(), false).unwrap();
        let deleted = shown.latest_message.unwrap();
        assert!(deleted.deleted && deleted.content.is_empty() && deleted.tags.is_empty());
        // A malformed live body must fail closed rather than publish stale plaintext.
        let body = activity.latest_message.as_mut().unwrap();
        body.record.deleted = false;
        body.record.payload = b"invalid canonical record".to_vec();
        assert!(matches!(
            present_chat_activity(activity, false),
            Err(AccountChatReadError::InvalidRecord)
        ));
    }
}
