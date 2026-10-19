//! Synthetic storage controls; these scopes do not prove original SDK approval.
use super::*;
use crate::SqliteAccountStorage;
use cgka_traits::{
    MemberId,
    group::ProtocolProfile,
    mirrored_chat_catalog::{MirroredChatCatalogStorage, MirroredChatState},
    mirrored_chat_messages::MirroredChatMessageStorage,
    storage::{AccountDeviceSignerBinding, AccountDeviceSignerStorage, GroupStorage},
};
use sha2::{Digest, Sha256};

#[test]
fn mirrored_activity_page_is_bounded_latest_deduplicated_and_read_only() {
    let storage = stored();
    let a = scope(3);
    let b = scope(4);
    let group = GroupId::new(vec![1]);
    catalog(&storage, &a, &[1, 2, 3], MirroredChatState::Active);
    catalog(&storage, &b, &[1], MirroredChatState::Active);
    storage
        .apply_mirrored_chat_messages(&a, &group, &[record(1, 10), record(2, 20)], 0, &|| Ok(()))
        .unwrap();
    storage
        .apply_mirrored_chat_messages(&b, &group, &[record(2, 20), record(3, 20)], 0, &|| Ok(()))
        .unwrap();
    let scopes = [a, b];
    let changes = storage.lock().unwrap().total_changes();
    let page = storage
        .app_storage()
        .mirrored_catalog_activity_page(&scopes, None, 2, 0)
        .unwrap();
    assert_eq!(page.len(), 2);
    assert!(page[0].catalog.entry.group_id == group);
    let latest = page[0].latest_message.as_ref().unwrap();
    assert_eq!(latest.record.event_id, [3; 32]);
    assert_eq!(latest.record.created_at, 20);
    assert_eq!(latest.scope.source_device, [4; 32]);
    assert!(page[1].latest_message.is_none());
    let tail = storage
        .app_storage()
        .mirrored_catalog_activity_page(&scopes, Some(&page[1].catalog.entry.group_id), 2, 0)
        .unwrap();
    assert_eq!(tail.len(), 1);
    assert!(tail[0].catalog.entry.group_id == GroupId::new(vec![3]));
    assert_eq!(storage.lock().unwrap().total_changes(), changes);
    assert!(matches!(
        storage.get_group(&group),
        Err(StorageError::NotFound)
    ));
}

#[test]
fn mirrored_activity_preserves_block_expiry_and_global_terminal_fences() {
    let storage = stored();
    let a = scope(3);
    let b = scope(4);
    let group = GroupId::new(vec![1]);
    catalog(&storage, &a, &[1], MirroredChatState::Active);
    catalog(&storage, &b, &[1], MirroredChatState::Active);
    let mut older = record(1, 10);
    older.author = [8; 32];
    older.expires_at = Some(20);
    storage
        .apply_mirrored_chat_messages(&a, &group, &[older.clone(), record(2, 30)], 0, &|| Ok(()))
        .unwrap();
    storage
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO user_blocks(public_key,is_private,created_at_ms) VALUES(?1,0,0)",
            [hex::encode([7; 32])],
        )
        .unwrap();
    older.expires_at = Some(15);
    older.source_sequence = 2;
    storage
        .apply_mirrored_chat_messages(&b, &group, &[older.clone()], 0, &|| Ok(()))
        .unwrap();
    let page = storage
        .app_storage()
        .mirrored_catalog_activity_page(std::slice::from_ref(&a), None, 1, 15)
        .unwrap();
    let latest = page[0].latest_message.as_ref().unwrap();
    assert_eq!(latest.record.event_id, [1; 32]);
    assert!(latest.record.deleted && latest.record.payload.is_empty());
    older.deleted = true;
    older.payload.clear();
    older.source_sequence = 3;
    storage
        .apply_mirrored_chat_messages(&b, &group, &[older], 0, &|| Ok(()))
        .unwrap();
    let page = storage
        .app_storage()
        .mirrored_catalog_activity_page(std::slice::from_ref(&a), None, 1, 0)
        .unwrap();
    assert!(page[0].latest_message.is_none());
    let page = storage
        .app_storage()
        .mirrored_catalog_activity_page(&[a, b], None, 1, 0)
        .unwrap();
    assert!(page[0].latest_message.as_ref().unwrap().record.deleted);
}

#[test]
fn mirrored_activity_rejects_invalid_or_closed_inputs_and_omits_retired_sources() {
    let storage = stored();
    let a = scope(3);
    catalog(&storage, &a, &[1], MirroredChatState::Active);
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_activity_page(&[a.clone(), a.clone()], None, 1, 0)
            .is_err()
    );
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_activity_page(std::slice::from_ref(&a), None, 0, 0)
            .is_err()
    );
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_activity_page(std::slice::from_ref(&a), None, 1, u64::MAX)
            .is_err()
    );
    let mut wrong = a.clone();
    wrong.account = [9; 32];
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_activity_page(&[wrong], None, 1, 0)
            .is_err()
    );
    catalog(&storage, &a, &[1], MirroredChatState::Deleted);
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_activity_page(std::slice::from_ref(&a), None, 1, 0)
            .unwrap()
            .is_empty()
    );
    storage.close().unwrap();
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_activity_page(&[a], None, 1, 0)
            .is_err()
    );
}

fn scope(source: u8) -> MirroredChatScope {
    MirroredChatScope {
        account: [1; 32],
        local_device: [2; 32],
        source_device: [source; 32],
        policy_digest: [source; 32],
        protected_group: GroupId::new(vec![99]),
        protected_generation: 1,
    }
}
fn stored() -> SqliteAccountStorage {
    let storage = SqliteAccountStorage::in_memory().unwrap();
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
    storage
}
fn catalog(
    storage: &SqliteAccountStorage,
    scope: &MirroredChatScope,
    ids: &[u8],
    state: MirroredChatState,
) {
    let entries = ids
        .iter()
        .map(|id| MirroredChatEntry {
            group_id: GroupId::new(vec![*id]),
            source_epoch: 1,
            source_sequence: if state == MirroredChatState::Active {
                1
            } else {
                2
            },
            source_digest: [*id; 32],
            profile: ProtocolProfile::Current,
            name: if state == MirroredChatState::Active {
                "synthetic".into()
            } else {
                String::new()
            },
            description: String::new(),
            state,

            accepted_origin: None,

            same_account_source_count: None,

            direct_peer_account: None,
        })
        .collect::<Vec<_>>();
    storage
        .apply_mirrored_chat_catalog(scope, &entries, &|| Ok(()))
        .unwrap();
}
fn record(id: u8, time: u64) -> MirroredChatRecord {
    let payload = serde_json::to_vec(&("synthetic", Vec::<Vec<String>>::new())).unwrap();
    MirroredChatRecord {
        event_id: [id; 32],
        author: [7; 32],
        created_at: time,
        kind: 9,
        content_digest: Some(Sha256::digest(&payload).into()),
        payload,
        expires_at: None,
        deleted: false,
        source_epoch: 1,
        source_sequence: 1,
        source_digest: [id; 32],

        accepted_origin: None,
    }
}
#[test]
fn mirrored_presentation_total_limit_dedup_and_catalog_cursor() {
    let storage = stored();
    let a = scope(3);
    let b = scope(4);
    catalog(&storage, &a, &[3, 1], MirroredChatState::Active);
    catalog(&storage, &b, &[1, 2], MirroredChatState::Active);
    let scopes = [a, b];
    let rows = storage
        .app_storage()
        .mirrored_catalog_observation_page(&scopes, None, 2)
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows[0].entry.group_id == GroupId::new(vec![1]));
    assert!(rows[1].entry.group_id == GroupId::new(vec![2]));
    let tail = storage
        .app_storage()
        .mirrored_catalog_observation_page(&scopes, Some(&rows[1].entry.group_id), 2)
        .unwrap();
    assert_eq!(tail.len(), 1);
    assert!(tail[0].entry.group_id == GroupId::new(vec![3]));
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_observation_page(&[], None, 128)
            .unwrap()
            .is_empty()
    );
}
#[test]
fn mirrored_presentation_excludes_unselected_generation_and_terminal_source() {
    let storage = stored();
    let a = scope(3);
    let b = scope(4);
    catalog(&storage, &a, &[1], MirroredChatState::Active);
    catalog(&storage, &b, &[2], MirroredChatState::Active);
    let mut renewed = a.clone();
    renewed.protected_generation = 2;
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_observation_page(&[renewed.clone()], None, 128)
            .unwrap()
            .is_empty()
    );
    catalog(&storage, &renewed, &[1], MirroredChatState::Deleted);
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_observation_page(&[a], None, 128)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        storage
            .app_storage()
            .mirrored_catalog_observation_page(&[b], None, 128)
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn mirrored_presentation_message_union_orders_and_paginates_once() {
    let storage = stored();
    let a = scope(3);
    let b = scope(4);
    let group = GroupId::new(vec![1]);
    catalog(&storage, &a, &[1], MirroredChatState::Active);
    catalog(&storage, &b, &[1], MirroredChatState::Active);
    storage
        .apply_mirrored_chat_messages(&a, &group, &[record(3, 30), record(1, 10)], 0, &|| Ok(()))
        .unwrap();
    storage
        .apply_mirrored_chat_messages(&b, &group, &[record(2, 20), record(1, 10)], 0, &|| Ok(()))
        .unwrap();
    let scopes = [a, b];
    let rows = storage
        .app_storage()
        .mirrored_message_observation_page(&scopes, &group, None, 2, 0)
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].record.event_id, [1; 32]);
    assert_eq!(rows[1].record.event_id, [2; 32]);
    let cursor = MirroredChatCursor {
        created_at: 20,
        event_id: [2; 32],
    };
    let tail = storage
        .app_storage()
        .mirrored_message_observation_page(&scopes, &group, Some(&cursor), 2, 0)
        .unwrap();
    assert_eq!(tail.len(), 1);
    assert_eq!(tail[0].record.event_id, [3; 32]);
}
#[test]
fn mirrored_presentation_expiry_and_cross_source_tombstone_hide_payload() {
    let storage = stored();
    let a = scope(3);
    let b = scope(4);
    let group = GroupId::new(vec![1]);
    catalog(&storage, &a, &[1], MirroredChatState::Active);
    catalog(&storage, &b, &[1], MirroredChatState::Active);
    let mut original = record(1, 10);
    original.expires_at = Some(20);
    storage
        .apply_mirrored_chat_messages(&a, &group, &[original.clone()], 0, &|| Ok(()))
        .unwrap();
    let expired = storage
        .app_storage()
        .mirrored_message_observation_page(std::slice::from_ref(&a), &group, None, 128, 20)
        .unwrap();
    assert!(expired[0].record.deleted && expired[0].record.payload.is_empty());
    original.deleted = true;
    original.payload.clear();
    original.source_sequence = 2;
    storage
        .apply_mirrored_chat_messages(&b, &group, &[original], 0, &|| Ok(()))
        .unwrap();
    assert!(
        storage
            .app_storage()
            .mirrored_message_observation_page(&[a], &group, None, 128, 0)
            .unwrap()
            .is_empty()
    );
    let terminal = storage
        .app_storage()
        .mirrored_message_observation_page(&[b], &group, None, 128, 0)
        .unwrap();
    assert!(terminal[0].record.deleted && terminal[0].record.payload.is_empty());
}
#[test]
fn mirrored_presentation_bounds_duplicate_scopes_and_wrong_account_fail_closed() {
    let storage = stored();
    let a = scope(3);
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_observation_page(&[a.clone(), a.clone()], None, 128)
            .is_err()
    );
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_observation_page(&[], None, 0)
            .is_err()
    );
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_observation_page(&[], None, 129)
            .is_err()
    );
    let mut wrong = a;
    wrong.account = [8; 32];
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_observation_page(&[wrong], None, 128)
            .is_err()
    );
    let scopes = (3..132).map(scope).collect::<Vec<_>>();
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_observation_page(&scopes, None, 128)
            .is_err()
    );
}
#[test]
fn mirrored_presentation_real_ordinary_id_precedence_even_after_invalidation() {
    let storage = stored();
    let a = scope(3);
    let group = GroupId::new(vec![1]);
    catalog(&storage, &a, &[1], MirroredChatState::Active);
    storage
        .apply_mirrored_chat_messages(&a, &group, &[record(1, 10)], 0, &|| Ok(()))
        .unwrap();
    storage.lock().unwrap().execute("INSERT INTO app_events(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,recorded_at,received_at,invalidated) VALUES(?1,?2,'inbound','synthetic','',9,'[]',10,10,1)",rusqlite::params![hex::encode(group.as_slice()),hex::encode([1;32])]).unwrap();
    let activity = storage
        .app_storage()
        .mirrored_catalog_activity_page(std::slice::from_ref(&a), None, 1, 0)
        .unwrap();
    assert!(activity[0].latest_message.is_none());
    assert!(
        storage
            .app_storage()
            .mirrored_message_observation_page(std::slice::from_ref(&a), &group, None, 128, 0)
            .unwrap()
            .is_empty()
    );
    storage
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO cgka_groups(id,epoch,record) VALUES(?1,0,X'00')",
            [group.as_slice()],
        )
        .unwrap();
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_observation_page(std::slice::from_ref(&a), None, 128)
            .unwrap()
            .is_empty()
    );
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_activity_page(&[a], None, 128, 0)
            .unwrap()
            .is_empty()
    );
}
#[test]
fn mirrored_presentation_blocked_author_is_filtered_before_total_limit() {
    let storage = stored();
    let a = scope(3);
    let group = GroupId::new(vec![1]);
    catalog(&storage, &a, &[1], MirroredChatState::Active);
    let blocked = record(1, 10);
    let mut allowed = record(2, 20);
    allowed.author = [8; 32];
    storage
        .apply_mirrored_chat_messages(&a, &group, &[blocked, allowed], 0, &|| Ok(()))
        .unwrap();
    storage
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO user_blocks(public_key,is_private,created_at_ms) VALUES(?1,0,0)",
            [hex::encode([7; 32])],
        )
        .unwrap();
    let page = storage
        .app_storage()
        .mirrored_message_observation_page(std::slice::from_ref(&a), &group, None, 1, 0)
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].record.event_id, [2; 32]);
}

#[test]
fn mirrored_presentation_latest_window_uses_canonical_exclusive_cursor() {
    let storage = stored();
    let a = scope(3);
    let group = GroupId::new(vec![1]);
    catalog(&storage, &a, &[1], MirroredChatState::Active);
    storage
        .apply_mirrored_chat_messages(
            &a,
            &group,
            &[record(1, 10), record(2, 20), record(3, 20)],
            0,
            &|| Ok(()),
        )
        .unwrap();
    let latest = storage
        .app_storage()
        .mirrored_message_observation_window(std::slice::from_ref(&a), &group, None, 2, 0)
        .unwrap();
    assert_eq!(
        latest.iter().map(|r| r.record.event_id).collect::<Vec<_>>(),
        [[2; 32], [3; 32]]
    );
    let earlier = storage
        .app_storage()
        .mirrored_message_observation_window(
            std::slice::from_ref(&a),
            &group,
            Some(&MirroredChatCursor {
                created_at: 20,
                event_id: [2; 32],
            }),
            2,
            0,
        )
        .unwrap();
    assert_eq!(
        earlier
            .iter()
            .map(|r| r.record.event_id)
            .collect::<Vec<_>>(),
        [[1; 32]]
    );
}

#[test]
fn mirrored_presentation_conversation_union_has_one_limit_and_real_ordinary_precedence() {
    let storage = stored();
    let scope = scope(3);
    let group = GroupId::new(vec![1]);
    catalog(&storage, &scope, &[1], MirroredChatState::Active);
    storage
        .apply_mirrored_chat_messages(
            &scope,
            &group,
            &[record(1, 10), record(2, 20), record(3, 30)],
            0,
            &|| Ok(()),
        )
        .unwrap();
    let event = crate::StoredAppEvent {
        group_id_hex: hex::encode(group.as_slice()),
        message_id_hex: hex::encode([2; 32]),
        direction: "received".into(),
        sender: hex::encode([8; 32]),
        plaintext: "ordinary".into(),
        kind: 9,
        tags: Vec::new(),
        recorded_at: 25,
        received_at: 26,
        source_message_id_hex: Some(hex::encode([2; 32])),
        source_epoch: Some(1),
        origin_commit_id: None,
        moderation_grant: false,
    };
    storage.app_storage().record_app_event(&event).unwrap();
    let rows = storage
        .app_storage()
        .account_conversation_observation_window(std::slice::from_ref(&scope), &group, None, 2, 0)
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        matches!(&rows[0],AccountConversationObservation::LocalMls(row) if row.message_id_hex==hex::encode([2;32]) && row.plaintext=="ordinary")
    );
    assert!(
        matches!(&rows[1],AccountConversationObservation::PairedSource(row) if row.record.event_id==[3;32])
    );
    let cursor = MirroredChatCursor {
        created_at: 25,
        event_id: [2; 32],
    };
    let earlier = storage
        .app_storage()
        .account_conversation_observation_window(
            std::slice::from_ref(&scope),
            &group,
            Some(&cursor),
            2,
            0,
        )
        .unwrap();
    assert_eq!(earlier.len(), 1);
    assert!(
        matches!(&earlier[0],AccountConversationObservation::PairedSource(row) if row.record.event_id==[1;32])
    );
    storage.lock().unwrap().execute("UPDATE app_events SET retention_seconds=1,retention_expires_at=26 WHERE message_id_hex=?1",[hex::encode([2;32])]).unwrap();
    let expired = storage
        .app_storage()
        .account_conversation_observation_window(std::slice::from_ref(&scope), &group, None, 2, 26)
        .unwrap();
    assert!(
        matches!(&expired[0],AccountConversationObservation::LocalMls(row) if row.deleted && row.plaintext.is_empty() && row.tags.is_empty())
    );
    assert!(
        storage
            .app_storage()
            .mirrored_catalog_observation(&[scope], &group)
            .unwrap()
            .is_some()
    );
}

#[test]
fn mirrored_edits_update_the_original_message_without_creating_activity() {
    let storage = stored();
    let scope = scope(3);
    let group = GroupId::new(vec![1]);
    catalog(&storage, &scope, &[1], MirroredChatState::Active);
    let original = record(1, 10);
    let mut edit = record(2, 20);
    edit.kind = 1009;
    edit.payload = serde_json::to_vec(&(
        "corrected text",
        vec![vec!["e".to_owned(), hex::encode(original.event_id)]],
    ))
    .unwrap();
    edit.content_digest = Some(Sha256::digest(&edit.payload).into());
    storage
        .apply_mirrored_chat_messages(&scope, &group, &[original.clone(), edit], 0, &|| Ok(()))
        .unwrap();
    let page = storage
        .app_storage()
        .mirrored_message_observation_page(std::slice::from_ref(&scope), &group, None, 128, 0)
        .unwrap();
    assert_eq!(
        page.len(),
        1,
        "an edit modifies its target, never adds a conversation row"
    );
    assert_eq!(page[0].record.event_id, original.event_id);
    assert_eq!(page[0].record.created_at, original.created_at);
    assert_eq!(
        page[0].record.payload, original.payload,
        "canonical source bytes stay immutable"
    );
    let accepted = page[0].edit.as_ref().expect("edit metadata");
    assert_eq!(accepted.plaintext, "corrected text");
    assert_eq!(accepted.summary.edit_count, 1);
    assert_eq!(accepted.summary.edited_at, 20);
    let activity = storage
        .app_storage()
        .mirrored_catalog_activity_page(&[scope], None, 1, 0)
        .unwrap();
    assert_eq!(
        activity[0].latest_message.as_ref().unwrap().record.event_id,
        original.event_id
    );
}

fn edit_record(id: u8, at: u64, target: [u8; 32], text: &str) -> MirroredChatRecord {
    let mut edit = record(id, at);
    edit.kind = 1009;
    edit.payload =
        serde_json::to_vec(&(text, vec![vec!["e".to_owned(), hex::encode(target)]])).unwrap();
    edit.content_digest = Some(Sha256::digest(&edit.payload).into());
    edit
}

#[test]
fn mirrored_edits_require_author_and_exact_target_and_survive_out_of_order_arrival() {
    let storage = stored();
    let scope = scope(3);
    let group = GroupId::new(vec![1]);
    catalog(&storage, &scope, &[1], MirroredChatState::Active);
    let original = record(1, 10);
    let valid = edit_record(2, 20, original.event_id, "corrected");
    let mut impostor = edit_record(3, 30, original.event_id, "wrong author");
    impostor.author = [8; 32];
    let mut ambiguous = edit_record(4, 40, original.event_id, "ambiguous");
    ambiguous.payload = serde_json::to_vec(&(
        "ambiguous",
        vec![
            vec!["e", &hex::encode(original.event_id)],
            vec!["e", &hex::encode([5; 32])],
        ],
    ))
    .unwrap();
    ambiguous.content_digest = Some(Sha256::digest(&ambiguous.payload).into());
    storage
        .apply_mirrored_chat_messages(&scope, &group, &[valid, impostor, ambiguous], 0, &|| Ok(()))
        .unwrap();
    assert!(
        storage
            .app_storage()
            .mirrored_message_observation_page(std::slice::from_ref(&scope), &group, None, 1, 0)
            .unwrap()
            .is_empty()
    );
    storage
        .apply_mirrored_chat_messages(&scope, &group, &[original], 0, &|| Ok(()))
        .unwrap();
    let page = storage
        .app_storage()
        .mirrored_message_observation_window(&[scope], &group, None, 1, 0)
        .unwrap();
    assert_eq!(page.len(), 1);
    let edit = page[0].edit.as_ref().unwrap();
    assert_eq!(edit.plaintext, "corrected");
    assert_eq!(edit.summary.edit_count, 1);
}

#[test]
fn mirrored_edits_deduplicate_sources_and_honor_global_retraction_and_expiry() {
    let storage = stored();
    let a = scope(3);
    let b = scope(4);
    let group = GroupId::new(vec![1]);
    for scope in [&a, &b] {
        catalog(&storage, scope, &[1], MirroredChatState::Active);
    }
    let original = record(1, 10);
    let first = edit_record(2, 20, original.event_id, "first correction");
    let mut latest = edit_record(3, 20, original.event_id, "second correction");
    latest.expires_at = Some(30);
    for scope in [&a, &b] {
        storage
            .apply_mirrored_chat_messages(
                scope,
                &group,
                &[original.clone(), first.clone(), latest.clone()],
                0,
                &|| Ok(()),
            )
            .unwrap();
    }
    let scopes = [a.clone(), b.clone()];
    let read = |now| {
        storage
            .app_storage()
            .mirrored_message_observation_page(&scopes, &group, None, 1, now)
            .unwrap()
            .remove(0)
    };
    let edit = read(0).edit.unwrap();
    assert_eq!(edit.plaintext, "second correction");
    assert_eq!(edit.summary.edit_count, 2);
    assert_eq!(edit.next_expiry, Some(30));
    assert_eq!(read(30).edit.unwrap().plaintext, "first correction");
    latest.deleted = true;
    latest.payload.clear();
    latest.source_sequence += 1;
    storage
        .apply_mirrored_chat_messages(&a, &group, &[latest], 0, &|| Ok(()))
        .unwrap();
    assert_eq!(read(0).edit.unwrap().plaintext, "first correction");
    let mut deleted = original;
    deleted.deleted = true;
    deleted.payload.clear();
    deleted.source_sequence += 1;
    storage
        .apply_mirrored_chat_messages(&b, &group, &[deleted], 0, &|| Ok(()))
        .unwrap();
    let row = read(0);
    assert!(row.record.deleted);
    assert!(
        row.edit.is_none(),
        "an edit cannot restore deleted plaintext"
    );
}
