//! Synthetic storage controls; these scopes do not prove original SDK approval.
use super::*;
use cgka_traits::{
    MemberId,
    group::ProtocolProfile,
    mirrored_chat_catalog::{MirroredChatCatalogStorage, MirroredChatState},
    mirrored_chat_messages::MirroredChatMessageStorage,
    storage::{AccountDeviceSignerBinding, AccountDeviceSignerStorage},
};
use sha2::{Digest, Sha256};

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
        .mirrored_catalog_observation_page(&scopes, None, 2)
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows[0].entry.group_id == GroupId::new(vec![1]));
    assert!(rows[1].entry.group_id == GroupId::new(vec![2]));
    let tail = storage
        .mirrored_catalog_observation_page(&scopes, Some(&rows[1].entry.group_id), 2)
        .unwrap();
    assert_eq!(tail.len(), 1);
    assert!(tail[0].entry.group_id == GroupId::new(vec![3]));
    assert!(
        storage
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
            .mirrored_catalog_observation_page(&[renewed.clone()], None, 128)
            .unwrap()
            .is_empty()
    );
    catalog(&storage, &renewed, &[1], MirroredChatState::Deleted);
    assert!(
        storage
            .mirrored_catalog_observation_page(&[a], None, 128)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        storage
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
            .mirrored_message_observation_page(&[a], &group, None, 128, 0)
            .unwrap()
            .is_empty()
    );
    let terminal = storage
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
            .mirrored_catalog_observation_page(&[a.clone(), a.clone()], None, 128)
            .is_err()
    );
    assert!(
        storage
            .mirrored_catalog_observation_page(&[], None, 0)
            .is_err()
    );
    assert!(
        storage
            .mirrored_catalog_observation_page(&[], None, 129)
            .is_err()
    );
    let mut wrong = a;
    wrong.account = [8; 32];
    assert!(
        storage
            .mirrored_catalog_observation_page(&[wrong], None, 128)
            .is_err()
    );
    let scopes = (3..132).map(scope).collect::<Vec<_>>();
    assert!(
        storage
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
    assert!(
        storage
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
            .mirrored_catalog_observation_page(&[a], None, 128)
            .unwrap()
            .is_empty()
    );
}
