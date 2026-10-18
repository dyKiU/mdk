//! Genuine local crypto creation provenance. These values never represent SAS permission.
use super::*;
use cgka_traits::device_group_genesis::PRIVATE_DEVICE_GROUP_COMPONENT_ID;
use cgka_traits::device_group_genesis::PRIVATE_DEVICE_GROUP_PROFILE;
use cgka_traits::engine::SendIntent;
use cgka_traits::storage::{GroupStorage, StorageProvider};
#[tokio::test]
async fn private_genesis_factory_and_reopen_revalidate_original_crypto_tree() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("isolated-genesis.db");
    let key = storage_sqlite::SqlCipherKey::new("79".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut engine = client(storage.clone());
    let created = engine.create_private_device_group_genesis().unwrap();
    let group = created.group_id().clone();
    assert_eq!(created.scope().selection_generation, 1);
    assert_eq!(created.birth().leaves.len(), 1);
    assert!(created.current().roster_commitment == created.birth().roster_commitment);
    assert!(
        engine
            .app_component(&group, PRIVATE_DEVICE_GROUP_COMPONENT_ID)
            .unwrap()
            .unwrap()
            == PRIVATE_DEVICE_GROUP_PROFILE
    );
    assert!(engine.create_private_device_group_genesis().is_err());
    let scope = created.scope().clone();
    drop(created);
    drop(engine);
    drop(storage);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut engine = client(storage.clone());
    engine.hydrate_stable_groups_from_storage().unwrap();
    engine.ensure_hydrated(&group).unwrap();
    let current = engine
        .validated_private_device_group_genesis(&group)
        .unwrap()
        .unwrap();
    assert!(current.scope() == &scope);
    assert_eq!(current.current().epoch.0, 0);
    engine
        .retire_private_device_group_genesis(&scope, &group)
        .unwrap();
    assert!(
        engine
            .validated_private_device_group_genesis(&group)
            .unwrap()
            .is_none()
    );
    let selected = storage
        .device_group_genesis_storage()
        .unwrap()
        .genesis_selection()
        .unwrap()
        .unwrap();
    assert!(selected.active_denied && selected.fact.birth == *current.birth());
    let fresh = engine.create_private_device_group_genesis().unwrap();
    assert_eq!(fresh.scope().selection_generation, 2);
    assert!(fresh.group_id() != &group);
    assert!(
        engine
            .retire_private_device_group_genesis(&scope, &group)
            .is_err()
    );
}
#[tokio::test]
async fn private_genesis_factory_failure_rolls_back_crypto_projection_and_generation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("isolated-genesis-failure.db");
    let key = storage_sqlite::SqlCipherKey::new("81".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut engine = client(storage.clone());
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    let before: i64 = injector
        .query_row("SELECT count(*) FROM openmls_values", [], |row| row.get(0))
        .unwrap();
    injector.execute_batch("CREATE TRIGGER fail_genesis BEFORE INSERT ON device_group_genesis_selection BEGIN SELECT RAISE(ABORT,'injected genesis write failure'); END;").unwrap();
    assert!(engine.create_private_device_group_genesis().is_err());
    assert!(storage.list_groups().unwrap().is_empty());
    assert_eq!(
        injector
            .query_row(
                "SELECT count(*) FROM private_group_chat_exclusion",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0,
        "later genesis write failure must rollback the negative fence too"
    );
    assert!(
        storage
            .device_group_genesis_storage()
            .unwrap()
            .genesis_selection()
            .unwrap()
            .is_none()
    );
    assert_eq!(
        injector
            .query_row("SELECT count(*) FROM openmls_values", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        before
    );
    injector
        .execute_batch("DROP TRIGGER fail_genesis;")
        .unwrap();
    drop(engine);
    drop(storage);
    drop(injector);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut engine = client(storage);
    assert_eq!(
        engine
            .create_private_device_group_genesis()
            .unwrap()
            .scope()
            .selection_generation,
        1
    );
}
#[tokio::test]
async fn private_genesis_generic_solo_candidate_cannot_promote_and_private_mutations_are_denied() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut engine = client(storage);
    let (ordinary, _) = engine
        .create_group(CreateGroupRequest {
            name: "ordinary-solo".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    assert_eq!(
        engine
            .candidate_device_group_snapshot(&ordinary)
            .unwrap()
            .unwrap()
            .leaves
            .len(),
        1
    );
    assert!(
        engine
            .validated_private_device_group_genesis(&ordinary)
            .unwrap()
            .is_none()
    );
    let created = engine.create_private_device_group_genesis().unwrap();
    let group = created.group_id().clone();
    let mut recipient = client(SqliteAccountStorage::in_memory().unwrap());
    let key_package = recipient.fresh_key_package().await.unwrap();
    let payload = cgka_traits::app_event::MarmotAppEvent::new(
        hex::encode(engine.self_id().as_slice()),
        1_700_000_000,
        9,
        vec![],
        "not authorized",
    )
    .encode()
    .unwrap();
    let intents = vec![
        SendIntent::SelfUpdate {
            group_id: group.clone(),
        },
        SendIntent::Invite {
            group_id: group.clone(),
            key_packages: vec![key_package],
            initial_admins: vec![],
        },
        SendIntent::AppMessage {
            group_id: group.clone(),
            payload,
            expected_epoch: None,
        },
    ];
    for intent in intents {
        assert!(
            matches!(
                engine.send(intent).await,
                Err(cgka_traits::EngineError::InvalidTransition(_))
            ),
            "birth facts must not authorize private mutation"
        );
    }
    assert_eq!(engine.epoch(&group).unwrap().0, 0);
    assert!(
        engine
            .validated_private_device_group_genesis(&group)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn private_genesis_group_deletion_retains_denied_birth_and_new_generation_is_fresh() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut engine = client(storage.clone());
    let original = engine.create_private_device_group_genesis().unwrap();
    let birth = original.birth().clone();
    storage.delete_group(original.group_id()).unwrap();
    let selection = storage
        .device_group_genesis_storage()
        .unwrap()
        .genesis_selection()
        .unwrap()
        .unwrap();
    assert!(selection.active_denied && selection.fact.birth == birth);
    assert!(
        engine
            .validated_private_device_group_genesis(original.group_id())
            .unwrap()
            .is_none()
    );
    let fresh = engine.create_private_device_group_genesis().unwrap();
    assert_eq!(
        fresh.scope().selection_generation,
        original.scope().selection_generation + 1
    );
    assert!(fresh.group_id() != original.group_id());
}

#[tokio::test]
async fn private_profile_payload_is_exact_and_ordinary_groups_do_not_require_it() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut engine = client(storage.clone());
    let request = CreateGroupRequest {
        name: String::new(),
        description: String::new(),
        members: vec![],
        required_features: vec![],
        initial_admins: vec![],
        app_components: vec![cgka_traits::app_components::AppComponentData {
            component_id: PRIVATE_DEVICE_GROUP_COMPONENT_ID,
            data: b"another private profile".to_vec(),
        }],
    };
    assert!(engine.create_group(request).await.is_err());
    assert!(
        storage
            .device_group_genesis_storage()
            .unwrap()
            .genesis_selection()
            .unwrap()
            .is_none()
    );
    let (ordinary, _) = engine
        .create_group(CreateGroupRequest {
            name: String::new(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            initial_admins: vec![],
            app_components: vec![],
        })
        .await
        .unwrap();
    assert!(
        engine
            .app_component(&ordinary, PRIVATE_DEVICE_GROUP_COMPONENT_ID)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn private_genesis_factory_cannot_orphan_an_active_accepted_selection() {
    use cgka_traits::accepted_device_group_anchor::*;
    use cgka_traits::device_group_genesis::GenesisLeaf;
    use cgka_traits::device_linking_key_package::PurposeAttemptScope;
    use cgka_traits::storage::AccountDeviceSignerStorage;
    use cgka_traits::types::{EpochId, GroupId};
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut engine = client(storage.clone());
    let account: [u8; 32] = engine.self_id().as_slice().try_into().unwrap();
    let local: [u8; 32] = storage
        .account_device_signer(&engine.self_id())
        .unwrap()
        .unwrap()
        .mls_signature_public_key
        .try_into()
        .unwrap();
    // Synthetic durable negative fence, never an enrollment authorization.
    let approver = [37; 32];
    let previous = GenesisLeaf {
        leaf_index: 0,
        account,
        signature_public_key: approver,
    };
    let recipient = GenesisLeaf {
        leaf_index: 4,
        account,
        signature_public_key: local,
    };
    let draft = AcceptedDeviceGroupAnchorDraft {
        format_version: 1,
        purpose: PurposeAttemptScope {
            account,
            local_device: local,
            generation: 1,
        },
        group_id: GroupId::new(vec![91; 19]),
        nonce: [1; 32],
        context_digest: [2; 32],
        key_package_reference: [3; 32],
        welcome_digest: [4; 32],
        approver,
        recipient: local,
        predecessor: DeviceGroupAnchorRoster {
            epoch: EpochId(1),
            epoch_authenticator_digest: [5; 32],
            leaves: vec![previous.clone()],
        },
        successor: DeviceGroupAnchorRoster {
            epoch: EpochId(2),
            epoch_authenticator_digest: [6; 32],
            leaves: vec![previous, recipient],
        },
    };
    let fact = storage
        .accepted_device_group_anchor_storage()
        .unwrap()
        .install_accepted_anchor(&draft)
        .unwrap();
    assert!(
        engine.create_private_device_group_genesis().is_err(),
        "a second independent private selection must not orphan the active accepted lineage"
    );
    assert!(storage.list_groups().unwrap().is_empty());
    storage
        .accepted_device_group_anchor_storage()
        .unwrap()
        .deny_accepted_anchor(&fact.scope, &draft.group_id)
        .unwrap();
    assert_eq!(
        engine
            .create_private_device_group_genesis()
            .unwrap()
            .scope()
            .selection_generation,
        1
    );
}
