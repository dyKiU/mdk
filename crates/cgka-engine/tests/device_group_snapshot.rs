//! Local indexed-tree candidates are evidence, never enrollment authorization.
#![cfg(feature = "experimental-device-sync")]

use cgka_engine::{Engine, EngineBuilder, key_package_metadata};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::group::ProtocolProfile;
use cgka_traits::storage::GroupStorage;
use cgka_traits::types::{GroupId, MemberId};
use storage_sqlite::SqliteAccountStorage;

mod support;
use support::{account_identity, epoch_sealed_peeler::EpochSealedPeeler, proof_signer};

fn client(account: &[u8], profile: ProtocolProfile) -> Engine<SqliteAccountStorage> {
    client_with_storage(account, profile, SqliteAccountStorage::in_memory().unwrap())
}

fn client_with_storage(
    account: &[u8],
    profile: ProtocolProfile,
    storage: SqliteAccountStorage,
) -> Engine<SqliteAccountStorage> {
    let builder = EngineBuilder::new(storage)
        .identity(account_identity(account))
        .account_identity_proof_signer(proof_signer(account))
        .protocol_profile(profile)
        .peeler(Box::new(EpochSealedPeeler));
    let builder = if profile == ProtocolProfile::Legacy {
        builder.legacy_compatibility_profile()
    } else {
        builder
    };
    builder.build().unwrap()
}

async fn joined_group(
    approver: &mut Engine<SqliteAccountStorage>,
    recipient: &mut Engine<SqliteAccountStorage>,
) -> GroupId {
    let kp = recipient.fresh_key_package().await.unwrap();
    let (group, result) = approver
        .create_group(CreateGroupRequest {
            name: "isolated-device-snapshot".into(),
            description: String::new(),
            members: vec![kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { mut welcomes } = result else {
        panic!("expected canonical founding Welcome");
    };
    assert_eq!(welcomes.len(), 1);
    assert_eq!(
        recipient.join_welcome(welcomes.remove(0)).await.unwrap(),
        group
    );
    group
}

#[tokio::test]
async fn independent_same_account_devices_read_identical_indexed_tree_candidate() {
    let mut approver = client(b"device-account", ProtocolProfile::Current);
    let mut recipient = client(b"device-account", ProtocolProfile::Current);
    let approver_key = key_package_metadata(&approver.fresh_key_package().await.unwrap())
        .unwrap()
        .signature_public_key_hex;
    let recipient_key = key_package_metadata(&recipient.fresh_key_package().await.unwrap())
        .unwrap()
        .signature_public_key_hex;
    assert_ne!(approver_key, recipient_key);
    let group = joined_group(&mut approver, &mut recipient).await;
    let left = approver
        .candidate_device_group_snapshot(&group)
        .unwrap()
        .unwrap();
    let right = recipient
        .candidate_device_group_snapshot(&group)
        .unwrap()
        .unwrap();
    assert_eq!(left, right);
    assert_eq!(left.account.as_slice(), account_identity(b"device-account"));
    assert_eq!(left.group_id, group);
    assert_eq!(left.leaves.len(), 2);
    for (client, key) in [(&approver, approver_key), (&recipient, recipient_key)] {
        let own_index = client.own_leaf_index(&group).unwrap();
        let leaf = left
            .leaves
            .iter()
            .find(|leaf| leaf.leaf_index == own_index)
            .unwrap();
        assert_eq!(leaf.signature_public_key, hex::decode(key).unwrap());
    }
    let debug = format!("{left:?}");
    assert!(!debug.contains(&hex::encode(left.account.as_slice())));
    assert!(!debug.contains(&format!("{:?}", left.leaves[0].signature_public_key)));
}

#[tokio::test]
async fn pending_publish_refuses_candidate_and_confirmed_epoch_changes_commitment() {
    let mut approver = client(b"device-account", ProtocolProfile::Current);
    let mut recipient = client(b"device-account", ProtocolProfile::Current);
    let group = joined_group(&mut approver, &mut recipient).await;
    let before = approver
        .candidate_device_group_snapshot(&group)
        .unwrap()
        .unwrap();
    let SendResult::GroupEvolution { pending, .. } = approver
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("expected staged MLS commit");
    };
    assert!(
        approver
            .candidate_device_group_snapshot(&group)
            .unwrap()
            .is_none()
    );
    approver.confirm_published(pending).await.unwrap();
    let after = approver
        .candidate_device_group_snapshot(&group)
        .unwrap()
        .unwrap();
    assert_eq!(after.epoch.0, before.epoch.0 + 1);
    assert_eq!(after.leaves, before.leaves);
    assert_ne!(
        after.epoch_authenticator_digest,
        before.epoch_authenticator_digest
    );
    assert_ne!(after.roster_commitment, before.roster_commitment);
    // Local stability does not establish remote settlement: the peer remains old.
    let peer = recipient
        .candidate_device_group_snapshot(&group)
        .unwrap()
        .unwrap();
    assert_eq!(peer, before);
    assert_ne!(peer.roster_commitment, after.roster_commitment);
}

#[tokio::test]
async fn mixed_accounts_cannot_be_a_device_group_candidate() {
    let mut approver = client(b"device-account", ProtocolProfile::Current);
    let mut recipient = client(b"other-account", ProtocolProfile::Current);
    let group = joined_group(&mut approver, &mut recipient).await;
    assert!(
        approver
            .candidate_device_group_snapshot(&group)
            .unwrap()
            .is_none()
    );
    assert!(
        recipient
            .candidate_device_group_snapshot(&group)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn removed_middle_leaf_preserves_real_indices_in_candidate() {
    let mut approver = client(b"device-account", ProtocolProfile::Current);
    let mut recipient = client(b"device-account", ProtocolProfile::Current);
    let mut other = client(b"other-account", ProtocolProfile::Current);
    // Sequential invites keep this peeler's pass-through Welcome IDs distinct.
    let group = joined_group(&mut approver, &mut other).await;
    let recipient_kp = recipient.fresh_key_package().await.unwrap();
    let SendResult::GroupEvolution {
        pending,
        mut welcomes,
        ..
    } = approver
        .send(SendIntent::Invite {
            group_id: group.clone(),
            key_packages: vec![recipient_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    else {
        panic!("expected invite commit");
    };
    approver.confirm_published(pending).await.unwrap();
    assert_eq!(welcomes.len(), 1);
    recipient.join_welcome(welcomes.remove(0)).await.unwrap();
    let recipient_index = recipient.own_leaf_index(&group).unwrap();
    let other_index = other.own_leaf_index(&group).unwrap();
    assert!(
        other_index < recipient_index,
        "fixture must create an interior hole"
    );
    let SendResult::GroupEvolution { pending, .. } = approver
        .send(SendIntent::RemoveMembers {
            group_id: group.clone(),
            members: vec![MemberId::new(account_identity(b"other-account"))],
        })
        .await
        .unwrap()
    else {
        panic!("expected removal commit");
    };
    approver.confirm_published(pending).await.unwrap();
    let snapshot = approver
        .candidate_device_group_snapshot(&group)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.leaves.len(), 2);
    assert!(
        snapshot
            .leaves
            .iter()
            .all(|leaf| leaf.leaf_index != other_index)
    );
    assert!(
        snapshot
            .leaves
            .iter()
            .any(|leaf| leaf.leaf_index == recipient_index)
    );
    assert_ne!(
        snapshot.leaves[1].leaf_index, 1,
        "occupied vector positions are not MLS indices"
    );
}

#[tokio::test]
async fn incompatible_or_inconsistent_durable_record_cannot_release_candidate() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut approver =
        client_with_storage(b"device-account", ProtocolProfile::Current, storage.clone());
    let mut recipient = client(b"device-account", ProtocolProfile::Current);
    let group = joined_group(&mut approver, &mut recipient).await;
    let original = storage.get_group(&group).unwrap();
    assert!(
        approver
            .candidate_device_group_snapshot(&group)
            .unwrap()
            .is_some()
    );
    let mut record = original.clone();
    record.protocol_profile = ProtocolProfile::Legacy;
    storage.put_group(&record).unwrap();
    assert!(
        approver
            .candidate_device_group_snapshot(&group)
            .unwrap()
            .is_none()
    );
    record = original.clone();
    record.epoch.0 += 1;
    storage.put_group(&record).unwrap();
    assert!(
        approver
            .candidate_device_group_snapshot(&group)
            .unwrap()
            .is_none()
    );
    record = original.clone();
    record.removed = true;
    storage.put_group(&record).unwrap();
    assert!(
        approver
            .candidate_device_group_snapshot(&group)
            .unwrap()
            .is_none()
    );
    storage.put_group(&original).unwrap();
    assert!(
        approver
            .candidate_device_group_snapshot(&group)
            .unwrap()
            .is_some()
    );
    storage.delete_group(&group).unwrap();
    assert!(approver.candidate_device_group_snapshot(&group).is_err());
}

#[tokio::test]
async fn legacy_mls_context_cannot_be_upgraded_by_a_current_projection_record() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut legacy =
        client_with_storage(b"device-account", ProtocolProfile::Legacy, storage.clone());
    let (group, result) = legacy
        .create_group(CreateGroupRequest {
            name: "isolated-legacy-group".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, .. } = result else {
        panic!("expected legacy publish-before-apply founding commit");
    };
    legacy.confirm_published(pending).await.unwrap();
    assert!(
        legacy
            .candidate_device_group_snapshot(&group)
            .unwrap()
            .is_none()
    );
    let mut record = storage.get_group(&group).unwrap();
    record.protocol_profile = ProtocolProfile::Current;
    storage.put_group(&record).unwrap();
    assert!(
        legacy
            .candidate_device_group_snapshot(&group)
            .unwrap()
            .is_none(),
        "a projected profile value cannot upgrade the authenticated MLS context"
    );
}
