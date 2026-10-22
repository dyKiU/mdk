//! Actual session origin lifecycle; no native permission or network transport.
use super::*;
use cgka_engine::device_group_genesis::GenesisFactoryError;
use cgka_traits::device_group_genesis::GenesisError;

#[test]
fn session_private_device_genesis_is_reauthenticated_after_reopen_and_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("private-session.sqlite");
    let key = SqlCipherKey::new("synthetic-private-session-key").unwrap();
    let make_config =
        || config(&path, &key, b"private-session").protocol_profile(ProtocolProfile::Current);
    let mut session = AccountDeviceSession::open(make_config()).unwrap();
    let created = session.create_private_device_group_genesis().unwrap();
    let group = created.group_id().clone();
    let scope = created.scope().clone();
    let digest = created.current().epoch_authenticator_digest;
    assert_eq!(scope.account.as_slice(), session.self_id().as_slice());
    assert_eq!(created.current().epoch, EpochId(0));
    assert_eq!(created.current().leaves.len(), 1);
    assert!(created.current().leaves[0].signature_public_key == scope.local_device);
    assert!(matches!(
        session.create_private_device_group_genesis(),
        Err(GenesisFactoryError::Genesis(GenesisError::SelectionBusy))
    ));
    drop(session);
    let mut reopened = AccountDeviceSession::open(make_config()).unwrap();
    let fresh = reopened
        .validated_private_device_group_genesis(&group)
        .unwrap()
        .unwrap();
    assert!(fresh.scope() == &scope);
    assert_eq!(fresh.current().epoch_authenticator_digest, digest);
    let mut stale = scope.clone();
    stale.selection_generation += 1;
    assert!(matches!(
        reopened.retire_private_device_group_genesis(&stale, &group),
        Err(GenesisFactoryError::Genesis(GenesisError::ScopeMismatch))
    ));
    assert!(
        reopened
            .validated_private_device_group_genesis(&group)
            .unwrap()
            .is_some()
    );
    reopened
        .retire_private_device_group_genesis(&scope, &group)
        .unwrap();
    assert!(
        reopened
            .validated_private_device_group_genesis(&group)
            .unwrap()
            .is_none()
    );
    let next = reopened.create_private_device_group_genesis().unwrap();
    assert_eq!(
        next.scope().selection_generation,
        scope.selection_generation + 1
    );
    assert!(next.group_id() != &group);
    assert!(next.scope().local_device == scope.local_device);
}

#[tokio::test]
async fn session_generic_solo_group_is_never_promoted_to_private_creation_origin() {
    let directory = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("synthetic-unapproved-session-key").unwrap();
    let path = directory.path().join("unapproved-session.sqlite");
    let mut session = AccountDeviceSession::open(
        config(&path, &key, b"unapproved-session").protocol_profile(ProtocolProfile::Current),
    )
    .unwrap();
    let created = session
        .create_group(CreateGroupRequest {
            name: "synthetic ordinary group".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    assert!(
        session
            .candidate_device_group_snapshot(&created.group_id)
            .unwrap()
            .is_some()
    );
    assert!(
        session
            .validated_private_device_group_genesis(&created.group_id)
            .unwrap()
            .is_none()
    );
    let private = session.create_private_device_group_genesis().unwrap();
    assert!(private.group_id() != &created.group_id);
    assert!(
        session
            .validated_private_device_group_genesis(&created.group_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn session_same_account_private_groups_use_independent_device_signers() {
    let directory = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("synthetic-independent-device-key").unwrap();
    let mut left = AccountDeviceSession::open(
        config(
            directory.path().join("left.sqlite"),
            &key,
            b"shared-private-account",
        )
        .protocol_profile(ProtocolProfile::Current),
    )
    .unwrap();
    let mut right = AccountDeviceSession::open(
        config(
            directory.path().join("right.sqlite"),
            &key,
            b"shared-private-account",
        )
        .protocol_profile(ProtocolProfile::Current),
    )
    .unwrap();
    let left = left.create_private_device_group_genesis().unwrap();
    let right = right.create_private_device_group_genesis().unwrap();
    assert!(left.scope().account == right.scope().account);
    assert!(left.scope().local_device != right.scope().local_device);
    assert!(left.group_id() != right.group_id());
    assert!(
        left.current().leaves[0].signature_public_key
            != right.current().leaves[0].signature_public_key
    );
}
