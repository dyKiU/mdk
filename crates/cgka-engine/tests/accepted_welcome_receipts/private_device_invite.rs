//! Real MLS no-grant boundary; injected-policy success is tested only with durable staging.
use super::*;

#[tokio::test]
async fn private_invite_without_live_sdk_policy_cannot_stage_or_change_real_tree() {
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let mut recipient = client(SqliteAccountStorage::in_memory().unwrap());
    let origin = approver.create_private_device_group_genesis().unwrap();
    let group = origin.group_id().clone();
    let before = origin.current().clone();
    let package = recipient.fresh_linking_key_package().await.unwrap();
    assert!(
        approver
            .prepare_private_device_invite(&group, package.clone())
            .await
            .is_err()
    );
    let after = approver
        .validated_private_device_group_genesis(&group)
        .unwrap()
        .unwrap();
    assert!(after.current() == &before);
    assert_eq!(approver.epoch(&group).unwrap().0, 0);
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&package)
    );
}
