//! Exact private linking KeyPackages use MLS single-use consumption.
use super::*;
use cgka_engine::key_package::is_last_resort_key_package;

#[tokio::test]
async fn single_use_linking_key_package_is_consumed_exactly_and_cannot_be_reused() {
    let mut recipient = client(SqliteAccountStorage::in_memory().unwrap());
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = recipient.fresh_linking_key_package().await.unwrap();
    let spare = recipient.fresh_linking_key_package().await.unwrap();
    let public = recipient.fresh_key_package().await.unwrap();
    assert!(!is_last_resort_key_package(&kp).unwrap());
    assert!(is_last_resort_key_package(&public).unwrap());
    let metadata = key_package_metadata(&kp).unwrap();
    let (first_group, first) = invite(&mut approver, kp.clone()).await;
    let (second_group, second) = invite(&mut approver, kp.clone()).await;
    assert!(first_group != second_group);
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&kp)
    );
    recipient.join_welcome(first.clone()).await.unwrap();
    let owned = recipient.durably_owned_key_packages().unwrap();
    assert!(!owned.contains(&kp));
    assert!(owned.contains(&spare));
    assert!(owned.contains(&public));
    let receipt = recipient
        .accepted_welcome_receipt(&first.id)
        .unwrap()
        .unwrap();
    assert!(receipt.consumed_key_package_ref == hex::decode(metadata.key_package_ref_hex).unwrap());
    assert!(matches!(
        recipient.join_welcome(second.clone()).await,
        Err(cgka_traits::EngineError::MissingWelcomeKeyPackage)
    ));
    assert!(recipient.epoch(&second_group).is_err());
    assert!(
        recipient
            .accepted_welcome_receipt(&second.id)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn ordinary_public_last_resort_key_package_remains_reusable() {
    let mut recipient = client(SqliteAccountStorage::in_memory().unwrap());
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = recipient.fresh_key_package().await.unwrap();
    assert!(is_last_resort_key_package(&kp).unwrap());
    let (first_group, first) = invite(&mut approver, kp.clone()).await;
    let (second_group, second) = invite(&mut approver, kp.clone()).await;
    assert!(first_group != second_group);
    recipient.join_welcome(first).await.unwrap();
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&kp)
    );
    recipient.join_welcome(second).await.unwrap();
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&kp)
    );
    assert!(recipient.epoch(&first_group).is_ok());
    assert!(recipient.epoch(&second_group).is_ok());
}
