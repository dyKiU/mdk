//! Public session boundary: private linking material survives reopen, then consumes once.
use super::*;
use cgka_traits::engine::KeyPackage;

async fn offer(sender: &mut AccountDeviceSession, kp: KeyPackage) -> (GroupId, TransportMessage) {
    let created = sender
        .create_group(CreateGroupRequest {
            name: "isolated-private-link".into(),
            description: String::new(),
            members: vec![kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let mut welcomes = created
        .effects
        .publish
        .into_iter()
        .find_map(|work| {
            if let PublishWork::FoundingGroupCreated { welcomes } = work {
                Some(welcomes)
            } else {
                None
            }
        })
        .expect("current-profile founding Welcome");
    assert_eq!(welcomes.len(), 1);
    (created.group_id, welcomes.remove(0))
}

#[tokio::test]
async fn session_single_use_linking_key_package_survives_reopen_then_consumes_once() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("isolated-single-use-session-key").unwrap();
    let recipient_path = dir.path().join("recipient.sqlite");
    let approver_path = dir.path().join("approver.sqlite");
    let make_config = |path: &std::path::Path| {
        config(path, &key, b"same-account").protocol_profile(ProtocolProfile::Current)
    };
    let mut recipient = AccountDeviceSession::open(make_config(&recipient_path)).unwrap();
    let kp = recipient.fresh_linking_key_package().await.unwrap();
    let metadata = recipient.key_package_metadata(&kp).unwrap();
    assert!(!cgka_engine::key_package::is_last_resort_key_package(&kp).unwrap());
    drop(recipient);
    let mut recipient = AccountDeviceSession::open(make_config(&recipient_path)).unwrap();
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&kp)
    );
    let mut approver = AccountDeviceSession::open(make_config(&approver_path)).unwrap();
    let (first_group, first) = offer(&mut approver, kp.clone()).await;
    let (second_group, second) = offer(&mut approver, kp.clone()).await;
    assert!(first_group != second_group);
    let result = recipient.ingest(first.clone()).await.unwrap();
    assert!(matches!(
        result.outcome,
        cgka_traits::ingest::IngestOutcome::Processed
    ));
    assert!(
        !recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&kp)
    );
    let receipt = recipient
        .accepted_welcome_receipt(&first.id)
        .unwrap()
        .unwrap();
    assert!(receipt.consumed_key_package_ref == hex::decode(metadata.key_package_ref_hex).unwrap());
    assert!(matches!(
        recipient.ingest(second).await.unwrap().outcome,
        cgka_traits::ingest::IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::MissingWelcomeKeyPackage
        }
    ));
    assert!(recipient.epoch(&second_group).is_err());
    drop(recipient);
    let recipient = AccountDeviceSession::open(make_config(&recipient_path)).unwrap();
    assert!(
        !recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&kp)
    );
    assert!(
        recipient
            .accepted_welcome_receipt(&first.id)
            .unwrap()
            .is_some()
    );
}
