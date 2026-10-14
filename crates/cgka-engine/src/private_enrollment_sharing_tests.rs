//! Genuine B original and authenticated packet terms, not bilateral policy grants.
use super::*;
use crate::private_enrollment_endorsement::{PROTOCOL, SHARING_PROTOCOL};

#[tokio::test]
async fn private_enrollment_metadata_is_mls_authenticated_without_changing_signed_terms() {
    let mut f = endorsement_fixture(None).await;
    let a = coordinator_wire(&f);
    let mut b =
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .unwrap();
    let original_wire = b.wire().unwrap().to_vec();
    let tags = vec![
        vec!["share_chats".into(), "true".into()],
        vec!["transport".into(), "public-key".into()],
    ];
    assert!(
        f.b.set_owned_enrollment_metadata(&mut b, vec![vec!["x".repeat(2049)]])
            .is_err()
    );
    f.b.set_owned_enrollment_metadata(&mut b, tags.clone())
        .unwrap();
    assert_eq!(b.wire().unwrap(), original_wire);
    f.b.set_owned_enrollment_metadata(&mut b, tags.clone())
        .unwrap();
    assert!(
        f.b.set_owned_enrollment_metadata(&mut b, vec![vec!["different".into()]])
            .is_err()
    );
    let message =
        f.b.wrap_private_enrollment_endorsement(&mut b)
            .await
            .unwrap();
    f.a.ingest_private_enrollment_delivery(message)
        .await
        .unwrap();
    let received = f.a.drain_authenticated_enrollment_endorsements().unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].metadata_tags(), tags);
    let proof =
        f.a.authenticate_all_private_enrollment_endorsements(
            &f.authenticated,
            &f.request.binding_digest().unwrap(),
            &[&a, &received[0].wire],
        )
        .unwrap();
    assert!(
        proof.sharing_devices().is_empty(),
        "outer tags cannot upgrade signed sharing terms"
    );
    b.cancellation_handle().cancel();
    assert!(f.b.set_owned_enrollment_metadata(&mut b, tags).is_err());
}

fn coordinator_wire(f: &EndorsementFixture) -> Vec<u8> {
    // A portable signature fixture does not simulate A's SDK sharing choice.
    crate::private_enrollment_endorsement::sign_public_packet_for_test(
        &f.a,
        &GroupId::new(f.request.group_id().to_vec()),
        f.request.binding_digest().unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn private_enrollment_sharing_signed_original_terms_survive_real_private_carrier() {
    let mut f = endorsement_fixture(None).await;
    let a = coordinator_wire(&f);
    let mut b =
        f.b.endorse_private_enrollment_request_and_share_chats(
            &f.request,
            &f.artifact,
            &f.package,
            &[10; 32],
        )
        .unwrap();
    let wire = b.wire().unwrap().to_vec();
    let packet: serde_json::Value = serde_json::from_slice(&wire).unwrap();
    assert_eq!(packet["protocol"], SHARING_PROTOCOL);
    assert_eq!(packet["share_chats"], true);
    let binding = f.request.binding_digest().unwrap();
    let proof = f
        .b
        .authenticate_all_private_enrollment_endorsements(&f.authenticated, &binding, &[&a, &wire])
        .unwrap();
    let signer: [u8; 32] = f.b.identity.signer.public().try_into().unwrap();
    assert_eq!(proof.sharing_devices(), &[signer]);
    assert_eq!(proof.leaf_count(), 2);
    let message =
        f.b.wrap_private_enrollment_endorsement(&mut b)
            .await
            .unwrap();
    f.a.ingest_private_enrollment_delivery(message)
        .await
        .unwrap();
    let received = f.a.drain_authenticated_enrollment_endorsements().unwrap();
    assert_eq!(received.len(), 1);
    let received_proof =
        f.a.authenticate_all_private_enrollment_endorsements(
            &f.authenticated,
            &binding,
            &[&a, &received[0].wire],
        )
        .unwrap();
    assert_eq!(received_proof.sharing_devices(), &[signer]);
    assert!(
        f.a.drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. }))
    );
    assert!(
        f.b.storage
            .approved_account_sharing_policy_storage()
            .unwrap()
            .approved_account_sharing_policies()
            .unwrap()
            .is_empty(),
        "signed requested terms cannot create bilateral policy"
    );
}

#[tokio::test]
async fn private_enrollment_sharing_ordinary_v1_packets_remain_unmarked() {
    let f = endorsement_fixture(None).await;
    let a = coordinator_wire(&f);
    let b =
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .unwrap();
    let packet: serde_json::Value = serde_json::from_slice(b.wire().unwrap()).unwrap();
    assert_eq!(packet["protocol"], PROTOCOL);
    assert!(packet.get("share_chats").is_none());
    let proof =
        f.b.authenticate_all_private_enrollment_endorsements(
            &f.authenticated,
            &f.request.binding_digest().unwrap(),
            &[&a, b.wire().unwrap()],
        )
        .unwrap();
    assert!(proof.sharing_devices().is_empty());
    assert!(
        f.b.endorse_private_enrollment_request_and_share_chats(
            &f.request,
            &f.artifact,
            &f.package,
            &[10; 32],
        )
        .is_err(),
        "ordinary original cannot be upgraded after signing"
    );
}

#[tokio::test]
async fn private_enrollment_sharing_marker_context_and_signer_tampering_are_refused() {
    let f = endorsement_fixture(None).await;
    let a = coordinator_wire(&f);
    let b =
        f.b.endorse_private_enrollment_request_and_share_chats(
            &f.request,
            &f.artifact,
            &f.package,
            &[10; 32],
        )
        .unwrap();
    let original: serde_json::Value = serde_json::from_slice(b.wire().unwrap()).unwrap();
    for alteration in 0..6 {
        let mut packet = original.clone();
        match alteration {
            0 => {
                packet["share_chats"] = serde_json::json!(false);
            }
            1 => {
                packet["protocol"] = serde_json::json!(PROTOCOL);
                packet.as_object_mut().unwrap().remove("share_chats");
            }
            2 => {
                packet["binding_digest"] = serde_json::json!(vec![66u8; 32]);
            }
            3 => {
                packet["source_signer"] = serde_json::json!(vec![77u8; 32]);
            }
            4 => {
                packet["sharing_capabilities"] = serde_json::json!(255);
            }
            _ => {
                packet["signature"][0] =
                    serde_json::json!(packet["signature"][0].as_u64().unwrap() ^ 1);
            }
        }
        let bytes = serde_json::to_vec(&packet).unwrap();
        assert!(
            f.b.authenticate_all_private_enrollment_endorsements(
                &f.authenticated,
                &f.request.binding_digest().unwrap(),
                &[&a, &bytes],
            )
            .is_err(),
            "altered signed marker must fail"
        );
    }
    let ordinary: serde_json::Value = serde_json::from_slice(&a).unwrap();
    let mut forged = ordinary;
    forged["protocol"] = serde_json::json!(SHARING_PROTOCOL);
    forged["share_chats"] = serde_json::json!(true);
    assert!(
        f.b.authenticate_all_private_enrollment_endorsements(
            &f.authenticated,
            &f.request.binding_digest().unwrap(),
            &[&serde_json::to_vec(&forged).unwrap(), b.wire().unwrap()],
        )
        .is_err(),
        "ordinary signed proof cannot be relabeled as broad terms"
    );
}

#[tokio::test]
async fn private_enrollment_sharing_original_cancel_and_foreign_engine_cannot_restore_action() {
    let mut f = endorsement_fixture(None).await;
    assert!(
        f.a.endorse_private_enrollment_request_and_share_chats(
            &f.request,
            &f.artifact,
            &f.package,
            &[10; 32],
        )
        .is_err()
    );
    let mut b =
        f.b.endorse_private_enrollment_request_and_share_chats(
            &f.request,
            &f.artifact,
            &f.package,
            &[10; 32],
        )
        .unwrap();
    let wire = b.wire().unwrap().to_vec();
    b.cancellation_handle().cancel();
    assert!(b.wire().is_err());
    assert!(
        f.b.wrap_private_enrollment_endorsement(&mut b)
            .await
            .is_err()
    );
    assert!(
        f.b.validate_owned_private_enrollment_endorsement(&b)
            .is_err()
    );
    let a = coordinator_wire(&f);
    assert_eq!(
        f.a.authenticate_all_private_enrollment_endorsements(
            &f.authenticated,
            &f.request.binding_digest().unwrap(),
            &[&a, &wire],
        )
        .unwrap()
        .sharing_devices()
        .len(),
        1,
        "portable signatures remain observations, never restored original ownership"
    );
}

#[tokio::test]
async fn private_enrollment_sharing_unchanged_original_deadline_refuses_late_publication() {
    let mut f = endorsement_fixture(Some(Duration::from_secs(1))).await;
    let mut b =
        f.b.endorse_private_enrollment_request_and_share_chats(
            &f.request,
            &f.artifact,
            &f.package,
            &[10; 32],
        )
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(b.wire().is_err());
    assert!(
        f.b.wrap_private_enrollment_endorsement(&mut b)
            .await
            .is_err()
    );
    assert!(
        f.b.endorse_private_enrollment_request_and_share_chats(
            &f.request,
            &f.artifact,
            &f.package,
            &[10; 32],
        )
        .is_err()
    );
}
