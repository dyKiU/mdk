//! Proof capture parity using real independent MLS leaves of one account.
use super::*;
use cgka_traits::engine::{GroupEvent, SendIntent};

fn payload(sender: &Engine<SqliteAccountStorage>) -> Vec<u8> {
    cgka_traits::app_event::MarmotAppEvent::new(
        hex::encode(sender.self_id().as_slice()),
        1_700_000_000,
        cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        "isolated-control-fixture",
    )
    .encode()
    .unwrap()
}
async fn sent(
    sender: &mut Engine<SqliteAccountStorage>,
    group: &cgka_traits::types::GroupId,
) -> TransportMessage {
    let payload = payload(sender);
    match sender
        .send(SendIntent::AppMessage {
            group_id: group.clone(),
            payload,
            expected_epoch: None,
        })
        .await
        .unwrap()
    {
        SendResult::ApplicationMessage { msg, .. } => msg,
        _ => panic!("expected MLS application"),
    }
}
fn source_proof(events: Vec<GroupEvent>) -> serde_json::Value {
    let event = events
        .iter()
        .find(|event| matches!(event, GroupEvent::MessageReceived { .. }))
        .unwrap_or_else(|| {
            let kinds: Vec<_> = events
                .iter()
                .map(|event| {
                    serde_json::to_value(event)
                        .unwrap()
                        .as_object()
                        .unwrap()
                        .keys()
                        .next()
                        .unwrap()
                        .clone()
                })
                .collect();
            panic!("real application event required; only event kinds: {kinds:?}");
        });
    let serialized = serde_json::to_value(event).unwrap();
    serialized["MessageReceived"]
        .get("source_leaf")
        .filter(|proof| !proof.is_null())
        .cloned()
        .expect("an authenticated current-epoch message must expose its exact source leaf proof")
}
#[tokio::test]
async fn source_leaf_proofs_current_direct_distinguishes_same_account_signers() {
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let mut recipient = client(SqliteAccountStorage::in_memory().unwrap());
    let approver_meta = key_package_metadata(&approver.fresh_key_package().await.unwrap()).unwrap();
    let kp = recipient.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut approver, kp).await;
    recipient.join_welcome(welcome.clone()).await.unwrap();
    let receipt = recipient
        .accepted_welcome_receipt(&welcome.id)
        .unwrap()
        .unwrap();
    let message = sent(&mut approver, &group).await;
    recipient.ingest(message.clone()).await.unwrap();
    let proof = source_proof(recipient.drain_events());
    assert!(
        proof["signature_public_key"]
            == serde_json::json!(hex::decode(approver_meta.signature_public_key_hex).unwrap())
    );
    assert!(proof["signature_public_key"] != serde_json::json!(receipt.own_signature_public_key));
    assert!(proof["epoch"] == serde_json::json!(receipt.joined_epoch.0));
    assert!(
        proof["epoch_authenticator_digest"]
            == serde_json::json!(receipt.joined_epoch_authenticator_digest)
    );
}
#[tokio::test]
async fn source_leaf_proofs_current_replay_preserves_exact_verified_leaf() {
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let mut recipient = client(SqliteAccountStorage::in_memory().unwrap());
    let approver_meta = key_package_metadata(&approver.fresh_key_package().await.unwrap()).unwrap();
    let kp = recipient.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut approver, kp).await;
    recipient.join_welcome(welcome.clone()).await.unwrap();
    let receipt = recipient
        .accepted_welcome_receipt(&welcome.id)
        .unwrap()
        .unwrap();
    let message = sent(&mut approver, &group).await;
    recipient
        .buffer_openmls_convergence_message_at(&group, message.clone(), 1_000)
        .unwrap();
    recipient
        .advance_convergence_inputs_until_settled(&group, 2_000_000)
        .await
        .unwrap();
    let proof = source_proof(recipient.drain_events());
    assert!(
        proof["signature_public_key"]
            == serde_json::json!(hex::decode(approver_meta.signature_public_key_hex).unwrap())
    );
    assert!(
        proof["epoch_authenticator_digest"]
            == serde_json::json!(receipt.joined_epoch_authenticator_digest)
    );
}
