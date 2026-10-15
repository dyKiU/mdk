//! Negative classification facts are synthetic; no stored row grants membership.
use super::*;
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::device_group_genesis::GenesisLeaf;
use cgka_traits::selected_chat_key_package::*;
use cgka_traits::storage::{MessageStorage, StorageProvider};
use cgka_traits::types::{EpochId, GroupId};
use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, Welcome};
use tls_codec::{Deserialize as _, Serialize as _};

fn retain_negative_fact(
    storage: &SqliteAccountStorage,
    kp: &cgka_traits::engine::KeyPackage,
    ordinary_group: GroupId,
    state: SelectedChatPurposeState,
) {
    let metadata = key_package_metadata(kp).unwrap();
    let account = pad32(ACCOUNT).try_into().unwrap();
    let device = hex::decode(metadata.signature_public_key_hex)
        .unwrap()
        .try_into()
        .unwrap();
    storage
        .ensure_account_projection_with_identity(
            "isolated-selected-classification",
            &hex::encode(account),
        )
        .unwrap();
    let row = SelectedChatPurposeKeyPackage {
        scope: SelectedChatPurposeScope {
            account,
            local_device: device,
            generation: 1,
            request_binding: [2; 32],
        },
        context: SelectedChatPurposeContext {
            approved_response_digest: [3; 32],
            protected_group: GroupId::new(vec![4; 16]),
            protected_anchor: DeviceGroupAnchorRoster {
                epoch: EpochId(2),
                epoch_authenticator_digest: [5; 32],
                leaves: vec![
                    GenesisLeaf {
                        leaf_index: 0,
                        account,
                        signature_public_key: [1; 32],
                    },
                    GenesisLeaf {
                        leaf_index: 1,
                        account,
                        signature_public_key: device,
                    },
                ],
            },
            protected_settlement_generation: 1,
            ordinary_group,
            ordinary_epoch: EpochId(0),
            ordinary_own_leaf_index: 0,
            ordinary_own_leaf_hash: vec![6; 32],
            ordinary_roster_digest: [7; 32],
        },
        public_bytes: kp.bytes().to_vec(),
        reference: hex::decode(metadata.key_package_ref_hex)
            .unwrap()
            .try_into()
            .unwrap(),
        signature_public_key: device,
        state: SelectedChatPurposeState::Pending,
    };
    let purpose = storage.selected_chat_key_package_storage().unwrap();
    purpose.put_selected_chat_key_package(&row).unwrap();
    match state {
        SelectedChatPurposeState::Pending => {}
        SelectedChatPurposeState::Denied => purpose
            .deny_selected_chat_key_package(&row.scope, &row.reference)
            .unwrap(),
        SelectedChatPurposeState::Consumed => purpose
            .consume_selected_chat_key_package(&row.scope, &row.reference)
            .unwrap(),
    }
}

async fn assert_retryable_denial(
    recipient: &mut Engine<SqliteAccountStorage>,
    storage: &SqliteAccountStorage,
    group: &GroupId,
    welcome: TransportMessage,
) {
    let before = recipient.durably_owned_key_packages().unwrap();
    for _ in 0..2 {
        assert!(
            matches!(
                recipient.ingest(welcome.clone()).await,
                Ok(cgka_traits::ingest::IngestOutcome::Ignored {
                    category: cgka_traits::ingest::InputRejectionCategory::AuthorizationFailed
                })
            ),
            "selected purpose must be classified before any usable public/private fallback"
        );
        assert!(!storage.has_ingress_dedup_marker(&welcome.id).unwrap());
        assert!(
            recipient
                .accepted_welcome_receipt(&welcome.id)
                .unwrap()
                .is_none()
        );
        assert!(recipient.epoch(group).is_err());
        assert!(recipient.durably_owned_key_packages().unwrap() == before);
    }
}

#[tokio::test]
async fn selected_pending_welcome_without_original_owner_is_retryable_and_keeps_bundle() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut recipient = client(storage.clone());
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let private = recipient.fresh_linking_key_package().await.unwrap();
    let (group, welcome) = invite(&mut approver, private.clone()).await;
    retain_negative_fact(
        &storage,
        &private,
        group.clone(),
        SelectedChatPurposeState::Pending,
    );
    assert_retryable_denial(&mut recipient, &storage, &group, welcome).await;
}

// Hostile-container coverage: preserve a genuine public Welcome's encrypted
// secret and GroupInfo, adding only a forged extra selected reference. This is
// not a canonical multiple-recipient Welcome or positive SDK admission.
async fn hostile_container(state: SelectedChatPurposeState, selected_first: bool) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut recipient = client(storage.clone());
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let private = recipient.fresh_linking_key_package().await.unwrap();
    let public = recipient.fresh_key_package().await.unwrap();
    let (group, mut message) = invite(&mut approver, public).await;
    retain_negative_fact(&storage, &private, group.clone(), state);
    if state != SelectedChatPurposeState::Pending {
        recipient.delete_key_package(&private).await.unwrap();
    }
    let incoming = MlsMessageIn::tls_deserialize_exact(&message.payload).unwrap();
    let MlsMessageBodyIn::Welcome(welcome) = incoming.extract() else {
        panic!("expected Welcome")
    };
    let mut json = serde_json::to_value(welcome).unwrap();
    let secrets = json["secrets"].as_array_mut().unwrap();
    let mut hostile = secrets[0].clone();
    let reference =
        hex::decode(key_package_metadata(&private).unwrap().key_package_ref_hex).unwrap();
    let encoded = tls_codec::VLBytes::from(reference)
        .tls_serialize_detached()
        .unwrap();
    let exact_ref = openmls::prelude::KeyPackageRef::tls_deserialize_exact(encoded).unwrap();
    hostile["new_member"] = serde_json::to_value(exact_ref).unwrap();
    secrets.insert(if selected_first { 0 } else { 1 }, hostile);
    let modified: Welcome = serde_json::from_value(json).unwrap();
    let outgoing =
        MlsMessageOut::from_welcome(modified, openmls::prelude::ProtocolVersion::default());
    message.payload = outgoing.tls_serialize_detached().unwrap();
    message.id = hash_id(&message.payload);
    assert_retryable_denial(&mut recipient, &storage, &group, message).await;
}

#[tokio::test]
async fn selected_denied_reference_blocks_public_last_resort_in_both_orders() {
    for first in [true, false] {
        hostile_container(SelectedChatPurposeState::Denied, first).await;
    }
}
#[tokio::test]
async fn selected_consumed_reference_blocks_public_last_resort_in_both_orders() {
    for first in [true, false] {
        hostile_container(SelectedChatPurposeState::Consumed, first).await;
    }
}
#[tokio::test]
async fn selected_pending_reference_after_public_secret_blocks_generic_join() {
    hostile_container(SelectedChatPurposeState::Pending, false).await;
}
