//! Experimental accepted-join evidence using real independent OpenMLS identities.
#![cfg(feature = "experimental-device-sync")]
use async_trait::async_trait;
use cgka_engine::key_package::key_package_metadata;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{MemberId, MessageId};
use storage_sqlite::SqliteAccountStorage;
mod support;
use support::proof_signer;
fn pad32(name: &[u8]) -> Vec<u8> {
    // Marmot credential identities MUST be a valid 32-byte x-only secp256k1
    // public key (spec/foundation/identity.md). Derive one deterministically
    // from the ergonomic label so admin/member tracking stays stable across a
    // run while the engine accepts the identity.
    use k256::schnorr::SigningKey;
    use sha2::{Digest, Sha256};
    let mut counter = 0u64;
    loop {
        let mut material = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-test-identity-v1");
        hasher.update(name);
        hasher.update(counter.to_be_bytes());
        material.copy_from_slice(&hasher.finalize());
        if let Ok(sk) = SigningKey::from_bytes(&material) {
            return sk.verifying_key().to_bytes().to_vec();
        }
        counter += 1;
    }
}

#[derive(Default)]
struct MockPeeler {
    welcome_sender: Option<MemberId>,
    collide_welcome_ids: bool,
    captured_ciphertexts: Option<std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>>,
}

fn hash_id(bytes: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

#[async_trait]
impl TransportPeeler for MockPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::MlsMessage {
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        // Pass-through: the engine put the raw MLS welcome bytes in
        // `payload` on the wrap side; unwrap by returning them as-is.
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: self.welcome_sender.clone(),
            content: PeeledContent::Welcome {
                created_at: None,
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        if let Some(captured) = &self.captured_ciphertexts {
            captured.lock().unwrap().push(payload.ciphertext.clone());
        }
        Ok(TransportMessage {
            id: hash_id(&payload.ciphertext),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: ctx.transport_group_id().unwrap_or_default().to_vec(),
            },
        })
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        let mut id_material = payload.ciphertext.clone();
        id_material.extend_from_slice(recipient.as_slice());
        Ok(TransportMessage {
            id: if self.collide_welcome_ids {
                MessageId::new(b"colliding-founding-welcome-id".to_vec())
            } else {
                hash_id(&id_material)
            },
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

const ACCOUNT: &[u8] = b"isolated-sibling-device-account";
fn client(storage: SqliteAccountStorage) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .identity(pad32(ACCOUNT))
        .account_identity_proof_signer(proof_signer(ACCOUNT))
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(MockPeeler::default()))
        .build()
        .unwrap()
}
async fn invite(
    approver: &mut Engine<SqliteAccountStorage>,
    kp: cgka_traits::engine::KeyPackage,
) -> (cgka_traits::types::GroupId, TransportMessage) {
    let (group, result) = approver
        .create_group(CreateGroupRequest {
            name: "isolated-device-group".into(),
            description: String::new(),
            members: vec![kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    match result {
        SendResult::FoundingGroupCreated { mut welcomes } => {
            assert_eq!(welcomes.len(), 1);
            (group, welcomes.remove(0))
        }
        _ => panic!("expected canonical founding Welcome"),
    }
}
#[tokio::test]
async fn accepted_welcome_receipt_binds_exact_key_package_and_independent_same_account_signer() {
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let mut recipient = client(SqliteAccountStorage::in_memory().unwrap());
    let approver_kp = approver.fresh_key_package().await.unwrap();
    let recipient_kp = recipient.fresh_key_package().await.unwrap();
    let approver_meta = key_package_metadata(&approver_kp).unwrap();
    let recipient_meta = key_package_metadata(&recipient_kp).unwrap();
    assert!(approver_meta.credential_identity_hex == recipient_meta.credential_identity_hex);
    assert!(approver_meta.signature_public_key_hex != recipient_meta.signature_public_key_hex);
    let (group, welcome) = invite(&mut approver, recipient_kp).await;
    let accepted = recipient.join_welcome(welcome.clone()).await.unwrap();
    assert!(accepted == group);
    let receipt = recipient
        .accepted_welcome_receipt(&welcome.id)
        .unwrap()
        .expect("a real accepted join must persist its exact device-bound Welcome receipt");
    assert!(receipt.welcome_id == welcome.id && receipt.group_id == group);
    assert!(
        receipt.consumed_key_package_ref
            == hex::decode(recipient_meta.key_package_ref_hex).unwrap()
    );
    assert!(
        receipt.own_signature_public_key
            == hex::decode(recipient_meta.signature_public_key_hex).unwrap()
    );
    assert!(
        receipt.welcomer_signature_public_key
            == hex::decode(approver_meta.signature_public_key_hex).unwrap()
    );
    assert!(
        receipt.own_account.as_slice() == pad32(ACCOUNT)
            && receipt.welcomer_account == receipt.own_account
    );
    assert_eq!(receipt.joined_epoch.0, recipient.epoch(&group).unwrap().0);
}

#[tokio::test]
async fn unrelated_wrapper_key_package_and_group_cannot_replace_exact_join_receipt() {
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let mut recipient = client(SqliteAccountStorage::in_memory().unwrap());
    let first = recipient.fresh_key_package().await.unwrap();
    let second = recipient.fresh_key_package().await.unwrap();
    let first_ref = hex::decode(key_package_metadata(&first).unwrap().key_package_ref_hex).unwrap();
    let second_ref =
        hex::decode(key_package_metadata(&second).unwrap().key_package_ref_hex).unwrap();
    assert!(first_ref != second_ref);
    let (first_group, first_welcome) = invite(&mut approver, first).await;
    recipient.join_welcome(first_welcome.clone()).await.unwrap();
    let first_receipt = recipient
        .accepted_welcome_receipt(&first_welcome.id)
        .unwrap()
        .unwrap();
    let mut wrapper = first_welcome.clone();
    wrapper.id = MessageId::new(vec![99; 17]);
    assert!(recipient.join_welcome(wrapper.clone()).await.is_err());
    assert!(
        recipient
            .accepted_welcome_receipt(&wrapper.id)
            .unwrap()
            .is_none()
    );
    let (second_group, second_welcome) = invite(&mut approver, second).await;
    recipient
        .join_welcome(second_welcome.clone())
        .await
        .unwrap();
    let second_receipt = recipient
        .accepted_welcome_receipt(&second_welcome.id)
        .unwrap()
        .unwrap();
    assert!(first_group != second_group && first_receipt.group_id != second_receipt.group_id);
    assert!(
        first_receipt.consumed_key_package_ref == first_ref
            && first_receipt.consumed_key_package_ref != second_ref
    );
    assert!(second_receipt.consumed_key_package_ref == second_ref);
    // The global latest-consumed slot changed; the exact first Welcome fact did not.
    assert!(
        recipient
            .accepted_welcome_receipt(&first_welcome.id)
            .unwrap()
            .unwrap()
            == first_receipt
    );
}
#[tokio::test]
async fn wrong_same_account_device_and_corrupt_welcome_produce_no_receipt() {
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let mut recipient = client(SqliteAccountStorage::in_memory().unwrap());
    let mut wrong_device = client(SqliteAccountStorage::in_memory().unwrap());
    wrong_device.fresh_key_package().await.unwrap();
    let kp = recipient.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut approver, kp).await;
    assert!(wrong_device.join_welcome(welcome.clone()).await.is_err());
    assert!(
        wrong_device
            .accepted_welcome_receipt(&welcome.id)
            .unwrap()
            .is_none()
    );
    let mut corrupt = welcome.clone();
    let last = corrupt.payload.len() - 1;
    corrupt.payload[last] ^= 1;
    assert!(recipient.join_welcome(corrupt).await.is_err());
    assert!(
        recipient
            .accepted_welcome_receipt(&welcome.id)
            .unwrap()
            .is_none()
    );
    assert!(recipient.epoch(&group).is_err());
}
#[tokio::test]
async fn receipt_write_failure_rolls_back_private_key_package_and_all_join_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt-failure.db");
    let key = storage_sqlite::SqlCipherKey::new("04".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut recipient = client(storage.clone());
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = recipient.fresh_linking_key_package().await.unwrap();
    let retained = kp.clone();
    let (group, welcome) = invite(&mut approver, kp).await;
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER reject_receipt BEFORE INSERT ON accepted_welcome_receipts BEGIN SELECT RAISE(ABORT,'injected accepted receipt failure'); END;").unwrap();
    assert!(matches!(
        recipient.join_welcome(welcome.clone()).await,
        Err(cgka_traits::EngineError::Storage(_))
    ));
    assert!(
        recipient
            .accepted_welcome_receipt(&welcome.id)
            .unwrap()
            .is_none()
    );
    assert!(recipient.epoch(&group).is_err());
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&retained)
    );
    let count: i64 = injector
        .query_row("SELECT count(*) FROM cgka_groups", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
    injector
        .execute_batch("DROP TRIGGER reject_receipt;")
        .unwrap();
    recipient.join_welcome(welcome.clone()).await.expect(
        "the same private KeyPackage and Welcome must remain retryable after atomic rollback",
    );
    assert!(
        recipient
            .accepted_welcome_receipt(&welcome.id)
            .unwrap()
            .is_some()
    );
    assert!(
        !recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&retained)
    );
}
#[tokio::test]
async fn encrypted_restart_retains_exact_join_fact_after_hydration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt-reopen.db");
    let key = storage_sqlite::SqlCipherKey::new("03".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut recipient = client(storage.clone());
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = recipient.fresh_key_package().await.unwrap();
    let (_group, welcome) = invite(&mut approver, kp).await;
    recipient.join_welcome(welcome.clone()).await.unwrap();
    let before = recipient
        .accepted_welcome_receipt(&welcome.id)
        .unwrap()
        .unwrap();
    drop(recipient);
    storage.close().unwrap();
    drop(storage);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut reopened = client(storage);
    reopened.hydrate_all_stored_groups().unwrap();
    assert!(
        reopened
            .accepted_welcome_receipt(&welcome.id)
            .unwrap()
            .unwrap()
            == before
    );
}

#[tokio::test]
async fn forgetting_group_retains_history_but_refuses_live_receipt_query() {
    use cgka_traits::storage::{AcceptedWelcomeStorage, StorageError};
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut recipient = client(storage.clone());
    let mut approver = client(SqliteAccountStorage::in_memory().unwrap());
    let kp = recipient.fresh_key_package().await.unwrap();
    let (group, welcome) = invite(&mut approver, kp).await;
    recipient.join_welcome(welcome.clone()).await.unwrap();
    assert!(recipient.forget_group_local(&group).unwrap());
    assert!(
        storage
            .accepted_welcome_receipt(&welcome.id)
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        recipient.accepted_welcome_receipt(&welcome.id),
        Err(cgka_traits::EngineError::Storage(StorageError::NotFound))
    ));
}

#[path = "accepted_welcome_receipts/source_leaf_proofs.rs"]
mod source_leaf_proofs;

#[path = "accepted_welcome_receipts/single_use_key_packages.rs"]
mod single_use_key_packages;

#[path = "accepted_welcome_receipts/purpose_key_packages.rs"]
mod purpose_key_packages;

#[path = "accepted_welcome_receipts/purpose_welcome.rs"]
mod purpose_welcome;

#[path = "accepted_welcome_receipts/roster_ack_capture.rs"]
mod roster_ack_capture;

#[path = "accepted_welcome_receipts/device_group_genesis.rs"]
mod device_group_genesis;

#[path = "accepted_welcome_receipts/private_device_invite.rs"]
mod private_device_invite;

#[path = "accepted_welcome_receipts/private_batch.rs"]
mod private_batch;
