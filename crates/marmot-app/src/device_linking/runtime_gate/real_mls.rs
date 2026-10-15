//! Combined real stock-SDK + private purpose-KeyPackage + actual MLS join.
//! Isolated SQLCipher/synthetic accounts and actual NIP59, with no network.
//! Cached prepared batches are accessed only by this test fixture; no sender
//! publication/confirmation/delivery or settled-roster permission is implied.
use super::*;
use crate::device_linking::LinkingContext;
use crate::external_signer::AccountSigner;
use cgka_engine::key_package::key_package_metadata;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::engine::{CgkaEngine, KeyPackage};
use cgka_traits::group::ProtocolProfile;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{MessageStorage, StorageProvider, WelcomeStorage};
use cgka_traits::transport::{EncryptedPayload, TransportMessage};
use cgka_traits::types::GroupId;
use storage_sqlite::SqliteAccountStorage;
fn engine(
    storage: SqliteAccountStorage,
    keys: &nostr::prelude::Keys,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .identity(keys.public_key().to_bytes().to_vec())
        .account_identity_proof_signer(AccountSigner::Local(keys.clone()).as_proof_signer())
        .protocol_profile(ProtocolProfile::Current)
        .supported_app_components(
            cgka_traits::app_components::default_group_components()
                .into_iter()
                .chain([cgka_traits::app_components::NOSTR_ROUTING_COMPONENT_ID]),
        )
        .peeler(Box::new(
            transport_nostr_peeler::NostrMlsPeeler::new().with_welcome_signer(keys.clone()),
        ))
        .build()
        .unwrap()
}

/// A malicious synthetic peer uses actual OpenMLS, independently of trusted
/// single-Add preparation. These negative inputs are real signed private trees
/// and real NIP59, never caller DTO authorization or relay publication.
async fn adversarial_batch(
    storage: &SqliteAccountStorage,
    keys: &nostr::prelude::Keys,
    approved: &GroupId,
    context: &LinkingContext,
    packages: &[KeyPackage],
    wrong_group: bool,
) -> (
    cgka_traits::peeler::PrivateLinkingWelcomeContext,
    Vec<TransportMessage>,
) {
    use openmls::prelude::*;
    use openmls_basic_credential::SignatureKeyPair;
    use sha2::{Digest, Sha256};
    use tls_codec::{Deserialize as _, Serialize as _};
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let provider = cgka_engine::provider::EngineOpenMlsProvider::<SqliteAccountStorage>::new(
        &crypto,
        storage.mls_storage(),
    );
    let mut group = MlsGroup::load(
        provider.storage(),
        &openmls::group::GroupId::from_slice(approved.as_slice()),
    )
    .unwrap()
    .unwrap();
    let signer = SignatureKeyPair::read(
        provider.storage(),
        &context.approver,
        SignatureScheme::ED25519,
    )
    .unwrap();
    if wrong_group {
        let leaf = group.own_leaf_node().unwrap();
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(group.ciphersuite())
            .capabilities(leaf.capabilities().clone())
            .with_leaf_node_extensions(leaf.extensions().clone())
            .unwrap()
            .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .with_group_context_extensions(group.extensions().clone())
            .use_ratchet_tree_extension(true)
            .build();
        let credential = CredentialWithKey {
            credential: leaf.credential().clone(),
            signature_key: context.approver.to_vec().into(),
        };
        group = MlsGroup::new(&provider, &signer, &config, credential).unwrap();
    }
    assert!(group.pending_commit().is_none());
    assert!(group.pending_proposals().next().is_none());
    let packages = packages
        .iter()
        .map(|p| {
            let MlsMessageBodyIn::KeyPackage(kp) = MlsMessageIn::tls_deserialize_exact(&p.bytes)
                .unwrap()
                .extract()
            else {
                panic!("actual KP expected")
            };
            kp.validate(&crypto, ProtocolVersion::Mls10).unwrap()
        })
        .collect::<Vec<_>>();
    let (commit, welcome, _) = group.add_members(&provider, &signer, &packages).unwrap();
    let commit = commit.tls_serialize_detached().unwrap();
    let welcome = welcome.tls_serialize_detached().unwrap();
    let transport = cgka_traits::peeler::PrivateLinkingWelcomeContext {
        account: context.account,
        approver: context.approver,
        recipient: context.recipient,
        approver_generation: context.approver_generation,
        recipient_generation: context.new_device_generation,
        group_id: cgka_traits::GroupId::new(group.group_id().as_slice().to_vec()),
        nonce: context.nonce,
        context_digest: context.digest().unwrap(),
        key_package_reference: context.key_package_reference,
        key_package_digest: Sha256::digest(&context.exact_key_package).into(),
        commit_digest: Sha256::digest(commit).into(),
        welcome_digest: Sha256::digest(&welcome).into(),
    };
    let messages = transport_nostr_peeler::NostrMlsPeeler::new()
        .with_welcome_signer(keys.clone())
        .wrap_private_linking_welcome(
            &EncryptedPayload {
                ciphertext: welcome,
                aad: vec![],
            },
            &transport,
        )
        .await
        .unwrap();
    (transport, messages)
}

fn signer(kp: &KeyPackage) -> [u8; 32] {
    hex::decode(key_package_metadata(kp).unwrap().signature_public_key_hex)
        .unwrap()
        .try_into()
        .unwrap()
}
#[tokio::test]
async fn genuine_sdk_gate_authorizes_only_exact_real_mls_welcome_once() {
    verify_real_welcome(false, false).await;
}
#[tokio::test]
async fn device_linking_real_welcome_with_unapproved_extra_leaf_is_rolled_back() {
    verify_real_welcome(true, false).await;
}
#[tokio::test]
async fn device_linking_collected_real_welcome_joins_once_with_atomic_sql_retry() {
    verify_real_welcome(false, true).await;
}
#[tokio::test]
async fn device_linking_collected_unapproved_leaf_is_rolled_back() {
    verify_real_welcome(true, true).await;
}
async fn verify_real_welcome(extra_leaf: bool, use_collection: bool) {
    let keys = nostr::prelude::Keys::generate();
    let account = keys.public_key().to_bytes();
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("combined-linking.db");
    let key = storage_sqlite::SqlCipherKey::new("19".repeat(32)).unwrap();
    let new_store = Arc::new(SqliteAccountStorage::open_encrypted(&database, &key).unwrap());
    let approver_store = Arc::new(SqliteAccountStorage::in_memory().unwrap());
    for store in [&new_store, &approver_store] {
        store
            .ensure_account_projection_with_identity(
                "isolated-combined-test",
                &hex::encode(account),
            )
            .unwrap();
    }
    let mut recipient = engine((*new_store).clone(), &keys);
    let mut approver = engine((*approver_store).clone(), &keys);
    let recipient_device = signer(&recipient.fresh_key_package().await.unwrap());
    let approver_device = signer(&approver.fresh_key_package().await.unwrap());
    assert!(recipient_device != approver_device);
    let mut a = LinkingOwner::startup(new_store.clone(), account, recipient_device).unwrap();
    let mut b = LinkingOwner::startup(approver_store.clone(), account, approver_device).unwrap();
    let generation = a.reserve().unwrap();
    let approver_generation = b.reserve().unwrap();
    let scope = PurposeAttemptScope {
        account,
        local_device: recipient_device,
        generation,
    };
    let kp = recipient.resolve_linking_key_package(&scope).await.unwrap();
    let metadata = key_package_metadata(&kp).unwrap();
    let reference: [u8; 32] = hex::decode(metadata.key_package_ref_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let extra = if extra_leaf {
        let mut third = engine(SqliteAccountStorage::in_memory().unwrap(), &keys);
        Some(third.fresh_key_package().await.unwrap())
    } else {
        None
    };
    use cgka_traits::app_components::{
        AppComponentData, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, encode_nostr_routing_v1,
    };
    let routing = NostrRoutingV1::new([73; 32], vec!["wss://isolated.example".into()]).unwrap();
    let origin = approver
        .create_private_device_group_genesis_with_components(vec![AppComponentData {
            component_id: NOSTR_ROUTING_COMPONENT_ID,
            data: encode_nostr_routing_v1(&routing).unwrap(),
        }])
        .unwrap();
    let group = origin.group_id().clone();
    let predecessor =
        crate::device_linking::PredecessorRoster::from_candidate(origin.current()).unwrap();
    let context = LinkingContext {
        version: 1,
        nonce: [13; 32],
        new_device_generation: generation,
        approver_generation,
        account,
        exact_key_package: kp.bytes.clone(),
        key_package_reference: reference,
        device_group: group.as_slice().to_vec(),
        predecessor,
        approver: approver_device,
        recipient: recipient_device,
    };
    let now = Instant::now();
    a.begin(context.clone(), Role::NewDevice, now)
        .await
        .unwrap();
    b.begin(context.clone(), Role::Approver, now).await.unwrap();
    new_store
        .device_linking_key_package_storage()
        .unwrap()
        .bind_purpose_context(
            &scope,
            &PurposeContextBinding {
                nonce: context.nonce,
                context_digest: context.digest().unwrap(),
            },
        )
        .unwrap();
    let ao = a.offer(now).unwrap();
    let bo = b.offer(now).unwrap();
    a.admit_peer(&bo, now).await.unwrap();
    b.admit_peer(&ao, now).await.unwrap();
    a.start_verification(now).await.unwrap();
    for _ in 0..8 {
        drain(&mut a, &mut b, now).await;
        drain(&mut b, &mut a, now).await;
    }
    assert!(a.decimals(now).unwrap().is_some());
    assert!(a.decimals(now).unwrap() == b.decimals(now).unwrap());
    a.confirm(now).await.unwrap();
    b.confirm(now).await.unwrap();
    for _ in 0..8 {
        drain(&mut a, &mut b, now).await;
        drain(&mut b, &mut a, now).await;
    }
    let token = a.take_verified(now).await.unwrap();
    let approver_token = b.take_verified(now).await.unwrap();
    let sender_gate = Arc::new(crate::device_linking::invite_gate::RuntimeInviteGate::new());
    sender_gate.arm_genesis(approver_token, &origin).unwrap();
    approver.install_trusted_private_invite_policy(sender_gate);
    let (wrong_transport, wrong_batch) = adversarial_batch(
        &approver_store,
        &keys,
        &group,
        &context,
        std::slice::from_ref(&kp),
        true,
    )
    .await;
    let wrong_group = wrong_transport.group_id.clone();
    let mut prepared = None;
    let (mut transport, mut batch) = if let Some(extra) = extra {
        adversarial_batch(
            &approver_store,
            &keys,
            &group,
            &context,
            &[kp.clone(), extra],
            false,
        )
        .await
    } else {
        prepared = Some(
            approver
                .prepare_private_device_invite(&group, kp.clone())
                .await
                .unwrap(),
        );
        let fact = approver_store
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            .unwrap();
        let messages = fact.transport.as_ref().unwrap().welcomes.clone();
        let observation = transport_nostr_peeler::NostrMlsPeeler::new()
            .with_welcome_signer(keys.clone())
            .observe_private_linking_welcome(&messages[0])
            .await
            .unwrap();
        (observation.context, messages)
    };
    let welcome_id = batch[0].id.clone();
    let wrong_id = wrong_batch[0].id.clone();
    let gate = Arc::new(RuntimeWelcomeGate::new());
    recipient.install_trusted_linking_welcome_policy(gate.clone());
    // SQL PairingVerified and authentic MLS alone still grant nothing.
    assert!(
        recipient
            .join_private_linking_welcome_batch(batch.clone(), &transport)
            .await
            .is_err()
    );
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&kp)
    );
    gate.arm(token).unwrap();
    let mut retained_collection = None;
    if use_collection {
        let purpose = new_store
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap();
        let peeler =
            transport_nostr_peeler::NostrMlsPeeler::new().with_welcome_signer(keys.clone());
        let mut collection =
            crate::device_linking::welcome_collection::PrivateWelcomeCollection::default();
        for message in batch.iter().rev() {
            collection
                .observe(&gate, &purpose, &peeler, message.clone())
                .await
                .unwrap();
        }
        let complete = collection
            .complete_for_retry(&gate, &purpose)
            .unwrap()
            .unwrap();
        assert!(complete.context == transport);
        assert!(
            gate.maintain().unwrap(),
            "collection alone grants no membership"
        );
        transport = complete.context;
        batch = complete.messages;
        retained_collection = Some(collection);
    }
    if extra_leaf {
        assert!(
            recipient
                .join_private_linking_welcome_batch(batch.clone(), &transport)
                .await
                .is_err(),
            "a genuine SAS result must refuse a real same-account leaf absent from the predecessor"
        );
        assert!(recipient.epoch(&group).is_err());
        assert!(
            new_store
                .accepted_device_group_anchor_storage()
                .unwrap()
                .accepted_anchor()
                .unwrap()
                .is_none()
        );
        assert!(!new_store.has_ingress_dedup_marker(&welcome_id).unwrap());
        assert!(
            recipient
                .accepted_welcome_receipt(&welcome_id)
                .unwrap()
                .is_none()
        );
        assert!(
            recipient
                .durably_owned_key_packages()
                .unwrap()
                .contains(&kp)
        );
        assert!(
            !new_store
                .device_linking_key_package_storage()
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .unwrap()
                .consumed
        );
        return;
    }
    // An authentic Welcome from the approved signer but another actual group
    // must roll back tentative private-key consumption and preserve exact retry.
    assert!(
        recipient
            .join_private_linking_welcome_batch(wrong_batch.clone(), &wrong_transport)
            .await
            .is_err()
    );
    assert!(recipient.epoch(&wrong_group).is_err());
    assert!(
        recipient
            .accepted_welcome_receipt(&wrong_id)
            .unwrap()
            .is_none()
    );
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&kp)
    );
    // Inject a real SQL failure after private consumption and receipt writes.
    // A lease rollback must retain the same still-live SDK evidence for retry.
    let injector = rusqlite::Connection::open(&database).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER reject_linking_consumption BEFORE UPDATE OF consumed ON device_linking_key_package WHEN NEW.consumed = 1 BEGIN SELECT RAISE(ABORT,'injected purpose consumption failure'); END;").unwrap();
    let failure = recipient
        .join_private_linking_welcome_batch(batch.clone(), &transport)
        .await;
    assert!(
        matches!(failure, Err(cgka_traits::error::EngineError::Storage(_))),
        "supported backend write failures must propagate"
    );
    assert!(recipient.epoch(&group).is_err());
    assert!(
        new_store
            .accepted_device_group_anchor_storage()
            .unwrap()
            .accepted_anchor()
            .unwrap()
            .is_none()
    );
    assert!(!new_store.has_ingress_dedup_marker(&welcome_id).unwrap());
    assert!(
        recipient
            .accepted_welcome_receipt(&welcome_id)
            .unwrap()
            .is_none()
    );
    assert!(
        recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&kp)
    );
    assert!(
        !new_store
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap()
            .consumed
    );
    if let Some(collection) = retained_collection.as_mut() {
        let purpose = new_store
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap();
        let retry = collection
            .complete_for_retry(&gate, &purpose)
            .unwrap()
            .expect("actual SQL rollback must retain the exact authenticated completed batch");
        assert!(retry.context == transport);
        assert!(retry.messages == batch);
        transport = retry.context;
        batch = retry.messages;
    }
    injector
        .execute_batch("DROP TRIGGER reject_linking_consumption;")
        .unwrap();
    assert!(
        recipient
            .join_private_linking_welcome_batch(batch.clone(), &transport)
            .await
            .unwrap()
            == group
    );
    let receipt = recipient
        .accepted_welcome_receipt(&welcome_id)
        .unwrap()
        .unwrap();
    assert!(receipt.group_id == group && receipt.consumed_key_package_ref == reference);
    assert!(
        receipt.own_signature_public_key == recipient_device
            && receipt.welcomer_signature_public_key == approver_device
    );
    assert!(
        receipt.own_account.as_slice() == account && receipt.welcomer_account.as_slice() == account
    );
    assert!(
        new_store
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap()
            .consumed
    );
    assert!(
        !recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&kp)
    );
    assert!(
        recipient
            .join_private_linking_welcome_batch(wrong_batch, &wrong_transport)
            .await
            .is_err()
    );
    assert!(gate.begin_join(&purpose(&context)).is_err());
    let anchor = new_store
        .accepted_device_group_anchor_storage()
        .unwrap()
        .accepted_anchor()
        .unwrap()
        .unwrap();
    assert!(
        anchor.draft.group_id == group
            && anchor.draft.successor.epoch == receipt.joined_epoch
            && anchor.draft.successor.epoch_authenticator_digest
                == receipt.joined_epoch_authenticator_digest
    );
    assert!(new_store.list_welcomes().unwrap().is_empty());
    drop(prepared);
}
