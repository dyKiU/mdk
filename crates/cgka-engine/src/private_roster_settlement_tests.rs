//! Actual isolated MLS/SQL controls; no SDK/native permission fixtures.
use super::*;
use crate::private_successor::tests::joined_pair;
use cgka_traits::engine::{CgkaEngine, GroupEvent};
use sha2::{Digest, Sha256};
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};

pub(crate) async fn complete_pair(
    storage: SqliteAccountStorage,
) -> (
    Engine<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
    GroupId,
) {
    let (mut initiator, mut responder, group) = joined_pair(storage).await;
    responder.select_private_roster_settlement(&group).unwrap();
    let SendResult::ApplicationMessage { msg: challenge, .. } = initiator
        .start_private_roster_settlement(&group)
        .await
        .unwrap()
    else {
        panic!("expected genuine encrypted private challenge");
    };
    responder.ingest(challenge).await.unwrap();
    let SendResult::ApplicationMessage { msg: ack, .. } =
        responder.prepare_private_roster_ack(&group).await.unwrap()
    else {
        panic!("expected genuine encrypted private ACK");
    };
    initiator.ingest(ack).await.unwrap();
    assert!(
        initiator
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
    (initiator, responder, group)
}

#[tokio::test]
async fn private_roster_settlement_expired_selection_never_counts_real_challenge() {
    let (mut initiator, mut responder, group) =
        joined_pair(SqliteAccountStorage::in_memory().unwrap()).await;
    responder.select_private_roster_settlement(&group).unwrap();
    let SendResult::ApplicationMessage { msg: challenge, .. } = initiator
        .start_private_roster_settlement(&group)
        .await
        .unwrap()
    else {
        panic!("expected genuine encrypted challenge");
    };
    // Move only this isolated test's original monotonic deadline into the past.
    // No serialized state, positive fact or production authority is constructed.
    {
        let mut slot = responder.settlement_admission.lock().unwrap();
        Arc::get_mut(slot.as_mut().unwrap()).unwrap().deadline =
            Instant::now() - Duration::from_secs(1);
    }
    responder.drain_events();
    responder.ingest(challenge).await.unwrap();
    let store = responder
        .storage
        .private_roster_settlement_storage()
        .unwrap();
    assert!(matches!(
        store.read_round().unwrap().unwrap().phase,
        PrivateSettlementPhase::Denied
    ));
    assert!(store.read_facts().unwrap().is_empty());
    assert!(responder.prepare_private_roster_ack(&group).await.is_err());
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_none()
    );
    assert!(
        !responder
            .drain_events()
            .iter()
            .any(|event| matches!(event, GroupEvent::MessageReceived { .. }))
    );
}

#[tokio::test]
async fn private_roster_settlement_completed_encrypted_reopen_preserves_roster_without_admission() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-completed-round.db");
    let key = SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (initiator, responder, group) = complete_pair(storage.clone()).await;
    let expected = responder
        .validated_settled_device_roster(&group)
        .unwrap()
        .unwrap()
        .candidate()
        .clone();
    drop(initiator);
    drop(responder);
    drop(storage);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut reopened = crate::device_group_genesis::tests::current_test_engine(storage.clone());
    reopened.hydrate_all_stored_groups().unwrap();
    assert!(
        reopened
            .validated_settled_device_roster(&group)
            .unwrap()
            .unwrap()
            .candidate()
            == &expected
    );
    assert!(reopened.settlement_admission_for(&group).unwrap().is_none());
    assert!(
        reopened
            .device_revocation_storage_retry_groups()
            .unwrap()
            .is_empty(),
        "durable completed facts cannot restore a revoked retry owner"
    );
    assert!(reopened.linking_welcome_policy.is_none());
    assert!(
        reopened.prepare_private_roster_ack(&group).await.is_err(),
        "completed SQL facts cannot reconstruct publication admission"
    );
    assert!(matches!(
        storage
            .private_roster_settlement_storage()
            .unwrap()
            .read_round()
            .unwrap()
            .unwrap()
            .phase,
        PrivateSettlementPhase::Completed
    ));
}

fn crypto_digest(connection: &rusqlite::Connection) -> [u8; 32] {
    let mut query = connection.prepare("SELECT provider_version,label,storage_key,group_key,value FROM openmls_values ORDER BY provider_version,storage_key").unwrap();
    let rows = query
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })
        .unwrap();
    let mut hash = Sha256::new();
    for row in rows {
        let (version, label, key, group, value) = row.unwrap();
        hash.update(version.to_be_bytes());
        for bytes in [label, key, group.unwrap_or_default(), value] {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
    }
    hash.finalize().into()
}

#[tokio::test]
async fn private_roster_settlement_local_sql_fault_rolls_back_crypto_then_retries_real_ack() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-round-fault.db");
    let key = SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (mut initiator, mut responder, group) = joined_pair(storage.clone()).await;
    responder.select_private_roster_settlement(&group).unwrap();
    let SendResult::ApplicationMessage { msg: challenge, .. } = initiator
        .start_private_roster_settlement(&group)
        .await
        .unwrap()
    else {
        panic!("expected genuine encrypted challenge");
    };
    responder.ingest(challenge).await.unwrap();
    let before = storage
        .private_roster_settlement_storage()
        .unwrap()
        .read_round()
        .unwrap()
        .unwrap();
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    let before_crypto = crypto_digest(&injector);
    injector.execute_batch("CREATE TRIGGER fail_settlement_local BEFORE INSERT ON private_roster_settlement_facts BEGIN SELECT RAISE(ABORT,'isolated settlement SQL fault'); END;").unwrap();
    assert!(
        matches!(
            responder.prepare_private_roster_ack(&group).await,
            Err(EngineError::Storage(_))
        ),
        "actual own-slot failure must retain its typed SQL error"
    );
    assert_eq!(
        crypto_digest(&injector),
        before_crypto,
        "failed own-slot transaction must restore actual MLS ratchets"
    );
    let store = storage.private_roster_settlement_storage().unwrap();
    let after = store.read_round().unwrap().unwrap();
    assert_eq!(after.generation, before.generation);
    assert!(matches!(after.phase, PrivateSettlementPhase::Pending));
    assert!(after.prepared_ciphertext.is_none());
    assert_eq!(store.read_facts().unwrap().len(), 1);
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_none()
    );
    injector
        .execute_batch("DROP TRIGGER fail_settlement_local;")
        .unwrap();
    let SendResult::ApplicationMessage { msg: ack, .. } =
        responder.prepare_private_roster_ack(&group).await.unwrap()
    else {
        panic!("expected real ACK after SQL rollback");
    };
    initiator.ingest(ack).await.unwrap();
    assert!(
        initiator
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn private_roster_settlement_delete_permanently_fences_completed_round() {
    let (mut initiator, responder, group) =
        complete_pair(SqliteAccountStorage::in_memory().unwrap()).await;
    assert!(initiator.forget_group_local(&group).unwrap());
    let store = initiator
        .storage
        .private_roster_settlement_storage()
        .unwrap();
    assert!(matches!(
        store.read_round().unwrap().unwrap().phase,
        PrivateSettlementPhase::Denied
    ));
    assert!(store.read_facts().unwrap().is_empty());
    assert!(
        initiator
            .settlement_admission_for(&group)
            .unwrap()
            .is_none()
    );
    assert!(
        initiator
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_none()
    );
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some(),
        "local deletion does not invent peer delivery knowledge"
    );
}

#[tokio::test]
async fn private_roster_settlement_delete_sql_fault_preserves_crypto_round_and_live_admission() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-delete-fault.db");
    let key = SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (initiator, mut responder, group) = complete_pair(storage.clone()).await;
    let admission = responder.settlement_admission_for(&group).unwrap().unwrap();
    let prior = storage
        .private_roster_settlement_storage()
        .unwrap()
        .read_round()
        .unwrap()
        .unwrap();
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    let prior_crypto = crypto_digest(&injector);
    injector.execute_batch("CREATE TRIGGER fail_settlement_delete BEFORE DELETE ON cgka_groups BEGIN SELECT RAISE(ABORT,'isolated deletion SQL fault'); END;").unwrap();
    assert!(matches!(
        responder.forget_group_local(&group),
        Err(EngineError::Storage(_))
    ));
    assert_eq!(
        crypto_digest(&injector),
        prior_crypto,
        "failed deletion must restore actual MLS state"
    );
    assert!(
        storage
            .private_roster_settlement_storage()
            .unwrap()
            .read_round()
            .unwrap()
            .unwrap()
            == prior,
        "failed deletion must roll back the negative fence and exact completed round together"
    );
    assert!(admission.is_live());
    assert!(Arc::ptr_eq(
        &admission,
        &responder.settlement_admission_for(&group).unwrap().unwrap()
    ));
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
    injector
        .execute_batch("DROP TRIGGER fail_settlement_delete;")
        .unwrap();
    assert!(responder.forget_group_local(&group).unwrap());
    assert!(!admission.is_live());
    assert!(matches!(
        storage
            .private_roster_settlement_storage()
            .unwrap()
            .read_round()
            .unwrap()
            .unwrap()
            .phase,
        PrivateSettlementPhase::Denied
    ));
    assert!(
        initiator
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn private_enrollment_predecessor_export_verifies_actual_tree_without_granting_consent() {
    use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn, ProposalStore, PublicGroup};
    use tls_codec::Deserialize;
    let (_, unfinished, unfinished_group) =
        joined_pair(SqliteAccountStorage::in_memory().unwrap()).await;
    assert!(
        unfinished
            .export_settled_device_predecessor(&unfinished_group)
            .unwrap()
            .is_none(),
        "uncompleted protected lineage cannot export a settled predecessor"
    );
    let (_, responder, group) = complete_pair(SqliteAccountStorage::in_memory().unwrap()).await;
    let candidate = responder
        .validated_settled_device_roster(&group)
        .unwrap()
        .unwrap()
        .candidate()
        .clone();
    let artifact = responder.export_settled_device_predecessor(&group).unwrap();
    assert!(
        artifact.is_some(),
        "a genuine completed protected predecessor must export actual signed MLS GroupInfo"
    );
    let bytes = artifact.unwrap();
    let MlsMessageBodyIn::GroupInfo(info) = MlsMessageIn::tls_deserialize_exact(&bytes)
        .unwrap()
        .extract()
    else {
        panic!("predecessor artifact must contain actual MLS GroupInfo");
    };
    let tree = info
        .extensions()
        .ratchet_tree()
        .unwrap()
        .ratchet_tree()
        .clone();
    let scratch = openmls_memory_storage::MemoryStorage::default();
    let (public, verified) = PublicGroup::from_external(
        &responder.crypto,
        &scratch,
        tree,
        info,
        ProposalStore::new(),
    )
    .unwrap();
    assert!(public.group_id().as_slice() == candidate.group_id.as_slice());
    assert_eq!(public.group_context().epoch().as_u64(), candidate.epoch.0);
    let members = public.members().collect::<Vec<_>>();
    assert_eq!(members.len(), candidate.leaves.len());
    assert!(
        candidate
            .leaves
            .iter()
            .all(|leaf| members
                .iter()
                .any(|member| member.index.u32() == leaf.leaf_index
                    && member.signature_key == leaf.signature_public_key
                    && crate::identity::validated_member_id(&member.credential).unwrap()
                        == candidate.account))
    );
    for leaf in public.export_ratchet_tree().leaves() {
        assert!(
            crate::account_identity_proof::validate_leaf_account_identity_proof(
                leaf,
                public.group_context().ciphersuite()
            )
            .unwrap()
                == cgka_traits::group::ProtocolProfile::Current
        );
    }
    assert!(
        verified
            .group_context()
            .extensions()
            .app_data_dictionary()
            .unwrap()
            .dictionary()
            .get(&cgka_traits::device_group_genesis::PRIVATE_DEVICE_GROUP_COMPONENT_ID)
            == Some(cgka_traits::device_group_genesis::PRIVATE_DEVICE_GROUP_PROFILE)
    );
    let mut corrupted = bytes.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    let MlsMessageBodyIn::GroupInfo(info) = MlsMessageIn::tls_deserialize_exact(&corrupted)
        .unwrap()
        .extract()
    else {
        panic!("signature mutation must preserve message framing");
    };
    let tree = info
        .extensions()
        .ratchet_tree()
        .unwrap()
        .ratchet_tree()
        .clone();
    assert!(
        PublicGroup::from_external(
            &responder.crypto,
            &openmls_memory_storage::MemoryStorage::default(),
            tree,
            info,
            ProposalStore::new()
        )
        .is_err(),
        "actual GroupInfo signature mutation must fail OpenMLS validation"
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert!(MlsMessageIn::tls_deserialize_exact(&trailing).is_err());
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .unwrap()
            .candidate()
            == &candidate
    );
}

#[tokio::test]
async fn private_predecessor_metadata_validates_crypto_and_rejects_copied_expectations() {
    let (_, engine, group) = complete_pair(SqliteAccountStorage::in_memory().unwrap()).await;
    let candidate = engine
        .validated_settled_device_roster(&group)
        .unwrap()
        .unwrap()
        .candidate()
        .clone();
    let bytes = engine
        .export_settled_device_predecessor(&group)
        .unwrap()
        .unwrap();
    let record_before = cgka_traits::GroupStorage::get_group(&engine.storage, &group).unwrap();
    let proof = engine.validate_private_device_predecessor(
        &bytes,
        &candidate.account,
        &group,
        candidate.epoch,
        &candidate.leaves,
    );
    assert!(
        proof.is_ok(),
        "actual signed portable predecessor must authenticate into scratch metadata"
    );
    let proof = proof.unwrap();
    assert!(proof.account() == &candidate.account && proof.group_id() == &group);
    assert_eq!(proof.epoch(), candidate.epoch);
    assert!(proof.leaves() == candidate.leaves);
    assert!(proof.artifact_digest().as_slice() == Sha256::digest(&bytes).as_slice());
    let wrong_account = cgka_traits::MemberId::new(vec![1; 32]);
    assert!(
        engine
            .validate_private_device_predecessor(
                &bytes,
                &wrong_account,
                &group,
                candidate.epoch,
                &candidate.leaves
            )
            .is_err()
    );
    let wrong_group = GroupId::new(vec![2; 16]);
    assert!(
        engine
            .validate_private_device_predecessor(
                &bytes,
                &candidate.account,
                &wrong_group,
                candidate.epoch,
                &candidate.leaves
            )
            .is_err()
    );
    assert!(
        engine
            .validate_private_device_predecessor(
                &bytes,
                &candidate.account,
                &group,
                cgka_traits::EpochId(candidate.epoch.0 + 1),
                &candidate.leaves
            )
            .is_err()
    );
    let mut substituted = candidate.leaves.clone();
    substituted[0].signature_public_key[0] ^= 1;
    assert!(
        engine
            .validate_private_device_predecessor(
                &bytes,
                &candidate.account,
                &group,
                candidate.epoch,
                &substituted
            )
            .is_err()
    );
    let mut substituted = candidate.leaves.clone();
    substituted[0].leaf_index += 5;
    assert!(
        engine
            .validate_private_device_predecessor(
                &bytes,
                &candidate.account,
                &group,
                candidate.epoch,
                &substituted
            )
            .is_err()
    );
    let mut reordered = candidate.leaves.clone();
    reordered.reverse();
    assert!(
        engine
            .validate_private_device_predecessor(
                &bytes,
                &candidate.account,
                &group,
                candidate.epoch,
                &reordered
            )
            .is_err()
    );
    assert!(
        engine
            .validate_private_device_predecessor(
                &bytes,
                &candidate.account,
                &group,
                candidate.epoch,
                &candidate.leaves[..1]
            )
            .is_err()
    );
    let mut duplicate = candidate.leaves.clone();
    duplicate[1] = duplicate[0].clone();
    assert!(
        engine
            .validate_private_device_predecessor(
                &bytes,
                &candidate.account,
                &group,
                candidate.epoch,
                &duplicate
            )
            .is_err()
    );
    assert!(
        engine
            .validate_private_device_predecessor(
                &bytes,
                &candidate.account,
                &group,
                candidate.epoch,
                &[]
            )
            .is_err()
    );
    assert!(
        cgka_traits::GroupStorage::get_group(&engine.storage, &group).unwrap() == record_before,
        "portable validation must not mutate account group storage"
    );
    assert!(
        engine
            .export_settled_device_predecessor(&group)
            .unwrap()
            .unwrap()
            == bytes,
        "portable validation must not mutate account MLS state"
    );
}

#[tokio::test]
async fn private_predecessor_metadata_rejects_signature_framing_and_resource_abuse() {
    let (_, engine, group) = complete_pair(SqliteAccountStorage::in_memory().unwrap()).await;
    let candidate = engine
        .validated_settled_device_roster(&group)
        .unwrap()
        .unwrap()
        .candidate()
        .clone();
    let bytes = engine
        .export_settled_device_predecessor(&group)
        .unwrap()
        .unwrap();
    let mut corrupted = bytes.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    let mut trailing = bytes.clone();
    trailing.push(0);
    for invalid in [
        &corrupted[..],
        &trailing[..],
        &bytes[..bytes.len() - 1],
        &[],
    ] {
        assert!(
            engine
                .validate_private_device_predecessor(
                    invalid,
                    &candidate.account,
                    &group,
                    candidate.epoch,
                    &candidate.leaves
                )
                .is_err()
        );
    }
    assert!(
        engine
            .validate_private_device_predecessor(
                &vec![0; 256 * 1024 + 1],
                &candidate.account,
                &group,
                candidate.epoch,
                &candidate.leaves
            )
            .is_err()
    );
    let excessive = vec![candidate.leaves[0].clone(); 129];
    assert!(
        engine
            .validate_private_device_predecessor(
                &bytes,
                &candidate.account,
                &group,
                candidate.epoch,
                &excessive
            )
            .is_err()
    );
}

#[tokio::test]
async fn private_predecessor_metadata_rejects_real_ordinary_profile_even_with_matching_caller_roster()
 {
    use crate::device_group_genesis::tests::current_test_engine;
    use cgka_traits::engine::CreateGroupRequest;
    use tls_codec::Serialize;
    let mut engine = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
    let (group, _) = engine
        .create_group(CreateGroupRequest {
            name: "ordinary portable negative".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let candidate = engine
        .candidate_device_group_snapshot(&group)
        .unwrap()
        .unwrap();
    let bytes = engine
        .with_mls_group(&group, |mls| {
            Ok(mls
                .export_group_info(&engine.crypto, &engine.identity.signer, true)
                .unwrap()
                .tls_serialize_detached()
                .unwrap())
        })
        .unwrap();
    assert!(
        engine
            .validate_private_device_predecessor(
                &bytes,
                &candidate.account,
                &group,
                candidate.epoch,
                &candidate.leaves
            )
            .is_err(),
        "actual ordinary Current signed tree is not private F574, even when caller metadata matches"
    );
}

#[tokio::test]
async fn private_predecessor_metadata_rejects_actual_signed_wrong_private_payload() {
    use cgka_traits::device_group_genesis::PRIVATE_DEVICE_GROUP_COMPONENT_ID;
    use cgka_traits::group::ProtocolProfile;
    use openmls::extensions::{AppDataDictionaryExtension, Extension, Extensions};
    use openmls::group::{MlsGroupCreateConfig, PURE_PLAINTEXT_WIRE_FORMAT_POLICY};
    use tls_codec::Serialize;
    let mut engine = crate::device_group_genesis::tests::current_test_engine(
        SqliteAccountStorage::in_memory().unwrap(),
    );
    let template = engine
        .create_private_device_group_genesis()
        .unwrap()
        .group_id()
        .clone();
    let extensions = engine
        .with_mls_group(&template, |mls| Ok(mls.extensions().clone()))
        .unwrap();
    let mut dictionary = extensions
        .app_data_dictionary()
        .unwrap()
        .dictionary()
        .clone();
    dictionary.insert(
        PRIVATE_DEVICE_GROUP_COMPONENT_ID,
        b"incorrect private payload".to_vec(),
    );
    let mut values = extensions
        .iter()
        .filter(|ext| !matches!(ext, Extension::AppDataDictionary(_)))
        .cloned()
        .collect::<Vec<_>>();
    values.push(Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dictionary),
    ));
    // Actual OpenMLS-signed adversarial profile. Engine's component mutation
    // validator rejects this payload, so use the independent library boundary;
    // no private origin/approval or protected completed fact is created for it.
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(engine.ciphersuite)
        .capabilities(crate::capabilities::leaf_capabilities(
            &engine.registry,
            engine.ciphersuite,
            ProtocolProfile::Current,
        ))
        .with_leaf_node_extensions(
            engine
                .identity
                .leaf_extensions(&engine.supported_app_components)
                .unwrap(),
        )
        .unwrap()
        .with_group_context_extensions(Extensions::from_vec(values).unwrap())
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let provider = crate::provider::EngineOpenMlsProvider::<SqliteAccountStorage>::new(
        &engine.crypto,
        cgka_traits::StorageProvider::mls_storage(&engine.storage),
    );
    let mls = openmls::prelude::MlsGroup::new(
        &provider,
        &engine.identity.signer,
        &config,
        engine.identity.credential_with_key.clone(),
    )
    .unwrap();
    let bytes = mls
        .export_group_info(&engine.crypto, &engine.identity.signer, true)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    let group = GroupId::new(mls.group_id().as_slice().to_vec());
    let leaves = mls
        .members()
        .map(|member| crate::device_group_snapshot::CandidateDeviceLeaf {
            leaf_index: member.index.u32(),
            signature_public_key: member.signature_key,
        })
        .collect::<Vec<_>>();
    assert!(
        engine
            .validate_private_device_predecessor(
                &bytes,
                &engine.self_id(),
                &group,
                cgka_traits::EpochId(mls.epoch().as_u64()),
                &leaves
            )
            .is_err(),
        "actual signed Current tree with required F574 but wrong payload must be refused"
    );
}

#[tokio::test]
async fn private_predecessor_metadata_rejects_actual_mixed_account_private_tree() {
    use crate::device_group_genesis::tests::{current_test_engine, current_test_engine_with_key};
    use cgka_traits::device_group_genesis::PRIVATE_DEVICE_GROUP_COMPONENT_ID;
    use openmls_traits::OpenMlsProvider;
    use tls_codec::Serialize;
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut engine = current_test_engine(storage.clone());
    let group = engine
        .create_private_device_group_genesis()
        .unwrap()
        .group_id()
        .clone();
    let mut peer = current_test_engine_with_key(
        SqliteAccountStorage::in_memory().unwrap(),
        k256::schnorr::SigningKey::from_bytes(&[91; 32]).unwrap(),
    );
    assert!(peer.self_id() != engine.self_id());
    peer.supported_app_components
        .insert(PRIVATE_DEVICE_GROUP_COMPONENT_ID);
    let package = peer.fresh_key_package().await.unwrap();
    let package = engine.parse_key_package(&package).unwrap();
    let provider = crate::provider::EngineOpenMlsProvider::<SqliteAccountStorage>::new(
        &engine.crypto,
        cgka_traits::StorageProvider::mls_storage(&storage),
    );
    let mut mls = openmls::prelude::MlsGroup::load(
        provider.storage(),
        &openmls::group::GroupId::from_slice(group.as_slice()),
    )
    .unwrap()
    .unwrap();
    // OpenMLS authenticates this adversarial Add/tree. Private Engine policy
    // does not authorize it; no accepted/confirmed origin or approval is minted.
    mls.add_members(&provider, &engine.identity.signer, &[package])
        .unwrap();
    mls.merge_pending_commit(&provider).unwrap();
    let bytes = mls
        .export_group_info(&engine.crypto, &engine.identity.signer, true)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    let leaves = mls
        .members()
        .map(|member| crate::device_group_snapshot::CandidateDeviceLeaf {
            leaf_index: member.index.u32(),
            signature_public_key: member.signature_key,
        })
        .collect::<Vec<_>>();
    assert_eq!(leaves.len(), 2);
    assert!(
        engine
            .validate_private_device_predecessor(
                &bytes,
                &engine.self_id(),
                &group,
                cgka_traits::EpochId(mls.epoch().as_u64()),
                &leaves
            )
            .is_err(),
        "copied indexedsigners cannot hide authenticated foreignaccount credentials/proofs"
    );
}

struct PortableLegacyProofSigner(k256::schnorr::SigningKey);
impl crate::account_identity_proof::AccountIdentityProofSigner for PortableLegacyProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &crate::account_identity_proof::AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        use k256::schnorr::signature::hazmat::PrehashSigner;
        let signature = self
            .0
            .sign_prehash(&request.proof_event_id()?)
            .map_err(|_| "isolated proof signing failed".to_owned())?;
        Ok(signature.to_bytes())
    }
}
#[tokio::test]
async fn private_predecessor_metadata_rejects_actual_legacy_group_profile() {
    use cgka_traits::engine::CreateGroupRequest;
    use tls_codec::Serialize;
    let key = k256::schnorr::SigningKey::from_bytes(&[92; 32]).unwrap();
    let mut engine = crate::EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(key.verifying_key().to_bytes().to_vec())
        .account_identity_proof_signer(Arc::new(PortableLegacyProofSigner(key)))
        .peeler(Box::new(
            crate::device_group_genesis::tests::PassthroughPeeler,
        ))
        .legacy_compatibility_profile()
        .build()
        .unwrap();
    let (group, _) = engine
        .create_group(CreateGroupRequest {
            name: "legacy portable negative".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (bytes, epoch, leaves) = engine
        .with_mls_group(&group, |mls| {
            assert!(
                crate::account_identity_proof::protocol_profile_of_group(mls).unwrap()
                    == cgka_traits::group::ProtocolProfile::Legacy
            );
            Ok((
                mls.export_group_info(&engine.crypto, &engine.identity.signer, true)
                    .unwrap()
                    .tls_serialize_detached()
                    .unwrap(),
                cgka_traits::EpochId(mls.epoch().as_u64()),
                mls.members()
                    .map(|member| crate::device_group_snapshot::CandidateDeviceLeaf {
                        leaf_index: member.index.u32(),
                        signature_public_key: member.signature_key,
                    })
                    .collect::<Vec<_>>(),
            ))
        })
        .unwrap();
    assert!(
        engine
            .validate_private_device_predecessor(&bytes, &engine.self_id(), &group, epoch, &leaves)
            .is_err()
    );
}

async fn encrypted_enrollment_request_fixture_with_storage(
    storage: SqliteAccountStorage,
    alter: impl FnOnce(&mut serde_json::Value),
) -> (
    Engine<SqliteAccountStorage>,
    cgka_traits::TransportMessage,
    u32,
) {
    let (sender, receiver, group_id) = complete_pair(storage).await;
    encrypt_enrollment_request(&sender, receiver, group_id, alter).await
}

async fn encrypt_enrollment_request(
    sender: &Engine<SqliteAccountStorage>,
    receiver: Engine<SqliteAccountStorage>,
    group_id: GroupId,
    alter: impl FnOnce(&mut serde_json::Value),
) -> (
    Engine<SqliteAccountStorage>,
    cgka_traits::TransportMessage,
    u32,
) {
    use cgka_traits::app_event::MarmotAppEvent;
    use tls_codec::Serialize;
    let proof = sender
        .validated_settled_device_roster(&group_id)
        .unwrap()
        .unwrap();
    let own = proof
        .candidate()
        .leaves
        .iter()
        .find(|leaf| leaf.signature_public_key == sender.identity.signer.public())
        .unwrap();
    let expected_index = own.leaf_index;
    let mut content = serde_json::json!({
        "protocol": "whitenoise.experimental.enrollment-request.v1",
        "account": sender.self_id().as_slice(), "group_id": group_id.as_slice(),
        "epoch": proof.candidate().epoch.0,
        "epoch_authenticator_digest": proof.candidate().epoch_authenticator_digest,
        "leaves": proof.candidate().leaves.iter().map(|leaf| serde_json::json!({"leaf_index":leaf.leaf_index,"signature_public_key":leaf.signature_public_key})).collect::<Vec<_>>(),
        "artifact_digest": ([9u8;32]), "context_digest": ([10u8;32]),
        "enrollment_nonce": ([11u8;32]), "request_nonce": ([12u8;32]),
        "approver": sender.identity.signer.public(), "recipient": ([13u8;32]),
        "approver_generation": 2, "recipient_generation": 1,
        "key_package_reference": ([14u8;32]), "key_package_digest": ([15u8;32])
    });
    alter(&mut content);
    let event = MarmotAppEvent::new(
        hex::encode(sender.self_id().as_slice()),
        0,
        38175,
        vec![],
        content.to_string(),
    );
    let payload = event.encode().unwrap();
    let provider = crate::provider::EngineOpenMlsProvider::<SqliteAccountStorage>::new(
        &sender.crypto,
        sender.storage.mls_storage(),
    );
    let mut group = sender.take_mls_group(&group_id).unwrap().unwrap();
    let encrypted = group
        .create_message(&provider, &sender.identity.signer, &payload)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    sender.return_mls_group(&group_id, group);
    let message = cgka_traits::TransportMessage {
        id: crate::message_processor::content_dedup_id(&encrypted),
        payload: encrypted,
        timestamp: cgka_traits::Timestamp(0),
        causal_deps: vec![],
        source: cgka_traits::transport::TransportSource("test".into()),
        envelope: cgka_traits::transport::TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    };
    (receiver, message, expected_index)
}

#[tokio::test]
async fn private_enrollment_request_genuine_completed_predecessor_emits_sealed_metadata_once() {
    let (mut receiver, message, expected_index) =
        encrypted_enrollment_request_fixture(|_| {}).await;
    receiver.drain_events();
    receiver
        .ingest_private_enrollment_delivery(message.clone())
        .await
        .unwrap();
    let metadata = receiver.drain_authenticated_enrollment_requests().unwrap();
    assert_eq!(
        metadata.len(),
        1,
        "genuine completed predecessor delivery must emit metadata"
    );
    assert_eq!(metadata[0].source_index(), expected_index);
    assert!(
        !receiver
            .drain_events()
            .iter()
            .any(|event| matches!(event, GroupEvent::MessageReceived { .. }))
    );
    receiver
        .ingest_private_enrollment_delivery(message)
        .await
        .unwrap();
    assert!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn private_enrollment_request_substituted_approver_never_becomes_chat_output() {
    let (mut receiver, message, _) = encrypted_enrollment_request_fixture(|frame| {
        frame["approver"] = serde_json::json!(([99u8; 32]));
    })
    .await;
    receiver.drain_events();
    receiver
        .ingest_private_enrollment_delivery(message.clone())
        .await
        .unwrap();
    assert!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty()
    );
    assert!(
        !receiver
            .drain_events()
            .iter()
            .any(|event| matches!(event, GroupEvent::MessageReceived { .. })),
        "invalid private enrollment declarations must never become ordinary chat output"
    );
    receiver
        .ingest_private_enrollment_delivery(message)
        .await
        .unwrap();
    assert!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty()
    );
}

async fn assert_private_enrollment_declaration_rejected(
    alter: impl FnOnce(&mut serde_json::Value),
) {
    let (mut receiver, message, _) = encrypted_enrollment_request_fixture(alter).await;
    receiver.drain_events();
    receiver
        .ingest_private_enrollment_delivery(message.clone())
        .await
        .unwrap();
    assert!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty(),
        "substituted request declarations must not produce authenticated metadata"
    );
    assert!(
        !receiver
            .drain_events()
            .iter()
            .any(|event| matches!(event, GroupEvent::MessageReceived { .. })),
        "rejected private enrollment request must remain absent from ordinary chat output"
    );
    receiver
        .ingest_private_enrollment_delivery(message)
        .await
        .unwrap();
    assert!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn private_enrollment_request_rejects_account() {
    assert_private_enrollment_declaration_rejected(|frame| {
        frame["account"] = serde_json::json!(([98u8; 32]));
    })
    .await;
}

#[tokio::test]
async fn private_enrollment_request_rejects_epoch() {
    assert_private_enrollment_declaration_rejected(|frame| {
        frame["epoch"] = serde_json::json!(frame["epoch"].as_u64().unwrap() + 1);
    })
    .await;
}

#[tokio::test]
async fn private_enrollment_request_rejects_indexed_roster() {
    assert_private_enrollment_declaration_rejected(|frame| {
        frame["leaves"][0]["leaf_index"] = serde_json::json!(127);
    })
    .await;
}

#[tokio::test]
async fn private_enrollment_request_rejects_existing_recipient() {
    assert_private_enrollment_declaration_rejected(|frame| {
        frame["recipient"] = frame["approver"].clone();
    })
    .await;
}

#[tokio::test]
async fn private_enrollment_request_rejects_generation_bound() {
    assert_private_enrollment_declaration_rejected(|frame| {
        frame["approver_generation"] = serde_json::json!(u64::MAX);
    })
    .await;
}

#[tokio::test]
async fn private_enrollment_request_rejects_zero_artifact_digest() {
    assert_private_enrollment_declaration_rejected(|frame| {
        frame["artifact_digest"] = serde_json::json!(([0u8; 32]));
    })
    .await;
}

async fn encrypted_enrollment_request_fixture(
    alter: impl FnOnce(&mut serde_json::Value),
) -> (
    Engine<SqliteAccountStorage>,
    cgka_traits::TransportMessage,
    u32,
) {
    encrypted_enrollment_request_fixture_with_storage(
        SqliteAccountStorage::in_memory().unwrap(),
        alter,
    )
    .await
}

#[tokio::test]
async fn private_enrollment_request_sql_fault_preserves_crypto_and_original_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-enrollment-request-fault.db");
    let key = SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (mut receiver, message, expected_index) =
        encrypted_enrollment_request_fixture_with_storage(storage.clone(), |_| {}).await;
    let cgka_traits::transport::TransportEnvelope::GroupMessage { transport_group_id } =
        &message.envelope
    else {
        panic!("expected actual encrypted group request")
    };
    let group = GroupId::new(transport_group_id.clone());
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    let before_crypto = crypto_digest(&injector);
    // The real normalized message codec maps Processed to2. Fail only a new
    // positive disposition; existing completed controls are untouched.
    injector.execute_batch("CREATE TRIGGER fail_request_terminal_update BEFORE UPDATE ON cgka_messages WHEN NEW.state=2 AND OLD.state<>2 BEGIN SELECT RAISE(ABORT,'isolated request SQL fault'); END; CREATE TRIGGER fail_request_terminal_insert BEFORE INSERT ON cgka_messages WHEN NEW.state=2 BEGIN SELECT RAISE(ABORT,'isolated request SQL fault'); END;").unwrap();
    receiver.drain_events();
    assert!(
        matches!(
            receiver
                .ingest_private_enrollment_delivery(message.clone())
                .await,
            Err(EngineError::Storage(_))
        ),
        "request transaction fault must retain typed SQL error"
    );
    assert!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty(),
        "failed SQL must not publish request metadata"
    );
    assert!(
        receiver
            .drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. })),
        "failed private request must not produce chat output"
    );
    assert_eq!(
        crypto_digest(&injector),
        before_crypto,
        "failed request disposition must restore actual MLS ratchets"
    );
    assert!(
        receiver
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
    injector
        .execute_batch(
            "DROP TRIGGER fail_request_terminal_update; DROP TRIGGER fail_request_terminal_insert;",
        )
        .unwrap();
    receiver
        .ingest_private_enrollment_delivery(message.clone())
        .await
        .unwrap();
    for _ in 0..16 {
        if receiver.advance_convergence_inputs(&group).await.unwrap() {
            break;
        }
    }
    let observations = receiver.drain_authenticated_enrollment_requests().unwrap();
    assert_eq!(
        observations.len(),
        1,
        "same original encrypted request must emit exactly one observation after SQL retry"
    );
    assert_eq!(observations[0].source_index(), expected_index);
    receiver
        .ingest_private_enrollment_delivery(message)
        .await
        .unwrap();
    assert!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn private_enrollment_request_rewrapped_ciphertext_never_renews_original_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-enrollment-request-fault.db");
    let key = SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (mut receiver, message, _expected_index) =
        encrypted_enrollment_request_fixture_with_storage(storage.clone(), |_| {}).await;
    let cgka_traits::transport::TransportEnvelope::GroupMessage { transport_group_id } =
        &message.envelope
    else {
        panic!("expected actual encrypted group request")
    };
    let group = GroupId::new(transport_group_id.clone());
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    let before_crypto = crypto_digest(&injector);
    // The real normalized message codec maps Processed to2. Fail only a new
    // positive disposition; existing completed controls are untouched.
    injector.execute_batch("CREATE TRIGGER fail_request_terminal_update BEFORE UPDATE ON cgka_messages WHEN NEW.state=2 AND OLD.state<>2 BEGIN SELECT RAISE(ABORT,'isolated request SQL fault'); END; CREATE TRIGGER fail_request_terminal_insert BEFORE INSERT ON cgka_messages WHEN NEW.state=2 BEGIN SELECT RAISE(ABORT,'isolated request SQL fault'); END;").unwrap();
    receiver.drain_events();
    assert!(
        matches!(
            receiver
                .ingest_private_enrollment_delivery(message.clone())
                .await,
            Err(EngineError::Storage(_))
        ),
        "request transaction fault must retain typed SQL error"
    );
    assert!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty(),
        "failed SQL must not publish request metadata"
    );
    assert!(
        receiver
            .drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. })),
        "failed private request must not produce chat output"
    );
    assert_eq!(
        crypto_digest(&injector),
        before_crypto,
        "failed request disposition must restore actual MLS ratchets"
    );
    assert!(
        receiver
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
    injector
        .execute_batch(
            "DROP TRIGGER fail_request_terminal_update; DROP TRIGGER fail_request_terminal_insert;",
        )
        .unwrap();
    receiver
        .enrollment_intake
        .expire_existing_delivery_for_test(&message.id);
    let mut rewrapped = message.clone();
    rewrapped.id = cgka_traits::MessageId::new(vec![23u8; 32]);
    assert!(rewrapped.id != message.id);
    receiver
        .ingest_private_enrollment_delivery(rewrapped)
        .await
        .unwrap();
    for _ in 0..16 {
        if receiver.advance_convergence_inputs(&group).await.unwrap() {
            break;
        }
    }
    assert!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty(),
        "a new wrapper of the same actual MLS request must not renew its original clock"
    );
    assert!(
        receiver
            .drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. }))
    );
}

#[tokio::test]
async fn private_enrollment_request_unpersisted_rewrap_preserves_earliest_bound_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-enrollment-request-fault.db");
    let key = SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (mut receiver, message, _expected_index) =
        encrypted_enrollment_request_fixture_with_storage(storage.clone(), |_| {}).await;
    let cgka_traits::transport::TransportEnvelope::GroupMessage { transport_group_id } =
        &message.envelope
    else {
        panic!("expected actual encrypted group request")
    };
    let group = GroupId::new(transport_group_id.clone());
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    let before_crypto = crypto_digest(&injector);
    // The real normalized message codec maps Processed to2. Fail only a new
    // positive disposition; existing completed controls are untouched.
    injector.execute_batch("CREATE TRIGGER fail_request_retention BEFORE INSERT ON cgka_messages BEGIN SELECT RAISE(ABORT,'isolated pre-retention request fault'); END;").unwrap();
    receiver.drain_events();
    assert!(
        matches!(
            receiver
                .ingest_private_enrollment_delivery(message.clone())
                .await,
            Err(EngineError::Storage(_))
        ),
        "request transaction fault must retain typed SQL error"
    );
    assert!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty(),
        "failed SQL must not publish request metadata"
    );
    assert!(
        receiver
            .drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. })),
        "failed private request must not produce chat output"
    );
    assert_eq!(
        crypto_digest(&injector),
        before_crypto,
        "failed request disposition must restore actual MLS ratchets"
    );
    assert!(
        receiver
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
    receiver
        .enrollment_intake
        .expire_existing_delivery_for_test(&message.id);
    let mut rewrapped = message.clone();
    rewrapped.id = cgka_traits::MessageId::new(vec![23u8; 32]);
    assert!(rewrapped.id != message.id);
    let (original_deadline, original_bound_content) = receiver
        .enrollment_intake
        .existing_delivery_deadline_for_test(&message.id)
        .unwrap();
    assert!(matches!(
        receiver
            .ingest_private_enrollment_delivery(rewrapped.clone())
            .await,
        Err(EngineError::Storage(_))
    ));
    let (alias_deadline, alias_bound_content) = receiver
        .enrollment_intake
        .existing_delivery_deadline_for_test(&rewrapped.id)
        .unwrap();
    assert!(
        original_bound_content.as_ref() == Some(&message.id),
        "original delivery must reach actual content binding before SQL fault"
    );
    assert!(
        alias_bound_content == original_bound_content,
        "rewrapped delivery must bind the same decrypted MLS content before SQL fault"
    );
    assert!(
        alias_deadline <= original_deadline,
        "same actual encrypted request must retain earliest original deadline before SQL retry"
    );
    injector
        .execute_batch("DROP TRIGGER fail_request_retention;")
        .unwrap();
    receiver
        .ingest_private_enrollment_delivery(rewrapped)
        .await
        .unwrap();
    for _ in 0..16 {
        if receiver.advance_convergence_inputs(&group).await.unwrap() {
            break;
        }
    }
    assert!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty(),
        "a new wrapper of the same actual MLS request must not renew its original clock"
    );
    assert!(
        receiver
            .drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. }))
    );
}

#[tokio::test]
async fn private_enrollment_request_ordinary_history_ingress_never_becomes_live_metadata() {
    let (mut receiver, message, _) = encrypted_enrollment_request_fixture(|_| {}).await;
    receiver.drain_events();
    receiver.ingest(message.clone()).await.unwrap();
    assert!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty(),
        "ordinary acquired history must not create live request metadata"
    );
    assert!(
        receiver
            .drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. })),
        "history request must remain private"
    );
    receiver
        .ingest_private_enrollment_delivery(message)
        .await
        .unwrap();
    assert!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty(),
        "already classified historical ciphertext must not acquire a new live observation"
    );
}

#[tokio::test]
async fn private_enrollment_request_encrypted_reopen_never_restores_live_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-enrollment-history-reopen.db");
    let key = SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (mut receiver, message, _) =
        encrypted_enrollment_request_fixture_with_storage(storage.clone(), |_| {}).await;
    receiver
        .ingest_private_enrollment_delivery(message.clone())
        .await
        .unwrap();
    // Leave the genuine observation queued, then close the original engine.
    // Protected completed lineage persists; the live observation must not.
    drop(receiver);
    drop(storage);
    let reopened_storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut reopened = crate::device_group_genesis::tests::current_test_engine(reopened_storage);
    reopened.hydrate_all_stored_groups().unwrap();
    assert!(
        reopened
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty(),
        "encrypted reopen must never restore a live observation from SQL"
    );
    reopened.drain_events();
    reopened.ingest(message.clone()).await.unwrap();
    reopened
        .ingest_private_enrollment_delivery(message)
        .await
        .unwrap();
    assert!(
        reopened
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty(),
        "processed request replay after reopen must never mint live observation"
    );
    assert!(
        reopened
            .drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. }))
    );
}

#[tokio::test]
async fn private_enrollment_request_acquisition_deadline_expired_before_ingest_stays_private() {
    let (mut receiver, message, _) = encrypted_enrollment_request_fixture(|_| {}).await;
    receiver.drain_events();
    receiver
        .ingest_private_enrollment_delivery_until(
            message,
            web_time::Instant::now() - std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert!(
        receiver
            .drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. }))
    );
    assert_eq!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .len(),
        0,
        "an already expired acquisition must emit no live metadata",
    );
}

#[tokio::test]
async fn private_enrollment_request_acquisition_deadline_remaining_time_bounds_observation() {
    let (mut receiver, message, expected_index) =
        encrypted_enrollment_request_fixture(|_| {}).await;
    receiver.drain_events();
    let original_deadline = web_time::Instant::now() + std::time::Duration::from_secs(30);
    receiver
        .ingest_private_enrollment_delivery_until(message, original_deadline)
        .await
        .unwrap();
    assert!(
        receiver
            .drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. }))
    );
    let metadata = receiver.drain_authenticated_enrollment_requests().unwrap();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].source_index(), expected_index);
    assert!(
        metadata[0].observed_deadline() <= original_deadline,
        "ingest must preserve the remaining original acquisition time",
    );
}

#[tokio::test]
async fn private_enrollment_request_acquisition_deadline_expired_retry_shortens_cached_aliases() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-enrollment-request-fault.db");
    let key = SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (mut receiver, message, _expected_index) =
        encrypted_enrollment_request_fixture_with_storage(storage.clone(), |_| {}).await;
    let cgka_traits::transport::TransportEnvelope::GroupMessage { transport_group_id } =
        &message.envelope
    else {
        panic!("expected actual encrypted group request")
    };
    let group = GroupId::new(transport_group_id.clone());
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    let before_crypto = crypto_digest(&injector);
    // The real normalized message codec maps Processed to2. Fail only a new
    // positive disposition; existing completed controls are untouched.
    injector.execute_batch("CREATE TRIGGER fail_request_retention BEFORE INSERT ON cgka_messages BEGIN SELECT RAISE(ABORT,'isolated pre-retention request fault'); END;").unwrap();
    receiver.drain_events();
    assert!(
        matches!(
            receiver
                .ingest_private_enrollment_delivery(message.clone())
                .await,
            Err(EngineError::Storage(_))
        ),
        "request transaction fault must retain typed SQL error"
    );
    assert!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty(),
        "failed SQL must not publish request metadata"
    );
    assert!(
        receiver
            .drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. })),
        "failed private request must not produce chat output"
    );
    assert_eq!(
        crypto_digest(&injector),
        before_crypto,
        "failed request disposition must restore actual MLS ratchets"
    );
    assert!(
        receiver
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
    let expired_deadline = web_time::Instant::now() - std::time::Duration::from_secs(1);
    assert!(matches!(
        receiver
            .ingest_private_enrollment_delivery_until(message.clone(), expired_deadline)
            .await,
        Err(EngineError::Storage(_))
    ));
    let (shortened, _) = receiver
        .enrollment_intake
        .existing_delivery_deadline_for_test(&message.id)
        .unwrap();
    assert!(
        shortened <= expired_deadline,
        "expired exact retry must shorten cached eligibility despite SQL failure"
    );
    let mut rewrapped = message.clone();
    rewrapped.id = cgka_traits::MessageId::new(vec![23u8; 32]);
    assert!(rewrapped.id != message.id);
    let (original_deadline, original_bound_content) = receiver
        .enrollment_intake
        .existing_delivery_deadline_for_test(&message.id)
        .unwrap();
    assert!(matches!(
        receiver
            .ingest_private_enrollment_delivery(rewrapped.clone())
            .await,
        Err(EngineError::Storage(_))
    ));
    let (alias_deadline, alias_bound_content) = receiver
        .enrollment_intake
        .existing_delivery_deadline_for_test(&rewrapped.id)
        .unwrap();
    assert!(
        original_bound_content.as_ref() == Some(&message.id),
        "original delivery must reach actual content binding before SQL fault"
    );
    assert!(
        alias_bound_content == original_bound_content,
        "rewrapped delivery must bind the same decrypted MLS content before SQL fault"
    );
    assert!(
        alias_deadline <= original_deadline,
        "same actual encrypted request must retain earliest original deadline before SQL retry"
    );
    injector
        .execute_batch("DROP TRIGGER fail_request_retention;")
        .unwrap();
    receiver
        .ingest_private_enrollment_delivery(rewrapped)
        .await
        .unwrap();
    for _ in 0..16 {
        if receiver.advance_convergence_inputs(&group).await.unwrap() {
            break;
        }
    }
    assert!(
        receiver
            .drain_authenticated_enrollment_requests()
            .unwrap()
            .is_empty(),
        "a new wrapper of the same actual MLS request must not renew its original clock"
    );
    assert!(
        receiver
            .drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. }))
    );
}

#[tokio::test]
async fn private_enrollment_endorsement_real_received_request_requires_every_current_leaf() {
    let (sender, receiver, group) = complete_pair(SqliteAccountStorage::in_memory().unwrap()).await;
    let artifact = sender
        .export_settled_device_predecessor(&group)
        .unwrap()
        .unwrap();
    let own_artifact = receiver
        .export_settled_device_predecessor(&group)
        .unwrap()
        .unwrap();
    assert_ne!(
        Sha256::digest(&artifact),
        Sha256::digest(&own_artifact),
        "different actual leaf signers must not be compared by export bytes"
    );
    let candidate = receiver
        .validated_settled_device_roster(&group)
        .unwrap()
        .unwrap()
        .candidate()
        .clone();
    let authenticated = receiver
        .validate_private_device_predecessor(
            &artifact,
            &candidate.account,
            &group,
            candidate.epoch,
            &candidate.leaves,
        )
        .unwrap();
    let mut recipient = crate::device_group_genesis::tests::current_test_engine(
        SqliteAccountStorage::in_memory().unwrap(),
    );
    let package = recipient.fresh_linking_key_package().await.unwrap();
    let metadata = crate::key_package::key_package_metadata(&package).unwrap();
    let reference = hex::decode(metadata.key_package_ref_hex).unwrap();
    let signer = hex::decode(metadata.signature_public_key_hex).unwrap();
    let artifact_digest: [u8; 32] = Sha256::digest(&artifact).into();
    let package_digest: [u8; 32] = Sha256::digest(package.bytes()).into();
    let context_digest = [10u8; 32];
    let (mut receiver, message, _) =
        encrypt_enrollment_request(&sender, receiver, group, |frame| {
            frame["artifact_digest"] = serde_json::json!(artifact_digest);
            frame["key_package_digest"] = serde_json::json!(package_digest);
            frame["key_package_reference"] = serde_json::json!(reference);
            frame["recipient"] = serde_json::json!(signer);
        })
        .await;
    receiver
        .ingest_private_enrollment_delivery(message)
        .await
        .unwrap();
    let requests = receiver.drain_authenticated_enrollment_requests().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "real encrypted source must reach the actual intake"
    );
    let request = &requests[0];
    let binding = request.binding_digest().unwrap();
    let endorsement =
        receiver.endorse_private_enrollment_request(request, &artifact, &package, &context_digest);
    assert!(
        endorsement.is_ok(),
        "explicit existing-leaf action must endorse the exact authenticated request under its fresh own predecessor"
    );
    let endorsement = endorsement.unwrap();
    assert!(
        receiver
            .authenticate_all_private_enrollment_endorsements(
                &authenticated,
                &binding,
                &[endorsement.wire().unwrap()],
            )
            .is_err(),
        "one of two real occupied leaves cannot authorize all-leaf enrollment"
    );
    assert!(
        receiver
            .drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. })),
        "endorsement metadata cannot become chat or join another device"
    );
}

struct EndorsementFixture {
    a: Engine<SqliteAccountStorage>,
    b: Engine<SqliteAccountStorage>,
    request: crate::private_enrollment_request::AuthenticatedEnrollmentRequest,
    artifact: Vec<u8>,
    package: cgka_traits::KeyPackage,
    authenticated: crate::private_enrollment_predecessor::AuthenticatedPrivatePredecessor,
}
async fn endorsement_fixture(lifetime: Option<Duration>) -> EndorsementFixture {
    endorsement_fixture_with_storage(lifetime, SqliteAccountStorage::in_memory().unwrap()).await
}
async fn endorsement_fixture_with_storage(
    lifetime: Option<Duration>,
    storage: SqliteAccountStorage,
) -> EndorsementFixture {
    let (a, b, group) = complete_pair(storage).await;
    let artifact = a
        .export_settled_device_predecessor(&group)
        .unwrap()
        .unwrap();
    let candidate = b
        .validated_settled_device_roster(&group)
        .unwrap()
        .unwrap()
        .candidate()
        .clone();
    let authenticated = b
        .validate_private_device_predecessor(
            &artifact,
            &candidate.account,
            &group,
            candidate.epoch,
            &candidate.leaves,
        )
        .unwrap();
    let mut c = crate::device_group_genesis::tests::current_test_engine(
        SqliteAccountStorage::in_memory().unwrap(),
    );
    let package = c.fresh_linking_key_package().await.unwrap();
    let metadata = crate::key_package::key_package_metadata(&package).unwrap();
    let reference = hex::decode(metadata.key_package_ref_hex).unwrap();
    let signer = hex::decode(metadata.signature_public_key_hex).unwrap();
    let artifact_digest: [u8; 32] = Sha256::digest(&artifact).into();
    let package_digest: [u8; 32] = Sha256::digest(package.bytes()).into();
    let (mut b, message, _) = encrypt_enrollment_request(&a, b, group, |frame| {
        frame["artifact_digest"] = serde_json::json!(artifact_digest);
        frame["key_package_digest"] = serde_json::json!(package_digest);
        frame["key_package_reference"] = serde_json::json!(reference);
        frame["recipient"] = serde_json::json!(signer);
    })
    .await;
    b.drain_events();
    if let Some(lifetime) = lifetime {
        b.ingest_private_enrollment_delivery_until(message, Instant::now() + lifetime)
            .await
            .unwrap();
    } else {
        b.ingest_private_enrollment_delivery(message).await.unwrap();
    }
    let mut requests = b.drain_authenticated_enrollment_requests().unwrap();
    assert_eq!(requests.len(), 1);
    EndorsementFixture {
        a,
        b,
        request: requests.pop().unwrap(),
        artifact,
        package,
        authenticated,
    }
}
#[tokio::test]
async fn private_enrollment_endorsement_all_real_leaf_signatures_and_negative_packets() {
    let f = endorsement_fixture(None).await;
    assert!(
        f.a.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .is_err(),
        "a different engine cannot adopt the original received selection"
    );
    // A did not receive B's opaque observation. This tests portable signatures,
    // not an A-owned approval or its original SDK continuation.
    let binding = f.request.binding_digest().unwrap();
    let a = crate::private_enrollment_endorsement::sign_public_packet_for_test(
        &f.a,
        &GroupId::new(f.request.group_id().to_vec()),
        binding,
    )
    .unwrap();
    let b =
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .unwrap();
    let binding = f.request.binding_digest().unwrap();
    let wires = [a.as_slice(), b.wire().unwrap()];
    let proof =
        f.b.authenticate_all_private_enrollment_endorsements(&f.authenticated, &binding, &wires)
            .unwrap();
    assert_eq!(proof.leaf_count(), 2);
    assert_eq!(proof.binding_digest(), &binding);
    assert_eq!(proof.artifact_digest(), f.authenticated.artifact_digest());
    assert!(
        f.b.authenticate_all_private_enrollment_endorsements(
            &f.authenticated,
            &binding,
            &wires[..1]
        )
        .is_err()
    );
    assert!(
        f.b.authenticate_all_private_enrollment_endorsements(
            &f.authenticated,
            &binding,
            &[wires[1], wires[1]]
        )
        .is_err()
    );
    assert!(
        f.b.authenticate_all_private_enrollment_endorsements(&f.authenticated, &[55; 32], &wires)
            .is_err()
    );
    let mut value: serde_json::Value = serde_json::from_slice(wires[0]).unwrap();
    let bit = value["signature"][0].as_u64().unwrap() ^ 1;
    value["signature"][0] = serde_json::json!(bit);
    let altered = serde_json::to_vec(&value).unwrap();
    assert!(
        f.b.authenticate_all_private_enrollment_endorsements(
            &f.authenticated,
            &binding,
            &[&altered, wires[1]]
        )
        .is_err()
    );
    let mut value: serde_json::Value = serde_json::from_slice(wires[0]).unwrap();
    value["permission"] = serde_json::json!(true);
    let altered = serde_json::to_vec(&value).unwrap();
    assert!(
        f.b.authenticate_all_private_enrollment_endorsements(
            &f.authenticated,
            &binding,
            &[&altered, wires[1]]
        )
        .is_err()
    );
}
#[tokio::test]
async fn private_enrollment_endorsement_invalid_binding_does_not_consume_explicit_action() {
    let mut f = endorsement_fixture(None).await;
    let mut artifact = f.artifact.clone();
    let last = artifact.len() - 1;
    artifact[last] ^= 1;
    assert!(
        f.b.endorse_private_enrollment_request(&f.request, &artifact, &f.package, &[10; 32])
            .is_err()
    );
    assert!(
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[11; 32])
            .is_err()
    );
    let mut other = crate::device_group_genesis::tests::current_test_engine(
        SqliteAccountStorage::in_memory().unwrap(),
    );
    let package = other.fresh_linking_key_package().await.unwrap();
    assert!(
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &package, &[10; 32])
            .is_err()
    );
    let valid =
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .unwrap();
    f.b.validate_owned_private_enrollment_endorsement(&valid)
        .unwrap();
    assert!(
        f.b.drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. }))
    );
}
#[tokio::test]
async fn private_enrollment_endorsement_owned_action_cannot_transfer_or_survive_cancel_reopen() {
    let f = endorsement_fixture(None).await;
    let approval =
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .unwrap();
    f.b.validate_owned_private_enrollment_endorsement(&approval)
        .unwrap();
    assert!(
        f.a.validate_owned_private_enrollment_endorsement(&approval)
            .is_err()
    );
    let mut reopened = crate::device_group_genesis::tests::current_test_engine(f.b.storage.clone());
    reopened.hydrate_all_stored_groups().unwrap();
    assert!(
        reopened
            .validate_owned_private_enrollment_endorsement(&approval)
            .is_err()
    );
    assert!(
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .is_err()
    );
    f.b.cancel_private_enrollment_endorsements().unwrap();
    assert!(approval.wire().is_err());
    assert!(
        f.b.validate_owned_private_enrollment_endorsement(&approval)
            .is_err()
    );
    let replacement =
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .unwrap();
    f.b.validate_owned_private_enrollment_endorsement(&replacement)
        .unwrap();
    drop(f.b);
    assert!(
        replacement.wire().is_err(),
        "engine teardown cannot leave a live continuation"
    );
}
#[tokio::test]
async fn private_enrollment_endorsement_original_received_deadline_cannot_be_renewed() {
    let f = endorsement_fixture(Some(Duration::from_secs(2))).await;
    let approval =
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .unwrap();
    let now = Instant::now();
    tokio::time::sleep(
        f.request.observed_deadline().saturating_duration_since(now) + Duration::from_millis(20),
    )
    .await;
    assert!(approval.wire().is_err());
    assert!(
        f.b.validate_owned_private_enrollment_endorsement(&approval)
            .is_err()
    );
    f.b.cancel_private_enrollment_endorsements().unwrap();
    assert!(
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .is_err()
    );
}
#[tokio::test]
async fn private_enrollment_endorsement_actual_changed_tree_denies_owned_handoff() {
    let mut f = endorsement_fixture(None).await;
    let approval =
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .unwrap();
    f.b.validate_owned_private_enrollment_endorsement(&approval)
        .unwrap();
    let SendResult::GroupEvolution { pending, .. } =
        f.b.do_send_self_update(f.authenticated.group_id().clone())
            .await
            .unwrap()
    else {
        panic!("expected actual private test epoch evolution");
    };
    f.b.confirm_published(pending).await.unwrap();
    assert!(
        f.b.validate_owned_private_enrollment_endorsement(&approval)
            .is_err()
    );
    assert!(
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .is_err()
    );
}
// Original-owner policy injection tests the Core boundary, never genuine SDK SAS.
struct LocalProposalPolicy {
    allow_add: bool,
    starts: Arc<std::sync::atomic::AtomicUsize>,
    consent: crate::private_device_invite::PrivateInviteConsent,
    artifact_digest: [u8; 32],
    deadline: Instant,
    live: Arc<std::sync::atomic::AtomicBool>,
}
struct LocalProposalLease {
    allow_add: bool,
    consent: crate::private_device_invite::PrivateInviteConsent,
    artifact_digest: [u8; 32],
    deadline: Instant,
    live: Arc<std::sync::atomic::AtomicBool>,
}
impl crate::private_device_invite::TrustedPrivateInvitePolicy for LocalProposalPolicy {
    fn begin_prepare(
        &self,
        _: &crate::private_device_invite::AuthenticatedPrivateInvite,
    ) -> Result<
        Box<dyn crate::private_device_invite::PrivateInviteLease>,
        cgka_traits::device_linking_key_package::LinkingWelcomeDenied,
    > {
        self.starts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Box::new(LocalProposalLease {
            allow_add: self.allow_add,
            consent: self.consent.clone(),
            artifact_digest: self.artifact_digest,
            deadline: self.deadline,
            live: self.live.clone(),
        }))
    }
}
impl crate::private_device_invite::PrivateInviteLease for LocalProposalLease {
    fn consent(&self) -> &crate::private_device_invite::PrivateInviteConsent {
        &self.consent
    }
    fn enrollment_proposal_metadata(
        &mut self,
    ) -> Result<
        crate::private_device_invite::PrivateEnrollmentProposalMetadata,
        cgka_traits::device_linking_key_package::LinkingWelcomeDenied,
    > {
        self.check_live_before_commit()?;
        Ok(
            crate::private_device_invite::PrivateEnrollmentProposalMetadata {
                context_json: "{}".into(),
                artifact_digest: self.artifact_digest,
                original_deadline: self.deadline,
            },
        )
    }
    fn check_staged(
        &mut self,
        _: &crate::private_device_invite::AuthenticatedPrivateAdd,
    ) -> Result<(), cgka_traits::device_linking_key_package::LinkingWelcomeDenied> {
        self.check_live_before_commit()
    }
    fn check_live_before_commit(
        &mut self,
    ) -> Result<(), cgka_traits::device_linking_key_package::LinkingWelcomeDenied> {
        use cgka_traits::device_linking_key_package::LinkingWelcomeDenied;
        if !self.live.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(LinkingWelcomeDenied::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(LinkingWelcomeDenied::Expired);
        }
        Ok(())
    }
    fn preparation_committed(
        &mut self,
        _: &cgka_traits::private_device_invite::PrivateInviteScope,
    ) {
        assert!(
            self.allow_add,
            "proposal metadata alone must never consume or stage an Add"
        );
    }
}

enum LocalProposalOwnerControl {
    Metadata,
    HandoffClocks,
    Retain,
    Reopen,
    Drop,
}
async fn exercise_local_enrollment_proposal(control: LocalProposalOwnerControl) {
    use cgka_traits::device_linking_key_package::PurposeAttemptScope;
    use std::sync::atomic::{AtomicBool, Ordering};
    let (mut a, mut b, group) = complete_pair(SqliteAccountStorage::in_memory().unwrap()).await;
    let artifact = a
        .export_settled_device_predecessor(&group)
        .unwrap()
        .unwrap();
    let before = a
        .validated_settled_device_roster(&group)
        .unwrap()
        .unwrap()
        .candidate()
        .clone();
    let origin = a
        .validated_settled_device_roster(&group)
        .unwrap()
        .unwrap()
        .origin()
        .clone();
    let mut c = crate::device_group_genesis::tests::current_test_engine(
        SqliteAccountStorage::in_memory().unwrap(),
    );
    let package = c.fresh_linking_key_package().await.unwrap();
    let expected = a.validate_private_invite_input(&group, &package).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let live = Arc::new(AtomicBool::new(true));
    let approver_generation = if matches!(control, LocalProposalOwnerControl::HandoffClocks) {
        // Core-only injected trusted policy fixture, never stock SDK verification.
        let account = a.self_id().as_slice().try_into().unwrap();
        let device = a.identity.signer.public().try_into().unwrap();
        let generation = a
            .storage
            .reserve_device_linking_attempt(&account, &device)
            .unwrap();
        let binding = storage_sqlite::DeviceLinkingBinding {
            generation,
            nonce: [11; 32],
            context_digest: [10; 32],
        };
        a.storage.bind_device_linking_context(&binding).unwrap();
        a.storage
            .bind_device_linking_flow(&binding, "isolated-core-enrollment-handoff")
            .unwrap();
        a.storage
            .finish_device_linking_attempt(
                generation,
                storage_sqlite::DeviceLinkingOutcome::PairingVerified,
            )
            .unwrap();
        generation
    } else {
        2
    };
    let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    a.install_trusted_private_invite_policy(Arc::new(LocalProposalPolicy {
        allow_add: matches!(control, LocalProposalOwnerControl::HandoffClocks),
        starts: starts.clone(),
        consent: crate::private_device_invite::PrivateInviteConsent {
            approver_scope: PurposeAttemptScope {
                account: a.self_id().as_slice().try_into().unwrap(),
                local_device: a.identity.signer.public().try_into().unwrap(),
                generation: approver_generation,
            },
            recipient_generation: 1,
            origin,
            nonce: [11; 32],
            context_digest: [10; 32],
        },
        artifact_digest: Sha256::digest(&artifact).into(),
        deadline,
        live: live.clone(),
    }));
    let result = a.prepare_private_enrollment_proposal(&group, package.clone());
    assert!(
        result.is_ok(),
        "original trusted lease must seal a local proposal before staging Add"
    );
    let mut proposal = result.unwrap();
    assert_eq!(proposal.original_deadline(), deadline);
    let binding = proposal.binding_digest().unwrap();
    let metadata_tags = vec![vec!["transport".into(), "public-key".into()]];
    if matches!(control, LocalProposalOwnerControl::Metadata) {
        assert!(
            a.set_owned_local_enrollment_metadata(&mut proposal, vec![vec!["x".repeat(2049)]])
                .is_err()
        );
        assert!(
            b.set_owned_local_enrollment_metadata(&mut proposal, metadata_tags.clone())
                .is_err()
        );
        a.set_owned_local_enrollment_metadata(&mut proposal, metadata_tags.clone())
            .unwrap();
        assert_eq!(proposal.binding_digest().unwrap(), binding);
        assert!(
            a.set_owned_local_enrollment_metadata(&mut proposal, vec![vec!["different".into()]])
                .is_err()
        );
    }
    assert!(
        b.wrap_private_enrollment_proposal(&mut proposal)
            .await
            .is_err(),
        "another Core cannot use the local owned continuation"
    );
    let first = a
        .wrap_private_enrollment_proposal(&mut proposal)
        .await
        .unwrap();
    let retry = a
        .wrap_private_enrollment_proposal(&mut proposal)
        .await
        .unwrap();
    if matches!(control, LocalProposalOwnerControl::Reopen) {
        let mut reopened =
            crate::device_group_genesis::tests::current_test_engine(a.storage.clone());
        reopened.hydrate_all_stored_groups().unwrap();
        reopened.install_trusted_private_invite_policy(
            a.private_invite_policy.as_ref().unwrap().clone(),
        );
        assert!(
            reopened
                .endorse_owned_local_enrollment_proposal(&mut proposal)
                .is_err()
        );
        assert!(
            reopened
                .wrap_private_enrollment_proposal(&mut proposal)
                .await
                .is_err(),
            "reopened Core sharing the same policy cannot use the original owned proposal"
        );
    }
    assert_eq!(first.id, retry.id);
    assert_eq!(
        first.payload, retry.payload,
        "retry must preserve the generated ciphertext"
    );
    assert!(
        a.validated_settled_device_roster(&group)
            .unwrap()
            .unwrap()
            .candidate()
            == &before
    );
    assert!(
        a.storage
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            .is_none_or(|row| row.phase
                == cgka_traits::private_device_invite::PrivateInvitePhase::Confirmed)
    );
    b.drain_events();
    b.ingest_private_enrollment_delivery_until(first, deadline)
        .await
        .unwrap();
    assert!(
        b.drain_authenticated_enrollment_requests_up_to(0)
            .unwrap()
            .is_empty(),
        "a full App owner must leave the original proof in Core"
    );
    let requests = b.drain_authenticated_enrollment_requests_up_to(1).unwrap();
    assert_eq!(
        requests.len(),
        1,
        "actual encrypted proposal must reach the private opaque inlet"
    );
    assert_eq!(requests[0].binding_digest().unwrap(), binding);
    if matches!(control, LocalProposalOwnerControl::Metadata) {
        assert_eq!(requests[0].metadata_tags(), metadata_tags);
        a.set_owned_local_enrollment_metadata(&mut proposal, metadata_tags.clone())
            .unwrap();
    }
    assert_eq!(
        requests[0].key_package_reference(),
        expected.key_package_reference
    );
    assert_eq!(
        requests[0].recipient(),
        &expected.recipient_signature_public_key
    );
    assert!(requests[0].observed_deadline() <= deadline);
    assert!(
        b.drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::MessageReceived { .. }))
    );
    if matches!(
        control,
        LocalProposalOwnerControl::Retain
            | LocalProposalOwnerControl::HandoffClocks
            | LocalProposalOwnerControl::Metadata
    ) {
        let mut b_owned = b
            .endorse_private_enrollment_request(&requests[0], &artifact, &package, &[10; 32])
            .unwrap();
        assert!(
            a.wrap_private_enrollment_endorsement(&mut b_owned)
                .await
                .is_err()
        );
        let b_message = b
            .wrap_private_enrollment_endorsement(&mut b_owned)
            .await
            .unwrap();
        let retry = b
            .wrap_private_enrollment_endorsement(&mut b_owned)
            .await
            .unwrap();
        assert_eq!(b_message.id, retry.id);
        assert_eq!(b_message.payload, retry.payload);
        let own_wire = a
            .endorse_owned_local_enrollment_proposal(&mut proposal)
            .unwrap();
        assert_eq!(
            own_wire,
            a.endorse_owned_local_enrollment_proposal(&mut proposal)
                .unwrap()
        );
        assert!(
            a.authenticate_owned_local_enrollment_endorsements(&mut proposal, &[])
                .is_err()
        );
        a.drain_events();
        a.ingest_private_enrollment_delivery_until(b_message, deadline)
            .await
            .unwrap();
        let received = a.drain_authenticated_enrollment_endorsements().unwrap();
        assert_eq!(
            received.len(),
            1,
            "B encrypted endorsement must be authenticated from actual MLS intake"
        );
        assert!(
            a.drain_authenticated_enrollment_requests()
                .unwrap()
                .is_empty()
        );
        assert!(
            a.drain_events()
                .iter()
                .all(|event| !matches!(event, GroupEvent::MessageReceived { .. }))
        );
        assert_eq!(
            a.authenticate_owned_local_enrollment_endorsement(&mut proposal, &received[0])
                .unwrap(),
            Some(received[0].source_index()),
            "single-receipt retention validates the actual occupied sender signature"
        );
        let complete = a
            .authenticate_owned_local_enrollment_endorsements(&mut proposal, &[&received[0]])
            .unwrap();
        assert_eq!(complete.leaf_count(), 2);
        assert_eq!(complete.binding_digest(), &binding);
        assert!(
            b.authenticate_owned_local_enrollment_endorsements(&mut proposal, &[&received[0]])
                .is_err()
        );
        if matches!(control, LocalProposalOwnerControl::HandoffClocks) {
            let mut received = received;
            let observed = Instant::now() + Duration::from_secs(2);
            received[0].deadline = observed; // Negative-only shortening of actual receipt provenance.
            let mut prepared = a
                .prepare_private_invite_from_owned_enrollment_proposal(
                    &mut proposal,
                    &[&received[0]],
                )
                .await
                .unwrap();
            assert_eq!(
                starts.load(Ordering::SeqCst),
                1,
                "handoff must never begin a replacement lease"
            );
            assert_eq!(prepared.enrollment_observation_deadline(), Some(observed));
            assert!(
                proposal.binding_digest().is_err(),
                "original producer no longer owns the transferred lease"
            );
            tokio::time::sleep(Duration::from_millis(2100)).await;
            assert!(live.load(Ordering::SeqCst));
            assert!(
                Instant::now() < deadline,
                "original lease clock must still be live"
            );
            assert!(
                prepared.check_live_permission().is_err(),
                "shorter B receipt clock must remain on Prepared"
            );
            let publisher = HandoffExpiryPublisher(std::sync::atomic::AtomicUsize::new(0));
            assert!(
                a.dispatch_prepared_private_device_invite(&mut prepared, &publisher)
                    .await
                    .is_err()
            );
            assert_eq!(
                publisher.0.load(Ordering::SeqCst),
                0,
                "expired approval must not invoke real dispatch"
            );
            assert!(
                a.storage
                    .private_device_invite_storage()
                    .unwrap()
                    .private_invite()
                    .unwrap()
                    .unwrap()
                    .phase
                    == cgka_traits::private_device_invite::PrivateInvitePhase::Retired
            );
            return;
        }
        let mut substituted: serde_json::Value = serde_json::from_slice(&received[0].wire).unwrap();
        substituted["binding_digest"] = serde_json::json!(([55u8; 32]));
        let mut altered = received;
        let original_wire = std::mem::replace(
            &mut altered[0].wire,
            serde_json::to_vec(&substituted).unwrap(),
        );
        assert!(
            a.authenticate_owned_local_enrollment_endorsements(&mut proposal, &[&altered[0]])
                .is_err()
        );
        assert_eq!(
            a.authenticate_owned_local_enrollment_endorsement(&mut proposal, &altered[0])
                .unwrap(),
            None,
            "a wrong-bound packet must not occupy a sibling collection slot"
        );
        altered[0].wire = original_wire;
        let received = altered;

        a.select_private_roster_settlement(&group).unwrap();
        b.select_private_roster_settlement(&group).unwrap();
        let SendResult::ApplicationMessage { msg: challenge, .. } =
            a.start_private_roster_settlement(&group).await.unwrap()
        else {
            panic!("real challenge expected");
        };
        b.ingest(challenge).await.unwrap();
        let SendResult::ApplicationMessage { msg: ack, .. } =
            b.prepare_private_roster_ack(&group).await.unwrap()
        else {
            panic!("real ACK expected");
        };
        a.ingest(ack).await.unwrap();
        assert_eq!(
            a.validated_settled_device_roster(&group)
                .unwrap()
                .unwrap()
                .candidate(),
            &before
        );
        assert!(
            a.authenticate_owned_local_enrollment_endorsements(&mut proposal, &[&received[0]])
                .is_err(),
            "same genuine tree under a new Completed generation must not restore collection"
        );
        assert!(
            a.authenticate_owned_local_enrollment_endorsement(&mut proposal, &received[0])
                .is_err(),
            "single-receipt validation cannot revive the old original SDK lease selection"
        );
        assert!(
            a.prepare_private_invite_from_owned_enrollment_proposal(&mut proposal, &[&received[0]])
                .await
                .is_err(),
            "same-tree new Completed generation must deny original Add handoff"
        );
        b.cancel_private_enrollment_endorsements().unwrap();
        assert!(
            b.wrap_private_enrollment_endorsement(&mut b_owned)
                .await
                .is_err()
        );
        live.store(false, Ordering::SeqCst);
        assert!(
            a.endorse_owned_local_enrollment_proposal(&mut proposal)
                .is_err()
        );
        assert!(
            a.authenticate_owned_local_enrollment_endorsements(&mut proposal, &[&received[0]])
                .is_err()
        );
    }
    if matches!(control, LocalProposalOwnerControl::Drop) {
        drop(a);
        assert!(
            proposal.binding_digest().is_err(),
            "Core teardown cannot leave the original owned proposal live"
        );
        return;
    }
    live.store(false, Ordering::SeqCst);
    assert!(
        a.wrap_private_enrollment_proposal(&mut proposal)
            .await
            .is_err(),
        "cached wire cannot restore a cancelled original owner"
    );
    assert!(proposal.binding_digest().is_err());
}

#[tokio::test]
async fn private_enrollment_local_proposal_real_encryption_preserves_original_owner_and_retry() {
    exercise_local_enrollment_proposal(LocalProposalOwnerControl::Retain).await;
}

#[tokio::test]
async fn private_enrollment_local_proposal_metadata_is_immutable_authenticated_and_not_authority() {
    exercise_local_enrollment_proposal(LocalProposalOwnerControl::Metadata).await;
}
#[tokio::test]
async fn private_enrollment_local_proposal_reopened_shared_policy_cannot_use_original_owner() {
    exercise_local_enrollment_proposal(LocalProposalOwnerControl::Reopen).await;
}

#[tokio::test]
async fn private_enrollment_local_proposal_core_teardown_cannot_preserve_original_owner() {
    exercise_local_enrollment_proposal(LocalProposalOwnerControl::Drop).await;
}

async fn exercise_endorsement_reselection(create_before: bool) {
    let mut f = endorsement_fixture(None).await;
    let group = GroupId::new(f.request.group_id().to_vec());
    let before =
        f.b.validated_settled_device_roster(&group)
            .unwrap()
            .unwrap()
            .candidate()
            .clone();
    let old_generation =
        f.b.storage
            .private_roster_settlement_storage()
            .unwrap()
            .read_round()
            .unwrap()
            .unwrap()
            .generation;
    let owned = create_before.then(|| {
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .unwrap()
    });
    f.a.select_private_roster_settlement(&group).unwrap();
    f.b.select_private_roster_settlement(&group).unwrap();
    let SendResult::ApplicationMessage { msg: challenge, .. } =
        f.a.start_private_roster_settlement(&group).await.unwrap()
    else {
        panic!("encrypted challenge expected");
    };
    f.b.ingest(challenge).await.unwrap();
    let SendResult::ApplicationMessage { msg: ack, .. } =
        f.b.prepare_private_roster_ack(&group).await.unwrap()
    else {
        panic!("encrypted ACK expected");
    };
    f.a.ingest(ack).await.unwrap();
    let current =
        f.b.validated_settled_device_roster(&group)
            .unwrap()
            .unwrap();
    assert!(current.candidate() == &before);
    let new_generation =
        f.b.storage
            .private_roster_settlement_storage()
            .unwrap()
            .read_round()
            .unwrap()
            .unwrap()
            .generation;
    assert!(new_generation > old_generation);
    if let Some(owned) = owned {
        assert!(
            f.b.validate_owned_private_enrollment_endorsement(&owned)
                .is_err(),
            "same tree cannot revive an original action"
        );
    } else {
        assert!(
            f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
                .is_err(),
            "an old received observation cannot be laundered into the replacement Completed generation"
        );
    }
}

#[tokio::test]
async fn private_enrollment_endorsement_same_tree_completed_reselection_denies_original_action() {
    exercise_endorsement_reselection(true).await;
}
#[tokio::test]
async fn private_enrollment_endorsement_reselection_denies_first_action_on_old_observation() {
    exercise_endorsement_reselection(false).await;
}

struct EndorsementWrapPeeler {
    mode: std::sync::atomic::AtomicUsize,
    invalidate: Option<SqliteAccountStorage>,
    calls: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}
#[async_trait::async_trait]
impl cgka_traits::peeler::TransportPeeler for EndorsementWrapPeeler {
    async fn peel_group_message(
        &self,
        msg: &cgka_traits::TransportMessage,
        ctx: &cgka_traits::group_context::GroupContextSnapshot,
    ) -> Result<cgka_traits::ingest::PeeledMessage, cgka_traits::PeelerError> {
        crate::device_group_genesis::tests::PassthroughPeeler
            .peel_group_message(msg, ctx)
            .await
    }
    async fn peel_welcome(
        &self,
        msg: &cgka_traits::TransportMessage,
    ) -> Result<cgka_traits::ingest::PeeledMessage, cgka_traits::PeelerError> {
        crate::device_group_genesis::tests::PassthroughPeeler
            .peel_welcome(msg)
            .await
    }
    async fn wrap_welcome(
        &self,
        payload: &cgka_traits::EncryptedPayload,
        recipient: &cgka_traits::MemberId,
    ) -> Result<cgka_traits::TransportMessage, cgka_traits::PeelerError> {
        crate::device_group_genesis::tests::PassthroughPeeler
            .wrap_welcome(payload, recipient)
            .await
    }
    async fn wrap_group_message(
        &self,
        payload: &cgka_traits::EncryptedPayload,
        ctx: &cgka_traits::group_context::GroupContextSnapshot,
    ) -> Result<cgka_traits::TransportMessage, cgka_traits::PeelerError> {
        self.calls.lock().unwrap().push(payload.ciphertext.clone());
        match self.mode.load(std::sync::atomic::Ordering::SeqCst) {
            1 => {
                self.mode.store(0, std::sync::atomic::Ordering::SeqCst);
                Err(cgka_traits::PeelerError::DecryptFailed)
            }
            2 => std::future::pending().await,
            3 => {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let store = self
                    .invalidate
                    .as_ref()
                    .unwrap()
                    .private_roster_settlement_storage()
                    .unwrap();
                let generation = store.read_round().unwrap().unwrap().generation;
                store.deny_round(generation).unwrap();
                crate::device_group_genesis::tests::PassthroughPeeler
                    .wrap_group_message(payload, ctx)
                    .await
            }
            _ => {
                crate::device_group_genesis::tests::PassthroughPeeler
                    .wrap_group_message(payload, ctx)
                    .await
            }
        }
    }
}
#[tokio::test]
async fn private_enrollment_endorsement_failed_wrap_reuses_ciphertext_and_stalled_cancel_wakes() {
    use std::sync::atomic::AtomicUsize;
    let mut f = endorsement_fixture(None).await;
    let mut owned =
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .unwrap();
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    f.b.peeler = Box::new(EndorsementWrapPeeler {
        mode: AtomicUsize::new(1),
        invalidate: None,
        calls: calls.clone(),
    });
    assert!(matches!(
        f.b.wrap_private_enrollment_endorsement(&mut owned).await,
        Err(EngineError::Peeler(_))
    ));
    let message =
        f.b.wrap_private_enrollment_endorsement(&mut owned)
            .await
            .unwrap();
    let retry =
        f.b.wrap_private_enrollment_endorsement(&mut owned)
            .await
            .unwrap();
    assert_eq!(message.id, retry.id);
    assert_eq!(calls.lock().unwrap().len(), 2);
    {
        let observed = calls.lock().unwrap();
        assert_eq!(observed[0], observed[1]);
    }
    let stale = owned.cancellation_handle();
    f.b.cancel_private_enrollment_endorsements().unwrap();
    let mut fresh =
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .unwrap();
    stale.cancel();
    f.b.validate_owned_private_enrollment_endorsement(&fresh)
        .unwrap();
    let cancel = fresh.cancellation_handle();
    f.b.peeler = Box::new(EndorsementWrapPeeler {
        mode: AtomicUsize::new(2),
        invalidate: None,
        calls: calls.clone(),
    });
    let operation = f.b.wrap_private_enrollment_endorsement(&mut fresh);
    let revocation = async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.cancel();
    };
    let (result, _) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(operation, revocation)
    })
    .await
    .expect("negative revocation must wake the stalled Core wrap");
    assert!(result.is_err());
    assert!(
        f.b.wrap_private_enrollment_endorsement(&mut fresh)
            .await
            .is_err()
    );
    assert_eq!(calls.lock().unwrap().len(), 3);
}
#[tokio::test]
async fn private_enrollment_endorsement_send_sql_fault_rolls_back_actual_ratchet() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-endorsement-send.db");
    let key = SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut f = endorsement_fixture_with_storage(None, storage).await;
    let mut owned =
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .unwrap();
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    let before = crypto_digest(&injector);
    injector.execute_batch("CREATE TRIGGER fail_endorsement_ratchet BEFORE INSERT ON openmls_values BEGIN SELECT RAISE(ABORT,'isolated endorsement ratchet fault'); END;").unwrap();
    assert!(
        f.b.wrap_private_enrollment_endorsement(&mut owned)
            .await
            .is_err()
    );
    assert_eq!(before, crypto_digest(&injector));
    injector
        .execute_batch("DROP TRIGGER fail_endorsement_ratchet")
        .unwrap();
    let message =
        f.b.wrap_private_enrollment_endorsement(&mut owned)
            .await
            .unwrap();
    assert_ne!(before, crypto_digest(&injector));
    f.a.ingest_private_enrollment_delivery(message)
        .await
        .unwrap();
    assert_eq!(
        f.a.drain_authenticated_enrollment_endorsements()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn private_enrollment_endorsement_malformed_and_wrong_kind_are_private_controls() {
    let sender = cgka_traits::MemberId::new(vec![1; 32]);
    for (kind, content) in [
        (38176, "{broken"),
        (
            1,
            "{\"protocol\":\"whitenoise.experimental.enrollment-endorsement.v1\"}",
        ),
        (
            1,
            "{\"protocol\":\"whitenoise.experimental.enrollment-request.v2\"}",
        ),
    ] {
        let payload = cgka_traits::app_event::MarmotAppEvent::new(
            hex::encode(sender.as_slice()),
            0,
            kind,
            vec![],
            content,
        )
        .encode()
        .unwrap();
        assert!(crate::private_enrollment_request::is_request_payload(
            &payload,
            Some(&sender)
        ));
    }
}

#[tokio::test]
async fn private_enrollment_endorsement_protected_selection_denial_during_await_refuses_handoff() {
    let mut f = endorsement_fixture(None).await;
    let mut owned =
        f.b.endorse_private_enrollment_request(&f.request, &f.artifact, &f.package, &[10; 32])
            .unwrap();
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    f.b.peeler = Box::new(EndorsementWrapPeeler {
        mode: std::sync::atomic::AtomicUsize::new(3),
        invalidate: Some(f.b.storage.clone()),
        calls: calls.clone(),
    });
    assert!(
        f.b.wrap_private_enrollment_endorsement(&mut owned)
            .await
            .is_err(),
        "a real negative protected-state write while wrapping must deny handing out transport"
    );
    assert!(
        f.b.wrap_private_enrollment_endorsement(&mut owned)
            .await
            .is_err()
    );
    assert_eq!(calls.lock().unwrap().len(), 1);
}

struct HandoffExpiryPublisher(std::sync::atomic::AtomicUsize);
#[async_trait::async_trait]
impl crate::private_device_invite::TrustedPrivateInvitePublisher for HandoffExpiryPublisher {
    async fn publish_commit(
        &self,
        _: &cgka_traits::TransportMessage,
    ) -> Result<(), cgka_traits::EngineError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}
#[tokio::test]
async fn private_enrollment_local_proposal_handoff_preserves_original_lease_and_shorter_receipt_clock()
 {
    exercise_local_enrollment_proposal(LocalProposalOwnerControl::HandoffClocks).await;
}

#[path = "private_enrollment_sharing_tests.rs"]
mod sharing_endorsement;

#[tokio::test]
async fn revoked_successor_retry_scope_refuses_terminal_mismatch_expiry_and_cancellation() {
    let (initiator, responder, group) =
        complete_pair(SqliteAccountStorage::in_memory().unwrap()).await;
    let mut round = responder
        .storage
        .private_roster_settlement_storage()
        .unwrap()
        .read_round()
        .unwrap()
        .unwrap();
    // Predicate-only negative scope model based on a real joined/settled tree.
    // These local copies are never installed in an Engine, written to SQL, or
    // used to grant a revoked original. Genuine Revoked ownership is proved by
    // the separate App confirmation-fault journey.
    round.anchor.origin = cgka_traits::private_device_invite::PrivateInviteOrigin::Revoked(7);
    round.phase = PrivateSettlementPhase::Pending;
    let mut admission = LiveSettlementAdmission {
        anchor: round.anchor.clone(),
        generation: round.generation,
        deadline: Instant::now() + Duration::from_secs(30),
        cancelled: AtomicBool::new(false),
        guard: None,
    };
    let matches =
        crate::device_leaf_revocation::transition::pending_revoked_successor_round_matches;
    assert!(matches(&admission, &round));
    for phase in [
        PrivateSettlementPhase::Denied,
        PrivateSettlementPhase::Completed,
    ] {
        let mut terminal = round.clone();
        terminal.phase = phase;
        assert!(!matches(&admission, &terminal));
    }
    let mut mismatched = round.clone();
    mismatched.generation += 1;
    assert!(!matches(&admission, &mismatched));
    mismatched = round.clone();
    mismatched.anchor.context_digest[0] ^= 1;
    assert!(!matches(&admission, &mismatched));
    admission.cancel();
    assert!(!matches(&admission, &round));
    admission.cancelled.store(false, Ordering::SeqCst);
    admission.deadline = Instant::now() - Duration::from_secs(1);
    assert!(!matches(&admission, &round));
    // Real durable completed facts and an invited owner's live metadata do not
    // manufacture the missing Revoked in-memory capability.
    assert!(
        initiator
            .device_revocation_storage_retry_groups()
            .unwrap()
            .is_empty()
    );
    assert!(
        responder
            .device_revocation_storage_retry_groups()
            .unwrap()
            .is_empty()
    );
    drop(initiator);
    drop(responder);
    let _ = group;
}

#[tokio::test]
async fn private_roster_settlement_fresh_read_rejects_foreign_mls_tree_deletion() {
    use openmls_traits::storage::StorageProvider as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-warm-roster.db");
    let key = SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (initiator, responder, group) = complete_pair(storage.clone()).await;
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
    // A real independently opened writer invalidates an previously read MLS tree.
    let foreign = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mls_group = openmls::group::GroupId::from_slice(group.as_slice());
    foreign.mls_storage().delete_tree(&mls_group).unwrap();
    assert!(
        !matches!(
            responder.validated_settled_device_roster(&group),
            Ok(Some(_))
        ),
        "a fresh read cannot conceal an authoritative foreign tree deletion"
    );
    assert!(
        initiator
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn private_roster_settlement_fresh_read_rechecks_foreign_confirmation_facts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-warm-facts.db");
    let key = SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (initiator, responder, group) = complete_pair(storage.clone()).await;
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
    let foreign = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &foreign,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    let removed = foreign
        .execute("DELETE FROM private_roster_settlement_facts", [])
        .unwrap();
    assert!(
        removed > 0,
        "the completed fixture must have actual authenticated leaf receipts"
    );
    assert!(
        matches!(
            responder.validated_settled_device_roster(&group),
            Err(EngineError::Storage(cgka_traits::storage::StorageError::Serialization(message)))
                if message == "invalid private settlement facts"
        ),
        "corrupt completed facts retain their exact typed storage error"
    );
    assert!(
        initiator
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn private_roster_settlement_fresh_read_rechecks_foreign_denial() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-warm-denial.db");
    let key = SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (initiator, responder, group) = complete_pair(storage.clone()).await;
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
    let generation = storage
        .private_roster_settlement_storage()
        .unwrap()
        .read_round()
        .unwrap()
        .unwrap()
        .generation;
    let foreign = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    foreign
        .private_roster_settlement_storage()
        .unwrap()
        .deny_round(generation)
        .unwrap();
    assert!(
        responder
            .validated_private_successor(&group)
            .unwrap()
            .is_some(),
        "the same protected successor remains valid after the actual round denial"
    );
    assert!(
        responder
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_none(),
        "a fresh read never revives a denied settlement"
    );
    assert!(
        initiator
            .validated_settled_device_roster(&group)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn private_roster_settlement_fresh_read_rechecks_foreign_generation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-fresh-generation.db");
    let key = SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (initiator, responder, group) = complete_pair(storage.clone()).await;
    let previous = responder.validated_settled_device_roster(&group).unwrap().unwrap();
    let round = storage.private_roster_settlement_storage().unwrap().read_round().unwrap().unwrap();
    let foreign = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let selected = foreign.private_roster_settlement_storage().unwrap().select_round(&round.anchor).unwrap();
    assert!(selected.generation > previous.settlement_generation());
    assert!(responder.validated_private_successor(&group).unwrap().is_some());
    assert!(responder.validated_settled_device_roster(&group).unwrap().is_none(), "a new pending generation cannot reuse previous completed facts");
    assert!(initiator.validated_settled_device_roster(&group).unwrap().is_some());
}

#[tokio::test]
async fn private_roster_settlement_fresh_read_rechecks_foreign_origin_denial() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-fresh-origin.db");
    let key = SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (initiator, responder, group) = complete_pair(storage.clone()).await;
    assert!(responder.validated_settled_device_roster(&group).unwrap().is_some());
    let foreign = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let anchors = foreign.accepted_device_group_anchor_storage().unwrap();
    let actual = anchors.accepted_anchor().unwrap().unwrap();
    anchors.deny_accepted_anchor(&actual.scope, &group).unwrap();
    assert!(responder.validated_private_successor(&group).unwrap().is_none());
    assert!(responder.validated_settled_device_roster(&group).unwrap().is_none(), "denied protected origin cannot reuse a previous completed observation");
    assert!(initiator.validated_settled_device_roster(&group).unwrap().is_some());
}

#[tokio::test]
async fn private_roster_settlement_loaded_facts_stay_inside_pinned_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("isolated-pinned-facts.db");
    let key = SqlCipherKey::new("18".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let (initiator, responder, group) = complete_pair(storage.clone()).await;
    let foreign = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    storage.with_read_snapshot(|_| -> Result<(), EngineError> {
        let first = responder.validated_settled_device_roster(&group)?.unwrap();
        foreign.private_roster_settlement_storage().unwrap().deny_round(first.settlement_generation())?;
        let pinned = responder.validated_settled_device_roster(&group)?.unwrap();
        assert_eq!(first.settlement_generation(), pinned.settlement_generation());
        assert!(first.candidate() == pinned.candidate(), "nested reads retain the actual pinned tree and facts");
        Ok(())
    }).unwrap();
    assert!(responder.validated_settled_device_roster(&group).unwrap().is_none(), "fresh call after the snapshot must observe the foreign denial");
    assert!(initiator.validated_settled_device_roster(&group).unwrap().is_some());
}
