//! Protected local creation provenance for an opt-in private experimental profile.
//! Evidence can support fresh consent; it is never enrollment or history permission.
mod recovery;

use crate::Engine;
use crate::device_group_snapshot::{CandidateDeviceGroupSnapshot, CandidateDeviceLeaf};
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::capabilities::Feature;
use cgka_traits::device_group_genesis::*;
use cgka_traits::engine::CreateGroupRequest;
use cgka_traits::error::EngineError;
use cgka_traits::group::{Group, ProtocolProfile};
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::{EpochId, GroupId};
use openmls::group::{MlsGroup, MlsGroupCreateConfig};
use openmls::prelude::{Extension, Extensions};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum GenesisFactoryError {
    #[error(transparent)]
    Genesis(#[from] GenesisError),
    #[error(transparent)]
    Anchor(#[from] cgka_traits::accepted_device_group_anchor::AnchorError),
    #[error(transparent)]
    Engine(#[from] EngineError),
}
impl From<cgka_traits::storage::StorageError> for GenesisFactoryError {
    fn from(error: cgka_traits::storage::StorageError) -> Self {
        Self::Engine(error.into())
    }
}
/// Fresh validated birth/current-tree evidence, not a transferable approval token.
pub struct PrivateDeviceGroupGenesisEvidence {
    selection: DeviceGroupGenesisSelection,
    current: CandidateDeviceGroupSnapshot,
}
impl PrivateDeviceGroupGenesisEvidence {
    pub fn scope(&self) -> &GenesisScope {
        &self.selection.fact.scope
    }
    pub fn birth(&self) -> &GenesisBirthDraft {
        &self.selection.fact.birth
    }
    pub fn current(&self) -> &CandidateDeviceGroupSnapshot {
        &self.current
    }
    pub fn group_id(&self) -> &GroupId {
        &self.current.group_id
    }
}
pub(crate) fn has_backend_capabilities<S: StorageProvider>(storage: &S) -> bool {
    storage.private_group_privacy_storage().is_some()
        && storage.device_group_genesis_storage().is_some()
        && storage.private_device_invite_storage().is_some()
        && storage.accepted_device_group_anchor_storage().is_some()
        && storage.accepted_welcome_storage().is_some()
        && storage.device_linking_key_package_storage().is_some()
        && storage.roster_ack_capture_storage().is_some()
}
pub(crate) fn has_private_component(group: &MlsGroup) -> Result<bool, EngineError> {
    Ok(
        crate::app_components::required_app_components_of_group(group)?
            .contains(PRIVATE_DEVICE_GROUP_COMPONENT_ID),
    )
}
pub(crate) fn exact_profile(group: &MlsGroup) -> Result<bool, EngineError> {
    Ok(has_private_component(group)?
        && crate::account_identity_proof::protocol_profile_of_group(group)?
            == ProtocolProfile::Current
        && crate::app_components::app_component_data_of_group(
            group,
            PRIVATE_DEVICE_GROUP_COMPONENT_ID,
        )
        .as_deref()
            == Some(PRIVATE_DEVICE_GROUP_PROFILE))
}

/// Denial from an actual adopted tree, in the same SQL unit. Probe trees never
/// reach this entry. Birth provenance is immutable; only active use is fenced.
pub(crate) fn deny_changed_birth_for_tree<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    group: &MlsGroup,
) -> Result<(), EngineError> {
    let Some(store) = storage.device_group_genesis_storage() else {
        return Ok(());
    };
    let map_error = |error| match error {
        GenesisError::Storage(error) => EngineError::Storage(error),
        _ => EngineError::Other("private genesis denial failed".into()),
    };
    let Some(selection) = store.genesis_selection().map_err(map_error)? else {
        return Ok(());
    };
    if selection.active_denied || selection.fact.birth.group_id != *group_id {
        return Ok(());
    }
    let birth = &selection.fact.birth;
    let digest: [u8; 32] = Sha256::digest(group.epoch_authenticator().as_slice()).into();
    if !group.is_active()
        || group.epoch().as_u64() != birth.epoch.0
        || digest != birth.epoch_authenticator_digest
        || !exact_profile(group)?
    {
        store
            .deny_genesis_selection(&selection.fact.scope, group_id)
            .map_err(map_error)?;
    }
    Ok(())
}

impl<S: StorageProvider> Engine<S> {
    pub fn create_private_device_group_genesis(
        &mut self,
    ) -> Result<PrivateDeviceGroupGenesisEvidence, GenesisFactoryError> {
        self.create_private_device_group_genesis_with_components(Vec::new())
    }
    /// Authenticate transport-neutral initial component bytes before protected
    /// birth capture. The factory owns its mandatory private profile; callers
    /// cannot override engine-owned/reserved state or invent runtime consent.
    pub fn create_private_device_group_genesis_with_components(
        &mut self,
        mut components: Vec<cgka_traits::app_components::AppComponentData>,
    ) -> Result<PrivateDeviceGroupGenesisEvidence, GenesisFactoryError> {
        use cgka_traits::app_components::{
            APP_COMPONENT_DATA_MAX_LEN, APP_OWNED_APP_COMPONENT_ID_START,
            PROTOCOL_OWNED_APP_COMPONENT_IDS,
        };
        if components.len() > 128
            || components.iter().any(|component| {
                component.component_id == PRIVATE_DEVICE_GROUP_COMPONENT_ID
                    || component.data.len() > APP_COMPONENT_DATA_MAX_LEN
                    || (component.component_id < APP_OWNED_APP_COMPONENT_ID_START
                        && !PROTOCOL_OWNED_APP_COMPONENT_IDS.contains(&component.component_id))
            })
        {
            return Err(GenesisError::InvalidFact.into());
        }
        for component in &components {
            crate::app_components::validate_app_component_update(component)?;
        }
        components.push(cgka_traits::app_components::AppComponentData {
            component_id: PRIVATE_DEVICE_GROUP_COMPONENT_ID,
            data: PRIVATE_DEVICE_GROUP_PROFILE.to_vec(),
        });
        if !has_backend_capabilities(&self.storage)
            || self.new_protocol_profile != ProtocolProfile::Current
        {
            return Err(GenesisError::Unsupported.into());
        }
        let account: [u8; 32] = self
            .identity
            .self_id()
            .as_slice()
            .try_into()
            .map_err(|_| GenesisError::InvalidFact)?;
        let local_device: [u8; 32] = self
            .identity
            .signer
            .public()
            .try_into()
            .map_err(|_| GenesisError::InvalidFact)?;
        let request = CreateGroupRequest {
            name: String::new(),
            description: String::new(),
            members: vec![],
            required_features: vec![Feature(PRIVATE_DEVICE_GROUP_FEATURE)],
            app_components: components,
            initial_admins: vec![],
        };
        let capabilities = self.creation_key_package_capabilities(&request)?;
        let mut required = capabilities.required;
        let mut self_supported = self.supported_app_components.clone();
        // Current identity proof is injected by leaf_extensions, matching the
        // ordinary creation capability check rather than caller advertisement.
        self_supported.insert(cgka_traits::app_components::ACCOUNT_IDENTITY_PROOF_COMPONENT_ID);
        let missing = required.app_components.missing_from(&self_supported);
        if !missing.is_empty() {
            return Err(GenesisError::InvalidFact.into());
        }

        for id in capabilities.mandatory_components.ids {
            required.app_components.insert(id);
        }
        let leaf_extensions = self
            .identity
            .leaf_extensions(&self.supported_app_components)?;
        let dictionary = crate::app_components::app_data_dictionary_extension_for_group(
            &required.app_components,
            &crate::app_components::InitialComponentState {
                name: String::new(),
                description: String::new(),
                admins: vec![crate::app_components::admin_pubkey_from_member_id(
                    self.identity.self_id(),
                )?],
                app_components: request.app_components,
                optional_app_components: Default::default(),
            },
        )?;
        let extensions = Extensions::from_vec(vec![
            Extension::RequiredCapabilities(
                crate::capabilities::extension_from_group_capabilities(&required),
            ),
            dictionary,
        ])
        .map_err(|_| EngineError::Backend("private genesis extensions rejected".into()))?;
        let config =
            MlsGroupCreateConfig::builder()
                .ciphersuite(self.ciphersuite)
                .capabilities(crate::capabilities::leaf_capabilities(
                    &self.registry,
                    self.ciphersuite,
                    ProtocolProfile::Current,
                ))
                .with_leaf_node_extensions(leaf_extensions)
                .map_err(|_| {
                    EngineError::Backend("private genesis leaf extensions rejected".into())
                })?
                .wire_format_policy(crate::wire_format::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .max_past_epochs(self.max_past_epochs)
                .with_group_context_extensions(extensions)
                .use_ratchet_tree_extension(true)
                .sender_ratchet_configuration(
                    crate::wire_format::default_sender_ratchet_configuration(),
                )
                .build();
        let (result, route) =
            self.storage
                .with_transaction(|storage| -> Result<_, GenesisFactoryError> {
                    if let Some(fact) = storage
                        .accepted_device_group_anchor_storage()
                        .ok_or(GenesisError::Unsupported)?
                        .accepted_anchor()?
                    {
                        if fact.scope.account != account || fact.scope.local_device != local_device
                        {
                            return Err(GenesisError::ScopeMismatch.into());
                        }
                        if !fact.denied {
                            return Err(GenesisError::SelectionBusy.into());
                        }
                    }
                    let provenance = storage
                        .device_group_genesis_storage()
                        .ok_or(GenesisError::Unsupported)?;
                    if provenance
                        .genesis_selection()?
                        .is_some_and(|row| !row.active_denied)
                    {
                        return Err(GenesisError::SelectionBusy.into());
                    }
                    let provider =
                        EngineOpenMlsProvider::<S>::new(&self.crypto, storage.mls_storage());
                    let group = MlsGroup::new(
                        &provider,
                        &self.identity.signer,
                        &config,
                        self.identity.credential_with_key.clone(),
                    )
                    .map_err(|_| EngineError::Backend("private genesis creation failed".into()))?;
                    crate::app_components::validate_current_profile_group_invariants(&group)?;
                    let id = GroupId::new(group.group_id().as_slice().to_vec());
                    let epoch = EpochId(group.epoch().as_u64());
                    let mut current = CandidateDeviceGroupSnapshot {
                        account: self.identity.self_id().clone(),
                        group_id: id.clone(),
                        epoch,
                        epoch_authenticator_digest: Sha256::digest(
                            group.epoch_authenticator().as_slice(),
                        )
                        .into(),
                        leaves: vec![CandidateDeviceLeaf {
                            leaf_index: group.own_leaf_index().u32(),
                            signature_public_key: self.identity.signer.public().to_vec(),
                        }],
                        roster_commitment: [0; 32],
                    };
                    current.roster_commitment = crate::device_group_snapshot::commitment(&current);
                    let birth = GenesisBirthDraft {
                        format_version: 1,
                        group_id: id.clone(),
                        epoch,
                        epoch_authenticator_digest: current.epoch_authenticator_digest,
                        leaves: vec![GenesisLeaf {
                            leaf_index: group.own_leaf_index().u32(),
                            account,
                            signature_public_key: local_device,
                        }],
                        roster_commitment: current.roster_commitment,
                    };
                    storage.put_group(&Group {
                        id: id.clone(),
                        name: String::new(),
                        description: String::new(),
                        epoch,
                        members: crate::group_lifecycle::marmot_members(&group),
                        required_capabilities: required.clone(),
                        protocol_profile: ProtocolProfile::Current,
                        removed: false,
                        unrecoverable: false,
                        disbanded: None,
                        join_epoch: epoch,
                        local_copy_install_epoch: epoch,
                        local_copy_welcome_created_at: None,
                    })?;
                    crate::capability_manager::cache_self_capabilities(
                        storage,
                        &id,
                        &group,
                        self.identity.self_id(),
                        self.ciphersuite,
                    )?;
                    let route = crate::app_components::transport_group_id_of_group(&group)?;
                    storage.put_transport_group_route(&route, &id, epoch)?;
                    storage
                        .private_group_privacy_storage()
                        .ok_or(GenesisError::Unsupported)?
                        .mark_private_group_for_chat_exclusion(&account, &local_device, &id)?;
                    let selection =
                        provenance.store_genesis_birth(&account, &local_device, &birth)?;
                    Ok((
                        PrivateDeviceGroupGenesisEvidence { selection, current },
                        route,
                    ))
                })?;
        self.epoch_manager
            .set_stable(result.group_id().clone(), result.current.epoch);
        self.transport_group_id_index
            .insert(route, result.group_id().clone());
        Ok(result)
    }
    pub fn validated_private_device_group_genesis(
        &self,
        group: &GroupId,
    ) -> Result<Option<PrivateDeviceGroupGenesisEvidence>, GenesisFactoryError> {
        if !has_backend_capabilities(&self.storage) {
            return Err(GenesisError::Unsupported.into());
        }
        self.storage.with_read_snapshot(|storage| {
            let Some(selection) = storage
                .device_group_genesis_storage()
                .ok_or(GenesisError::Unsupported)?
                .genesis_selection()?
            else {
                return Ok(None);
            };
            if selection.active_denied
                || selection.fact.birth.group_id != *group
                || selection.fact.scope.account.as_slice() != self.identity.self_id().as_slice()
                || selection.fact.scope.local_device.as_slice() != self.identity.signer.public()
            {
                return Ok(None);
            }
            let Some(current) = self.candidate_device_group_snapshot(group)? else {
                return Ok(None);
            };
            let birth = &selection.fact.birth;
            if current.epoch != birth.epoch
                || current.epoch_authenticator_digest != birth.epoch_authenticator_digest
                || current.roster_commitment != birth.roster_commitment
                || current.leaves.len() != 1
                || current.leaves[0].leaf_index != birth.leaves[0].leaf_index
                || current.leaves[0].signature_public_key != birth.leaves[0].signature_public_key
                || !self.with_mls_group(group, exact_profile)?
            {
                return Ok(None);
            }
            Ok(Some(PrivateDeviceGroupGenesisEvidence {
                selection,
                current,
            }))
        })
    }
    pub fn retire_private_device_group_genesis(
        &mut self,
        scope: &GenesisScope,
        group: &GroupId,
    ) -> Result<(), GenesisFactoryError> {
        self.storage
            .device_group_genesis_storage()
            .ok_or(GenesisError::Unsupported)?
            .deny_genesis_selection(scope, group)?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use cgka_traits::error::PeelerError;
    use cgka_traits::group_context::GroupContextSnapshot;
    use cgka_traits::ingest::{PeeledContent, PeeledMessage};
    use cgka_traits::peeler::TransportPeeler;
    use cgka_traits::transport::{
        EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
    };
    use cgka_traits::types::{MemberId, MessageId};
    use sha2::{Digest, Sha256};

    #[derive(Default)]
    pub(crate) struct PassthroughPeeler;

    fn hash_id(bytes: &[u8]) -> MessageId {
        MessageId::new(Sha256::digest(bytes).to_vec())
    }

    #[async_trait]
    impl TransportPeeler for PassthroughPeeler {
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
            Ok(PeeledMessage {
                id: msg.id.clone(),
                group_id: None,
                sender: None,
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
            _ctx: &GroupContextSnapshot,
        ) -> Result<TransportMessage, PeelerError> {
            Ok(TransportMessage {
                id: hash_id(&payload.ciphertext),
                payload: payload.ciphertext.clone(),
                timestamp: Timestamp(0),
                causal_deps: vec![],
                source: TransportSource("test".into()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: vec![],
                },
            })
        }
        async fn wrap_private_linking_welcome(
            &self,
            payload: &EncryptedPayload,
            context: &cgka_traits::peeler::PrivateLinkingWelcomeContext,
        ) -> Result<Vec<TransportMessage>, PeelerError> {
            Ok(vec![
                self.wrap_welcome(payload, &MemberId::new(context.account.to_vec()))
                    .await?,
            ])
        }
        async fn wrap_welcome(
            &self,
            payload: &EncryptedPayload,
            recipient: &MemberId,
        ) -> Result<TransportMessage, PeelerError> {
            Ok(TransportMessage {
                id: hash_id(&payload.ciphertext),
                payload: payload.ciphertext.clone(),
                timestamp: Timestamp(0),
                causal_deps: vec![],
                source: TransportSource("test".into()),
                envelope: TransportEnvelope::Welcome {
                    recipient: recipient.clone(),
                },
            })
        }
    }

    struct TestProofSigner(k256::schnorr::SigningKey);

    impl crate::account_identity_proof::AccountIdentityProofSigner for TestProofSigner {
        fn sign_account_identity_proof(
            &self,
            request: &crate::account_identity_proof::AccountIdentityProofRequest,
        ) -> Result<[u8; 64], String> {
            use k256::schnorr::signature::hazmat::PrehashSigner;
            let signature = self
                .0
                .sign_prehash(&request.proof_event_id()?)
                .map_err(|e| e.to_string())?;
            Ok(signature.to_bytes())
        }
    }

    /// Deterministic, spec-valid x-only secp256k1 signing key.
    fn signing_key() -> k256::schnorr::SigningKey {
        let mut counter = 0u64;
        loop {
            let mut material = [0u8; 32];
            let mut hasher = Sha256::new();
            hasher.update(b"cgka-engine-seen-id-unit-test");
            hasher.update(counter.to_be_bytes());
            material.copy_from_slice(&hasher.finalize());
            if let Ok(sk) = k256::schnorr::SigningKey::from_bytes(&material) {
                return sk;
            }
            counter += 1;
        }
    }

    pub(crate) fn current_test_engine(
        storage: storage_sqlite::SqliteAccountStorage,
    ) -> crate::Engine<storage_sqlite::SqliteAccountStorage> {
        current_test_engine_with_key(storage, signing_key())
    }
    pub(crate) fn current_test_engine_with_key(
        storage: storage_sqlite::SqliteAccountStorage,
        key: k256::schnorr::SigningKey,
    ) -> crate::Engine<storage_sqlite::SqliteAccountStorage> {
        crate::EngineBuilder::new(storage)
            .identity(key.verifying_key().to_bytes().to_vec())
            .account_identity_proof_signer(Arc::new(TestProofSigner(key)))
            .peeler(Box::new(PassthroughPeeler))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn private_birth_active_denial_survives_real_epoch_advance_and_rewind() {
        use cgka_traits::engine::{CgkaEngine, SendResult};
        use cgka_traits::storage::{MessageStorage, StorageProvider};
        let storage = storage_sqlite::SqliteAccountStorage::in_memory().unwrap();
        let key = signing_key();
        let mut engine = crate::EngineBuilder::new(storage.clone())
            .identity(key.verifying_key().to_bytes().to_vec())
            .account_identity_proof_signer(Arc::new(TestProofSigner(key)))
            .peeler(Box::new(PassthroughPeeler))
            .build()
            .unwrap();
        let genesis = engine.create_private_device_group_genesis().unwrap();
        let group = genesis.group_id().clone();
        let original_birth = genesis.birth().clone();
        storage
            .create_group_snapshot(&group, "genesis-original-crypto")
            .unwrap();
        // Exercise the actual internal evolution/publish seam. Generic callers
        // remain denied; this simulates an unexpected internal adopted change.
        let SendResult::GroupEvolution { pending, .. } =
            engine.do_send_self_update(group.clone()).await.unwrap()
        else {
            panic!("real update");
        };
        engine.confirm_published(pending).await.unwrap();
        assert!(
            engine
                .validated_private_device_group_genesis(&group)
                .unwrap()
                .is_none()
        );
        storage
            .rollback_group_to_snapshot(&group, "genesis-original-crypto")
            .unwrap();
        storage
            .release_group_snapshot(&group, "genesis-original-crypto")
            .unwrap();
        drop(engine);
        let key = signing_key();
        let mut engine = crate::EngineBuilder::new(storage.clone())
            .identity(key.verifying_key().to_bytes().to_vec())
            .account_identity_proof_signer(Arc::new(TestProofSigner(key)))
            .peeler(Box::new(PassthroughPeeler))
            .build()
            .unwrap();
        engine.hydrate_stable_groups_from_storage().unwrap();
        engine.ensure_hydrated(&group).unwrap();
        assert!(
            engine
                .validated_private_device_group_genesis(&group)
                .unwrap()
                .is_none(),
            "A-to-B-to-A must never revive birth-active lineage"
        );
        let row = storage
            .device_group_genesis_storage()
            .unwrap()
            .genesis_selection()
            .unwrap()
            .unwrap();
        assert!(row.active_denied && row.fact.birth == original_birth);
    }
}

#[cfg(test)]
mod transport_component_tests {
    use super::*;
    use cgka_traits::app_components::{
        AppComponentData, GROUP_PROFILE_COMPONENT_ID, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1,
        encode_nostr_routing_v1,
    };
    use cgka_traits::storage::GroupStorage;
    #[test]
    fn private_genesis_authenticates_caller_route_before_birth_and_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("isolated-private-genesis-route.db");
        let key = storage_sqlite::SqlCipherKey::new("91".repeat(32)).unwrap();
        let mut engine = tests::current_test_engine(
            storage_sqlite::SqliteAccountStorage::open_encrypted(&path, &key).unwrap(),
        );
        engine
            .supported_app_components
            .insert(NOSTR_ROUTING_COMPONENT_ID);
        let routing = NostrRoutingV1::new([73; 32], vec!["wss://isolated.example".into()]).unwrap();
        let component = AppComponentData {
            component_id: NOSTR_ROUTING_COMPONENT_ID,
            data: encode_nostr_routing_v1(&routing).unwrap(),
        };
        for components in [
            vec![component.clone(), component.clone()],
            vec![AppComponentData {
                component_id: PRIVATE_DEVICE_GROUP_COMPONENT_ID,
                data: PRIVATE_DEVICE_GROUP_PROFILE.to_vec(),
            }],
            vec![AppComponentData {
                component_id: GROUP_PROFILE_COMPONENT_ID,
                data: vec![],
            }],
            vec![AppComponentData {
                component_id: 0x0123,
                data: vec![],
            }],
            vec![AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: vec![0; 32],
            }],
            vec![AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: vec![0; 4097],
            }],
        ] {
            assert!(
                engine
                    .create_private_device_group_genesis_with_components(components)
                    .is_err()
            );
            assert!(
                engine
                    .storage
                    .device_group_genesis_storage()
                    .unwrap()
                    .genesis_selection()
                    .unwrap()
                    .is_none()
            );
        }
        let injector = rusqlite::Connection::open(&path).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &injector,
            &key,
            storage_sqlite::SqlCipherHardening::default(),
        )
        .unwrap();
        injector.execute_batch("CREATE TRIGGER fail_private_origin_route BEFORE INSERT ON cgka_transport_group_routes BEGIN SELECT RAISE(ABORT,'isolated route write fault'); END;").unwrap();
        assert!(matches!(
            engine.create_private_device_group_genesis_with_components(vec![component.clone()]),
            Err(GenesisFactoryError::Engine(EngineError::Storage(_)))
        ));
        assert!(
            engine
                .storage
                .device_group_genesis_storage()
                .unwrap()
                .genesis_selection()
                .unwrap()
                .is_none()
        );
        assert!(engine.storage.list_groups().unwrap().is_empty());
        injector
            .execute_batch("DROP TRIGGER fail_private_origin_route")
            .unwrap();
        let origin = engine
            .create_private_device_group_genesis_with_components(vec![component])
            .unwrap();
        let id = origin.group_id().clone();
        assert!(
            engine
                .with_mls_group(&id, |group| {
                    assert!(
                        crate::app_components::nostr_routing_of_group(group)?.as_ref()
                            == Some(&routing)
                    );
                    assert!(
                        crate::app_components::transport_group_id_of_group(group)?
                            == routing.nostr_group_id
                    );
                    assert!(exact_profile(group)?);
                    Ok(())
                })
                .is_ok()
        );
        let birth = origin.birth().clone();
        drop(engine);
        let mut reopened = tests::current_test_engine(
            storage_sqlite::SqliteAccountStorage::open_encrypted(&path, &key).unwrap(),
        );
        reopened.hydrate_stable_groups_from_storage().unwrap();
        reopened.ensure_hydrated(&id).unwrap();
        assert!(
            reopened
                .storage
                .list_transport_group_routes()
                .unwrap()
                .iter()
                .any(|route| route.transport_group_id == routing.nostr_group_id
                    && route.group_id == id)
        );
        assert!(
            reopened
                .validated_private_device_group_genesis(&id)
                .unwrap()
                .unwrap()
                .birth()
                == &birth
        );
        assert!(
            reopened
                .with_mls_group(&id, |group| Ok(
                    crate::app_components::nostr_routing_of_group(group)?.as_ref()
                        == Some(&routing)
                ))
                .unwrap()
        );
    }
}
