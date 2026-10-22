//! Default-off trusted private Add preparation. Metadata alone never grants consent.
//! Exact raw/final bytes remain in the dedicated ledger, outside ordinary replay.
use crate::Engine;
use crate::device_group_snapshot::CandidateDeviceGroupSnapshot;
use cgka_traits::engine::KeyPackage;
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::{GroupId, MemberId};

/// Actual read-only cryptographic input metadata, never consent or permission.
/// The eventual trusted preparation path must derive this again inside its SQL unit.
pub struct AuthenticatedPrivateInvite {
    pub predecessor: CandidateDeviceGroupSnapshot,
    pub own_leaf_index: u32,
    pub exact_key_package: KeyPackage,
    pub key_package_reference: [u8; 32],
    pub recipient_account: MemberId,
    pub recipient_signature_public_key: [u8; 32],
}

/// Validated actual staged successor metadata, never publication permission.
pub struct AuthenticatedPrivateAdd {
    pub successor: cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster,
    pub recipient_leaf_index: u32,
}

impl<S: StorageProvider> Engine<S> {
    /// Inspect a real staged commit without merging it or mutating the engine.
    /// The eventual owned SDK lease must independently authorize the preparation.
    pub fn validate_private_staged_add(
        &self,
        group: &openmls::group::MlsGroup,
        staged: &openmls::group::StagedCommit,
        input: &AuthenticatedPrivateInvite,
    ) -> Result<AuthenticatedPrivateAdd, EngineError> {
        let package = self.parse_key_package(&input.exact_key_package)?;
        self.validate_private_staged_add_package(group, staged, input, &package)
    }

    /// The package here comes only from the retained authenticated staged Add.
    /// Reconciliation does not republish a KP or renew its admission lifetime.
    fn validate_private_staged_add_package(
        &self,
        group: &openmls::group::MlsGroup,
        staged: &openmls::group::StagedCommit,
        input: &AuthenticatedPrivateInvite,
        package: &openmls::prelude::KeyPackage,
    ) -> Result<AuthenticatedPrivateAdd, EngineError> {
        use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
        use cgka_traits::device_group_genesis::GenesisLeaf;
        use cgka_traits::types::EpochId;
        use openmls::prelude::Proposal;
        use openmls::treesync::Node;
        use sha2::{Digest, Sha256};
        use std::collections::BTreeSet;
        let invalid = || EngineError::Other("incompatible private staged Add".into());
        if !group.is_active()
            || !crate::device_group_genesis::exact_profile(group)?
            || input.predecessor.group_id.as_slice() != group.group_id().as_slice()
            || input.predecessor.account != *self.identity.self_id()
            || input.predecessor.epoch.0 != group.epoch().as_u64()
            || input.predecessor.epoch_authenticator_digest
                != <[u8; 32]>::from(Sha256::digest(group.epoch_authenticator().as_slice()))
            || input.own_leaf_index != group.own_leaf_index().u32()
            || staged.group_context().group_id() != group.group_id()
            || staged.epoch().as_u64()
                != group.epoch().as_u64().checked_add(1).ok_or_else(invalid)?
            || staged.group_context().extensions() != group.extensions()
            || staged.group_context().ciphersuite() != group.ciphersuite()
            || input.exact_key_package.bytes().is_empty()
            || input.exact_key_package.bytes().len() > 16 * 1024
        {
            return Err(invalid());
        }
        let mut actual_predecessor = Vec::new();
        for member in group.members() {
            if crate::identity::validated_member_id(&member.credential)?
                != input.predecessor.account
            {
                return Err(invalid());
            }
            actual_predecessor.push(crate::device_group_snapshot::CandidateDeviceLeaf {
                leaf_index: member.index.u32(),
                signature_public_key: member.signature_key,
            });
        }
        actual_predecessor.sort_unstable_by_key(|leaf| leaf.leaf_index);
        if actual_predecessor != input.predecessor.leaves
            || !(1..128).contains(&actual_predecessor.len())
            || !actual_predecessor.iter().any(|leaf| {
                leaf.leaf_index == group.own_leaf_index().u32()
                    && leaf.signature_public_key == self.identity.signer.public()
            })
        {
            return Err(invalid());
        }
        let reference = package.hash_ref(&self.crypto).map_err(|_| invalid())?;
        if package.last_resort()
            || package.ciphersuite() != group.ciphersuite()
            || reference.as_slice() != input.key_package_reference
            || crate::identity::validated_member_id_of_leaf(package.leaf_node())?
                != input.recipient_account
            || input.recipient_account != input.predecessor.account
            || package.leaf_node().signature_key().as_slice()
                != input.recipient_signature_public_key
            || actual_predecessor
                .iter()
                .any(|leaf| leaf.signature_public_key == input.recipient_signature_public_key)
        {
            return Err(invalid());
        }
        let mut proposals = staged.queued_proposals();
        match proposals.next().map(|queued| queued.proposal()) {
            Some(Proposal::Add(add)) if add.key_package() == package => {}
            _ => return Err(invalid()),
        }
        if proposals.next().is_some() {
            return Err(invalid());
        }
        crate::account_identity_proof::validate_staged_commit_account_identity_proofs(
            staged,
            group,
            self.identity.self_id(),
            group.ciphersuite(),
        )?;
        crate::app_components::validate_current_profile_invariants_for_staged_commit(
            group,
            staged,
            group.own_leaf_index(),
        )?;
        let tree = staged
            .export_ratchet_tree(&self.crypto, group.export_ratchet_tree())
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        let mut leaves = Vec::new();
        let mut signers = BTreeSet::new();
        for (index, node) in crate::app_components::ratchet_tree_nodes(tree)?
            .into_iter()
            .enumerate()
        {
            let Some(Node::LeafNode(leaf)) = node else {
                continue;
            };
            let account = crate::identity::validated_member_id_of_leaf(&leaf)?;
            let signature_public_key: [u8; 32] = leaf
                .signature_key()
                .as_slice()
                .try_into()
                .map_err(|_| invalid())?;
            if index % 2 != 0
                || leaves.len() == 128
                || account != input.predecessor.account
                || !signers.insert(signature_public_key)
            {
                return Err(invalid());
            }
            leaves.push(GenesisLeaf {
                account: account.as_slice().try_into().map_err(|_| invalid())?,
                leaf_index: u32::try_from(index / 2).map_err(|_| invalid())?,
                signature_public_key,
            });
        }
        if leaves.len() != actual_predecessor.len() + 1
            || actual_predecessor.iter().any(|prior| {
                !leaves.iter().any(|leaf| {
                    leaf.leaf_index == prior.leaf_index
                        && leaf.signature_public_key.as_slice() == prior.signature_public_key
                })
            })
        {
            return Err(invalid());
        }
        let recipient_leaf_index = leaves
            .iter()
            .find(|leaf| leaf.signature_public_key == input.recipient_signature_public_key)
            .ok_or_else(invalid)?
            .leaf_index;
        let digest =
            Sha256::digest(staged.epoch_authenticator().ok_or_else(invalid)?.as_slice()).into();
        Ok(AuthenticatedPrivateAdd {
            successor: DeviceGroupAnchorRoster {
                epoch: EpochId(staged.epoch().as_u64()),
                epoch_authenticator_digest: digest,
                leaves,
            },
            recipient_leaf_index,
        })
    }

    /// Validate one exact, signed, single-use package against a stable private tree.
    /// Does not stage an Add, alter private bundles, or authorize enrollment.
    pub fn validate_private_invite_input(
        &self,
        group_id: &GroupId,
        package: &KeyPackage,
    ) -> Result<AuthenticatedPrivateInvite, EngineError> {
        let invalid = || EngineError::Other("incompatible private invitation input".into());
        if package.bytes().is_empty() || package.bytes().len() > 16 * 1024 {
            return Err(invalid());
        }
        let parsed = self.parse_key_package(package)?;
        if parsed.last_resort() {
            return Err(invalid());
        }
        self.storage.with_read_snapshot(|_| {
            let predecessor = self
                .candidate_device_group_snapshot(group_id)?
                .ok_or_else(invalid)?;
            if predecessor.leaves.len() >= 128 || predecessor.epoch.0 == u64::MAX {
                return Err(invalid());
            }
            self.invite_key_package_requirements(group_id)?
                .validate(package)?;
            let recipient_account =
                crate::identity::validated_member_id_of_leaf(parsed.leaf_node())?;
            let recipient_signature_public_key: [u8; 32] = parsed
                .leaf_node()
                .signature_key()
                .as_slice()
                .try_into()
                .map_err(|_| invalid())?;
            if recipient_account != predecessor.account
                || predecessor
                    .leaves
                    .iter()
                    .any(|leaf| leaf.signature_public_key == recipient_signature_public_key)
            {
                return Err(invalid());
            }
            let own_leaf_index = self.with_mls_group(group_id, |group| {
                if !crate::device_group_genesis::exact_profile(group)? {
                    return Err(invalid());
                }
                Ok(group.own_leaf_index().u32())
            })?;
            let reference = parsed
                .hash_ref(&self.crypto)
                .map_err(|_| EngineError::Other("private KeyPackage reference failed".into()))?;
            let key_package_reference = reference.as_slice().try_into().map_err(|_| invalid())?;
            Ok(AuthenticatedPrivateInvite {
                predecessor,
                own_leaf_index,
                exact_key_package: package.clone(),
                key_package_reference,
                recipient_account,
                recipient_signature_public_key,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::device_group_genesis::tests::{current_test_engine, current_test_engine_with_key};
    use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, KeyPackage};
    use cgka_traits::group::ProtocolProfile;
    use storage_sqlite::SqliteAccountStorage;

    #[tokio::test]
    async fn private_invite_input_returns_real_predecessor_and_exact_validated_single_use_key_package()
     {
        let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
        let origin = approver.create_private_device_group_genesis().unwrap();
        let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
        let kp = recipient.fresh_linking_key_package().await.unwrap();
        let metadata = crate::key_package::key_package_metadata(&kp).unwrap();
        let input = approver
            .validate_private_invite_input(origin.group_id(), &kp)
            .unwrap();
        assert!(input.predecessor == *origin.current());
        assert_eq!(input.own_leaf_index, 0);
        assert!(input.exact_key_package == kp);
        assert!(
            input.key_package_reference.as_slice()
                == hex::decode(metadata.key_package_ref_hex).unwrap()
        );
        assert!(input.recipient_account == recipient.self_id());
        assert!(
            input.recipient_signature_public_key.as_slice()
                == hex::decode(metadata.signature_public_key_hex).unwrap()
        );
        assert!(input.recipient_signature_public_key != origin.scope().local_device);
        assert!(
            recipient
                .durably_owned_key_packages()
                .unwrap()
                .contains(&kp)
        );
    }

    #[tokio::test]
    async fn private_invite_input_rejects_genuine_incompatible_packages_without_tree_or_origin_change()
     {
        let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
        let origin = approver.create_private_device_group_genesis().unwrap();
        let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
        let exact = recipient.fresh_linking_key_package().await.unwrap();
        let public = recipient.fresh_key_package().await.unwrap();
        let own_new_reference = approver.fresh_linking_key_package().await.unwrap();
        let mut foreign = current_test_engine_with_key(
            SqliteAccountStorage::in_memory().unwrap(),
            k256::schnorr::SigningKey::from_bytes(&[19; 32]).unwrap(),
        );
        let foreign_kp = foreign.fresh_linking_key_package().await.unwrap();
        recipient
            .supported_app_components
            .ids
            .remove(&cgka_traits::device_group_genesis::PRIVATE_DEVICE_GROUP_COMPONENT_ID);
        let old_client_kp = recipient.fresh_linking_key_package().await.unwrap();
        let mut tampered = exact.bytes().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let tampered = KeyPackage::new(tampered).with_protocol_profile(ProtocolProfile::Current);
        let excessive =
            KeyPackage::new(vec![0; 16 * 1024 + 1]).with_protocol_profile(ProtocolProfile::Current);
        for invalid in [
            public,
            own_new_reference,
            foreign_kp,
            old_client_kp,
            tampered,
            excessive,
        ] {
            assert!(
                approver
                    .validate_private_invite_input(origin.group_id(), &invalid)
                    .is_err()
            );
        }
        let current = approver
            .validated_private_device_group_genesis(origin.group_id())
            .unwrap()
            .unwrap();
        assert!(current.current() == origin.current());
        assert!(
            recipient
                .durably_owned_key_packages()
                .unwrap()
                .contains(&exact)
        );
        let (ordinary, _) = approver
            .create_group(CreateGroupRequest {
                name: String::new(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        assert!(
            approver
                .validate_private_invite_input(&ordinary, &exact)
                .is_err()
        );
    }
    #[tokio::test]
    async fn private_staged_add_ignores_queued_unapproved_add_and_returns_actual_successor() {
        use cgka_traits::storage::StorageProvider;
        use openmls::group::MlsGroup;
        use openmls_traits::OpenMlsProvider;
        let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
        let origin = approver.create_private_device_group_genesis().unwrap();
        let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
        let exact = recipient.fresh_linking_key_package().await.unwrap();
        let input = approver
            .validate_private_invite_input(origin.group_id(), &exact)
            .unwrap();
        let mut unwanted = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
        let extra = unwanted.fresh_linking_key_package().await.unwrap();
        let provider = crate::provider::EngineOpenMlsProvider::<SqliteAccountStorage>::new(
            &approver.crypto,
            approver.storage.mls_storage(),
        );
        let mut group = MlsGroup::load(
            provider.storage(),
            &openmls::group::GroupId::from_slice(origin.group_id().as_slice()),
        )
        .unwrap()
        .unwrap();
        group
            .propose_add_member(
                &provider,
                &approver.identity.signer,
                &approver.parse_key_package(&extra).unwrap(),
            )
            .unwrap();
        assert_eq!(group.pending_proposals().count(), 1);
        let _bundle = group
            .commit_builder()
            .consume_proposal_store(false)
            .propose_adds([approver.parse_key_package(&exact).unwrap()])
            .load_psks(provider.storage())
            .unwrap()
            .build(
                provider.rand(),
                provider.crypto(),
                &approver.identity.signer,
                |_| true,
            )
            .unwrap()
            .stage_commit(&provider)
            .unwrap();
        let staged = group.pending_commit().unwrap();
        assert_eq!(staged.queued_proposals().count(), 1);
        assert!(
            recipient
                .validate_private_staged_add(&group, staged, &input)
                .is_err()
        );
        let actual = approver
            .validate_private_staged_add(&group, staged, &input)
            .unwrap();
        assert_eq!(actual.successor.epoch.0, input.predecessor.epoch.0 + 1);
        assert_eq!(actual.successor.leaves.len(), 2);
        assert!(
            actual
                .successor
                .leaves
                .iter()
                .any(|leaf| leaf.signature_public_key == input.recipient_signature_public_key)
        );
        assert!(
            actual
                .successor
                .leaves
                .iter()
                .any(|leaf| leaf.leaf_index == input.own_leaf_index
                    && leaf.signature_public_key == approver.identity.signer.public())
        );
        assert!(
            actual.successor.epoch_authenticator_digest
                != input.predecessor.epoch_authenticator_digest
        );
        assert!(
            recipient
                .durably_owned_key_packages()
                .unwrap()
                .contains(&exact)
        );
    }

    #[tokio::test]
    async fn private_staged_add_rejects_actual_unapproved_extra_leaf() {
        use cgka_traits::storage::StorageProvider;
        use openmls::group::MlsGroup;
        use openmls_traits::OpenMlsProvider;
        let mut approver = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
        let origin = approver.create_private_device_group_genesis().unwrap();
        let mut recipient = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
        let exact = recipient.fresh_linking_key_package().await.unwrap();
        let input = approver
            .validate_private_invite_input(origin.group_id(), &exact)
            .unwrap();
        let mut unwanted = current_test_engine(SqliteAccountStorage::in_memory().unwrap());
        let extra = unwanted.fresh_linking_key_package().await.unwrap();
        let provider = crate::provider::EngineOpenMlsProvider::<SqliteAccountStorage>::new(
            &approver.crypto,
            approver.storage.mls_storage(),
        );
        let mut group = MlsGroup::load(
            provider.storage(),
            &openmls::group::GroupId::from_slice(origin.group_id().as_slice()),
        )
        .unwrap()
        .unwrap();
        let _bundle = group
            .commit_builder()
            .consume_proposal_store(false)
            .propose_adds([
                approver.parse_key_package(&exact).unwrap(),
                approver.parse_key_package(&extra).unwrap(),
            ])
            .load_psks(provider.storage())
            .unwrap()
            .build(
                provider.rand(),
                provider.crypto(),
                &approver.identity.signer,
                |_| true,
            )
            .unwrap()
            .stage_commit(&provider)
            .unwrap();
        assert!(
            approver
                .validate_private_staged_add(&group, group.pending_commit().unwrap(), &input)
                .is_err()
        );
    }
}

#[cfg(test)]
#[path = "private_device_invite_prepare_tests.rs"]
mod prepare_tests;

mod preparation;
pub use preparation::*;
mod confirmation;
