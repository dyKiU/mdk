//! Signed public predecessor artifacts for the private enrollment protocol.
//! These bytes cannot grant SDK consent, membership, or chat/history access.
use crate::Engine;
use tls_codec::Serialize;

const MAX_PREDECESSOR_ARTIFACT_BYTES: usize = 256 * 1024;
use cgka_traits::{EngineError, GroupId, storage::StorageProvider};

impl<S: StorageProvider> Engine<S> {
    /// Export actual signed GroupInfo only from a freshly completed protected
    /// predecessor. The transport artifact is not a transferable approval.
    pub fn export_settled_device_predecessor(
        &self,
        group: &GroupId,
    ) -> Result<Option<Vec<u8>>, EngineError> {
        self.ensure_group_live(group)?;
        // Keep fresh protected settlement and actual public-tree export in one
        // read snapshot. No await, external join, or production storage write.
        self.storage.with_read_snapshot(|_| {
            if self.validated_settled_device_roster(group)?.is_none() {
                return Ok(None);
            }
            self.with_mls_group(group, |mls| {
                let message = mls
                    .export_group_info(&self.crypto, &self.identity.signer, true)
                    .map_err(|_| {
                        EngineError::Backend("private predecessor export failed".into())
                    })?;
                let bytes = message.tls_serialize_detached().map_err(|_| {
                    EngineError::Serialize("private predecessor serialization failed".into())
                })?;
                if bytes.len() > MAX_PREDECESSOR_ARTIFACT_BYTES {
                    return Err(EngineError::Serialize(
                        "private predecessor artifact exceeds bound".into(),
                    ));
                }
                Ok(Some(bytes))
            })
        })
    }
}

/// Authenticated public metadata only; no SDK/approval/admission authority.
pub struct AuthenticatedPrivatePredecessor {
    account: cgka_traits::MemberId,
    group_id: GroupId,
    epoch: cgka_traits::EpochId,
    leaves: Vec<crate::device_group_snapshot::CandidateDeviceLeaf>,
    artifact_digest: [u8; 32],
}
impl AuthenticatedPrivatePredecessor {
    pub fn account(&self) -> &cgka_traits::MemberId {
        &self.account
    }
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }
    pub fn epoch(&self) -> cgka_traits::EpochId {
        self.epoch
    }
    pub fn leaves(&self) -> &[crate::device_group_snapshot::CandidateDeviceLeaf] {
        &self.leaves
    }
    pub fn artifact_digest(&self) -> &[u8; 32] {
        &self.artifact_digest
    }
}
impl<S: StorageProvider> Engine<S> {
    /// Authenticate bounded portable metadata into scratch storage only.
    /// Matching caller expectations never establish settlement or consent.
    pub fn validate_private_device_predecessor(
        &self,
        artifact: &[u8],
        expected_account: &cgka_traits::MemberId,
        expected_group: &GroupId,
        expected_epoch: cgka_traits::EpochId,
        expected_leaves: &[crate::device_group_snapshot::CandidateDeviceLeaf],
    ) -> Result<AuthenticatedPrivatePredecessor, EngineError> {
        use cgka_traits::app_components::{APP_COMPONENTS_COMPONENT_ID, decode_components_list};
        use cgka_traits::device_group_genesis::{
            PRIVATE_DEVICE_GROUP_COMPONENT_ID, PRIVATE_DEVICE_GROUP_PROFILE,
        };
        use cgka_traits::group::ProtocolProfile;
        use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn, ProposalStore, PublicGroup};
        use sha2::{Digest, Sha256};
        use std::collections::HashSet;
        use tls_codec::Deserialize;

        let mismatch = || EngineError::Other("private predecessor metadata mismatch".into());
        if artifact.is_empty()
            || artifact.len() > MAX_PREDECESSOR_ARTIFACT_BYTES
            || expected_account.as_slice().len() != 32
            || expected_group.as_slice().is_empty()
            || expected_group.as_slice().len() > 1024
            || expected_leaves.is_empty()
            || expected_leaves.len() > 128
        {
            return Err(mismatch());
        }
        let mut keys = HashSet::new();
        let mut previous_index = None;
        for leaf in expected_leaves {
            if leaf.signature_public_key.len() != 32
                || previous_index.is_some_and(|previous| previous >= leaf.leaf_index)
                || !keys.insert(leaf.signature_public_key.as_slice())
            {
                return Err(mismatch());
            }
            previous_index = Some(leaf.leaf_index);
        }
        let message = MlsMessageIn::tls_deserialize_exact(artifact)
            .map_err(|_| EngineError::Serialize("private predecessor framing invalid".into()))?;
        let MlsMessageBodyIn::GroupInfo(info) = message.extract() else {
            return Err(mismatch());
        };
        let tree = info
            .extensions()
            .ratchet_tree()
            .ok_or_else(mismatch)?
            .ratchet_tree()
            .clone();
        // This is a new provider per call. Never install its public-group rows in
        // account storage or use this operation to restore an MLS member copy.
        let scratch = openmls_memory_storage::MemoryStorage::default();
        let (public, _) =
            PublicGroup::from_external(&self.crypto, &scratch, tree, info, ProposalStore::new())
                .map_err(|_| {
                    EngineError::Other("private predecessor authentication failed".into())
                })?;
        let group_id = GroupId::new(public.group_id().as_slice().to_vec());
        let epoch = cgka_traits::EpochId(public.group_context().epoch().as_u64());
        if group_id != *expected_group
            || epoch != expected_epoch
            || crate::account_identity_proof::protocol_profile_of_group_extensions(
                public.group_context().extensions(),
            )? != ProtocolProfile::Current
        {
            return Err(mismatch());
        }
        let dictionary = public
            .group_context()
            .extensions()
            .app_data_dictionary()
            .ok_or_else(mismatch)?
            .dictionary();
        let required = decode_components_list(
            dictionary
                .get(&APP_COMPONENTS_COMPONENT_ID)
                .ok_or_else(mismatch)?,
        )
        .map_err(|_| mismatch())?;
        if !required.contains(&PRIVATE_DEVICE_GROUP_COMPONENT_ID)
            || dictionary.get(&PRIVATE_DEVICE_GROUP_COMPONENT_ID)
                != Some(PRIVATE_DEVICE_GROUP_PROFILE)
        {
            return Err(mismatch());
        }
        let members = public.members().collect::<Vec<_>>();
        if members.is_empty() || members.len() > 128 || members.len() != expected_leaves.len() {
            return Err(mismatch());
        }
        let account = crate::identity::validated_member_id(&members[0].credential)?;
        if account != *expected_account {
            return Err(mismatch());
        }
        let mut leaves = Vec::with_capacity(members.len());
        for member in members {
            if crate::identity::validated_member_id(&member.credential)? != account
                || member.signature_key.len() != 32
            {
                return Err(mismatch());
            }
            leaves.push(crate::device_group_snapshot::CandidateDeviceLeaf {
                leaf_index: member.index.u32(),
                signature_public_key: member.signature_key,
            });
        }
        leaves.sort_by_key(|leaf| leaf.leaf_index);
        if leaves != expected_leaves {
            return Err(mismatch());
        }
        for leaf in public.export_ratchet_tree().leaves() {
            if crate::account_identity_proof::validate_leaf_account_identity_proof_for_member(
                leaf,
                public.group_context().ciphersuite(),
                &account,
                "private predecessor",
            )? != ProtocolProfile::Current
            {
                return Err(mismatch());
            }
        }
        Ok(AuthenticatedPrivatePredecessor {
            account,
            group_id,
            epoch,
            leaves,
            artifact_digest: Sha256::digest(artifact).into(),
        })
    }
}
