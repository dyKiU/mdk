//! Positive historical creation observation; absence is unknown, never consent.
use crate::{Engine, openmls_projection::with_retained_anchor_group, snapshot_guard::RewindSite};
use cgka_traits::{EngineError, EpochId, GroupId, storage::StorageProvider};
use openmls::prelude::{BasicCredential, MlsGroup};

impl<S: StorageProvider> Engine<S> {
    /// Observe this actual signer's epoch-zero founding leaf, when retained.
    /// App eligibility independently needs current ordinary membership and
    /// an original approved sharing channel. A missing Welcome is no witness.
    pub fn retained_local_group_creation(&self, group_id: &GroupId) -> Result<bool, EngineError> {
        self.ensure_group_live(group_id)?;
        let creator = |group: &MlsGroup| -> Result<bool, EngineError> {
            if group.epoch().as_u64() != 0 || group.own_leaf_index().u32() != 0 {
                return Ok(false);
            }
            let Some(leaf) = group.own_leaf_node() else {
                return Ok(false);
            };
            let credential = BasicCredential::try_from(leaf.credential().clone())
                .map_err(|_| EngineError::Backend("invalid founding credential".into()))?;
            Ok(credential.identity() == self.identity.self_id().as_slice()
                && leaf.signature_key().as_slice() == self.identity.signer.public())
        };
        if self.with_mls_group(group_id, creator)? {
            return Ok(true);
        }
        self.storage.with_transaction(|storage| {
            let live_record = storage.get_group(group_id)?;
            let live_epoch = self.with_mls_group(group_id, |group| {
                Ok((
                    group.epoch().as_u64(),
                    group.epoch_authenticator().as_slice().to_vec(),
                ))
            })?;
            let result = with_retained_anchor_group(
                storage,
                &self.crypto,
                group_id,
                EpochId(0),
                RewindSite::LocalCreationOrigin,
                "acceptance-origin",
                |group, _| creator(group).map(Some),
            )?;
            let restored_epoch = self.with_mls_group(group_id, |group| {
                Ok((
                    group.epoch().as_u64(),
                    group.epoch_authenticator().as_slice().to_vec(),
                ))
            })?;
            if storage.get_group(group_id)? != live_record || live_epoch != restored_epoch {
                return Err(EngineError::Backend(
                    "founding observation did not restore live state".into(),
                ));
            }
            Ok(result.unwrap_or(false))
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::distributed_convergence::tests::test_engine;
    use cgka_traits::{
        engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult},
        storage::{GroupStorage, MessageStorage},
    };

    #[tokio::test]
    async fn actual_founder_witness_restores_live_state_and_never_credits_incoming_sibling() {
        let mut founder = test_engine();
        let mut sibling = test_engine();
        assert!(founder.self_id() == sibling.self_id());
        assert!(founder.identity.signer.public() != sibling.identity.signer.public());
        let (group, created) = founder
            .create_group(CreateGroupRequest {
                name: "creation witness".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let SendResult::GroupCreated { pending, .. } = created else {
            panic!("legacy fixture");
        };
        founder.confirm_published(pending).await.unwrap();
        assert!(founder.retained_local_group_creation(&group).unwrap());
        let package = sibling.fresh_key_package().await.unwrap();
        let SendResult::GroupEvolution {
            pending,
            mut welcomes,
            ..
        } = founder
            .send(SendIntent::Invite {
                group_id: group.clone(),
                key_packages: vec![package],
                initial_admins: vec![],
            })
            .await
            .unwrap()
        else {
            panic!("actual sibling invitation");
        };
        founder.confirm_published(pending).await.unwrap();
        sibling.join_welcome(welcomes.remove(0)).await.unwrap();
        let before = founder.storage.get_group(&group).unwrap();
        let authority = founder.group_authority(&group).unwrap();
        assert!(authority.facts.epoch.0 > 0);
        assert!(founder.retained_local_group_creation(&group).unwrap());
        assert!(founder.storage.get_group(&group).unwrap() == before);
        assert!(founder.group_authority(&group).unwrap() == authority);
        assert!(!sibling.retained_local_group_creation(&group).unwrap());
        for name in founder.storage.list_group_snapshots(&group).unwrap() {
            if crate::openmls_projection::retained_anchor_epoch_from_snapshot_name(&name) == Some(0)
            {
                founder
                    .storage
                    .release_group_snapshot(&group, &name)
                    .unwrap();
            }
        }
        assert!(!founder.retained_local_group_creation(&group).unwrap());
        assert!(founder.storage.get_group(&group).unwrap() == before);
    }
}
