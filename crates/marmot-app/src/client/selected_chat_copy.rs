//! Fresh read-only selections for an independent ordinary-chat request.
use super::AppClient;
use crate::selected_chat_copy::{SelectedChatCopyError, enabled::OrdinaryChatAnchor};
use cgka_session::AccountDeviceSession;
use cgka_traits::{GroupId, GroupLifecycleState, group::ProtocolProfile};
use sha2::{Digest, Sha256};

impl From<cgka_traits::StorageError> for SelectedChatCopyError {
    fn from(_: cgka_traits::StorageError) -> Self {
        Self::RuntimeUnavailable
    }
}
impl From<cgka_session::SessionError> for SelectedChatCopyError {
    fn from(_: cgka_session::SessionError) -> Self {
        Self::RuntimeUnavailable
    }
}

fn ordinary_anchor(
    session: &AccountDeviceSession,
    group: &GroupId,
    authority: cgka_engine::group_authority::GroupAuthoritySnapshot,
) -> Result<OrdinaryChatAnchor, SelectedChatCopyError> {
    let record = session.group_record(group)?;
    if record.protocol_profile != ProtocolProfile::Current {
        return Err(SelectedChatCopyError::UnsupportedGroup);
    }
    if authority.lifecycle != GroupLifecycleState::Stable
        || authority.disbanding
        || !authority.facts.is_member
        || authority.facts.removed
        || authority.facts.unrecoverable
        || authority.facts.disbanded
    {
        return Err(SelectedChatCopyError::NotReady);
    }
    let membership = session.canonical_group_membership(group)?;
    let own_index = session
        .own_leaf_index(group)
        .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?;
    if !membership.local_leaf_active
        || !membership
            .member_leaves
            .iter()
            .any(|leaf| leaf.leaf_index == own_index && leaf.member == session.self_id())
    {
        return Err(SelectedChatCopyError::InvalidSelection);
    }
    if !authority.facts.is_admin {
        return Err(SelectedChatCopyError::NotAdmin);
    }
    let mut leaves = membership.member_leaves;
    leaves.sort_by_key(|leaf| leaf.leaf_index);
    let mut digest = Sha256::new();
    digest.update(b"WN-selected-chat-original-roster-v1");
    digest.update((leaves.len() as u64).to_be_bytes());
    for leaf in leaves {
        digest.update(leaf.leaf_index.to_be_bytes());
        digest.update((leaf.member.as_slice().len() as u64).to_be_bytes());
        digest.update(leaf.member.as_slice());
    }
    Ok(OrdinaryChatAnchor {
        _group: group.clone(),
        _epoch: authority.facts.epoch,
        _local_leaf_index: own_index,
        _local_leaf_hash: session.own_leaf_hash(group)?,
        _canonical_roster_digest: digest.finalize().into(),
    })
}

impl AppClient {
    pub(crate) fn begin_owned_selected_chat_copy(
        &mut self,
        group: &GroupId,
        selector: &[u8],
    ) -> Result<
        std::sync::Arc<crate::selected_chat_copy::enabled::RequestState>,
        SelectedChatCopyError,
    > {
        if group.as_slice().is_empty()
            || group.as_slice().len() > 256
            || selector.is_empty()
            || selector.len() > 256
            || selector == group.as_slice()
        {
            return Err(SelectedChatCopyError::InvalidSelection);
        }
        self.ensure_group(group)
            .map_err(|_| SelectedChatCopyError::InvalidSelection)?;
        let protected_group = GroupId::new(selector.to_vec());
        for selected in [group, &protected_group] {
            if !self.runtime.session_mut().ensure_group_hydrated(selected)? {
                return Err(SelectedChatCopyError::InvalidSelection);
            }
        }
        let session = self.runtime.session();
        let (ordinary, protected) =
            session.with_group_authority_snapshot(group, |_, authority| {
                let ordinary = ordinary_anchor(session, group, authority)?;
                let protected = session
                    .validated_settled_device_roster(&protected_group)
                    .map_err(|_| SelectedChatCopyError::InvalidSelection)?
                    .ok_or(SelectedChatCopyError::InvalidSelection)?;
                if protected.candidate().account.as_slice() != session.self_id().as_slice() {
                    return Err(SelectedChatCopyError::InvalidSelection);
                }
                Ok::<_, SelectedChatCopyError>((ordinary, protected))
            })?;
        self.selected_chat_copy_owner.reserve(ordinary, protected)
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn actual_legacy_group_cannot_supply_selected_chat_request_anchor() {
        use cgka_session::{PublishWork, SessionConfig};
        use cgka_traits::engine::CreateGroupRequest;
        let dir = tempfile::tempdir().unwrap();
        let keys = nostr::prelude::Keys::generate();
        let signer = crate::external_signer::AccountSigner::Local(keys.clone());
        let mut session = AccountDeviceSession::open(
            SessionConfig::new(
                dir.path().join("legacy.sqlite"),
                storage_sqlite::SqlCipherKey::new("selected legacy fixture").unwrap(),
                keys.public_key().to_bytes().to_vec(),
                Box::new(transport_nostr_peeler::NostrMlsPeeler::new().with_welcome_signer(keys)),
            )
            .legacy_compatibility_profile()
            .account_identity_proof_signer(signer.as_proof_signer()),
        )
        .unwrap();
        let created = session
            .create_group(CreateGroupRequest {
                name: "legacy selected chat negative".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let PublishWork::GroupCreated { pending, .. } = created.effects.publish[0] else {
            panic!("actual legacy founding commit");
        };
        session.confirm_published(pending).await.unwrap();
        let authority = session.group_authority(&created.group_id).unwrap();
        assert_eq!(authority.lifecycle, GroupLifecycleState::Stable);
        assert!(authority.facts.is_admin);
        assert!(matches!(
            ordinary_anchor(&session, &created.group_id, authority),
            Err(SelectedChatCopyError::UnsupportedGroup)
        ));
    }
}
