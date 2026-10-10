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
    pub(crate) fn selected_consent_offer(
        &mut self,
        original: &std::sync::Arc<crate::selected_chat_copy::enabled::ConsentState>,
        revision: u64,
    ) -> Result<Vec<u8>, SelectedChatCopyError> {
        let response = self.selected_consent_response(original, revision)?;
        let mut lease = OriginalPackageLease {
            original: original.clone(),
            revision,
            response_digest: Sha256::digest(&response).into(),
        };
        let offer = self
            .runtime
            .session()
            .resolve_selected_chat_package(&original.observation, &response, &mut lease)
            .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?;
        let (wire, scope, reference) = offer.into_parts();
        if let Err(error) = self.selected_chat_copy_owner.register_package_cleanup(
            original,
            scope.clone(),
            reference,
        ) {
            original.cancel();
            self.runtime
                .session()
                .retire_selected_chat_package(&scope, &reference)
                .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?;
            return Err(error);
        }
        if let Err(error) = self.fresh_selected_consent(original, revision) {
            original.cancel();
            self.runtime
                .session()
                .retire_selected_chat_package(&scope, &reference)
                .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?;
            self.selected_chat_copy_owner
                .clear_package_cleanup(&reference);
            return Err(error);
        }
        Ok(wire)
    }
    pub(crate) fn maintain_selected_chat_packages(
        &mut self,
    ) -> Result<(), cgka_traits::EngineError> {
        for (scope, reference) in self.selected_chat_copy_owner.packages_to_retire() {
            self.runtime
                .session()
                .retire_selected_chat_package(&scope, &reference)?;
            self.selected_chat_copy_owner
                .clear_package_cleanup(&reference);
        }
        Ok(())
    }
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

struct OriginalPackageLease {
    original: std::sync::Arc<crate::selected_chat_copy::enabled::ConsentState>,
    revision: u64,
    response_digest: [u8; 32],
}
impl cgka_engine::selected_chat_consent::SelectedChatPackageLease for OriginalPackageLease {
    fn check_original(
        &mut self,
        scope: &cgka_traits::selected_chat_key_package::SelectedChatPurposeScope,
        context: &cgka_traits::selected_chat_key_package::SelectedChatPurposeContext,
    ) -> Result<(), cgka_traits::EngineError> {
        self.original
            .check_revision(self.revision)
            .map_err(|_| cgka_traits::EngineError::Other("selected consent unavailable".into()))?;
        let progress = self
            .original
            .progress
            .lock()
            .expect("selected package original consent");
        if progress.nonce.is_none()
            || scope.generation != self.original.generation()
            || scope.request_binding != self.original.observation.binding()
            || context.approved_response_digest != self.response_digest
            || context.protected_settlement_generation != self.original.protected_generation
            || context.protected_group != self.original.observation.protected_group()
            || context.ordinary_group != self.original.observation.ordinary_group()
        {
            return Err(cgka_traits::EngineError::Other(
                "selected consent unavailable".into(),
            ));
        }
        Ok(())
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

impl AppClient {
    fn fresh_selected_request(
        &self,
        original: &std::sync::Arc<crate::selected_chat_copy::enabled::RequestState>,
        revision: u64,
    ) -> Result<(), SelectedChatCopyError> {
        if !self.selected_chat_copy_owner.owns(original) {
            return Err(SelectedChatCopyError::Closed);
        }
        original.check_revision(revision)?;
        let session = self.runtime.session();
        session.with_group_authority_snapshot(&original._ordinary._group, |_, authority| {
            let ordinary = ordinary_anchor(session, &original._ordinary._group, authority)?;
            let protected = session
                .validated_settled_device_roster(&original._protected.group_id)
                .map_err(|_| SelectedChatCopyError::InvalidSelection)?
                .ok_or(SelectedChatCopyError::InvalidSelection)?;
            if ordinary != original._ordinary
                || protected.candidate() != &original._protected
                || protected.settlement_generation() != original._protected_generation
            {
                return Err(SelectedChatCopyError::InvalidSelection);
            }
            original.check_revision(revision)
        })
    }
    pub(crate) fn selected_request_packet(
        &self,
        original: &std::sync::Arc<crate::selected_chat_copy::enabled::RequestState>,
        revision: u64,
    ) -> Result<Vec<u8>, SelectedChatCopyError> {
        self.fresh_selected_request(original, revision)?;
        let mut progress = original.progress.lock().expect("selected request packet");
        let packet = match &progress.packet {
            Some(packet) => packet.clone(),
            None => self
                .runtime
                .session()
                .selected_chat_request_observation(
                    &original._ordinary._group,
                    &original._protected.group_id,
                    original._request_nonce,
                )
                .map_err(|_| SelectedChatCopyError::InvalidPacket)?,
        };
        // Tail revalidation must not hold the progress lock used by observations.
        drop(progress);
        self.fresh_selected_request(original, revision)?;
        progress = original.progress.lock().expect("selected request packet");
        progress.packet = Some(packet.clone());
        Ok(packet)
    }
    pub(crate) fn selected_receive_request(
        &mut self,
        packet: Vec<u8>,
    ) -> Result<
        std::sync::Arc<crate::selected_chat_copy::enabled::ConsentState>,
        SelectedChatCopyError,
    > {
        let observation = self
            .runtime
            .session()
            .authenticate_selected_chat_request(&packet)
            .map_err(|_| SelectedChatCopyError::InvalidPacket)?;
        let selected = self
            .runtime
            .session()
            .validated_settled_device_roster(&observation.protected_group())
            .map_err(|_| SelectedChatCopyError::InvalidPacket)?
            .ok_or(SelectedChatCopyError::InvalidPacket)?;
        let index = self
            .runtime
            .session()
            .own_leaf_index(&observation.protected_group())
            .map_err(|_| SelectedChatCopyError::InvalidPacket)?;
        if selected.candidate().leaves.iter().any(|leaf| {
            leaf.leaf_index == index && leaf.signature_public_key == observation.source_key()
        }) {
            return Err(SelectedChatCopyError::InvalidPacket);
        }
        self.selected_chat_copy_owner.receive_consent(
            observation,
            packet,
            selected.settlement_generation(),
        )
    }
    fn fresh_selected_consent(
        &self,
        original: &std::sync::Arc<crate::selected_chat_copy::enabled::ConsentState>,
        revision: u64,
    ) -> Result<(), SelectedChatCopyError> {
        if !self.selected_chat_copy_owner.owns_consent(original) {
            return Err(SelectedChatCopyError::Closed);
        }
        original.check_revision(revision)?;
        let current = self
            .runtime
            .session()
            .authenticate_selected_chat_request(&original.packet)
            .map_err(|_| SelectedChatCopyError::InvalidPacket)?;
        if current.binding() != original.observation.binding() {
            return Err(SelectedChatCopyError::InvalidPacket);
        }
        if self
            .runtime
            .session()
            .validated_settled_device_roster(&original.observation.protected_group())
            .map_err(|_| SelectedChatCopyError::InvalidSelection)?
            .is_none_or(|current| current.settlement_generation() != original.protected_generation)
        {
            return Err(SelectedChatCopyError::InvalidSelection);
        }
        original.check_revision(revision)
    }
    pub(crate) fn selected_consent_approve(
        &self,
        original: &std::sync::Arc<crate::selected_chat_copy::enabled::ConsentState>,
        revision: u64,
    ) -> Result<(), SelectedChatCopyError> {
        self.fresh_selected_consent(original, revision)?;
        let mut nonce = [0; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let mut progress = original.progress.lock().expect("selected consent approve");
        if progress.nonce.is_some() {
            return Err(SelectedChatCopyError::StaleRevision);
        }
        progress.nonce = Some(nonce);
        drop(progress);
        self.fresh_selected_consent(original, revision + 1)
    }
    pub(crate) fn selected_consent_response(
        &self,
        original: &std::sync::Arc<crate::selected_chat_copy::enabled::ConsentState>,
        revision: u64,
    ) -> Result<Vec<u8>, SelectedChatCopyError> {
        self.fresh_selected_consent(original, revision)?;
        let progress = original.progress.lock().expect("selected consent response");
        let nonce = progress.nonce.ok_or(SelectedChatCopyError::NotReady)?;
        let packet = match &progress.response {
            Some(packet) => packet.clone(),
            None => self
                .runtime
                .session()
                .selected_chat_consent_observation(
                    &original.observation,
                    original.generation(),
                    nonce,
                )
                .map_err(|_| SelectedChatCopyError::InvalidPacket)?,
        };
        drop(progress);
        self.fresh_selected_consent(original, revision)?;
        original
            .progress
            .lock()
            .expect("selected consent response")
            .response = Some(packet.clone());
        Ok(packet)
    }
    pub(crate) fn selected_request_collect(
        &self,
        original: &std::sync::Arc<crate::selected_chat_copy::enabled::RequestState>,
        revision: u64,
        packet: &[u8],
    ) -> Result<(), SelectedChatCopyError> {
        use sha2::{Digest, Sha256};
        self.fresh_selected_request(original, revision)?;
        let request = original
            .progress
            .lock()
            .expect("selected original packet")
            .packet
            .clone()
            .ok_or(SelectedChatCopyError::NotReady)?;
        let receipt = self
            .runtime
            .session()
            .authenticate_selected_chat_consent(&request, packet)
            .map_err(|_| SelectedChatCopyError::InvalidPacket)?;
        self.fresh_selected_request(original, revision)?;
        let digest = Sha256::digest(packet).into();
        let mut progress = original
            .progress
            .lock()
            .expect("selected receipt observation");
        if let Some(prior) = progress.receipts.get(&receipt.source_index()) {
            return if prior == &(digest, receipt.source_key().to_vec()) {
                Ok(())
            } else {
                Err(SelectedChatCopyError::InvalidPacket)
            };
        }
        if progress.receipts.len() >= original._protected.leaves.len().saturating_sub(1) {
            return Err(SelectedChatCopyError::InvalidPacket);
        }
        progress.receipts.insert(
            receipt.source_index(),
            (digest, receipt.source_key().to_vec()),
        );
        Ok(())
    }
}
