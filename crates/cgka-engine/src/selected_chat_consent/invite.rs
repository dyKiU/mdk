//! Original selected request staging. No generic Welcome replay or owner restoration.
use super::*;
use cgka_traits::{MessageId, PendingStateRef, engine::SendResult};
use openmls::prelude::{MlsGroup, Node, Proposal};
use std::collections::BTreeSet;
use tls_codec::Serialize as _;

/// Trusted runtime checks its exact original request, collected offers, revision,
/// cancellation and monotonic lifetime. Metadata cannot instantiate this owner.
pub trait SelectedChatInviteLease: Send {
    /// Only a trusted original owner can supply its privately verified package
    /// transport identity. This metadata grants no membership by itself.
    fn key_package_event_id(
        &mut self,
        _original: &AuthenticatedSelectedChatRequest,
        _offer: &AuthenticatedSelectedChatOffer,
    ) -> Result<MessageId, EngineError> {
        Err(denied())
    }
    fn check_original(
        &mut self,
        original: &AuthenticatedSelectedChatRequest,
        offers: &[&AuthenticatedSelectedChatOffer],
    ) -> Result<(), EngineError>;
}

pub(super) fn indexed_tree(
    tree: openmls::treesync::RatchetTree,
) -> Result<Vec<IndexedOrdinaryLeaf>, EngineError> {
    let mut leaves = Vec::new();
    let mut signers = BTreeSet::new();
    for (index, node) in crate::app_components::ratchet_tree_nodes(tree)?
        .into_iter()
        .enumerate()
    {
        let Some(Node::LeafNode(leaf)) = node else {
            continue;
        };
        let account = crate::identity::validated_member_id_of_leaf(&leaf)?
            .as_slice()
            .to_vec();
        let signer = leaf.signature_key().as_slice().to_vec();
        if index % 2 != 0
            || leaves.len() == 128
            || account.len() != 32
            || signer.len() != 32
            || !signers.insert(signer.clone())
        {
            return Err(denied());
        }
        leaves.push(IndexedOrdinaryLeaf {
            index: u32::try_from(index / 2).map_err(|_| denied())?,
            account,
            signer,
            hash: Sha256::digest(leaf.tls_serialize_detached().map_err(|_| denied())?).into(),
        });
    }
    Ok(leaves)
}

impl<S: StorageProvider> Engine<S> {
    pub(super) fn selected_indexed_ordinary_leaves(
        &self,
        group: &GroupId,
    ) -> Result<Vec<IndexedOrdinaryLeaf>, EngineError> {
        let loaded = MlsGroup::load(
            self.storage.mls_storage(),
            &openmls::group::GroupId::from_slice(group.as_slice()),
        )
        .map_err(|_| denied())?
        .ok_or_else(denied)?;
        indexed_tree(loaded.export_ratchet_tree())
    }
    fn check_selected_offers(
        &self,
        original: &AuthenticatedSelectedChatRequest,
        offers: &[&AuthenticatedSelectedChatOffer],
    ) -> Result<(), EngineError> {
        let fresh = self.authenticate_selected_chat_request(&original.wire)?;
        if fresh.actual != original.actual
            || fresh.local_protected_generation != original.local_protected_generation
            || offers.is_empty()
            || offers.len() > 127
        {
            return Err(denied());
        }
        let mut indices = BTreeSet::new();
        let mut refs = BTreeSet::new();
        for offer in offers {
            if offer.request_binding != original.binding()
                || !indices.insert(offer.source_index())
                || !refs.insert(*offer.reference())
                || offer.source_key() == original.source_key()
                || !original.actual.leaves.iter().any(|leaf| {
                    leaf.leaf_index == offer.source_index()
                        && leaf.signature_public_key == offer.source_key()
                })
            {
                return Err(denied());
            }
        }
        if offers.len() + 1 != original.actual.leaves.len() {
            return Err(denied());
        }
        Ok(())
    }
    fn check_selected_successor(
        &self,
        original: &AuthenticatedSelectedChatRequest,
        offers: &[&AuthenticatedSelectedChatOffer],
        actual: &[IndexedOrdinaryLeaf],
        epoch: u64,
    ) -> Result<(), EngineError> {
        if epoch
            != original
                .frame
                .ordinary
                .epoch
                .checked_add(1)
                .ok_or_else(denied)?
            || actual.len() != original.frame.ordinary.leaves.len() + offers.len()
        {
            return Err(denied());
        }
        for old in &original.frame.ordinary.leaves {
            let leaf = actual
                .iter()
                .find(|leaf| leaf.index == old.index)
                .ok_or_else(denied)?;
            if leaf.account != old.account
                || leaf.signer != old.signer
                || (old.index != original.frame.ordinary.own_index && leaf.hash != old.hash)
            {
                return Err(denied());
            }
        }
        let mut expected = BTreeSet::new();
        for offer in offers {
            let package = self.parse_key_package(offer.key_package())?;
            let hash: [u8; 32] = Sha256::digest(
                package
                    .leaf_node()
                    .tls_serialize_detached()
                    .map_err(|_| denied())?,
            )
            .into();
            let leaf = actual
                .iter()
                .find(|leaf| leaf.signer == offer.source_key())
                .ok_or_else(denied)?;
            if leaf.account != original.frame.account
                || leaf.hash != hash
                || original
                    .frame
                    .ordinary
                    .leaves
                    .iter()
                    .any(|old| old.index == leaf.index)
                || !expected.insert(leaf.index)
            {
                return Err(denied());
            }
        }
        Ok(())
    }
    /// Stage only after the original runtime lease and actual admin/full trees
    /// validate. Frozen Welcomes remain caller-owned; no durable fanout is created.
    pub async fn prepare_selected_chat_invite(
        &mut self,
        original: &AuthenticatedSelectedChatRequest,
        offers: &[&AuthenticatedSelectedChatOffer],
        lease: &mut dyn SelectedChatInviteLease,
    ) -> Result<SendResult, EngineError> {
        self.check_selected_offers(original, offers)?;
        lease.check_original(original, offers)?;
        let packages = offers
            .iter()
            .map(|offer| {
                let event_id = lease.key_package_event_id(original, offer)?;
                if event_id.as_slice().len() != 32 {
                    return Err(denied());
                }
                Ok(cgka_traits::engine::KeyPackage::with_source_event_id(
                    offer.key_package().bytes().to_vec(),
                    event_id,
                )
                .with_protocol_profile(ProtocolProfile::Current))
            })
            .collect::<Result<Vec<_>, EngineError>>()?;
        let mut check = |engine: &Self| {
            engine.check_selected_offers(original, offers)?;
            if engine.selected_ordinary(&original.ordinary_group())? != original.frame.ordinary {
                return Err(denied());
            }
            lease.check_original(original, offers)
        };
        check(self)?;
        let result = self
            .do_send_invite_with_guard(
                original.ordinary_group(),
                packages,
                vec![],
                Some(&mut check),
            )
            .await?;
        let SendResult::GroupEvolution { pending, msg, .. } = &result else {
            return Err(denied());
        };
        if let Err(error) = self
            .validate_prepared_selected_chat_invite(original, offers, *pending, &msg.id)
            .and_then(|()| lease.check_original(original, offers))
        {
            self.do_publish_failed(*pending).await?;
            return Err(error);
        }
        Ok(result)
    }
    /// An exact pending identity is observation only. The caller must separately
    /// retain/check its original owner before each network poll and confirmation.
    pub fn validate_prepared_selected_chat_invite(
        &self,
        original: &AuthenticatedSelectedChatRequest,
        offers: &[&AuthenticatedSelectedChatOffer],
        pending: PendingStateRef,
        origin: &MessageId,
    ) -> Result<(), EngineError> {
        self.check_selected_offers(original, offers)?;
        if self.pending_origin_message_id(pending)? != *origin {
            return Err(denied());
        }
        let group = MlsGroup::load(
            self.storage.mls_storage(),
            &openmls::group::GroupId::from_slice(original.ordinary_group().as_slice()),
        )
        .map_err(|_| denied())?
        .ok_or_else(denied)?;
        let staged = group.pending_commit().ok_or_else(denied)?;
        let proposals = staged.queued_proposals().collect::<Vec<_>>();
        if proposals.len() != offers.len() {
            return Err(denied());
        }
        for proposal in proposals {
            let Proposal::Add(add) = proposal.proposal() else {
                return Err(denied());
            };
            if !offers.iter().any(|offer| {
                self.parse_key_package(offer.key_package())
                    .is_ok_and(|kp| kp == *add.key_package())
            }) {
                return Err(denied());
            }
        }
        let tree = staged
            .export_ratchet_tree(&self.crypto, group.export_ratchet_tree())
            .map_err(|_| denied())?
            .ok_or_else(denied)?;
        self.check_selected_successor(
            original,
            offers,
            &indexed_tree(tree)?,
            staged.epoch().as_u64(),
        )
    }
    /// Negative-only cleanup. A consumed pending slot is successful only when
    /// its exact locally confirmed commit still matches canonical crypto state.
    pub async fn retire_selected_chat_pending(
        &mut self,
        pending: PendingStateRef,
        origin: &MessageId,
        group_id: &GroupId,
    ) -> Result<(), EngineError> {
        match self.pending_origin_message_id(pending) {
            Ok(actual) => {
                if actual != *origin || self.pending_group_id(pending)? != *group_id {
                    return Err(denied());
                }
                self.do_publish_failed(pending).await?;
                Ok(())
            }
            Err(EngineError::UnknownPending) => {
                let record = self.storage.get_message(origin)?;
                let payload = cgka_traits::message::StoredMessagePayload::decode(&record.payload)
                    .map_err(|_| denied())?;
                let stamp = payload.own_commit_stamp().ok_or_else(denied)?;
                let group = MlsGroup::load(
                    self.storage.mls_storage(),
                    &openmls::group::GroupId::from_slice(group_id.as_slice()),
                )
                .map_err(|_| denied())?
                .ok_or_else(denied)?;
                if record.group_id != *group_id
                    || record.state != cgka_traits::message::MessageState::Processed
                    || stamp.committer != *self.identity.self_id()
                    || stamp.checkpoint_id.is_none()
                    || stamp.resulting_epoch_authenticator.is_none()
                    || record
                        .epoch
                        .0
                        .checked_add(1)
                        .is_none_or(|epoch| epoch > group.epoch().as_u64())
                    || (record.epoch.0.checked_add(1) == Some(group.epoch().as_u64())
                        && stamp.resulting_epoch_authenticator.as_deref()
                            != Some(hex::encode(group.epoch_authenticator().as_slice()).as_str()))
                {
                    return Err(denied());
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
    /// Fresh actual merged Current/admin successor, never a copied/joined claim.
    pub fn confirmed_selected_chat_successor(
        &self,
        original: &AuthenticatedSelectedChatRequest,
        offers: &[&AuthenticatedSelectedChatOffer],
    ) -> Result<(), EngineError> {
        self.check_selected_offers(original, offers)?;
        let actual = self.selected_ordinary(&original.ordinary_group())?;
        self.check_selected_successor(original, offers, &actual.leaves, actual.epoch)
    }
}
