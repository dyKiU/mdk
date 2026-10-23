//! Separate selected-chat recipient authority, retained only in process memory.
use super::*;
use cgka_traits::selected_chat_key_package::SelectedChatPurposeKeyPackage;
use openmls::group::MlsGroup;
use std::sync::Arc;

/// Trusted account runtime obtains a lease from its exact original approved
/// sibling consent. Durable packages and request observations are not owners.
pub trait SelectedChatWelcomePolicy: Send + Sync {
    fn begin_join(
        &self,
        package: &SelectedChatPurposeKeyPackage,
    ) -> Result<Box<dyn SelectedChatWelcomeLease>, EngineError>;
}
pub trait SelectedChatWelcomeLease: Send {
    fn original(&self) -> &AuthenticatedSelectedChatRequest;
    fn check_live(&mut self, package: &SelectedChatPurposeKeyPackage) -> Result<(), EngineError>;
}
impl<S: StorageProvider> Engine<S> {
    pub fn install_trusted_selected_chat_welcome_policy(
        &mut self,
        policy: Arc<dyn SelectedChatWelcomePolicy>,
    ) {
        self.selected_chat_welcome_policy = Some(policy);
    }
    pub(crate) fn validate_selected_chat_join(
        &self,
        lease: &mut dyn SelectedChatWelcomeLease,
        package: &SelectedChatPurposeKeyPackage,
        group: &MlsGroup,
        sender_index: u32,
        sender_key: &[u8],
    ) -> Result<(), EngineError> {
        lease.check_live(package)?;
        let original = lease.original();
        let fresh = self.authenticate_selected_chat_request(&original.wire)?;
        let settled = self
            .validated_settled_device_roster(&original.protected_group())?
            .ok_or_else(denied)?;
        if fresh.actual != original.actual
            || fresh.local_protected_generation != original.local_protected_generation
            || settled.settlement_generation() != package.context.protected_settlement_generation
            || package.scope.request_binding != original.binding()
            || package.context.ordinary_group != original.ordinary_group()
            || group.group_id().as_slice() != original.ordinary_group().as_slice()
            || group.epoch().as_u64()
                != original
                    .frame
                    .ordinary
                    .epoch
                    .checked_add(1)
                    .ok_or_else(denied)?
            || sender_index != original.frame.ordinary.own_index
            || sender_key != original.source_key()
            || crate::device_group_genesis::exact_profile(group)?
        {
            return Err(EngineError::SelectedChatWelcomeDenied);
        }
        let actual = super::invite::indexed_tree(group.export_ratchet_tree())?;
        let additions = original
            .actual
            .leaves
            .iter()
            .filter(|leaf| leaf.signature_public_key != original.source_key())
            .collect::<Vec<_>>();
        if actual.len() != original.frame.ordinary.leaves.len() + additions.len() {
            return Err(EngineError::SelectedChatWelcomeDenied);
        }
        for old in &original.frame.ordinary.leaves {
            let leaf = actual
                .iter()
                .find(|leaf| leaf.index == old.index)
                .ok_or(EngineError::SelectedChatWelcomeDenied)?;
            if leaf.account != old.account
                || leaf.signer != old.signer
                || (old.index != sender_index && leaf.hash != old.hash)
            {
                return Err(EngineError::SelectedChatWelcomeDenied);
            }
        }
        for addition in additions {
            let leaf = actual
                .iter()
                .find(|leaf| leaf.signer == addition.signature_public_key)
                .ok_or(EngineError::SelectedChatWelcomeDenied)?;
            if leaf.account != original.frame.account
                || original
                    .frame
                    .ordinary
                    .leaves
                    .iter()
                    .any(|old| old.index == leaf.index)
            {
                return Err(EngineError::SelectedChatWelcomeDenied);
            }
        }
        let own = actual
            .iter()
            .find(|leaf| leaf.index == group.own_leaf_index().u32())
            .ok_or(EngineError::SelectedChatWelcomeDenied)?;
        let public = cgka_traits::engine::KeyPackage::new(package.public_bytes.clone())
            .with_protocol_profile(ProtocolProfile::Current);
        let parsed = self.parse_key_package(&public)?;
        use tls_codec::Serialize as _;
        let own_hash: [u8; 32] = Sha256::digest(
            parsed
                .leaf_node()
                .tls_serialize_detached()
                .map_err(|_| denied())?,
        )
        .into();
        if own.account != package.scope.account
            || own.signer != package.scope.local_device
            || own.hash != own_hash
            || parsed
                .hash_ref(&self.crypto)
                .map_err(|_| denied())?
                .as_slice()
                != package.reference
        {
            return Err(EngineError::SelectedChatWelcomeDenied);
        }
        lease.check_live(package)
    }
}
