//! Original approved sibling consent injection; no SQL-restored owner.
use super::*;
use crate::selected_chat_copy::enabled::ConsentState;
use cgka_engine::selected_chat_consent::{
    AuthenticatedSelectedChatRequest, SelectedChatWelcomeLease, SelectedChatWelcomePolicy,
};
use cgka_traits::{
    EngineError,
    selected_chat_key_package::{SelectedChatPurposeKeyPackage, SelectedChatPurposeScope},
};
use std::sync::{Arc, Weak};

struct OriginalRecipientPolicy {
    original: Weak<ConsentState>,
    revision: u64,
    scope: SelectedChatPurposeScope,
    reference: [u8; 32],
}
struct OriginalRecipientLease {
    original: Arc<ConsentState>,
    revision: u64,
    scope: SelectedChatPurposeScope,
    reference: [u8; 32],
}
impl SelectedChatWelcomePolicy for OriginalRecipientPolicy {
    fn begin_join(
        &self,
        package: &SelectedChatPurposeKeyPackage,
    ) -> Result<Box<dyn SelectedChatWelcomeLease>, EngineError> {
        let mut lease = OriginalRecipientLease {
            original: self
                .original
                .upgrade()
                .ok_or(EngineError::SelectedChatWelcomeDenied)?,
            revision: self.revision,
            scope: self.scope.clone(),
            reference: self.reference,
        };
        lease.check_live(package)?;
        Ok(Box::new(lease))
    }
}
impl SelectedChatWelcomeLease for OriginalRecipientLease {
    fn original(&self) -> &AuthenticatedSelectedChatRequest {
        &self.original.observation
    }
    fn check_live(&mut self, package: &SelectedChatPurposeKeyPackage) -> Result<(), EngineError> {
        self.original
            .check_revision(self.revision)
            .map_err(|_| EngineError::SelectedChatWelcomeDenied)?;
        let progress = self
            .original
            .progress
            .lock()
            .map_err(|_| EngineError::SelectedChatWelcomeDenied)?;
        let response = progress
            .response
            .as_ref()
            .ok_or(EngineError::SelectedChatWelcomeDenied)?;
        let digest: [u8; 32] = Sha256::digest(response).into();
        if progress.nonce.is_none()
            || self.scope != package.scope
            || self.reference != package.reference
            || self.scope.generation != self.original.generation()
            || self.scope.request_binding != self.original.observation.binding()
            || package.context.approved_response_digest != digest
            || package.context.protected_settlement_generation != self.original.protected_generation
        {
            return Err(EngineError::SelectedChatWelcomeDenied);
        }
        Ok(())
    }
}
impl AppClient {
    pub(super) fn install_selected_recipient(
        &mut self,
        original: &Arc<ConsentState>,
        revision: u64,
        scope: SelectedChatPurposeScope,
        reference: [u8; 32],
    ) {
        self.runtime
            .session_mut()
            .install_trusted_selected_chat_welcome_policy(Arc::new(OriginalRecipientPolicy {
                original: Arc::downgrade(original),
                revision,
                scope,
                reference,
            }));
    }
}
