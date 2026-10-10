//! Original approved sibling consent injection; no SQL-restored owner.
use super::*;
use crate::selected_chat_copy::enabled::{ConsentState, SelectedRecipientAttempt};
use cgka_engine::selected_chat_consent::{
    AuthenticatedSelectedChatRequest, SelectedChatWelcomeLease, SelectedChatWelcomePolicy,
};
use cgka_traits::{
    EngineError,
    selected_chat_key_package::{SelectedChatPurposeKeyPackage, SelectedChatPurposeScope},
    storage::StorageProvider,
};
use std::sync::{Arc, Mutex, Weak};

struct OriginalRecipientPolicy {
    attempt: Arc<Mutex<Option<SelectedRecipientAttempt>>>,
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
        // This records which original owner Core actually validated. It cannot
        // admit a Welcome; every retry enters the same fresh Core policy again.
        *self
            .attempt
            .lock()
            .map_err(|_| EngineError::SelectedChatWelcomeDenied)? =
            Some(SelectedRecipientAttempt {
                original: self.original.clone(),
                revision: self.revision,
                scope: self.scope.clone(),
                reference: self.reference,
            });
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
    pub(crate) fn begin_selected_recipient_ingest(&self) {
        self.selected_chat_copy_owner
            .recipient_attempt
            .lock()
            .expect("selected recipient ingress")
            .take();
    }

    pub(crate) fn selected_recipient_storage_retry(
        &self,
        error: &crate::AppError,
    ) -> Option<SelectedRecipientAttempt> {
        let attempt = self
            .selected_chat_copy_owner
            .recipient_attempt
            .lock()
            .ok()?
            .take()?;
        if !matches!(error.as_engine_error(), Some(EngineError::Storage(_))) || !attempt.is_live() {
            return None;
        }
        // Pending only excludes a committed join from this retry path. The SQL
        // fact never grants admission or replaces the original live owner.
        let storage = self.app.account_storage(&self.state.label).ok()?;
        let package = storage
            .selected_chat_key_package_storage()?
            .selected_chat_key_package_by_ref(&attempt.reference)
            .ok()??;
        if package.scope != attempt.scope
            || package.state
                != cgka_traits::selected_chat_key_package::SelectedChatPurposeState::Pending
        {
            return None;
        }
        Some(attempt)
    }

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
                attempt: self.selected_chat_copy_owner.recipient_attempt.clone(),
                original: Arc::downgrade(original),
                revision,
                scope,
                reference,
            }));
    }
}
