//! Explicit selected-chat copy boundary. Protected linking is not chat consent.
use crate::{GroupId, runtime::AccountManager};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SelectedChatCopyError {
    #[error("Selected chat copying is unsupported by this build")]
    Unsupported,
    #[error("Selected chat copying is not ready")]
    NotReady,
    #[error("Invalid selected chat or linked roster")]
    InvalidSelection,
    #[error("Selected chat is not a supported Current ordinary group")]
    UnsupportedGroup,
    #[error("Only the current local ordinary-chat admin can request a copy")]
    NotAdmin,
    #[error("A selected chat request is already active")]
    Busy,
    #[error("Selected chat request runtime is unavailable")]
    RuntimeUnavailable,
    #[error("Invalid selected chat observation packet")]
    InvalidPacket,
    #[error("Selected chat observation revision is stale")]
    StaleRevision,
    #[error("Selected chat original owner is closed")]
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedChatCopyPhase {
    AwaitingSiblingConsent,
    Cancelled,
    Expired,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedChatCopySnapshot {
    pub revision: u64,
    pub phase: SelectedChatCopyPhase,
    pub sibling_count: u32,
    pub consenting_sibling_count: u32,
}

/// Opaque original request; neither its snapshot nor linked roster is consent.
pub struct SelectedChatCopy {
    #[cfg(not(feature = "experimental-device-sync"))]
    _private: (),
    #[cfg(feature = "experimental-device-sync")]
    inner: std::sync::Arc<enabled::RequestState>,
    #[cfg(feature = "experimental-device-sync")]
    manager: AccountManager,
    #[cfg(feature = "experimental-device-sync")]
    account: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedChatConsentPhase {
    AwaitingApproval,
    Approved,
    Cancelled,
    Expired,
    Closed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedChatConsentSnapshot {
    pub revision: u64,
    pub phase: SelectedChatConsentPhase,
    pub chat_selector: Vec<u8>,
}
/// Imported metadata does not create explicit sibling consent.
pub struct SelectedChatConsent {
    #[cfg(not(feature = "experimental-device-sync"))]
    _private: (),
    #[cfg(feature = "experimental-device-sync")]
    inner: std::sync::Arc<enabled::ConsentHandle>,
    #[cfg(feature = "experimental-device-sync")]
    manager: AccountManager,
    #[cfg(feature = "experimental-device-sync")]
    account: String,
}
impl SelectedChatConsent {
    #[cfg(feature = "experimental-device-sync")]
    pub(crate) fn from_original(
        original: std::sync::Arc<enabled::ConsentState>,
        manager: AccountManager,
        account: String,
    ) -> Self {
        Self {
            inner: original.public_handle(),
            manager,
            account,
        }
    }

    pub async fn snapshot(&self) -> Result<SelectedChatConsentSnapshot, SelectedChatCopyError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            Ok(self.inner.original.snapshot())
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            Err(SelectedChatCopyError::Unsupported)
        }
    }
    pub async fn approve(&self, revision: u64) -> Result<(), SelectedChatCopyError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.manager
                .selected_consent_approve(&self.account, self.inner.original.clone(), revision)
                .await
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = revision;
            Err(SelectedChatCopyError::Unsupported)
        }
    }
    pub async fn response_packet(&self, revision: u64) -> Result<Vec<u8>, SelectedChatCopyError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.manager
                .selected_consent_response(&self.account, self.inner.original.clone(), revision)
                .await
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = revision;
            Err(SelectedChatCopyError::Unsupported)
        }
    }
    /// Export a private single-use package under this original explicit consent.
    pub async fn offer_packet(&self, revision: u64) -> Result<Vec<u8>, SelectedChatCopyError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.manager
                .selected_consent_offer(&self.account, self.inner.original.clone(), revision)
                .await
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = revision;
            Err(SelectedChatCopyError::Unsupported)
        }
    }
    pub async fn cancel(&self) -> Result<(), SelectedChatCopyError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.inner.original.cancel();
            Ok(())
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            Err(SelectedChatCopyError::Unsupported)
        }
    }
}

impl SelectedChatCopy {
    pub async fn request_packet(&self, revision: u64) -> Result<Vec<u8>, SelectedChatCopyError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.manager
                .selected_request_packet(&self.account, self.inner.clone(), revision)
                .await
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = revision;
            Err(SelectedChatCopyError::Unsupported)
        }
    }
    pub async fn receive_consent_packet(
        &self,
        revision: u64,
        packet: Vec<u8>,
    ) -> Result<(), SelectedChatCopyError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.manager
                .selected_request_collect(&self.account, self.inner.clone(), revision, packet)
                .await
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (revision, packet);
            Err(SelectedChatCopyError::Unsupported)
        }
    }
    #[cfg(feature = "experimental-device-sync")]
    pub(crate) fn from_original(
        inner: std::sync::Arc<enabled::RequestState>,
        manager: AccountManager,
        account: String,
    ) -> Self {
        Self {
            inner,
            manager,
            account,
        }
    }

    pub async fn snapshot(&self) -> Result<SelectedChatCopySnapshot, SelectedChatCopyError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            Ok(self.inner.snapshot())
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            Err(SelectedChatCopyError::Unsupported)
        }
    }
    pub async fn cancel(&self) -> Result<(), SelectedChatCopyError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.inner.cancel();
            Ok(())
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            Err(SelectedChatCopyError::Unsupported)
        }
    }
}
#[cfg(feature = "experimental-device-sync")]
impl Drop for SelectedChatCopy {
    fn drop(&mut self) {
        self.inner.cancel();
    }
}

impl AccountManager {
    pub async fn receive_selected_chat_copy_request(
        &self,
        account_ref: &str,
        packet: Vec<u8>,
    ) -> Result<SelectedChatConsent, SelectedChatCopyError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.selected_receive_request(account_ref, packet).await
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account_ref, packet);
            Err(SelectedChatCopyError::Unsupported)
        }
    }
    /// Explicitly request one Current ordinary chat for a fresh linked roster.
    /// This retains new local A consent only. No sibling consent, private
    /// KeyPackage, package offer, Invite or transport work is created here.
    pub async fn begin_selected_chat_copy(
        &self,
        account_ref: &str,
        group_id: &GroupId,
        linked_roster_selector: Vec<u8>,
    ) -> Result<SelectedChatCopy, SelectedChatCopyError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.begin_owned_selected_chat_copy(account_ref, group_id, linked_roster_selector)
                .await
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account_ref, group_id, linked_roster_selector);
            Err(SelectedChatCopyError::Unsupported)
        }
    }
}

#[cfg(feature = "experimental-device-sync")]
pub(crate) mod enabled;

#[cfg(all(
    test,
    any(
        not(feature = "experimental-device-sync"),
        feature = "test-policy-overrides"
    )
))]
mod tests;
