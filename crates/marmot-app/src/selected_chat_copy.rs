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
}

/// Opaque original request; neither its snapshot nor linked roster is consent.
pub struct SelectedChatCopy {
    #[cfg(not(feature = "experimental-device-sync"))]
    _private: (),
    #[cfg(feature = "experimental-device-sync")]
    inner: std::sync::Arc<enabled::RequestState>,
}

impl SelectedChatCopy {
    #[cfg(feature = "experimental-device-sync")]
    pub(crate) fn from_original(inner: std::sync::Arc<enabled::RequestState>) -> Self {
        Self { inner }
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
