//! Explicit selected-chat copy boundary. Protected linking is not chat consent.
use crate::{GroupId, runtime::AccountManager};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SelectedChatCopyError {
    #[error("Selected chat copying is unsupported by this build")]
    Unsupported,
    #[error("Selected chat copying is not ready")]
    NotReady,
}

/// Reserved opaque operation boundary; this slice creates no operation or authority.
pub struct SelectedChatCopy {
    _private: (),
}

impl AccountManager {
    /// Request a copy of one ordinary chat to an observed linked-device roster.
    /// The selector is an observation, never consent. No KeyPackage is created
    /// and no worker is started while this boundary remains unavailable.
    pub async fn begin_selected_chat_copy(
        &self,
        _account_ref: &str,
        _group_id: &GroupId,
        _linked_roster_selector: Vec<u8>,
    ) -> Result<SelectedChatCopy, SelectedChatCopyError> {
        if cfg!(feature = "experimental-device-sync") {
            Err(SelectedChatCopyError::NotReady)
        } else {
            Err(SelectedChatCopyError::Unsupported)
        }
    }
}

#[cfg(all(
    test,
    any(
        not(feature = "experimental-device-sync"),
        feature = "test-policy-overrides"
    )
))]
mod tests;
