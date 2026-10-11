//! Explicit pair-wide approval originals; roster observations are never consent.
use crate::runtime::AccountManager;
#[cfg(feature = "experimental-device-sync")]
pub(crate) mod enabled;
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AccountSharingError {
    #[error("Account sharing is unsupported by this build")]
    Unsupported,
    #[error("Account sharing is not ready")]
    NotReady,
    #[error("Account sharing original is closed")]
    Closed,
    #[error("Account sharing displayed revision changed")]
    StaleRevision,
    #[error("Account sharing runtime is unavailable")]
    RuntimeUnavailable,
}
/// Immutable authenticated review; no permission constructors or packet export.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountSharingSnapshot {
    pub protected_group: crate::GroupId,
    pub protected_epoch: u64,
    pub source_device: Vec<u8>,
    pub recipient_device: Vec<u8>,
    pub revision: u64,
    pub approved: bool,
    pub complete: bool,
}
pub struct AccountSharingApproval {
    #[cfg(feature = "experimental-device-sync")]
    pub(crate) original: std::sync::Arc<enabled::State>,
    #[cfg(feature = "experimental-device-sync")]
    manager: AccountManager,
    #[cfg(feature = "experimental-device-sync")]
    account: String,
    #[cfg(not(feature = "experimental-device-sync"))]
    _private: (),
}
impl AccountSharingApproval {
    #[cfg(feature = "experimental-device-sync")]
    fn held(
        original: std::sync::Arc<enabled::State>,
        manager: AccountManager,
        account: String,
    ) -> Self {
        original.retain();
        Self {
            original,
            manager,
            account,
        }
    }
    pub fn snapshot(&self) -> Result<AccountSharingSnapshot, AccountSharingError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.original.snapshot()
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            Err(AccountSharingError::Unsupported)
        }
    }
    pub async fn approve(&self, displayed_revision: u64) -> Result<(), AccountSharingError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.manager
                .approve_account_sharing(&self.account, self.original.clone(), displayed_revision)
                .await
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = displayed_revision;
            Err(AccountSharingError::Unsupported)
        }
    }
    pub fn cancel(&self) {
        #[cfg(feature = "experimental-device-sync")]
        self.original.cancel();
    }
}
#[cfg(feature = "experimental-device-sync")]
impl Clone for AccountSharingApproval {
    fn clone(&self) -> Self {
        Self::held(
            self.original.clone(),
            self.manager.clone(),
            self.account.clone(),
        )
    }
}
#[cfg(feature = "experimental-device-sync")]
impl Drop for AccountSharingApproval {
    fn drop(&mut self) {
        self.original.release();
    }
}
impl AccountManager {
    pub async fn begin_account_chat_sharing(
        &self,
        account: &str,
        recipient_device: Vec<u8>,
    ) -> Result<AccountSharingApproval, AccountSharingError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            let original = self
                .begin_account_sharing(account, recipient_device)
                .await?;
            Ok(AccountSharingApproval::held(
                original,
                self.clone(),
                account.to_owned(),
            ))
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account, recipient_device);
            Err(AccountSharingError::Unsupported)
        }
    }
    pub async fn pending_account_chat_sharing(
        &self,
        account: &str,
    ) -> Result<Vec<AccountSharingApproval>, AccountSharingError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            Ok(self
                .pending_account_sharing(account)
                .await?
                .into_iter()
                .map(|original| {
                    AccountSharingApproval::held(original, self.clone(), account.to_owned())
                })
                .collect())
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = account;
            Err(AccountSharingError::Unsupported)
        }
    }
}
