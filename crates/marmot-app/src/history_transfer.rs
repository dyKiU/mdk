//! Opt-in logical archive boundary; no host-supplied manifest is authority.
use crate::{GroupId, runtime::AccountManager};
#[cfg(feature = "experimental-device-sync")]
pub(crate) mod enabled;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HistoryTransferError {
    #[error("History transfer is unsupported by this build")]
    Unsupported,
    #[error("History transfer is not ready")]
    NotReady,
    #[error("History original action is closed")]
    Closed,
    #[error("History displayed revision changed")]
    StaleRevision,
    #[error("History runtime is unavailable")]
    RuntimeUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryTransferSnapshot {
    pub revision: u64,
    pub imported_records: u32,
    pub complete: bool,
    /// Authenticated captured selection for recipient review; never a grant.
    pub group: GroupId,
    pub source_device: Vec<u8>,
    pub recipient_device: Vec<u8>,
    pub snapshot_timestamp_ceiling: u64,
    pub record_count: u32,
    pub encoded_bytes: u32,
    pub fragment_count: u32,
}
/// Opaque original source owner; observation cannot authorize import.
pub struct HistoryTransfer {
    #[cfg(feature = "experimental-device-sync")]
    original: std::sync::Arc<enabled::State>,
    #[cfg(feature = "experimental-device-sync")]
    manager: AccountManager,
    #[cfg(feature = "experimental-device-sync")]
    account: String,
    #[cfg(not(feature = "experimental-device-sync"))]
    _private: (),
}
/// Opaque original recipient action; linked membership is not consent.
pub struct HistoryConsent {
    #[cfg(feature = "experimental-device-sync")]
    original: std::sync::Arc<enabled::State>,
    #[cfg(feature = "experimental-device-sync")]
    manager: AccountManager,
    #[cfg(feature = "experimental-device-sync")]
    account: String,
    #[cfg(not(feature = "experimental-device-sync"))]
    _private: (),
}
impl AccountManager {
    pub async fn begin_history_transfer(
        &self,
        account: &str,
        group: &GroupId,
        recipient_device: Vec<u8>,
    ) -> Result<HistoryTransfer, HistoryTransferError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            let original = self
                .begin_original_history(account, group, recipient_device)
                .await?;
            original.retain_host();
            Ok(HistoryTransfer {
                original,
                manager: self.clone(),
                account: account.to_owned(),
            })
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account, group, recipient_device);
            Err(HistoryTransferError::Unsupported)
        }
    }
    pub async fn pending_history_requests(
        &self,
        account: &str,
    ) -> Result<Vec<HistoryConsent>, HistoryTransferError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            Ok(self
                .pending_original_history(account)
                .await?
                .into_iter()
                .map(|original| {
                    original.retain_host();
                    HistoryConsent {
                        original,
                        manager: self.clone(),
                        account: account.to_owned(),
                    }
                })
                .collect())
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = account;
            Err(HistoryTransferError::Unsupported)
        }
    }
}
impl HistoryTransfer {
    pub async fn snapshot(&self) -> Result<HistoryTransferSnapshot, HistoryTransferError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.original.snapshot()
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            Err(HistoryTransferError::Unsupported)
        }
    }
    pub async fn continue_transfer(&self, revision: u64) -> Result<(), HistoryTransferError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.manager
                .continue_original_history(&self.account, self.original.clone(), revision)
                .await
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = revision;
            Err(HistoryTransferError::Unsupported)
        }
    }
    pub fn cancel(&self) {
        #[cfg(feature = "experimental-device-sync")]
        self.original.cancel();
    }
}
impl HistoryConsent {
    pub async fn snapshot(&self) -> Result<HistoryTransferSnapshot, HistoryTransferError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.original.snapshot()
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            Err(HistoryTransferError::Unsupported)
        }
    }
    pub async fn approve(&self, revision: u64) -> Result<(), HistoryTransferError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.manager
                .approve_original_history(&self.account, self.original.clone(), revision)
                .await
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = revision;
            Err(HistoryTransferError::Unsupported)
        }
    }
    pub fn cancel(&self) {
        #[cfg(feature = "experimental-device-sync")]
        self.original.cancel();
    }
}
#[cfg(feature = "experimental-device-sync")]
impl Drop for HistoryTransfer {
    fn drop(&mut self) {
        self.original.release_host();
    }
}
#[cfg(feature = "experimental-device-sync")]
impl Drop for HistoryConsent {
    fn drop(&mut self) {
        self.original.release_host();
    }
}

#[cfg(all(test, not(feature = "experimental-device-sync")))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn default_history_transfer_refuses_before_account_or_worker_effects() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = crate::MarmotAppRuntime::new(crate::MarmotApp::with_relay(
            dir.path(),
            "wss://relay.example",
        ));
        let manager = runtime.accounts();
        assert!(matches!(
            manager
                .begin_history_transfer("missing", &GroupId::new(vec![]), vec![0; 65536])
                .await,
            Err(HistoryTransferError::Unsupported)
        ));
        assert!(matches!(
            manager.pending_history_requests("missing").await,
            Err(HistoryTransferError::Unsupported)
        ));
        assert!(manager.managed_accounts().unwrap().is_empty());
        runtime.shutdown_and_close().await.unwrap();
    }
}
