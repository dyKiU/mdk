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

/// Current eligible linked device observation; never consent or transfer authority.
#[derive(Clone, PartialEq, Eq)]
pub struct HistoryTransferRecipient {
    pub leaf_index: u32,
    pub device: Vec<u8>,
}
impl std::fmt::Debug for HistoryTransferRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryTransferRecipient")
            .field("leaf_index", &self.leaf_index)
            .finish_non_exhaustive()
    }
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
    /// List fresh Core-derived eligible recipients for one ordinary chat.
    /// The result creates no original transfer, recipient request or consent.
    pub async fn history_transfer_recipients(
        &self,
        account: &str,
        group: &GroupId,
    ) -> Result<Vec<HistoryTransferRecipient>, HistoryTransferError> {
        #[cfg(feature = "experimental-device-sync")]
        {
            self.query_history_recipients(account, group).await
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account, group);
            Err(HistoryTransferError::Unsupported)
        }
    }

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
        assert!(matches!(
            manager
                .history_transfer_recipients("missing", &GroupId::new(vec![]))
                .await,
            Err(HistoryTransferError::Unsupported)
        ));
        assert!(manager.managed_accounts().unwrap().is_empty());
        runtime.shutdown_and_close().await.unwrap();
    }
}

#[cfg(all(
    test,
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
impl HistoryTransfer {
    pub(crate) async fn republish_original_request_for_test(
        &self,
    ) -> Result<(), HistoryTransferError> {
        self.manager
            .republish_original_history_request_for_test(&self.account, self.original.clone())
            .await
    }
}

#[cfg(all(
    test,
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
impl HistoryTransfer {
    pub(crate) async fn original_record_for_test(
        &self,
        message_id: [u8; 32],
    ) -> Result<(bool, usize), HistoryTransferError> {
        self.manager
            .inspect_original_history_record_for_test(
                &self.account,
                self.original.clone(),
                message_id,
            )
            .await
    }
}

#[cfg(all(test, feature = "experimental-device-sync"))]
mod recipient_tests {
    use super::*;
    #[tokio::test]
    async fn history_recipient_query_validates_group_bounds_before_worker_effects() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = crate::MarmotAppRuntime::new(crate::MarmotApp::with_relay(
            dir.path(),
            "wss://relay.example",
        ));
        let manager = runtime.accounts();
        for bytes in [vec![], vec![1; 256]] {
            assert!(matches!(
                manager
                    .history_transfer_recipients("missing", &GroupId::new(bytes))
                    .await,
                Err(HistoryTransferError::NotReady)
            ));
        }
        assert!(matches!(
            manager
                .history_transfer_recipients("missing", &GroupId::new(vec![1; 16]))
                .await,
            Err(HistoryTransferError::RuntimeUnavailable)
        ));
        assert!(manager.managed_accounts().unwrap().is_empty());
        runtime.shutdown_and_close().await.unwrap();
    }
}
