//! Thin original history owners. App owns consent, lifetime, transport and import.
use crate::{HistoryTransferRecipientFfi, HistoryTransferSnapshotFfi, Marmot, MarmotKitError};
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct HistoryTransfer {
    inner: marmot_app::HistoryTransfer,
}
#[derive(uniffi::Object)]
pub struct HistoryConsent {
    inner: marmot_app::HistoryConsent,
}

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Observe current linked-recipient choices; creates no transfer or consent.
    pub async fn history_transfer_recipients(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<Vec<HistoryTransferRecipientFfi>, MarmotKitError> {
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account_ref, group_id_hex);
            Err(MarmotKitError::HistoryTransferUnsupported)
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            let group = crate::conversions::group_id_from_hex(&group_id_hex)
                .map_err(|_| MarmotKitError::HistoryTransferNotReady)?;
            Ok(self
                .runtime
                .accounts()
                .history_transfer_recipients(&account_ref, &group)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        }
    }

    /// Request a bounded logical snapshot for one original linked recipient.
    pub async fn begin_history_transfer(
        &self,
        account_ref: String,
        group_id_hex: String,
        recipient_device: Vec<u8>,
    ) -> Result<Arc<HistoryTransfer>, MarmotKitError> {
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account_ref, group_id_hex, recipient_device);
            Err(MarmotKitError::HistoryTransferUnsupported)
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            let group = crate::conversions::group_id_from_hex(&group_id_hex)
                .map_err(|_| MarmotKitError::HistoryTransferNotReady)?;
            let inner = self
                .runtime
                .accounts()
                .begin_history_transfer(&account_ref, &group, recipient_device)
                .await?;
            Ok(Arc::new(HistoryTransfer { inner }))
        }
    }

    /// Observe original authenticated requests; polling never approves history.
    pub async fn pending_history_requests(
        &self,
        account_ref: String,
    ) -> Result<Vec<Arc<HistoryConsent>>, MarmotKitError> {
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = account_ref;
            Err(MarmotKitError::HistoryTransferUnsupported)
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            Ok(self
                .runtime
                .accounts()
                .pending_history_requests(&account_ref)
                .await?
                .into_iter()
                .map(|inner| Arc::new(HistoryConsent { inner }))
                .collect())
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl HistoryTransfer {
    /// Observe the original selection and committed completion; never a grant.
    pub async fn snapshot(&self) -> Result<HistoryTransferSnapshotFfi, MarmotKitError> {
        Ok(self.inner.snapshot().await?.into())
    }
    /// Continue this exact live original action at its displayed revision.
    pub async fn continue_transfer(&self, revision: u64) -> Result<(), MarmotKitError> {
        Ok(self.inner.continue_transfer(revision).await?)
    }
}
#[uniffi::export]
impl HistoryTransfer {
    /// Permanently cancel this original action; retained history is not revoked.
    pub fn cancel(&self) {
        self.inner.cancel();
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl HistoryConsent {
    /// Review the authenticated source, chat, bounds and current revision.
    pub async fn snapshot(&self) -> Result<HistoryTransferSnapshotFfi, MarmotKitError> {
        Ok(self.inner.snapshot().await?.into())
    }
    /// Explicitly approve this exact original request at its displayed revision.
    pub async fn approve(&self, revision: u64) -> Result<(), MarmotKitError> {
        Ok(self.inner.approve(revision).await?)
    }
}
#[uniffi::export]
impl HistoryConsent {
    /// Cancel this original consent without restoring it from persisted receipts.
    pub fn cancel(&self) {
        self.inner.cancel();
    }
}

#[cfg(all(test, not(feature = "experimental-device-sync")))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn default_history_bindings_refuse_before_input_or_account_effects() {
        let dir = tempfile::tempdir().unwrap();
        let app = marmot_app::MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        assert!(matches!(
            kit.begin_history_transfer("missing".into(), "invalid".into(), vec![0; 65536])
                .await,
            Err(MarmotKitError::HistoryTransferUnsupported)
        ));
        assert!(matches!(
            kit.pending_history_requests("missing".into()).await,
            Err(MarmotKitError::HistoryTransferUnsupported)
        ));
        assert!(matches!(
            kit.history_transfer_recipients("missing".into(), "invalid".into())
                .await,
            Err(MarmotKitError::HistoryTransferUnsupported)
        ));
        assert!(
            kit.runtime
                .accounts()
                .managed_accounts()
                .unwrap()
                .is_empty()
        );
        kit.runtime.shutdown_and_close().await.unwrap();
    }
}

#[cfg(all(test, feature = "experimental-device-sync"))]
mod recipient_tests {
    use super::*;
    #[tokio::test]
    async fn history_recipient_native_query_preserves_input_and_runtime_gates() {
        let dir = tempfile::tempdir().unwrap();
        let app = marmot_app::MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        for group in [String::new(), "invalid".into(), "ab".repeat(256)] {
            assert!(matches!(
                kit.history_transfer_recipients("missing".into(), group)
                    .await,
                Err(MarmotKitError::HistoryTransferNotReady)
            ));
        }
        assert!(matches!(
            kit.history_transfer_recipients("missing".into(), "ab".repeat(16))
                .await,
            Err(MarmotKitError::HistoryTransferRuntimeUnavailable)
        ));
        assert!(
            kit.runtime
                .accounts()
                .managed_accounts()
                .unwrap()
                .is_empty()
        );
        kit.runtime.shutdown_and_close().await.unwrap();
    }
}
