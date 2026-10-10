//! Original exact-device actions; observations never recreate authority.
use crate::{DeviceRevocationSnapshotFfi, Marmot, MarmotKitError};
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct DeviceRevocation {
    inner: marmot_app::DeviceRevocation,
}

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Observe actual protected devices; the original factory independently revalidates selection.
    pub async fn device_revocation_targets(
        &self,
        account_ref: String,
    ) -> Result<crate::DeviceRevocationTargetsFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .device_revocation_targets(&account_ref)
            .await?
            .into())
    }

    /// Capture fresh authenticated groups for an exact linked device; requires explicit review.
    pub async fn begin_device_revocation(
        &self,
        account_ref: String,
        target_device: Vec<u8>,
    ) -> Result<Arc<DeviceRevocation>, MarmotKitError> {
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account_ref, target_device);
            Err(MarmotKitError::DeviceRevocationUnsupported)
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            if target_device.len() != 32 {
                return Err(MarmotKitError::DeviceRevocationInvalidSelection);
            }
            let inner = self
                .runtime
                .accounts()
                .begin_device_revocation(&account_ref, target_device)
                .await?;
            Ok(Arc::new(DeviceRevocation { inner }))
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl DeviceRevocation {
    /// Observe the fixed original scope and per-group confirmed progress.
    pub async fn snapshot(&self) -> Result<DeviceRevocationSnapshotFfi, MarmotKitError> {
        Ok(self.inner.snapshot().await?.into())
    }
    /// Explicitly approve only this held original at its displayed revision.
    pub async fn approve(&self, revision: u64) -> Result<(), MarmotKitError> {
        Ok(self.inner.approve(revision).await?)
    }
}
#[uniffi::export]
impl DeviceRevocation {
    /// Permanently retire this original action; cancellation cannot be undone by a record.
    pub fn cancel(&self) {
        self.inner.cancel();
    }
}

#[cfg(all(test, not(feature = "experimental-device-sync")))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn default_revocation_refuses_before_account_or_target_effects() {
        let dir = tempfile::tempdir().unwrap();
        let app = marmot_app::MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        assert!(matches!(
            kit.begin_device_revocation("missing".into(), vec![0; 65536])
                .await,
            Err(MarmotKitError::DeviceRevocationUnsupported)
        ));
        assert!(matches!(
            kit.device_revocation_targets("missing".into()).await,
            Err(MarmotKitError::DeviceRevocationUnsupported)
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
