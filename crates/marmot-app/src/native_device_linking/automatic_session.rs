//! Role-neutral host handle. The backend adopts one genuine SDK original only
//! after transport negotiation, and exposes the existing revision-bound checks.
use super::*;

pub struct AutomaticDeviceLinkingSession {
    #[cfg(feature = "experimental-device-sync")]
    pub(super) inner: std::sync::Arc<enabled::negotiated::State>,
    #[cfg(not(feature = "experimental-device-sync"))]
    inner: DeviceLinkingSession,
}
impl AutomaticDeviceLinkingSession {
    #[cfg(all(
        test,
        feature = "experimental-device-sync",
        feature = "test-policy-overrides"
    ))]
    pub(super) async fn original_for_test(&self) -> std::sync::Arc<DeviceLinkingSession> {
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if let Some(original) = self.inner.original_for_test() {
                    return original;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("negotiation must adopt a genuine original")
    }

    pub async fn automatic_pairing_code(&self) -> Result<String, DeviceLinkingError> {
        self.inner.automatic_pairing_code().await
    }
    pub fn setup_packet(&self) -> Vec<u8> {
        self.inner.setup_packet()
    }
    pub async fn snapshot(&self) -> Result<DeviceLinkingSnapshot, DeviceLinkingError> {
        self.inner.snapshot().await
    }
    pub fn subscribe(&self) -> DeviceLinkingSubscription {
        self.inner.subscribe()
    }
    pub async fn confirm_comparison(&self, revision: u64) -> Result<(), DeviceLinkingError> {
        self.inner.confirm_comparison(revision).await
    }
    pub async fn continue_automatic_linking(
        &self,
        revision: u64,
        share_chats: bool,
    ) -> Result<(), DeviceLinkingError> {
        self.inner
            .continue_automatic_linking(revision, share_chats)
            .await
    }
    pub async fn cancel(&self) -> Result<(), DeviceLinkingError> {
        self.inner.cancel().await
    }
}
#[cfg(feature = "experimental-device-sync")]
impl Drop for AutomaticDeviceLinkingSession {
    fn drop(&mut self) {
        self.inner.close();
    }
}
#[cfg(not(feature = "experimental-device-sync"))]
impl AccountManager {
    pub async fn begin_automatic_device_linking_session(
        &self,
        _account_ref: &str,
    ) -> Result<AutomaticDeviceLinkingSession, DeviceLinkingError> {
        Err(DeviceLinkingError::Unsupported)
    }
    pub async fn scan_automatic_device_linking_session(
        &self,
        _account_ref: &str,
        _code: String,
    ) -> Result<AutomaticDeviceLinkingSession, DeviceLinkingError> {
        Err(DeviceLinkingError::Unsupported)
    }
}
