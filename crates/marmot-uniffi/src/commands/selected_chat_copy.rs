//! Opaque selected-chat request and consent objects; App owns every lease and admission check.
use crate::{Marmot, MarmotKitError, SelectedChatConsentSnapshotFfi, SelectedChatCopySnapshotFfi};
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct SelectedChatCopy {
    inner: marmot_app::SelectedChatCopy,
}
#[derive(uniffi::Object)]
pub struct SelectedChatConsent {
    inner: marmot_app::SelectedChatConsent,
}

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Request one ordinary chat for a fresh protected roster; explicit sibling consent is separate.
    pub async fn begin_selected_chat_copy(
        &self,
        account_ref: String,
        group_id_hex: String,
        linked_roster_selector: Vec<u8>,
    ) -> Result<Arc<SelectedChatCopy>, MarmotKitError> {
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account_ref, group_id_hex, linked_roster_selector);
            Err(MarmotKitError::SelectedChatCopyUnsupported)
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            let group = crate::conversions::group_id_from_hex(&group_id_hex)
                .map_err(|_| MarmotKitError::SelectedChatCopyInvalidSelection)?;
            let inner = self
                .runtime
                .accounts()
                .begin_selected_chat_copy(&account_ref, &group, linked_roster_selector)
                .await?;
            Ok(Arc::new(SelectedChatCopy { inner }))
        }
    }
    /// Import bounded request metadata; importing never approves the displayed chat.
    pub async fn receive_selected_chat_copy_request(
        &self,
        account_ref: String,
        packet: Vec<u8>,
    ) -> Result<Arc<SelectedChatConsent>, MarmotKitError> {
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account_ref, packet);
            Err(MarmotKitError::SelectedChatCopyUnsupported)
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            let inner = self
                .runtime
                .accounts()
                .receive_selected_chat_copy_request(&account_ref, packet)
                .await?;
            Ok(Arc::new(SelectedChatConsent { inner }))
        }
    }
}

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl SelectedChatCopy {
    /// Forward snapshot to this exact original App owner.
    pub async fn snapshot(&self) -> Result<SelectedChatCopySnapshotFfi, MarmotKitError> {
        Ok(self.inner.snapshot().await?.into())
    }
    /// Forward request packet to this exact original App owner.
    pub async fn request_packet(&self, revision: u64) -> Result<Vec<u8>, MarmotKitError> {
        Ok(self.inner.request_packet(revision).await?)
    }
    /// Forward receive consent packet to this exact original App owner.
    pub async fn receive_consent_packet(
        &self,
        revision: u64,
        packet: Vec<u8>,
    ) -> Result<(), MarmotKitError> {
        Ok(self.inner.receive_consent_packet(revision, packet).await?)
    }
    /// Forward receive offer packet to this exact original App owner.
    pub async fn receive_offer_packet(
        &self,
        revision: u64,
        packet: Vec<u8>,
    ) -> Result<(), MarmotKitError> {
        Ok(self.inner.receive_offer_packet(revision, packet).await?)
    }
    /// Forward continue copy to this exact original App owner.
    pub async fn continue_copy(&self, revision: u64) -> Result<(), MarmotKitError> {
        Ok(self.inner.continue_copy(revision).await?)
    }
    /// Forward cancel to this exact original App owner.
    pub async fn cancel(&self) -> Result<(), MarmotKitError> {
        Ok(self.inner.cancel().await?)
    }
}

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl SelectedChatConsent {
    /// Forward snapshot to this exact original App owner.
    pub async fn snapshot(&self) -> Result<SelectedChatConsentSnapshotFfi, MarmotKitError> {
        Ok(self.inner.snapshot().await?.into())
    }
    /// Forward approve to this exact original App owner.
    pub async fn approve(&self, revision: u64) -> Result<(), MarmotKitError> {
        Ok(self.inner.approve(revision).await?)
    }
    /// Forward response packet to this exact original App owner.
    pub async fn response_packet(&self, revision: u64) -> Result<Vec<u8>, MarmotKitError> {
        Ok(self.inner.response_packet(revision).await?)
    }
    /// Forward offer packet to this exact original App owner.
    pub async fn offer_packet(&self, revision: u64) -> Result<Vec<u8>, MarmotKitError> {
        Ok(self.inner.offer_packet(revision).await?)
    }
    /// Forward cancel to this exact original App owner.
    pub async fn cancel(&self) -> Result<(), MarmotKitError> {
        Ok(self.inner.cancel().await?)
    }
}

#[cfg(test)]
mod tests;
