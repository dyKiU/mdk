//! Thin opaque native verification handles; all consent stays in the App actor.
use crate::conversions::{
    DeviceLinkingCapabilitiesFfi, DeviceLinkingOutgoingPacketFfi, DeviceLinkingSnapshotFfi,
};
use crate::{Marmot, MarmotKitError};
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct DeviceLinkingSession {
    inner: marmot_app::DeviceLinkingSession,
}
#[derive(uniffi::Object)]
pub struct DeviceLinkingSubscription {
    inner: marmot_app::DeviceLinkingSubscription,
}
#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Actual runtime capabilities; verification completion is never enrollment readiness.
    pub fn device_linking_capabilities(&self) -> DeviceLinkingCapabilitiesFfi {
        self.runtime.accounts().device_linking_capabilities().into()
    }
    /// Reserve the new device's original purpose and return an opaque verification session.
    pub async fn begin_device_linking_session(
        &self,
        account_ref: String,
    ) -> Result<Arc<DeviceLinkingSession>, MarmotKitError> {
        let inner = self
            .runtime
            .accounts()
            .begin_device_linking_session(&account_ref)
            .await?;
        Ok(Arc::new(DeviceLinkingSession { inner }))
    }
    /// Approve bounded setup metadata; no context, generation or proof is accepted.
    pub async fn approve_device_linking_session(
        &self,
        account_ref: String,
        request: Vec<u8>,
        target: Option<Vec<u8>>,
    ) -> Result<Arc<DeviceLinkingSession>, MarmotKitError> {
        let inner = self
            .runtime
            .accounts()
            .approve_device_linking_session(&account_ref, request, target)
            .await?;
        Ok(Arc::new(DeviceLinkingSession { inner }))
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl DeviceLinkingSession {
    /// Copy the original bounded setup packet; it cannot restore a live session.
    pub fn setup_packet(&self) -> Vec<u8> {
        self.inner.setup_packet()
    }
    /// Accept the approver's challenge under the original worker-owned purpose.
    pub async fn receive_setup_packet(&self, packet: Vec<u8>) -> Result<(), MarmotKitError> {
        Ok(self.inner.receive_setup_packet(packet).await?)
    }
    /// Read bounded SDK transport packets without consuming verifier permission.
    pub async fn outgoing_packets(
        &self,
    ) -> Result<Vec<DeviceLinkingOutgoingPacketFfi>, MarmotKitError> {
        Ok(self
            .inner
            .outgoing_packets()
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }
    /// Deliver a bounded original SDK packet; binding and role are actor-validated.
    pub async fn receive_packet(&self, packet: Vec<u8>) -> Result<(), MarmotKitError> {
        Ok(self.inner.receive_packet(packet).await?)
    }
    /// Acknowledge transport delivery only; this cannot approve enrollment.
    pub async fn acknowledge_packet(
        &self,
        acknowledgement_id: String,
    ) -> Result<(), MarmotKitError> {
        Ok(self.inner.acknowledge_packet(acknowledgement_id).await?)
    }
    /// Observe sanitized phase, displayed revision and standard SAS decimals.
    pub async fn snapshot(&self) -> Result<DeviceLinkingSnapshotFfi, MarmotKitError> {
        Ok(self.inner.snapshot().await?.into())
    }
    /// Explicit human confirmation of the revision actually displayed.
    pub async fn confirm_comparison(&self, displayed_revision: u64) -> Result<(), MarmotKitError> {
        Ok(self.inner.confirm_comparison(displayed_revision).await?)
    }
    /// Create an independently closeable coalesced observation stream.
    pub fn subscribe(&self) -> Arc<DeviceLinkingSubscription> {
        Arc::new(DeviceLinkingSubscription {
            inner: self.inner.subscribe(),
        })
    }
    /// Revoke this exact session before waiting for durable actor cleanup.
    pub async fn cancel(&self) -> Result<(), MarmotKitError> {
        Ok(self.inner.cancel().await?)
    }
    /// Enrollment remains gated; verification-only builds return NotReady.
    pub async fn continue_linking(&self, displayed_revision: u64) -> Result<(), MarmotKitError> {
        Ok(self.inner.continue_linking(displayed_revision).await?)
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl DeviceLinkingSubscription {
    /// Await an observation; explicit close wakes this call with a typed Closed error.
    pub async fn next(&self) -> Result<DeviceLinkingSnapshotFfi, MarmotKitError> {
        Ok(self.inner.next().await?.into())
    }
    /// Close this stream without granting permission or cancelling another session.
    pub fn close(&self) {
        self.inner.close();
    }
}

#[cfg(test)]
mod tests;
