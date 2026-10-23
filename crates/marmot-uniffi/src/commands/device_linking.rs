//! Thin opaque native linking handles; all consent stays in the App actor.
use crate::conversions::{
    DeviceLinkingApprovalSnapshotFfi, DeviceLinkingCapabilitiesFfi, DeviceLinkingOutgoingPacketFfi,
    DeviceLinkingSnapshotFfi, DeviceLinkingTargetFfi,
};
use crate::{Marmot, MarmotKitError};
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct DeviceLinkingSession {
    inner: Session,
}
enum Session {
    Direct(marmot_app::DeviceLinkingSession),
    Automatic(marmot_app::AutomaticDeviceLinkingSession),
}
impl DeviceLinkingSession {
    fn direct(&self) -> Result<&marmot_app::DeviceLinkingSession, MarmotKitError> {
        match &self.inner {
            Session::Direct(inner) => Ok(inner),
            Session::Automatic(_) => Err(marmot_app::DeviceLinkingError::NotReady.into()),
        }
    }
}
#[derive(uniffi::Object)]
pub struct DeviceLinkingApproval {
    inner: marmot_app::DeviceLinkingApproval,
}
#[derive(uniffi::Object)]
pub struct DeviceLinkingSubscription {
    inner: marmot_app::DeviceLinkingSubscription,
}
#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Display one transport QR without assigning the installation a new-device role.
    pub async fn begin_automatic_device_linking_session(
        &self,
        account_ref: String,
    ) -> Result<Arc<DeviceLinkingSession>, MarmotKitError> {
        let inner = self
            .runtime
            .accounts()
            .begin_automatic_device_linking_session(&account_ref)
            .await?;
        Ok(Arc::new(DeviceLinkingSession {
            inner: Session::Automatic(inner),
        }))
    }
    /// Scan either transport direction; Core selects and retains the genuine enrollment original.
    pub async fn scan_automatic_device_linking_session(
        &self,
        account_ref: String,
        code: String,
    ) -> Result<Arc<DeviceLinkingSession>, MarmotKitError> {
        let inner = self
            .runtime
            .accounts()
            .scan_automatic_device_linking_session(&account_ref, code)
            .await?;
        Ok(Arc::new(DeviceLinkingSession {
            inner: Session::Automatic(inner),
        }))
    }
    /// Scan one bounded bootstrap; the returned original is paused until host adoption.
    pub async fn approve_automatic_device_linking_session(
        &self,
        account_ref: String,
        code: String,
        target: Option<Vec<u8>>,
    ) -> Result<Arc<DeviceLinkingSession>, MarmotKitError> {
        let inner = self
            .runtime
            .accounts()
            .approve_automatic_device_linking_session(&account_ref, code, target)
            .await?;
        Ok(Arc::new(DeviceLinkingSession {
            inner: Session::Direct(inner),
        }))
    }
    /// Actual runtime capabilities; verification completion is never enrollment readiness.
    pub fn device_linking_capabilities(&self) -> DeviceLinkingCapabilitiesFfi {
        self.runtime.accounts().device_linking_capabilities().into()
    }
    /// Observe protected roster selectors; the actor revalidates any selected target.
    pub async fn device_linking_targets(
        &self,
        account_ref: String,
    ) -> Result<Vec<DeviceLinkingTargetFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .device_linking_targets(&account_ref)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }
    /// Return opaque handles sharing each original existing-device approval action.
    pub async fn pending_device_linking_approvals(
        &self,
        account_ref: String,
    ) -> Result<Vec<Arc<DeviceLinkingApproval>>, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .pending_device_linking_approvals(&account_ref)
            .await?
            .into_iter()
            .map(|inner| Arc::new(DeviceLinkingApproval { inner }))
            .collect())
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
        Ok(Arc::new(DeviceLinkingSession {
            inner: Session::Direct(inner),
        }))
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
        Ok(Arc::new(DeviceLinkingSession {
            inner: Session::Direct(inner),
        }))
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl DeviceLinkingSession {
    /// Activate only after exact host account-scope adoption. Display this compact
    /// bootstrap only on the initiating device; the scanner needs no response QR.
    pub async fn automatic_pairing_code(&self) -> Result<String, MarmotKitError> {
        Ok(match &self.inner {
            Session::Direct(inner) => inner.automatic_pairing_code().await?,
            Session::Automatic(inner) => inner.automatic_pairing_code().await?,
        })
    }
    /// Explicit comparison-complete enrollment choice. Native transport forwards
    /// packets and receipts; this never confirms comparison or sibling approvals.
    pub async fn continue_automatic_linking(
        &self,
        displayed_revision: u64,
        share_chats: bool,
    ) -> Result<(), MarmotKitError> {
        Ok(match &self.inner {
            Session::Direct(inner) => {
                inner
                    .continue_automatic_linking(displayed_revision, share_chats)
                    .await?
            }
            Session::Automatic(inner) => {
                inner
                    .continue_automatic_linking(displayed_revision, share_chats)
                    .await?
            }
        })
    }
    /// Copy the original bounded setup packet; it cannot restore a live session.
    pub fn setup_packet(&self) -> Vec<u8> {
        match &self.inner {
            Session::Direct(inner) => inner.setup_packet(),
            Session::Automatic(inner) => inner.setup_packet(),
        }
    }
    /// Accept the approver's challenge under the original worker-owned purpose.
    pub async fn receive_setup_packet(&self, packet: Vec<u8>) -> Result<(), MarmotKitError> {
        Ok(self.direct()?.receive_setup_packet(packet).await?)
    }
    /// Read bounded SDK transport packets without consuming verifier permission.
    pub async fn outgoing_packets(
        &self,
    ) -> Result<Vec<DeviceLinkingOutgoingPacketFfi>, MarmotKitError> {
        Ok(self
            .direct()?
            .outgoing_packets()
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }
    /// Deliver a bounded original SDK packet; binding and role are actor-validated.
    pub async fn receive_packet(&self, packet: Vec<u8>) -> Result<(), MarmotKitError> {
        Ok(self.direct()?.receive_packet(packet).await?)
    }
    /// Acknowledge transport delivery only; this cannot approve enrollment.
    pub async fn acknowledge_packet(
        &self,
        acknowledgement_id: String,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .direct()?
            .acknowledge_packet(acknowledgement_id)
            .await?)
    }
    /// Observe sanitized phase, displayed revision and standard SAS decimals.
    pub async fn snapshot(&self) -> Result<DeviceLinkingSnapshotFfi, MarmotKitError> {
        Ok(match &self.inner {
            Session::Direct(inner) => inner.snapshot().await?,
            Session::Automatic(inner) => inner.snapshot().await?,
        }
        .into())
    }
    /// Explicit human confirmation of the revision actually displayed.
    pub async fn confirm_comparison(&self, displayed_revision: u64) -> Result<(), MarmotKitError> {
        Ok(match &self.inner {
            Session::Direct(inner) => inner.confirm_comparison(displayed_revision).await?,
            Session::Automatic(inner) => inner.confirm_comparison(displayed_revision).await?,
        })
    }
    /// Create an independently closeable coalesced observation stream.
    pub fn subscribe(&self) -> Arc<DeviceLinkingSubscription> {
        Arc::new(DeviceLinkingSubscription {
            inner: match &self.inner {
                Session::Direct(inner) => inner.subscribe(),
                Session::Automatic(inner) => inner.subscribe(),
            },
        })
    }
    /// Export the bounded complete all-leaf packet before the original lease transfers.
    pub async fn enrollment_packet(
        &self,
        displayed_revision: u64,
    ) -> Result<Vec<u8>, MarmotKitError> {
        Ok(self.direct()?.enrollment_packet(displayed_revision).await?)
    }
    /// Validate enrollment bytes under the original recipient action, without host authority.
    pub async fn receive_enrollment_packet(
        &self,
        displayed_revision: u64,
        packet: Vec<u8>,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .direct()?
            .receive_enrollment_packet(displayed_revision, packet)
            .await?)
    }
    /// Explicitly finalize the original approver action after recipient packet handling.
    pub async fn finalize_linking(&self, displayed_revision: u64) -> Result<(), MarmotKitError> {
        Ok(self.direct()?.finalize_linking(displayed_revision).await?)
    }
    /// Revoke this exact session before waiting for durable actor cleanup.
    pub async fn cancel(&self) -> Result<(), MarmotKitError> {
        Ok(match &self.inner {
            Session::Direct(inner) => inner.cancel().await?,
            Session::Automatic(inner) => inner.cancel().await?,
        })
    }
    /// Explicitly approve sharing existing/future chats, history and messaging
    /// while continuing this exact original pairing action. Retained metadata
    /// and ordinary linking completion cannot grant this policy.
    pub async fn continue_linking_and_share_chats(
        &self,
        displayed_revision: u64,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .direct()?
            .continue_linking_and_share_chats(displayed_revision)
            .await?)
    }
    /// Continue original singleton actions after genuine verification of the displayed revision.
    pub async fn continue_linking(&self, displayed_revision: u64) -> Result<(), MarmotKitError> {
        Ok(self.direct()?.continue_linking(displayed_revision).await?)
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl DeviceLinkingApproval {
    /// Read authenticated display metadata for this original pending approval and displayed revision.
    pub async fn review_metadata(
        &self,
        displayed_revision: u64,
    ) -> Result<crate::DeviceLinkingApprovalReviewMetadataFfi, MarmotKitError> {
        Ok(self.inner.review_metadata(displayed_revision).await?.into())
    }
    /// Finite observation of the exact original existing-device action.
    pub async fn snapshot(&self) -> Result<DeviceLinkingApprovalSnapshotFfi, MarmotKitError> {
        Ok(self.inner.snapshot().await?.into())
    }
    /// Explicit human approval bound to the revision displayed on this device.
    pub async fn approve(&self, displayed_revision: u64) -> Result<(), MarmotKitError> {
        Ok(self.inner.approve(displayed_revision).await?)
    }
    /// Approve this original enrollment and sharing existing and future chats
    /// with the joining device. Ordinary approval cannot be upgraded later.
    pub async fn approve_and_share_chats(
        &self,
        displayed_revision: u64,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .inner
            .approve_and_share_chats(displayed_revision)
            .await?)
    }
    /// Validate the complete packet through the same original approval action.
    pub async fn receive_enrollment_packet(
        &self,
        displayed_revision: u64,
        packet: Vec<u8>,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .inner
            .receive_enrollment_packet(displayed_revision, packet)
            .await?)
    }
    /// Revoke the exact original action; cancellation cannot be undone by packet replay.
    pub async fn cancel(&self) -> Result<(), MarmotKitError> {
        Ok(self.inner.cancel().await?)
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl DeviceLinkingSubscription {
    /// Await an observation; explicit close wakes this call with a typed Closed error.
    pub async fn next(&self) -> Result<DeviceLinkingSnapshotFfi, MarmotKitError> {
        Ok(self.inner.next().await?.into())
    }
    /// Close this stream without granting permission or cancelling another session.
    /// Foreign hosts use closeStream, distinct from Kotlin object disposal's close.
    #[uniffi::method(name = "close_stream")]
    pub fn close(&self) {
        self.inner.close();
    }
}

#[cfg(test)]
mod tests;
