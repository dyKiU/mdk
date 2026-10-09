//! Native verification sessions expose packets and observations, never pairing proofs.
use crate::runtime::AccountManager;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceLinkingCapabilities {
    pub verification_supported: bool,
    pub enrollment_supported: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceLinkingDecimals {
    pub first: u16,
    pub second: u16,
    pub third: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceLinkingPhase {
    AwaitingSetup,
    AwaitingPeer,
    ComparisonAvailable,
    AwaitingPeerVerification,
    VerificationCompleteEnrollmentPending,
    Cancelled,
    Expired,
    Failed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceLinkingSnapshot {
    pub revision: u64,
    pub phase: DeviceLinkingPhase,
    pub decimals: Option<DeviceLinkingDecimals>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceLinkingOutgoingPacket {
    pub acknowledgement_id: String,
    pub bytes: Vec<u8>,
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeviceLinkingError {
    #[error("Device verification is not supported by this build")]
    Unsupported,
    #[error("Device verification session is closed")]
    Closed,
    #[error("Invalid device verification packet")]
    InvalidPacket,
    #[error("Device verification is not ready for this action")]
    NotReady,
    #[error("The displayed device verification state is stale")]
    StaleRevision,
    #[error("Device verification runtime is unavailable")]
    RuntimeUnavailable,
}

pub struct DeviceLinkingSession {
    #[cfg(not(feature = "experimental-device-sync"))]
    _private: (),
    #[cfg(feature = "experimental-device-sync")]
    inner: std::sync::Arc<enabled::SessionState>,
}
pub struct DeviceLinkingSubscription {
    #[cfg(not(feature = "experimental-device-sync"))]
    _private: (),
    #[cfg(feature = "experimental-device-sync")]
    inner: enabled::SubscriptionState,
}

impl AccountManager {
    pub fn device_linking_capabilities(&self) -> DeviceLinkingCapabilities {
        DeviceLinkingCapabilities {
            verification_supported: cfg!(feature = "experimental-device-sync"),
            enrollment_supported: false,
        }
    }
}

#[cfg(not(feature = "experimental-device-sync"))]
impl AccountManager {
    pub async fn begin_device_linking_session(
        &self,
        _account_ref: &str,
    ) -> Result<DeviceLinkingSession, DeviceLinkingError> {
        Err(DeviceLinkingError::Unsupported)
    }
    pub async fn approve_device_linking_session(
        &self,
        _account_ref: &str,
        _request: Vec<u8>,
        _target: Option<Vec<u8>>,
    ) -> Result<DeviceLinkingSession, DeviceLinkingError> {
        Err(DeviceLinkingError::Unsupported)
    }
}
#[cfg(not(feature = "experimental-device-sync"))]
impl DeviceLinkingSession {
    pub fn setup_packet(&self) -> Vec<u8> {
        Vec::new()
    }
    pub async fn receive_setup_packet(&self, _packet: Vec<u8>) -> Result<(), DeviceLinkingError> {
        Err(DeviceLinkingError::Unsupported)
    }
    pub async fn outgoing_packets(
        &self,
    ) -> Result<Vec<DeviceLinkingOutgoingPacket>, DeviceLinkingError> {
        Err(DeviceLinkingError::Unsupported)
    }
    pub async fn receive_packet(&self, _packet: Vec<u8>) -> Result<(), DeviceLinkingError> {
        Err(DeviceLinkingError::Unsupported)
    }
    pub async fn acknowledge_packet(&self, _id: String) -> Result<(), DeviceLinkingError> {
        Err(DeviceLinkingError::Unsupported)
    }
    pub async fn snapshot(&self) -> Result<DeviceLinkingSnapshot, DeviceLinkingError> {
        Err(DeviceLinkingError::Unsupported)
    }
    pub async fn confirm_comparison(&self, _revision: u64) -> Result<(), DeviceLinkingError> {
        Err(DeviceLinkingError::Unsupported)
    }
    pub fn subscribe(&self) -> DeviceLinkingSubscription {
        DeviceLinkingSubscription { _private: () }
    }
    pub async fn cancel(&self) -> Result<(), DeviceLinkingError> {
        Err(DeviceLinkingError::Unsupported)
    }
    pub async fn continue_linking(&self, _revision: u64) -> Result<(), DeviceLinkingError> {
        Err(DeviceLinkingError::Unsupported)
    }
}
#[cfg(not(feature = "experimental-device-sync"))]
impl DeviceLinkingSubscription {
    pub async fn next(&self) -> Result<DeviceLinkingSnapshot, DeviceLinkingError> {
        Err(DeviceLinkingError::Unsupported)
    }
    pub fn close(&self) {}
}

#[cfg(all(
    test,
    any(
        not(feature = "experimental-device-sync"),
        feature = "test-policy-overrides"
    )
))]
mod tests;

#[cfg(feature = "experimental-device-sync")]
mod enabled;
