//! Display metadata and bounded transport packets, never verifier authority.

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeviceLinkingCapabilitiesFfi {
    pub verification_supported: bool,
    pub enrollment_supported: bool,
}
impl From<marmot_app::DeviceLinkingCapabilities> for DeviceLinkingCapabilitiesFfi {
    fn from(value: marmot_app::DeviceLinkingCapabilities) -> Self {
        Self {
            verification_supported: value.verification_supported,
            enrollment_supported: value.enrollment_supported,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeviceLinkingDecimalsFfi {
    pub first: u16,
    pub second: u16,
    pub third: u16,
}
impl From<marmot_app::DeviceLinkingDecimals> for DeviceLinkingDecimalsFfi {
    fn from(value: marmot_app::DeviceLinkingDecimals) -> Self {
        Self {
            first: value.first,
            second: value.second,
            third: value.third,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeviceLinkingSnapshotFfi {
    pub revision: u64,
    pub phase: DeviceLinkingPhaseFfi,
    pub decimals: Option<DeviceLinkingDecimalsFfi>,
}
impl From<marmot_app::DeviceLinkingSnapshot> for DeviceLinkingSnapshotFfi {
    fn from(value: marmot_app::DeviceLinkingSnapshot) -> Self {
        Self {
            revision: value.revision,
            phase: value.phase.into(),
            decimals: value.decimals.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeviceLinkingOutgoingPacketFfi {
    pub acknowledgement_id: String,
    pub bytes: Vec<u8>,
}
impl From<marmot_app::DeviceLinkingOutgoingPacket> for DeviceLinkingOutgoingPacketFfi {
    fn from(value: marmot_app::DeviceLinkingOutgoingPacket) -> Self {
        Self {
            acknowledgement_id: value.acknowledgement_id,
            bytes: value.bytes,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DeviceLinkingPhaseFfi {
    AwaitingSetup,
    AwaitingPeer,
    ComparisonAvailable,
    AwaitingPeerVerification,
    VerificationCompleteEnrollmentPending,
    Cancelled,
    Expired,
    Failed,
    EnrollmentComplete,
}
impl From<marmot_app::DeviceLinkingPhase> for DeviceLinkingPhaseFfi {
    fn from(value: marmot_app::DeviceLinkingPhase) -> Self {
        match value {
            marmot_app::DeviceLinkingPhase::AwaitingSetup => Self::AwaitingSetup,
            marmot_app::DeviceLinkingPhase::AwaitingPeer => Self::AwaitingPeer,
            marmot_app::DeviceLinkingPhase::ComparisonAvailable => Self::ComparisonAvailable,
            marmot_app::DeviceLinkingPhase::AwaitingPeerVerification => {
                Self::AwaitingPeerVerification
            }
            marmot_app::DeviceLinkingPhase::VerificationCompleteEnrollmentPending => {
                Self::VerificationCompleteEnrollmentPending
            }
            marmot_app::DeviceLinkingPhase::Cancelled => Self::Cancelled,
            marmot_app::DeviceLinkingPhase::Expired => Self::Expired,
            marmot_app::DeviceLinkingPhase::Failed => Self::Failed,
            marmot_app::DeviceLinkingPhase::EnrollmentComplete => Self::EnrollmentComplete,
        }
    }
}

/// Observed protected roster selector; never enrollment authority.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeviceLinkingTargetFfi {
    pub selector: Vec<u8>,
    pub device_count: u32,
}
impl From<marmot_app::DeviceLinkingTarget> for DeviceLinkingTargetFfi {
    fn from(value: marmot_app::DeviceLinkingTarget) -> Self {
        Self {
            selector: value.selector,
            device_count: value.device_count,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DeviceLinkingApprovalPhaseFfi {
    AwaitingApproval,
    ApprovedAwaitingPacket,
    AwaitingSettlement,
    Settled,
    Cancelled,
    Expired,
}
impl From<marmot_app::DeviceLinkingApprovalPhase> for DeviceLinkingApprovalPhaseFfi {
    fn from(value: marmot_app::DeviceLinkingApprovalPhase) -> Self {
        use marmot_app::DeviceLinkingApprovalPhase as Phase;
        match value {
            Phase::AwaitingApproval => Self::AwaitingApproval,
            Phase::ApprovedAwaitingPacket => Self::ApprovedAwaitingPacket,
            Phase::AwaitingSettlement => Self::AwaitingSettlement,
            Phase::Settled => Self::Settled,
            Phase::Cancelled => Self::Cancelled,
            Phase::Expired => Self::Expired,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeviceLinkingApprovalSnapshotFfi {
    pub revision: u64,
    pub phase: DeviceLinkingApprovalPhaseFfi,
}
impl From<marmot_app::DeviceLinkingApprovalSnapshot> for DeviceLinkingApprovalSnapshotFfi {
    fn from(value: marmot_app::DeviceLinkingApprovalSnapshot) -> Self {
        Self {
            revision: value.revision,
            phase: value.phase.into(),
        }
    }
}

/// Authenticated display metadata; copying it grants no enrollment authority.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DeviceLinkingApprovalReviewMetadataFfi {
    pub revision: u64,
    pub source_device_public_key: Vec<u8>,
    pub joining_device_public_key: Vec<u8>,
    pub existing_device_count: u32,
}
impl From<marmot_app::DeviceLinkingApprovalReviewMetadata>
    for DeviceLinkingApprovalReviewMetadataFfi
{
    fn from(value: marmot_app::DeviceLinkingApprovalReviewMetadata) -> Self {
        Self {
            revision: value.revision,
            source_device_public_key: value.source_device_public_key,
            joining_device_public_key: value.joining_device_public_key,
            existing_device_count: value.existing_device_count,
        }
    }
}
