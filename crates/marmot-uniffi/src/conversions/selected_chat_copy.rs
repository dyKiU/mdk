//! Selected-chat display observations; these records do not grant consent or membership.

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SelectedChatCopySnapshotFfi {
    pub revision: u64,
    pub phase: SelectedChatCopyPhaseFfi,
    pub sibling_count: u32,
    pub consenting_sibling_count: u32,
    pub offered_sibling_count: u32,
}
impl From<marmot_app::SelectedChatCopySnapshot> for SelectedChatCopySnapshotFfi {
    fn from(value: marmot_app::SelectedChatCopySnapshot) -> Self {
        Self {
            revision: value.revision,
            phase: value.phase.into(),
            sibling_count: value.sibling_count,
            consenting_sibling_count: value.consenting_sibling_count,
            offered_sibling_count: value.offered_sibling_count,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SelectedChatConsentSnapshotFfi {
    pub revision: u64,
    pub phase: SelectedChatConsentPhaseFfi,
    pub chat_selector: Vec<u8>,
}
impl From<marmot_app::SelectedChatConsentSnapshot> for SelectedChatConsentSnapshotFfi {
    fn from(value: marmot_app::SelectedChatConsentSnapshot) -> Self {
        Self {
            revision: value.revision,
            phase: value.phase.into(),
            chat_selector: value.chat_selector,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SelectedChatCopyPhaseFfi {
    AwaitingSiblingConsent,
    Cancelled,
    Expired,
    Closed,
    InviteConfirmed,
}
impl From<marmot_app::SelectedChatCopyPhase> for SelectedChatCopyPhaseFfi {
    fn from(value: marmot_app::SelectedChatCopyPhase) -> Self {
        match value {
            marmot_app::SelectedChatCopyPhase::AwaitingSiblingConsent => {
                Self::AwaitingSiblingConsent
            }
            marmot_app::SelectedChatCopyPhase::Cancelled => Self::Cancelled,
            marmot_app::SelectedChatCopyPhase::Expired => Self::Expired,
            marmot_app::SelectedChatCopyPhase::Closed => Self::Closed,
            marmot_app::SelectedChatCopyPhase::InviteConfirmed => Self::InviteConfirmed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SelectedChatConsentPhaseFfi {
    AwaitingApproval,
    Approved,
    Cancelled,
    Expired,
    Closed,
}
impl From<marmot_app::SelectedChatConsentPhase> for SelectedChatConsentPhaseFfi {
    fn from(value: marmot_app::SelectedChatConsentPhase) -> Self {
        match value {
            marmot_app::SelectedChatConsentPhase::AwaitingApproval => Self::AwaitingApproval,
            marmot_app::SelectedChatConsentPhase::Approved => Self::Approved,
            marmot_app::SelectedChatConsentPhase::Cancelled => Self::Cancelled,
            marmot_app::SelectedChatConsentPhase::Expired => Self::Expired,
            marmot_app::SelectedChatConsentPhase::Closed => Self::Closed,
        }
    }
}
