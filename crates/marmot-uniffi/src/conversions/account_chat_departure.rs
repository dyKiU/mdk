//! Display-only departure status; never a synthetic group-management or MLS record.
use marmot_app as app;

#[derive(Clone, Copy, uniffi::Enum)]
pub enum AccountChatDepartureStatusFfi {
    Available,
    Pending,
    NeedsAdministrator,
    Completed,
    Unavailable,
}
#[derive(Clone, Copy, uniffi::Enum)]
pub enum AccountChatDepartureReasonFfi {
    None,
    AwaitingSources,
    AwaitingAdministrator,
    SharingUnavailable,
    NoAcceptedChat,
}
#[derive(Clone, uniffi::Record)]
pub struct AccountChatDepartureStateFfi {
    pub status: AccountChatDepartureStatusFfi,
    pub reason: AccountChatDepartureReasonFfi,
    pub operation_id: Option<String>,
}
redact!(AccountChatDepartureStateFfi);
impl From<app::AccountChatDepartureState> for AccountChatDepartureStateFfi {
    fn from(value: app::AccountChatDepartureState) -> Self {
        let status = match value.status {
            app::AccountChatDepartureStatus::Available => AccountChatDepartureStatusFfi::Available,
            app::AccountChatDepartureStatus::Pending => AccountChatDepartureStatusFfi::Pending,
            app::AccountChatDepartureStatus::NeedsAdministrator => {
                AccountChatDepartureStatusFfi::NeedsAdministrator
            }
            app::AccountChatDepartureStatus::Completed => AccountChatDepartureStatusFfi::Completed,
            app::AccountChatDepartureStatus::Unavailable => {
                AccountChatDepartureStatusFfi::Unavailable
            }
        };
        let reason = match value.reason {
            app::AccountChatDepartureReason::None => AccountChatDepartureReasonFfi::None,
            app::AccountChatDepartureReason::AwaitingSources => {
                AccountChatDepartureReasonFfi::AwaitingSources
            }
            app::AccountChatDepartureReason::AwaitingAdministrator => {
                AccountChatDepartureReasonFfi::AwaitingAdministrator
            }
            app::AccountChatDepartureReason::SharingUnavailable => {
                AccountChatDepartureReasonFfi::SharingUnavailable
            }
            app::AccountChatDepartureReason::NoAcceptedChat => {
                AccountChatDepartureReasonFfi::NoAcceptedChat
            }
        };
        Self {
            status,
            reason,
            operation_id: value.operation_id,
        }
    }
}
