use super::AppClient;
use crate::{
    AccountChatDepartureReason, AccountChatDepartureState, AccountChatDepartureStatus, AppError,
    GroupId,
};

impl AppClient {
    pub(crate) fn account_chat_departure_state(
        &self,
        group: &GroupId,
    ) -> Result<AccountChatDepartureState, AppError> {
        #[cfg(feature = "experimental-device-sync")]
        if let Some(state) = self.approved_account_chat_departure_state(group)? {
            return Ok(state);
        }
        // Account-wide departure requires genuine approved linked-device
        // coverage. Local MLS membership cannot prove an account-wide action.
        Ok(AccountChatDepartureState {
            status: AccountChatDepartureStatus::Unavailable,
            reason: AccountChatDepartureReason::SharingUnavailable,
            operation_id: None,
        })
    }

    pub(crate) async fn leave_account_chat(
        &mut self,
        group: &GroupId,
    ) -> Result<AccountChatDepartureState, AppError> {
        #[cfg(feature = "experimental-device-sync")]
        if let Some(state) = self.admit_account_chat_departure(group)? {
            return Ok(state);
        }
        // Keep device-only SelfRemove available through leave_group. This
        // explicit account-wide operation must refuse before any local effect.
        self.account_chat_departure_state(group)
    }
}
