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
        let storage = self.app.account_storage(&self.state.label)?;
        let status = match storage.get_group(group) {
            Err(cgka_traits::storage::StorageError::NotFound) => {
                AccountChatDepartureStatus::Unavailable
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {
                let canonical = self
                    .runtime
                    .session()
                    .canonical_group_membership(group)
                    .map_err(cgka_session::SessionError::from)?;
                if canonical.local_leaf_active {
                    let authority = self
                        .runtime
                        .session()
                        .group_authority(group)
                        .map_err(cgka_session::SessionError::from)?;
                    if authority.facts.is_admin {
                        AccountChatDepartureStatus::NeedsAdministrator
                    } else {
                        AccountChatDepartureStatus::Available
                    }
                } else {
                    AccountChatDepartureStatus::Completed
                }
            }
        };
        Ok(AccountChatDepartureState {
            status,
            reason: match status {
                AccountChatDepartureStatus::NeedsAdministrator => {
                    AccountChatDepartureReason::AwaitingAdministrator
                }
                AccountChatDepartureStatus::Unavailable => {
                    AccountChatDepartureReason::NoAcceptedChat
                }
                _ => AccountChatDepartureReason::None,
            },
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
        let before = self.account_chat_departure_state(group)?;
        if before.status != AccountChatDepartureStatus::Available {
            return Ok(before);
        }
        // Without an approved linked-account policy the established public
        // device-local SelfRemove remains the ordinary interoperable operation.
        Box::pin(self.leave_group(group)).await?;
        Ok(AccountChatDepartureState {
            status: AccountChatDepartureStatus::Pending,
            reason: AccountChatDepartureReason::None,
            operation_id: None,
        })
    }
}
