//! Thin entry points for automatically refreshed account chat views.
use crate::commands::account_chat_presentation::account_chat_read_error;
use crate::conversions::group_id_from_hex;
use crate::subscriptions::{
    AccountChatListWindowSubscription, AccountConversationWindowSubscription,
};
use crate::{Marmot, MarmotKitError};
use std::sync::Arc;

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Account-owned ordinary and paired-source rows, at most 2–128 retained.
    pub async fn open_account_chat_list_window(
        &self,
        account_ref: String,
        initial_rows: u32,
    ) -> Result<Arc<AccountChatListWindowSubscription>, MarmotKitError> {
        if !cfg!(feature = "experimental-device-sync") {
            return Err(MarmotKitError::AccountSharingUnsupported);
        }
        Ok(AccountChatListWindowSubscription::new(
            self.runtime
                .open_account_chat_list_window(&account_ref, initial_rows)
                .await
                .map_err(account_chat_read_error)?,
        ))
    }
    /// Account conversation observations, 1–128 rows, with an explicit source header.
    pub async fn open_account_conversation_window(
        &self,
        account_ref: String,
        group_id_hex: String,
        initial_rows: u32,
    ) -> Result<Arc<AccountConversationWindowSubscription>, MarmotKitError> {
        if !cfg!(feature = "experimental-device-sync") {
            return Err(MarmotKitError::AccountSharingUnsupported);
        }
        let group = group_id_from_hex(&group_id_hex)?;
        Ok(AccountConversationWindowSubscription::new(
            self.runtime
                .open_account_conversation_window(&account_ref, &group, initial_rows)
                .await
                .map_err(account_chat_read_error)?,
        ))
    }
}

#[cfg(test)]
mod tests;
