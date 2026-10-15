use crate::conversions::group_id_from_hex;
use crate::{Marmot, MarmotKitError, conversions::AccountChatDepartureStateFfi};

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Genuine local/paired-source readiness; does not require mirrored chats to
    /// pretend they have local MLS management state. Errors remain errors.
    pub async fn account_chat_departure_state(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<AccountChatDepartureStateFfi, MarmotKitError> {
        let group = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .account_chat_departure_state(&account_ref, &group)
            .await?
            .into())
    }
    /// Explicit account-wide negative intent. Pending is not actual remote MLS
    /// departure; administrators must use their ordinary management workflow.
    pub async fn leave_account_chat(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<AccountChatDepartureStateFfi, MarmotKitError> {
        let group = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .leave_account_chat(&account_ref, &group)
            .await?
            .into())
    }
}

#[cfg(all(test, feature = "experimental-device-sync"))]
mod tests;
