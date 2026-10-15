//! Bounded read-only views of authenticated paired observations.
use crate::conversions::{
    ExistingAccountDirectConversationFfi, PairedChatListPageFfi, PairedChatMessageCursorFfi,
    PairedChatMessagePageFfi, group_id_from_hex,
};
use crate::{Marmot, MarmotKitError};

pub(crate) fn account_chat_read_error(error: marmot_app::AccountChatReadError) -> MarmotKitError {
    use marmot_app::AccountChatReadError as E;
    match error {
        E::Unsupported => MarmotKitError::AccountSharingUnsupported,
        E::InvalidQuery => MarmotKitError::SynchronizedHistoryInvalidQuery,
        E::NotReady => MarmotKitError::AccountSharingNotReady,
        E::StaleWindow => MarmotKitError::ChatWindowStale,
        E::Closed => MarmotKitError::AccountSharingClosed,
        E::RuntimeUnavailable => MarmotKitError::AccountSharingRuntimeUnavailable,
        E::InvalidRecord => MarmotKitError::SynchronizedHistoryInvalidRecord,
    }
}
pub(crate) fn paired_cursor(
    value: PairedChatMessageCursorFfi,
) -> Result<marmot_app::PairedChatMessageCursor, MarmotKitError> {
    let event_id = hex::decode(&value.message_id_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(MarmotKitError::SynchronizedHistoryInvalidQuery)?;
    Ok(marmot_app::PairedChatMessageCursor {
        created_at: value.created_at,
        event_id,
    })
}
#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Resolve an existing contact conversation without creating an invitation.
    /// Local MLS reuse has precedence; paired routes require current sharing approval.
    pub async fn existing_account_direct_conversation(
        &self,
        account_ref: String,
        peer_account_id: String,
    ) -> Result<Option<ExistingAccountDirectConversationFfi>, MarmotKitError> {
        self.runtime
            .existing_account_direct_conversation(&account_ref, &peer_account_id)
            .await
            .map(|row| row.map(Into::into))
            .map_err(account_chat_read_error)
    }

    /// Bounded paired-source chat catalog. No membership, media or send authority is reconstructed.
    pub async fn paired_chat_list_page(
        &self,
        account_ref: String,
        after_group_id_hex: Option<String>,
        limit: u32,
    ) -> Result<PairedChatListPageFfi, MarmotKitError> {
        if !cfg!(feature = "experimental-device-sync") {
            return Err(MarmotKitError::AccountSharingUnsupported);
        }
        let after = after_group_id_hex
            .map(|value| group_id_from_hex(&value))
            .transpose()?;
        Ok(self
            .runtime
            .accounts()
            .paired_chat_list_page(&account_ref, after, limit)
            .await
            .map_err(account_chat_read_error)?
            .into())
    }
    /// Canonical bounded message observations; use the returned chronological cursor verbatim.
    pub async fn paired_chat_message_page(
        &self,
        account_ref: String,
        group_id_hex: String,
        after: Option<PairedChatMessageCursorFfi>,
        limit: u32,
    ) -> Result<PairedChatMessagePageFfi, MarmotKitError> {
        if !cfg!(feature = "experimental-device-sync") {
            return Err(MarmotKitError::AccountSharingUnsupported);
        }
        let group = group_id_from_hex(&group_id_hex)?;
        let after = after.map(paired_cursor).transpose()?;
        Ok(self
            .runtime
            .accounts()
            .paired_chat_message_page(&account_ref, group, after, limit)
            .await
            .map_err(account_chat_read_error)?
            .into())
    }
}
