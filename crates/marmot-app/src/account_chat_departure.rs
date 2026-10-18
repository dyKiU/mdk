//! Account-wide departure progress is distinct from device-local MLS membership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountChatDepartureStatus {
    Available,
    Pending,
    NeedsAdministrator,
    Completed,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountChatDepartureReason {
    None,
    AwaitingSources,
    AwaitingAdministrator,
    SharingUnavailable,
    NoAcceptedChat,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AccountChatDepartureState {
    pub status: AccountChatDepartureStatus,
    pub reason: AccountChatDepartureReason,
    /// Negative-operation correlation only; never a membership or approval token.
    pub operation_id: Option<String>,
}
impl std::fmt::Debug for AccountChatDepartureState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountChatDepartureState")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "experimental-device-sync")]
impl crate::MarmotApp {
    /// Token admission and worker publication both call this. It observes only
    /// immutable negative cuts; ordinary Core membership is still checked later.
    pub(crate) fn ensure_local_chat_not_account_departed(
        &self,
        account: &str,
        group: &crate::GroupId,
    ) -> Result<(), crate::AppError> {
        use cgka_traits::storage::AccountDeviceSignerStorage;
        let summary = self.account_home().account(account)?;
        let identity = cgka_traits::MemberId::new(hex::decode(&summary.account_id_hex)?);
        let storage = self.account_storage(&summary.label)?;
        let Some(signer) = storage.account_device_signer(&identity)? else {
            return Ok(());
        };
        let account: [u8; 32] = identity.as_slice().try_into().map_err(|_| {
            crate::AppError::InvalidAppMessagePayload("invalid account identity".into())
        })?;
        let local: [u8; 32] = signer
            .mls_signature_public_key
            .as_slice()
            .try_into()
            .map_err(|_| {
                crate::AppError::InvalidAppMessagePayload("invalid account signer".into())
            })?;
        let origin = storage
            .app_storage()
            .current_account_chat_source_origin(&account, &local, group)?
            .or(storage
                .app_storage()
                .current_account_chat_source_terminal_origin(&account, &local, group)?);
        if storage
            .app_storage()
            .account_chat_departure_denies_source(&account, &local, group, &local, origin)?
        {
            return Err(crate::AppError::AccountChatDepartureDenied);
        }
        Ok(())
    }
}
