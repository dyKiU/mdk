//! Receiver and command ownership for automatic source-qualified chat views.
use super::{Mutex, StdMutex, take_snapshot};
use crate::MarmotKitError;
use crate::commands::account_chat_presentation::{account_chat_read_error, paired_cursor};
use crate::conversions::*;
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct AccountChatListWindowSubscription {
    snapshot: StdMutex<Option<AccountChatListWindowSnapshotFfi>>,
    commands: marmot_app::AccountChatListWindowHandle,
    receiver: Mutex<marmot_app::RuntimeAccountChatListWindowSubscription>,
}
impl AccountChatListWindowSubscription {
    pub(crate) fn new(inner: marmot_app::RuntimeAccountChatListWindowSubscription) -> Arc<Self> {
        Arc::new(Self {
            snapshot: StdMutex::new(Some(inner.snapshot.clone().into())),
            commands: inner.window_handle(),
            receiver: Mutex::new(inner),
        })
    }
}
impl Drop for AccountChatListWindowSubscription {
    fn drop(&mut self) {
        self.commands.cancel();
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl AccountChatListWindowSubscription {
    /// Initial complete replacement, available once before receiving updates.
    pub fn snapshot(&self) -> Option<AccountChatListWindowSnapshotFfi> {
        take_snapshot(&self.snapshot)
    }
    /// One receiver; commands and cancellation remain independent of this wait.
    pub async fn next(&self) -> Result<Option<AccountChatListWindowSnapshotFfi>, MarmotKitError> {
        Ok(self
            .receiver
            .lock()
            .await
            .recv()
            .await
            .map_err(account_chat_read_error)?
            .map(Into::into))
    }
    /// Use the installed sequence and opaque paired-source cursor verbatim.
    pub async fn paired_page(
        &self,
        sequence: u64,
        after_group_id_hex: Option<String>,
    ) -> Result<AccountChatListWindowSnapshotFfi, MarmotKitError> {
        let after = after_group_id_hex
            .map(|value| group_id_from_hex(&value))
            .transpose()?;
        Ok(self
            .commands
            .paired_page(sequence, after)
            .await
            .map_err(account_chat_read_error)?
            .into())
    }
    /// Synchronously retire the original window and wake pending receivers.
    pub fn cancel(&self) {
        self.commands.cancel();
        take_snapshot(&self.snapshot);
    }
}

#[derive(uniffi::Object)]
pub struct AccountConversationWindowSubscription {
    snapshot: StdMutex<Option<AccountConversationWindowSnapshotFfi>>,
    commands: marmot_app::AccountConversationWindowHandle,
    receiver: Mutex<marmot_app::RuntimeAccountConversationWindowSubscription>,
}
impl AccountConversationWindowSubscription {
    pub(crate) fn new(
        inner: marmot_app::RuntimeAccountConversationWindowSubscription,
    ) -> Arc<Self> {
        Arc::new(Self {
            snapshot: StdMutex::new(Some(inner.snapshot.clone().into())),
            commands: inner.window_handle(),
            receiver: Mutex::new(inner),
        })
    }
}
impl Drop for AccountConversationWindowSubscription {
    fn drop(&mut self) {
        self.commands.cancel();
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl AccountConversationWindowSubscription {
    /// Initial complete replacement; local authority remains explicitly local.
    pub fn snapshot(&self) -> Option<AccountConversationWindowSnapshotFfi> {
        take_snapshot(&self.snapshot)
    }
    pub async fn next(
        &self,
    ) -> Result<Option<AccountConversationWindowSnapshotFfi>, MarmotKitError> {
        Ok(self
            .receiver
            .lock()
            .await
            .recv()
            .await
            .map_err(account_chat_read_error)?
            .map(Into::into))
    }
    /// Bounded chronological page, conditional on the installed sequence.
    pub async fn older_page(
        &self,
        sequence: u64,
        before: Option<PairedChatMessageCursorFfi>,
    ) -> Result<AccountConversationWindowSnapshotFfi, MarmotKitError> {
        let before = before.map(paired_cursor).transpose()?;
        Ok(self
            .commands
            .older_page(sequence, before)
            .await
            .map_err(account_chat_read_error)?
            .into())
    }
    pub fn cancel(&self) {
        self.commands.cancel();
        take_snapshot(&self.snapshot);
    }
}
