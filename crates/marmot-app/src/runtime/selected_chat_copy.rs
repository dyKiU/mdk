//! Account-worker admission; no linking proof or transport command is accepted.
use super::{AccountManager, AccountWorkerCommand};
use crate::selected_chat_copy::{SelectedChatCopy, SelectedChatCopyError};
use cgka_traits::GroupId;
use tokio::sync::oneshot;

impl AccountManager {
    pub(crate) async fn begin_owned_selected_chat_copy(
        &self,
        account_ref: &str,
        group: &GroupId,
        selector: Vec<u8>,
    ) -> Result<SelectedChatCopy, SelectedChatCopyError> {
        if group.as_slice().is_empty()
            || group.as_slice().len() > 256
            || selector.is_empty()
            || selector.len() > 256
            || selector == group.as_slice()
        {
            return Err(SelectedChatCopyError::InvalidSelection);
        }
        let commands = self
            .worker_commands(account_ref)
            .await
            .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?;
        let (respond, receive) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::BeginSelectedChatCopy {
                group: group.clone(),
                selector,
                respond,
            })
            .await
            .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?;
        match tokio::time::timeout(super::APP_RUNTIME_WORKER_RESPONSE_WAIT, receive).await {
            Ok(Ok(result)) => result.map(SelectedChatCopy::from_original),
            _ => Err(SelectedChatCopyError::RuntimeUnavailable),
        }
    }
}
