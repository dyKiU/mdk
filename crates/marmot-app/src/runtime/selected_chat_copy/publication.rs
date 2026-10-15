use super::{AccountManager, ConsentCommand, Reply, RequestState};
use crate::selected_chat_copy::SelectedChatCopyError;
use std::sync::Arc;

pub(super) async fn handle(
    client: &mut crate::AppClient,
    original: Arc<RequestState>,
    revision: u64,
    mut respond: Reply<()>,
) {
    if respond.is_closed() {
        original.cancel();
        return;
    }
    let result = tokio::select! {
        biased;
        _ = respond.closed() => {
            original.cancel();
            return;
        }
        _ = original.revoked() => {
            original.cancel();
            Err(SelectedChatCopyError::Closed)
        }
        result = client.selected_request_continue(&original, revision) => result,
    };
    if respond.send(result).is_err() {
        original.cancel();
    }
}

impl AccountManager {
    pub(crate) async fn selected_request_continue(
        &self,
        account: &str,
        original: Arc<RequestState>,
        revision: u64,
    ) -> Result<(), SelectedChatCopyError> {
        original.check_live_revision(revision)?;
        self.selected_command(account, |respond| ConsentCommand::Continue {
            original,
            revision,
            respond,
        })
        .await
    }
}
