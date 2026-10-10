//! Account-worker admission; no linking proof or transport command is accepted.
use super::{AccountManager, AccountWorkerCommand};
use crate::selected_chat_copy::{SelectedChatCopy, SelectedChatCopyError};
use cgka_traits::GroupId;
use tokio::sync::oneshot;
mod publication;

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
        let account = self
            .resolve(account_ref)
            .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?
            .label;
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
            Ok(Ok(result)) => {
                result.map(|inner| SelectedChatCopy::from_original(inner, self.clone(), account))
            }
            _ => Err(SelectedChatCopyError::RuntimeUnavailable),
        }
    }
}

use crate::selected_chat_copy::{
    SelectedChatConsent,
    enabled::{ConsentState, RequestState},
};
use std::sync::Arc;
type Reply<T> = oneshot::Sender<Result<T, SelectedChatCopyError>>;
pub(crate) enum ConsentCommand {
    Continue {
        original: Arc<RequestState>,
        revision: u64,
        respond: Reply<()>,
    },
    RequestPacket {
        original: Arc<RequestState>,
        revision: u64,
        respond: Reply<Vec<u8>>,
    },
    Collect {
        original: Arc<RequestState>,
        revision: u64,
        packet: Vec<u8>,
        respond: Reply<()>,
    },
    CollectOffer {
        original: Arc<RequestState>,
        revision: u64,
        packet: Vec<u8>,
        respond: Reply<()>,
    },
    Receive {
        packet: Vec<u8>,
        respond: Reply<Arc<ConsentState>>,
    },
    Approve {
        original: Arc<ConsentState>,
        revision: u64,
        respond: Reply<()>,
    },
    Response {
        original: Arc<ConsentState>,
        revision: u64,
        respond: Reply<Vec<u8>>,
    },
    Offer {
        original: Arc<ConsentState>,
        revision: u64,
        respond: Reply<Vec<u8>>,
    },
}
pub(crate) async fn handle_consent(client: &mut crate::AppClient, command: ConsentCommand) {
    match command {
        ConsentCommand::Continue {
            original,
            revision,
            respond,
        } => {
            publication::handle(client, original, revision, respond).await;
        }
        ConsentCommand::CollectOffer {
            original,
            revision,
            packet,
            respond,
        } => {
            if respond.is_closed() {
                original.cancel();
                return;
            }
            if respond
                .send(client.selected_request_collect_offer(&original, revision, &packet))
                .is_err()
            {
                original.cancel();
            }
        }
        ConsentCommand::RequestPacket {
            original,
            revision,
            respond,
        } => {
            if respond.is_closed() {
                return;
            }
            if respond
                .send(client.selected_request_packet(&original, revision))
                .is_err()
            {
                original.cancel();
            }
        }
        ConsentCommand::Collect {
            original,
            revision,
            packet,
            respond,
        } => {
            if respond.is_closed() {
                return;
            }
            if respond
                .send(client.selected_request_collect(&original, revision, &packet))
                .is_err()
            {
                original.cancel();
            }
        }
        ConsentCommand::Receive { packet, respond } => {
            if respond.is_closed() {
                return;
            }
            if let Err(Ok(original)) = respond.send(client.selected_receive_request(packet)) {
                original.cancel();
            }
        }
        ConsentCommand::Approve {
            original,
            revision,
            respond,
        } => {
            if respond.is_closed() {
                return;
            }
            if respond
                .send(client.selected_consent_approve(&original, revision))
                .is_err()
            {
                original.cancel();
            }
        }
        ConsentCommand::Response {
            original,
            revision,
            respond,
        } => {
            if respond.is_closed() {
                return;
            }
            if respond
                .send(client.selected_consent_response(&original, revision))
                .is_err()
            {
                original.cancel();
            }
        }
        ConsentCommand::Offer {
            original,
            revision,
            mut respond,
        } => {
            if respond.is_closed() {
                original.cancel();
                return;
            }
            let result = tokio::select! {
                biased;
                _ = respond.closed() => { original.cancel(); return; }
                _ = original.revoked() => { original.cancel(); return; }
                result = client.selected_consent_offer(&original, revision) => result,
            };
            if respond.send(result).is_err() {
                original.cancel();
            }
        }
    }
}
fn bounded(packet: &[u8]) -> Result<(), SelectedChatCopyError> {
    if packet.is_empty()
        || packet.len() > cgka_engine::selected_chat_consent::MAX_SELECTED_CHAT_PACKET_BYTES
    {
        Err(SelectedChatCopyError::InvalidPacket)
    } else {
        Ok(())
    }
}
impl AccountManager {
    pub(crate) async fn selected_request_collect_offer(
        &self,
        account: &str,
        original: Arc<RequestState>,
        revision: u64,
        packet: Vec<u8>,
    ) -> Result<(), SelectedChatCopyError> {
        bounded(&packet)?;
        original.check_revision(revision)?;
        self.selected_command(account, |respond| ConsentCommand::CollectOffer {
            original,
            revision,
            packet,
            respond,
        })
        .await
    }
    async fn selected_command<T>(
        &self,
        account: &str,
        make: impl FnOnce(Reply<T>) -> ConsentCommand,
    ) -> Result<T, SelectedChatCopyError> {
        let commands = self
            .worker_commands(account)
            .await
            .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?;
        let (respond, receiver) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::SelectedChatConsent(Box::new(make(
                respond,
            ))))
            .await
            .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?;
        match tokio::time::timeout(super::APP_RUNTIME_WORKER_RESPONSE_WAIT, receiver).await {
            Ok(Ok(result)) => result,
            _ => Err(SelectedChatCopyError::RuntimeUnavailable),
        }
    }
    pub(crate) async fn selected_request_packet(
        &self,
        account: &str,
        original: Arc<RequestState>,
        revision: u64,
    ) -> Result<Vec<u8>, SelectedChatCopyError> {
        original.check_revision(revision)?;
        self.selected_command(account, |respond| ConsentCommand::RequestPacket {
            original,
            revision,
            respond,
        })
        .await
    }
    pub(crate) async fn selected_request_collect(
        &self,
        account: &str,
        original: Arc<RequestState>,
        revision: u64,
        packet: Vec<u8>,
    ) -> Result<(), SelectedChatCopyError> {
        bounded(&packet)?;
        original.check_revision(revision)?;
        self.selected_command(account, |respond| ConsentCommand::Collect {
            original,
            revision,
            packet,
            respond,
        })
        .await
    }
    pub(crate) async fn selected_receive_request(
        &self,
        account_ref: &str,
        packet: Vec<u8>,
    ) -> Result<SelectedChatConsent, SelectedChatCopyError> {
        bounded(&packet)?;
        let account = self
            .resolve(account_ref)
            .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?
            .label;
        let original = self
            .selected_command(account_ref, |respond| ConsentCommand::Receive {
                packet,
                respond,
            })
            .await?;
        Ok(SelectedChatConsent::from_original(
            original,
            self.clone(),
            account,
        ))
    }
    pub(crate) async fn selected_consent_approve(
        &self,
        account: &str,
        original: Arc<ConsentState>,
        revision: u64,
    ) -> Result<(), SelectedChatCopyError> {
        original.check_revision(revision)?;
        self.selected_command(account, |respond| ConsentCommand::Approve {
            original,
            revision,
            respond,
        })
        .await
    }
    pub(crate) async fn selected_consent_response(
        &self,
        account: &str,
        original: Arc<ConsentState>,
        revision: u64,
    ) -> Result<Vec<u8>, SelectedChatCopyError> {
        original.check_revision(revision)?;
        self.selected_command(account, |respond| ConsentCommand::Response {
            original,
            revision,
            respond,
        })
        .await
    }
    pub(crate) async fn selected_consent_offer(
        &self,
        account: &str,
        original: Arc<ConsentState>,
        revision: u64,
    ) -> Result<Vec<u8>, SelectedChatCopyError> {
        original.check_revision(revision)?;
        self.selected_command(account, |respond| ConsentCommand::Offer {
            original,
            revision,
            respond,
        })
        .await
    }
}
