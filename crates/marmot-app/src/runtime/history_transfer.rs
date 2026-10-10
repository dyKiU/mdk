//! Scope-free host commands; the account worker retains original Core channels.
use super::{AccountManager, AccountWorkerCommand};
use crate::history_transfer::{HistoryTransferError, enabled::State};
use cgka_traits::GroupId;
use std::sync::Arc;
use tokio::sync::oneshot;
type Reply<T> = oneshot::Sender<Result<T, HistoryTransferError>>;
pub(crate) enum Command {
    #[cfg(all(test, feature = "test-policy-overrides"))]
    ObservedChunks {
        respond: Reply<(usize, usize, usize, usize, usize)>,
    },
    #[cfg(all(test, feature = "test-policy-overrides"))]
    RepublishOriginalRequest {
        original: Arc<State>,
        respond: Reply<()>,
    },
    #[cfg(all(test, feature = "test-policy-overrides"))]
    InspectOriginalRecord {
        original: Arc<State>,
        message_id: [u8; 32],
        respond: Reply<(bool, usize)>,
    },
    #[cfg(all(test, feature = "test-policy-overrides"))]
    CancelAfterStage {
        imported: bool,
        respond: Reply<()>,
    },
    Begin {
        group: GroupId,
        recipient: Vec<u8>,
        respond: Reply<Arc<State>>,
    },
    Pending {
        respond: Reply<Vec<Arc<State>>>,
    },
    Approve {
        original: Arc<State>,
        revision: u64,
        respond: Reply<()>,
    },
    Continue {
        original: Arc<State>,
        revision: u64,
        respond: Reply<()>,
    },
}
impl AccountManager {
    async fn send_history<T>(
        &self,
        account: &str,
        build: impl FnOnce(Reply<T>) -> Command,
    ) -> Result<T, HistoryTransferError> {
        let commands = self
            .worker_commands(account)
            .await
            .map_err(|_| HistoryTransferError::RuntimeUnavailable)?;
        let (respond, receive) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::HistoryTransfer(Box::new(build(
                respond,
            ))))
            .await
            .map_err(|_| HistoryTransferError::RuntimeUnavailable)?;
        match tokio::time::timeout(super::APP_RUNTIME_WORKER_RESPONSE_WAIT, receive).await {
            Ok(Ok(result)) => result,
            _ => Err(HistoryTransferError::RuntimeUnavailable),
        }
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) async fn observed_history_chunks_for_test(
        &self,
        account: &str,
    ) -> Result<(usize, usize, usize, usize, usize), HistoryTransferError> {
        self.send_history(account, |respond| Command::ObservedChunks { respond })
            .await
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) async fn republish_original_history_request_for_test(
        &self,
        account: &str,
        original: Arc<State>,
    ) -> Result<(), HistoryTransferError> {
        self.send_history(account, |respond| Command::RepublishOriginalRequest {
            original,
            respond,
        })
        .await
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) async fn inspect_original_history_record_for_test(
        &self,
        account: &str,
        original: Arc<State>,
        message_id: [u8; 32],
    ) -> Result<(bool, usize), HistoryTransferError> {
        self.send_history(account, |respond| Command::InspectOriginalRecord {
            original,
            message_id,
            respond,
        })
        .await
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) async fn cancel_after_original_history_stage_for_test(
        &self,
        account: &str,
        imported: bool,
    ) -> Result<(), HistoryTransferError> {
        self.send_history(account, |respond| Command::CancelAfterStage {
            imported,
            respond,
        })
        .await
    }
    pub(crate) async fn begin_original_history(
        &self,
        account: &str,
        group: &GroupId,
        recipient: Vec<u8>,
    ) -> Result<Arc<State>, HistoryTransferError> {
        if group.as_slice().is_empty() || group.as_slice().len() > 255 || recipient.len() != 32 {
            return Err(HistoryTransferError::NotReady);
        }
        self.send_history(account, |respond| Command::Begin {
            group: group.clone(),
            recipient,
            respond,
        })
        .await
    }
    pub(crate) async fn pending_original_history(
        &self,
        account: &str,
    ) -> Result<Vec<Arc<State>>, HistoryTransferError> {
        self.send_history(account, |respond| Command::Pending { respond })
            .await
    }
    pub(crate) async fn approve_original_history(
        &self,
        account: &str,
        original: Arc<State>,
        revision: u64,
    ) -> Result<(), HistoryTransferError> {
        self.send_history(account, |respond| Command::Approve {
            original,
            revision,
            respond,
        })
        .await
    }
    pub(crate) async fn continue_original_history(
        &self,
        account: &str,
        original: Arc<State>,
        revision: u64,
    ) -> Result<(), HistoryTransferError> {
        self.send_history(account, |respond| Command::Continue {
            original,
            revision,
            respond,
        })
        .await
    }
}
pub(crate) async fn handle(client: &mut crate::AppClient, command: Command) {
    match command {
        #[cfg(all(test, feature = "test-policy-overrides"))]
        Command::ObservedChunks { respond } => {
            let _ = respond.send(Ok((
                client.history_owner.authenticated_chunk_observations,
                client.history_owner.refused_original_requests,
                client.history_owner.authenticated_request_observations,
                client.history_owner.channels.len(),
                client.history_owner.cleanup_attempts_for_test,
            )));
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        Command::RepublishOriginalRequest { original, respond } => {
            let result = client
                .republish_original_history_request_for_test(&original)
                .await;
            let _ = respond.send(result);
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        Command::InspectOriginalRecord {
            original,
            message_id,
            respond,
        } => {
            let _ = respond
                .send(client.inspect_original_history_record_for_test(&original, message_id));
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        Command::CancelAfterStage { imported, respond } => {
            client.history_owner.cancel_after_stage_for_test = Some(imported);
            let _ = respond.send(Ok(()));
        }
        Command::Begin {
            group,
            recipient,
            mut respond,
        } => {
            let result = tokio::select! {
                biased;
                () = respond.closed() => return,
                result = client.begin_original_history(&group, &recipient) => result,
            };
            if let Err(Ok(original)) = respond.send(result) {
                original.cancel();
            }
        }
        Command::Pending { respond } => {
            let originals = client
                .history_owner
                .channels
                .values()
                .filter_map(|entry| {
                    entry
                        .pending_original
                        .as_ref()
                        .filter(|state| state.live())
                        .cloned()
                })
                .collect();
            let _ = respond.send(Ok(originals));
        }
        Command::Approve {
            original,
            revision,
            mut respond,
        } => {
            let result = tokio::select! {
                biased;
                () = respond.closed() => { original.cancel(); return; },
                result = client.approve_original_history(&original, revision) => result,
            };
            if respond.send(result).is_err() {
                original.cancel();
            }
        }
        Command::Continue {
            original,
            revision,
            respond,
        } => {
            client.continue_original_history(original, revision, respond);
        }
    }
}
