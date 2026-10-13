use super::{AccountManager, AccountWorkerCommand};
use crate::{AccountSharingError, account_chat_sharing::enabled::State};
use std::sync::Arc;
use tokio::sync::oneshot;
type Reply<T> = oneshot::Sender<Result<T, AccountSharingError>>;
#[cfg(all(test, feature = "test-policy-overrides"))]
use crate::account_chat_sharing::enabled::RecordReceiptProbe;
pub(crate) enum Command {
    #[cfg(all(test, feature = "test-policy-overrides"))]
    NextOriginalLifetime {
        lifetime: std::time::Duration,
        respond: Reply<()>,
    },
    SubmitChat {
        group: crate::GroupId,
        token: String,
        request: crate::local_submissions::LocalMessageRequest,
        respond: oneshot::Sender<Result<crate::LocalSendAcceptance, crate::AppError>>,
    },
    #[cfg(all(test, feature = "test-policy-overrides"))]
    AutomaticKick {
        respond: Reply<()>,
    },
    #[cfg(all(test, feature = "test-policy-overrides"))]
    ObserveRecordReceipts {
        respond: Reply<Arc<RecordReceiptProbe>>,
    },
    Targets {
        respond: Reply<crate::AccountSharingTargets>,
    },
    Begin {
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
}
impl AccountManager {
    /// Set only the NEXT genuinely constructed original's fixed deadline.
    /// Never changes an existing owner, grant, policy, or authenticated channel.
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) async fn next_original_account_sharing_lifetime_for_test(
        &self,
        account: &str,
        lifetime: std::time::Duration,
    ) -> Result<(), AccountSharingError> {
        self.send_account_sharing(account, |respond| Command::NextOriginalLifetime {
            lifetime,
            respond,
        })
        .await
    }
    pub(crate) async fn admit_forwarded_chat(
        &self,
        account: &str,
        group: crate::GroupId,
        token: String,
        request: crate::local_submissions::LocalMessageRequest,
    ) -> Result<crate::LocalSendAcceptance, crate::AppError> {
        let commands = self.worker_commands(account).await?;
        let (respond, receive) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::AccountSharing(Box::new(
                Command::SubmitChat {
                    group,
                    token,
                    request,
                    respond,
                },
            )))
            .await
            .map_err(|_| crate::AppError::TransportClosed)?;
        receive
            .await
            .map_err(|_| crate::AppError::TransportClosed)?
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) async fn kick_approved_automatic_channel(
        &self,
        account: &str,
    ) -> Result<(), AccountSharingError> {
        self.send_account_sharing(account, |respond| Command::AutomaticKick { respond })
            .await
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) async fn observe_automatic_record_receipts_for_test(
        &self,
        account: &str,
    ) -> Result<Arc<RecordReceiptProbe>, AccountSharingError> {
        self.send_account_sharing(account, |respond| Command::ObserveRecordReceipts {
            respond,
        })
        .await
    }
    pub(crate) async fn query_account_sharing_targets(
        &self,
        account: &str,
    ) -> Result<crate::AccountSharingTargets, AccountSharingError> {
        self.send_account_sharing(account, |respond| Command::Targets { respond })
            .await
    }
    async fn send_account_sharing<T>(
        &self,
        account: &str,
        build: impl FnOnce(Reply<T>) -> Command,
    ) -> Result<T, AccountSharingError> {
        let commands = self
            .worker_commands(account)
            .await
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        let (respond, receive) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::AccountSharing(Box::new(build(
                respond,
            ))))
            .await
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        tokio::time::timeout(std::time::Duration::from_secs(30), receive)
            .await
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?
    }
    pub(crate) async fn begin_account_sharing(
        &self,
        account: &str,
        recipient: Vec<u8>,
    ) -> Result<Arc<State>, AccountSharingError> {
        self.send_account_sharing(account, |respond| Command::Begin { recipient, respond })
            .await
    }
    pub(crate) async fn pending_account_sharing(
        &self,
        account: &str,
    ) -> Result<Vec<Arc<State>>, AccountSharingError> {
        self.send_account_sharing(account, |respond| Command::Pending { respond })
            .await
    }
    pub(crate) async fn approve_account_sharing(
        &self,
        account: &str,
        original: Arc<State>,
        revision: u64,
    ) -> Result<(), AccountSharingError> {
        self.send_account_sharing(account, |respond| Command::Approve {
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
        Command::NextOriginalLifetime { lifetime, respond } => {
            assert!(!lifetime.is_zero() && lifetime <= std::time::Duration::from_secs(600));
            client.account_sharing_owner.next_original_lifetime_for_test = Some(lifetime);
            let _ = respond.send(Ok(()));
        }
        Command::SubmitChat {
            group,
            token,
            request,
            respond,
        } => {
            let _ = respond.send(client.admit_forwarded_chat(&group, token, request));
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        Command::AutomaticKick { respond } => {
            let _ = respond.send(client.kick_approved_automatic_channel().await);
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        Command::ObserveRecordReceipts { respond } => {
            let probe = Arc::new(RecordReceiptProbe::default());
            client.account_sharing_owner.record_receipt_probe = Some(Arc::clone(&probe));
            let _ = respond.send(Ok(probe));
        }
        Command::Targets { respond } => {
            let _ = respond.send(client.account_sharing_targets());
        }
        Command::Begin { recipient, respond } => {
            let result = client.begin_existing_pair_sharing(&recipient);
            if let Err(Ok(original)) = respond.send(result) {
                original.cancel();
            }
        }
        Command::Pending { respond } => {
            let originals = client
                .account_sharing_owner
                .entries
                .values()
                .filter_map(|e| {
                    e.pending
                        .as_ref()
                        .filter(|x| {
                            x.live() && !x.progress.lock().expect("sharing progress").complete
                        })
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
            let revoked = original.revoked.notified();
            tokio::pin!(revoked);
            revoked.as_mut().enable();
            let mut shutdown = client.history_owner.runtime_shutdown.clone();
            let stopping = async {
                if let Some(watch) = shutdown.as_mut() {
                    if *watch.borrow() {
                        return;
                    }
                    while watch.changed().await.is_ok() {
                        if *watch.borrow() {
                            return;
                        }
                    }
                } else {
                    std::future::pending::<()>().await
                }
            };
            let result = tokio::select! {biased;
                ()=respond.closed()=>{original.cancel();return;},
                ()=stopping=>{original.cancel();Err(AccountSharingError::Closed)},
                ()=&mut revoked=>Err(AccountSharingError::Closed),
                ()=tokio::time::sleep_until(original.deadline.into())=>{original.cancel();Err(AccountSharingError::Closed)},
                result=client.approve_existing_pair_sharing(&original,revision)=>result
            };
            if respond.send(result).is_err() {
                original.cancel();
            }
        }
    }
}
