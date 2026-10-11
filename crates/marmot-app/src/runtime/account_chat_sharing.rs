use super::{AccountManager, AccountWorkerCommand};
use crate::{AccountSharingError, account_chat_sharing::enabled::State};
use std::sync::Arc;
use tokio::sync::oneshot;
type Reply<T> = oneshot::Sender<Result<T, AccountSharingError>>;
pub(crate) enum Command {
    #[cfg(test)]
    AutomaticKick {
        respond: Reply<()>,
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
    #[cfg(test)]
    pub(crate) async fn kick_approved_automatic_channel(
        &self,
        account: &str,
    ) -> Result<(), AccountSharingError> {
        self.send_account_sharing(account, |respond| Command::AutomaticKick { respond })
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
        #[cfg(test)]
        Command::AutomaticKick { respond } => {
            let _ = respond.send(client.kick_approved_automatic_channel().await);
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
