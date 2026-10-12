use super::{AccountManager, AccountWorkerCommand, MarmotAppRuntime};
use crate::{AccountChatDepartureState, AppError, GroupId};
use tokio::sync::oneshot;

pub(crate) enum Command {
    State {
        group: GroupId,
        respond: oneshot::Sender<Result<AccountChatDepartureState, AppError>>,
    },
    Leave {
        group: GroupId,
        respond: oneshot::Sender<Result<AccountChatDepartureState, AppError>>,
    },
}
impl AccountManager {
    async fn account_chat_departure_command(
        &self,
        account: &str,
        group: &GroupId,
        leave: bool,
    ) -> Result<AccountChatDepartureState, AppError> {
        let command = self.worker_commands(account).await?;
        let (respond, receive) = oneshot::channel();
        let request = if leave {
            Command::Leave {
                group: group.clone(),
                respond,
            }
        } else {
            Command::State {
                group: group.clone(),
                respond,
            }
        };
        command
            .send(AccountWorkerCommand::AccountDeparture(Box::new(request)))
            .await
            .map_err(|_| AppError::TransportClosed)?;
        super::account_worker_response(receive).await
    }
    pub async fn account_chat_departure_state(
        &self,
        account: &str,
        group: &GroupId,
    ) -> Result<AccountChatDepartureState, AppError> {
        self.account_chat_departure_command(account, group, false)
            .await
    }
    pub async fn leave_account_chat(
        &self,
        account: &str,
        group: &GroupId,
    ) -> Result<AccountChatDepartureState, AppError> {
        self.account_chat_departure_command(account, group, true)
            .await
    }
}
impl MarmotAppRuntime {
    pub async fn account_chat_departure_state(
        &self,
        account: &str,
        group: &GroupId,
    ) -> Result<AccountChatDepartureState, AppError> {
        self.accounts
            .account_chat_departure_state(account, group)
            .await
    }
    pub async fn leave_account_chat(
        &self,
        account: &str,
        group: &GroupId,
    ) -> Result<AccountChatDepartureState, AppError> {
        self.accounts.leave_account_chat(account, group).await
    }
}

pub(crate) async fn handle(client: &mut crate::AppClient, command: Command) -> GroupId {
    match command {
        Command::State { group, respond } => {
            let _ = respond.send(client.account_chat_departure_state(&group));
            group
        }
        Command::Leave { group, respond } => {
            let _ = respond.send(Box::pin(client.leave_account_chat(&group)).await);
            group
        }
    }
}
