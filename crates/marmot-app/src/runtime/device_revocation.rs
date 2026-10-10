//! Original administrator review RPC; no host-created Core action or Remove.
use super::{AccountManager, AccountWorkerCommand};
use crate::device_revocation::{
    GroupDeviceRevocationError, GroupDeviceRevocationSnapshot, enabled::State,
};
use cgka_traits::GroupId;
use std::sync::Arc;
use tokio::sync::oneshot;
type Reply<T> = oneshot::Sender<Result<T, GroupDeviceRevocationError>>;
pub(crate) enum Command {
    Targets {
        respond: Reply<crate::DeviceRevocationTargets>,
    },
    BeginDevice {
        target: Vec<u8>,
        respond: Reply<Arc<State>>,
    },
    ObserveDevice {
        original: Arc<State>,
        respond: Reply<crate::DeviceRevocationSnapshot>,
    },
    Approve {
        original: Arc<State>,
        revision: u64,
        respond: Reply<()>,
    },
    Begin {
        group: GroupId,
        target: Vec<u8>,
        respond: Reply<Arc<State>>,
    },
    Observe {
        original: Arc<State>,
        respond: Reply<GroupDeviceRevocationSnapshot>,
    },
}
impl AccountManager {
    pub(crate) async fn observe_device_revocation_targets(
        &self,
        account: &str,
    ) -> Result<crate::DeviceRevocationTargets, GroupDeviceRevocationError> {
        self.device_revocation_command(account, |respond| Command::Targets { respond })
            .await
    }

    pub(crate) async fn begin_original_device_revocation(
        &self,
        account: &str,
        target: Vec<u8>,
    ) -> Result<Arc<State>, GroupDeviceRevocationError> {
        if target.len() != 32 {
            return Err(GroupDeviceRevocationError::InvalidSelection);
        }
        self.device_revocation_command(account, |respond| Command::BeginDevice { target, respond })
            .await
    }
    pub(crate) async fn observe_original_device_revocation(
        &self,
        account: &str,
        original: Arc<State>,
    ) -> Result<crate::DeviceRevocationSnapshot, GroupDeviceRevocationError> {
        original.check()?;
        self.device_revocation_command(account, |respond| Command::ObserveDevice {
            original,
            respond,
        })
        .await
    }
    pub(crate) async fn approve_original_device_revocation(
        &self,
        account: &str,
        original: Arc<State>,
        revision: u64,
    ) -> Result<(), GroupDeviceRevocationError> {
        if !original.whole_device {
            return Err(GroupDeviceRevocationError::InvalidSelection);
        }
        self.approve_original_group_device_revocation(account, original, revision)
            .await
    }
    async fn device_revocation_command<T>(
        &self,
        account: &str,
        build: impl FnOnce(Reply<T>) -> Command,
    ) -> Result<T, GroupDeviceRevocationError> {
        let commands = self
            .worker_commands(account)
            .await
            .map_err(|_| GroupDeviceRevocationError::RuntimeUnavailable)?;
        let (respond, receive) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::DeviceRevocation(Box::new(build(
                respond,
            ))))
            .await
            .map_err(|_| GroupDeviceRevocationError::RuntimeUnavailable)?;
        match tokio::time::timeout(super::APP_RUNTIME_WORKER_RESPONSE_WAIT, receive).await {
            Ok(Ok(result)) => result,
            _ => Err(GroupDeviceRevocationError::RuntimeUnavailable),
        }
    }
    pub(crate) async fn approve_original_group_device_revocation(
        &self,
        account: &str,
        original: Arc<State>,
        revision: u64,
    ) -> Result<(), GroupDeviceRevocationError> {
        original.check_revision(revision)?;
        self.device_revocation_command(account, |respond| Command::Approve {
            original,
            revision,
            respond,
        })
        .await
    }
    pub(crate) async fn begin_original_group_device_revocation(
        &self,
        account: &str,
        group: &GroupId,
        target: Vec<u8>,
    ) -> Result<Arc<State>, GroupDeviceRevocationError> {
        if group.as_slice().is_empty() || group.as_slice().len() > 256 || target.len() != 32 {
            return Err(GroupDeviceRevocationError::InvalidSelection);
        }
        self.device_revocation_command(account, |respond| Command::Begin {
            group: group.clone(),
            target,
            respond,
        })
        .await
    }
    pub(crate) async fn observe_original_group_device_revocation(
        &self,
        account: &str,
        original: Arc<State>,
    ) -> Result<GroupDeviceRevocationSnapshot, GroupDeviceRevocationError> {
        original.check()?;
        self.device_revocation_command(account, |respond| Command::Observe { original, respond })
            .await
    }
}
pub(crate) async fn handle(client: &mut crate::AppClient, command: Command) {
    match command {
        Command::Targets { respond } => {
            if !respond.is_closed() {
                let _ = respond.send(client.device_revocation_targets());
            }
        }
        Command::BeginDevice { target, respond } => {
            if respond.is_closed() {
                return;
            }
            let result = client.begin_original_device_revocation(&target);
            if let Err(Ok(original)) = respond.send(result) {
                original.cancel();
            }
        }
        Command::ObserveDevice { original, respond } => {
            let _ = respond.send(client.observe_original_device_revocation(&original));
        }
        Command::Approve {
            original,
            revision,
            mut respond,
        } => {
            if respond.is_closed() {
                original.cancel();
                return;
            }
            let result = tokio::select! {biased;
                _ = respond.closed() => {original.cancel(); return;}
                _ = original.revoked() => {original.cancel(); Err(GroupDeviceRevocationError::Closed)}
                result = client.approve_original_group_device_revocation(&original, revision) => result,
            };
            if respond.send(result).is_err() {
                original.cancel();
            }
        }

        Command::Begin {
            group,
            target,
            respond,
        } => {
            if respond.is_closed() {
                return;
            }
            let result = client.begin_original_group_device_revocation(&group, &target);
            if let Err(Ok(original)) = respond.send(result) {
                original.cancel();
            }
        }
        Command::Observe { original, respond } => {
            let _ = respond.send(client.observe_original_group_device_revocation(&original));
        }
    }
}
