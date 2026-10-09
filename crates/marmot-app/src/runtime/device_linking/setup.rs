//! Account-worker setup bridge; all context and proof construction stays private.
use super::{AccountManager, AppClient, ClientLinkingError, Reply, VerifierCommand};
pub(crate) use crate::client::device_linking::setup::SetupPacket;
use crate::client::device_linking::setup::{MAX_REQUEST_PACKET_BYTES, MAX_SETUP_PACKET_BYTES};
use crate::device_linking::{LinkError, OwnerError};
use cgka_traits::{GroupId, device_linking_key_package::PurposeAttemptScope};

pub(crate) enum SetupCommand {
    Continue {
        scope: PurposeAttemptScope,
        new_device: bool,
        respond: Reply<()>,
    },
    Observe {
        scope: PurposeAttemptScope,
        respond: Reply<(
            crate::DeviceLinkingPhase,
            Option<crate::DeviceLinkingDecimals>,
        )>,
    },
    ReserveRequest {
        respond: Reply<SetupPacket>,
    },
    ApproveRequest {
        packet: Vec<u8>,
        target: Option<GroupId>,
        respond: Reply<SetupPacket>,
    },
    AcceptChallenge {
        scope: PurposeAttemptScope,
        packet: Vec<u8>,
        respond: Reply<()>,
    },
}

fn check_size(packet: &[u8], limit: usize) -> Result<(), ClientLinkingError> {
    if packet.len() > limit {
        Err(ClientLinkingError::Owner(OwnerError::Verifier(
            LinkError::InvalidFrame,
        )))
    } else {
        Ok(())
    }
}

async fn cancel_abandoned_setup(client: &mut AppClient, scope: &PurposeAttemptScope) {
    // The client revokes memory before durable cleanup; its maintenance retries
    // a failed terminal write without restoring the lost caller's permission.
    if client.cancel_device_linking_scope(scope).await.is_err() {
        tracing::debug!(target: "marmot_app::device_linking", method = "worker_abandoned_setup", "device linking cleanup deferred");
    }
}

async fn send_setup_reply(
    client: &mut AppClient,
    respond: Reply<SetupPacket>,
    result: Result<SetupPacket, ClientLinkingError>,
) {
    if let Err(Ok(packet)) = respond.send(result) {
        cancel_abandoned_setup(client, &packet.scope).await;
    }
}

pub(super) async fn handle(
    client: &mut AppClient,
    command: SetupCommand,
    publication_control: &crate::runtime::private_commit::PublicationControl,
) {
    match command {
        SetupCommand::Continue {
            scope,
            new_device,
            respond,
        } => {
            let result = client
                .continue_owned_native_linking(&scope, new_device)
                .await;
            if result.is_ok()
                && !new_device
                && let Ok((_, gate)) = client.private_commit_control(&scope)
            {
                publication_control.install(scope.clone(), gate);
            }
            if respond.send(result).is_err() {
                cancel_abandoned_setup(client, &scope).await;
            }
        }
        SetupCommand::Observe { scope, respond } => {
            let result = client.linking_native_observation(&scope);
            let _ = respond.send(result);
        }
        SetupCommand::ReserveRequest { respond } => {
            let result = client.reserve_owned_linking_setup_request().await;
            send_setup_reply(client, respond, result).await;
        }
        SetupCommand::ApproveRequest {
            packet,
            target,
            respond,
        } => {
            let result = client
                .approve_owned_linking_setup_request(&packet, target.as_ref())
                .await;
            send_setup_reply(client, respond, result).await;
        }
        SetupCommand::AcceptChallenge {
            scope,
            packet,
            respond,
        } => {
            let result = client
                .accept_owned_linking_setup_challenge(&scope, &packet)
                .await;
            if respond.send(result).is_err() {
                cancel_abandoned_setup(client, &scope).await;
            }
        }
    }
}

impl AccountManager {
    pub(crate) async fn native_continue_device_linking(
        &self,
        account: &str,
        scope: &PurposeAttemptScope,
        new_device: bool,
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::Continue {
                scope: scope.clone(),
                new_device,
                respond,
            })
        })
        .await
    }
    pub(crate) async fn linking_native_observation(
        &self,
        account: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<
        (
            crate::DeviceLinkingPhase,
            Option<crate::DeviceLinkingDecimals>,
        ),
        ClientLinkingError,
    > {
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::Observe {
                scope: scope.clone(),
                respond,
            })
        })
        .await
    }
    pub(crate) async fn reserve_device_linking_setup(
        &self,
        account: &str,
    ) -> Result<SetupPacket, ClientLinkingError> {
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::ReserveRequest { respond })
        })
        .await
    }
    pub(crate) async fn approve_device_linking_setup(
        &self,
        account: &str,
        packet: Vec<u8>,
        target: Option<GroupId>,
    ) -> Result<SetupPacket, ClientLinkingError> {
        check_size(&packet, MAX_REQUEST_PACKET_BYTES)?;
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::ApproveRequest {
                packet,
                target,
                respond,
            })
        })
        .await
    }
    pub(crate) async fn accept_device_linking_setup(
        &self,
        account: &str,
        scope: &PurposeAttemptScope,
        packet: Vec<u8>,
    ) -> Result<(), ClientLinkingError> {
        check_size(&packet, MAX_SETUP_PACKET_BYTES)?;
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::AcceptChallenge {
                scope: scope.clone(),
                packet,
                respond,
            })
        })
        .await
    }
}

#[cfg(all(test, feature = "test-policy-overrides"))]
mod tests;
