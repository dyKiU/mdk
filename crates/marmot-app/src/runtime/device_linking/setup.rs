//! Account-worker setup bridge; all context and proof construction stays private.
use super::{AccountManager, AppClient, ClientLinkingError, Reply, VerifierCommand};
pub(crate) use crate::client::device_linking::setup::SetupPacket;
use crate::client::device_linking::setup::{MAX_REQUEST_PACKET_BYTES, MAX_SETUP_PACKET_BYTES};
use crate::device_linking::{LinkError, OwnerError};
use cgka_traits::{GroupId, device_linking_key_package::PurposeAttemptScope};

pub(crate) enum SetupCommand {
    ApprovalCancellation {
        binding: [u8; 32],
        respond:
            Reply<cgka_engine::private_enrollment_endorsement::EnrollmentEndorsementCancellation>,
    },
    PairingMetadata {
        scope: PurposeAttemptScope,
        tags: Vec<Vec<String>>,
        respond: Reply<()>,
    },
    ApprovalPairingMetadata {
        binding: [u8; 32],
        attach: Option<Vec<Vec<String>>>,
        respond: Reply<Vec<Vec<String>>>,
    },
    SiblingPairingMetadata {
        scope: PurposeAttemptScope,
        respond: Reply<Vec<Vec<Vec<String>>>>,
    },
    CaptureSharingChoice {
        scope: PurposeAttemptScope,
        respond: Reply<
            std::sync::Arc<
                crate::client::device_linking::sibling_sharing::OriginalEnrollmentSharingChoice,
            >,
        >,
    },
    ApprovalBindings {
        respond: Reply<Vec<([u8; 32], std::time::Instant)>>,
    },
    Targets {
        respond: Reply<Vec<crate::DeviceLinkingTarget>>,
    },
    ReceiveEnrollment {
        scope: PurposeAttemptScope,
        packet: Vec<u8>,
        respond: Reply<()>,
    },
    FinalizeEnrollment {
        scope: PurposeAttemptScope,
        respond: Reply<()>,
    },
    ApprovalPhase {
        binding: [u8; 32],
        respond: Reply<crate::DeviceLinkingApprovalPhase>,
    },
    ApprovalReview {
        binding: [u8; 32],
        respond: Reply<([u8; 32], [u8; 32], u32)>,
    },
    ContinueAndShareChats {
        scope: PurposeAttemptScope,
        new_device: bool,
        respond: Reply<()>,
    },
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
        SetupCommand::ApprovalCancellation { binding, respond } => {
            if let Err(Ok(control)) = respond.send(client.native_approval_cancellation(&binding)) {
                control.cancel();
            }
        }
        SetupCommand::PairingMetadata {
            scope,
            tags,
            respond,
        } => {
            let _ = respond.send(client.prepare_pairing_metadata(&scope, tags));
        }
        SetupCommand::ApprovalPairingMetadata {
            binding,
            attach,
            respond,
        } => {
            let _ = respond.send(client.approval_pairing_metadata(&binding, attach));
        }
        SetupCommand::SiblingPairingMetadata { scope, respond } => {
            let _ = respond.send(client.sibling_pairing_metadata(&scope));
        }
        SetupCommand::CaptureSharingChoice { scope, respond } => {
            let result = client.capture_owned_native_sharing_choice(&scope);
            if let Err(result) = respond.send(result) {
                if let Ok(original) = result {
                    original.cancel();
                }
                cancel_abandoned_setup(client, &scope).await;
            }
        }
        SetupCommand::ApprovalBindings { respond } => {
            let _ = respond.send(client.native_authenticated_received_bindings());
        }
        SetupCommand::Targets { respond } => {
            let _ = respond.send(client.native_device_linking_targets());
        }
        SetupCommand::ApprovalPhase { binding, respond } => {
            let _ = respond.send(client.native_received_approval_phase(&binding));
        }
        SetupCommand::ApprovalReview { binding, respond } => {
            let _ = respond.send(client.native_received_approval_review(&binding));
        }
        SetupCommand::ReceiveEnrollment {
            scope,
            packet,
            respond,
        } => {
            let result = client
                .native_receive_enrollment_packet(&scope, &packet)
                .await;
            if respond.send(result).is_err() {
                cancel_abandoned_setup(client, &scope).await;
            }
        }
        SetupCommand::FinalizeEnrollment { scope, respond } => {
            let result = client.native_finalize_enrollment(&scope).await;
            if result.is_ok()
                && let Ok((_, gate)) = client.private_commit_control(&scope)
            {
                publication_control.install(scope.clone(), gate);
            }
            if respond.send(result).is_err() {
                cancel_abandoned_setup(client, &scope).await;
            }
        }
        SetupCommand::ContinueAndShareChats {
            scope,
            new_device,
            respond,
        } => {
            let result = client
                .continue_owned_native_linking_and_share_chats(&scope, new_device)
                .await;
            if result.is_ok()
                && !new_device
                && let Ok((_, gate)) = client
                    .private_commit_control(&scope)
                    .or_else(|_| client.enrollment_proposal_control(&scope))
            {
                publication_control.install(scope.clone(), gate);
            }
            if respond.send(result).is_err() {
                cancel_abandoned_setup(client, &scope).await;
            }
        }
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
                && let Ok((_, gate)) = client
                    .private_commit_control(&scope)
                    .or_else(|_| client.enrollment_proposal_control(&scope))
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
    pub(crate) async fn native_approval_cancellation(
        &self,
        account: &str,
        binding: &[u8; 32],
    ) -> Result<
        cgka_engine::private_enrollment_endorsement::EnrollmentEndorsementCancellation,
        ClientLinkingError,
    > {
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::ApprovalCancellation {
                binding: *binding,
                respond,
            })
        })
        .await
    }

    pub(crate) async fn native_pairing_metadata(
        &self,
        account: &str,
        scope: &PurposeAttemptScope,
        tags: Vec<Vec<String>>,
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::PairingMetadata {
                scope: scope.clone(),
                tags,
                respond,
            })
        })
        .await
    }
    pub(crate) async fn native_approval_pairing_metadata(
        &self,
        account: &str,
        binding: &[u8; 32],
        attach: Option<Vec<Vec<String>>>,
    ) -> Result<Vec<Vec<String>>, ClientLinkingError> {
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::ApprovalPairingMetadata {
                binding: *binding,
                attach,
                respond,
            })
        })
        .await
    }
    pub(crate) async fn native_sibling_pairing_metadata(
        &self,
        account: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<Vec<Vec<Vec<String>>>, ClientLinkingError> {
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::SiblingPairingMetadata {
                scope: scope.clone(),
                respond,
            })
        })
        .await
    }

    pub(crate) async fn native_capture_sharing_choice(
        &self,
        account: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<
        std::sync::Arc<
            crate::client::device_linking::sibling_sharing::OriginalEnrollmentSharingChoice,
        >,
        ClientLinkingError,
    > {
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::CaptureSharingChoice {
                scope: scope.clone(),
                respond,
            })
        })
        .await
    }
    pub(crate) async fn native_received_proposals(
        &self,
        account: &str,
    ) -> Result<Vec<([u8; 32], std::time::Instant)>, ClientLinkingError> {
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::ApprovalBindings { respond })
        })
        .await
    }
    pub(crate) async fn native_approve_received_proposal(
        &self,
        account: &str,
        binding: &[u8; 32],
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account, |respond| {
            VerifierCommand::EndorseReceivedEnrollmentProposal {
                binding: *binding,
                respond,
            }
        })
        .await
    }
    pub(crate) async fn native_approve_received_proposal_and_share_chats(
        &self,
        account: &str,
        binding: &[u8; 32],
    ) -> Result<
        std::sync::Arc<crate::client::private_enrollment_proposal::OriginalSiblingSharingApproval>,
        ClientLinkingError,
    > {
        self.verifier_command(account, |respond| {
            VerifierCommand::EndorseReceivedEnrollmentProposalAndShareChats {
                binding: *binding,
                respond,
            }
        })
        .await
    }
    pub(crate) async fn native_arm_existing_member(
        &self,
        account: &str,
        binding: &[u8; 32],
        packet: Vec<u8>,
    ) -> Result<(), ClientLinkingError> {
        check_size(&packet, 16_384)?;
        self.verifier_command(account, |respond| {
            VerifierCommand::ArmExistingMemberEnrollment {
                binding: *binding,
                packet,
                respond,
            }
        })
        .await
    }

    pub(crate) async fn native_device_linking_targets(
        &self,
        account: &str,
    ) -> Result<Vec<crate::DeviceLinkingTarget>, ClientLinkingError> {
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::Targets { respond })
        })
        .await
    }
    pub(crate) async fn native_received_approval_phase(
        &self,
        account: &str,
        binding: &[u8; 32],
    ) -> Result<crate::DeviceLinkingApprovalPhase, ClientLinkingError> {
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::ApprovalPhase {
                binding: *binding,
                respond,
            })
        })
        .await
    }
    pub(crate) async fn native_received_approval_review(
        &self,
        account: &str,
        binding: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32], u32), ClientLinkingError> {
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::ApprovalReview {
                binding: *binding,
                respond,
            })
        })
        .await
    }
    pub(crate) async fn native_receive_enrollment_packet(
        &self,
        account: &str,
        scope: &PurposeAttemptScope,
        packet: Vec<u8>,
    ) -> Result<(), ClientLinkingError> {
        check_size(&packet, 16_384)?;
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::ReceiveEnrollment {
                scope: scope.clone(),
                packet,
                respond,
            })
        })
        .await
    }
    pub(crate) async fn native_finalize_enrollment(
        &self,
        account: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::FinalizeEnrollment {
                scope: scope.clone(),
                respond,
            })
        })
        .await
    }

    pub(crate) async fn native_continue_device_linking_and_share_chats(
        &self,
        account: &str,
        scope: &PurposeAttemptScope,
        new_device: bool,
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account, |respond| {
            VerifierCommand::Setup(SetupCommand::ContinueAndShareChats {
                scope: scope.clone(),
                new_device,
                respond,
            })
        })
        .await
    }
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
