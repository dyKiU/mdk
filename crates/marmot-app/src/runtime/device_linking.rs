//! Private lifecycle/verifier RPCs; no enrollment or history grants.
mod setup;
use super::{AccountManager, AccountWorkerCommand};
use crate::AppError;
use crate::client::AppClient;
use crate::client::device_linking::{ClientLinkingError, PreparedDeviceLinking};
use crate::device_linking::{LinkFrame, LinkingContext, PeerOffer, Role, VerifiedPairing};
use cgka_engine::device_group_snapshot::CandidateDeviceGroupSnapshot;
use cgka_traits::GroupId;
use cgka_traits::device_linking_key_package::PurposeAttemptScope;
use tokio::sync::oneshot;

type Reply<T> = oneshot::Sender<Result<T, ClientLinkingError>>;
impl AccountManager {
    pub(crate) fn device_pairing_transport(
        &self,
    ) -> (crate::MarmotRelayPlane, Vec<cgka_traits::TransportEndpoint>) {
        (
            self.shared.relay_plane().clone(),
            if self.app.config.pairing_relay_urls.is_empty() {
                &self.app.relay_urls
            } else {
                &self.app.config.pairing_relay_urls
            }
            .iter()
            .cloned()
            .map(cgka_traits::TransportEndpoint)
            .collect(),
        )
    }
}
#[cfg(all(test, feature = "test-policy-overrides"))]
impl VerifierCommand {
    pub(crate) fn native_observe_scope_for_test(&self) -> Option<&PurposeAttemptScope> {
        match self {
            Self::Setup(setup::SetupCommand::Observe { scope, .. }) => Some(scope),
            _ => None,
        }
    }
}
pub(crate) enum VerifierCommand {
    #[cfg(all(
        test,
        feature = "experimental-device-sync",
        feature = "test-policy-overrides"
    ))]
    ArmSiblingPreAuthFailureForTest {
        original: std::sync::Arc<
            crate::client::private_enrollment_proposal::OriginalSiblingSharingApproval,
        >,
        respond: Reply<
            std::sync::Arc<
                crate::client::device_linking::sibling_sharing::SiblingPreAuthFailureProbe,
            >,
        >,
    },
    ArmExistingMemberEnrollment {
        binding: [u8; 32],
        packet: Vec<u8>,
        respond: Reply<()>,
    },
    ExportOwnedEnrollmentRecipientPacket {
        scope: PurposeAttemptScope,
        respond: Reply<Vec<u8>>,
    },
    ArmEndorsedEnrollmentRecipient {
        scope: PurposeAttemptScope,
        packet: Vec<u8>,
        respond: Reply<()>,
    },
    Setup(setup::SetupCommand),
    PrepareEndorsedEnrollmentInvite {
        scope: PurposeAttemptScope,
        respond: Reply<cgka_traits::private_device_invite::PrivateInviteScope>,
    },
    PublishReceivedEnrollmentEndorsement {
        binding: [u8; 32],
        respond: Reply<()>,
    },
    CollectOwnedEnrollmentEndorsements {
        scope: PurposeAttemptScope,
        respond: Reply<usize>,
    },
    ReceivedEnrollmentProposalBindings {
        respond: Reply<Vec<[u8; 32]>>,
    },
    CancelReceivedEnrollmentEndorsement {
        binding: [u8; 32],
        respond: Reply<()>,
    },
    EndorseReceivedEnrollmentProposal {
        binding: [u8; 32],
        respond: Reply<()>,
    },
    EndorseReceivedEnrollmentProposalAndShareChats {
        binding: [u8; 32],
        respond: Reply<
            std::sync::Arc<
                crate::client::private_enrollment_proposal::OriginalSiblingSharingApproval,
            >,
        >,
    },
    PrepareEnrollmentProposal {
        scope: PurposeAttemptScope,
        respond: Reply<()>,
    },
    PublishEnrollmentProposal {
        scope: PurposeAttemptScope,
        respond: Reply<()>,
    },
    ValidateReceivedEnrollmentProposals {
        respond: Reply<usize>,
    },
    #[cfg(all(test, feature = "test-policy-overrides"))]
    CurrentEnrollmentEndpointEoseForTest {
        group: GroupId,
        endpoint: cgka_traits::TransportEndpoint,
        respond: Reply<bool>,
    },
    #[cfg(all(test, feature = "test-policy-overrides"))]
    EnrollmentEndpointEoseForTest {
        group: GroupId,
        transport_group: Vec<u8>,
        endpoint: cgka_traits::TransportEndpoint,
        respond: Reply<bool>,
    },
    #[cfg(all(test, feature = "test-policy-overrides"))]
    DrainEnrollmentObservationsForTest {
        respond:
            Reply<Vec<cgka_engine::private_enrollment_request::AuthenticatedEnrollmentRequest>>,
    },
    CreateGenesis {
        respond: Reply<cgka_engine::device_group_genesis::PrivateDeviceGroupGenesisEvidence>,
    },
    ReserveApprover {
        respond: Reply<PurposeAttemptScope>,
    },
    Candidate {
        group: GroupId,
        respond: Reply<Option<CandidateDeviceGroupSnapshot>>,
    },
    ExportPredecessor {
        group: GroupId,
        respond: Reply<Option<Vec<u8>>>,
    },
    BeginWithPredecessor {
        scope: PurposeAttemptScope,
        context: Box<LinkingContext>,
        role: Role,
        artifact: Vec<u8>,
        respond: Reply<()>,
    },
    Begin {
        scope: PurposeAttemptScope,
        context: Box<LinkingContext>,
        role: Role,
        respond: Reply<()>,
    },
    Offer {
        scope: PurposeAttemptScope,
        respond: Reply<PeerOffer>,
    },
    AdmitPeer {
        scope: PurposeAttemptScope,
        offer: PeerOffer,
        respond: Reply<()>,
    },
    Start {
        scope: PurposeAttemptScope,
        respond: Reply<()>,
    },
    Receive {
        scope: PurposeAttemptScope,
        frame: LinkFrame,
        respond: Reply<()>,
    },
    Outgoing {
        scope: PurposeAttemptScope,
        respond: Reply<Vec<LinkFrame>>,
    },
    Acknowledge {
        scope: PurposeAttemptScope,
        token: String,
        respond: Reply<()>,
    },
    Decimals {
        scope: PurposeAttemptScope,
        respond: Reply<Option<(u16, u16, u16)>>,
    },
    Confirm {
        scope: PurposeAttemptScope,
        respond: Reply<()>,
    },
    ArmSingletonRecipient {
        scope: PurposeAttemptScope,
        respond: Reply<()>,
    },
    PreparePrivateInvite {
        scope: PurposeAttemptScope,
        respond: Reply<cgka_traits::private_device_invite::PrivateInviteScope>,
    },
    PublishPrivateWelcomes {
        scope: PurposeAttemptScope,
        respond: Reply<()>,
    },
    PublishPrivateCommit {
        scope: PurposeAttemptScope,
        respond: Reply<()>,
    },
    #[cfg(all(test, feature = "test-policy-overrides"))]
    RejectForeignSettlementGuardForTest {
        respond: Reply<()>,
    },
    #[cfg(all(test, feature = "test-policy-overrides"))]
    ProposalHandoffSnapshotForTest {
        scope: PurposeAttemptScope,
        respond: Reply<crate::client::device_linking::ProposalHandoffSnapshotForTest>,
    },
    #[cfg(all(test, feature = "test-policy-overrides"))]
    CaptureProposalOnlyCancelForTest {
        scope: PurposeAttemptScope,
        respond: Reply<crate::client::device_linking::ProposalOnlyCancelObservationHandleForTest>,
    },
    #[cfg(all(test, feature = "test-policy-overrides"))]
    CheckOwnedPermissionForTest {
        respond: Reply<()>,
    },
    #[cfg(all(test, feature = "test-policy-overrides"))]
    PublishPrivateSettlementForTest {
        scope: PurposeAttemptScope,
        respond: Reply<()>,
    },
    TakeVerified {
        scope: PurposeAttemptScope,
        respond: Reply<VerifiedPairing>,
    },
}

/// Called only from the serial account worker; no frozen-read bypass.
pub(super) async fn handle_verifier_command(
    client: &mut AppClient,
    command: VerifierCommand,
    publication_control: &super::private_commit::PublicationControl,
) {
    match command {
        #[cfg(all(
            test,
            feature = "experimental-device-sync",
            feature = "test-policy-overrides"
        ))]
        VerifierCommand::ArmSiblingPreAuthFailureForTest { original, respond } => {
            let result = client.arm_sibling_pre_auth_failure(&original).map_err(|_| {
                ClientLinkingError::Owner(crate::device_linking::OwnerError::Verifier(
                    crate::device_linking::LinkError::InvalidContext,
                ))
            });
            let _ = respond.send(result);
        }
        VerifierCommand::ArmExistingMemberEnrollment {
            binding,
            packet,
            respond,
        } => {
            let result = client.arm_existing_member_enrollment(&binding, &packet);
            if respond.send(result).is_err() {
                let _ = client.cancel_received_enrollment_endorsement(&binding);
            }
        }
        VerifierCommand::ExportOwnedEnrollmentRecipientPacket { scope, respond } => {
            let result = client.export_owned_enrollment_recipient_packet(&scope);
            if respond.send(result).is_err() {
                let _ = client.cancel_device_linking_scope(&scope).await;
            }
        }
        VerifierCommand::ArmEndorsedEnrollmentRecipient {
            scope,
            packet,
            respond,
        } => {
            let result = client
                .arm_endorsed_enrollment_recipient(&scope, &packet)
                .await;
            if respond.send(result).is_err() {
                let _ = client.cancel_device_linking_scope(&scope).await;
            }
        }
        VerifierCommand::Setup(command) => {
            setup::handle(client, command, publication_control).await
        }
        VerifierCommand::PrepareEndorsedEnrollmentInvite { scope, respond } => {
            let result = client
                .prepare_owned_endorsed_enrollment_invite(&scope)
                .await;
            if result.is_ok()
                && let Ok((_, gate)) = client.private_commit_control(&scope)
            {
                publication_control.install(scope.clone(), gate);
            }
            #[cfg(all(test, feature = "test-policy-overrides"))]
            publication_control.record_prepare_reply_for_test(&scope, result.is_ok());
            if respond.send(result).is_err() {
                let _ = client.cancel_device_linking_scope(&scope).await;
            }
        }
        VerifierCommand::PublishReceivedEnrollmentEndorsement { binding, respond } => {
            let _ = binding;
            let _ = respond.send(Err(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier,
            )));
        }
        VerifierCommand::CollectOwnedEnrollmentEndorsements { scope, respond } => {
            let _ = respond.send(client.collect_owned_enrollment_endorsements(&scope));
        }
        VerifierCommand::ReceivedEnrollmentProposalBindings { respond } => {
            let _ = respond.send(client.received_enrollment_proposal_bindings());
        }
        VerifierCommand::EndorseReceivedEnrollmentProposal { binding, respond } => {
            let result = client.endorse_received_enrollment_proposal(&binding);
            if respond.send(result).is_err() {
                let _ = client.cancel_received_enrollment_endorsement(&binding);
            }
        }
        VerifierCommand::EndorseReceivedEnrollmentProposalAndShareChats { binding, respond } => {
            let result = client.endorse_received_enrollment_proposal_and_share_chats(&binding);
            if let Err(result) = respond.send(result) {
                if let Ok(original) = result {
                    original.cancel();
                }
                let _ = client.cancel_received_enrollment_endorsement(&binding);
            }
        }
        VerifierCommand::CancelReceivedEnrollmentEndorsement { binding, respond } => {
            let _ = respond.send(client.cancel_received_enrollment_endorsement(&binding));
        }
        VerifierCommand::ValidateReceivedEnrollmentProposals { respond } => {
            let _ = respond.send(client.validate_received_enrollment_proposals());
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        VerifierCommand::CurrentEnrollmentEndpointEoseForTest {
            group,
            endpoint,
            respond,
        } => {
            let component = client
                .runtime
                .session()
                .app_component(&group, crate::NOSTR_ROUTING_COMPONENT_ID)
                .unwrap()
                .unwrap();
            let route = cgka_traits::app_components::decode_nostr_routing_v1(&component).unwrap();
            let result = client
                .app
                .relay_plane
                .enrollment_endpoint_eose_for_test(
                    &client.runtime.session().self_id(),
                    &group,
                    &route.nostr_group_id,
                    endpoint,
                )
                .await;
            let _ = respond.send(Ok(result));
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        VerifierCommand::EnrollmentEndpointEoseForTest {
            group,
            transport_group,
            endpoint,
            respond,
        } => {
            let result = client
                .app
                .relay_plane
                .enrollment_endpoint_eose_for_test(
                    &client.runtime.session().self_id(),
                    &group,
                    &transport_group,
                    endpoint,
                )
                .await;
            let _ = respond.send(Ok(result));
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        VerifierCommand::DrainEnrollmentObservationsForTest { respond } => {
            let _ = respond.send(
                client
                    .runtime
                    .session_mut()
                    .drain_authenticated_enrollment_requests()
                    .map_err(ClientLinkingError::Engine),
            );
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        VerifierCommand::PublishPrivateSettlementForTest { scope, respond } => {
            let _ = respond.send(client.dispatch_owned_private_settlement(&scope).await);
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        VerifierCommand::RejectForeignSettlementGuardForTest { respond } => {
            let _ = respond.send(client.reject_foreign_guard_against_real_settlement_for_test());
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        VerifierCommand::ProposalHandoffSnapshotForTest { scope, respond } => {
            let _ = respond.send(client.proposal_handoff_snapshot_for_test(&scope));
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        VerifierCommand::CaptureProposalOnlyCancelForTest { scope, respond } => {
            let _ = respond.send(client.capture_proposal_only_cancel_for_test(&scope));
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        VerifierCommand::CheckOwnedPermissionForTest { respond } => {
            let _ = respond.send(client.check_owned_private_commit_permission_for_test());
        }
        VerifierCommand::CreateGenesis { respond } => {
            // A completed birth is durable provenance, not a pending verifier.
            // Dropping a reply cannot restore consent or undo its SQL creation.
            let _ = respond.send(client.create_private_device_group_genesis());
        }
        VerifierCommand::ReserveApprover { respond } => {
            let result = client
                .reserve_device_linking()
                .map_err(ClientLinkingError::Owner);
            if let Err(Ok(scope)) = respond.send(result)
                && client.cancel_device_linking_scope(&scope).await.is_err()
            {
                tracing::debug!(target: "marmot_app::device_linking", method = "worker_abandoned_approver_reservation", "device linking cleanup deferred");
            }
        }
        VerifierCommand::Candidate { group, respond } => {
            let _ = respond.send(
                client
                    .runtime
                    .session()
                    .candidate_device_group_snapshot(&group)
                    .map_err(ClientLinkingError::Engine),
            );
        }
        VerifierCommand::ExportPredecessor { group, respond } => {
            let _ = respond.send(
                client
                    .runtime
                    .session()
                    .export_settled_device_predecessor(&group)
                    .map_err(ClientLinkingError::Engine),
            );
        }
        VerifierCommand::BeginWithPredecessor {
            scope,
            context,
            role,
            artifact,
            respond,
        } => {
            let result = client
                .begin_device_linking_with_predecessor(&scope, *context, role, &artifact)
                .await;
            if let Err(Ok(())) = respond.send(result)
                && client.cancel_device_linking_scope(&scope).await.is_err()
            {
                tracing::debug!(target: "marmot_app::device_linking", method = "worker_abandoned_artifact_setup", "device linking cleanup deferred");
            }
        }
        VerifierCommand::Begin {
            scope,
            context,
            role,
            respond,
        } => {
            let _ = respond.send(client.begin_device_linking(&scope, *context, role).await);
        }
        VerifierCommand::Offer { scope, respond } => {
            let _ = respond.send(client.device_linking_offer(&scope));
        }
        VerifierCommand::AdmitPeer {
            scope,
            offer,
            respond,
        } => {
            let _ = respond.send(client.admit_device_linking_peer(&scope, &offer).await);
        }
        VerifierCommand::Start { scope, respond } => {
            let _ = respond.send(client.start_device_linking_verification(&scope).await);
        }
        VerifierCommand::Receive {
            scope,
            frame,
            respond,
        } => {
            let _ = respond.send(client.receive_device_linking_frame(&scope, &frame).await);
        }
        VerifierCommand::Outgoing { scope, respond } => {
            let _ = respond.send(client.device_linking_outgoing(&scope));
        }
        VerifierCommand::Acknowledge {
            scope,
            token,
            respond,
        } => {
            let _ = respond.send(
                client
                    .acknowledge_device_linking_frame(&scope, &token)
                    .await,
            );
        }
        VerifierCommand::Decimals { scope, respond } => {
            let _ = respond.send(client.device_linking_decimals(&scope));
        }
        VerifierCommand::Confirm { scope, respond } => {
            let _ = respond.send(client.confirm_device_linking(&scope).await);
        }
        VerifierCommand::ArmSingletonRecipient { scope, respond } => {
            let result = client.arm_singleton_device_welcome(&scope).await;
            if respond.send(result).is_err()
                && client.cancel_device_linking_scope(&scope).await.is_err()
            {
                tracing::debug!(target: "marmot_app::device_linking", method = "worker_abandoned_recipient_arm", "device linking cleanup deferred");
            }
        }
        VerifierCommand::PrepareEnrollmentProposal { scope, respond } => {
            let result = client.prepare_owned_enrollment_proposal(&scope).await;
            if result.is_ok()
                && let Ok((_, gate)) = client.enrollment_proposal_control(&scope)
            {
                publication_control.install_proposal(
                    scope.clone(),
                    gate,
                    client.proposal_retirement_for_control(&scope),
                );
            }
            if respond.send(result).is_err() {
                let _ = client.cancel_device_linking_scope(&scope).await;
            }
        }
        VerifierCommand::PublishEnrollmentProposal { respond, .. } => {
            let _ = respond.send(Err(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier,
            )));
        }
        VerifierCommand::PreparePrivateInvite { scope, respond } => {
            let result = client.prepare_private_device_invite(&scope).await;
            if result.is_ok()
                && let Ok((_, gate)) = client.private_commit_control(&scope)
            {
                publication_control.install(scope.clone(), gate);
            }
            // Failed wrapping can leave an exact raw draft for retry. If its
            // reply is abandoned, revoke and clean that attempt too.
            if respond.send(result).is_err()
                && client.cancel_device_linking_scope(&scope).await.is_err()
            {
                tracing::debug!(target: "marmot_app::device_linking", method = "worker_abandoned_private_invite", "device linking cleanup deferred");
            }
        }
        VerifierCommand::PublishPrivateWelcomes { scope, respond } => {
            // Deliberate unsupported boundary until dedicated Engine delivery
            // validates both the confirmed successor and original owned lease.
            let _ = scope;
            let _ = respond.send(Err(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier,
            )));
        }
        VerifierCommand::PublishPrivateCommit { scope: _, respond } => {
            let _ = respond.send(Err(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier,
            )));
        }
        VerifierCommand::TakeVerified { scope, respond } => {
            let _ = respond.send(client.take_device_linking_verified(&scope).await);
        }
    }
}

fn runtime_error(error: AppError) -> ClientLinkingError {
    ClientLinkingError::Runtime(Box::new(error))
}
async fn response<T>(
    receiver: oneshot::Receiver<Result<T, ClientLinkingError>>,
) -> Result<T, ClientLinkingError> {
    match tokio::time::timeout(super::APP_RUNTIME_WORKER_RESPONSE_WAIT, receiver).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(runtime_error(AppError::TransportClosed)),
        Err(_) => Err(runtime_error(AppError::AccountWorkerResponseTimedOut)),
    }
}
impl AccountManager {
    #[cfg(all(
        test,
        feature = "experimental-device-sync",
        feature = "test-policy-overrides"
    ))]
    pub(crate) async fn arm_sibling_pre_auth_failure_for_test(
        &self,
        account_ref: &str,
        original: std::sync::Arc<
            crate::client::private_enrollment_proposal::OriginalSiblingSharingApproval,
        >,
    ) -> Result<
        std::sync::Arc<crate::client::device_linking::sibling_sharing::SiblingPreAuthFailureProbe>,
        ClientLinkingError,
    > {
        self.verifier_command(account_ref, |respond| {
            VerifierCommand::ArmSiblingPreAuthFailureForTest { original, respond }
        })
        .await
    }
    async fn verifier_command<T>(
        &self,
        account_ref: &str,
        make: impl FnOnce(Reply<T>) -> VerifierCommand,
    ) -> Result<T, ClientLinkingError> {
        let commands = self
            .worker_commands(account_ref)
            .await
            .map_err(runtime_error)?;
        let (respond, receiver) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::DeviceLinkingVerifier(Box::new(make(
                respond,
            ))))
            .await
            .map_err(|_| runtime_error(AppError::TransportClosed))?;
        response(receiver).await
    }
    pub(crate) async fn publish_private_device_invite_commit(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account_ref, |respond| {
            VerifierCommand::PublishPrivateCommit {
                scope: scope.clone(),
                respond,
            }
        })
        .await
    }
    pub(crate) async fn publish_received_enrollment_endorsement(
        &self,
        account_ref: &str,
        binding: &[u8; 32],
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account_ref, |respond| {
            VerifierCommand::PublishReceivedEnrollmentEndorsement {
                binding: *binding,
                respond,
            }
        })
        .await
    }
    pub(crate) async fn collect_owned_enrollment_endorsements(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<usize, ClientLinkingError> {
        self.verifier_command(account_ref, |respond| {
            VerifierCommand::CollectOwnedEnrollmentEndorsements {
                scope: scope.clone(),
                respond,
            }
        })
        .await
    }
    pub(crate) async fn cancel_received_enrollment_endorsement(
        &self,
        account_ref: &str,
        binding: &[u8; 32],
    ) -> Result<(), ClientLinkingError> {
        // Negative-only revocation reaches the exact active B action before
        // blocked queue admission, just like existing original SDK cancellation.
        let account = self.resolve(account_ref).map_err(runtime_error)?;
        if let Some(worker) = self.workers.lock().await.get(&account.account_id_hex) {
            worker.publication_control.revoke_endorsement(binding);
        }
        self.verifier_command(account_ref, |respond| {
            VerifierCommand::CancelReceivedEnrollmentEndorsement {
                binding: *binding,
                respond,
            }
        })
        .await
    }
    pub(crate) async fn reserve_device_linking_for_approver(
        &self,
        account_ref: &str,
    ) -> Result<PurposeAttemptScope, ClientLinkingError> {
        self.verifier_command(account_ref, |respond| VerifierCommand::ReserveApprover {
            respond,
        })
        .await
    }
    pub(crate) async fn create_private_device_group_genesis(
        &self,
        account_ref: &str,
    ) -> Result<
        cgka_engine::device_group_genesis::PrivateDeviceGroupGenesisEvidence,
        ClientLinkingError,
    > {
        self.verifier_command(account_ref, |respond| VerifierCommand::CreateGenesis {
            respond,
        })
        .await
    }
    pub(crate) async fn candidate_device_group_snapshot(
        &self,
        account_ref: &str,
        group: &GroupId,
    ) -> Result<Option<CandidateDeviceGroupSnapshot>, ClientLinkingError> {
        self.verifier_command(account_ref, |respond| VerifierCommand::Candidate {
            group: group.clone(),
            respond,
        })
        .await
    }
    pub(crate) async fn export_settled_device_predecessor(
        &self,
        account_ref: &str,
        group: &GroupId,
    ) -> Result<Option<Vec<u8>>, ClientLinkingError> {
        self.verifier_command(account_ref, |respond| VerifierCommand::ExportPredecessor {
            group: group.clone(),
            respond,
        })
        .await
    }

    pub(crate) async fn begin_device_linking_with_predecessor(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
        context: LinkingContext,
        role: Role,
        artifact: Vec<u8>,
    ) -> Result<(), ClientLinkingError> {
        if artifact.is_empty() || artifact.len() > 256 * 1024 {
            return Err(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
            ));
        }
        self.verifier_command(account_ref, |respond| {
            VerifierCommand::BeginWithPredecessor {
                scope: scope.clone(),
                context: Box::new(context),
                role,
                artifact,
                respond,
            }
        })
        .await
    }

    pub(crate) async fn begin_device_linking(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
        context: LinkingContext,
        role: Role,
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account_ref, |respond| VerifierCommand::Begin {
            scope: scope.clone(),
            context: Box::new(context),
            role,
            respond,
        })
        .await
    }
    pub(crate) async fn device_linking_offer(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<PeerOffer, ClientLinkingError> {
        self.verifier_command(account_ref, |respond| VerifierCommand::Offer {
            scope: scope.clone(),
            respond,
        })
        .await
    }
    pub(crate) async fn admit_device_linking_peer(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
        offer: PeerOffer,
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account_ref, |respond| VerifierCommand::AdmitPeer {
            scope: scope.clone(),
            offer,
            respond,
        })
        .await
    }
    pub(crate) async fn start_device_linking_verification(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account_ref, |respond| VerifierCommand::Start {
            scope: scope.clone(),
            respond,
        })
        .await
    }
    pub(crate) async fn receive_device_linking_frame(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
        frame: LinkFrame,
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account_ref, |respond| VerifierCommand::Receive {
            scope: scope.clone(),
            frame,
            respond,
        })
        .await
    }
    pub(crate) async fn device_linking_outgoing(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<Vec<LinkFrame>, ClientLinkingError> {
        self.verifier_command(account_ref, |respond| VerifierCommand::Outgoing {
            scope: scope.clone(),
            respond,
        })
        .await
    }
    pub(crate) async fn acknowledge_device_linking_frame(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
        token: String,
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account_ref, |respond| VerifierCommand::Acknowledge {
            scope: scope.clone(),
            token,
            respond,
        })
        .await
    }
    pub(crate) async fn device_linking_decimals(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<Option<(u16, u16, u16)>, ClientLinkingError> {
        self.verifier_command(account_ref, |respond| VerifierCommand::Decimals {
            scope: scope.clone(),
            respond,
        })
        .await
    }
    pub(crate) async fn confirm_device_linking(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account_ref, |respond| VerifierCommand::Confirm {
            scope: scope.clone(),
            respond,
        })
        .await
    }
    pub(crate) async fn arm_singleton_device_welcome(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account_ref, |respond| {
            VerifierCommand::ArmSingletonRecipient {
                scope: scope.clone(),
                respond,
            }
        })
        .await
    }
    pub(crate) async fn prepare_enrollment_proposal(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account_ref, |respond| {
            VerifierCommand::PrepareEnrollmentProposal {
                scope: scope.clone(),
                respond,
            }
        })
        .await
    }
    pub(crate) async fn publish_enrollment_proposal(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.verifier_command(account_ref, |respond| {
            VerifierCommand::PublishEnrollmentProposal {
                scope: scope.clone(),
                respond,
            }
        })
        .await
    }
    pub(crate) async fn export_owned_enrollment_recipient_packet(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<Vec<u8>, ClientLinkingError> {
        self.verifier_command(account_ref, |respond| {
            VerifierCommand::ExportOwnedEnrollmentRecipientPacket {
                scope: scope.clone(),
                respond,
            }
        })
        .await
    }
    pub(crate) async fn arm_endorsed_enrollment_recipient(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
        packet: &[u8],
    ) -> Result<(), ClientLinkingError> {
        if packet.is_empty() || packet.len() > 16 * 1024 {
            return Err(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
            ));
        }
        self.verifier_command(account_ref, |respond| {
            VerifierCommand::ArmEndorsedEnrollmentRecipient {
                scope: scope.clone(),
                packet: packet.to_vec(),
                respond,
            }
        })
        .await
    }
    pub(crate) async fn prepare_endorsed_enrollment_invite(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<cgka_traits::private_device_invite::PrivateInviteScope, ClientLinkingError> {
        self.verifier_command(account_ref, |respond| {
            VerifierCommand::PrepareEndorsedEnrollmentInvite {
                scope: scope.clone(),
                respond,
            }
        })
        .await
    }
    pub(crate) async fn prepare_private_device_invite(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<cgka_traits::private_device_invite::PrivateInviteScope, ClientLinkingError> {
        self.verifier_command(account_ref, |respond| {
            VerifierCommand::PreparePrivateInvite {
                scope: scope.clone(),
                respond,
            }
        })
        .await
    }
    pub(crate) async fn take_device_linking_verified(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<VerifiedPairing, ClientLinkingError> {
        self.verifier_command(account_ref, |respond| VerifierCommand::TakeVerified {
            scope: scope.clone(),
            respond,
        })
        .await
    }
    pub(crate) async fn prepare_device_linking(
        &self,
        account_ref: &str,
    ) -> Result<PreparedDeviceLinking, ClientLinkingError> {
        let commands = self
            .worker_commands(account_ref)
            .await
            .map_err(runtime_error)?;
        let (respond, receiver) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::PrepareDeviceLinking { respond })
            .await
            .map_err(|_| runtime_error(AppError::TransportClosed))?;
        response(receiver).await
    }
    pub(crate) async fn cancel_device_linking(
        &self,
        account_ref: &str,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        // Exact-scope revocation bypasses saturated command admission. This slot
        // is installed only by the actor and can never issue consent.
        let account = self.resolve(account_ref).map_err(runtime_error)?;
        if let Some(worker) = self.workers.lock().await.get(&account.account_id_hex) {
            worker.publication_control.revoke(scope);
        }
        let commands = self
            .worker_commands(account_ref)
            .await
            .map_err(runtime_error)?;
        let (respond, receiver) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::CancelDeviceLinking {
                scope: scope.clone(),
                respond,
            })
            .await
            .map_err(|_| runtime_error(AppError::TransportClosed))?;
        response(receiver).await
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) async fn maintain_device_linking_at_for_test(
        &self,
        account_ref: &str,
        now: std::time::Instant,
    ) -> Result<(), ClientLinkingError> {
        let commands = self
            .worker_commands(account_ref)
            .await
            .map_err(runtime_error)?;
        let (respond, receiver) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::MaintainDeviceLinkingAtForTest { now, respond })
            .await
            .map_err(|_| runtime_error(AppError::TransportClosed))?;
        response(receiver).await
    }
}

#[cfg(all(test, feature = "test-policy-overrides"))]
mod tests {
    use super::*;
    use crate::MarmotApp;
    use crate::device_linking::{LinkingContext, Role};
    use crate::runtime::MarmotAppRuntime;
    use crate::tests::ScriptedPushRelayClient;
    use marmot_account::AccountHome;
    use std::sync::Arc;

    #[cfg(feature = "experimental-device-sync")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expired_automatic_scan_is_rejected_after_real_roster_wait() {
        use crate::device_linking::network::rendezvous::Rendezvous;
        use nostr::prelude::{Keys, Timestamp};
        use std::task::Poll;
        use std::time::Duration;

        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let keys = Keys::generate();
        AccountHome::open(dir.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(
            dir.path(),
            relay.url().await.to_string(),
        ));
        runtime.reconcile_accounts().await.unwrap();
        let accounts = runtime.accounts();
        let initial_targets_empty = accounts
            .device_linking_targets("test")
            .await
            .unwrap()
            .is_empty();

        // Hold the real account-worker acquisition, not a fabricated roster reply.
        let held_workers = accounts.workers.lock().await;
        let now = Timestamp::now().as_secs();
        let expires_at = now + 2;
        let code = Rendezvous::new(Keys::generate().public_key(), expires_at)
            .encode(now)
            .unwrap();
        let initially_valid = Rendezvous::decode(&code, Timestamp::now().as_secs()).is_ok();
        let mut scan = Box::pin(accounts.scan_automatic_device_linking_session("test", code));
        let mut early_result = None;
        let roster_wait_pending = match futures::poll!(scan.as_mut()) {
            Poll::Pending => true,
            Poll::Ready(result) => {
                early_result = Some(result);
                false
            }
        };
        let initial_code_valid = initially_valid && Timestamp::now().as_secs() < expires_at;
        // This QR's original two-second expiry is never renewed or clock-shifted.
        let wall_expired_before_release = tokio::time::timeout(Duration::from_secs(5), async {
            while Timestamp::now().as_secs() < expires_at {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok()
            && Timestamp::now().as_secs() >= expires_at;
        drop(held_workers);
        let outcome = match early_result {
            Some(result) => Ok(result),
            None => tokio::time::timeout(Duration::from_secs(5), scan.as_mut()).await,
        };
        let (scan_completed, expired_scan_rejected, session_cleanup) = match outcome {
            Ok(Err(crate::DeviceLinkingError::InvalidPacket)) => (true, true, true),
            Ok(Err(_)) => (true, false, true),
            Ok(Ok(session)) => (
                true,
                false,
                tokio::time::timeout(Duration::from_secs(5), session.cancel())
                    .await
                    .is_ok_and(|result| result.is_ok()),
            ),
            Err(_) => (false, false, true),
        };
        drop(scan);
        let runtime_cleanup = tokio::time::timeout(
            Duration::from_secs(10),
            runtime.shutdown_and_close(),
        )
        .await
        .is_ok_and(|result| result.is_ok());
        drop(relay);
        let cleanup_succeeded = session_cleanup && runtime_cleanup;
        eprintln!(
            "AUTOMATIC_SCAN_EXPIRY_PROBE {}",
            serde_json::json!({
                "initial_targets_empty": initial_targets_empty,
                "initial_code_valid": initial_code_valid,
                "roster_wait_pending": roster_wait_pending,
                "wall_expired_before_release": wall_expired_before_release,
                "scan_completed": scan_completed,
                "cleanup_succeeded": cleanup_succeeded,
                "expired_scan_rejected": expired_scan_rejected,
            })
        );
        assert!(
            initial_targets_empty
                && initial_code_valid
                && roster_wait_pending
                && wall_expired_before_release
                && scan_completed
                && cleanup_succeeded,
            "held roster expiry fixture prerequisites must complete before the verdict"
        );
        assert!(
            expired_scan_rejected,
            "expired scanned bootstrap must not be renewed by the protected roster wait"
        );
    }

    async fn drain(
        from: &AccountManager,
        from_scope: &PurposeAttemptScope,
        to: &AccountManager,
        to_scope: &PurposeAttemptScope,
    ) {
        for frame in from
            .device_linking_outgoing("test", from_scope)
            .await
            .unwrap()
        {
            let token = frame.acknowledgement_token().to_owned();
            to.receive_device_linking_frame("test", to_scope, frame)
                .await
                .unwrap();
            from.acknowledge_device_linking_frame("test", from_scope, token)
                .await
                .unwrap();
        }
    }

    struct VerifiedWorkers {
        directories: [tempfile::TempDir; 2],
        runtime_a: MarmotAppRuntime,
        runtime_b: MarmotAppRuntime,
        a: AccountManager,
        b: AccountManager,
        prepared: PreparedDeviceLinking,
        b_scope: PurposeAttemptScope,
        relay_b: Arc<ScriptedPushRelayClient>,
        relay_a: Arc<ScriptedPushRelayClient>,
    }
    async fn verified_workers() -> VerifiedWorkers {
        verified_workers_at("wss://relay.example").await
    }
    async fn verified_workers_at(relay_url: &str) -> VerifiedWorkers {
        verified_workers_with_transport(relay_url, true).await
    }
    async fn verified_workers_with_transport(relay_url: &str, scripted: bool) -> VerifiedWorkers {
        let keys = nostr::prelude::Keys::generate();
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        for dir in [&a_dir, &b_dir] {
            AccountHome::open(dir.path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
        }
        let relay_a = Arc::new(ScriptedPushRelayClient::default());
        let app_a = MarmotApp::with_relay(a_dir.path(), relay_url);
        let app_a = if scripted {
            app_a.with_test_relay_client(relay_a.clone())
        } else {
            app_a
        };
        let relay_b = Arc::new(ScriptedPushRelayClient::default());
        let app_b = MarmotApp::with_relay(b_dir.path(), relay_url);
        let app_b = if scripted {
            app_b.with_test_relay_client(relay_b.clone())
        } else {
            app_b
        };
        let runtime_a = MarmotAppRuntime::new(app_a.clone());
        let runtime_b = MarmotAppRuntime::new(app_b.clone());
        runtime_a.reconcile_accounts().await.unwrap();
        runtime_b.reconcile_accounts().await.unwrap();
        let a = runtime_a.accounts();
        let b = runtime_b.accounts();
        let prepared = a.prepare_device_linking("test").await.unwrap();
        let b_scope = b.reserve_device_linking_for_approver("test").await.unwrap();
        let origin = b.create_private_device_group_genesis("test").await.unwrap();
        let group = origin.group_id().clone();
        let candidate = origin.current();
        let metadata = cgka_engine::key_package::key_package_metadata(&prepared.package).unwrap();
        let context = LinkingContext {
            version: 1,
            nonce: [43; 32],
            new_device_generation: prepared.scope.generation,
            approver_generation: b_scope.generation,
            account: prepared.scope.account,
            exact_key_package: prepared.package.bytes.clone(),
            key_package_reference: hex::decode(metadata.key_package_ref_hex)
                .unwrap()
                .try_into()
                .unwrap(),
            device_group: group.as_slice().to_vec(),
            predecessor: crate::device_linking::PredecessorRoster::from_candidate(candidate)
                .unwrap(),
            approver: b_scope.local_device,
            recipient: prepared.scope.local_device,
        };
        let mut wrong_scope = prepared.scope.clone();
        wrong_scope.local_device = b_scope.local_device;
        assert!(
            a.begin_device_linking("test", &wrong_scope, context.clone(), Role::NewDevice)
                .await
                .is_err()
        );
        a.begin_device_linking("test", &prepared.scope, context.clone(), Role::NewDevice)
            .await
            .unwrap();
        b.begin_device_linking("test", &b_scope, context, Role::Approver)
            .await
            .unwrap();
        let ao = a
            .device_linking_offer("test", &prepared.scope)
            .await
            .unwrap();
        let bo = b.device_linking_offer("test", &b_scope).await.unwrap();
        a.admit_device_linking_peer("test", &prepared.scope, bo)
            .await
            .unwrap();
        b.admit_device_linking_peer("test", &b_scope, ao)
            .await
            .unwrap();
        a.start_device_linking_verification("test", &prepared.scope)
            .await
            .unwrap();
        for _ in 0..8 {
            drain(&a, &prepared.scope, &b, &b_scope).await;
            drain(&b, &b_scope, &a, &prepared.scope).await;
        }
        let digits = a
            .device_linking_decimals("test", &prepared.scope)
            .await
            .unwrap();
        assert!(digits.is_some());
        assert!(digits == b.device_linking_decimals("test", &b_scope).await.unwrap());
        a.confirm_device_linking("test", &prepared.scope)
            .await
            .unwrap();
        b.confirm_device_linking("test", &b_scope).await.unwrap();
        for _ in 0..8 {
            drain(&a, &prepared.scope, &b, &b_scope).await;
            drain(&b, &b_scope, &a, &prepared.scope).await;
        }
        VerifiedWorkers {
            directories: [a_dir, b_dir],
            runtime_a,
            runtime_b,
            a,
            b,
            prepared,
            b_scope,
            relay_b,
            relay_a,
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_managed_workers_complete_scoped_verification_without_native_grants() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            a,
            b,
            prepared,
            b_scope,
            ..
        } = verified_workers().await;
        let _a_proof = a
            .take_device_linking_verified("test", &prepared.scope)
            .await
            .unwrap();
        let _b_proof = b
            .take_device_linking_verified("test", &b_scope)
            .await
            .unwrap();
        assert!(
            a.take_device_linking_verified("test", &prepared.scope)
                .await
                .is_err()
        );
        runtime_a.shutdown().await;
        runtime_b.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_receives_private_welcome_through_relay_without_chat() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            a,
            b,
            prepared,
            b_scope,
            ..
        } = verified_workers().await;
        a.arm_singleton_device_welcome("test", &prepared.scope)
            .await
            .unwrap();
        b.prepare_private_device_invite("test", &b_scope)
            .await
            .unwrap();
        let sender = b.app.account_storage("test").unwrap();
        let fact = cgka_traits::StorageProvider::private_device_invite_storage(&sender)
            .unwrap()
            .private_invite()
            .unwrap()
            .unwrap();
        let transport = fact.transport.unwrap();
        // Fixture supplies genuine prepared transport to qualify recipient routing;
        // sender confirmation/delivery and final settlement are separate gates.
        for message in transport.welcomes {
            let event =
                transport_nostr_peeler::NostrTransportEvent::from_transport_message(&message)
                    .unwrap();
            let routed = a
                .app
                .relay_plane
                .handle_relay_event_for_test(transport_nostr_adapter::NostrRelayEvent {
                    endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
                    subscription_id: None,
                    event,
                })
                .await
                .unwrap();
            assert_eq!(
                routed, 1,
                "private Welcome must enter the actual account delivery queue"
            );
        }
        let recipient = a.app.account_storage("test").unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if cgka_traits::StorageProvider::device_linking_key_package_storage(&recipient)
                    .unwrap()
                    .purpose_key_package()
                    .unwrap()
                    .is_some_and(|row| row.consumed)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("live worker must collect and join its private Welcome through relay ingress");
        let group =
            cgka_traits::GroupStorage::get_group(&recipient, &fact.raw.binding.group_id).unwrap();
        assert_eq!(group.epoch, cgka_traits::EpochId(1));
        assert!(
            cgka_traits::StorageProvider::accepted_device_group_anchor_storage(&recipient)
                .unwrap()
                .accepted_anchor()
                .unwrap()
                .is_some()
        );
        assert!(a.app.load_state("test").unwrap().groups.is_empty());
        runtime_a.shutdown_and_close().await.unwrap();
        runtime_b.shutdown_and_close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_abandoned_recipient_arm_reply_retires_exact_purpose() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            a,
            prepared,
            ..
        } = verified_workers().await;
        let commands = a.worker_commands("test").await.unwrap();
        let (respond, receiver) = oneshot::channel();
        drop(receiver);
        commands
            .send(AccountWorkerCommand::DeviceLinkingVerifier(Box::new(
                VerifierCommand::ArmSingletonRecipient {
                    scope: prepared.scope.clone(),
                    respond,
                },
            )))
            .await
            .unwrap();
        a.maintain_device_linking_at_for_test("test", std::time::Instant::now())
            .await
            .unwrap();
        let storage = a.app.account_storage("test").unwrap();
        assert!(
            cgka_traits::StorageProvider::device_linking_key_package_storage(&storage)
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .is_none(),
            "lost arming reply must retire its exact unjoined package"
        );
        let next = a.prepare_device_linking("test").await.unwrap();
        assert!(next.scope.generation > prepared.scope.generation);
        assert!(
            a.arm_singleton_device_welcome("test", &prepared.scope)
                .await
                .is_err()
        );
        runtime_a.shutdown_and_close().await.unwrap();
        runtime_b.shutdown_and_close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_ordinary_welcome_preserves_live_private_recipient_gate() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            a,
            b,
            prepared,
            b_scope,
            relay_a,
            ..
        } = verified_workers().await;
        let mut stale = prepared.scope.clone();
        stale.generation += 1;
        assert!(
            a.arm_singleton_device_welcome("test", &stale)
                .await
                .is_err()
        );
        a.arm_singleton_device_welcome("test", &prepared.scope)
            .await
            .unwrap();
        a.publish_key_package("test").await.unwrap();
        let mut package = a
            .durably_owned_key_packages("test")
            .await
            .unwrap()
            .into_iter()
            .find(|package| package.bytes != prepared.package.bytes)
            .expect("ordinary lifecycle package must remain separate from private purpose");
        // Owned MLS bytes omit transport provenance; use the actual published
        // event for this exact routine package, not a fabricated Welcome e tag.
        use base64::Engine as _;
        let published = relay_a
            .published_events_snapshot()
            .into_iter()
            .find(|event| {
                event.kind == 30443
                    && base64::engine::general_purpose::STANDARD
                        .decode(&event.content)
                        .is_ok_and(|bytes| bytes == package.bytes)
            })
            .expect("ordinary package must have an actual published source event");
        package.source = Some(cgka_traits::engine::KeyPackageSource {
            event_id: cgka_traits::MessageId::new(hex::decode(&published.id).unwrap()),
        });
        let other_dir = tempfile::tempdir().unwrap();
        AccountHome::open(other_dir.path())
            .create_account("other")
            .unwrap();
        let other_app = MarmotApp::with_relay(other_dir.path(), "wss://relay.example");
        let plane =
            crate::MarmotRelayPlane::new(None, Arc::new(ScriptedPushRelayClient::default()));
        let mut other = other_app
            .local_client_with_relay_plane("other", &plane, None)
            .await
            .unwrap();
        let routing = other_app.new_nostr_routing(None).unwrap();
        let created = other
            .runtime
            .session_mut()
            .create_group(cgka_traits::engine::CreateGroupRequest {
                name: "ordinary invitation coexistence".into(),
                description: String::new(),
                members: vec![package],
                required_features: vec![],
                initial_admins: vec![],
                app_components: vec![cgka_traits::app_components::AppComponentData {
                    component_id: cgka_traits::app_components::NOSTR_ROUTING_COMPONENT_ID,
                    data: cgka_traits::app_components::encode_nostr_routing_v1(&routing).unwrap(),
                }],
            })
            .await
            .unwrap();
        let mut ordinary = Vec::new();
        for work in created.effects.publish {
            match work {
                cgka_session::PublishWork::GroupCreated { welcomes, .. }
                | cgka_session::PublishWork::FoundingGroupCreated { welcomes } => {
                    ordinary.extend(welcomes)
                }
                _ => {}
            }
        }
        assert!(!ordinary.is_empty());
        let recipient = a.app.account_storage("test").unwrap();
        for message in ordinary {
            let event =
                transport_nostr_peeler::NostrTransportEvent::from_transport_message(&message)
                    .unwrap();
            assert_eq!(
                a.app
                    .relay_plane
                    .handle_relay_event_for_test(transport_nostr_adapter::NostrRelayEvent {
                        endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
                        subscription_id: None,
                        event,
                    })
                    .await
                    .unwrap(),
                1
            );
        }
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while cgka_traits::GroupStorage::get_group(&recipient, &created.group_id).is_err() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("ordinary invitation must join while private gate is live");
        assert!(
            !cgka_traits::StorageProvider::device_linking_key_package_storage(&recipient)
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .unwrap()
                .consumed
        );
        b.prepare_private_device_invite("test", &b_scope)
            .await
            .unwrap();
        let sender = b.app.account_storage("test").unwrap();
        let fact = cgka_traits::StorageProvider::private_device_invite_storage(&sender)
            .unwrap()
            .private_invite()
            .unwrap()
            .unwrap();
        for message in fact.transport.unwrap().welcomes {
            let event =
                transport_nostr_peeler::NostrTransportEvent::from_transport_message(&message)
                    .unwrap();
            assert_eq!(
                a.app
                    .relay_plane
                    .handle_relay_event_for_test(transport_nostr_adapter::NostrRelayEvent {
                        endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
                        subscription_id: None,
                        event,
                    })
                    .await
                    .unwrap(),
                1
            );
        }
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !cgka_traits::StorageProvider::device_linking_key_package_storage(&recipient)
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .unwrap()
                .consumed
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("ordinary invitation must preserve the real private continuation");
        a.maintain_device_linking_at_for_test("test", std::time::Instant::now())
            .await
            .unwrap();
        let state = a.app.load_state("test").unwrap();
        assert_eq!(state.groups.len(), 1);
        assert!(
            state
                .groups
                .iter()
                .any(|row| row.group_id_hex == hex::encode(created.group_id.as_slice()))
        );
        assert_eq!(
            cgka_traits::GroupStorage::get_group(&recipient, &fact.raw.binding.group_id)
                .unwrap()
                .epoch,
            cgka_traits::EpochId(1)
        );
        drop(other);
        runtime_a.shutdown_and_close().await.unwrap();
        runtime_b.shutdown_and_close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_sql_rollback_retains_exact_live_welcome_for_retry() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            a,
            b,
            prepared,
            b_scope,
            ..
        } = verified_workers().await;
        a.arm_singleton_device_welcome("test", &prepared.scope)
            .await
            .unwrap();
        b.prepare_private_device_invite("test", &b_scope)
            .await
            .unwrap();
        let sender = b.app.account_storage("test").unwrap();
        let fact = cgka_traits::StorageProvider::private_device_invite_storage(&sender)
            .unwrap()
            .private_invite()
            .unwrap()
            .unwrap();
        let path = a.app.account_storage_path("test");
        let keys = a.app.account_home().load_signing_keys("test").unwrap();
        let key = a
            .app
            .sqlcipher_key(
                "test",
                &keys,
                &path,
                crate::sqlcipher::SqlcipherDatabaseKind::Session,
            )
            .unwrap();
        let injector = rusqlite::Connection::open(&path).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &injector,
            &key,
            storage_sqlite::SqlCipherHardening::cipher_only(),
        )
        .unwrap();
        injector.execute_batch("CREATE TRIGGER reject_worker_linking_consumption BEFORE UPDATE OF consumed ON device_linking_key_package WHEN NEW.consumed = 1 BEGIN SELECT RAISE(ABORT,'injected purpose consumption failure'); END;").unwrap();
        let mut events = runtime_a.subscribe_events();
        for message in fact.transport.unwrap().welcomes {
            let event =
                transport_nostr_peeler::NostrTransportEvent::from_transport_message(&message)
                    .unwrap();
            assert_eq!(
                a.app
                    .relay_plane
                    .handle_relay_event_for_test(transport_nostr_adapter::NostrRelayEvent {
                        endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
                        subscription_id: None,
                        event,
                    })
                    .await
                    .unwrap(),
                1
            );
        }
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                match events.recv().await {
                    Some(crate::MarmotAppEvent::AccountError(error))
                        if error.message.starts_with("runtime receive failed") =>
                    {
                        break;
                    }
                    Some(_) => {}
                    None => panic!("worker event stream closed before actual SQL failure"),
                }
            }
        })
        .await
        .expect("actual SQL rollback must be observed through worker error publication");
        injector
            .execute_batch("DROP TRIGGER reject_worker_linking_consumption;")
            .unwrap();
        // No replay injection, replacement verifier or second approval. The actor
        // must retry the retained exact batch under the original owned lease.
        let recipient = a.app.account_storage("test").unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if cgka_traits::StorageProvider::device_linking_key_package_storage(&recipient)
                    .unwrap()
                    .purpose_key_package()
                    .unwrap()
                    .is_some_and(|row| row.scope == prepared.scope && row.consumed)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("SQL rollback must retain and autonomously retry the exact live recipient batch");
        assert_eq!(
            cgka_traits::GroupStorage::get_group(&recipient, &fact.raw.binding.group_id)
                .unwrap()
                .epoch,
            cgka_traits::EpochId(1)
        );
        assert!(
            cgka_traits::StorageProvider::accepted_device_group_anchor_storage(&recipient)
                .unwrap()
                .accepted_anchor()
                .unwrap()
                .is_some()
        );
        assert!(a.app.load_state("test").unwrap().groups.is_empty());
        runtime_a.shutdown_and_close().await.unwrap();
        runtime_b.shutdown_and_close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_prepares_real_private_invite_and_scoped_cancel_retires_it() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            ..
        } = verified_workers().await;
        let invite = b.prepare_private_device_invite("test", &b_scope).await;
        assert!(
            invite.is_ok(),
            "genuine verified worker must prepare a real private invite"
        );
        let invite = invite.unwrap();
        assert!(invite.account == b_scope.account && invite.local_device == b_scope.local_device);
        assert!(invite.staging_generation > 0);
        b.maintain_device_linking_at_for_test("test", std::time::Instant::now())
            .await
            .unwrap();
        let mut stale = b_scope.clone();
        stale.generation += 1;
        assert!(b.cancel_device_linking("test", &stale).await.is_err());
        assert!(
            b.prepare_private_device_invite("test", &stale)
                .await
                .is_err()
        );
        assert!(b.reserve_device_linking_for_approver("test").await.is_err());
        let same = b
            .prepare_private_device_invite("test", &b_scope)
            .await
            .unwrap();
        assert!(same == invite);
        b.cancel_device_linking("test", &b_scope).await.unwrap();
        let next = b.reserve_device_linking_for_approver("test").await.unwrap();
        assert!(next.generation > b_scope.generation);
        runtime_a.shutdown().await;
        runtime_b.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_expiry_retires_owned_preparation_without_restoring_consent() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            ..
        } = verified_workers().await;
        b.prepare_private_device_invite("test", &b_scope)
            .await
            .unwrap();
        b.maintain_device_linking_at_for_test(
            "test",
            std::time::Instant::now() + std::time::Duration::from_secs(3600),
        )
        .await
        .unwrap();
        assert!(
            b.prepare_private_device_invite("test", &b_scope)
                .await
                .is_err()
        );
        let next = b.reserve_device_linking_for_approver("test").await.unwrap();
        assert!(next.generation > b_scope.generation);
        runtime_a.shutdown().await;
        runtime_b.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_abandoned_private_invite_reply_cleans_exact_preparation() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            ..
        } = verified_workers().await;
        let commands = b.worker_commands("test").await.unwrap();
        let (respond, receiver) = oneshot::channel();
        drop(receiver);
        commands
            .send(AccountWorkerCommand::DeviceLinkingVerifier(Box::new(
                VerifierCommand::PreparePrivateInvite {
                    scope: b_scope.clone(),
                    respond,
                },
            )))
            .await
            .unwrap();
        // FIFO maintenance is the barrier after the abandoned response turn.
        b.maintain_device_linking_at_for_test("test", std::time::Instant::now())
            .await
            .unwrap();
        // A failed wrap also permits cleanup. Require the frozen real transport
        // batch to prove this abandoned reply followed successful preparation.
        let storage = b.app.account_storage("test").unwrap();
        let fact = cgka_traits::StorageProvider::private_device_invite_storage(&storage)
            .unwrap()
            .private_invite()
            .unwrap()
            .unwrap();
        assert_eq!(
            fact.phase,
            cgka_traits::private_device_invite::PrivateInvitePhase::Retired
        );
        assert!(fact.raw.binding.approver_scope == b_scope);
        assert!(
            fact.transport
                .is_some_and(|transport| !transport.welcomes.is_empty())
        );
        let next = b.reserve_device_linking_for_approver("test").await.unwrap();
        assert!(next.generation > b_scope.generation);
        assert!(
            b.prepare_private_device_invite("test", &b_scope)
                .await
                .is_err()
        );
        runtime_a.shutdown().await;
        runtime_b.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_hidden_route_unknown_reopen_and_refresh_use_real_echo() {
        let VerifiedWorkers {
            directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            ..
        } = verified_workers().await;
        b.prepare_private_device_invite("test", &b_scope)
            .await
            .unwrap();
        b.publish_private_device_invite_commit("test", &b_scope)
            .await
            .unwrap();
        assert_private_commit_unknown(&b);
        let fact = cgka_traits::StorageProvider::private_device_invite_storage(
            &b.app.account_storage("test").unwrap(),
        )
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
        let event = transport_nostr_peeler::NostrTransportEvent::from_transport_message(
            &fact.transport.as_ref().unwrap().commit,
        )
        .unwrap();
        runtime_a.shutdown_and_close().await.unwrap();
        runtime_b.shutdown_and_close().await.unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(directories[1].path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let mut client = app.client("test").await.unwrap();
        assert!(relay.accepted_subscriptions().iter().any(|subscription| matches!(subscription,
            transport_nostr_adapter::NostrSubscription::Group { group_id, .. } if group_id == &fact.raw.binding.group_id)),
            "encrypted Unknown reopen must restore only its hidden reconciliation subscription");
        assert!(client.state.groups.is_empty());
        // Existing ordinary publication rebuilds routing; it must keep the hidden selection.
        client.publish_key_package().await.unwrap();
        assert!(
            marmot_account::TransportRoutingPolicy::group_subscriptions(&client.routing)
                .iter()
                .any(|route| route.group_id == fact.raw.binding.group_id)
        );
        let cap_storage = app.account_storage("test").unwrap();
        let cap =
            cgka_traits::StorageProvider::private_device_invite_storage(&cap_storage).unwrap();
        assert!(
            cap.private_invite().unwrap().unwrap().phase
                == cgka_traits::private_device_invite::PrivateInvitePhase::PublicationUnknown
        );
        assert!(cap.confirmed_private_invite().unwrap().is_none());
        assert_eq!(
            client
                .relay_plane
                .handle_relay_event_for_test(transport_nostr_adapter::NostrRelayEvent {
                    endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
                    subscription_id: None,
                    event,
                })
                .await
                .unwrap(),
            1
        );
        // The real hidden echo can confirm Core state without a visible sync
        // summary. Drive the bounded drain instead of waiting for a later event.
        tokio::time::timeout(std::time::Duration::from_secs(20), client.sync())
            .await
            .unwrap()
            .unwrap();
        assert!(
            cap.private_invite().unwrap().unwrap().phase
                == cgka_traits::private_device_invite::PrivateInvitePhase::Confirmed
        );
        assert!(cap.confirmed_private_invite().unwrap().unwrap().binding == fact.raw.binding);
        assert!(
            client.state.groups.is_empty() && app.load_state("test").unwrap().groups.is_empty()
        );
        drop(client);
        app.close_storage().unwrap();
    }
    struct CapabilitySwitchRelay {
        url: String,
        reject_negentropy: std::sync::Arc<std::sync::atomic::AtomicBool>,
        rejected: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        stall_exact: std::sync::Arc<std::sync::atomic::AtomicBool>,
        stalled: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for CapabilitySwitchRelay {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn capability_switch_relay(backend: String) -> CapabilitySwitchRelay {
        use futures::{SinkExt, StreamExt};
        use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let reject_negentropy = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let rejected = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stall_exact = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stalled = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stall = stall_exact.clone();
        let blocked = stalled.clone();
        let reject = reject_negentropy.clone();
        let tally = rejected.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break; };
                        assert!(connections.len() < 32, "fixture connection bound");
                        let backend = backend.clone();
                        let reject = reject.clone();
                        let tally = tally.clone();
                        let stall = stall.clone();
                        let blocked = blocked.clone();
                        connections.spawn(async move {
                            let Ok(client) = accept_async(stream).await else { return; };
                            let Ok((upstream, _)) = connect_async(backend).await else { return; };
                            let (mut client_write, mut client_read) = client.split();
                            let (mut upstream_write, mut upstream_read) = upstream.split();
                            loop {
                                tokio::select! {
                                    inbound = client_read.next() => {
                                        let Some(Ok(message)) = inbound else { break; };
                                        if let Message::Text(text) = &message
                                            && text.starts_with("[\"NEG-OPEN\"")
                                            && reject.load(std::sync::atomic::Ordering::SeqCst)
                                        {
                                            tally.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                            let response = serde_json::json!(["NOTICE", "bad msg: unknown cmd NEG-OPEN"]);
                                            if client_write.send(Message::Text(response.to_string().into())).await.is_err() { break; }
                                            continue;
                                        }
                                        if let Message::Text(text) = &message
                                            && stall.load(std::sync::atomic::Ordering::SeqCst)
                                            && let Ok(frame) = serde_json::from_str::<serde_json::Value>(text)
                                            && frame.get(0).and_then(serde_json::Value::as_str) == Some("REQ")
                                            && frame.get(2).and_then(|filter| filter.get("ids")).is_some()
                                        {
                                            blocked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                            continue;
                                        }
                                        if upstream_write.send(message).await.is_err() { break; }
                                    }
                                    outbound = upstream_read.next() => {
                                        let Some(Ok(message)) = outbound else { break; };
                                        if client_write.send(message).await.is_err() { break; }
                                    }
                                }
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        CapabilitySwitchRelay {
            url,
            reject_negentropy,
            rejected,
            stall_exact,
            stalled,
            task,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_private_echo_below_advanced_cursor_is_acquired_autonomously() {
        private_echo_cursor_recovery(false, false, false).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_private_echo_below_cursor_recovers_without_negentropy() {
        private_echo_cursor_recovery(true, false, false).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_stalled_private_echo_keeps_actor_responsive_and_unknown() {
        private_echo_cursor_recovery(true, true, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_dispatching_echo_below_cursor_recovers_after_genuine_intent_restart() {
        private_echo_cursor_recovery(true, false, true).await;
    }

    async fn private_echo_cursor_recovery(
        unsupported_negentropy: bool,
        stall_exact: bool,
        dispatching_restart: bool,
    ) {
        use cgka_traits::private_device_invite::PrivateInvitePhase;
        let uncertain_phase = if dispatching_restart {
            PrivateInvitePhase::Dispatching
        } else {
            PrivateInvitePhase::PublicationUnknown
        };
        use nostr_sdk::prelude::{Client as NostrSdkClient, RelayUrl};
        #[derive(Clone)]
        struct QueryObservation(
            std::sync::Arc<std::sync::Mutex<Vec<nostr_relay_builder::prelude::Filter>>>,
        );
        impl std::fmt::Debug for QueryObservation {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("QueryObservation(redacted)")
            }
        }
        impl nostr_relay_builder::builder::QueryPolicy for QueryObservation {
            fn admit_query<'a>(
                &'a self,
                query: &'a nostr_relay_builder::prelude::Filter,
                _addr: &'a std::net::SocketAddr,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = nostr_relay_builder::builder::PolicyResult>
                        + Send
                        + 'a,
                >,
            > {
                let mut observed = self.0.lock().unwrap();
                assert!(observed.len() < 256, "observational fixture request bound");
                observed.push(query.clone());
                Box::pin(async { nostr_relay_builder::builder::PolicyResult::Accept })
            }
        }
        let observed = QueryObservation(Default::default());
        let relay = nostr_relay_builder::LocalRelay::new(
            nostr_relay_builder::RelayBuilder::default().query_policy(observed.clone()),
        );
        relay.run().await.unwrap();
        let proxy = if unsupported_negentropy {
            Some(capability_switch_relay(relay.url().await.to_string()).await)
        } else {
            None
        };
        let url = if let Some(proxy) = &proxy {
            proxy.url.clone()
        } else {
            relay.url().await.to_string()
        };
        let VerifiedWorkers {
            directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            relay_b,
            ..
        } = verified_workers_at(&url).await;
        b.prepare_private_device_invite("test", &b_scope)
            .await
            .unwrap();
        // This is a genuine publication intent, not a phase-forged UPDATE.
        // The actual prepared commit reaches the publisher; only its subsequent
        // Unknown fact write is faulted, modelling interruption after intent.
        let intent_fault = dispatching_restart.then(|| private_commit_injector(&b));
        if let Some(injector) = &intent_fault {
            injector.execute_batch("CREATE TRIGGER private_restart_unknown_fault BEFORE UPDATE OF phase ON private_device_invite_staging WHEN NEW.phase=3 BEGIN SELECT RAISE(ABORT,'isolated restart uncertainty fault'); END;").unwrap();
            assert!(
                b.publish_private_device_invite_commit("test", &b_scope)
                    .await
                    .is_err()
            );
        } else {
            b.publish_private_device_invite_commit("test", &b_scope)
                .await
                .unwrap();
            assert_private_commit_unknown(&b);
        }
        let fact = cgka_traits::StorageProvider::private_device_invite_storage(
            &b.app.account_storage("test").unwrap(),
        )
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
        assert!(fact.phase == uncertain_phase);
        assert!(
            cgka_traits::StorageProvider::private_device_invite_storage(
                &b.app.account_storage("test").unwrap()
            )
            .unwrap()
            .confirmed_private_invite()
            .unwrap()
            .is_none()
        );
        let event = transport_nostr_peeler::NostrTransportEvent::from_transport_message(
            &fact.transport.as_ref().unwrap().commit,
        )
        .unwrap();
        assert!(relay_b.attempted_event_ids().iter().any(|id| id == &hex::encode(fact.transport.as_ref().unwrap().commit.id.as_slice())), "actual publisher must receive the exact frozen commit before restart");
        // Real wall time, then a real ordinary message/adapter mirror advances
        // the durable account cursor. No fabricated state cursor or private input.
        while crate::unix_now_seconds() <= event.created_at + 2 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        runtime_a.shutdown_and_close().await.unwrap();
        runtime_b.shutdown_and_close().await.unwrap();
        // Remove the fault only after the owner/database have closed: no live
        // maintenance can turn the genuine durable intent into Unknown.
        if let Some(injector) = intent_fault {
            injector
                .execute_batch("DROP TRIGGER private_restart_unknown_fault;")
                .unwrap();
        }
        // The scripted publisher has no EOSE/consumer, so it cannot establish
        // cursor promotion. Use a real third account and ordinary SDK delivery.
        let cursor_app = MarmotApp::with_relay(directories[1].path(), &url);
        let cursor_runtime = MarmotAppRuntime::new(cursor_app.clone());
        cursor_runtime.reconcile_accounts().await.unwrap();
        cursor_runtime
            .accounts()
            .publish_key_package("test")
            .await
            .unwrap();
        let peer_dir = tempfile::tempdir().unwrap();
        AccountHome::open(peer_dir.path())
            .create_account("peer")
            .unwrap();
        let peer_app = MarmotApp::with_relay(peer_dir.path(), &url);
        let mut peer = crate::tests::client_on_app_relay_plane(&peer_app, "peer").await;
        let recipient = hex::encode(b_scope.account);
        let ordinary = peer
            .create_group("ordinary cursor control", &[recipient.as_str()])
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if cursor_app
                    .load_state("test")
                    .unwrap()
                    .groups
                    .iter()
                    .any(|group| group.group_id_hex == hex::encode(ordinary.as_slice()))
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("real ordinary Welcome must join before cursor control message");
        peer.send(&ordinary, b"ordinary cursor progression")
            .await
            .unwrap();
        // Live admission intentionally does not settle an account's very first
        // cursor. The ordinary worker drain commits its received prefix/EOSE.
        cursor_runtime.accounts().catch_up_accounts().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if cursor_app
                    .load_state("test")
                    .unwrap()
                    .last_transport_timestamp
                    .is_some_and(|cursor| cursor > event.created_at + 1)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("real ordinary SDK delivery must advance the persisted cursor");
        let advanced = cursor_app
            .load_state("test")
            .unwrap()
            .last_transport_timestamp
            .unwrap();
        assert!(advanced <= crate::unix_now_seconds());
        assert!(
            cgka_traits::StorageProvider::private_device_invite_storage(
                &cursor_app.account_storage("test").unwrap()
            )
            .unwrap()
            .private_invite()
            .unwrap()
            .is_some_and(|row| row.phase == uncertain_phase)
        );
        cursor_runtime.shutdown_and_close().await.unwrap();
        drop(peer);
        peer_app.relay_plane.shutdown().await;
        peer_app.close_storage().unwrap();
        // Deposit the exact frozen signed commit on the actual websocket relay
        // while the account is offline; subsequent delivery must come from SDK REQ.
        let writer = NostrSdkClient::default();
        let relay_url = RelayUrl::parse(&url).unwrap();
        writer.add_relay(relay_url.clone()).await.unwrap();
        writer
            .try_connect_relay(relay_url.clone(), std::time::Duration::from_secs(5))
            .await
            .unwrap();
        writer
            .send_event(&event.to_verified_nostr_event().unwrap())
            .to([relay_url])
            .await
            .unwrap();
        let mut app = MarmotApp::with_relay(directories[1].path(), &url);
        app.relay_plane = transport_nostr::MarmotRelayPlane::runtime_default_with_loopback(
            std::time::Duration::from_secs(1),
            true,
        );
        assert!(
            app.relay_plane
                .subscription_rebuild_since(Some(advanced))
                .unwrap()
                .0
                > event.created_at
        );
        if let Some(proxy) = &proxy {
            proxy
                .reject_negentropy
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let known = event.to_verified_nostr_event().unwrap();
            let control = writer
                .fetch_events(nostr_sdk::prelude::Filter::new().id(known.id).limit(1))
                .await
                .unwrap();
            assert!(
                control.iter().any(|actual| actual.id == known.id),
                "normal exact-ID query remains available while Negentropy is unsupported"
            );
        }
        observed.0.lock().unwrap().clear();
        if stall_exact {
            proxy
                .as_ref()
                .unwrap()
                .stall_exact
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.reconcile_accounts().await.unwrap();
        let storage = app.account_storage("test").unwrap();
        let cap = cgka_traits::StorageProvider::private_device_invite_storage(&storage).unwrap();
        // Autonomous recovery may finish as soon as reconciliation starts.
        // The offline assertions above establish the original uncertain state;
        // a live observation may see its genuine confirmation. A stalled exact
        // request must still leave it unresolved.
        let observed_fact = cap.private_invite().unwrap().unwrap();
        assert!(observed_fact.raw.binding == fact.raw.binding);
        assert!(
            observed_fact.phase == uncertain_phase
                || (!stall_exact && observed_fact.phase == PrivateInvitePhase::Confirmed)
        );
        assert!(
            runtime
                .accounts()
                .publish_private_device_invite_commit("test", &b_scope)
                .await
                .is_err(),
            "reopen must not reconstruct publication consent"
        );
        let observed_fact = cap.private_invite().unwrap().unwrap();
        assert!(observed_fact.raw.binding == fact.raw.binding);
        assert!(
            observed_fact.phase == uncertain_phase
                || (!stall_exact && observed_fact.phase == PrivateInvitePhase::Confirmed)
        );
        if stall_exact {
            let proxy = proxy.as_ref().unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                while proxy.stalled.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("genuine exact-ID request must become stalled");
            let candidate = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                runtime
                    .accounts()
                    .candidate_device_group_snapshot("test", &fact.raw.binding.group_id),
            )
            .await
            .expect("actor must serve metadata while acquisition is stalled")
            .unwrap();
            assert!(
                candidate.is_none(),
                "uncertain pending tree never becomes a settled candidate"
            );
            let cancelled = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                runtime.accounts().cancel_device_linking("test", &b_scope),
            )
            .await
            .expect("actor must serve stale cancellation while acquisition is stalled");
            assert!(
                cancelled.is_ok(),
                "same-identity old-scope cleanup is idempotent without a live grant"
            );
            let mut wrong_device = b_scope.clone();
            wrong_device.local_device[0] ^= 1;
            let rejected = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                runtime
                    .accounts()
                    .cancel_device_linking("test", &wrong_device),
            )
            .await
            .expect("wrong-device cancellation must remain responsive");
            assert!(
                rejected.is_err(),
                "wrong-device cancellation must be rejected before mutation"
            );
            assert!(
                cap.private_invite().unwrap().unwrap() == fact,
                "negative controls preserve exact unresolved publication"
            );
            assert!(cap.private_invite().unwrap().unwrap().phase == uncertain_phase);
            assert!(cap.confirmed_private_invite().unwrap().is_none());
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                runtime.shutdown_and_close(),
            )
            .await
            .expect("shutdown must interrupt private acquisition")
            .unwrap();
            let reopened = MarmotApp::with_relay(directories[1].path(), &url);
            let reopened_storage = reopened.account_storage("test").unwrap();
            let reopened_cap =
                cgka_traits::StorageProvider::private_device_invite_storage(&reopened_storage)
                    .unwrap();
            assert!(reopened_cap.private_invite().unwrap().unwrap().phase == uncertain_phase);
            assert!(reopened_cap.confirmed_private_invite().unwrap().is_none());
            assert!(
                reopened_cap.private_invite().unwrap().unwrap() == fact,
                "encrypted reopen preserves the exact uncertain commit"
            );
            assert_eq!(
                cgka_traits::GroupStorage::get_group(&reopened_storage, &fact.raw.binding.group_id)
                    .unwrap()
                    .epoch
                    .0,
                0
            );
            reopened.close_storage().unwrap();
            writer.shutdown().await;
            relay.shutdown();
            return;
        }
        let recovered = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if cap
                    .private_invite()
                    .unwrap()
                    .is_some_and(|row| row.phase == PrivateInvitePhase::Confirmed)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        if let Some(proxy) = &proxy {
            assert!(
                proxy.rejected.load(std::sync::atomic::Ordering::SeqCst) > 0,
                "actual relay must reject Negentropy attempts"
            );
        }
        assert!(
            recovered.is_ok(),
            "autonomous private recovery must confirm the exact old event"
        );
        let queries = observed.0.lock().unwrap().clone();
        let verified_event: nostr_relay_builder::prelude::Event = serde_json::from_value(
            serde_json::to_value(event.to_verified_nostr_event().unwrap()).unwrap(),
        )
        .unwrap();
        let matching = queries
            .iter()
            .filter(|query| query.match_event(&verified_event, Default::default()))
            .collect::<Vec<_>>();
        assert!(
            !matching.is_empty(),
            "actual relay query must admit the offline private event"
        );
        assert!(
            matching.iter().all(|query| {
                query
                    .ids
                    .as_ref()
                    .is_some_and(|ids| ids.len() == 1 && ids.contains(&verified_event.id))
                    && query.since.is_none()
                    && query.limit.is_some_and(|limit| limit <= 16)
            }),
            "only bounded exact-ID acquisition may admit the older private event"
        );
        assert!(
            queries.iter().any(|query| {
                query
                    .since
                    .is_some_and(|since| since.as_secs() > event.created_at)
                    && query
                        .clone()
                        .remove_since()
                        .match_event(&verified_event, Default::default())
            }),
            "actual matching group subscription must exclude the commit solely by its cursor floor"
        );

        assert!(cap.confirmed_private_invite().unwrap().unwrap().binding == fact.raw.binding);
        assert_eq!(
            cgka_traits::GroupStorage::get_group(&storage, &fact.raw.binding.group_id)
                .unwrap()
                .epoch
                .0,
            1
        );
        assert!(
            app.load_state("test").unwrap().groups.iter().all(
                |group| group.group_id_hex != hex::encode(fact.raw.binding.group_id.as_slice())
            )
        );
        assert!(
            cgka_traits::MessageStorage::get_message(
                &storage,
                &fact.transport.as_ref().unwrap().commit.id
            )
            .is_err()
        );
        runtime.shutdown_and_close().await.unwrap();
        writer.shutdown().await;
        relay.shutdown();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_hidden_route_real_echo_confirms_without_chat() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            relay_b,
            ..
        } = verified_workers().await;
        b.prepare_private_device_invite("test", &b_scope)
            .await
            .unwrap();
        let storage = b.app.account_storage("test").unwrap();
        let cap = cgka_traits::StorageProvider::private_device_invite_storage(&storage).unwrap();
        let fact = cap.private_invite().unwrap().unwrap();
        let event = transport_nostr_peeler::NostrTransportEvent::from_transport_message(
            &fact.transport.as_ref().unwrap().commit,
        )
        .unwrap();
        b.publish_private_device_invite_commit("test", &b_scope)
            .await
            .unwrap();
        assert!(relay_b.accepted_subscriptions().iter().any(|subscription| matches!(subscription,
            transport_nostr_adapter::NostrSubscription::Group { account_id, group_id, .. }
                if account_id.as_slice() == b_scope.account && group_id == &fact.raw.binding.group_id)),
            "private publication must first subscribe the exact authenticated hidden group");
        // A local relay ACK is not an inbound cryptographic echo.
        assert_private_commit_unknown(&b);
        assert!(b.app.load_state("test").unwrap().groups.is_empty());
        let routed = b
            .app
            .relay_plane
            .handle_relay_event_for_test(transport_nostr_adapter::NostrRelayEvent {
                endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
                subscription_id: None,
                event,
            })
            .await
            .unwrap();
        assert_eq!(
            routed, 1,
            "exact relay echo must enter the normal account delivery path"
        );
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if cap.private_invite().unwrap().is_some_and(|row| {
                    row.phase == cgka_traits::private_device_invite::PrivateInvitePhase::Confirmed
                }) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("authenticated own echo must confirm through account ingest");
        let confirmed = cap.confirmed_private_invite().unwrap().unwrap();
        assert!(confirmed.binding == fact.raw.binding);
        assert!(
            cgka_traits::GroupStorage::get_group(&storage, &fact.raw.binding.group_id)
                .unwrap()
                .epoch
                .0
                == 1
        );
        assert!(b.app.load_state("test").unwrap().groups.is_empty());
        let published = relay_b.published_event_ids();
        assert!(
            fact.transport
                .as_ref()
                .unwrap()
                .welcomes
                .iter()
                .all(|message| !published.contains(
                    &transport_nostr_peeler::NostrTransportEvent::from_transport_message(message)
                        .unwrap()
                        .id
                ))
        );
        runtime_a.shutdown().await;
        runtime_b.shutdown_and_close().await.unwrap();
    }
    async fn confirmed_sender_fixture() -> (
        VerifiedWorkers,
        cgka_traits::private_device_invite::PrivateInviteFact,
    ) {
        let workers = verified_workers().await;
        workers
            .b
            .prepare_private_device_invite("test", &workers.b_scope)
            .await
            .unwrap();
        let storage = workers.b.app.account_storage("test").unwrap();
        let cap = cgka_traits::StorageProvider::private_device_invite_storage(&storage).unwrap();
        let fact = cap.private_invite().unwrap().unwrap();
        workers
            .b
            .publish_private_device_invite_commit("test", &workers.b_scope)
            .await
            .unwrap();
        workers
            .b
            .app
            .relay_plane
            .handle_relay_event_for_test(transport_nostr_adapter::NostrRelayEvent {
                endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
                subscription_id: None,
                event: transport_nostr_peeler::NostrTransportEvent::from_transport_message(
                    &fact.transport.as_ref().unwrap().commit,
                )
                .unwrap(),
            })
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while !cap.private_invite().unwrap().is_some_and(|row| {
                row.phase == cgka_traits::private_device_invite::PrivateInvitePhase::Confirmed
            }) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("control fixture must genuinely confirm through the worker");
        (workers, fact)
    }
    fn assert_no_private_welcomes(
        relay: &ScriptedPushRelayClient,
        fact: &cgka_traits::private_device_invite::PrivateInviteFact,
    ) {
        let published = relay.published_event_ids();
        assert!(
            fact.transport
                .as_ref()
                .unwrap()
                .welcomes
                .iter()
                .all(|message| !published.contains(
                    &transport_nostr_peeler::NostrTransportEvent::from_transport_message(message)
                        .unwrap()
                        .id
                ))
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_welcome_delivery_wrong_scope_preserves_live_original() {
        let (workers, fact) = confirmed_sender_fixture().await;
        let mut wrong = workers.b_scope.clone();
        wrong.local_device[0] ^= 1;
        assert!(
            workers
                .b
                .verifier_command("test", |respond| VerifierCommand::PublishPrivateWelcomes {
                    scope: wrong,
                    respond
                })
                .await
                .is_err()
        );
        assert_no_private_welcomes(&workers.relay_b, &fact);
        workers
            .b
            .verifier_command("test", |respond| VerifierCommand::PublishPrivateWelcomes {
                scope: workers.b_scope.clone(),
                respond,
            })
            .await
            .unwrap();
        let published = workers.relay_b.published_event_ids();
        assert!(
            fact.transport
                .as_ref()
                .unwrap()
                .welcomes
                .iter()
                .all(|message| published.contains(
                    &transport_nostr_peeler::NostrTransportEvent::from_transport_message(message)
                        .unwrap()
                        .id
                ))
        );
        workers.runtime_a.shutdown_and_close().await.unwrap();
        workers.runtime_b.shutdown_and_close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_welcome_delivery_expiry_preserves_confirmed_membership() {
        let (workers, fact) = confirmed_sender_fixture().await;
        workers
            .b
            .maintain_device_linking_at_for_test(
                "test",
                std::time::Instant::now() + std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap();
        assert!(
            workers
                .b
                .verifier_command("test", |respond| VerifierCommand::PublishPrivateWelcomes {
                    scope: workers.b_scope.clone(),
                    respond
                })
                .await
                .is_err()
        );
        assert_no_private_welcomes(&workers.relay_b, &fact);
        let storage = workers.b.app.account_storage("test").unwrap();
        let confirmed = cgka_traits::StorageProvider::private_device_invite_storage(&storage)
            .unwrap()
            .confirmed_private_invite()
            .unwrap()
            .unwrap();
        assert!(!confirmed.denied && confirmed.binding == fact.raw.binding);
        workers.runtime_a.shutdown_and_close().await.unwrap();
        workers.runtime_b.shutdown_and_close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_welcome_delivery_stalled_cancel_releases_worker() {
        let (workers, fact) = confirmed_sender_fixture().await;
        workers.relay_b.block_next_publish();
        let manager = workers.b.clone();
        let scope = workers.b_scope.clone();
        let job = tokio::spawn(async move {
            manager
                .verifier_command("test", |respond| VerifierCommand::PublishPrivateWelcomes {
                    scope,
                    respond,
                })
                .await
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            workers.relay_b.wait_for_blocked_publish(),
        )
        .await
        .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            workers.b.cancel_device_linking("test", &workers.b_scope),
        )
        .await
        .expect("exact cancellation must not wait for stalled Welcome publication")
        .unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(500), job)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_no_private_welcomes(&workers.relay_b, &fact);
        let storage = workers.b.app.account_storage("test").unwrap();
        assert!(
            cgka_traits::StorageProvider::private_device_invite_storage(&storage)
                .unwrap()
                .confirmed_private_invite()
                .unwrap()
                .is_some_and(|row| !row.denied && row.binding == fact.raw.binding)
        );
        workers.runtime_a.shutdown_and_close().await.unwrap();
        workers.runtime_b.shutdown_and_close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_welcome_delivery_reopen_cannot_restore_consent() {
        let (workers, fact) = confirmed_sender_fixture().await;
        workers.runtime_a.shutdown_and_close().await.unwrap();
        workers.runtime_b.shutdown_and_close().await.unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app = MarmotApp::with_relay(workers.directories[1].path(), "wss://relay.example")
            .with_test_relay_client(relay.clone());
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.reconcile_accounts().await.unwrap();
        assert!(
            runtime
                .accounts()
                .verifier_command("test", |respond| VerifierCommand::PublishPrivateWelcomes {
                    scope: workers.b_scope.clone(),
                    respond
                })
                .await
                .is_err()
        );
        assert_no_private_welcomes(&relay, &fact);
        let storage = app.account_storage("test").unwrap();
        assert!(
            cgka_traits::StorageProvider::private_device_invite_storage(&storage)
                .unwrap()
                .confirmed_private_invite()
                .unwrap()
                .is_some_and(|row| !row.denied && row.binding == fact.raw.binding)
        );
        runtime.shutdown_and_close().await.unwrap();
    }
    async fn joined_live_workers() -> (
        VerifiedWorkers,
        nostr_relay_builder::LocalRelay,
        cgka_traits::GroupId,
    ) {
        let relay =
            nostr_relay_builder::LocalRelay::new(nostr_relay_builder::RelayBuilder::default());
        relay.run().await.unwrap();
        let url = relay.url().await.to_string();
        let workers = verified_workers_with_transport(&url, false).await;
        let VerifiedWorkers {
            directories: _directories,
            a,
            b,
            prepared,
            b_scope,
            ..
        } = &workers;
        b.prepare_private_device_invite("test", b_scope)
            .await
            .unwrap();
        a.arm_singleton_device_welcome("test", &prepared.scope)
            .await
            .unwrap();
        let sender = b.app.account_storage("test").unwrap();
        let cap = cgka_traits::StorageProvider::private_device_invite_storage(&sender).unwrap();
        let fact = cap.private_invite().unwrap().unwrap();
        assert!(
            b.verifier_command("test", |respond| VerifierCommand::PublishPrivateWelcomes {
                scope: b_scope.clone(),
                respond,
            })
            .await
            .is_err(),
            "unconfirmed live sender cannot release a Welcome"
        );
        b.publish_private_device_invite_commit("test", b_scope)
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while !cap.private_invite().unwrap().is_some_and(|row| {
                row.scope == fact.scope
                    && row.phase
                        == cgka_traits::private_device_invite::PrivateInvitePhase::Confirmed
            }) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("actual WebSocket commit echo must confirm in the worker");
        b.verifier_command("test", |respond| VerifierCommand::PublishPrivateWelcomes {
            scope: b_scope.clone(),
            respond,
        })
        .await
        .expect("original live sender must publish through the actual SDK relay client");
        let recipient = a.app.account_storage("test").unwrap();
        let purpose =
            cgka_traits::StorageProvider::device_linking_key_package_storage(&recipient).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while !purpose
                .purpose_key_package()
                .unwrap()
                .is_some_and(|row| row.scope == prepared.scope && row.consumed)
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("actual WebSocket Welcome delivery must join in the recipient worker");
        let anchor = cgka_traits::StorageProvider::accepted_device_group_anchor_storage(&recipient)
            .unwrap()
            .accepted_anchor()
            .unwrap()
            .unwrap();
        assert!(
            !anchor.denied
                && anchor.draft.group_id == fact.raw.binding.group_id
                && anchor.draft.successor == fact.raw.binding.successor
        );
        assert!(
            cgka_traits::GroupStorage::get_group(&sender, &fact.raw.binding.group_id)
                .unwrap()
                .epoch
                .0
                == 1
        );
        assert!(
            cgka_traits::GroupStorage::get_group(&recipient, &fact.raw.binding.group_id)
                .unwrap()
                .epoch
                .0
                == 1
        );
        assert!(a.app.load_state("test").unwrap().groups.is_empty());
        assert!(b.app.load_state("test").unwrap().groups.is_empty());
        let group = fact.raw.binding.group_id.clone();
        (workers, relay, group)
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_live_relay_confirms_and_delivers_without_injection() {
        let (workers, relay, _) = joined_live_workers().await;
        workers.runtime_a.shutdown_and_close().await.unwrap();
        workers.runtime_b.shutdown_and_close().await.unwrap();
        relay.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_live_relay_settles_exact_roster_without_chat() {
        let (workers, relay, group) = joined_live_workers().await;
        let sender = workers.b.app.account_storage("test").unwrap();
        let recipient = workers.a.app.account_storage("test").unwrap();
        let sender_round =
            cgka_traits::StorageProvider::private_roster_settlement_storage(&sender).unwrap();
        let recipient_round =
            cgka_traits::StorageProvider::private_roster_settlement_storage(&recipient).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let complete = [sender_round, recipient_round].iter().all(|store| {
                    store.read_round().unwrap().is_some_and(|round| {
                        round.phase == cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed
                            && round.anchor.group_id == group
                            && round.anchor.successor.leaves.len() == 2
                            && round.prepared_ciphertext.is_some()
                            && store.read_facts().unwrap().len() == 2
                    })
                });
                if complete {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        let hidden = workers.a.app.load_state("test").unwrap().groups.is_empty()
            && workers.b.app.load_state("test").unwrap().groups.is_empty();
        workers.runtime_a.shutdown_and_close().await.unwrap();
        workers.runtime_b.shutdown_and_close().await.unwrap();
        relay.shutdown();
        assert!(hidden, "private settlement must never project a chat group");
        result.expect("genuine SDK-linked successor workers must exchange encrypted confirmations and settle the exact roster");
    }
    async fn wait_completed_approver_predecessor(
        workers: &VerifiedWorkers,
        group: &cgka_traits::GroupId,
    ) {
        use cgka_traits::private_roster_settlement::PrivateSettlementPhase;
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let complete = [&workers.a, &workers.b].iter().all(|manager| {
                    let storage = manager.app.account_storage("test").unwrap();
                    let cap =
                        cgka_traits::StorageProvider::private_roster_settlement_storage(&storage)
                            .unwrap();
                    cap.read_round().unwrap().is_some_and(|round| {
                        round.phase == PrivateSettlementPhase::Completed
                            && round.anchor.group_id == *group
                            && round.anchor.successor.leaves.len() == 2
                            && cap.read_facts().unwrap().len() == 2
                    })
                });
                if complete {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("genuine predecessor must complete before negative setup control");
    }

    async fn fresh_approver_control_context(
        workers: &VerifiedWorkers,
        candidate: &cgka_engine::device_group_snapshot::CandidateDeviceGroupSnapshot,
    ) -> (
        tempfile::TempDir,
        MarmotAppRuntime,
        LinkingContext,
        PurposeAttemptScope,
    ) {
        let keys = AccountHome::open(workers.directories[0].path())
            .load_signing_keys("test")
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        AccountHome::open(directory.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let runtime = MarmotAppRuntime::new(app);
        runtime.reconcile_accounts().await.unwrap();
        let prepared = runtime
            .accounts()
            .prepare_device_linking("test")
            .await
            .unwrap();
        let scope = workers
            .a
            .reserve_device_linking_for_approver("test")
            .await
            .unwrap();
        let metadata = cgka_engine::key_package::key_package_metadata(&prepared.package).unwrap();
        let context = LinkingContext {
            version: 1,
            nonce: [45; 32],
            new_device_generation: prepared.scope.generation,
            approver_generation: scope.generation,
            account: scope.account,
            exact_key_package: prepared.package.bytes.clone(),
            key_package_reference: hex::decode(metadata.key_package_ref_hex)
                .unwrap()
                .try_into()
                .unwrap(),
            device_group: candidate.group_id.as_slice().to_vec(),
            predecessor: crate::device_linking::PredecessorRoster::from_candidate(candidate)
                .unwrap(),
            approver: scope.local_device,
            recipient: prepared.scope.local_device,
        };
        assert!(context.approver != context.recipient);
        (directory, runtime, context, scope)
    }

    async fn rejected_approver_setup_preserves_scope(
        workers: &VerifiedWorkers,
        scope: &PurposeAttemptScope,
        context: LinkingContext,
    ) {
        let storage = workers.a.app.account_storage("test").unwrap();
        let purposes =
            cgka_traits::StorageProvider::device_linking_key_package_storage(&storage).unwrap();
        let anchors =
            cgka_traits::StorageProvider::accepted_device_group_anchor_storage(&storage).unwrap();
        let purpose = purposes.purpose_key_package().unwrap();
        let anchor = anchors.accepted_anchor().unwrap();
        assert!(
            workers
                .a
                .begin_device_linking("test", scope, context, Role::Approver)
                .await
                .is_err(),
            "unapproved predecessor must not begin SDK setup"
        );
        assert!(purposes.purpose_key_package().unwrap() == purpose);
        assert!(anchors.accepted_anchor().unwrap() == anchor);
        workers
            .a
            .cancel_device_linking("test", scope)
            .await
            .expect("rejected setup must preserve the exact live reservation for cancellation");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_settled_approver_control_incomplete_round_denies_setup() {
        use cgka_traits::private_roster_settlement::PrivateSettlementPhase;
        let (workers, fact) = confirmed_sender_fixture().await;
        workers
            .a
            .arm_singleton_device_welcome("test", &workers.prepared.scope)
            .await
            .unwrap();
        workers
            .b
            .verifier_command("test", |respond| VerifierCommand::PublishPrivateWelcomes {
                scope: workers.b_scope.clone(),
                respond,
            })
            .await
            .unwrap();
        for message in &fact.transport.as_ref().unwrap().welcomes {
            workers
                .a
                .app
                .relay_plane
                .handle_relay_event_for_test(transport_nostr_adapter::NostrRelayEvent {
                    endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
                    subscription_id: None,
                    event: transport_nostr_peeler::NostrTransportEvent::from_transport_message(
                        message,
                    )
                    .unwrap(),
                })
                .await
                .unwrap();
        }
        let storage = workers.a.app.account_storage("test").unwrap();
        let cap =
            cgka_traits::StorageProvider::private_roster_settlement_storage(&storage).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while !cap.read_round().unwrap().is_some_and(|round| {
                round.phase == PrivateSettlementPhase::Pending
                    && round.anchor.group_id == fact.raw.binding.group_id
            }) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            cap.read_facts().unwrap().len() < 2,
            "no coordinator challenge was delivered"
        );
        let candidate = workers
            .a
            .candidate_device_group_snapshot("test", &fact.raw.binding.group_id)
            .await
            .unwrap()
            .unwrap();
        let (_dir, c, context, scope) = fresh_approver_control_context(&workers, &candidate).await;
        assert!(
            cap.read_round().unwrap().unwrap().phase == PrivateSettlementPhase::Denied,
            "reservation cleanup must negatively fence unfinished round"
        );
        rejected_approver_setup_preserves_scope(&workers, &scope, context).await;
        c.shutdown_and_close().await.unwrap();
        workers.runtime_a.shutdown_and_close().await.unwrap();
        workers.runtime_b.shutdown_and_close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_settled_approver_control_forgotten_lineage_denies_setup() {
        let (workers, relay, group) = joined_live_workers().await;
        wait_completed_approver_predecessor(&workers, &group).await;
        let candidate = workers
            .a
            .candidate_device_group_snapshot("test", &group)
            .await
            .unwrap()
            .unwrap();
        assert!(workers.a.forget_group_local("test", &group).await.unwrap());
        let storage = workers.a.app.account_storage("test").unwrap();
        assert!(
            cgka_traits::StorageProvider::accepted_device_group_anchor_storage(&storage)
                .unwrap()
                .accepted_anchor()
                .unwrap()
                .unwrap()
                .denied
        );
        let (_dir, c, context, scope) = fresh_approver_control_context(&workers, &candidate).await;
        rejected_approver_setup_preserves_scope(&workers, &scope, context).await;
        c.shutdown_and_close().await.unwrap();
        workers.runtime_a.shutdown_and_close().await.unwrap();
        workers.runtime_b.shutdown_and_close().await.unwrap();
        relay.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_settled_approver_control_ordinary_candidate_denies_setup() {
        let (workers, relay, group) = joined_live_workers().await;
        wait_completed_approver_predecessor(&workers, &group).await;
        let ordinary = workers
            .a
            .create_group("test", "ordinary candidate control", &[], None)
            .await
            .unwrap();
        let candidate = workers
            .a
            .candidate_device_group_snapshot("test", &ordinary)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(candidate.leaves.len(), 1);
        let (_dir, c, context, scope) = fresh_approver_control_context(&workers, &candidate).await;
        rejected_approver_setup_preserves_scope(&workers, &scope, context).await;
        c.shutdown_and_close().await.unwrap();
        workers.runtime_a.shutdown_and_close().await.unwrap();
        workers.runtime_b.shutdown_and_close().await.unwrap();
        relay.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_settled_approver_control_modified_predecessor_preserves_exact_retry() {
        let (workers, relay, group) = joined_live_workers().await;
        wait_completed_approver_predecessor(&workers, &group).await;
        let candidate = workers
            .a
            .candidate_device_group_snapshot("test", &group)
            .await
            .unwrap()
            .unwrap();
        let (_dir, c, context, scope) = fresh_approver_control_context(&workers, &candidate).await;
        let storage = workers.a.app.account_storage("test").unwrap();
        let purposes =
            cgka_traits::StorageProvider::device_linking_key_package_storage(&storage).unwrap();
        let anchors =
            cgka_traits::StorageProvider::accepted_device_group_anchor_storage(&storage).unwrap();
        let original_purpose = purposes.purpose_key_package().unwrap();
        let original_anchor = anchors.accepted_anchor().unwrap();
        let mut wrong = context.clone();
        wrong.predecessor.epoch_authenticator_digest[0] ^= 1;
        assert!(
            workers
                .a
                .begin_device_linking("test", &scope, wrong, Role::Approver)
                .await
                .is_err()
        );
        assert!(purposes.purpose_key_package().unwrap() == original_purpose);
        assert!(anchors.accepted_anchor().unwrap() == original_anchor);
        workers
            .a
            .begin_device_linking("test", &scope, context, Role::Approver)
            .await
            .expect("same exact reservation must retry corrected authenticated predecessor");
        assert!(workers.a.device_linking_offer("test", &scope).await.is_ok());
        assert!(purposes.purpose_key_package().unwrap() == original_purpose);
        assert!(anchors.accepted_anchor().unwrap() == original_anchor);
        workers
            .a
            .cancel_device_linking("test", &scope)
            .await
            .unwrap();
        c.shutdown_and_close().await.unwrap();
        workers.runtime_a.shutdown_and_close().await.unwrap();
        workers.runtime_b.shutdown_and_close().await.unwrap();
        relay.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_artifact_worker_authenticates_before_original_sdk() {
        use sha2::{Digest, Sha256};
        let (workers, relay, group) = joined_live_workers().await;
        wait_completed_approver_predecessor(&workers, &group).await;
        let candidate = workers
            .a
            .candidate_device_group_snapshot("test", &group)
            .await
            .unwrap()
            .unwrap();
        let artifact = workers
            .a
            .export_settled_device_predecessor("test", &group)
            .await
            .unwrap()
            .unwrap();
        let (_directory, runtime_c, mut context, a_scope) =
            fresh_approver_control_context(&workers, &candidate).await;
        let c = runtime_c.accounts();
        let c_scope = PurposeAttemptScope {
            account: context.account,
            local_device: context.recipient,
            generation: context.new_device_generation,
        };
        context.version = 2;
        context.predecessor.artifact_digest = Some(Sha256::digest(&artifact).into());
        let storage_a = workers.a.app.account_storage("test").unwrap();
        let anchors =
            cgka_traits::StorageProvider::accepted_device_group_anchor_storage(&storage_a).unwrap();
        let settlement =
            cgka_traits::StorageProvider::private_roster_settlement_storage(&storage_a).unwrap();
        let original_anchor = anchors.accepted_anchor().unwrap();
        let original_round = settlement.read_round().unwrap();
        let original_facts = settlement.read_facts().unwrap();
        let storage_c = c.app.account_storage("test").unwrap();
        let purposes =
            cgka_traits::StorageProvider::device_linking_key_package_storage(&storage_c).unwrap();
        let original_purpose = purposes.purpose_key_package().unwrap();
        let mut altered = artifact.clone();
        let last = altered.len() - 1;
        altered[last] ^= 1;
        let mut trailing = artifact.clone();
        trailing.push(0);
        let mut changed_digest = context.clone();
        changed_digest.predecessor.artifact_digest.as_mut().unwrap()[0] ^= 1;
        let mut wrong_epoch = context.clone();
        wrong_epoch.predecessor.epoch += 1;
        let mut wrong_roster = context.clone();
        wrong_roster.predecessor.leaves[1].signature_public_key[0] ^= 1;
        let mut downgraded = context.clone();
        downgraded.version = 1;
        downgraded.predecessor.artifact_digest = None;
        for (input, bytes) in [
            (context.clone(), altered),
            (context.clone(), trailing),
            (changed_digest, artifact.clone()),
            (wrong_epoch, artifact.clone()),
            (wrong_roster, artifact.clone()),
            (downgraded, artifact.clone()),
        ] {
            assert!(
                c.begin_device_linking_with_predecessor(
                    "test",
                    &c_scope,
                    input.clone(),
                    Role::NewDevice,
                    bytes.clone()
                )
                .await
                .is_err()
            );
            assert!(
                workers
                    .a
                    .begin_device_linking_with_predecessor(
                        "test",
                        &a_scope,
                        input,
                        Role::Approver,
                        bytes
                    )
                    .await
                    .is_err()
            );
            assert!(c.device_linking_offer("test", &c_scope).await.is_err());
            assert!(
                workers
                    .a
                    .device_linking_offer("test", &a_scope)
                    .await
                    .is_err()
            );
            assert!(purposes.purpose_key_package().unwrap() == original_purpose);
            assert!(anchors.accepted_anchor().unwrap() == original_anchor);
            assert!(settlement.read_round().unwrap() == original_round);
            assert!(settlement.read_facts().unwrap() == original_facts);
        }
        let begin = c
            .begin_device_linking_with_predecessor(
                "test",
                &c_scope,
                context.clone(),
                Role::NewDevice,
                artifact.clone(),
            )
            .await;
        if begin.is_err() {
            c.cancel_device_linking("test", &c_scope).await.unwrap();
            workers
                .a
                .cancel_device_linking("test", &a_scope)
                .await
                .unwrap();
            runtime_c.shutdown_and_close().await.unwrap();
            workers.runtime_a.shutdown_and_close().await.unwrap();
            workers.runtime_b.shutdown_and_close().await.unwrap();
            relay.shutdown();
            assert!(
                begin.is_ok(),
                "exact authenticated artifact must begin original account-owned SDK pairing"
            );
            return;
        }
        workers
            .a
            .begin_device_linking_with_predecessor(
                "test",
                &a_scope,
                context.clone(),
                Role::Approver,
                artifact,
            )
            .await
            .unwrap();
        let co = c.device_linking_offer("test", &c_scope).await.unwrap();
        let ao = workers
            .a
            .device_linking_offer("test", &a_scope)
            .await
            .unwrap();
        c.admit_device_linking_peer("test", &c_scope, ao)
            .await
            .unwrap();
        workers
            .a
            .admit_device_linking_peer("test", &a_scope, co)
            .await
            .unwrap();
        c.start_device_linking_verification("test", &c_scope)
            .await
            .unwrap();
        for _ in 0..8 {
            drain(&c, &c_scope, &workers.a, &a_scope).await;
            drain(&workers.a, &a_scope, &c, &c_scope).await;
        }
        let digits = c.device_linking_decimals("test", &c_scope).await.unwrap();
        assert!(digits.is_some());
        assert!(
            digits
                == workers
                    .a
                    .device_linking_decimals("test", &a_scope)
                    .await
                    .unwrap()
        );
        c.confirm_device_linking("test", &c_scope).await.unwrap();
        workers
            .a
            .confirm_device_linking("test", &a_scope)
            .await
            .unwrap();
        for _ in 0..8 {
            drain(&c, &c_scope, &workers.a, &a_scope).await;
            drain(&workers.a, &a_scope, &c, &c_scope).await;
        }
        let new = c
            .take_device_linking_verified("test", &c_scope)
            .await
            .unwrap();
        let approver = workers
            .a
            .take_device_linking_verified("test", &a_scope)
            .await
            .unwrap();
        assert!(new.context().digest().unwrap() == context.digest().unwrap());
        assert!(approver.context().digest().unwrap() == context.digest().unwrap());
        assert!(new.original_deadline().is_some() && approver.original_deadline().is_some());
        assert!(
            c.take_device_linking_verified("test", &c_scope)
                .await
                .is_err()
        );
        assert!(anchors.accepted_anchor().unwrap() == original_anchor);
        assert!(settlement.read_round().unwrap() == original_round);
        assert!(settlement.read_facts().unwrap() == original_facts);
        assert!(workers.a.app.load_state("test").unwrap().groups.is_empty());
        assert!(c.app.load_state("test").unwrap().groups.is_empty());
        runtime_c.shutdown_and_close().await.unwrap();
        workers.runtime_a.shutdown_and_close().await.unwrap();
        workers.runtime_b.shutdown_and_close().await.unwrap();
        relay.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_singleton_preparation_refusal_preserves_exact_original_scope() {
        exercise_third_device_invite(ThirdDeviceCheck::RetainedScope).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_singleton_recipient_rejects_completed_multi_device_predecessor() {
        exercise_third_device_invite(ThirdDeviceCheck::Settlement).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_third_device_cannot_publish_without_existing_sibling_approval() {
        exercise_third_device_invite(ThirdDeviceCheck::UnapprovedPublication).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_artifact_bound_predecessor_prepares_exact_proposal_without_add() {
        exercise_third_device_invite(ThirdDeviceCheck::ArtifactPreparation).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_original_sdk_produces_received_proposal_without_add() {
        exercise_third_device_invite(ThirdDeviceCheck::LocalProposal).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_proposal_only_cancel_after_real_maintenance_reports_success() {
        exercise_third_device_invite(ThirdDeviceCheck::UnapprovedPublicationCancelMaintenance)
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_retired_proposal_rejects_foreign_scopes_and_acknowledges_only_once() {
        exercise_third_device_invite(ThirdDeviceCheck::UnapprovedPublicationForeignOnce).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_retired_proposal_cannot_ack_after_newer_terminal_reservation() {
        exercise_third_device_invite(ThirdDeviceCheck::UnapprovedPublicationNewerTerminal).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_original_sdk_received_proposal_requires_explicit_b_owner() {
        exercise_third_device_invite(ThirdDeviceCheck::LocalProposalEndorsement).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_original_sdk_collects_actual_b_encrypted_endorsement() {
        exercise_third_device_invite(ThirdDeviceCheck::LocalProposalCollection).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_original_sdk_endorsed_proposal_transfers_to_trusted_add() {
        exercise_third_device_invite(ThirdDeviceCheck::LocalProposalTrustedAdd).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_original_sdk_incomplete_handoff_retries_after_actual_b_receipt() {
        exercise_third_device_invite(ThirdDeviceCheck::LocalProposalTrustedAddRetry).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_original_sdk_cancel_after_real_maintenance_retires_owned_invite() {
        exercise_third_device_invite(
            ThirdDeviceCheck::LocalProposalTrustedAddRetryCancelMaintenance,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_original_sdk_endorsed_recipient_arms_exact_original_purpose() {
        exercise_third_device_invite(ThirdDeviceCheck::LocalProposalRecipientAdmission).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_original_sdk_endorsed_recipient_joins_with_atomic_retry() {
        exercise_third_device_invite(ThirdDeviceCheck::LocalProposalRecipientJoin).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_original_b_action_bridges_actual_c_add_atomically() {
        exercise_third_device_invite(ThirdDeviceCheck::LocalProposalExistingTransition).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_original_abc_actions_settle_actual_three_device_roster() {
        exercise_third_device_invite(ThirdDeviceCheck::LocalProposalAbcSettlement).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_b_endorsement_abandoned_reply_burns_original_action() {
        exercise_third_device_invite(ThirdDeviceCheck::LocalProposalDroppedReply).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_b_endorsement_encrypted_reopen_cannot_restore_action() {
        exercise_third_device_invite(ThirdDeviceCheck::LocalProposalReopen).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_retired_cancel_cannot_ack_after_a_newer_terminal_reservation() {
        exercise_third_device_invite(ThirdDeviceCheck::LocalProposalCancelMaintenanceNewerTerminal)
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_foreign_guard_cannot_cancel_real_guarded_same_group_admission() {
        exercise_third_device_invite(ThirdDeviceCheck::LocalProposalTrustedAddRetryGuardIdentity)
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_first_old_cancel_after_newer_terminal_does_not_touch_current_gate() {
        exercise_third_device_invite(ThirdDeviceCheck::LocalProposalTrustedAddRetryLateFirstCancel)
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_failed_add_handoff_cannot_reinstall_proposal_cancel_receipt() {
        exercise_third_device_invite(ThirdDeviceCheck::LocalProposalFailedAddReceipt).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_proposal_cancel_sql_read_error_preserves_exact_once_retry() {
        exercise_third_device_invite(ThirdDeviceCheck::UnapprovedPublicationSqlReadError).await;
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ThirdDeviceCheck {
        LocalProposal,
        LocalProposalEndorsement,
        LocalProposalCollection,
        LocalProposalTrustedAdd,
        LocalProposalFailedAddReceipt,
        LocalProposalTrustedAddRetry,
        LocalProposalTrustedAddRetryCancelMaintenance,
        LocalProposalTrustedAddRetryLateFirstCancel,
        LocalProposalTrustedAddRetryGuardIdentity,
        LocalProposalCancelMaintenanceNewerTerminal,
        LocalProposalRecipientAdmission,
        LocalProposalRecipientJoin,
        LocalProposalExistingTransition,
        LocalProposalAbcSettlement,
        LocalProposalDroppedReply,
        LocalProposalReopen,
        RetainedScope,
        Settlement,
        UnapprovedPublication,
        UnapprovedPublicationCancelMaintenance,
        UnapprovedPublicationSqlReadError,
        UnapprovedPublicationForeignOnce,
        UnapprovedPublicationNewerTerminal,
        ArtifactPreparation,
    }

    async fn exercise_third_device_invite(check: ThirdDeviceCheck) {
        let failed_add_receipt = check == ThirdDeviceCheck::LocalProposalFailedAddReceipt;
        let check = if failed_add_receipt {
            ThirdDeviceCheck::LocalProposalTrustedAdd
        } else {
            check
        };
        let proposal_receipt_foreign_once =
            check == ThirdDeviceCheck::UnapprovedPublicationForeignOnce;
        let proposal_receipt_newer_terminal =
            check == ThirdDeviceCheck::UnapprovedPublicationNewerTerminal;
        let proposal_receipt_safety =
            proposal_receipt_foreign_once || proposal_receipt_newer_terminal;
        let check = if proposal_receipt_safety {
            ThirdDeviceCheck::UnapprovedPublication
        } else {
            check
        };
        let proposal_cancel_sql_read_error =
            check == ThirdDeviceCheck::UnapprovedPublicationSqlReadError;
        let proposal_only_cancel_maintenance = check
            == ThirdDeviceCheck::UnapprovedPublicationCancelMaintenance
            || proposal_cancel_sql_read_error;
        let check = if proposal_only_cancel_maintenance {
            ThirdDeviceCheck::UnapprovedPublication
        } else {
            check
        };
        // The new race case reuses every real original setup/approval step.
        let newer_terminal_after_maintenance =
            check == ThirdDeviceCheck::LocalProposalCancelMaintenanceNewerTerminal;
        let cancel_after_maintenance = check
            == ThirdDeviceCheck::LocalProposalTrustedAddRetryCancelMaintenance
            || newer_terminal_after_maintenance;
        let test_guard_identity =
            check == ThirdDeviceCheck::LocalProposalTrustedAddRetryGuardIdentity;
        let late_first_cancel =
            check == ThirdDeviceCheck::LocalProposalTrustedAddRetryLateFirstCancel;
        let check = if cancel_after_maintenance || test_guard_identity || late_first_cancel {
            ThirdDeviceCheck::LocalProposalTrustedAddRetry
        } else {
            check
        };
        use cgka_traits::private_roster_settlement::PrivateSettlementPhase;
        let (workers, relay, group) = joined_live_workers().await;
        let a_storage = workers.a.app.account_storage("test").unwrap();
        let b_storage = workers.b.app.account_storage("test").unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let complete = [&a_storage, &b_storage].iter().all(|storage| {
                    let store =
                        cgka_traits::StorageProvider::private_roster_settlement_storage(*storage)
                            .unwrap();
                    store.read_round().unwrap().is_some_and(|round| {
                        round.phase == PrivateSettlementPhase::Completed
                            && round.anchor.group_id == group
                            && round.anchor.successor.leaves.len() == 2
                            && store.read_facts().unwrap().len() == 2
                    })
                });
                if complete {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("both actual predecessor workers must settle before a third-device request");
        if test_guard_identity {
            // A's original actual SDK Welcome/join guard is selected here;
            // a later Wrapped A/C Add cannot yet supply a selected +1 guard.
            workers
                .a
                .verifier_command("test", |respond| {
                    VerifierCommand::RejectForeignSettlementGuardForTest { respond }
                })
                .await
                .expect(
                    "foreign negative guard must not revoke the real original guarded admission",
                );
        }
        let candidate = workers
            .a
            .candidate_device_group_snapshot("test", &group)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(candidate.leaves.len(), 2);
        assert_eq!(candidate.epoch.0, 1);
        // Import only this test account's signing identity into a fresh root.
        // No MLS database, encryption state or prior runtime permission is copied.
        let keys = AccountHome::open(workers.directories[0].path())
            .load_signing_keys("test")
            .unwrap();
        let c_dir = tempfile::tempdir().unwrap();
        AccountHome::open(c_dir.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        let app_c = MarmotApp::with_relay(c_dir.path(), relay.url().await.to_string());
        let runtime_c = MarmotAppRuntime::new(app_c.clone());
        runtime_c.reconcile_accounts().await.unwrap();
        let c = runtime_c.accounts();
        let prepared = c.prepare_device_linking("test").await.unwrap();
        let c_storage = app_c.account_storage("test").unwrap();
        let a_scope = workers
            .a
            .reserve_device_linking_for_approver("test")
            .await
            .unwrap();
        assert!(prepared.scope.account == a_scope.account);
        assert!(
            candidate
                .leaves
                .iter()
                .all(|leaf| leaf.signature_public_key.as_slice() != prepared.scope.local_device)
        );
        let metadata = cgka_engine::key_package::key_package_metadata(&prepared.package).unwrap();
        let context = LinkingContext {
            version: 1,
            nonce: [44; 32],
            new_device_generation: prepared.scope.generation,
            approver_generation: a_scope.generation,
            account: prepared.scope.account,
            exact_key_package: prepared.package.bytes.clone(),
            key_package_reference: hex::decode(metadata.key_package_ref_hex)
                .unwrap()
                .try_into()
                .unwrap(),
            device_group: group.as_slice().to_vec(),
            predecessor: crate::device_linking::PredecessorRoster::from_candidate(&candidate)
                .unwrap(),
            approver: a_scope.local_device,
            recipient: prepared.scope.local_device,
        };
        let mut context = context;
        let expected_package_reference = context.key_package_reference;
        let begin = if matches!(
            check,
            ThirdDeviceCheck::UnapprovedPublication
                | ThirdDeviceCheck::ArtifactPreparation
                | ThirdDeviceCheck::LocalProposal
                | ThirdDeviceCheck::LocalProposalEndorsement
                | ThirdDeviceCheck::LocalProposalCollection
                | ThirdDeviceCheck::LocalProposalTrustedAdd
                | ThirdDeviceCheck::LocalProposalTrustedAddRetry
                | ThirdDeviceCheck::LocalProposalRecipientAdmission
                | ThirdDeviceCheck::LocalProposalRecipientJoin
                | ThirdDeviceCheck::LocalProposalExistingTransition
                | ThirdDeviceCheck::LocalProposalAbcSettlement
                | ThirdDeviceCheck::LocalProposalDroppedReply
                | ThirdDeviceCheck::LocalProposalReopen
        ) {
            use sha2::{Digest, Sha256};
            let artifact = workers
                .a
                .export_settled_device_predecessor("test", &group)
                .await
                .unwrap()
                .unwrap();
            context.version = 2;
            context.predecessor.artifact_digest = Some(Sha256::digest(&artifact).into());
            c.begin_device_linking_with_predecessor(
                "test",
                &prepared.scope,
                context.clone(),
                Role::NewDevice,
                artifact.clone(),
            )
            .await
            .unwrap();
            workers
                .a
                .begin_device_linking_with_predecessor(
                    "test",
                    &a_scope,
                    context,
                    Role::Approver,
                    artifact,
                )
                .await
        } else {
            c.begin_device_linking("test", &prepared.scope, context.clone(), Role::NewDevice)
                .await
                .unwrap();
            workers
                .a
                .begin_device_linking("test", &a_scope, context, Role::Approver)
                .await
        };
        assert!(
            begin.is_ok(),
            "an actual settled two-device predecessor must support a fresh third-device pairing"
        );
        let co = c
            .device_linking_offer("test", &prepared.scope)
            .await
            .unwrap();
        let ao = workers
            .a
            .device_linking_offer("test", &a_scope)
            .await
            .unwrap();
        c.admit_device_linking_peer("test", &prepared.scope, ao)
            .await
            .unwrap();
        workers
            .a
            .admit_device_linking_peer("test", &a_scope, co)
            .await
            .unwrap();
        c.start_device_linking_verification("test", &prepared.scope)
            .await
            .unwrap();
        for _ in 0..8 {
            drain(&c, &prepared.scope, &workers.a, &a_scope).await;
            drain(&workers.a, &a_scope, &c, &prepared.scope).await;
        }
        let digits = c
            .device_linking_decimals("test", &prepared.scope)
            .await
            .unwrap();
        assert!(digits.is_some());
        assert!(
            digits
                == workers
                    .a
                    .device_linking_decimals("test", &a_scope)
                    .await
                    .unwrap()
        );
        c.confirm_device_linking("test", &prepared.scope)
            .await
            .unwrap();
        workers
            .a
            .confirm_device_linking("test", &a_scope)
            .await
            .unwrap();
        for _ in 0..8 {
            drain(&c, &prepared.scope, &workers.a, &a_scope).await;
            drain(&workers.a, &a_scope, &c, &prepared.scope).await;
        }
        if check == ThirdDeviceCheck::Settlement {
            let before =
                cgka_traits::StorageProvider::device_linking_key_package_storage(&c_storage)
                    .unwrap()
                    .purpose_key_package()
                    .unwrap();
            assert!(
                c.arm_singleton_device_welcome("test", &prepared.scope)
                    .await
                    .is_err(),
                "a completed multi-device predecessor cannot use singleton recipient admission"
            );
            assert!(
                cgka_traits::StorageProvider::device_linking_key_package_storage(&c_storage)
                    .unwrap()
                    .purpose_key_package()
                    .unwrap()
                    == before
            );
            // A refused singleton arm must not consume the original SDK continuation.
            c.take_device_linking_verified("test", &prepared.scope)
                .await
                .unwrap();
            assert!(
                cgka_traits::StorageProvider::accepted_device_group_anchor_storage(&c_storage)
                    .unwrap()
                    .accepted_anchor()
                    .unwrap()
                    .is_none()
            );
            runtime_c.shutdown_and_close().await.unwrap();
            workers.runtime_a.shutdown_and_close().await.unwrap();
            workers.runtime_b.shutdown_and_close().await.unwrap();
            relay.shutdown();
            return;
        }
        if check == ThirdDeviceCheck::UnapprovedPublication {
            let before = cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                .unwrap()
                .private_invite()
                .unwrap();
            assert!(
                workers
                    .a
                    .prepare_private_device_invite("test", &a_scope)
                    .await
                    .is_err(),
                "direct singleton preparation must refuse a multi-device predecessor before SDK take"
            );
            assert!(
                workers
                    .a
                    .publish_private_device_invite_commit("test", &a_scope)
                    .await
                    .is_err()
            );
            assert!(
                cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                    .unwrap()
                    .private_invite()
                    .unwrap()
                    == before
            );
            assert_eq!(
                workers
                    .a
                    .candidate_device_group_snapshot("test", &group)
                    .await
                    .unwrap()
                    .unwrap()
                    .epoch
                    .0,
                1
            );
            // The same genuine verifier remains available for the required all-leaf proposal path.
            workers
                .a
                .prepare_enrollment_proposal("test", &a_scope)
                .await
                .unwrap();
            assert_eq!(
                workers
                    .a
                    .collect_owned_enrollment_endorsements("test", &a_scope)
                    .await
                    .unwrap(),
                0
            );
            if proposal_receipt_safety {
                let probe = workers
                    .a
                    .verifier_command("test", |respond| {
                        VerifierCommand::CaptureProposalOnlyCancelForTest {
                            scope: a_scope.clone(),
                            respond,
                        }
                    })
                    .await
                    .unwrap();
                let account = workers.a.resolve("test").unwrap();
                {
                    let active = workers.a.workers.lock().await;
                    active
                        .get(&account.account_id_hex)
                        .unwrap()
                        .publication_control
                        .revoke(&a_scope);
                }
                workers
                    .a
                    .maintain_device_linking_at_for_test("test", std::time::Instant::now())
                    .await
                    .unwrap();
                let observed = probe
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .clone();
                let durable_absent =
                    cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                        .unwrap()
                        .private_invite()
                        .unwrap()
                        .is_none();
                assert!(
                    observed.owned_proposal && observed.retired_proposal && durable_absent,
                    "proposal receipt safety requires the actual retired proposal without an Add fact"
                );
                let c_storage = c.app.account_storage("test").unwrap();
                if proposal_receipt_foreign_once {
                    let revision = {
                        let active = workers.a.workers.lock().await;
                        active
                            .get(&account.account_id_hex)
                            .unwrap()
                            .publication_control
                            .current_retired_proposal_revision_for_test(&a_scope)
                            .unwrap()
                    };
                    let approver_purpose =
                        cgka_traits::StorageProvider::device_linking_key_package_storage(
                            &a_storage,
                        )
                        .unwrap()
                        .purpose_key_package()
                        .unwrap();
                    let recipient_purpose =
                        cgka_traits::StorageProvider::device_linking_key_package_storage(
                            &c_storage,
                        )
                        .unwrap()
                        .purpose_key_package()
                        .unwrap();
                    let mut foreign_account = a_scope.clone();
                    foreign_account.account[0] ^= 1;
                    let mut foreign_device = a_scope.clone();
                    foreign_device.local_device[0] ^= 1;
                    let mut foreign_generation = a_scope.clone();
                    foreign_generation.generation =
                        foreign_generation.generation.checked_add(1).unwrap();
                    let mut foreign_denied = [false; 3];
                    for (index, foreign) in [foreign_account, foreign_device, foreign_generation]
                        .iter()
                        .enumerate()
                    {
                        foreign_denied[index] = matches!(
                            workers.a.cancel_device_linking("test", foreign).await,
                            Err(ClientLinkingError::Owner(
                                crate::device_linking::OwnerError::Verifier(
                                    crate::device_linking::LinkError::BindingMismatch
                                        | crate::device_linking::LinkError::StaleFlow
                                )
                            ))
                        );
                    }
                    let revision_unchanged = revision.revision_matches_for_negative_completion();
                    drop(revision);
                    let purposes_unchanged =
                        cgka_traits::StorageProvider::device_linking_key_package_storage(
                            &a_storage,
                        )
                        .unwrap()
                        .purpose_key_package()
                        .unwrap()
                            == approver_purpose
                            && cgka_traits::StorageProvider::device_linking_key_package_storage(
                                &c_storage,
                            )
                            .unwrap()
                            .purpose_key_package()
                            .unwrap()
                                == recipient_purpose;
                    let exact_cancel_ok = workers
                        .a
                        .cancel_device_linking("test", &a_scope)
                        .await
                        .is_ok();
                    let repeated_cancel_stale = matches!(
                        workers.a.cancel_device_linking("test", &a_scope).await,
                        Err(ClientLinkingError::Owner(
                            crate::device_linking::OwnerError::Verifier(
                                crate::device_linking::LinkError::StaleFlow
                            )
                        ))
                    );
                    runtime_c.shutdown_and_close().await.unwrap();
                    crate::test_support::emit_line(format_args!(
                        "proposal-receipt-safety-close index=0"
                    ));
                    workers.runtime_a.shutdown_and_close().await.unwrap();
                    crate::test_support::emit_line(format_args!(
                        "proposal-receipt-safety-close index=1"
                    ));
                    workers.runtime_b.shutdown_and_close().await.unwrap();
                    crate::test_support::emit_line(format_args!(
                        "proposal-receipt-safety-close index=2"
                    ));
                    relay.shutdown();
                    crate::test_support::emit_line(format_args!(
                        "proposal-receipt-foreign-once-control {}",
                        serde_json::json!({
                            "owned_proposal": observed.owned_proposal,
                            "retired_proposal": observed.retired_proposal,
                            "durable_absent": durable_absent,
                            "foreign_account_denied": foreign_denied[0],
                            "foreign_device_denied": foreign_denied[1],
                            "foreign_generation_denied": foreign_denied[2],
                            "revision_unchanged": revision_unchanged,
                            "purposes_unchanged": purposes_unchanged,
                            "exact_cancel_ok": exact_cancel_ok,
                            "repeated_cancel_stale": repeated_cancel_stale,
                            "runtime_closed": true,
                        })
                    ));
                    assert!(
                        foreign_denied.into_iter().all(|denied| denied)
                            && revision_unchanged
                            && purposes_unchanged
                            && exact_cancel_ok
                            && repeated_cancel_stale,
                        "retired proposal foreign requests must preserve the original one-shot cancellation"
                    );
                    return;
                }
                let newer = workers
                    .a
                    .reserve_device_linking_for_approver("test")
                    .await
                    .unwrap();
                let newer_reserved = newer.generation > a_scope.generation && newer != a_scope;
                let newer_cancel_ok = workers
                    .a
                    .cancel_device_linking("test", &newer)
                    .await
                    .is_ok();
                let injector = private_commit_injector(&workers.a);
                let before_terminal: (i64, i64) = injector
                    .query_row(
                        "SELECT generation,state FROM device_linking_attempt WHERE singleton=1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                let newer_terminal = newer_cancel_ok
                    && before_terminal.0 == i64::try_from(newer.generation).unwrap()
                    && before_terminal.1 == storage_sqlite::DeviceLinkingOutcome::Cancelled as i64;
                let approver_purpose =
                    cgka_traits::StorageProvider::device_linking_key_package_storage(&a_storage)
                        .unwrap()
                        .purpose_key_package()
                        .unwrap();
                let recipient_purpose =
                    cgka_traits::StorageProvider::device_linking_key_package_storage(&c_storage)
                        .unwrap()
                        .purpose_key_package()
                        .unwrap();
                let revision = {
                    let active = workers.a.workers.lock().await;
                    active
                        .get(&account.account_id_hex)
                        .unwrap()
                        .publication_control
                        .current_retired_proposal_revision_for_test(&a_scope)
                        .unwrap()
                };
                let old_cancel_stale = matches!(
                    workers.a.cancel_device_linking("test", &a_scope).await,
                    Err(ClientLinkingError::Owner(
                        crate::device_linking::OwnerError::Verifier(
                            crate::device_linking::LinkError::StaleFlow
                        )
                    ))
                );
                let newer_revision_unchanged = revision.revision_matches_for_negative_completion();
                drop(revision);
                let after_terminal: (i64, i64) = injector
                    .query_row(
                        "SELECT generation,state FROM device_linking_attempt WHERE singleton=1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                let newer_terminal_unchanged = before_terminal == after_terminal;
                let purposes_unchanged =
                    cgka_traits::StorageProvider::device_linking_key_package_storage(&a_storage)
                        .unwrap()
                        .purpose_key_package()
                        .unwrap()
                        == approver_purpose
                        && cgka_traits::StorageProvider::device_linking_key_package_storage(
                            &c_storage,
                        )
                        .unwrap()
                        .purpose_key_package()
                        .unwrap()
                            == recipient_purpose;
                drop(injector);
                runtime_c.shutdown_and_close().await.unwrap();
                crate::test_support::emit_line(format_args!(
                    "proposal-receipt-safety-close index=0"
                ));
                workers.runtime_a.shutdown_and_close().await.unwrap();
                crate::test_support::emit_line(format_args!(
                    "proposal-receipt-safety-close index=1"
                ));
                workers.runtime_b.shutdown_and_close().await.unwrap();
                crate::test_support::emit_line(format_args!(
                    "proposal-receipt-safety-close index=2"
                ));
                relay.shutdown();
                crate::test_support::emit_line(format_args!(
                    "proposal-receipt-newer-terminal-control {}",
                    serde_json::json!({
                        "owned_proposal": observed.owned_proposal,
                        "retired_proposal": observed.retired_proposal,
                        "durable_absent": durable_absent,
                        "newer_reserved": newer_reserved,
                        "newer_terminal": newer_terminal,
                        "old_cancel_stale": old_cancel_stale,
                        "newer_revision_unchanged": newer_revision_unchanged,
                        "newer_terminal_unchanged": newer_terminal_unchanged,
                        "purposes_unchanged": purposes_unchanged,
                        "runtime_closed": true,
                    })
                ));
                assert!(
                    newer_reserved
                        && newer_terminal
                        && old_cancel_stale
                        && newer_revision_unchanged
                        && newer_terminal_unchanged
                        && purposes_unchanged,
                    "retired proposal must not acknowledge or mutate a newer terminal reservation"
                );
                return;
            }
            if proposal_only_cancel_maintenance {
                let probe = workers
                    .a
                    .verifier_command("test", |respond| {
                        VerifierCommand::CaptureProposalOnlyCancelForTest {
                            scope: a_scope.clone(),
                            respond,
                        }
                    })
                    .await
                    .unwrap();
                let account = workers.a.resolve("test").unwrap();
                {
                    let active = workers.a.workers.lock().await;
                    active
                        .get(&account.account_id_hex)
                        .unwrap()
                        .publication_control
                        .revoke(&a_scope);
                }
                workers
                    .a
                    .maintain_device_linking_at_for_test("test", std::time::Instant::now())
                    .await
                    .unwrap();
                let retired = probe
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .retired_proposal;
                assert!(
                    retired,
                    "the real proposal-only original must retire before cancellation"
                );
                if proposal_cancel_sql_read_error {
                    let a_anchor =
                        cgka_traits::StorageProvider::accepted_device_group_anchor_storage(
                            &a_storage,
                        )
                        .unwrap()
                        .accepted_anchor()
                        .unwrap();
                    let b_round =
                        cgka_traits::StorageProvider::private_roster_settlement_storage(&b_storage)
                            .unwrap()
                            .read_round()
                            .unwrap();
                    let c_purpose =
                        cgka_traits::StorageProvider::device_linking_key_package_storage(
                            &c_storage,
                        )
                        .unwrap()
                        .purpose_key_package()
                        .unwrap();
                    let cap =
                        cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                            .unwrap();
                    assert!(cap.private_invite().unwrap().is_none());
                    let injector = private_commit_injector(&workers.a);
                    let empty: i64 = injector
                        .query_row(
                            "SELECT count(*) FROM private_device_invite_staging",
                            [],
                            |row| row.get(0),
                        )
                        .unwrap();
                    assert_eq!(
                        empty, 0,
                        "the SQL read-error fixture must never drop actual invite data"
                    );
                    let schema = |connection: &rusqlite::Connection| {
                        let mut statement = connection.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name, tbl_name").unwrap();
                        let rows = statement
                            .query_map([], |row| {
                                Ok((
                                    row.get::<_, String>(0)?,
                                    row.get::<_, String>(1)?,
                                    row.get::<_, String>(2)?,
                                    row.get::<_, Option<String>>(3)?,
                                ))
                            })
                            .unwrap();
                        rows.collect::<Result<Vec<_>, _>>().unwrap()
                    };
                    let original_schema = schema(&injector);
                    let table = original_schema
                        .iter()
                        .filter(|row| row.0 == "table" && row.1 == "private_device_invite_staging")
                        .map(|row| {
                            row.3
                                .clone()
                                .expect("actual staging table has its original DDL")
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(table.len(), 1);
                    let attached = original_schema
                        .iter()
                        .filter(|row| {
                            row.2 == "private_device_invite_staging"
                                && (row.0 == "index" || row.0 == "trigger")
                        })
                        .filter_map(|row| row.3.clone())
                        .collect::<Vec<_>>();
                    // Only this isolated fixture's proven-empty table is removed. No rows,
                    // permission, sqlite_master edits or migration-version changes are made.
                    injector
                        .execute_batch("DROP TABLE private_device_invite_staging;")
                        .unwrap();
                    let first_result = workers.a.cancel_device_linking("test", &a_scope).await;
                    let storage_error =
                        matches!(first_result, Err(ClientLinkingError::PrivateInvite(
                        cgka_engine::private_device_invite::PrivateInviteError::Storage(
                            cgka_traits::private_device_invite::PrivateInviteStorageError::Storage(
                                cgka_traits::storage::StorageError::Backend(_)
                            )
                        )
                    )));
                    let first_observed = probe
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .clone();
                    // Restore exact captured DDL even when the behavioral verdict was false.
                    injector.execute_batch(&table[0]).unwrap();
                    for sql in &attached {
                        injector.execute_batch(sql).unwrap();
                    }
                    let schema_restored = schema(&injector) == original_schema;
                    assert!(
                        schema_restored,
                        "the isolated SQL fault must restore every original schema object exactly"
                    );
                    drop(injector);
                    let fact_still_absent = cap.private_invite().unwrap().is_none();
                    let retry_ok = workers
                        .a
                        .cancel_device_linking("test", &a_scope)
                        .await
                        .is_ok();
                    let repeat_stale = matches!(
                        workers.a.cancel_device_linking("test", &a_scope).await,
                        Err(ClientLinkingError::Owner(
                            crate::device_linking::OwnerError::Verifier(
                                crate::device_linking::LinkError::StaleFlow
                            )
                        ))
                    );
                    let anchors_unchanged =
                        cgka_traits::StorageProvider::accepted_device_group_anchor_storage(
                            &a_storage,
                        )
                        .unwrap()
                        .accepted_anchor()
                        .unwrap()
                            == a_anchor
                            && cgka_traits::StorageProvider::private_roster_settlement_storage(
                                &b_storage,
                            )
                            .unwrap()
                            .read_round()
                            .unwrap()
                                == b_round
                            && cgka_traits::StorageProvider::device_linking_key_package_storage(
                                &c_storage,
                            )
                            .unwrap()
                            .purpose_key_package()
                            .unwrap()
                                == c_purpose;
                    let safe = storage_error
                        && first_observed.owned_proposal
                        && first_observed.retired_proposal
                        && first_observed.fallback_entered
                        && !first_observed.context_rejected
                        && first_observed.scope_check_entered
                        && first_observed.scope_check_passed
                        && !first_observed.durable_query_completed
                        && first_observed.durable_phase.is_none()
                        && first_observed.exact_retired.is_none()
                        && schema_restored
                        && fact_still_absent
                        && retry_ok
                        && repeat_stale
                        && anchors_unchanged;
                    runtime_c.shutdown_and_close().await.unwrap();
                    crate::test_support::emit_line(format_args!(
                        "proposal-sql-cancel-close index=0"
                    ));
                    workers.runtime_a.shutdown_and_close().await.unwrap();
                    crate::test_support::emit_line(format_args!(
                        "proposal-sql-cancel-close index=1"
                    ));
                    workers.runtime_b.shutdown_and_close().await.unwrap();
                    crate::test_support::emit_line(format_args!(
                        "proposal-sql-cancel-close index=2"
                    ));
                    relay.shutdown();
                    crate::test_support::emit_line(format_args!(
                        "proposal-sql-cancel-control {}",
                        serde_json::json!({
                            "storage_error": storage_error, "owned_proposal": first_observed.owned_proposal,
                            "locally_retired": first_observed.retired_proposal, "fallback_entered": first_observed.fallback_entered,
                            "context_rejected": first_observed.context_rejected, "scope_check_entered": first_observed.scope_check_entered,
                            "scope_check_passed": first_observed.scope_check_passed, "durable_query_completed": first_observed.durable_query_completed,
                            "durable_phase": first_observed.durable_phase, "exact_retired": first_observed.exact_retired,
                            "schema_restored": schema_restored, "fact_still_absent": fact_still_absent,
                            "retry_ok": retry_ok, "repeat_stale": repeat_stale, "anchors_unchanged": anchors_unchanged,
                        })
                    ));
                    assert!(
                        safe,
                        "a real proposal cancellation storage error must preserve exact once-only retry after schema restoration"
                    );
                    return;
                }

                let cancel_result = workers.a.cancel_device_linking("test", &a_scope).await;
                let cancel_ok = cancel_result.is_ok();
                let cancel_stale = matches!(
                    cancel_result,
                    Err(ClientLinkingError::Owner(
                        crate::device_linking::OwnerError::Verifier(
                            crate::device_linking::LinkError::StaleFlow
                        )
                    ))
                );
                let observed = probe
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .clone();
                runtime_c.shutdown_and_close().await.unwrap();
                crate::test_support::emit_line(format_args!("proposal-only-cancel-close index=0"));
                workers.runtime_a.shutdown_and_close().await.unwrap();
                crate::test_support::emit_line(format_args!("proposal-only-cancel-close index=1"));
                workers.runtime_b.shutdown_and_close().await.unwrap();
                crate::test_support::emit_line(format_args!("proposal-only-cancel-close index=2"));
                relay.shutdown();
                crate::test_support::emit_line(format_args!(
                    "proposal-only-cancel-control {}",
                    serde_json::json!({
                        "owned_proposal": observed.owned_proposal, "retired_proposal": observed.retired_proposal,
                        "fallback_entered": observed.fallback_entered, "context_rejected": observed.context_rejected,
                        "scope_check_entered": observed.scope_check_entered, "scope_check_passed": observed.scope_check_passed,
                        "durable_query_completed": observed.durable_query_completed,
                        "durable_phase": observed.durable_phase, "exact_retired": observed.exact_retired,
                        "cancel_ok": cancel_ok, "cancel_stale": cancel_stale,
                    })
                ));
                assert!(
                    cancel_ok,
                    "proposal-only cancellation must acknowledge the exact original after real maintenance"
                );
                return;
            }
            workers
                .a
                .cancel_device_linking("test", &a_scope)
                .await
                .unwrap();
            runtime_c.shutdown_and_close().await.unwrap();
            workers.runtime_a.shutdown_and_close().await.unwrap();
            workers.runtime_b.shutdown_and_close().await.unwrap();
            relay.shutdown();
            return;
        }
        if check == ThirdDeviceCheck::RetainedScope {
            let mut foreign = a_scope.clone();
            foreign.account[0] ^= 1;
            assert!(
                workers
                    .a
                    .prepare_private_device_invite("test", &foreign)
                    .await
                    .is_err()
            );
            assert!(
                workers
                    .a
                    .cancel_device_linking("test", &foreign)
                    .await
                    .is_err()
            );
            assert!(
                workers
                    .a
                    .prepare_private_device_invite("test", &a_scope)
                    .await
                    .is_err()
            );
            workers
                .a
                .take_device_linking_verified("test", &a_scope)
                .await
                .unwrap();
            runtime_c.shutdown_and_close().await.unwrap();
            workers.runtime_a.shutdown_and_close().await.unwrap();
            workers.runtime_b.shutdown_and_close().await.unwrap();
            relay.shutdown();
            return;
        }
        if check == ThirdDeviceCheck::ArtifactPreparation {
            let before = cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                .unwrap()
                .private_invite()
                .unwrap();
            workers
                .a
                .prepare_enrollment_proposal("test", &a_scope)
                .await
                .unwrap();
            assert_eq!(
                workers
                    .a
                    .collect_owned_enrollment_endorsements("test", &a_scope)
                    .await
                    .unwrap(),
                0
            );
            assert!(
                cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                    .unwrap()
                    .private_invite()
                    .unwrap()
                    == before
            );
            workers
                .a
                .cancel_device_linking("test", &a_scope)
                .await
                .unwrap();
            runtime_c.shutdown_and_close().await.unwrap();
            workers.runtime_a.shutdown_and_close().await.unwrap();
            workers.runtime_b.shutdown_and_close().await.unwrap();
            relay.shutdown();
            return;
        }
        if matches!(
            check,
            ThirdDeviceCheck::LocalProposal
                | ThirdDeviceCheck::LocalProposalEndorsement
                | ThirdDeviceCheck::LocalProposalCollection
                | ThirdDeviceCheck::LocalProposalTrustedAdd
                | ThirdDeviceCheck::LocalProposalTrustedAddRetry
                | ThirdDeviceCheck::LocalProposalRecipientAdmission
                | ThirdDeviceCheck::LocalProposalRecipientJoin
                | ThirdDeviceCheck::LocalProposalExistingTransition
                | ThirdDeviceCheck::LocalProposalAbcSettlement
                | ThirdDeviceCheck::LocalProposalDroppedReply
                | ThirdDeviceCheck::LocalProposalReopen
        ) {
            let c_storage = c.app.account_storage("test").unwrap();
            let c_purpose =
                cgka_traits::StorageProvider::device_linking_key_package_storage(&c_storage)
                    .unwrap()
                    .purpose_key_package()
                    .unwrap();
            assert!(c_purpose.as_ref().is_some_and(|package| !package.consumed));
            let a_anchor =
                cgka_traits::StorageProvider::accepted_device_group_anchor_storage(&a_storage)
                    .unwrap()
                    .accepted_anchor()
                    .unwrap();
            let before = cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                .unwrap()
                .private_invite()
                .unwrap();
            let b_before =
                cgka_traits::StorageProvider::private_roster_settlement_storage(&b_storage)
                    .unwrap()
                    .read_round()
                    .unwrap();
            workers
                .a
                .prepare_enrollment_proposal("test", &a_scope)
                .await
                .expect("the original fresh A/C SDK owner must produce its encrypted proposal");
            workers
                .a
                .prepare_enrollment_proposal("test", &a_scope)
                .await
                .unwrap();
            // Caller metadata cannot substitute a different generation or
            // turn the retained original proposal into an Add continuation.
            let mut future = a_scope.clone();
            future.generation += 1;
            assert!(
                workers
                    .a
                    .prepare_enrollment_proposal("test", &future)
                    .await
                    .is_err()
            );
            assert!(
                workers
                    .a
                    .cancel_device_linking("test", &future)
                    .await
                    .is_err()
            );
            assert!(
                workers
                    .a
                    .prepare_private_device_invite("test", &a_scope)
                    .await
                    .is_err()
            );
            workers
                .a
                .prepare_enrollment_proposal("test", &a_scope)
                .await
                .unwrap();
            let endpoint = cgka_traits::TransportEndpoint(relay.url().await.to_string());
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                loop {
                    if workers
                        .b
                        .verifier_command("test", |respond| {
                            VerifierCommand::CurrentEnrollmentEndpointEoseForTest {
                                group: group.clone(),
                                endpoint: endpoint.clone(),
                                respond,
                            }
                        })
                        .await
                        .unwrap()
                    {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the exact B private route must reach current EOSE before the live proposal");
            workers
                .a
                .publish_enrollment_proposal("test", &a_scope)
                .await
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                loop {
                    if workers
                        .b
                        .verifier_command("test", |respond| {
                            VerifierCommand::ValidateReceivedEnrollmentProposals { respond }
                        })
                        .await
                        .unwrap()
                        == 1
                    {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("B must authenticate the actual received A/C SDK proposal");
            if matches!(
                check,
                ThirdDeviceCheck::LocalProposalEndorsement
                    | ThirdDeviceCheck::LocalProposalCollection
                    | ThirdDeviceCheck::LocalProposalTrustedAdd
                    | ThirdDeviceCheck::LocalProposalTrustedAddRetry
                    | ThirdDeviceCheck::LocalProposalRecipientAdmission
                    | ThirdDeviceCheck::LocalProposalRecipientJoin
                    | ThirdDeviceCheck::LocalProposalExistingTransition
                    | ThirdDeviceCheck::LocalProposalAbcSettlement
                    | ThirdDeviceCheck::LocalProposalReopen
            ) {
                let bindings = workers
                    .b
                    .verifier_command("test", |respond| {
                        VerifierCommand::ReceivedEnrollmentProposalBindings { respond }
                    })
                    .await
                    .unwrap();
                assert_eq!(bindings.len(), 1);
                workers.b.verifier_command("test", |respond|
                    VerifierCommand::EndorseReceivedEnrollmentProposal {
                        binding: bindings[0], respond,
                    }).await.expect("B's explicit action on the actual received SDK proposal must retain its owned endorsement");
            }

            if matches!(
                check,
                ThirdDeviceCheck::LocalProposalCollection
                    | ThirdDeviceCheck::LocalProposalTrustedAdd
                    | ThirdDeviceCheck::LocalProposalTrustedAddRetry
                    | ThirdDeviceCheck::LocalProposalRecipientAdmission
                    | ThirdDeviceCheck::LocalProposalRecipientJoin
                    | ThirdDeviceCheck::LocalProposalExistingTransition
                    | ThirdDeviceCheck::LocalProposalAbcSettlement
            ) {
                assert_eq!(
                    workers
                        .a
                        .verifier_command("test", |respond| {
                            VerifierCommand::CollectOwnedEnrollmentEndorsements {
                                scope: a_scope.clone(),
                                respond,
                            }
                        })
                        .await
                        .expect("the original live A proposal must expose pending collection"),
                    0
                );
                tokio::time::timeout(std::time::Duration::from_secs(20), async {
                    loop {
                        if workers
                            .a
                            .verifier_command("test", |respond| {
                                VerifierCommand::CurrentEnrollmentEndpointEoseForTest {
                                    group: group.clone(),
                                    endpoint: endpoint.clone(),
                                    respond,
                                }
                            })
                            .await
                            .unwrap()
                        {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("A's exact current private route must reach EOSE before B publication");
                if check == ThirdDeviceCheck::LocalProposalTrustedAddRetry {
                    assert!(
                        workers
                            .a
                            .prepare_endorsed_enrollment_invite("test", &a_scope)
                            .await
                            .is_err(),
                        "A cannot stage before B has actually published its approval"
                    );
                }
                let selected = workers
                    .b
                    .verifier_command("test", |respond| {
                        VerifierCommand::ReceivedEnrollmentProposalBindings { respond }
                    })
                    .await
                    .unwrap()[0];
                workers
                    .b
                    .verifier_command("test", |respond| {
                        VerifierCommand::PublishReceivedEnrollmentEndorsement {
                            binding: selected,
                            respond,
                        }
                    })
                    .await
                    .expect(
                        "B's original explicit action must publish its real encrypted endorsement",
                    );
                if check == ThirdDeviceCheck::LocalProposalTrustedAddRetry {
                    let owned = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                        loop {
                            if let Ok(owned) = workers.a.prepare_endorsed_enrollment_invite("test", &a_scope).await {
                                break owned;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        }
                    }).await.expect("incomplete original handoff must automatically collect B's later actual receipt and retry");
                    let fact =
                        cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                            .unwrap()
                            .private_invite()
                            .unwrap()
                            .unwrap();
                    assert!(fact.scope == owned);
                    assert_eq!(fact.raw.binding.successor.epoch.0, 2);
                    assert_eq!(fact.raw.binding.successor.leaves.len(), 3);
                    assert!(
                        cgka_traits::StorageProvider::device_linking_key_package_storage(
                            &c_storage
                        )
                        .unwrap()
                        .purpose_key_package()
                        .unwrap()
                            == c_purpose
                    );
                    if late_first_cancel {
                        use cgka_traits::private_device_invite::PrivateInvitePhase;
                        assert!(fact.phase == PrivateInvitePhase::Wrapped);
                        assert!(fact.raw.binding.approver_scope == a_scope);
                        assert!(fact.transport.is_some());
                        // Abandon an ACTUAL successful cached Prepare reply.
                        // Its actor cleanup retires the invite without caller revoke.
                        let account = workers.a.resolve("test").unwrap();
                        let prior_reply = {
                            let active = workers.a.workers.lock().await;
                            active
                                .get(&account.account_id_hex)
                                .unwrap()
                                .publication_control
                                .prepare_reply_for_test(&a_scope)
                                .unwrap()
                        };
                        assert!(prior_reply.1);
                        let commands = workers.a.worker_commands("test").await.unwrap();
                        let (respond, receiver) = tokio::sync::oneshot::channel();
                        drop(receiver);
                        commands
                            .send(AccountWorkerCommand::DeviceLinkingVerifier(Box::new(
                                VerifierCommand::PrepareEndorsedEnrollmentInvite {
                                    scope: a_scope.clone(),
                                    respond,
                                },
                            )))
                            .await
                            .unwrap();
                        // Real serial command barrier after abandoned-response cleanup.
                        workers
                            .a
                            .maintain_device_linking_at_for_test("test", std::time::Instant::now())
                            .await
                            .unwrap();
                        let retired =
                            cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                                .unwrap()
                                .private_invite()
                                .unwrap()
                                .unwrap();
                        assert!(retired.phase == PrivateInvitePhase::Retired);
                        assert!(
                            retired.scope == fact.scope
                                && retired.raw == fact.raw
                                && retired.transport == fact.transport
                        );
                        {
                            let active = workers.a.workers.lock().await;
                            let worker = active.get(&account.account_id_hex).unwrap();
                            let reply = worker
                                .publication_control
                                .prepare_reply_for_test(&a_scope)
                                .unwrap();
                            assert!(reply.1);
                            assert_eq!(reply.0, prior_reply.0.checked_add(1).unwrap());
                            assert!(
                                worker
                                    .publication_control
                                    .unrevoked_invite_revision_for_test(&a_scope)
                                    .is_some()
                            );
                        }
                        let newer = workers
                            .a
                            .reserve_device_linking_for_approver("test")
                            .await
                            .unwrap();
                        assert!(newer.generation > a_scope.generation);
                        workers
                            .a
                            .cancel_device_linking("test", &newer)
                            .await
                            .unwrap();
                        let purpose_before =
                            cgka_traits::StorageProvider::device_linking_key_package_storage(
                                &a_storage,
                            )
                            .unwrap()
                            .purpose_key_package()
                            .unwrap();
                        let before_late = {
                            let active = workers.a.workers.lock().await;
                            active
                                .get(&account.account_id_hex)
                                .unwrap()
                                .publication_control
                                .unrevoked_invite_revision_for_test(&a_scope)
                                .unwrap()
                        };
                        crate::test_support::emit_line(format_args!(
                            "cancel-late-first-prerequisites {{\"successful_reply_abandoned\":true,\"same_owned_retired\":true,\"old_slot_unrevoked\":true,\"newer_reservation_terminal\":true}}"
                        ));
                        let old_result = workers.a.cancel_device_linking("test", &a_scope).await;
                        let old_acknowledged = old_result.is_ok();
                        let old_stale_rejected = matches!(
                            old_result,
                            Err(ClientLinkingError::Owner(
                                crate::device_linking::OwnerError::Verifier(
                                    crate::device_linking::LinkError::StaleFlow
                                )
                            ))
                        );
                        let current_revision_unchanged =
                            before_late.revision_matches_for_negative_completion();
                        drop(before_late);
                        assert!(
                            cgka_traits::StorageProvider::device_linking_key_package_storage(
                                &a_storage
                            )
                            .unwrap()
                            .purpose_key_package()
                            .unwrap()
                                == purpose_before
                        );
                        assert!(
                            cgka_traits::StorageProvider::device_linking_key_package_storage(
                                &c_storage
                            )
                            .unwrap()
                            .purpose_key_package()
                            .unwrap()
                                == c_purpose
                        );
                        // Freeze the verdict before positive owned teardown; teardown
                        // necessarily changes cancellation counters and cannot be sampled instead.
                        runtime_c.shutdown_and_close().await.unwrap();
                        workers.runtime_a.shutdown_and_close().await.unwrap();
                        workers.runtime_b.shutdown_and_close().await.unwrap();
                        relay.shutdown();
                        crate::test_support::emit_line(format_args!(
                            "cancel-late-first-result {{\"old_acknowledged\":{},\"old_stale_rejected\":{},\"current_revision_unchanged\":{},\"owned_runtimes_closed\":true}}",
                            old_acknowledged, old_stale_rejected, current_revision_unchanged
                        ));
                        assert!(
                            old_stale_rejected && current_revision_unchanged,
                            "late first cancellation must reject old scope without touching the newer gate"
                        );
                        return;
                    }
                    if cancel_after_maintenance {
                        use cgka_traits::private_device_invite::PrivateInvitePhase;
                        assert!(fact.phase == PrivateInvitePhase::Wrapped);
                        assert!(fact.raw.binding.approver_scope == a_scope);
                        assert!(fact.transport.is_some());
                        let account = workers.a.resolve("test").unwrap();
                        {
                            let active = workers.a.workers.lock().await;
                            let worker = active.get(&account.account_id_hex).unwrap();
                            worker.publication_control.revoke(&a_scope);
                        }
                        workers
                            .a
                            .maintain_device_linking_at_for_test("test", std::time::Instant::now())
                            .await
                            .unwrap();
                        let retired =
                            cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                                .unwrap()
                                .private_invite()
                                .unwrap()
                                .unwrap();
                        assert!(retired.phase == PrivateInvitePhase::Retired);
                        assert!(retired.scope == fact.scope);
                        assert!(retired.raw == fact.raw);
                        assert!(retired.transport == fact.transport);
                        assert!(
                            cgka_traits::StorageProvider::device_linking_key_package_storage(
                                &c_storage
                            )
                            .unwrap()
                            .purpose_key_package()
                            .unwrap()
                                == c_purpose
                        );
                        crate::test_support::emit_line(format_args!(
                            "cancel-maintenance-control {{\"wrapped_owned\":true,\"same_retired_owned\":true,\"recipient_purpose_unchanged\":true,\"real_maintenance_completed\":true}}"
                        ));
                    }
                    if newer_terminal_after_maintenance {
                        // A real reservation must invalidate the old revision,
                        // even after this newer owner reaches terminal state.
                        let newer = workers
                            .a
                            .reserve_device_linking_for_approver("test")
                            .await
                            .unwrap();
                        assert!(newer != a_scope);
                        assert!(newer.generation > a_scope.generation);
                        workers
                            .a
                            .cancel_device_linking("test", &newer)
                            .await
                            .unwrap();
                        let purpose_before =
                            cgka_traits::StorageProvider::device_linking_key_package_storage(
                                &a_storage,
                            )
                            .unwrap()
                            .purpose_key_package()
                            .unwrap();
                        assert!(matches!(
                            workers.a.cancel_device_linking("test", &a_scope).await,
                            Err(ClientLinkingError::Owner(
                                crate::device_linking::OwnerError::Verifier(
                                    crate::device_linking::LinkError::StaleFlow
                                )
                            ))
                        ));
                        assert!(
                            cgka_traits::StorageProvider::device_linking_key_package_storage(
                                &a_storage
                            )
                            .unwrap()
                            .purpose_key_package()
                            .unwrap()
                                == purpose_before
                        );
                        assert!(
                            cgka_traits::StorageProvider::device_linking_key_package_storage(
                                &c_storage
                            )
                            .unwrap()
                            .purpose_key_package()
                            .unwrap()
                                == c_purpose
                        );
                        runtime_c.shutdown_and_close().await.unwrap();
                        workers.runtime_a.shutdown_and_close().await.unwrap();
                        workers.runtime_b.shutdown_and_close().await.unwrap();
                        relay.shutdown();
                        return;
                    }
                    workers
                        .a
                        .cancel_device_linking("test", &a_scope)
                        .await
                        .unwrap();
                    runtime_c.shutdown_and_close().await.unwrap();
                    workers.runtime_a.shutdown_and_close().await.unwrap();
                    workers.runtime_b.shutdown_and_close().await.unwrap();
                    relay.shutdown();
                    return;
                }
                tokio::time::timeout(std::time::Duration::from_secs(20), async {
                    loop {
                        if workers.a.verifier_command("test", |respond|
                            VerifierCommand::CollectOwnedEnrollmentEndorsements { scope: a_scope.clone(), respond })
                            .await.unwrap() == 2 { break; }
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }).await.expect("A must collect its original local signature and B's actual encrypted MLS receipt");
                assert_eq!(
                    workers
                        .a
                        .verifier_command("test", |respond| {
                            VerifierCommand::CollectOwnedEnrollmentEndorsements {
                                scope: a_scope.clone(),
                                respond,
                            }
                        })
                        .await
                        .unwrap(),
                    2
                );
                assert!(
                    workers
                        .a
                        .verifier_command("test", |respond| {
                            VerifierCommand::CollectOwnedEnrollmentEndorsements {
                                scope: future.clone(),
                                respond,
                            }
                        })
                        .await
                        .is_err(),
                    "future scope cannot collect the original A proposal"
                );
                if matches!(
                    check,
                    ThirdDeviceCheck::LocalProposalRecipientAdmission
                        | ThirdDeviceCheck::LocalProposalRecipientJoin
                        | ThirdDeviceCheck::LocalProposalExistingTransition
                        | ThirdDeviceCheck::LocalProposalAbcSettlement
                ) {
                    let packet = workers.a.verifier_command("test", |respond|
                        VerifierCommand::ExportOwnedEnrollmentRecipientPacket { scope: a_scope.clone(), respond })
                        .await.expect("complete original A approval must export bounded signed recipient evidence before lease transfer");
                    assert!(packet.len() <= 16 * 1024);
                    let mut wrong = prepared.scope.clone();
                    wrong.generation += 1;
                    assert!(
                        c.verifier_command("test", |respond| {
                            VerifierCommand::ArmEndorsedEnrollmentRecipient {
                                scope: wrong,
                                packet: packet.clone(),
                                respond,
                            }
                        })
                        .await
                        .is_err(),
                        "foreign purpose cannot consume the original C verifier"
                    );
                    assert!(
                        c.verifier_command("test", |respond| {
                            VerifierCommand::ArmEndorsedEnrollmentRecipient {
                                scope: prepared.scope.clone(),
                                packet: vec![b'{'],
                                respond,
                            }
                        })
                        .await
                        .is_err(),
                        "malformed evidence must preserve valid original purpose retry"
                    );
                    let decoded: serde_json::Value = serde_json::from_slice(&packet).unwrap();
                    let original_json = String::from_utf8(packet.clone()).unwrap();
                    let last = decoded["endorsements"].as_array().unwrap().last().unwrap();
                    let suffix = format!(",{}]}}", serde_json::to_string(last).unwrap());
                    assert!(original_json.ends_with(&suffix));
                    let unsigned = format!("{}]}}", original_json.strip_suffix(&suffix).unwrap());
                    assert!(
                        c.arm_endorsed_enrollment_recipient(
                            "test",
                            &prepared.scope,
                            unsigned.as_bytes()
                        )
                        .await
                        .is_err(),
                        "canonical incomplete indexed-leaf coverage must preserve original C retry"
                    );
                    let old_digest = &decoded["request"]["context_digest"];
                    let mut new_digest = old_digest.clone();
                    new_digest[0] = serde_json::json!(old_digest[0].as_u64().unwrap() ^ 1);
                    let substituted = original_json.replacen(
                        &format!("\"context_digest\":{}", old_digest),
                        &format!("\"context_digest\":{}", new_digest),
                        1,
                    );
                    assert_ne!(substituted, original_json);
                    assert!(
                        c.arm_endorsed_enrollment_recipient(
                            "test",
                            &prepared.scope,
                            substituted.as_bytes()
                        )
                        .await
                        .is_err(),
                        "canonical substituted context must not consume the original C SDK result"
                    );
                    assert!(
                        c.arm_endorsed_enrollment_recipient(
                            "test",
                            &prepared.scope,
                            &vec![b'x'; 16 * 1024 + 1]
                        )
                        .await
                        .is_err(),
                        "packet cap must deny before worker admission"
                    );
                    let existing_member_packet = packet.clone();
                    c.verifier_command("test", |respond|
                        VerifierCommand::ArmEndorsedEnrollmentRecipient { scope: prepared.scope.clone(), packet, respond })
                        .await.expect("actual all-leaf signatures plus original C SDK/purpose must arm dedicated recipient admission");
                    assert!(
                        cgka_traits::StorageProvider::device_linking_key_package_storage(
                            &c_storage
                        )
                        .unwrap()
                        .purpose_key_package()
                        .unwrap()
                            == c_purpose,
                        "arming is not acceptance and cannot consume the purpose"
                    );
                    if matches!(
                        check,
                        ThirdDeviceCheck::LocalProposalExistingTransition
                            | ThirdDeviceCheck::LocalProposalAbcSettlement
                    ) {
                        let mut foreign = selected;
                        foreign[0] ^= 1;
                        assert!(
                            workers
                                .b
                                .verifier_command("test", |respond| {
                                    VerifierCommand::ArmExistingMemberEnrollment {
                                        binding: foreign,
                                        packet: existing_member_packet.clone(),
                                        respond,
                                    }
                                })
                                .await
                                .is_err()
                        );
                        assert!(
                            workers
                                .b
                                .verifier_command("test", |respond| {
                                    VerifierCommand::ArmExistingMemberEnrollment {
                                        binding: selected,
                                        packet: vec![b'{'],
                                        respond,
                                    }
                                })
                                .await
                                .is_err()
                        );
                        workers.b.verifier_command("test", |respond|
                            VerifierCommand::ArmExistingMemberEnrollment { binding: selected, packet: existing_member_packet.clone(), respond })
                            .await.expect("B's same explicit original action plus complete actual signatures must arm its existing-member transition");
                    }
                    if matches!(
                        check,
                        ThirdDeviceCheck::LocalProposalRecipientJoin
                            | ThirdDeviceCheck::LocalProposalExistingTransition
                            | ThirdDeviceCheck::LocalProposalAbcSettlement
                    ) {
                        workers
                            .a
                            .prepare_endorsed_enrollment_invite("test", &a_scope)
                            .await
                            .unwrap();
                        let b_injector = matches!(
                            check,
                            ThirdDeviceCheck::LocalProposalExistingTransition
                                | ThirdDeviceCheck::LocalProposalAbcSettlement
                        )
                        .then(|| private_commit_injector(&workers.b));
                        if let Some(injector) = &b_injector {
                            injector.execute_batch("CREATE TRIGGER reject_existing_transition BEFORE INSERT ON existing_device_group_anchor BEGIN SELECT RAISE(ABORT,'injected existing transition rollback'); END;").unwrap();
                        }
                        let mut b_events = workers.runtime_b.subscribe_events();
                        workers
                            .a
                            .publish_private_device_invite_commit("test", &a_scope)
                            .await
                            .unwrap();
                        tokio::time::timeout(std::time::Duration::from_secs(20), async {
                            loop {
                                if cgka_traits::StorageProvider::private_device_invite_storage(
                                    &a_storage,
                                )
                                .unwrap()
                                .confirmed_private_invite()
                                .unwrap()
                                .is_some_and(|row| {
                                    !row.denied
                                        && row.binding.successor.epoch == cgka_traits::EpochId(2)
                                }) {
                                    break;
                                }
                                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                            }
                        })
                        .await
                        .expect("original endorsed A Add must confirm through actual relay intake");
                        if let Some(injector) = &b_injector {
                            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                                loop {
                                    match b_events.recv().await {
                                        Some(crate::MarmotAppEvent::AccountError(error)) if error.message.starts_with("scheduled convergence failed") || error.message.starts_with("runtime receive failed") => break,
                                        Some(_) => {}, None => panic!("B event stream closed before actual transition SQL fault"),
                                    }
                                }
                            }).await.expect("B must encounter the injected actual merge/anchor SQL fault");
                            assert!(
                                cgka_traits::StorageProvider::existing_device_group_anchor_storage(
                                    &b_storage
                                )
                                .unwrap()
                                .existing_anchor()
                                .unwrap()
                                .is_none()
                            );
                            assert_eq!(
                                cgka_traits::GroupStorage::get_group(&b_storage, &group)
                                    .unwrap()
                                    .epoch
                                    .0,
                                1
                            );
                            assert!(
                                cgka_traits::StorageProvider::private_roster_settlement_storage(
                                    &b_storage
                                )
                                .unwrap()
                                .read_round()
                                .unwrap()
                                .is_some_and(|round| round.phase
                                    == PrivateSettlementPhase::Completed
                                    && round.anchor.successor.epoch.0 == 1)
                            );
                            injector
                                .execute_batch("DROP TRIGGER reject_existing_transition;")
                                .unwrap();
                            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                                loop {
                                    if cgka_traits::StorageProvider::existing_device_group_anchor_storage(&b_storage).unwrap().existing_anchor().unwrap().is_some_and(|fact| !fact.denied && fact.draft.action_binding == selected && fact.draft.successor.epoch.0 == 2) { break; }
                                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                                }
                            }).await.unwrap_or_else(|_| panic!("B retry timeout: epoch={}, existing={}, mls={:?}, round={:?}", cgka_traits::GroupStorage::get_group(&b_storage, &group).unwrap().epoch.0, cgka_traits::StorageProvider::existing_device_group_anchor_storage(&b_storage).unwrap().existing_anchor().unwrap().is_some(), openmls::group::MlsGroup::load(cgka_traits::StorageProvider::mls_storage(&b_storage), &openmls::group::GroupId::from_slice(group.as_slice())).unwrap().map(|mls| mls.epoch().as_u64()), cgka_traits::StorageProvider::private_roster_settlement_storage(&b_storage).unwrap().read_round().unwrap().map(|round| serde_json::to_string(&round.phase).unwrap())));
                        }
                        let path = c.app.account_storage_path("test");
                        let keys = c.app.account_home().load_signing_keys("test").unwrap();
                        let key = c
                            .app
                            .sqlcipher_key(
                                "test",
                                &keys,
                                &path,
                                crate::sqlcipher::SqlcipherDatabaseKind::Session,
                            )
                            .unwrap();
                        let injector = rusqlite::Connection::open(&path).unwrap();
                        storage_sqlite::open_hardened_sqlcipher(
                            &injector,
                            &key,
                            storage_sqlite::SqlCipherHardening::cipher_only(),
                        )
                        .unwrap();
                        injector.execute_batch("CREATE TRIGGER reject_endorsed_recipient_consumption BEFORE UPDATE OF consumed ON device_linking_key_package WHEN NEW.consumed = 1 BEGIN SELECT RAISE(ABORT,'injected endorsed recipient rollback'); END;").unwrap();
                        let mut events = runtime_c.subscribe_events();
                        workers
                            .a
                            .verifier_command("test", |respond| {
                                VerifierCommand::PublishPrivateWelcomes {
                                    scope: a_scope.clone(),
                                    respond,
                                }
                            })
                            .await
                            .unwrap();
                        tokio::time::timeout(std::time::Duration::from_secs(10), async {
                            loop {
                                match events.recv().await {
                                    Some(crate::MarmotAppEvent::AccountError(error))
                                        if error.message.starts_with("runtime receive failed") =>
                                    {
                                        break;
                                    }
                                    Some(_) => {}
                                    None => {
                                        panic!("C event stream closed before actual join SQL fault")
                                    }
                                }
                            }
                        })
                        .await
                        .expect("actual C join must encounter injected final purpose SQL rollback");
                        assert!(
                            cgka_traits::StorageProvider::accepted_device_group_anchor_storage(
                                &c_storage
                            )
                            .unwrap()
                            .accepted_anchor()
                            .unwrap()
                            .is_none()
                        );
                        assert!(
                            cgka_traits::StorageProvider::device_linking_key_package_storage(
                                &c_storage
                            )
                            .unwrap()
                            .purpose_key_package()
                            .unwrap()
                                == c_purpose
                        );
                        assert!(cgka_traits::GroupStorage::get_group(&c_storage, &group).is_err());
                        injector
                            .execute_batch("DROP TRIGGER reject_endorsed_recipient_consumption;")
                            .unwrap();
                        tokio::time::timeout(std::time::Duration::from_secs(20), async {
                            loop {
                                if cgka_traits::StorageProvider::accepted_device_group_anchor_storage(&c_storage)
                                    .unwrap().accepted_anchor().unwrap().is_some() { break; }
                                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                            }
                        }).await.expect("C must autonomously retry the same original SDK/evidence/Welcome batch");
                        let anchor =
                            cgka_traits::StorageProvider::accepted_device_group_anchor_storage(
                                &c_storage,
                            )
                            .unwrap()
                            .accepted_anchor()
                            .unwrap()
                            .unwrap();
                        assert!(!anchor.denied && anchor.draft.purpose == prepared.scope);
                        assert_eq!(anchor.draft.predecessor.epoch.0, 1);
                        assert_eq!(anchor.draft.predecessor.leaves.len(), 2);
                        assert_eq!(anchor.draft.successor.epoch.0, 2);
                        assert_eq!(anchor.draft.successor.leaves.len(), 3);
                        let purpose =
                            cgka_traits::StorageProvider::device_linking_key_package_storage(
                                &c_storage,
                            )
                            .unwrap()
                            .purpose_key_package()
                            .unwrap()
                            .unwrap();
                        assert!(purpose.consumed && purpose.scope == prepared.scope);
                        assert_eq!(
                            cgka_traits::GroupStorage::get_group(&c_storage, &group)
                                .unwrap()
                                .epoch
                                .0,
                            2
                        );
                        if matches!(
                            check,
                            ThirdDeviceCheck::LocalProposalExistingTransition
                                | ThirdDeviceCheck::LocalProposalAbcSettlement
                        ) {
                            let candidate = workers.b.candidate_device_group_snapshot("test", &group).await.unwrap()
                                .expect("B must observe the actual successor before guarded protected round selection");
                            assert_eq!(candidate.epoch.0, 2);
                            assert_eq!(candidate.leaves.len(), 3);
                            let old_accepted =
                                cgka_traits::StorageProvider::accepted_device_group_anchor_storage(
                                    &b_storage,
                                )
                                .unwrap()
                                .accepted_anchor()
                                .unwrap();
                            let old_confirmed =
                                cgka_traits::StorageProvider::private_device_invite_storage(
                                    &b_storage,
                                )
                                .unwrap()
                                .confirmed_private_invite()
                                .unwrap();
                            assert!(
                                old_accepted.as_ref().is_none_or(
                                    |row| row.denied && row.draft.successor.epoch.0 == 1
                                )
                            );
                            assert!(
                                old_confirmed.as_ref().is_none_or(
                                    |row| row.denied && row.binding.successor.epoch.0 == 1
                                ),
                                "old AB109/110 facts must remain immutable and permanently denied"
                            );
                            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                                loop {
                                    if cgka_traits::StorageProvider::private_roster_settlement_storage(&b_storage)
                                        .unwrap().read_round().unwrap().is_some_and(|round|
                                            (round.phase == PrivateSettlementPhase::Pending
                                                || (check == ThirdDeviceCheck::LocalProposalAbcSettlement && round.phase == PrivateSettlementPhase::Completed))
                                            && round.anchor.successor.epoch.0 == 2
                                            && round.anchor.successor.leaves.len() == 3) { break; }
                                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                                }
                            }).await.expect("B's same local approval must select a guarded round under its distinct new protected origin");
                            let protected =
                                cgka_traits::StorageProvider::existing_device_group_anchor_storage(
                                    &b_storage,
                                )
                                .unwrap()
                                .existing_anchor()
                                .unwrap()
                                .unwrap();
                            assert!(
                                protected.draft.action_binding == selected && !protected.denied
                            );
                            assert!(
                                matches!(cgka_traits::StorageProvider::private_roster_settlement_storage(&b_storage).unwrap().read_round().unwrap().unwrap().anchor.origin, cgka_traits::private_device_invite::PrivateInviteOrigin::Existing(generation) if generation == protected.generation)
                            );
                            if check == ThirdDeviceCheck::LocalProposalExistingTransition {
                                workers
                                    .b
                                    .verifier_command("test", |respond| {
                                        VerifierCommand::CancelReceivedEnrollmentEndorsement {
                                            binding: selected,
                                            respond,
                                        }
                                    })
                                    .await
                                    .unwrap();
                                assert!(
                                    workers
                                        .b
                                        .verifier_command("test", |respond| {
                                            VerifierCommand::ArmExistingMemberEnrollment {
                                                binding: selected,
                                                packet: existing_member_packet.clone(),
                                                respond,
                                            }
                                        })
                                        .await
                                        .is_err(),
                                    "protected SQL facts and copied complete signatures cannot restore cancelled original B approval"
                                );
                                assert!(
                                cgka_traits::StorageProvider::existing_device_group_anchor_storage(
                                    &b_storage
                                )
                                .unwrap()
                                .existing_anchor()
                                .unwrap()
                                    == Some(protected)
                            );
                                assert!(
                                cgka_traits::StorageProvider::private_roster_settlement_storage(
                                    &b_storage
                                )
                                .unwrap()
                                .read_round()
                                .unwrap()
                                .is_some_and(|round| round.phase == PrivateSettlementPhase::Denied
                                    && round.anchor.successor.epoch.0 == 2)
                            );
                            } else {
                                tokio::time::timeout(std::time::Duration::from_secs(20), async {
                                    loop {
                                        let settled = [&a_storage, &b_storage, &c_storage].iter().all(|storage| {
                                            let store = cgka_traits::StorageProvider::private_roster_settlement_storage(*storage).unwrap();
                                            store.read_round().unwrap().is_some_and(|round|
                                                round.phase == PrivateSettlementPhase::Completed
                                                && round.anchor.group_id == group
                                                && round.anchor.successor.epoch.0 == 2
                                                && round.anchor.successor.leaves.len() == 3)
                                                && store.read_facts().unwrap().len() == 3
                                        });
                                        if settled { break; }
                                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                                    }
                                }).await.unwrap_or_else(|_| {
                                    let states = [&a_storage, &b_storage, &c_storage].iter().map(|storage| {
                                        let store = cgka_traits::StorageProvider::private_roster_settlement_storage(*storage).unwrap();
                                        (store.read_round().unwrap().map(|r| (serde_json::to_string(&r.phase).unwrap(), r.anchor.successor.epoch.0, r.anchor.successor.leaves.len())), store.read_facts().unwrap().len())
                                    }).collect::<Vec<_>>();
                                    let rounds = [&a_storage, &b_storage, &c_storage].iter().map(|storage| cgka_traits::StorageProvider::private_roster_settlement_storage(*storage).unwrap().read_round().unwrap().unwrap().anchor).collect::<Vec<_>>();
                                    let a=&rounds[0]; let b=&rounds[1]; let c=&rounds[2];
                                    panic!("original ABC settlement timeout: {:?}, ABmatch(commitment,nonce,context,coordinator,tree)={:?}, ACmatch={:?}", states, (a.roster_commitment==b.roster_commitment,a.enrollment_nonce==b.enrollment_nonce,a.context_digest==b.context_digest,a.coordinator==b.coordinator,a.successor==b.successor), (a.roster_commitment==c.roster_commitment,a.enrollment_nonce==c.enrollment_nonce,a.context_digest==c.context_digest,a.coordinator==c.coordinator,a.successor==c.successor));
                                });
                                for manager in [&workers.a, &workers.b, &c] {
                                    let artifact = manager.export_settled_device_predecessor("test", &group).await
                                        .expect("each final roster must validate its actual protected completed tree");
                                    assert!(!artifact.unwrap().is_empty());
                                }
                            }
                        }
                        assert!(workers.a.app.load_state("test").unwrap().groups.is_empty());
                        assert!(workers.b.app.load_state("test").unwrap().groups.is_empty());
                        assert!(c.app.load_state("test").unwrap().groups.is_empty());
                    }
                    c.cancel_device_linking("test", &prepared.scope)
                        .await
                        .unwrap();
                    runtime_c.shutdown_and_close().await.unwrap();
                    workers.runtime_a.shutdown_and_close().await.unwrap();
                    workers.runtime_b.shutdown_and_close().await.unwrap();
                    relay.shutdown();
                    return;
                }
                if check == ThirdDeviceCheck::LocalProposalTrustedAdd {
                    assert!(
                        workers
                            .a
                            .verifier_command("test", |respond| {
                                VerifierCommand::PrepareEndorsedEnrollmentInvite {
                                    scope: future.clone(),
                                    respond,
                                }
                            })
                            .await
                            .is_err(),
                        "future scope cannot transfer the original lease"
                    );
                    let path = workers.a.app.account_storage_path("test");
                    let keys = workers
                        .a
                        .app
                        .account_home()
                        .load_signing_keys("test")
                        .unwrap();
                    let key = workers
                        .a
                        .app
                        .sqlcipher_key(
                            "test",
                            &keys,
                            &path,
                            crate::sqlcipher::SqlcipherDatabaseKind::Session,
                        )
                        .unwrap();
                    let injector = rusqlite::Connection::open(&path).unwrap();
                    storage_sqlite::open_hardened_sqlcipher(
                        &injector,
                        &key,
                        storage_sqlite::SqlCipherHardening::cipher_only(),
                    )
                    .unwrap();
                    injector.execute_batch("CREATE TRIGGER reject_enrollment_raw BEFORE INSERT ON private_device_invite_staging BEGIN SELECT RAISE(ABORT,'injected enrollment raw rollback'); END;").unwrap();
                    assert!(
                        workers
                            .a
                            .verifier_command("test", |respond| {
                                VerifierCommand::PrepareEndorsedEnrollmentInvite {
                                    scope: a_scope.clone(),
                                    respond,
                                }
                            })
                            .await
                            .is_err()
                    );
                    assert!(
                        cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                            .unwrap()
                            .private_invite()
                            .unwrap()
                            == before,
                        "raw SQL failure must roll back pending MLS and ledger together"
                    );
                    if failed_add_receipt {
                        // This is an actual SDK handoff followed by a real SQL staging rollback.
                        // App has not set for_add on error; that alone is not proposal provenance.
                        assert!(
                            before.is_none(),
                            "the failed-handoff control requires no earlier invite fact"
                        );
                        let first = workers
                            .a
                            .verifier_command("test", |respond| {
                                VerifierCommand::ProposalHandoffSnapshotForTest {
                                    scope: a_scope.clone(),
                                    respond,
                                }
                            })
                            .await
                            .unwrap();
                        assert!(first.preparation_started && !first.for_add && !first.prepared);
                        assert!(
                            first.receipt.invalid_for_test(),
                            "the actual Add call must burn proposal-only eligibility before returning an error"
                        );
                        workers
                            .a
                            .prepare_enrollment_proposal("test", &a_scope)
                            .await
                            .unwrap();
                        let cached = workers
                            .a
                            .verifier_command("test", |respond| {
                                VerifierCommand::ProposalHandoffSnapshotForTest {
                                    scope: a_scope.clone(),
                                    respond,
                                }
                            })
                            .await
                            .unwrap();
                        assert!(std::sync::Arc::ptr_eq(&first.receipt, &cached.receipt));
                        assert!(
                            cached.preparation_started
                                && !cached.for_add
                                && !cached.prepared
                                && cached.receipt.invalid_for_test()
                        );
                        let retry_failed = matches!(
                            workers
                                .a
                                .verifier_command("test", |respond| {
                                    VerifierCommand::PrepareEndorsedEnrollmentInvite {
                                        scope: a_scope.clone(),
                                        respond,
                                    }
                                })
                                .await,
                            Err(ClientLinkingError::PrivateInvite(
                                cgka_engine::private_device_invite::PrivateInviteError::Storage(_)
                            ))
                        );
                        assert!(
                            retry_failed,
                            "the same real raw-staging fault must remain active for the Add retry"
                        );
                        let retried = workers
                            .a
                            .verifier_command("test", |respond| {
                                VerifierCommand::ProposalHandoffSnapshotForTest {
                                    scope: a_scope.clone(),
                                    respond,
                                }
                            })
                            .await
                            .unwrap();
                        assert!(std::sync::Arc::ptr_eq(&first.receipt, &retried.receipt));
                        assert!(
                            retried.preparation_started
                                && !retried.for_add
                                && !retried.prepared
                                && retried.receipt.invalid_for_test()
                        );
                        assert!(
                            cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                                .unwrap()
                                .private_invite()
                                .unwrap()
                                .is_none()
                        );
                        injector
                            .execute_batch("DROP TRIGGER reject_enrollment_raw;")
                            .unwrap();
                        drop(injector);
                        let probe = workers
                            .a
                            .verifier_command("test", |respond| {
                                VerifierCommand::CaptureProposalOnlyCancelForTest {
                                    scope: a_scope.clone(),
                                    respond,
                                }
                            })
                            .await
                            .unwrap();
                        let account = workers.a.resolve("test").unwrap();
                        {
                            let active = workers.a.workers.lock().await;
                            active
                                .get(&account.account_id_hex)
                                .unwrap()
                                .publication_control
                                .revoke(&a_scope);
                        }
                        workers
                            .a
                            .maintain_device_linking_at_for_test("test", std::time::Instant::now())
                            .await
                            .unwrap();
                        let locally_retired = probe
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .retired_proposal;
                        assert!(
                            locally_retired,
                            "actual cleanup must drop the failed handoff continuation before cancel"
                        );
                        let no_fact_after_cleanup =
                            cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                                .unwrap()
                                .private_invite()
                                .unwrap()
                                .is_none();
                        assert!(no_fact_after_cleanup);
                        let cancel_result = workers.a.cancel_device_linking("test", &a_scope).await;
                        let cancel_stale = matches!(
                            cancel_result,
                            Err(ClientLinkingError::Owner(
                                crate::device_linking::OwnerError::Verifier(
                                    crate::device_linking::LinkError::StaleFlow
                                )
                            ))
                        );
                        let observed = probe
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .clone();
                        let receipt_still_invalid = first.receipt.invalid_for_test();
                        let anchors_unchanged =
                            cgka_traits::StorageProvider::accepted_device_group_anchor_storage(
                                &a_storage,
                            )
                            .unwrap()
                            .accepted_anchor()
                            .unwrap()
                                == a_anchor
                                && cgka_traits::StorageProvider::private_roster_settlement_storage(
                                    &b_storage,
                                )
                                .unwrap()
                                .read_round()
                                .unwrap()
                                    == b_before
                                && cgka_traits::StorageProvider::device_linking_key_package_storage(
                                    &c_storage,
                                )
                                .unwrap()
                                .purpose_key_package()
                                .unwrap() == c_purpose;
                        let safe = cancel_stale
                            && receipt_still_invalid
                            && anchors_unchanged
                            && observed.fallback_entered
                            && !observed.context_rejected
                            && observed.scope_check_entered
                            && observed.scope_check_passed
                            && observed.durable_query_completed
                            && observed.durable_phase.is_none()
                            && observed.exact_retired == Some(false);
                        runtime_c.shutdown_and_close().await.unwrap();
                        crate::test_support::emit_line(format_args!(
                            "proposal-failed-handoff-close index=0"
                        ));
                        workers.runtime_a.shutdown_and_close().await.unwrap();
                        crate::test_support::emit_line(format_args!(
                            "proposal-failed-handoff-close index=1"
                        ));
                        workers.runtime_b.shutdown_and_close().await.unwrap();
                        crate::test_support::emit_line(format_args!(
                            "proposal-failed-handoff-close index=2"
                        ));
                        relay.shutdown();
                        crate::test_support::emit_line(format_args!(
                            "proposal-failed-handoff-control {}",
                            serde_json::json!({
                                "actual_handoff": first.preparation_started, "app_for_add": first.for_add, "app_prepared": first.prepared,
                                "cached_same_receipt": std::sync::Arc::ptr_eq(&first.receipt, &cached.receipt),
                                "retry_same_receipt": std::sync::Arc::ptr_eq(&first.receipt, &retried.receipt),
                                "retry_failed": retry_failed, "locally_retired": locally_retired,
                                "no_fact_after_cleanup": no_fact_after_cleanup, "receipt_still_invalid": receipt_still_invalid,
                                "cancel_stale": cancel_stale, "anchors_unchanged": anchors_unchanged,
                                "fallback_entered": observed.fallback_entered, "context_rejected": observed.context_rejected,
                                "scope_check_passed": observed.scope_check_passed, "durable_query_completed": observed.durable_query_completed,
                                "durable_phase": observed.durable_phase, "exact_retired": observed.exact_retired,
                            })
                        ));
                        assert!(
                            safe,
                            "a real failed Add handoff must never regain proposal-only cancellation acknowledgment"
                        );
                        return;
                    }
                    injector.execute_batch("DROP TRIGGER reject_enrollment_raw; CREATE TRIGGER reject_enrollment_wrap BEFORE UPDATE OF transport ON private_device_invite_staging WHEN NEW.phase = 1 BEGIN SELECT RAISE(ABORT,'injected enrollment wrapper rollback'); END;").unwrap();
                    assert!(
                        workers
                            .a
                            .verifier_command("test", |respond| {
                                VerifierCommand::PrepareEndorsedEnrollmentInvite {
                                    scope: a_scope.clone(),
                                    respond,
                                }
                            })
                            .await
                            .is_err()
                    );
                    let raw_retry =
                        cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                            .unwrap()
                            .private_invite()
                            .unwrap()
                            .unwrap();
                    assert!(
                        raw_retry.phase
                            == cgka_traits::private_device_invite::PrivateInvitePhase::RawStaged
                    );
                    assert!(raw_retry.transport.is_none());
                    injector
                        .execute_batch("DROP TRIGGER reject_enrollment_wrap;")
                        .unwrap();
                    let owned = workers.a.verifier_command("test", |respond|
                        VerifierCommand::PrepareEndorsedEnrollmentInvite { scope: a_scope.clone(), respond })
                        .await.expect("complete actual endorsements must transfer the same original SDK lease into trusted Add preparation");
                    assert_eq!(owned.account, a_scope.account);
                    assert_eq!(owned.local_device, a_scope.local_device);
                    let fact =
                        cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                            .unwrap()
                            .private_invite()
                            .unwrap()
                            .unwrap();
                    assert!(fact.scope == raw_retry.scope);
                    assert!(
                        fact.raw == raw_retry.raw,
                        "retry must retain original exact MLS ciphertexts and staging generation"
                    );
                    assert_eq!(fact.raw.binding.predecessor.epoch.0, 1);
                    assert_eq!(fact.raw.binding.successor.epoch.0, 2);
                    assert_eq!(fact.raw.binding.successor.leaves.len(), 3);
                    assert_eq!(fact.raw.binding.recipient, prepared.scope.local_device);
                    assert!(fact.raw.binding.approver_scope == a_scope);
                    assert_eq!(
                        fact.raw.binding.key_package_reference,
                        expected_package_reference
                    );
                    assert!(
                        cgka_traits::StorageProvider::accepted_device_group_anchor_storage(
                            &a_storage
                        )
                        .unwrap()
                        .accepted_anchor()
                        .unwrap()
                            == a_anchor
                    );
                    assert!(
                        cgka_traits::StorageProvider::private_roster_settlement_storage(&b_storage)
                            .unwrap()
                            .read_round()
                            .unwrap()
                            == b_before
                    );
                    assert!(
                        cgka_traits::StorageProvider::device_linking_key_package_storage(
                            &c_storage
                        )
                        .unwrap()
                        .purpose_key_package()
                        .unwrap()
                            == c_purpose
                    );
                    assert!(workers.a.app.load_state("test").unwrap().groups.is_empty());
                    assert!(workers.b.app.load_state("test").unwrap().groups.is_empty());
                    assert!(
                        workers
                            .a
                            .collect_owned_enrollment_endorsements("test", &a_scope)
                            .await
                            .is_err(),
                        "transferred proposal cannot reuse the original Add lease as a collection producer"
                    );
                    workers
                        .a
                        .cancel_device_linking("test", &a_scope)
                        .await
                        .unwrap();
                    assert!(
                        workers
                            .a
                            .publish_private_device_invite_commit("test", &a_scope)
                            .await
                            .is_err()
                    );
                    runtime_c.shutdown_and_close().await.unwrap();
                    workers.runtime_a.shutdown_and_close().await.unwrap();
                    workers.runtime_b.shutdown_and_close().await.unwrap();
                    relay.shutdown();
                    return;
                }
                let mut wrong = selected;
                wrong[0] ^= 1;
                assert!(
                    workers
                        .b
                        .cancel_received_enrollment_endorsement("test", &wrong)
                        .await
                        .is_err()
                );
                workers
                    .b
                    .publish_received_enrollment_endorsement("test", &selected)
                    .await
                    .unwrap();
                assert_eq!(
                    workers
                        .a
                        .collect_owned_enrollment_endorsements("test", &a_scope)
                        .await
                        .unwrap(),
                    2
                );
                workers
                    .b
                    .cancel_received_enrollment_endorsement("test", &selected)
                    .await
                    .unwrap();
                workers
                    .b
                    .cancel_received_enrollment_endorsement("test", &selected)
                    .await
                    .unwrap();
                assert!(
                    workers
                        .b
                        .publish_received_enrollment_endorsement("test", &selected)
                        .await
                        .is_err()
                );
            }

            if check == ThirdDeviceCheck::LocalProposalCollection {
                assert!(
                    workers
                        .b
                        .verifier_command("test", |respond| {
                            VerifierCommand::ReceivedEnrollmentProposalBindings { respond }
                        })
                        .await
                        .unwrap()
                        .is_empty(),
                    "cancelled original B action cannot remain selectable"
                );
                assert!(
                    cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                        .unwrap()
                        .private_invite()
                        .unwrap()
                        == before
                );
                assert!(
                    cgka_traits::StorageProvider::private_roster_settlement_storage(&b_storage)
                        .unwrap()
                        .read_round()
                        .unwrap()
                        == b_before
                );
                workers
                    .a
                    .cancel_device_linking("test", &a_scope)
                    .await
                    .unwrap();
                assert!(
                    workers
                        .a
                        .collect_owned_enrollment_endorsements("test", &a_scope)
                        .await
                        .is_err()
                );
                runtime_c.shutdown_and_close().await.unwrap();
                workers.runtime_a.shutdown_and_close().await.unwrap();
                workers.runtime_b.shutdown_and_close().await.unwrap();
                relay.shutdown();
                return;
            }
            // Wrong selectors cannot affect the exact original B action.
            let bindings = workers
                .b
                .verifier_command("test", |respond| {
                    VerifierCommand::ReceivedEnrollmentProposalBindings { respond }
                })
                .await
                .unwrap();
            let binding = bindings[0];
            let mut reopened_round = None;
            if check == ThirdDeviceCheck::LocalProposalDroppedReply {
                let commands = workers.b.worker_commands("test").await.unwrap();
                let (respond, receiver) = tokio::sync::oneshot::channel();
                drop(receiver);
                commands
                    .send(AccountWorkerCommand::DeviceLinkingVerifier(Box::new(
                        VerifierCommand::EndorseReceivedEnrollmentProposal { binding, respond },
                    )))
                    .await
                    .unwrap();
                // Serial command barrier: the abandoned action already ran and
                // cleanup must have burned this exact original receipt.
                workers
                    .b
                    .verifier_command("test", |respond| {
                        VerifierCommand::ReceivedEnrollmentProposalBindings { respond }
                    })
                    .await
                    .unwrap();
                assert!(
                    workers
                        .b
                        .verifier_command("test", |respond| {
                            VerifierCommand::EndorseReceivedEnrollmentProposal { binding, respond }
                        })
                        .await
                        .is_err(),
                    "an abandoned original action cannot be recreated from its receipt"
                );
            }
            if check == ThirdDeviceCheck::LocalProposalReopen {
                workers.runtime_b.shutdown_and_close().await.unwrap();
                let app = MarmotApp::with_relay(
                    workers.directories[1].path(),
                    relay.url().await.to_string(),
                );
                let reopened = MarmotAppRuntime::new(app);
                reopened.reconcile_accounts().await.unwrap();
                let b = reopened.accounts();
                assert!(
                    b.verifier_command("test", |respond| {
                        VerifierCommand::ReceivedEnrollmentProposalBindings { respond }
                    })
                    .await
                    .unwrap()
                    .is_empty()
                );
                assert!(
                    b.verifier_command("test", |respond| {
                        VerifierCommand::EndorseReceivedEnrollmentProposal { binding, respond }
                    })
                    .await
                    .is_err(),
                    "encrypted reopen cannot restore the old observation or owned action"
                );
                assert_eq!(
                    b.candidate_device_group_snapshot("test", &group)
                        .await
                        .unwrap()
                        .unwrap()
                        .epoch
                        .0,
                    1
                );
                assert!(b.app.load_state("test").unwrap().groups.is_empty());
                let storage = b.app.account_storage("test").unwrap();
                reopened_round =
                    cgka_traits::StorageProvider::private_roster_settlement_storage(&storage)
                        .unwrap()
                        .read_round()
                        .unwrap();
                assert!(reopened_round == b_before);
                reopened.shutdown_and_close().await.unwrap();
            }
            if check == ThirdDeviceCheck::LocalProposalEndorsement {
                let mut wrong = binding;
                wrong[0] ^= 1;
                assert!(
                    workers
                        .b
                        .verifier_command("test", |respond| {
                            VerifierCommand::CancelReceivedEnrollmentEndorsement {
                                binding: wrong,
                                respond,
                            }
                        })
                        .await
                        .is_err()
                );
                workers
                    .b
                    .verifier_command("test", |respond| {
                        VerifierCommand::EndorseReceivedEnrollmentProposal { binding, respond }
                    })
                    .await
                    .unwrap();
                workers
                    .b
                    .verifier_command("test", |respond| {
                        VerifierCommand::CancelReceivedEnrollmentEndorsement { binding, respond }
                    })
                    .await
                    .unwrap();
                assert!(
                    workers
                        .b
                        .verifier_command("test", |respond| {
                            VerifierCommand::EndorseReceivedEnrollmentProposal { binding, respond }
                        })
                        .await
                        .is_err(),
                    "cancelled original receipt cannot create a later action with the same selector"
                );
            }

            assert!(
                cgka_traits::StorageProvider::private_device_invite_storage(&a_storage)
                    .unwrap()
                    .private_invite()
                    .unwrap()
                    == before
            );
            let b_after = if check == ThirdDeviceCheck::LocalProposalReopen {
                reopened_round
            } else {
                cgka_traits::StorageProvider::private_roster_settlement_storage(&b_storage)
                    .unwrap()
                    .read_round()
                    .unwrap()
            };
            assert!(b_after == b_before);
            assert_eq!(
                workers
                    .a
                    .candidate_device_group_snapshot("test", &group)
                    .await
                    .unwrap()
                    .unwrap()
                    .epoch
                    .0,
                1
            );
            assert!(
                cgka_traits::StorageProvider::accepted_device_group_anchor_storage(&a_storage)
                    .unwrap()
                    .accepted_anchor()
                    .unwrap()
                    == a_anchor
            );
            assert!(
                cgka_traits::StorageProvider::device_linking_key_package_storage(&c_storage)
                    .unwrap()
                    .purpose_key_package()
                    .unwrap()
                    == c_purpose
            );
            assert!(workers.a.app.load_state("test").unwrap().groups.is_empty());
            if check != ThirdDeviceCheck::LocalProposalReopen {
                assert!(workers.b.app.load_state("test").unwrap().groups.is_empty());
            }
            workers
                .a
                .cancel_device_linking("test", &a_scope)
                .await
                .unwrap();
            assert!(
                workers
                    .a
                    .publish_enrollment_proposal("test", &a_scope)
                    .await
                    .is_err()
            );
            if matches!(
                check,
                ThirdDeviceCheck::LocalProposalCollection
                    | ThirdDeviceCheck::LocalProposalTrustedAdd
                    | ThirdDeviceCheck::LocalProposalTrustedAddRetry
                    | ThirdDeviceCheck::LocalProposalRecipientAdmission
                    | ThirdDeviceCheck::LocalProposalRecipientJoin
                    | ThirdDeviceCheck::LocalProposalExistingTransition
                    | ThirdDeviceCheck::LocalProposalAbcSettlement
            ) {
                assert!(
                    workers
                        .a
                        .collect_owned_enrollment_endorsements("test", &a_scope)
                        .await
                        .is_err(),
                    "original A cancellation ends collection even with retained signed metadata"
                );
            }
            runtime_c.shutdown_and_close().await.unwrap();
            workers.runtime_a.shutdown_and_close().await.unwrap();
            if check != ThirdDeviceCheck::LocalProposalReopen {
                workers.runtime_b.shutdown_and_close().await.unwrap();
            }
            relay.shutdown();
            return;
        }
        unreachable!("every explicit third-device test mode has its own admission boundary");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_confirmed_sender_delivers_exact_welcome_to_recipient() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            a,
            prepared,
            b,
            b_scope,
            relay_b,
            ..
        } = verified_workers().await;
        b.prepare_private_device_invite("test", &b_scope)
            .await
            .unwrap();
        let storage = b.app.account_storage("test").unwrap();
        let cap = cgka_traits::StorageProvider::private_device_invite_storage(&storage).unwrap();
        let fact = cap.private_invite().unwrap().unwrap();
        let event = transport_nostr_peeler::NostrTransportEvent::from_transport_message(
            &fact.transport.as_ref().unwrap().commit,
        )
        .unwrap();
        a.arm_singleton_device_welcome("test", &prepared.scope)
            .await
            .unwrap();
        assert!(
            b.verifier_command("test", |respond| VerifierCommand::PublishPrivateWelcomes {
                scope: b_scope.clone(),
                respond,
            })
            .await
            .is_err(),
            "unconfirmed preparation cannot publish a private Welcome"
        );
        b.publish_private_device_invite_commit("test", &b_scope)
            .await
            .unwrap();
        assert!(relay_b.accepted_subscriptions().iter().any(|subscription| matches!(subscription,
            transport_nostr_adapter::NostrSubscription::Group { account_id, group_id, .. }
                if account_id.as_slice() == b_scope.account && group_id == &fact.raw.binding.group_id)),
            "private publication must first subscribe the exact authenticated hidden group");
        // A local relay ACK is not an inbound cryptographic echo.
        assert_private_commit_unknown(&b);
        assert!(
            b.verifier_command("test", |respond| VerifierCommand::PublishPrivateWelcomes {
                scope: b_scope.clone(),
                respond,
            })
            .await
            .is_err(),
            "uncertain commit publication cannot authorize Welcome delivery"
        );
        assert!(b.app.load_state("test").unwrap().groups.is_empty());
        let routed = b
            .app
            .relay_plane
            .handle_relay_event_for_test(transport_nostr_adapter::NostrRelayEvent {
                endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
                subscription_id: None,
                event,
            })
            .await
            .unwrap();
        assert_eq!(
            routed, 1,
            "exact relay echo must enter the normal account delivery path"
        );
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if cap.private_invite().unwrap().is_some_and(|row| {
                    row.phase == cgka_traits::private_device_invite::PrivateInvitePhase::Confirmed
                }) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("authenticated own echo must confirm through account ingest");
        let confirmed = cap.confirmed_private_invite().unwrap().unwrap();
        assert!(confirmed.binding == fact.raw.binding);
        assert!(
            cgka_traits::GroupStorage::get_group(&storage, &fact.raw.binding.group_id)
                .unwrap()
                .epoch
                .0
                == 1
        );
        assert!(b.app.load_state("test").unwrap().groups.is_empty());
        let published = relay_b.published_event_ids();
        assert!(
            fact.transport
                .as_ref()
                .unwrap()
                .welcomes
                .iter()
                .all(|message| !published.contains(
                    &transport_nostr_peeler::NostrTransportEvent::from_transport_message(message)
                        .unwrap()
                        .id
                ))
        );
        b.verifier_command("test", |respond| VerifierCommand::PublishPrivateWelcomes {
            scope: b_scope.clone(),
            respond,
        })
        .await
        .expect("confirmed original live sender must publish its exact Welcome batch");
        let published = relay_b.published_events_snapshot();
        for message in &fact.transport.as_ref().unwrap().welcomes {
            let expected =
                transport_nostr_peeler::NostrTransportEvent::from_transport_message(message)
                    .unwrap();
            let actual = published
                .iter()
                .find(|event| event.id == expected.id)
                .expect("sender must publish every frozen private Welcome");
            assert!(serde_json::to_vec(actual).unwrap() == serde_json::to_vec(&expected).unwrap());
            a.app
                .relay_plane
                .handle_relay_event_for_test(transport_nostr_adapter::NostrRelayEvent {
                    endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
                    subscription_id: None,
                    event: actual.clone(),
                })
                .await
                .unwrap();
        }
        let recipient = a.app.account_storage("test").unwrap();
        let purpose =
            cgka_traits::StorageProvider::device_linking_key_package_storage(&recipient).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !purpose
                .purpose_key_package()
                .unwrap()
                .is_some_and(|row| row.scope == prepared.scope && row.consumed)
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("sender's actual frozen publication must join through the recipient worker");
        assert!(a.app.load_state("test").unwrap().groups.is_empty());
        assert!(b.app.load_state("test").unwrap().groups.is_empty());
        runtime_a.shutdown_and_close().await.unwrap();
        runtime_b.shutdown_and_close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_confirmed_echo_retains_original_delivery_lease_until_cancel() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            relay_b,
            ..
        } = verified_workers().await;
        b.prepare_private_device_invite("test", &b_scope)
            .await
            .unwrap();
        let storage = b.app.account_storage("test").unwrap();
        let cap = cgka_traits::StorageProvider::private_device_invite_storage(&storage).unwrap();
        let fact = cap.private_invite().unwrap().unwrap();
        let event = transport_nostr_peeler::NostrTransportEvent::from_transport_message(
            &fact.transport.as_ref().unwrap().commit,
        )
        .unwrap();
        b.publish_private_device_invite_commit("test", &b_scope)
            .await
            .unwrap();
        assert!(relay_b.accepted_subscriptions().iter().any(|subscription| matches!(subscription,
            transport_nostr_adapter::NostrSubscription::Group { account_id, group_id, .. }
                if account_id.as_slice() == b_scope.account && group_id == &fact.raw.binding.group_id)),
            "private publication must first subscribe the exact authenticated hidden group");
        // A local relay ACK is not an inbound cryptographic echo.
        assert_private_commit_unknown(&b);
        assert!(b.app.load_state("test").unwrap().groups.is_empty());
        let routed = b
            .app
            .relay_plane
            .handle_relay_event_for_test(transport_nostr_adapter::NostrRelayEvent {
                endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
                subscription_id: None,
                event,
            })
            .await
            .unwrap();
        assert_eq!(
            routed, 1,
            "exact relay echo must enter the normal account delivery path"
        );
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if cap.private_invite().unwrap().is_some_and(|row| {
                    row.phase == cgka_traits::private_device_invite::PrivateInvitePhase::Confirmed
                }) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("authenticated own echo must confirm through account ingest");
        let confirmed = cap.confirmed_private_invite().unwrap().unwrap();
        assert!(confirmed.binding == fact.raw.binding);
        assert!(
            cgka_traits::GroupStorage::get_group(&storage, &fact.raw.binding.group_id)
                .unwrap()
                .epoch
                .0
                == 1
        );
        assert!(b.app.load_state("test").unwrap().groups.is_empty());
        let published = relay_b.published_event_ids();
        assert!(
            fact.transport
                .as_ref()
                .unwrap()
                .welcomes
                .iter()
                .all(|message| !published.contains(
                    &transport_nostr_peeler::NostrTransportEvent::from_transport_message(message)
                        .unwrap()
                        .id
                ))
        );
        assert!(
            b.verifier_command("test", |respond| {
                VerifierCommand::CheckOwnedPermissionForTest { respond }
            })
            .await
            .is_ok(),
            "confirmed exact successor must retain the original live lease for gated Welcome delivery"
        );
        b.cancel_device_linking("test", &b_scope).await.unwrap();
        assert!(
            b.verifier_command("test", |respond| {
                VerifierCommand::CheckOwnedPermissionForTest { respond }
            })
            .await
            .is_err(),
            "cancellation must revoke the same retained lease"
        );
        assert!(
            cap.confirmed_private_invite().unwrap().is_some(),
            "revoking delivery consent must preserve genuine confirmed membership"
        );
        runtime_a.shutdown_and_close().await.unwrap();
        runtime_b.shutdown_and_close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_private_commit_uses_exact_frozen_nostr_without_welcome() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            relay_b,
            ..
        } = verified_workers().await;
        b.prepare_private_device_invite("test", &b_scope)
            .await
            .unwrap();
        let storage = b.app.account_storage("test").unwrap();
        let cap = cgka_traits::StorageProvider::private_device_invite_storage(&storage).unwrap();
        let fact = cap.private_invite().unwrap().unwrap();
        let transport = fact.transport.as_ref().unwrap();
        let commit =
            transport_nostr_peeler::NostrTransportEvent::from_transport_message(&transport.commit)
                .unwrap();
        let welcome_ids: Vec<String> = transport
            .welcomes
            .iter()
            .map(|message| {
                transport_nostr_peeler::NostrTransportEvent::from_transport_message(message)
                    .unwrap()
                    .id
            })
            .collect();
        let before = relay_b.published_event_ids();
        assert!(
            b.publish_private_device_invite_commit("test", &b_scope)
                .await
                .is_ok(),
            "genuine worker-owned verification must publish its frozen private commit"
        );
        let after = relay_b.published_event_ids();
        let added: Vec<_> = after.iter().filter(|id| !before.contains(id)).collect();
        assert!(added.len() == 1 && added[0] == &commit.id);
        assert!(after.iter().all(|id| !welcome_ids.contains(id)));
        let published = relay_b.published_events_snapshot();
        assert!(
            published
                .iter()
                .filter(|event| event.id == commit.id)
                .all(|event| serde_json::to_vec(event).unwrap()
                    == serde_json::to_vec(&commit).unwrap())
        );
        assert_private_commit_unknown(&b);
        assert!(
            b.publish_private_device_invite_commit("test", &b_scope)
                .await
                .is_err()
        );
        assert!(relay_b.published_event_ids() == after);
        runtime_a.shutdown().await;
        runtime_b.shutdown_and_close().await.unwrap();
        let reopened_app = MarmotApp::with_relay(_directories[1].path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let client = reopened_app.client("test").await.unwrap();
        let retained = reopened_app.account_storage("test").unwrap();
        let retained_cap =
            cgka_traits::StorageProvider::private_device_invite_storage(&retained).unwrap();
        let retained_fact = retained_cap.private_invite().unwrap().unwrap();
        assert!(retained_fact.scope == fact.scope && retained_fact.transport == fact.transport);
        assert!(
            retained_fact.phase
                == cgka_traits::private_device_invite::PrivateInvitePhase::PublicationUnknown
        );
        assert!(matches!(
            client
                .runtime
                .session()
                .epoch_state(&fact.raw.binding.group_id),
            Some(cgka_traits::EpochState::PendingPublish(_))
        ));
        assert!(retained_cap.confirmed_private_invite().unwrap().is_none());
        drop(client);
        reopened_app.close_storage().unwrap();
    }

    fn assert_private_commit_unknown(b: &AccountManager) {
        let storage = b.app.account_storage("test").unwrap();
        let cap = cgka_traits::StorageProvider::private_device_invite_storage(&storage).unwrap();
        let fact = cap.private_invite().unwrap().unwrap();
        assert!(
            fact.phase
                == cgka_traits::private_device_invite::PrivateInvitePhase::PublicationUnknown
        );
        assert!(cap.confirmed_private_invite().unwrap().is_none());
        assert!(
            cgka_traits::MessageStorage::list_messages(
                &storage,
                &fact.raw.binding.group_id,
                cgka_traits::EpochId(0)
            )
            .unwrap()
            .is_empty()
        );
        assert!(
            cgka_traits::GroupStorage::get_group(&storage, &fact.raw.binding.group_id)
                .unwrap()
                .epoch
                .0
                == 0
        );
    }
    async fn blocked_private_commit(
        b: &AccountManager,
        scope: &PurposeAttemptScope,
        relay: &ScriptedPushRelayClient,
    ) -> tokio::task::JoinHandle<Result<(), ClientLinkingError>> {
        b.prepare_private_device_invite("test", scope)
            .await
            .unwrap();
        relay.block_next_publish();
        let manager = b.clone();
        let scope = scope.clone();
        let job = tokio::spawn(async move {
            manager
                .publish_private_device_invite_commit("test", &scope)
                .await
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            relay.wait_for_blocked_publish(),
        )
        .await
        .unwrap();
        job
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_private_commit_exact_cancel_bypasses_saturation() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            relay_b,
            ..
        } = verified_workers().await;
        let before = relay_b.published_event_ids();
        let job = blocked_private_commit(&b, &b_scope, &relay_b).await;
        let commands = b.worker_commands("test").await.unwrap();
        // The bounded actor buffer plus channel fill while the actual relay is stalled.
        let mut drains = Vec::new();
        for _ in 0..16 {
            let (respond, receiver) = oneshot::channel();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                commands.send(AccountWorkerCommand::Drain { respond }),
            )
            .await
            .unwrap()
            .unwrap();
            drains.push(receiver);
        }
        assert!(commands.capacity() == 0);
        let mut stale = b_scope.clone();
        stale.local_device[0] ^= 1;
        let stale_manager = b.clone();
        let stale_cancel =
            tokio::spawn(async move { stale_manager.cancel_device_linking("test", &stale).await });
        tokio::task::yield_now().await;
        assert!(!job.is_finished());
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            b.cancel_device_linking("test", &b_scope),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(job.await.unwrap().is_err());
        assert!(stale_cancel.await.unwrap().is_err());
        for drain in drains {
            drain.await.unwrap();
        }
        assert!(relay_b.published_event_ids() == before);
        assert_private_commit_unknown(&b);
        relay_b.release_publish();
        tokio::task::yield_now().await;
        assert!(relay_b.published_event_ids() == before);
        runtime_a.shutdown().await;
        runtime_b.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_private_commit_explicit_shutdown_interrupts_network() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            relay_b,
            ..
        } = verified_workers().await;
        let before = relay_b.published_event_ids();
        let job = blocked_private_commit(&b, &b_scope, &relay_b).await;
        let account = b.resolve("test").unwrap();
        let worker = b
            .workers
            .lock()
            .await
            .remove(&account.account_id_hex)
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), worker.shutdown())
            .await
            .unwrap();
        assert!(job.await.unwrap().is_err());
        assert_private_commit_unknown(&b);
        relay_b.release_publish();
        tokio::task::yield_now().await;
        assert!(relay_b.published_event_ids() == before);
        runtime_a.shutdown().await;
        runtime_b.shutdown().await;
    }
    // Pauses Tokio's clock after actual publication entry; this requires one thread.
    #[tokio::test(flavor = "current_thread")]
    async fn device_linking_worker_private_commit_deadline_actively_wakes_stalled_network() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            relay_b,
            ..
        } = verified_workers().await;
        let before = relay_b.published_event_ids();
        b.prepare_private_device_invite("test", &b_scope)
            .await
            .unwrap();
        relay_b.block_next_publish();
        let commands = b.worker_commands("test").await.unwrap();
        let (respond, receiver) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::DeviceLinkingVerifier(Box::new(
                VerifierCommand::PublishPrivateCommit {
                    scope: b_scope,
                    respond,
                },
            )))
            .await
            .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            relay_b.wait_for_blocked_publish(),
        )
        .await
        .unwrap();
        // A direct receiver keeps the independent RPC timeout out of this proof.
        // Advance only Tokio's monotonic timer after real preparation/network
        // entry. No cryptographic lifetime or verifier clock is spoofed.
        tokio::time::pause();
        tokio::time::advance(std::time::Duration::from_secs(601)).await;
        assert!(matches!(
            receiver.await.unwrap(),
            Err(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::Expired
            ))
        ));
        tokio::time::resume();
        assert_private_commit_unknown(&b);
        relay_b.release_publish();
        tokio::task::yield_now().await;
        assert!(relay_b.published_event_ids() == before);
        runtime_a.shutdown().await;
        runtime_b.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_private_commit_abandoned_reply_preserves_unknown() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            relay_b,
            ..
        } = verified_workers().await;
        b.prepare_private_device_invite("test", &b_scope)
            .await
            .unwrap();
        let before = relay_b.published_event_ids();
        relay_b.block_next_publish();
        let commands = b.worker_commands("test").await.unwrap();
        let (respond, receiver) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::DeviceLinkingVerifier(Box::new(
                VerifierCommand::PublishPrivateCommit {
                    scope: b_scope,
                    respond,
                },
            )))
            .await
            .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            relay_b.wait_for_blocked_publish(),
        )
        .await
        .unwrap();
        drop(receiver);
        let (respond, drain) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::Drain { respond })
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), drain)
            .await
            .unwrap()
            .unwrap();
        assert_private_commit_unknown(&b);
        relay_b.release_publish();
        tokio::task::yield_now().await;
        assert!(relay_b.published_event_ids() == before);
        runtime_a.shutdown().await;
        runtime_b.shutdown().await;
    }

    fn private_commit_injector(b: &AccountManager) -> rusqlite::Connection {
        let path = b.app.account_storage_path("test");
        let keys = b.app.account_home().load_signing_keys("test").unwrap();
        let key = b
            .app
            .sqlcipher_key(
                "test",
                &keys,
                &path,
                crate::sqlcipher::SqlcipherDatabaseKind::Session,
            )
            .unwrap();
        let injector = rusqlite::Connection::open(path).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &injector,
            &key,
            storage_sqlite::SqlCipherHardening::cipher_only(),
        )
        .unwrap();
        injector
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_private_commit_preintent_fault_retains_exact_live_retry() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            relay_b,
            ..
        } = verified_workers().await;
        let prepared_scope = b
            .prepare_private_device_invite("test", &b_scope)
            .await
            .unwrap();
        let storage = b.app.account_storage("test").unwrap();
        let cap = cgka_traits::StorageProvider::private_device_invite_storage(&storage).unwrap();
        let before = cap.private_invite().unwrap().unwrap();
        let attempted = relay_b.attempted_event_ids();
        let injector = private_commit_injector(&b);
        injector.execute_batch("CREATE TRIGGER private_worker_dispatch_fault BEFORE UPDATE OF phase ON private_device_invite_staging WHEN NEW.phase=2 BEGIN SELECT RAISE(ABORT,'isolated dispatch fault'); END;").unwrap();
        assert!(matches!(
            b.publish_private_device_invite_commit("test", &b_scope)
                .await,
            Err(ClientLinkingError::PrivateInvite(
                cgka_engine::private_device_invite::PrivateInviteError::Storage(_)
            ))
        ));
        assert!(cap.private_invite().unwrap().unwrap() == before);
        assert!(relay_b.attempted_event_ids() == attempted);
        assert!(
            b.prepare_private_device_invite("test", &b_scope)
                .await
                .unwrap()
                == prepared_scope
        );
        injector
            .execute_batch("DROP TRIGGER private_worker_dispatch_fault;")
            .unwrap();
        b.publish_private_device_invite_commit("test", &b_scope)
            .await
            .unwrap();
        assert!(relay_b.attempted_event_ids().len() == attempted.len() + 1);
        assert_private_commit_unknown(&b);
        runtime_a.shutdown().await;
        runtime_b.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_private_commit_unknown_fault_keeps_revoked_cleanup_retry() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            relay_b,
            ..
        } = verified_workers().await;
        let job = blocked_private_commit(&b, &b_scope, &relay_b).await;
        let attempted = relay_b.attempted_event_ids();
        let injector = private_commit_injector(&b);
        injector.execute_batch("CREATE TRIGGER private_worker_unknown_fault BEFORE UPDATE OF phase ON private_device_invite_staging WHEN NEW.phase=3 BEGIN SELECT RAISE(ABORT,'isolated unknown fault'); END;").unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                b.cancel_device_linking("test", &b_scope)
            )
            .await
            .unwrap()
            .is_err()
        );
        assert!(job.await.unwrap().is_err());
        assert!(
            b.prepare_private_device_invite("test", &b_scope)
                .await
                .is_err()
        );
        let storage = b.app.account_storage("test").unwrap();
        let cap = cgka_traits::StorageProvider::private_device_invite_storage(&storage).unwrap();
        assert!(
            cap.private_invite().unwrap().unwrap().phase
                == cgka_traits::private_device_invite::PrivateInvitePhase::Dispatching
        );
        assert!(relay_b.attempted_event_ids() == attempted);
        injector
            .execute_batch("DROP TRIGGER private_worker_unknown_fault;")
            .unwrap();
        b.maintain_device_linking_at_for_test("test", std::time::Instant::now())
            .await
            .unwrap();
        assert_private_commit_unknown(&b);
        relay_b.release_publish();
        tokio::task::yield_now().await;
        assert!(relay_b.attempted_event_ids() == attempted);
        runtime_a.shutdown().await;
        runtime_b.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_private_commit_queued_cancel_denies_before_first_poll() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            relay_b,
            ..
        } = verified_workers().await;
        b.prepare_private_device_invite("test", &b_scope)
            .await
            .unwrap();
        let attempted = relay_b.attempted_event_ids();
        let commands = b.worker_commands("test").await.unwrap();
        let (respond, receiver) = oneshot::channel();
        // Both bounded-channel sends and the uncontended slot revoke are ready
        // on this single-thread runtime, before yielding to the account actor.
        commands
            .send(AccountWorkerCommand::DeviceLinkingVerifier(Box::new(
                VerifierCommand::PublishPrivateCommit {
                    scope: b_scope.clone(),
                    respond,
                },
            )))
            .await
            .unwrap();
        b.cancel_device_linking("test", &b_scope).await.unwrap();
        assert!(receiver.await.unwrap().is_err());
        assert!(relay_b.attempted_event_ids() == attempted);
        let storage = b.app.account_storage("test").unwrap();
        let cap = cgka_traits::StorageProvider::private_device_invite_storage(&storage).unwrap();
        assert!(
            cap.private_invite().unwrap().unwrap().phase
                == cgka_traits::private_device_invite::PrivateInvitePhase::Retired
        );
        assert!(cap.confirmed_private_invite().unwrap().is_none());
        runtime_a.shutdown().await;
        runtime_b.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_worker_private_commit_postintent_backend_failure_revokes_owned_permission()
     {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            b,
            b_scope,
            relay_b,
            ..
        } = verified_workers().await;
        let job = blocked_private_commit(&b, &b_scope, &relay_b).await;
        let storage = b.app.account_storage("test").unwrap();
        storage.close().unwrap();
        relay_b.release_publish();
        assert!(job.await.unwrap().is_err());
        // No SQL operation is needed for an already-owned preparation retry.
        // Even when durable phase cannot be read, uncertain publication must
        // revoke the still-held SDK lease rather than return it as live.
        assert!(matches!(
            b.verifier_command("test", |respond| {
                VerifierCommand::CheckOwnedPermissionForTest { respond }
            })
            .await,
            Err(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::Cancelled
            ))
        ));
        runtime_a.shutdown().await;
        runtime_b.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_settlement_cancel_sql_fault_revokes_original_delivery_permission() {
        use cgka_traits::private_roster_settlement::PrivateSettlementPhase;
        let (workers, fact) = confirmed_sender_fixture().await;
        let storage = workers.b.app.account_storage("test").unwrap();
        let settlement =
            cgka_traits::StorageProvider::private_roster_settlement_storage(&storage).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if settlement.read_round().unwrap().is_some_and(|round| {
                    round.anchor.group_id == fact.raw.binding.group_id
                        && round.phase == PrivateSettlementPhase::Pending
                        && round.prepared_ciphertext.is_some()
                        && round.outbound.is_some()
                }) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("actual confirmed successor must autonomously prepare its pending confirmation");
        assert!(
            workers
                .b
                .verifier_command("test", |respond| {
                    VerifierCommand::CheckOwnedPermissionForTest { respond }
                })
                .await
                .is_ok(),
            "original SDK delivery lease must be live before requested cancellation"
        );
        assert_no_private_welcomes(&workers.relay_b, &fact);
        let injector = private_commit_injector(&workers.b);
        injector.execute_batch("CREATE TRIGGER private_settlement_cancel_fault BEFORE UPDATE OF state ON private_roster_settlement WHEN json_extract(CAST(NEW.state AS TEXT),'$.phase')='Denied' BEGIN SELECT RAISE(ABORT,'isolated settlement cancellation fault'); END;").unwrap();
        let cancelled = workers
            .b
            .cancel_device_linking("test", &workers.b_scope)
            .await;
        assert!(
            matches!(
                cancelled,
                Err(ClientLinkingError::Engine(
                    cgka_traits::EngineError::Storage(_)
                ))
            ),
            "real denial SQL failure must remain typed"
        );
        let permission = workers
            .b
            .verifier_command("test", |respond| {
                VerifierCommand::CheckOwnedPermissionForTest { respond }
            })
            .await;
        let delivery = workers
            .b
            .verifier_command("test", |respond| VerifierCommand::PublishPrivateWelcomes {
                scope: workers.b_scope.clone(),
                respond,
            })
            .await;
        assert!(
            permission.is_err(),
            "requested cancellation must revoke the original opaque SDK lease even while denial SQL fails; delivery_denied={}",
            delivery.is_err()
        );
        assert!(
            delivery.is_err(),
            "failed denial persistence must not authorize actual private Welcome publication"
        );
        assert_no_private_welcomes(&workers.relay_b, &fact);
        assert!(
            settlement.read_round().unwrap().unwrap().phase == PrivateSettlementPhase::Pending,
            "SQL fault preserves the original pending fact without granting permission"
        );
        injector
            .execute_batch("DROP TRIGGER private_settlement_cancel_fault")
            .unwrap();
        workers.runtime_a.shutdown().await;
        workers.runtime_b.shutdown_and_close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_settlement_reservation_cleanup_fault_does_not_allocate_inaccessible_scope()
     {
        use cgka_traits::private_roster_settlement::PrivateSettlementPhase;
        let (workers, fact) = confirmed_sender_fixture().await;
        workers
            .a
            .arm_singleton_device_welcome("test", &workers.prepared.scope)
            .await
            .unwrap();
        workers
            .b
            .verifier_command("test", |respond| VerifierCommand::PublishPrivateWelcomes {
                scope: workers.b_scope.clone(),
                respond,
            })
            .await
            .unwrap();
        for message in &fact.transport.as_ref().unwrap().welcomes {
            let event =
                transport_nostr_peeler::NostrTransportEvent::from_transport_message(message)
                    .unwrap();
            assert_eq!(
                workers
                    .a
                    .app
                    .relay_plane
                    .handle_relay_event_for_test(transport_nostr_adapter::NostrRelayEvent {
                        endpoint: cgka_traits::TransportEndpoint("wss://relay.example".into()),
                        subscription_id: None,
                        event,
                    })
                    .await
                    .unwrap(),
                1
            );
        }
        let storage = workers.a.app.account_storage("test").unwrap();
        let settlement =
            cgka_traits::StorageProvider::private_roster_settlement_storage(&storage).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if settlement.read_round().unwrap().is_some_and(|round| round.anchor.group_id == fact.raw.binding.group_id && round.phase == PrivateSettlementPhase::Pending) { break; }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }).await.expect("genuine accepted recipient must select a pending round before any coordinator challenge");
        assert!(
            cgka_traits::StorageProvider::accepted_device_group_anchor_storage(&storage)
                .unwrap()
                .accepted_anchor()
                .unwrap()
                .is_some()
        );
        assert!(
            cgka_traits::StorageProvider::device_linking_key_package_storage(&storage)
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .unwrap()
                .consumed
        );
        let injector = private_commit_injector(&workers.a);
        injector.execute_batch("CREATE TRIGGER private_settlement_reserve_fault BEFORE UPDATE OF state ON private_roster_settlement WHEN json_extract(CAST(NEW.state AS TEXT),'$.phase')='Denied' BEGIN SELECT RAISE(ABORT,'isolated old settlement cleanup fault'); END;").unwrap();
        assert!(
            workers
                .a
                .reserve_device_linking_for_approver("test")
                .await
                .is_err(),
            "new reservation must report the actual previous-round denial fault"
        );
        injector
            .execute_batch("DROP TRIGGER private_settlement_reserve_fault")
            .unwrap();
        let retry = workers.a.reserve_device_linking_for_approver("test").await;
        assert!(
            retry.is_ok(),
            "failed old settlement cleanup must not strand an unreported new SDK reservation"
        );
        let next = retry.unwrap();
        assert_eq!(
            next.generation,
            workers.prepared.scope.generation + 1,
            "only the successful reservation may advance the local attempt generation"
        );
        let purposes =
            cgka_traits::StorageProvider::device_linking_key_package_storage(&storage).unwrap();
        let anchors =
            cgka_traits::StorageProvider::accepted_device_group_anchor_storage(&storage).unwrap();
        let original_purpose = purposes.purpose_key_package().unwrap().unwrap();
        let original_anchor = anchors.accepted_anchor().unwrap().unwrap();
        assert!(original_purpose.consumed);
        assert!(original_purpose.scope == workers.prepared.scope);
        let mut forged = next.clone();
        forged.generation = forged.generation.checked_add(1).unwrap();
        for invalid in [&workers.prepared.scope, &forged] {
            assert!(
                matches!(
                    workers.a.cancel_device_linking("test", invalid).await,
                    Err(ClientLinkingError::Owner(
                        crate::device_linking::OwnerError::Verifier(
                            crate::device_linking::LinkError::StaleFlow
                        )
                    ))
                ),
                "stale and unreserved generations must not cancel the current reservation"
            );
            assert!(purposes.purpose_key_package().unwrap().as_ref() == Some(&original_purpose));
            assert!(anchors.accepted_anchor().unwrap().as_ref() == Some(&original_anchor));
        }
        workers
            .a
            .cancel_device_linking("test", &next)
            .await
            .unwrap();
        assert!(purposes.purpose_key_package().unwrap().as_ref() == Some(&original_purpose));
        assert!(anchors.accepted_anchor().unwrap().as_ref() == Some(&original_anchor));
        assert!(
            settlement
                .read_round()
                .unwrap()
                .is_some_and(|round| round.phase == PrivateSettlementPhase::Denied)
        );
        workers.runtime_a.shutdown_and_close().await.unwrap();
        workers.runtime_b.shutdown_and_close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_settlement_original_gate_revocation_denies_actual_cached_publication() {
        use cgka_traits::private_roster_settlement::PrivateSettlementPhase;
        let (workers, fact) = confirmed_sender_fixture().await;
        let storage = workers.b.app.account_storage("test").unwrap();
        let settlement =
            cgka_traits::StorageProvider::private_roster_settlement_storage(&storage).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if settlement.read_round().unwrap().is_some_and(|round| {
                    round.anchor.group_id == fact.raw.binding.group_id
                        && round.phase == PrivateSettlementPhase::Pending
                        && round.outbound.is_some()
                }) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("real SDK successor must have prepared its exact encrypted confirmation");
        let commands = workers.b.worker_commands("test").await.unwrap();
        let (respond, receiver) = tokio::sync::oneshot::channel();
        drop(receiver);
        commands
            .send(AccountWorkerCommand::DeviceLinkingVerifier(Box::new(
                VerifierCommand::PublishPrivateCommit {
                    scope: workers.b_scope.clone(),
                    respond,
                },
            )))
            .await
            .unwrap();
        assert!(
            workers
                .b
                .verifier_command("test", |respond| {
                    VerifierCommand::CheckOwnedPermissionForTest { respond }
                })
                .await
                .is_err(),
            "abandoned production dispatch must revoke the original owned invite lease"
        );
        assert!(
            cgka_traits::StorageProvider::private_device_invite_storage(&storage)
                .unwrap()
                .confirmed_private_invite()
                .unwrap()
                .is_some_and(|confirmed| !confirmed.denied),
            "negative SDK cleanup preserves actual confirmed membership"
        );
        let attempted = workers.relay_b.attempted_event_ids().len();
        let result = workers
            .b
            .verifier_command("test", |respond| {
                VerifierCommand::PublishPrivateSettlementForTest {
                    scope: workers.b_scope.clone(),
                    respond,
                }
            })
            .await;
        assert!(
            result.is_err(),
            "an SDK continuation whose original invite gate was cancelled must not publish cached settlement controls; extra_network_calls={}",
            workers
                .relay_b
                .attempted_event_ids()
                .len()
                .saturating_sub(attempted)
        );
        assert_eq!(
            workers.relay_b.attempted_event_ids().len(),
            attempted,
            "cancelled original SDK custody must produce zero new network invocations"
        );
        workers.runtime_a.shutdown_and_close().await.unwrap();
        workers.runtime_b.shutdown_and_close().await.unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_enrollment_actual_relay_notification_reaches_observer_metadata() {
        exercise_enrollment_relay_observation(false, false, None).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_enrollment_proposal_actual_artifact_and_context_reaches_intake() {
        exercise_enrollment_relay_observation(true, false, None).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_enrollment_received_proposal_validates_actual_context_and_artifact() {
        exercise_enrollment_relay_observation(true, true, None).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_received_proposal_rejects_unknown_context() {
        exercise_enrollment_relay_observation(true, true, Some("unknown_context")).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_received_proposal_rejects_unknown_leaf() {
        exercise_enrollment_relay_observation(true, true, Some("unknown_leaf")).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_received_proposal_rejects_noncanonical_context() {
        exercise_enrollment_relay_observation(true, true, Some("noncanonical_context")).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_received_proposal_rejects_noncanonical_base64() {
        exercise_enrollment_relay_observation(true, true, Some("noncanonical_base64")).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_received_proposal_rejects_foreign_account() {
        exercise_enrollment_relay_observation(true, true, Some("foreign_account")).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_received_proposal_rejects_substituted_package() {
        exercise_enrollment_relay_observation(true, true, Some("substituted_package")).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_b_endorsement_valid_selection_survives_wrong_carrier_batch() {
        exercise_enrollment_relay_observation(true, true, Some("mixed_batch")).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_b_endorsement_later_valid_arrival_remains_selectable() {
        exercise_enrollment_relay_observation(true, true, Some("late_batch")).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_received_proposal_rejects_artifact_signed_by_other_current_leaf() {
        exercise_enrollment_relay_observation(true, true, Some("wrong_artifact_carrier")).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_received_proposal_rejects_tampered_artifact() {
        exercise_enrollment_relay_observation(true, true, Some("tampered_artifact")).await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn device_linking_received_proposal_v1_is_never_validation_input() {
        exercise_enrollment_relay_observation(false, true, Some("v1")).await;
    }
    async fn exercise_enrollment_relay_observation(
        proposal: bool,
        validate: bool,
        control: Option<&str>,
    ) {
        use cgka_traits::engine::CgkaEngine;
        use cgka_traits::peeler::TransportPeeler;
        use cgka_traits::storage::{AccountDeviceSignerStorage, StorageProvider};
        use openmls::prelude::*;
        use openmls_basic_credential::SignatureKeyPair;
        use tls_codec::Serialize as _;
        let (workers, relay, group_id) = joined_live_workers().await;
        // The original coordinator still owns its confirmed invite continuation.
        // Use the completed recipient as the fresh proposal source; the v1
        // control retains its original sender/observer direction.
        let (source, observer, source_runtime) = if proposal {
            (&workers.a, &workers.b, &workers.runtime_a)
        } else {
            (&workers.b, &workers.a, &workers.runtime_b)
        };
        let sender = source.app.account_storage("test").unwrap();
        let receiver = observer.app.account_storage("test").unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let done = [&sender, &receiver].iter().all(|storage| {
                    cgka_traits::StorageProvider::private_roster_settlement_storage(*storage)
                        .unwrap().read_round().unwrap().is_some_and(|round|
                            round.phase == cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed
                            && round.anchor.group_id == group_id)
                });
                if done { break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.expect("the genuine two-worker protected predecessor must complete");
        // A fresh independent recipient owns the real single-use package. The
        // canonical context below is metadata, not a completed SDK/SAS result.
        let proposal_fixture = if proposal {
            use base64::Engine as _;
            use sha2::{Digest, Sha256};
            let keys = source.app.account_home().load_signing_keys("test").unwrap();
            let dir = tempfile::tempdir().unwrap();
            AccountHome::open(dir.path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
            let app = MarmotApp::with_relay(dir.path(), relay.url().await.to_string());
            let runtime = MarmotAppRuntime::new(app);
            runtime.reconcile_accounts().await.unwrap();
            let c = runtime.accounts();
            let prepared = c.prepare_device_linking("test").await.unwrap();
            let scope = source
                .reserve_device_linking_for_approver("test")
                .await
                .unwrap();
            let candidate = source
                .candidate_device_group_snapshot("test", &group_id)
                .await
                .unwrap()
                .unwrap();
            let artifact = source
                .export_settled_device_predecessor("test", &group_id)
                .await
                .unwrap()
                .unwrap();
            let metadata =
                cgka_engine::key_package::key_package_metadata(&prepared.package).unwrap();
            let mut predecessor =
                crate::device_linking::PredecessorRoster::from_candidate(&candidate).unwrap();
            predecessor.artifact_digest = Some(Sha256::digest(&artifact).into());
            let context = LinkingContext {
                version: 2,
                nonce: [11; 32],
                new_device_generation: prepared.scope.generation,
                approver_generation: scope.generation,
                account: scope.account,
                exact_key_package: prepared.package.bytes.clone(),
                key_package_reference: hex::decode(metadata.key_package_ref_hex)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                device_group: group_id.as_slice().to_vec(),
                predecessor,
                approver: scope.local_device,
                recipient: prepared.scope.local_device,
            };
            context.digest().unwrap();
            let context_json = serde_json::to_string(&context).unwrap();
            let artifact_base64 = base64::engine::general_purpose::STANDARD.encode(&artifact);
            Some((artifact_base64, context_json, context, runtime, dir))
        } else {
            None
        };
        // Stop the sender actor before a separate provider mutates its genuine
        // application sender ratchet. No concurrent cached group can overwrite it.
        source_runtime.shutdown().await;
        // Real signed/encrypted MLS from the already-completed source. The
        // declaration hashes below are metadata; this does not approve a third device.
        let round = sender
            .private_roster_settlement_storage()
            .unwrap()
            .read_round()
            .unwrap()
            .unwrap();
        let binding = sender
            .account_device_signer(&cgka_traits::MemberId::new(round.anchor.account.to_vec()))
            .unwrap()
            .unwrap();
        let crypto = openmls_rust_crypto::RustCrypto::default();
        let provider = cgka_engine::provider::EngineOpenMlsProvider::<
            storage_sqlite::SqliteAccountStorage,
        >::new(&crypto, sender.mls_storage());
        let mut source_group = MlsGroup::load(
            provider.storage(),
            &openmls::group::GroupId::from_slice(group_id.as_slice()),
        )
        .unwrap()
        .unwrap();
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &binding.mls_signature_public_key,
            SignatureScheme::ED25519,
        )
        .unwrap();
        let mut frame = serde_json::json!({
            "protocol":"whitenoise.experimental.enrollment-request.v1",
            "account":round.anchor.account,"group_id":group_id.as_slice(),
            "epoch":round.anchor.successor.epoch.0,
            "epoch_authenticator_digest":round.anchor.successor.epoch_authenticator_digest,
            "leaves":round.anchor.successor.leaves.iter().map(|leaf| serde_json::json!({"leaf_index":leaf.leaf_index,"signature_public_key":leaf.signature_public_key})).collect::<Vec<_>>(),
            "artifact_digest":([9u8;32]),"context_digest":([10u8;32]),
            "enrollment_nonce":([11u8;32]),"request_nonce":([12u8;32]),
            "approver":binding.mls_signature_public_key,"recipient":([13u8;32]),
            "approver_generation":2,"recipient_generation":1,
            "key_package_reference":([14u8;32]),"key_package_digest":([15u8;32])
        });
        if let Some((artifact_base64, context_json, context, _, _)) = &proposal_fixture {
            use sha2::{Digest, Sha256};
            frame["protocol"] = serde_json::json!("whitenoise.experimental.enrollment-request.v2");
            frame["artifact_digest"] =
                serde_json::json!(context.predecessor.artifact_digest.unwrap());
            frame["context_digest"] = serde_json::json!(context.digest().unwrap());
            frame["recipient"] = serde_json::json!(context.recipient);
            frame["approver_generation"] = serde_json::json!(context.approver_generation);
            frame["recipient_generation"] = serde_json::json!(context.new_device_generation);
            frame["key_package_reference"] = serde_json::json!(context.key_package_reference);
            let package_digest: [u8; 32] = Sha256::digest(&context.exact_key_package).into();
            frame["key_package_digest"] = serde_json::json!(package_digest);
            frame["proposal"] = serde_json::json!({
                "artifact_base64":artifact_base64, "context_json":context_json
            });
        }
        let valid_frame = frame.clone();
        if let Some(control) = control.filter(|control| *control != "v1") {
            use base64::Engine as _;
            use sha2::{Digest, Sha256};
            let parts = frame.get_mut("proposal").unwrap();
            let mut context: serde_json::Value =
                serde_json::from_str(parts["context_json"].as_str().unwrap()).unwrap();
            match control {
                "unknown_context" => context["unexpected"] = serde_json::json!(1),
                "unknown_leaf" => {
                    context["predecessor"]["leaves"][0]["unexpected"] = serde_json::json!(1)
                }
                "foreign_account" => context["account"] = serde_json::json!(([42u8; 32])),
                "substituted_package" => {
                    let byte = context["exact_key_package"][0].as_u64().unwrap();
                    context["exact_key_package"][0] = serde_json::json!(byte ^ 1);
                }
                "wrong_artifact_carrier" | "mixed_batch" | "late_batch" => {
                    // B's actual signed export is valid for this exact tree,
                    // but the real encrypted request is carried by A.
                    let bytes = observer
                        .export_settled_device_predecessor("test", &group_id)
                        .await
                        .unwrap()
                        .unwrap();
                    let hash: [u8; 32] = Sha256::digest(&bytes).into();
                    parts["artifact_base64"] =
                        serde_json::json!(base64::engine::general_purpose::STANDARD.encode(bytes));
                    context["predecessor"]["artifact_digest"] = serde_json::json!(hash);
                }
                "tampered_artifact" => {
                    let mut bytes = base64::engine::general_purpose::STANDARD
                        .decode(parts["artifact_base64"].as_str().unwrap())
                        .unwrap();
                    let last = bytes.len() - 1;
                    bytes[last] ^= 1;
                    let hash: [u8; 32] = Sha256::digest(&bytes).into();
                    parts["artifact_base64"] =
                        serde_json::json!(base64::engine::general_purpose::STANDARD.encode(bytes));
                    context["predecessor"]["artifact_digest"] = serde_json::json!(hash);
                }
                "noncanonical_context" | "noncanonical_base64" => {}
                _ => panic!("unknown private test control"),
            }
            // Deserialize into the actual private shape, when structurally
            // possible, so reordered Value serialization cannot mask the
            // intended field/signature substitution behind canonicality alone.
            let canonical = serde_json::from_value::<LinkingContext>(context.clone()).ok();
            let json = if let Some(canonical) = &canonical {
                serde_json::to_string(canonical).unwrap()
            } else {
                serde_json::to_string(&context).unwrap()
            };
            let parts = frame.get_mut("proposal").unwrap();
            parts["context_json"] = serde_json::json!(if control == "noncanonical_context" {
                format!(" {json}")
            } else {
                json
            });
            if control == "noncanonical_base64" {
                let value = parts["artifact_base64"].as_str().unwrap().to_owned();
                parts["artifact_base64"] = serde_json::json!(format!("{value}\n"));
            }
            if let Some(canonical) = canonical {
                if let Ok(digest) = canonical.digest() {
                    frame["context_digest"] = serde_json::json!(digest);
                }
                if matches!(
                    control,
                    "tampered_artifact" | "wrong_artifact_carrier" | "mixed_batch" | "late_batch"
                ) {
                    frame["artifact_digest"] =
                        serde_json::json!(canonical.predecessor.artifact_digest.unwrap());
                }
            }
        }
        let event = cgka_traits::app_event::MarmotAppEvent::new(
            hex::encode(round.anchor.account),
            0,
            38175,
            vec![],
            frame.to_string(),
        );
        let payload = event.encode().unwrap();
        assert!(
            payload.len() <= 16 * 1024,
            "actual three-device proposal fixture must fit the unchanged intake bound"
        );
        let cipher = source_group
            .create_message(&provider, &signer, &payload)
            .unwrap()
            .tls_serialize_detached()
            .unwrap();
        let keys = source.app.account_home().load_signing_keys("test").unwrap();
        let read_engine = cgka_engine::EngineBuilder::new(sender.clone())
            .identity(round.anchor.account.to_vec())
            .account_identity_proof_signer(
                crate::external_signer::AccountSigner::Local(keys.clone()).as_proof_signer(),
            )
            .protocol_profile(cgka_traits::group::ProtocolProfile::Current)
            .supported_app_components(
                cgka_traits::app_components::default_group_components()
                    .into_iter()
                    .chain([cgka_traits::app_components::NOSTR_ROUTING_COMPONENT_ID]),
            )
            .peeler(Box::new(transport_nostr_peeler::NostrMlsPeeler::new()))
            .build()
            .unwrap();
        let context = cgka_traits::group_context::GroupContextSnapshot::from_context(
            read_engine.group_context(&group_id).unwrap().as_ref(),
            &[transport_nostr_peeler::DEFAULT_EXPORTER_LABEL],
        );
        // The exact current account/group/endpoint attempt must reach EOSE
        // before publication; Completed membership alone is not acquisition phase.
        let endpoint = cgka_traits::TransportEndpoint(relay.url().await.to_string());
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let eose = observer
                    .verifier_command("test", |respond| {
                        VerifierCommand::EnrollmentEndpointEoseForTest {
                            group: group_id.clone(),
                            transport_group: context.transport_group_id().unwrap().to_vec(),
                            endpoint: endpoint.clone(),
                            respond,
                        }
                    })
                    .await
                    .unwrap();
                if eose {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the relevant current endpoint and subscription attempt must reach actual EOSE");
        // Exact actual MLS ciphertext identity, independent of its Nostr wrapping.
        use sha2::Digest as _;
        let content_id = cgka_traits::MessageId::new(sha2::Sha256::digest(&cipher).to_vec());
        let message = transport_nostr_peeler::NostrMlsPeeler::new()
            .wrap_group_message(
                &cgka_traits::transport::EncryptedPayload {
                    ciphertext: cipher,
                    aad: vec![],
                },
                &context,
            )
            .await
            .unwrap();
        let signed = transport_nostr_peeler::NostrTransportEvent::from_transport_message(&message)
            .unwrap()
            .to_verified_nostr_event()
            .unwrap();
        let publisher = nostr_sdk::prelude::Client::default();
        publisher
            .add_relay(relay.url().await.to_string())
            .await
            .unwrap();
        publisher.connect().await;
        let acquired_before = std::time::Instant::now();
        publisher.send_event(&signed).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if cgka_traits::MessageStorage::get_message(&receiver, &content_id).is_ok_and(|row|
                    row.state == cgka_traits::message::MessageState::Processed) { break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.expect("the exact real ciphertext must reach committed crypto/observer disposition before checking metadata");
        assert!(workers.a.app.load_state("test").unwrap().groups.is_empty());
        if matches!(control, Some("mixed_batch" | "late_batch")) {
            if control == Some("late_batch") {
                let first = observer
                    .verifier_command("test", |respond| {
                        VerifierCommand::ReceivedEnrollmentProposalBindings { respond }
                    })
                    .await
                    .unwrap();
                assert_eq!(
                    first.len(),
                    1,
                    "retain the actual first invalid observation before a later good arrival"
                );
            }
            let event = cgka_traits::app_event::MarmotAppEvent::new(
                hex::encode(round.anchor.account),
                0,
                38175,
                vec![],
                valid_frame.to_string(),
            );
            let cipher = source_group
                .create_message(&provider, &signer, &event.encode().unwrap())
                .unwrap()
                .tls_serialize_detached()
                .unwrap();
            let id = cgka_traits::MessageId::new(sha2::Sha256::digest(&cipher).to_vec());
            let wrapped = transport_nostr_peeler::NostrMlsPeeler::new()
                .wrap_group_message(
                    &cgka_traits::transport::EncryptedPayload {
                        ciphertext: cipher,
                        aad: vec![],
                    },
                    &context,
                )
                .await
                .unwrap();
            let signed =
                transport_nostr_peeler::NostrTransportEvent::from_transport_message(&wrapped)
                    .unwrap()
                    .to_verified_nostr_event()
                    .unwrap();
            publisher.send_event(&signed).await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while !cgka_traits::MessageStorage::get_message(&receiver, &id)
                    .is_ok_and(|row| row.state == cgka_traits::message::MessageState::Processed)
                {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("both real encrypted requests must reach durable observer disposition");
            let bindings = observer
                .verifier_command("test", |respond| {
                    VerifierCommand::ReceivedEnrollmentProposalBindings { respond }
                })
                .await
                .expect("opaque selectors must not authenticate unrelated noise");
            assert_eq!(bindings.len(), 2);
            let mut accepted = 0;
            for binding in bindings {
                if observer
                    .verifier_command("test", |respond| {
                        VerifierCommand::EndorseReceivedEnrollmentProposal { binding, respond }
                    })
                    .await
                    .is_ok()
                {
                    accepted += 1;
                    observer
                        .verifier_command("test", |respond| {
                            VerifierCommand::CancelReceivedEnrollmentEndorsement {
                                binding,
                                respond,
                            }
                        })
                        .await
                        .unwrap();
                }
            }
            assert_eq!(
                accepted, 1,
                "exact valid selection must work despite an unrelated wrong-carrier request"
            );
        } else if validate {
            let result = observer
                .verifier_command("test", |respond| {
                    VerifierCommand::ValidateReceivedEnrollmentProposals { respond }
                })
                .await;
            if let Some(control) = control {
                if control == "v1" {
                    assert_eq!(
                        result.unwrap(),
                        0,
                        "v1 declarations are never proposal validation input"
                    );
                } else {
                    assert!(
                        result.is_err(),
                        "an actually received substituted proposal must not authenticate"
                    );
                }
            } else {
                let count = result.unwrap();
                assert_eq!(
                    count, 1,
                    "the actually received canonical proposal must authenticate internally without granting approval"
                );
                let retry = observer
                    .verifier_command("test", |respond| {
                        VerifierCommand::ValidateReceivedEnrollmentProposals { respond }
                    })
                    .await
                    .unwrap();
                assert_eq!(
                    retry, 1,
                    "exact retained metadata validation must be idempotent"
                );
            }
            assert!(workers.a.app.load_state("test").unwrap().groups.is_empty());
            assert!(workers.b.app.load_state("test").unwrap().groups.is_empty());
        } else {
            let observations = observer
                .verifier_command("test", |respond| {
                    VerifierCommand::DrainEnrollmentObservationsForTest { respond }
                })
                .await
                .unwrap();
            assert_eq!(
                observations.len(),
                1,
                "actual bounded signed-artifact/context proposal must reach the fresh opaque intake"
            );
            if let Some((artifact_base64, context_json, _, _, _)) = &proposal_fixture {
                assert_eq!(
                    observations[0].proposal_parts(),
                    Some((artifact_base64.as_str(), context_json.as_str()))
                );
            } else {
                assert!(observations[0].proposal_parts().is_none());
            }
            assert!(
                observations[0].observed_deadline()
                    <= acquired_before + std::time::Duration::from_secs(610)
            );
            assert!(workers.a.app.load_state("test").unwrap().groups.is_empty());
            assert!(workers.b.app.load_state("test").unwrap().groups.is_empty());
            assert!(
                observer
                    .verifier_command("test", |respond| {
                        VerifierCommand::DrainEnrollmentObservationsForTest { respond }
                    })
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        publisher.shutdown().await;
        workers.runtime_a.shutdown_and_close().await.unwrap();
        workers.runtime_b.shutdown_and_close().await.unwrap();
        if let Some((_, _, _, runtime, _dir)) = proposal_fixture {
            runtime.shutdown_and_close().await.unwrap();
        }
        relay.shutdown();
    }
}
