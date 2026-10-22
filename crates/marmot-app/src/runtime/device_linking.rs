//! Private lifecycle/verifier RPCs; no enrollment or history grants.
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
pub(crate) enum VerifierCommand {
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
    PreparePrivateInvite {
        scope: PurposeAttemptScope,
        respond: Reply<cgka_traits::private_device_invite::PrivateInviteScope>,
    },
    TakeVerified {
        scope: PurposeAttemptScope,
        respond: Reply<VerifiedPairing>,
    },
}

/// Called only from the serial account worker; no frozen-read bypass.
pub(super) async fn handle_verifier_command(client: &mut AppClient, command: VerifierCommand) {
    match command {
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
                tracing::debug!(target:"marmot_app::device_linking", method="worker_abandoned_approver_reservation", "device linking cleanup deferred");
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
        VerifierCommand::PreparePrivateInvite { scope, respond } => {
            let result = client.prepare_private_device_invite(&scope).await;
            // Failed wrapping can leave an exact raw draft for retry. If its
            // reply is abandoned, revoke and clean that attempt too.
            if respond.send(result).is_err()
                && client.cancel_device_linking_scope(&scope).await.is_err()
            {
                tracing::debug!(target:"marmot_app::device_linking", method="worker_abandoned_private_invite", "device linking cleanup deferred");
            }
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
    }
    async fn verified_workers() -> VerifiedWorkers {
        let keys = nostr::prelude::Keys::generate();
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        for dir in [&a_dir, &b_dir] {
            AccountHome::open(dir.path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
        }
        let app_a = MarmotApp::with_relay(a_dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let app_b = MarmotApp::with_relay(b_dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
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
        }
    }
    #[tokio::test]
    async fn device_linking_managed_workers_complete_scoped_verification_without_native_grants() {
        let VerifiedWorkers {
            directories: _directories,
            runtime_a,
            runtime_b,
            a,
            b,
            prepared,
            b_scope,
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
    #[tokio::test]
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
    #[tokio::test]
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
    #[tokio::test]
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
}
