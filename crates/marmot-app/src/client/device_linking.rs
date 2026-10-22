//! Private account-client ownership, with identities read from the live session.
use super::AppClient;
use crate::device_linking::invite_gate::RuntimeInviteGate;
use crate::device_linking::runtime_gate::RuntimeWelcomeGate;
use crate::device_linking::{
    LinkFrame, LinkingContext, LinkingOwner, OwnerError, PeerOffer, Role, VerifiedPairing,
};
use cgka_engine::linking_welcome_policy::LinkingWelcomePolicy;
use cgka_traits::device_linking_key_package::PurposeAttemptScope;
use cgka_traits::storage::{AccountDeviceSignerStorage, StorageError, StorageResult};
use cgka_traits::{KeyPackage, MemberId};
use std::sync::Arc;
use storage_sqlite::SqliteAccountStorage;

/// The actor owns the only continuation and exact public retry inputs. Metadata
/// cannot reconstruct its gate lease after drop, cancellation or restart.
struct OwnedPrivateInvite {
    scope: PurposeAttemptScope,
    group: cgka_traits::GroupId,
    package: KeyPackage,
    deadline: std::time::Instant,
    prepared: Option<cgka_engine::private_device_invite::PreparedPrivateDeviceInvite>,
}

pub(crate) struct AccountLinkingOwner {
    verifier: LinkingOwner,
    welcome: Arc<RuntimeWelcomeGate>,
    invite: Arc<RuntimeInviteGate>,
    invite_attempt: Option<OwnedPrivateInvite>,
}

impl Drop for AccountLinkingOwner {
    fn drop(&mut self) {
        // The engine also retains this policy Arc. Revoke it before the verifier
        // fences its generation and before the client releases its session.
        self.welcome.shutdown();
        self.invite.shutdown();
    }
}

impl AccountLinkingOwner {
    /// The caller holds exclusive account ownership and has already fenced and
    /// cleaned the previous attempt. No presentation identity enters this path.
    pub(crate) fn attach(
        storage: Arc<SqliteAccountStorage>,
        identity: &MemberId,
    ) -> StorageResult<Self> {
        let invalid_identity = || StorageError::Backend("invalid linking session identity".into());
        let account = identity
            .as_slice()
            .try_into()
            .map_err(|_| invalid_identity())?;
        let binding = storage
            .account_device_signer(identity)?
            .ok_or_else(invalid_identity)?;
        if &binding.marmot_identity != identity {
            return Err(invalid_identity());
        }
        let device = binding
            .mls_signature_public_key
            .try_into()
            .map_err(|_| invalid_identity())?;
        Ok(Self {
            verifier: LinkingOwner::attach_after_restart_fence(storage, account, device),
            welcome: Arc::new(RuntimeWelcomeGate::new()),
            invite: Arc::new(RuntimeInviteGate::new()),
            invite_attempt: None,
        })
    }
    pub(crate) fn welcome_policy(&self) -> Arc<dyn LinkingWelcomePolicy> {
        self.welcome.clone()
    }
    pub(crate) fn invite_policy(
        &self,
    ) -> Arc<dyn cgka_engine::private_device_invite::TrustedPrivateInvitePolicy> {
        self.invite.clone()
    }
    pub(crate) fn arm_invite_genesis(
        &self,
        token: VerifiedPairing,
        origin: &cgka_engine::device_group_genesis::PrivateDeviceGroupGenesisEvidence,
    ) -> Result<(), cgka_traits::device_linking_key_package::LinkingWelcomeDenied> {
        self.invite.arm_genesis(token, origin)
    }
}

impl AppClient {
    pub(crate) fn linking_welcome_policy(&self) -> Arc<dyn LinkingWelcomePolicy> {
        self.linking_owner.welcome_policy()
    }
    pub(crate) fn reserve_device_linking(&mut self) -> Result<PurposeAttemptScope, OwnerError> {
        if self.linking_owner.invite_attempt.is_some() {
            return Err(OwnerError::Verifier(
                crate::device_linking::LinkError::SimultaneousRequest,
            ));
        }
        let scope = self.linking_owner.verifier.reserve_scope()?;
        self.linking_owner.invite.cancel();
        Ok(scope)
    }
}

/// Public package metadata for a private generation. No verifier permission.
pub(crate) struct PreparedDeviceLinking {
    pub(crate) scope: PurposeAttemptScope,
    pub(crate) package: KeyPackage,
}

#[derive(Debug)]
pub(crate) enum ClientLinkingError {
    Owner(OwnerError),
    Runtime(Box<crate::AppError>),
    Engine(cgka_traits::EngineError),
    Genesis(cgka_engine::device_group_genesis::GenesisFactoryError),
    Gate(cgka_traits::device_linking_key_package::LinkingWelcomeDenied),
    PrivateInvite(cgka_engine::private_device_invite::PrivateInviteError),
}

impl AppClient {
    /// Protected local birth, without publication or verifier consent.
    pub(crate) fn create_private_device_group_genesis(
        &mut self,
    ) -> Result<
        cgka_engine::device_group_genesis::PrivateDeviceGroupGenesisEvidence,
        ClientLinkingError,
    > {
        let routing = self
            .app
            .new_nostr_routing(None)
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        let data =
            cgka_traits::app_components::encode_nostr_routing_v1(&routing).map_err(|error| {
                ClientLinkingError::Runtime(Box::new(crate::AppError::InvalidNostrRouting(error)))
            })?;
        self.runtime
            .session_mut()
            .create_private_device_group_genesis_with_components(vec![
                cgka_traits::app_components::AppComponentData {
                    component_id: cgka_traits::app_components::NOSTR_ROUTING_COMPONENT_ID,
                    data,
                },
            ])
            .map_err(ClientLinkingError::Genesis)
    }

    fn scoped_linking_verifier(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<&mut LinkingOwner, ClientLinkingError> {
        self.linking_owner
            .verifier
            .check_scope(scope)
            .map_err(ClientLinkingError::Owner)?;
        Ok(&mut self.linking_owner.verifier)
    }

    pub(crate) async fn begin_device_linking(
        &mut self,
        scope: &PurposeAttemptScope,
        context: LinkingContext,
        role: Role,
    ) -> Result<(), ClientLinkingError> {
        self.scoped_linking_verifier(scope)?;
        if role == Role::Approver {
            let mismatch = || {
                ClientLinkingError::Gate(
                    cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
                )
            };
            let group = cgka_traits::GroupId::new(context.device_group.clone());
            let origin = self
                .runtime
                .session()
                .validated_private_device_group_genesis(&group)
                .map_err(ClientLinkingError::Genesis)?
                .ok_or_else(mismatch)?;
            let predecessor =
                crate::device_linking::PredecessorRoster::from_candidate(origin.current())
                    .map_err(|_| mismatch())?;
            if origin.scope().account != scope.account
                || origin.scope().local_device != scope.local_device
                || context.account != scope.account
                || context.approver != scope.local_device
                || context.predecessor != predecessor
            {
                return Err(mismatch());
            }
        }
        self.linking_owner
            .verifier
            .begin_for_scope(scope, context, role, std::time::Instant::now())
            .await
            .map_err(ClientLinkingError::Owner)
    }
    pub(crate) fn device_linking_offer(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<PeerOffer, ClientLinkingError> {
        self.scoped_linking_verifier(scope)?
            .offer(std::time::Instant::now())
            .map_err(ClientLinkingError::Owner)
    }
    pub(crate) async fn admit_device_linking_peer(
        &mut self,
        scope: &PurposeAttemptScope,
        offer: &PeerOffer,
    ) -> Result<(), ClientLinkingError> {
        self.scoped_linking_verifier(scope)?
            .admit_peer(offer, std::time::Instant::now())
            .await
            .map_err(ClientLinkingError::Owner)
    }
    pub(crate) async fn start_device_linking_verification(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.scoped_linking_verifier(scope)?
            .start_verification(std::time::Instant::now())
            .await
            .map_err(ClientLinkingError::Owner)
    }
    pub(crate) async fn receive_device_linking_frame(
        &mut self,
        scope: &PurposeAttemptScope,
        frame: &LinkFrame,
    ) -> Result<(), ClientLinkingError> {
        self.scoped_linking_verifier(scope)?
            .receive(frame, std::time::Instant::now())
            .await
            .map_err(ClientLinkingError::Owner)
    }
    pub(crate) fn device_linking_outgoing(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<Vec<LinkFrame>, ClientLinkingError> {
        self.scoped_linking_verifier(scope)?
            .outgoing(std::time::Instant::now())
            .map_err(ClientLinkingError::Owner)
    }
    pub(crate) async fn acknowledge_device_linking_frame(
        &mut self,
        scope: &PurposeAttemptScope,
        token: &str,
    ) -> Result<(), ClientLinkingError> {
        self.scoped_linking_verifier(scope)?
            .acknowledge(token, std::time::Instant::now())
            .await
            .map_err(ClientLinkingError::Owner)
    }
    pub(crate) fn device_linking_decimals(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<Option<(u16, u16, u16)>, ClientLinkingError> {
        self.scoped_linking_verifier(scope)?
            .decimals(std::time::Instant::now())
            .map_err(ClientLinkingError::Owner)
    }
    pub(crate) async fn confirm_device_linking(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.scoped_linking_verifier(scope)?
            .confirm(std::time::Instant::now())
            .await
            .map_err(ClientLinkingError::Owner)
    }
    /// Internal one-shot evidence only; approved-roster checks must precede any
    /// use in Welcome admission. No native caller can manufacture this result.
    pub(crate) async fn take_device_linking_verified(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<VerifiedPairing, ClientLinkingError> {
        self.scoped_linking_verifier(scope)?
            .take_verified(std::time::Instant::now())
            .await
            .map_err(ClientLinkingError::Owner)
    }

    /// Internal coordinator inlet only. Refresh genuine origin evidence after
    /// SDK completion; a returned DTO or native approval flag cannot arm this gate.
    pub(crate) fn arm_private_device_invite(
        &mut self,
        token: VerifiedPairing,
    ) -> Result<(), ClientLinkingError> {
        let group = cgka_traits::GroupId::new(token.device_group().to_vec());
        let origin = self
            .runtime
            .session()
            .validated_private_device_group_genesis(&group)
            .map_err(ClientLinkingError::Genesis)?
            .ok_or(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
            ))?;
        self.linking_owner
            .arm_invite_genesis(token, &origin)
            .map_err(ClientLinkingError::Gate)
    }

    /// Consume genuine SDK evidence inside the account actor and retain the
    /// opaque prepared lease here. RPC callers receive only exact scope metadata.
    pub(crate) async fn prepare_private_device_invite(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<cgka_traits::private_device_invite::PrivateInviteScope, ClientLinkingError> {
        self.check_private_invite_attempt_scope(scope)?;
        if self.linking_owner.invite_attempt.is_none() {
            let token = self.take_device_linking_verified(scope).await?;
            let context = token.context();
            if context.account != scope.account
                || context.approver != scope.local_device
                || context.approver_generation != scope.generation
            {
                return Err(ClientLinkingError::Gate(
                    cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
                ));
            }
            let group = cgka_traits::GroupId::new(context.device_group.clone());
            let package = KeyPackage::new(context.exact_key_package.clone())
                .with_protocol_profile(self.runtime.session().new_protocol_profile());
            let deadline = token.original_deadline().ok_or(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier,
            ))?;
            self.arm_private_device_invite(token)?;
            self.linking_owner.invite_attempt = Some(OwnedPrivateInvite {
                scope: scope.clone(),
                group,
                package,
                deadline,
                prepared: None,
            });
        }
        let attempt = self.linking_owner.invite_attempt.as_mut().unwrap();
        if let Some(prepared) = attempt.prepared.as_mut() {
            prepared
                .check_live_permission()
                .map_err(ClientLinkingError::Gate)?;
            return Ok(prepared.scope().clone());
        }
        // Only these exact verifier-bound inputs may retry a raw draft. The
        // Engine independently checks the original gate before/after each phase.
        let group = attempt.group.clone();
        let package = attempt.package.clone();
        let prepared = self
            .runtime
            .session_mut()
            .prepare_private_device_invite(&group, package)
            .await
            .map_err(ClientLinkingError::PrivateInvite)?;
        let result = prepared.scope().clone();
        self.linking_owner.invite_attempt.as_mut().unwrap().prepared = Some(prepared);
        Ok(result)
    }

    fn check_private_invite_attempt_scope(
        &self,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.linking_owner
            .verifier
            .check_scope(scope)
            .map_err(ClientLinkingError::Owner)?;
        if self
            .linking_owner
            .invite_attempt
            .as_ref()
            .is_some_and(|attempt| attempt.scope != *scope)
        {
            return Err(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
            ));
        }
        Ok(())
    }

    fn retire_owned_private_invite(&mut self) -> Result<(), ClientLinkingError> {
        if let Some(attempt) = self.linking_owner.invite_attempt.as_ref() {
            if let Some(prepared) = attempt.prepared.as_ref() {
                self.runtime
                    .session_mut()
                    .retire_prepared_private_device_invite(prepared)
                    .map_err(ClientLinkingError::PrivateInvite)?;
            } else {
                self.runtime
                    .session_mut()
                    .retire_unprepared_private_device_invite(&attempt.scope)
                    .map_err(ClientLinkingError::PrivateInvite)?;
            }
            // Retain the exact continuation on SQL failure. Only durable
            // cleanup success may drop it and release the held lease mutex.
            self.linking_owner.invite_attempt = None;
        }
        Ok(())
    }

    pub(crate) async fn prepare_device_linking(
        &mut self,
    ) -> Result<PreparedDeviceLinking, ClientLinkingError> {
        let result = match self.reserve_device_linking() {
            Ok(scope) => self
                .runtime
                .session_mut()
                .resolve_linking_key_package(&scope)
                .await
                .map(|package| PreparedDeviceLinking { scope, package })
                .map_err(ClientLinkingError::Engine),
            Err(error) => Err(ClientLinkingError::Owner(error)),
        };
        if result.is_err() {
            // A cleanup failure takes precedence: no further preparation may
            // proceed while the previous private package is still durable.
            self.cancel_device_linking().await?;
        }
        result
    }

    pub(crate) async fn maintain_device_linking(
        &mut self,
        now: std::time::Instant,
    ) -> Result<(), ClientLinkingError> {
        let reservation_live = self
            .linking_owner
            .verifier
            .maintain(now)
            .map_err(ClientLinkingError::Owner)?;
        let approval_live = self
            .linking_owner
            .welcome
            .maintain()
            .map_err(ClientLinkingError::Gate)?;
        if self
            .linking_owner
            .invite_attempt
            .as_ref()
            .is_some_and(|attempt| now >= attempt.deadline)
        {
            // Housekeeping may revoke early but can never extend the original
            // deadline or issue a positive dispatch permission.
            self.linking_owner.invite.cancel();
        }
        let invite_live = match self
            .linking_owner
            .invite_attempt
            .as_mut()
            .and_then(|attempt| attempt.prepared.as_mut())
        {
            Some(prepared) => match prepared.check_live_permission() {
                Ok(()) => true,
                Err(
                    cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier
                    | cgka_traits::device_linking_key_package::LinkingWelcomeDenied::Expired
                    | cgka_traits::device_linking_key_package::LinkingWelcomeDenied::Cancelled,
                ) => false,
                Err(error) => return Err(ClientLinkingError::Gate(error)),
            },
            None => self
                .linking_owner
                .invite
                .maintain()
                .map_err(ClientLinkingError::Gate)?,
        };
        if !invite_live {
            self.retire_owned_private_invite()?;
        }
        if !reservation_live && !approval_live && !invite_live {
            // Retry cleanup after transient storage failure without restoring
            // an expired verifier or approval from a durable terminal fact.
            self.retire_unjoined_device_linking().await?;
        }
        Ok(())
    }

    pub(crate) async fn cancel_device_linking_scope(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        // Validate before revoking the gate: an old native request must not
        // mutate a later attempt owned by this same serial account worker.
        self.check_private_invite_attempt_scope(scope)?;
        self.cancel_device_linking().await
    }

    pub(crate) async fn cancel_device_linking(&mut self) -> Result<(), ClientLinkingError> {
        // Revoke admission before terminal fencing or private deletion. The
        // serial owner must not retire a package while its join lease is busy.
        self.linking_owner.invite.cancel();
        self.linking_owner
            .welcome
            .cancel()
            .map_err(ClientLinkingError::Gate)?;
        self.linking_owner
            .verifier
            .cancel()
            .map_err(ClientLinkingError::Owner)?;
        self.retire_owned_private_invite()?;
        self.retire_unjoined_device_linking().await
    }

    async fn retire_unjoined_device_linking(&mut self) -> Result<(), ClientLinkingError> {
        if let Some(scope) = self
            .linking_owner
            .verifier
            .unjoined_purpose_scope()
            .map_err(ClientLinkingError::Owner)?
        {
            self.runtime
                .session_mut()
                .retire_linking_key_package(&scope)
                .await
                .map_err(ClientLinkingError::Engine)?;
        }
        Ok(())
    }
}
