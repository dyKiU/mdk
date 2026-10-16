//! Private account-client ownership, with identities read from the live session.
mod enrollment;
pub(crate) mod native_enrollment;
mod pairing_metadata;
pub(crate) mod setup;
pub(crate) mod sibling_sharing;
use super::AppClient;
use crate::device_linking::invite_gate::RuntimeInviteGate;
use crate::device_linking::runtime_gate::RuntimeWelcomeGate;
use crate::device_linking::welcome_collection::{CollectionError, PrivateWelcomeCollection};
use crate::device_linking::{
    LinkFrame, LinkingContext, LinkingOwner, OwnerError, PeerOffer, Role, VerifiedPairing,
};
use cgka_engine::linking_welcome_policy::LinkingWelcomePolicy;
use cgka_traits::StorageProvider;
use cgka_traits::device_linking_key_package::PurposeAttemptScope;
use cgka_traits::device_linking_key_package::PurposeKeyPackage;
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
    proposal: Option<cgka_engine::private_enrollment_request::OwnedLocalEnrollmentProposal>,
    endorsements:
        Vec<cgka_engine::private_enrollment_endorsement::AuthenticatedEnrollmentEndorsement>,
    for_add: bool,
}

#[cfg(all(test, feature = "test-policy-overrides"))]
#[derive(Default)]
pub(crate) struct RevocationRetryCustodyStateForTest {
    pub(crate) entries: Vec<(cgka_traits::GroupId, [u8; 32])>,
    pub(crate) overflow: bool,
}
#[cfg(all(test, feature = "test-policy-overrides"))]
pub(crate) type RevocationRetryCustodyForTest =
    Arc<std::sync::Mutex<RevocationRetryCustodyStateForTest>>;

#[cfg(all(test, feature = "test-policy-overrides"))]
pub(crate) type RevocationBindingObservationForTest =
    Result<(Option<[u8; 32]>, RevocationRetryCustodyForTest), crate::AppError>;

pub(crate) struct AccountLinkingOwner {
    verifier: LinkingOwner,
    pub(super) received_endorsement:
        Option<super::private_enrollment_proposal::OwnedReceivedEndorsement>,
    pub(super) cancelled_endorsements: Vec<([u8; 32], std::time::Instant)>,
    pub(super) received_enrollment_proposals:
        Vec<cgka_engine::private_enrollment_request::AuthenticatedEnrollmentRequest>,
    welcome: Arc<RuntimeWelcomeGate>,
    invite: Arc<RuntimeInviteGate>,
    invite_attempt: Option<OwnedPrivateInvite>,
    pub(super) settlement_attempt: Option<super::private_settlement::OwnedSettlementAttempt>,
    pub(super) existing_settlement_attempt:
        Option<super::private_settlement::OwnedExistingSettlementAttempt>,
    recipient_enrollment:
        Option<cgka_engine::private_enrollment_request::OwnedEnrollmentRecipientEvidence>,
    welcome_collection: PrivateWelcomeCollection,
    native_setup_request: Option<setup::NewDeviceSetup>,
    native_enrollment: Option<native_enrollment::NativeEnrollmentIntent>,
    sharing_approval: Option<Arc<sibling_sharing::OriginalEnrollmentSharingChoice>>,
    pairing_metadata: Option<(PurposeAttemptScope, Vec<Vec<String>>)>,
    pub(super) approval_pairing_metadata: Option<([u8; 32], Vec<Vec<String>>)>,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    sibling_projection_observations:
        Arc<std::sync::Mutex<std::collections::HashMap<cgka_traits::MessageId, [usize; 6]>>>,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(super) revocation_retry_custody: RevocationRetryCustodyForTest,
    sibling_channels: Vec<sibling_sharing::SiblingChannel>,
    sibling_publication_completions: tokio::sync::watch::Sender<()>,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(super) sibling_pre_auth_probe: Option<(
        std::sync::Weak<super::private_enrollment_proposal::OriginalSiblingSharingApproval>,
        Arc<sibling_sharing::SiblingPreAuthFailureProbe>,
    )>,
    pub(super) hidden_transport_group: Option<cgka_traits::GroupId>,
    pub(super) private_echo_retry: Option<std::time::Instant>,
    pub(super) private_echo_compared_route: Option<(
        cgka_traits::private_device_invite::PrivateInviteScope,
        [u8; 32],
    )>,
}

impl Drop for AccountLinkingOwner {
    fn drop(&mut self) {
        if let Some(choice) = &self.sharing_approval {
            choice.cancel();
        }
        // The engine also retains this policy Arc. Revoke it before the verifier
        // fences its generation and before the client releases its session.
        if let Some(attempt) = &self.settlement_attempt {
            attempt.guard.revoke();
        }
        if let Some(attempt) = &self.existing_settlement_attempt {
            attempt.guard.cancellation_handle().cancel();
        }
        self.welcome.shutdown();
        self.welcome_collection.clear();
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
            received_enrollment_proposals: Vec::new(),
            received_endorsement: None,
            cancelled_endorsements: Vec::new(),
            verifier: LinkingOwner::attach_after_restart_fence(storage, account, device),
            welcome: Arc::new(RuntimeWelcomeGate::new()),
            invite: Arc::new(RuntimeInviteGate::new()),
            invite_attempt: None,
            settlement_attempt: None,
            existing_settlement_attempt: None,
            recipient_enrollment: None,
            welcome_collection: PrivateWelcomeCollection::default(),
            native_setup_request: None,
            native_enrollment: None,
            sharing_approval: None,
            pairing_metadata: None,
            approval_pairing_metadata: None,
            #[cfg(all(test, feature = "test-policy-overrides"))]
            sibling_projection_observations: Arc::default(),
            #[cfg(all(test, feature = "test-policy-overrides"))]
            revocation_retry_custody: Arc::default(),
            sibling_channels: Vec::new(),
            sibling_publication_completions: tokio::sync::watch::channel(()).0,
            #[cfg(all(test, feature = "test-policy-overrides"))]
            sibling_pre_auth_probe: None,
            hidden_transport_group: None,
            private_echo_retry: None,
            private_echo_compared_route: None,
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
        self.revoke_owned_private_settlement()
            .map_err(|error| match error {
                ClientLinkingError::Engine(cgka_traits::EngineError::Storage(_)) => {
                    OwnerError::Storage
                }
                _ => OwnerError::Verifier(crate::device_linking::LinkError::NotReady),
            })?;
        self.linking_owner.native_enrollment = None;
        if let Some(choice) = &self.linking_owner.sharing_approval {
            choice.cancel();
        }
        self.linking_owner.sharing_approval = None;
        let scope = self.linking_owner.verifier.reserve_scope()?;
        self.clear_private_welcome_collection();
        self.linking_owner.received_enrollment_proposals.clear();
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
    Collection(CollectionError),
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

    /// Authenticate an artifact before original SDK setup. This inlet grants no
    /// invite, recipient admission or existing-member approval.
    pub(crate) async fn begin_device_linking_with_predecessor(
        &mut self,
        scope: &PurposeAttemptScope,
        context: LinkingContext,
        role: Role,
        artifact: &[u8],
    ) -> Result<(), ClientLinkingError> {
        self.scoped_linking_verifier(scope)?;
        let mismatch = || {
            ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
            )
        };
        if context.version != 2 || context.account != scope.account {
            return Err(mismatch());
        }
        // Shape and bounds precede allocation, portable authentication and all
        // durable context binding. Metadata does not grant enrollment consent.
        context
            .digest()
            .map_err(|error| ClientLinkingError::Owner(OwnerError::Verifier(error)))?;
        let group = cgka_traits::GroupId::new(context.device_group.clone());
        let leaves = context
            .predecessor
            .leaves
            .iter()
            .map(
                |leaf| cgka_engine::device_group_snapshot::CandidateDeviceLeaf {
                    leaf_index: leaf.leaf_index,
                    signature_public_key: leaf.signature_public_key.to_vec(),
                },
            )
            .collect::<Vec<_>>();
        let authenticated = self
            .runtime
            .session()
            .validate_private_device_predecessor(
                artifact,
                &MemberId::new(scope.account.to_vec()),
                &group,
                cgka_traits::EpochId(context.predecessor.epoch),
                &leaves,
            )
            .map_err(ClientLinkingError::Engine)?;
        if context.predecessor.artifact_digest != Some(*authenticated.artifact_digest()) {
            return Err(mismatch());
        }
        if role == Role::Approver {
            let mut predecessor = self.settled_linking_predecessor(scope, &group)?;
            predecessor.artifact_digest = Some(*authenticated.artifact_digest());
            if context.approver != scope.local_device || context.predecessor != predecessor {
                return Err(mismatch());
            }
            // A portable tree is not protected local settlement provenance.
            // Require this exact Approver's fresh export before original SAS.
            let exported = self
                .runtime
                .session()
                .export_settled_device_predecessor(&group)
                .map_err(ClientLinkingError::Engine)?
                .ok_or_else(mismatch)?;
            if exported.as_slice() != artifact {
                return Err(mismatch());
            }
        }
        self.linking_owner
            .verifier
            .begin_for_scope(scope, context, role, std::time::Instant::now())
            .await
            .map_err(ClientLinkingError::Owner)
    }

    fn settled_linking_predecessor(
        &self,
        scope: &PurposeAttemptScope,
        group: &cgka_traits::GroupId,
    ) -> Result<crate::device_linking::PredecessorRoster, ClientLinkingError> {
        let mismatch = || {
            ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
            )
        };
        let settled = self
            .runtime
            .session()
            .validated_settled_device_roster(group)
            .map_err(ClientLinkingError::Engine)?
            .ok_or_else(mismatch)?;
        let candidate = settled.candidate();
        if candidate.account.as_slice() != scope.account
            || candidate.group_id != *group
            || !candidate
                .leaves
                .iter()
                .any(|leaf| leaf.signature_public_key.as_slice() == scope.local_device)
        {
            return Err(mismatch());
        }
        crate::device_linking::PredecessorRoster::from_candidate(candidate).map_err(|_| mismatch())
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
            let predecessor = if let Some(origin) = self
                .runtime
                .session()
                .validated_private_device_group_genesis(&group)
                .map_err(ClientLinkingError::Genesis)?
            {
                if origin.scope().account != scope.account
                    || origin.scope().local_device != scope.local_device
                {
                    return Err(mismatch());
                }
                crate::device_linking::PredecessorRoster::from_candidate(origin.current())
                    .map_err(|_| mismatch())?
            } else {
                // This sealed read revalidates protected lineage, the actual
                // full tree and every completed leaf confirmation. It allows
                // starting SAS only; invite/Welcome admission remain separate.
                self.settled_linking_predecessor(scope, &group)?
            };
            if context.account != scope.account
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
    pub(crate) async fn arm_singleton_device_welcome(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.linking_owner
            .verifier
            .validate_singleton_bootstrap(scope, std::time::Instant::now())
            .map_err(ClientLinkingError::Owner)?;
        let token = self.take_device_linking_verified(scope).await?;
        let guard = Arc::new(
            crate::device_linking::settlement::SettlementGuard::from_verified(
                &token,
                scope,
                self.linking_owner.welcome.cancellation_fence(),
            )
            .map_err(ClientLinkingError::Engine)?,
        );
        self.linking_owner
            .welcome
            .arm(token)
            .map_err(ClientLinkingError::Gate)?;
        self.linking_owner.settlement_attempt = Some(
            super::private_settlement::OwnedSettlementAttempt::new(guard),
        );
        Ok(())
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
        if let Some(origin) = self
            .runtime
            .session()
            .validated_private_device_group_genesis(&group)
            .map_err(ClientLinkingError::Genesis)?
        {
            self.linking_owner
                .arm_invite_genesis(token, &origin)
                .map_err(ClientLinkingError::Gate)
        } else {
            // Refresh after SDK completion; the earlier pairing snapshot cannot
            // authorize this later preparation. The Engine also rechecks the
            // same actual protected origin during its atomic preparation.
            let settled = self
                .runtime
                .session()
                .validated_settled_device_roster(&group)
                .map_err(ClientLinkingError::Engine)?
                .ok_or(ClientLinkingError::Gate(
                    cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
                ))?;
            // Re-export and authenticate this Approver's current artifact after
            // SDK completion. An old setup proof or caller digest cannot bind
            // the later preparation, and B's differently signed export is not
            // substituted for A's original context artifact.
            let authenticated = if token.context().version == 2 {
                let candidate = settled.candidate();
                let bytes = self
                    .runtime
                    .session()
                    .export_settled_device_predecessor(&group)
                    .map_err(ClientLinkingError::Engine)?
                    .ok_or(ClientLinkingError::Gate(
                        cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
                    ))?;
                Some(
                    self.runtime
                        .session()
                        .validate_private_device_predecessor(
                            &bytes,
                            &candidate.account,
                            &group,
                            candidate.epoch,
                            &candidate.leaves,
                        )
                        .map_err(ClientLinkingError::Engine)?,
                )
            } else {
                None
            };
            self.linking_owner
                .invite
                .arm_settled(token, &settled, authenticated.as_ref())
                .map_err(ClientLinkingError::Gate)
        }
    }

    /// Consume genuine SDK evidence inside the account actor and retain the
    /// opaque prepared lease here. RPC callers receive only exact scope metadata.
    pub(crate) async fn prepare_private_device_invite(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<cgka_traits::private_device_invite::PrivateInviteScope, ClientLinkingError> {
        self.ensure_owned_private_invite(scope, true).await?;
        let attempt = self.linking_owner.invite_attempt.as_mut().unwrap();
        if let Some(prepared) = attempt.prepared.as_mut() {
            prepared
                .check_live_permission()
                .map_err(ClientLinkingError::Gate)?;
            return Ok(prepared.scope().clone());
        }
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

    /// Export complete signed metadata without transferring the original SDK lease.
    pub(crate) fn export_owned_enrollment_recipient_packet(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<Vec<u8>, ClientLinkingError> {
        self.check_private_invite_attempt_scope(scope)?;
        self.collect_owned_enrollment_endorsements(scope)?;
        let attempt =
            self.linking_owner
                .invite_attempt
                .as_mut()
                .ok_or(ClientLinkingError::Gate(
                    cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier,
                ))?;
        let proposal = attempt.proposal.as_mut().ok_or(ClientLinkingError::Gate(
            cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier,
        ))?;
        let receipts = attempt.endorsements.iter().collect::<Vec<_>>();
        self.runtime
            .session()
            .export_owned_enrollment_recipient_packet(proposal, &receipts)
            .map_err(ClientLinkingError::Engine)
    }

    /// Same actor-owned SDK lease, never a second verifier or received proposal.
    pub(crate) async fn prepare_owned_endorsed_enrollment_invite(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<cgka_traits::private_device_invite::PrivateInviteScope, ClientLinkingError> {
        self.check_private_invite_attempt_scope(scope)?;
        let attempt =
            self.linking_owner
                .invite_attempt
                .as_mut()
                .ok_or(ClientLinkingError::Gate(
                    cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier,
                ))?;
        if let Some(prepared) = attempt.prepared.as_mut() {
            prepared
                .check_live_permission()
                .map_err(ClientLinkingError::Gate)?;
            return Ok(prepared.scope().clone());
        }
        if !attempt
            .proposal
            .as_ref()
            .is_some_and(|proposal| proposal.preparation_has_started())
        {
            self.collect_owned_enrollment_endorsements(scope)?;
        }
        let attempt = self.linking_owner.invite_attempt.as_mut().unwrap();
        let proposal = attempt.proposal.as_mut().ok_or(ClientLinkingError::Gate(
            cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier,
        ))?;
        let receipts = attempt.endorsements.iter().collect::<Vec<_>>();
        let prepared = self
            .runtime
            .session_mut()
            .prepare_private_invite_from_owned_enrollment_proposal(proposal, &receipts)
            .await
            .map_err(ClientLinkingError::PrivateInvite)?;
        let result = prepared.scope().clone();
        if let Some(deadline) = prepared.enrollment_observation_deadline() {
            attempt.deadline = attempt.deadline.min(deadline);
            if let Some(settlement) = self.linking_owner.settlement_attempt.as_ref() {
                settlement.guard.shorten_deadline(deadline);
            }
        }
        attempt.prepared = Some(prepared);
        attempt.for_add = true;
        Ok(result)
    }

    async fn ensure_owned_private_invite(
        &mut self,
        scope: &PurposeAttemptScope,
        for_add: bool,
    ) -> Result<(), ClientLinkingError> {
        self.check_private_invite_attempt_scope(scope)?;
        if self.linking_owner.invite_attempt.is_none() {
            if for_add {
                self.linking_owner
                    .verifier
                    .validate_singleton_invite_preparation(scope, std::time::Instant::now())
                    .map_err(ClientLinkingError::Owner)?;
            }
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
            // Preserve this exact SDK token's settlement continuation before
            // its nonclone lease moves into the proposal/Add owner.
            let guard = Arc::new(
                crate::device_linking::settlement::SettlementGuard::from_verified(
                    &token,
                    scope,
                    self.linking_owner.invite.cancellation_fence(),
                )
                .map_err(ClientLinkingError::Engine)?,
            );
            self.arm_private_device_invite(token)?;
            self.linking_owner.settlement_attempt = Some(
                super::private_settlement::OwnedSettlementAttempt::new(guard),
            );
            self.linking_owner.invite_attempt = Some(OwnedPrivateInvite {
                scope: scope.clone(),
                group,
                package,
                deadline,
                prepared: None,
                proposal: None,
                endorsements: Vec::new(),
                for_add,
            });
        }
        let attempt = self.linking_owner.invite_attempt.as_ref().unwrap();
        if for_add != attempt.for_add {
            return Err(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
            ));
        }
        Ok(())
    }

    /// Scope-only internal proposal creation retains the actual SDK lease.
    pub(crate) async fn prepare_owned_enrollment_proposal(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.ensure_owned_private_invite(scope, false).await?;
        let attempt = self.linking_owner.invite_attempt.as_mut().unwrap();
        if attempt.prepared.is_some() {
            return Err(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
            ));
        }
        if let Some(proposal) = attempt.proposal.as_mut() {
            proposal
                .binding_digest()
                .map_err(ClientLinkingError::Engine)?;
            return Ok(());
        }
        let mut proposal = self
            .runtime
            .session_mut()
            .prepare_private_enrollment_proposal(&attempt.group, attempt.package.clone())
            .map_err(ClientLinkingError::Engine)?;
        if let Some((owner, tags)) = &self.linking_owner.pairing_metadata
            && owner == scope
        {
            self.runtime
                .session()
                .set_owned_local_enrollment_metadata(&mut proposal, tags.clone())
                .map_err(ClientLinkingError::Engine)?;
        }
        attempt.proposal = Some(proposal);
        Ok(())
    }

    pub(super) fn retained_enrollment_endorsement_count(&self) -> usize {
        self.linking_owner
            .invite_attempt
            .as_ref()
            .map_or(0, |attempt| attempt.endorsements.len())
    }

    /// Collection stays on the original local SDK-owned proposal. Counts expose
    /// authentication progress only, never Add or recipient permission.
    pub(crate) fn collect_owned_enrollment_endorsements(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<usize, ClientLinkingError> {
        self.enrollment_proposal_control(scope)?;
        let held_requests = self.linking_owner.received_enrollment_proposals.len();
        let attempt = self.linking_owner.invite_attempt.as_mut().unwrap();
        let proposal = attempt.proposal.as_mut().unwrap();
        let session = self.runtime.session();
        session
            .endorse_owned_local_enrollment_proposal(proposal)
            .map_err(ClientLinkingError::Engine)?;
        attempt
            .endorsements
            .retain(|receipt| std::time::Instant::now() < receipt.observed_deadline());
        // Revalidate every held receipt against the original lease and current
        // protected generation; expiry/invalid packets cannot occupy a leaf.
        let mut index = 0;
        while index < attempt.endorsements.len() {
            if session
                .authenticate_owned_local_enrollment_endorsement(
                    proposal,
                    &attempt.endorsements[index],
                )
                .map_err(ClientLinkingError::Engine)?
                .is_some()
            {
                index += 1;
            } else {
                attempt.endorsements.remove(index);
            }
        }
        let available = 128usize
            .saturating_sub(held_requests)
            .saturating_sub(attempt.endorsements.len());
        let received = self
            .runtime
            .session_mut()
            .drain_authenticated_enrollment_endorsements_up_to(available)
            .map_err(ClientLinkingError::Engine)?;
        for receipt in received {
            let Some(leaf) = self
                .runtime
                .session()
                .authenticate_owned_local_enrollment_endorsement(proposal, &receipt)
                .map_err(ClientLinkingError::Engine)?
            else {
                continue;
            };
            if let Some(existing) = attempt
                .endorsements
                .iter()
                .position(|held| held.source_index() == leaf)
            {
                // Never extend an original observation clock on duplicate input.
                if receipt.observed_deadline() < attempt.endorsements[existing].observed_deadline()
                {
                    attempt.endorsements[existing] = receipt;
                }
            } else {
                attempt.endorsements.push(receipt);
            }
        }
        let session = self.runtime.session();
        let settled = session
            .validated_settled_device_roster(&attempt.group)
            .map_err(ClientLinkingError::Engine)?
            .ok_or(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
            ))?;
        session
            .endorse_owned_local_enrollment_proposal(proposal)
            .map_err(ClientLinkingError::Engine)?;
        if attempt.endorsements.len().checked_add(1) != Some(settled.candidate().leaves.len()) {
            return Ok(0);
        }
        let receipts = attempt.endorsements.iter().collect::<Vec<_>>();
        session
            .authenticate_owned_local_enrollment_endorsements(proposal, &receipts)
            .map(|metadata| metadata.leaf_count())
            .map_err(ClientLinkingError::Engine)
    }

    pub(crate) fn enrollment_proposal_control(
        &self,
        scope: &PurposeAttemptScope,
    ) -> Result<(std::time::Instant, Arc<RuntimeInviteGate>), ClientLinkingError> {
        self.check_private_invite_attempt_scope(scope)?;
        let attempt = self
            .linking_owner
            .invite_attempt
            .as_ref()
            .filter(|attempt| attempt.proposal.is_some())
            .ok_or(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier,
            ))?;
        Ok((attempt.deadline, self.linking_owner.invite.clone()))
    }

    pub(crate) async fn dispatch_owned_enrollment_proposal(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.enrollment_proposal_control(scope)?;
        self.refresh_private_transport_route()
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        self.sync_runtime_groups()
            .await
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        let attempt = self.linking_owner.invite_attempt.as_mut().unwrap();
        let proposal = attempt.proposal.as_mut().unwrap();
        let message = self
            .runtime
            .session_mut()
            .wrap_private_enrollment_proposal(proposal)
            .await
            .map_err(ClientLinkingError::Engine)?;
        let component = self
            .runtime
            .session()
            .app_component(&attempt.group, crate::NOSTR_ROUTING_COMPONENT_ID)
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error.into())))?
            .ok_or(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
            ))?;
        let route =
            cgka_traits::app_components::decode_nostr_routing_v1(&component).map_err(|_| {
                ClientLinkingError::Gate(
                    cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
                )
            })?;
        proposal
            .binding_digest()
            .map_err(ClientLinkingError::Engine)?;
        let report = self
            .adapter
            .publish_private_enrollment_proposal(
                cgka_traits::transport_adapter::TransportPublishRequest {
                    account_id: self.runtime.session().self_id(),
                    message,
                    target: cgka_traits::TransportPublishTarget::Group {
                        group_id: attempt.group.clone(),
                        transport_group_id: route.nostr_group_id.to_vec(),
                        endpoints: route
                            .relays
                            .into_iter()
                            .map(cgka_traits::TransportEndpoint)
                            .collect(),
                    },
                    required_acks: 1,
                },
            )
            .await
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error.into())))?;
        proposal
            .binding_digest()
            .map_err(ClientLinkingError::Engine)?;
        if !report.met_required_acks() {
            return Err(ClientLinkingError::Engine(cgka_traits::EngineError::Other(
                "private proposal publication uncertain".into(),
            )));
        }
        self.native_proposal_published(scope);
        Ok(())
    }

    fn check_private_invite_attempt_scope(
        &self,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        if let Some(attempt) = self.linking_owner.invite_attempt.as_ref() {
            // Only this original SDK-owned continuation may outlive the
            // verifier reservation. Reject caller scope substitutions before
            // any gate or storage mutation; metadata cannot construct it.
            if attempt.scope != *scope {
                return Err(ClientLinkingError::Gate(
                    cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
                ));
            }
            self.linking_owner
                .verifier
                .check_retained_invite_scope(scope)
        } else {
            self.linking_owner.verifier.check_scope(scope)
        }
        .map_err(ClientLinkingError::Owner)
    }

    fn retire_owned_private_invite(&mut self) -> Result<(), ClientLinkingError> {
        if let Some(attempt) = self.linking_owner.invite_attempt.as_ref() {
            if let Some(prepared) = attempt.prepared.as_ref() {
                self.runtime
                    .session_mut()
                    .finish_interrupted_private_device_invite(prepared)
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
            self.linking_owner.native_enrollment = None;
        }
        Ok(())
    }

    /// Inspect the existing opaque lease directly in a test actor, even when
    /// storage is unavailable. This is not compiled into native/release APIs.
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn check_owned_private_commit_permission_for_test(
        &mut self,
    ) -> Result<(), ClientLinkingError> {
        self.linking_owner
            .invite_attempt
            .as_mut()
            .and_then(|attempt| attempt.prepared.as_mut())
            .ok_or(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier,
            ))?
            .check_live_permission()
            .map_err(ClientLinkingError::Gate)
    }

    /// Actor-only negative control metadata; neither the lease nor transport leaves the owner.
    pub(crate) fn private_commit_control(
        &self,
        scope: &PurposeAttemptScope,
    ) -> Result<(std::time::Instant, Arc<RuntimeInviteGate>), ClientLinkingError> {
        self.check_private_invite_attempt_scope(scope)?;
        let attempt = self
            .linking_owner
            .invite_attempt
            .as_ref()
            .filter(|attempt| attempt.prepared.is_some())
            .ok_or(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier,
            ))?;
        Ok((attempt.deadline, self.linking_owner.invite.clone()))
    }
    pub(crate) fn finish_private_commit_interruption(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.check_private_invite_attempt_scope(scope)?;
        self.linking_owner.native_enrollment = None;
        self.linking_owner.received_enrollment_proposals.clear();
        self.linking_owner.invite.cancel();
        self.retire_owned_private_invite()
    }
    pub(crate) async fn dispatch_owned_private_commit(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.check_private_invite_attempt_scope(scope)?;
        self.refresh_private_transport_route()
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        self.sync_runtime_groups()
            .await
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        // Read only the authenticated transport component; do not promote this
        // private group into an ordinary chat projection. The normal adapter
        // still applies account/relay safety and envelope-target checks.
        let group = self
            .linking_owner
            .invite_attempt
            .as_ref()
            .unwrap()
            .group
            .clone();
        let component = self
            .runtime
            .session()
            .app_component(&group, crate::NOSTR_ROUTING_COMPONENT_ID)
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error.into())))?
            .ok_or(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
            ))?;
        let route =
            cgka_traits::app_components::decode_nostr_routing_v1(&component).map_err(|_| {
                ClientLinkingError::Gate(
                    cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
                )
            })?;
        let target = cgka_traits::TransportPublishTarget::Group {
            group_id: group,
            transport_group_id: route.nostr_group_id.to_vec(),
            endpoints: route
                .relays
                .into_iter()
                .map(cgka_traits::TransportEndpoint)
                .collect(),
        };
        let publisher = PrivateCommitPublisher {
            adapter: self.adapter.clone(),
            target,
            account: self.runtime.session().self_id(),
        };
        let revocation = self.linking_owner.invite.clone();
        let attempt = self.linking_owner.invite_attempt.as_mut().unwrap();
        let prepared = attempt.prepared.as_mut().ok_or(ClientLinkingError::Gate(
            cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier,
        ))?;
        let result = self
            .runtime
            .session_mut()
            .dispatch_prepared_private_device_invite(prepared, &publisher)
            .await
            .map_err(ClientLinkingError::PrivateInvite);
        // Success means only an attempted network publication, never membership
        // confirmation or delivery permission. Storage errors keep the exact owner.
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|error| {
                revocation.cancel();
                ClientLinkingError::Runtime(Box::new(error))
            })?;
        let phase = cgka_traits::StorageProvider::private_device_invite_storage(&storage)
            .ok_or_else(|| {
                revocation.cancel();
                ClientLinkingError::Gate(cgka_traits::device_linking_key_package::LinkingWelcomeDenied::UnsupportedStorage)
            })?
            .private_invite()
            .map_err(|error| {
                // An unreadable phase may already represent a real side effect.
                // Revoke memory permission but retain exact cleanup ownership;
                // never guess that the pending MLS commit can be retired.
                revocation.cancel();
                ClientLinkingError::PrivateInvite(error.into())
            })?
            .filter(|fact| fact.scope == *prepared.scope())
            .map(|fact| fact.phase);
        // Keep only the original opaque continuation through uncertainty and
        // genuine confirmation. Neither phase grants Welcome delivery; that
        // operation must independently validate the exact confirmed successor.
        // Cancellation/expiry/reply loss still revoke this same original lease.
        if !matches!(
            phase,
            Some(
                cgka_traits::private_device_invite::PrivateInvitePhase::Wrapped
                    | cgka_traits::private_device_invite::PrivateInvitePhase::Dispatching
                    | cgka_traits::private_device_invite::PrivateInvitePhase::PublicationUnknown
                    | cgka_traits::private_device_invite::PrivateInvitePhase::Confirmed
            )
        ) {
            self.linking_owner.received_enrollment_proposals.clear();
            self.linking_owner.invite.cancel();
            self.retire_owned_private_invite()?;
        }
        result
    }

    pub(crate) async fn dispatch_owned_private_welcomes(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        self.check_private_invite_attempt_scope(scope)?;
        let attempt =
            self.linking_owner
                .invite_attempt
                .as_ref()
                .ok_or(ClientLinkingError::Gate(
                    cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier,
                ))?;
        let component = self
            .runtime
            .session()
            .app_component(&attempt.group, crate::NOSTR_ROUTING_COMPONENT_ID)
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error.into())))?
            .ok_or(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
            ))?;
        let route =
            cgka_traits::app_components::decode_nostr_routing_v1(&component).map_err(|_| {
                ClientLinkingError::Gate(
                    cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
                )
            })?;
        let account = self.runtime.session().self_id();
        let publisher = PrivateWelcomePublisher {
            adapter: self.adapter.clone(),
            account: account.clone(),
            target: cgka_traits::TransportPublishTarget::Inbox {
                recipient: account,
                endpoints: route
                    .relays
                    .into_iter()
                    .map(cgka_traits::TransportEndpoint)
                    .collect(),
            },
        };
        let prepared = self
            .linking_owner
            .invite_attempt
            .as_mut()
            .unwrap()
            .prepared
            .as_mut()
            .ok_or(ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::NoLiveVerifier,
            ))?;
        let result = self
            .runtime
            .session_mut()
            .dispatch_confirmed_private_welcomes(prepared, &publisher)
            .await
            .map_err(ClientLinkingError::PrivateInvite);
        if result.is_ok() {
            self.native_welcomes_published(scope);
        }
        result
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
        // MAINTENANCE_PHASE_GROUP_0_BEGIN
        #[cfg(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides"))]
        crate::maintenance_phase_diagnostics::observe_phase(0, Box::pin(async {
        self.maintain_selected_chat_packages()
            .map_err(ClientLinkingError::Engine)?;
        self.maintain_selected_chat_pending()
            .await
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error.into())))?;
            Ok::<(), ClientLinkingError>(())
        })).await?;
        #[cfg(not(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides")))]
        {
        self.maintain_selected_chat_packages()
            .map_err(ClientLinkingError::Engine)?;
        self.maintain_selected_chat_pending()
            .await
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error.into())))?;
        }
        // MAINTENANCE_PHASE_GROUP_0_END
        // MAINTENANCE_PHASE_GROUP_1_BEGIN
        #[cfg(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides"))]
        crate::maintenance_phase_diagnostics::observe_phase(1, Box::pin(async {
        self.maintain_device_leaf_revocation_pending()
            .await
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error.into())))?;
            Ok::<(), ClientLinkingError>(())
        })).await?;
        #[cfg(not(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides")))]
        {
        self.maintain_device_leaf_revocation_pending()
            .await
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error.into())))?;
        }
        // MAINTENANCE_PHASE_GROUP_1_END
        // MAINTENANCE_PHASE_GROUP_2_BEGIN
        #[cfg(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides"))]
        crate::maintenance_phase_diagnostics::observe_phase(2, Box::pin(async {
        self.maintain_original_history().await.map_err(|_| {
            ClientLinkingError::Runtime(Box::new(crate::AppError::InvalidAppMessagePayload(
                "history original maintenance unavailable".into(),
            )))
        })?;
            Ok::<(), ClientLinkingError>(())
        })).await?;
        #[cfg(not(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides")))]
        {
        self.maintain_original_history().await.map_err(|_| {
            ClientLinkingError::Runtime(Box::new(crate::AppError::InvalidAppMessagePayload(
                "history original maintenance unavailable".into(),
            )))
        })?;
        }
        // MAINTENANCE_PHASE_GROUP_2_END
        // MAINTENANCE_PHASE_GROUP_3_BEGIN
        #[cfg(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides"))]
        crate::maintenance_phase_diagnostics::observe_phase(3, Box::pin(async {
        self.maintain_existing_pair_sharing().map_err(|_| {
            ClientLinkingError::Runtime(Box::new(crate::AppError::InvalidAppMessagePayload(
                "account sharing original maintenance unavailable".into(),
            )))
        })?;
        self.persist_completed_pair_sharing_approval()?;
            Ok::<(), ClientLinkingError>(())
        })).await?;
        #[cfg(not(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides")))]
        {
        self.maintain_existing_pair_sharing().map_err(|_| {
            ClientLinkingError::Runtime(Box::new(crate::AppError::InvalidAppMessagePayload(
                "account sharing original maintenance unavailable".into(),
            )))
        })?;
        self.persist_completed_pair_sharing_approval()?;
        }
        // MAINTENANCE_PHASE_GROUP_3_END
        // MAINTENANCE_PHASE_GROUP_4_BEGIN
        #[cfg(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides"))]
        crate::maintenance_phase_diagnostics::observe_phase(4, Box::pin(async {
        self.maintain_sibling_sharing().await?;
            Ok::<(), ClientLinkingError>(())
        })).await?;
        #[cfg(not(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides")))]
        {
        self.maintain_sibling_sharing().await?;
        }
        // MAINTENANCE_PHASE_GROUP_4_END
        #[cfg(all(test, feature = "test-policy-overrides"))]
        let observer = self.linking_owner.sharing_approval.clone();
        // MAINTENANCE_PHASE_GROUP_5_BEGIN
        #[cfg(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides"))]
        crate::maintenance_phase_diagnostics::observe_phase(5, Box::pin(async {
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(observer) = &observer {
            observer.record_observation_stage_for_test(
                sibling_sharing::NativeObservationStage::AutomaticEntered,
            );
        }
        let automatic = self.maintain_automatic_account_sharing().await;
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(observer) = &observer {
            observer.record_observation_stage_for_test(
                sibling_sharing::NativeObservationStage::AutomaticExited,
            );
        }
        automatic.map_err(|_| {
            ClientLinkingError::Runtime(Box::new(crate::AppError::InvalidAppMessagePayload(
                "automatic sharing maintenance unavailable".into(),
            )))
        })?;
            Ok::<(), ClientLinkingError>(())
        })).await?;
        #[cfg(not(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides")))]
        {
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(observer) = &observer {
            observer.record_observation_stage_for_test(
                sibling_sharing::NativeObservationStage::AutomaticEntered,
            );
        }
        let automatic = self.maintain_automatic_account_sharing().await;
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(observer) = &observer {
            observer.record_observation_stage_for_test(
                sibling_sharing::NativeObservationStage::AutomaticExited,
            );
        }
        automatic.map_err(|_| {
            ClientLinkingError::Runtime(Box::new(crate::AppError::InvalidAppMessagePayload(
                "automatic sharing maintenance unavailable".into(),
            )))
        })?;
        }
        // MAINTENANCE_PHASE_GROUP_5_END
        // MAINTENANCE_PHASE_GROUP_6_BEGIN
        #[cfg(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides"))]
        crate::maintenance_phase_diagnostics::observe_phase(6, Box::pin(async {
        self.prune_native_enrollment_intent();
        self.maintain_received_enrollment_endorsement(now)?;
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
        if !approval_live {
            self.clear_private_welcome_collection();
        }
        if approval_live && self.linking_owner.welcome_collection.has_complete() {
            let scope = self
                .linking_owner
                .verifier
                .unjoined_purpose_scope()
                .map_err(ClientLinkingError::Owner)?
                .ok_or(ClientLinkingError::Collection(CollectionError::Denied))?;
            self.join_collected_private_device_welcome(&scope).await?;
            self.refresh_group_routes()
                .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
            self.save_state_with_pending_local_group_deletion_frontier_clears()
                .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        }
        if self
            .linking_owner
            .invite_attempt
            .as_ref()
            .is_some_and(|attempt| now >= attempt.deadline)
        {
            // Housekeeping may revoke early but can never extend the original
            // deadline or issue a positive dispatch permission.
            self.linking_owner.received_enrollment_proposals.clear();
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
            None => match self
                .linking_owner
                .invite_attempt
                .as_mut()
                .and_then(|attempt| attempt.proposal.as_mut())
            {
                Some(proposal) => proposal.binding_digest().is_ok(),
                None => self
                    .linking_owner
                    .invite
                    .maintain()
                    .map_err(ClientLinkingError::Gate)?,
            },
        };
        if !invite_live {
            self.retire_owned_private_invite()?;
        }
        if !reservation_live && !approval_live && !invite_live {
            // Retry cleanup after transient storage failure without restoring
            // an expired verifier or approval from a durable terminal fact.
            self.retire_unjoined_device_linking().await?;
        }
            Ok::<(), ClientLinkingError>(())
        })).await?;
        #[cfg(not(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides")))]
        {
        self.prune_native_enrollment_intent();
        self.maintain_received_enrollment_endorsement(now)?;
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
        if !approval_live {
            self.clear_private_welcome_collection();
        }
        if approval_live && self.linking_owner.welcome_collection.has_complete() {
            let scope = self
                .linking_owner
                .verifier
                .unjoined_purpose_scope()
                .map_err(ClientLinkingError::Owner)?
                .ok_or(ClientLinkingError::Collection(CollectionError::Denied))?;
            self.join_collected_private_device_welcome(&scope).await?;
            self.refresh_group_routes()
                .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
            self.save_state_with_pending_local_group_deletion_frontier_clears()
                .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        }
        if self
            .linking_owner
            .invite_attempt
            .as_ref()
            .is_some_and(|attempt| now >= attempt.deadline)
        {
            // Housekeeping may revoke early but can never extend the original
            // deadline or issue a positive dispatch permission.
            self.linking_owner.received_enrollment_proposals.clear();
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
            None => match self
                .linking_owner
                .invite_attempt
                .as_mut()
                .and_then(|attempt| attempt.proposal.as_mut())
            {
                Some(proposal) => proposal.binding_digest().is_ok(),
                None => self
                    .linking_owner
                    .invite
                    .maintain()
                    .map_err(ClientLinkingError::Gate)?,
            },
        };
        if !invite_live {
            self.retire_owned_private_invite()?;
        }
        if !reservation_live && !approval_live && !invite_live {
            // Retry cleanup after transient storage failure without restoring
            // an expired verifier or approval from a durable terminal fact.
            self.retire_unjoined_device_linking().await?;
        }
        }
        // MAINTENANCE_PHASE_GROUP_6_END
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
        self.linking_owner.native_setup_request = None;
        self.linking_owner.native_enrollment = None;
        self.linking_owner.pairing_metadata = None;
        self.linking_owner.approval_pairing_metadata = None;
        if let Some(choice) = &self.linking_owner.sharing_approval {
            choice.cancel();
        }
        self.linking_owner.sharing_approval = None;
        self.linking_owner.recipient_enrollment = None;
        // Revoke admission before terminal fencing or private deletion. The
        // serial owner must not retire a package while its join lease is busy.
        if let Some(attempt) = &self.linking_owner.settlement_attempt {
            attempt.guard.revoke();
        }
        let endorsement_cancel = self.cancel_owned_enrollment_endorsement();
        self.linking_owner.received_enrollment_proposals.clear();
        self.linking_owner.invite.cancel();
        let welcome_cancel = self
            .linking_owner
            .welcome
            .cancel()
            .map_err(ClientLinkingError::Gate);
        self.clear_private_welcome_collection();
        // finish drops verifier secrets before its own durable write. Perform
        // every memory revocation even if one durable fence subsequently fails.
        let verifier_cancel = self
            .linking_owner
            .verifier
            .cancel()
            .map_err(ClientLinkingError::Owner);
        let settlement_cancel = self.revoke_owned_private_settlement();
        endorsement_cancel?;
        welcome_cancel?;
        settlement_cancel?;
        verifier_cancel?;
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

/// Actual account adapter publication of the one Engine-selected cached commit.
struct PrivateCommitPublisher {
    adapter: crate::relay_plane::MarmotRelayPlaneAccountAdapter,
    target: cgka_traits::TransportPublishTarget,
    account: MemberId,
}
#[async_trait::async_trait]
impl cgka_engine::private_device_invite::TrustedPrivateInvitePublisher for PrivateCommitPublisher {
    async fn publish_commit(
        &self,
        commit: &cgka_traits::TransportMessage,
    ) -> Result<(), cgka_traits::EngineError> {
        use cgka_traits::transport_adapter::TransportPublishRequest;
        let target = self.target.clone();
        let required_acks = 1;
        let report = self
            .adapter
            .publish_private_commit(TransportPublishRequest {
                account_id: self.account.clone(),
                message: commit.clone(),
                target,
                required_acks,
            })
            .await
            .map_err(|_| {
                cgka_traits::EngineError::Other("private commit publication uncertain".into())
            })?;
        if !report.met_required_acks() {
            return Err(cgka_traits::EngineError::Other(
                "private commit publication uncertain".into(),
            ));
        }
        Ok(())
    }
}

impl AppClient {
    pub(crate) async fn collect_private_device_welcome(
        &mut self,
        scope: &PurposeAttemptScope,
        message: cgka_traits::transport::TransportMessage,
    ) -> Result<Option<cgka_traits::GroupId>, ClientLinkingError> {
        self.scoped_linking_verifier(scope)?;
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        let purpose =
            actual_recipient_purpose(&storage, scope).map_err(ClientLinkingError::Collection)?;
        let gate = self.linking_owner.welcome.clone();
        let session = self.runtime.session();
        let observation = async {
            let observed = session
                .observe_private_linking_welcome(&message)
                .await
                .map_err(|_| CollectionError::InvalidTransport)?;
            // Read actual durable purpose after authentication, before buffering.
            // Storage failure preserves retry but admits no stale chunk.
            if actual_recipient_purpose(&storage, scope)? != purpose {
                return Err(CollectionError::Denied);
            }
            Ok(observed)
        };
        let complete = self
            .linking_owner
            .welcome_collection
            .observe_with(&gate, &purpose, &message, observation)
            .await
            .map_err(ClientLinkingError::Collection)?;
        if !complete {
            return Ok(None);
        }
        self.join_collected_private_device_welcome(scope)
            .await
            .map(Some)
    }

    async fn join_collected_private_device_welcome(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<cgka_traits::GroupId, ClientLinkingError> {
        self.scoped_linking_verifier(scope)?;
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        let purpose =
            actual_recipient_purpose(&storage, scope).map_err(ClientLinkingError::Collection)?;
        let gate = self.linking_owner.welcome.clone();
        let batch = self
            .linking_owner
            .welcome_collection
            .complete_for_retry(&gate, &purpose)
            .map_err(ClientLinkingError::Collection)?
            .ok_or(ClientLinkingError::Collection(CollectionError::Denied))?;
        // Engine independently checks actual transport, tree and the same live
        // lease in its atomic SQL join. Failure retains only exact retry bytes.
        let group = if let Some(evidence) = self.linking_owner.recipient_enrollment.as_ref() {
            self.runtime
                .session_mut()
                .join_endorsed_private_linking_welcome_batch(
                    batch.messages,
                    &batch.context,
                    evidence,
                )
                .await
        } else {
            self.runtime
                .session_mut()
                .join_private_linking_welcome_batch(batch.messages, &batch.context)
                .await
        }
        .map_err(ClientLinkingError::Engine)?;
        if self.select_owned_private_settlement().is_err() {
            // The join already committed. Keep its original memory continuation
            // for bounded retry; controls remain hidden and uncounted meanwhile.
            tracing::debug!(target: "marmot_app::device_linking", method = "private_settlement_selection", "confirmation selection deferred after committed join");
        }
        self.clear_private_welcome_collection();
        Ok(group)
    }

    /// Retain only already-complete transport under the existing live gate after
    /// a typed Engine storage failure. This is negative reconnect scheduling;
    /// the next join must independently reread purpose and validate the lease.
    pub(crate) fn retain_private_welcome_after_storage_error(
        &mut self,
        error: &crate::AppError,
    ) -> bool {
        matches!(
            error.as_engine_error(),
            Some(cgka_traits::EngineError::Storage(_))
        ) && self.linking_owner.welcome_collection.has_complete()
            && self.linking_owner.welcome.maintain().unwrap_or(false)
    }

    fn clear_private_welcome_collection(&mut self) {
        // release_account_delivery only removes a still-held pin in this queue
        // generation; already released chunks have nothing to release. Joining
        // committed all receipts, or cancellation deliberately discards inputs.
        for id in self.linking_owner.welcome_collection.transport_ids() {
            self.adapter.release_account_delivery(&id);
        }
        self.linking_owner.welcome_collection.clear();
        self.linking_owner.recipient_enrollment = None;
    }
}

// Static error classes preserve backend failure without exposing database text.
// Actual records are negative scope fences, never membership/consent evidence.
fn actual_recipient_purpose(
    storage: &SqliteAccountStorage,
    scope: &PurposeAttemptScope,
) -> Result<PurposeKeyPackage, CollectionError> {
    let purpose = storage
        .device_linking_key_package_storage()
        .ok_or(CollectionError::Storage)?
        .purpose_key_package()
        .map_err(|_| CollectionError::Storage)?
        .ok_or(CollectionError::Denied)?;
    if purpose.scope != *scope || purpose.consumed {
        return Err(CollectionError::Denied);
    }
    Ok(purpose)
}

/// Private chunks remain fetchable until the complete batch commits atomically.
pub(crate) enum PrivateWelcomeIngress {
    Buffered,
    Joined,
}

impl AppClient {
    /// Only the live account-owned gate can route a chunk into its collector.
    /// None delegates to ordinary Engine admission, which independently verifies
    /// the ordinary rumor kind and rejects private profile/purpose bypasses.
    pub(crate) async fn try_collect_private_device_welcome(
        &mut self,
        message: &cgka_traits::TransportMessage,
    ) -> Result<Option<PrivateWelcomeIngress>, ClientLinkingError> {
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        let Some(capability) = storage.device_linking_key_package_storage() else {
            return Ok(None);
        };
        let Some(purpose) = capability
            .purpose_key_package()
            .map_err(|_| ClientLinkingError::Collection(CollectionError::Storage))?
        else {
            return Ok(None);
        };
        if purpose.consumed
            || self
                .linking_owner
                .welcome
                .collection_deadline(&purpose)
                .is_err()
        {
            return Ok(None);
        }
        // Private limits must precede cloning. A large ordinary Welcome may
        // exceed the private chunk bounds; delegate it to ordinary Engine
        // validation rather than applying this private profile's size policy.
        if crate::device_linking::welcome_collection::bound_transport(message).is_err() {
            return Ok(None);
        }
        match self
            .collect_private_device_welcome(&purpose.scope, message.clone())
            .await
        {
            Ok(Some(_)) => Ok(Some(PrivateWelcomeIngress::Joined)),
            Ok(None) => Ok(Some(PrivateWelcomeIngress::Buffered)),
            // The configured private observer rejects ordinary Welcomes. This
            // explicit fallback grants nothing: ordinary Engine ingest still
            // authenticates its own kind/profile and purpose policy. No valid
            // private observation with denied context/lease can take this path.
            Err(ClientLinkingError::Collection(CollectionError::InvalidTransport)) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

struct PrivateWelcomePublisher {
    adapter: crate::relay_plane::MarmotRelayPlaneAccountAdapter,
    target: cgka_traits::TransportPublishTarget,
    account: MemberId,
}
#[async_trait::async_trait]
impl cgka_engine::private_device_invite::TrustedPrivateWelcomePublisher
    for PrivateWelcomePublisher
{
    async fn publish_welcome(
        &self,
        welcome: &cgka_traits::TransportMessage,
    ) -> Result<(), cgka_traits::EngineError> {
        let report = self
            .adapter
            .publish_private_welcome(cgka_traits::transport_adapter::TransportPublishRequest {
                account_id: self.account.clone(),
                message: welcome.clone(),
                target: self.target.clone(),
                required_acks: 1,
            })
            .await
            .map_err(|_| {
                cgka_traits::EngineError::Other("private Welcome publication uncertain".into())
            })?;
        if !report.met_required_acks() {
            return Err(cgka_traits::EngineError::Other(
                "private Welcome publication uncertain".into(),
            ));
        }
        Ok(())
    }
}
