//! Trusted owned lease spanning crypto staging, async wrapping and dispatch.
use super::{AuthenticatedPrivateAdd, AuthenticatedPrivateInvite};
use crate::{Engine, provider::EngineOpenMlsProvider};
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::device_group_genesis::GenesisLeaf;
use cgka_traits::device_linking_key_package::{LinkingWelcomeDenied, PurposeAttemptScope};
use cgka_traits::engine::KeyPackage;
use cgka_traits::engine_state::{EpochState, PendingStateRef, StagedCommitHandle};
use cgka_traits::error::EngineError;
use cgka_traits::private_device_invite::*;
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::{EncryptedPayload, GroupId, TransportMessage};
use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use tls_codec::Serialize;

/// Immutable SDK-derived scope metadata. This never replaces the owned lease.
#[derive(Clone)]
pub struct PrivateInviteConsent {
    pub approver_scope: PurposeAttemptScope,
    pub recipient_generation: u64,
    pub origin: PrivateInviteOrigin,
    pub nonce: [u8; 32],
    pub context_digest: [u8; 32],
}
/// Retained original-owner metadata, supplied only through its live lease.
/// App owns canonical context validation; Core authenticates the actual artifact.
pub struct PrivateEnrollmentProposalMetadata {
    pub context_json: String,
    pub artifact_digest: [u8; 32],
    pub original_deadline: web_time::Instant,
}
/// Trusted account runtime supplies the opaque Approver SDK result, not a bool.
pub trait TrustedPrivateInvitePolicy: Send + Sync {
    fn begin_prepare(
        &self,
        actual: &AuthenticatedPrivateInvite,
    ) -> Result<Box<dyn PrivateInviteLease>, LinkingWelcomeDenied>;
}
/// Owns original deadline, generation and consent across all awaits. Callbacks
/// must not await, relock storage or perform network operations. Drop may restore
/// only the same still-live verifier before preparation_committed; afterwards it
/// must never restore consent. The same lease remains live through dispatch.
/// Sync preserves account-client shared read access/Send futures while the
/// actor exclusively mutates this opaque continuation through &mut methods.
pub trait PrivateInviteLease: Send + Sync {
    fn consent(&self) -> &PrivateInviteConsent;
    /// Only the original trusted owner can supply its retained context and clock.
    /// This metadata does not grant sibling approval or Add permission.
    fn enrollment_proposal_metadata(
        &mut self,
    ) -> Result<PrivateEnrollmentProposalMetadata, LinkingWelcomeDenied> {
        Err(LinkingWelcomeDenied::NoLiveVerifier)
    }

    fn check_staged(
        &mut self,
        actual: &AuthenticatedPrivateAdd,
    ) -> Result<(), LinkingWelcomeDenied>;
    fn check_live_before_commit(&mut self) -> Result<(), LinkingWelcomeDenied>;
    fn preparation_committed(&mut self, scope: &PrivateInviteScope);
}
#[derive(Debug, thiserror::Error)]
pub enum PrivateInviteError {
    #[error(transparent)]
    Engine(#[from] EngineError),
    #[error(transparent)]
    Storage(#[from] PrivateInviteStorageError),
    #[error(transparent)]
    Denied(#[from] LinkingWelcomeDenied),
}
impl From<StorageError> for PrivateInviteError {
    fn from(error: StorageError) -> Self {
        Self::Engine(error.into())
    }
}
/// No Clone/Serialize or transport accessor: publication requires this live lease.
pub struct PreparedPrivateDeviceInvite {
    scope: PrivateInviteScope,
    group_id: GroupId,
    pub(super) pending: PendingStateRef,
    lease: Box<dyn PrivateInviteLease>,
}
impl PreparedPrivateDeviceInvite {
    pub fn scope(&self) -> &PrivateInviteScope {
        &self.scope
    }
    /// Negative housekeeping check of this still-owned original lease. This
    /// result is not a publication permit; dispatch independently rechecks it.
    pub fn check_live_permission(&mut self) -> Result<(), LinkingWelcomeDenied> {
        self.lease.check_live_before_commit()
    }
}
/// Dedicated trusted publisher. Invoked only while the original lease is live;
/// the Welcome is never passed here. Restart cannot construct a dispatch permit.
#[async_trait::async_trait]
pub trait TrustedPrivateInvitePublisher: Send + Sync {
    async fn publish_commit(&self, commit: &TransportMessage) -> Result<(), EngineError>;
}
/// Dedicated frozen Welcome publisher. The Engine checks the original lease and
/// exact confirmed current successor before passing any cached transport here.
#[async_trait::async_trait]
pub trait TrustedPrivateWelcomePublisher: Send + Sync {
    async fn publish_welcome(&self, welcome: &TransportMessage) -> Result<(), EngineError>;
}
fn incompatible() -> PrivateInviteError {
    LinkingWelcomeDenied::ContextMismatch.into()
}
fn roster(
    input: &AuthenticatedPrivateInvite,
) -> Result<DeviceGroupAnchorRoster, PrivateInviteError> {
    let account = input
        .predecessor
        .account
        .as_slice()
        .try_into()
        .map_err(|_| incompatible())?;
    let leaves = input
        .predecessor
        .leaves
        .iter()
        .map(|leaf| {
            Ok(GenesisLeaf {
                account,
                leaf_index: leaf.leaf_index,
                signature_public_key: leaf
                    .signature_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| incompatible())?,
            })
        })
        .collect::<Result<Vec<_>, PrivateInviteError>>()?;
    Ok(DeviceGroupAnchorRoster {
        epoch: input.predecessor.epoch,
        epoch_authenticator_digest: input.predecessor.epoch_authenticator_digest,
        leaves,
    })
}
impl<S: StorageProvider> Engine<S> {
    /// Dedicated private preparation. Ordinary Invite/chat stay forbidden. Every
    /// raw MLS write and ledger insertion commit together; final transport is
    /// cached only in110 and cannot be retried by ordinary Sent replay.
    pub async fn prepare_private_device_invite(
        &mut self,
        group_id: &GroupId,
        package: KeyPackage,
    ) -> Result<PreparedPrivateDeviceInvite, PrivateInviteError> {
        let policy = self
            .private_invite_policy
            .clone()
            .ok_or(LinkingWelcomeDenied::NoLiveVerifier)?;
        let cap = self
            .storage
            .private_device_invite_storage()
            .ok_or(LinkingWelcomeDenied::UnsupportedStorage)?;
        let prior = cap.private_invite()?;
        let retry = prior.filter(|row| {
            row.phase != PrivateInvitePhase::Retired && row.phase != PrivateInvitePhase::Confirmed
        });
        if retry.as_ref().is_some_and(|row| {
            row.phase != PrivateInvitePhase::RawStaged || &row.raw.binding.group_id != group_id
        }) {
            return Err(PrivateInviteStorageError::Busy.into());
        }
        if !matches!(
            self.epoch_manager.state(group_id),
            Some(EpochState::Stable { .. })
        ) {
            return Err(incompatible());
        }
        let input = if let Some(row) = &retry {
            if Sha256::digest(package.bytes()).as_slice() != row.raw.binding.key_package_digest {
                return Err(incompatible());
            }
            self.invite_key_package_requirements(group_id)?
                .validate(&package)?;
            let parsed = self.parse_key_package(&package)?;
            let mut predecessor = crate::device_group_snapshot::CandidateDeviceGroupSnapshot {
                account: self.identity.self_id().clone(),
                group_id: group_id.clone(),
                epoch: row.raw.binding.predecessor.epoch,
                epoch_authenticator_digest: row.raw.binding.predecessor.epoch_authenticator_digest,
                leaves: row
                    .raw
                    .binding
                    .predecessor
                    .leaves
                    .iter()
                    .map(|l| crate::device_group_snapshot::CandidateDeviceLeaf {
                        leaf_index: l.leaf_index,
                        signature_public_key: l.signature_public_key.to_vec(),
                    })
                    .collect(),
                roster_commitment: [0; 32],
            };
            predecessor.roster_commitment = crate::device_group_snapshot::commitment(&predecessor);
            let own_leaf_index =
                self.with_mls_group(group_id, |group| Ok(group.own_leaf_index().u32()))?;
            AuthenticatedPrivateInvite {
                predecessor,
                own_leaf_index,
                exact_key_package: package.clone(),
                key_package_reference: parsed
                    .hash_ref(&self.crypto)
                    .map_err(|_| incompatible())?
                    .as_slice()
                    .try_into()
                    .map_err(|_| incompatible())?,
                recipient_account: crate::identity::validated_member_id_of_leaf(
                    parsed.leaf_node(),
                )?,
                recipient_signature_public_key: parsed
                    .leaf_node()
                    .signature_key()
                    .as_slice()
                    .try_into()
                    .map_err(|_| incompatible())?,
            }
        } else {
            self.validate_private_invite_input(group_id, &package)?
        };
        let mut lease = policy.begin_prepare(&input)?;
        lease.check_live_before_commit()?;
        let consent = lease.consent().clone();
        if consent.approver_scope.account.as_slice() != self.identity.self_id().as_slice()
            || consent.approver_scope.local_device.as_slice() != self.identity.signer.public()
        {
            return Err(incompatible());
        }
        let (fact, ctx) =
            self.storage
                .with_transaction(|storage| -> Result<_, PrivateInviteError> {
                    let provider =
                        EngineOpenMlsProvider::<S>::new(&self.crypto, storage.mls_storage());
                    let mut group = MlsGroup::load(
                        provider.storage(),
                        &openmls::group::GroupId::from_slice(group_id.as_slice()),
                    )
                    .map_err(|_| EngineError::Backend("private MLS storage load failed".into()))?
                    .ok_or_else(incompatible)?;
                    let ctx =
                        crate::group_lifecycle::build_group_context_snapshot(&group, &provider)?;
                    let fact = if let Some(row) = &retry {
                        let actual = self.validate_private_staged_add(
                            &group,
                            group.pending_commit().ok_or_else(incompatible)?,
                            &input,
                        )?;
                        lease.check_staged(&actual)?;
                        let b = &row.raw.binding;
                        if b.approver_scope != consent.approver_scope
                            || b.recipient_generation != consent.recipient_generation
                            || b.origin != consent.origin
                            || b.nonce != consent.nonce
                            || b.context_digest != consent.context_digest
                            || b.successor != actual.successor
                            || b.predecessor != roster(&input)?
                        {
                            return Err(incompatible());
                        }
                        storage
                            .private_device_invite_storage()
                            .ok_or(LinkingWelcomeDenied::UnsupportedStorage)?
                            .stage_private_invite(&row.raw)?
                    } else {
                        if group.pending_commit().is_some() {
                            return Err(incompatible());
                        }
                        let bundle = group
                            .commit_builder()
                            .consume_proposal_store(false)
                            .propose_adds([self.parse_key_package(&package)?])
                            .load_psks(provider.storage())
                            .map_err(|_| {
                                EngineError::Backend("private MLS PSK load failed".into())
                            })?
                            .build(
                                provider.rand(),
                                provider.crypto(),
                                &self.identity.signer,
                                |_| true,
                            )
                            .map_err(|_| {
                                EngineError::Backend(
                                    "private MLS commit construction failed".into(),
                                )
                            })?
                            .stage_commit(&provider)
                            .map_err(|_| {
                                EngineError::Backend("private MLS pending stage failed".into())
                            })?;
                        let actual = self.validate_private_staged_add(
                            &group,
                            group.pending_commit().ok_or_else(incompatible)?,
                            &input,
                        )?;
                        lease.check_staged(&actual)?;
                        let commit = bundle.commit().tls_serialize_detached().map_err(|_| {
                            EngineError::Serialize(
                                "private MLS artifact serialization failed".into(),
                            )
                        })?;
                        let welcome = bundle
                            .to_welcome_msg()
                            .ok_or_else(incompatible)?
                            .tls_serialize_detached()
                            .map_err(|_| {
                                EngineError::Serialize(
                                    "private MLS artifact serialization failed".into(),
                                )
                            })?;
                        let raw = PrivateInviteRawDraft {
                            binding: PrivateInviteBinding {
                                format_version: 1,
                                approver_scope: consent.approver_scope.clone(),
                                recipient_generation: consent.recipient_generation,
                                origin: consent.origin.clone(),
                                group_id: group_id.clone(),
                                recipient: input.recipient_signature_public_key,
                                nonce: consent.nonce,
                                context_digest: consent.context_digest,
                                key_package_reference: input.key_package_reference,
                                key_package_digest: Sha256::digest(package.bytes()).into(),
                                commit_digest: Sha256::digest(&commit).into(),
                                welcome_digest: Sha256::digest(&welcome).into(),
                                predecessor: roster(&input)?,
                                successor: actual.successor,
                            },
                            commit,
                            welcome,
                        };
                        storage
                            .private_device_invite_storage()
                            .ok_or(LinkingWelcomeDenied::UnsupportedStorage)?
                            .stage_private_invite(&raw)?
                    };
                    lease.check_live_before_commit()?;
                    Ok((fact, ctx))
                })?;
        let final_result = async {
            let commit = self
                .peeler
                .wrap_group_message(
                    &EncryptedPayload {
                        ciphertext: fact.raw.commit.clone(),
                        aad: vec![],
                    },
                    &ctx,
                )
                .await
                .map_err(EngineError::Peeler)?;
            let commit = crate::message_processor::route_wrapped_group_message(commit, &ctx);
            let payload = EncryptedPayload {
                ciphertext: fact.raw.welcome.clone(),
                aad: vec![],
            };
            let binding = &fact.raw.binding;
            let context = cgka_traits::peeler::PrivateLinkingWelcomeContext {
                account: binding.approver_scope.account,
                approver: binding.approver_scope.local_device,
                recipient: binding.recipient,
                approver_generation: binding.approver_scope.generation,
                recipient_generation: binding.recipient_generation,
                group_id: binding.group_id.clone(),
                nonce: binding.nonce,
                context_digest: binding.context_digest,
                key_package_reference: binding.key_package_reference,
                key_package_digest: binding.key_package_digest,
                commit_digest: binding.commit_digest,
                welcome_digest: binding.welcome_digest,
            };
            let welcomes = self
                .peeler
                .wrap_private_linking_welcome(&payload, &context)
                .await
                .map_err(EngineError::Peeler)?;
            let transport = PrivateInviteTransport { commit, welcomes };
            self.storage
                .with_transaction(|storage| -> Result<_, PrivateInviteError> {
                    let provider =
                        EngineOpenMlsProvider::<S>::new(&self.crypto, storage.mls_storage());
                    let group = MlsGroup::load(
                        provider.storage(),
                        &openmls::group::GroupId::from_slice(group_id.as_slice()),
                    )
                    .map_err(|_| EngineError::Backend("private MLS storage load failed".into()))?
                    .ok_or_else(incompatible)?;
                    let actual = self.validate_private_staged_add(
                        &group,
                        group.pending_commit().ok_or_else(incompatible)?,
                        &input,
                    )?;
                    if actual.successor != fact.raw.binding.successor {
                        return Err(incompatible());
                    }
                    lease.check_staged(&actual)?;
                    storage
                        .private_device_invite_storage()
                        .ok_or(LinkingWelcomeDenied::UnsupportedStorage)?
                        .cache_private_invite_transport(&fact.scope, &transport)?;
                    lease.check_live_before_commit()?;
                    Ok(())
                })?;
            Ok::<(), PrivateInviteError>(())
        }
        .await;
        if let Err(error) = final_result {
            // Storage/peeler failure retains the exact raw draft for the same
            // still-live verification retry. Terminal consent cannot strand it.
            let denial = match error {
                PrivateInviteError::Denied(denial) => Some(denial),
                _ => lease.check_live_before_commit().err(),
            };
            if let Some(denial) = denial {
                self.retire_private_invite_pending(&fact.scope, group_id)?;
                return Err(denial.into());
            }
            return Err(error);
        }
        // Logical consumption is the first infallible memory action after SQL.
        // Exclusive &mut Engine retains the Stable state checked before awaits;
        // EpochState::begin_pending rejects only non-Stable, so the subsequent
        // owner transition cannot fail under this guarded state/ownership.
        lease.preparation_committed(&fact.scope);
        let pending = self.epoch_manager.next_pending_ref();
        self.epoch_manager.begin_pending(
            group_id.clone(),
            input.predecessor.epoch,
            fact.raw.binding.successor.epoch,
            StagedCommitHandle::from_bytes(group_id.as_slice().to_vec()),
            pending,
            crate::epoch_manager::PendingKind::GroupEvolution,
            self.current_audit_context.clone(),
        )?;
        Ok(PreparedPrivateDeviceInvite {
            scope: fact.scope,
            group_id: group_id.clone(),
            pending,
            lease,
        })
    }
    fn retire_private_invite_pending(
        &self,
        scope: &PrivateInviteScope,
        group_id: &GroupId,
    ) -> Result<(), PrivateInviteError> {
        self.storage
            .with_transaction(|storage| -> Result<_, PrivateInviteError> {
                let cap = storage
                    .private_device_invite_storage()
                    .ok_or(LinkingWelcomeDenied::UnsupportedStorage)?;
                let fact = cap.private_invite()?.ok_or_else(incompatible)?;
                if &fact.scope != scope
                    || &fact.raw.binding.group_id != group_id
                    || scope.account.as_slice() != self.identity.self_id().as_slice()
                    || scope.local_device.as_slice() != self.identity.signer.public()
                {
                    return Err(incompatible());
                }
                let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, storage.mls_storage());
                let mut group = MlsGroup::load(
                    provider.storage(),
                    &openmls::group::GroupId::from_slice(group_id.as_slice()),
                )
                .map_err(|_| EngineError::Backend("private pending storage load failed".into()))?
                .ok_or_else(incompatible)?;
                let staged = group.pending_commit().ok_or_else(incompatible)?;
                if !crate::device_group_genesis::exact_profile(&group)?
                    || group.epoch().as_u64() != fact.raw.binding.predecessor.epoch.0
                    || <[u8; 32]>::from(Sha256::digest(group.epoch_authenticator().as_slice()))
                        != fact.raw.binding.predecessor.epoch_authenticator_digest
                    || staged.epoch().as_u64() != fact.raw.binding.successor.epoch.0
                    || <[u8; 32]>::from(Sha256::digest(
                        staged
                            .epoch_authenticator()
                            .ok_or_else(incompatible)?
                            .as_slice(),
                    )) != fact.raw.binding.successor.epoch_authenticator_digest
                {
                    return Err(incompatible());
                }
                cap.retire_undispatched_private_invite(scope)?;
                group
                    .clear_pending_commit(provider.storage())
                    .map_err(|_| {
                        EngineError::Backend("private pending storage clear failed".into())
                    })?;
                Ok(())
            })?;
        self.mls_group_cache.forget_group(group_id);
        Ok(())
    }
    /// Negative cleanup before an opaque prepared continuation exists. Terminal
    /// history is untouched; active work must belong to this exact attempt.
    pub fn retire_unprepared_private_device_invite(
        &mut self,
        attempt: &PurposeAttemptScope,
    ) -> Result<bool, PrivateInviteError> {
        self.storage
            .with_transaction(|storage| -> Result<_, PrivateInviteError> {
                let cap = storage
                    .private_device_invite_storage()
                    .ok_or(LinkingWelcomeDenied::UnsupportedStorage)?;
                let Some(fact) = cap.private_invite()? else {
                    return Ok(false);
                };
                if matches!(
                    fact.phase,
                    PrivateInvitePhase::Retired | PrivateInvitePhase::Confirmed
                ) {
                    return Ok(false);
                }
                if fact.raw.binding.approver_scope != *attempt {
                    return Err(LinkingWelcomeDenied::ContextMismatch.into());
                }
                if fact.phase != PrivateInvitePhase::RawStaged {
                    return Err(PrivateInviteStorageError::Busy.into());
                }
                self.retire_private_invite_pending(&fact.scope, &fact.raw.binding.group_id)?;
                Ok(true)
            })
    }
    /// Only undispatched work can be atomically cancelled. Uncertainty remains
    /// blocked for actual transport/convergence reconciliation, never presumed failed.
    pub fn cancel_prepared_private_device_invite(
        &mut self,
        prepared: PreparedPrivateDeviceInvite,
    ) -> Result<(), PrivateInviteError> {
        self.retire_prepared_private_device_invite(&prepared)
    }
    /// Borrowed negative cleanup lets the actor retain its opaque continuation
    /// after a typed SQL failure and retry. It never schedules or grants access.
    pub fn retire_prepared_private_device_invite(
        &mut self,
        prepared: &PreparedPrivateDeviceInvite,
    ) -> Result<(), PrivateInviteError> {
        if self
            .epoch_manager
            .group_for_pending(prepared.pending)
            .as_ref()
            != Some(&prepared.group_id)
        {
            return Err(EngineError::UnknownPending.into());
        }
        self.retire_private_invite_pending(&prepared.scope, &prepared.group_id)?;
        self.epoch_manager.rollback_publish(prepared.pending)?;
        Ok(())
    }
    /// Marks intent before a real trusted network invocation while holding the
    /// same original-deadline lease. No ordinary replay row is produced. Any
    /// attempted/uncertain publication remains blocked until reconciliation.
    /// Borrow the actor-owned continuation so a pre-intent SQL failure preserves
    /// its original live lease for exact retry. Durable intent forbids redispatch.
    pub async fn dispatch_prepared_private_device_invite(
        &mut self,
        prepared: &mut PreparedPrivateDeviceInvite,
        publisher: &dyn TrustedPrivateInvitePublisher,
    ) -> Result<(), PrivateInviteError> {
        if let Err(error) = prepared.lease.check_live_before_commit() {
            self.retire_prepared_private_device_invite(prepared)?;
            return Err(error.into());
        }
        let fact_result =
            self.storage
                .with_transaction(|storage| -> Result<_, PrivateInviteError> {
                    let fact = storage
                        .private_device_invite_storage()
                        .ok_or(LinkingWelcomeDenied::UnsupportedStorage)?
                        .mark_private_invite_dispatch(&prepared.scope)?;
                    prepared.lease.check_live_before_commit()?;
                    Ok(fact)
                });
        let fact = match fact_result {
            Ok(fact) => fact,
            Err(PrivateInviteError::Denied(error)) => {
                self.retire_prepared_private_device_invite(prepared)?;
                return Err(error.into());
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = prepared.lease.check_live_before_commit() {
            self.storage
                .private_device_invite_storage()
                .ok_or(LinkingWelcomeDenied::UnsupportedStorage)?
                .mark_private_invite_publication_unknown(&prepared.scope)?;
            return Err(error.into());
        }
        let transport = fact.transport.ok_or_else(incompatible)?;
        let mut publication = publisher.publish_commit(&transport.commit);
        let result = std::future::poll_fn(|cx| {
            if let Err(error) = prepared.lease.check_live_before_commit() {
                return std::task::Poll::Ready(Err(PrivateInviteError::Denied(error)));
            }
            publication
                .as_mut()
                .poll(cx)
                .map(|result| result.map_err(PrivateInviteError::from))
        })
        .await;
        self.storage
            .private_device_invite_storage()
            .ok_or(LinkingWelcomeDenied::UnsupportedStorage)?
            .mark_private_invite_publication_unknown(&prepared.scope)?;
        result
    }
    /// Negative-only cleanup after an interrupted owned dispatch. Uncertain
    /// membership is never cleared or reported as retired. SQL failure retains
    /// the caller's continuation so this exact cleanup can be retried.
    pub fn finish_interrupted_private_device_invite(
        &mut self,
        prepared: &PreparedPrivateDeviceInvite,
    ) -> Result<(), PrivateInviteError> {
        let cap = self
            .storage
            .private_device_invite_storage()
            .ok_or(LinkingWelcomeDenied::UnsupportedStorage)?;
        let fact = cap.private_invite()?.ok_or_else(incompatible)?;
        if fact.scope != prepared.scope || fact.raw.binding.group_id != prepared.group_id {
            return Err(incompatible());
        }
        match fact.phase {
            PrivateInvitePhase::Dispatching | PrivateInvitePhase::PublicationUnknown => {
                cap.mark_private_invite_publication_unknown(&prepared.scope)?;
                Ok(())
            }
            PrivateInvitePhase::Confirmed | PrivateInvitePhase::Retired => Ok(()),
            PrivateInvitePhase::Wrapped => self.retire_prepared_private_device_invite(prepared),
            PrivateInvitePhase::RawStaged => Err(incompatible()),
        }
    }

    pub(crate) fn forbid_generic_private_publish(
        &self,
        group: &GroupId,
    ) -> Result<(), EngineError> {
        if let Some(cap) = self.storage.private_device_invite_storage() {
            let fact = cap.private_invite().map_err(|error| match error {
                PrivateInviteStorageError::Storage(error) => EngineError::Storage(error),
                _ => EngineError::Other("private publication ledger denied".into()),
            })?;
            if fact.is_some_and(|fact| {
                &fact.raw.binding.group_id == group
                    && !matches!(
                        fact.phase,
                        PrivateInvitePhase::Retired | PrivateInvitePhase::Confirmed
                    )
            }) {
                return Err(EngineError::InvalidTransition(
                    cgka_traits::engine_state::InvalidTransition {
                        from: "PrivateInvite",
                        to: "GenericPublish",
                        reason: "private publication requires original owned consent and dedicated reconciliation",
                    },
                ));
            }
        }
        Ok(())
    }
}

impl<S: StorageProvider> Engine<S> {
    fn confirmed_private_welcomes(
        &self,
        prepared: &mut PreparedPrivateDeviceInvite,
    ) -> Result<Vec<TransportMessage>, PrivateInviteError> {
        self.storage.with_read_snapshot(|storage| {
            let cap = storage
                .private_device_invite_storage()
                .ok_or(LinkingWelcomeDenied::UnsupportedStorage)?;
            let fact = cap.private_invite()?.ok_or_else(incompatible)?;
            let confirmed = cap.confirmed_private_invite()?.ok_or_else(incompatible)?;
            let binding = &fact.raw.binding;
            let consent = prepared.lease.consent();
            if fact.phase != PrivateInvitePhase::Confirmed
                || confirmed.denied
                || fact.scope != prepared.scope
                || confirmed.scope != prepared.scope
                || confirmed.binding != *binding
                || binding.group_id != prepared.group_id
                || fact.scope.account.as_slice() != self.identity.self_id().as_slice()
                || fact.scope.local_device.as_slice() != self.identity.signer.public()
                || binding.approver_scope != consent.approver_scope
                || binding.recipient_generation != consent.recipient_generation
                || binding.origin != consent.origin
                || binding.nonce != consent.nonce
                || binding.context_digest != consent.context_digest
                || <[u8; 32]>::from(Sha256::digest(&fact.raw.commit)) != binding.commit_digest
                || <[u8; 32]>::from(Sha256::digest(&fact.raw.welcome)) != binding.welcome_digest
            {
                return Err(incompatible());
            }
            let validated = self
                .validated_private_successor(&prepared.group_id)?
                .ok_or_else(incompatible)?;
            if !validated.matches_confirmed(&confirmed) {
                return Err(incompatible());
            }
            let actual = validated.candidate();
            if actual.account.as_slice() != fact.scope.account
                || actual.epoch != binding.successor.epoch
                || actual.epoch_authenticator_digest != binding.successor.epoch_authenticator_digest
                || actual.leaves.len() != binding.successor.leaves.len()
                || actual
                    .leaves
                    .iter()
                    .zip(&binding.successor.leaves)
                    .any(|(actual, bound)| {
                        actual.leaf_index != bound.leaf_index
                            || actual.signature_public_key.as_slice() != bound.signature_public_key
                            || bound.account != fact.scope.account
                    })
                || !self.with_mls_group(
                    &prepared.group_id,
                    crate::device_group_genesis::exact_profile,
                )?
            {
                return Err(incompatible());
            }
            // Revalidate the actual current successor through the original SDK
            // lease policy. Protected facts and matching shape alone cannot arm
            // or restore approval. Every leaf below came from live MLS above.
            let recipient_leaf_index = actual
                .leaves
                .iter()
                .find(|leaf| leaf.signature_public_key.as_slice() == binding.recipient)
                .map(|leaf| leaf.leaf_index)
                .ok_or_else(incompatible)?;
            let successor = DeviceGroupAnchorRoster {
                epoch: actual.epoch,
                epoch_authenticator_digest: actual.epoch_authenticator_digest,
                leaves: actual
                    .leaves
                    .iter()
                    .map(|leaf| {
                        Ok(GenesisLeaf {
                            account: fact.scope.account,
                            leaf_index: leaf.leaf_index,
                            signature_public_key: leaf
                                .signature_public_key
                                .as_slice()
                                .try_into()
                                .map_err(|_| incompatible())?,
                        })
                    })
                    .collect::<Result<Vec<_>, PrivateInviteError>>()?,
            };
            prepared.lease.check_staged(&AuthenticatedPrivateAdd {
                successor,
                recipient_leaf_index,
            })?;
            let transport = fact.transport.ok_or_else(incompatible)?;
            if transport.welcomes.is_empty()
                || transport.welcomes.len() > MAX_PRIVATE_INVITE_WELCOME_MESSAGES
                || transport
                    .welcomes
                    .iter()
                    .try_fold(0usize, |sum, message| {
                        sum.checked_add(message.payload.len())
                    })
                    .is_none_or(|bytes| bytes > MAX_PRIVATE_INVITE_TRANSPORT_BYTES)
                || transport.welcomes.iter().any(|message| {
                    !matches!(&message.envelope,
                    cgka_traits::TransportEnvelope::Welcome { recipient }
                    if recipient.as_slice() == fact.scope.account)
                })
            {
                return Err(incompatible());
            }
            Ok(transport.welcomes)
        })
    }

    /// Publish only an exact frozen batch after authenticated own-echo confirmation
    /// and current selected-tree revalidation. No ordinary replay work is created;
    /// receipts do not settle the roster or reconstruct delivery consent on reopen.
    pub async fn dispatch_confirmed_private_welcomes(
        &mut self,
        prepared: &mut PreparedPrivateDeviceInvite,
        publisher: &dyn TrustedPrivateWelcomePublisher,
    ) -> Result<(), PrivateInviteError> {
        prepared.lease.check_live_before_commit()?;
        let messages = self.confirmed_private_welcomes(prepared)?;
        for message in messages {
            // The actor holds exclusive Engine ownership throughout. Recheck the
            // original revocable lease on every poll, including stalled network.
            prepared.lease.check_live_before_commit()?;
            let mut work = publisher.publish_welcome(&message);
            std::future::poll_fn(|cx| {
                if let Err(error) = prepared.lease.check_live_before_commit() {
                    return std::task::Poll::Ready(Err(PrivateInviteError::Denied(error)));
                }
                work.as_mut()
                    .poll(cx)
                    .map(|result| result.map_err(PrivateInviteError::from))
            })
            .await?;
            prepared.lease.check_live_before_commit()?;
        }
        Ok(())
    }
}
