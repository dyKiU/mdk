//! Exact authenticated own-echo reconciliation. No consent or delivery restoration.
use super::{AuthenticatedPrivateAdd, AuthenticatedPrivateInvite};
use crate::{Engine, provider::EngineOpenMlsProvider};
use cgka_traits::device_linking_key_package::LinkingWelcomeDenied;
use cgka_traits::engine::KeyPackage;
use cgka_traits::ingest::{IngestOutcome, InputRejectionCategory, PeeledContent};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::private_device_invite::*;
use cgka_traits::storage::{GroupStateCheckpointRef, StorageProvider};
use cgka_traits::{EpochId, GroupEvent, GroupId, TransportMessage};
use openmls::prelude::{MlsGroup, MlsMessageOut, ProcessedMessageContent, Sender};
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use tls_codec::Serialize;

fn denied() -> cgka_traits::EngineError {
    cgka_traits::EngineError::LinkingWelcomeDenied(LinkingWelcomeDenied::ContextMismatch)
}
fn ledger_error(error: PrivateInviteStorageError) -> cgka_traits::EngineError {
    match error {
        PrivateInviteStorageError::Storage(error) => error.into(),
        _ => denied(),
    }
}
fn refused() -> IngestOutcome {
    IngestOutcome::Ignored {
        category: InputRejectionCategory::AuthorizationFailed,
    }
}

// Constructed only after actual OpenMLS processing, never serialized or exposed.
struct AuthenticatedOwnEcho {
    source_epoch: EpochId,
    leaf_index: u32,
    signature_key: Vec<u8>,
}

impl<S: StorageProvider> Engine<S> {
    fn retained_private_add(
        &self,
        group: &MlsGroup,
        fact: &PrivateInviteFact,
    ) -> Result<AuthenticatedPrivateAdd, cgka_traits::EngineError> {
        let binding = &fact.raw.binding;
        if binding.group_id.as_slice() != group.group_id().as_slice()
            || fact.scope.account.as_slice() != self.identity.self_id().as_slice()
            || fact.scope.local_device.as_slice() != self.identity.signer.public()
            || binding.approver_scope.account != fact.scope.account
            || binding.approver_scope.local_device != fact.scope.local_device
            || <[u8; 32]>::from(Sha256::digest(&fact.raw.commit)) != binding.commit_digest
            || <[u8; 32]>::from(Sha256::digest(&fact.raw.welcome)) != binding.welcome_digest
        {
            return Err(denied());
        }
        let staged = group.pending_commit().ok_or_else(denied)?;
        let mut adds = staged.add_proposals();
        let add = adds.next().ok_or_else(denied)?;
        let package = add.add_proposal().key_package();
        if adds.next().is_some() {
            return Err(denied());
        }
        let wire: MlsMessageOut = package.clone().into();
        let bytes = wire.tls_serialize_detached().map_err(|_| {
            cgka_traits::EngineError::Serialize(
                "private retained package serialization failed".into(),
            )
        })?;
        if <[u8; 32]>::from(Sha256::digest(&bytes)) != binding.key_package_digest {
            return Err(denied());
        }
        let mut predecessor = crate::device_group_snapshot::CandidateDeviceGroupSnapshot {
            account: self.identity.self_id().clone(),
            group_id: binding.group_id.clone(),
            epoch: EpochId(group.epoch().as_u64()),
            epoch_authenticator_digest: Sha256::digest(group.epoch_authenticator().as_slice())
                .into(),
            leaves: group
                .members()
                .map(|member| crate::device_group_snapshot::CandidateDeviceLeaf {
                    leaf_index: member.index.u32(),
                    signature_public_key: member.signature_key,
                })
                .collect(),
            roster_commitment: [0; 32],
        };
        predecessor
            .leaves
            .sort_unstable_by_key(|leaf| leaf.leaf_index);
        predecessor.roster_commitment = crate::device_group_snapshot::commitment(&predecessor);
        if predecessor.epoch != binding.predecessor.epoch
            || predecessor.epoch_authenticator_digest
                != binding.predecessor.epoch_authenticator_digest
            || predecessor.leaves.len() != binding.predecessor.leaves.len()
            || predecessor
                .leaves
                .iter()
                .zip(&binding.predecessor.leaves)
                .any(|(actual, bound)| {
                    actual.leaf_index != bound.leaf_index
                        || actual.signature_public_key.as_slice() != bound.signature_public_key
                        || bound.account != fact.scope.account
                })
        {
            return Err(denied());
        }
        let input = AuthenticatedPrivateInvite {
            predecessor,
            own_leaf_index: group.own_leaf_index().u32(),
            exact_key_package: KeyPackage::new(bytes),
            key_package_reference: binding.key_package_reference,
            recipient_account: crate::identity::validated_member_id_of_leaf(package.leaf_node())?,
            recipient_signature_public_key: binding.recipient,
        };
        let actual = self.validate_private_staged_add_package(group, staged, &input, package)?;
        if actual.successor != binding.successor {
            return Err(denied());
        }
        Ok(actual)
    }

    /// Negative restart barrier only. Unknown publication cannot be treated as
    /// failed or turned back into SDK consent. Mismatch quarantines instead.
    pub(crate) fn uncertain_private_pending(
        &self,
        group_id: &GroupId,
        group: &MlsGroup,
    ) -> Result<bool, cgka_traits::EngineError> {
        let Some(cap) = self.storage.private_device_invite_storage() else {
            return Ok(false);
        };
        let Some(fact) = cap.private_invite().map_err(ledger_error)? else {
            return Ok(false);
        };
        if &fact.raw.binding.group_id != group_id
            || !matches!(
                fact.phase,
                PrivateInvitePhase::Dispatching | PrivateInvitePhase::PublicationUnknown
            )
        {
            return Ok(false);
        }
        self.retained_private_add(group, &fact)?;
        Ok(true)
    }

    /// Runs before ordinary dedup/held-publish gates. Cached identity is only a
    /// candidate hint; the actual processed own commit is the cryptographic seal.
    pub(crate) async fn ingest_private_commit_echo(
        &mut self,
        message: &TransportMessage,
    ) -> Result<Option<IngestOutcome>, cgka_traits::EngineError> {
        let Some(cap) = self.storage.private_device_invite_storage() else {
            return Ok(None);
        };
        let Some(fact) = cap.private_invite().map_err(ledger_error)? else {
            return Ok(None);
        };
        let Some(transport) = &fact.transport else {
            return Ok(None);
        };
        if transport.commit.id != message.id || fact.phase == PrivateInvitePhase::Confirmed {
            return Ok(None);
        }
        if !matches!(
            fact.phase,
            PrivateInvitePhase::Dispatching | PrivateInvitePhase::PublicationUnknown
        ) || transport.commit.payload != message.payload
            || transport.commit.envelope != message.envelope
        {
            return Ok(Some(refused()));
        }
        let group_id = &fact.raw.binding.group_id;
        self.ensure_hydrated(group_id)?;
        self.ensure_group_live(group_id)?;
        let pending = self.epoch_manager.pending_refs_for_group(group_id);
        if pending.len() != 1 {
            return Err(denied());
        }
        let context = self.storage.with_read_snapshot(|storage| {
            let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, storage.mls_storage());
            let group = MlsGroup::load(
                provider.storage(),
                &openmls::group::GroupId::from_slice(group_id.as_slice()),
            )
            .map_err(|_| {
                cgka_traits::EngineError::Backend("private echo storage load failed".into())
            })?
            .ok_or_else(denied)?;
            self.retained_private_add(&group, &fact)?;
            crate::group_lifecycle::build_group_context_snapshot(&group, &provider)
        })?;
        let peeled = self
            .peeler
            .peel_group_message(message, &context)
            .await
            .map_err(cgka_traits::EngineError::Peeler)?;
        let PeeledContent::MlsMessage { bytes } = peeled.content else {
            return Ok(Some(refused()));
        };
        if bytes != fact.raw.commit {
            return Ok(Some(refused()));
        }
        let content_id = crate::message_processor::content_dedup_id(&bytes);
        let source_epoch = fact.raw.binding.predecessor.epoch;
        let resulting_epoch = fact.raw.binding.successor.epoch;
        self.storage
            .with_transaction(|storage| -> Result<(), cgka_traits::EngineError> {
                let current = storage
                    .private_device_invite_storage()
                    .ok_or_else(denied)?
                    .private_invite()
                    .map_err(ledger_error)?
                    .ok_or_else(denied)?;
                if current.scope != fact.scope
                    || current.raw != fact.raw
                    || current.transport != fact.transport
                    || !matches!(
                        current.phase,
                        PrivateInvitePhase::Dispatching | PrivateInvitePhase::PublicationUnknown
                    )
                {
                    return Err(denied());
                }
                let record = storage.get_group(group_id)?;
                if record.removed
                    || record.unrecoverable
                    || record.disbanded.is_some()
                    || record.epoch != source_epoch
                {
                    return Err(denied());
                }
                let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, storage.mls_storage());
                let mut group = MlsGroup::load(
                    provider.storage(),
                    &openmls::group::GroupId::from_slice(group_id.as_slice()),
                )
                .map_err(|_| {
                    cgka_traits::EngineError::Backend("private echo storage load failed".into())
                })?
                .ok_or_else(denied)?;
                let successor = self.retained_private_add(&group, &current)?.successor;
                let (_, protocol) = crate::openmls_projection::project_protocol_message(&bytes)
                    .map_err(|_| {
                        cgka_traits::EngineError::Serialize(
                            "private echo MLS decoding failed".into(),
                        )
                    })?;
                let processed = group
                    .process_message(&provider, protocol.ok_or_else(denied)?)
                    .map_err(|error| match error {
                        openmls::group::ProcessMessageError::ValidationError(_) => denied(),
                        _ => cgka_traits::EngineError::Backend(
                            "private echo MLS processing failed".into(),
                        ),
                    })?;
                let Sender::Member(index) = processed.sender() else {
                    return Err(denied());
                };
                let index = *index;
                let member = group
                    .members()
                    .find(|member| member.index == index)
                    .ok_or_else(denied)?;
                if processed.epoch().as_u64() != source_epoch.0
                    || index != group.own_leaf_index()
                    || member.signature_key.as_slice() != self.identity.signer.public()
                    || crate::identity::validated_member_id(processed.credential())?
                        != *self.identity.self_id()
                    || !matches!(
                        processed.into_content(),
                        ProcessedMessageContent::OwnPendingCommit
                    )
                {
                    return Err(denied());
                }
                let seal = AuthenticatedOwnEcho {
                    source_epoch,
                    leaf_index: index.u32(),
                    signature_key: member.signature_key,
                };
                if seal.source_epoch != source_epoch
                    || seal.leaf_index != group.own_leaf_index().u32()
                    || seal.signature_key.as_slice() != current.scope.local_device
                {
                    return Err(denied());
                }
                let staged = group.pending_commit().ok_or_else(denied)?;
                let mut stamp = crate::openmls_projection::own_commit_stamp(
                    staged,
                    self.identity.self_id().clone(),
                )?;
                crate::capability_manager::cache_from_staged_commit(storage, group_id, staged)?;
                crate::openmls_projection::retain_current_group_epoch_snapshot(
                    storage,
                    group_id,
                    self.convergence_policy.convergence.max_rewind_commits,
                )
                .map_err(|_| {
                    cgka_traits::EngineError::Backend("private source retention failed".into())
                })?;
                // This is a staged CAS only inside the enclosing crypto transaction.
                // The later merge/projection failure rolls it back with all MLS writes.
                storage
                    .private_device_invite_storage()
                    .ok_or_else(denied)?
                    .confirm_private_invite(&current.scope, &successor)
                    .map_err(ledger_error)?;
                group.merge_pending_commit(&provider).map_err(|_| {
                    cgka_traits::EngineError::Backend("private echo MLS merge failed".into())
                })?;
                crate::group_lifecycle::validate_member_credentials_and_account_proofs(
                    &group,
                    self.ciphersuite,
                )?;
                crate::app_components::validate_current_profile_group_invariants(&group)?;
                let actual_leaves = group
                    .members()
                    .map(|member| {
                        Ok(cgka_traits::device_group_genesis::GenesisLeaf {
                            account: crate::identity::validated_member_id(&member.credential)?
                                .as_slice()
                                .try_into()
                                .map_err(|_| denied())?,
                            leaf_index: member.index.u32(),
                            signature_public_key: member
                                .signature_key
                                .as_slice()
                                .try_into()
                                .map_err(|_| denied())?,
                        })
                    })
                    .collect::<Result<Vec<_>, cgka_traits::EngineError>>()?;
                if group.epoch().as_u64() != successor.epoch.0
                    || <[u8; 32]>::from(Sha256::digest(group.epoch_authenticator().as_slice()))
                        != successor.epoch_authenticator_digest
                    || actual_leaves != successor.leaves
                    || !crate::device_group_genesis::exact_profile(&group)?
                {
                    return Err(denied());
                }
                crate::roster_ack_capture::invalidate_capture_for_tree(storage, group_id, &group)?;
                let mut projection = record;
                projection.epoch = resulting_epoch;
                projection.members = crate::group_lifecycle::marmot_members(&group);
                projection.required_capabilities =
                    crate::capability_manager::required_capabilities_from_group(&group);
                crate::group_lifecycle::mirror_app_components_into_record(&group, &mut projection);
                storage.put_group(&projection)?;
                crate::capability_manager::cache_self_capabilities(
                    storage,
                    group_id,
                    &group,
                    self.identity.self_id(),
                    self.ciphersuite,
                )?;
                let wire = TransportMessage {
                    id: content_id.clone(),
                    payload: bytes.clone(),
                    ..message.clone()
                };
                let checkpoint_id = format!(
                    "openmls-own-commit-v1-{}",
                    hex::encode(Sha256::digest(&bytes))
                );
                stamp.checkpoint_id = Some(checkpoint_id.clone());
                stamp.resulting_epoch_authenticator = Some(
                    crate::openmls_projection::own_commit_post_merge_epoch_authenticator(&group),
                );
                let mut payload = StoredMessagePayload::signed_openmls_wire(message.clone(), wire);
                if let StoredMessagePayload::SignedOpenMlsWire { stamp: slot, .. } = &mut payload {
                    *slot = Some(stamp);
                }
                storage.put_message(&MessageRecord {
                    id: content_id.clone(),
                    group_id: group_id.clone(),
                    epoch: source_epoch,
                    state: MessageState::Processed,
                    payload: payload.encode().map_err(|_| {
                        cgka_traits::EngineError::Serialize(
                            "private confirmation record encoding failed".into(),
                        )
                    })?,
                    deferred_peel: None,
                })?;
                storage.put_processed_transport_id(group_id, &message.id)?;
                storage.create_group_state_checkpoint(
                    group_id,
                    &GroupStateCheckpointRef {
                        id: checkpoint_id,
                        resulting_epoch,
                    },
                )?;
                crate::openmls_projection::retain_current_group_epoch_snapshot(
                    storage,
                    group_id,
                    self.convergence_policy.convergence.max_rewind_commits,
                )
                .map_err(|_| {
                    cgka_traits::EngineError::Backend("private successor retention failed".into())
                })?;
                if let Some(route) = context.transport_group_id() {
                    storage.put_transport_group_route(route, group_id, resulting_epoch)?;
                }
                Ok(())
            })?;
        self.epoch_manager.confirm_publish(pending[0])?;
        self.mls_group_cache.forget_group(group_id);
        self.invalidate_deferred_peel_candidate_cache(group_id);
        self.reindex_transport_group_id(group_id);
        self.valid_proposal_groups.remove(group_id);
        self.seen_message_ids.insert(message.id.clone());
        self.seen_message_ids.insert(content_id);
        self.events_buf.push_back(GroupEvent::EpochChanged {
            group_id: group_id.clone(),
            from: source_epoch,
            to: resulting_epoch,
        });
        Ok(Some(IngestOutcome::Processed))
    }
}
