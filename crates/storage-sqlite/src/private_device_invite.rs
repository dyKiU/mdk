//! Outgoing persistence facts, never SDK consent or publication permission.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::private_device_invite::*;
use cgka_traits::storage::StorageProvider;
use cgka_traits::{GroupId, TransportEnvelope};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
type Result<T> = PrivateInviteStorageResult<T>;
use PrivateInviteStorageError as Error;

fn generation(value: u64) -> Result<i64> {
    i64::try_from(value)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(Error::GenerationExhausted)
}
fn bounded(bytes: &[u8], maximum: usize) -> Result<()> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(Error::InvalidFact);
    }
    Ok(())
}
fn validate_roster(roster: &DeviceGroupAnchorRoster, account: &[u8; 32]) -> Result<()> {
    if roster.epoch.0 > i64::MAX as u64
        || roster.leaves.is_empty()
        || roster.leaves.len() > 128
        || roster.epoch_authenticator_digest == [0; 32]
    {
        return Err(Error::InvalidFact);
    }
    let mut previous = None;
    let mut signers = HashSet::new();
    for leaf in &roster.leaves {
        if leaf.account != *account
            || leaf.signature_public_key == [0; 32]
            || previous.is_some_and(|index| index >= leaf.leaf_index)
            || !signers.insert(leaf.signature_public_key)
        {
            return Err(Error::InvalidFact);
        }
        previous = Some(leaf.leaf_index);
    }
    Ok(())
}
fn validate_binding(binding: &PrivateInviteBinding) -> Result<()> {
    generation(binding.approver_scope.generation)?;
    generation(binding.recipient_generation)?;
    generation(match binding.origin {
        PrivateInviteOrigin::Genesis(v)
        | PrivateInviteOrigin::Accepted(v)
        | PrivateInviteOrigin::Confirmed(v)
        | PrivateInviteOrigin::Existing(v)
        | PrivateInviteOrigin::Revoked(v) => v,
    })?;
    bounded(binding.group_id.as_slice(), 255)?;
    if binding.format_version != 1
        || binding.recipient == binding.approver_scope.local_device
        || [
            binding.nonce,
            binding.context_digest,
            binding.key_package_reference,
            binding.key_package_digest,
            binding.commit_digest,
            binding.welcome_digest,
        ]
        .contains(&[0; 32])
    {
        return Err(Error::InvalidFact);
    }
    validate_roster(&binding.predecessor, &binding.approver_scope.account)?;
    validate_roster(&binding.successor, &binding.approver_scope.account)?;
    if binding.predecessor.leaves.len() >= 128
        || binding.predecessor.epoch.0.checked_add(1) != Some(binding.successor.epoch.0)
        || binding.successor.leaves.len() != binding.predecessor.leaves.len() + 1
        || !binding
            .predecessor
            .leaves
            .iter()
            .any(|leaf| leaf.signature_public_key == binding.approver_scope.local_device)
        || binding
            .predecessor
            .leaves
            .iter()
            .any(|leaf| leaf.signature_public_key == binding.recipient)
        || !binding
            .successor
            .leaves
            .iter()
            .any(|leaf| leaf.signature_public_key == binding.recipient)
        || !binding
            .predecessor
            .leaves
            .iter()
            .all(|leaf| binding.successor.leaves.contains(leaf))
    {
        return Err(Error::InvalidFact);
    }
    Ok(())
}
fn binding_bytes(binding: &PrivateInviteBinding) -> Result<Vec<u8>> {
    validate_binding(binding)?;
    let bytes = serde_json::to_vec(binding).map_err(|_| Error::InvalidFact)?;
    bounded(&bytes, MAX_PRIVATE_INVITE_BINDING_BYTES)?;
    Ok(bytes)
}
fn validate_raw(raw: &PrivateInviteRawDraft) -> Result<()> {
    validate_binding(&raw.binding)?;
    bounded(&raw.commit, MAX_PRIVATE_INVITE_COMMIT_BYTES)?;
    bounded(&raw.welcome, MAX_PRIVATE_INVITE_WELCOME_BYTES)?;
    if Sha256::digest(&raw.commit).as_slice() != raw.binding.commit_digest
        || Sha256::digest(&raw.welcome).as_slice() != raw.binding.welcome_digest
    {
        return Err(Error::InvalidFact);
    }
    Ok(())
}
fn transport_bytes(
    binding: &PrivateInviteBinding,
    transport: &PrivateInviteTransport,
) -> Result<Vec<u8>> {
    if transport.welcomes.is_empty()
        || transport.welcomes.len() > MAX_PRIVATE_INVITE_WELCOME_MESSAGES
    {
        return Err(Error::InvalidFact);
    }
    let mut ids = std::collections::HashSet::new();
    let mut payload_bytes = 0usize;
    for message in std::iter::once(&transport.commit).chain(&transport.welcomes) {
        bounded(&message.payload, MAX_PRIVATE_INVITE_TRANSPORT_BYTES)?;
        payload_bytes = payload_bytes
            .checked_add(message.payload.len())
            .ok_or(Error::InvalidFact)?;
        if payload_bytes > MAX_PRIVATE_INVITE_TRANSPORT_BYTES {
            return Err(Error::InvalidFact);
        }
        if message.id.as_slice().is_empty()
            || message.id.as_slice().len() > 128
            || !ids.insert(message.id.as_slice())
            || message.source.0.is_empty()
            || message.source.0.len() > 128
            || message.causal_deps.len() > 128
            || message
                .causal_deps
                .iter()
                .any(|id| id.as_slice().is_empty() || id.as_slice().len() > 128)
        {
            return Err(Error::InvalidFact);
        }
    }
    if !matches!(&transport.commit.envelope, TransportEnvelope::GroupMessage { transport_group_id } if !transport_group_id.is_empty() && transport_group_id.len()<=255)
        || transport.welcomes.iter().any(|message| !matches!(&message.envelope, TransportEnvelope::Welcome { recipient } if recipient.as_slice()==binding.approver_scope.account))
    {
        return Err(Error::InvalidFact);
    }
    let bytes = serde_json::to_vec(transport).map_err(|_| Error::InvalidFact)?;
    bounded(&bytes, MAX_PRIVATE_INVITE_TRANSPORT_BYTES)?;
    Ok(bytes)
}
fn scope(counter: i64, account: Vec<u8>, device: Vec<u8>) -> Result<PrivateInviteScope> {
    let staging_generation = u64::try_from(counter).map_err(|_| Error::InvalidFact)?;
    generation(staging_generation)?;
    Ok(PrivateInviteScope {
        account: account.try_into().map_err(|_| Error::InvalidFact)?,
        local_device: device.try_into().map_err(|_| Error::InvalidFact)?,
        staging_generation,
    })
}
fn decode_binding(
    bytes: &[u8],
    scope: &PrivateInviteScope,
    group: &[u8],
) -> Result<PrivateInviteBinding> {
    bounded(bytes, MAX_PRIVATE_INVITE_BINDING_BYTES)?;
    let binding: PrivateInviteBinding =
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidFact)?;
    validate_binding(&binding)?;
    if binding.approver_scope.account != scope.account
        || binding.approver_scope.local_device != scope.local_device
        || binding.group_id.as_slice() != group
    {
        return Err(Error::InvalidFact);
    }
    Ok(binding)
}
fn read_pending(connection: &rusqlite::Connection) -> Result<Option<PrivateInviteFact>> {
    type Row = (
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        i64,
    );
    let row:Option<Row>=connection.query_row("SELECT generation,account,local_device,group_id,binding,raw_commit,raw_welcome,transport,phase FROM private_device_invite_staging WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?))).optional().storage()?;
    row.map(
        |(counter, account, device, group, bytes, commit, welcome, transport, phase)| {
            let scope = scope(counter, account, device)?;
            let binding = decode_binding(&bytes, &scope, &group)?;
            let raw = PrivateInviteRawDraft {
                binding,
                commit,
                welcome,
            };
            validate_raw(&raw)?;
            let transport = transport
                .map(|bytes| -> Result<PrivateInviteTransport> {
                    bounded(&bytes, MAX_PRIVATE_INVITE_TRANSPORT_BYTES)?;
                    let transport =
                        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidFact)?;
                    transport_bytes(&raw.binding, &transport)?;
                    Ok(transport)
                })
                .transpose()?;
            let phase = match phase {
                0 => PrivateInvitePhase::RawStaged,
                1 => PrivateInvitePhase::Wrapped,
                2 => PrivateInvitePhase::Dispatching,
                3 => PrivateInvitePhase::PublicationUnknown,
                4 => PrivateInvitePhase::Retired,
                5 => PrivateInvitePhase::Confirmed,
                _ => return Err(Error::InvalidFact),
            };
            if (phase == PrivateInvitePhase::RawStaged && transport.is_some())
                || (matches!(
                    phase,
                    PrivateInvitePhase::Wrapped
                        | PrivateInvitePhase::Dispatching
                        | PrivateInvitePhase::PublicationUnknown
                        | PrivateInvitePhase::Confirmed
                ) && transport.is_none())
            {
                return Err(Error::InvalidFact);
            }
            Ok(PrivateInviteFact {
                scope,
                raw,
                transport,
                phase,
            })
        },
    )
    .transpose()
}
fn read_confirmed(connection: &rusqlite::Connection) -> Result<Option<ConfirmedPrivateInviteFact>> {
    type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, bool);
    let row:Option<Row>=connection.query_row("SELECT generation,account,local_device,group_id,binding,denied FROM private_device_invite_confirmed WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().storage()?;
    row.map(|(counter, account, device, group, bytes, denied)| {
        let scope = scope(counter, account, device)?;
        let binding = decode_binding(&bytes, &scope, &group)?;
        Ok(ConfirmedPrivateInviteFact {
            scope,
            binding,
            denied,
        })
    })
    .transpose()
}
fn exact_pending(
    connection: &rusqlite::Connection,
    scope: &PrivateInviteScope,
) -> Result<PrivateInviteFact> {
    let fact = read_pending(connection)?.ok_or(Error::ScopeMismatch)?;
    if fact.scope != *scope {
        return Err(Error::ScopeMismatch);
    }
    Ok(fact)
}

fn unresolved(phase: PrivateInvitePhase) -> bool {
    matches!(
        phase,
        PrivateInvitePhase::RawStaged
            | PrivateInvitePhase::Wrapped
            | PrivateInvitePhase::Dispatching
            | PrivateInvitePhase::PublicationUnknown
    )
}

/// Negative reservation fence, not consent or restart recovery.
pub(crate) fn has_unresolved_invite(connection: &rusqlite::Connection) -> Result<bool> {
    Ok(read_pending(connection)?.is_some_and(|fact| unresolved(fact.phase)))
}

/// A new selection cannot orphan pending work or another active lineage.
pub(crate) fn check_selection_allocation(
    connection: &rusqlite::Connection,
    account: &[u8; 32],
    device: &[u8; 32],
) -> Result<()> {
    let existing = crate::existing_device_group_anchor::read(connection).map_err(Error::Storage)?;
    if let Some(fact) = &existing {
        if fact.draft.account != *account || fact.draft.local_device != *device {
            return Err(Error::ScopeMismatch);
        }
        if !fact.denied {
            return Err(Error::Busy);
        }
    }
    if let Some(fact) =
        crate::revoked_device_group_anchor::read(connection).map_err(Error::Storage)?
    {
        if fact.draft.account != *account || fact.draft.local_device != *device {
            return Err(Error::ScopeMismatch);
        }
        if !fact.denied {
            return Err(Error::Busy);
        }
    }
    let pending = read_pending(connection)?;
    let confirmed = read_confirmed(connection)?;
    for scope in pending
        .as_ref()
        .map(|fact| &fact.scope)
        .into_iter()
        .chain(confirmed.as_ref().map(|fact| &fact.scope))
    {
        if scope.account != *account || scope.local_device != *device {
            return Err(Error::ScopeMismatch);
        }
    }
    if pending.is_some_and(|fact| unresolved(fact.phase))
        || confirmed.is_some_and(|fact| !fact.denied)
    {
        return Err(Error::Busy);
    }
    Ok(())
}
fn check_attempt(connection: &rusqlite::Connection, binding: &PrivateInviteBinding) -> Result<()> {
    // Negative current-attempt fence only: a verified row cannot grant consent.
    let matches:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM device_linking_attempt WHERE singleton=1 AND account_id=?1 AND local_device=?2 AND generation=?3 AND state=3 AND nonce=?4 AND context_digest=?5 AND flow IS NOT NULL)",params![binding.approver_scope.account.as_slice(),binding.approver_scope.local_device.as_slice(),generation(binding.approver_scope.generation)?,binding.nonce.as_slice(),binding.context_digest.as_slice()],|r|r.get(0)).storage()?;
    if !matches {
        return Err(Error::ScopeMismatch);
    }
    Ok(())
}
fn check_origin(storage: &SqliteAccountStorage, binding: &PrivateInviteBinding) -> Result<()> {
    let confirmed = storage.confirmed_private_invite()?;
    if let Some(fact) = &confirmed {
        if fact.scope.account != binding.approver_scope.account
            || fact.scope.local_device != binding.approver_scope.local_device
        {
            return Err(Error::ScopeMismatch);
        }
        if fact.binding.group_id == binding.group_id
            && (!fact.denied
                || !matches!(
                    binding.origin,
                    PrivateInviteOrigin::Existing(_) | PrivateInviteOrigin::Revoked(_)
                ))
        {
            if fact.denied
                || binding.origin != PrivateInviteOrigin::Confirmed(fact.scope.staging_generation)
                || binding.predecessor != fact.binding.successor
            {
                return Err(Error::ScopeMismatch);
            }
            return Ok(());
        }
        if !fact.denied {
            return Err(Error::Busy);
        }
    }
    match binding.origin {
        PrivateInviteOrigin::Genesis(counter) => {
            let fact = storage
                .device_group_genesis_storage()
                .ok_or(Error::Unsupported)?
                .genesis_selection()
                .map_err(|error| match error {
                    cgka_traits::device_group_genesis::GenesisError::Storage(error) => {
                        Error::Storage(error)
                    }
                    _ => Error::InvalidFact,
                })?
                .ok_or(Error::ScopeMismatch)?;
            if fact.active_denied
                || fact.fact.scope.selection_generation != counter
                || fact.fact.scope.account != binding.approver_scope.account
                || fact.fact.scope.local_device != binding.approver_scope.local_device
                || fact.fact.birth.group_id != binding.group_id
                || fact.fact.birth.epoch != binding.predecessor.epoch
                || fact.fact.birth.epoch_authenticator_digest
                    != binding.predecessor.epoch_authenticator_digest
                || fact.fact.birth.leaves != binding.predecessor.leaves
            {
                return Err(Error::ScopeMismatch);
            }
        }
        PrivateInviteOrigin::Accepted(counter) => {
            let fact = storage
                .accepted_device_group_anchor_storage()
                .ok_or(Error::Unsupported)?
                .accepted_anchor()
                .map_err(|error| match error {
                    cgka_traits::accepted_device_group_anchor::AnchorError::Storage(error) => {
                        Error::Storage(error)
                    }
                    _ => Error::InvalidFact,
                })?
                .ok_or(Error::ScopeMismatch)?;
            if fact.denied
                || fact.scope.selection_generation != counter
                || fact.scope.account != binding.approver_scope.account
                || fact.scope.local_device != binding.approver_scope.local_device
                || fact.draft.group_id != binding.group_id
                || fact.draft.successor != binding.predecessor
            {
                return Err(Error::ScopeMismatch);
            }
        }
        PrivateInviteOrigin::Existing(counter) => {
            let fact = storage
                .existing_device_group_anchor_storage()
                .ok_or(Error::Unsupported)?
                .existing_anchor()
                .map_err(Error::Storage)?
                .ok_or(Error::ScopeMismatch)?;
            if fact.denied
                || fact.generation != counter
                || fact.draft.account != binding.approver_scope.account
                || fact.draft.local_device != binding.approver_scope.local_device
                || fact.draft.group_id != binding.group_id
                || fact.draft.successor != binding.predecessor
            {
                return Err(Error::ScopeMismatch);
            }
        }
        PrivateInviteOrigin::Revoked(counter) => {
            let fact = {
                let conn = storage.lock().map_err(Error::Storage)?;
                crate::revoked_device_group_anchor::read(&conn)
                    .map_err(Error::Storage)?
                    .ok_or(Error::ScopeMismatch)?
            };
            if fact.denied
                || fact.generation != counter
                || fact.draft.account != binding.approver_scope.account
                || fact.draft.local_device != binding.approver_scope.local_device
                || fact.draft.group_id != binding.group_id
                || fact.draft.successor != binding.predecessor
            {
                return Err(Error::ScopeMismatch);
            }
        }
        PrivateInviteOrigin::Confirmed(_) => return Err(Error::ScopeMismatch),
    }
    Ok(())
}
impl PrivateDeviceInviteStorage for SqliteAccountStorage {
    fn private_invite(&self) -> Result<Option<PrivateInviteFact>> {
        let connection = self.lock()?;
        read_pending(&connection)
    }
    fn confirmed_private_invite(&self) -> Result<Option<ConfirmedPrivateInviteFact>> {
        let connection = self.lock()?;
        read_confirmed(&connection)
    }
    fn stage_private_invite(&self, draft: &PrivateInviteRawDraft) -> Result<PrivateInviteFact> {
        validate_raw(draft)?;
        let bytes = binding_bytes(&draft.binding)?;
        self.with_transaction(|storage| {
            check_origin(storage,&draft.binding)?;
            let connection=storage.lock()?;
            check_attempt(&connection,&draft.binding)?;
            let projection_matches:bool=connection.query_row("SELECT NOT EXISTS(SELECT 1 FROM account_state WHERE local_account_id_hex IS NULL OR local_account_id_hex<>?1)",[hex::encode(draft.binding.approver_scope.account)],|r|r.get(0)).storage()?;
            if !projection_matches {return Err(Error::ScopeMismatch);}
            if let Some(old)=read_pending(&connection)? {
                if old.scope.account!=draft.binding.approver_scope.account || old.scope.local_device!=draft.binding.approver_scope.local_device {return Err(Error::ScopeMismatch);}
                if matches!(old.phase,PrivateInvitePhase::RawStaged|PrivateInvitePhase::Wrapped) {
                    if old.raw==*draft {return Ok(old);}
                    return Err(Error::Busy);
                }
                if matches!(old.phase,PrivateInvitePhase::Dispatching|PrivateInvitePhase::PublicationUnknown) {return Err(Error::PublicationUncertain);}
                if draft.binding.approver_scope.generation<=old.raw.binding.approver_scope.generation {return Err(Error::ScopeMismatch);}
            }
            let counter:Option<i64>=connection.query_row("SELECT generation FROM private_device_invite_counter WHERE singleton=1",[],|r|r.get(0)).optional().storage()?;
            let next=counter.unwrap_or(0).checked_add(1).ok_or(Error::GenerationExhausted)?;
            if next<=0 {return Err(Error::GenerationExhausted);}
            connection.execute("INSERT INTO private_device_invite_counter(singleton,generation) VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation",[next]).storage()?;
            connection.execute("INSERT INTO private_device_invite_staging(singleton,generation,account,local_device,group_id,binding,raw_commit,raw_welcome,transport,phase) VALUES(1,?1,?2,?3,?4,?5,?6,?7,NULL,0) ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation,group_id=excluded.group_id,binding=excluded.binding,raw_commit=excluded.raw_commit,raw_welcome=excluded.raw_welcome,transport=NULL,phase=0",params![next,draft.binding.approver_scope.account.as_slice(),draft.binding.approver_scope.local_device.as_slice(),draft.binding.group_id.as_slice(),bytes,draft.commit,draft.welcome]).storage()?;
            Ok(PrivateInviteFact {scope:PrivateInviteScope {account:draft.binding.approver_scope.account,local_device:draft.binding.approver_scope.local_device,staging_generation:next as u64},raw:draft.clone(),transport:None,phase:PrivateInvitePhase::RawStaged})
        })
    }
    fn cache_private_invite_transport(
        &self,
        scope: &PrivateInviteScope,
        transport: &PrivateInviteTransport,
    ) -> Result<PrivateInviteFact> {
        self.with_transaction(|storage| {
            let current=storage.private_invite()?.ok_or(Error::ScopeMismatch)?;
            if current.scope!=*scope {return Err(Error::ScopeMismatch);}
            check_origin(storage,&current.raw.binding)?;
            let bytes=transport_bytes(&current.raw.binding,transport)?;
            let connection=storage.lock()?;
            check_attempt(&connection,&current.raw.binding)?;
            if current.phase==PrivateInvitePhase::Wrapped && current.transport.as_ref()==Some(transport) {return Ok(current);}
            if current.phase!=PrivateInvitePhase::RawStaged {return Err(Error::Busy);}
            connection.execute("UPDATE private_device_invite_staging SET transport=?1,phase=1 WHERE singleton=1",[bytes]).storage()?;
            exact_pending(&connection,scope)
        })
    }
    fn mark_private_invite_dispatch(
        &self,
        scope: &PrivateInviteScope,
    ) -> Result<PrivateInviteFact> {
        self.with_transaction(|storage| {
            let current = storage.private_invite()?.ok_or(Error::ScopeMismatch)?;
            if current.scope != *scope {
                return Err(Error::ScopeMismatch);
            }
            check_origin(storage, &current.raw.binding)?;
            let connection = storage.lock()?;
            check_attempt(&connection, &current.raw.binding)?;
            if current.phase != PrivateInvitePhase::Wrapped {
                return Err(Error::Busy);
            }
            connection
                .execute(
                    "UPDATE private_device_invite_staging SET phase=2 WHERE singleton=1",
                    [],
                )
                .storage()?;
            exact_pending(&connection, scope)
        })
    }
    fn mark_private_invite_publication_unknown(&self, scope: &PrivateInviteScope) -> Result<()> {
        self.with_transaction(|storage| {
            let connection = storage.lock()?;
            let current = exact_pending(&connection, scope)?;
            if !matches!(
                current.phase,
                PrivateInvitePhase::Dispatching | PrivateInvitePhase::PublicationUnknown
            ) {
                return Err(Error::ScopeMismatch);
            }
            connection
                .execute(
                    "UPDATE private_device_invite_staging SET phase=3 WHERE singleton=1",
                    [],
                )
                .storage()?;
            Ok(())
        })
    }
    fn confirm_private_invite(
        &self,
        scope: &PrivateInviteScope,
        actual_successor: &DeviceGroupAnchorRoster,
    ) -> Result<ConfirmedPrivateInviteFact> {
        self.with_transaction(|storage| {
            let pending = storage.private_invite()?.ok_or(Error::ScopeMismatch)?;
            if pending.scope != *scope {
                return Err(Error::ScopeMismatch);
            }
            // Controlled handoff must preserve origin validity until this unit
            // completes. A delayed callback cannot clear permanent denial.
            if pending.phase != PrivateInvitePhase::Confirmed {
                check_origin(storage, &pending.raw.binding)?;
            }
            let connection=storage.lock()?;
            let current=exact_pending(&connection,scope)?;
            if current.raw.binding.successor!=*actual_successor {return Err(Error::ScopeMismatch);}
            if current.phase==PrivateInvitePhase::Confirmed {
                let fact=read_confirmed(&connection)?.ok_or(Error::ScopeMismatch)?;
                if fact.scope==*scope && fact.binding==current.raw.binding && !fact.denied {return Ok(fact);}
                return Err(Error::ScopeMismatch);
            }
            if !matches!(current.phase,PrivateInvitePhase::Dispatching|PrivateInvitePhase::PublicationUnknown) {return Err(Error::ScopeMismatch);}
            let old=read_confirmed(&connection)?;
            if old.as_ref().is_some_and(|old| old.scope.account!=scope.account || old.scope.local_device!=scope.local_device || old.scope.staging_generation>=scope.staging_generation) {
                return Err(Error::ScopeMismatch);
            }
            if let PrivateInviteOrigin::Confirmed(origin_generation)=current.raw.binding.origin {
                let old=old.as_ref().ok_or(Error::ScopeMismatch)?;
                if old.denied || old.scope.staging_generation!=origin_generation
                    || old.binding.group_id!=current.raw.binding.group_id
                    || old.binding.successor!=current.raw.binding.predecessor {return Err(Error::ScopeMismatch);}
            } else if let Some(old) = old.as_ref().filter(|old| old.binding.group_id==current.raw.binding.group_id) {
                // check_origin freshly validated the exact existing/removal successor.
                // A denied historical confirmation must not veto this new generation;
                // it still cannot be reused as the current Confirmed origin above.
                if !old.denied || !matches!(current.raw.binding.origin,
                    PrivateInviteOrigin::Existing(_) | PrivateInviteOrigin::Revoked(_)) {
                    return Err(Error::ScopeMismatch);
                }
            }
            let bytes=binding_bytes(&current.raw.binding)?;
            connection.execute("INSERT INTO private_device_invite_confirmed(singleton,generation,account,local_device,group_id,binding,denied) VALUES(1,?1,?2,?3,?4,?5,0) ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation,group_id=excluded.group_id,binding=excluded.binding,denied=0",params![generation(scope.staging_generation)?,scope.account.as_slice(),scope.local_device.as_slice(),current.raw.binding.group_id.as_slice(),bytes]).storage()?;
            connection.execute("UPDATE private_device_invite_staging SET phase=5 WHERE singleton=1",[]).storage()?;
            Ok(ConfirmedPrivateInviteFact {scope:scope.clone(),binding:current.raw.binding,denied:false})
        })
    }
    fn retire_undispatched_private_invite(&self, scope: &PrivateInviteScope) -> Result<()> {
        self.with_transaction(|storage| {
            let connection = storage.lock()?;
            let current = exact_pending(&connection, scope)?;
            if matches!(
                current.phase,
                PrivateInvitePhase::Dispatching | PrivateInvitePhase::PublicationUnknown
            ) {
                return Err(Error::PublicationUncertain);
            }
            if current.phase == PrivateInvitePhase::Confirmed {
                return Err(Error::ScopeMismatch);
            }
            connection
                .execute(
                    "UPDATE private_device_invite_staging SET phase=4 WHERE singleton=1",
                    [],
                )
                .storage()?;
            Ok(())
        })
    }
    fn deny_confirmed_private_invite(
        &self,
        scope: &PrivateInviteScope,
        group: &GroupId,
    ) -> Result<()> {
        self.with_transaction(|storage| {
            let connection = storage.lock()?;
            let current = read_confirmed(&connection)?.ok_or(Error::ScopeMismatch)?;
            if current.scope != *scope || current.binding.group_id != *group {
                return Err(Error::ScopeMismatch);
            }
            connection
                .execute(
                    "UPDATE private_device_invite_confirmed SET denied=1 WHERE singleton=1",
                    [],
                )
                .storage()?;
            Ok(())
        })
    }
}
