//! Account-wide negative intents over genuine approved channels. Ordinary MLS
//! leaves are still performed independently by each actual owning device.
use super::*;
use crate::{
    AccountChatDepartureReason as Reason, AccountChatDepartureState as View,
    AccountChatDepartureStatus as Status, AppError,
};
use cgka_traits::{
    EngineError,
    storage::{StorageError, StorageResult},
};
use std::collections::BTreeMap;
use storage_sqlite::account_chat_departure::{
    AccountChatDepartureDeliveryKind as DeliveryKind, AccountChatDepartureIntent as Intent,
    AccountChatDepartureLocalState as LocalState, AccountChatDepartureTarget as Target,
    MAX_ACCOUNT_CHAT_DEPARTURE_BYTES,
};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum ReceiptPhase {
    PeerStatus,
    CoordinatorComplete,
    CompletionAcknowledgement,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u8,
    action_id: [u8; 32],
    phase: ReceiptPhase,
    complete: bool,
    needs_administrator: bool,
    awaiting_sources: bool,
}
struct Publication {
    action_id: [u8; 32],
    is_reply: bool,
}
#[derive(Default)]
pub(super) struct DepartureProgress {
    assembly: Option<(AccountSharedBodyKind, Assembly)>,
    pending: Option<Publication>,
    cursor: Option<[u8; 32]>,
    last: Option<([u8; 32], [u8; 32], std::time::Instant)>,
}

fn failure() -> AccountSharingError {
    AccountSharingError::NotReady
}
fn app_failure(error: AccountSharingError) -> AppError {
    match error {
        AccountSharingError::RuntimeUnavailable => AppError::TransportClosed,
        _ => AppError::InvalidAppMessagePayload("approved account departure is unavailable".into()),
    }
}

impl AppClient {
    fn departure_policies(&self) -> Result<Vec<ApprovedAccountSharingPolicy>, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let Some(store) = storage.approved_account_sharing_policy_storage() else {
            return Ok(Vec::new());
        };
        let mut result = Vec::new();
        for policy in store.approved_account_sharing_policies()? {
            if policy.revoked {
                continue;
            }
            match self.automatic_policy_current(&policy) {
                Ok(()) => result.push(policy),
                Err(AccountSharingError::Closed | AccountSharingError::NotReady) => {}
                Err(error) => return Err(app_failure(error)),
            }
        }
        result.sort_by_key(|policy| policy.peer_device);
        if let Some(first) = result.first() {
            if result.iter().any(|policy| {
                policy.account != first.account
                    || policy.local_device != first.local_device
                    || policy.protected_group != first.protected_group
            }) || result.len() > 128
            {
                return Err(app_failure(failure()));
            }
        }
        Ok(result)
    }

    fn departure_policy_tail(
        &self,
        policies: &[ApprovedAccountSharingPolicy],
    ) -> StorageResult<()> {
        for policy in policies {
            self.automatic_policy_current(policy).map_err(|_| {
                StorageError::Serialization("account departure original unavailable".into())
            })?;
        }
        Ok(())
    }

    /// Readiness needs all actual source-origin observations, not merely a name
    /// or an account roster. The authenticated count is advisory, never membership.
    fn departure_targets(
        &self,
        group: &crate::GroupId,
        policies: &[ApprovedAccountSharingPolicy],
    ) -> Result<(Vec<Target>, bool), AppError> {
        let Some(first) = policies.first() else {
            return Ok((Vec::new(), false));
        };
        let storage = self.app.account_storage(&self.state.label)?;
        let mut targets = BTreeMap::new();
        let mut expected = 0usize;
        let mut missing = false;
        match storage.get_group(group) {
            Ok(_) => {
                let membership = self
                    .runtime
                    .session()
                    .canonical_group_membership(group)
                    .map_err(cgka_session::SessionError::from)?;
                if membership.local_leaf_active {
                    expected = membership
                        .member_leaves
                        .iter()
                        .filter(|leaf| leaf.member.as_slice() == first.account)
                        .count();
                    if let Some(origin) = storage.current_account_chat_source_origin(
                        &first.account,
                        &first.local_device,
                        group,
                    )? {
                        targets.insert(first.local_device, origin);
                    } else {
                        missing = true;
                    }
                }
            }
            Err(StorageError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        let mut after = None;
        loop {
            let page = self
                .current_mirrored_catalog_page(after.as_ref(), 128)
                .map_err(app_failure)?;
            for row in page.iter().filter(|row| {
                &row.entry.group_id == group && row.entry.state == MirroredChatState::Active
            }) {
                if row.scope.account != first.account
                    || row.scope.local_device != first.local_device
                    || row.scope.protected_group != first.protected_group
                {
                    return Err(app_failure(failure()));
                }
                if let Some(count) = row.entry.same_account_source_count {
                    if !(1..=128).contains(&count) {
                        return Err(app_failure(failure()));
                    }
                    expected = expected.max(count as usize);
                } else {
                    missing = true;
                }
                if let Some(origin) = row.entry.accepted_origin {
                    if targets
                        .insert(row.scope.source_device, origin)
                        .is_some_and(|old| old != origin)
                    {
                        return Err(app_failure(failure()));
                    }
                } else {
                    missing = true;
                }
            }
            if page.len() < 128 {
                break;
            }
            after = page.last().map(|row| row.entry.group_id.clone());
        }
        self.departure_policy_tail(policies)?;
        if expected == 0 || targets.is_empty() || targets.len() < expected || targets.len() > 128 {
            missing = true;
        }
        Ok((
            targets
                .into_iter()
                .map(|(source_device, accepted_origin)| Target {
                    source_device,
                    accepted_origin,
                })
                .collect(),
            missing,
        ))
    }

    pub(crate) fn approved_account_chat_departure_state(
        &self,
        group: &crate::GroupId,
    ) -> Result<Option<View>, AppError> {
        let policies = self.departure_policies()?;
        let Some(first) = policies.first() else {
            return Ok(None);
        };
        let storage = self.app.account_storage(&self.state.label)?;
        let (targets, missing) = self.departure_targets(group, &policies)?;
        let any_cut = targets
            .iter()
            .map(|target| {
                storage.account_chat_departure_denies_source(
                    &first.account,
                    &first.local_device,
                    group,
                    &target.source_device,
                    Some(target.accepted_origin),
                )
            })
            .collect::<StorageResult<Vec<_>>>()?
            .into_iter()
            .any(|cut| cut);
        if !missing && !any_cut {
            let admin = match storage.get_group(group) {
                Err(StorageError::NotFound) => false,
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    self.runtime
                        .session()
                        .group_authority(group)
                        .map_err(cgka_session::SessionError::from)?
                        .facts
                        .is_admin
                }
            };
            return Ok(Some(View {
                status: if admin {
                    Status::NeedsAdministrator
                } else {
                    Status::Available
                },
                reason: if admin {
                    Reason::AwaitingAdministrator
                } else {
                    Reason::None
                },
                operation_id: None,
            }));
        }
        if !targets.is_empty() && !any_cut {
            // Fresh lineage observations must not inherit a prior operation's
            // completed state while another real source is still undiscovered.
            return Ok(Some(View {
                status: Status::Unavailable,
                reason: Reason::AwaitingSources,
                operation_id: None,
            }));
        }
        if let Some(progress) =
            storage.account_chat_departure_progress(&first.account, &first.local_device, group)?
        {
            let status = if progress.needs_administrator {
                Status::NeedsAdministrator
            } else if progress.global_complete && progress.local_complete {
                Status::Completed
            } else {
                Status::Pending
            };
            return Ok(Some(View {
                status,
                reason: if progress.needs_administrator {
                    Reason::AwaitingAdministrator
                } else if progress.awaiting_sources {
                    Reason::AwaitingSources
                } else {
                    Reason::None
                },
                operation_id: Some(hex::encode(progress.action_id)),
            }));
        }
        Ok(Some(View {
            status: Status::Unavailable,
            reason: Reason::AwaitingSources,
            operation_id: None,
        }))
    }

    pub(crate) fn admit_account_chat_departure(
        &mut self,
        group: &crate::GroupId,
    ) -> Result<Option<View>, AppError> {
        let policies = self.departure_policies()?;
        let Some(first) = policies.first() else {
            return Ok(None);
        };
        let current = self
            .approved_account_chat_departure_state(group)?
            .ok_or_else(|| app_failure(failure()))?;
        if current.status != Status::Available {
            return Ok(Some(current));
        }
        let (targets, missing) = self.departure_targets(group, &policies)?;
        if missing {
            return Ok(Some(View {
                status: Status::Unavailable,
                reason: Reason::AwaitingSources,
                operation_id: None,
            }));
        }
        let mut intent = Intent {
            version: 1,
            action_id: [0; 32],
            account: first.account,
            initiator: first.local_device,
            protected_group: first.protected_group.clone(),
            group: group.clone(),
            targets,
        };
        intent.action_id = intent.identity();
        let peers: Vec<_> = policies.iter().map(|policy| policy.peer_device).collect();
        let storage = self.app.account_storage(&self.state.label)?;
        storage.apply_account_chat_departure(&first.local_device, &intent, &peers, &|| {
            self.departure_policy_tail(&policies)?;
            // Cuts filter the live view within this transaction. Re-reading that
            // filtered view at the tail would reject our own newly admitted cut.
            // Revalidate immutable target observations and the actual original.
            self.validate_departure_target_observations(&intent, &policies)?;
            Ok(())
        })?;
        self.invalidate_after_account_departure();
        self.notify_mirrored_presentation_changed();
        Ok(Some(View {
            status: Status::Pending,
            reason: Reason::None,
            operation_id: Some(hex::encode(intent.action_id)),
        }))
    }

    fn validate_departure_target_observations(
        &self,
        intent: &Intent,
        policies: &[ApprovedAccountSharingPolicy],
    ) -> StorageResult<()> {
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| StorageError::Backend("account departure storage unavailable".into()))?;
        let first = policies.first().ok_or_else(|| {
            StorageError::Serialization("account departure original unavailable".into())
        })?;
        for target in &intent.targets {
            let observed = if target.source_device == first.local_device {
                storage.account_chat_source_origin_was_accepted(
                    &first.account,
                    &first.local_device,
                    &intent.group,
                    target.accepted_origin,
                )?
            } else {
                // Retained authenticated lineage observation survives negative
                // live-view filtering; it supplies no original or MLS authority.
                storage
                    .current_mirrored_chat_origin_observation(
                        &first.account,
                        &first.local_device,
                        &target.source_device,
                        &intent.group,
                    )?
                    .is_some_and(|origin| {
                        origin == target.accepted_origin
                            || (origin.id != target.accepted_origin.id
                                && origin.order > target.accepted_origin.order)
                    })
            };
            if !observed {
                return Err(StorageError::Serialization(
                    "account departure source observation unavailable".into(),
                ));
            }
        }
        Ok(())
    }

    fn invalidate_after_account_departure(&mut self) {
        for entry in self.account_sharing_owner.automatic.values_mut() {
            entry.renew = true;
        }
    }

    fn departure_original(&self, entry: &AutomaticChannel) -> StorageResult<()> {
        self.automatic_policy_current(&entry.policy)
            .map_err(|_| StorageError::Serialization("account departure policy changed".into()))?;
        self.runtime
            .session()
            .validate_account_sharing_channel(&entry.channel)
            .map_err(|_| StorageError::Serialization("account departure original changed".into()))
    }

    pub(super) fn accept_automatic_departure(
        &mut self,
        entry: &mut AutomaticChannel,
        kind: AccountSharedBodyKind,
        bytes: &[u8],
    ) -> Result<(), AccountSharingError> {
        self.departure_original(entry).map_err(|_| failure())?;
        let fragment: CatalogFragment = serde_json::from_slice(bytes).map_err(|_| failure())?;
        if fragment.version != 1
            || fragment.count == 0
            || fragment.count as usize > MAX_ACCOUNT_CHAT_DEPARTURE_BYTES.div_ceil(FRAGMENT_BYTES)
            || fragment.ordinal >= fragment.count
        {
            return Err(failure());
        }
        let part = base64::engine::general_purpose::STANDARD
            .decode(&fragment.body)
            .map_err(|_| failure())?;
        if part.is_empty()
            || part.len() > FRAGMENT_BYTES
            || base64::engine::general_purpose::STANDARD.encode(&part) != fragment.body
        {
            return Err(failure());
        }
        if entry
            .departures
            .assembly
            .as_ref()
            .is_none_or(|(old_kind, assembly)| {
                *old_kind != kind || assembly.digest != fragment.digest
            })
        {
            entry.departures.assembly = Some((
                kind,
                Assembly {
                    digest: fragment.digest,
                    fragments: vec![None; fragment.count as usize],
                },
            ));
        }
        let (_, assembly) = entry.departures.assembly.as_mut().ok_or_else(failure)?;
        if assembly.fragments.len() != fragment.count as usize {
            return Err(failure());
        }
        let slot = &mut assembly.fragments[fragment.ordinal as usize];
        if slot.as_ref().is_some_and(|old| old != &part) {
            return Err(failure());
        }
        *slot = Some(part);
        if assembly.fragments.iter().any(Option::is_none) {
            return Ok(());
        }
        let body: Vec<u8> = assembly
            .fragments
            .iter()
            .flat_map(|part| part.as_ref().expect("complete fragments").iter().copied())
            .collect();
        if body.len() > MAX_ACCOUNT_CHAT_DEPARTURE_BYTES
            || <[u8; 32]>::from(Sha256::digest(&body)) != assembly.digest
        {
            return Err(failure());
        }
        self.commit_automatic_departure_body(entry, kind, &body)
    }

    fn commit_automatic_departure_body(
        &mut self,
        entry: &mut AutomaticChannel,
        kind: AccountSharedBodyKind,
        body: &[u8],
    ) -> Result<(), AccountSharingError> {
        self.departure_original(entry).map_err(|_| failure())?;
        // Retain complete assembly until all fallible transactional work succeeds.
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        match kind {
            AccountSharedBodyKind::DepartureIntent => {
                let intent: Intent = serde_json::from_slice(body).map_err(|_| failure())?;
                intent.validate().map_err(|_| failure())?;
                if intent.account != entry.policy.account
                    || intent.initiator != entry.policy.peer_device
                    || intent.protected_group != entry.policy.protected_group
                {
                    return Err(failure());
                }
                let roster = self
                    .runtime
                    .session()
                    .account_chat_sharing_targets(&entry.policy.protected_group)
                    .map_err(|_| failure())?;
                if intent.targets.iter().any(|target| {
                    target.source_device != entry.policy.local_device
                        && !roster
                            .targets
                            .iter()
                            .any(|peer| peer.device == target.source_device)
                }) {
                    return Err(failure());
                }
                storage
                    .apply_account_chat_departure(
                        &entry.policy.local_device,
                        &intent,
                        &[entry.policy.peer_device],
                        &|| {
                            self.departure_original(entry)?;
                            self.validate_departure_target_observations(
                                &intent,
                                std::slice::from_ref(&entry.policy),
                            )
                        },
                    )
                    .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
                entry.renew = true;
                self.invalidate_after_account_departure();
                self.notify_mirrored_presentation_changed();
            }
            AccountSharedBodyKind::DepartureReceipt => {
                let receipt: Receipt = serde_json::from_slice(body).map_err(|_| failure())?;
                if receipt.version != 1
                    || (receipt.complete
                        && (receipt.needs_administrator || receipt.awaiting_sources))
                {
                    return Err(failure());
                }
                match receipt.phase {
                    ReceiptPhase::PeerStatus => storage.acknowledge_account_chat_departure(
                        &entry.policy.account,
                        &entry.policy.local_device,
                        &receipt.action_id,
                        &entry.policy.peer_device,
                        receipt.complete,
                        receipt.needs_administrator,
                        receipt.awaiting_sources,
                        &|| self.departure_original(entry),
                    ),
                    ReceiptPhase::CoordinatorComplete => {
                        if !receipt.complete {
                            return Err(failure());
                        }
                        storage.account_chat_departure_completion(
                            &entry.policy.account,
                            &entry.policy.local_device,
                            &receipt.action_id,
                            &entry.policy.peer_device,
                            false,
                            &|| self.departure_original(entry),
                        )
                    }
                    ReceiptPhase::CompletionAcknowledgement => {
                        if !receipt.complete {
                            return Err(failure());
                        }
                        storage.account_chat_departure_completion(
                            &entry.policy.account,
                            &entry.policy.local_device,
                            &receipt.action_id,
                            &entry.policy.peer_device,
                            true,
                            &|| self.departure_original(entry),
                        )
                    }
                }
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
            }
            _ => return Err(failure()),
        }
        entry.departures.assembly = None;
        Ok(())
    }

    pub(super) fn retry_automatic_departure(
        &mut self,
        entry: &mut AutomaticChannel,
    ) -> Result<(), AccountSharingError> {
        let Some((kind, assembly)) = entry.departures.assembly.as_ref() else {
            return Ok(());
        };
        if assembly.fragments.iter().any(Option::is_none) {
            return Ok(());
        }
        let kind = *kind;
        let body: Vec<u8> = assembly
            .fragments
            .iter()
            .flat_map(|part| part.as_ref().expect("complete fragments").iter().copied())
            .collect();
        self.commit_automatic_departure_body(entry, kind, &body)
    }

    pub(super) fn prepare_automatic_departure(
        &self,
        entry: &mut AutomaticChannel,
    ) -> Result<(), AccountSharingError> {
        if entry.departures.pending.is_some() {
            return Ok(());
        }
        self.departure_original(entry).map_err(|_| failure())?;
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        let rows = storage
            .account_chat_departure_outbox(
                &entry.policy.account,
                &entry.policy.local_device,
                &entry.policy.peer_device,
                entry.departures.cursor.as_ref(),
                1,
            )
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        let Some(row) = rows.first() else {
            entry.departures.cursor = None;
            return Ok(());
        };
        let (kind, bytes, is_reply) = match row.kind {
            DeliveryKind::Intent => (
                AccountSharedBodyKind::DepartureIntent,
                serde_json::to_vec(&row.intent).map_err(|_| failure())?,
                false,
            ),
            DeliveryKind::StatusReceipt
            | DeliveryKind::CompletionNotice
            | DeliveryKind::CompletionAcknowledgement => {
                let phase = match row.kind {
                    DeliveryKind::StatusReceipt => ReceiptPhase::PeerStatus,
                    DeliveryKind::CompletionNotice => ReceiptPhase::CoordinatorComplete,
                    _ => ReceiptPhase::CompletionAcknowledgement,
                };
                let receipt = Receipt {
                    version: 1,
                    action_id: row.intent.action_id,
                    phase,
                    complete: row.complete,
                    needs_administrator: row.needs_administrator,
                    awaiting_sources: row.awaiting_sources,
                };
                (
                    AccountSharedBodyKind::DepartureReceipt,
                    serde_json::to_vec(&receipt).map_err(|_| failure())?,
                    phase != ReceiptPhase::CoordinatorComplete,
                )
            }
        };
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if entry.departures.last.is_some_and(|(id, old, when)| {
            id == row.intent.action_id
                && old == digest
                && when.elapsed() < std::time::Duration::from_secs(10)
        }) {
            entry.departures.cursor = Some(row.intent.action_id);
            return Ok(());
        }
        let count = bytes.len().div_ceil(FRAGMENT_BYTES) as u32;
        if bytes.is_empty() || bytes.len() > MAX_ACCOUNT_CHAT_DEPARTURE_BYTES {
            return Err(failure());
        }
        if entry.next_body + u64::from(count) > CHANNEL_BODY_BUDGET {
            entry.renew = true;
            return Ok(());
        }
        for (ordinal, part) in bytes.chunks(FRAGMENT_BYTES).enumerate() {
            entry.pending.push_back(PendingBody {
                kind,
                bytes: serde_json::to_vec(&CatalogFragment {
                    version: 1,
                    digest,
                    ordinal: ordinal as u32,
                    count,
                    body: base64::engine::general_purpose::STANDARD.encode(part),
                })
                .map_err(|_| failure())?,
            });
        }
        entry.departures.pending = Some(Publication {
            action_id: row.intent.action_id,
            is_reply,
        });
        entry.departures.last = Some((row.intent.action_id, digest, std::time::Instant::now()));
        Ok(())
    }

    pub(super) fn automatic_departure_mark_published(
        &self,
        entry: &mut AutomaticChannel,
    ) -> Result<(), AccountSharingError> {
        if !entry.pending.is_empty() {
            return Ok(());
        }
        if let Some(publication) = entry.departures.pending.take() {
            if publication.is_reply {
                self.app
                    .account_storage(&self.state.label)
                    .map_err(|_| AccountSharingError::RuntimeUnavailable)?
                    .account_chat_departure_reply_published(
                        &entry.policy.account,
                        &entry.policy.local_device,
                        &publication.action_id,
                        &|| self.departure_original(entry),
                    )
                    .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
            }
            entry.departures.cursor = Some(publication.action_id);
        }
        Ok(())
    }

    pub(super) async fn maintain_local_account_chat_departures(
        &mut self,
        policies: &[ApprovedAccountSharingPolicy],
    ) -> Result<(), AccountSharingError> {
        let Some(first) = policies.first() else {
            return Ok(());
        };
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        let rows = storage
            .pending_local_account_chat_departures(
                &first.account,
                &first.local_device,
                self.account_sharing_owner.departure_cursor.as_ref(),
                16,
            )
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        if rows.is_empty() {
            self.account_sharing_owner.departure_cursor = None;
        }
        for (intent, state) in rows {
            self.account_sharing_owner.departure_cursor = Some(intent.action_id);
            let authorized: Vec<_> = policies
                .iter()
                .filter(|policy| {
                    policy.account == intent.account
                        && policy.protected_group == intent.protected_group
                        && (intent.initiator == policy.local_device
                            || intent.initiator == policy.peer_device)
                })
                .cloned()
                .collect();
            if authorized.is_empty() || self.departure_policy_tail(&authorized).is_err() {
                continue;
            }
            let own_target = intent
                .targets
                .iter()
                .find(|target| target.source_device == first.local_device);
            match storage.get_group(&intent.group) {
                Err(StorageError::NotFound) if own_target.is_none() => {
                    storage
                        .mark_account_chat_departure_local_state(
                            &first.account,
                            &first.local_device,
                            &intent.action_id,
                            LocalState::Complete,
                            &|| self.departure_policy_tail(&authorized),
                        )
                        .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
                    continue;
                }
                Err(StorageError::NotFound) => continue,
                Err(_) => return Err(AccountSharingError::RuntimeUnavailable),
                Ok(_) => {}
            }
            let canonical = self
                .runtime
                .session()
                .canonical_group_membership(&intent.group)
                .map_err(|_| failure())?;
            if !canonical.local_leaf_active {
                storage
                    .mark_account_chat_departure_local_state(
                        &first.account,
                        &first.local_device,
                        &intent.action_id,
                        LocalState::Complete,
                        &|| self.departure_policy_tail(&authorized),
                    )
                    .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
                continue;
            }
            let origin = storage
                .current_account_chat_source_origin(
                    &first.account,
                    &first.local_device,
                    &intent.group,
                )
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
            let Some(target) = own_target else {
                storage
                    .mark_account_chat_departure_awaiting_sources(
                        &first.account,
                        &first.local_device,
                        &intent.action_id,
                        true,
                        &|| self.departure_policy_tail(&authorized),
                    )
                    .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
                continue;
            }; // Never retire an undiscovered or newly accepted source.
            if origin.is_some_and(|origin| {
                origin != target.accepted_origin && origin.order > target.accepted_origin.order
            }) {
                storage
                    .mark_account_chat_departure_local_state(
                        &first.account,
                        &first.local_device,
                        &intent.action_id,
                        LocalState::Complete,
                        &|| self.departure_policy_tail(&authorized),
                    )
                    .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
                continue;
            }
            if !storage
                .account_chat_source_origin_was_accepted(
                    &first.account,
                    &first.local_device,
                    &intent.group,
                    target.accepted_origin,
                )
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?
            {
                return Err(failure());
            }
            if state == LocalState::Published {
                continue;
            }
            let authority = self
                .runtime
                .session()
                .group_authority(&intent.group)
                .map_err(|_| failure())?;
            if authority.facts.is_admin {
                storage
                    .mark_account_chat_departure_needs_administrator(
                        &first.account,
                        &first.local_device,
                        &intent.action_id,
                        true,
                        &|| self.departure_policy_tail(&authorized),
                    )
                    .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
                continue;
            }
            // Preserve the established public SelfRemove, push-registration
            // compensation, pending-leave journal, and ordinary publisher.
            match Box::pin(self.leave_group(&intent.group)).await {
                Ok(_)
                | Err(AppError::Session(cgka_session::SessionError::Engine(
                    EngineError::LeaveAlreadyRequested { .. },
                ))) => {
                    storage
                        .mark_account_chat_departure_local_state(
                            &first.account,
                            &first.local_device,
                            &intent.action_id,
                            LocalState::Published,
                            &|| self.departure_policy_tail(&authorized),
                        )
                        .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
                }
                Err(_) => return Err(AccountSharingError::RuntimeUnavailable), // Durable work remains pending for retry.
            }
        }
        storage
            .finalize_account_chat_departure_coordinator(
                &first.account,
                &first.local_device,
                &|| self.departure_policy_tail(policies),
            )
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        Ok(())
    }
}
