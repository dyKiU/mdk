//! Fresh scheduling from durable explicit policy. Stored facts do not restore keys.
use super::*;
use crate::account_chat_sharing::enabled::OriginalLease;
use base64::Engine as _;
use cgka_engine::account_chat_sharing::{AccountSharedBodyKind, OwnedAccountSharingChannel};
use cgka_traits::approved_account_sharing_policy::{
    ApprovedAccountSharingPolicy, approved_account_sharing_identity,
};
use cgka_traits::mirrored_chat_catalog::{MirroredChatEntry, MirroredChatScope, MirroredChatState};
use cgka_traits::storage::GroupStorage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
const FRAGMENT_BYTES: usize = 768;
const MAX_ENTRY_BYTES: usize = 65536;
const CHANNEL_BODY_BUDGET: u64 = 100;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFragment {
    version: u8,
    digest: [u8; 32],
    ordinal: u32,
    count: u32,
    body: String,
}
struct Assembly {
    digest: [u8; 32],
    count: u32,
    bytes: Vec<u8>,
    next: u32,
}
struct CatalogProgress {
    generation: u64,
    cursor: Option<crate::GroupId>,
    inventory_digest: Option<[u8; 32]>,
    sent: BTreeMap<Vec<u8>, [u8; 32]>,
}
pub(crate) struct AutomaticChannel {
    original: Arc<State>,
    policy: ApprovedAccountSharingPolicy,
    channel: OwnedAccountSharingChannel,
    recipient: bool,
    ready: bool,
    handshake_published: bool,
    pending: VecDeque<Vec<u8>>,
    next_body: u64,
    cursor: Option<crate::GroupId>,
    inventory_digest: Option<[u8; 32]>,
    sent: BTreeMap<Vec<u8>, [u8; 32]>,
    assembly: Option<Assembly>,
    pending_catalog: Option<(crate::GroupId, [u8; 32])>,
    renew: bool,
}
impl AutomaticChannel {
    fn take_catalog_progress(&mut self) -> CatalogProgress {
        CatalogProgress {
            generation: self.channel.scope().local_generation,
            cursor: self.cursor.take(),
            inventory_digest: self.inventory_digest.take(),
            sent: std::mem::take(&mut self.sent),
        }
    }
    fn restore_catalog_progress(&mut self, progress: Option<CatalogProgress>) {
        if let Some(progress) = progress
            && progress.generation == self.channel.scope().local_generation
        {
            self.cursor = progress.cursor;
            self.inventory_digest = progress.inventory_digest;
            self.sent = progress.sent;
        }
    }
}
impl Drop for AutomaticChannel {
    fn drop(&mut self) {
        self.original.cancel();
        self.channel.retire();
    }
}
impl AppClient {
    fn automatic_policy_id(
        policy: &ApprovedAccountSharingPolicy,
    ) -> Result<[u8; 32], AccountSharingError> {
        approved_account_sharing_identity(
            &policy.account,
            &policy.protected_group,
            &policy.local_device,
            &policy.peer_device,
            &policy.approval_id,
        )
        .map_err(|_| AccountSharingError::NotReady)
    }
    fn automatic_policy_current(
        &self,
        policy: &ApprovedAccountSharingPolicy,
    ) -> Result<(), AccountSharingError> {
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        let facts = storage
            .approved_account_sharing_policy_storage()
            .ok_or(AccountSharingError::NotReady)?
            .approved_account_sharing_policies()
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        if policy.revoked || !facts.iter().any(|current| current == policy) {
            return Err(AccountSharingError::Closed);
        }
        let current = self
            .runtime
            .session()
            .account_chat_sharing_targets(&policy.protected_group)
            .map_err(|_| AccountSharingError::Closed)?;
        if current.protected_epoch < policy.approved_protected_epoch
            || !current
                .targets
                .iter()
                .any(|target| target.device == policy.peer_device)
        {
            return Err(AccountSharingError::Closed);
        }
        if let Some(negative) = storage.revoked_device_group_anchor_storage()
            && negative
                .revoked_anchors()
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?
                .iter()
                .any(|fact| {
                    fact.draft.group_id == policy.protected_group
                        && fact.draft.removed_device == policy.peer_device
                        && fact.draft.successor.epoch.0 > policy.approved_protected_epoch
                })
        {
            return Err(AccountSharingError::Closed);
        }
        Ok(())
    }
    pub(super) fn observe_automatic_sharing_control(
        &mut self,
        received: &cgka_engine::account_chat_sharing::ReceivedAccountSharingControl,
        wire: &[u8],
    ) -> Result<bool, AccountSharingError> {
        if received.control == AccountSharingControl::Request {
            let Ok(request) = self
                .runtime
                .session()
                .authenticate_account_sharing_request(wire)
            else {
                return Ok(false);
            };
            let storage = self
                .app
                .account_storage(&self.state.label)
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
            let Some(store) = storage.approved_account_sharing_policy_storage() else {
                return Ok(false);
            };
            let matching = store
                .approved_account_sharing_policies()
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?
                .into_iter()
                .find(|fact| {
                    !fact.revoked
                        && fact.approval_id == request.scope().approval_id
                        && fact.protected_group == request.scope().protected.group_id
                        && fact.local_device.as_slice() == request.scope().recipient
                        && fact.peer_device.as_slice() == request.scope().source
                        && Self::automatic_policy_id(fact).ok()
                            == Some(request.scope().approved_policy_identity)
                });
            let Some(policy) = matching else {
                return Ok(false);
            };
            self.automatic_policy_current(&policy)?;
            let id = Self::automatic_policy_id(&policy)?;
            if self
                .account_sharing_owner
                .automatic
                .get(&id)
                .is_some_and(|entry| entry.channel.scope().nonce == received.nonce)
            {
                return Ok(true);
            }
            let original = State::new(&self.account_sharing_owner.lifetime, policy.approval_id);
            let channel = self
                .runtime
                .session()
                .approve_account_sharing_policy(
                    &request,
                    Arc::new(OriginalLease(Arc::downgrade(&original))),
                )
                .map_err(|_| AccountSharingError::NotReady)?;
            let progress = self
                .account_sharing_owner
                .automatic
                .get_mut(&id)
                .map(AutomaticChannel::take_catalog_progress);
            self.account_sharing_owner.automatic.insert(
                id,
                AutomaticChannel {
                    original,
                    policy,
                    channel,
                    recipient: true,
                    ready: false,
                    handshake_published: false,
                    pending: VecDeque::new(),
                    next_body: 0,
                    cursor: None,
                    inventory_digest: None,
                    sent: BTreeMap::new(),
                    assembly: None,
                    pending_catalog: None,
                    renew: false,
                },
            );
            self.account_sharing_owner
                .automatic
                .get_mut(&id)
                .expect("inserted automatic channel")
                .restore_catalog_progress(progress);
            return Ok(true);
        }
        let id = self
            .account_sharing_owner
            .automatic
            .iter()
            .find(|(_, entry)| entry.channel.scope().nonce == received.nonce)
            .map(|(id, _)| *id);
        let Some(id) = id else { return Ok(false) };
        let mut entry = self
            .account_sharing_owner
            .automatic
            .remove(&id)
            .expect("found automatic channel");
        let result = (|| {
            self.automatic_policy_current(&entry.policy)?;
            if received.control == AccountSharingControl::Consent && !entry.recipient {
                self.runtime
                    .session()
                    .bind_account_sharing_consent(&mut entry.channel, wire)
                    .map_err(|_| AccountSharingError::NotReady)?;
                entry.ready = true;
            } else if matches!(received.control, AccountSharingControl::Body(_)) && entry.ready {
                let (kind, _, body) = self
                    .runtime
                    .session()
                    .open_account_shared_body(&entry.channel, wire)
                    .map_err(|_| AccountSharingError::NotReady)?;
                if kind == AccountSharedBodyKind::Catalog {
                    self.accept_automatic_catalog(&mut entry, &body)?;
                }
            }
            Ok(true)
        })();
        self.account_sharing_owner.automatic.insert(id, entry);
        result
    }
    fn accept_automatic_catalog(
        &self,
        entry: &mut AutomaticChannel,
        body: &[u8],
    ) -> Result<(), AccountSharingError> {
        let fragment: CatalogFragment =
            serde_json::from_slice(body).map_err(|_| AccountSharingError::NotReady)?;
        if fragment.version != 1
            || fragment.count == 0
            || fragment.count as usize > MAX_ENTRY_BYTES.div_ceil(FRAGMENT_BYTES)
            || fragment.ordinal >= fragment.count
            || serde_json::to_vec(&fragment).map_err(|_| AccountSharingError::NotReady)? != body
        {
            return Err(AccountSharingError::NotReady);
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&fragment.body)
            .map_err(|_| AccountSharingError::NotReady)?;
        if bytes.is_empty()
            || bytes.len() > FRAGMENT_BYTES
            || base64::engine::general_purpose::STANDARD.encode(&bytes) != fragment.body
        {
            return Err(AccountSharingError::NotReady);
        }
        if fragment.ordinal == 0 {
            entry.assembly = Some(Assembly {
                digest: fragment.digest,
                count: fragment.count,
                bytes: Vec::new(),
                next: 0,
            });
        }
        let assembly = entry
            .assembly
            .as_mut()
            .ok_or(AccountSharingError::NotReady)?;
        if assembly.digest != fragment.digest
            || assembly.count != fragment.count
            || assembly.next != fragment.ordinal
            || assembly.bytes.len() + bytes.len() > MAX_ENTRY_BYTES
        {
            return Err(AccountSharingError::NotReady);
        }
        assembly.bytes.extend(bytes);
        assembly.next += 1;
        if assembly.next != assembly.count {
            return Ok(());
        }
        let bytes = entry.assembly.take().expect("complete assembly").bytes;
        if <[u8; 32]>::from(Sha256::digest(&bytes)) != fragment.digest {
            return Err(AccountSharingError::NotReady);
        }
        let record: MirroredChatEntry =
            serde_json::from_slice(&bytes).map_err(|_| AccountSharingError::NotReady)?;
        if serde_json::to_vec(&record).map_err(|_| AccountSharingError::NotReady)? != bytes {
            return Err(AccountSharingError::NotReady);
        }
        let scope = entry.channel.scope();
        let mirror = MirroredChatScope {
            account: entry.policy.account,
            local_device: entry.policy.local_device,
            source_device: entry.policy.peer_device,
            policy_digest: Self::automatic_policy_id(&entry.policy)?,
            protected_group: entry.policy.protected_group.clone(),
            protected_generation: scope.local_generation,
        };
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        let validate = || {
            self.automatic_policy_current(&entry.policy)
                .and_then(|()| {
                    self.runtime
                        .session()
                        .validate_account_sharing_channel(&entry.channel)
                        .map_err(|_| AccountSharingError::Closed)
                })
                .map_err(|_| {
                    cgka_traits::storage::StorageError::Serialization(
                        "automatic sharing original unavailable".into(),
                    )
                })
        };
        storage
            .mirrored_chat_catalog_storage()
            .ok_or(AccountSharingError::NotReady)?
            .apply_mirrored_chat_catalog(&mirror, &[record], &validate)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        Ok(())
    }
}
impl AppClient {
    // A valid request can arrive before the matching signed consent's policy
    // transaction commits. Only its already source-authenticated opaque request
    // is retained. A fresh owner is scheduled from the now-current approval,
    // not from the old review state or a stored packet.
    fn promote_approved_automatic_requests(
        &mut self,
        policies: &[ApprovedAccountSharingPolicy],
    ) -> Result<(), AccountSharingError> {
        let nonces: Vec<_> = self
            .account_sharing_owner
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.recipient
                    && entry.request.is_some()
                    && entry.original.upgrade().is_some_and(|original| {
                        original.live()
                            && !original.progress.lock().expect("sharing progress").approved
                    })
            })
            .map(|(nonce, _)| *nonce)
            .collect();
        for nonce in nonces {
            let Some(entry) = self.account_sharing_owner.entries.remove(&nonce) else {
                continue;
            };
            let Some(old) = entry.original.upgrade().filter(|original| original.live()) else {
                continue;
            };
            let request = entry
                .request
                .as_ref()
                .expect("selected authenticated request");
            let scope = request.scope();
            let policy = policies
                .iter()
                .find(|policy| {
                    !policy.revoked
                        && policy.account.as_slice() == scope.protected.account.as_slice()
                        && policy.approval_id == scope.approval_id
                        && policy.protected_group == scope.protected.group_id
                        && policy.local_device.as_slice() == scope.recipient
                        && policy.peer_device.as_slice() == scope.source
                        && Self::automatic_policy_id(policy).ok()
                            == Some(scope.approved_policy_identity)
                })
                .cloned();
            let Some(policy) = policy else {
                self.account_sharing_owner.entries.insert(nonce, entry);
                continue;
            };
            let id = Self::automatic_policy_id(&policy)?;
            if self.account_sharing_owner.automatic.contains_key(&id) {
                self.account_sharing_owner.entries.insert(nonce, entry);
                continue;
            }
            if self.automatic_policy_current(&policy).is_err() {
                self.account_sharing_owner.entries.insert(nonce, entry);
                continue;
            }
            let original = State::new_until(
                &self.account_sharing_owner.lifetime,
                policy.approval_id,
                old.deadline,
            );
            let result = self.runtime.session().approve_account_sharing_policy(
                request,
                Arc::new(OriginalLease(Arc::downgrade(&original))),
            );
            let channel = match result {
                Ok(channel) => channel,
                Err(_) => {
                    self.account_sharing_owner.entries.insert(nonce, entry);
                    continue;
                }
            };
            if !old.live() || !original.live() {
                self.account_sharing_owner.entries.insert(nonce, entry);
                continue;
            }
            old.cancel();
            self.account_sharing_owner.automatic.insert(
                id,
                AutomaticChannel {
                    original,
                    policy,
                    channel,
                    recipient: true,
                    ready: false,
                    handshake_published: false,
                    pending: VecDeque::new(),
                    next_body: 0,
                    cursor: None,
                    inventory_digest: None,
                    sent: BTreeMap::new(),
                    assembly: None,
                    pending_catalog: None,
                    renew: false,
                },
            );
        }
        Ok(())
    }
    fn begin_automatic_channel(
        &mut self,
        policy: ApprovedAccountSharingPolicy,
        progress: Option<CatalogProgress>,
    ) -> Result<(), AccountSharingError> {
        self.automatic_policy_current(&policy)?;
        let id = Self::automatic_policy_id(&policy)?;
        if self.account_sharing_owner.automatic.contains_key(&id) {
            return Ok(());
        }
        let original = State::new(&self.account_sharing_owner.lifetime, policy.approval_id);
        let channel = self
            .runtime
            .session()
            .begin_account_sharing_policy(
                &policy.protected_group,
                &policy.peer_device,
                Arc::new(OriginalLease(Arc::downgrade(&original))),
            )
            .map_err(|_| AccountSharingError::NotReady)?;
        self.account_sharing_owner.automatic.insert(
            id,
            AutomaticChannel {
                original,
                policy,
                channel,
                recipient: false,
                ready: false,
                handshake_published: false,
                pending: VecDeque::new(),
                next_body: 0,
                cursor: None,
                inventory_digest: None,
                sent: BTreeMap::new(),
                assembly: None,
                pending_catalog: None,
                renew: false,
            },
        );
        self.account_sharing_owner
            .automatic
            .get_mut(&id)
            .expect("inserted automatic channel")
            .restore_catalog_progress(progress);
        Ok(())
    }
    #[cfg(test)]
    pub(crate) async fn kick_approved_automatic_channel(
        &mut self,
    ) -> Result<(), AccountSharingError> {
        let policies = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?
            .approved_account_sharing_policy_storage()
            .ok_or(AccountSharingError::NotReady)?
            .approved_account_sharing_policies()
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        for policy in policies {
            self.begin_automatic_channel(policy, None)?;
        }
        self.maintain_automatic_account_sharing().await
    }
    pub(crate) async fn maintain_automatic_account_sharing(
        &mut self,
    ) -> Result<(), AccountSharingError> {
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        let Some(store) = storage.approved_account_sharing_policy_storage() else {
            return Ok(());
        };
        let policies = store
            .approved_account_sharing_policies()
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        self.promote_approved_automatic_requests(&policies)?;
        for policy in policies {
            let id = Self::automatic_policy_id(&policy)?;
            if self.automatic_policy_current(&policy).is_err() {
                self.account_sharing_owner.automatic.remove(&id);
                continue;
            }
            let retired = self
                .account_sharing_owner
                .automatic
                .get(&id)
                .is_some_and(|entry| {
                    !entry.original.live()
                        || self
                            .runtime
                            .session()
                            .validate_account_sharing_channel(&entry.channel)
                            .is_err()
                        || entry.next_body >= CHANNEL_BODY_BUDGET
                        || entry.renew
                });
            let mut progress = None;
            let mut budget_renewal = false;
            if retired && let Some(mut old) = self.account_sharing_owner.automatic.remove(&id) {
                budget_renewal = old.renew || old.next_body >= CHANNEL_BODY_BUDGET;
                progress = Some(old.take_catalog_progress());
            }
            if !self.account_sharing_owner.automatic.contains_key(&id)
                && (policy.local_device < policy.peer_device || budget_renewal)
            {
                self.begin_automatic_channel(policy, progress)?;
            }
        }
        let ids: Vec<_> = self
            .account_sharing_owner
            .automatic
            .keys()
            .copied()
            .collect();
        for id in ids {
            let Some(mut entry) = self.account_sharing_owner.automatic.remove(&id) else {
                continue;
            };
            let result = self.automatic_sharing_tick(&mut entry).await;
            if entry.original.live() {
                self.account_sharing_owner.automatic.insert(id, entry);
            }
            result?;
        }
        Ok(())
    }
    async fn automatic_sharing_tick(
        &mut self,
        entry: &mut AutomaticChannel,
    ) -> Result<(), AccountSharingError> {
        self.automatic_policy_current(&entry.policy)?;
        if !entry.handshake_published {
            let kind = if entry.recipient {
                AccountSharingControl::Consent
            } else {
                AccountSharingControl::Request
            };
            self.publish_automatic_control(entry, kind).await?;
            entry.handshake_published = true;
            if entry.recipient {
                entry.ready = true;
            }
            return Ok(());
        }
        if !entry.ready {
            return Ok(());
        }
        if entry.pending.is_empty() {
            self.prepare_automatic_catalog(entry)?;
        }
        let Some(body) = entry.pending.front() else {
            return Ok(());
        };
        self.runtime
            .session()
            .seal_account_shared_body(
                &mut entry.channel,
                AccountSharedBodyKind::Catalog,
                entry.next_body,
                body,
            )
            .map_err(|_| AccountSharingError::NotReady)?;
        self.publish_automatic_control(entry, AccountSharingControl::Body(entry.next_body))
            .await?;
        entry.pending.pop_front();
        entry.next_body += 1;
        if entry.pending.is_empty()
            && let Some((group, digest)) = entry.pending_catalog.take()
        {
            entry.cursor = Some(group.clone());
            entry.sent.insert(group.as_slice().to_vec(), digest);
        }
        Ok(())
    }
    fn prepare_automatic_catalog(
        &self,
        entry: &mut AutomaticChannel,
    ) -> Result<(), AccountSharingError> {
        let current: [u8; 32] = Sha256::digest(
            serde_json::to_vec(&self.state.groups).map_err(|_| AccountSharingError::NotReady)?,
        )
        .into();
        if entry.inventory_digest != Some(current) {
            entry.inventory_digest = Some(current);
            entry.cursor = None;
        }
        let page = self
            .runtime
            .session()
            .account_chat_catalog(&entry.policy.protected_group, entry.cursor.as_ref(), 1)
            .map_err(|_| AccountSharingError::Closed)?;
        let Some(source) = page.entries.first() else {
            return Ok(());
        };
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        let group = storage
            .get_group(&source.group_id)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        let mut record = MirroredChatEntry {
            group_id: source.group_id.clone(),
            source_epoch: source.epoch,
            source_sequence: 0,
            source_digest: [0; 32],
            profile: source.profile,
            name: group.name,
            description: group.description,
            state: MirroredChatState::Active,
        };
        let digest: [u8; 32] =
            Sha256::digest(serde_json::to_vec(&record).map_err(|_| AccountSharingError::NotReady)?)
                .into();
        if entry.sent.get(record.group_id.as_slice()) == Some(&digest) {
            entry.cursor = Some(record.group_id.clone());
            return Ok(());
        }
        let validate = || {
            self.automatic_policy_current(&entry.policy)
                .and_then(|()| {
                    self.runtime
                        .session()
                        .validate_account_sharing_channel(&entry.channel)
                        .map_err(|_| AccountSharingError::Closed)
                })
                .map_err(|_| {
                    cgka_traits::storage::StorageError::Serialization(
                        "automatic journal original unavailable".into(),
                    )
                })
        };
        record.source_sequence = storage
            .approved_account_sharing_policy_storage()
            .ok_or(AccountSharingError::NotReady)?
            .reserve_account_chat_sequence(
                &Self::automatic_policy_id(&entry.policy)?,
                &record.group_id,
                &digest,
                &validate,
            )
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        record.source_digest = digest;
        let bytes = serde_json::to_vec(&record).map_err(|_| AccountSharingError::NotReady)?;
        if bytes.len() > MAX_ENTRY_BYTES {
            return Err(AccountSharingError::NotReady);
        }
        let whole: [u8; 32] = Sha256::digest(&bytes).into();
        let count = bytes.len().div_ceil(FRAGMENT_BYTES) as u32;
        if entry.next_body + u64::from(count) > CHANNEL_BODY_BUDGET {
            entry.renew = true;
            return Ok(());
        }
        for (ordinal, body) in bytes.chunks(FRAGMENT_BYTES).enumerate() {
            entry.pending.push_back(
                serde_json::to_vec(&CatalogFragment {
                    version: 1,
                    digest: whole,
                    ordinal: ordinal as u32,
                    count,
                    body: base64::engine::general_purpose::STANDARD.encode(body),
                })
                .map_err(|_| AccountSharingError::NotReady)?,
            );
        }
        entry.pending_catalog = Some((record.group_id, digest));
        Ok(())
    }
    async fn publish_automatic_control(
        &mut self,
        entry: &mut AutomaticChannel,
        kind: AccountSharingControl,
    ) -> Result<(), AccountSharingError> {
        self.automatic_policy_current(&entry.policy)?;
        let message = self
            .runtime
            .session_mut()
            .wrap_account_sharing_control(&mut entry.channel, kind)
            .await
            .map_err(|_| AccountSharingError::NotReady)?;
        let evidence = self
            .runtime
            .session()
            .private_transport_evidence(crate::NOSTR_ROUTING_COMPONENT_ID)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?
            .ok_or(AccountSharingError::NotReady)?;
        if evidence.group_id() != &entry.policy.protected_group {
            return Err(AccountSharingError::Closed);
        }
        let route = cgka_traits::app_components::decode_nostr_routing_v1(evidence.component())
            .map_err(|_| AccountSharingError::NotReady)?;
        let request = cgka_traits::TransportPublishRequest {
            account_id: self.runtime.session().self_id(),
            message,
            target: cgka_traits::TransportPublishTarget::Group {
                group_id: evidence.group_id().clone(),
                transport_group_id: route.nostr_group_id.to_vec(),
                endpoints: route
                    .relays
                    .into_iter()
                    .map(cgka_traits::TransportEndpoint)
                    .collect(),
            },
            required_acks: 1,
        };
        let revoked = entry.original.revoked.notified();
        tokio::pin!(revoked);
        revoked.as_mut().enable();
        if !entry.original.live() {
            return Err(AccountSharingError::Closed);
        }
        let mut shutdown = self.history_owner.runtime_shutdown.clone();
        let stopping = async {
            if let Some(watch) = shutdown.as_mut() {
                if *watch.borrow() {
                    return;
                }
                while watch.changed().await.is_ok() {
                    if *watch.borrow() {
                        return;
                    }
                }
            } else {
                std::future::pending::<()>().await
            }
        };
        tokio::select! {biased;()=stopping=>return Err(AccountSharingError::Closed),()=&mut revoked=>return Err(AccountSharingError::Closed),()=tokio::time::sleep_until(entry.original.deadline.into())=>return Err(AccountSharingError::Closed),report=self.adapter.publish_selected_chat(request)=>{if !report.map_err(|_|AccountSharingError::RuntimeUnavailable)?.met_required_acks(){return Err(AccountSharingError::NotReady)}}}
        self.automatic_policy_current(&entry.policy)?;
        self.runtime
            .session()
            .validate_account_sharing_channel(&entry.channel)
            .map_err(|_| AccountSharingError::Closed)
    }
}
