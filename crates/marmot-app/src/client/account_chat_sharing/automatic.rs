//! Fresh scheduling from durable explicit policy. Stored facts do not restore keys.
use super::*;
#[cfg(all(test, feature = "test-policy-overrides"))]
pub(super) mod consent_delivery_probe;
mod departure;
#[cfg(all(test, feature = "test-policy-overrides"))]
pub(super) mod departure_replay_probe;
#[cfg(all(test, feature = "test-policy-overrides"))]
pub(super) mod diagnostics;
#[cfg(all(test, feature = "test-policy-overrides"))]
pub(super) mod duplicate_departure_probe;
#[cfg(all(test, feature = "test-policy-overrides"))]
mod pending_restart_acceptance;
mod records;
#[cfg(all(test, feature = "test-policy-overrides"))]
mod restart_acceptance;
mod sends;
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
const CHANNEL_BODY_BUDGET: u64 = 120;
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
    fragments: Vec<Option<Vec<u8>>>,
}
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CatalogReceipt {
    version: u8,
    group: crate::GroupId,
    sequence: u64,
    source_digest: [u8; 32],
    encoded_digest: [u8; 32],
}
struct PendingBody {
    kind: AccountSharedBodyKind,
    bytes: Vec<u8>,
}
struct PendingCatalog {
    receipt: CatalogReceipt,
    published_at: Option<std::time::Instant>,
    state: MirroredChatState,
}
struct CatalogProgress {
    generation: u64,
    cursor: Option<crate::GroupId>,
    inventory_digest: Option<[u8; 32]>,
    sent: BTreeMap<Vec<u8>, [u8; 32]>,
    record_cursor: records::RecordSourceCursor,
}
pub(crate) struct AutomaticChannel {
    original: Arc<State>,
    policy: ApprovedAccountSharingPolicy,
    channel: OwnedAccountSharingChannel,
    recipient: bool,
    ready: bool,
    handshake_published: bool,
    handshake_published_at: Option<std::time::Instant>,
    pending: VecDeque<PendingBody>,
    next_body: u64,
    cursor: Option<crate::GroupId>,
    inventory_digest: Option<[u8; 32]>,
    sent: BTreeMap<Vec<u8>, [u8; 32]>,
    assembly: Option<Assembly>,
    pending_catalog: Option<PendingCatalog>,
    records: records::RecordProgress,
    sends: sends::SendProgress,
    departures: departure::DepartureProgress,
    renew: bool,
}
impl AutomaticChannel {
    fn pending_canonical_request_expired(&self) -> bool {
        !self.recipient
            && !self.ready
            && self.policy.local_device < self.policy.peer_device
            && self
                .handshake_published_at
                .is_some_and(|published| published.elapsed() >= std::time::Duration::from_secs(10))
    }

    fn take_catalog_progress(&mut self) -> CatalogProgress {
        CatalogProgress {
            generation: self.channel.scope().local_generation,
            cursor: self.cursor.take(),
            inventory_digest: self.inventory_digest.take(),
            sent: std::mem::take(&mut self.sent),
            record_cursor: self.records.take_source_cursor(),
        }
    }
    fn restore_catalog_progress(&mut self, progress: Option<CatalogProgress>) {
        if let Some(progress) = progress
            && progress.generation == self.channel.scope().local_generation
        {
            self.cursor = progress.cursor;
            self.inventory_digest = progress.inventory_digest;
            self.sent = progress.sent;
            self.records.restore_source_cursor(progress.record_cursor);
        }
    }
}
impl Drop for AutomaticChannel {
    fn drop(&mut self) {
        self.original.cancel();
        self.channel.retire();
    }
}
// Test-only compatibility encoding keeps the actual eligibility, digest and
// channel-authentication path. It never constructs a grant or a storage row.
#[cfg(all(test, feature = "test-policy-overrides"))]
mod legacy_encoding {
    use std::{
        collections::BTreeSet,
        path::{Path, PathBuf},
        sync::{Mutex, OnceLock},
    };
    fn roots() -> &'static Mutex<BTreeSet<PathBuf>> {
        static ROOTS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();
        ROOTS.get_or_init(|| Mutex::new(BTreeSet::new()))
    }
    pub(super) struct Guard(PathBuf);
    impl Drop for Guard {
        fn drop(&mut self) {
            assert!(roots().lock().unwrap().remove(&self.0));
        }
    }
    pub(super) fn hold(root: &Path) -> Guard {
        assert!(roots().lock().unwrap().insert(root.to_owned()));
        Guard(root.to_owned())
    }
    pub(super) fn active(root: &Path) -> bool {
        roots().lock().unwrap().contains(root)
    }
}
impl AppClient {
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn test_legacy_account_chat_encoding(root: &std::path::Path) -> impl Drop {
        legacy_encoding::hold(root)
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    fn test_uses_legacy_account_chat_encoding(&self) -> bool {
        legacy_encoding::active(self.app.account_home().root())
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(super) fn test_trace_catalog_stage(
        &self,
        stage: &'static str,
        category: &str,
        comparison: Option<(
            &storage_sqlite::SqliteAccountStorage,
            &MirroredChatScope,
            &MirroredChatEntry,
        )>,
    ) {
        let Some(owner) = diagnostics::owner(self.app.account_home().root()) else {
            return;
        };
        type SeenStages = std::collections::BTreeSet<(std::path::PathBuf, &'static str, String)>;
        static SEEN: std::sync::OnceLock<std::sync::Mutex<SeenStages>> = std::sync::OnceLock::new();
        let mut seen = SEEN.get_or_init(Default::default).lock().unwrap();
        let key = (
            self.app.account_home().root().to_owned(),
            stage,
            category.to_owned(),
        );
        if seen.contains(&key) || seen.len() >= 1024 {
            return;
        }
        diagnostics::report(
            stage,
            category,
            || {
                let Some((storage, scope, incoming)) = comparison else {
                    return Ok(None);
                };
                let rows = storage
                    .mirrored_chat_catalog_storage()
                    .unwrap()
                    .mirrored_chat_catalog_page(scope, None, 128)
                    .map_err(|error| diagnostics::storage_category(&error))?;
                let old = rows.iter().find(|old| old.group_id == incoming.group_id);
                let higher = incoming.accepted_origin.is_some_and(|new| {
                    old.is_some_and(|old| {
                        old.accepted_origin.is_none_or(|old| new.order > old.order)
                    })
                });
                Ok(Some(format!(
                    "old_present={}, old_left={}, origin_present={}, same_origin={}, higher_origin_order={higher}, newer_sequence={}, epoch_nonregression={}",
                    old.is_some(),
                    old.is_some_and(|old| old.state == MirroredChatState::Left),
                    incoming.accepted_origin.is_some(),
                    old.is_some_and(|old| incoming.accepted_origin == old.accepted_origin),
                    old.is_some_and(|old| incoming.source_sequence > old.source_sequence),
                    old.is_some_and(|old| incoming.source_epoch >= old.source_epoch)
                )))
            },
            |line| eprintln!("{line}, owner={owner}"),
        );
        seen.insert(key);
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn test_capture_account_chat_progress(
        root: &std::path::Path,
        owner: &'static str,
    ) -> impl Drop {
        diagnostics::trace_root(root, owner)
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn test_label_account_chat_peers(
        root: &std::path::Path,
        peers: &[([u8; 32], &'static str)],
    ) {
        diagnostics::label_peers(root, peers);
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    fn test_trace_automatic_peer_stage(&self, stage: &'static str, device: &[u8], category: &str) {
        let peer = diagnostics::peer(self.app.account_home().root(), device);
        self.test_trace_catalog_stage(stage, &format!("{category}, peer={peer}"), None);
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    fn test_trace_automatic_progress(
        &self,
        stage: &'static str,
        entry: &AutomaticChannel,
        outcome: &str,
    ) {
        let summary = format!(
            "{outcome}, ready={}, handshake_published={}, recipient_channel={}, local_is_lower={}, departure_pending={}, pending_bodies={}, pending_catalog={}, pending_records={}, sent_groups={}, catalog_cursor={}, renew={}, {}",
            entry.ready,
            entry.handshake_published,
            entry.recipient,
            entry.policy.local_device < entry.policy.peer_device,
            entry.departures.test_has_pending(),
            entry.pending.len(),
            entry.pending_catalog.is_some(),
            entry.records.has_pending(),
            entry.sent.len(),
            entry.cursor.is_some(),
            entry.renew,
            entry.records.test_progress()
        );
        self.test_trace_automatic_peer_stage(stage, &entry.policy.peer_device, &summary);
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn test_capture_automatic_consent_delivery(
        account: [u8; 32],
        group: crate::GroupId,
        roots: [&std::path::Path; 3],
        devices: [[u8; 32]; 3],
    ) -> std::sync::Arc<consent_delivery_probe::ConsentDeliveryProbe> {
        consent_delivery_probe::arm(
            account,
            group,
            std::array::from_fn(|index| consent_delivery_probe::Peer {
                root: roots[index].to_path_buf(),
                device: devices[index],
            }),
        )
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn test_observe_automatic_consent_raw(
        &self,
        message: &cgka_traits::TransportMessage,
    ) {
        consent_delivery_probe::raw_received(
            self.app.account_home().root(),
            &message.id,
            Sha256::digest(&message.payload).into(),
        );
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(super) fn test_consent_outcome(
        result: &Result<(), AccountSharingError>,
    ) -> consent_delivery_probe::Outcome {
        use consent_delivery_probe::Outcome;
        match result {
            Ok(()) => Outcome::Success,
            Err(AccountSharingError::NotReady) => Outcome::NotReady,
            Err(AccountSharingError::Closed) => Outcome::Closed,
            Err(AccountSharingError::RuntimeUnavailable) => Outcome::RuntimeUnavailable,
            Err(_) => Outcome::Refused,
        }
    }
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
    pub(super) fn automatic_policy_current(
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
            .map_err(|error| {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                self.test_trace_automatic_peer_stage(
                    "automatic_policy_core_targets",
                    &policy.peer_device,
                    error.privacy_safe_kind(),
                );
                let _ = error;
                AccountSharingError::Closed
            })?;
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
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_automatic_peer_stage(
                "automatic_request_received",
                &received.source,
                "outer_core_authenticated",
            );
            let authentication = self
                .runtime
                .session()
                .authenticate_account_sharing_request(wire);
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_automatic_peer_stage(
                "automatic_request_core_auth",
                &received.source,
                authentication
                    .as_ref()
                    .err()
                    .map(|error| error.privacy_safe_kind())
                    .unwrap_or("authenticated"),
            );
            let Ok(request) = authentication else {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                self.test_trace_catalog_stage("automatic_request_authentication", "refused", None);
                return Ok(false);
            };
            let storage = self.app.account_storage(&self.state.label).map_err(|_| {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                self.test_trace_automatic_peer_stage(
                    "automatic_request_policy_storage",
                    &received.signer,
                    "runtime_unavailable",
                );
                AccountSharingError::RuntimeUnavailable
            })?;
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
                #[cfg(all(test, feature = "test-policy-overrides"))]
                self.test_trace_automatic_peer_stage(
                    "automatic_request_policy",
                    &received.signer,
                    "no_match",
                );
                return Ok(false);
            };
            let current = self.automatic_policy_current(&policy);
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_automatic_peer_stage(
                "automatic_request_current_policy",
                &policy.peer_device,
                current
                    .as_ref()
                    .err()
                    .map(diagnostics::sharing_category)
                    .unwrap_or("current"),
            );
            current?;
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_automatic_peer_stage(
                "automatic_request_policy",
                &policy.peer_device,
                if policy.local_device < policy.peer_device {
                    "higher_request_authenticated"
                } else {
                    "lower_request_authenticated"
                },
            );
            let id = Self::automatic_policy_id(&policy)?;
            if policy.local_device < policy.peer_device {
                // An authenticated higher-device request is a restart signal,
                // never consent for its noncanonical direction. A live lower
                // pending request wins; otherwise begin a fresh lower original.
                // This also handles a delayed losing request after Consent.
                #[cfg(all(test, feature = "test-policy-overrides"))]
                let peer_device = policy.peer_device;
                let restart = self.ensure_canonical_automatic_initiator(policy);
                #[cfg(all(test, feature = "test-policy-overrides"))]
                self.test_trace_automatic_peer_stage(
                    "automatic_request_canonical_restart",
                    &peer_device,
                    restart
                        .as_ref()
                        .err()
                        .map(diagnostics::sharing_category)
                        .unwrap_or("ok"),
                );
                restart?;
                return Ok(true);
            }
            if self
                .account_sharing_owner
                .automatic
                .get(&id)
                .is_some_and(|entry| {
                    entry.channel.scope().nonce == received.nonce
                        && entry.original.live()
                        && self
                            .runtime
                            .session()
                            .validate_account_sharing_channel(&entry.channel)
                            .is_ok()
                })
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
                    handshake_published_at: None,
                    pending: VecDeque::new(),
                    next_body: 0,
                    cursor: None,
                    inventory_digest: None,
                    sent: BTreeMap::new(),
                    assembly: None,
                    pending_catalog: None,
                    records: records::RecordProgress::default(),
                    sends: sends::SendProgress::default(),
                    departures: departure::DepartureProgress::default(),
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
        let Some(id) = id else {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_automatic_peer_stage(
                "automatic_dispatch",
                &received.signer,
                "no_nonce_match",
            );
            return Ok(false);
        };
        let mut entry = self
            .account_sharing_owner
            .automatic
            .remove(&id)
            .expect("found automatic channel");
        #[cfg(all(test, feature = "test-policy-overrides"))]
        self.test_trace_automatic_progress("dispatch_before", &entry, "matched");
        #[cfg(all(test, feature = "test-policy-overrides"))]
        consent_delivery_probe::automatic_matched(
            self.app.account_home().root(),
            received,
            Sha256::digest(wire).into(),
        );
        let result = (|| {
            self.automatic_policy_current(&entry.policy)?;
            if received.control == AccountSharingControl::Consent && !entry.recipient {
                self.runtime
                    .session()
                    .bind_account_sharing_consent(&mut entry.channel, wire)
                    .map_err(|_| AccountSharingError::NotReady)?;
                entry.ready = true;
                #[cfg(all(test, feature = "test-policy-overrides"))]
                consent_delivery_probe::consent_bound(
                    self.app.account_home().root(),
                    received,
                    Sha256::digest(wire).into(),
                );
            } else if matches!(received.control, AccountSharingControl::Body(_)) && entry.ready {
                let (kind, _, body) = self
                    .runtime
                    .session()
                    .open_account_shared_body(&entry.channel, wire)
                    .map_err(|error| {
                        #[cfg(all(test, feature = "test-policy-overrides"))]
                        self.test_trace_catalog_stage(
                            "authenticated_body_open",
                            "core_refused",
                            None,
                        );
                        let _ = error;
                        AccountSharingError::NotReady
                    })?;
                match kind {
                    AccountSharedBodyKind::Catalog => {
                        self.accept_automatic_catalog(&mut entry, &body)?
                    }
                    AccountSharedBodyKind::CatalogReceipt => {
                        self.accept_automatic_catalog_receipt(&mut entry, &body)?
                    }
                    AccountSharedBodyKind::Records => {
                        self.accept_automatic_records(&mut entry, &body)?
                    }
                    AccountSharedBodyKind::RecordReceipt => {
                        self.accept_automatic_record_receipt(&mut entry, &body)?
                    }
                    AccountSharedBodyKind::SendIntent => {
                        self.accept_automatic_send_intent(&mut entry, &body)?
                    }
                    AccountSharedBodyKind::SendReceipt => {
                        self.accept_automatic_send_receipt(&mut entry, &body)?
                    }
                    AccountSharedBodyKind::DepartureIntent
                    | AccountSharedBodyKind::DepartureReceipt => {
                        #[cfg(all(test, feature = "test-policy-overrides"))]
                        self.test_trace_automatic_progress(
                            "departure_body_core_opened",
                            &entry,
                            if kind == AccountSharedBodyKind::DepartureIntent {
                                "intent"
                            } else {
                                "receipt"
                            },
                        );
                        self.accept_automatic_departure(&mut entry, kind, &body)?;
                    }
                    _ => return Err(AccountSharingError::NotReady),
                }
            }
            Ok(true)
        })();
        #[cfg(all(test, feature = "test-policy-overrides"))]
        self.test_trace_automatic_progress(
            "dispatch_after",
            &entry,
            result
                .as_ref()
                .err()
                .map(diagnostics::sharing_category)
                .unwrap_or("ok"),
        );
        self.account_sharing_owner.automatic.insert(id, entry);
        result
    }
    fn accept_automatic_catalog(
        &self,
        entry: &mut AutomaticChannel,
        body: &[u8],
    ) -> Result<(), AccountSharingError> {
        let fragment: CatalogFragment = serde_json::from_slice(body).map_err(|error| {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_catalog_stage(
                "fragment_decode",
                diagnostics::json_category(&error),
                None,
            );
            let _ = error;
            AccountSharingError::NotReady
        })?;
        if fragment.version != 1
            || fragment.count == 0
            || fragment.count as usize > MAX_ENTRY_BYTES.div_ceil(FRAGMENT_BYTES)
            || fragment.ordinal >= fragment.count
            || serde_json::to_vec(&fragment).map_err(|_| AccountSharingError::NotReady)? != body
        {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_catalog_stage("fragment_bounds_or_canonical", "refused", None);
            return Err(AccountSharingError::NotReady);
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&fragment.body)
            .map_err(|error| {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                self.test_trace_catalog_stage("fragment_base64", "refused", None);
                let _ = error;
                AccountSharingError::NotReady
            })?;
        if bytes.is_empty()
            || bytes.len() > FRAGMENT_BYTES
            || base64::engine::general_purpose::STANDARD.encode(&bytes) != fragment.body
        {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_catalog_stage("fragment_bytes", "refused", None);
            return Err(AccountSharingError::NotReady);
        }
        if entry
            .assembly
            .as_ref()
            .is_none_or(|assembly| assembly.digest != fragment.digest)
        {
            entry.assembly = Some(Assembly {
                digest: fragment.digest,
                fragments: vec![None; fragment.count as usize],
            });
        }
        let assembly = entry.assembly.as_mut().expect("bounded assembly");
        if assembly.fragments.len() != fragment.count as usize {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_catalog_stage("assembly_count", "refused", None);
            return Err(AccountSharingError::NotReady);
        }
        let slot = &mut assembly.fragments[fragment.ordinal as usize];
        if slot.as_ref().is_some_and(|old| old != &bytes) {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_catalog_stage("assembly_conflict", "refused", None);
            return Err(AccountSharingError::NotReady);
        }
        *slot = Some(bytes);
        if assembly.fragments.iter().any(Option::is_none) {
            return Ok(());
        }
        let bytes: Vec<u8> = assembly
            .fragments
            .iter()
            .flat_map(|part| part.as_ref().expect("complete fragment").iter().copied())
            .collect();
        if bytes.len() > MAX_ENTRY_BYTES {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_catalog_stage("catalog_bound", "refused", None);
            return Err(AccountSharingError::NotReady);
        }
        if <[u8; 32]>::from(Sha256::digest(&bytes)) != fragment.digest {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_catalog_stage("catalog_digest", "refused", None);
            return Err(AccountSharingError::NotReady);
        }
        let record: MirroredChatEntry = serde_json::from_slice(&bytes).map_err(|error| {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_catalog_stage(
                "catalog_decode",
                diagnostics::json_category(&error),
                None,
            );
            let _ = error;
            AccountSharingError::NotReady
        })?;
        if serde_json::to_vec(&record).map_err(|_| AccountSharingError::NotReady)? != bytes {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_catalog_stage("catalog_canonical", "refused", None);
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
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if record.state == MirroredChatState::Active {
            match storage
                .mirrored_chat_catalog_storage()
                .unwrap()
                .mirrored_chat_catalog_page(&mirror, None, 128)
            {
                Ok(rows)
                    if rows.iter().any(|old| {
                        old.group_id == record.group_id && old.state == MirroredChatState::Left
                    }) =>
                {
                    self.test_trace_catalog_stage(
                        "catalog_before_sql",
                        "retained_left",
                        Some((&storage, &mirror, &record)),
                    )
                }
                Err(error) => self.test_trace_catalog_stage(
                    "catalog_diagnostic_read",
                    diagnostics::storage_category(&error),
                    None,
                ),
                _ => {}
            }
        }
        storage
            .mirrored_chat_catalog_storage()
            .ok_or(AccountSharingError::NotReady)?
            .apply_mirrored_chat_catalog(&mirror, std::slice::from_ref(&record), &validate)
            .map_err(|error| {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                self.test_trace_catalog_stage(
                    "catalog_sql",
                    diagnostics::storage_category(&error),
                    Some((&storage, &mirror, &record)),
                );
                let _ = error;
                AccountSharingError::RuntimeUnavailable
            })?;
        self.notify_mirrored_presentation_changed();
        // Keep the complete authenticated body until its SQL transaction succeeds.
        // Only a committed recipient import creates this encrypted receipt.
        entry.assembly = None;
        let receipt = CatalogReceipt {
            version: 1,
            group: record.group_id,
            sequence: record.source_sequence,
            source_digest: record.source_digest,
            encoded_digest: fragment.digest,
        };
        let bytes = serde_json::to_vec(&receipt).map_err(|_| AccountSharingError::NotReady)?;
        if entry.pending.len() >= CHANNEL_BODY_BUDGET as usize {
            return Err(AccountSharingError::NotReady);
        }
        entry.pending.push_back(PendingBody {
            kind: AccountSharedBodyKind::CatalogReceipt,
            bytes,
        });
        Ok(())
    }
    fn accept_automatic_catalog_receipt(
        &self,
        entry: &mut AutomaticChannel,
        body: &[u8],
    ) -> Result<(), AccountSharingError> {
        let receipt: CatalogReceipt =
            serde_json::from_slice(body).map_err(|_| AccountSharingError::NotReady)?;
        if receipt.version != 1
            || serde_json::to_vec(&receipt).map_err(|_| AccountSharingError::NotReady)? != body
        {
            return Err(AccountSharingError::NotReady);
        }
        let Some(pending) = entry.pending_catalog.as_ref() else {
            return Ok(());
        };
        if pending.receipt != receipt {
            return Err(AccountSharingError::NotReady);
        }
        entry.cursor = Some(receipt.group.clone());
        entry
            .sent
            .insert(receipt.group.as_slice().to_vec(), receipt.source_digest);
        entry.pending_catalog = None;
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
            let current = self.automatic_policy_current(&policy);
            #[cfg(all(test, feature = "test-policy-overrides"))]
            if let Err(error) = &current {
                self.test_trace_catalog_stage(
                    "maintain_policy_refusal",
                    diagnostics::sharing_category(error),
                    None,
                );
            }
            if current.is_err() {
                self.account_sharing_owner.entries.insert(nonce, entry);
                continue;
            }
            if policy.local_device < policy.peer_device {
                // The early request was authenticated under its still-live
                // original, but actual policy completion does not make its
                // noncanonical direction the automatic channel owner.
                match self.ensure_canonical_automatic_initiator(policy) {
                    Ok(()) => old.cancel(),
                    Err(_) => {
                        self.account_sharing_owner.entries.insert(nonce, entry);
                    }
                }
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
                    handshake_published_at: None,
                    pending: VecDeque::new(),
                    next_body: 0,
                    cursor: None,
                    inventory_digest: None,
                    sent: BTreeMap::new(),
                    assembly: None,
                    pending_catalog: None,
                    records: records::RecordProgress::default(),
                    sends: sends::SendProgress::default(),
                    departures: departure::DepartureProgress::default(),
                    renew: false,
                },
            );
        }
        Ok(())
    }
    fn ensure_canonical_automatic_initiator(
        &mut self,
        policy: ApprovedAccountSharingPolicy,
    ) -> Result<(), AccountSharingError> {
        self.automatic_policy_current(&policy)?;
        let id = Self::automatic_policy_id(&policy)?;
        if self
            .account_sharing_owner
            .automatic
            .get(&id)
            .is_some_and(|entry| {
                !entry.recipient
                    && !entry.ready
                    && !entry.renew
                    && !entry.pending_canonical_request_expired()
                    && entry.original.live()
                    && self
                        .runtime
                        .session()
                        .validate_account_sharing_channel(&entry.channel)
                        .is_ok()
            })
        {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_automatic_progress(
                "canonical_restart_signal",
                self.account_sharing_owner.automatic.get(&id).unwrap(),
                "retained_live_pending_lower",
            );
            return Ok(());
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        self.test_trace_catalog_stage("canonical_restart_signal", "begin_fresh_lower", None);
        let mut previous = self.account_sharing_owner.automatic.remove(&id);
        let progress = previous
            .as_mut()
            .map(AutomaticChannel::take_catalog_progress);
        match self.begin_automatic_channel(policy, progress) {
            Ok(()) => {
                // Fresh begin owns an independent actual Core lease before the
                // previous one is retired. No old lease/deadline is extended.
                drop(previous);
                Ok(())
            }
            Err(error) => {
                if let Some(mut previous) = previous {
                    // A transient failure must not consume the only restart
                    // observation. Usual maintenance retries the same negative
                    // renewal; the original's lifetime remains unchanged.
                    previous.renew = true;
                    self.account_sharing_owner.automatic.insert(id, previous);
                }
                Err(error)
            }
        }
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
                handshake_published_at: None,
                pending: VecDeque::new(),
                next_body: 0,
                cursor: None,
                inventory_digest: None,
                sent: BTreeMap::new(),
                assembly: None,
                pending_catalog: None,
                records: records::RecordProgress::default(),
                sends: sends::SendProgress::default(),
                departures: departure::DepartureProgress::default(),
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
    #[cfg(all(test, feature = "test-policy-overrides"))]
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
    /// Actual Core termination invalidates source disclosure, even when a local
    /// hide had already removed its presentation row. It grants no new channel.
    pub(crate) fn invalidate_automatic_catalog_after_termination(
        &mut self,
        group: &crate::GroupId,
    ) {
        for entry in self.account_sharing_owner.automatic.values_mut() {
            if &entry.policy.protected_group == group {
                continue;
            }
            entry.cursor = None;
            entry.inventory_digest = None;
            if entry.pending_catalog.as_ref().is_some_and(|pending| {
                pending.state == MirroredChatState::Active && &pending.receipt.group == group
            }) {
                entry.original.cancel();
                entry
                    .pending
                    .retain(|body| body.kind != AccountSharedBodyKind::Catalog);
                entry.pending_catalog = None;
                entry.renew = true;
            }
        }
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

        #[cfg(all(test, feature = "test-policy-overrides"))]
        self.test_trace_catalog_stage(
            "maintain_begin",
            &format!(
                "approved_policy_count={}, current_channel_count={}",
                policies.len(),
                self.account_sharing_owner.automatic.len()
            ),
            None,
        );
        self.promote_approved_automatic_requests(&policies)
            .inspect_err(|_error| {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                self.test_trace_catalog_stage(
                    "maintain_promote",
                    diagnostics::sharing_category(_error),
                    None,
                );
            })?;

        let current: Vec<_> = policies
            .iter()
            .filter(|policy| self.automatic_policy_current(policy).is_ok())
            .cloned()
            .collect();
        self.maintain_local_account_chat_departures(&current)
            .await?;

        for policy in policies {
            let id = Self::automatic_policy_id(&policy)?;
            if self.automatic_policy_current(&policy).is_err() {
                if self.account_sharing_owner.automatic.remove(&id).is_some() {
                    self.notify_mirrored_presentation_changed();
                }
                continue;
            }
            let retry_canonical =
                self.account_sharing_owner
                    .automatic
                    .get(&id)
                    .is_some_and(|entry| {
                        entry.policy.local_device < entry.policy.peer_device
                            && (entry.renew || entry.pending_canonical_request_expired())
                            && entry.original.live()
                            && self
                                .runtime
                                .session()
                                .validate_account_sharing_channel(&entry.channel)
                                .is_ok()
                    });
            if retry_canonical {
                // An acknowledged publication is not a peer Consent. Re-enter
                // normal fresh Core begin after a bounded unanswered request,
                // keeping the old owner alive until new begin succeeds. Its
                // lease/deadline and any observed permission remain unchanged.
                self.ensure_canonical_automatic_initiator(policy.clone())?;
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
            if retired && let Some(mut old) = self.account_sharing_owner.automatic.remove(&id) {
                progress = Some(old.take_catalog_progress());
            }
            if !self.account_sharing_owner.automatic.contains_key(&id) {
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
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_automatic_progress("tick_before", &entry, "observed");
            let result = self.automatic_sharing_tick(&mut entry).await;
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_automatic_progress(
                "tick_after",
                &entry,
                result
                    .as_ref()
                    .err()
                    .map(diagnostics::sharing_category)
                    .unwrap_or("ok"),
            );
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
            entry.handshake_published_at = Some(std::time::Instant::now());
            if entry.recipient {
                entry.ready = true;
            }
            return Ok(());
        }
        if !entry.ready {
            return Ok(());
        }
        self.retry_automatic_departure(entry)?;
        if entry.renew {
            return Ok(());
        }
        if let Some(pending) = &entry.pending_catalog
            && pending.state == MirroredChatState::Active
            && (self
                .app
                .account_storage(&self.state.label)
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?
                .get_group(&pending.receipt.group)
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?
                .is_terminal()
                || !self
                    .automatic_chat_source_accepted(&pending.receipt.group)
                    .map_err(|_| AccountSharingError::RuntimeUnavailable)?)
        {
            // An old sealed body cannot be replaced at the same channel ordinal.
            // Retire the original context, retaining only durable journal progress;
            // a fresh approved-policy channel will publish the empty withdrawal.
            entry
                .pending
                .retain(|body| body.kind != AccountSharedBodyKind::Catalog);
            entry.pending_catalog = None;
            entry.cursor = None;
            entry.inventory_digest = None;
            entry.renew = true;
            return Ok(());
        }
        if entry.pending.is_empty() {
            self.prepare_automatic_departure(entry)?;
        }
        if entry.pending.is_empty() {
            self.prepare_automatic_sends(entry).await?;
        }
        if entry.pending.is_empty()
            && entry.pending_catalog.is_none()
            && !entry.records.has_pending()
        {
            self.prepare_automatic_catalog(entry)?;
            if entry.pending.is_empty() && entry.pending_catalog.is_none() {
                self.prepare_automatic_records(entry)?;
            }
        }
        if !self.automatic_record_publication_current(entry)? {
            return Ok(());
        }
        if entry
            .pending_catalog
            .as_ref()
            .and_then(|pending| pending.published_at)
            .is_some_and(|published| published.elapsed() >= std::time::Duration::from_secs(10))
        {
            // Relay publication does not prove recipient commit. Retry the same
            // durable source sequence through fresh owned cryptographic context.
            entry.renew = true;
            return Ok(());
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if self.automatic_departure_reply_held(entry)? {
            return Ok(());
        }
        let Some(body) = entry.pending.front() else {
            return Ok(());
        };
        self.runtime
            .session()
            .seal_account_shared_body(&mut entry.channel, body.kind, entry.next_body, &body.bytes)
            .map_err(|_| AccountSharingError::NotReady)?;
        self.publish_automatic_control(entry, AccountSharingControl::Body(entry.next_body))
            .await?;
        entry.pending.pop_front();
        entry.next_body += 1;
        if entry.pending.is_empty()
            && let Some(pending) = entry.pending_catalog.as_mut()
            && pending.published_at.is_none()
        {
            pending.published_at = Some(std::time::Instant::now());
        }
        self.automatic_record_mark_published(entry);
        self.automatic_send_mark_published(entry);
        self.automatic_departure_mark_published(entry)?;
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
            .account_chat_catalog_journal(&entry.policy.protected_group, entry.cursor.as_ref(), 1)
            .map_err(|_| AccountSharingError::Closed)?;
        let Some(source) = page.entries.first() else {
            return Ok(());
        };
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        use cgka_engine::account_chat_catalog::AccountChatCatalogObservation;
        let (group_id, epoch, profile, mut state) = match source {
            AccountChatCatalogObservation::Active(source) => (
                source.group_id.clone(),
                source.epoch,
                source.profile,
                MirroredChatState::Active,
            ),
            AccountChatCatalogObservation::Withdrawn {
                group_id,
                epoch,
                profile,
                disbanded,
            } => (
                group_id.clone(),
                *epoch,
                *profile,
                if *disbanded {
                    MirroredChatState::Deleted
                } else {
                    MirroredChatState::Left
                },
            ),
        };
        if state == MirroredChatState::Active
            && self
                .automatic_chat_source_denied(&group_id)
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?
        {
            // The actual explicit decline is a source-scoped negative intent.
            // It need not wait for an offline ordinary administrator to commit
            // the SelfRemove, and never removes another genuine member source.
            state = MirroredChatState::Left;
        }
        let (name, description) = if state == MirroredChatState::Active {
            if !self
                .automatic_chat_source_accepted(&group_id)
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?
            {
                entry.cursor = Some(group_id);
                return Ok(());
            }
            let group = storage
                .get_group(&group_id)
                .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
            (group.name, group.description)
        } else {
            (String::new(), String::new())
        };
        let accepted_origin = if state == MirroredChatState::Active {
            storage.current_account_chat_source_origin(
                &entry.policy.account,
                &entry.policy.local_device,
                &group_id,
            )
        } else {
            storage
                .current_account_chat_source_terminal_origin(
                    &entry.policy.account,
                    &entry.policy.local_device,
                    &group_id,
                )
                .and_then(|origin| match origin {
                    Some(_) => Ok(origin),
                    None => storage.current_account_chat_source_origin(
                        &entry.policy.account,
                        &entry.policy.local_device,
                        &group_id,
                    ),
                })
        }
        .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        // No origin is manufactured for old packets/observations.
        let same_account_source_count = if state == MirroredChatState::Active {
            let membership = self
                .runtime
                .session()
                .canonical_group_membership(&group_id)
                .map_err(|_| AccountSharingError::NotReady)?;
            let count = membership
                .member_leaves
                .iter()
                .filter(|leaf| leaf.member.as_slice() == entry.policy.account)
                .count();
            if !(1..=128).contains(&count) {
                return Err(AccountSharingError::NotReady);
            }
            Some(count as u32)
        } else {
            None
        };
        let mut record = MirroredChatEntry {
            group_id,
            source_epoch: epoch,
            source_sequence: 0,
            source_digest: [0; 32],
            profile,
            name,
            description,
            state,

            accepted_origin,

            same_account_source_count,
        };
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if self.test_uses_legacy_account_chat_encoding() {
            record.accepted_origin = None;
            record.same_account_source_count = None;
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        self.test_trace_catalog_stage(
            "catalog_prepared",
            &format!(
                "state={}, origin_present={}, catalog_ack_present={}",
                match record.state {
                    MirroredChatState::Active => "Active",
                    MirroredChatState::Left => "Left",
                    MirroredChatState::Deleted => "Deleted",
                },
                record.accepted_origin.is_some(),
                entry.sent.contains_key(record.group_id.as_slice())
            ),
            None,
        );
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
            entry.pending.push_back(PendingBody {
                kind: AccountSharedBodyKind::Catalog,
                bytes: serde_json::to_vec(&CatalogFragment {
                    version: 1,
                    digest: whole,
                    ordinal: ordinal as u32,
                    count,
                    body: base64::engine::general_purpose::STANDARD.encode(body),
                })
                .map_err(|_| AccountSharingError::NotReady)?,
            });
        }
        entry.pending_catalog = Some(PendingCatalog {
            receipt: CatalogReceipt {
                version: 1,
                group: record.group_id,
                sequence: record.source_sequence,
                source_digest: digest,
                encoded_digest: whole,
            },
            published_at: None,
            state: record.state,
        });
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
        #[cfg(all(test, feature = "test-policy-overrides"))]
        let input_payload_digest: [u8; 32] = Sha256::digest(&message.payload).into();
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
        let original = Arc::clone(&entry.original);
        let revoked = original.revoked.notified();
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
        let publication_deadline = self.automatic_record_publication_deadline(entry)?;
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if matches!(kind, AccountSharingControl::Consent)
            && let (Some(content_id), Some(inner_wire_sha256)) = (
                entry.channel.outbound_content_id_for_test(kind),
                entry.channel.outbound_control_wire_digest_for_test(kind),
            )
        {
            consent_delivery_probe::prepared(
                self.app.account_home().root(),
                &consent_delivery_probe::PreparedConsent {
                    account: entry.policy.account,
                    protected_group: entry.policy.protected_group.clone(),
                    local_device: entry.policy.local_device,
                    peer_device: entry.policy.peer_device,
                    nonce: entry.channel.scope().nonce,
                    content_id,
                    input_outer_payload_sha256: input_payload_digest,
                    inner_wire_sha256,
                },
            );
        }
        let _publication = tokio::select! {biased;()=stopping=>return Err(AccountSharingError::Closed),()=&mut revoked=>return Err(AccountSharingError::Closed),()=tokio::time::sleep_until(publication_deadline.into())=>{entry.renew=true;return Err(AccountSharingError::Closed)},report=self.adapter.publish_selected_chat(request)=>{let report=report.map_err(|_|AccountSharingError::RuntimeUnavailable)?;if !report.met_required_acks(){return Err(AccountSharingError::NotReady)} report}};
        self.automatic_policy_current(&entry.policy)?;
        if !self.automatic_record_publication_current(entry)? {
            return Err(AccountSharingError::Closed);
        }
        self.runtime
            .session()
            .validate_account_sharing_channel(&entry.channel)
            .map_err(|_| AccountSharingError::Closed)
            .inspect(|_| {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                if matches!(kind, AccountSharingControl::Consent)
                    && let (Some(content_id), Some(inner_wire_sha256)) = (
                        entry.channel.outbound_content_id_for_test(kind),
                        entry.channel.outbound_control_wire_digest_for_test(kind),
                    )
                {
                    consent_delivery_probe::published(
                        self.app.account_home().root(),
                        &consent_delivery_probe::Publication {
                            account: entry.policy.account,
                            protected_group: entry.policy.protected_group.clone(),
                            local_device: entry.policy.local_device,
                            peer_device: entry.policy.peer_device,
                            nonce: entry.channel.scope().nonce,
                            content_id,
                            outer_id: _publication.message_id.clone(),
                            input_outer_payload_sha256: input_payload_digest,
                            inner_wire_sha256,
                        },
                    );
                }
            })
    }
}
