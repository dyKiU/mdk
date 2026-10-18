//! Test-only observations of one real owned Body and authenticated SQL rollback.
//! Roots and identities stay in memory; only counters/booleans leave the fixture.
use super::*;
use std::{
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock, Weak},
};

#[derive(Clone, Default)]
pub(crate) struct Observation {
    pub(crate) sql_failures: u64,
    pub(crate) associated_sql_failures: u64,
    pub(crate) barrier_observations: u64,
    pub(crate) retained: bool,
    pub(crate) aborted_task_finished: bool,
    pub(crate) commit_at: u64,
    pub(crate) harvest_at: u64,
    pub(crate) retirement_at: u64,
    pub(crate) body_effects: u64,
    pub(crate) harvested_cancelled: bool,
    pub(crate) retired_task_finished: bool,
}
#[derive(Default)]
pub(crate) struct HeldCatalogDiagnostic {
    pub(crate) evaluated: u16,
    pub(crate) matched: u16,
    pub(crate) capture_ordinal: Option<u64>,
    pub(crate) observation_ordinal: Option<u64>,
    pub(crate) known: bool,
}
struct Captured {
    original: Weak<State>,
    nonce: [u8; 32],
    sequence: u64,
    task: tokio::task::Id,
    pending_len: usize,
    payload_digest: [u8; 32],
    catalog_group: crate::GroupId,
    account: [u8; 32],
    protected_group: crate::GroupId,
    local_device: [u8; 32],
    peer_device: [u8; 32],
}
struct PreparedIntent {
    action: [u8; 32],
    nonce: [u8; 32],
    account: [u8; 32],
    protected_group: crate::GroupId,
    local_device: [u8; 32],
    peer_device: [u8; 32],
}
pub(super) struct IntentGate {
    binding: PreparedIntent,
    prepared_payload_digest: [u8; 32],
    release: tokio::sync::watch::Sender<bool>,
    entered: std::sync::atomic::AtomicBool,
}
impl IntentGate {
    pub(super) async fn wait(&self, payload_digest: [u8; 32]) {
        if self.prepared_payload_digest != payload_digest {
            return;
        }
        let mut release = self.release.subscribe();
        self.entered
            .store(true, std::sync::atomic::Ordering::Release);
        while !*release.borrow_and_update() {
            if release.changed().await.is_err() {
                break;
            }
        }
    }
}
struct Progress {
    captured: Option<Captured>,
    diagnostic_ordinal: u64,
    diagnostic_capture_ordinal: Option<u64>,
    diagnostic_known: bool,
    ordinal: u64,
    observed: Observation,
    prepared_intent: Option<PreparedIntent>,
    intent_gate: Option<Arc<IntentGate>>,
}
pub(crate) struct Probe {
    root: PathBuf,
    peer_root: PathBuf,
    old_chat: crate::GroupId,
    progress: Mutex<Progress>,
}
fn registry() -> &'static Mutex<BTreeMap<PathBuf, Weak<Probe>>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Probe>>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}
impl Probe {
    pub(crate) fn peer_intent_is_held(&self) -> bool {
        self.progress
            .lock()
            .expect("negative probe")
            .intent_gate
            .as_ref()
            .is_some_and(|gate| {
                gate.entered.load(std::sync::atomic::Ordering::Acquire)
                    && gate.release.receiver_count() > 0
            })
    }
    pub(crate) fn release_peer_intent(&self) {
        if let Some(gate) = &self.progress.lock().expect("negative probe").intent_gate {
            gate.release.send_replace(true);
        }
    }
    pub(crate) fn snapshot(&self) -> Observation {
        self.progress
            .lock()
            .expect("negative probe")
            .observed
            .clone()
    }
    pub(crate) fn matches_held_catalog(
        &self,
        group: &crate::GroupId,
        payload_digest: [u8; 32],
        diagnostic: &mut HeldCatalogDiagnostic,
    ) -> bool {
        fn note(diagnostic: &mut HeldCatalogDiagnostic, index: u32, value: bool) -> bool {
            diagnostic.evaluated |= 1u16 << index;
            if value {
                diagnostic.matched |= 1u16 << index;
            }
            value
        }
        let mut progress = self.progress.lock().expect("negative probe");
        // This is the existing lock. No new read/lock/wait is added to the fixture.
        *diagnostic = HeldCatalogDiagnostic::default();
        diagnostic.known = progress.diagnostic_known;
        diagnostic.capture_ordinal = progress.diagnostic_capture_ordinal;
        match progress.diagnostic_ordinal.checked_add(1) {
            Some(next) => {
                progress.diagnostic_ordinal = next;
                diagnostic.observation_ordinal = Some(next);
            }
            None => {
                progress.diagnostic_known = false;
                diagnostic.known = false;
            }
        }
        // zip originally evaluates BOTH Option::as_ref values. Preserve that behavior.
        note(diagnostic, 0, progress.captured.is_some());
        note(diagnostic, 1, progress.intent_gate.is_some());
        progress
            .captured
            .as_ref()
            .zip(progress.intent_gate.as_ref())
            .is_some_and(|(captured, gate)| {
                note(diagnostic, 2, &captured.catalog_group == group)
                    && note(diagnostic, 3, captured.payload_digest == payload_digest)
                    && note(diagnostic, 4, captured.nonce == gate.binding.nonce)
                    && note(diagnostic, 5, captured.account == gate.binding.account)
                    && note(
                        diagnostic,
                        6,
                        captured.protected_group == gate.binding.protected_group,
                    )
                    && note(
                        diagnostic,
                        7,
                        captured.local_device == gate.binding.peer_device,
                    )
                    && note(
                        diagnostic,
                        8,
                        captured.peer_device == gate.binding.local_device,
                    )
                    && note(
                        diagnostic,
                        9,
                        gate.entered.load(std::sync::atomic::Ordering::Acquire),
                    )
                    && note(diagnostic, 10, gate.release.receiver_count() > 0)
            })
    }
    fn same(captured: &Captured, entry: &AutomaticChannel) -> bool {
        Weak::ptr_eq(&captured.original, &Arc::downgrade(&entry.original))
            && captured.nonce == entry.channel.scope().nonce
            && captured.sequence == entry.next_body
            && captured.pending_len == entry.pending.len()
            && entry.publication.as_ref().is_some_and(|publication| {
                publication.task.id() == captured.task
                    && publication.payload_digest == captured.payload_digest
                    && publication.body_context.is_some()
                    && publication.body_context == entry.body_publication_context()
            })
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        self.release_peer_intent();
        registry()
            .lock()
            .expect("negative registry")
            .remove(&self.root);
    }
}
impl AppClient {
    pub(crate) fn test_capture_automatic_body_negative(
        root: &Path,
        peer_root: &Path,
        old_chat: &crate::GroupId,
    ) -> Arc<Probe> {
        let mut registry = registry().lock().expect("negative registry");
        registry.retain(|_, weak| weak.strong_count() > 0);
        assert!(registry.len() < 8 && !registry.contains_key(root));
        let probe = Arc::new(Probe {
            root: root.to_owned(),
            peer_root: peer_root.to_owned(),
            old_chat: old_chat.clone(),
            progress: Mutex::new(Progress {
                captured: None,
                diagnostic_ordinal: 0,
                diagnostic_capture_ordinal: None,
                diagnostic_known: true,
                ordinal: 0,
                observed: Observation {
                    retained: true,
                    ..Observation::default()
                },
                prepared_intent: None,
                intent_gate: None,
            }),
        });
        registry.insert(root.to_owned(), Arc::downgrade(&probe));
        probe
    }
}
fn at(root: &Path) -> Option<Arc<Probe>> {
    registry()
        .lock()
        .expect("negative registry")
        .get(root)
        .and_then(Weak::upgrade)
}
fn peer_at(root: &Path) -> Option<Arc<Probe>> {
    let weak: Vec<_> = registry()
        .lock()
        .expect("negative registry")
        .values()
        .cloned()
        .collect();
    weak.into_iter()
        .filter_map(|weak| weak.upgrade())
        .find(|probe| probe.peer_root == root)
}
pub(super) fn peer_intent_prepared(
    root: &Path,
    entry: &AutomaticChannel,
    intent: &storage_sqlite::account_chat_departure::AccountChatDepartureIntent,
) {
    let Some(probe) = peer_at(root) else {
        return;
    };
    if intent.group != probe.old_chat {
        return;
    }
    let mut progress = probe.progress.lock().expect("negative probe");
    if progress.intent_gate.is_some() {
        return;
    }
    progress.prepared_intent = Some(PreparedIntent {
        action: intent.action_id,
        nonce: entry.channel.scope().nonce,
        account: entry.policy.account,
        protected_group: entry.policy.protected_group.clone(),
        local_device: entry.policy.local_device,
        peer_device: entry.policy.peer_device,
    });
}
pub(super) fn peer_gate(
    root: &Path,
    entry: &AutomaticChannel,
    kind: AccountSharingControl,
    payload_digest: [u8; 32],
) -> Option<Arc<IntentGate>> {
    if !matches!(kind, AccountSharingControl::Body(_))
        || !entry
            .pending
            .front()
            .is_some_and(|body| body.kind == AccountSharedBodyKind::DepartureIntent)
    {
        return None;
    }
    let probe = peer_at(root)?;
    let mut progress = probe.progress.lock().expect("negative probe");
    if progress.intent_gate.is_some() {
        return None;
    }
    let binding = progress.prepared_intent.as_ref()?;
    if entry.departures.pending_action_for_test() != Some(binding.action)
        || binding.nonce != entry.channel.scope().nonce
    {
        return None;
    }
    let binding = progress.prepared_intent.take()?;
    let (release, _) = tokio::sync::watch::channel(false);
    let gate = Arc::new(IntentGate {
        binding,
        prepared_payload_digest: payload_digest,
        release,
        entered: std::sync::atomic::AtomicBool::new(false),
    });
    progress.intent_gate = Some(gate.clone());
    Some(gate)
}
pub(super) fn capture(root: &Path, entry: &AutomaticChannel) {
    let Some(probe) = at(root) else {
        return;
    };
    let mut progress = probe.progress.lock().expect("negative probe");
    if progress.captured.is_some()
        || !entry
            .pending
            .front()
            .is_some_and(|body| body.kind == AccountSharedBodyKind::Catalog)
    {
        return;
    }
    let Some(catalog) = entry
        .pending_catalog
        .as_ref()
        .filter(|catalog| catalog.receipt.group != probe.old_chat)
    else {
        return;
    };
    let Some(publication) = entry
        .publication
        .as_ref()
        .filter(|publication| publication.body_context.is_some())
    else {
        return;
    };
    match progress.diagnostic_ordinal.checked_add(1) {
        Some(next) => {
            progress.diagnostic_ordinal = next;
            progress.diagnostic_capture_ordinal = Some(next);
        }
        None => progress.diagnostic_known = false,
    }
    progress.captured = Some(Captured {
        original: Arc::downgrade(&entry.original),
        nonce: entry.channel.scope().nonce,
        sequence: entry.next_body,
        task: publication.task.id(),
        pending_len: entry.pending.len(),
        payload_digest: publication.payload_digest,
        catalog_group: catalog.receipt.group.clone(),
        account: entry.policy.account,
        protected_group: entry.policy.protected_group.clone(),
        local_device: entry.policy.local_device,
        peer_device: entry.policy.peer_device,
    });
}
pub(super) fn sql_failure(
    root: &Path,
    entry: &AutomaticChannel,
    group: &crate::GroupId,
    error: &cgka_traits::storage::StorageError,
) {
    let Some(probe) = at(root) else {
        return;
    };
    if group != &probe.old_chat
        || !matches!(error, cgka_traits::storage::StorageError::Backend(message) if message.contains("isolated genuine negative cut rollback"))
    {
        return;
    }
    let mut progress = probe.progress.lock().expect("negative probe");
    progress.observed.sql_failures += 1;
    let associated = progress.captured.as_ref().is_some_and(|captured| {
        Weak::ptr_eq(&captured.original, &Arc::downgrade(&entry.original))
            && captured.nonce == entry.channel.scope().nonce
            && entry.publication.as_ref().is_some_and(|publication| {
                publication.task.id() == captured.task && publication.body_context.is_some()
            })
    });
    progress.observed.associated_sql_failures += u64::from(associated);
    let retained = progress
        .captured
        .as_ref()
        .is_some_and(|captured| Probe::same(captured, entry))
        && !entry.renew
        && entry.original.live()
        && entry.departures.complete_assembly_for_test();
    progress.observed.retained &= retained;
}
pub(super) fn barrier(root: &Path, entry: &AutomaticChannel) {
    let Some(probe) = at(root) else {
        return;
    };
    let mut progress = probe.progress.lock().expect("negative probe");
    progress.observed.barrier_observations += 1;
    let retained = progress
        .captured
        .as_ref()
        .is_some_and(|captured| Probe::same(captured, entry))
        && !entry.renew
        && entry.departures.complete_assembly_for_test();
    progress.observed.retained &= retained;
    progress.observed.aborted_task_finished |= entry
        .publication
        .as_ref()
        .is_some_and(|publication| publication.task.is_finished());
}
pub(super) fn commit(root: &Path, entry: &AutomaticChannel, group: &crate::GroupId) {
    let Some(probe) = at(root) else {
        return;
    };
    if group != &probe.old_chat {
        return;
    }
    let mut progress = probe.progress.lock().expect("negative probe");
    if progress.observed.sql_failures == 0 {
        return;
    }
    progress.ordinal += 1;
    if progress.observed.commit_at == 0 {
        progress.observed.commit_at = progress.ordinal;
    }
    let retained = progress
        .captured
        .as_ref()
        .is_some_and(|captured| Probe::same(captured, entry));
    progress.observed.retained &= retained;
}
pub(super) fn harvest(root: &Path, task: tokio::task::Id, cancelled: bool) {
    let Some(probe) = at(root) else {
        return;
    };
    let mut progress = probe.progress.lock().expect("negative probe");
    if !progress
        .captured
        .as_ref()
        .is_some_and(|captured| captured.task == task)
    {
        return;
    }
    progress.ordinal += 1;
    if progress.observed.harvest_at == 0 {
        progress.observed.harvest_at = progress.ordinal;
    }
    progress.observed.harvested_cancelled |= cancelled;
}
pub(super) fn effects(root: &Path, entry: &AutomaticChannel) {
    let Some(probe) = at(root) else {
        return;
    };
    let mut progress = probe.progress.lock().expect("negative probe");
    if progress.captured.as_ref().is_some_and(|captured| {
        captured.nonce == entry.channel.scope().nonce && captured.sequence == entry.next_body
    }) {
        progress.observed.body_effects += 1;
    }
}
pub(super) fn retired(entry: &AutomaticChannel) {
    // Called only after the original cancel and channel retirement have run.
    // This is actual owner destruction, never an invented JoinHandle harvest.
    let weak: Vec<_> = registry()
        .lock()
        .expect("negative registry")
        .values()
        .cloned()
        .collect();
    for probe in weak.into_iter().filter_map(|weak| weak.upgrade()) {
        let mut progress = probe.progress.lock().expect("negative probe");
        let same = progress.captured.as_ref().is_some_and(|captured| {
            Weak::ptr_eq(&captured.original, &Arc::downgrade(&entry.original))
                && captured.nonce == entry.channel.scope().nonce
                && captured.sequence == entry.next_body
                && entry.publication.as_ref().is_some_and(|publication| {
                    publication.task.id() == captured.task && publication.body_context.is_some()
                })
        });
        if same {
            progress.ordinal += 1;
            if progress.observed.retirement_at == 0 {
                progress.observed.retirement_at = progress.ordinal;
            }
            progress.observed.retired_task_finished |= entry
                .publication
                .as_ref()
                .is_some_and(|publication| publication.task.is_finished());
        }
    }
}
