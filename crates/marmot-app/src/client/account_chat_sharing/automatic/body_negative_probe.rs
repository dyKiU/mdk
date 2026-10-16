//! Test-only observations of one real owned Body and authenticated SQL rollback.
//! Roots and identities stay in memory; only counters/booleans leave the fixture.
use super::*;
use std::{path::{Path, PathBuf}, sync::{Mutex, OnceLock, Weak}};

#[derive(Clone, Default)]
pub(crate) struct Observation {
    pub(crate) sql_failures: u64,
    pub(crate) barrier_observations: u64,
    pub(crate) retained: bool,
    pub(crate) aborted_task_finished: bool,
    pub(crate) commit_at: u64,
    pub(crate) harvest_at: u64,
    pub(crate) body_effects: u64,
    pub(crate) harvested_cancelled: bool,
}
struct Captured {
    original: Weak<State>,
    nonce: [u8; 32],
    sequence: u64,
    task: tokio::task::Id,
    pending_len: usize,
    payload_digest: [u8; 32],
    catalog_group: crate::GroupId,
}
struct Progress { captured: Option<Captured>, ordinal: u64, observed: Observation }
pub(crate) struct Probe { root: PathBuf, old_chat: crate::GroupId, progress: Mutex<Progress> }
fn registry() -> &'static Mutex<BTreeMap<PathBuf, Weak<Probe>>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Probe>>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}
impl Probe {
    pub(crate) fn snapshot(&self) -> Observation { self.progress.lock().expect("negative probe").observed.clone() }
    pub(crate) fn matches_held_catalog(&self, group: &crate::GroupId, payload_digest: [u8; 32]) -> bool {
        self.progress.lock().expect("negative probe").captured.as_ref().is_some_and(|captured| &captured.catalog_group == group && captured.payload_digest == payload_digest)
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
    fn drop(&mut self) { registry().lock().expect("negative registry").remove(&self.root); }
}
impl AppClient {
    pub(crate) fn test_capture_automatic_body_negative(root: &Path, old_chat: &crate::GroupId) -> Arc<Probe> {
        let mut registry = registry().lock().expect("negative registry");
        registry.retain(|_, weak| weak.strong_count() > 0);
        assert!(registry.len() < 8 && !registry.contains_key(root));
        let probe = Arc::new(Probe { root: root.to_owned(), old_chat: old_chat.clone(), progress: Mutex::new(Progress { captured: None, ordinal: 0, observed: Observation { retained: true, ..Observation::default() } }) });
        registry.insert(root.to_owned(), Arc::downgrade(&probe)); probe
    }
}
fn at(root: &Path) -> Option<Arc<Probe>> { registry().lock().expect("negative registry").get(root).and_then(Weak::upgrade) }
pub(super) fn capture(root: &Path, entry: &AutomaticChannel) {
    let Some(probe) = at(root) else { return; };
    let mut progress = probe.progress.lock().expect("negative probe");
    if progress.captured.is_some() || !entry.pending.front().is_some_and(|body| body.kind == AccountSharedBodyKind::Catalog) { return; }
    let Some(catalog) = entry.pending_catalog.as_ref().filter(|catalog| catalog.receipt.group != probe.old_chat) else { return; };
    let Some(publication) = entry.publication.as_ref().filter(|publication| publication.body_context.is_some()) else { return; };
    progress.captured = Some(Captured { original: Arc::downgrade(&entry.original), nonce: entry.channel.scope().nonce, sequence: entry.next_body, task: publication.task.id(), pending_len: entry.pending.len(), payload_digest: publication.payload_digest, catalog_group: catalog.receipt.group.clone() });
}
pub(super) fn sql_failure(root: &Path, entry: &AutomaticChannel, group: &crate::GroupId, error: &cgka_traits::storage::StorageError) {
    let Some(probe) = at(root) else { return; };
    if group != &probe.old_chat || !matches!(error, cgka_traits::storage::StorageError::Backend(message) if message.contains("isolated genuine negative cut rollback")) { return; }
    let mut progress = probe.progress.lock().expect("negative probe");
    progress.observed.sql_failures += 1;
    let retained = progress.captured.as_ref().is_some_and(|captured| Probe::same(captured, entry))
        && !entry.renew && entry.original.live() && entry.departures.complete_assembly_for_test();
    progress.observed.retained &= retained;
}
pub(super) fn barrier(root: &Path, entry: &AutomaticChannel) {
    let Some(probe) = at(root) else { return; };
    let mut progress = probe.progress.lock().expect("negative probe");
    progress.observed.barrier_observations += 1;
    let retained = progress.captured.as_ref().is_some_and(|captured| Probe::same(captured, entry)) && !entry.renew && entry.departures.complete_assembly_for_test();
    progress.observed.retained &= retained;
    progress.observed.aborted_task_finished |= entry.publication.as_ref().is_some_and(|publication| publication.task.is_finished());
}
pub(super) fn commit(root: &Path, entry: &AutomaticChannel, group: &crate::GroupId) {
    let Some(probe) = at(root) else { return; };
    if group != &probe.old_chat { return; }
    let mut progress = probe.progress.lock().expect("negative probe");
    if progress.observed.sql_failures == 0 { return; }
    progress.ordinal += 1;
    if progress.observed.commit_at == 0 { progress.observed.commit_at = progress.ordinal; }
    let retained = progress.captured.as_ref().is_some_and(|captured| Probe::same(captured, entry));
    progress.observed.retained &= retained;
}
pub(super) fn harvest(root: &Path, task: tokio::task::Id, cancelled: bool) {
    let Some(probe) = at(root) else { return; };
    let mut progress = probe.progress.lock().expect("negative probe");
    if !progress.captured.as_ref().is_some_and(|captured| captured.task == task) { return; }
    progress.ordinal += 1;
    if progress.observed.harvest_at == 0 { progress.observed.harvest_at = progress.ordinal; }
    progress.observed.harvested_cancelled |= cancelled;
}
pub(super) fn effects(root: &Path, entry: &AutomaticChannel) {
    let Some(probe) = at(root) else { return; };
    let mut progress = probe.progress.lock().expect("negative probe");
    if progress.captured.as_ref().is_some_and(|captured| captured.nonce == entry.channel.scope().nonce && captured.sequence == entry.next_body) { progress.observed.body_effects += 1; }
}
