//! Explicit validation-error injection after real peer authentication; never a SQL fault.
use super::*;
use std::sync::atomic::AtomicUsize;

pub(crate) struct Probe {
    owner: Weak<Existing>,
    nonce: [u8; 32],
    rejecting: AtomicBool,
    accepted: AtomicUsize,
    rejected: AtomicUsize,
    own_publications: AtomicUsize,
    open_attempts: AtomicUsize,
}

fn probes() -> &'static Mutex<Vec<Weak<Probe>>> {
    static PROBES: OnceLock<Mutex<Vec<Weak<Probe>>>> = OnceLock::new();
    PROBES.get_or_init(Default::default)
}

pub(crate) fn arm(owner: &Arc<Existing>, nonce: [u8; 32], reject: bool) -> Arc<Probe> {
    let probe = Arc::new(Probe {
        owner: Arc::downgrade(owner), nonce,
        rejecting: AtomicBool::new(reject), accepted: AtomicUsize::new(0),
        rejected: AtomicUsize::new(0), own_publications: AtomicUsize::new(0),
        open_attempts: AtomicUsize::new(0),
    });
    let mut rows = probes().lock().expect("negative peer proof probes");
    rows.retain(|row| row.strong_count() != 0);
    assert!(rows.len() < 4, "bounded negative proof probes");
    assert!(!rows.iter().filter_map(Weak::upgrade).any(|row| row.owner.ptr_eq(&probe.owner)));
    rows.push(Arc::downgrade(&probe));
    probe
}

impl Probe {
    pub(crate) fn clear(&self) { self.rejecting.store(false, Ordering::Release); }
    pub(crate) fn counts(&self) -> [usize; 4] {
        [self.accepted.load(Ordering::Acquire), self.rejected.load(Ordering::Acquire),
            self.own_publications.load(Ordering::Acquire), self.open_attempts.load(Ordering::Acquire)]
    }
}
impl Drop for Probe {
    fn drop(&mut self) { self.clear(); }
}

fn exact(entry: &SiblingChannel) -> Option<Arc<Probe>> {
    let SiblingOriginal::Existing { original, .. } = entry.original.as_ref() else { return None; };
    probes().lock().expect("negative peer proof probes").iter().filter_map(Weak::upgrade)
        .find(|probe| probe.nonce == entry.channel.scope().nonce
            && probe.owner.ptr_eq(&Arc::downgrade(original)))
}

pub(in crate::client::device_linking::sibling_sharing) fn accepted(entry: &SiblingChannel) {
    if let Some(probe) = exact(entry) { probe.accepted.fetch_add(1, Ordering::AcqRel); }
}
pub(in crate::client::device_linking::sibling_sharing) fn started(entry: &SiblingChannel, proof: bool) {
    if proof && let Some(probe) = exact(entry) { probe.own_publications.fetch_add(1, Ordering::AcqRel); }
}
pub(in crate::client::device_linking::sibling_sharing) fn reject(entry: &SiblingChannel) -> bool {
    if entry.peer_committed && let Some(probe) = exact(entry)
        && probe.rejecting.load(Ordering::Acquire) {
        probe.rejected.fetch_add(1, Ordering::AcqRel);
        return true;
    }
    false
}

pub(in crate::client::device_linking::sibling_sharing) fn opened(entry: &SiblingChannel) {
    if let Some(probe) = exact(entry) { probe.open_attempts.fetch_add(1, Ordering::AcqRel); }
}
