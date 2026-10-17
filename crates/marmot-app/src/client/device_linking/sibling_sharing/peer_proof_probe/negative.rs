//! Explicit validation-error injection after real peer authentication; never a SQL fault.
use super::*;
use cgka_engine::account_chat_sharing::AccountSharingControl;
use sha2::{Digest, Sha256};
use std::sync::atomic::AtomicUsize;

pub(crate) struct Probe {
    owner: Weak<Existing>,
    nonce: [u8; 32],
    wire_digest: [u8; 32],
    routed_after_cancel: AtomicUsize,
    closed_denials: AtomicUsize,
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

pub(crate) fn arm(
    owner: &Arc<Existing>,
    nonce: [u8; 32],
    wire_digest: [u8; 32],
    reject: bool,
) -> Arc<Probe> {
    let probe = Arc::new(Probe {
        owner: Arc::downgrade(owner),
        nonce,
        wire_digest,
        routed_after_cancel: AtomicUsize::new(0),
        closed_denials: AtomicUsize::new(0),
        rejecting: AtomicBool::new(reject),
        accepted: AtomicUsize::new(0),
        rejected: AtomicUsize::new(0),
        own_publications: AtomicUsize::new(0),
        open_attempts: AtomicUsize::new(0),
    });
    let mut rows = probes().lock().expect("negative peer proof probes");
    rows.retain(|row| row.strong_count() != 0);
    assert!(rows.len() < 4, "bounded negative proof probes");
    assert!(
        !rows
            .iter()
            .filter_map(Weak::upgrade)
            .any(|row| row.owner.ptr_eq(&probe.owner))
    );
    rows.push(Arc::downgrade(&probe));
    probe
}

impl Probe {
    pub(crate) fn clear(&self) {
        self.rejecting.store(false, Ordering::Release);
    }
    pub(crate) fn counts(&self) -> [usize; 6] {
        [
            self.accepted.load(Ordering::Acquire),
            self.rejected.load(Ordering::Acquire),
            self.own_publications.load(Ordering::Acquire),
            self.open_attempts.load(Ordering::Acquire),
            self.routed_after_cancel.load(Ordering::Acquire),
            self.closed_denials.load(Ordering::Acquire),
        ]
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        self.clear();
    }
}

fn exact(entry: &SiblingChannel) -> Option<Arc<Probe>> {
    let SiblingOriginal::Existing { original, .. } = entry.original.as_ref() else {
        return None;
    };
    probes()
        .lock()
        .expect("negative peer proof probes")
        .iter()
        .filter_map(Weak::upgrade)
        .find(|probe| {
            probe.nonce == entry.channel.scope().nonce
                && probe.owner.ptr_eq(&Arc::downgrade(original))
        })
}

pub(in crate::client::device_linking::sibling_sharing) fn accepted(entry: &SiblingChannel) {
    if let Some(probe) = exact(entry) {
        probe.accepted.fetch_add(1, Ordering::AcqRel);
    }
}
pub(in crate::client::device_linking::sibling_sharing) fn started(
    entry: &SiblingChannel,
    proof: bool,
) {
    if proof && let Some(probe) = exact(entry) {
        probe.own_publications.fetch_add(1, Ordering::AcqRel);
    }
}
pub(in crate::client::device_linking::sibling_sharing) fn reject(entry: &SiblingChannel) -> bool {
    if entry.peer_committed
        && let Some(probe) = exact(entry)
        && probe.rejecting.load(Ordering::Acquire)
    {
        probe.rejected.fetch_add(1, Ordering::AcqRel);
        return true;
    }
    false
}

pub(in crate::client::device_linking::sibling_sharing) fn opened(entry: &SiblingChannel) {
    if let Some(probe) = exact(entry) {
        probe.open_attempts.fetch_add(1, Ordering::AcqRel);
    }
}

// Passive capture of the actual Core-sealed proof before its owned SDK task starts.
pub(in crate::client::device_linking::sibling_sharing) fn prepared(
    original: &Arc<SiblingOriginal>,
    nonce: [u8; 32],
    digest: Option<[u8; 32]>,
) {
    let SiblingOriginal::Recipient { choice, .. } = original.as_ref() else {
        return;
    };
    let Some(digest) = digest else {
        return;
    };
    for gate in registry()
        .lock()
        .expect("peer proof gates")
        .iter()
        .filter_map(Weak::upgrade)
    {
        if !gate.owner.ptr_eq(&Arc::downgrade(choice)) {
            continue;
        }
        let mut rows = gate.prepared.lock().expect("prepared peer proof");
        if let Some(row) = rows.iter().find(|row| row.0 == nonce) {
            assert!(row.1 == digest, "immutable actual sealed proof");
        } else {
            assert!(rows.len() < 4, "bounded prepared peer proofs");
            rows.push((nonce, digest));
        }
    }
}

fn exact_closed_wire(
    entry: &SiblingChannel,
    received: &cgka_engine::account_chat_sharing::ReceivedAccountSharingControl,
    wire: &[u8],
) -> Option<Arc<Probe>> {
    let probe = exact(entry)?;
    let scope = entry.channel.scope();
    if entry.original.live()
        || !matches!(received.control, AccountSharingControl::Body(0))
        || received.nonce != scope.nonce
        || received.source != scope.source
        || received.recipient != scope.recipient
        || received.approval_id != scope.approval_id
        || received.signer != scope.recipient
        || <[u8; 32]>::from(Sha256::digest(wire)) != probe.wire_digest
    {
        return None;
    }
    Some(probe)
}

// Called before the original live gate, not an inference from a missing actor row.
pub(in crate::client::device_linking::sibling_sharing) fn routed(
    entry: &SiblingChannel,
    received: &cgka_engine::account_chat_sharing::ReceivedAccountSharingControl,
    wire: &[u8],
) {
    if let Some(probe) = exact_closed_wire(entry, received, wire) {
        probe.routed_after_cancel.fetch_add(1, Ordering::AcqRel);
    }
}
pub(in crate::client::device_linking::sibling_sharing) fn closed(
    entry: &SiblingChannel,
    received: &cgka_engine::account_chat_sharing::ReceivedAccountSharingControl,
    wire: &[u8],
) {
    if let Some(probe) = exact_closed_wire(entry, received, wire) {
        probe.closed_denials.fetch_add(1, Ordering::AcqRel);
    }
}
