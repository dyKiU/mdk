//! Test-only custody of an actually admitted old negative body. This probe
//! neither creates an intent nor restores a cryptographic channel or owner.
use super::*;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};
use storage_sqlite::account_chat_departure::AccountChatDepartureIntent;

type Registry = BTreeMap<PathBuf, Weak<DepartureReplayProbe>>;
fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}
struct Captured {
    policy: ApprovedAccountSharingPolicy,
    action: [u8; 32],
    body_digest: [u8; 32],
    original_nonce: [u8; 32],
    fragments: Vec<Vec<u8>>,
    queued: BTreeSet<[u8; 32]>,
}
impl Drop for Captured {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.fragments.zeroize();
    }
}
#[derive(Default)]
struct Progress {
    captures: BTreeMap<[u8; 32], Captured>,
    replay: bool,
    received: BTreeSet<[u8; 32]>,
}
pub(crate) struct DepartureReplayProbe {
    root: PathBuf,
    group: crate::GroupId,
    peers: BTreeSet<[u8; 32]>,
    deadline: Instant,
    progress: Mutex<Progress>,
}
impl Drop for DepartureReplayProbe {
    fn drop(&mut self) {
        let mut entries = registry()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if entries
            .get(&self.root)
            .is_some_and(|weak| weak.upgrade().is_none())
        {
            entries.remove(&self.root);
        }
    }
}
impl DepartureReplayProbe {
    pub(crate) fn request_replay(&self) {
        assert!(Instant::now() < self.deadline);
        let mut progress = self.progress.lock().unwrap();
        assert_eq!(progress.captures.len(), self.peers.len());
        progress.replay = true;
    }
    pub(crate) fn received_peer_count(&self) -> usize {
        self.progress.lock().unwrap().received.len()
    }
    pub(crate) fn captured_peer_count(&self) -> usize {
        self.progress.lock().unwrap().captures.len()
    }
}
impl AppClient {
    pub(crate) fn test_capture_departure_replay(
        root: &Path,
        group: &crate::GroupId,
        peers: &[[u8; 32]],
    ) -> Arc<DepartureReplayProbe> {
        let peers: BTreeSet<_> = peers.iter().copied().collect();
        assert!(!peers.is_empty() && peers.len() <= 2 && !peers.contains(&[0; 32]));
        let mut entries = registry().lock().unwrap();
        entries.retain(|_, weak| weak.upgrade().is_some());
        assert!(entries.len() < 8 && !entries.contains_key(root));
        let probe = Arc::new(DepartureReplayProbe {
            root: root.to_owned(),
            group: group.clone(),
            peers,
            deadline: Instant::now() + Duration::from_secs(600),
            progress: Mutex::default(),
        });
        entries.insert(root.to_owned(), Arc::downgrade(&probe));
        probe
    }
}
fn at(root: &Path) -> Option<Arc<DepartureReplayProbe>> {
    registry()
        .lock()
        .unwrap()
        .get(root)
        .and_then(Weak::upgrade)
        .filter(|probe| Instant::now() < probe.deadline)
}

/// Caller supplies serialization and fragments already produced by the genuine
/// Intent outbox path, before sealing. No storage query or reconstruction here.
pub(super) fn capture(
    root: &Path,
    policy: &ApprovedAccountSharingPolicy,
    intent: &AccountChatDepartureIntent,
    original_nonce: [u8; 32],
    body: &[u8],
    fragments: &[Vec<u8>],
) {
    let Some(probe) = at(root) else {
        return;
    };
    if intent.group != probe.group || !probe.peers.contains(&policy.peer_device) {
        return;
    }
    assert!(!body.is_empty() && body.len() <= 64 * 1024);
    assert!(!fragments.is_empty() && fragments.len() <= 128);
    assert!(
        fragments
            .iter()
            .all(|part| !part.is_empty() && part.len() <= 4096)
    );
    assert!(fragments.iter().map(Vec::len).sum::<usize>() <= 128 * 1024);
    assert!(intent.initiator == policy.local_device && intent.account == policy.account);
    let digest: [u8; 32] = Sha256::digest(body).into();
    let mut progress = probe.progress.lock().unwrap();
    if let Some(old) = progress.captures.get(&policy.peer_device) {
        if old.action != intent.action_id {
            return;
        }
        assert!(
            old.action == intent.action_id
                && old.body_digest == digest
                && old.fragments == fragments
        );
        return;
    }
    if progress.replay {
        return;
    }
    progress.captures.insert(
        policy.peer_device,
        Captured {
            policy: policy.clone(),
            action: intent.action_id,
            body_digest: digest,
            original_nonce,
            fragments: fragments.to_vec(),
            queued: BTreeSet::new(),
        },
    );
}

/// Only exact retained bytes are returned. Caller must validate current policy,
/// Core channel and whole-body budget before queueing, then call mark_queued.
pub(super) fn prepared_replay(
    root: &Path,
    policy: &ApprovedAccountSharingPolicy,
    nonce: [u8; 32],
) -> Option<Vec<Vec<u8>>> {
    let probe = at(root)?;
    let progress = probe.progress.lock().unwrap();
    if !progress.replay || progress.received.contains(&policy.peer_device) {
        return None;
    }
    let capture = progress.captures.get(&policy.peer_device)?;
    if capture.policy != *policy
        || nonce == capture.original_nonce
        || capture.queued.contains(&nonce)
        || capture.queued.len() >= 8
    {
        return None;
    }
    Some(capture.fragments.clone())
}
pub(super) fn mark_queued(root: &Path, policy: &ApprovedAccountSharingPolicy, nonce: [u8; 32]) {
    let Some(probe) = at(root) else {
        return;
    };
    let mut progress = probe.progress.lock().unwrap();
    let capture = progress
        .captures
        .get_mut(&policy.peer_device)
        .expect("captured actual intent");
    assert!(
        capture.policy == *policy && nonce != capture.original_nonce && capture.queued.len() < 8
    );
    assert!(capture.queued.insert(nonce));
}

/// Called after actual Core authentication and successful atomic negative apply.
/// Match the reversed real peer policy and the fresh queued channel nonce.
pub(super) fn observe_received(
    policy: &ApprovedAccountSharingPolicy,
    nonce: [u8; 32],
    action: [u8; 32],
    body: &[u8],
) {
    let probes: Vec<_> = registry()
        .lock()
        .unwrap()
        .values()
        .filter_map(Weak::upgrade)
        .collect();
    for probe in probes {
        if Instant::now() >= probe.deadline {
            continue;
        }
        let mut progress = probe.progress.lock().unwrap();
        if !progress.replay {
            continue;
        }
        let Some(captured) = progress.captures.get(&policy.local_device) else {
            continue;
        };
        if captured.policy.account == policy.account
            && captured.policy.local_device == policy.peer_device
            && captured.policy.peer_device == policy.local_device
            && captured.policy.protected_group == policy.protected_group
            && captured.policy.approval_id == policy.approval_id
            && captured.action == action
            && captured.queued.contains(&nonce)
            && captured.body_digest == <[u8; 32]>::from(Sha256::digest(body))
        {
            progress.received.insert(policy.local_device);
        }
    }
}
