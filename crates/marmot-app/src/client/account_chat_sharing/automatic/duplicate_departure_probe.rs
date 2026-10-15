//! Bounded test observation of one genuine C→A negative intent. Publication
//! pauses are nonblocking and never create a channel, consent or storage grant.
use super::*;
use std::{
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};
use storage_sqlite::account_chat_departure::AccountChatDepartureIntent;

#[derive(Clone, Copy)]
pub(crate) struct DuplicateDepartureBinding {
    pub(crate) account: [u8; 32],
    pub(crate) sender_device: [u8; 32],
    pub(crate) receiver_device: [u8; 32],
}
type Registry = BTreeMap<PathBuf, Weak<DuplicateDepartureProbe>>;
fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}
struct Captured {
    policy: ApprovedAccountSharingPolicy,
    intent: AccountChatDepartureIntent,
    original_nonce: [u8; 32],
    body_digest: [u8; 32],
    fragments: Vec<Vec<u8>>,
}
impl Drop for Captured {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.fragments.zeroize();
    }
}
struct Context {
    nonce: [u8; 32],
    queued: bool,
    released: bool,
}
#[derive(Default)]
struct Progress {
    captured: Option<Captured>,
    context: Option<Context>,
    first_held: Option<Instant>,
    held_contexts: u64,
    queued_duplicates: u64,
    applied_duplicates: u64,
}
pub(crate) struct DuplicateDepartureProbe {
    sender_root: PathBuf,
    receiver_root: PathBuf,
    group: crate::GroupId,
    binding: DuplicateDepartureBinding,
    deadline: Instant,
    progress: Mutex<Progress>,
}
impl Drop for DuplicateDepartureProbe {
    fn drop(&mut self) {
        let mut entries = registry().lock().unwrap_or_else(|error| error.into_inner());
        if entries
            .get(&self.sender_root)
            .is_some_and(|weak| weak.strong_count() == 0)
        {
            entries.remove(&self.sender_root);
        }
    }
}
impl DuplicateDepartureProbe {
    pub(crate) fn first_held(&self) -> Option<Instant> {
        self.progress
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .first_held
    }
    pub(crate) fn captured(&self) -> bool {
        self.progress
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .captured
            .is_some()
    }
    pub(crate) fn counters(&self) -> (u64, u64, u64) {
        let progress = self
            .progress
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        (
            progress.held_contexts,
            progress.queued_duplicates,
            progress.applied_duplicates,
        )
    }
    fn sender(&self, policy: &ApprovedAccountSharingPolicy) -> bool {
        policy.account == self.binding.account
            && policy.local_device == self.binding.sender_device
            && policy.peer_device == self.binding.receiver_device
    }
    fn receiver(&self, policy: &ApprovedAccountSharingPolicy, captured: &Captured) -> bool {
        policy.account == self.binding.account
            && policy.local_device == self.binding.receiver_device
            && policy.peer_device == self.binding.sender_device
            && policy.protected_group == captured.policy.protected_group
            && policy.approval_id == captured.policy.approval_id
    }
}
impl AppClient {
    pub(crate) fn test_capture_duplicate_departure(
        sender_root: &Path,
        receiver_root: &Path,
        group: &crate::GroupId,
        binding: DuplicateDepartureBinding,
    ) -> Arc<DuplicateDepartureProbe> {
        assert!(
            sender_root != receiver_root
                && sender_root.is_absolute()
                && receiver_root.is_absolute()
        );
        assert!(
            binding.sender_device != binding.receiver_device
                && binding.sender_device != [0; 32]
                && binding.receiver_device != [0; 32]
                && binding.account != [0; 32]
        );
        let mut entries = registry().lock().unwrap_or_else(|error| error.into_inner());
        entries.retain(|_, weak| weak.strong_count() > 0);
        assert!(entries.len() < 8 && !entries.contains_key(sender_root));
        let probe = Arc::new(DuplicateDepartureProbe {
            sender_root: sender_root.to_owned(),
            receiver_root: receiver_root.to_owned(),
            group: group.clone(),
            binding,
            deadline: Instant::now() + Duration::from_secs(120),
            progress: Mutex::default(),
        });
        entries.insert(sender_root.to_owned(), Arc::downgrade(&probe));
        probe
    }
}
fn sender_at(root: &Path) -> Option<Arc<DuplicateDepartureProbe>> {
    let weak = registry()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(root)
        .cloned();
    weak.and_then(|weak| weak.upgrade())
        .filter(|probe| Instant::now() < probe.deadline)
}
fn receiver_at(root: &Path) -> Option<Arc<DuplicateDepartureProbe>> {
    let weak: Vec<_> = registry()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .values()
        .cloned()
        .collect();
    weak.into_iter()
        .filter_map(|weak| weak.upgrade())
        .find(|probe| probe.receiver_root == root && Instant::now() < probe.deadline)
}

/// Exact already-prepared bytes only. The sender's original ordinary actor
/// supplied both serialization and fragments; nothing is rebuilt or queried.
pub(super) fn capture(
    root: &Path,
    policy: &ApprovedAccountSharingPolicy,
    intent: &AccountChatDepartureIntent,
    original_nonce: [u8; 32],
    body: &[u8],
    fragments: &[Vec<u8>],
) {
    let Some(probe) = sender_at(root) else {
        return;
    };
    if !probe.sender(policy) || intent.group != probe.group {
        return;
    }
    assert!(
        intent.account == policy.account
            && intent.initiator == policy.local_device
            && intent.protected_group == policy.protected_group
    );
    assert!(!body.is_empty() && body.len() <= 64 * 1024);
    assert!(!fragments.is_empty() && fragments.len() <= 128);
    assert!(
        fragments
            .iter()
            .all(|bytes| !bytes.is_empty() && bytes.len() <= 4096)
            && fragments.iter().map(Vec::len).sum::<usize>() <= 128 * 1024
    );
    let digest: [u8; 32] = Sha256::digest(body).into();
    let mut progress = probe
        .progress
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(old) = &progress.captured {
        if old.intent.action_id != intent.action_id {
            return;
        }
        assert!(old.intent == *intent && old.body_digest == digest && old.fragments == fragments);
        return;
    }
    progress.captured = Some(Captured {
        policy: policy.clone(),
        intent: intent.clone(),
        original_nonce,
        body_digest: digest,
        fragments: fragments.to_vec(),
    });
}

/// Caller has validated the CURRENT Core channel and actual pending completed
/// StatusReceipt. Returning true only postpones publication until another tick.
pub(super) fn should_hold_reply(
    root: &Path,
    policy: &ApprovedAccountSharingPolicy,
    nonce: [u8; 32],
    action: [u8; 32],
    status_complete: bool,
) -> bool {
    if !status_complete {
        return false;
    }
    let Some(probe) = receiver_at(root) else {
        return false;
    };
    let mut progress = probe
        .progress
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(captured) = &progress.captured else {
        return false;
    };
    if !probe.receiver(policy, captured) || captured.intent.action_id != action {
        return false;
    }
    if progress
        .context
        .as_ref()
        .is_none_or(|context| context.nonce != nonce)
    {
        progress.context = Some(Context {
            nonce,
            queued: false,
            released: false,
        });
        progress.held_contexts = progress.held_contexts.saturating_add(1);
        progress.first_held.get_or_insert_with(Instant::now);
    }
    !progress.context.as_ref().unwrap().released
}

/// The sender requeues only on the same actual current context being held.
/// Parent validates Core/policy/body budget before queue and mark_queued.
pub(super) fn prepared_duplicate(
    root: &Path,
    policy: &ApprovedAccountSharingPolicy,
    nonce: [u8; 32],
) -> Option<Vec<Vec<u8>>> {
    let probe = sender_at(root)?;
    let progress = probe
        .progress
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let captured = progress.captured.as_ref()?;
    let context = progress.context.as_ref()?;
    if !probe.sender(policy)
        || captured.policy != *policy
        || context.nonce != nonce
        || context.queued
        || context.released
    {
        return None;
    }
    // Preserve observation of the first transport context without prescribing
    // either reuse or replacement as the functional completion criterion.
    let _actual_original_nonce = captured.original_nonce;
    Some(captured.fragments.clone())
}
pub(super) fn mark_queued(root: &Path, policy: &ApprovedAccountSharingPolicy, nonce: [u8; 32]) {
    let Some(probe) = sender_at(root) else {
        return;
    };
    let mut progress = probe
        .progress
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    assert!(probe.sender(policy));
    let context = progress
        .context
        .as_mut()
        .expect("actual pending completion receipt");
    assert!(context.nonce == nonce && !context.queued && !context.released);
    context.queued = true;
    progress.queued_duplicates = progress.queued_duplicates.saturating_add(1);
}

/// AFTER actual authenticated SQL apply returned false. Identity equality is
/// negative replay evidence only; it never substitutes for a native original.
pub(super) fn observe_duplicate(
    root: &Path,
    policy: &ApprovedAccountSharingPolicy,
    nonce: [u8; 32],
    intent: &AccountChatDepartureIntent,
) {
    let Some(probe) = receiver_at(root) else {
        return;
    };
    let mut progress = probe
        .progress
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(captured) = &progress.captured else {
        return;
    };
    if !probe.receiver(policy, captured) || captured.intent != *intent {
        return;
    }
    let Some(context) = progress.context.as_mut() else {
        return;
    };
    if context.nonce != nonce || !context.queued || context.released {
        return;
    }
    context.released = true;
    progress.applied_duplicates = progress.applied_duplicates.saturating_add(1);
}
