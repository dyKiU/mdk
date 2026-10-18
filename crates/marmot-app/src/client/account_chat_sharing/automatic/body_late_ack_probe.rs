//! Passive observations and one original-future receipt gate for real relay ACK tests.
use super::*;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, Weak};

#[derive(Clone, Copy, Default)]
pub(crate) struct Observed {
    pub(crate) armed: bool,
    pub(crate) final_fragment: bool,
    pub(crate) captured: bool,
    pub(crate) receipt_accepted: u64,
    pub(crate) receipt_during_publication: bool,
    pub(crate) context_changed: bool,
    pub(crate) context_rejected: u64,
    pub(crate) future_dropped: u64,
    pub(crate) sdk_success: u64,
    pub(crate) successful_harvest: u64,
    pub(crate) cancelled_harvest: u64,
    pub(crate) retired: u64,
    pub(crate) old_body_effects: u64,
}
struct Captured {
    original: Weak<State>,
    nonce: [u8; 32],
    sequence: u64,
    task: Option<tokio::task::Id>,
    receipt: CatalogReceipt,
    payload_digest: [u8; 32],
    body_digest: [u8; 32],
    message: cgka_traits::MessageId,
    account: [u8; 32],
    protected_group: crate::GroupId,
    local_device: [u8; 32],
    peer_device: [u8; 32],
}
pub(crate) struct Probe {
    peer_root: PathBuf,
    excluded: crate::GroupId,
    endpoint: cgka_traits::TransportEndpoint,
    arm: Box<dyn Fn(&cgka_traits::MessageId) + Send + Sync>,
    hold_receipt: bool,
    release: tokio::sync::watch::Sender<bool>,
    receipt_entered: std::sync::atomic::AtomicBool,
    progress: Mutex<(Option<Captured>, Observed)>,
}
fn registry() -> &'static Mutex<BTreeMap<PathBuf, Weak<Probe>>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Probe>>>> = OnceLock::new();
    REGISTRY.get_or_init(Mutex::default)
}
fn at(root: &Path) -> Option<Arc<Probe>> {
    registry()
        .lock()
        .expect("late ACK registry")
        .get(root)?
        .upgrade()
}
impl AppClient {
    pub(crate) fn test_capture_automatic_body_late_ack(
        root: &Path,
        peer_root: &Path,
        excluded: &crate::GroupId,
        endpoint: cgka_traits::TransportEndpoint,
        hold_receipt: bool,
        arm: impl Fn(&cgka_traits::MessageId) + Send + Sync + 'static,
    ) -> Arc<Probe> {
        let (release, _) = tokio::sync::watch::channel(false);
        let probe = Arc::new(Probe {
            peer_root: peer_root.to_owned(),
            excluded: excluded.clone(),
            endpoint,
            arm: Box::new(arm),
            hold_receipt,
            release,
            receipt_entered: std::sync::atomic::AtomicBool::new(false),
            progress: Mutex::new((None, Observed::default())),
        });
        let mut registry = registry().lock().expect("late ACK registry");
        registry.retain(|_, weak| weak.strong_count() != 0);
        assert!(registry.len() < 8, "bounded isolated late ACK fixtures");
        assert!(
            registry
                .insert(root.to_owned(), Arc::downgrade(&probe))
                .is_none()
        );
        probe
    }
}
impl Probe {
    pub(crate) fn observed(&self) -> Observed {
        self.progress.lock().expect("late ACK probe").1
    }
    pub(crate) fn receipt_is_held(&self) -> bool {
        self.receipt_entered
            .load(std::sync::atomic::Ordering::Acquire)
            && self.release.receiver_count() > 0
    }
    pub(crate) fn release_receipt(&self) {
        self.release.send_replace(true);
    }
}
fn same_owner(captured: &Captured, entry: &AutomaticChannel) -> bool {
    Weak::ptr_eq(&captured.original, &Arc::downgrade(&entry.original))
        && captured.nonce == entry.channel.scope().nonce
}
fn same_body(captured: &Captured, entry: &AutomaticChannel) -> bool {
    same_owner(captured, entry)
        && captured.sequence == entry.next_body
        && entry.pending.front().is_some_and(|body| {
            body.kind == AccountSharedBodyKind::Catalog
                && <[u8; 32]>::from(Sha256::digest(&body.bytes)) == captured.body_digest
        })
}
pub(super) fn arm(
    root: &Path,
    entry: &AutomaticChannel,
    kind: AccountSharingControl,
    request: &cgka_traits::TransportPublishRequest,
) {
    if !matches!(kind, AccountSharingControl::Body(_)) {
        return;
    }
    let Some(probe) = at(root) else { return };
    let Some(pending) = entry.pending_catalog.as_ref() else {
        return;
    };
    let Some(body) = entry.pending.front() else {
        return;
    };
    if pending.receipt.group == probe.excluded
        || entry.pending.len() != 1
        || body.kind != AccountSharedBodyKind::Catalog
    {
        return;
    }
    let Ok(fragment) = serde_json::from_slice::<CatalogFragment>(&body.bytes) else {
        return;
    };
    if fragment.count == 0
        || fragment.ordinal.checked_add(1) != Some(fragment.count)
        || fragment.digest != pending.receipt.encoded_digest
    {
        return;
    }
    let mut progress = probe.progress.lock().expect("late ACK probe");
    if progress.0.is_some() {
        return;
    }
    assert!(
        request.target.endpoints().len() == 1
            && crate::relay_plane::same_relay(
                request.target.endpoints()[0].as_str(),
                probe.endpoint.as_str()
            ),
        "actual request cannot bypass ACK proxy"
    );
    progress.0 = Some(Captured {
        original: Arc::downgrade(&entry.original),
        nonce: entry.channel.scope().nonce,
        sequence: entry.next_body,
        task: None,
        receipt: pending.receipt.clone(),
        payload_digest: Sha256::digest(&request.message.payload).into(),
        body_digest: Sha256::digest(&body.bytes).into(),
        message: request.message.id.clone(),
        account: entry.policy.account,
        protected_group: entry.policy.protected_group.clone(),
        local_device: entry.policy.local_device,
        peer_device: entry.policy.peer_device,
    });
    progress.1.armed = true;
    progress.1.final_fragment = true;
    // The filter exists before spawn can poll the immutable prepared request.
    (probe.arm)(&request.message.id);
}
pub(super) fn capture(root: &Path, entry: &AutomaticChannel) {
    let Some(probe) = at(root) else { return };
    let Some(publication) = entry.publication.as_ref() else {
        return;
    };
    let mut progress = probe.progress.lock().expect("late ACK probe");
    if let Some(captured) = progress.0.as_mut()
        && captured.task.is_none()
        && same_body(captured, entry)
        && publication.body_context.is_some()
        && publication.payload_digest == captured.payload_digest
    {
        captured.task = Some(publication.task.id());
        progress.1.captured = true;
    }
}
pub(super) struct Lifetime {
    probe: Weak<Probe>,
}
impl Lifetime {
    pub(super) fn accepted(&self) {
        if let Some(probe) = self.probe.upgrade() {
            probe.progress.lock().expect("late ACK probe").1.sdk_success += 1;
        }
    }
}
impl Drop for Lifetime {
    fn drop(&mut self) {
        if let Some(probe) = self.probe.upgrade() {
            probe
                .progress
                .lock()
                .expect("late ACK probe")
                .1
                .future_dropped += 1;
        }
    }
}
pub(super) fn lifetime(root: &Path, message: &cgka_traits::MessageId) -> Option<Lifetime> {
    let probe = at(root)?;
    let matched = probe
        .progress
        .lock()
        .expect("late ACK probe")
        .0
        .as_ref()
        .is_some_and(|captured| &captured.message == message);
    matched.then(|| Lifetime {
        probe: Arc::downgrade(&probe),
    })
}
pub(super) fn receipt_gate(
    root: &Path,
    entry: &AutomaticChannel,
    kind: AccountSharingControl,
) -> Option<Arc<Probe>> {
    if !matches!(kind, AccountSharingControl::Body(_)) {
        return None;
    }
    let probes: Vec<_> = registry()
        .lock()
        .expect("late ACK registry")
        .values()
        .cloned()
        .collect();
    for probe in probes.into_iter().filter_map(|weak| weak.upgrade()) {
        if !probe.hold_receipt || probe.peer_root != root {
            continue;
        }
        let matched = probe
            .progress
            .lock()
            .expect("late ACK probe")
            .0
            .as_ref()
            .is_some_and(|captured| {
                captured.nonce == entry.channel.scope().nonce
                    && captured.account == entry.policy.account
                    && captured.protected_group == entry.policy.protected_group
                    && captured.local_device == entry.policy.peer_device
                    && captured.peer_device == entry.policy.local_device
                    && entry.pending.front().is_some_and(|body| {
                        body.kind == AccountSharedBodyKind::CatalogReceipt
                            && serde_json::from_slice::<CatalogReceipt>(&body.bytes)
                                .is_ok_and(|receipt| receipt == captured.receipt)
                    })
            });
        if matched {
            return Some(probe);
        }
    }
    None
}
pub(super) async fn wait_receipt(probe: &Probe) {
    let mut release = probe.release.subscribe();
    probe
        .receipt_entered
        .store(true, std::sync::atomic::Ordering::Release);
    while !*release.borrow_and_update() {
        if release.changed().await.is_err() {
            break;
        }
    }
}
pub(super) fn receipt(root: &Path, entry: &AutomaticChannel, receipt: &CatalogReceipt) {
    let Some(probe) = at(root) else { return };
    let mut progress = probe.progress.lock().expect("late ACK probe");
    let Some(captured) = progress
        .0
        .as_ref()
        .filter(|captured| same_owner(captured, entry) && &captured.receipt == receipt)
    else {
        return;
    };
    let during = entry.publication.as_ref().is_some_and(|publication| {
        Some(publication.task.id()) == captured.task
            && !publication.task.is_finished()
            && publication.body_context != entry.body_publication_context()
    });
    progress.1.receipt_accepted += 1;
    progress.1.receipt_during_publication |= during;
    progress.1.context_changed |= during;
}
pub(super) fn rejected(root: &Path, entry: &AutomaticChannel, publication: &AutomaticPublication) {
    let Some(probe) = at(root) else { return };
    let mut progress = probe.progress.lock().expect("late ACK probe");
    if progress.0.as_ref().is_some_and(|captured| {
        same_body(captured, entry) && captured.task == Some(publication.task.id())
    }) {
        progress.1.context_rejected += 1;
    }
}
pub(super) fn harvest(root: &Path, task: tokio::task::Id, success: bool, cancelled: bool) {
    let Some(probe) = at(root) else { return };
    let mut progress = probe.progress.lock().expect("late ACK probe");
    if progress
        .0
        .as_ref()
        .is_some_and(|captured| captured.task == Some(task))
    {
        progress.1.successful_harvest += u64::from(success);
        progress.1.cancelled_harvest += u64::from(cancelled);
    }
}
pub(super) fn effects(root: &Path, entry: &AutomaticChannel) {
    let Some(probe) = at(root) else { return };
    let mut progress = probe.progress.lock().expect("late ACK probe");
    if progress
        .0
        .as_ref()
        .is_some_and(|captured| same_body(captured, entry))
    {
        progress.1.old_body_effects += 1;
    }
}
pub(super) fn retired(entry: &AutomaticChannel) {
    let probes: Vec<_> = registry()
        .lock()
        .expect("late ACK registry")
        .values()
        .cloned()
        .collect();
    for probe in probes.into_iter().filter_map(|weak| weak.upgrade()) {
        let mut progress = probe.progress.lock().expect("late ACK probe");
        if progress
            .0
            .as_ref()
            .is_some_and(|captured| same_owner(captured, entry))
        {
            progress.1.retired += 1;
        }
    }
}
