//! Exact real recipient retry selection; no synthetic state, ACK, or timer.
use super::*;
use cgka_engine::account_chat_sharing::AccountSharingControl;
use cgka_traits::MessageId;

type Existing = crate::client::private_enrollment_proposal::OriginalSiblingSharingApproval;
struct SourceGate {
    owner: Weak<Existing>,
    nonce: [u8; 32],
    deadline: Instant,
    captured: AtomicBool,
    released: AtomicBool,
    dispatched: AtomicBool,
    acknowledged: AtomicBool,
    invalid: AtomicBool,
    message: Mutex<Option<MessageId>>,
    observed: Notify,
    release: Notify,
}
pub(crate) struct SourceGuard(Arc<SourceGate>);
enum ReleaseKind {
    Source(Weak<SourceGate>),
    Recipient(Weak<RecipientProbe>),
}
pub(crate) struct ReleaseWitness(ReleaseKind);
impl ReleaseWitness {
    pub(crate) fn released(&self) -> bool {
        match &self.0 {
            ReleaseKind::Source(owner) => owner.strong_count() == 0,
            ReleaseKind::Recipient(owner) => owner.strong_count() == 0,
        }
    }
}
impl SourceGuard {
    pub(crate) fn release_witness(&self) -> ReleaseWitness {
        ReleaseWitness(ReleaseKind::Source(Arc::downgrade(&self.0)))
    }
    pub(crate) async fn observed(&self) {
        self.0.observed.notified().await;
    }
    pub(crate) fn captured(&self) -> bool {
        self.0.captured.load(Ordering::Acquire)
    }
    pub(crate) fn dispatched_and_acknowledged_after_release(&self) -> bool {
        self.0.released.load(Ordering::Acquire)
            && self.0.dispatched.load(Ordering::Acquire)
            && self.0.acknowledged.load(Ordering::Acquire)
            && !self.0.invalid.load(Ordering::Acquire)
    }
    pub(crate) fn release(&self) {
        self.0.released.store(true, Ordering::Release);
        self.0.release.notify_one();
    }
}
impl Drop for SourceGuard {
    fn drop(&mut self) {
        self.release();
    }
}
fn source_registry() -> &'static Mutex<Vec<Weak<SourceGate>>> {
    static GATES: OnceLock<Mutex<Vec<Weak<SourceGate>>>> = OnceLock::new();
    GATES.get_or_init(Default::default)
}
pub(crate) fn arm_source(owner: Weak<Existing>, nonce: [u8; 32], deadline: Instant) -> SourceGuard {
    let gate = Arc::new(SourceGate {
        owner,
        nonce,
        deadline,
        captured: AtomicBool::new(false),
        released: AtomicBool::new(false),
        dispatched: AtomicBool::new(false),
        acknowledged: AtomicBool::new(false),
        invalid: AtomicBool::new(false),
        message: Mutex::new(None),
        observed: Notify::new(),
        release: Notify::new(),
    });
    let mut gates = source_registry().lock().expect("priority source gates");
    gates.retain(|old| old.strong_count() != 0);
    assert!(
        gates.len() < 4
            && !gates
                .iter()
                .filter_map(Weak::upgrade)
                .any(|old| old.owner.ptr_eq(&gate.owner))
    );
    gates.push(Arc::downgrade(&gate));
    SourceGuard(gate)
}
// Called only for the genuine sealed proof inside the original cancellation select.
pub(crate) async fn hold_source(
    original: &Arc<SiblingOriginal>,
    nonce: [u8; 32],
    deadline: Instant,
    message: &MessageId,
) {
    let SiblingOriginal::Existing { original, .. } = original.as_ref() else {
        return;
    };
    let gate = source_registry()
        .lock()
        .expect("priority source gates")
        .iter()
        .filter_map(Weak::upgrade)
        .find(|gate| {
            gate.owner.ptr_eq(&Arc::downgrade(original))
                && gate.nonce == nonce
                && gate.deadline == deadline
                && !gate.released.load(Ordering::Acquire)
                && !gate.captured.swap(true, Ordering::AcqRel)
        });
    if let Some(gate) = gate {
        *gate.message.lock().expect("held source proof message") = Some(message.clone());
        gate.observed.notify_one();
        gate.release.notified().await;
    }
}
fn source_event(
    original: &Arc<SiblingOriginal>,
    nonce: [u8; 32],
    deadline: Instant,
    message: &MessageId,
    ack: bool,
) {
    let SiblingOriginal::Existing { original, .. } = original.as_ref() else {
        return;
    };
    let gate = source_registry()
        .lock()
        .expect("priority source gates")
        .iter()
        .filter_map(Weak::upgrade)
        .find(|gate| {
            gate.owner.ptr_eq(&Arc::downgrade(original))
                && gate.nonce == nonce
                && gate.deadline == deadline
                && gate.captured.load(Ordering::Acquire)
        });
    if let Some(gate) = gate {
        if !gate.released.load(Ordering::Acquire)
            || gate
                .message
                .lock()
                .expect("held source proof message")
                .as_ref()
                != Some(message)
            || (ack && !gate.dispatched.load(Ordering::Acquire))
        {
            gate.invalid.store(true, Ordering::Release);
            return;
        }
        if ack {
            gate.acknowledged.store(true, Ordering::Release);
        } else {
            gate.dispatched.store(true, Ordering::Release);
        }
    }
}
pub(crate) fn source_dispatched(
    original: &Arc<SiblingOriginal>,
    nonce: [u8; 32],
    deadline: Instant,
    message: &MessageId,
) {
    source_event(original, nonce, deadline, message, false);
}
pub(crate) fn source_acknowledged(
    original: &Arc<SiblingOriginal>,
    nonce: [u8; 32],
    deadline: Instant,
    message: &MessageId,
) {
    source_event(original, nonce, deadline, message, true);
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireKind {
    Consent,
    Proof,
}
#[derive(Clone, Copy)]
pub(crate) struct Snapshot {
    // ready, handshake ACK, durable policy, own proof ACK, peer proof, publication present.
    pub(crate) flags: [bool; 6],
    pub(crate) retry_at: [Option<Instant>; 2],
    pub(crate) live: [bool; 2],
    pub(crate) deadlines: [Instant; 2],
    pub(crate) harvested: [u64; 2],
    pub(crate) version: u64,
    pub(crate) invalid: bool,
}
#[derive(Clone, Copy)]
pub(crate) struct NextWire {
    pub(crate) kind: WireKind,
    pub(crate) acknowledged: bool,
}
struct Wire {
    id: MessageId,
    kind: WireKind,
    acknowledged: bool,
}
#[derive(Default)]
struct Progress {
    latest: Option<Snapshot>,
    harvested: [u64; 2],
    version: u64,
    invalid: bool,
    next_armed: bool,
    next: Option<Wire>,
    last: Option<Wire>,
    peer_authenticated: bool,
    original: Option<Weak<SiblingOriginal>>,
    state: Option<Weak<State>>,
}
struct RecipientProbe {
    owner: Weak<OriginalEnrollmentSharingChoice>,
    nonce: [u8; 32],
    progress: Mutex<Progress>,
}
pub(crate) struct RecipientGuard(Arc<RecipientProbe>);
impl RecipientGuard {
    pub(crate) fn release_witness(&self) -> ReleaseWitness {
        ReleaseWitness(ReleaseKind::Recipient(Arc::downgrade(&self.0)))
    }
    pub(crate) fn snapshot(&self) -> Option<Snapshot> {
        let (latest, original, state, invalid) = {
            let progress = self
                .0
                .progress
                .lock()
                .expect("priority recipient observation");
            (
                progress.latest,
                progress.original.clone(),
                progress.state.clone(),
                progress.invalid,
            )
        };
        latest.map(|mut latest| {
            latest.invalid |= invalid;
            latest.live = [
                original
                    .and_then(|owner| owner.upgrade())
                    .is_some_and(|original| original.live()),
                state
                    .and_then(|owner| owner.upgrade())
                    .is_some_and(|state| state.live()),
            ];
            latest
        })
    }
    pub(crate) fn held_consent_matches(&self, message: &MessageId) -> bool {
        self.0
            .progress
            .lock()
            .expect("priority recipient observation")
            .last
            .as_ref()
            .is_some_and(|wire| {
                &wire.id == message && wire.kind == WireKind::Consent && !wire.acknowledged
            })
    }
    pub(crate) fn peer_authenticated(&self) -> bool {
        self.0
            .progress
            .lock()
            .expect("priority recipient observation")
            .peer_authenticated
    }
    pub(crate) fn arm_next(&self) {
        let mut progress = self
            .0
            .progress
            .lock()
            .expect("priority recipient observation");
        assert!(!progress.next_armed);
        progress.next_armed = true;
    }
    pub(crate) fn next(&self) -> Option<NextWire> {
        self.0
            .progress
            .lock()
            .expect("priority recipient observation")
            .next
            .as_ref()
            .map(|wire| NextWire {
                kind: wire.kind,
                acknowledged: wire.acknowledged,
            })
    }
}
fn recipient_registry() -> &'static Mutex<Vec<Weak<RecipientProbe>>> {
    static PROBES: OnceLock<Mutex<Vec<Weak<RecipientProbe>>>> = OnceLock::new();
    PROBES.get_or_init(Default::default)
}
pub(crate) fn arm_recipient(
    owner: &Arc<OriginalEnrollmentSharingChoice>,
    nonce: [u8; 32],
) -> RecipientGuard {
    let probe = Arc::new(RecipientProbe {
        owner: Arc::downgrade(owner),
        nonce,
        progress: Mutex::new(Progress::default()),
    });
    let mut probes = recipient_registry()
        .lock()
        .expect("priority recipient probes");
    probes.retain(|old| old.strong_count() != 0);
    assert!(
        probes.len() < 4
            && !probes
                .iter()
                .filter_map(Weak::upgrade)
                .any(|old| old.owner.ptr_eq(&probe.owner))
    );
    probes.push(Arc::downgrade(&probe));
    RecipientGuard(probe)
}
fn current(entry: &SiblingChannel) -> Option<Arc<RecipientProbe>> {
    if !entry.recipient {
        return None;
    }
    let SiblingOriginal::Recipient { choice, .. } = entry.original.as_ref() else {
        return None;
    };
    recipient_registry()
        .lock()
        .expect("priority recipient probes")
        .iter()
        .filter_map(Weak::upgrade)
        .find(|probe| {
            probe.owner.ptr_eq(&Arc::downgrade(choice))
                && probe.nonce == entry.channel.scope().nonce
        })
}
fn bump(value: &mut u64) -> bool {
    if let Some(next) = value.checked_add(1) {
        *value = next;
        false
    } else {
        true
    }
}
fn snapshot(entry: &SiblingChannel, progress: &mut Progress) {
    let overflow = bump(&mut progress.version);
    progress.invalid |= overflow;
    progress.original = Some(Arc::downgrade(&entry.original));
    progress.state = Some(Arc::downgrade(&entry.state));
    let SiblingOriginal::Recipient { choice, .. } = entry.original.as_ref() else {
        return;
    };
    progress.latest = Some(Snapshot {
        live: [false; 2],
        deadlines: [choice.deadline, entry.state.deadline],
        flags: [
            entry.ready,
            entry.handshake_published,
            entry.policy_committed,
            entry.proof_published,
            entry.peer_committed,
            entry.publication.is_some(),
        ],
        retry_at: [entry.handshake_retry_at, entry.proof_retry_at],
        harvested: progress.harvested,
        version: progress.version,
        invalid: progress.invalid,
    });
}
pub(in crate::client::device_linking::sibling_sharing) fn started(entry: &SiblingChannel) {
    if let Some(probe) = current(entry) {
        snapshot(
            entry,
            &mut probe
                .progress
                .lock()
                .expect("priority recipient observation"),
        );
    }
}
pub(in crate::client::device_linking::sibling_sharing) fn harvested(
    entry: &SiblingChannel,
    proof: bool,
) {
    if let Some(probe) = current(entry) {
        let mut progress = probe
            .progress
            .lock()
            .expect("priority recipient observation");
        let overflow = bump(&mut progress.harvested[usize::from(proof)]);
        progress.invalid |= overflow;
        snapshot(entry, &mut progress);
    }
}
pub(crate) struct Capture {
    probe: Arc<RecipientProbe>,
    id: MessageId,
    kind: WireKind,
}
pub(in crate::client::device_linking::sibling_sharing) fn prepared(
    entry: &SiblingChannel,
    kind: AccountSharingControl,
    id: &MessageId,
) -> Option<Capture> {
    let probe = current(entry)?;
    let kind = match kind {
        AccountSharingControl::Consent => WireKind::Consent,
        AccountSharingControl::Body(0) => WireKind::Proof,
        _ => return None,
    };
    {
        let mut progress = probe
            .progress
            .lock()
            .expect("priority recipient observation");
        progress.last = Some(Wire {
            id: id.clone(),
            kind,
            acknowledged: false,
        });
        if progress.next_armed && progress.next.is_none() {
            progress.next = Some(Wire {
                id: id.clone(),
                kind,
                acknowledged: false,
            });
        }
    }
    Some(Capture {
        probe,
        id: id.clone(),
        kind,
    })
}
pub(crate) fn acknowledged(capture: &Capture, id: &MessageId) {
    let mut progress = capture
        .probe
        .progress
        .lock()
        .expect("priority recipient observation");
    if id != &capture.id {
        progress.invalid = true;
        return;
    }
    if let Some(wire) = progress.last.as_mut()
        && wire.id == capture.id
        && wire.kind == capture.kind
    {
        wire.acknowledged = true;
    }
    if let Some(wire) = progress.next.as_mut()
        && wire.id == capture.id
        && wire.kind == capture.kind
    {
        wire.acknowledged = true;
    }
}

// Called only after the existing Core open and all version/policy/digest/device checks.
pub(in crate::client::device_linking::sibling_sharing) fn peer_authenticated(entry: &SiblingChannel) {
    if entry.peer_committed
        && let Some(probe) = current(entry)
    {
        probe
            .progress
            .lock()
            .expect("priority recipient observation")
            .peer_authenticated = true;
    }
}
