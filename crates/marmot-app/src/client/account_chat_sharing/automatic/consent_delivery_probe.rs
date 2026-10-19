//! Test-only Consent boundary observations. No payloads, owners, retries or grants.
use cgka_engine::account_chat_sharing::{AccountSharingControl, ReceivedAccountSharingControl};
use cgka_traits::{GroupId, MessageId, source_leaf::SourceLeafProof};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};

pub(crate) struct Peer {
    pub(crate) root: PathBuf,
    pub(crate) device: [u8; 32],
}

/// Private observed identities and hashes; deliberately no Debug implementation.
#[derive(Clone)]
pub(crate) struct Publication {
    pub(crate) account: [u8; 32],
    pub(crate) protected_group: GroupId,
    pub(crate) local_device: [u8; 32],
    pub(crate) peer_device: [u8; 32],
    pub(crate) nonce: [u8; 32],
    pub(crate) content_id: MessageId,
    pub(crate) outer_id: MessageId,
    pub(crate) input_outer_payload_sha256: [u8; 32],
    pub(crate) inner_wire_sha256: [u8; 32],
}
/// Frozen, validated Consent metadata before publisher await; no ACK/report identity.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PreparedConsent {
    pub(crate) account: [u8; 32],
    pub(crate) protected_group: GroupId,
    pub(crate) local_device: [u8; 32],
    pub(crate) peer_device: [u8; 32],
    pub(crate) nonce: [u8; 32],
    pub(crate) content_id: MessageId,
    pub(crate) input_outer_payload_sha256: [u8; 32],
    pub(crate) inner_wire_sha256: [u8; 32],
}
impl From<&Publication> for PreparedConsent {
    fn from(publication: &Publication) -> Self {
        Self {
            account: publication.account,
            protected_group: publication.protected_group.clone(),
            local_device: publication.local_device,
            peer_device: publication.peer_device,
            nonce: publication.nonce,
            content_id: publication.content_id.clone(),
            input_outer_payload_sha256: publication.input_outer_payload_sha256,
            inner_wire_sha256: publication.inner_wire_sha256,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Success,
    NotReady,
    Closed,
    RuntimeUnavailable,
    Refused,
}
impl Outcome {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::NotReady => "not_ready",
            Self::Closed => "closed",
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::Refused => "refused",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Consent,
    PeerProof,
}

/// Fixed passive checkpoints, not validation or a grant.
#[derive(Clone, Copy)]
pub(crate) enum ProofStage {
    Routed = 0,
    Open = 1,
    Accepted = 2,
}

enum Observation {
    Proof([u8; 32], Vec<u8>, [u8; 32], ProofStage),
    Raw(MessageId, [u8; 32]),
    Event(GroupId, MessageId, SourceLeafProof, [u8; 32]),
    Auth(
        GroupId,
        SourceLeafProof,
        [u8; 32],
        Option<[u8; 32]>,
        Outcome,
    ),
    Dispatch([u8; 32], Vec<u8>, [u8; 32], Outcome),
    Automatic([u8; 32], Vec<u8>, [u8; 32], bool),
}
#[derive(Default)]
struct Progress {
    attempts: [usize; 3],
    dropped: [usize; 3],
    receive_attempts: [usize; 3],
    receive_dropped: [usize; 3],
    records: Vec<Attempt>,
    observations: Vec<(usize, Observation)>,
}
pub(crate) struct ConsentDeliveryProbe {
    mode: Mode,
    account: [u8; 32],
    group: GroupId,
    peers: [Peer; 3],
    deadline: Instant,
    progress: Mutex<Progress>,
}
type Registry = BTreeMap<PathBuf, Weak<ConsentDeliveryProbe>>;
fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}
impl Drop for ConsentDeliveryProbe {
    fn drop(&mut self) {
        let mut roots = registry().lock().unwrap_or_else(|e| e.into_inner());
        for peer in &self.peers {
            if roots
                .get(&peer.root)
                .is_some_and(|weak| weak.strong_count() == 0)
            {
                roots.remove(&peer.root);
            }
        }
    }
}
pub(crate) fn arm(
    account: [u8; 32],
    group: GroupId,
    peers: [Peer; 3],
) -> Arc<ConsentDeliveryProbe> {
    arm_mode(account, group, peers, Mode::Consent)
}
pub(crate) fn arm_peer_proofs(
    account: [u8; 32],
    group: GroupId,
    peers: [Peer; 3],
) -> Arc<ConsentDeliveryProbe> {
    arm_mode(account, group, peers, Mode::PeerProof)
}
fn arm_mode(
    account: [u8; 32],
    group: GroupId,
    peers: [Peer; 3],
    mode: Mode,
) -> Arc<ConsentDeliveryProbe> {
    for (index, peer) in peers.iter().enumerate() {
        assert!(
            peers[..index]
                .iter()
                .all(|old| old.root != peer.root && old.device != peer.device)
        );
    }
    let mut roots = registry().lock().unwrap_or_else(|e| e.into_inner());
    roots.retain(|_, probe| probe.strong_count() > 0);
    assert!(roots.len() + peers.len() <= 8);
    assert!(peers.iter().all(|peer| !roots.contains_key(&peer.root)));
    let probe = Arc::new(ConsentDeliveryProbe {
        mode,
        account,
        group,
        peers,
        deadline: Instant::now() + Duration::from_secs(600),
        progress: Mutex::new(Progress::default()),
    });
    for peer in &probe.peers {
        roots.insert(peer.root.clone(), Arc::downgrade(&probe));
    }
    probe
}
fn current(root: &Path) -> Option<Arc<ConsentDeliveryProbe>> {
    let weak = registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(root)
        .cloned();
    weak.and_then(|weak| weak.upgrade())
        .filter(|probe| Instant::now() < probe.deadline)
}
impl ConsentDeliveryProbe {
    fn index(&self, root: &Path) -> Option<usize> {
        self.peers.iter().position(|peer| peer.root == root)
    }
    fn record(&self, root: &Path, observation: Observation) {
        let Some(index) = self.index(root) else {
            return;
        };
        let mut progress = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        progress.receive_attempts[index] = progress.receive_attempts[index].saturating_add(1);
        let mut matched = false;
        for record in &mut progress.records {
            if record.receiver_root == root {
                matched |= record.observe(&self.group, &observation);
            }
        }
        if matched {
            return;
        }
        // Only unknown-before-publication observations need rolling storage.
        if progress
            .observations
            .iter()
            .filter(|(root, _)| *root == index)
            .count()
            >= 64
        {
            let oldest = progress
                .observations
                .iter()
                .position(|(root, _)| *root == index)
                .unwrap();
            progress.observations.remove(oldest);
            progress.receive_dropped[index] = progress.receive_dropped[index].saturating_add(1);
        }
        progress.observations.push((index, observation));
    }
    /// Private records are only for bounded fixture queries; never log them.
    pub(crate) fn snapshot(&self) -> Snapshot {
        let progress = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        let expired = Instant::now() >= self.deadline;
        let mut records: Vec<_> = progress
            .records
            .iter()
            .filter_map(Attempt::published_record)
            .collect();
        for record in &mut records {
            let receiver = self.index(&record.receiver_root).unwrap();
            record.observation_incomplete |= progress.receive_dropped[receiver] > 0 || expired;
        }
        Snapshot {
            records,
            prepared: progress.records.len(),
            ack_unseen: progress
                .records
                .iter()
                .filter(|attempt| attempt.outer_id.is_none())
                .count(),
            attempts: progress.attempts,
            dropped: progress.dropped,
            receive_attempts: progress.receive_attempts,
            receive_dropped: progress.receive_dropped,
            expired: Instant::now() >= self.deadline,
        }
    }
}
#[derive(Clone)]
pub(crate) struct ObservedPublication {
    pub(crate) publication: Publication,
    pub(crate) receiver_root: PathBuf,
    pub(crate) raw_id_seen: bool,
    pub(crate) raw_payload_hash_matches: bool,
    pub(crate) event_seen: bool,
    /// A bounded receive buffer overflowed: unobserved boundaries are unknown.
    pub(crate) observation_incomplete: bool,
    pub(crate) authentication: Option<Outcome>,
    pub(crate) authenticated_nonce_matches: bool,
    pub(crate) dispatch: Option<Outcome>,
    pub(crate) automatic_matched: bool,
    pub(crate) consent_bound: bool,
}
#[derive(Default, Clone)]
struct Evidence {
    proof_queue: Option<ProofQueueFacts>,
    proof_stages: [usize; 3],
    raw_id_seen: bool,
    raw_payload_hash_matches: bool,
    event_seen: bool,
    observation_incomplete: bool,
    authentication: Option<Outcome>,
    authenticated_nonce_matches: bool,
    dispatch: Option<Outcome>,
    automatic_matched: bool,
    consent_bound: bool,
}
struct Attempt {
    prepared: PreparedConsent,
    outer_id: Option<MessageId>,
    receiver_root: PathBuf,
    evidence: Evidence,
}
impl Attempt {
    fn published_record(&self) -> Option<ObservedPublication> {
        Some(ObservedPublication {
            publication: Publication {
                account: self.prepared.account,
                protected_group: self.prepared.protected_group.clone(),
                local_device: self.prepared.local_device,
                peer_device: self.prepared.peer_device,
                nonce: self.prepared.nonce,
                content_id: self.prepared.content_id.clone(),
                outer_id: self.outer_id.clone()?,
                input_outer_payload_sha256: self.prepared.input_outer_payload_sha256,
                inner_wire_sha256: self.prepared.inner_wire_sha256,
            },
            receiver_root: self.receiver_root.clone(),
            raw_id_seen: self.evidence.raw_id_seen,
            raw_payload_hash_matches: self.evidence.raw_payload_hash_matches,
            event_seen: self.evidence.event_seen,
            observation_incomplete: self.evidence.observation_incomplete,
            authentication: self.evidence.authentication,
            authenticated_nonce_matches: self.evidence.authenticated_nonce_matches,
            dispatch: self.evidence.dispatch,
            automatic_matched: self.evidence.automatic_matched,
            consent_bound: self.evidence.consent_bound,
        })
    }
    /// Accumulate only exact boundary matches; unrelated traffic cannot erase them.
    fn observe(&mut self, expected_group: &GroupId, observation: &Observation) -> bool {
        match observation {
            Observation::Proof(nonce, signer, digest, stage)
                if nonce == &self.prepared.nonce
                    && signer.as_slice() == self.prepared.local_device
                    && digest == &self.prepared.inner_wire_sha256 =>
            {
                let count = &mut self.evidence.proof_stages[*stage as usize];
                *count = count.saturating_add(1);
            }
            Observation::Raw(id, digest) if self.outer_id.as_ref() == Some(id) => {
                self.evidence.raw_id_seen = true;
                // Adapter signing may change payload bytes; mismatch is not absence.
                self.evidence.raw_payload_hash_matches |=
                    digest == &self.prepared.input_outer_payload_sha256;
            }
            Observation::Event(group, content, source, digest)
                if group == expected_group
                    && content == &self.prepared.content_id
                    && source.signature_public_key.as_slice() == self.prepared.local_device
                    && digest == &self.prepared.inner_wire_sha256 =>
            {
                self.evidence.event_seen = true;
            }
            Observation::Auth(group, source, digest, nonce, outcome)
                if group == expected_group
                    && source.signature_public_key.as_slice() == self.prepared.local_device
                    && digest == &self.prepared.inner_wire_sha256 =>
            {
                self.evidence.authentication = Some(*outcome);
                self.evidence.authenticated_nonce_matches |= *nonce == Some(self.prepared.nonce);
            }
            Observation::Dispatch(nonce, signer, digest, outcome)
                if nonce == &self.prepared.nonce
                    && signer.as_slice() == self.prepared.local_device
                    && digest == &self.prepared.inner_wire_sha256 =>
            {
                self.evidence.dispatch = Some(*outcome);
            }
            Observation::Automatic(nonce, signer, digest, bound)
                if nonce == &self.prepared.nonce
                    && signer.as_slice() == self.prepared.local_device
                    && digest == &self.prepared.inner_wire_sha256 =>
            {
                if *bound {
                    self.evidence.consent_bound = true;
                } else {
                    self.evidence.automatic_matched = true;
                }
            }
            _ => return false,
        }
        true
    }
}
pub(crate) struct Snapshot {
    prepared: usize,
    ack_unseen: usize,
    pub(crate) records: Vec<ObservedPublication>,
    attempts: [usize; 3],
    dropped: [usize; 3],
    receive_attempts: [usize; 3],
    receive_dropped: [usize; 3],
    pub(crate) expired: bool,
}
#[derive(Debug)]
pub(crate) struct Summary {
    pub(crate) prepared: usize,
    pub(crate) ack_unseen: usize,
    pub(crate) attempts: [usize; 3],
    pub(crate) dropped: [usize; 3],
    pub(crate) receive_attempts: [usize; 3],
    pub(crate) receive_dropped: [usize; 3],
    pub(crate) published: usize,
    pub(crate) expired: bool,
    pub(crate) observation_incomplete: usize,
    pub(crate) raw_id_seen: usize,
    pub(crate) raw_payload_hash_matches: usize,
    pub(crate) event_seen: usize,
    pub(crate) authenticated_nonce_matches: usize,
    pub(crate) authentication: [usize; 5],
    pub(crate) dispatch: [usize; 5],
    pub(crate) automatic_matched: usize,
    pub(crate) consent_bound: usize,
}
impl Snapshot {
    pub(crate) fn summary(&self) -> Summary {
        let mut summary = Summary {
            prepared: self.prepared,
            ack_unseen: self.ack_unseen,
            attempts: self.attempts,
            dropped: self.dropped,
            receive_attempts: self.receive_attempts,
            receive_dropped: self.receive_dropped,
            published: self.records.len(),
            expired: self.expired,
            observation_incomplete: 0,
            raw_id_seen: 0,
            raw_payload_hash_matches: 0,
            event_seen: 0,
            authenticated_nonce_matches: 0,
            authentication: [0; 5],
            dispatch: [0; 5],
            automatic_matched: 0,
            consent_bound: 0,
        };
        for record in &self.records {
            summary.observation_incomplete += usize::from(record.observation_incomplete);
            summary.automatic_matched += usize::from(record.automatic_matched);
            summary.consent_bound += usize::from(record.consent_bound);
            summary.raw_id_seen += usize::from(record.raw_id_seen);
            summary.raw_payload_hash_matches += usize::from(record.raw_payload_hash_matches);
            summary.event_seen += usize::from(record.event_seen);
            summary.authenticated_nonce_matches += usize::from(record.authenticated_nonce_matches);
            if let Some(outcome) = record.authentication {
                summary.authentication[outcome as usize] += 1;
            }
            if let Some(outcome) = record.dispatch {
                summary.dispatch[outcome as usize] += 1;
            }
        }
        summary
    }
}
fn register_attempt(
    probe: &ConsentDeliveryProbe,
    root: &Path,
    prepared: &PreparedConsent,
    progress: &mut Progress,
) -> Option<usize> {
    let index = probe.index(root)?;
    if prepared.account != probe.account
        || prepared.protected_group != probe.group
        || prepared.local_device != probe.peers[index].device
        || !probe
            .peers
            .iter()
            .any(|peer| peer.device == prepared.peer_device && peer.root != root)
    {
        return None;
    }
    if let Some(existing) = progress
        .records
        .iter()
        .position(|attempt| attempt.prepared == *prepared)
    {
        return Some(existing);
    }
    if progress.attempts[index] >= 64 {
        progress.dropped[index] = progress.dropped[index].saturating_add(1);
        return None;
    }
    progress.attempts[index] += 1;
    let receiver = probe
        .peers
        .iter()
        .position(|peer| peer.device == prepared.peer_device)
        .unwrap();
    let mut attempt = Attempt {
        prepared: prepared.clone(),
        outer_id: None,
        receiver_root: probe.peers[receiver].root.clone(),
        evidence: Evidence {
            observation_incomplete: progress.receive_dropped[receiver] > 0,
            ..Evidence::default()
        },
    };
    for (_, observation) in progress
        .observations
        .iter()
        .filter(|(index, _)| *index == receiver)
    {
        attempt.observe(&probe.group, observation);
    }
    progress.records.push(attempt);
    Some(progress.records.len() - 1)
}
/// Call after existing original/route checks, using only actual frozen metadata.
pub(crate) fn prepared(root: &Path, prepared: &PreparedConsent) {
    prepared_mode(root, prepared, Mode::Consent);
}
fn prepared_mode(root: &Path, prepared: &PreparedConsent, mode: Mode) {
    let Some(probe) = current(root).filter(|probe| probe.mode == mode) else {
        return;
    };
    let mut progress = probe.progress.lock().unwrap_or_else(|e| e.into_inner());
    register_attempt(&probe, root, prepared, &mut progress);
}
/// Only actual successful publication/ACK and original validation tail supply report ID.
pub(crate) fn published(root: &Path, publication: &Publication) {
    published_mode(root, publication, Mode::Consent);
}
fn published_mode(root: &Path, publication: &Publication, mode: Mode) {
    let Some(probe) = current(root).filter(|probe| probe.mode == mode) else {
        return;
    };
    let mut progress = probe.progress.lock().unwrap_or_else(|e| e.into_inner());
    let Some(index) = register_attempt(&probe, root, &publication.into(), &mut progress) else {
        return;
    };
    let receiver = probe.index(&progress.records[index].receiver_root).unwrap();
    let Progress {
        records,
        observations,
        ..
    } = &mut *progress;
    let attempt = &mut records[index];
    attempt.outer_id = Some(publication.outer_id.clone());
    // Raw receive may precede the adapter report; match its actual ID only now.
    for (_, observation) in observations.iter().filter(|(index, _)| *index == receiver) {
        attempt.observe(&probe.group, observation);
    }
}

pub(crate) fn raw_received(root: &Path, id: &MessageId, digest: [u8; 32]) {
    if let Some(probe) = current(root) {
        probe.record(root, Observation::Raw(id.clone(), digest));
    }
}
pub(crate) fn event_received(
    root: &Path,
    group: &GroupId,
    content: &MessageId,
    source: &SourceLeafProof,
    digest: [u8; 32],
) {
    if let Some(probe) = current(root).filter(|probe| probe.group == *group) {
        probe.record(
            root,
            Observation::Event(group.clone(), content.clone(), source.clone(), digest),
        );
    }
}
pub(crate) fn authenticated(
    root: &Path,
    group: &GroupId,
    source: &SourceLeafProof,
    digest: [u8; 32],
    received: Option<&ReceivedAccountSharingControl>,
    outcome: Outcome,
) {
    if let Some(probe) = current(root).filter(|probe| probe.group == *group) {
        if received.is_some_and(|received| {
            !probe.matches_control(received.control)
                || received.signer != source.signature_public_key
        }) {
            return;
        }
        probe.record(
            root,
            Observation::Auth(
                group.clone(),
                source.clone(),
                digest,
                received.map(|received| received.nonce),
                outcome,
            ),
        );
    }
}
pub(crate) fn dispatched(
    root: &Path,
    received: &ReceivedAccountSharingControl,
    digest: [u8; 32],
    outcome: Outcome,
) {
    if let Some(probe) = current(root).filter(|probe| probe.matches_control(received.control)) {
        probe.record(
            root,
            Observation::Dispatch(received.nonce, received.signer.clone(), digest, outcome),
        );
    }
}

/// Exact automatic nonce lookup; this is an observation, not a bind or approval.
pub(crate) fn automatic_matched(
    root: &Path,
    received: &ReceivedAccountSharingControl,
    digest: [u8; 32],
) {
    observe_automatic(root, received, digest, false);
}
/// Call only after the real existing Core Consent bind succeeds and sets ready.
pub(crate) fn consent_bound(
    root: &Path,
    received: &ReceivedAccountSharingControl,
    digest: [u8; 32],
) {
    observe_automatic(root, received, digest, true);
}
fn observe_automatic(
    root: &Path,
    received: &ReceivedAccountSharingControl,
    digest: [u8; 32],
    bound: bool,
) {
    if received.control == AccountSharingControl::Consent
        && let Some(probe) = current(root).filter(|probe| probe.mode == Mode::Consent)
    {
        probe.record(
            root,
            Observation::Automatic(received.nonce, received.signer.clone(), digest, bound),
        );
    }
}

impl ConsentDeliveryProbe {
    fn matches_control(&self, control: AccountSharingControl) -> bool {
        match self.mode {
            Mode::Consent => control == AccountSharingControl::Consent,
            Mode::PeerProof => control == AccountSharingControl::Body(0),
        }
    }
    /// Only closed counters are printable. Peer/root/nonce/hash records stay private.
    pub(crate) fn proof_summary(&self) -> [ProofSummary; 2] {
        let progress = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        std::array::from_fn(|source| {
            let mut summary = ProofSummary {
                prepared: 0,
                acknowledged: 0,
                raw_id: 0,
                raw_payload_match: 0,
                event: 0,
                nonce_match: 0,
                authentication: [0; 5],
                dispatch: [0; 5],
                owned: [0; 3],
                queue: None,
                queue_ambiguous: false,
                incomplete: self.mode != Mode::PeerProof
                    || Instant::now() >= self.deadline
                    || progress.dropped[source] > 0
                    || progress.receive_dropped[2] > 0,
            };
            for record in &progress.records {
                if record.prepared.local_device != self.peers[source].device
                    || record.receiver_root != self.peers[2].root
                {
                    continue;
                }
                summary.prepared += 1;
                summary.acknowledged += usize::from(record.outer_id.is_some());
                let evidence = &record.evidence;
                summary.queue = evidence.proof_queue;
                summary.raw_id += usize::from(evidence.raw_id_seen);
                summary.raw_payload_match += usize::from(evidence.raw_payload_hash_matches);
                summary.event += usize::from(evidence.event_seen);
                summary.nonce_match += usize::from(evidence.authenticated_nonce_matches);
                summary.incomplete |= evidence.observation_incomplete;
                if let Some(outcome) = evidence.authentication {
                    summary.authentication[outcome as usize] += 1;
                }
                if let Some(outcome) = evidence.dispatch {
                    summary.dispatch[outcome as usize] += 1;
                }
                for (total, count) in summary.owned.iter_mut().zip(evidence.proof_stages) {
                    *total = total.saturating_add(count);
                }
            }
            summary.queue_ambiguous = summary.prepared > 1;
            if summary.prepared != 1 { summary.queue = None; }
            summary.incomplete |= summary.prepared == 0 || summary.acknowledged != summary.prepared
                || summary.queue_ambiguous
                || summary.queue.is_none_or(|queue| queue.capture_ms.is_none()
                    || queue.same_receiver.is_none()
                    || queue.outer.is_none_or(|outer| outer.invalid));
            summary
        })
    }
}
#[derive(Debug)]
pub(crate) struct ProofSummary {
    prepared: usize,
    acknowledged: usize,
    raw_id: usize,
    raw_payload_match: usize,
    event: usize,
    nonce_match: usize,
    authentication: [usize; 5],
    dispatch: [usize; 5],
    owned: [usize; 3],
    queue: Option<ProofQueueFacts>,
    queue_ambiguous: bool,
    incomplete: bool,
}
pub(crate) fn proof_enabled(root: &Path) -> bool {
    current(root).is_some_and(|probe| probe.mode == Mode::PeerProof)
}
pub(crate) fn proof_prepared(root: &Path, prepared: &PreparedConsent) {
    // Fixed A/B -> D fixture slots only. Source-side captured proof kind is the discriminator.
    let Some(probe) = current(root).filter(|probe| probe.mode == Mode::PeerProof) else {
        return;
    };
    if prepared.peer_device != probe.peers[2].device
        || probe.index(root).is_none_or(|index| index >= 2)
    {
        return;
    }
    prepared_mode(root, prepared, Mode::PeerProof);
}
pub(crate) fn proof_acknowledged(root: &Path, prepared: &PreparedConsent, outer_id: &MessageId) {
    let Some(probe) = current(root).filter(|probe| probe.mode == Mode::PeerProof) else {
        return;
    };
    if prepared.peer_device != probe.peers[2].device
        || probe.index(root).is_none_or(|index| index >= 2)
    {
        return;
    }
    published_mode(
        root,
        &Publication {
            account: prepared.account,
            protected_group: prepared.protected_group.clone(),
            local_device: prepared.local_device,
            peer_device: prepared.peer_device,
            nonce: prepared.nonce,
            content_id: prepared.content_id.clone(),
            outer_id: outer_id.clone(),
            input_outer_payload_sha256: prepared.input_outer_payload_sha256,
            inner_wire_sha256: prepared.inner_wire_sha256,
        },
        Mode::PeerProof,
    );
}
pub(crate) fn proof_stage(
    root: &Path,
    received: &ReceivedAccountSharingControl,
    owned_group: &GroupId,
    owned_nonce: [u8; 32],
    digest: [u8; 32],
    stage: ProofStage,
) {
    if received.control != AccountSharingControl::Body(0) || received.nonce != owned_nonce {
        return;
    }
    if let Some(probe) = current(root).filter(|probe| {
        probe.mode == Mode::PeerProof && probe.group == *owned_group && probe.index(root) == Some(2)
    }) {
        probe.record(
            root,
            Observation::Proof(owned_nonce, received.signer.clone(), digest, stage),
        );
    }
}


/// Closed copied observations only: never an ID, path, pointer or raw Instant.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProofQueueObservation {
    pub(crate) disposition: [u64; 8],
    pub(crate) placement: [u64; 6],
    pub(crate) depths: Option<(usize, usize)>,
    pub(crate) dequeued: u64,
    pub(crate) accepted_ms: Option<u64>,
    pub(crate) dequeued_ms: Option<u64>,
    pub(crate) invalid: bool,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProofQueueFacts {
    pub(crate) capture_ms: Option<u64>,
    pub(crate) outer: Option<ProofQueueObservation>,
    pub(crate) content: Option<ProofQueueObservation>,
    pub(crate) same_receiver: Option<bool>,
    pub(crate) outer_equals_content: bool,
}
/// Borrow the actual worker adapter identity only inside the synchronous query.
/// Source identities are transient lookup keys, never part of stored queue facts.
pub(crate) fn capture_proof_queue<F>(root: &Path, account: &cgka_traits::MemberId, mut query: F)
where F: FnMut(&MessageId, &MessageId, Instant) -> ProofQueueFacts,
{
    let Some(probe) = current(root).filter(|probe| probe.mode == Mode::PeerProof
        && probe.index(root) == Some(2) && account.as_slice() == probe.account) else { return };
    let Some(origin) = probe.deadline.checked_sub(Duration::from_secs(600)) else { return };
    // Never hold the probe mutex while reading the relay-plane observer locks.
    let targets: Vec<_> = {
        let progress = probe.progress.lock().unwrap_or_else(|e| e.into_inner());
        (0..2).filter_map(|source| {
            let mut records = progress.records.iter().enumerate().filter(|(_, record)|
                record.prepared.local_device == probe.peers[source].device
                    && record.receiver_root == probe.peers[2].root);
            let (index, record) = records.next()?;
            if records.next().is_some() { return None; }
            Some((index, record.outer_id.clone()?, record.prepared.content_id.clone()))
        }).collect()
    };
    for (index, outer, content) in targets {
        let facts = query(&outer, &content, origin);
        let mut progress = probe.progress.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(record) = progress.records.get_mut(index)
            && record.outer_id.as_ref() == Some(&outer)
            && record.prepared.content_id == content {
            record.evidence.proof_queue = Some(facts);
        }
    }
}
