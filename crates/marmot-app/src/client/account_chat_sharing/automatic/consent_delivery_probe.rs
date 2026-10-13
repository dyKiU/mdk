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

enum Observation {
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
}
#[derive(Default)]
struct Progress {
    attempts: [usize; 3],
    dropped: [usize; 3],
    receive_attempts: [usize; 3],
    receive_dropped: [usize; 3],
    publications: Vec<Publication>,
    observations: Vec<(usize, Observation)>,
}
pub(crate) struct ConsentDeliveryProbe {
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
        if progress.receive_attempts[index] >= 64 {
            progress.receive_dropped[index] += 1;
            return;
        }
        progress.receive_attempts[index] += 1;
        progress.observations.push((index, observation));
    }
    /// Private records are only for bounded fixture queries; never log them.
    pub(crate) fn snapshot(&self) -> Snapshot {
        let progress = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        let mut records = Vec::new();
        for publication in &progress.publications {
            let receiver = self
                .peers
                .iter()
                .position(|peer| peer.device == publication.peer_device)
                .unwrap();
            let mut record = ObservedPublication {
                publication: publication.clone(),
                receiver_root: self.peers[receiver].root.clone(),
                raw_id_seen: false,
                raw_payload_hash_matches: false,
                event_seen: false,
                observation_incomplete: progress.receive_dropped[receiver] > 0
                    || Instant::now() >= self.deadline,
                authentication: None,
                authenticated_nonce_matches: false,
                dispatch: None,
            };
            for (_, observation) in progress
                .observations
                .iter()
                .filter(|(index, _)| *index == receiver)
            {
                match observation {
                    Observation::Raw(id, digest) if id == &publication.outer_id => {
                        record.raw_id_seen = true;
                        // Adapter signing may change payload bytes; mismatch is not absence.
                        record.raw_payload_hash_matches |=
                            digest == &publication.input_outer_payload_sha256;
                    }
                    Observation::Event(group, content, source, digest)
                        if group == &self.group
                            && content == &publication.content_id
                            && source.signature_public_key.as_slice()
                                == publication.local_device
                            && digest == &publication.inner_wire_sha256 =>
                    {
                        record.event_seen = true;
                    }
                    Observation::Auth(group, source, digest, nonce, outcome)
                        if group == &self.group
                            && source.signature_public_key.as_slice()
                                == publication.local_device
                            && digest == &publication.inner_wire_sha256 =>
                    {
                        record.authentication = Some(*outcome);
                        record.authenticated_nonce_matches |= *nonce == Some(publication.nonce);
                    }
                    Observation::Dispatch(nonce, signer, digest, outcome)
                        if nonce == &publication.nonce
                            && signer.as_slice() == publication.local_device
                            && digest == &publication.inner_wire_sha256 =>
                    {
                        record.dispatch = Some(*outcome);
                    }
                    _ => {}
                }
            }
            records.push(record);
        }
        Snapshot {
            records,
            attempts: progress.attempts,
            dropped: progress.dropped,
            receive_attempts: progress.receive_attempts,
            receive_dropped: progress.receive_dropped,
        }
    }
}
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
}
pub(crate) struct Snapshot {
    pub(crate) records: Vec<ObservedPublication>,
    attempts: [usize; 3],
    dropped: [usize; 3],
    receive_attempts: [usize; 3],
    receive_dropped: [usize; 3],
}
#[derive(Debug)]
pub(crate) struct Summary {
    pub(crate) attempts: [usize; 3],
    pub(crate) dropped: [usize; 3],
    pub(crate) receive_attempts: [usize; 3],
    pub(crate) receive_dropped: [usize; 3],
    pub(crate) published: usize,
    pub(crate) raw_id_seen: usize,
    pub(crate) raw_payload_hash_matches: usize,
    pub(crate) event_seen: usize,
    pub(crate) authenticated_nonce_matches: usize,
    pub(crate) authentication: [usize; 5],
    pub(crate) dispatch: [usize; 5],
}
impl Snapshot {
    pub(crate) fn summary(&self) -> Summary {
        let mut summary = Summary {
            attempts: self.attempts,
            dropped: self.dropped,
            receive_attempts: self.receive_attempts,
            receive_dropped: self.receive_dropped,
            published: self.records.len(),
            raw_id_seen: 0,
            raw_payload_hash_matches: 0,
            event_seen: 0,
            authenticated_nonce_matches: 0,
            authentication: [0; 5],
            dispatch: [0; 5],
        };
        for record in &self.records {
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
pub(crate) fn published(root: &Path, publication: &Publication) {
    let Some(probe) = current(root) else { return };
    let Some(index) = probe.index(root) else {
        return;
    };
    if publication.account != probe.account
        || publication.protected_group != probe.group
        || publication.local_device != probe.peers[index].device
        || !probe
            .peers
            .iter()
            .any(|peer| peer.device == publication.peer_device && peer.root != root)
    {
        return;
    }
    let mut progress = probe.progress.lock().unwrap_or_else(|e| e.into_inner());
    if progress.attempts[index] >= 64 {
        progress.dropped[index] += 1;
        return;
    }
    progress.attempts[index] += 1;
    if !progress
        .publications
        .iter()
        .any(|old| old.outer_id == publication.outer_id && old.nonce == publication.nonce)
    {
        progress.publications.push(publication.clone());
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
            received.control != AccountSharingControl::Consent
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
    if received.control == AccountSharingControl::Consent
        && let Some(probe) = current(root)
    {
        probe.record(
            root,
            Observation::Dispatch(received.nonce, received.signer.clone(), digest, outcome),
        );
    }
}
