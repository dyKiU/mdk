//! Passive, opt-in exact sibling Request delivery; never an owner, hold or grant.
use super::consent_delivery_probe::{Outcome, PreparedConsent, ProofQueueFacts};
use cgka_engine::account_chat_sharing::{
    AccountSharingControl, AccountSharingScope, ReceivedAccountSharingControl,
};
use cgka_traits::{GroupId, MemberId, MessageId, source_leaf::SourceLeafProof};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};

const PAIRS: [(usize, usize); 6] = [(0, 2), (0, 3), (1, 3), (0, 4), (2, 4), (3, 4)];
const MAX_RECORDS: usize = 64;
const MAX_ROLLING_PER_ROOT: usize = 64;
pub(crate) struct Peer {
    pub(crate) root: PathBuf,
    pub(crate) device: [u8; 32],
}
// These identity-bearing structs deliberately have no Debug implementation.
pub(crate) struct Capture {
    root: PathBuf,
    prepared: PreparedConsent,
    approval: [u8; 32],
}
pub(crate) struct ConsentCapture {
    root: PathBuf,
    nonce: [u8; 32],
    approval: [u8; 32],
    source: [u8; 32],
    recipient: [u8; 32],
    group: GroupId,
}
struct Record {
    pair: usize,
    prepared: PreparedConsent,
    approval: [u8; 32],
    prepared_ms: Option<u64>,
    ack_ms: Option<u64>,
    ack_conflict: bool,
    outer: Option<MessageId>,
    evidence: Evidence,
}
#[derive(Default)]
struct Evidence {
    consent: [usize; 3],
    consent_ms: [Option<u64>; 3],
    raw: bool,
    event: bool,
    nonce: bool,
    auth: Option<Outcome>,
    dispatch: Option<Outcome>,
    admitted: usize,
    flags: Option<[bool; 4]>,
    queue: Option<ProofQueueFacts>,
}
enum Observation {
    Raw(MessageId),
    Event(GroupId, MessageId, Vec<u8>, [u8; 32]),
    Auth(GroupId, Vec<u8>, [u8; 32], Option<[u8; 32]>, Outcome),
    Dispatch([u8; 32], Vec<u8>, [u8; 32], Outcome),
    Admitted(GroupId, [u8; 32], Vec<u8>, [u8; 32], [bool; 4]),
}
#[derive(Default)]
struct Progress {
    records: Vec<Record>,
    rolling: Vec<(usize, Observation)>,
    dropped: [usize; 6],
    receive_dropped: [usize; 5],
    // Shared Request origin: wait start, wait end (also unwind), first primary SQL commit.
    recipient_step_ms: [[Option<u64>; 3]; 5],
}
pub(crate) struct Probe {
    account: [u8; 32],
    group: GroupId,
    peers: [Peer; 5],
    origin: Instant,
    deadline: Instant,
    progress: Mutex<Progress>,
}
fn registry() -> &'static Mutex<BTreeMap<PathBuf, Weak<Probe>>> {
    static ROOTS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Probe>>>> = OnceLock::new();
    ROOTS.get_or_init(Default::default)
}
fn current(root: &Path) -> Option<Arc<Probe>> {
    let weak = {
        registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(root)
            .cloned()
    };
    weak.and_then(|weak| weak.upgrade())
        .filter(|probe| Instant::now() < probe.deadline)
}
/// Borrow only the existing passive clock after exact root/account/group lookup.
/// No owner, authority, path or Instant is exported from diagnostics.
pub(super) fn observation_origin(root: &Path, account: &MemberId, group: &GroupId) -> Option<Instant> {
    let probe = current(root).filter(|probe| probe.account.as_slice() == account.as_slice() && probe.group == *group)?;
    Some(probe.origin)
}
impl Drop for Probe {
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
pub(crate) fn arm(account: [u8; 32], group: GroupId, peers: [Peer; 5]) -> Arc<Probe> {
    for (index, peer) in peers.iter().enumerate() {
        assert!(
            peers[..index]
                .iter()
                .all(|old| old.root != peer.root && old.device != peer.device)
        );
    }
    let mut roots = registry().lock().unwrap_or_else(|e| e.into_inner());
    roots.retain(|_, weak| weak.strong_count() > 0);
    assert!(
        roots.len() + peers.len() <= 16 && peers.iter().all(|peer| !roots.contains_key(&peer.root))
    );
    let origin = Instant::now();
    let probe = Arc::new(Probe {
        account,
        group,
        peers,
        origin,
        deadline: origin + Duration::from_secs(600),
        progress: Mutex::default(),
    });
    for peer in &probe.peers {
        roots.insert(peer.root.clone(), Arc::downgrade(&probe));
    }
    probe
}
impl Record {
    fn observe(&mut self, group: &GroupId, observation: &Observation) -> bool {
        let p = &self.prepared;
        match observation {
            Observation::Raw(id) if self.outer.as_ref() == Some(id) => self.evidence.raw = true,
            Observation::Event(g, id, signer, digest)
                if g == group
                    && id == &p.content_id
                    && signer.as_slice() == p.local_device
                    && digest == &p.inner_wire_sha256 =>
            {
                self.evidence.event = true
            }
            Observation::Auth(g, signer, digest, nonce, outcome)
                if g == group
                    && signer.as_slice() == p.local_device
                    && digest == &p.inner_wire_sha256 =>
            {
                self.evidence.auth = Some(*outcome);
                self.evidence.nonce |= *nonce == Some(p.nonce);
            }
            Observation::Dispatch(nonce, signer, digest, outcome)
                if nonce == &p.nonce
                    && signer.as_slice() == p.local_device
                    && digest == &p.inner_wire_sha256 =>
            {
                self.evidence.dispatch = Some(*outcome)
            }
            Observation::Admitted(g, nonce, signer, digest, flags)
                if g == group
                    && nonce == &p.nonce
                    && signer.as_slice() == p.local_device
                    && digest == &p.inner_wire_sha256 =>
            {
                self.evidence.admitted = self.evidence.admitted.saturating_add(1);
                self.evidence.flags = Some(*flags);
            }
            _ => return false,
        }
        true
    }
}
/// Borrows only passive diagnostic storage; never an action/lease/session owner.
pub(crate) struct RecipientWait<'a> {
    probe: &'a Probe,
    recipient: usize,
}
impl Drop for RecipientWait<'_> {
    fn drop(&mut self) {
        let mut progress = self
            .probe
            .progress
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let end = &mut progress.recipient_step_ms[self.recipient][1];
        if end.is_none() {
            *end = self.probe.elapsed();
        }
    }
}
impl Probe {
    /// Scope immediately around the unchanged helper await, including panic unwind.
    pub(crate) fn recipient_wait(&self, recipient: usize) -> Option<RecipientWait<'_>> {
        if !(2..=4).contains(&recipient) || Instant::now() >= self.deadline {
            return None;
        }
        let mut progress = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        let start = &mut progress.recipient_step_ms[recipient][0];
        if start.is_some() {
            return None;
        }
        *start = self.elapsed();
        Some(RecipientWait {
            probe: self,
            recipient,
        })
    }
    fn elapsed(&self) -> Option<u64> {
        Instant::now()
            .checked_duration_since(self.origin)
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
    }
    fn index(&self, root: &Path) -> Option<usize> {
        self.peers.iter().position(|peer| peer.root == root)
    }
    fn record(&self, root: &Path, observation: Observation) {
        let Some(receiver) = self.index(root) else {
            return;
        };
        let mut progress = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        let mut matched = false;
        for record in &mut progress.records {
            if PAIRS[record.pair].1 == receiver {
                matched |= record.observe(&self.group, &observation);
            }
        }
        if matched {
            return;
        }
        if progress
            .rolling
            .iter()
            .filter(|(index, _)| *index == receiver)
            .count()
            >= MAX_ROLLING_PER_ROOT
        {
            if let Some(index) = progress
                .rolling
                .iter()
                .position(|(index, _)| *index == receiver)
            {
                progress.rolling.remove(index);
                progress.receive_dropped[receiver] =
                    progress.receive_dropped[receiver].saturating_add(1);
            }
        }
        progress.rolling.push((receiver, observation));
    }
    fn register(
        &self,
        root: &Path,
        prepared: &PreparedConsent,
        approval: [u8; 32],
        progress: &mut Progress,
    ) -> Option<usize> {
        let source = self.index(root)?;
        let recipient = self
            .peers
            .iter()
            .position(|peer| peer.device == prepared.peer_device)?;
        let pair = PAIRS
            .iter()
            .position(|value| *value == (source, recipient))?;
        if prepared.account != self.account
            || prepared.protected_group != self.group
            || prepared.local_device != self.peers[source].device
        {
            return None;
        }
        if let Some(index) = progress.records.iter().position(|record| {
            record.pair == pair && record.prepared == *prepared && record.approval == approval
        }) {
            return Some(index);
        }
        if progress.records.len() >= MAX_RECORDS {
            progress.dropped[pair] = progress.dropped[pair].saturating_add(1);
            return None;
        }
        let mut record = Record {
            pair,
            prepared: prepared.clone(),
            approval,
            prepared_ms: self.elapsed(),
            ack_ms: None,
            ack_conflict: false,
            outer: None,
            evidence: Evidence::default(),
        };
        for (_, observation) in progress
            .rolling
            .iter()
            .filter(|(index, _)| *index == recipient)
        {
            record.observe(&self.group, observation);
        }
        progress.records.push(record);
        Some(progress.records.len() - 1)
    }
    pub(crate) fn summaries(&self) -> [Summary; 6] {
        let progress = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        std::array::from_fn(|pair| {
            let (source_slot, recipient_slot) = PAIRS[pair];
            let mut row = Summary {
                source_slot,
                recipient_slot,
                prepared: 0,
                acknowledged: 0,
                raw: 0,
                event: 0,
                nonce: 0,
                authentication: [0; 5],
                dispatch: [0; 5],
                admitted: 0,
                admission_flags: None,
                prepared_ms: None,
                sdk_ack_ms: None,
                recipient_wait_start_ms: progress.recipient_step_ms[recipient_slot][0],
                recipient_wait_end_ms: progress.recipient_step_ms[recipient_slot][1],
                recipient_primary_commit_ms: progress.recipient_step_ms[recipient_slot][2],
                consent: [0; 3],
                consent_ms: [None; 3],
                queue: None,
                ambiguous: false,
                incomplete: Instant::now() >= self.deadline
                    || progress.dropped[pair] > 0
                    || progress.receive_dropped[recipient_slot] > 0,
            };
            for record in progress.records.iter().filter(|record| record.pair == pair) {
                let e = &record.evidence;
                row.prepared += 1;
                row.acknowledged += usize::from(record.outer.is_some());
                row.raw += usize::from(e.raw);
                row.event += usize::from(e.event);
                row.nonce += usize::from(e.nonce);
                if let Some(outcome) = e.auth {
                    row.authentication[outcome as usize] += 1;
                }
                if let Some(outcome) = e.dispatch {
                    row.dispatch[outcome as usize] += 1;
                }
                row.admitted = row.admitted.saturating_add(e.admitted);
                row.admission_flags = e.flags;
                row.queue = e.queue;
                row.prepared_ms = record.prepared_ms;
                row.sdk_ack_ms = record.ack_ms;
                for (sum, count) in row.consent.iter_mut().zip(e.consent) {
                    *sum = sum.saturating_add(count);
                }
                row.consent_ms = e.consent_ms;
                row.incomplete |=
                    record.ack_conflict || record.prepared_ms.is_none() || record.ack_ms.is_none();
            }
            row.ambiguous = row.prepared > 1;
            if row.prepared != 1 {
                row.queue = None;
                row.admission_flags = None;
                row.prepared_ms = None;
                row.sdk_ack_ms = None;
                row.consent_ms = [None; 3];
            }
            row.incomplete |= row.prepared != 1
                || row.acknowledged != row.prepared
                || row.queue.is_none_or(|facts| {
                    facts.capture_ms.is_none()
                        || facts.same_receiver.is_none()
                        || facts.outer.is_none_or(|outer| outer.invalid)
                });
            row
        })
    }
}
#[derive(Debug)]
pub(crate) struct Summary {
    source_slot: usize,
    recipient_slot: usize,
    prepared: usize,
    acknowledged: usize,
    raw: usize,
    event: usize,
    nonce: usize,
    authentication: [usize; 5],
    dispatch: [usize; 5],
    admitted: usize,
    admission_flags: Option<[bool; 4]>,
    prepared_ms: Option<u64>,
    sdk_ack_ms: Option<u64>,
    recipient_wait_start_ms: Option<u64>,
    recipient_wait_end_ms: Option<u64>,
    recipient_primary_commit_ms: Option<u64>,
    consent: [usize; 3],
    consent_ms: [Option<u64>; 3],
    queue: Option<ProofQueueFacts>,
    ambiguous: bool,
    incomplete: bool,
}
/// Observation only, called after the actual guarded primary policy transaction succeeded.
pub(crate) fn primary_committed(
    root: &Path,
    account: &[u8; 32],
    group: &GroupId,
    local_device: &[u8; 32],
    context_recipient: &[u8; 32],
) {
    if local_device != context_recipient {
        return;
    }
    let Some(probe) =
        current(root).filter(|probe| probe.account == *account && probe.group == *group)
    else {
        return;
    };
    let Some(recipient) = probe.index(root).filter(|index| (2..=4).contains(index)) else {
        return;
    };
    if probe.peers[recipient].device != *local_device {
        return;
    }
    let mut progress = probe.progress.lock().unwrap_or_else(|e| e.into_inner());
    let first = &mut progress.recipient_step_ms[recipient][2];
    if first.is_none() {
        *first = probe.elapsed();
    }
}
pub(crate) fn enabled(root: &Path) -> bool {
    current(root).is_some()
}
pub(crate) fn prepared(
    root: &Path,
    account: &MemberId,
    scope: &AccountSharingScope,
    content: Option<MessageId>,
    wire: Option<[u8; 32]>,
    payload: &[u8],
) -> Option<Capture> {
    let probe = current(root)?;
    let prepared = PreparedConsent {
        account: account.as_slice().try_into().ok()?,
        protected_group: scope.protected.group_id.clone(),
        local_device: scope.source.as_slice().try_into().ok()?,
        peer_device: scope.recipient.as_slice().try_into().ok()?,
        nonce: scope.nonce,
        content_id: content?,
        input_outer_payload_sha256: Sha256::digest(payload).into(),
        inner_wire_sha256: wire?,
    };
    let mut progress = probe.progress.lock().unwrap_or_else(|e| e.into_inner());
    probe.register(root, &prepared, scope.approval_id, &mut progress)?;
    Some(Capture {
        root: root.to_path_buf(),
        prepared,
        approval: scope.approval_id,
    })
}
pub(crate) fn acknowledged(capture: &Capture, outer: &MessageId) {
    let Some(probe) = current(&capture.root) else {
        return;
    };
    let mut progress = probe.progress.lock().unwrap_or_else(|e| e.into_inner());
    let Some(index) = probe.register(
        &capture.root,
        &capture.prepared,
        capture.approval,
        &mut progress,
    ) else {
        return;
    };
    if progress.records[index]
        .outer
        .as_ref()
        .is_some_and(|old| old != outer)
    {
        progress.records[index].ack_conflict = true;
        return;
    }
    if progress.records[index].outer.is_none() {
        progress.records[index].outer = Some(outer.clone());
        progress.records[index].ack_ms = probe.elapsed();
    }
    let receiver = PAIRS[progress.records[index].pair].1;
    let Progress {
        records, rolling, ..
    } = &mut *progress;
    for (_, observation) in rolling.iter().filter(|(index, _)| *index == receiver) {
        records[index].observe(&probe.group, observation);
    }
}
pub(crate) fn raw(root: &Path, id: &MessageId) {
    if let Some(probe) = current(root) {
        probe.record(root, Observation::Raw(id.clone()));
    }
}
pub(crate) fn event(
    root: &Path,
    group: &GroupId,
    content: &MessageId,
    source: &SourceLeafProof,
    digest: [u8; 32],
) {
    if let Some(probe) = current(root).filter(|probe| probe.group == *group) {
        probe.record(
            root,
            Observation::Event(
                group.clone(),
                content.clone(),
                source.signature_public_key.clone(),
                digest,
            ),
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
    if received.is_some_and(|received| {
        received.control != AccountSharingControl::Request
            || received.signer != source.signature_public_key
    }) {
        return;
    }
    if let Some(probe) = current(root).filter(|probe| probe.group == *group) {
        probe.record(
            root,
            Observation::Auth(
                group.clone(),
                source.signature_public_key.clone(),
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
    if received.control == AccountSharingControl::Request
        && let Some(probe) = current(root)
    {
        probe.record(
            root,
            Observation::Dispatch(received.nonce, received.signer.clone(), digest, outcome),
        );
    }
}
pub(crate) fn admitted(
    root: &Path,
    group: &GroupId,
    received: &ReceivedAccountSharingControl,
    owned_nonce: [u8; 32],
    digest: [u8; 32],
    flags: [bool; 4],
) {
    if received.control == AccountSharingControl::Request
        && received.nonce == owned_nonce
        && let Some(probe) = current(root).filter(|probe| probe.group == *group)
    {
        probe.record(
            root,
            Observation::Admitted(
                group.clone(),
                owned_nonce,
                received.signer.clone(),
                digest,
                flags,
            ),
        );
    }
}
pub(crate) fn capture_queue<F>(root: &Path, account: &MemberId, mut query: F)
where
    F: FnMut(&MessageId, &MessageId, Instant) -> ProofQueueFacts,
{
    let Some(probe) = current(root).filter(|probe| account.as_slice() == probe.account.as_slice())
    else {
        return;
    };
    let Some(receiver) = probe.index(root) else {
        return;
    };
    let targets: Vec<_> = {
        let progress = probe.progress.lock().unwrap_or_else(|e| e.into_inner());
        PAIRS
            .iter()
            .enumerate()
            .filter(|(_, (_, recipient))| *recipient == receiver)
            .filter_map(|(pair, _)| {
                let mut records = progress
                    .records
                    .iter()
                    .enumerate()
                    .filter(|(_, record)| record.pair == pair);
                let (index, record) = records.next()?;
                if records.next().is_some() {
                    return None;
                }
                Some((
                    index,
                    record.outer.clone()?,
                    record.prepared.content_id.clone(),
                ))
            })
            .collect()
    };
    for (index, outer, content) in targets {
        let facts = query(&outer, &content, probe.origin);
        let mut progress = probe.progress.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(record) = progress.records.get_mut(index)
            && record.outer.as_ref() == Some(&outer)
            && record.prepared.content_id == content
        {
            record.evidence.queue = Some(facts);
        }
    }
}

pub(crate) fn consent_prepared(root: &Path, scope: &AccountSharingScope) -> Option<ConsentCapture> {
    let probe = current(root)?;
    let recipient = probe.index(root)?;
    let source = probe
        .peers
        .iter()
        .position(|peer| peer.device.as_slice() == scope.source.as_slice())?;
    if !PAIRS.contains(&(source, recipient))
        || scope.protected.group_id != probe.group
        || probe.peers[recipient].device.as_slice() != scope.recipient.as_slice()
    {
        return None;
    }
    let capture = ConsentCapture {
        root: root.to_path_buf(),
        nonce: scope.nonce,
        approval: scope.approval_id,
        source: scope.source.as_slice().try_into().ok()?,
        recipient: scope.recipient.as_slice().try_into().ok()?,
        group: scope.protected.group_id.clone(),
    };
    consent_phase(&capture, 0);
    Some(capture)
}
/// Phase0 is real Core-wrapped Consent,1 actual publisher branch first poll,2 actualSDKACK.
pub(crate) fn consent_phase(capture: &ConsentCapture, phase: usize) {
    if phase >= 3 {
        return;
    }
    let Some(probe) = current(&capture.root) else {
        return;
    };
    if probe.group != capture.group {
        return;
    }
    let mut progress = probe.progress.lock().unwrap_or_else(|e| e.into_inner());
    for record in &mut progress.records {
        if record.prepared.nonce == capture.nonce
            && record.approval == capture.approval
            && record.prepared.local_device == capture.source
            && record.prepared.peer_device == capture.recipient
        {
            let count = &mut record.evidence.consent[phase];
            *count = count.saturating_add(1);
            if record.evidence.consent_ms[phase].is_none() {
                record.evidence.consent_ms[phase] = probe.elapsed();
            }
        }
    }
}
