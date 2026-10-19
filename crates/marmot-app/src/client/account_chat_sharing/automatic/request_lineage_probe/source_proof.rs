//! First actual source PairPolicyCommitted proof for each captured genuine Request.
//! Passive and bounded: no action owner, publication, authentication or retry authority.
use super::super::consent_delivery_probe::{Outcome, PreparedConsent, ProofQueueFacts, ProofStage};
use super::{MAX_RECORDS, MAX_ROLLING_PER_ROOT, PAIRS, Probe, current};
use cgka_engine::account_chat_sharing::{AccountSharingControl, ReceivedAccountSharingControl};
use cgka_traits::{GroupId, MemberId, MessageId, source_leaf::SourceLeafProof};
use std::{
    path::{Path, PathBuf},
    time::Instant,
};

// No Debug on any identity-bearing structure.
pub(crate) struct Capture {
    root: PathBuf,
    request: usize,
    approval: [u8; 32],
    prepared: PreparedConsent,
}
struct First {
    request: usize,
    pair: usize,
    approval: [u8; 32],
    prepared: PreparedConsent,
    prepared_ms: Option<u64>,
    ack_ms: Option<u64>,
    outer: Option<MessageId>,
    ack_conflict: bool,
    later_attempts: usize,
    later_distinct_attempts: usize,
    overflow: bool,
    raw: bool,
    event: bool,
    nonce: bool,
    auth: Option<Outcome>,
    dispatch: Option<Outcome>,
    owned: [usize; 3],
    queue: Option<ProofQueueFacts>,
}
enum Observation {
    Raw(MessageId),
    Event(GroupId, MessageId, Vec<u8>, [u8; 32]),
    Auth(GroupId, Vec<u8>, [u8; 32], Option<[u8; 32]>, Outcome),
    Dispatch([u8; 32], Vec<u8>, [u8; 32], Outcome),
    Owned(GroupId, [u8; 32], Vec<u8>, [u8; 32], ProofStage),
}
#[derive(Default)]
pub(super) struct Progress {
    first: Vec<First>,
    rolling: Vec<(usize, Observation)>,
    receive_dropped: [usize; 5],
    unbound: [usize; 6],
    overflow: bool,
}
fn increment(value: &mut usize, overflow: &mut bool) {
    if let Some(next) = value.checked_add(1) {
        *value = next;
    } else {
        *overflow = true;
    }
}
impl First {
    fn observe(&mut self, group: &GroupId, observation: &Observation) -> bool {
        let p = &self.prepared;
        match observation {
            Observation::Raw(id) if self.outer.as_ref() == Some(id) => self.raw = true,
            Observation::Event(g, id, signer, digest)
                if g == group
                    && id == &p.content_id
                    && signer.as_slice() == p.local_device
                    && digest == &p.inner_wire_sha256 =>
            {
                self.event = true
            }
            Observation::Auth(g, signer, digest, nonce, outcome)
                if g == group
                    && signer.as_slice() == p.local_device
                    && digest == &p.inner_wire_sha256 =>
            {
                self.auth = Some(*outcome);
                self.nonce |= *nonce == Some(p.nonce);
            }
            Observation::Dispatch(nonce, signer, digest, outcome)
                if nonce == &p.nonce
                    && signer.as_slice() == p.local_device
                    && digest == &p.inner_wire_sha256 =>
            {
                self.dispatch = Some(*outcome)
            }
            Observation::Owned(g, nonce, signer, digest, stage)
                if g == group
                    && nonce == &p.nonce
                    && signer.as_slice() == p.local_device
                    && digest == &p.inner_wire_sha256 =>
            {
                increment(&mut self.owned[*stage as usize], &mut self.overflow);
            }
            _ => return false,
        }
        true
    }
}
/// Only the first actual preparation gets an ACK token. Later publisher attempts
/// are counted but cannot assign their ACK or metadata to the first attempt.
pub(crate) fn prepared(
    root: &Path,
    prepared: &PreparedConsent,
    approval: [u8; 32],
) -> Option<Capture> {
    let probe = current(root)?;
    let source = probe.index(root)?;
    let recipient = probe
        .peers
        .iter()
        .position(|peer| peer.device == prepared.peer_device)?;
    let pair = PAIRS
        .iter()
        .position(|value| *value == (source, recipient))?;
    if prepared.account != probe.account
        || prepared.protected_group != probe.group
        || prepared.local_device != probe.peers[source].device
    {
        return None;
    }
    let mut progress = probe
        .progress
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut matches = progress.records.iter().enumerate().filter(|(_, request)| {
        request.pair == pair
            && request.approval == approval
            && request.prepared.nonce == prepared.nonce
            && request.prepared.local_device == prepared.local_device
            && request.prepared.peer_device == prepared.peer_device
            && request.prepared.account == prepared.account
            && request.prepared.protected_group == prepared.protected_group
    });
    let request = matches.next().map(|(index, _)| index);
    let unique = request.is_some() && matches.next().is_none();
    drop(matches);
    if !unique {
        let p = &mut progress.source_proofs;
        increment(&mut p.unbound[pair], &mut p.overflow);
        return None;
    }
    let request = request.expect("unique captured Request");
    let p = &mut progress.source_proofs;
    if let Some(first) = p.first.iter_mut().find(|first| first.request == request) {
        increment(&mut first.later_attempts, &mut first.overflow);
        if first.prepared != *prepared {
            increment(&mut first.later_distinct_attempts, &mut first.overflow);
        }
        return None;
    }
    if p.first.len() >= MAX_RECORDS {
        increment(&mut p.unbound[pair], &mut p.overflow);
        return None;
    }
    let mut first = First {
        request,
        pair,
        approval,
        prepared: prepared.clone(),
        prepared_ms: probe.elapsed(),
        ack_ms: None,
        outer: None,
        ack_conflict: false,
        later_attempts: 0,
        later_distinct_attempts: 0,
        overflow: false,
        raw: false,
        event: false,
        nonce: false,
        auth: None,
        dispatch: None,
        owned: [0; 3],
        queue: None,
    };
    for (_, observation) in p.rolling.iter().filter(|(root, _)| *root == recipient) {
        first.observe(&probe.group, observation);
    }
    p.first.push(first);
    Some(Capture {
        root: root.to_path_buf(),
        request,
        approval,
        prepared: prepared.clone(),
    })
}
pub(crate) fn acknowledged(capture: &Capture, outer: &MessageId) {
    let Some(probe) = current(&capture.root).filter(|probe| {
        probe.account == capture.prepared.account && probe.group == capture.prepared.protected_group
    }) else {
        return;
    };
    let mut progress = probe
        .progress
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let p = &mut progress.source_proofs;
    let Some(index) = p.first.iter().position(|first| {
        first.request == capture.request
            && first.approval == capture.approval
            && first.prepared == capture.prepared
    }) else {
        return;
    };
    if let Some(previous) = &p.first[index].outer {
        if previous != outer {
            p.first[index].ack_conflict = true;
        }
        return;
    }
    p.first[index].outer = Some(outer.clone());
    p.first[index].ack_ms = probe.elapsed();
    let recipient = PAIRS[p.first[index].pair].1;
    let Progress { first, rolling, .. } = p;
    // Other stages were replayed at preparation or recorded directly since it.
    // Only raw IDs required the newly available outer ACK binding.
    for (_, observation) in rolling.iter().filter(|(root, observation)| {
        *root == recipient && matches!(observation, Observation::Raw(_))
    }) {
        first[index].observe(&probe.group, observation);
    }
}
fn record(root: &Path, observation: Observation) {
    let Some(probe) = current(root) else {
        return;
    };
    let Some(recipient) = probe.index(root) else {
        return;
    };
    let mut progress = probe
        .progress
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let p = &mut progress.source_proofs;
    let mut matched = false;
    for first in p
        .first
        .iter_mut()
        .filter(|first| PAIRS[first.pair].1 == recipient)
    {
        matched |= first.observe(&probe.group, &observation);
    }
    if matched {
        return;
    }
    if p.rolling
        .iter()
        .filter(|(root, _)| *root == recipient)
        .count()
        >= MAX_ROLLING_PER_ROOT
    {
        if let Some(index) = p.rolling.iter().position(|(root, _)| *root == recipient) {
            p.rolling.remove(index);
            increment(&mut p.receive_dropped[recipient], &mut p.overflow);
        }
    }
    p.rolling.push((recipient, observation));
}
pub(crate) fn raw(root: &Path, id: &MessageId) {
    record(root, Observation::Raw(id.clone()));
}
pub(crate) fn event(
    root: &Path,
    group: &GroupId,
    content: &MessageId,
    source: &SourceLeafProof,
    digest: [u8; 32],
) {
    record(
        root,
        Observation::Event(
            group.clone(),
            content.clone(),
            source.signature_public_key.clone(),
            digest,
        ),
    );
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
        received.control != AccountSharingControl::Body(0)
            || received.signer != source.signature_public_key
    }) {
        return;
    }
    record(
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
pub(crate) fn dispatched(
    root: &Path,
    received: &ReceivedAccountSharingControl,
    digest: [u8; 32],
    outcome: Outcome,
) {
    if received.control == AccountSharingControl::Body(0) {
        record(
            root,
            Observation::Dispatch(received.nonce, received.signer.clone(), digest, outcome),
        );
    }
}
pub(crate) fn owned(
    root: &Path,
    group: &GroupId,
    received: &ReceivedAccountSharingControl,
    nonce: [u8; 32],
    digest: [u8; 32],
    stage: ProofStage,
) {
    if received.control == AccountSharingControl::Body(0) && received.nonce == nonce {
        record(
            root,
            Observation::Owned(group.clone(), nonce, received.signer.clone(), digest, stage),
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
    let Some(recipient) = probe.index(root) else {
        return;
    };
    let targets: Vec<_> = {
        let progress = probe
            .progress
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        PAIRS
            .iter()
            .enumerate()
            .filter(|(_, (_, receiver))| *receiver == recipient)
            .filter_map(|(pair, _)| {
                let mut requests = progress
                    .records
                    .iter()
                    .enumerate()
                    .filter(|(_, request)| request.pair == pair);
                let (request, _) = requests.next()?;
                if requests.next().is_some() {
                    return None;
                }
                let (index, first) = progress
                    .source_proofs
                    .first
                    .iter()
                    .enumerate()
                    .find(|(_, first)| first.request == request)?;
                Some((
                    index,
                    first.outer.clone()?,
                    first.prepared.content_id.clone(),
                ))
            })
            .collect()
    };
    // Maximum three targets, three existing synchronous plane reads each. No guard
    // is held across those queries and the actual receiver token is only borrowed.
    for (index, outer, content) in targets {
        let facts = query(&outer, &content, probe.origin);
        let mut progress = probe
            .progress
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(first) = progress.source_proofs.first.get_mut(index)
            && first.outer.as_ref() == Some(&outer)
            && first.prepared.content_id == content
        {
            first.queue = Some(facts);
        }
    }
}
#[derive(Debug)]
pub(crate) struct SourceProofSummary {
    source_slot: usize,
    recipient_slot: usize,
    request_records: usize,
    prepared: usize,
    acknowledged: usize,
    later_attempts: usize,
    later_distinct_attempts: usize,
    unbound_preparations: usize,
    raw: usize,
    event: usize,
    nonce: usize,
    authentication: [usize; 5],
    dispatch: [usize; 5],
    owned: [usize; 3],
    prepared_ms: Option<u64>,
    sdk_ack_ms: Option<u64>,
    queue: Option<ProofQueueFacts>,
    ack_conflict: bool,
    overflow: bool,
    ambiguous: bool,
    partial: bool,
}
impl Probe {
    pub(crate) fn source_proof_summaries(&self) -> [SourceProofSummary; 6] {
        let progress = self
            .progress
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let p = &progress.source_proofs;
        std::array::from_fn(|pair| {
            let (source_slot, recipient_slot) = PAIRS[pair];
            let mut row = SourceProofSummary {
                source_slot,
                recipient_slot,
                request_records: progress
                    .records
                    .iter()
                    .filter(|request| request.pair == pair)
                    .count(),
                prepared: 0,
                acknowledged: 0,
                later_attempts: 0,
                later_distinct_attempts: 0,
                unbound_preparations: p.unbound[pair],
                raw: 0,
                event: 0,
                nonce: 0,
                authentication: [0; 5],
                dispatch: [0; 5],
                owned: [0; 3],
                prepared_ms: None,
                sdk_ack_ms: None,
                queue: None,
                ack_conflict: false,
                overflow: p.overflow,
                ambiguous: false,
                partial: Instant::now() >= self.deadline
                    || progress.dropped[pair] > 0
                    || p.receive_dropped[recipient_slot] > 0,
            };
            for first in p.first.iter().filter(|first| first.pair == pair) {
                increment(&mut row.prepared, &mut row.overflow);
                if first.outer.is_some() {
                    increment(&mut row.acknowledged, &mut row.overflow);
                }
                if first.raw {
                    increment(&mut row.raw, &mut row.overflow);
                }
                if first.event {
                    increment(&mut row.event, &mut row.overflow);
                }
                if first.nonce {
                    increment(&mut row.nonce, &mut row.overflow);
                }
                if let Some(outcome) = first.auth {
                    increment(&mut row.authentication[outcome as usize], &mut row.overflow);
                }
                if let Some(outcome) = first.dispatch {
                    increment(&mut row.dispatch[outcome as usize], &mut row.overflow);
                }
                for (total, count) in row.owned.iter_mut().zip(first.owned) {
                    if let Some(sum) = total.checked_add(count) {
                        *total = sum;
                    } else {
                        row.overflow = true;
                    }
                }
                if let Some(sum) = row.later_attempts.checked_add(first.later_attempts) {
                    row.later_attempts = sum;
                } else {
                    row.overflow = true;
                }
                if let Some(sum) = row
                    .later_distinct_attempts
                    .checked_add(first.later_distinct_attempts)
                {
                    row.later_distinct_attempts = sum;
                } else {
                    row.overflow = true;
                }
                row.ack_conflict |= first.ack_conflict;
                row.overflow |= first.overflow;
                row.prepared_ms = first.prepared_ms;
                row.sdk_ack_ms = first.ack_ms;
                row.queue = first.queue;
            }
            row.ambiguous = row.request_records > 1
                || row.prepared > 1
                || row.later_distinct_attempts > 0
                || row.ack_conflict;
            if row.request_records != 1 || row.prepared != 1 {
                row.prepared_ms = None;
                row.sdk_ack_ms = None;
                row.queue = None;
            }
            row.partial |= row.request_records != 1
                || row.prepared != 1
                || row.acknowledged != 1
                || row.later_attempts > 0
                || row.unbound_preparations > 0
                || row.ambiguous
                || row.overflow
                || row.prepared_ms.is_none()
                || row.sdk_ack_ms.is_none()
                || row.queue.is_none_or(|facts| {
                    facts.capture_ms.is_none()
                        || facts.same_receiver != Some(true)
                        || facts.outer.is_none_or(|outer| outer.invalid)
                        || facts.content.is_none_or(|content| content.invalid)
                });
            row
        })
    }
}
