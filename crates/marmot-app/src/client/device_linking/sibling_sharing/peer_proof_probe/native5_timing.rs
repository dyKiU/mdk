//! Fixed, passive observations for the one exact fourth-join recipient choice; never transport authority.
use super::*;
use cgka_engine::account_chat_sharing::AccountSharingControl;
use std::sync::TryLockError;
use std::sync::atomic::AtomicU32;

const FROZEN: u32 = 1 << 31;
const LOCK_BUSY: u32 = 1;
const LOCK_POISONED: u32 = 2;
const CAPACITY: u32 = 4;
const IDENTITY: u32 = 8;
const OVERFLOW: u32 = 16;
const ARM_UNAVAILABLE: u32 = 32;
const DUPLICATE: u32 = 64;
const MAX_US: u64 = 600_000_000;

#[derive(Clone)]
struct Key {
    state: Weak<State>,
    nonce: [u8; 32],
    message: cgka_traits::MessageId,
}
impl Key {
    fn same_channel(&self, other: &Self) -> bool {
        self.state.ptr_eq(&other.state) && self.nonce == other.nonce
    }
    fn same_attempt(&self, other: &Self) -> bool {
        self.same_channel(other) && self.message == other.message
    }
}
// Pure wire-common identity only. Local generations and cross-device pointers
// are deliberately excluded; these observations never grant channel authority.
struct CommonScope {
    account: Vec<u8>,
    group: Vec<u8>,
    epoch: u64,
    authenticator: [u8; 32],
    roster: [u8; 32],
    source: Vec<u8>,
    recipient: Vec<u8>,
    nonce: [u8; 32],
    policy: [u8; 32],
    approval: [u8; 32],
}
impl CommonScope {
    fn new(scope: &AccountSharingScope) -> Self {
        Self {
            account: scope.protected.account.as_slice().to_vec(),
            group: scope.protected.group_id.as_slice().to_vec(),
            epoch: scope.protected.epoch.0,
            authenticator: scope.protected.epoch_authenticator_digest,
            roster: scope.protected.roster_commitment,
            source: scope.source.clone(),
            recipient: scope.recipient.clone(),
            nonce: scope.nonce,
            policy: scope.approved_policy_identity,
            approval: scope.approval_id,
        }
    }
    fn matches(&self, scope: &AccountSharingScope) -> bool {
        self.account == scope.protected.account.as_slice()
            && self.group == scope.protected.group_id.as_slice()
            && self.epoch == scope.protected.epoch.0
            && self.authenticator == scope.protected.epoch_authenticator_digest
            && self.roster == scope.protected.roster_commitment
            && self.source == scope.source
            && self.recipient == scope.recipient
            && self.nonce == scope.nonce
            && self.policy == scope.approved_policy_identity
            && self.approval == scope.approval_id
    }
}
struct Peer {
    original: Weak<crate::client::private_enrollment_proposal::OriginalSiblingSharingApproval>,
    state: Weak<State>,
    proof: Option<Proof>,
    sealed_wire: Option<Vec<u8>>,
    progress: [Option<u64>; 7],
    repeats: [u32; 7],
    bind_results: [u32; 2],
    validation_results: [u32; 8],
}
struct Incoming {
    times: [Option<u64>; 6],
    opened_ok: Option<bool>,
    disposition: Option<u8>,
    later_routes: u32,
    first_successful_accept: Option<(u64, u32)>,
}
// The reciprocal side binds its OWN real local original and State. Never compare
// either pointer to the recipient's unrelated State.
fn peer_slot(data: &mut Data, entry: &SiblingChannel, probe: &Probe) -> Option<usize> {
    if entry.recipient {
        return None;
    }
    let SiblingOriginal::Existing { original, .. } = entry.original.as_ref() else {
        return None;
    };
    let index = data.slots.iter().position(|row| {
        row.as_ref()
            .is_some_and(|slot| slot.common.matches(entry.channel.scope()))
    })?;
    let slot = data.slots[index].as_mut()?;
    if let Some(peer) = &slot.peer {
        if !peer.original.ptr_eq(&Arc::downgrade(original))
            || !peer.state.ptr_eq(&Arc::downgrade(&entry.state))
        {
            probe.loss(IDENTITY);
            return None;
        }
    } else {
        slot.peer = Some(Peer {
            original: Arc::downgrade(original),
            state: Arc::downgrade(&entry.state),
            proof: None,
            sealed_wire: None,
            progress: [None; 7],
            repeats: [0; 7],
            bind_results: [0; 2],
            validation_results: [0; 8],
        });
    }
    Some(index)
}
pub(in super::super::super) fn peer_progress(entry: &SiblingChannel, stage: usize) {
    let Some(probe) = active_probe() else {
        return;
    };
    probe.observe(|data, time| {
        let Some(index) = peer_slot(data, entry, &probe) else {
            return;
        };
        let Some(peer) = data.slots[index]
            .as_mut()
            .and_then(|slot| slot.peer.as_mut())
        else {
            return;
        };
        let Some(field) = peer.progress.get_mut(stage) else {
            probe.loss(IDENTITY);
            return;
        };
        if field.is_some() {
            increment(&mut peer.repeats[stage], &probe);
        } else {
            *field = time;
        }
    });
}
pub(in super::super::super) fn peer_bind_result(entry: &SiblingChannel, ok: bool) {
    let Some(probe) = active_probe() else {
        return;
    };
    probe.observe(|data, _| {
        let Some(index) = peer_slot(data, entry, &probe) else {
            return;
        };
        if let Some(peer) = data.slots[index]
            .as_mut()
            .and_then(|slot| slot.peer.as_mut())
        {
            increment(&mut peer.bind_results[usize::from(!ok)], &probe);
        }
    });
}
pub(in super::super::super) fn peer_validation(
    entry: &SiblingChannel,
    result: &Result<(), ClientLinkingError>,
) {
    let Some(probe) = active_probe() else {
        return;
    };
    let category = match result {
        Ok(()) => 0,
        Err(ClientLinkingError::Owner(_)) => 1,
        Err(ClientLinkingError::Collection(_)) => 2,
        Err(ClientLinkingError::Runtime(_)) => 3,
        Err(ClientLinkingError::Engine(_)) => 4,
        Err(ClientLinkingError::Genesis(_)) => 5,
        Err(ClientLinkingError::Gate(_)) => 6,
        Err(ClientLinkingError::PrivateInvite(_)) => 7,
    };
    probe.observe(|data, _| {
        let Some(index) = peer_slot(data, entry, &probe) else {
            return;
        };
        if let Some(peer) = data.slots[index]
            .as_mut()
            .and_then(|slot| slot.peer.as_mut())
        {
            increment(&mut peer.validation_results[category], &probe);
        }
    });
}
pub(in super::super::super) struct IncomingToken {
    probe: Weak<Probe>,
    index: usize,
    category: usize,
    ordinal: u32,
    first: bool,
}
pub(in super::super::super) fn incoming(
    entry: &SiblingChannel,
    received: &cgka_engine::account_chat_sharing::ReceivedAccountSharingControl,
    wire: &[u8],
) -> Option<IncomingToken> {
    if received.control != AccountSharingControl::Body(0) {
        return None;
    }
    let probe = active_probe()?;
    let mut selected = None;
    probe.observe(|data, time| {
        if !owned(data, entry) {
            return;
        }
        let Some(index) = data.slots.iter().position(|row| {
            row.as_ref().is_some_and(|slot| {
                same_entry(slot, entry) && slot.common.matches(entry.channel.scope())
            })
        }) else {
            return;
        };
        let Some(slot) = data.slots[index].as_mut() else {
            return;
        };
        let category = match slot
            .peer
            .as_ref()
            .and_then(|peer| peer.sealed_wire.as_deref())
        {
            Some(first) if first == wire => 0,
            Some(_) => 1,
            None => 2,
        };
        let row = &mut slot.incoming[category];
        let first = row.is_none();
        if first {
            *row = Some(Incoming {
                times: [time, None, None, None, None, None],
                opened_ok: None,
                disposition: None,
                later_routes: 0,
                first_successful_accept: None,
            });
        } else if let Some(row) = row.as_mut() {
            increment(&mut row.later_routes, &probe);
        }
        if first && category == 0 {
            if let Some(time) = time {
                probe.worker.endpoint(index, 1, time);
            }
        }
        let ordinal = row.as_ref().map_or(0, |row| row.later_routes);
        selected = Some(IncomingToken {
            probe: Arc::downgrade(&probe),
            index,
            category,
            ordinal,
            first,
        });
    });
    selected
}
impl IncomingToken {
    pub(in super::super::super) fn stage(&self, stage: usize, opened_ok: Option<bool>) {
        if !self.first && stage != 3 {
            return;
        }
        let Some(probe) = self.probe.upgrade() else {
            return;
        };
        probe.observe(|data, time| {
            let Some(row) = data
                .slots
                .get_mut(self.index)
                .and_then(Option::as_mut)
                .and_then(|slot| slot.incoming.get_mut(self.category))
                .and_then(Option::as_mut)
            else {
                probe.loss(IDENTITY);
                return;
            };
            if stage == 3 && row.first_successful_accept.is_none() {
                if let Some(time) = time {
                    row.first_successful_accept = Some((time, self.ordinal));
                }
            }
            if !self.first {
                return;
            }
            let Some(field) = row.times.get_mut(stage) else {
                probe.loss(IDENTITY);
                return;
            };
            if field.is_some() {
                probe.loss(DUPLICATE);
                return;
            }
            *field = time;
            if let Some(ok) = opened_ok {
                row.opened_ok = Some(ok);
            }
        });
    }
    pub(in super::super::super) fn finish(
        &self,
        result: &Result<bool, crate::AccountSharingError>,
    ) {
        if !self.first {
            return;
        }
        let category = match result {
            Ok(true) => 0,
            Ok(false) => 1,
            Err(crate::AccountSharingError::Unsupported) => 2,
            Err(crate::AccountSharingError::NotReady) => 3,
            Err(crate::AccountSharingError::Closed) => 4,
            Err(crate::AccountSharingError::StaleRevision) => 5,
            Err(crate::AccountSharingError::RuntimeUnavailable) => 6,
        };
        let Some(probe) = self.probe.upgrade() else {
            return;
        };
        probe.observe(|data, time| {
            let Some(row) = data
                .slots
                .get_mut(self.index)
                .and_then(Option::as_mut)
                .and_then(|slot| slot.incoming.get_mut(self.category))
                .and_then(Option::as_mut)
            else {
                probe.loss(IDENTITY);
                return;
            };
            if row.times[5].is_some() {
                probe.loss(DUPLICATE);
                return;
            }
            row.times[5] = time;
            row.disposition = Some(category);
        });
    }
}

pub(in super::super::super) enum PublicationAttempt {
    Own(ProofAttempt),
    Peer(PeerAttempt),
}
impl PublicationAttempt {
    pub(in super::super::super) fn boundary(&self, index: usize) {
        match self {
            Self::Own(a) => a.boundary(index),
            Self::Peer(a) => a.boundary(index),
        }
    }
    pub(in super::super::super) fn sealed(&self, wire: &[u8]) {
        if let Self::Peer(peer) = self {
            peer.sealed(wire);
        }
    }
    fn prepared(
        &self,
        entry: &SiblingChannel,
        request: &cgka_traits::TransportPublishRequest,
    ) -> Option<Token> {
        match self {
            Self::Own(a) => a.prepared(entry, request),
            Self::Peer(a) => a.prepared(entry, request),
        }
    }
}
pub(in super::super::super) struct PeerAttempt {
    probe: Weak<Probe>,
    index: usize,
}
impl PeerAttempt {
    fn sealed(&self, wire: &[u8]) {
        let Some(probe) = self.probe.upgrade() else {
            return;
        };
        if wire.is_empty() || wire.len() > 16 * 1024 {
            probe.loss(CAPACITY);
            return;
        }
        probe.observe(|data, _| {
            let Some(peer) = data
                .slots
                .get_mut(self.index)
                .and_then(Option::as_mut)
                .and_then(|slot| slot.peer.as_mut())
            else {
                probe.loss(IDENTITY);
                return;
            };
            if peer.sealed_wire.is_some() {
                probe.loss(DUPLICATE);
            } else {
                peer.sealed_wire = Some(wire.to_vec());
            }
        });
    }
    fn boundary(&self, index: usize) {
        let Some(probe) = self.probe.upgrade() else {
            return;
        };
        probe.observe(|data, time| {
            let Some(proof) = data
                .slots
                .get_mut(self.index)
                .and_then(Option::as_mut)
                .and_then(|slot| slot.peer.as_mut())
                .and_then(|peer| peer.proof.as_mut())
            else {
                probe.loss(IDENTITY);
                return;
            };
            let Some(field) = proof.preparation.get_mut(index) else {
                probe.loss(IDENTITY);
                return;
            };
            if field.is_some() {
                probe.loss(DUPLICATE);
            } else {
                *field = time;
            }
        });
    }
    fn prepared(
        &self,
        entry: &SiblingChannel,
        request: &cgka_traits::TransportPublishRequest,
    ) -> Option<Token> {
        let probe = self.probe.upgrade()?;
        let mut selected = None;
        probe.observe(|data, time| {
            if peer_slot(data, entry, &probe) != Some(self.index) {
                probe.loss(IDENTITY);
                return;
            }
            let Some(peer) = data.slots[self.index]
                .as_mut()
                .and_then(|slot| slot.peer.as_mut())
            else {
                return;
            };
            let Some(proof) = peer.proof.as_mut() else {
                probe.loss(IDENTITY);
                return;
            };
            if proof.key.is_some() {
                probe.loss(DUPLICATE);
                return;
            }
            let key = Key {
                state: Arc::downgrade(&entry.state),
                nonce: entry.channel.scope().nonce,
                message: request.message.id.clone(),
            };
            proof.key = Some(key.clone());
            proof.times[0] = time;
            selected = Some(Token {
                probe: Arc::downgrade(&probe),
                index: self.index,
                key,
                proof: true,
                peer: true,
            });
        });
        selected.map(|token| {
            token.bind_sdk();
            token
        })
    }
}
pub(in super::super::super) fn begin_proof(entry: &SiblingChannel) -> Option<PublicationAttempt> {
    if entry.recipient {
        return begin_owned_proof(entry).map(PublicationAttempt::Own);
    }
    let probe = active_probe()?;
    let mut selected = None;
    probe.observe(|data, time| {
        let Some(index) = peer_slot(data, entry, &probe) else {
            return;
        };
        let Some(peer) = data.slots[index]
            .as_mut()
            .and_then(|slot| slot.peer.as_mut())
        else {
            return;
        };
        if let Some(proof) = peer.proof.as_mut() {
            increment(&mut proof.subsequent_attempts, &probe);
            return;
        }
        peer.proof = Some(Proof {
            key: None,
            times: [None; 9],
            outcomes: [None; 5],
            preparation: [time, None, None, None],
            spawn_boundaries: [None; 6],
            subsequent_attempts: 0,
        });
        selected = Some(PublicationAttempt::Peer(PeerAttempt {
            probe: Arc::downgrade(&probe),
            index,
        }));
    });
    selected
}

struct Slot {
    common: CommonScope,
    peer: Option<Peer>,
    incoming: [Option<Incoming>; 3],
    key: Key,
    times: [Option<u64>; 9],
    // Actual adapter Result Ok, report met ACKs, send accepted, receive Ok,
    // final harvest success. None is unobserved, never false/zero.
    outcomes: [Option<bool>; 5],
    retry_prepared: u32,
    proof: Option<Proof>,
    // First policy call/success, proof eligibility, authenticated peer proof,
    // and actual complete write; repeats are counted rather than overwritten.
    progress: [Option<u64>; 5],
    progress_repeats: [u32; 5],
}
struct Proof {
    // Unbound until this SAME first attempt obtains an actual wrapped message.
    key: Option<Key>,
    times: [Option<u64>; 9],
    outcomes: [Option<bool>; 5],
    // Actual seal-before/after, wrap-before/after of first attempt only.
    preparation: [Option<u64>; 4],
    // Before/after negative hook, publication test mutex, and actual spawn call.
    spawn_boundaries: [Option<u64>; 6],
    subsequent_attempts: u32,
}
impl Slot {
    fn publication_mut(
        &mut self,
        proof: bool,
        peer: bool,
    ) -> Option<(&Key, &mut [Option<u64>; 9], &mut [Option<bool>; 5])> {
        if peer {
            let publication = self.peer.as_mut()?.proof.as_mut()?;
            Some((
                publication.key.as_ref()?,
                &mut publication.times,
                &mut publication.outcomes,
            ))
        } else if proof {
            let publication = self.proof.as_mut()?;
            Some((
                publication.key.as_ref()?,
                &mut publication.times,
                &mut publication.outcomes,
            ))
        } else {
            Some((&self.key, &mut self.times, &mut self.outcomes))
        }
    }
}
#[derive(Clone, Copy)]
struct RpcRow {
    times: [Option<u64>; 5],
    // Worker/facade result: phase discriminant0..8 or error9(timeout)/10(other).
    results: [Option<u8>; 2],
    sent: Option<bool>,
}
// Passive actual worker poll boundaries; no retained App, Client, waker or authority.
const EXPECTED_WORKERS: usize = 5;
static WORKER_SPAWNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[derive(Clone)]
pub(crate) struct WorkerTag(Arc<WorkerTagState>);
struct WorkerTagState {
    ordinal: usize,
    active: AtomicU32,
    mask: AtomicU32,
}
pub(crate) struct WorkerSection {
    tag: WorkerTag,
    previous: u32,
}
impl Drop for WorkerSection {
    fn drop(&mut self) {
        self.tag.0.active.store(self.previous, Ordering::Release);
    }
}
impl WorkerTag {
    pub(crate) fn new() -> Self {
        let ordinal = WORKER_SPAWNS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(1)
            })
            .unwrap_or(usize::MAX);
        Self(Arc::new(WorkerTagState {
            ordinal,
            active: AtomicU32::new(0),
            mask: AtomicU32::new(0),
        }))
    }
    pub(crate) fn section(&self, category: u32) -> WorkerSection {
        let previous = self.0.active.swap(category, Ordering::AcqRel);
        self.0
            .mask
            .fetch_or(1u32.checked_shl(category).unwrap_or(0), Ordering::AcqRel);
        WorkerSection {
            tag: self.clone(),
            previous,
        }
    }
    pub(crate) fn ordinal(&self) -> usize {
        self.0.ordinal
    }
}
pub(crate) struct WorkerFuture<F> {
    inner: std::pin::Pin<Box<F>>,
    tag: WorkerTag,
}
impl<F> WorkerFuture<F> {
    pub(crate) fn new(inner: std::pin::Pin<Box<F>>, tag: WorkerTag) -> Self {
        Self { inner, tag }
    }
}
impl<F: std::future::Future> std::future::Future for WorkerFuture<F> {
    type Output = F::Output;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        let token = WorkerPoll::begin(&this.tag);
        let result = this.inner.as_mut().poll(cx);
        if let Some(token) = token {
            token.finish(&this.tag, result.is_ready());
        }
        result
    }
}
// ordinal,enter,returned,thread ordinal,entry category,exit category,selected mask,Ready.
type WorkerSample = (u64, u64, u64, u8, u8, u8, u32, bool);
type WorkerInFlight = (u64, u64, u8, u8);
#[derive(Clone, Copy, Default)]
struct WorkerRow {
    counts: [u64; 7],
    threads: u16,
    inflight: Option<WorkerInFlight>,
    longest: [Option<WorkerSample>; 4],
    focus: [[Option<WorkerSample>; 4]; 3],
}
struct WorkerData {
    deliveries: [Option<DeliveryRow>; 3],
}
impl Default for WorkerData {
    fn default() -> Self {
        Self {
            deliveries: [None; 3],
        }
    }
}
struct WorkerThreads {
    ids: [Option<std::thread::ThreadId>; 8],
    count: usize,
}
struct WorkerRecorder {
    origin: Instant,
    status: AtomicU32,
    rows: [Mutex<WorkerRow>; 5],
    threads: Mutex<WorkerThreads>,
    endpoints: [std::sync::atomic::AtomicU64; 6],
}
impl WorkerRecorder {
    fn new(origin: Instant) -> Self {
        Self {
            origin,
            status: AtomicU32::new(0),
            rows: std::array::from_fn(|_| Mutex::new(WorkerRow::default())),
            threads: Mutex::new(WorkerThreads {
                ids: [None; 8],
                count: 0,
            }),
            endpoints: std::array::from_fn(|_| std::sync::atomic::AtomicU64::new(0)),
        }
    }
    fn loss(&self, reason: u32) {
        let _ = self
            .status
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                (old & FROZEN == 0).then_some(old | reason)
            });
    }
    fn elapsed(&self) -> Option<u64> {
        let value = self.origin.elapsed().as_micros();
        if value > u128::from(MAX_US) {
            self.loss(OVERFLOW);
            None
        } else {
            Some(value as u64)
        }
    }
    fn endpoint(&self, channel: usize, edge: usize, time: u64) {
        if self.status.load(Ordering::Acquire) & FROZEN != 0 {
            return;
        }
        if let Some(slot) = self.endpoints.get(channel * 2 + edge) {
            if slot
                .compare_exchange(0, time + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                self.loss(DUPLICATE);
            }
        } else {
            self.loss(CAPACITY);
        }
    }
    fn thread(&self) -> Option<u8> {
        if self.status.load(Ordering::Acquire) & FROZEN != 0 {
            return None;
        }
        match self.threads.try_lock() {
            Ok(mut threads) => {
                if self.status.load(Ordering::Acquire) & FROZEN != 0 {
                    return None;
                }
                let id = std::thread::current().id();
                if let Some(index) = threads.ids.iter().position(|old| old.as_ref() == Some(&id)) {
                    return Some(index as u8);
                }
                let index = threads.count;
                if index >= 8 {
                    self.loss(CAPACITY);
                    return None;
                }
                threads.ids[index] = Some(id);
                threads.count += 1;
                Some(index as u8)
            }
            Err(TryLockError::WouldBlock) => {
                self.loss(LOCK_BUSY);
                None
            }
            Err(TryLockError::Poisoned(_)) => {
                self.loss(LOCK_POISONED);
                None
            }
        }
    }
    fn with_row(&self, index: usize, apply: impl FnOnce(&mut WorkerRow, u64)) {
        if self.status.load(Ordering::Acquire) & FROZEN != 0 {
            return;
        }
        let Some(row) = self.rows.get(index) else {
            self.loss(CAPACITY);
            return;
        };
        match row.try_lock() {
            Ok(mut row) => {
                if self.status.load(Ordering::Acquire) & FROZEN == 0 {
                    if let Some(time) = self.elapsed() {
                        apply(&mut row, time);
                    }
                }
            }
            Err(TryLockError::WouldBlock) => self.loss(LOCK_BUSY),
            Err(TryLockError::Poisoned(_)) => self.loss(LOCK_POISONED),
        }
    }
    fn report(&self) -> String {
        use std::fmt::Write as _;
        let mut loss = self.status.fetch_or(FROZEN, Ordering::AcqRel) & !FROZEN;
        let spawned = WORKER_SPAWNS.load(Ordering::Acquire);
        if spawned != EXPECTED_WORKERS {
            loss |= CAPACITY;
        }
        let mut rows: [Option<WorkerRow>; 5] = [None; 5];
        for (index, slot) in self.rows.iter().enumerate() {
            match slot.try_lock() {
                Ok(row) => rows[index] = Some(*row),
                Err(TryLockError::WouldBlock) => loss |= LOCK_BUSY,
                Err(TryLockError::Poisoned(_)) => loss |= LOCK_POISONED,
            }
        }
        let threads = match self.threads.try_lock() {
            Ok(threads) => Some(threads.count),
            Err(TryLockError::WouldBlock) => {
                loss |= LOCK_BUSY;
                None
            }
            Err(TryLockError::Poisoned(_)) => {
                loss |= LOCK_POISONED;
                None
            }
        };
        let endpoints = self
            .endpoints
            .each_ref()
            .map(|value| value.load(Ordering::Acquire).checked_sub(1));
        // Endpoint and worker copies are independent snapshots. Retain only online
        // candidates intersecting the endpoint values visible at this freeze.
        for row in rows.iter_mut().flatten() {
            for channel in 0..3 {
                let ack = endpoints[channel * 2];
                let route = endpoints[channel * 2 + 1];
                let old = row.focus[channel];
                row.focus[channel] = [None; 4];
                for sample in old.into_iter().flatten() {
                    if ack.is_some_and(|ack| {
                        sample.2 >= ack
                            && route.is_none_or(|route| ack <= route && sample.1 <= route)
                    }) {
                        longest_insert(&mut row.focus[channel], sample);
                    }
                }
            }
        }
        let mut report = String::new();
        let _ = writeln!(
            &mut report,
            "native5-worker-meta known={} loss_mask={loss} spawned={spawned} threads={threads:?} endpoints={endpoints:?}",
            loss == 0
        );
        for (index, row) in rows.into_iter().enumerate() {
            let closed = row.map(|row| (row.counts, row.threads, row.inflight, row.longest));
            let _ = writeln!(
                &mut report,
                "native5-worker-poll index={index} observation={closed:?}"
            );
            for channel in 0..3 {
                let focus = row.map(|row| row.focus[channel]);
                let _ = writeln!(
                    &mut report,
                    "native5-worker-focus worker={index} channel={channel} observation={focus:?}"
                );
            }
        }
        report
    }
}
#[derive(Clone, Copy)]
struct DeliveryRow {
    worker: usize,
    before: Option<u64>,
    after: Option<u64>,
    ok: Option<bool>,
    later: u32,
}
fn longest_insert(rows: &mut [Option<WorkerSample>; 4], sample: WorkerSample) {
    let duration = sample.2 - sample.1;
    if let Some(index) = rows.iter().position(|old| {
        old.is_none_or(|old| {
            duration > old.2 - old.1 || duration == old.2 - old.1 && sample.0 < old.0
        })
    }) {
        for next in (index + 1..4).rev() {
            rows[next] = rows[next - 1];
        }
        rows[index] = Some(sample);
    }
}
pub(crate) struct WorkerPoll {
    probe: Weak<WorkerRecorder>,
    worker: usize,
    ordinal: u64,
}
impl WorkerPoll {
    fn begin(tag: &WorkerTag) -> Option<Self> {
        let active = tag.0.active.load(Ordering::Acquire);
        tag.0
            .mask
            .store(1u32.checked_shl(active).unwrap_or(0), Ordering::Release);
        let probe = active_probe()?.worker.clone();
        if tag.ordinal() >= EXPECTED_WORKERS
            || WORKER_SPAWNS.load(Ordering::Acquire) != EXPECTED_WORKERS
        {
            probe.loss(CAPACITY);
            return None;
        }
        let thread = probe.thread()?;
        let mut selected = None;
        probe.with_row(tag.ordinal(), |row, time| {
            if row.inflight.is_some() || active > 6 {
                probe.loss(IDENTITY);
                return;
            }
            let Some(next) = row.counts[0].checked_add(1).filter(|n| *n <= 1_000_000) else {
                probe.loss(OVERFLOW);
                return;
            };
            row.counts[0] = next;
            row.counts[4] = 1;
            row.threads |= 1u16 << thread;
            row.inflight = Some((next, time, thread, active as u8));
            selected = Some(Self {
                probe: Arc::downgrade(&probe),
                worker: tag.ordinal(),
                ordinal: next,
            });
        });
        selected
    }
    fn finish(self, tag: &WorkerTag, ready: bool) {
        let Some(probe) = self.probe.upgrade() else {
            return;
        };
        let exit = tag.0.active.load(Ordering::Acquire);
        let mask = tag.0.mask.load(Ordering::Acquire);
        probe.with_row(self.worker, |row, end| {
            let Some((ordinal, start, thread, entry)) = row.inflight.take() else {
                probe.loss(IDENTITY);
                return;
            };
            if ordinal != self.ordinal || end < start || exit > 6 || mask > 127 {
                probe.loss(IDENTITY);
                return;
            }
            let duration = end - start;
            let Some(total) = row.counts[5].checked_add(duration) else {
                probe.loss(OVERFLOW);
                return;
            };
            row.counts[4] = 0;
            row.counts[1] += 1;
            row.counts[2 + usize::from(ready)] += 1;
            row.counts[5] = total;
            row.counts[6] = row.counts[6].max(duration);
            let sample = (ordinal, start, end, thread, entry, exit as u8, mask, ready);
            longest_insert(&mut row.longest, sample);
            for index in 0..3 {
                let ack = probe.endpoints[index * 2]
                    .load(Ordering::Acquire)
                    .checked_sub(1);
                let route = probe.endpoints[index * 2 + 1]
                    .load(Ordering::Acquire)
                    .checked_sub(1);
                if let Some(ack) = ack
                    && end >= ack
                    && route.is_none_or(|route| ack <= route && start <= route)
                {
                    longest_insert(&mut row.focus[index], sample);
                }
            }
        });
    }
}
pub(crate) struct DeliveryToken {
    probe: Weak<Probe>,
    index: usize,
    first: bool,
}
pub(in super::super::super) fn first_peer_delivery(
    entry: &SiblingChannel,
    message: &cgka_traits::MessageId,
    worker: usize,
) -> Option<DeliveryToken> {
    let probe = active_probe()?;
    let mut selected = None;
    probe.observe(|data, time| {
        if !owned(data, entry) {
            return;
        }
        let Some(index) = data.slots.iter().position(|slot| {
            slot.as_ref().is_some_and(|slot| {
                same_entry(slot, entry)
                    && slot
                        .peer
                        .as_ref()
                        .and_then(|peer| peer.proof.as_ref())
                        .and_then(|proof| proof.key.as_ref())
                        .is_some_and(|key| &key.message == message)
            })
        }) else {
            return;
        };
        if worker >= 5 {
            probe.worker.loss(CAPACITY);
            return;
        }
        let first = data.worker.deliveries[index].is_none();
        if first {
            data.worker.deliveries[index] = Some(DeliveryRow {
                worker,
                before: time,
                after: None,
                ok: None,
                later: 0,
            });
        } else if let Some(row) = data.worker.deliveries[index].as_mut() {
            if row.worker != worker {
                probe.loss(IDENTITY);
                return;
            }
            increment(&mut row.later, &probe);
        }
        selected = Some(DeliveryToken {
            probe: Arc::downgrade(&probe),
            index,
            first,
        });
    });
    selected
}
impl DeliveryToken {
    pub(crate) fn finish(self, ok: bool) {
        if !self.first {
            return;
        }
        let Some(probe) = self.probe.upgrade() else {
            return;
        };
        probe.observe(|data, time| {
            let Some(row) = data.worker.deliveries[self.index].as_mut() else {
                probe.loss(IDENTITY);
                return;
            };
            if row.after.is_some() {
                probe.loss(DUPLICATE);
                return;
            }
            row.after = time;
            row.ok = Some(ok);
        });
    }
}

struct Data {
    worker: WorkerData,
    owner: Option<Weak<OriginalEnrollmentSharingChoice>>,
    slots: [Option<Slot>; 3],
    rpc: [Option<RpcRow>; 128],
    rpc_count: usize,
    before: Option<u64>,
    after: Option<u64>,
    wait_outcome: Option<bool>,
    wait_observed: Option<u64>,
    // All actors, only terminal/no-publication periodic calls started during
    // the exact fourth wait. Wall time includes preemption, never CPU time.
    terminal_cost: [u64; 8],
    terminal_inflight: u64,
    terminal_bounds: [Option<u64>; 2],
}
impl Default for Data {
    fn default() -> Self {
        Self {
            worker: WorkerData::default(),
            owner: None,
            slots: std::array::from_fn(|_| None),
            rpc: [None; 128],
            rpc_count: 0,
            before: None,
            after: None,
            wait_outcome: None,
            wait_observed: None,
            terminal_cost: [0; 8],
            terminal_inflight: 0,
            terminal_bounds: [None; 2],
        }
    }
}
// Immutable weak bindings are published at existing token boundaries, outside
// native Data locks. Unrelated calls never contend on optional row recording.
#[derive(Clone, Default)]
struct IntakeData {
    selection: [[Option<(u64, u8, u32)>; 3]; 5],
    gates: [Option<GateRow>; 5],
    receipts: [[Option<(u64, bool, u32, u32)>; 3]; 3],
    ingests: [[Option<(u64, Option<u64>, Option<bool>, u32, u32)>; 3]; 2],
    receives: [Option<(Option<u64>, Option<[bool; 3]>, Option<u64>, u32, u32)>; 5],
}
#[derive(Clone, Copy)]
struct GateRow {
    samples: [Option<(u64, bool)>; 16],
    transitions: u32,
    repeated: u32,
    last: bool,
}
struct IntakeLoss {
    count: AtomicU32,
    first: std::sync::atomic::AtomicU64,
    mask: AtomicU32,
}
impl IntakeLoss {
    fn new() -> Self { Self { count: AtomicU32::new(0), first: std::sync::atomic::AtomicU64::new(0), mask: AtomicU32::new(0) } }
    fn record(&self, reason: u32, time: Option<u64>) {
        self.mask.fetch_or(reason | if time.is_none() { OVERFLOW } else { 0 }, Ordering::AcqRel);
        if let Some(time) = time {
            let _ = self.first.compare_exchange(0, time + 1, Ordering::AcqRel, Ordering::Acquire);
        }
        if self.count.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| value.checked_add(1)).is_err() {
            self.mask.fetch_or(OVERFLOW, Ordering::AcqRel);
        }
    }
}
struct IntakeRecorder {
    origin: Instant,
    status: AtomicU32,
    active: AtomicU32,
    owner: OnceLock<Weak<OriginalEnrollmentSharingChoice>>,
    recipient: [OnceLock<Key>; 3],
    peer: [OnceLock<Key>; 3],
    losses: [IntakeLoss; 53],
    data: Mutex<IntakeData>,
}
struct IntakeOperation<'a>(&'a IntakeRecorder);
impl Drop for IntakeOperation<'_> {
    fn drop(&mut self) { self.0.active.fetch_sub(1, Ordering::AcqRel); }
}
impl IntakeRecorder {
    fn new(origin: Instant) -> Self {
        Self { origin, status: AtomicU32::new(0), active: AtomicU32::new(0),
            owner: OnceLock::new(), recipient: std::array::from_fn(|_| OnceLock::new()),
            peer: std::array::from_fn(|_| OnceLock::new()), losses: std::array::from_fn(|_| IntakeLoss::new()),
            data: Mutex::new(IntakeData::default()) }
    }
    fn time(&self) -> Option<u64> {
        Instant::now().checked_duration_since(self.origin)
            .and_then(|duration| u64::try_from(duration.as_micros()).ok()).filter(|time| *time <= MAX_US)
    }
    fn enter(&self) -> Option<IntakeOperation<'_>> {
        if self.status.load(Ordering::Acquire) & FROZEN != 0 { return None; }
        // Only existing bounded actors and publication callbacks enter; never
        // spans an await. Freeze does not wait for this counter to reach zero.
        self.active.fetch_add(1, Ordering::AcqRel);
        let operation = IntakeOperation(self);
        if self.status.load(Ordering::Acquire) & FROZEN != 0 { return None; }
        Some(operation)
    }
    fn loss(&self, slot: usize, reason: u32) {
        if let Some(row) = self.losses.get(slot) { row.record(reason, self.time()); }
    }
    fn observe(&self, slot: usize, operation: impl FnOnce(&mut IntakeData, u64)) {
        let Some(_operation) = self.enter() else { return; };
        let mut data = match self.data.try_lock() {
            Ok(data) => data,
            Err(TryLockError::WouldBlock) => { self.loss(slot, LOCK_BUSY); return; }
            Err(TryLockError::Poisoned(_)) => { self.loss(slot, LOCK_POISONED); return; }
        };
        let Some(time) = self.time() else { self.loss(slot, OVERFLOW); return; };
        operation(&mut data, time);
    }
    fn increment(&self, slot: usize, counter: &mut u32) {
        if let Some(next) = counter.checked_add(1) { *counter = next; }
        else { self.loss(slot, OVERFLOW); }
    }
    fn owner_matches(&self, current: Option<&Arc<OriginalEnrollmentSharingChoice>>) -> bool {
        self.owner.get().is_some_and(|owner| current.is_some_and(|current| owner.ptr_eq(&Arc::downgrade(current))))
    }
    fn peer_index(&self, message: &cgka_traits::MessageId) -> Option<usize> {
        self.peer.iter().position(|key| key.get().is_some_and(|key| &key.message == message))
    }
    fn bind_owner(&self, owner: Weak<OriginalEnrollmentSharingChoice>) {
        let Some(_operation) = self.enter() else { return; };
        if let Err(owner) = self.owner.set(owner) {
            if !self.owner.get().is_some_and(|old| old.ptr_eq(&owner)) { self.loss(0, IDENTITY); }
        }
    }
    fn bind_key(&self, index: usize, key: &Key, peer: bool) {
        let Some(_operation) = self.enter() else { return; };
        let loss_slot = if peer { 4 + index.min(2) } else { 1 + index.min(2) };
        let keys = if peer { &self.peer } else { &self.recipient };
        let Some(slot) = keys.get(index) else { self.loss(loss_slot, CAPACITY); return; };
        if let Err(key) = slot.set(key.clone()) {
            if !slot.get().is_some_and(|old| old.state.ptr_eq(&key.state) && old.nonce == key.nonce && old.message == key.message) {
                self.loss(loss_slot, IDENTITY);
            }
        }
    }
    fn report(&self, native_ids: &[Option<cgka_traits::MessageId>; 3], native_snapshot: bool) -> String {
        use std::fmt::Write as _;
        self.status.fetch_or(FROZEN, Ordering::AcqRel);
        // No waiting: a live operation makes all absence/completeness claims
        // unknown. Positive atomic loss fields remain supplemental observations.
        let inflight = self.active.load(Ordering::Acquire);
        let snapshot = match self.data.try_lock() {
            Ok(data) => Some(data.clone()),
            Err(error) => { self.loss(52, match error { TryLockError::WouldBlock => LOCK_BUSY, TryLockError::Poisoned(_) => LOCK_POISONED }); None }
        };
        if native_snapshot && self.peer.iter().zip(native_ids).any(|(key, id)| key.get().map(|key| &key.message) != id.as_ref()) { self.loss(52, IDENTITY); }
        let losses: [(u32, Option<u64>, u32); 53] = std::array::from_fn(|index| {
            let row = &self.losses[index];
            (row.count.load(Ordering::Acquire), row.first.load(Ordering::Acquire).checked_sub(1), row.mask.load(Ordering::Acquire))
        });
        let loss = losses.iter().fold(0, |mask, row| mask | row.2);
        let available = snapshot.is_some();
        let owner_bound = available && self.owner.get().is_some();
        let bound: [Option<bool>; 3] = std::array::from_fn(|index| available.then(|| self.peer[index].get().is_some()));
        let mut output = String::new();
        let _ = writeln!(&mut output, "native5-intake-meta known={} loss_mask={loss} snapshot_available={available} owner_bound={owner_bound} source_id_bound={bound:?} inflight_at_freeze={inflight}", available && loss == 0 && inflight == 0);
        for worker in 0..5 { for channel in 0..3 {
            let row = snapshot.as_ref().and_then(|data| data.selection[worker][channel]);
            let _ = writeln!(&mut output, "native5-intake-selection worker={worker} channel={channel} observation={row:?}");
        } }
        for worker in 0..5 {
            let row = snapshot.as_ref().and_then(|data| data.gates[worker].map(|row| (row.samples, row.transitions, row.repeated)));
            let _ = writeln!(&mut output, "native5-intake-gate worker={worker} observation={row:?}");
        }
        for path in 0..3 { for channel in 0..3 {
            let row = snapshot.as_ref().and_then(|data| data.receipts[path][channel]);
            let _ = writeln!(&mut output, "native5-intake-receipt path={path} channel={channel} observation={row:?}");
        } }
        for path in 0..2 { for channel in 0..3 {
            let row = snapshot.as_ref().and_then(|data| data.ingests[path][channel]);
            let _ = writeln!(&mut output, "native5-intake-ingest path={path} channel={channel} observation={row:?}");
        } }
        for worker in 0..5 {
            let row = snapshot.as_ref().and_then(|data| data.receives[worker]);
            let _ = writeln!(&mut output, "native5-intake-receive worker={worker} observation={row:?}");
        }
        for (slot, (count, first, mask)) in losses.into_iter().enumerate() {
            let _ = writeln!(&mut output, "native5-intake-loss slot={slot} count={count} first_us={first:?} mask={mask}");
        }
        output
    }
}
pub(in super::super::super) fn intake_selected(
    current: Option<&Arc<OriginalEnrollmentSharingChoice>>, entries: &[SiblingChannel], message: &cgka_traits::MessageId, worker: usize,
) {
    let Some(probe) = active_probe() else { return; };
    let Some(index) = probe.intake.peer_index(message) else { return; };
    let loss_slot = 7 + worker.min(4) * 3 + index;
    let reason = match current {
        None => 1,
        Some(current) if probe.intake.owner_matches(Some(current)) => {
            if probe.intake.recipient[index].get().is_some_and(|key| entries.iter().any(|entry| {
                key.state.ptr_eq(&Arc::downgrade(&entry.state)) && key.nonce == entry.channel.scope().nonce
                && matches!(entry.original.as_ref(), SiblingOriginal::Recipient { choice, .. } if Arc::ptr_eq(choice, current))
            })) { 0 } else { 3 }
        }
        _ => 2,
    };
    probe.intake.observe(loss_slot, |data, time| {
        if worker >= 5 { probe.intake.loss(loss_slot, CAPACITY); return; }
        if let Some(row) = &mut data.selection[worker][index] { probe.intake.increment(loss_slot, &mut row.2); }
        else { data.selection[worker][index] = Some((time, reason, 0)); }
    });
}
pub(in super::super::super) fn intake_gate(current: Option<&Arc<OriginalEnrollmentSharingChoice>>, worker: usize, enabled: bool) {
    let Some(probe) = active_probe() else { return; };
    if !probe.intake.owner_matches(current) { return; }
    let loss_slot = 22 + worker.min(4);
    probe.intake.observe(loss_slot, |data, time| {
        let Some(slot) = data.gates.get_mut(worker) else { probe.intake.loss(loss_slot, CAPACITY); return; };
        let row = slot.get_or_insert(GateRow { samples: [None; 16], transitions: 0, repeated: 0, last: enabled });
        let length = row.samples.iter().take_while(|sample| sample.is_some()).count();
        if length == 0 { row.samples[0] = Some((time, enabled)); }
        else if row.last == enabled { probe.intake.increment(loss_slot, &mut row.repeated); }
        else { probe.intake.increment(loss_slot, &mut row.transitions); if length < 16 { row.samples[length] = Some((time, enabled)); } else { probe.intake.loss(loss_slot, CAPACITY); } }
        row.last = enabled;
    });
}
#[derive(Clone)]
pub(crate) struct IntakeToken { probe: Weak<Probe>, index: usize }
pub(in super::super::super) fn intake_token(current: Option<&Arc<OriginalEnrollmentSharingChoice>>, message: &cgka_traits::MessageId) -> Option<IntakeToken> {
    let probe = active_probe()?;
    if !probe.intake.owner_matches(current) { return None; }
    let index = probe.intake.peer_index(message)?;
    Some(IntakeToken { probe: Arc::downgrade(&probe), index })
}
impl IntakeToken {
    pub(crate) fn receipt(&self, path: usize, already_held: bool) {
        let Some(probe) = self.probe.upgrade() else { return; };
        let loss_slot = 27 + path.min(2) * 3 + self.index;
        probe.intake.observe(loss_slot, |data, time| {
            let Some(rows) = data.receipts.get_mut(path) else { probe.intake.loss(loss_slot, CAPACITY); return; };
            if let Some(row) = &mut rows[self.index] { probe.intake.increment(loss_slot, if already_held { &mut row.2 } else { &mut row.3 }); }
            else { rows[self.index] = Some((time, already_held, 0, 0)); }
        });
    }
    pub(crate) fn begin_ingest(&self, path: usize) -> Option<IntakeIngest> {
        let probe = self.probe.upgrade()?;
        let loss_slot = 36 + path.min(1) * 3 + self.index;
        let mut first = None;
        probe.intake.observe(loss_slot, |data, time| {
            let Some(rows) = data.ingests.get_mut(path) else { probe.intake.loss(loss_slot, CAPACITY); return; };
            if let Some(row) = &mut rows[self.index] { probe.intake.increment(loss_slot, &mut row.3); first = Some(false); }
            else { rows[self.index] = Some((time, None, None, 0, 0)); first = Some(true); }
        });
        Some(IntakeIngest { token: self.clone(), path, first: first? })
    }
}
pub(crate) struct IntakeIngest { token: IntakeToken, path: usize, first: bool }
impl IntakeIngest {
    pub(crate) fn finish(&self, ok: bool) {
        let Some(probe) = self.token.probe.upgrade() else { return; };
        let loss_slot = 36 + self.path * 3 + self.token.index;
        probe.intake.observe(loss_slot, |data, time| {
            let Some(row) = data.ingests[self.path][self.token.index].as_mut() else { probe.intake.loss(loss_slot, IDENTITY); return; };
            if self.first {
                if row.1.is_some() { probe.intake.loss(loss_slot, IDENTITY); return; }
                row.1 = Some(time); row.2 = Some(ok);
            } else { probe.intake.increment(loss_slot, &mut row.4); }
        });
    }
}
pub(in super::super::super) fn intake_receipt(current: Option<&Arc<OriginalEnrollmentSharingChoice>>, message: &cgka_traits::MessageId, path: usize, already_held: bool) {
    if let Some(token) = intake_token(current, message) { token.receipt(path, already_held); }
}
pub(in super::super::super) fn intake_receive(current: Option<&Arc<OriginalEnrollmentSharingChoice>>, worker: usize, stage: usize, retries: Option<[bool; 3]>) {
    let Some(probe) = active_probe() else { return; };
    if !probe.intake.owner_matches(current) { return; }
    let loss_slot = 42 + worker.min(4) * 2 + stage.min(1);
    probe.intake.observe(loss_slot, |data, time| {
        if worker >= 5 || stage > 1 || (stage == 0) != retries.is_some() { probe.intake.loss(loss_slot, IDENTITY); return; }
        let row = data.receives[worker].get_or_insert((None, None, None, 0, 0));
        if stage == 0 {
            if row.0.is_none() { row.0 = Some(time); row.1 = retries; }
            else { probe.intake.increment(loss_slot, &mut row.3); }
        } else if row.2.is_none() { row.2 = Some(time); }
        else { probe.intake.increment(loss_slot, &mut row.4); }
    });
}

struct Probe {
    worker: Arc<WorkerRecorder>,
    intake: IntakeRecorder,
    sdk: transport_nostr_adapter::sdk_publication_timing::Guard,
    origin: Instant,
    status: AtomicU32,
    data: Mutex<Data>,
}
struct Registry {
    slots: [OnceLock<Weak<Probe>>; 2],
    next: std::sync::atomic::AtomicUsize,
    active: std::sync::atomic::AtomicUsize,
}
fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry {
        slots: [OnceLock::new(), OnceLock::new()],
        next: std::sync::atomic::AtomicUsize::new(0),
        active: std::sync::atomic::AtomicUsize::new(2),
    })
}
fn active_probe() -> Option<Arc<Probe>> {
    let registry = registry();
    let index = registry.active.load(Ordering::Acquire);
    let probe = registry.slots.get(index)?.get()?.upgrade()?;
    (probe.status.load(Ordering::Acquire) & FROZEN == 0).then_some(probe)
}
fn register(probe: &Arc<Probe>) {
    let registry = registry();
    let index = registry
        .next
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
            if next < 2 { Some(next + 1) } else { None }
        })
        .unwrap_or(2);
    let Some(slot) = registry.slots.get(index) else {
        probe.loss(4);
        return;
    };
    if slot.set(Arc::downgrade(probe)).is_err() {
        probe.loss(64);
        return;
    }
    // Publish only after this immutable weak slot is initialized. No reuse/wrap.
    registry.active.store(index, Ordering::Release);
}

impl Probe {
    fn loss(&self, reason: u32) {
        let _ = self
            .status
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                (value & FROZEN == 0).then_some(value | reason)
            });
    }
    fn elapsed(&self) -> Option<u64> {
        let value = self.origin.elapsed().as_micros();
        if value > u128::from(MAX_US) {
            self.loss(OVERFLOW);
            None
        } else {
            Some(value as u64)
        }
    }
    fn observe(&self, apply: impl FnOnce(&mut Data, Option<u64>)) {
        if self.status.load(Ordering::Acquire) & FROZEN != 0 {
            return;
        }
        match self.data.try_lock() {
            Ok(mut data) => {
                if self.status.load(Ordering::Acquire) & FROZEN == 0 {
                    apply(&mut data, self.elapsed());
                }
            }
            Err(TryLockError::WouldBlock) => self.loss(LOCK_BUSY),
            Err(TryLockError::Poisoned(_)) => self.loss(LOCK_POISONED),
        }
    }
}
// Closed global aggregate on the same active weak trace; no account IDs.
pub(in super::super::super) struct TerminalValidation {
    probe: Weak<Probe>,
    started: u64,
}
pub(in super::super::super) fn terminal_validation(
    entry: &SiblingChannel,
    periodic: bool,
) -> Option<TerminalValidation> {
    if !periodic || entry.publication.is_some() {
        return None;
    }
    let probe = active_probe()?;
    let mut active = false;
    probe.observe(|data, _| {
        active = data.after.is_some() && data.wait_observed.is_none();
    });
    if !active {
        return None;
    }
    let complete = match entry.state.progress.try_lock() {
        Ok(progress) => progress.complete,
        Err(TryLockError::WouldBlock) => {
            probe.loss(LOCK_BUSY);
            return None;
        }
        Err(TryLockError::Poisoned(_)) => {
            probe.loss(LOCK_POISONED);
            return None;
        }
    };
    if !complete {
        return None;
    }
    let mut started = None;
    probe.observe(|data, time| {
        if data.after.is_none() || data.wait_observed.is_some() {
            return;
        }
        let Some(time) = time else {
            return;
        };
        if data.terminal_cost[0] >= 1_000_000 {
            probe.loss(OVERFLOW);
            return;
        }
        data.terminal_cost[0] += 1;
        data.terminal_inflight += 1;
        data.terminal_bounds[0].get_or_insert(time);
        started = Some(time);
    });
    started.map(|started| TerminalValidation {
        probe: Arc::downgrade(&probe),
        started,
    })
}
impl TerminalValidation {
    pub(in super::super::super) fn finish(self, error: bool) {
        let Some(probe) = self.probe.upgrade() else {
            return;
        };
        probe.observe(|data, time| {
            let Some(end) = time else {
                return;
            };
            let Some(duration) = end.checked_sub(self.started) else {
                probe.loss(OVERFLOW);
                return;
            };
            let Some(total) = data.terminal_cost[3]
                .checked_add(duration)
                .filter(|v| *v <= MAX_US)
            else {
                probe.loss(OVERFLOW);
                return;
            };
            if data.terminal_inflight == 0 {
                probe.loss(IDENTITY);
                return;
            }
            data.terminal_inflight -= 1;
            data.terminal_cost[1] += 1;
            data.terminal_cost[2] += u64::from(error);
            data.terminal_cost[3] = total;
            data.terminal_cost[4] = data.terminal_cost[4].max(duration);
            data.terminal_bounds[1] = Some(end);
            // Entire call definitely between constructed timeout and its
            // earliest possible deadline, not an inferred exact deadline.
            if data.after.is_some_and(|after| self.started >= after)
                && data
                    .before
                    .and_then(|before| before.checked_add(15_000_000))
                    .is_some_and(|lower| end < lower)
            {
                data.terminal_cost[5] += 1;
                data.terminal_cost[6] += duration;
                data.terminal_cost[7] = data.terminal_cost[7].max(duration);
            }
        });
    }
}
pub(crate) struct Guard(Arc<Probe>);
pub(crate) fn arm() -> (Guard, Pending) {
    let origin = Instant::now();
    let probe = Arc::new(Probe {
        worker: Arc::new(WorkerRecorder::new(origin)),
        intake: IntakeRecorder::new(origin),
        sdk: transport_nostr_adapter::sdk_publication_timing::Guard::arm(origin),
        status: AtomicU32::new(0),
        origin,
        data: Mutex::new(Data::default()),
    });
    register(&probe);
    let pending = Pending(Arc::downgrade(&probe));
    (Guard(probe), pending)
}
// This opaque weak registration belongs to native SessionState. It never holds
// or names SessionState here, and never retains a real original across an await.
#[derive(Clone)]
pub(crate) struct Pending(Weak<Probe>);
impl Pending {
    pub(crate) fn bind(&self, owner: Weak<OriginalEnrollmentSharingChoice>) {
        let Some(probe) = self.0.upgrade() else {
            return;
        };
        probe.observe(|data, _| {
            if let Some(old) = &data.owner {
                // The real continuation can present its SAME original again.
                // Idempotent binding never retries or creates protocol work.
                if !old.ptr_eq(&owner) {
                    probe.loss(IDENTITY);
                }
            } else {
                data.owner = Some(owner.clone());
            }
        });
        probe.intake.bind_owner(owner);
    }
    pub(crate) fn registration_failed(&self, poisoned: bool) {
        if let Some(probe) = self.0.upgrade() {
            probe.loss(if poisoned { LOCK_POISONED } else { LOCK_BUSY });
        }
    }
    pub(crate) fn duplicate_registration(&self) {
        if let Some(probe) = self.0.upgrade() {
            probe.loss(DUPLICATE);
        }
    }
    pub(crate) fn identity_failed(&self) {
        if let Some(probe) = self.0.upgrade() {
            probe.loss(IDENTITY);
        }
    }
    pub(crate) fn rpc(&self) -> Option<Rpc> {
        let probe = self.0.upgrade()?;
        let mut selected = None;
        probe.observe(|data, time| {
            let index = data.rpc_count;
            if index >= data.rpc.len() {
                probe.loss(CAPACITY);
                return;
            }
            data.rpc[index] = Some(RpcRow {
                times: [time, None, None, None, None],
                results: [None; 2],
                sent: None,
            });
            data.rpc_count += 1;
            selected = Some(Rpc {
                probe: Arc::downgrade(&probe),
                index,
            });
        });
        selected
    }
    pub(crate) fn wait_before(&self) -> Option<Wait> {
        let probe = self.0.upgrade()?;
        probe.observe(|data, time| {
            if data.before.is_some() {
                probe.loss(DUPLICATE);
            } else {
                data.before = time;
            }
        });
        Some(Wait(Arc::downgrade(&probe)))
    }
}
pub(crate) fn registration_unavailable(poisoned: bool) {
    if let Some(probe) = active_probe() {
        probe.loss(if poisoned { LOCK_POISONED } else { LOCK_BUSY });
    }
}
#[derive(Clone)]
pub(crate) struct Token {
    probe: Weak<Probe>,
    index: usize,
    key: Key,
    proof: bool,
    peer: bool,
}
impl Token {
    fn bind_sdk(&self) {
        if let Some(probe) = self.probe.upgrade() {
            probe.sdk.bind(
                if self.peer {
                    6 + self.index
                } else {
                    self.index * 2 + usize::from(self.proof)
                },
                self.key.message.as_slice(),
            );
            // No native Data lock is held at this existing token boundary.
            if self.peer || !self.proof {
                probe.intake.bind_key(self.index, &self.key, self.peer);
            }
        }
    }
    pub(in super::super::super) fn spawn_boundary(&self, index: usize) {
        if !self.proof {
            return;
        }
        let Some(probe) = self.probe.upgrade() else {
            return;
        };
        probe.observe(|data, time| {
            let Some(slot) = data.slots.get_mut(self.index).and_then(Option::as_mut) else {
                probe.loss(IDENTITY);
                return;
            };
            let candidate = if self.peer {
                slot.peer.as_mut().and_then(|peer| peer.proof.as_mut())
            } else {
                slot.proof.as_mut()
            };
            let Some(proof) = candidate else {
                probe.loss(IDENTITY);
                return;
            };
            if !proof
                .key
                .as_ref()
                .is_some_and(|key| key.same_attempt(&self.key))
            {
                probe.loss(IDENTITY);
                return;
            }
            let Some(field) = proof.spawn_boundaries.get_mut(index) else {
                probe.loss(IDENTITY);
                return;
            };
            if field.is_some() {
                probe.loss(DUPLICATE);
            } else {
                *field = time;
            }
        });
    }

    pub(in super::super::super) fn stage(&self, index: usize, outcome: Option<(usize, bool)>) {
        let Some(probe) = self.probe.upgrade() else {
            return;
        };
        probe.observe(|data, time| {
            let Some(slot) = data.slots.get_mut(self.index).and_then(Option::as_mut) else {
                probe.loss(IDENTITY);
                return;
            };
            let Some((key, times, outcomes)) = slot.publication_mut(self.proof, self.peer) else {
                probe.loss(IDENTITY);
                return;
            };
            if !key.same_attempt(&self.key) || index >= times.len() {
                probe.loss(IDENTITY);
                return;
            }
            if times[index].is_some() {
                probe.loss(DUPLICATE);
                return;
            }
            times[index] = time;
            if self.peer && index == 5 {
                if let Some(time) = time {
                    probe.worker.endpoint(self.index, 0, time);
                }
            }
            if let Some((field, value)) = outcome {
                if let Some(destination) = outcomes.get_mut(field) {
                    *destination = Some(value);
                } else {
                    probe.loss(IDENTITY);
                }
            }
        });
    }
    pub(in super::super::super) fn report(&self, ok: bool, met: Option<bool>) {
        let Some(probe) = self.probe.upgrade() else {
            return;
        };
        probe.observe(|data, time| {
            let Some(slot) = data.slots.get_mut(self.index).and_then(Option::as_mut) else {
                probe.loss(IDENTITY);
                return;
            };
            let Some((key, times, outcomes)) = slot.publication_mut(self.proof, self.peer) else {
                probe.loss(IDENTITY);
                return;
            };
            if !key.same_attempt(&self.key) {
                probe.loss(IDENTITY);
                return;
            }
            if times[4].is_some() {
                probe.loss(DUPLICATE);
                return;
            }
            times[4] = time;
            outcomes[0] = Some(ok);
            outcomes[1] = met;
        });
    }
}
// Weak-only correlation exists before sealing; it cannot create a control,
// request, receipt or permission. Failed first attempts are never overwritten.
#[derive(Clone)]
pub(crate) struct ProofAttempt {
    probe: Weak<Probe>,
    index: usize,
    channel: Key,
}
impl ProofAttempt {
    pub(in super::super::super) fn boundary(&self, index: usize) {
        let Some(probe) = self.probe.upgrade() else {
            return;
        };
        probe.observe(|data, time| {
            let Some(slot) = data.slots.get_mut(self.index).and_then(Option::as_mut) else {
                probe.loss(IDENTITY);
                return;
            };
            if !slot.key.same_channel(&self.channel) {
                probe.loss(IDENTITY);
                return;
            }
            let Some(proof) = slot.proof.as_mut() else {
                probe.loss(IDENTITY);
                return;
            };
            let Some(field) = proof.preparation.get_mut(index) else {
                probe.loss(IDENTITY);
                return;
            };
            if field.is_some() {
                probe.loss(DUPLICATE);
            } else {
                *field = time;
            }
        });
    }
    fn prepared(
        &self,
        entry: &SiblingChannel,
        request: &cgka_traits::TransportPublishRequest,
    ) -> Option<Token> {
        let probe = self.probe.upgrade()?;
        let mut selected = None;
        probe.observe(|data, time| {
            if !owned(data, entry) {
                probe.loss(IDENTITY);
                return;
            }
            let Some(slot) = data.slots.get_mut(self.index).and_then(Option::as_mut) else {
                probe.loss(IDENTITY);
                return;
            };
            if !same_entry(slot, entry) || !slot.key.same_channel(&self.channel) {
                probe.loss(IDENTITY);
                return;
            }
            let Some(proof) = slot.proof.as_mut() else {
                probe.loss(IDENTITY);
                return;
            };
            if proof.key.is_some() {
                probe.loss(DUPLICATE);
                return;
            }
            let key = Key {
                state: self.channel.state.clone(),
                nonce: self.channel.nonce,
                message: request.message.id.clone(),
            };
            proof.key = Some(key.clone());
            proof.times[0] = time;
            selected = Some(Token {
                probe: Arc::downgrade(&probe),
                index: self.index,
                key,
                proof: true,
                peer: false,
            });
        });
        selected.map(|token| {
            token.bind_sdk();
            token
        })
    }
}
fn same_entry(slot: &Slot, entry: &SiblingChannel) -> bool {
    slot.key.state.ptr_eq(&Arc::downgrade(&entry.state))
        && slot.key.nonce == entry.channel.scope().nonce
}
fn owned(data: &Data, entry: &SiblingChannel) -> bool {
    entry.recipient
        && matches!(entry.original.as_ref(), SiblingOriginal::Recipient { choice, .. }
        if data.owner.as_ref().is_some_and(|owner| owner.ptr_eq(&Arc::downgrade(choice))))
}
fn increment(value: &mut u32, probe: &Probe) {
    if let Some(next) = value.checked_add(1) {
        *value = next;
    } else {
        *value = u32::MAX;
        probe.loss(OVERFLOW);
    }
}
pub(in super::super::super) fn progress(entry: &SiblingChannel, index: usize) {
    if !entry.recipient {
        if index < 3 {
            peer_progress(entry, index + 4);
        }
        return;
    }
    let Some(probe) = active_probe() else {
        return;
    };
    probe.observe(|data, time| {
        if !owned(data, entry) {
            return;
        }
        let Some(slot) = data
            .slots
            .iter_mut()
            .flatten()
            .find(|slot| same_entry(slot, entry))
        else {
            probe.loss(IDENTITY);
            return;
        };
        let Some(field) = slot.progress.get_mut(index) else {
            probe.loss(IDENTITY);
            return;
        };
        if field.is_some() {
            increment(&mut slot.progress_repeats[index], &probe);
        } else {
            *field = time;
        }
    });
}
fn begin_owned_proof(entry: &SiblingChannel) -> Option<ProofAttempt> {
    let probe = active_probe()?;
    let mut selected = None;
    probe.observe(|data, time| {
        if !owned(data, entry) {
            return;
        }
        let Some(index) = data
            .slots
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|slot| same_entry(slot, entry)))
        else {
            probe.loss(IDENTITY);
            return;
        };
        let Some(slot) = data.slots[index].as_mut() else {
            probe.loss(IDENTITY);
            return;
        };
        if let Some(proof) = &mut slot.proof {
            increment(&mut proof.subsequent_attempts, &probe);
            return;
        }
        slot.proof = Some(Proof {
            key: None,
            times: [None; 9],
            outcomes: [None; 5],
            preparation: [time, None, None, None],
            spawn_boundaries: [None; 6],
            subsequent_attempts: 0,
        });
        selected = Some(ProofAttempt {
            probe: Arc::downgrade(&probe),
            index,
            channel: slot.key.clone(),
        });
    });
    selected
}

pub(in super::super::super) fn prepared(
    entry: &SiblingChannel,
    request: &cgka_traits::TransportPublishRequest,
    kind: AccountSharingControl,
    proof_attempt: Option<&PublicationAttempt>,
) -> Option<Token> {
    if kind == AccountSharingControl::Body(0) {
        return proof_attempt.and_then(|attempt| attempt.prepared(entry, request));
    }
    if !entry.recipient || kind != AccountSharingControl::Consent {
        return None;
    }
    let SiblingOriginal::Recipient { choice, .. } = entry.original.as_ref() else {
        return None;
    };
    let probe = active_probe()?;
    let key = Key {
        state: Arc::downgrade(&entry.state),
        nonce: entry.channel.scope().nonce,
        message: request.message.id.clone(),
    };
    let mut selected = None;
    probe.observe(|data, time| {
        if !data
            .owner
            .as_ref()
            .is_some_and(|owner| owner.ptr_eq(&Arc::downgrade(choice)))
        {
            return;
        }
        if let Some(slot) = data
            .slots
            .iter_mut()
            .flatten()
            .find(|slot| slot.key.same_channel(&key))
        {
            // Follow only the first actual attempt. Retries cannot overwrite it.
            if let Some(next) = slot.retry_prepared.checked_add(1) {
                slot.retry_prepared = next;
            } else {
                slot.retry_prepared = u32::MAX;
                probe.loss(OVERFLOW);
            }
            return;
        }
        let Some(index) = data.slots.iter().position(Option::is_none) else {
            probe.loss(CAPACITY);
            return;
        };
        let mut times = [None; 9];
        times[0] = time;
        data.slots[index] = Some(Slot {
            common: CommonScope::new(entry.channel.scope()),
            peer: None,
            incoming: std::array::from_fn(|_| None),
            key: key.clone(),
            times,
            outcomes: [None; 5],
            retry_prepared: 0,
            proof: None,
            progress: [None; 5],
            progress_repeats: [0; 5],
        });
        selected = Some(Token {
            probe: Arc::downgrade(&probe),
            index,
            key: key.clone(),
            proof: false,
            peer: false,
        });
    });
    selected.map(|token| {
        token.bind_sdk();
        token
    })
}
pub(crate) fn armed() -> bool {
    active_probe().is_some()
}
pub(crate) struct Wait(Weak<Probe>);
impl Wait {
    pub(crate) fn constructed(&self) {
        if let Some(probe) = self.0.upgrade() {
            probe.observe(|data, time| {
                if data.after.is_some() {
                    probe.loss(DUPLICATE);
                } else {
                    data.after = time;
                }
            });
        }
    }
    pub(crate) fn observed(&self, ok: bool) {
        if let Some(probe) = self.0.upgrade() {
            probe.observe(|data, time| {
                if data.wait_observed.is_some() {
                    probe.loss(DUPLICATE);
                } else {
                    data.wait_outcome = Some(ok);
                    data.wait_observed = time;
                }
            });
        }
    }
}
// Same opaque token travels only on the already-existing exact Observe RPC.
// It cannot construct a command, retain a SessionState, or grant any authority.
#[derive(Clone)]
pub(crate) struct Rpc {
    probe: Weak<Probe>,
    index: usize,
}
type ObservationResult = Result<
    (
        crate::DeviceLinkingPhase,
        Option<crate::DeviceLinkingDecimals>,
    ),
    crate::client::device_linking::ClientLinkingError,
>;
fn result_category(result: &ObservationResult) -> u8 {
    use crate::DeviceLinkingPhase as P;
    match result {
        Ok((phase, _)) => match phase {
            P::AwaitingSetup => 0,
            P::AwaitingPeer => 1,
            P::ComparisonAvailable => 2,
            P::AwaitingPeerVerification => 3,
            P::VerificationCompleteEnrollmentPending => 4,
            P::Cancelled => 5,
            P::Expired => 6,
            P::Failed => 7,
            P::EnrollmentComplete => 8,
        },
        Err(crate::client::device_linking::ClientLinkingError::Runtime(error))
            if matches!(
                error.as_ref(),
                crate::AppError::AccountWorkerResponseTimedOut
            ) =>
        {
            9
        }
        Err(_) => 10,
    }
}
impl Rpc {
    fn record(&self, stage: usize, result: Option<u8>, sent: Option<bool>) {
        let Some(probe) = self.probe.upgrade() else {
            return;
        };
        probe.observe(|data, time| {
            let Some(row) = data.rpc.get_mut(self.index).and_then(Option::as_mut) else {
                probe.loss(IDENTITY);
                return;
            };
            if stage >= row.times.len() || row.times[stage].is_some() {
                probe.loss(DUPLICATE);
                return;
            }
            row.times[stage] = time;
            if stage == 2 {
                row.results[0] = result;
            }
            if stage == 3 {
                row.sent = sent;
            }
            if stage == 4 {
                row.results[1] = result;
            }
        });
    }
    pub(crate) fn stage(&self, stage: usize) {
        self.record(stage, None, None);
    }
    pub(crate) fn worker_returned(&self, result: &ObservationResult) {
        self.record(2, Some(result_category(result)), None);
    }
    pub(crate) fn sent(&self, accepted: bool) {
        self.record(3, None, Some(accepted));
    }
    pub(crate) fn facade(&self, result: &ObservationResult) {
        self.record(4, Some(result_category(result)), None);
    }
}
impl Guard {
    // Freeze and copy first, release the try-lock, then serialize bounded closed
    // values. Only the recognized test fixture emits this returned text.
    pub(crate) fn freeze(
        self,
        observe_notifications: impl FnOnce(
            Instant,
            [Option<cgka_traits::MessageId>; 3],
        )
            -> [[(Option<[u64; 8]>, Option<[Option<u64>; 8]>, Option<u8>, Option<[u64; 6]>, Option<[Option<u64>; 6]>, Option<u8>); 3]; 5],
    ) -> String {
        use std::fmt::Write as _;
        let worker_report = self.0.worker.report();
        let sdk_report = self.0.sdk.freeze();
        let mut output = String::with_capacity(65536);
        let old = self.0.status.fetch_or(FROZEN, Ordering::AcqRel);
        // Copy only closed aggregates; print after the lock has been dropped.
        let mut peer_outer_ids = std::array::from_fn::<_, 3, _>(|_| None);
        let snapshot = match self.0.data.try_lock() {
            Ok(data) => {
                // Copy the first actual outer IDs in this SAME snapshot. These
                // locators carry no state/authority and never enter the report.
                peer_outer_ids = std::array::from_fn(|index| {
                    data.slots[index]
                        .as_ref()
                        .and_then(|slot| slot.peer.as_ref())
                        .and_then(|peer| peer.proof.as_ref())
                        .and_then(|proof| proof.key.as_ref())
                        .map(|key| key.message.clone())
                });
                Some((
                    data.before,
                    data.after,
                    data.wait_outcome,
                    data.wait_observed,
                    data.owner.is_some(),
                    std::array::from_fn::<_, 3, _>(|index| {
                        data.slots[index]
                            .as_ref()
                            .map(|slot| (slot.times, slot.outcomes, slot.retry_prepared))
                    }),
                    data.rpc,
                    data.rpc_count,
                    std::array::from_fn::<_, 3, _>(|index| {
                        data.slots[index].as_ref().and_then(|slot| {
                            slot.proof.as_ref().map(|proof| {
                                (
                                    proof.key.is_some(),
                                    proof.times,
                                    proof.outcomes,
                                    proof.preparation,
                                    proof.subsequent_attempts,
                                    proof.spawn_boundaries,
                                )
                            })
                        })
                    }),
                    std::array::from_fn::<_, 3, _>(|index| {
                        data.slots[index]
                            .as_ref()
                            .map(|slot| (slot.progress, slot.progress_repeats))
                    }),
                    (
                        data.terminal_cost,
                        data.terminal_inflight,
                        data.terminal_bounds,
                    ),
                    std::array::from_fn::<_, 3, _>(|index| {
                        data.slots[index]
                            .as_ref()
                            .and_then(|slot| slot.peer.as_ref())
                            .and_then(|peer| peer.proof.as_ref())
                            .map(|proof| {
                                (
                                    proof.key.is_some(),
                                    proof.times,
                                    proof.outcomes,
                                    proof.preparation,
                                    proof.subsequent_attempts,
                                    proof.spawn_boundaries,
                                )
                            })
                    }),
                    std::array::from_fn::<_, 3, _>(|index| {
                        data.slots[index]
                            .as_ref()
                            .and_then(|slot| slot.peer.as_ref())
                            .map(|peer| {
                                (
                                    peer.progress,
                                    peer.repeats,
                                    peer.bind_results,
                                    peer.validation_results,
                                )
                            })
                    }),
                    std::array::from_fn::<_, 9, _>(|index| {
                        data.slots[index / 3]
                            .as_ref()
                            .and_then(|slot| slot.incoming[index % 3].as_ref())
                            .map(|row| {
                                (
                                    row.times,
                                    row.opened_ok,
                                    row.disposition,
                                    row.later_routes,
                                    row.first_successful_accept,
                                )
                            })
                    }),
                    data.worker.deliveries.map(|row| {
                        row.map(|row| (row.worker, row.before, row.after, row.ok, row.later))
                    }),
                ))
            }
            Err(TryLockError::WouldBlock) => None,
            Err(TryLockError::Poisoned(_)) => None,
        };
        let source_ids_snapshot_available = snapshot.is_some();
        let source_id_bound = std::array::from_fn::<_, 3, _>(|index| {
            source_ids_snapshot_available.then_some(peer_outer_ids[index].is_some())
        });
        let mut loss = old & !FROZEN;
        if snapshot.as_ref().is_some_and(|row| !row.4) {
            loss |= ARM_UNAVAILABLE;
        }
        if snapshot.is_none() {
            // Snapshot failure is explicitly unknown; never a partial zero matrix.
            loss |= LOCK_BUSY;
            if self.0.data.is_poisoned() {
                loss |= LOCK_POISONED;
            }
        }
        let _ = writeln!(
            &mut output,
            "native5-consent-timing known={} loss_mask={} snapshot_available={}",
            loss == 0,
            loss,
            snapshot.is_some()
        );
        if let Some((
            before,
            after,
            outcome,
            observed,
            _bound,
            slots,
            rpc,
            rpc_count,
            proofs,
            progress,
            terminal_cost,
            peer_proofs,
            peer_progress,
            incoming,
            deliveries,
        )) = snapshot
        {
            let lower = before.and_then(|value| value.checked_add(15_000_000));
            let upper = after.and_then(|value| value.checked_add(15_000_000));
            let _ = writeln!(
                &mut output,
                "native5-consent-wait constructed_before_us={before:?} constructed_after_us={after:?} deadline_lower_us={lower:?} deadline_upper_us={upper:?} outcome_ok={outcome:?} observed_us={observed:?} exact_deadline_known=false"
            );
            for (index, slot) in slots.into_iter().enumerate() {
                let _ = writeln!(
                    &mut output,
                    "native5-consent-slot index={index} observation={slot:?}"
                );
            }
            for (index, proof) in proofs.into_iter().enumerate() {
                let _ = writeln!(
                    &mut output,
                    "native5-consent-proof index={index} observation={proof:?}"
                );
            }
            for (index, row) in progress.into_iter().enumerate() {
                let _ = writeln!(
                    &mut output,
                    "native5-consent-progress index={index} observation={row:?}"
                );
            }
            for (index, row) in peer_proofs.into_iter().enumerate() {
                let _ = writeln!(
                    &mut output,
                    "native5-consent-peer-proof index={index} observation={row:?}"
                );
            }
            for (index, row) in peer_progress.into_iter().enumerate() {
                let _ = writeln!(
                    &mut output,
                    "native5-consent-peer-progress index={index} observation={row:?}"
                );
            }
            for (index, row) in incoming.into_iter().enumerate() {
                let _ = writeln!(
                    &mut output,
                    "native5-consent-incoming index={index} observation={row:?}"
                );
            }
            for (index, row) in deliveries.into_iter().enumerate() {
                let _ = writeln!(
                    &mut output,
                    "native5-consent-first-outer-delivery index={index} observation={row:?}"
                );
            }
            let _ = writeln!(&mut output, "native5-consent-rpc-count count={rpc_count}");
            for (index, row) in rpc.into_iter().take(rpc_count).enumerate() {
                if let Some(row) = row {
                    let _ = writeln!(
                        &mut output,
                        "native5-consent-rpc index={index} times={:?} results={:?} sent={:?}",
                        row.times, row.results, row.sent
                    );
                }
            }
            let _ = writeln!(
                &mut output,
                "native5-consent-terminal-cost observation={terminal_cost:?}"
            );
        }
        output.push_str(&sdk_report);
        output.push_str(&worker_report);
        // The native lock is released before these existing plane-counter
        // lookups. Planes are read sequentially after the wait, not at deadline.
        output.push_str(
            &self
                .0
                .intake
                .report(&peer_outer_ids, source_ids_snapshot_available),
        );
        let notification_counts = observe_notifications(self.0.origin, peer_outer_ids);
        let _ = writeln!(
            &mut output,
            "native5-notification-meta source_ids_snapshot_available={source_ids_snapshot_available} source_id_bound={source_id_bound:?}"
        );
        for (plane, rows) in notification_counts.into_iter().enumerate() {
            for (channel, (counts, first_us, clock_invalid_mask, placement_counts, placement_first_us, placement_clock_invalid_mask)) in rows.into_iter().enumerate() {
                let _ = writeln!(
                    &mut output,
                    "native5-notification-disposition plane={plane} channel={channel} counts={counts:?} first_us={first_us:?} clock_invalid_mask={clock_invalid_mask:?} placement_counts={placement_counts:?} placement_first_us={placement_first_us:?} placement_clock_invalid_mask={placement_clock_invalid_mask:?}"
                );
            }
        }
        if output.len() > 65536 {
            return "native5-consent-timing known=false loss_mask=4 snapshot_available=false\n"
                .to_owned();
        }
        output
    }
}
