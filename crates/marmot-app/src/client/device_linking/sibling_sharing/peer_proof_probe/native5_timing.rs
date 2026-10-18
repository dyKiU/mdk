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
struct Data {
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
struct Probe {
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
                data.owner = Some(owner);
            }
        });
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
    pub(crate) fn freeze(self) -> String {
        use std::fmt::Write as _;
        let sdk_report = self.0.sdk.freeze();
        let mut output = String::with_capacity(65536);
        let old = self.0.status.fetch_or(FROZEN, Ordering::AcqRel);
        // Copy only closed aggregates; print after the lock has been dropped.
        let snapshot = match self.0.data.try_lock() {
            Ok(data) => Some((
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
            )),
            Err(TryLockError::WouldBlock) => None,
            Err(TryLockError::Poisoned(_)) => None,
        };
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
        if output.len() > 65536 {
            return "native5-consent-timing known=false loss_mask=4 snapshot_available=false\n"
                .to_owned();
        }
        output
    }
}
