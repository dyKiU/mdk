//! Opt-in passive native-frame test facts. Identifiers and owners never leave RAM.
use super::*;
use super::replay_ingress::{ReplayConsumer, ReplayIngressState};
use std::sync::{Mutex as StdMutex, Weak};

/// No constructor, Debug, serialization, or strong consumer/adapter ownership.
#[derive(Clone)]
pub struct NativeConsumerIdentityForTest {
    consumer: Weak<ReplayConsumer>,
    shared: Weak<ReplayIngressState>,
    state: Weak<RwLock<AdapterState>>,
    account: MemberId,
    serial: u64,
}

pub(super) fn identity(
    consumer: &Arc<ReplayConsumer>, shared: &Arc<ReplayIngressState>,
    state: &Weak<RwLock<AdapterState>>, account: &MemberId,
) -> NativeConsumerIdentityForTest {
    NativeConsumerIdentityForTest {
        consumer: Arc::downgrade(consumer), shared: Arc::downgrade(shared),
        state: state.clone(), account: account.clone(), serial: consumer.serial_for_test(),
    }
}

impl NativeConsumerIdentityForTest {
    pub fn matches(&self, other: &Self) -> bool {
        self.consumer.ptr_eq(&other.consumer) && self.shared.ptr_eq(&other.shared)
            && self.state.ptr_eq(&other.state) && self.account == other.account
            && self.serial == other.serial && self.is_current()
    }

    fn is_current(&self) -> bool {
        let Some(consumer) = self.consumer.upgrade() else { return false; };
        let Some(shared) = self.shared.upgrade() else { return false; };
        self.state.strong_count() > 0 && consumer.serial_for_test() == self.serial
            && shared.consumer_is_current_for_test(self.serial)
    }

    /// Called only after the real sender's exact publication/fanout/MLS binding,
    /// before real publish. Refuse a second watch; never register a consumer.
    pub fn watch(&self, group: &GroupId, packet: &[u8]) -> Option<NativeFrameWatchForTest> {
        if packet.len() != 32 || !self.is_current() { return None; }
        let consumer = self.consumer.upgrade()?;
        let mut slot = consumer.probe.lock().unwrap_or_else(|p| p.into_inner());
        if slot.upgrade().is_some() { return None; }
        let probe = Arc::new(Probe {
            identity: self.clone(), group: group.clone(), packet: packet.to_vec(),
            facts: StdMutex::new(Facts::default()),
        });
        *slot = Arc::downgrade(&probe);
        Some(NativeFrameWatchForTest { probe })
    }
}

#[derive(Default)]
struct Facts {
    counts: [u64; 3],
    overflow: bool,
    borrowed: Option<Instant>,
    ingested: Option<Instant>,
    completed: Option<[Instant; 3]>,
    custody: Option<Instant>,
}

pub(super) struct Probe {
    identity: NativeConsumerIdentityForTest,
    group: GroupId,
    packet: Vec<u8>,
    facts: StdMutex<Facts>,
}

pub struct NativeFrameWatchForTest { probe: Arc<Probe> }

impl NativeFrameWatchForTest {
    pub fn matches(&self, identity: &NativeConsumerIdentityForTest) -> bool {
        self.probe.identity.matches(identity)
    }

    /// Counts are bounded attempt facts; optional times never imply absence.
    /// A complete triple belongs to one borrowed turn ending in checked ACK.
    pub fn sample_custody(&self) {
        // A read-only ready-range query, not registration or a second receiver.
        let queued = self.probe.identity.shared.upgrade().is_some_and(|shared|
            self.probe.identity.consumer.strong_count() > 0
                && shared.queued_frame_for_test(self.probe.identity.serial,
                    &self.probe.identity.account, &self.probe.group, &self.probe.packet));
        let sampled_at = Instant::now();
        let mut facts = self.probe.facts.lock().unwrap_or_else(|p| p.into_inner());
        if queued && facts.custody.is_none() { facts.custody = Some(sampled_at); }
    }

    pub fn facts(&self, start: Instant, frozen: Instant) -> ([u64; 3], [bool; 5]) {
        let current = self.probe.identity.is_current();
        let facts = self.probe.facts.lock().unwrap_or_else(|p| p.into_inner());
        let ordered = facts.completed.is_some_and(|t|
            start <= t[0] && t[0] <= t[1] && t[1] <= t[2] && t[2] <= frozen);
        (facts.counts, [current, !facts.overflow,
            facts.completed.is_some(), ordered,
            facts.custody.is_some_and(|at| start <= at && at <= frozen)])
    }
}

impl Drop for NativeFrameWatchForTest {
    fn drop(&mut self) {
        if let Some(consumer) = self.probe.identity.consumer.upgrade() {
            let mut slot = consumer.probe.lock().unwrap_or_else(|p| p.into_inner());
            if slot.ptr_eq(&Arc::downgrade(&self.probe)) { *slot = Weak::new(); }
        }
    }
}

pub(super) fn record(
    consumer: &Arc<ReplayConsumer>, state: &Weak<RwLock<AdapterState>>,
    account: &MemberId, delivery: &TransportDelivery, stage: usize,
) {
    let probe = consumer.probe.lock().unwrap_or_else(|p| p.into_inner()).upgrade();
    let Some(probe) = probe else { return; };
    if !probe.identity.consumer.ptr_eq(&Arc::downgrade(consumer))
        || !probe.identity.state.ptr_eq(state) || &probe.identity.account != account
        || &delivery.account_id != account || delivery.group_id_hint.as_ref() != Some(&probe.group)
        || delivery.message.id.as_slice() != probe.packet.as_slice() { return; }
    let mut facts = probe.facts.lock().unwrap_or_else(|p| p.into_inner());
    // Fixed bound; any overflow disqualifies the observation, never grants input.
    if stage > 2 || facts.counts.iter().sum::<u64>() >= 64 {
        facts.overflow = true; return;
    }
    facts.counts[stage] += 1;
    let now = Instant::now();
    match stage {
        0 => {
            facts.borrowed = Some(now); facts.ingested = None;
            if facts.custody.is_none() { facts.custody = Some(now); }
        }
        1 if facts.borrowed.is_some() => { facts.ingested = Some(now); }
        2 if facts.completed.is_none() => {
            if let (Some(borrowed), Some(ingested)) = (facts.borrowed, facts.ingested) {
                facts.completed = Some([borrowed, ingested, now]);
            }
        }
        _ => {}
    }
}
