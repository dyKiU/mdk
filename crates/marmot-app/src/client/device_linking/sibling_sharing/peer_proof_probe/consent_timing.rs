//! Fixed, passive observations for one original D choice; never transport authority.
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
struct Slot {
    key: Key,
    times: [Option<u64>; 9],
    // Actual adapter Result Ok, report met ACKs, send accepted, receive Ok,
    // final harvest success. None is unobserved, never false/zero.
    outcomes: [Option<bool>; 5],
    retry_prepared: u32,
}
#[derive(Default)]
struct Data {
    owner: Option<Weak<OriginalEnrollmentSharingChoice>>,
    slots: [Option<Slot>; 2],
    before: Option<u64>,
    after: Option<u64>,
    wait_outcome: Option<bool>,
    wait_observed: Option<u64>,
}
struct Probe {
    origin: Instant,
    status: AtomicU32,
    data: Mutex<Data>,
}
fn registry() -> &'static OnceLock<Weak<Probe>> {
    static REGISTRY: OnceLock<Weak<Probe>> = OnceLock::new();
    &REGISTRY
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
pub(crate) struct Guard(Arc<Probe>);
pub(crate) fn arm() -> (Guard, Pending) {
    let probe = Arc::new(Probe {
        status: AtomicU32::new(0),
        origin: Instant::now(),
        data: Mutex::new(Data::default()),
    });
    if registry().set(Arc::downgrade(&probe)).is_err() {
        probe.loss(DUPLICATE);
        if let Some(old) = registry().get().and_then(Weak::upgrade) {
            old.loss(DUPLICATE);
        }
    }
    let pending = Pending(Arc::downgrade(&probe));
    (Guard(probe), pending)
}
// This opaque weak registration belongs to native SessionState. It never holds
// or names SessionState here, and never retains a real original across an await.
#[derive(Clone)]
pub(crate) struct Pending(Weak<Probe>);
impl Pending {
    pub(crate) fn bind(&self, owner: Weak<OriginalEnrollmentSharingChoice>) {
        let Some(probe) = self.0.upgrade() else { return; };
        probe.observe(|data, _| {
            if let Some(old) = &data.owner {
                // The real continuation can present its SAME original again.
                // Idempotent binding never retries or creates protocol work.
                if !old.ptr_eq(&owner) { probe.loss(IDENTITY); }
            } else { data.owner = Some(owner); }
        });
    }
    pub(crate) fn registration_failed(&self, poisoned: bool) {
        if let Some(probe) = self.0.upgrade() { probe.loss(if poisoned { LOCK_POISONED } else { LOCK_BUSY }); }
    }
    pub(crate) fn duplicate_registration(&self) {
        if let Some(probe) = self.0.upgrade() { probe.loss(DUPLICATE); }
    }
    pub(crate) fn identity_failed(&self) {
        if let Some(probe) = self.0.upgrade() { probe.loss(IDENTITY); }
    }
    pub(crate) fn wait_before(&self) -> Option<Wait> {
        let probe = self.0.upgrade()?;
        probe.observe(|data, time| {
            if data.before.is_some() { probe.loss(DUPLICATE); }
            else { data.before = time; }
        });
        Some(Wait(Arc::downgrade(&probe)))
    }
}
pub(crate) fn registration_unavailable(poisoned: bool) {
    if let Some(probe) = registry().get().and_then(Weak::upgrade) {
        probe.loss(if poisoned { LOCK_POISONED } else { LOCK_BUSY });
    }
}
#[derive(Clone)]
pub(crate) struct Token {
    probe: Weak<Probe>,
    index: usize,
    key: Key,
}
impl Token {
    pub(in super::super::super) fn stage(&self, index: usize, outcome: Option<(usize, bool)>) {
        let Some(probe) = self.probe.upgrade() else {
            return;
        };
        probe.observe(|data, time| {
            let Some(slot) = data.slots.get_mut(self.index).and_then(Option::as_mut) else {
                probe.loss(IDENTITY);
                return;
            };
            if !slot.key.same_attempt(&self.key) || index >= slot.times.len() {
                probe.loss(IDENTITY);
                return;
            }
            if slot.times[index].is_some() {
                probe.loss(DUPLICATE);
                return;
            }
            slot.times[index] = time;
            if let Some((field, value)) = outcome {
                if let Some(destination) = slot.outcomes.get_mut(field) {
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
            if let Some(slot) = data.slots.get_mut(self.index).and_then(Option::as_mut)
                && slot.key.same_attempt(&self.key)
            {
                if slot.times[4].is_some() {
                    probe.loss(DUPLICATE);
                    return;
                }
                slot.times[4] = time;
                slot.outcomes[0] = Some(ok);
                slot.outcomes[1] = met;
            } else {
                probe.loss(IDENTITY);
            }
        });
    }
}
pub(in super::super::super) fn prepared(
    entry: &SiblingChannel,
    request: &cgka_traits::TransportPublishRequest,
    kind: AccountSharingControl,
) -> Option<Token> {
    if !entry.recipient || kind != AccountSharingControl::Consent {
        return None;
    }
    let SiblingOriginal::Recipient { choice, .. } = entry.original.as_ref() else {
        return None;
    };
    let probe = registry().get()?.upgrade()?;
    let key = Key {
        state: Arc::downgrade(&entry.state),
        nonce: entry.channel.scope().nonce,
        message: request.message.id.clone(),
    };
    let mut selected = None;
    probe.observe(|data, time| {
        if !data.owner.as_ref().is_some_and(|owner| owner.ptr_eq(&Arc::downgrade(choice))) {
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
            key: key.clone(),
            times,
            outcomes: [None; 5],
            retry_prepared: 0,
        });
        selected = Some(Token {
            probe: Arc::downgrade(&probe),
            index,
            key: key.clone(),
        });
    });
    selected
}
pub(crate) fn armed() -> bool {
    registry().get().and_then(Weak::upgrade).is_some()
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
impl Drop for Guard {
    fn drop(&mut self) {
        let old = self.0.status.fetch_or(FROZEN, Ordering::AcqRel);
        // Copy only closed aggregates; print after the lock has been dropped.
        let snapshot = match self.0.data.try_lock() {
            Ok(data) => Some((
                data.before,
                data.after,
                data.wait_outcome,
                data.wait_observed,
                data.owner.is_some(),
                std::array::from_fn::<_, 2, _>(|index| {
                    data.slots[index]
                        .as_ref()
                        .map(|slot| (slot.times, slot.outcomes, slot.retry_prepared))
                }),
            )),
            Err(TryLockError::WouldBlock) => None,
            Err(TryLockError::Poisoned(_)) => None,
        };
        let mut loss = old & !FROZEN;
        if snapshot.as_ref().is_some_and(|row| !row.4) { loss |= ARM_UNAVAILABLE; }
        if snapshot.is_none() {
            // Snapshot failure is explicitly unknown; never a partial zero matrix.
            loss |= LOCK_BUSY;
            if self.0.data.is_poisoned() {
                loss |= LOCK_POISONED;
            }
        }
        eprintln!(
            "stress0-consent-timing known={} loss_mask={} snapshot_available={}",
            loss == 0,
            loss,
            snapshot.is_some()
        );
        if let Some((before, after, outcome, observed, _bound, slots)) = snapshot {
            let lower = before.and_then(|value| value.checked_add(15_000_000));
            let upper = after.and_then(|value| value.checked_add(15_000_000));
            eprintln!(
                "stress0-consent-wait constructed_before_us={before:?} constructed_after_us={after:?} deadline_lower_us={lower:?} deadline_upper_us={upper:?} outcome_ok={outcome:?} observed_us={observed:?} exact_deadline_known=false"
            );
            for (index, slot) in slots.into_iter().enumerate() {
                eprintln!("stress0-consent-slot index={index} observation={slot:?}");
            }
        }
    }
}
