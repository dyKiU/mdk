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
struct Slot {
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
    subsequent_attempts: u32,
}
impl Slot {
    fn publication_mut(
        &mut self,
        proof: bool,
    ) -> Option<(&Key, &mut [Option<u64>; 9], &mut [Option<bool>; 5])> {
        if proof {
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
        }
    }
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
    if let Some(probe) = registry().get().and_then(Weak::upgrade) {
        probe.loss(if poisoned { LOCK_POISONED } else { LOCK_BUSY });
    }
}
#[derive(Clone)]
pub(crate) struct Token {
    probe: Weak<Probe>,
    index: usize,
    key: Key,
    proof: bool,
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
            let Some((key, times, outcomes)) = slot.publication_mut(self.proof) else {
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
            let Some((key, times, outcomes)) = slot.publication_mut(self.proof) else {
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
            });
        });
        selected
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
    let Some(probe) = registry().get().and_then(Weak::upgrade) else {
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
pub(in super::super::super) fn begin_proof(entry: &SiblingChannel) -> Option<ProofAttempt> {
    let probe = registry().get()?.upgrade()?;
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
    proof_attempt: Option<&ProofAttempt>,
) -> Option<Token> {
    if entry.recipient && kind == AccountSharingControl::Body(0) {
        return proof_attempt.and_then(|attempt| attempt.prepared(entry, request));
    }
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
                            )
                        })
                    })
                }),
                std::array::from_fn::<_, 3, _>(|index| {
                    data.slots[index]
                        .as_ref()
                        .map(|slot| (slot.progress, slot.progress_repeats))
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
        }
        if output.len() > 65536 {
            return "native5-consent-timing known=false loss_mask=4 snapshot_available=false\n"
                .to_owned();
        }
        output
    }
}
