//! Account-owned Approver policy. Durable facts never restore SDK permission.
use super::{PredecessorRoster, Role, VerifiedPairing};
use cgka_engine::device_group_genesis::PrivateDeviceGroupGenesisEvidence;
use cgka_engine::private_device_invite::{
    AuthenticatedPrivateAdd, AuthenticatedPrivateInvite, PrivateInviteConsent, PrivateInviteLease,
    TrustedPrivateInvitePolicy,
};
use cgka_traits::device_linking_key_package::{LinkingWelcomeDenied, PurposeAttemptScope};
use cgka_traits::private_device_invite::{PrivateInviteOrigin, PrivateInviteScope};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Instant;
use tokio::sync::{Mutex, OwnedMutexGuard};

type GateResult<T> = Result<T, LinkingWelcomeDenied>;
trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}
struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}
// The optional portable proof contributes authenticated metadata only. Local
// settled provenance and the original owner-stamped SDK result remain mandatory.
struct BoundPredecessor {
    group: cgka_traits::GroupId,
    roster: PredecessorRoster,
}
impl BoundPredecessor {
    fn from_current(
        candidate: &cgka_engine::device_group_snapshot::CandidateDeviceGroupSnapshot,
        artifact: Option<
            &cgka_engine::private_enrollment_predecessor::AuthenticatedPrivatePredecessor,
        >,
    ) -> GateResult<Self> {
        let mut roster = PredecessorRoster::from_candidate(candidate)
            .map_err(|_| LinkingWelcomeDenied::ContextMismatch)?;
        if let Some(artifact) = artifact {
            if artifact.account() != &candidate.account
                || artifact.group_id() != &candidate.group_id
                || artifact.epoch() != candidate.epoch
                || artifact.leaves() != candidate.leaves.as_slice()
            {
                return Err(LinkingWelcomeDenied::ContextMismatch);
            }
            roster.artifact_digest = Some(*artifact.artifact_digest());
        }
        Ok(Self {
            group: candidate.group_id.clone(),
            roster,
        })
    }
}

struct Armed {
    token: VerifiedPairing,
    consent: PrivateInviteConsent,
    cancel_epoch: u64,
}
#[derive(Default)]
struct State {
    armed: Option<Armed>,
    owner: Option<([u8; 32], [u8; 32])>,
    generation: u64,
    terminal: Option<LinkingWelcomeDenied>,
}
impl State {
    fn live(&mut self, now: Instant, cancelled: u64, closed: bool) -> GateResult<&Armed> {
        if closed
            || self
                .armed
                .as_ref()
                .is_some_and(|armed| armed.cancel_epoch != cancelled)
        {
            self.armed = None;
            self.terminal = Some(LinkingWelcomeDenied::Cancelled);
        } else if self.armed.as_ref().is_some_and(|armed| {
            armed
                .token
                .owner_deadline
                .is_none_or(|deadline| now >= deadline)
        }) {
            self.armed = None;
            self.terminal = Some(LinkingWelcomeDenied::Expired);
        }
        self.armed.as_ref().ok_or(
            self.terminal
                .unwrap_or(LinkingWelcomeDenied::NoLiveVerifier),
        )
    }
}
pub(crate) struct RuntimeInviteGate {
    state: Arc<Mutex<State>>,
    clock: Arc<dyn Clock>,
    cancelled: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
}
impl RuntimeInviteGate {
    pub(crate) fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }
    fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            clock,
            cancelled: Arc::new(AtomicU64::new(0)),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }
    /// Accept only the sealed Approver result and genuine current origin evidence.
    /// Engine/storage independently revalidate origin CAS during preparation.
    pub(crate) fn arm_genesis(
        &self,
        token: VerifiedPairing,
        origin: &PrivateDeviceGroupGenesisEvidence,
    ) -> GateResult<()> {
        let cancel_epoch = self.cancelled.load(Ordering::Acquire);
        self.arm_bound_predecessor(
            token,
            BoundPredecessor::from_current(origin.current(), None)?,
            PrivateInviteOrigin::Genesis(origin.scope().selection_generation),
            (origin.scope().account, origin.scope().local_device),
            cancel_epoch,
        )
    }
    /// The opaque proof is freshly checked by the account actor after SAS.
    /// Public candidate/origin metadata cannot enter this arming inlet alone.
    pub(crate) fn arm_settled(
        &self,
        token: VerifiedPairing,
        settled: &cgka_engine::private_roster_settlement::ValidatedSettledDeviceRoster,
        artifact: Option<
            &cgka_engine::private_enrollment_predecessor::AuthenticatedPrivatePredecessor,
        >,
    ) -> GateResult<()> {
        let cancel_epoch = self.cancelled.load(Ordering::Acquire);
        let candidate = settled.candidate();
        let account = candidate
            .account
            .as_slice()
            .try_into()
            .map_err(|_| LinkingWelcomeDenied::ContextMismatch)?;
        let local_device = token.context.approver;
        if !candidate
            .leaves
            .iter()
            .any(|leaf| leaf.signature_public_key.as_slice() == local_device)
        {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        self.arm_bound_predecessor(
            token,
            BoundPredecessor::from_current(candidate, artifact)?,
            settled.origin().clone(),
            (account, local_device),
            cancel_epoch,
        )
    }
    fn arm_bound_predecessor(
        &self,
        token: VerifiedPairing,
        predecessor: BoundPredecessor,
        origin: PrivateInviteOrigin,
        expected_owner: ([u8; 32], [u8; 32]),
        cancel_epoch: u64,
    ) -> GateResult<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(LinkingWelcomeDenied::Cancelled);
        }
        if token.role != Role::Approver || token.owner_deadline.is_none() {
            return Err(LinkingWelcomeDenied::NoLiveVerifier);
        }
        if self.clock.now() >= token.owner_deadline.unwrap() {
            return Err(LinkingWelcomeDenied::Expired);
        }
        let context = &token.context;
        let digest = context
            .digest()
            .map_err(|_| LinkingWelcomeDenied::ContextMismatch)?;
        if context.account != expected_owner.0
            || context.approver != expected_owner.1
            || context.device_group != predecessor.group.as_slice()
            || context.predecessor != predecessor.roster
        {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        let consent = PrivateInviteConsent {
            approver_scope: PurposeAttemptScope {
                account: context.account,
                local_device: context.approver,
                generation: context.approver_generation,
            },
            recipient_generation: context.new_device_generation,
            origin,
            nonce: context.nonce,
            context_digest: digest,
        };
        let owner = (context.account, context.approver);
        let mut state = self
            .state
            .clone()
            .try_lock_owned()
            .map_err(|_| LinkingWelcomeDenied::NoLiveVerifier)?;
        if self.closed.load(Ordering::Acquire)
            || self.cancelled.load(Ordering::Acquire) != cancel_epoch
        {
            return Err(LinkingWelcomeDenied::Cancelled);
        }
        if state.armed.is_some() || context.approver_generation <= state.generation {
            return Err(LinkingWelcomeDenied::NoLiveVerifier);
        }
        if state.owner.is_some_and(|previous| previous != owner) {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        state.owner = Some(owner);
        state.generation = context.approver_generation;
        state.armed = Some(Armed {
            token,
            consent,
            cancel_epoch,
        });
        state.terminal = None;
        Ok(())
    }
    pub(crate) fn cancellation_fence(&self) -> super::settlement::SdkCancellationFence {
        super::settlement::SdkCancellationFence::capture(
            self.cancelled.clone(),
            self.closed.clone(),
        )
    }

    /// Revocation never waits for a held preparation/dispatch lease.
    pub(crate) fn cancel(&self) {
        if self
            .cancelled
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            })
            .is_err()
        {
            self.closed.store(true, Ordering::Release);
        }
        if let Ok(mut state) = self.state.clone().try_lock_owned() {
            state.armed = None;
            state.terminal = Some(LinkingWelcomeDenied::Cancelled);
        }
    }
    pub(crate) fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        self.cancel();
    }
    pub(crate) fn maintain(&self) -> GateResult<bool> {
        let mut state = self
            .state
            .clone()
            .try_lock_owned()
            .map_err(|_| LinkingWelcomeDenied::NoLiveVerifier)?;
        match state.live(
            self.clock.now(),
            self.cancelled.load(Ordering::Acquire),
            self.closed.load(Ordering::Acquire),
        ) {
            Ok(_) => Ok(true),
            Err(
                LinkingWelcomeDenied::NoLiveVerifier
                | LinkingWelcomeDenied::Expired
                | LinkingWelcomeDenied::Cancelled,
            ) => Ok(false),
            Err(error) => Err(error),
        }
    }
}
impl TrustedPrivateInvitePolicy for RuntimeInviteGate {
    fn begin_prepare(
        &self,
        actual: &AuthenticatedPrivateInvite,
    ) -> GateResult<Box<dyn PrivateInviteLease>> {
        let mut state = self
            .state
            .clone()
            .try_lock_owned()
            .map_err(|_| LinkingWelcomeDenied::NoLiveVerifier)?;
        let armed = state.live(
            self.clock.now(),
            self.cancelled.load(Ordering::Acquire),
            self.closed.load(Ordering::Acquire),
        )?;
        let context = &armed.token.context;
        // Arming authenticated this exact artifact through Core and matched it
        // to the fresh protected predecessor. Actual Add input has no portable
        // artifact field: recheck its complete tree/authenticator while retaining
        // the original authenticated digest bound by the same SDK context.
        let mut predecessor = PredecessorRoster::from_candidate(&actual.predecessor)
            .map_err(|_| LinkingWelcomeDenied::ContextMismatch)?;
        predecessor.artifact_digest = context.predecessor.artifact_digest;
        if context.account.as_slice() != actual.predecessor.account.as_slice()
            || context.device_group != actual.predecessor.group_id.as_slice()
            || context.predecessor != predecessor
            || context.exact_key_package != actual.exact_key_package.bytes()
            || context.key_package_reference != actual.key_package_reference
            || context.account.as_slice() != actual.recipient_account.as_slice()
            || context.recipient != actual.recipient_signature_public_key
            || !context.predecessor.leaves.iter().any(|leaf| {
                leaf.leaf_index == actual.own_leaf_index
                    && leaf.signature_public_key == context.approver
            })
        {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        let consent = armed.consent.clone();
        Ok(Box::new(Lease {
            state,
            consent,
            clock: self.clock.clone(),
            cancelled: self.cancelled.clone(),
            closed: self.closed.clone(),
            committed: false,
        }))
    }
}
struct Lease {
    state: OwnedMutexGuard<State>,
    consent: PrivateInviteConsent,
    clock: Arc<dyn Clock>,
    cancelled: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
    committed: bool,
}
impl PrivateInviteLease for Lease {
    fn consent(&self) -> &PrivateInviteConsent {
        &self.consent
    }
    fn enrollment_proposal_metadata(
        &mut self,
    ) -> GateResult<cgka_engine::private_device_invite::PrivateEnrollmentProposalMetadata> {
        let armed = self.state.live(
            self.clock.now(),
            self.cancelled.load(Ordering::Acquire),
            self.closed.load(Ordering::Acquire),
        )?;
        // Only the original sealed SDK token supplies this metadata. This does
        // not create approval; the retained lease still checks its original
        // deadline and cancellation counter at every producer phase.
        let context = &armed.token.context;
        Ok(
            cgka_engine::private_device_invite::PrivateEnrollmentProposalMetadata {
                context_json: serde_json::to_string(context)
                    .map_err(|_| LinkingWelcomeDenied::ContextMismatch)?,
                artifact_digest: context
                    .predecessor
                    .artifact_digest
                    .ok_or(LinkingWelcomeDenied::ContextMismatch)?,
                original_deadline: armed
                    .token
                    .owner_deadline
                    .ok_or(LinkingWelcomeDenied::NoLiveVerifier)?,
            },
        )
    }

    fn check_staged(&mut self, actual: &AuthenticatedPrivateAdd) -> GateResult<()> {
        let armed = self.state.live(
            self.clock.now(),
            self.cancelled.load(Ordering::Acquire),
            self.closed.load(Ordering::Acquire),
        )?;
        let context = &armed.token.context;
        let successor = &actual.successor;
        if Some(successor.epoch.0) != context.predecessor.epoch.checked_add(1)
            || successor.epoch_authenticator_digest == [0; 32]
            || successor.leaves.len() != context.predecessor.leaves.len() + 1
            || successor
                .leaves
                .windows(2)
                .any(|pair| pair[0].leaf_index >= pair[1].leaf_index)
            || successor
                .leaves
                .iter()
                .any(|leaf| leaf.account != context.account)
            || context.predecessor.leaves.iter().any(|prior| {
                !successor.leaves.iter().any(|leaf| {
                    leaf.leaf_index == prior.leaf_index
                        && leaf.signature_public_key == prior.signature_public_key
                })
            })
            || context
                .predecessor
                .leaves
                .iter()
                .any(|prior| prior.leaf_index == actual.recipient_leaf_index)
            || !successor.leaves.iter().any(|leaf| {
                leaf.leaf_index == actual.recipient_leaf_index
                    && leaf.signature_public_key == context.recipient
            })
        {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        Ok(())
    }
    fn check_live_before_commit(&mut self) -> GateResult<()> {
        self.state.live(
            self.clock.now(),
            self.cancelled.load(Ordering::Acquire),
            self.closed.load(Ordering::Acquire),
        )?;
        Ok(())
    }
    fn preparation_committed(&mut self, scope: &PrivateInviteScope) {
        self.committed = true;
        if scope.account != self.consent.approver_scope.account
            || scope.local_device != self.consent.approver_scope.local_device
            || scope.staging_generation == 0
        {
            self.state.armed = None;
            self.state.terminal = Some(LinkingWelcomeDenied::ContextMismatch);
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.committed {
            self.state.armed = None;
            self.state.terminal = Some(LinkingWelcomeDenied::NoLiveVerifier);
        } else {
            let _ = self.state.live(
                self.clock.now(),
                self.cancelled.load(Ordering::Acquire),
                self.closed.load(Ordering::Acquire),
            );
        }
    }
}
#[cfg(test)]
#[path = "invite_gate/tests.rs"]
mod tests;
