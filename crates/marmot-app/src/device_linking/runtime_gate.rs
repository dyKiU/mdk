//! Private stock-SDK result to exact Welcome policy. No enrollment grant.
//! A non-await owned mutex lease spans the complete synchronous SQL join, so
//! account-owner cancellation/reservation cannot race the final deadline check.
use super::{Role, VerifiedPairing};
use cgka_engine::linking_welcome_policy::{
    AuthenticatedLinkingWelcome, LinkingWelcomeDenied, LinkingWelcomeLease, LinkingWelcomePolicy,
};
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::accepted_welcome::AcceptedWelcomeReceipt;
use cgka_traits::device_group_genesis::GenesisLeaf;
use cgka_traits::device_linking_key_package::PurposeKeyPackage;
use cgka_traits::peeler::PrivateLinkingWelcomeContext;
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Instant;
use tokio::sync::{Mutex, OwnedMutexGuard};

type GateResult<T> = std::result::Result<T, LinkingWelcomeDenied>;
trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}
struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}
#[derive(Default)]
struct State {
    token: Option<VerifiedPairing>,
    owner_scope: Option<([u8; 32], [u8; 32])>,
    generation: u64,
    terminal: Option<LinkingWelcomeDenied>,
}
impl State {
    fn live(&mut self, now: Instant, revoked: bool) -> GateResult<&VerifiedPairing> {
        if revoked {
            self.token = None;
            self.terminal = Some(LinkingWelcomeDenied::Cancelled);
            return Err(LinkingWelcomeDenied::Cancelled);
        }
        let deadline = self.token.as_ref().and_then(|token| token.owner_deadline);
        if deadline.is_some_and(|deadline| now >= deadline) {
            self.token = None;
            self.terminal = Some(LinkingWelcomeDenied::Expired);
        }
        self.token.as_ref().ok_or(
            self.terminal
                .unwrap_or(LinkingWelcomeDenied::NoLiveVerifier),
        )
    }
}
/// Crate-private trusted account facade; arming accepts only non-clone sealed
/// SDK evidence, never a caller-set approved flag or durable receipt.
pub(crate) struct RuntimeWelcomeGate {
    state: Arc<Mutex<State>>,
    clock: Arc<dyn Clock>,
    revoked: Arc<AtomicBool>,
    cancelled: Arc<AtomicU64>,
}
impl RuntimeWelcomeGate {
    pub(crate) fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }
    fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            clock,
            revoked: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicU64::new(0)),
        }
    }
    pub(crate) fn arm(&self, token: VerifiedPairing) -> GateResult<()> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(LinkingWelcomeDenied::Cancelled);
        }
        if token.role != Role::NewDevice || token.owner_deadline.is_none() {
            return Err(LinkingWelcomeDenied::NoLiveVerifier);
        }
        let deadline = token
            .owner_deadline
            .ok_or(LinkingWelcomeDenied::NoLiveVerifier)?;
        if self.clock.now() >= deadline {
            return Err(LinkingWelcomeDenied::Expired);
        }
        token
            .context
            .digest()
            .map_err(|_| LinkingWelcomeDenied::ContextMismatch)?;
        let scope = (token.context.account, token.context.recipient);
        let mut state = self
            .state
            .clone()
            .try_lock_owned()
            .map_err(|_| LinkingWelcomeDenied::NoLiveVerifier)?;
        if self.revoked.load(Ordering::Acquire) {
            return Err(LinkingWelcomeDenied::Cancelled);
        }
        if state.token.is_some() || token.context.new_device_generation <= state.generation {
            return Err(LinkingWelcomeDenied::NoLiveVerifier);
        }
        if state.owner_scope.is_some_and(|previous| previous != scope) {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        state.owner_scope = Some(scope);
        state.generation = token.context.new_device_generation;
        state.token = Some(token);
        state.terminal = None;
        Ok(())
    }
    /// Prune expired approval and report only whether the sealed token is live.
    /// A busy join lease refuses maintenance; it checks the same deadline itself.
    pub(crate) fn maintain(&self) -> GateResult<bool> {
        let mut state = self
            .state
            .clone()
            .try_lock_owned()
            .map_err(|_| LinkingWelcomeDenied::NoLiveVerifier)?;
        match state.live(self.clock.now(), self.revoked.load(Ordering::Acquire)) {
            Ok(_) => Ok(true),
            Err(
                LinkingWelcomeDenied::NoLiveVerifier
                | LinkingWelcomeDenied::Expired
                | LinkingWelcomeDenied::Cancelled,
            ) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Call on the serial account owner before retiring private purpose state.
    /// A competing synchronous join owns this mutex and must finish first.
    pub(crate) fn cancellation_fence(&self) -> super::settlement::SdkCancellationFence {
        super::settlement::SdkCancellationFence::capture(
            self.cancelled.clone(),
            self.revoked.clone(),
        )
    }

    pub(crate) fn cancel(&self) -> GateResult<()> {
        // Revoke downstream continuations even if an owned join lease makes
        // token cleanup temporarily unavailable. The serial owner retries it.
        if self
            .cancelled
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            })
            .is_err()
        {
            self.revoked.store(true, Ordering::Release);
        }
        let mut state = self
            .state
            .clone()
            .try_lock_owned()
            .map_err(|_| LinkingWelcomeDenied::NoLiveVerifier)?;
        state.token = None;
        state.terminal = Some(LinkingWelcomeDenied::Cancelled);
        Ok(())
    }
    /// Terminal revocation is infallible, including while a join owns the mutex.
    /// The outstanding lease observes the revocation and scrubs its token when
    /// it next checks or drops; retained policy Arcs cannot restore approval.
    pub(crate) fn shutdown(&self) {
        self.revoked.store(true, Ordering::Release);
        if let Ok(mut state) = self.state.clone().try_lock_owned() {
            state.token = None;
            state.terminal = Some(LinkingWelcomeDenied::Cancelled);
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum JoinPhase {
    AwaitingTransport,
    AwaitingTree,
    Authenticated,
}
struct Lease {
    phase: JoinPhase,
    state: OwnedMutexGuard<State>,
    clock: Arc<dyn Clock>,
    revoked: Arc<AtomicBool>,
}
impl RuntimeWelcomeGate {
    /// Scheduling metadata from the actual sealed attempt. This does not arm
    /// admission; the same purpose and live context are checked again on return.
    pub(crate) fn collection_deadline(&self, purpose: &PurposeKeyPackage) -> GateResult<Instant> {
        let lease = self.begin_owned_join(purpose)?;
        lease
            .state
            .token
            .as_ref()
            .and_then(|token| token.owner_deadline)
            .ok_or(LinkingWelcomeDenied::NoLiveVerifier)
    }

    fn begin_owned_join(&self, purpose: &PurposeKeyPackage) -> GateResult<Lease> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(LinkingWelcomeDenied::Cancelled);
        }
        let mut state = self
            .state
            .clone()
            .try_lock_owned()
            .map_err(|_| LinkingWelcomeDenied::NoLiveVerifier)?;
        let token = state.live(self.clock.now(), self.revoked.load(Ordering::Acquire))?;
        let context = &token.context;
        let digest = context
            .digest()
            .map_err(|_| LinkingWelcomeDenied::ContextMismatch)?;
        let binding = purpose
            .context
            .as_ref()
            .ok_or(LinkingWelcomeDenied::ContextMismatch)?;
        if purpose.consumed
            || purpose.scope.account != context.account
            || purpose.scope.local_device != context.recipient
            || purpose.scope.generation != context.new_device_generation
            || purpose.public_bytes != context.exact_key_package
            || purpose.reference != context.key_package_reference
            || purpose.signature_public_key != context.recipient
            || binding.nonce != context.nonce
            || binding.context_digest != digest
        {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        Ok(Lease {
            phase: JoinPhase::AwaitingTransport,
            state,
            clock: self.clock.clone(),
            revoked: self.revoked.clone(),
        })
    }
}
impl LinkingWelcomePolicy for RuntimeWelcomeGate {
    fn begin_join(&self, purpose: &PurposeKeyPackage) -> GateResult<Box<dyn LinkingWelcomeLease>> {
        Ok(Box::new(self.begin_owned_join(purpose)?))
    }
}
impl LinkingWelcomeLease for Lease {
    fn check_transport_context(
        &mut self,
        observed: &PrivateLinkingWelcomeContext,
    ) -> GateResult<()> {
        self.phase = JoinPhase::AwaitingTransport;
        let token = self
            .state
            .live(self.clock.now(), self.revoked.load(Ordering::Acquire))?;
        let context = &token.context;
        let digest = context
            .digest()
            .map_err(|_| LinkingWelcomeDenied::ContextMismatch)?;
        let package_digest: [u8; 32] = Sha256::digest(&context.exact_key_package).into();
        if observed.account != context.account
            || observed.approver != context.approver
            || observed.recipient != context.recipient
            || observed.approver_generation != context.approver_generation
            || observed.recipient_generation != context.new_device_generation
            || observed.group_id.as_slice() != context.device_group
            || observed.nonce != context.nonce
            || observed.context_digest != digest
            || observed.key_package_reference != context.key_package_reference
            || observed.key_package_digest != package_digest
        {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        // Artifact hashes are authenticated by the peeler and checked against
        // actual MLS bytes by Engine. They were not known during SDK consent.
        self.phase = JoinPhase::AwaitingTree;
        Ok(())
    }
    fn approved_predecessor(&mut self) -> GateResult<DeviceGroupAnchorRoster> {
        let token = self
            .state
            .live(self.clock.now(), self.revoked.load(Ordering::Acquire))?;
        if self.phase != JoinPhase::Authenticated {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        let context = &token.context;
        Ok(DeviceGroupAnchorRoster {
            epoch: cgka_traits::EpochId(context.predecessor.epoch),
            epoch_authenticator_digest: context.predecessor.epoch_authenticator_digest,
            leaves: context
                .predecessor
                .leaves
                .iter()
                .map(|leaf| GenesisLeaf {
                    leaf_index: leaf.leaf_index,
                    account: context.account,
                    signature_public_key: leaf.signature_public_key,
                })
                .collect(),
        })
    }
    fn check_authenticated(&mut self, welcome: &AuthenticatedLinkingWelcome) -> GateResult<()> {
        let token = self
            .state
            .live(self.clock.now(), self.revoked.load(Ordering::Acquire))?;
        let context = &token.context;
        if self.phase == JoinPhase::AwaitingTransport {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        self.phase = JoinPhase::AwaitingTree;
        if !welcome.private_device_profile
            || welcome.group_id.as_slice() != context.device_group
            || welcome.own_account.as_slice() != context.account
            || welcome.own_signature_public_key != context.recipient
            || welcome.welcomer_account.as_slice() != context.account
            || welcome.welcomer_signature_public_key != context.approver
        {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        if !matches_predecessor_and_recipient(context, welcome) {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        self.phase = JoinPhase::Authenticated;
        Ok(())
    }
    fn check_live_before_commit(&mut self) -> GateResult<()> {
        self.state
            .live(self.clock.now(), self.revoked.load(Ordering::Acquire))?;
        if self.phase != JoinPhase::Authenticated {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        Ok(())
    }
    fn commit_accepted(mut self: Box<Self>, _receipt: &AcceptedWelcomeReceipt) {
        // The engine already committed exact staged facts and receipt atomically.
        // Consume only memory; no callback, network, storage or grants.
        self.state.token = None;
        self.state.terminal = Some(LinkingWelcomeDenied::NoLiveVerifier);
    }
}

/// Match the authenticated staged tree before any group or receipt is installed.
/// A SAS-bound descriptor still needs an approved anchor at the coordinator;
/// this check cannot establish predecessor authority or roster settlement.
fn matches_predecessor_and_recipient(
    context: &super::LinkingContext,
    welcome: &AuthenticatedLinkingWelcome,
) -> bool {
    let predecessor = &context.predecessor;
    if welcome.protocol_profile != cgka_traits::group::ProtocolProfile::Current
        || Some(welcome.joined_epoch.0) != predecessor.epoch.checked_add(1)
        || welcome.leaves.len() != predecessor.leaves.len() + 1
        || welcome
            .leaves
            .windows(2)
            .any(|pair| pair[0].leaf_index >= pair[1].leaf_index)
        || predecessor
            .leaves
            .iter()
            .any(|leaf| leaf.leaf_index == welcome.own_leaf_index)
        || !predecessor.leaves.iter().any(|leaf| {
            leaf.leaf_index == welcome.welcomer_leaf_index
                && leaf.signature_public_key == context.approver
        })
    {
        return false;
    }
    welcome.leaves.iter().all(|leaf| {
        leaf.account.as_slice() == context.account
            && if leaf.leaf_index == welcome.own_leaf_index {
                leaf.signature_public_key == context.recipient
            } else {
                predecessor.leaves.iter().any(|expected| {
                    expected.leaf_index == leaf.leaf_index
                        && leaf.signature_public_key == expected.signature_public_key
                })
            }
    })
}
impl Drop for Lease {
    fn drop(&mut self) {
        // Rollback releases the same token only while its original deadline
        // remains live. No copied token or freshly extended timer is made.
        let _ = self
            .state
            .live(self.clock.now(), self.revoked.load(Ordering::Acquire));
    }
}
#[cfg(test)]
#[path = "runtime_gate/tests.rs"]
pub(super) mod tests;
