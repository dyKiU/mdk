//! Original SDK-owned confirmation continuation. Never serialized or restored.
use super::{LinkingContext, Role, VerifiedPairing};
use cgka_engine::private_roster_settlement::TrustedPrivateSettlementGuard;
use cgka_traits::device_linking_key_package::PurposeAttemptScope;
use cgka_traits::private_roster_settlement::PrivateSettlementAnchor;
use cgka_traits::{EngineError, GroupId};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Instant;

/// Snapshot of an original memory gate's cancellation generation. This can
/// only revoke a continuation; it is never an SDK permission or persisted fact.
pub(crate) struct SdkCancellationFence {
    current: Arc<AtomicU64>,
    generation: u64,
    closed: Arc<AtomicBool>,
}
impl SdkCancellationFence {
    pub(crate) fn capture(current: Arc<AtomicU64>, closed: Arc<AtomicBool>) -> Self {
        let generation = current.load(Ordering::Acquire);
        Self {
            current,
            generation,
            closed,
        }
    }
    fn is_revoked(&self) -> bool {
        self.closed.load(Ordering::Acquire)
            || self.current.load(Ordering::Acquire) != self.generation
    }
}

pub(crate) struct SettlementGuard {
    context: LinkingContext,
    scope: PurposeAttemptScope,
    deadline: Mutex<Instant>,
    revoked: AtomicBool,
    cancellation: SdkCancellationFence,
}
impl SettlementGuard {
    pub(crate) fn from_verified(
        token: &VerifiedPairing,
        scope: &PurposeAttemptScope,
        cancellation: SdkCancellationFence,
    ) -> Result<Self, EngineError> {
        let context = token.context();
        let (device, generation) = match token.role {
            Role::Approver => (context.approver, context.approver_generation),
            Role::NewDevice => (context.recipient, context.new_device_generation),
        };
        let deadline = token.original_deadline().ok_or_else(unavailable)?;
        if scope.account != context.account
            || scope.local_device != device
            || scope.generation != generation
            || Instant::now() >= deadline
        {
            return Err(unavailable());
        }
        context.digest().map_err(|_| unavailable())?;
        Ok(Self {
            context: context.clone(),
            scope: scope.clone(),
            deadline: Mutex::new(deadline),
            revoked: AtomicBool::new(false),
            cancellation,
        })
    }
    pub(crate) fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }
    pub(crate) fn is_live(&self) -> bool {
        !self.revoked.load(Ordering::SeqCst)
            && !self.cancellation.is_revoked()
            && Instant::now() < self.deadline()
    }
    pub(crate) fn deadline(&self) -> Instant {
        *self
            .deadline
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
    /// Negative-only observation bound; it cannot extend or revive SDK consent.
    pub(crate) fn shorten_deadline(&self, deadline: Instant) {
        let mut original = self
            .deadline
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *original = (*original).min(deadline);
    }
    pub(crate) fn scope(&self) -> &PurposeAttemptScope {
        &self.scope
    }
    pub(crate) fn group(&self) -> GroupId {
        GroupId::new(self.context.device_group.clone())
    }
}
impl TrustedPrivateSettlementGuard for SettlementGuard {
    fn validate(&self, anchor: &PrivateSettlementAnchor) -> Result<Instant, EngineError> {
        let context = &self.context;
        let digest = context.digest().map_err(|_| unavailable())?;
        if !self.is_live()
            || anchor.account != self.scope.account
            || anchor.local_device != self.scope.local_device
            || anchor.group_id.as_slice() != context.device_group.as_slice()
            || anchor.coordinator != context.approver
            || anchor.enrollment_nonce != context.nonce
            || anchor.context_digest != digest
            || anchor.successor.epoch.0 != context.predecessor.epoch + 1
            || anchor.successor.leaves.len() != context.predecessor.leaves.len() + 1
            || !context.predecessor.leaves.iter().all(|old| {
                anchor.successor.leaves.iter().any(|leaf| {
                    leaf.leaf_index == old.leaf_index
                        && leaf.signature_public_key == old.signature_public_key
                })
            })
            || !anchor
                .successor
                .leaves
                .iter()
                .any(|leaf| leaf.signature_public_key == context.recipient)
        {
            return Err(unavailable());
        }
        Ok(self.deadline())
    }
}
fn unavailable() -> EngineError {
    EngineError::Other("private settlement owner unavailable".into())
}
