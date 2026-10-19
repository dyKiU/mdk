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
    /// Negative completion only: unchanged revocation revision, never consent.
    pub(crate) fn revision_matches_for_negative_completion(&self) -> bool {
        !self.is_revoked()
    }
    /// Revoke only this exact captured negative revision. The returned fence
    /// is bound to the CAS result, never a later observation of the counter.
    pub(super) fn advance_original_revision(
        &self, current: &Arc<AtomicU64>, closed: &Arc<AtomicBool>,
    ) -> Option<Self> {
        if !Arc::ptr_eq(&self.current, current) || !Arc::ptr_eq(&self.closed, closed)
            || self.closed.load(Ordering::Acquire)
        { return None; }
        let Some(next) = self.generation.checked_add(1) else {
            if current.compare_exchange(self.generation, self.generation, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                closed.store(true, Ordering::Release);
            }
            return None;
        };
        current.compare_exchange(self.generation, next, Ordering::AcqRel, Ordering::Acquire).ok()?;
        Some(Self { current: current.clone(), generation: next, closed: closed.clone() })
    }
    pub(super) fn captured_revision_is(&self, revision: u64) -> bool {
        self.generation == revision
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
    pub(crate) fn matches_original_context(&self, context: &LinkingContext) -> bool {
        self.is_live()
            && self
                .context
                .digest()
                .ok()
                .zip(context.digest().ok())
                .is_some_and(|(own, other)| own == other)
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

#[cfg(test)]
mod negative_revision_tests {
    use super::*;
    #[test]
    fn cas_fence_is_exact_and_cannot_follow_a_later_revision() {
        let current = Arc::new(AtomicU64::new(0));
        let closed = Arc::new(AtomicBool::new(false));
        let original = SdkCancellationFence::capture(current.clone(), closed.clone());
        let after = original.advance_original_revision(&current, &closed).unwrap();
        assert!(after.revision_matches_for_negative_completion());
        current.fetch_add(1, Ordering::AcqRel); // Actual concurrent negative invalidation.
        assert!(!after.revision_matches_for_negative_completion());
        assert!(original.advance_original_revision(&current, &closed).is_none());
        assert_eq!(current.load(Ordering::Acquire), 2);
    }
    #[test]
    fn foreign_counter_closed_and_overflow_fail_without_witness() {
        let current = Arc::new(AtomicU64::new(0));
        let closed = Arc::new(AtomicBool::new(false));
        let original = SdkCancellationFence::capture(current.clone(), closed.clone());
        assert!(original.advance_original_revision(&Arc::new(AtomicU64::new(0)), &closed).is_none());
        assert_eq!(current.load(Ordering::Acquire), 0);
        closed.store(true, Ordering::Release);
        assert!(original.advance_original_revision(&current, &closed).is_none());
        let current = Arc::new(AtomicU64::new(u64::MAX));
        let closed = Arc::new(AtomicBool::new(false));
        let overflow = SdkCancellationFence::capture(current.clone(), closed.clone());
        assert!(overflow.advance_original_revision(&current, &closed).is_none());
        assert!(closed.load(Ordering::Acquire));
        assert_eq!(current.load(Ordering::Acquire), u64::MAX);
    }
}
