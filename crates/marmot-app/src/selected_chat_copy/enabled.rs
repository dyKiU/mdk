//! New explicit selected-chat consent, independent of consumed device-linking attempts.
use super::{SelectedChatCopyError, SelectedChatCopyPhase, SelectedChatCopySnapshot};
use cgka_traits::{EpochId, GroupId};
use rand::RngCore;
use std::sync::{
    Arc, Weak,
    atomic::{AtomicU8, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

// Native consent-owner lifetime/resource bound, not a convergence or SDK clock.
const SELECTED_CHAT_REQUEST_LIFETIME: Duration = Duration::from_secs(600);

pub(crate) struct OrdinaryChatAnchor {
    pub(crate) _group: GroupId,
    pub(crate) _epoch: EpochId,
    pub(crate) _local_leaf_index: u32,
    pub(crate) _local_leaf_hash: Vec<u8>,
    pub(crate) _canonical_roster_digest: [u8; 32],
}

struct OwnerLease {
    lifetime: Weak<AtomicU64>,
    generation: u64,
    original_deadline: Instant,
    terminal: AtomicU8,
}
impl OwnerLease {
    fn phase(&self) -> SelectedChatCopyPhase {
        let observed = if Instant::now() >= self.original_deadline {
            2
        } else if self
            .lifetime
            .upgrade()
            .is_none_or(|owner| owner.load(Ordering::Acquire) != self.generation)
        {
            3
        } else {
            0
        };
        if observed != 0 {
            let _ =
                self.terminal
                    .compare_exchange(0, observed, Ordering::AcqRel, Ordering::Acquire);
        }
        match self.terminal.load(Ordering::Acquire) {
            0 => SelectedChatCopyPhase::AwaitingSiblingConsent,
            1 => SelectedChatCopyPhase::Cancelled,
            2 => SelectedChatCopyPhase::Expired,
            _ => SelectedChatCopyPhase::Closed,
        }
    }
    fn cancel(&self) {
        // Observe expiry/owner loss first; a terminal observation stays terminal.
        self.phase();
        let _ = self
            .terminal
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
    }
}

pub(crate) struct RequestState {
    lease: OwnerLease,
    sibling_count: u32,
    // Read-only captured selections, never SDK consent or recipient permission.
    _ordinary: OrdinaryChatAnchor,
    _protected: cgka_engine::device_group_snapshot::CandidateDeviceGroupSnapshot,
    _protected_generation: u64,
    _request_nonce: [u8; 32],
}
impl RequestState {
    pub(crate) fn snapshot(&self) -> SelectedChatCopySnapshot {
        let phase = self.lease.phase();
        SelectedChatCopySnapshot {
            revision: if phase == SelectedChatCopyPhase::AwaitingSiblingConsent {
                1
            } else {
                2
            },
            phase,
            sibling_count: self.sibling_count,
        }
    }
    pub(crate) fn cancel(&self) {
        self.lease.cancel();
    }
}

pub(crate) struct AccountCopyOwner {
    lifetime: Arc<AtomicU64>,
    current: Option<Weak<RequestState>>,
}
impl Default for AccountCopyOwner {
    fn default() -> Self {
        Self {
            lifetime: Arc::new(AtomicU64::new(0)),
            current: None,
        }
    }
}
impl AccountCopyOwner {
    pub(crate) fn reserve(
        &mut self,
        ordinary: OrdinaryChatAnchor,
        protected: cgka_engine::private_roster_settlement::ValidatedSettledDeviceRoster,
    ) -> Result<Arc<RequestState>, SelectedChatCopyError> {
        if self
            .current
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|request| {
                request.snapshot().phase == SelectedChatCopyPhase::AwaitingSiblingConsent
            })
        {
            return Err(SelectedChatCopyError::Busy);
        }
        let generation = self
            .lifetime
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or(SelectedChatCopyError::RuntimeUnavailable)?;
        let deadline = Instant::now()
            .checked_add(SELECTED_CHAT_REQUEST_LIFETIME)
            .ok_or(SelectedChatCopyError::RuntimeUnavailable)?;
        let mut nonce = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let sibling_count = protected
            .candidate()
            .leaves
            .len()
            .checked_sub(1)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n > 0)
            .ok_or(SelectedChatCopyError::InvalidSelection)?;
        let state = Arc::new(RequestState {
            lease: OwnerLease {
                lifetime: Arc::downgrade(&self.lifetime),
                generation,
                original_deadline: deadline,
                terminal: AtomicU8::new(0),
            },
            sibling_count,
            _ordinary: ordinary,
            _protected: protected.candidate().clone(),
            _protected_generation: protected.settlement_generation(),
            _request_nonce: nonce,
        });
        self.lifetime.store(generation, Ordering::Release);
        self.current = Some(Arc::downgrade(&state));
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lease(owner: &Arc<AtomicU64>, deadline: Instant) -> OwnerLease {
        OwnerLease {
            lifetime: Arc::downgrade(owner),
            generation: 1,
            original_deadline: deadline,
            terminal: AtomicU8::new(0),
        }
    }
    #[test]
    fn original_deadline_remains_expired_after_cancel_or_generation_change() {
        let owner = Arc::new(AtomicU64::new(1));
        let request = lease(&owner, Instant::now() - Duration::from_secs(1));
        assert_eq!(request.phase(), SelectedChatCopyPhase::Expired);
        request.cancel();
        owner.store(2, Ordering::Release);
        assert_eq!(request.phase(), SelectedChatCopyPhase::Expired);
    }
    #[test]
    fn exact_old_cancel_cannot_retire_a_new_generation_and_account_drop_closes_it() {
        let owner = Arc::new(AtomicU64::new(1));
        let old = lease(&owner, Instant::now() + Duration::from_secs(60));
        old.cancel();
        owner.store(2, Ordering::Release);
        let new = OwnerLease {
            generation: 2,
            ..lease(&owner, Instant::now() + Duration::from_secs(60))
        };
        old.cancel();
        assert_eq!(new.phase(), SelectedChatCopyPhase::AwaitingSiblingConsent);
        drop(owner);
        assert_eq!(new.phase(), SelectedChatCopyPhase::Closed);
        new.cancel();
        assert_eq!(new.phase(), SelectedChatCopyPhase::Closed);
    }
}
