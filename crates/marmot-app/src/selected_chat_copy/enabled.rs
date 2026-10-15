//! New explicit selected-chat consent, independent of consumed device-linking attempts.
use super::{SelectedChatCopyError, SelectedChatCopyPhase, SelectedChatCopySnapshot};
use cgka_traits::{EpochId, GroupId};
use rand::RngCore;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU8, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

// Native consent-owner lifetime/resource bound, not a convergence or SDK clock.
const MAX_SELECTED_CHAT_RECEIPT_IDENTITIES: usize = 128;
const SELECTED_CHAT_REQUEST_LIFETIME: Duration = Duration::from_secs(600);

#[derive(PartialEq, Eq)]
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
    cancelled: tokio::sync::Notify,
    // Read-only captured selections, never SDK consent or recipient permission.
    pub(crate) _ordinary: OrdinaryChatAnchor,
    pub(crate) _protected: cgka_engine::device_group_snapshot::CandidateDeviceGroupSnapshot,
    pub(crate) _protected_generation: u64,
    pub(crate) _request_nonce: [u8; 32],
    pub(crate) progress: Mutex<RequestProgress>,
}
#[derive(Default)]
pub(crate) struct RequestProgress {
    pub(crate) packet: Option<Vec<u8>>,
    pub(crate) receipts: std::collections::HashMap<u32, ([u8; 32], Vec<u8>)>,
    pub(crate) offers: std::collections::HashMap<u32, CollectedOffer>,
    pub(crate) invite: Option<PreparedSelectedInvite>,
}
// Retained only by this original process-local request; never durable permission.
pub(crate) struct PreparedSelectedInvite {
    pub(crate) pending: cgka_traits::PendingStateRef,
    pub(crate) origin: cgka_traits::MessageId,
    pub(crate) message: cgka_traits::TransportMessage,
    pub(crate) welcomes: Vec<cgka_traits::TransportMessage>,
    pub(crate) commit_report: Option<cgka_traits::TransportPublishReport>,
    pub(crate) confirmed_effects: Option<cgka_session::SessionEffects>,
    pub(crate) confirmed: bool,
    pub(crate) next_welcome: usize,
}
pub(crate) struct CollectedOffer {
    pub(crate) wire: Vec<u8>,
    pub(crate) observation: Arc<cgka_engine::selected_chat_consent::AuthenticatedSelectedChatOffer>,
    pub(crate) package_event_id: cgka_traits::MessageId,
}
impl RequestState {
    pub(crate) fn check_revision(&self, revision: u64) -> Result<(), SelectedChatCopyError> {
        let snapshot = self.snapshot();
        if snapshot.phase != SelectedChatCopyPhase::AwaitingSiblingConsent {
            return Err(SelectedChatCopyError::Closed);
        }
        if snapshot.revision != revision {
            return Err(SelectedChatCopyError::StaleRevision);
        }
        Ok(())
    }

    pub(crate) fn check_live_revision(&self, revision: u64) -> Result<(), SelectedChatCopyError> {
        if self.lease.phase() != SelectedChatCopyPhase::AwaitingSiblingConsent {
            return Err(SelectedChatCopyError::Closed);
        }
        if self.snapshot().revision != revision {
            return Err(SelectedChatCopyError::StaleRevision);
        }
        Ok(())
    }
    pub(crate) fn is_live(&self) -> bool {
        self.lease.phase() == SelectedChatCopyPhase::AwaitingSiblingConsent
    }
    pub(crate) fn snapshot(&self) -> SelectedChatCopySnapshot {
        let progress = self.progress.lock().expect("selected request observation");
        let lease_phase = self.lease.phase();
        let confirmed = progress
            .invite
            .as_ref()
            .is_some_and(|invite| invite.confirmed);
        let phase = if lease_phase == SelectedChatCopyPhase::AwaitingSiblingConsent && confirmed {
            SelectedChatCopyPhase::InviteConfirmed
        } else {
            lease_phase
        };
        SelectedChatCopySnapshot {
            revision: 1
                + progress.receipts.len() as u64
                + progress.offers.len() as u64
                + u64::from(confirmed)
                + u64::from(lease_phase != SelectedChatCopyPhase::AwaitingSiblingConsent),
            phase,
            sibling_count: self.sibling_count,
            consenting_sibling_count: progress.receipts.len() as u32,
            offered_sibling_count: progress.offers.len() as u32,
        }
    }
    pub(crate) fn cancel(&self) {
        self.lease.cancel();
        self.cancelled.notify_waiters();
    }
    pub(crate) async fn revoked(&self) {
        let notified = self.cancelled.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if !self.is_live() {
            return;
        }
        tokio::select! {
            _ = &mut notified => {},
            _ = tokio::time::sleep_until(self.lease.original_deadline.into()) => {},
        }
    }
}

pub(crate) struct SelectedPendingCleanup {
    pub(crate) pending: cgka_traits::PendingStateRef,
    pub(crate) origin: cgka_traits::MessageId,
    pub(crate) group: GroupId,
    owner: Weak<RequestState>,
}
/// A negative retry fence from the actual Core recipient-policy invocation.
#[derive(Clone)]
pub(crate) struct SelectedRecipientAttempt {
    pub(crate) original: Weak<ConsentState>,
    pub(crate) revision: u64,
    pub(crate) scope: cgka_traits::selected_chat_key_package::SelectedChatPurposeScope,
    pub(crate) reference: [u8; 32],
}
impl SelectedRecipientAttempt {
    pub(crate) fn is_live(&self) -> bool {
        self.original.upgrade().is_some_and(|original| {
            original.check_revision(self.revision).is_ok()
                && original.generation() == self.scope.generation
        })
    }
}

pub(crate) struct AccountCopyOwner {
    pub(crate) recipient_attempt: Arc<Mutex<Option<SelectedRecipientAttempt>>>,
    lifetime: Arc<AtomicU64>,
    current: Option<Weak<RequestState>>,
    consent_lifetime: Arc<AtomicU64>,
    consent_history: std::collections::HashMap<[u8; 32], (Instant, Weak<ConsentState>)>,
    pending_cleanup:
        std::collections::HashMap<cgka_traits::PendingStateRef, SelectedPendingCleanup>,
    package_cleanup: std::collections::HashMap<
        [u8; 32],
        (
            cgka_traits::selected_chat_key_package::SelectedChatPurposeScope,
            Weak<ConsentState>,
        ),
    >,
}
impl Default for AccountCopyOwner {
    fn default() -> Self {
        Self {
            recipient_attempt: Arc::new(Mutex::new(None)),
            lifetime: Arc::new(AtomicU64::new(0)),
            current: None,
            consent_lifetime: Arc::new(AtomicU64::new(0)),
            consent_history: std::collections::HashMap::new(),
            package_cleanup: std::collections::HashMap::new(),
            pending_cleanup: std::collections::HashMap::new(),
        }
    }
}
impl AccountCopyOwner {
    pub(crate) fn check_pending_capacity(&self) -> Result<(), SelectedChatCopyError> {
        if self.pending_cleanup.len() >= MAX_SELECTED_CHAT_RECEIPT_IDENTITIES {
            return Err(SelectedChatCopyError::Busy);
        }
        Ok(())
    }
    pub(crate) fn register_pending_cleanup(
        &mut self,
        original: &Arc<RequestState>,
        pending: cgka_traits::PendingStateRef,
        origin: cgka_traits::MessageId,
        group: GroupId,
    ) -> Result<(), SelectedChatCopyError> {
        if !self.pending_cleanup.contains_key(&pending)
            && self.pending_cleanup.len() >= MAX_SELECTED_CHAT_RECEIPT_IDENTITIES
        {
            return Err(SelectedChatCopyError::Busy);
        }
        self.pending_cleanup.insert(
            pending,
            SelectedPendingCleanup {
                pending,
                origin,
                group,
                owner: Arc::downgrade(original),
            },
        );
        Ok(())
    }
    pub(crate) fn pending_to_retire(
        &self,
    ) -> Vec<(
        cgka_traits::PendingStateRef,
        cgka_traits::MessageId,
        GroupId,
    )> {
        self.pending_cleanup
            .values()
            .filter(|entry| {
                !entry
                    .owner
                    .upgrade()
                    .is_some_and(|original| original.is_live())
            })
            .map(|entry| (entry.pending, entry.origin.clone(), entry.group.clone()))
            .collect()
    }
    pub(crate) fn clear_pending_cleanup(&mut self, pending: cgka_traits::PendingStateRef) {
        self.pending_cleanup.remove(&pending);
    }
    pub(crate) fn register_package_cleanup(
        &mut self,
        original: &Arc<ConsentState>,
        scope: cgka_traits::selected_chat_key_package::SelectedChatPurposeScope,
        reference: [u8; 32],
    ) -> Result<(), SelectedChatCopyError> {
        if !self.package_cleanup.contains_key(&reference)
            && self.package_cleanup.len()
                >= cgka_traits::selected_chat_key_package::MAX_SELECTED_CHAT_PURPOSE_ROWS
        {
            return Err(SelectedChatCopyError::Busy);
        }
        self.package_cleanup
            .insert(reference, (scope, Arc::downgrade(original)));
        Ok(())
    }
    pub(crate) fn packages_to_retire(
        &self,
    ) -> Vec<(
        cgka_traits::selected_chat_key_package::SelectedChatPurposeScope,
        [u8; 32],
    )> {
        self.package_cleanup
            .iter()
            .filter(|(_, (_, owner))| !owner.upgrade().is_some_and(|original| original.is_live()))
            .map(|(reference, (scope, _))| (scope.clone(), *reference))
            .collect()
    }
    pub(crate) fn clear_package_cleanup(&mut self, reference: &[u8; 32]) {
        self.package_cleanup.remove(reference);
    }
    pub(crate) fn owns_consent(&self, state: &Arc<ConsentState>) -> bool {
        self.consent_history
            .get(&state.observation.binding())
            .and_then(|(_, weak)| weak.upgrade())
            .is_some_and(|current| Arc::ptr_eq(&current, state))
    }
    pub(crate) fn owns(&self, request: &Arc<RequestState>) -> bool {
        self.current
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|current| Arc::ptr_eq(&current, request))
    }
    pub(crate) fn receive_consent(
        &mut self,
        observation: cgka_engine::selected_chat_consent::AuthenticatedSelectedChatRequest,
        packet: Vec<u8>,
        protected_generation: u64,
        #[cfg(all(test, feature = "test-policy-overrides"))] test_lifetime: Option<Duration>,
    ) -> Result<Arc<ConsentState>, SelectedChatCopyError> {
        let binding = observation.binding();
        if let Some((deadline, prior)) = self.consent_history.get(&binding) {
            if Instant::now() >= *deadline {
                return Err(SelectedChatCopyError::Closed);
            }
            return prior
                .upgrade()
                .filter(|state| state.is_live())
                .ok_or(SelectedChatCopyError::Closed);
        }
        if self
            .consent_history
            .values()
            .any(|(_, weak)| weak.upgrade().is_some_and(|state| state.is_live()))
        {
            return Err(SelectedChatCopyError::Busy);
        }
        // Negative identities never renew a receipt clock in this account lifetime.
        if self.consent_history.len() >= MAX_SELECTED_CHAT_RECEIPT_IDENTITIES {
            return Err(SelectedChatCopyError::Busy);
        }
        let generation = self
            .consent_lifetime
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or(SelectedChatCopyError::RuntimeUnavailable)?;
        let lifetime = SELECTED_CHAT_REQUEST_LIFETIME;
        #[cfg(all(test, feature = "test-policy-overrides"))]
        let lifetime = test_lifetime.unwrap_or(lifetime);
        let deadline = Instant::now()
            .checked_add(lifetime)
            .ok_or(SelectedChatCopyError::RuntimeUnavailable)?;
        let state = Arc::new(ConsentState {
            lease: OwnerLease {
                lifetime: Arc::downgrade(&self.consent_lifetime),
                generation,
                original_deadline: deadline,
                terminal: AtomicU8::new(0),
            },
            cancelled: tokio::sync::Notify::new(),
            observation,
            packet,
            protected_generation,
            progress: Mutex::new(ConsentProgress::default()),
            public_handle: Mutex::new(Weak::new()),
        });
        self.consent_lifetime.store(generation, Ordering::Release);
        self.consent_history
            .insert(binding, (deadline, Arc::downgrade(&state)));
        Ok(state)
    }
    pub(crate) fn reserve(
        &mut self,
        ordinary: OrdinaryChatAnchor,
        protected: cgka_engine::private_roster_settlement::ValidatedSettledDeviceRoster,
    ) -> Result<Arc<RequestState>, SelectedChatCopyError> {
        if self
            .current
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|request| request.is_live())
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
            cancelled: tokio::sync::Notify::new(),
            _ordinary: ordinary,
            _protected: protected.candidate().clone(),
            _protected_generation: protected.settlement_generation(),
            _request_nonce: nonce,
            progress: Mutex::new(RequestProgress::default()),
        });
        self.lifetime.store(generation, Ordering::Release);
        self.current = Some(Arc::downgrade(&state));
        Ok(state)
    }
}

pub(crate) struct ConsentHandle {
    pub(crate) original: Arc<ConsentState>,
}
impl Drop for ConsentHandle {
    fn drop(&mut self) {
        self.original.cancel();
    }
}
#[derive(Default)]
pub(crate) struct ConsentProgress {
    pub(crate) offer: Option<Vec<u8>>,
    pub(crate) nonce: Option<[u8; 32]>,
    pub(crate) response: Option<Vec<u8>>,
}
pub(crate) struct ConsentState {
    lease: OwnerLease,
    cancelled: tokio::sync::Notify,
    pub(crate) observation: cgka_engine::selected_chat_consent::AuthenticatedSelectedChatRequest,
    pub(crate) packet: Vec<u8>,
    pub(crate) protected_generation: u64,
    pub(crate) progress: Mutex<ConsentProgress>,
    public_handle: Mutex<Weak<ConsentHandle>>,
}
impl ConsentState {
    pub(crate) fn public_handle(self: &Arc<Self>) -> Arc<ConsentHandle> {
        let mut slot = self.public_handle.lock().expect("selected consent handle");
        if let Some(handle) = slot.upgrade() {
            return handle;
        }
        let handle = Arc::new(ConsentHandle {
            original: self.clone(),
        });
        *slot = Arc::downgrade(&handle);
        handle
    }
    fn is_live(&self) -> bool {
        self.lease.phase() == SelectedChatCopyPhase::AwaitingSiblingConsent
    }
    pub(crate) fn generation(&self) -> u64 {
        self.lease.generation
    }
    pub(crate) fn cancel(&self) {
        self.lease.cancel();
        self.cancelled.notify_waiters();
    }
    pub(crate) async fn revoked(&self) {
        let notified = self.cancelled.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if !self.is_live() {
            return;
        }
        tokio::select! {
            _ = &mut notified => {},
            _ = tokio::time::sleep_until(self.lease.original_deadline.into()) => {},
        }
    }
    pub(crate) fn snapshot(&self) -> super::SelectedChatConsentSnapshot {
        let approved = self
            .progress
            .lock()
            .expect("selected consent observation")
            .nonce
            .is_some();
        let phase = match self.lease.phase() {
            SelectedChatCopyPhase::AwaitingSiblingConsent if approved => {
                super::SelectedChatConsentPhase::Approved
            }
            SelectedChatCopyPhase::AwaitingSiblingConsent => {
                super::SelectedChatConsentPhase::AwaitingApproval
            }
            SelectedChatCopyPhase::Cancelled => super::SelectedChatConsentPhase::Cancelled,
            SelectedChatCopyPhase::Expired => super::SelectedChatConsentPhase::Expired,
            SelectedChatCopyPhase::Closed | SelectedChatCopyPhase::InviteConfirmed => {
                super::SelectedChatConsentPhase::Closed
            }
        };
        super::SelectedChatConsentSnapshot {
            revision: if self.is_live() {
                1 + u64::from(approved)
            } else {
                2 + u64::from(approved)
            },
            phase,
            chat_selector: self.observation.ordinary_group().as_slice().to_vec(),
        }
    }
    pub(crate) fn check_revision(&self, revision: u64) -> Result<(), SelectedChatCopyError> {
        if !self.is_live() {
            return Err(SelectedChatCopyError::Closed);
        }
        if self.snapshot().revision != revision {
            return Err(SelectedChatCopyError::StaleRevision);
        }
        Ok(())
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
