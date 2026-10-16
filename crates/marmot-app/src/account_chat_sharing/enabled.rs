use super::{AccountSharingError, AccountSharingSnapshot};
use cgka_engine::account_chat_sharing::{
    AccountSharingScope, AuthenticatedAccountSharingRequest, OwnedAccountSharingChannel,
    TrustedAccountSharingLease,
};
use cgka_traits::EngineError;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
pub(crate) const MAX_OWNERS: usize = 128;
#[cfg(all(test, feature = "test-policy-overrides"))]
#[derive(Clone, Copy, Debug)]
pub(crate) enum SiblingMaintenanceFailure {
    Owner,
    Collection,
    Runtime,
    Engine,
    Genesis,
    Gate,
    PrivateInvite,
}
#[cfg(all(test, feature = "test-policy-overrides"))]
#[derive(Clone, Copy, Debug)]
pub(crate) enum SiblingPublicationStage {
    BeforeCoreWrap,
    AfterCoreWrap,
    BeforeRelayPublication,
    AfterRelayPublication,
}
#[cfg(all(test, feature = "test-policy-overrides"))]
#[derive(Default)]
pub(crate) struct SiblingMaintenanceDiagnostics {
// COMPLETION_TEST_BEGIN
pub(crate) successful_consent_message: Option<cgka_traits::MessageId>,
pub(crate) successful_commit_proof: bool,
// COMPLETION_TEST_END

    // Original live, state live, ready, handshake published, local policy,
    // proof published, peer proof received, complete (low to high bits).
    pub(crate) channel_bits: usize,
    pub(crate) visits: usize,
    pub(crate) failures: usize,
    pub(crate) last_failure: Option<SiblingMaintenanceFailure>,
    pub(crate) publication_stage: Option<SiblingPublicationStage>,
}

#[cfg(all(test, feature = "test-policy-overrides"))]
pub(crate) type SiblingMaintenanceSnapshot = (
    usize,
    usize,
    usize,
    Option<SiblingMaintenanceFailure>,
    Option<SiblingPublicationStage>,
);
#[cfg(all(test, feature = "test-policy-overrides"))]
impl SiblingMaintenanceDiagnostics {
    pub(crate) fn snapshot(&self) -> SiblingMaintenanceSnapshot {
        (
            self.channel_bits,
            self.visits,
            self.failures,
            self.last_failure,
            self.publication_stage,
        )
    }
}
pub(crate) struct State {
    owner: Weak<AtomicBool>,
    pub(crate) deadline: Instant,
    pub(crate) approval_id: [u8; 32],
    pub(crate) created_at: u64,
    pub(crate) scope: Mutex<Option<AccountSharingScope>>,
    pub(crate) progress: Mutex<Progress>,
    pub(crate) legacy_capture:
        Mutex<Option<Arc<crate::client::legacy_chat_acceptance::CapturedLegacyChats>>>,
    cancelled: AtomicBool,
    pub(crate) revoked: tokio::sync::Notify,
    aliases: AtomicUsize,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) sibling_diagnostics: Mutex<SiblingMaintenanceDiagnostics>,
}
#[derive(Default)]
pub(crate) struct Progress {
    pub(crate) revision: u64,
    pub(crate) approved: bool,
    pub(crate) complete: bool,
}
impl State {
    pub(crate) fn new(owner: &Arc<AtomicBool>, approval_id: [u8; 32]) -> Arc<Self> {
        Self::new_until(
            owner,
            approval_id,
            Instant::now() + Duration::from_secs(600),
        )
    }
    pub(crate) fn new_until(
        owner: &Arc<AtomicBool>,
        approval_id: [u8; 32],
        deadline: Instant,
    ) -> Arc<Self> {
        Arc::new(Self {
            owner: Arc::downgrade(owner),
            deadline: deadline.min(Instant::now() + Duration::from_secs(600)),
            approval_id,
            created_at: crate::unix_now_seconds(),
            scope: Mutex::new(None),
            progress: Mutex::new(Progress {
                revision: 1,
                ..Default::default()
            }),
            legacy_capture: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            revoked: tokio::sync::Notify::new(),
            aliases: AtomicUsize::new(0),
            #[cfg(all(test, feature = "test-policy-overrides"))]
            sibling_diagnostics: Mutex::new(SiblingMaintenanceDiagnostics::default()),
        })
    }
    pub(crate) fn live(&self) -> bool {
        !self.cancelled.load(Ordering::Acquire)
            && Instant::now() < self.deadline
            && self
                .owner
                .upgrade()
                .is_some_and(|x| x.load(Ordering::Acquire))
    }
    pub(crate) fn check(&self, revision: u64) -> Result<(), AccountSharingError> {
        if !self.live() {
            return Err(AccountSharingError::Closed);
        }
        if self.progress.lock().expect("sharing progress").revision != revision {
            return Err(AccountSharingError::StaleRevision);
        }
        Ok(())
    }
    pub(crate) fn snapshot(&self) -> Result<AccountSharingSnapshot, AccountSharingError> {
        let p = self.progress.lock().expect("sharing progress");
        if !p.complete && !self.live() {
            return Err(AccountSharingError::Closed);
        }
        let scope = self.scope.lock().expect("sharing scope");
        let s = scope.as_ref().ok_or(AccountSharingError::NotReady)?;
        Ok(AccountSharingSnapshot {
            protected_group: s.protected.group_id.clone(),
            protected_epoch: s.protected.epoch.0,
            source_device: s.source.clone(),
            recipient_device: s.recipient.clone(),
            revision: p.revision,
            approved: p.approved,
            complete: p.complete,
        })
    }
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.revoked.notify_waiters();
    }
    pub(crate) fn retain(&self) {
        self.aliases.fetch_add(1, Ordering::AcqRel);
    }
    pub(crate) fn release(&self) {
        if self.aliases.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.cancel();
        }
    }
}
pub(crate) struct OriginalLease(pub(crate) Weak<State>);
impl TrustedAccountSharingLease for OriginalLease {
    fn approved_policy_id(&self, _: &AccountSharingScope) -> Result<[u8; 32], EngineError> {
        self.0
            .upgrade()
            .filter(|s| s.live())
            .map(|s| s.approval_id)
            .ok_or_else(|| EngineError::Other("sharing original closed".into()))
    }
    fn validate(&self, scope: &AccountSharingScope) -> Result<Instant, EngineError> {
        let state = self
            .0
            .upgrade()
            .filter(|s| s.live())
            .ok_or_else(|| EngineError::Other("sharing original closed".into()))?;
        let mut fixed = state.scope.lock().expect("sharing scope");
        match fixed.as_ref() {
            Some(x) if x != scope => {
                return Err(EngineError::Other("sharing scope changed".into()));
            }
            None => *fixed = Some(scope.clone()),
            _ => {}
        }
        Ok(state.deadline)
    }
}
pub(crate) struct Entry {
    pub(crate) original: Weak<State>,
    pub(crate) pending: Option<Arc<State>>,
    pub(crate) request: Option<AuthenticatedAccountSharingRequest>,
    pub(crate) channel: Option<OwnedAccountSharingChannel>,
    pub(crate) recipient: bool,
    pub(crate) consent_ready: bool,
}
#[cfg(all(test, feature = "test-policy-overrides"))]
#[derive(Default)]
pub(crate) struct RecordReceiptProbe {
    pub(crate) committed: std::sync::atomic::AtomicUsize,
}

pub(crate) struct AccountSharingOwner {
    pub(crate) lifetime: Arc<AtomicBool>,
    pub(crate) entries: BTreeMap<[u8; 32], Entry>,
    pub(crate) seen: BTreeSet<[u8; 32]>,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) record_receipt_probe: Option<Arc<RecordReceiptProbe>>,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) next_original_lifetime_for_test: Option<Duration>,
    pub(crate) departure_cursor: Option<[u8; 32]>,
    pub(crate) automatic_handshake_slots: Arc<tokio::sync::Semaphore>,
    pub(crate) automatic:
        BTreeMap<[u8; 32], crate::client::account_chat_sharing::automatic::AutomaticChannel>,
}
impl Default for AccountSharingOwner {
    fn default() -> Self {
        Self {
            lifetime: Arc::new(AtomicBool::new(true)),
            entries: BTreeMap::new(),
            seen: BTreeSet::new(),
            #[cfg(all(test, feature = "test-policy-overrides"))]
            record_receipt_probe: None,
            #[cfg(all(test, feature = "test-policy-overrides"))]
            next_original_lifetime_for_test: None,
            automatic_handshake_slots: Arc::new(tokio::sync::Semaphore::new(
                crate::client::account_chat_sharing::automatic::MAX_AUTOMATIC_HANDSHAKES,
            )),
            automatic: BTreeMap::new(),
            departure_cursor: None,
        }
    }
}
impl Drop for AccountSharingOwner {
    fn drop(&mut self) {
        self.lifetime.store(false, Ordering::Release);
        for entry in self.entries.values() {
            if let Some(state) = entry.original.upgrade() {
                state.cancel();
            }
        }
    }
}
