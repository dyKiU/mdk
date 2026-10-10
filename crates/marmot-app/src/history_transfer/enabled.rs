//! Process-local original archive owners. Persisted archive rows never recreate these.
use super::{HistoryTransferError, HistoryTransferSnapshot};
use cgka_engine::history_transfer::{HistoryScope, TrustedHistoryLease};
use cgka_traits::EngineError;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

pub(crate) const MAX_HISTORY_OWNERS: usize = 128;
const ORIGINAL_HISTORY_LIFETIME: Duration = Duration::from_secs(600);

pub(crate) struct State {
    owner: Weak<AtomicBool>,
    pub(crate) deadline: Instant,
    pub(crate) scope: Mutex<Option<HistoryScope>>,
    pub(crate) progress: Mutex<Progress>,
    cancelled: AtomicBool,
    pub(crate) revoked: tokio::sync::Notify,
    aliases: AtomicUsize,
}
#[derive(Default)]
pub(crate) struct Progress {
    pub(crate) revision: u64,
    pub(crate) imported_records: u32,
    pub(crate) complete: bool,
}
impl State {
    pub(crate) fn new(owner: &Arc<AtomicBool>) -> Arc<Self> {
        Arc::new(Self {
            owner: Arc::downgrade(owner),
            deadline: Instant::now() + ORIGINAL_HISTORY_LIFETIME,
            scope: Mutex::new(None),
            progress: Mutex::new(Progress {
                revision: 1,
                ..Progress::default()
            }),
            cancelled: AtomicBool::new(false),
            revoked: tokio::sync::Notify::new(),
            aliases: AtomicUsize::new(0),
        })
    }
    pub(crate) fn live(&self) -> bool {
        !self.cancelled.load(Ordering::Acquire)
            && Instant::now() < self.deadline
            && self
                .owner
                .upgrade()
                .is_some_and(|owner| owner.load(Ordering::Acquire))
    }
    pub(crate) fn check(&self, revision: u64) -> Result<(), HistoryTransferError> {
        if !self.live() {
            return Err(HistoryTransferError::Closed);
        }
        if self
            .progress
            .lock()
            .expect("history original revision")
            .revision
            != revision
        {
            return Err(HistoryTransferError::StaleRevision);
        }
        Ok(())
    }
    pub(crate) fn snapshot(&self) -> Result<HistoryTransferSnapshot, HistoryTransferError> {
        let progress = self.progress.lock().expect("history original observation");
        // Completion is a committed receipt observation, not another positive action.
        if !progress.complete && !self.live() {
            return Err(HistoryTransferError::Closed);
        }
        let scope = self.scope.lock().expect("history authenticated review");
        let scope = scope.as_ref().ok_or(HistoryTransferError::NotReady)?;
        let descriptor = scope
            .snapshot
            .as_ref()
            .ok_or(HistoryTransferError::NotReady)?;
        Ok(HistoryTransferSnapshot {
            group: scope.ordinary_group.clone(),
            source_device: scope.source.clone(),
            recipient_device: scope.recipient.clone(),
            snapshot_timestamp_ceiling: descriptor.timestamp_ceiling,
            record_count: descriptor.record_count,
            encoded_bytes: descriptor.encoded_bytes,
            fragment_count: descriptor.fragment_count,
            revision: progress.revision,
            imported_records: progress.imported_records,
            complete: progress.complete,
        })
    }
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.revoked.notify_waiters();
    }
    pub(crate) fn retain_host(&self) {
        self.aliases.fetch_add(1, Ordering::AcqRel);
    }
    pub(crate) fn release_host(&self) {
        if self.aliases.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.cancel();
        }
    }
}
// Only installed by the account actor around a Core-derived original scope.
pub(crate) struct OriginalLease(pub(crate) Weak<State>);
impl TrustedHistoryLease for OriginalLease {
    fn validate(&self, scope: &HistoryScope) -> Result<Instant, EngineError> {
        let state = self
            .0
            .upgrade()
            .filter(|state| state.live())
            .ok_or_else(|| EngineError::Other("history original unavailable".into()))?;
        let mut original = state.scope.lock().expect("history original scope");
        match original.as_ref() {
            Some(bound) if bound != scope => {
                return Err(EngineError::Other(
                    "history original context changed".into(),
                ));
            }
            None => *original = Some(scope.clone()),
            _ => {}
        }
        Ok(state.deadline)
    }
}

pub(crate) struct ChannelEntry {
    pub(crate) original: Weak<State>,
    // Pending observations may survive polling; no recipient HPKE key exists yet.
    pub(crate) pending_original: Option<Arc<State>>,
    pub(crate) request: Option<cgka_engine::history_transfer::AuthenticatedHistoryRequest>,
    pub(crate) channel: Option<cgka_engine::history_transfer::OwnedHistoryChannel>,
    pub(crate) archive: Vec<u8>,
    pub(crate) next_chunk: u32,
    pub(crate) complete: bool,
    pub(crate) continue_reply:
        Option<tokio::sync::oneshot::Sender<Result<(), HistoryTransferError>>>,
    pub(crate) receipt_to_publish: Option<u32>,
    pub(crate) staging: Option<storage_sqlite::HistoryArchiveStagingManifest>,
    pub(crate) max_record_lifetime_seconds: Option<u64>,
    pub(crate) incoming:
        std::collections::VecDeque<(cgka_engine::history_transfer::HistoryControl, Vec<u8>)>,
}
pub(crate) struct AccountHistoryOwner {
    pub(crate) lifetime: Arc<AtomicBool>,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) authenticated_chunk_observations: usize,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) refused_original_requests: usize,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) authenticated_request_observations: usize,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) cleanup_attempts_for_test: usize,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) cancel_after_stage_for_test: Option<bool>,
    // Active and terminal IDs share one account-lifetime budget. These negative
    // facts never recreate a lease, key or permission after original retirement.
    pub(crate) seen_transfers: std::collections::BTreeSet<[u8; 32]>,
    pub(crate) channels: std::collections::BTreeMap<[u8; 32], ChannelEntry>,
}
impl Default for AccountHistoryOwner {
    fn default() -> Self {
        Self {
            lifetime: Arc::new(AtomicBool::new(true)),
            #[cfg(all(test, feature = "test-policy-overrides"))]
            authenticated_chunk_observations: 0,
            #[cfg(all(test, feature = "test-policy-overrides"))]
            refused_original_requests: 0,
            #[cfg(all(test, feature = "test-policy-overrides"))]
            authenticated_request_observations: 0,
            #[cfg(all(test, feature = "test-policy-overrides"))]
            cleanup_attempts_for_test: 0,
            #[cfg(all(test, feature = "test-policy-overrides"))]
            cancel_after_stage_for_test: None,
            seen_transfers: Default::default(),
            channels: Default::default(),
        }
    }
}
impl Drop for AccountHistoryOwner {
    fn drop(&mut self) {
        self.lifetime.store(false, Ordering::Release);
        for entry in self.channels.values_mut() {
            if let Some(original) = entry.original.upgrade() {
                original.cancel();
            }
            if let Some(channel) = entry.channel.as_mut() {
                channel.retire();
            }
        }
    }
}
