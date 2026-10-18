//! Opt-in, bounded observation of two exact native sessions; no enrollment authority.
use super::{
    ClientLinkingError, DeviceLinkingError, DeviceLinkingPhase, LinkError, OwnerError, SessionState,
};
use std::sync::{
    Arc, Mutex, OnceLock, Weak,
    atomic::{AtomicBool, Ordering},
};

static PROBES: OnceLock<Mutex<Vec<Weak<Probe>>>> = OnceLock::new();
static LOST: AtomicBool = AtomicBool::new(false);

pub(in super::super) struct Probe {
    owner: Weak<SessionState>,
    // First attempted failure: origin(1refresh/2driver), finitecategory, verifierdetail(or0NA).
    attempted_error: Mutex<Option<[u8; 3]>>,
    accepted_terminal: Mutex<Option<[u8; 2]>>,
}
impl Probe {
    pub(super) fn arm(owner: &Arc<SessionState>) -> Arc<Self> {
        let probe = Arc::new(Self {
            owner: Arc::downgrade(owner),
            attempted_error: Mutex::new(None),
            accepted_terminal: Mutex::new(None),
        });
        let registry = PROBES.get_or_init(|| Mutex::new(Vec::new()));
        if let Ok(mut entries) = registry.try_lock() {
            entries.retain(|entry| entry.strong_count() != 0);
            if entries.len() < 2 {
                entries.push(Arc::downgrade(&probe));
            } else {
                LOST.store(true, Ordering::Release);
            }
        } else {
            LOST.store(true, Ordering::Release);
        }
        probe
    }
    pub(in super::super) fn snapshot(&self) -> (bool, Option<[u8; 3]>, Option<[u8; 2]>) {
        match (
            self.attempted_error.try_lock(),
            self.accepted_terminal.try_lock(),
        ) {
            (Ok(error), Ok(transition)) => (!LOST.load(Ordering::Acquire), *error, *transition),
            _ => (false, None, None),
        }
    }
}
fn observe(owner: &SessionState, record: impl Fn(&Probe)) {
    let Some(registry) = PROBES.get() else {
        return;
    };
    let Ok(entries) = registry.try_lock() else {
        LOST.store(true, Ordering::Release);
        return;
    };
    for entry in entries.iter() {
        if let Some(probe) = entry.upgrade()
            && std::ptr::eq(probe.owner.as_ptr(), owner)
        {
            record(&probe);
        }
    }
}
fn first<T: Copy>(slot: &Mutex<Option<T>>, value: T) {
    if let Ok(mut slot) = slot.try_lock() {
        if slot.is_none() {
            *slot = Some(value);
        }
    } else {
        LOST.store(true, Ordering::Release);
    }
}
pub(super) fn refresh_error(owner: &SessionState, error: &ClientLinkingError) {
    let category = match error {
        ClientLinkingError::Owner(_) => 1,
        ClientLinkingError::Collection(_) => 2,
        ClientLinkingError::Runtime(_) => 3,
        ClientLinkingError::Engine(_) => 4,
        ClientLinkingError::Genesis(_) => 5,
        ClientLinkingError::Gate(_) => 6,
        ClientLinkingError::PrivateInvite(_) => 7,
    };
    let detail = match error {
        ClientLinkingError::Owner(OwnerError::Verifier(error)) => match error {
            LinkError::InvalidContext => 1,
            LinkError::BindingMismatch => 2,
            LinkError::InvalidFrame => 3,
            LinkError::StaleFlow => 4,
            LinkError::SimultaneousRequest => 5,
            LinkError::Expired => 6,
            LinkError::Cancelled => 7,
            LinkError::Closed => 8,
            LinkError::LimitExceeded => 9,
            LinkError::NotReady => 10,
            LinkError::AlreadyConsumed => 11,
            LinkError::Sdk => 12,
        },
        _ => 0, // Not a verifier error; this does not classify an opaque Engine/Runtime payload.
    };
    observe(owner, |probe| {
        first(&probe.attempted_error, [1, category, detail])
    });
}
pub(super) fn driver_error(owner: &SessionState, error: &DeviceLinkingError) {
    let category = match error {
        DeviceLinkingError::Unsupported => 1,
        DeviceLinkingError::Closed => 2,
        DeviceLinkingError::InvalidPacket => 3,
        DeviceLinkingError::NotReady => 4,
        DeviceLinkingError::StaleRevision => 5,
        DeviceLinkingError::RuntimeUnavailable => 6,
    };
    observe(owner, |probe| {
        first(&probe.attempted_error, [2, category, 0])
    });
}
fn phase(phase: DeviceLinkingPhase) -> u8 {
    match phase {
        DeviceLinkingPhase::AwaitingSetup => 0,
        DeviceLinkingPhase::AwaitingPeer => 1,
        DeviceLinkingPhase::ComparisonAvailable => 2,
        DeviceLinkingPhase::AwaitingPeerVerification => 3,
        DeviceLinkingPhase::VerificationCompleteEnrollmentPending => 4,
        DeviceLinkingPhase::Cancelled => 5,
        DeviceLinkingPhase::Expired => 6,
        DeviceLinkingPhase::Failed => 7,
        DeviceLinkingPhase::EnrollmentComplete => 8,
    }
}
pub(super) fn accepted_terminal(
    owner: &SessionState,
    before: DeviceLinkingPhase,
    after: DeviceLinkingPhase,
) {
    if matches!(
        after,
        DeviceLinkingPhase::Cancelled
            | DeviceLinkingPhase::Expired
            | DeviceLinkingPhase::Failed
            | DeviceLinkingPhase::EnrollmentComplete
    ) {
        observe(owner, |probe| {
            first(&probe.accepted_terminal, [phase(before), phase(after)])
        });
    }
}
