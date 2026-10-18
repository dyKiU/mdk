//! Opt-in, bounded observation of two exact native sessions; no enrollment authority.
use super::{
    ClientLinkingError, DeviceLinkingError, DeviceLinkingPhase, LinkError, OwnerError, SessionState,
};
use std::sync::{
    Arc, Mutex, OnceLock, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

static PROBES: OnceLock<Mutex<Vec<Weak<Probe>>>> = OnceLock::new();
static LOST: AtomicBool = AtomicBool::new(false);

pub(in super::super) struct Probe {
    owner: Weak<SessionState>,
    original_scope: super::PurposeAttemptScope,
    ordinal: AtomicU64,
    receive_before_reopen: Mutex<Option<([u8; 2], u64)>>,
    // First attempted failure: origin(1refresh/2driver), finitecategory, verifier/runtime detail (0=unclassified/not applicable).
    attempted_error: Mutex<Option<([u8; 3], u8, u64)>>,
    accepted_terminal: Mutex<Option<([u8; 2], u64)>>,
}
impl Probe {
    pub(super) fn arm(owner: &Arc<SessionState>) -> Arc<Self> {
        let probe = Arc::new(Self {
            owner: Arc::downgrade(owner),
            original_scope: owner.scope.clone(),
            ordinal: AtomicU64::new(0),
            receive_before_reopen: Mutex::new(None),
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
            (Ok(error), Ok(transition)) => (!LOST.load(Ordering::Acquire), error.as_ref().map(|v| v.0), transition.as_ref().map(|v| v.0)),
            _ => (false, None, None),
        }
    }
    pub(in super::super) fn producer_snapshot(&self) -> (bool, Option<[u64; 2]>, Option<[u64; 3]>, Option<u64>) {
        match (self.attempted_error.try_lock(), self.receive_before_reopen.try_lock(), self.accepted_terminal.try_lock()) {
            (Ok(error), Ok(receive), Ok(terminal)) => (
                !LOST.load(Ordering::Acquire),
                error.as_ref().map(|v| [u64::from(v.1), v.2]),
                receive.as_ref().map(|v| [u64::from(v.0[0]), u64::from(v.0[1]), v.1]),
                terminal.as_ref().map(|v| v.1),
            ),
            _ => (false, None, None, None),
        }
    }
    fn next_ordinal(&self) -> Option<u64> {
        match self.ordinal.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1)) {
            Ok(n) => Some(n + 1),
            Err(_) => { LOST.store(true, Ordering::Release); None }
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
fn first_error(probe: &Probe, value: [u8; 3], producer: u8) {
    if let Ok(mut slot) = probe.attempted_error.try_lock() {
        if slot.is_none() && let Some(ordinal) = probe.next_ordinal() { *slot = Some((value, producer, ordinal)); }
    } else { LOST.store(true, Ordering::Release); }
}
pub(super) fn refresh_error(owner: &SessionState, error: &ClientLinkingError, producer: u8) {
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
        ClientLinkingError::Runtime(error) => match error.privacy_safe_kind() {
            "transport_closed" => 1,
            "account_worker_response_timed_out" => 2,
            "runtime_stopping" => 3,
            "runtime_busy" => 4,
            "account_worker_busy" => 5,
            "account_session_busy" => 6,
            "relay_directory" => 7,
            "onboarding_required" => 8,
            "account_setup_recovery_required" => 9,
            "storage_busy" => 10,
            "storage_closed" => 11,
            "storage_backend" => 12,
            "storage_serialization" => 13,
            "storage_capacity" => 14,
            "storage_corruption" => 15,
            "storage_not_found" => 16,
            "storage_already_exists" => 17,
            "storage_unsupported_schema_version" => 18,
            "sqlite" => 19,
            "io" => 20,
            "account_home_secret_not_found" => 21,
            "account_home_unknown_account" => 22,
            _ => 0, // Runtime privacy kind outside this small set: UNKNOWN, never NA.
        },
        _ => 0, // Non-verifier/non-Runtime detail remains not applicable.
    };
    observe(owner, |probe| {
        first_error(probe, [1, category, detail], producer)
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
        first_error(probe, [2, category, 0], 0)
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
            if let Ok(mut slot) = probe.accepted_terminal.try_lock() {
                if slot.is_none() && let Some(ordinal) = probe.next_ordinal() { *slot = Some(([phase(before), phase(after)], ordinal)); }
            } else { LOST.store(true, Ordering::Release); }
        });
    }
}


struct ObservationContext {
    probe: Weak<Probe>,
    producer: std::cell::Cell<u8>,
}
tokio::task_local! { static OBSERVATION: ObservationContext; }

pub(super) async fn observation<T>(owner: &SessionState, future: impl std::future::Future<Output = T>) -> (T, u8) {
    let mut selected = Weak::new();
    if let Some(registry) = PROBES.get() {
        if let Ok(entries) = registry.try_lock() {
            for entry in entries.iter() {
                if let Some(probe) = entry.upgrade() && std::ptr::eq(probe.owner.as_ptr(), owner) {
                    selected = Arc::downgrade(&probe);
                    break;
                }
            }
        } else { LOST.store(true, Ordering::Release); }
    }
    OBSERVATION.scope(ObservationContext { probe: selected, producer: std::cell::Cell::new(0) }, async move {
        let result = future.await;
        let producer = OBSERVATION.with(|context| context.producer.get());
        (result, producer)
    }).await
}

// Called only on actual TransportClosed-producing branches. No new task/RPC.
pub(in super::super) fn producer(code: u8) {
    let _ = OBSERVATION.try_with(|context| {
        if context.probe.upgrade().is_some() {
            let old = context.producer.get();
            if old == 0 || old == code { context.producer.set(code); }
            else { context.producer.set(255); LOST.store(true, Ordering::Release); }
        }
    });
}

pub(in super::super) fn receive_before_reopen(client: &crate::AppClient, error: &crate::AppError) {
    let Some(scope) = client.native_settlement_scope_for_terminal_diagnostic() else { return; };
    let Some(registry) = PROBES.get() else { return; };
    let Ok(entries) = registry.try_lock() else { LOST.store(true, Ordering::Release); return; };
    for entry in entries.iter() {
        if let Some(probe) = entry.upgrade() && &probe.original_scope == scope
            && probe.owner.upgrade().is_some_and(|owner| !owner.closed.load(Ordering::Acquire))
        {
            if let Ok(mut slot) = probe.receive_before_reopen.try_lock() {
                if slot.is_none() && let Some(ordinal) = probe.next_ordinal() {
                    *slot = Some(([storage_shape(error), receive_kind(error)], ordinal));
                }
            } else { LOST.store(true, Ordering::Release); }
        }
    }
}

fn storage_shape(error: &crate::AppError) -> u8 {
    use crate::AppError;
    use cgka_session::SessionError;
    use cgka_traits::error::EngineError;
    use marmot_account::AccountError;
    match error {
        AppError::Storage(_) => 1,
        AppError::Session(SessionError::Storage(_)) => 2,
        AppError::Session(SessionError::Engine(EngineError::Storage(_))) => 3,
        AppError::Account(AccountError::Engine(EngineError::Storage(_))) => 4,
        AppError::Account(AccountError::Session(SessionError::Storage(_))) => 5,
        AppError::Account(AccountError::Session(SessionError::Engine(EngineError::Storage(_)))) => 6,
        AppError::Session(SessionError::Engine(_)) => 7,
        AppError::Account(AccountError::Engine(_)) => 8,
        AppError::Account(AccountError::Session(SessionError::Engine(_))) => 9,
        AppError::Sqlite(_) => 10,
        _ => 0,
    }
}
fn receive_kind(error: &crate::AppError) -> u8 {
    match error.privacy_safe_kind() {
        "transport_closed" => 1,
        "account_worker_response_timed_out" => 2,
        "runtime_stopping" => 3,
        "runtime_busy" => 4,
        "account_worker_busy" => 5,
        "account_session_busy" => 6,
        "relay_directory" => 7,
        "onboarding_required" => 8,
        "account_setup_recovery_required" => 9,
        "storage_busy" => 10,
        "storage_closed" => 11,
        "storage_backend" => 12,
        "storage_serialization" => 13,
        "storage_capacity" => 14,
        "storage_corruption" => 15,
        "storage_not_found" => 16,
        "storage_already_exists" => 17,
        "storage_unsupported_schema_version" => 18,
        "sqlite" => 19,
        "io" => 20,
        "account_home_secret_not_found" => 21,
        "account_home_unknown_account" => 22,
        "unknown_group" => 23,
        "group_not_hydrated" => 24,
        "unknown_pending" => 25,
        "not_a_member" => 26,
        "not_group_admin" => 27,
        "unknown_member" => 28,
        "invalid_credential_identity" => 29,
        "admin_cannot_self_remove" => 30,
        "leave_already_requested" => 31,
        "admin_depletion" => 32,
        "missing_required_capabilities" => 33,
        "disbanding_unsupported_members" => 34,
        "disbanding_not_enabled" => 35,
        "unsupported_ciphersuite" => 36,
        "invalid_app_message_payload" => 37,
        "invalid_account_identity_proof" => 38,
        "invalid_key_package_lifetime" => 39,
        "invalid_key_package_capabilities" => 40,
        "app_message_epoch_mismatch" => 41,
        "app_message_epoch_unsettled" => 42,
        "forked_epoch" => 43,
        "queued_outbound_at_capacity" => 44,
        "group_unrecoverable_repair_required" => 45,
        "invalid_transition" => 46,
        "storage" => 47,
        "peeler" => 48,
        "serialize" => 49,
        "invalid_welcome" => 50,
        "linking_welcome_denied" => 51,
        "selected_chat_welcome_denied" => 52,
        "missing_welcome_key_package" => 53,
        "welcome_already_processed" => 54,
        "private_enrollment_intake_at_capacity" => 55,
        "backend" => 56,
        "other" => 57,
        "transport" => 58,
        "account_transport" => 59,
        "account_transport_routing" => 60,
        "account_key_package" => 61,
        "account_clock_skew_blocked" => 62,
        "account_key_package_rotation_in_progress" => 63,
        "account_public_key_package_publication_disabled" => 64,
        "account_wrong_delivery" => 65,
        "account_unknown" => 66,
        "storage_record_denied_by_departure" => 67,
        "storage_snapshot_missing" => 68,
        "storage_timeline_cursor_expired" => 69,
        _ => 0, // Unclassified STATIC privacy kind: UNKNOWN, no payload printed.
    }
}
