//! Passive bounded diagnostic; never a permission, retry, wake or clock inlet.
use super::{ClientLinkingError, OriginalEnrollmentSharingChoice, SiblingOriginal};
use std::sync::{
    Arc, LazyLock, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};

const LIMIT: u64 = 1_000_000_000;
const WIDTH: usize = 23;
#[derive(Clone, Copy)]
pub(super) enum Event {
    ExpectedCaptured,
    PrimaryCommitted,
    RetainedBeforePrimary,
    RetainedAfterPrimary,
    RetainedPrimaryUnknown,
    RetryEntry,
    RetryAttempt,
    RetryAuthenticated,
    RetryAuthenticationFailed,
    RetryDispatched,
    RetryDispatchFailed,
    RequestAdmitted,
    WakeSent,
    CompletionEntered,
    CompletionReturned,
    ConsentAttempted,
    ConsentStarted,
    ConsentDeferred,
    ConsentDeniedGate,
    ConsentDeniedEngine,
    ConsentDeniedOwner,
    ConsentDeniedRuntime,
    ConsentDeniedOther,
}
#[derive(Default)]
struct Trace {
    seq: u64,
    counts: [u64; WIDTH],
    first: [u64; WIDTH],
    last: [u64; WIDTH],
    unknown: bool,
}
struct Entry {
    owner: Weak<OriginalEnrollmentSharingChoice>,
    trace: Trace,
}
static ACTIVE: LazyLock<bool> =
    LazyLock::new(|| std::env::var("MDK_UPSTREAM_RECIPIENT_INTAKE_TRACE").as_deref() == Ok("1"));
static TRACES: Mutex<Vec<Entry>> = Mutex::new(Vec::new());
static UNKNOWN: AtomicBool = AtomicBool::new(false);

pub(super) fn register(choice: &Arc<OriginalEnrollmentSharingChoice>) {
    if !*ACTIVE {
        return;
    }
    let Ok(mut traces) = TRACES.try_lock() else {
        UNKNOWN.store(true, Ordering::Relaxed);
        return;
    };
    traces.retain(|entry| entry.owner.strong_count() != 0);
    if traces
        .iter()
        .any(|entry| entry.owner.as_ptr() == Arc::as_ptr(choice))
    {
        return;
    }
    if traces.len() >= 16 {
        UNKNOWN.store(true, Ordering::Relaxed);
        return;
    }
    traces.push(Entry {
        owner: Arc::downgrade(choice),
        trace: Trace::default(),
    });
}
pub(super) fn record(choice: &OriginalEnrollmentSharingChoice, event: Event) {
    if !*ACTIVE {
        return;
    }
    let Ok(mut traces) = TRACES.try_lock() else {
        UNKNOWN.store(true, Ordering::Relaxed);
        return;
    };
    let Some(entry) = traces
        .iter_mut()
        .find(|entry| std::ptr::eq(entry.owner.as_ptr(), choice))
    else {
        UNKNOWN.store(true, Ordering::Relaxed);
        return;
    };
    let trace = &mut entry.trace;
    let index = event as usize;
    if trace.seq == LIMIT || trace.counts[index] == LIMIT {
        trace.unknown = true;
        return;
    }
    trace.seq += 1;
    trace.counts[index] += 1;
    if trace.first[index] == 0 {
        trace.first[index] = trace.seq;
    }
    trace.last[index] = trace.seq;
}
pub(super) fn retained(choice: &OriginalEnrollmentSharingChoice) {
    if !*ACTIVE {
        return;
    }
    let primary = choice
        .progress
        .try_lock()
        .ok()
        .map(|progress| progress.primary_committed);
    record(
        choice,
        match primary {
            Some(false) => Event::RetainedBeforePrimary,
            Some(true) => Event::RetainedAfterPrimary,
            None => Event::RetainedPrimaryUnknown,
        },
    );
}
pub(super) fn original(original: &SiblingOriginal, event: Event) {
    if let SiblingOriginal::Recipient { choice, .. } = original {
        record(choice, event);
    }
}
pub(super) fn deferred(original: &SiblingOriginal, error: &ClientLinkingError) {
    self::original(original, Event::ConsentDeferred);
    self::original(
        original,
        match error {
            ClientLinkingError::Gate(_) => Event::ConsentDeniedGate,
            ClientLinkingError::Engine(_) => Event::ConsentDeniedEngine,
            ClientLinkingError::Owner(_) => Event::ConsentDeniedOwner,
            ClientLinkingError::Runtime(_) => Event::ConsentDeniedRuntime,
            _ => Event::ConsentDeniedOther,
        },
    );
}
pub(super) fn emit(choice: &OriginalEnrollmentSharingChoice) {
    if !*ACTIVE {
        return;
    }
    let role = if choice.scope.local_device == choice.context.recipient {
        "recipient"
    } else if choice.scope.local_device == choice.context.approver {
        "sponsor"
    } else {
        "other"
    };
    let traces = TRACES.try_lock().ok();
    let found = traces.as_ref().and_then(|rows| {
        rows.iter()
            .find(|entry| std::ptr::eq(entry.owner.as_ptr(), choice))
    });
    let empty = Trace::default();
    let trace = found.map(|entry| &entry.trace).unwrap_or(&empty);
    let unknown = UNKNOWN.load(Ordering::Relaxed) || trace.unknown || found.is_none();
    eprintln!(
        "ordinary-recipient-intake role={role} seq={} counts={:?} first={:?} last={:?} unknown={unknown}",
        trace.seq, trace.counts, trace.first, trace.last
    );
}
