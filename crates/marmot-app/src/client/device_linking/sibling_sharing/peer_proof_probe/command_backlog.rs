//! One real SDK Body0 versus eight finite actor read commands. Test only.
use super::*;
use std::sync::atomic::AtomicUsize;
use tokio::sync::{Notify, oneshot};
type Reply = oneshot::Receiver<Result<Vec<crate::HistoryNotice>, crate::AppError>>;
struct Probe {
    target: Weak<Existing>,
    sender: Weak<OriginalEnrollmentSharingChoice>,
    nonce: [u8; 32],
    message: OnceLock<cgka_traits::MessageId>,
    fired: AtomicBool,
    known: AtomicBool,
    active_ingest: AtomicUsize,
    paused: Mutex<Option<[bool; 11]>>,
    replies: Mutex<Option<Vec<Reply>>>,
    consumed: AtomicUsize,
    reply_errors: AtomicBool,
    accepted: Mutex<Option<(usize, bool)>>,
    pause_observed: Notify,
    release: Notify,
    accepted_observed: Notify,
}
fn registry() -> &'static OnceLock<Weak<Probe>> {
    static REGISTRY: OnceLock<Weak<Probe>> = OnceLock::new();
    &REGISTRY
}
fn probe() -> Option<Arc<Probe>> { registry().get()?.upgrade() }
pub(crate) struct Guard(Arc<Probe>);
impl Guard {
    pub(crate) fn install_replies(&self, replies: Vec<Reply>) -> bool {
        if replies.len() != 8 { self.0.known.store(false, Ordering::Release); return false; }
        let Ok(mut slot) = self.0.replies.try_lock() else { self.0.known.store(false, Ordering::Release); return false; };
        if slot.is_some() { self.0.known.store(false, Ordering::Release); return false; }
        *slot = Some(replies); true
    }
    pub(crate) async fn paused(&self) -> Option<[bool; 11]> {
        self.0.pause_observed.notified().await;
        self.0.paused.lock().ok().and_then(|value| *value)
    }
    pub(crate) fn message(&self) -> Option<cgka_traits::MessageId> { self.0.message.get().cloned() }
    pub(crate) fn release(&self) { self.0.release.notify_one(); }
    pub(crate) async fn accepted(&self) -> Option<(usize, bool)> {
        self.0.accepted_observed.notified().await;
        self.0.accepted.lock().ok().and_then(|value| *value)
    }
    pub(crate) fn known(&self) -> bool { self.0.known.load(Ordering::Acquire) }
    pub(crate) async fn drain_replies(&self) -> bool {
        let replies = self.0.replies.lock().ok().and_then(|mut slot| slot.take());
        let Some(replies) = replies else { return false; };
        let mut count = self.0.consumed.load(Ordering::Acquire);
        let mut ok = !self.0.reply_errors.load(Ordering::Acquire);
        for reply in replies { count += 1; ok &= reply.await.is_ok_and(|result| result.is_ok()); }
        count == 8 && ok
    }
}
impl Drop for Guard { fn drop(&mut self) { self.release(); } }
impl super::Guard {
    pub(crate) fn arm_command_backlog_for_test(&self, target: Weak<Existing>, nonce: [u8; 32]) -> Option<Guard> {
        let probe = Arc::new(Probe { target, sender: self.0.owner.clone(), nonce,
            message: OnceLock::new(), fired: AtomicBool::new(false), known: AtomicBool::new(true),
            active_ingest: AtomicUsize::new(0), paused: Mutex::new(None), replies: Mutex::new(None),
            consumed: AtomicUsize::new(0), reply_errors: AtomicBool::new(false), accepted: Mutex::new(None),
            pause_observed: Notify::new(), release: Notify::new(), accepted_observed: Notify::new() });
        registry().set(Arc::downgrade(&probe)).ok()?;
        Some(Guard(probe))
    }
}
pub(in super::super) fn prepared(entry: &SiblingChannel, message: &cgka_traits::MessageId) {
    let Some(probe) = probe() else { return; };
    if entry.channel.scope().nonce != probe.nonce { return; }
    let SiblingOriginal::Recipient { choice, .. } = entry.original.as_ref() else { return; };
    if !probe.sender.ptr_eq(&Arc::downgrade(choice)) { return; }
    let _ = probe.message.set(message.clone()); // The first actual ID is immutable; later publications never replace it.
}
fn target(probe: &Probe, entry: &SiblingChannel) -> bool {
    entry.channel.scope().nonce == probe.nonce
        && matches!(entry.original.as_ref(), SiblingOriginal::Existing { original, .. } if probe.target.ptr_eq(&Arc::downgrade(original)))
}
pub(crate) struct Pause(Weak<Probe>);
impl Pause {
    pub(crate) async fn wait(self) {
        if let Some(probe) = self.0.upgrade() {
            probe.pause_observed.notify_one();
            probe.release.notified().await;
        }
    }
}
pub(in super::super) fn pause(entries: &[SiblingChannel], receive: [bool; 5]) -> Option<Pause> {
    let probe = probe()?;
    let entry = entries.iter().find(|entry| target(&probe, entry))?;
    if !entry.ready || !entry.policy_committed || !entry.proof_published || entry.peer_committed
        || entry.publication.is_some() || !entry.original.live() || !entry.state.live() { return None; }
    if !receive.into_iter().all(|value| value) { return None; }
    if probe.fired.swap(true, Ordering::AcqRel) { return None; }
    let Ok(mut paused) = probe.paused.try_lock() else { probe.known.store(false, Ordering::Release); return None; };
    *paused = Some([entry.original.live(), entry.state.live(), entry.ready, entry.policy_committed,
        entry.proof_published, !entry.peer_committed, receive[0], receive[1], receive[2], receive[3], receive[4]]);
    drop(paused);
    Some(Pause(Arc::downgrade(&probe)))
}
pub(crate) struct Ingest(Weak<Probe>);
impl Drop for Ingest {
    fn drop(&mut self) {
        if let Some(probe) = self.0.upgrade() { probe.active_ingest.fetch_sub(1, Ordering::AcqRel); }
    }
}
pub(in super::super) fn begin(entries: &[SiblingChannel], message: &cgka_traits::MessageId) -> Option<Ingest> {
    let probe = probe()?;
    if probe.message.get() != Some(message) || !entries.iter().any(|entry| target(&probe, entry)) { return None; }
    if probe.active_ingest.fetch_add(1, Ordering::AcqRel) != 0 { probe.known.store(false, Ordering::Release); }
    Some(Ingest(Arc::downgrade(&probe)))
}
pub(in super::super) fn accepted(entry: &SiblingChannel) {
    let Some(probe) = probe() else { return; };
    if !target(&probe, entry) || probe.active_ingest.load(Ordering::Acquire) != 1 { return; }
    let Ok(mut accepted) = probe.accepted.try_lock() else { probe.known.store(false, Ordering::Release); return; };
    if accepted.is_some() { return; }
    let Ok(mut replies) = probe.replies.try_lock() else { probe.known.store(false, Ordering::Release); return; };
    let Some(mut pending) = replies.take() else { probe.known.store(false, Ordering::Release); return; };
    let mut remaining = Vec::with_capacity(8);
    let mut completed = 0usize;
    let mut ok = true;
    for mut reply in pending.drain(..) {
        match reply.try_recv() {
            Ok(result) => { completed += 1; ok &= result.is_ok(); }
            Err(oneshot::error::TryRecvError::Empty) => remaining.push(reply),
            Err(oneshot::error::TryRecvError::Closed) => { completed += 1; ok = false; }
        }
    }
    *replies = Some(remaining);
    probe.consumed.store(completed, Ordering::Release);
    probe.reply_errors.store(!ok, Ordering::Release);
    *accepted = Some((completed, ok));
    drop(replies); drop(accepted);
    probe.accepted_observed.notify_one();
}
