//! Finite real watch hints, counted only after actual owner service returns.
//! This is scheduling pressure, never a publication result or sharing authority.
use super::*;

pub(super) struct Pressure {
    sender: OnceLock<tokio::sync::watch::Sender<()>>,
    started: AtomicBool,
    services: AtomicUsize,
    notifications: AtomicUsize,
    errors: AtomicUsize,
    done: Notify,
}
impl Pressure {
    fn new() -> Self {
        Self { sender: OnceLock::new(), started: AtomicBool::new(false),
            services: AtomicUsize::new(0), notifications: AtomicUsize::new(0),
            errors: AtomicUsize::new(0), done: Notify::new() }
    }
    pub(super) fn capture_sender(&self, sender: &tokio::sync::watch::Sender<()>) {
        // The actual ready/preselect hook calls this only for the registered
        // B original/nonce. A clone owns a wake channel, not an AppClient/State.
        if self.sender.get().is_none() { let _ = self.sender.set(sender.clone()); }
    }
    fn start(&self) -> bool {
        let Some(sender) = self.sender.get() else { return false; };
        if self.started.swap(true, Ordering::AcqRel) { return false; }
        self.notifications.store(1, Ordering::Release);
        sender.send_replace(());
        true
    }
    fn returned(&self, ok: bool) {
        if !self.started.load(Ordering::Acquire) { return; }
        let count = self.services.load(Ordering::Acquire);
        if count >= 8 { return; }
        // This exact serial actor alone calls returned. The fixture never
        // rearms via a racing waiter task and never fabricates changed().
        if !ok { self.errors.fetch_add(1, Ordering::AcqRel); }
        self.services.store(count + 1, Ordering::Release);
        if count + 1 < 8 {
            if let Some(sender) = self.sender.get() {
                self.notifications.fetch_add(1, Ordering::AcqRel);
                sender.send_replace(());
            }
        } else { self.done.notify_one(); }
    }
    pub(super) fn accepted(&self, probe: &Probe) {
        let Ok(mut accepted) = probe.accepted.try_lock() else {
            probe.known.store(false, Ordering::Release); return;
        };
        if accepted.is_some() { return; }
        let count = self.services.load(Ordering::Acquire);
        *accepted = Some((count, self.started.load(Ordering::Acquire)
            && self.errors.load(Ordering::Acquire) == 0));
        drop(accepted);
        probe.accepted_observed.notify_one();
    }
}

pub(crate) struct WatchGuard(Guard);
impl std::ops::Deref for WatchGuard {
    type Target = Guard;
    fn deref(&self) -> &Guard { &self.0 }
}
impl Guard {
    pub(crate) fn into_watch_pressure(self) -> Option<WatchGuard> {
        self.0.watch_pressure.set(Pressure::new()).ok()?;
        Some(WatchGuard(self))
    }
}
impl WatchGuard {
    pub(crate) fn start_watch_pressure(&self) -> bool {
        self.0.0.watch_pressure.get().is_some_and(Pressure::start)
    }
    pub(crate) async fn finish_watch_pressure(&self) -> bool {
        let Some(pressure) = self.0.0.watch_pressure.get() else { return false; };
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let done = pressure.done.notified();
                if pressure.services.load(Ordering::Acquire) == 8 { break; }
                done.await;
            }
        }).await.is_ok() && pressure.errors.load(Ordering::Acquire) == 0
    }
    pub(crate) fn watch_pressure_snapshot(&self) -> (bool, usize, usize, usize) {
        let pressure = self.0.0.watch_pressure.get().expect("attached watch pressure");
        (pressure.started.load(Ordering::Acquire), pressure.services.load(Ordering::Acquire),
         pressure.notifications.load(Ordering::Acquire), pressure.errors.load(Ordering::Acquire))
    }
}

pub(in super::super::super) fn service(entries: &[SiblingChannel], ok: bool) {
    let Some(probe) = probe() else { return; };
    if !entries.iter().any(|entry| target(&probe, entry) && entry.original.live() && entry.state.live()) {
        return;
    }
    if let Some(pressure) = probe.watch_pressure.get() { pressure.returned(ok); }
}
