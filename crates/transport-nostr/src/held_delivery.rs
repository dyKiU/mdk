//! Test-only arrival ordering for one exact ordinary event on one receive plane.
//! Retain each real delivery, its reserved queue slot and its normal cursor pin.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use transport_nostr_adapter::ObservedTransportDelivery;

type NativeDeliveryFacts = ([u64; 3], [bool; 4]);

pub(super) struct State {
    account: MemberId,
    message: MessageId,
    release: tokio::sync::watch::Sender<bool>,
    held: AtomicUsize,
    finished: AtomicUsize,
    enqueued: AtomicUsize,
    recovered_deferrals: AtomicUsize,
    native_held: AtomicUsize,
    native_unknown: AtomicBool,
    native: std::sync::Mutex<Option<transport_nostr_adapter::NativeFrameWatchForTest>>,
    started: Instant,
}

#[doc(hidden)]
pub struct Hold(Arc<State>);

impl MarmotRelayPlane {
    #[doc(hidden)]
    pub fn hold_account_delivery_for_test(&self, account: MemberId, message: MessageId) -> Hold {
        let (release, _) = tokio::sync::watch::channel(false);
        let state = Arc::new(State {
            account,
            message,
            release,
            held: AtomicUsize::new(0),
            finished: AtomicUsize::new(0),
            enqueued: AtomicUsize::new(0),
            recovered_deferrals: AtomicUsize::new(0),
            native_held: AtomicUsize::new(0),
            native_unknown: AtomicBool::new(false),
            native: std::sync::Mutex::new(None),
            started: Instant::now(),
        });
        let mut slot = self.inner.transport.held_delivery.lock().unwrap();
        assert!(slot.as_ref().and_then(Weak::upgrade).is_none());
        *slot = Some(Arc::downgrade(&state));
        Hold(state)
    }
}

impl Hold {
    #[doc(hidden)]
    pub fn observed(&self) -> (usize, usize, usize) {
        (
            self.0.held.load(Ordering::SeqCst),
            self.0.finished.load(Ordering::SeqCst),
            self.0.enqueued.load(Ordering::SeqCst),
        )
    }

    #[doc(hidden)]
    pub fn recovered_deferrals(&self) -> usize {
        self.0.recovered_deferrals.load(Ordering::SeqCst)
    }

    /// Actual exact native borrow, then typed ingest and checked ACK facts.
    /// A missing observation stays unknown; zero recovery deferrals do not
    /// substitute for custody. The watch owns only weak native identities.
    #[doc(hidden)]
    pub fn native_observed(&self) -> (usize, Option<NativeDeliveryFacts>, bool) {
        let native = self.0.native.lock().unwrap();
        let facts = native.as_ref().map(|watch| {
            let (counts, facts) = watch.facts(self.0.started, Instant::now());
            (counts, [facts[0], facts[1], facts[2], facts[3]])
        });
        (
            self.0.native_held.load(Ordering::SeqCst),
            facts,
            self.0.native_unknown.load(Ordering::SeqCst),
        )
    }

    #[doc(hidden)]
    pub fn release(&self) {
        self.0.release.send_replace(true);
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.release();
    }
}

pub(super) fn hold(
    transport: &RelayPlaneTransport,
    route: &AccountDeliveryRoute,
    delivery: ObservedTransportDelivery,
    placement: AccountDeliveryPlacement,
) -> Option<ObservedTransportDelivery> {
    let state = transport
        .held_delivery
        .lock()
        .unwrap()
        .as_ref()
        .and_then(Weak::upgrade);
    let Some(state) = state else {
        return Some(delivery);
    };
    if *state.release.borrow()
        || state.account != delivery.account_id
        || state.message != delivery.message.id
        || delivery.source.plane != TransportDeliveryPlane::Group
    {
        return Some(delivery);
    }
    assert_eq!(placement, AccountDeliveryPlacement::Queue);
    // Queue admission has already registered its cursor pin. Reserving its
    // actual slot also preserves the router's separate overflow-control slot.
    let permit = route.sender.clone().try_reserve_owned().unwrap();
    assert!(state.held.fetch_add(1, Ordering::SeqCst) < 8);
    let route = route.clone();
    let key = account_delivery_restart_key(&delivery);
    let mut release = state.release.subscribe();
    tokio::spawn(async move {
        while !*release.borrow_and_update() {
            if release.changed().await.is_err() {
                break;
            }
        }
        if route.sender.is_closed() {
            route.overflow.unqueue(route.epoch, key);
            drop(permit);
        } else {
            let sender = permit.send(AccountDeliveryEvent::Delivery(Box::new(delivery)));
            if sender.is_closed() {
                route.overflow.unqueue(route.epoch, key);
            } else {
                state.enqueued.fetch_add(1, Ordering::SeqCst);
            }
        }
        state.finished.fetch_add(1, Ordering::SeqCst);
    });
    None
}

impl MarmotRelayPlaneAccountAdapter {
    /// Keep one matching real native loan with the existing app owner, before
    /// recovered intake. The caller returns to its worker command select; it
    /// must not await release here and thereby block that worker's own Leave.
    #[doc(hidden)]
    pub fn defer_held_native_for_test(&self, batch: &transport_nostr_adapter::ReplayBatch) -> bool {
        let state = self
            .relay_plane
            .inner
            .transport
            .held_delivery
            .lock()
            .unwrap()
            .as_ref()
            .and_then(Weak::upgrade);
        let Some(state) = state else {
            return false;
        };
        if *state.release.borrow() || state.account != self.account_id {
            return false;
        }
        let Some(identity) = batch.held_remote_identity_for_test(&self.account_id, &state.message)
        else {
            return false;
        };
        let Some(group) = batch
            .delivery()
            .and_then(|delivery| delivery.group_id_hint.as_ref())
        else {
            return false;
        };
        let mut slot = state.native.lock().unwrap();
        if slot.as_ref().is_some_and(|watch| !watch.matches(&identity)) {
            state.native_unknown.store(true, Ordering::SeqCst);
            return true;
        }
        if slot.is_none() && !state.native_unknown.load(Ordering::SeqCst) {
            if let Some(watch) = identity.watch(group, state.message.as_slice()) {
                *slot = Some(watch);
                // This is a genuine checked current remote borrow, not the
                // comparison-copy deferral counter or a constructed delivery.
                batch.observe_frame_for_test(false);
                state.native_held.fetch_add(1, Ordering::SeqCst);
            } else {
                state.native_unknown.store(true, Ordering::SeqCst);
            }
        }
        true
    }

    /// The live queue hold alone cannot control a comparison's duplicate copy.
    /// Defer that exact copy without receipts, cursor release or certification.
    /// The genuine queued packet remains the fixture's original delivery.
    #[doc(hidden)]
    pub fn defer_held_recovery_for_test(&self, delivery: &TransportDelivery) -> bool {
        let state = self
            .relay_plane
            .inner
            .transport
            .held_delivery
            .lock()
            .unwrap()
            .as_ref()
            .and_then(Weak::upgrade);
        let Some(state) = state else {
            return false;
        };
        if *state.release.borrow()
            || state.account != self.account_id
            || delivery.account_id != self.account_id
            || state.message != delivery.message.id
            || delivery.source.plane != TransportDeliveryPlane::Group
            || !matches!(
                &delivery.message.envelope,
                cgka_traits::transport::TransportEnvelope::GroupMessage { .. }
            )
        {
            return false;
        }
        state.recovered_deferrals.fetch_add(1, Ordering::SeqCst);
        true
    }
}
