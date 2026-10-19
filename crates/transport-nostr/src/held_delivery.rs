//! Test-only arrival ordering for one exact ordinary event on one receive plane.
//! Retain each real delivery, its reserved queue slot and its normal cursor pin.
use super::*;
use std::sync::atomic::AtomicUsize;
use transport_nostr_adapter::ObservedTransportDelivery;

pub(super) struct State {
    account: MemberId,
    message: MessageId,
    release: tokio::sync::watch::Sender<bool>,
    held: AtomicUsize,
    finished: AtomicUsize,
    enqueued: AtomicUsize,
    recovered_deferrals: AtomicUsize,
}

#[doc(hidden)]
pub struct Hold(Arc<State>);

impl MarmotRelayPlane {
    #[doc(hidden)]
    pub fn hold_account_delivery_for_test(
        &self,
        account: MemberId,
        message: MessageId,
    ) -> Hold {
        let (release, _) = tokio::sync::watch::channel(false);
        let state = Arc::new(State {
            account,
            message,
            release,
            held: AtomicUsize::new(0),
            finished: AtomicUsize::new(0),
            enqueued: AtomicUsize::new(0),
            recovered_deferrals: AtomicUsize::new(0),
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
