//! Ephemeral acquisition metadata. Neither a membership nor SDK consent proof.
#[cfg(feature = "experimental-device-sync")]
use crate::SubscriptionAttempt;
use cgka_traits::TransportDelivery;
#[cfg(feature = "experimental-device-sync")]
use cgka_traits::{MemberId, MessageId};
use std::ops::Deref;
#[cfg(feature = "experimental-device-sync")]
use std::time::Instant;

/// Minted only by the trusted live notification inlet. No clone, serde or public constructor.
#[cfg(feature = "experimental-device-sync")]
pub struct LiveDeliveryObservation {
    pub(crate) account: MemberId,
    pub(crate) group: cgka_traits::GroupId,
    pub(crate) message: MessageId,
    pub(crate) attempt: SubscriptionAttempt,
    pub(crate) deadline: Instant,
}
#[cfg(feature = "experimental-device-sync")]
impl LiveDeliveryObservation {
    pub fn deadline_for(&self, delivery: &TransportDelivery) -> Option<Instant> {
        (self.account == delivery.account_id
            && self.message == delivery.message.id
            && delivery.group_id_hint.as_ref() == Some(&self.group))
        .then_some(self.deadline)
    }
    pub fn attempt(&self) -> SubscriptionAttempt {
        self.attempt
    }
}

/// Receiver-owned FIFO EOSE metadata. This is acquisition provenance, never consent.
#[cfg(feature = "experimental-device-sync")]
pub struct LiveNotificationReceiver {
    adapter: crate::NostrTransportAdapter,
    account: Option<MemberId>,
    eose: Vec<ReceiverEose>,
}
#[cfg(feature = "experimental-device-sync")]
#[derive(Clone)]
struct ReceiverEose {
    account: MemberId,
    group: cgka_traits::GroupId,
    transport_group: Vec<u8>,
    endpoint: cgka_traits::TransportEndpoint,
    subscription: String,
    attempt: SubscriptionAttempt,
}
/// Nonserializable, single-consumer capture fixed before the internal worker queue.
#[cfg(feature = "experimental-device-sync")]
pub struct CapturedLiveRelayEvent {
    adapter: crate::NostrTransportAdapter,
    message: MessageId,
    deadline: Instant,
    eose: Vec<ReceiverEose>,
}
#[cfg(feature = "experimental-device-sync")]
impl LiveNotificationReceiver {
    pub(crate) fn new(adapter: crate::NostrTransportAdapter, account: Option<MemberId>) -> Self {
        Self {
            adapter,
            account,
            eose: Vec::new(),
        }
    }
    /// Called in source FIFO order before reading subsequent Event notifications.
    /// Only a currently issued exact account/group route can contribute metadata.
    pub async fn observe_eose(
        &mut self,
        endpoint: cgka_traits::TransportEndpoint,
        subscription: &str,
    ) {
        let state = self.adapter.state.read().await;
        self.eose.retain(|token| token.matches_current(&state));
        for (account_id, account) in &state.accounts {
            if self
                .account
                .as_ref()
                .is_some_and(|wanted| wanted != account_id)
            {
                continue;
            }
            let mut routes = account.groups.clone();
            // A newly issued private route may be staged before ordinary routing
            // commits. This is only issuer metadata; Core still checks actual MLS.
            if let Some(wire) = state.private_observation_wires.get(account_id)
                && wire.ready
                && wire.attempt == account.attempt
                && let crate::NostrSubscription::Group {
                    group_id,
                    transport_group_id,
                    endpoints,
                    ..
                } = &wire.subscription
            {
                let route = cgka_traits::TransportGroupSubscription {
                    group_id: group_id.clone(),
                    transport_group_id: transport_group_id.clone(),
                    endpoints: endpoints.clone(),
                    retained_since: None,
                };
                if !routes.iter().any(|old| {
                    old.group_id == route.group_id
                        && old.transport_group_id == route.transport_group_id
                        && old.endpoints == route.endpoints
                }) {
                    routes.push(route);
                }
            }
            for route in routes {
                if state
                    .observation_wire_id(account_id, &route, account.attempt)
                    .as_deref()
                    != Some(subscription)
                    || !route.endpoints.iter().any(|candidate| {
                        crate::CanonicalEndpoint::new(candidate).matches(
                            &endpoint,
                            nostr::prelude::RelayUrl::parse(endpoint.as_str())
                                .ok()
                                .as_ref(),
                        )
                    })
                {
                    continue;
                }
                let token = ReceiverEose {
                    account: account_id.clone(),
                    group: route.group_id,
                    transport_group: route.transport_group_id,
                    endpoint: endpoint.clone(),
                    subscription: subscription.to_owned(),
                    attempt: account.attempt,
                };
                if !self.eose.iter().any(|old| {
                    old.account == token.account
                        && old.group == token.group
                        && old.endpoint == token.endpoint
                        && old.subscription == token.subscription
                }) {
                    self.eose.push(token);
                }
            }
        }
    }
    /// SDK captures are consumed only by the selected private wire. Ordinary
    /// batch EOSE remains owned by native replay; do not scan or retain its groups.
    #[cfg(feature = "sdk")]
    pub(crate) async fn observe_private_sdk_eose(
        &mut self,
        endpoint: cgka_traits::TransportEndpoint,
        subscription: &str,
    ) {
        let state = self.adapter.state.read().await;
        self.eose.retain(|token| token.matches_current(&state));
        let parsed_endpoint = nostr::prelude::RelayUrl::parse(endpoint.as_str()).ok();
        for (account_id, wire) in &state.private_observation_wires {
            if self.account.as_ref().is_some_and(|wanted| wanted != account_id)
                || !wire.ready
                || wire.actual != subscription
                || !state.accounts.get(account_id).is_some_and(|account| account.attempt == wire.attempt)
            {
                continue;
            }
            let crate::NostrSubscription::Group {
                group_id, transport_group_id, endpoints, ..
            } = &wire.subscription else {
                continue;
            };
            if &wire.group != group_id || !endpoints.iter().any(|candidate| {
                crate::CanonicalEndpoint::new(candidate).matches(&endpoint, parsed_endpoint.as_ref())
            }) {
                continue;
            }
            let token = ReceiverEose {
                account: account_id.clone(),
                group: group_id.clone(),
                transport_group: transport_group_id.clone(),
                endpoint: endpoint.clone(),
                subscription: subscription.to_owned(),
                attempt: wire.attempt,
            };
            // Reuse the existing full route/attempt/current-wire validation.
            if token.matches_current(&state) && !self.eose.iter().any(|old| {
                old.account == token.account && old.group == token.group
                    && old.endpoint == token.endpoint && old.subscription == token.subscription
            }) {
                self.eose.push(token);
            }
        }
    }

    /// No captured private EOSE means no acquisition observation can be minted.
    /// Skip DTO hashing/serialization for ordinary or pre-EOSE SDK copies only;
    /// their unchanged raw notifications still enter native admission.
    #[cfg(feature = "sdk")]
    pub(crate) fn capture_private_sdk_event(
        &self,
        event: &crate::NostrRelayEvent,
    ) -> Result<Option<CapturedLiveRelayEvent>, cgka_traits::TransportAdapterError> {
        if !self.eose.iter().any(|token| {
            event.subscription_id.as_deref() == Some(token.subscription.as_str())
                && event.endpoint == token.endpoint
        }) {
            return Ok(None);
        }
        self.capture(event).map(Some)
    }

    /// Synchronous capture: later worker progress cannot promote a pre-EOSE event.
    pub fn capture(
        &self,
        event: &crate::NostrRelayEvent,
    ) -> Result<CapturedLiveRelayEvent, cgka_traits::TransportAdapterError> {
        let deadline = Instant::now() + std::time::Duration::from_secs(600);
        let message = event
            .event
            .to_transport_message()
            .map_err(crate::map_inbound_event_error)?;
        let eose = self
            .eose
            .iter()
            .filter(|token| {
                event.subscription_id.as_deref() == Some(token.subscription.as_str())
                    && event.endpoint == token.endpoint
                    && matches!(&message.envelope, cgka_traits::TransportEnvelope::GroupMessage { transport_group_id } if transport_group_id == &token.transport_group)
            })
            .cloned()
            .collect();
        Ok(CapturedLiveRelayEvent {
            adapter: self.adapter.clone(),
            message: message.id,
            deadline,
            eose,
        })
    }
}
#[cfg(feature = "experimental-device-sync")]
impl ReceiverEose {
    fn matches_current(&self, state: &crate::AdapterState) -> bool {
        let Some(account) = state.accounts.get(&self.account) else {
            return false;
        };
        if account.attempt != self.attempt {
            return false;
        }
        let routes = account.groups.iter().find(|route| {
            route.group_id == self.group && route.transport_group_id == self.transport_group
        });
        if let Some(route) = routes {
            return state
                .observation_wire_id(&self.account, route, account.attempt)
                .as_deref()
                == Some(self.subscription.as_str())
                && route.endpoints.iter().any(|endpoint| {
                    crate::CanonicalEndpoint::new(endpoint).matches(
                        &self.endpoint,
                        nostr::prelude::RelayUrl::parse(self.endpoint.as_str())
                            .ok()
                            .as_ref(),
                    )
                });
        }
        state.private_observation_wires.get(&self.account).is_some_and(|wire|
            wire.ready && wire.attempt == self.attempt && wire.actual == self.subscription
            && matches!(&wire.subscription, crate::NostrSubscription::Group { group_id, transport_group_id, endpoints, .. } if *group_id == self.group && *transport_group_id == self.transport_group && endpoints.iter().any(|endpoint| crate::CanonicalEndpoint::new(endpoint).matches(&self.endpoint, nostr::prelude::RelayUrl::parse(self.endpoint.as_str()).ok().as_ref()))))
    }
}
#[cfg(feature = "experimental-device-sync")]
impl CapturedLiveRelayEvent {
    pub(crate) fn observations(
        self,
        adapter: &crate::NostrTransportAdapter,
        state: &crate::AdapterState,
        message: &cgka_traits::TransportMessage,
        account: Option<&MemberId>,
    ) -> std::collections::HashMap<(MemberId, cgka_traits::GroupId), LiveDeliveryObservation> {
        if !std::sync::Arc::ptr_eq(&self.adapter.state, &adapter.state)
            || message.id != self.message
        {
            return Default::default();
        }
        self.eose
            .into_iter()
            .filter(|token| {
                account.is_none_or(|wanted| wanted == &token.account)
                    && token.matches_current(state)
            })
            .map(|token| {
                (
                    (token.account.clone(), token.group.clone()),
                    LiveDeliveryObservation {
                        account: token.account,
                        group: token.group,
                        message: message.id.clone(),
                        attempt: token.attempt,
                        deadline: self.deadline,
                    },
                )
            })
            .collect()
    }
}

/// Internal queue envelope; generic consumers intentionally discard the observation.
pub struct ObservedTransportDelivery {
    pub delivery: TransportDelivery,
    #[cfg(feature = "experimental-device-sync")]
    pub observation: Option<LiveDeliveryObservation>,
}
impl From<TransportDelivery> for ObservedTransportDelivery {
    fn from(delivery: TransportDelivery) -> Self {
        Self {
            delivery,
            #[cfg(feature = "experimental-device-sync")]
            observation: None,
        }
    }
}
impl ObservedTransportDelivery {
    pub fn into_delivery(self) -> TransportDelivery {
        self.delivery
    }
}
impl Deref for ObservedTransportDelivery {
    type Target = TransportDelivery;
    fn deref(&self) -> &Self::Target {
        &self.delivery
    }
}
impl std::fmt::Debug for ObservedTransportDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("ObservedTransportDelivery");
        #[cfg(feature = "experimental-device-sync")]
        debug.field("has_live_observation", &self.observation.is_some());
        debug.finish_non_exhaustive()
    }
}

#[cfg(all(test, feature = "experimental-device-sync"))]
mod tests {
    use super::*;
    use crate::{
        NostrPublishOutcome, NostrRelayClient, NostrRelayEvent, NostrSubscription,
        NostrTransportAdapter,
    };
    use cgka_traits::{
        TransportAccountActivation, TransportAdapter, TransportAdapterError, TransportEndpoint,
        TransportGroupSubscription,
    };
    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};
    use std::sync::Arc;
    use transport_nostr_peeler::NostrTransportEvent;
    struct Relay;
    #[async_trait::async_trait]
    impl NostrRelayClient for Relay {
        async fn subscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
            Ok(())
        }
        async fn unsubscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
            Ok(())
        }
        async fn unsubscribe_account(
            &self,
            _: &MemberId,
            _: &[NostrSubscription],
        ) -> Result<(), TransportAdapterError> {
            Ok(())
        }
        async fn publish_event(
            &self,
            endpoints: &[TransportEndpoint],
            _: &NostrTransportEvent,
            _: usize,
        ) -> Result<NostrPublishOutcome, TransportAdapterError> {
            Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
        }
    }
    async fn fixture() -> (NostrTransportAdapter, MemberId, NostrRelayEvent) {
        let adapter = NostrTransportAdapter::new(Arc::new(Relay));
        let account = MemberId::new(vec![1; 32]);
        let group = TransportGroupSubscription {
            group_id: cgka_traits::GroupId::new(vec![2; 32]),
            transport_group_id: vec![3; 32],
            endpoints: vec![TransportEndpoint("wss://phase.example/".into())],
            retained_since: None,
        };
        adapter
            .activate_account(TransportAccountActivation {
                account_id: account.clone(),
                inbox_endpoints: vec![],
                group_subscriptions: vec![group.clone()],
                since: None,
            })
            .await
            .unwrap();
        let attempt = adapter
            .account_subscription_attempt(&account)
            .await
            .unwrap();
        let id = crate::group_subscription(&account, &group, None, attempt).subscription_id();
        let signed = EventBuilder::new(
            Kind::Custom(445),
            "actual signed transport acquisition fixture",
        )
        .tag(Tag::parse(["h".to_owned(), hex::encode(&group.transport_group_id)]).unwrap())
        .finalize(&Keys::generate())
        .unwrap();
        (
            adapter,
            account,
            NostrRelayEvent {
                endpoint: group.endpoints[0].clone(),
                subscription_id: Some(id),
                event: NostrTransportEvent::from_nostr_event(&signed).unwrap(),
            },
        )
    }
    // Real signed route, controlled concurrency only: EOSE changes while the
    // admitted Event is blocked before delivery routing. No crypto/SDK permission.
    #[tokio::test]
    async fn acquisition_phase_eose_after_first_poll_cannot_promote_backlog() {
        let (adapter, account, event) = fixture().await;
        let mut state = adapter.state.write().await;
        let future = adapter.handle_live_relay_event(Some(&account), event.clone());
        tokio::pin!(future);
        tokio::select! {
            biased;
            _ = &mut future => panic!("state-held event should await routing"),
            _ = tokio::task::yield_now() => {}
        }
        state.record_subscription_eose(event.subscription_id.as_ref().unwrap(), &event.endpoint, 1);
        drop(state);
        assert_eq!(future.await.unwrap(), 1);
        let delivered = adapter.receive_observed().await.unwrap().unwrap();
        assert!(
            delivered.observation.is_none(),
            "later EOSE cannot change original acquisition phase"
        );
    }

    #[cfg(feature = "sdk")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sdk_private_capture_skips_ordinary_wire_but_generic_capture_is_preserved() {
        let (adapter, account, mut event) = fixture().await;
        // Use the actual committed batch id, not the legacy per-group id.
        event.subscription_id = {
            let state = adapter.state.read().await;
            let routes = state.accounts.get(&account).unwrap();
            state.observation_wire_id(&account, &routes.groups[0], routes.attempt)
        };
        let subscription = event.subscription_id.as_deref().unwrap();
        let mut sdk = adapter.live_notification_receiver(Some(account.clone()));
        sdk.observe_private_sdk_eose(event.endpoint.clone(), subscription).await;
        let sdk_skipped = sdk.eose.is_empty()
            && sdk.capture_private_sdk_event(&event).unwrap().is_none();
        let mut generic = adapter.live_notification_receiver(Some(account.clone()));
        generic.observe_eose(event.endpoint.clone(), subscription).await;
        let generic_preserved = generic.capture(&event).unwrap().eose.len() == 1;
        adapter.deactivate_account(&account).await.unwrap();
        assert!(sdk_skipped && generic_preserved,
            "ordinary SDK copies must skip private capture while generic capture remains available");
    }
}
