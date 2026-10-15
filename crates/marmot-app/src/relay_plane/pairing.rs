//! One attempt's encrypted mailbox on the host-safety-filtered anonymous relay pool.
use super::*;
use crate::device_linking::network::EVENT_KIND;
use nostr::prelude::Event;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PairingRelayError {
    Unavailable,
    Expired,
    Invalid,
}

pub(crate) struct PairingMailbox {
    client: NostrSdkClient,
    relays: Vec<RelayUrl>,
    id: SubscriptionId,
    recipient: PublicKey,
    deadline: tokio::time::Instant,
    notifications: Pin<Box<dyn Stream<Item = NotificationUpdate<ClientNotification>> + Send>>,
}
impl MarmotRelayPlane {
    pub(crate) async fn pairing_mailbox(
        &self,
        endpoints: Vec<TransportEndpoint>,
        recipient: PublicKey,
        deadline: Instant,
    ) -> Result<PairingMailbox, PairingRelayError> {
        if Instant::now() >= deadline {
            return Err(PairingRelayError::Expired);
        }
        let endpoints = self
            .inner
            .relay_safety
            .sanitize_endpoints(endpoints, "pairing mailbox")
            .map_err(|_| PairingRelayError::Invalid)?;
        let client = self
            .inner
            .transport
            .directory_client
            .as_ref()
            .ok_or(PairingRelayError::Unavailable)?
            .clone();
        let relays = endpoints
            .iter()
            .map(|endpoint| {
                RelayUrl::parse(endpoint.as_str()).map_err(|_| PairingRelayError::Invalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Own cleanup before the first await that could install a subscription.
        let mailbox = PairingMailbox {
            notifications: client.notifications_with_gaps(),
            client,
            relays,
            id: SubscriptionId::generate(),
            recipient,
            deadline: deadline.into(),
        };
        for relay in &mailbox.relays {
            mailbox
                .client
                .add_relay(relay.clone())
                .await
                .map_err(|_| PairingRelayError::Unavailable)?;
            timeout_at(
                mailbox
                    .deadline
                    .min(tokio::time::Instant::now() + DIRECTORY_RELAY_CONNECT_WAIT),
                mailbox.client.connect_relay(relay.clone()),
            )
            .await
            .map_err(|_| PairingRelayError::Unavailable)?
            .map_err(|_| PairingRelayError::Unavailable)?;
        }
        let filter = Filter::new()
            .kind(EVENT_KIND)
            .pubkey(recipient)
            .since(NostrTimestamp::now())
            .limit(64);
        let output = timeout_at(
            mailbox.deadline,
            mailbox
                .client
                .subscribe(nostr_sdk::prelude::ReqTarget::manual(
                    mailbox
                        .relays
                        .iter()
                        .cloned()
                        .map(|url| (url, vec![filter.clone()])),
                ))
                .with_id(mailbox.id.clone()),
        )
        .await
        .map_err(|_| PairingRelayError::Expired)?
        .map_err(|_| PairingRelayError::Unavailable)?;
        if output.success.is_empty() {
            return Err(PairingRelayError::Unavailable);
        }
        Ok(mailbox)
    }
}
impl PairingMailbox {
    pub(crate) async fn publish(&mut self, event: &Event) -> Result<(), PairingRelayError> {
        if event.kind != EVENT_KIND || event.content.len() > 32768 || event.verify().is_err() {
            return Err(PairingRelayError::Invalid);
        }
        let output = timeout_at(
            self.deadline
                .min(tokio::time::Instant::now() + Duration::from_secs(3)),
            self.client
                .send_event(event)
                .to(self.relays.iter().cloned()),
        )
        .await
        .map_err(|_| PairingRelayError::Unavailable)?
        .map_err(|_| PairingRelayError::Unavailable)?;
        if output.success.is_empty() {
            return Err(PairingRelayError::Unavailable);
        }
        Ok(())
    }
    pub(crate) async fn next(&mut self) -> Result<Option<Event>, PairingRelayError> {
        for _ in 0..256 {
            let update = timeout_at(self.deadline, self.notifications.next())
                .await
                .map_err(|_| PairingRelayError::Expired)?;
            match update {
                // Use raw relay messages so SDK event deduplication cannot swallow
                // a retry whose authenticated processing receipt was lost.
                Some(NotificationUpdate::Notification(ClientNotification::Message {
                    message,
                    ..
                })) => {
                    if let RelayMessage::Event {
                        subscription_id,
                        event,
                    } = *message
                        && subscription_id.as_ref() == &self.id
                        && event.kind == EVENT_KIND
                        && event.content.len() <= 32768
                        && event
                            .tags
                            .contains(&nostr::prelude::Tag::public_key(self.recipient))
                    {
                        return Ok(Some(event.into_owned()));
                    }
                }
                Some(NotificationUpdate::Notification(ClientNotification::Shutdown)) | None => {
                    return Err(PairingRelayError::Unavailable);
                }
                Some(NotificationUpdate::Lagged { .. }) => return Ok(None),
                _ => {}
            }
        }
        Ok(None)
    }
}
impl Drop for PairingMailbox {
    fn drop(&mut self) {
        let client = self.client.clone();
        let id = self.id.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = client.unsubscribe(&id).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_linking::network::{Bootstrap, Channel, Message, MessageKind};
    use nostr::prelude::Keys;

    #[tokio::test]
    async fn pairing_mailboxes_exchange_encrypted_packets_both_ways_on_real_relay() {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let plane = MarmotRelayPlane::full_history_with_loopback(true);
        let endpoints = vec![TransportEndpoint(relay.url().await.to_string())];
        let a_keys = Keys::generate();
        let now = NostrTimestamp::now().as_secs();
        let bootstrap = Bootstrap::new(a_keys.public_key(), b"native request", now + 30);
        let deadline = Instant::now() + Duration::from_secs(30);
        let a = Channel::new(a_keys, &bootstrap, now, deadline).unwrap();
        let b = Channel::new(Keys::generate(), &bootstrap, now, deadline).unwrap();
        let mut a_box = plane
            .pairing_mailbox(endpoints.clone(), a.public_key(), deadline)
            .await
            .unwrap();
        let mut b_box = plane
            .pairing_mailbox(endpoints, b.public_key(), deadline)
            .await
            .unwrap();
        for reverse in [false, true] {
            let (sender, receiver, sender_box, receiver_box) = if reverse {
                (&b, &a, &mut b_box, &mut a_box)
            } else {
                (&a, &b, &mut a_box, &mut b_box)
            };
            let message = Message::new(
                bootstrap.binding().unwrap(),
                1,
                MessageKind::Verification,
                0,
                1,
                b"private packet",
            )
            .unwrap();
            let event = sender.seal(receiver.public_key(), &message, now).unwrap();
            sender_box.publish(&event).await.unwrap();
            let received = receiver_box.next().await.unwrap().unwrap();
            assert_eq!(
                receiver
                    .open(sender.public_key(), &received, now)
                    .unwrap()
                    .bytes()
                    .unwrap()
                    .as_slice(),
                b"private packet"
            );
            // Retry the same inner frame with fresh encryption so relay/SDK event
            // deduplication cannot hide a frame whose receipt was lost.
            let retry = sender.seal(receiver.public_key(), &message, now).unwrap();
            assert_ne!(retry.id, event.id);
            sender_box.publish(&retry).await.unwrap();
            assert!(receiver_box.next().await.unwrap().is_some());
        }
        drop(a_box);
        drop(b_box);
        plane.shutdown().await;
    }

    #[tokio::test]
    async fn pairing_mailbox_rejects_unsafe_endpoints_before_subscribing() {
        let plane = MarmotRelayPlane::full_history();
        let result = plane
            .pairing_mailbox(
                vec![TransportEndpoint("ws://127.0.0.1:1".into())],
                Keys::generate().public_key(),
                Instant::now() + Duration::from_secs(5),
            )
            .await;
        assert!(matches!(result, Err(PairingRelayError::Invalid)));
        plane.shutdown().await;
    }
}

#[cfg(test)]
#[path = "pairing/deployment_regressions.rs"]
mod deployment_regressions;
