//! One attempt's encrypted mailbox on the host-safety-filtered anonymous relay pool.
use super::*;
use crate::device_linking::network::EVENT_KIND;
use nostr::prelude::Event;
use std::collections::VecDeque;

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
    pending: VecDeque<Event>,
}

enum MailboxUpdate {
    Ready,
    Event(Event),
    Ignore,
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
        let mut mailbox = PairingMailbox {
            notifications: client.notifications_with_gaps(),
            client,
            relays,
            id: SubscriptionId::generate(),
            recipient,
            deadline: deadline.into(),
            pending: VecDeque::new(),
        };
        let connect_deadline = mailbox
            .deadline
            .min(tokio::time::Instant::now() + DIRECTORY_RELAY_CONNECT_WAIT);
        let connections = futures::future::join_all(mailbox.relays.iter().map(|relay| async {
            let connected = timeout_at(connect_deadline, async {
                mailbox.client.add_relay(relay.clone()).await?;
                mailbox.client.connect_relay(relay.clone()).await
            })
            .await;
            matches!(connected, Ok(Ok(_))).then(|| relay.clone())
        }))
        .await;
        mailbox.relays = connections.into_iter().flatten().collect();
        if mailbox.relays.is_empty() {
            return Err(PairingRelayError::Unavailable);
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
        mailbox
            .relays
            .retain(|relay| output.success.contains_key(relay));
        // A queued REQ is not relay acceptance. In particular, restricted relays
        // send CLOSED for this private application kind. Check before showing a
        // QR or waiting for the other device for the whole pairing lifetime.
        timeout_at(
            mailbox
                .deadline
                .min(tokio::time::Instant::now() + DIRECTORY_RELAY_CONNECT_WAIT),
            mailbox.wait_ready(),
        )
        .await
        .map_err(|_| PairingRelayError::Unavailable)??;
        Ok(mailbox)
    }
}
impl PairingMailbox {
    async fn wait_ready(&mut self) -> Result<(), PairingRelayError> {
        loop {
            match self.read_update().await? {
                MailboxUpdate::Ready => return Ok(()),
                MailboxUpdate::Event(event) => {
                    if self.pending.len() == 64 {
                        return Err(PairingRelayError::Unavailable);
                    }
                    self.pending.push_back(event);
                }
                MailboxUpdate::Ignore => {}
            }
        }
    }

    async fn read_update(&mut self) -> Result<MailboxUpdate, PairingRelayError> {
        let update = timeout_at(self.deadline, self.notifications.next())
            .await
            .map_err(|_| PairingRelayError::Expired)?;
        match update {
            Some(NotificationUpdate::Notification(ClientNotification::Message {
                relay_url,
                message,
            })) if self.relays.contains(&relay_url) => match *message {
                RelayMessage::Closed {
                    subscription_id, ..
                } if subscription_id.as_ref() == &self.id => {
                    self.relays.retain(|relay| relay != &relay_url);
                    if self.relays.is_empty() {
                        return Err(PairingRelayError::Unavailable);
                    }
                    Ok(MailboxUpdate::Ignore)
                }
                RelayMessage::EndOfStoredEvents(subscription_id)
                    if subscription_id.as_ref() == &self.id =>
                {
                    Ok(MailboxUpdate::Ready)
                }
                RelayMessage::Event {
                    subscription_id,
                    event,
                } if subscription_id.as_ref() == &self.id
                    && event.kind == EVENT_KIND
                    && event.content.len() <= 32768
                    && event
                        .tags
                        .contains(&nostr::prelude::Tag::public_key(self.recipient)) =>
                {
                    Ok(MailboxUpdate::Event(event.into_owned()))
                }
                _ => Ok(MailboxUpdate::Ignore),
            },
            Some(NotificationUpdate::Notification(ClientNotification::Shutdown)) | None => {
                Err(PairingRelayError::Unavailable)
            }
            _ => Ok(MailboxUpdate::Ignore),
        }
    }

    pub(crate) async fn publish(&mut self, event: &Event) -> Result<(), PairingRelayError> {
        if event.kind != EVENT_KIND || event.content.len() > 32768 || event.verify().is_err() {
            return Err(PairingRelayError::Invalid);
        }
        let deadline = self
            .deadline
            .min(tokio::time::Instant::now() + Duration::from_secs(3));
        // Bound each relay separately: timing out the aggregate SDK operation
        // discards healthy acknowledgements when one relay never responds.
        let outputs =
            futures::future::join_all(self.relays.iter().map(|relay| {
                timeout_at(deadline, self.client.send_event(event).to([relay.clone()]))
            }))
            .await;
        if !outputs
            .iter()
            .any(|result| matches!(result, Ok(Ok(output)) if !output.success.is_empty()))
        {
            return Err(PairingRelayError::Unavailable);
        }
        Ok(())
    }
    pub(crate) async fn next(&mut self) -> Result<Option<Event>, PairingRelayError> {
        if let Some(event) = self.pending.pop_front() {
            return Ok(Some(event));
        }
        for _ in 0..256 {
            // Raw messages retain retries whose processing receipt was lost.
            if let MailboxUpdate::Event(event) = self.read_update().await? {
                return Ok(Some(event));
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

    async fn rejecting_relay() -> (TransportEndpoint, tokio::task::JoinHandle<()>) {
        use futures::SinkExt;
        use tokio_tungstenite::{accept_async, tungstenite::Message};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = TransportEndpoint(format!("ws://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                let Message::Text(text) = message else {
                    continue;
                };
                let request: serde_json::Value = serde_json::from_str(&text).unwrap();
                if request[0] == "REQ" {
                    socket
                        .send(Message::Text(
                            serde_json::json!([
                                "CLOSED",
                                request[1],
                                "ERROR: bad req: kind not allowed: 21194"
                            ])
                            .to_string()
                            .into(),
                        ))
                        .await
                        .unwrap();
                }
            }
        });
        (endpoint, server)
    }

    #[tokio::test]
    async fn pairing_mailbox_reports_rejected_subscription_without_waiting_for_expiry() {
        let (endpoint, server) = rejecting_relay().await;
        let plane = MarmotRelayPlane::full_history_with_loopback(true);
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            let mut mailbox = plane
                .pairing_mailbox(
                    vec![endpoint],
                    Keys::generate().public_key(),
                    Instant::now() + Duration::from_secs(30),
                )
                .await?;
            mailbox.next().await
        })
        .await;
        server.abort();
        plane.shutdown().await;
        assert!(
            matches!(result, Ok(Err(PairingRelayError::Unavailable))),
            "relay CLOSED must surface before the pairing lifetime expires"
        );
    }

    #[tokio::test]
    async fn pairing_mailboxes_exchange_encrypted_packets_both_ways_on_real_relay() {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        exchange_encrypted_packets(
            MarmotRelayPlane::full_history_with_loopback(true),
            MarmotRelayPlane::full_history_with_loopback(true),
            vec![TransportEndpoint(relay.url().await.to_string())],
        )
        .await;
    }

    #[tokio::test]
    async fn pairing_mailboxes_keep_healthy_route_when_another_rejects_or_is_offline() {
        let (rejected, server) = rejecting_relay().await;
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let plane = MarmotRelayPlane::full_history_with_loopback(true);
        exchange_encrypted_packets(
            plane.clone(),
            plane,
            vec![
                rejected,
                TransportEndpoint("ws://127.0.0.1:1".into()),
                TransportEndpoint(relay.url().await.to_string()),
            ],
        )
        .await;
        server.abort();
    }

    #[tokio::test]
    #[ignore = "requires explicitly selected live public relays"]
    async fn public_pairing_relays_exchange_encrypted_packets_both_ways() {
        let urls =
            std::env::var("WN_PAIRING_TEST_RELAYS").expect("explicit test relay set required");
        let endpoints: Vec<_> = urls
            .split(',')
            .map(|url| {
                assert!(url.starts_with("wss://"));
                TransportEndpoint(url.to_owned())
            })
            .collect();
        assert!(!endpoints.is_empty());
        // Independent anonymous clients; only generated keys and synthetic data.
        exchange_encrypted_packets(
            MarmotRelayPlane::full_history(),
            MarmotRelayPlane::full_history(),
            endpoints,
        )
        .await;
    }

    async fn exchange_encrypted_packets(
        plane: MarmotRelayPlane,
        other_plane: MarmotRelayPlane,
        endpoints: Vec<TransportEndpoint>,
    ) {
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
        let mut b_box = other_plane
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
            // Connection setup may cross a timestamp second. Match the real
            // driver: seal at publication time, never before the receiver's REQ floor.
            let event = sender
                .seal(
                    receiver.public_key(),
                    &message,
                    NostrTimestamp::now().as_secs(),
                )
                .unwrap();
            sender_box
                .publish(&event)
                .await
                .expect("initial publication");
            let received = receive_exact(receiver_box, &event, reverse, "initial").await;
            assert_eq!(
                receiver
                    .open(
                        sender.public_key(),
                        &received,
                        NostrTimestamp::now().as_secs()
                    )
                    .unwrap()
                    .bytes()
                    .unwrap()
                    .as_slice(),
                b"private packet"
            );
            // Retry the same inner frame with fresh encryption so relay/SDK event
            // deduplication cannot hide a frame whose receipt was lost.
            let retry = sender
                .seal(
                    receiver.public_key(),
                    &message,
                    NostrTimestamp::now().as_secs(),
                )
                .unwrap();
            assert_ne!(retry.id, event.id);
            sender_box.publish(&retry).await.expect("retry publication");
            let received = receive_exact(receiver_box, &retry, reverse, "retry").await;
            assert_eq!(
                receiver
                    .open(
                        sender.public_key(),
                        &received,
                        NostrTimestamp::now().as_secs()
                    )
                    .unwrap()
                    .bytes()
                    .unwrap()
                    .as_slice(),
                b"private packet"
            );
        }
        drop(a_box);
        drop(b_box);
        plane.shutdown().await;
        other_plane.shutdown().await;
        eprintln!("pairing_encrypted_exchange directions=2 deliveries=4 retry_fresh_ids=true plane_closes=2");
    }

    async fn receive_exact(
        mailbox: &mut PairingMailbox,
        expected: &Event,
        reverse: bool,
        stage: &str,
    ) -> Event {
        loop {
            match mailbox.next().await {
                Ok(Some(event)) if event.id == expected.id => return event,
                // The same event can arrive through both relays. A duplicate of
                // the first publication cannot establish delivery of its retry.
                Ok(_) => {}
                Err(error) => panic!("pairing delivery reverse={reverse} stage={stage}: {error:?}"),
            }
        }
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
