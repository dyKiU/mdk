//! App-owned encrypted pairing protocol fixtures over the generic relay mailbox.
#[cfg(test)]
use super::*;
#[cfg(test)]
use crate::device_linking::network::EVENT_KIND;
#[cfg(test)]
use cgka_traits::TransportEndpoint;
#[cfg(test)]
use futures::StreamExt;
#[cfg(test)]
use nostr::prelude::Event;
#[cfg(test)]
use nostr_sdk::prelude::Timestamp as NostrTimestamp;
#[cfg(test)]
use std::time::{Duration, Instant};
pub(crate) use transport_nostr::pairing::{PairingMailbox, PairingRelayError};
#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_linking::network::{Bootstrap, Channel, Message, MessageKind};
    use nostr::prelude::Keys;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pairing_mailbox_retry_waits_for_connection_before_subscription_readiness() {
        use futures::SinkExt;
        use tokio_tungstenite::{accept_async, tungstenite::Message};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = TransportEndpoint(format!("ws://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // Connection and subscription each fit their own five-second budget,
            // but a queued connect is not yet a usable WebSocket connection.
            tokio::time::sleep(Duration::from_secs(3)).await;
            let mut socket = accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                let Message::Text(text) = message else {
                    continue;
                };
                let request: serde_json::Value = serde_json::from_str(&text).unwrap();
                if request[0] == "REQ" {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    if socket
                        .send(Message::Text(
                            serde_json::json!(["EOSE", request[1]]).to_string().into(),
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        });
        let plane = MarmotRelayPlane::full_history_with_loopback(true);
        // An expired caller must not poison the shared connection for a fresh
        // attempt, or leave its subscription in front of the fresh request.
        let first = plane
            .pairing_mailbox(
                EVENT_KIND,
                vec![endpoint.clone()],
                Keys::generate().public_key(),
                Instant::now() + Duration::from_millis(100),
            )
            .await;
        assert!(first.is_err());
        let retry = plane
            .pairing_mailbox(
                EVENT_KIND,
                vec![endpoint],
                Keys::generate().public_key(),
                Instant::now() + Duration::from_secs(15),
            )
            .await;
        assert!(
            retry.is_ok(),
            "fresh attempt must wait for a live connection and its own EOSE"
        );
        drop(retry);
        plane.shutdown().await;
        server.abort();
    }

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pairing_mailbox_reports_rejected_subscription_without_waiting_for_expiry() {
        let (endpoint, server) = rejecting_relay().await;
        let plane = MarmotRelayPlane::full_history_with_loopback(true);
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            let mut mailbox = plane
                .pairing_mailbox(
                    EVENT_KIND,
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pairing_mailboxes_exchange_encrypted_packets_both_ways_on_real_relay() {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        exchange_encrypted_packets(
            MarmotRelayPlane::full_history_with_loopback(true),
            MarmotRelayPlane::full_history_with_loopback(true),
            vec![TransportEndpoint(relay.url().await.to_string())],
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
            .pairing_mailbox(EVENT_KIND, endpoints.clone(), a.public_key(), deadline)
            .await
            .unwrap();
        let mut b_box = other_plane
            .pairing_mailbox(EVENT_KIND, endpoints, b.public_key(), deadline)
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
        eprintln!(
            "pairing_encrypted_exchange directions=2 deliveries=4 retry_fresh_ids=true plane_closes=2"
        );
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pairing_mailbox_rejects_unsafe_endpoints_before_subscribing() {
        let plane = MarmotRelayPlane::full_history();
        let result = plane
            .pairing_mailbox(
                EVENT_KIND,
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
