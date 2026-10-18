//! Real websocket witnesses for mailbox export and partial publication failures.
use super::*;
use crate::device_linking::network::{Bootstrap, Channel, Message, MessageKind};
use futures::SinkExt;
use nostr::prelude::Keys;
use tokio::sync::oneshot;
use tokio_tungstenite::{accept_async, tungstenite::Message as SocketMessage};

#[derive(Clone, Copy)]
enum RouteBehavior {
    RejectSubscription,
    AcceptWithoutPublicationReceipt,
}

async fn witnessed_route(
    behavior: RouteBehavior,
) -> (
    TransportEndpoint,
    oneshot::Receiver<()>,
    oneshot::Receiver<nostr::prelude::EventId>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = TransportEndpoint(format!("ws://{}", listener.local_addr().unwrap()));
    let (request_sent, request_seen) = oneshot::channel();
    let (event_sent, event_seen) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        drop(listener);
        let mut socket = accept_async(stream).await.unwrap();
        let mut request_sent = Some(request_sent);
        let mut event_sent = Some(event_sent);
        while let Some(Ok(message)) = socket.next().await {
            let SocketMessage::Text(text) = message else {
                if matches!(message, SocketMessage::Close(_)) {
                    break;
                }
                continue;
            };
            let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
            if frame[0] == "REQ" {
                let reply = match behavior {
                    RouteBehavior::RejectSubscription => {
                        serde_json::json!([
                            "CLOSED",
                            frame[1],
                            "restricted: kind not allowed: 21194"
                        ])
                    }
                    RouteBehavior::AcceptWithoutPublicationReceipt => {
                        serde_json::json!(["EOSE", frame[1]])
                    }
                };
                socket
                    .send(SocketMessage::Text(reply.to_string().into()))
                    .await
                    .unwrap();
                if let Some(sent) = request_sent.take() {
                    let _ = sent.send(());
                }
            } else if frame[0] == "EVENT" {
                let event: Event = serde_json::from_value(frame[1].clone()).unwrap();
                assert!(event.verify().is_ok() && event.kind == EVENT_KIND);
                if let Some(sent) = event_sent.take() {
                    let _ = sent.send(event.id);
                }
                // Keep the accepted websocket alive, deliberately withholding OK.
            }
        }
    });
    (endpoint, request_seen, event_seen, server)
}

async fn close_witness_socket(mut server: tokio::task::JoinHandle<()>) -> bool {
    match tokio::time::timeout(Duration::from_secs(3), &mut server).await {
        Ok(result) => result.is_ok(),
        Err(_) => {
            server.abort();
            let _ = server.await;
            false
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_pairing_subscription_cannot_export_a_mailbox() {
    let (endpoint, closed_seen, _, server) =
        witnessed_route(RouteBehavior::RejectSubscription).await;
    let plane = MarmotRelayPlane::full_history_with_loopback(true);
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        plane.pairing_mailbox(
            EVENT_KIND,
            vec![endpoint],
            Keys::generate().public_key(),
            Instant::now() + Duration::from_secs(30),
        ),
    )
    .await;
    let actual_closed = matches!(
        tokio::time::timeout(Duration::from_secs(3), closed_seen).await,
        Ok(Ok(()))
    );
    let refused_before_export = matches!(&result, Ok(Err(PairingRelayError::Unavailable)));
    drop(result);
    plane.shutdown().await;
    let socket_closed = close_witness_socket(server).await;
    assert!(
        actual_closed && socket_closed,
        "real_closed_route_prerequisites_and_positive_cleanup"
    );
    eprintln!("pairing_closed_export actual_req=true actual_closed=true sockets_closed=true");
    assert!(
        refused_before_export,
        "pairing_subscription_rejected_before_mailbox_export"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthy_pairing_ack_survives_another_accepted_route_without_ok() {
    let (silent, ready_seen, event_seen, server) =
        witnessed_route(RouteBehavior::AcceptWithoutPublicationReceipt).await;
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let healthy = relay.url().await.to_string();
    let plane = MarmotRelayPlane::full_history_with_loopback(true);
    let other_plane = MarmotRelayPlane::full_history_with_loopback(true);
    let now = NostrTimestamp::now().as_secs();
    let keys = Keys::generate();
    let bootstrap = Bootstrap::new(keys.public_key(), b"synthetic route witness", now + 30);
    let deadline = Instant::now() + Duration::from_secs(30);
    let sender = Channel::new(keys, &bootstrap, now, deadline).unwrap();
    let receiver = Channel::new(Keys::generate(), &bootstrap, now, deadline).unwrap();
    let mut sender_box = plane
        .pairing_mailbox(
            EVENT_KIND,
            vec![TransportEndpoint(healthy.clone()), silent],
            sender.public_key(),
            deadline,
        )
        .await
        .unwrap();
    let mut receiver_box = other_plane
        .pairing_mailbox(
            EVENT_KIND,
            vec![TransportEndpoint(healthy.clone())],
            receiver.public_key(),
            deadline,
        )
        .await
        .unwrap();
    let actual_eose = matches!(
        tokio::time::timeout(Duration::from_secs(3), ready_seen).await,
        Ok(Ok(()))
    );
    let message = Message::new(
        bootstrap.binding().unwrap(),
        1,
        MessageKind::Verification,
        0,
        1,
        b"synthetic packet",
    )
    .unwrap();
    let event = sender
        .seal(
            receiver.public_key(),
            &message,
            NostrTimestamp::now().as_secs(),
        )
        .unwrap();
    let published = sender_box.publish(&event).await.is_ok();
    let actual_event = matches!(tokio::time::timeout(Duration::from_secs(3), event_seen).await, Ok(Ok(id)) if id == event.id);
    let received = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match receiver_box.next().await {
                Ok(Some(received)) if received.id == event.id => break Some(received),
                Ok(_) => {}
                Err(_) => break None,
            }
        }
    })
    .await
    .ok()
    .flatten();
    let delivered = received
        .and_then(|received| {
            receiver
                .open(
                    sender.public_key(),
                    &received,
                    NostrTimestamp::now().as_secs(),
                )
                .ok()
        })
        .and_then(|message| {
            message
                .bytes()
                .ok()
                .map(|bytes| bytes.as_slice() == b"synthetic packet")
        })
        == Some(true);
    drop(sender_box);
    drop(receiver_box);
    plane.shutdown().await;
    other_plane.shutdown().await;
    let socket_closed = close_witness_socket(server).await;
    relay.shutdown();
    let address = healthy.strip_prefix("ws://").unwrap().trim_end_matches('/');
    let relay_closed = tokio::time::timeout(Duration::from_secs(3), async {
        while let Ok(stream) = tokio::net::TcpStream::connect(address).await {
            drop(stream);
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();
    assert!(
        actual_eose && actual_event && delivered && socket_closed && relay_closed,
        "real_ack_route_prerequisites_and_positive_cleanup"
    );
    eprintln!(
        "pairing_ack_witness actual_req=true actual_eose=true actual_event=true decrypted_delivery=true sockets_closed=true"
    );
    assert!(
        published,
        "healthy_pairing_ack_not_discarded_by_another_route_timeout"
    );
}
