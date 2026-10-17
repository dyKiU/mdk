//! One attempt's encrypted mailbox on the host-safety-filtered anonymous relay pool.
use super::*;
use nostr::prelude::Event;
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingRelayError {
    Unavailable,
    Expired,
    Invalid,
}

pub struct PairingMailbox {
    client: NostrSdkClient,
    relays: Vec<RelayUrl>,
    id: SubscriptionId,
    recipient: PublicKey,
    event_kind: Kind,
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
    pub async fn pairing_mailbox(
        &self,
        event_kind: Kind,
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
            event_kind,
            deadline: deadline.into(),
            pending: VecDeque::new(),
        };
        let connect_deadline = mailbox
            .deadline
            .min(tokio::time::Instant::now() + DIRECTORY_RELAY_CONNECT_WAIT);
        let connections = futures::future::join_all(mailbox.relays.iter().map(|relay| async {
            let connected = timeout_at(connect_deadline, async {
                mailbox.client.add_relay(relay.clone()).await.ok()?;
                let relay = mailbox.client.relay(relay.clone()).await.ok()??;
                // connect() only queues work. Observe before requesting it so a
                // fast connection (or a retiring previous task) cannot lose the
                // wakeup. Do not submit a REQ against a disconnected relay's
                // health gate, or consume its EOSE budget while still dialing.
                let mut updates = relay.notifications_with_gaps();
                relay.connect();
                loop {
                    let status = relay.status();
                    if status.is_connected() {
                        return Some(());
                    }
                    if matches!(
                        status,
                        nostr_sdk::prelude::RelayStatus::Banned
                            | nostr_sdk::prelude::RelayStatus::Shutdown
                    ) {
                        return None;
                    }
                    updates.next().await?;
                }
            })
            .await;
            matches!(connected, Ok(Some(()))).then(|| relay.clone())
        }))
        .await;
        mailbox.relays = connections.into_iter().flatten().collect();
        if mailbox.relays.is_empty() {
            return Err(PairingRelayError::Unavailable);
        }
        let filter = Filter::new()
            .kind(event_kind)
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
                    && event.kind == self.event_kind
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

    pub async fn publish(&mut self, event: &Event) -> Result<(), PairingRelayError> {
        if event.kind != self.event_kind || event.content.len() > 32768 || event.verify().is_err() {
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
    pub async fn next(&mut self) -> Result<Option<Event>, PairingRelayError> {
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
    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn generic_mailbox_refuses_a_different_kind_and_an_expired_original() {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let endpoint = TransportEndpoint(relay.url().await.to_string());
        let plane = MarmotRelayPlane::full_history_with_loopback(true);
        let keys = Keys::generate();
        let kind = Kind::Custom(20000);
        let mut mailbox = plane.pairing_mailbox(
            kind, vec![endpoint.clone()], keys.public_key(), Instant::now() + Duration::from_secs(15),
        ).await.unwrap();
        let other_kind = EventBuilder::new(Kind::Custom(20001), "fixed fixture")
            .finalize(&keys).unwrap();
        assert_eq!(mailbox.publish(&other_kind).await, Err(PairingRelayError::Invalid));
        drop(mailbox);
        let expired = plane.pairing_mailbox(
            kind, vec![endpoint], keys.public_key(), Instant::now() - Duration::from_millis(1),
        ).await;
        assert!(matches!(expired, Err(PairingRelayError::Expired)));
        plane.shutdown().await;
    }
}
