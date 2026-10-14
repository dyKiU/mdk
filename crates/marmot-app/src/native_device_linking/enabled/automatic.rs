//! Automatic transport retains the original verifier; it never confirms comparison.
use super::*;
use crate::device_linking::network::delivery::{Inbound, Receiver, Sender};
use crate::device_linking::network::{
    Bootstrap, Channel, Error as WireError, Message, MessageKind,
};
use crate::relay_plane::pairing::{PairingMailbox, PairingRelayError};
use nostr::prelude::{Event, Keys, PublicKey, Timestamp};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fn wire_error(error: WireError) -> DeviceLinkingError {
    match error {
        WireError::Expired => DeviceLinkingError::Closed,
        _ => DeviceLinkingError::InvalidPacket,
    }
}
fn relay_error(error: PairingRelayError) -> DeviceLinkingError {
    match error {
        PairingRelayError::Expired => DeviceLinkingError::Closed,
        PairingRelayError::Invalid => DeviceLinkingError::InvalidPacket,
        _ => DeviceLinkingError::RuntimeUnavailable,
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    AwaitHello,
    AwaitRequest,
    SendRequest,
    AwaitResponse,
    SendResponse,
    Verifying,
}
enum Sent {
    Hello,
    Request,
    Response,
    Verification(String),
}
pub(super) struct Driver {
    channel: Channel,
    mailbox: PairingMailbox,
    peer: Option<PublicKey>,
    request_digest: [u8; 32],
    sender: Sender,
    receiver: Receiver,
    stage: Stage,
    sent: Option<Sent>,
    last_send: std::time::Instant,
    deadline: std::time::Instant,
}
impl Driver {
    async fn open(
        manager: &AccountManager,
        keys: Keys,
        bootstrap: &Bootstrap,
        scanner: bool,
        deadline: std::time::Instant,
    ) -> Result<Self, DeviceLinkingError> {
        let (plane, endpoints) = manager.device_pairing_transport();
        let channel = Channel::new(keys, bootstrap, Timestamp::now().as_secs(), deadline)
            .map_err(wire_error)?;
        let mailbox = plane
            .pairing_mailbox(endpoints, channel.public_key(), deadline)
            .await
            .map_err(relay_error)?;
        let mut driver = Self {
            channel,
            mailbox,
            peer: scanner.then_some(bootstrap.public_key),
            request_digest: bootstrap.request_digest,
            sender: Sender::new(bootstrap.binding().map_err(wire_error)?),
            receiver: Receiver::new(bootstrap.binding().map_err(wire_error)?),
            stage: if scanner {
                Stage::AwaitRequest
            } else {
                Stage::AwaitHello
            },
            sent: None,
            last_send: std::time::Instant::now() - std::time::Duration::from_secs(1),
            deadline,
        };
        if scanner {
            driver
                .sender
                .queue(MessageKind::Hello, &[])
                .map_err(wire_error)?;
            driver.sent = Some(Sent::Hello);
        }
        Ok(driver)
    }
    async fn receipt(&mut self, receipt: Message) -> Result<(), DeviceLinkingError> {
        let peer = self.peer.ok_or(DeviceLinkingError::NotReady)?;
        let event = self
            .channel
            .seal(peer, &receipt, Timestamp::now().as_secs())
            .map_err(wire_error)?;
        // A lost receipt is recovered by peer retransmission. No native ACK
        // is manufactured from a relay publish result.
        let _ = self.mailbox.publish(&event).await;
        Ok(())
    }
    async fn receive(
        &mut self,
        event: Event,
        original: Option<&DeviceLinkingSession>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceLinkingError> {
        let peer = self.peer.unwrap_or(event.pubkey);
        let message = match self.channel.open(peer, &event, Timestamp::now().as_secs()) {
            Ok(message) => message,
            Err(_) => return Ok(None), // Unrelated/malicious relay data never retires the original.
        };
        if self.peer.is_none() {
            if self.stage != Stage::AwaitHello
                || message.kind != MessageKind::Hello
                || message.sequence != 0
                || message.parts != 1
                || !message.bytes().map_err(wire_error)?.is_empty()
            {
                return Ok(None);
            }
            // Physical QR binds the initiator; SAS must still authenticate this
            // first responder. Never replace its pinned key within the attempt.
            self.peer = Some(peer);
        }
        if message.kind == MessageKind::Receipt {
            if self.sender.receive_receipt(&message).map_err(wire_error)? {
                match self.sent.take() {
                    Some(Sent::Verification(id)) => {
                        original
                            .ok_or(DeviceLinkingError::NotReady)?
                            .acknowledge_packet(id)
                            .await?
                    }
                    Some(Sent::Request) if self.stage == Stage::SendRequest => {
                        self.stage = Stage::AwaitResponse
                    }
                    Some(Sent::Response) => self.stage = Stage::Verifying,
                    _ => {}
                }
            }
            return Ok(None);
        }
        match self.receiver.receive(message).map_err(wire_error)? {
            Inbound::Deferred => {}
            Inbound::Receipt(receipt) => self.receipt(receipt).await?,
            Inbound::Packet {
                kind,
                bytes,
                sequence,
            } => {
                match kind {
                    MessageKind::Hello if self.stage == Stage::AwaitHello && bytes.is_empty() => {
                        self.stage = Stage::SendRequest
                    }
                    MessageKind::SetupRequest
                        if self.stage == Stage::AwaitRequest && original.is_none() =>
                    {
                        if <[u8; 32]>::from(Sha256::digest(bytes.as_slice())) != self.request_digest
                        {
                            return Err(DeviceLinkingError::InvalidPacket);
                        }
                        return Ok(Some(bytes));
                    }
                    MessageKind::SetupResponse
                        if original.is_some_and(|session| session.inner.new_device) =>
                    {
                        original
                            .ok_or(DeviceLinkingError::NotReady)?
                            .receive_setup_packet(bytes.to_vec())
                            .await?;
                        self.stage = Stage::Verifying;
                    }
                    MessageKind::Verification => {
                        original
                            .ok_or(DeviceLinkingError::NotReady)?
                            .receive_packet(bytes.to_vec())
                            .await?
                    }
                    _ => return Err(DeviceLinkingError::InvalidPacket),
                }
                let receipt = self.receiver.commit(sequence).map_err(wire_error)?;
                self.receipt(receipt).await?;
            }
        }
        Ok(None)
    }
    async fn send_pending(&mut self) -> Result<(), DeviceLinkingError> {
        if self.last_send.elapsed() < std::time::Duration::from_millis(500) {
            return Ok(());
        }
        let Some(peer) = self.peer else {
            return Ok(());
        };
        self.last_send = std::time::Instant::now();
        for message in self.sender.outgoing() {
            // Fresh encryption on each retry avoids relay/SDK event deduplication.
            let event = self
                .channel
                .seal(peer, message, Timestamp::now().as_secs())
                .map_err(wire_error)?;
            let _ = self.mailbox.publish(&event).await;
        }
        Ok(())
    }
    async fn queue_native(
        &mut self,
        original: &DeviceLinkingSession,
    ) -> Result<(), DeviceLinkingError> {
        if self.sender.outgoing().next().is_some() {
            return Ok(());
        }
        match self.stage {
            Stage::SendRequest => {
                self.sender
                    .queue(MessageKind::SetupRequest, &original.inner.setup)
                    .map_err(wire_error)?;
                self.sent = Some(Sent::Request);
            }
            Stage::SendResponse => {
                self.sender
                    .queue(MessageKind::SetupResponse, &original.inner.setup)
                    .map_err(wire_error)?;
                self.sent = Some(Sent::Response);
            }
            Stage::Verifying => {
                // Enrollment transfer is a separate following slice. Never call
                // verifier operations after the original proof has moved.
                if original.inner.operation.lock().await.enrollment_started {
                    return Ok(());
                }
                if let Some(packet) = original.outgoing_packets().await?.into_iter().next() {
                    self.sender
                        .queue(MessageKind::Verification, &packet.bytes)
                        .map_err(wire_error)?;
                    self.sent = Some(Sent::Verification(packet.acknowledgement_id));
                }
            }
            _ => {}
        }
        Ok(())
    }
    async fn request(&mut self) -> Result<Zeroizing<Vec<u8>>, DeviceLinkingError> {
        loop {
            if std::time::Instant::now() >= self.deadline {
                return Err(DeviceLinkingError::Closed);
            }
            self.send_pending().await?;
            if let Ok(result) =
                tokio::time::timeout(std::time::Duration::from_millis(100), self.mailbox.next())
                    .await
                && let Some(event) = result.map_err(relay_error)?
                && let Some(request) = self.receive(event, None).await?
            {
                return Ok(request);
            }
        }
    }
    fn spawn(mut self, state: &Arc<SessionState>) {
        let weak = Arc::downgrade(state);
        let cancellation = state.transport_cancel.clone();
        state.runtime.spawn(async move {
            let result = async {
                loop {
                    let Some(state) = weak.upgrade() else {
                        return Ok::<(), DeviceLinkingError>(());
                    };
                    state.check_open()?;
                    // Only this internal borrowed facade skips Drop cleanup.
                    // The public original always closes admission synchronously.
                    let original = DeviceLinkingSession {
                        inner: state,
                        owns_lifetime: false,
                    };
                    self.queue_native(&original).await?;
                    self.send_pending().await?;
                    if let Ok(result) = tokio::time::timeout(
                        std::time::Duration::from_millis(100),
                        self.mailbox.next(),
                    )
                    .await
                        && let Some(event) = result.map_err(relay_error)?
                    {
                        self.receive(event, Some(&original)).await?;
                    }
                }
            };
            tokio::select! {
                _ = cancellation.cancelled() => {}
                result = result => {
                    if result.is_err() && let Some(state) = weak.upgrade() {
                        state.update(DeviceLinkingPhase::Failed, None);
                        state.close();
                        state.defer_cleanup();
                    }
                }
            }
        });
    }
}
impl DeviceLinkingSession {
    /// Starts one automatic mailbox for this exact original. QR contains no raw key.
    pub async fn automatic_pairing_code(&self) -> Result<String, DeviceLinkingError> {
        let mut bootstrap_code = self.inner.transport_bootstrap.lock().await;
        self.inner.check_open()?;
        if let Some(code) = bootstrap_code.as_ref() {
            // Host activates only after admitting this exact returned original
            // into its still-live account scope. A late factory cannot export a
            // responder's setup packet before that adoption check.
            if let Some(driver) = self
                .inner
                .pending_transport
                .lock()
                .expect("pending pairing transport")
                .take()
            {
                driver.spawn(&self.inner);
            }
            return Ok(code.clone());
        }
        if !self.inner.new_device {
            return Err(DeviceLinkingError::NotReady);
        }
        let remaining = self
            .inner
            .transport_deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_secs();
        if remaining == 0 {
            return Err(DeviceLinkingError::Closed);
        }
        let now = Timestamp::now().as_secs();
        let keys = Keys::generate();
        let bootstrap = Bootstrap::new(keys.public_key(), &self.inner.setup, now + remaining);
        let code = bootstrap.encode(now).map_err(wire_error)?;
        let driver = Driver::open(
            &self.inner.manager,
            keys,
            &bootstrap,
            false,
            self.inner.transport_deadline,
        )
        .await?;
        self.inner.check_open()?;
        *bootstrap_code = Some(code.clone());
        driver.spawn(&self.inner);
        Ok(code)
    }
}
impl AccountManager {
    /// Scanning selects a fresh transport, not trust. Native factory checks the account.
    pub async fn approve_automatic_device_linking_session(
        &self,
        account_ref: &str,
        code: String,
        target: Option<Vec<u8>>,
    ) -> Result<DeviceLinkingSession, DeviceLinkingError> {
        self.resolve(account_ref)
            .map_err(|_| DeviceLinkingError::RuntimeUnavailable)?;
        let now = Timestamp::now().as_secs();
        let bootstrap = Bootstrap::decode(&code, now).map_err(wire_error)?;
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(bootstrap.expires_at - now);
        let mut driver = Driver::open(self, Keys::generate(), &bootstrap, true, deadline).await?;
        let request = driver.request().await?;
        let original = self
            .approve_device_linking_session(account_ref, request.to_vec(), target)
            .await?;
        // Commit the request only after the exact actor accepted its setup.
        let receipt = driver
            .receiver
            .commit(driver.receiver.pending_sequence().map_err(wire_error)?)
            .map_err(wire_error)?;
        driver.receipt(receipt).await?;
        driver.stage = Stage::SendResponse;
        *original.inner.transport_bootstrap.lock().await = Some(code);
        let mut pending = original
            .inner
            .pending_transport
            .lock()
            .expect("pending pairing transport");
        original.inner.check_open()?;
        *pending = Some(driver);
        drop(pending);
        Ok(original)
    }
}
