//! Ordered, bounded packet delivery. A final receipt requires explicit consumer success.
use super::*;

const MAX_PACKET_BYTES: usize = MAX_CHUNK_BYTES * 64;

fn fingerprint(message: &Message) -> Result<[u8; 32]> {
    let bytes = Zeroizing::new(serde_json::to_vec(message).map_err(|_| Error::Invalid)?);
    Ok(Sha256::digest(bytes.as_slice()).into())
}
fn receipt(message: &Message) -> Result<Message> {
    Message::new(
        message.binding,
        message.sequence,
        MessageKind::Receipt,
        0,
        1,
        &fingerprint(message)?,
    )
}

pub(super) struct Sender {
    binding: [u8; 32],
    next: u32,
    pending: Vec<Message>,
    acknowledged: Vec<bool>,
}
impl Sender {
    pub(super) fn new(binding: [u8; 32]) -> Self {
        Self {
            binding,
            next: 0,
            pending: Vec::new(),
            acknowledged: Vec::new(),
        }
    }
    pub(super) fn queue(&mut self, kind: MessageKind, bytes: &[u8]) -> Result<()> {
        if !self.pending.is_empty()
            || bytes.len() > MAX_PACKET_BYTES
            || kind == MessageKind::Receipt
        {
            return Err(Error::Invalid);
        }
        let parts = bytes.len().div_ceil(MAX_CHUNK_BYTES).max(1);
        if self.next as usize + parts > MAX_SEQUENCE as usize {
            return Err(Error::Invalid);
        }
        let messages = (0..parts)
            .map(|part| {
                let start = part * MAX_CHUNK_BYTES;
                let end = (start + MAX_CHUNK_BYTES).min(bytes.len());
                Message::new(
                    self.binding,
                    self.next + part as u32,
                    kind,
                    part as u16,
                    parts as u16,
                    &bytes[start..end],
                )
            })
            .collect::<Result<Vec<_>>>()?;
        self.acknowledged = vec![false; parts];
        self.next += parts as u32;
        self.pending = messages;
        Ok(())
    }
    pub(super) fn outgoing(&self) -> impl Iterator<Item = &Message> {
        self.pending
            .iter()
            .zip(&self.acknowledged)
            .filter_map(|(message, acknowledged)| (!acknowledged).then_some(message))
    }
    /// True only when every fragment of the original queued packet was receipted.
    pub(super) fn receive_receipt(&mut self, message: &Message) -> Result<bool> {
        if message.binding != self.binding
            || message.kind != MessageKind::Receipt
            || message.part != 0
            || message.parts != 1
        {
            return Err(Error::Invalid);
        }
        let Some((index, original)) = self
            .pending
            .iter()
            .enumerate()
            .find(|(_, original)| original.sequence == message.sequence)
        else {
            // A late receipt for an older completed packet cannot acknowledge a new one.
            return Ok(false);
        };
        if message.bytes()?.as_slice() != fingerprint(original)? {
            return Err(Error::Invalid);
        }
        self.acknowledged[index] = true;
        if self.acknowledged.iter().all(|acknowledged| *acknowledged) {
            self.pending.clear();
            self.acknowledged.clear();
            return Ok(true);
        }
        Ok(false)
    }
}

pub(super) enum Inbound {
    Receipt(Message),
    /// An out-of-order packet needs retransmission; no state or receipt changed.
    Deferred,
    /// Repeated until the exact native operation reports success, then commit it.
    Packet {
        kind: MessageKind,
        bytes: Zeroizing<Vec<u8>>,
        sequence: u32,
    },
}
struct Assembly {
    kind: MessageKind,
    parts: u16,
    next_part: u16,
    bytes: Zeroizing<Vec<u8>>,
}
pub(super) struct Receiver {
    binding: [u8; 32],
    accepted: Vec<[u8; 32]>,
    assembly: Option<Assembly>,
    pending: Option<(Message, Zeroizing<Vec<u8>>)>,
}
impl Receiver {
    pub(super) fn new(binding: [u8; 32]) -> Self {
        Self {
            binding,
            accepted: Vec::new(),
            assembly: None,
            pending: None,
        }
    }
    pub(super) fn receive(&mut self, message: Message) -> Result<Inbound> {
        if message.binding != self.binding
            || message.domain != DOMAIN
            || message.kind == MessageKind::Receipt
            || message.sequence >= MAX_SEQUENCE
            || message.parts == 0
            || message.parts > 64
            || message.part >= message.parts
        {
            return Err(Error::Invalid);
        }
        let hash = fingerprint(&message)?;
        let sequence = message.sequence as usize;
        if let Some(previous) = self.accepted.get(sequence) {
            return if previous == &hash {
                Ok(Inbound::Receipt(receipt(&message)?))
            } else {
                Err(Error::Invalid)
            };
        }
        if sequence != self.accepted.len() {
            return Ok(Inbound::Deferred);
        }
        if let Some((original, bytes)) = &self.pending {
            return if fingerprint(original)? == hash {
                Ok(Inbound::Packet {
                    kind: original.kind,
                    bytes: bytes.clone(),
                    sequence: original.sequence,
                })
            } else {
                Err(Error::Invalid)
            };
        }
        let bytes = message.bytes()?;
        if let Some(assembly) = &self.assembly {
            if assembly.kind != message.kind
                || assembly.parts != message.parts
                || assembly.next_part != message.part
                || assembly.bytes.len() + bytes.len() > MAX_PACKET_BYTES
            {
                return Err(Error::Invalid);
            }
        } else if message.part != 0 {
            return Err(Error::Invalid);
        }
        let assembly = self.assembly.get_or_insert_with(|| Assembly {
            kind: message.kind,
            parts: message.parts,
            next_part: 0,
            bytes: Zeroizing::new(Vec::new()),
        });
        assembly.bytes.extend_from_slice(&bytes);
        assembly.next_part += 1;
        if assembly.next_part == assembly.parts {
            let bytes = self.assembly.take().ok_or(Error::Invalid)?.bytes;
            let result = Inbound::Packet {
                kind: message.kind,
                bytes: bytes.clone(),
                sequence: message.sequence,
            };
            self.pending = Some((message, bytes));
            Ok(result)
        } else {
            let result = receipt(&message)?;
            self.accepted.push(hash);
            Ok(Inbound::Receipt(result))
        }
    }
    /// Called after the original native consumer accepts this exact pending packet.
    pub(super) fn commit(&mut self, sequence: u32) -> Result<Message> {
        let (message, _) = self.pending.as_ref().ok_or(Error::Invalid)?;
        if message.sequence != sequence || sequence as usize != self.accepted.len() {
            return Err(Error::Invalid);
        }
        let acknowledgement = receipt(message)?;
        let hash = fingerprint(message)?;
        self.pending = None;
        self.accepted.push(hash);
        Ok(acknowledgement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn copy(message: &Message) -> Message {
        serde_json::from_slice(&serde_json::to_vec(message).unwrap()).unwrap()
    }

    #[test]
    fn final_receipt_requires_native_consumer_success_and_supports_retry() {
        let mut sender = Sender::new([1; 32]);
        let mut receiver = Receiver::new([1; 32]);
        sender
            .queue(MessageKind::Verification, b"opaque packet")
            .unwrap();
        let message = copy(sender.outgoing().next().unwrap());
        for _ in 0..2 {
            assert!(matches!(
                receiver.receive(copy(&message)).unwrap(),
                Inbound::Packet { .. }
            ));
            assert_eq!(sender.outgoing().count(), 1);
        }
        assert!(receiver.commit(99).is_err());
        let receipt = receiver.commit(message.sequence).unwrap();
        assert!(sender.receive_receipt(&receipt).unwrap());
        assert_eq!(sender.outgoing().count(), 0);
        assert!(matches!(
            receiver.receive(message).unwrap(),
            Inbound::Receipt(_)
        ));
    }

    #[test]
    fn fragmented_packet_reassembles_under_reordering_and_lost_receipts() {
        let mut sender = Sender::new([1; 32]);
        let mut receiver = Receiver::new([1; 32]);
        let bytes = vec![42; MAX_PACKET_BYTES];
        sender.queue(MessageKind::SetupResponse, &bytes).unwrap();
        let messages = sender.outgoing().map(copy).collect::<Vec<_>>();
        assert_eq!(messages.len(), 64);
        assert!(matches!(
            receiver.receive(copy(&messages[1])).unwrap(),
            Inbound::Deferred
        ));
        for message in &messages {
            match receiver.receive(copy(message)).unwrap() {
                Inbound::Receipt(receipt) => {
                    // Lose one receipt; replaying the same fragment produces it again.
                    assert!(matches!(
                        receiver.receive(copy(message)).unwrap(),
                        Inbound::Receipt(_)
                    ));
                    assert!(!sender.receive_receipt(&receipt).unwrap());
                }
                Inbound::Packet {
                    bytes: actual,
                    kind,
                    sequence,
                } => {
                    assert!(kind == MessageKind::SetupResponse);
                    assert_eq!(actual.as_slice(), bytes);
                    assert!(
                        sender
                            .receive_receipt(&receiver.commit(sequence).unwrap())
                            .unwrap()
                    );
                }
                Inbound::Deferred => panic!("in-order fragment deferred"),
            }
        }
    }

    #[test]
    fn conflicting_replay_and_receipt_cannot_advance_delivery() {
        let mut sender = Sender::new([1; 32]);
        let mut receiver = Receiver::new([1; 32]);
        sender.queue(MessageKind::Verification, b"packet").unwrap();
        let original = copy(sender.outgoing().next().unwrap());
        let mut forged = receipt(&original).unwrap();
        forged.payload = URL_SAFE_NO_PAD.encode([0; 32]);
        assert!(sender.receive_receipt(&forged).is_err());
        assert!(matches!(
            receiver.receive(copy(&original)).unwrap(),
            Inbound::Packet { .. }
        ));
        let mut conflict = copy(&original);
        conflict.payload = URL_SAFE_NO_PAD.encode(b"changed packet");
        assert!(receiver.receive(conflict).is_err());
        assert!(
            sender
                .receive_receipt(&receiver.commit(0).unwrap())
                .unwrap()
        );
        let mut conflict = copy(&original);
        conflict.kind = MessageKind::Enrollment;
        assert!(receiver.receive(conflict).is_err());
        sender
            .queue(MessageKind::Verification, b"next packet")
            .unwrap();
        assert!(
            !sender
                .receive_receipt(&receipt(&original).unwrap())
                .unwrap()
        );
        assert_eq!(sender.outgoing().count(), 1);
    }

    #[test]
    fn oversized_or_wrong_attempt_packet_leaves_receiver_unchanged() {
        let mut sender = Sender::new([1; 32]);
        assert!(
            sender
                .queue(MessageKind::SetupResponse, &vec![0; MAX_PACKET_BYTES + 1])
                .is_err()
        );
        sender.queue(MessageKind::Hello, b"").unwrap();
        let mut receiver = Receiver::new([2; 32]);
        assert!(
            receiver
                .receive(copy(sender.outgoing().next().unwrap()))
                .is_err()
        );
        assert!(receiver.accepted.is_empty());
        assert!(receiver.pending.is_none());
    }
}
