//! Bounded private verifier transport, with no approval or membership semantics.
//! These packets are not an adopted Marmot or Matrix transport profile.
use super::{LinkError, LinkFrame, MAX_FRAME_BYTES, PeerOffer, Result, Role};

const PREFIX: &[u8; 5] = b"WNLS\x01";
const OFFER: u8 = 1;
const FRAME: u8 = 2;
const MAX_TOKEN_BYTES: usize = 128;
pub(crate) const MAX_PACKET_BYTES: usize = MAX_FRAME_BYTES + 171;

fn header(kind: u8, binding: &[u8; 32]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(43);
    packet.extend_from_slice(PREFIX);
    packet.push(kind);
    packet.extend_from_slice(binding);
    packet
}

fn read_header(packet: &[u8], kind: u8) -> Result<([u8; 32], &[u8])> {
    if packet.len() > MAX_PACKET_BYTES {
        return Err(LinkError::LimitExceeded);
    }
    if packet.len() < 38 || &packet[..5] != PREFIX || packet[5] != kind {
        return Err(LinkError::InvalidFrame);
    }
    let binding = packet[6..38]
        .try_into()
        .map_err(|_| LinkError::InvalidFrame)?;
    Ok((binding, &packet[38..]))
}

fn validate_payload(payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(LinkError::LimitExceeded);
    }
    let value: serde_json::Value =
        serde_json::from_slice(payload).map_err(|_| LinkError::InvalidFrame)?;
    if !value.is_object()
        || serde_json::to_vec(&value).map_err(|_| LinkError::InvalidFrame)? != payload
    {
        return Err(LinkError::InvalidFrame);
    }
    Ok(())
}

fn append_payload(packet: &mut Vec<u8>, payload: &[u8]) -> Result<()> {
    validate_payload(payload)?;
    packet.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(())
}

fn read_payload(body: &[u8]) -> Result<Vec<u8>> {
    let length_bytes = body.get(..4).ok_or(LinkError::InvalidFrame)?;
    let length = u32::from_be_bytes(
        length_bytes
            .try_into()
            .map_err(|_| LinkError::InvalidFrame)?,
    ) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(LinkError::LimitExceeded);
    }
    let payload = body.get(4..).ok_or(LinkError::InvalidFrame)?;
    if payload.len() != length {
        return Err(LinkError::InvalidFrame);
    }
    validate_payload(payload)?;
    Ok(payload.to_vec())
}

impl PeerOffer {
    pub(crate) fn encode_wire(&self) -> Result<Vec<u8>> {
        let mut packet = header(OFFER, &self.binding);
        packet.push(match self.role {
            Role::NewDevice => 1,
            Role::Approver => 2,
        });
        append_payload(&mut packet, &self.keys_json)?;
        Ok(packet)
    }

    pub(crate) fn decode_wire(packet: &[u8]) -> Result<Self> {
        let (binding, body) = read_header(packet, OFFER)?;
        let (&role, body) = body.split_first().ok_or(LinkError::InvalidFrame)?;
        let role = match role {
            1 => Role::NewDevice,
            2 => Role::Approver,
            _ => return Err(LinkError::InvalidFrame),
        };
        Ok(Self {
            binding,
            role,
            keys_json: read_payload(body)?,
        })
    }
}

impl LinkFrame {
    pub(crate) fn encode_wire(&self) -> Result<Vec<u8>> {
        if self.token.is_empty() || self.token.len() > MAX_TOKEN_BYTES {
            return Err(LinkError::InvalidFrame);
        }
        let mut packet = header(FRAME, &self.binding);
        packet.push(self.token.len() as u8);
        packet.extend_from_slice(self.token.as_bytes());
        append_payload(&mut packet, &self.event_json)?;
        Ok(packet)
    }

    pub(crate) fn decode_wire(packet: &[u8]) -> Result<Self> {
        let (binding, body) = read_header(packet, FRAME)?;
        let (&length, body) = body.split_first().ok_or(LinkError::InvalidFrame)?;
        let length = usize::from(length);
        if length == 0 || length > MAX_TOKEN_BYTES {
            return Err(LinkError::InvalidFrame);
        }
        let token = body.get(..length).ok_or(LinkError::InvalidFrame)?;
        let token = std::str::from_utf8(token).map_err(|_| LinkError::InvalidFrame)?;
        let event_json = read_payload(body.get(length..).ok_or(LinkError::InvalidFrame)?)?;
        Ok(Self {
            binding,
            token: token.to_owned(),
            event_json,
        })
    }
}
