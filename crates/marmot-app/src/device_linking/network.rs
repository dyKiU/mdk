//! Private one-scan transport envelopes; these grant no verification or enrollment.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nostr::{
    event::FinalizeEvent,
    nips::nip44,
    prelude::{Event, EventBuilder, Keys, Kind, PublicKey, Tag, Timestamp},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const PREFIX: &str = "WNPAIR1:";
const DOMAIN: &str = "whitenoise-private-pairing-transport-v1";
// Ephemeral private application transport, not an adopted Marmot event kind.
pub(crate) const EVENT_KIND: Kind = Kind::Custom(21194);
pub(crate) const MAX_CHUNK_BYTES: usize = 8192;
const MAX_QR_BYTES: usize = 1024;
const MAX_CIPHERTEXT_BYTES: usize = 32768;
const MAX_SEQUENCE: u32 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Invalid,
    Expired,
    Crypto,
}
type Result<T> = std::result::Result<T, Error>;
pub(crate) mod delivery;
pub(crate) mod rendezvous;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bootstrap {
    nonce: [u8; 32],
    pub(crate) public_key: PublicKey,
    pub(crate) request_digest: [u8; 32],
    pub(crate) expires_at: u64,
}
impl Bootstrap {
    pub(crate) fn new(public_key: PublicKey, request: &[u8], expires_at: u64) -> Self {
        let mut nonce = [0; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        Self {
            nonce,
            public_key,
            request_digest: Sha256::digest(request).into(),
            expires_at,
        }
    }
    fn validate(&self, now: u64) -> Result<()> {
        if self.expires_at <= now {
            return Err(Error::Expired);
        }
        if self.expires_at - now > 600 || self.nonce == [0; 32] {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub(crate) fn encode(&self, now: u64) -> Result<String> {
        self.validate(now)?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::Invalid)?;
        let qr = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
        if qr.len() > MAX_QR_BYTES {
            return Err(Error::Invalid);
        }
        Ok(qr)
    }
    pub(crate) fn decode(qr: &str, now: u64) -> Result<Self> {
        if qr.len() > MAX_QR_BYTES {
            return Err(Error::Invalid);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(qr.strip_prefix(PREFIX).ok_or(Error::Invalid)?)
            .map_err(|_| Error::Invalid)?;
        let value: Self = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        value.validate(now)?;
        if value.encode(now)? != qr {
            return Err(Error::Invalid);
        }
        Ok(value)
    }
    pub(crate) fn binding(&self) -> Result<[u8; 32]> {
        let mut digest = Sha256::new();
        digest.update(DOMAIN.as_bytes());
        digest.update(serde_json::to_vec(self).map_err(|_| Error::Invalid)?);
        Ok(digest.finalize().into())
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MessageKind {
    Hello,
    SetupRequest,
    SetupResponse,
    Verification,
    Enrollment,
    RecipientReady,
    Receipt,
}

// No Debug/Clone: a decrypted packet may carry sensitive enrollment material.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Message {
    domain: String,
    binding: [u8; 32],
    pub(crate) sequence: u32,
    pub(crate) kind: MessageKind,
    pub(crate) part: u16,
    pub(crate) parts: u16,
    payload: String,
}
impl Drop for Message {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}
impl Message {
    pub(crate) fn new(
        binding: [u8; 32],
        sequence: u32,
        kind: MessageKind,
        part: u16,
        parts: u16,
        bytes: &[u8],
    ) -> Result<Self> {
        if bytes.len() > MAX_CHUNK_BYTES
            || sequence >= MAX_SEQUENCE
            || parts == 0
            || parts > 64
            || part >= parts
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            domain: DOMAIN.into(),
            binding,
            sequence,
            kind,
            part,
            parts,
            payload: URL_SAFE_NO_PAD.encode(bytes),
        })
    }
    pub(crate) fn bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.payload.len() > MAX_CHUNK_BYTES * 4 / 3 + 4 {
            return Err(Error::Invalid);
        }
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(&self.payload)
                .map_err(|_| Error::Invalid)?,
        );
        if bytes.len() > MAX_CHUNK_BYTES || URL_SAFE_NO_PAD.encode(bytes.as_slice()) != self.payload
        {
            return Err(Error::Invalid);
        }
        Ok(bytes)
    }
}

/// Separate ephemeral transport keys, never the account's identity secret.
pub(crate) struct Channel {
    keys: Keys,
    binding: [u8; 32],
    expires_at: u64,
    deadline: Instant,
}
const HINT_TAG: &str = "whitenoise-pairing-mailbox-v1";
/// Only a transport address. Callers must authenticate its actual MLS origin.
#[derive(Clone)]
pub(crate) struct PeerHint {
    pub(crate) public_key: PublicKey,
    pub(crate) binding: [u8; 32],
    pub(crate) expires_at: u64,
}
impl PeerHint {
    pub(crate) fn tags(&self) -> Vec<Vec<String>> {
        vec![vec![
            HINT_TAG.into(),
            self.public_key.to_hex(),
            URL_SAFE_NO_PAD.encode(self.binding),
            self.expires_at.to_string(),
        ]]
    }
    pub(crate) fn from_tags(tags: &[Vec<String>], now: u64) -> Result<Option<Self>> {
        let mut found = tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|s| s == HINT_TAG));
        let Some(tag) = found.next() else {
            return Ok(None);
        };
        if found.next().is_some() || tag.len() != 4 {
            return Err(Error::Invalid);
        }
        let hint = Self {
            public_key: PublicKey::from_hex(&tag[1]).map_err(|_| Error::Invalid)?,
            binding: URL_SAFE_NO_PAD
                .decode(&tag[2])
                .map_err(|_| Error::Invalid)?
                .try_into()
                .map_err(|_| Error::Invalid)?,
            expires_at: tag[3].parse().map_err(|_| Error::Invalid)?,
        };
        if hint.expires_at <= now {
            return Err(Error::Expired);
        }
        if hint.expires_at - now > 600 || hint.binding == [0; 32] || hint.tags()[0] != *tag {
            return Err(Error::Invalid);
        }
        Ok(Some(hint))
    }
}
impl Channel {
    pub(crate) fn hint(&self) -> PeerHint {
        PeerHint {
            public_key: self.public_key(),
            binding: self.binding,
            expires_at: self.expires_at,
        }
    }
    pub(crate) fn for_hint(
        keys: Keys,
        hint: &PeerHint,
        now: u64,
        deadline: Instant,
    ) -> Result<Self> {
        let validated = PeerHint::from_tags(&hint.tags(), now)?.ok_or(Error::Invalid)?;
        let deadline =
            deadline.min(Instant::now() + Duration::from_secs(validated.expires_at - now));
        if Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        Ok(Self {
            keys,
            binding: validated.binding,
            expires_at: validated.expires_at,
            deadline,
        })
    }
    pub(crate) fn new(
        keys: Keys,
        bootstrap: &Bootstrap,
        now: u64,
        original_deadline: Instant,
    ) -> Result<Self> {
        bootstrap.validate(now)?;
        let deadline =
            original_deadline.min(Instant::now() + Duration::from_secs(bootstrap.expires_at - now));
        if Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        Ok(Self {
            keys,
            binding: bootstrap.binding()?,
            expires_at: bootstrap.expires_at,
            deadline,
        })
    }
    pub(crate) fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }
    fn live(&self, now: u64) -> Result<()> {
        if now >= self.expires_at || Instant::now() >= self.deadline {
            Err(Error::Expired)
        } else {
            Ok(())
        }
    }
    pub(crate) fn seal(&self, peer: PublicKey, message: &Message, now: u64) -> Result<Event> {
        self.live(now)?;
        if message.binding != self.binding || message.domain != DOMAIN {
            return Err(Error::Invalid);
        }
        let _bytes = message.bytes()?;
        let plaintext = Zeroizing::new(serde_json::to_vec(message).map_err(|_| Error::Invalid)?);
        let ciphertext = nip44::encrypt(
            self.keys.secret_key(),
            &peer,
            plaintext.as_slice(),
            nip44::Version::V2,
        )
        .map_err(|_| Error::Crypto)?;
        if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(Error::Invalid);
        }
        EventBuilder::new(EVENT_KIND, ciphertext)
            .tags([
                Tag::public_key(peer),
                Tag::expiration(Timestamp::from_secs(self.expires_at)),
            ])
            .custom_created_at(Timestamp::from_secs(now))
            .finalize(&self.keys)
            .map_err(|_| Error::Crypto)
    }
    pub(crate) fn open(&self, peer: PublicKey, event: &Event, now: u64) -> Result<Message> {
        self.live(now)?;
        if event.kind != EVENT_KIND
            || event.pubkey != peer
            || event.content.len() > MAX_CIPHERTEXT_BYTES
            || event.tags.len() != 2
            || !event.tags.contains(&Tag::public_key(self.public_key()))
            || !event
                .tags
                .contains(&Tag::expiration(Timestamp::from_secs(self.expires_at)))
            || event.created_at.as_secs() > now.saturating_add(30)
        {
            return Err(Error::Invalid);
        }
        event.verify().map_err(|_| Error::Crypto)?;
        let plaintext = Zeroizing::new(
            nip44::decrypt(self.keys.secret_key(), &peer, &event.content)
                .map_err(|_| Error::Crypto)?,
        );
        let message: Message = serde_json::from_str(&plaintext).map_err(|_| Error::Invalid)?;
        if message.domain != DOMAIN
            || message.binding != self.binding
            || message.sequence >= MAX_SEQUENCE
            || message.parts == 0
            || message.parts > 64
            || message.part >= message.parts
        {
            return Err(Error::Invalid);
        }
        let _bytes = message.bytes()?;
        Ok(message)
    }
}

#[cfg(test)]
mod tests;
