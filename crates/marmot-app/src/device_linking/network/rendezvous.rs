//! Transport-only role negotiation. Neither QR direction nor this envelope grants trust.
use super::*;

const RENDEZVOUS_PREFIX: &str = "WNPAIR2:";
const MARKER: &[u8] = b"whitenoise-pairing-role-rendezvous-v1";

/// An existing installation advertises a mailbox, without reserving a NewDevice purpose.
pub(crate) struct Rendezvous(Bootstrap);
impl Rendezvous {
    pub(crate) fn new(public_key: PublicKey, expires_at: u64) -> Self {
        Self(Bootstrap::new(public_key, MARKER, expires_at))
    }
    pub(crate) fn bootstrap(&self) -> &Bootstrap {
        &self.0
    }
    pub(crate) fn encode(&self, now: u64) -> Result<String> {
        let code = self.0.encode(now)?;
        Ok(format!("{RENDEZVOUS_PREFIX}{}", &code[PREFIX.len()..]))
    }
    pub(crate) fn decode(code: &str, now: u64) -> Result<Self> {
        if code.len() > MAX_QR_BYTES {
            return Err(Error::Invalid);
        }
        let suffix = code.strip_prefix(RENDEZVOUS_PREFIX).ok_or(Error::Invalid)?;
        let bootstrap = Bootstrap::decode(&format!("{PREFIX}{suffix}"), now)?;
        if bootstrap.request_digest != <[u8; 32]>::from(Sha256::digest(MARKER)) {
            return Err(Error::Invalid);
        }
        Ok(Self(bootstrap))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReverseRequest {
    rendezvous_binding: [u8; 32],
    request_code: String,
}
impl Drop for ReverseRequest {
    fn drop(&mut self) {
        self.request_code.zeroize();
    }
}

/// Carries the joining device's ordinary request-bound bootstrap inside the
/// scanned mailbox's signed encrypted Hello. The actual verifier still checks
/// account identity, SAS confirmation and the original enrollment purposes.
pub(crate) fn reverse_hello(
    rendezvous: &Rendezvous,
    request_code: String,
    now: u64,
) -> Result<Message> {
    let request = Bootstrap::decode(&request_code, now)?;
    if request.expires_at > rendezvous.0.expires_at {
        return Err(Error::Invalid);
    }
    rendezvous.0.validate(now)?;
    let binding = rendezvous.0.binding()?;
    let bytes = Zeroizing::new(
        serde_json::to_vec(&ReverseRequest {
            rendezvous_binding: binding,
            request_code,
        })
        .map_err(|_| Error::Invalid)?,
    );
    Message::new(binding, 0, MessageKind::Hello, 0, 1, &bytes)
}

/// Call only after Channel::open authenticated the original scanned mailbox.
/// A reverse request can shorten, never renew, the scanned attempt's lifetime.
pub(crate) fn receive_reverse_hello(
    rendezvous: &Rendezvous,
    message: &Message,
    now: u64,
) -> Result<Zeroizing<String>> {
    rendezvous.0.validate(now)?;
    if message.binding != rendezvous.0.binding()?
        || message.kind != MessageKind::Hello
        || message.sequence != 0
        || message.part != 0
        || message.parts != 1
    {
        return Err(Error::Invalid);
    }
    let bytes = message.bytes()?;
    let request: ReverseRequest = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
    if request.rendezvous_binding != rendezvous.0.binding()? {
        return Err(Error::Invalid);
    }
    let bootstrap = Bootstrap::decode(&request.request_code, now)?;
    if bootstrap.expires_at > rendezvous.0.expires_at {
        return Err(Error::Invalid);
    }
    Ok(Zeroizing::new(request.request_code.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendezvous_is_small_and_cannot_be_decoded_as_a_legacy_setup() {
        let rendezvous = Rendezvous::new(Keys::generate().public_key(), 1600);
        let code = rendezvous.encode(1000).unwrap();
        assert!(code.len() <= MAX_QR_BYTES);
        assert!(Bootstrap::decode(&code, 1000).is_err());
        assert_eq!(
            Rendezvous::decode(&code, 1000)
                .unwrap()
                .0
                .binding()
                .unwrap(),
            rendezvous.0.binding().unwrap()
        );
        let ordinary = Bootstrap::new(Keys::generate().public_key(), b"setup", 1600);
        let forged = ordinary
            .encode(1000)
            .unwrap()
            .replacen(PREFIX, RENDEZVOUS_PREFIX, 1);
        assert!(Rendezvous::decode(&forged, 1000).is_err());
    }

    #[test]
    fn reverse_request_round_trips_only_inside_the_scanned_encrypted_channel() {
        let display_keys = Keys::generate();
        let rendezvous = Rendezvous::new(display_keys.public_key(), 1600);
        let deadline = Instant::now() + Duration::from_secs(600);
        let display = Channel::new(display_keys, rendezvous.bootstrap(), 1000, deadline).unwrap();
        let scanner =
            Channel::new(Keys::generate(), rendezvous.bootstrap(), 1000, deadline).unwrap();
        let code = Bootstrap::new(Keys::generate().public_key(), b"original setup", 1599)
            .encode(1000)
            .unwrap();
        let message = reverse_hello(&rendezvous, code.clone(), 1000).unwrap();
        let event = scanner.seal(display.public_key(), &message, 1000).unwrap();
        assert!(!event.content.contains(&code));
        let opened = display.open(scanner.public_key(), &event, 1000).unwrap();
        assert_eq!(
            receive_reverse_hello(&rendezvous, &opened, 1000)
                .unwrap()
                .as_str(),
            code
        );
        let other = Rendezvous::new(display.public_key(), 1600);
        assert!(receive_reverse_hello(&other, &opened, 1000).is_err());
        assert!(
            display
                .open(Keys::generate().public_key(), &event, 1000)
                .is_err()
        );
    }

    #[test]
    fn reverse_request_cannot_extend_expiry_or_carry_another_rendezvous() {
        let rendezvous = Rendezvous::new(Keys::generate().public_key(), 1500);
        let longer = Bootstrap::new(Keys::generate().public_key(), b"setup", 1501)
            .encode(1000)
            .unwrap();
        assert!(reverse_hello(&rendezvous, longer, 1000).is_err());
        assert!(reverse_hello(&rendezvous, rendezvous.encode(1000).unwrap(), 1000).is_err());
        assert!(Rendezvous::decode(&rendezvous.encode(1000).unwrap(), 1500).is_err());
    }
}
