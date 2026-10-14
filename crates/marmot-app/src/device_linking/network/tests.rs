use super::*;

fn fixture() -> (Bootstrap, Channel, Channel) {
    let keys = Keys::generate();
    let bootstrap = Bootstrap::new(keys.public_key(), b"native request", 1600);
    let deadline = Instant::now() + Duration::from_secs(600);
    let a = Channel::new(keys, &bootstrap, 1000, deadline).unwrap();
    let b = Channel::new(Keys::generate(), &bootstrap, 1000, deadline).unwrap();
    (bootstrap, a, b)
}

#[test]
fn one_small_bootstrap_binds_request_without_carrying_it() {
    let request = vec![42; 100_000];
    let keys = Keys::generate();
    let bootstrap = Bootstrap::new(keys.public_key(), &request, 1600);
    let qr = bootstrap.encode(1000).unwrap();
    assert!(qr.len() < 1024);
    let decoded = Bootstrap::decode(&qr, 1000).unwrap();
    assert_eq!(decoded.public_key, keys.public_key());
    assert_eq!(
        decoded.request_digest,
        <[u8; 32]>::from(Sha256::digest(&request))
    );
    assert_eq!(decoded.binding().unwrap(), bootstrap.binding().unwrap());
    assert!(!qr.contains(&keys.secret_key().to_secret_hex()));
}

#[test]
fn signed_encrypted_transport_round_trips_in_both_directions() {
    let (bootstrap, a, b) = fixture();
    for (sender, receiver) in [(&a, &b), (&b, &a)] {
        let packet = Message::new(
            bootstrap.binding().unwrap(),
            1,
            MessageKind::Verification,
            0,
            1,
            b"private packet sentinel",
        )
        .unwrap();
        let event = sender.seal(receiver.public_key(), &packet, 1000).unwrap();
        assert!(!event.content.contains("private packet sentinel"));
        let result = receiver.open(sender.public_key(), &event, 1000).unwrap();
        assert_eq!(
            result.bytes().unwrap().as_slice(),
            b"private packet sentinel"
        );
    }
}

#[test]
fn wrong_peer_signature_recipient_and_attempt_are_rejected() {
    let (bootstrap, a, b) = fixture();
    let packet = Message::new(
        bootstrap.binding().unwrap(),
        1,
        MessageKind::Verification,
        0,
        1,
        b"packet",
    )
    .unwrap();
    let event = a.seal(b.public_key(), &packet, 1000).unwrap();
    assert!(b.open(Keys::generate().public_key(), &event, 1000).is_err());
    let mut tampered = event.clone();
    tampered.content.push('A');
    assert!(b.open(a.public_key(), &tampered, 1000).is_err());
    let wrong_recipient = a
        .seal(Keys::generate().public_key(), &packet, 1000)
        .unwrap();
    assert!(b.open(a.public_key(), &wrong_recipient, 1000).is_err());
    let other = Bootstrap::new(a.public_key(), b"another request", 1600);
    let other_receiver = Channel::new(
        b.keys.clone(),
        &other,
        1000,
        Instant::now() + Duration::from_secs(600),
    )
    .unwrap();
    assert!(other_receiver.open(a.public_key(), &event, 1000).is_err());
}

#[test]
fn expiry_is_fixed_and_cannot_be_extended_by_a_packet() {
    let (bootstrap, a, b) = fixture();
    let packet = Message::new(
        bootstrap.binding().unwrap(),
        1,
        MessageKind::Hello,
        0,
        1,
        b"",
    )
    .unwrap();
    let event = a.seal(b.public_key(), &packet, 1000).unwrap();
    assert!(matches!(
        b.open(a.public_key(), &event, 1600),
        Err(Error::Expired)
    ));
    assert!(matches!(
        a.seal(b.public_key(), &packet, 1600),
        Err(Error::Expired)
    ));
    assert!(Bootstrap::decode(&bootstrap.encode(1000).unwrap(), 1600).is_err());
    assert!(bootstrap.encode(999).is_err());
    assert!(Channel::new(Keys::generate(), &bootstrap, 1000, Instant::now()).is_err());
}

#[test]
fn resource_and_fragment_bounds_reject_before_encryption() {
    let (bootstrap, _, _) = fixture();
    let binding = bootstrap.binding().unwrap();
    assert!(
        Message::new(binding, 0, MessageKind::Verification, 0, 1, &vec![
            0;
            MAX_CHUNK_BYTES
                + 1
        ])
        .is_err()
    );
    assert!(Message::new(binding, MAX_SEQUENCE, MessageKind::Verification, 0, 1, b"").is_err());
    for (part, parts) in [(0, 0), (1, 1), (0, 65)] {
        assert!(Message::new(binding, 0, MessageKind::SetupRequest, part, parts, b"").is_err());
    }
    assert!(Bootstrap::decode(&"A".repeat(MAX_QR_BYTES + 1), 1000).is_err());
}

#[test]
fn maximum_fragment_round_trip_stays_within_ciphertext_bound() {
    let (bootstrap, a, b) = fixture();
    let bytes = vec![255; MAX_CHUNK_BYTES];
    let packet = Message::new(
        bootstrap.binding().unwrap(),
        3,
        MessageKind::SetupResponse,
        31,
        64,
        &bytes,
    )
    .unwrap();
    let event = a.seal(b.public_key(), &packet, 1000).unwrap();
    assert!(event.content.len() <= MAX_CIPHERTEXT_BYTES);
    assert_eq!(
        b.open(a.public_key(), &event, 1000)
            .unwrap()
            .bytes()
            .unwrap()
            .as_slice(),
        bytes
    );
}
