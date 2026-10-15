use super::*;
pub(super) fn context() -> LinkingContext {
    LinkingContext {
        version: 1,
        nonce: [1; 32],
        new_device_generation: 1,
        approver_generation: 1,
        account: [2; 32],
        exact_key_package: vec![0, 1, 255],
        key_package_reference: [3; 32],
        device_group: vec![4; 16],
        predecessor: PredecessorRoster {
            artifact_digest: None,
            epoch: 0,
            epoch_authenticator_digest: [5; 32],
            leaves: vec![PredecessorLeaf {
                leaf_index: 0,
                signature_public_key: [6; 32],
            }],
        },
        approver: [6; 32],
        recipient: [7; 32],
    }
}
async fn drain(from: &mut DeviceLinker, to: &mut DeviceLinker, now: Instant) {
    for frame in from.outgoing(now).unwrap() {
        to.receive(&frame, now).await.unwrap();
        from.acknowledge(&frame.token, now).await.unwrap();
    }
}
async fn ready(now: Instant) -> (DeviceLinker, DeviceLinker) {
    ready_with_context(context(), now).await
}
async fn ready_with_context(input: LinkingContext, now: Instant) -> (DeviceLinker, DeviceLinker) {
    let mut a = DeviceLinker::new();
    let mut b = DeviceLinker::new();
    a.begin(
        input.clone(),
        Role::NewDevice,
        input.new_device_generation,
        now,
    )
    .await
    .unwrap();
    b.begin(
        input.clone(),
        Role::Approver,
        input.approver_generation,
        now,
    )
    .await
    .unwrap();
    let ao = a.offer(now).unwrap();
    let bo = b.offer(now).unwrap();
    a.admit_peer(&bo, now).await.unwrap();
    b.admit_peer(&ao, now).await.unwrap();
    a.start_verification(now).await.unwrap();
    for _ in 0..8 {
        drain(&mut a, &mut b, now).await;
        drain(&mut b, &mut a, now).await;
    }
    assert!(a.decimals(now).unwrap().is_some());
    assert_eq!(a.decimals(now).unwrap(), b.decimals(now).unwrap());
    (a, b)
}
#[tokio::test]
async fn expired_genuine_peer_mac_is_fenced_before_sdk_input() {
    let now = Instant::now();
    let (mut a, mut b) = ready(now).await;
    a.confirm(now).await.unwrap();
    b.confirm(now).await.unwrap();
    let mac = a
        .outgoing(now)
        .unwrap()
        .into_iter()
        .find(|frame| {
            let body: Value = serde_json::from_slice(&frame.event_json).unwrap();
            body["type"] == "m.key.verification.mac"
        })
        .unwrap();
    assert!(
        matches!(
            b.receive(&mac, now + ATTEMPT_LIFETIME).await,
            Err(LinkError::Expired)
        ),
        "a valid expired peer MAC must never reach the verifier"
    );
}

#[tokio::test]
async fn per_device_confirmation_requires_verified_remote_mac_and_done() {
    let now = Instant::now();
    let (mut a, mut b) = ready(now).await;
    assert!(matches!(
        a.take_verified(now).await,
        Err(LinkError::NotReady)
    ));
    a.confirm(now).await.unwrap();
    drain(&mut a, &mut b, now).await;
    assert!(matches!(
        a.take_verified(now).await,
        Err(LinkError::NotReady)
    ));
    assert!(matches!(
        b.take_verified(now).await,
        Err(LinkError::NotReady)
    ));
    b.confirm(now).await.unwrap();
    for _ in 0..4 {
        drain(&mut b, &mut a, now).await;
        drain(&mut a, &mut b, now).await;
    }
    let verified = a.take_verified(now).await.unwrap();
    assert!(verified.owner_deadline.is_none());
    assert_eq!(verified.role, Role::NewDevice);
    assert_eq!(
        verified.context.exact_key_package,
        context().exact_key_package
    );
    assert!(b.take_verified(now).await.is_ok());
    assert!(matches!(
        a.take_verified(now).await,
        Err(LinkError::AlreadyConsumed)
    ));
}
#[tokio::test]
async fn exact_context_and_signed_key_directory_substitution_are_rejected() {
    let now = Instant::now();
    let mut a = DeviceLinker::new();
    a.begin(context(), Role::NewDevice, 1, now).await.unwrap();
    for field in 0..10 {
        let mut changed = context();
        match field {
            0 => changed.account[0] ^= 1,
            1 => changed.exact_key_package[0] ^= 1,
            2 => changed.key_package_reference[0] ^= 1,
            3 => changed.device_group[0] ^= 1,
            4 => changed.predecessor.epoch_authenticator_digest[0] ^= 1,
            5 => {
                changed.approver[0] ^= 1;
                changed.predecessor.leaves[0].signature_public_key = changed.approver;
            }
            6 => changed.recipient[0] ^= 1,
            7 => changed.nonce[0] ^= 1,
            8 => changed.new_device_generation += 1,
            _ => changed.approver_generation += 1,
        }
        let mut peer = DeviceLinker::new();
        peer.begin(
            changed.clone(),
            Role::Approver,
            changed.local_generation(Role::Approver),
            now,
        )
        .await
        .unwrap();
        assert!(matches!(
            a.admit_peer(&peer.offer(now).unwrap(), now).await,
            Err(LinkError::BindingMismatch)
        ));
    }
    let mut b = DeviceLinker::new();
    b.begin(context(), Role::Approver, 1, now).await.unwrap();
    let mut offer = b.offer(now).unwrap();
    let mut value: Value = serde_json::from_slice(&offer.keys_json).unwrap();
    let key = value["keys"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap();
    *key = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    offer.keys_json = serde_json::to_vec(&value).unwrap();
    assert!(a.admit_peer(&offer, now).await.is_err());
    assert!(matches!(
        a.start_verification(now).await,
        Err(LinkError::NotReady)
    ));
}
#[tokio::test]
async fn tampered_update_cannot_replace_previously_admitted_key_directory() {
    let now = Instant::now();
    let (mut a, mut b) = ready(now).await;
    let mut offer = b.offer(now).unwrap();
    let mut value: Value = serde_json::from_slice(&offer.keys_json).unwrap();
    let key = value["keys"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap();
    *key = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    offer.keys_json = serde_json::to_vec(&value).unwrap();
    assert!(a.admit_peer(&offer, now).await.is_err());
    assert!(matches!(
        a.take_verified(now).await,
        Err(LinkError::NotReady)
    ));
}
#[tokio::test]
async fn stale_mac_and_duplicate_events_cannot_complete_a_fresh_session() {
    let now = Instant::now();
    let (mut old, _) = ready(now).await;
    old.confirm(now).await.unwrap();
    let frame = old
        .outgoing(now)
        .unwrap()
        .into_iter()
        .find(|f| {
            let v: Value = serde_json::from_slice(&f.event_json).unwrap();
            v["type"] == "m.key.verification.mac"
        })
        .unwrap();
    let (mut fresh, mut peer) = ready(now).await;
    for _ in 0..2 {
        assert!(matches!(
            peer.receive(&frame, now).await,
            Err(LinkError::StaleFlow)
        ));
    }
    assert!(matches!(
        peer.take_verified(now).await,
        Err(LinkError::NotReady)
    ));
    fresh.confirm(now).await.unwrap();
    let current = fresh.outgoing(now).unwrap();
    for f in &current {
        peer.receive(f, now).await.unwrap();
        peer.receive(f, now).await.unwrap();
    }
    assert!(matches!(
        peer.take_verified(now).await,
        Err(LinkError::NotReady)
    ));
}
#[tokio::test]
async fn dropping_remote_mac_keeps_own_confirmation_insufficient() {
    let now = Instant::now();
    let (mut a, mut b) = ready(now).await;
    a.confirm(now).await.unwrap();
    b.confirm(now).await.unwrap();
    // Deliberately never deliver A's genuine MAC to B.
    drain(&mut b, &mut a, now).await;
    assert!(matches!(
        b.take_verified(now).await,
        Err(LinkError::NotReady)
    ));
}
#[tokio::test]
async fn corrupted_mac_terminates_the_local_attempt() {
    let now = Instant::now();
    let (mut a, mut b) = ready(now).await;
    a.confirm(now).await.unwrap();
    let mut frame = a
        .outgoing(now)
        .unwrap()
        .into_iter()
        .find(|f| {
            let v: Value = serde_json::from_slice(&f.event_json).unwrap();
            v["type"] == "m.key.verification.mac"
        })
        .unwrap();
    let mut event: Value = serde_json::from_slice(&frame.event_json).unwrap();
    *event["content"]["mac"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap() = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    frame.event_json = serde_json::to_vec(&event).unwrap();
    assert!(matches!(
        b.receive(&frame, now).await,
        Err(LinkError::Cancelled)
    ));
    assert!(matches!(
        b.take_verified(now).await,
        Err(LinkError::Cancelled)
    ));
}
#[tokio::test]
async fn cancellation_and_shutdown_fence_replays_without_reopening() {
    let now = Instant::now();
    let (mut a, mut b) = ready(now).await;
    a.cancel();
    assert!(matches!(
        a.begin(context(), Role::NewDevice, 1, now).await,
        Err(LinkError::Cancelled)
    ));
    assert!(matches!(a.confirm(now).await, Err(LinkError::Cancelled)));
    b.shutdown();
    assert!(matches!(
        b.begin(context(), Role::Approver, 1, now).await,
        Err(LinkError::Closed)
    ));
    assert!(matches!(b.take_verified(now).await, Err(LinkError::Closed)));
}
#[tokio::test]
async fn simultaneous_attempts_fence_both_nonces() {
    let now = Instant::now();
    let mut a = DeviceLinker::new();
    let first = context();
    let mut second = context();
    second.nonce[0] ^= 1;
    second.approver_generation = 2;
    a.begin(first.clone(), Role::Approver, 1, now)
        .await
        .unwrap();
    assert!(matches!(
        a.begin(second.clone(), Role::Approver, 2, now).await,
        Err(LinkError::SimultaneousRequest)
    ));
    assert!(matches!(
        a.begin(first, Role::Approver, 1, now).await,
        Err(LinkError::Cancelled)
    ));
    assert!(matches!(
        a.begin(second, Role::Approver, 2, now).await,
        Err(LinkError::Cancelled)
    ));
}
#[tokio::test]
async fn simultaneous_wire_request_is_anomaly_and_closes_current_attempt() {
    let now = Instant::now();
    let (_, mut b) = ready(now).await;
    let mut second = DeviceLinker::new();
    second
        .begin(context(), Role::NewDevice, 1, now)
        .await
        .unwrap();
    second
        .admit_peer(&b.offer(now).unwrap(), now)
        .await
        .unwrap();
    second.start_verification(now).await.unwrap();
    let request = second.outgoing(now).unwrap().remove(0);
    assert!(matches!(
        b.receive(&request, now).await,
        Err(LinkError::SimultaneousRequest)
    ));
    assert!(matches!(b.offer(now), Err(LinkError::Cancelled)));
}
#[tokio::test]
async fn frame_bounds_and_ambiguous_json_are_rejected_before_sdk_input() {
    let now = Instant::now();
    let (mut a, mut b) = ready(now).await;
    a.confirm(now).await.unwrap();
    let original = a.outgoing(now).unwrap().remove(0);
    let mut big = original.clone();
    big.event_json = vec![b' '; MAX_FRAME_BYTES + 1];
    assert!(matches!(
        b.receive(&big, now).await,
        Err(LinkError::LimitExceeded)
    ));
    let mut huge_token = original.clone();
    huge_token.token = "x".repeat(129);
    assert!(matches!(
        b.receive(&huge_token, now).await,
        Err(LinkError::LimitExceeded)
    ));
    let mut empty_token = original.clone();
    empty_token.token.clear();
    assert!(matches!(
        b.receive(&empty_token, now).await,
        Err(LinkError::InvalidFrame)
    ));
    let mut wrong = original.clone();
    wrong.binding[0] ^= 1;
    assert!(matches!(
        b.receive(&wrong, now).await,
        Err(LinkError::BindingMismatch)
    ));
    let mut ambiguous = original.clone();
    ambiguous.event_json.push(b' ');
    assert!(matches!(
        b.receive(&ambiguous, now).await,
        Err(LinkError::InvalidFrame)
    ));
    assert!(matches!(
        b.take_verified(now).await,
        Err(LinkError::NotReady)
    ));
}
#[tokio::test]
async fn exact_request_retry_cannot_extend_response_deadline() {
    let now = Instant::now();
    let mut a = DeviceLinker::new();
    let mut b = DeviceLinker::new();
    a.begin(context(), Role::NewDevice, 1, now).await.unwrap();
    b.begin(context(), Role::Approver, 1, now).await.unwrap();
    let ao = a.offer(now).unwrap();
    let bo = b.offer(now).unwrap();
    a.admit_peer(&bo, now).await.unwrap();
    b.admit_peer(&ao, now).await.unwrap();
    a.start_verification(now).await.unwrap();
    let request = a.outgoing(now).unwrap().remove(0);
    b.receive(&request, now).await.unwrap();
    b.receive(&request, now + Duration::from_secs(599))
        .await
        .unwrap();
    assert!(matches!(
        b.receive(&request, now + ATTEMPT_LIFETIME).await,
        Err(LinkError::Expired)
    ));
    assert!(matches!(
        b.receive(&request, now).await,
        Err(LinkError::Cancelled)
    ));
}

#[tokio::test]
async fn peer_claimed_generation_cannot_burn_local_reservation() {
    let now = Instant::now();
    let mut linker = DeviceLinker::new();
    let mut claimed = context();
    claimed.new_device_generation = 99;
    assert!(matches!(
        linker.begin(claimed, Role::NewDevice, 1, now).await,
        Err(LinkError::BindingMismatch)
    ));
    linker
        .begin(context(), Role::NewDevice, 1, now)
        .await
        .unwrap();
    assert!(linker.offer(now).is_ok());
}

#[tokio::test]
async fn device_linking_approver_absent_from_predecessor_cannot_expose_offer() {
    let now = Instant::now();
    let mut input = context();
    input.approver = [9; 32];
    let mut linker = DeviceLinker::new();
    assert!(matches!(
        linker.begin(input, Role::NewDevice, 1, now).await,
        Err(LinkError::InvalidContext)
    ));
    assert!(linker.offer(now).is_err());
}

#[tokio::test]
async fn device_linking_malformed_predecessor_is_rejected_before_sdk_setup() {
    let now = Instant::now();
    let mut invalid = Vec::new();
    let mut empty = context();
    empty.predecessor.leaves.clear();
    invalid.push(empty);
    let mut duplicate_index = context();
    duplicate_index.predecessor.leaves.push(PredecessorLeaf {
        leaf_index: 0,
        signature_public_key: [8; 32],
    });
    invalid.push(duplicate_index);
    let mut duplicate_key = context();
    duplicate_key.predecessor.leaves.push(PredecessorLeaf {
        leaf_index: 4,
        signature_public_key: [6; 32],
    });
    invalid.push(duplicate_key);
    let mut unsorted = context();
    unsorted.predecessor.leaves.insert(
        0,
        PredecessorLeaf {
            leaf_index: 4,
            signature_public_key: [8; 32],
        },
    );
    invalid.push(unsorted);
    let mut recipient_already_present = context();
    recipient_already_present
        .predecessor
        .leaves
        .push(PredecessorLeaf {
            leaf_index: 4,
            signature_public_key: [7; 32],
        });
    invalid.push(recipient_already_present);
    let mut full = context();
    full.predecessor.leaves = (0_u32..128)
        .map(|index| {
            let mut key = [8; 32];
            key[..4].copy_from_slice(&index.to_be_bytes());
            PredecessorLeaf {
                leaf_index: index,
                signature_public_key: key,
            }
        })
        .collect();
    full.predecessor.leaves[0].signature_public_key = full.approver;
    invalid.push(full);
    let mut overflowing_epoch = context();
    overflowing_epoch.predecessor.epoch = i64::MAX as u64;
    invalid.push(overflowing_epoch);
    for input in invalid {
        let mut linker = DeviceLinker::new();
        assert!(matches!(
            linker.begin(input, Role::NewDevice, 1, now).await,
            Err(LinkError::InvalidContext)
        ));
        assert!(linker.offer(now).is_err());
        // Invalid input must not burn the owner's reserved generation.
        linker
            .begin(context(), Role::NewDevice, 1, now)
            .await
            .unwrap();
        assert!(linker.offer(now).is_ok());
    }
}

#[tokio::test]
async fn device_linking_predecessor_epoch_and_indexed_leaves_bind_peer_offers() {
    let now = Instant::now();
    let mut input = context();
    input.predecessor.leaves.push(PredecessorLeaf {
        leaf_index: 4,
        signature_public_key: [8; 32],
    });
    let mut recipient = DeviceLinker::new();
    recipient
        .begin(input.clone(), Role::NewDevice, 1, now)
        .await
        .unwrap();
    for field in 0..4 {
        let mut substituted = input.clone();
        match field {
            0 => substituted.predecessor.epoch += 1,
            1 => substituted.predecessor.epoch_authenticator_digest[0] ^= 1,
            2 => substituted.predecessor.leaves[1].leaf_index += 1,
            _ => substituted.predecessor.leaves[1].signature_public_key[0] ^= 1,
        }
        let mut approver = DeviceLinker::new();
        approver
            .begin(substituted, Role::Approver, 1, now)
            .await
            .unwrap();
        assert!(matches!(
            recipient
                .admit_peer(&approver.offer(now).unwrap(), now)
                .await,
            Err(LinkError::BindingMismatch)
        ));
    }
}

async fn drain_wire(from: &mut DeviceLinker, to: &mut DeviceLinker, now: Instant) {
    for outgoing in from.outgoing(now).unwrap() {
        let incoming = LinkFrame::decode_wire(&outgoing.encode_wire().unwrap()).unwrap();
        to.receive(&incoming, now).await.unwrap();
        from.acknowledge(incoming.acknowledgement_token(), now)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn device_linking_wire_round_trip_completes_real_two_sided_verification() {
    let now = Instant::now();
    let mut recipient = DeviceLinker::new();
    let mut approver = DeviceLinker::new();
    recipient
        .begin(context(), Role::NewDevice, 1, now)
        .await
        .unwrap();
    approver
        .begin(context(), Role::Approver, 1, now)
        .await
        .unwrap();
    let recipient_offer =
        PeerOffer::decode_wire(&recipient.offer(now).unwrap().encode_wire().unwrap()).unwrap();
    let approver_offer =
        PeerOffer::decode_wire(&approver.offer(now).unwrap().encode_wire().unwrap()).unwrap();
    recipient.admit_peer(&approver_offer, now).await.unwrap();
    approver.admit_peer(&recipient_offer, now).await.unwrap();
    recipient.start_verification(now).await.unwrap();
    for phase in 0..2 {
        for _ in 0..8 {
            drain_wire(&mut recipient, &mut approver, now).await;
            drain_wire(&mut approver, &mut recipient, now).await;
        }
        if phase == 0 {
            assert!(recipient.decimals(now).unwrap().is_some());
            assert_eq!(
                recipient.decimals(now).unwrap(),
                approver.decimals(now).unwrap()
            );
            recipient.confirm(now).await.unwrap();
            approver.confirm(now).await.unwrap();
        }
    }
    assert!(recipient.take_verified(now).await.is_ok());
    assert!(approver.take_verified(now).await.is_ok());
}

#[tokio::test]
async fn device_linking_wire_rejects_truncation_trailing_bytes_and_cross_kind_packets() {
    let now = Instant::now();
    let mut recipient = DeviceLinker::new();
    recipient
        .begin(context(), Role::NewDevice, 1, now)
        .await
        .unwrap();
    let offer = recipient.offer(now).unwrap().encode_wire().unwrap();
    for cut in 0..offer.len() {
        assert!(PeerOffer::decode_wire(&offer[..cut]).is_err());
    }
    assert!(LinkFrame::decode_wire(&offer).is_err());
    let mut trailing = offer.clone();
    trailing.push(0);
    assert!(PeerOffer::decode_wire(&trailing).is_err());
    let mut wrong_version = offer;
    wrong_version[4] ^= 1;
    assert!(PeerOffer::decode_wire(&wrong_version).is_err());
    assert!(PeerOffer::decode_wire(&vec![0; MAX_FRAME_BYTES + 256]).is_err());

    let (mut recipient, _) = ready(now).await;
    recipient.confirm(now).await.unwrap();
    let frame = recipient
        .outgoing(now)
        .unwrap()
        .remove(0)
        .encode_wire()
        .unwrap();
    for cut in 0..frame.len() {
        assert!(LinkFrame::decode_wire(&frame[..cut]).is_err());
    }
    assert!(PeerOffer::decode_wire(&frame).is_err());
    let mut trailing = frame;
    trailing.push(0);
    assert!(LinkFrame::decode_wire(&trailing).is_err());
    assert!(LinkFrame::decode_wire(&vec![0; MAX_FRAME_BYTES + 256]).is_err());
}

#[tokio::test]
async fn device_linking_wire_never_bypasses_context_or_canonical_sdk_validation() {
    let now = Instant::now();
    let (mut recipient, mut approver) = ready(now).await;
    recipient.confirm(now).await.unwrap();
    let mut original = recipient.outgoing(now).unwrap().remove(0);
    original.binding[0] ^= 1;
    let decoded = LinkFrame::decode_wire(&original.encode_wire().unwrap()).unwrap();
    assert!(matches!(
        approver.receive(&decoded, now).await,
        Err(LinkError::BindingMismatch)
    ));
    assert!(matches!(
        approver.take_verified(now).await,
        Err(LinkError::NotReady)
    ));
    original.token.clear();
    assert!(original.encode_wire().is_err());
    original.token = "x".repeat(129);
    assert!(original.encode_wire().is_err());
    original.token = "test".into();
    original.event_json = b"{\"a\":1,\"a\":2}".to_vec();
    assert!(original.encode_wire().is_err());
    let mut offer = approver.offer(now).unwrap();
    offer.keys_json = vec![b' '; MAX_FRAME_BYTES + 1];
    assert!(offer.encode_wire().is_err());
}

fn artifact_context() -> LinkingContext {
    let mut input = context();
    input.version = 2;
    input.predecessor.epoch = 1;
    input.predecessor.leaves.push(PredecessorLeaf {
        leaf_index: 4,
        signature_public_key: [8; 32],
    });
    // Synthetic digest isolates actual SDK binding, not artifact provenance.
    input.predecessor.artifact_digest = Some([9; 32]);
    input
}

#[tokio::test]
async fn device_linking_artifact_context_same_digest_completes_real_sdk() {
    let now = Instant::now();
    let input = artifact_context();
    let (mut a, mut b) = ready_with_context(input.clone(), now).await;
    a.confirm(now).await.unwrap();
    b.confirm(now).await.unwrap();
    for _ in 0..8 {
        drain_wire(&mut a, &mut b, now).await;
        drain_wire(&mut b, &mut a, now).await;
    }
    let verified = a.take_verified(now).await.unwrap();
    assert!(verified.context.predecessor.artifact_digest == input.predecessor.artifact_digest);
    assert!(verified.context.digest().unwrap() == input.digest().unwrap());
    assert!(
        verified.owner_deadline.is_none(),
        "raw SDK metadata cannot arm runtime admission"
    );
    assert!(b.take_verified(now).await.is_ok());
    assert!(matches!(
        a.take_verified(now).await,
        Err(LinkError::AlreadyConsumed)
    ));
}

#[tokio::test]
async fn device_linking_artifact_context_substitution_rejected_before_sdk() {
    let now = Instant::now();
    let input = artifact_context();
    let mut recipient = DeviceLinker::new();
    recipient
        .begin(input.clone(), Role::NewDevice, 1, now)
        .await
        .unwrap();
    for substitution in 0..2 {
        let mut changed = input.clone();
        if substitution == 0 {
            changed.predecessor.artifact_digest.as_mut().unwrap()[0] ^= 1;
        } else {
            changed.version = 1;
            changed.predecessor.artifact_digest = None;
        }
        let mut approver = DeviceLinker::new();
        approver
            .begin(changed, Role::Approver, 1, now)
            .await
            .unwrap();
        let offer =
            PeerOffer::decode_wire(&approver.offer(now).unwrap().encode_wire().unwrap()).unwrap();
        assert!(matches!(
            recipient.admit_peer(&offer, now).await,
            Err(LinkError::BindingMismatch)
        ));
    }
    // Rejected metadata must not revoke or burn the original verifier.
    let mut exact = DeviceLinker::new();
    exact.begin(input, Role::Approver, 1, now).await.unwrap();
    assert!(
        recipient
            .admit_peer(&exact.offer(now).unwrap(), now)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn device_linking_artifact_context_version_rules_preserve_reservation() {
    let now = Instant::now();
    let mut invalid = Vec::new();
    let mut v1 = context();
    v1.predecessor.artifact_digest = Some([9; 32]);
    invalid.push(v1);
    let mut missing = artifact_context();
    missing.predecessor.artifact_digest = None;
    invalid.push(missing);
    let mut zero = artifact_context();
    zero.predecessor.artifact_digest = Some([0; 32]);
    invalid.push(zero);
    let mut singleton = artifact_context();
    singleton.predecessor.leaves.pop();
    invalid.push(singleton);
    let mut founding_epoch = artifact_context();
    founding_epoch.predecessor.epoch = 0;
    invalid.push(founding_epoch);
    for input in invalid {
        let mut linker = DeviceLinker::new();
        assert!(matches!(
            linker.begin(input, Role::NewDevice, 1, now).await,
            Err(LinkError::InvalidContext)
        ));
        assert!(linker.offer(now).is_err());
        linker
            .begin(context(), Role::NewDevice, 1, now)
            .await
            .unwrap();
        assert!(linker.offer(now).is_ok());
    }
    let legacy = serde_json::to_value(context()).unwrap();
    assert!(legacy["predecessor"].get("artifact_digest").is_none());
}
