//! Actual independently stored paired MLS trees; injected actor leases are not UI consent.
use super::*;
use cgka_traits::engine::{CgkaEngine, GroupEvent};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use storage_sqlite::SqliteAccountStorage;

struct Lease {
    deadline: Instant,
    live: AtomicBool,
}
impl Lease {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            deadline: Instant::now() + Duration::from_secs(60),
            live: AtomicBool::new(true),
        })
    }
}
impl TrustedAccountSharingLease for Lease {
    fn approved_policy_id(&self, scope: &AccountSharingScope) -> Result<[u8; 32], EngineError> {
        // Fixture's explicit approval ID is fixed independently of new channel
        // nonces/keys. Production actors must check their durable approval.
        let mut digest = Sha256::new();
        digest.update(b"fixture explicit approval");
        digest.update(scope.protected.account.as_slice());
        digest.update(scope.protected.group_id.as_slice());
        digest.update(&scope.source);
        digest.update(&scope.recipient);
        Ok(digest.finalize().into())
    }
    fn validate(&self, _: &AccountSharingScope) -> Result<Instant, EngineError> {
        if !self.live.load(Ordering::SeqCst) {
            return Err(refused());
        }
        Ok(self.deadline)
    }
}
type TestEngine = Engine<SqliteAccountStorage>;
fn channels(
    a: &TestEngine,
    b: &TestEngine,
    protected: &GroupId,
) -> (
    OwnedAccountSharingChannel,
    OwnedAccountSharingChannel,
    Arc<Lease>,
    Arc<Lease>,
) {
    let al = Lease::new();
    let bl = Lease::new();
    let mut source = a
        .begin_account_sharing_policy(protected, b.identity.signer.public(), al.clone())
        .unwrap();
    let request = b
        .authenticate_account_sharing_request(&source.request_packet().unwrap())
        .unwrap();
    let recipient = b
        .approve_account_sharing_policy(&request, bl.clone())
        .unwrap();
    a.bind_account_sharing_consent(&mut source, &recipient.consent_packet().unwrap())
        .unwrap();
    (source, recipient, al, bl)
}

#[tokio::test]
async fn account_sharing_original_policy_encrypts_both_directions_without_ordinary_membership() {
    let (a, b, protected) = crate::private_roster_settlement::tests::complete_pair(
        SqliteAccountStorage::in_memory().unwrap(),
    )
    .await;
    let (mut source, mut recipient, _, _) = channels(&a, &b, &protected);
    assert_eq!(
        source.policy_digest().unwrap(),
        recipient.policy_digest().unwrap()
    );
    let (renewed_source, renewed_recipient, _, _) = channels(&a, &b, &protected);
    assert_eq!(
        source.scope.approved_policy_identity,
        renewed_source.scope.approved_policy_identity
    );
    assert_ne!(
        source.policy_digest().unwrap(),
        renewed_source.policy_digest().unwrap()
    );
    let body = vec![0x61; MAX_ACCOUNT_SHARED_BODY_BYTES];
    let wire = a
        .seal_account_shared_body(&mut source, AccountSharedBodyKind::Catalog, 0, &body)
        .unwrap();
    assert!(wire.len() <= MAX_WIRE_BYTES);
    assert_eq!(
        b.open_account_shared_body(&recipient, &wire).unwrap(),
        (AccountSharedBodyKind::Catalog, 0, body.clone())
    );
    assert_eq!(
        a.seal_account_shared_body(&mut source, AccountSharedBodyKind::Catalog, 0, &body)
            .unwrap(),
        wire
    );
    assert!(
        a.seal_account_shared_body(&mut source, AccountSharedBodyKind::Records, 0, &body)
            .is_err()
    );
    assert!(
        a.seal_account_shared_body(&mut source, AccountSharedBodyKind::Catalog, 0, b"different")
            .is_err()
    );
    let intent = b
        .seal_account_shared_body(
            &mut recipient,
            AccountSharedBodyKind::SendIntent,
            0,
            b"intent",
        )
        .unwrap();
    assert_eq!(
        a.open_account_shared_body(&source, &intent).unwrap(),
        (AccountSharedBodyKind::SendIntent, 0, b"intent".to_vec())
    );
    assert!(a.open_account_shared_body(&source, &wire).is_err());
    assert!(
        b.open_account_shared_body(&renewed_recipient, &wire)
            .is_err()
    );
    assert!(
        b.seal_account_shared_body(
            &mut recipient,
            AccountSharedBodyKind::SendIntent,
            1,
            &vec![0; MAX_ACCOUNT_SHARED_BODY_BYTES + 1]
        )
        .is_err()
    );
}

#[tokio::test]
async fn account_sharing_exact_unbound_consent_rejects_signed_context_substitution() {
    let (a, b, protected) = crate::private_roster_settlement::tests::complete_pair(
        SqliteAccountStorage::in_memory().unwrap(),
    )
    .await;
    // Every mutation uses its own unbound original and its exact valid consent.
    // A different nonce/transfer cannot mask the specific context assertion.
    for field in 0..11 {
        let mut source = a
            .begin_account_sharing_policy(&protected, b.identity.signer.public(), Lease::new())
            .unwrap();
        let request = b
            .authenticate_account_sharing_request(&source.request_packet().unwrap())
            .unwrap();
        let recipient = b
            .approve_account_sharing_policy(&request, Lease::new())
            .unwrap();
        let valid = recipient.consent_packet().unwrap();
        let mut altered = decode(&valid).unwrap();
        altered.signature.clear();
        match field {
            0 => altered.account[0] ^= 1,
            1 => altered.protected[0] ^= 1,
            2 => altered.epoch += 1,
            3 => altered.authenticator[0] ^= 1,
            4 => altered.roster[0] ^= 1,
            5 => altered.source[0] ^= 1,
            6 => altered.recipient[0] ^= 1,
            7 => altered.nonce[0] ^= 1,
            8 => altered.binding[0] ^= 1,
            9 => altered.approved_policy_identity[0] ^= 1,
            10 => altered.approval_id[0] ^= 1,
            _ => unreachable!(),
        }
        let wrong = b.sharing_sign(altered).unwrap();
        assert!(
            a.bind_account_sharing_consent(&mut source, &wrong).is_err(),
            "context field {field}"
        );
        a.bind_account_sharing_consent(&mut source, &valid).unwrap();
        a.bind_account_sharing_consent(&mut source, &valid).unwrap();
    }
}

#[tokio::test]
async fn account_sharing_original_cancel_expiry_retirement_and_engine_custody_refuse() {
    let (a, b, protected) = crate::private_roster_settlement::tests::complete_pair(
        SqliteAccountStorage::in_memory().unwrap(),
    )
    .await;
    let (mut source, recipient, al, bl) = channels(&a, &b, &protected);
    let wire = a
        .seal_account_shared_body(&mut source, AccountSharedBodyKind::Records, 1, b"record")
        .unwrap();
    bl.live.store(false, Ordering::SeqCst);
    assert!(b.open_account_shared_body(&recipient, &wire).is_err());
    al.live.store(false, Ordering::SeqCst);
    assert!(source.request_packet().is_err());
    assert!(
        a.seal_account_shared_body(&mut source, AccountSharedBodyKind::Records, 2, b"record")
            .is_err()
    );
    let expired = Arc::new(Lease {
        deadline: Instant::now() - Duration::from_secs(1),
        live: AtomicBool::new(true),
    });
    assert!(
        a.begin_account_sharing_policy(&protected, b.identity.signer.public(), expired)
            .is_err()
    );
    let (mut source, _, _, _) = channels(&a, &b, &protected);
    source.retire();
    assert!(source.keys.is_none());
    assert!(source.request_packet().is_err());
    let (source, _, _, _) = channels(&a, &b, &protected);
    drop(a);
    assert!(source.request_packet().is_err());
    assert!(b.authenticate_account_sharing_request(&wire).is_err());
}

fn received(engine: &mut TestEngine, protected: &GroupId) -> Vec<u8> {
    let (payload, proof) = engine
        .drain_events()
        .into_iter()
        .find_map(|event| match event {
            GroupEvent::MessageReceived {
                group_id,
                source_leaf: Some(proof),
                payload,
                ..
            } if &group_id == protected => Some((payload, proof)),
            _ => None,
        })
        .expect("actual protected MLS application and indexed sender proof");
    let event = cgka_traits::app_event::MarmotAppEvent::decode(&payload).unwrap();
    assert_eq!(event.kind, ACCOUNT_SHARING_CONTROL_KIND);
    let metadata = engine
        .authenticate_received_account_sharing_control(protected, &proof, event.content.as_bytes())
        .unwrap();
    assert_eq!(metadata.signer, proof.signature_public_key);
    let mut wrong = proof.clone();
    wrong.leaf_index += 1;
    assert!(
        engine
            .authenticate_received_account_sharing_control(
                protected,
                &wrong,
                event.content.as_bytes()
            )
            .is_err()
    );
    event.content.into_bytes()
}

#[tokio::test]
async fn account_sharing_carrier_reaches_actual_protected_leaf_and_retains_ciphertext() {
    let (mut a, mut b, protected) = crate::private_roster_settlement::tests::complete_pair(
        SqliteAccountStorage::in_memory().unwrap(),
    )
    .await;
    a.drain_events();
    b.drain_events();
    let mut source = a
        .begin_account_sharing_policy(&protected, b.identity.signer.public(), Lease::new())
        .unwrap();
    let message = a
        .wrap_account_sharing_control(&mut source, AccountSharingControl::Request)
        .await
        .unwrap();
    let retry = a
        .wrap_account_sharing_control(&mut source, AccountSharingControl::Request)
        .await
        .unwrap();
    assert_eq!(message.id, retry.id);
    assert_eq!(message.payload, retry.payload);
    b.ingest(message).await.unwrap();
    let request_wire = received(&mut b, &protected);
    let request = b
        .authenticate_account_sharing_request(&request_wire)
        .unwrap();
    let mut recipient = b
        .approve_account_sharing_policy(&request, Lease::new())
        .unwrap();
    let message = b
        .wrap_account_sharing_control(&mut recipient, AccountSharingControl::Consent)
        .await
        .unwrap();
    a.ingest(message).await.unwrap();
    let consent = received(&mut a, &protected);
    a.bind_account_sharing_consent(&mut source, &consent)
        .unwrap();
    let body = vec![0x61; MAX_ACCOUNT_SHARED_BODY_BYTES];
    a.seal_account_shared_body(&mut source, AccountSharedBodyKind::Catalog, 0, &body)
        .unwrap();
    let message = a
        .wrap_account_sharing_control(&mut source, AccountSharingControl::Body(0))
        .await
        .unwrap();
    assert!(message.payload.len() <= MAX_WIRE_BYTES); // Passthrough fixture only; production Nostr bound still pending.
    b.ingest(message).await.unwrap();
    let wire = received(&mut b, &protected);
    assert_eq!(
        b.open_account_shared_body(&recipient, &wire).unwrap(),
        (AccountSharedBodyKind::Catalog, 0, body)
    );
    a.select_private_roster_settlement(&protected).unwrap();
    assert!(
        a.wrap_account_sharing_control(&mut source, AccountSharingControl::Body(0))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn account_sharing_peer_generation_uses_authenticated_role_and_live_original() {
    use cgka_traits::engine::SendResult;
    let (mut a, mut b, protected) = crate::private_roster_settlement::tests::complete_pair(
        SqliteAccountStorage::in_memory().unwrap(),
    )
    .await;
    // Genuine independent reselections deliberately produce different local
    // counters, then a real encrypted Challenge/ACK completes both rosters.
    a.select_private_roster_settlement(&protected).unwrap();
    a.select_private_roster_settlement(&protected).unwrap();
    b.select_private_roster_settlement(&protected).unwrap();
    let SendResult::ApplicationMessage { msg: challenge, .. } =
        a.start_private_roster_settlement(&protected).await.unwrap()
    else {
        panic!("real encrypted challenge required")
    };
    b.ingest(challenge).await.unwrap();
    let SendResult::ApplicationMessage { msg: ack, .. } =
        b.prepare_private_roster_ack(&protected).await.unwrap()
    else {
        panic!("real encrypted ACK required")
    };
    a.ingest(ack).await.unwrap();
    let a_generation = a
        .validated_settled_device_roster(&protected)
        .unwrap()
        .unwrap()
        .settlement_generation();
    let b_generation = b
        .validated_settled_device_roster(&protected)
        .unwrap()
        .unwrap()
        .settlement_generation();
    assert_ne!(a_generation, b_generation);

    let al = Lease::new();
    let bl = Lease::new();
    let mut source = a
        .begin_account_sharing_policy(&protected, b.identity.signer.public(), al)
        .unwrap();
    assert!(source.authenticated_peer_generation().is_err());
    let request = b
        .authenticate_account_sharing_request(&source.request_packet().unwrap())
        .unwrap();
    let recipient = b
        .approve_account_sharing_policy(&request, bl.clone())
        .unwrap();
    assert_eq!(
        recipient.authenticated_peer_generation().unwrap(),
        a_generation
    );
    assert_ne!(
        recipient.authenticated_peer_generation().unwrap(),
        recipient.scope().local_generation
    );
    a.bind_account_sharing_consent(&mut source, &recipient.consent_packet().unwrap())
        .unwrap();
    assert_eq!(
        source.authenticated_peer_generation().unwrap(),
        b_generation
    );
    assert_ne!(
        source.authenticated_peer_generation().unwrap(),
        source.scope().local_generation
    );
    bl.live.store(false, Ordering::SeqCst);
    assert!(recipient.authenticated_peer_generation().is_err());
    source.retire();
    assert!(source.authenticated_peer_generation().is_err());

    // Complete the real handshake within the normal fixture lease. A 200ms
    // lease made this an assertion about setup throughput on loaded runners,
    // rather than rejection after an authenticated original actually expires.
    let expiry = Lease::new();
    let mut expiring = a
        .begin_account_sharing_policy(&protected, b.identity.signer.public(), expiry)
        .unwrap();
    let request = b
        .authenticate_account_sharing_request(&expiring.request_packet().unwrap())
        .unwrap();
    let consent = b
        .approve_account_sharing_policy(&request, Lease::new())
        .unwrap();
    a.bind_account_sharing_consent(&mut expiring, &consent.consent_packet().unwrap())
        .unwrap();
    assert_eq!(
        expiring.authenticated_peer_generation().unwrap(),
        b_generation
    );
    tokio::time::sleep(
        expiring
            .original_deadline()
            .saturating_duration_since(Instant::now())
            + Duration::from_millis(10),
    )
    .await;
    assert!(expiring.authenticated_peer_generation().is_err());

    let (owned, _, _, _) = channels(&a, &b, &protected);
    drop(a);
    assert!(owned.authenticated_peer_generation().is_err());
}
