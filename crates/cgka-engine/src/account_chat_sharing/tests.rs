//! Actual independently stored paired MLS trees; injected actor leases are not UI consent.
use super::*;
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
    for field in 0..9 {
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
