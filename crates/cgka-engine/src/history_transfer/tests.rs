//! Real MLS/SQL plus injected fixed actor leases; not native consent or archive delivery.
use super::*;
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendResult};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
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
impl TrustedHistoryLease for Lease {
    fn validate(&self, _: &HistoryScope) -> Result<Instant, EngineError> {
        if !self.live.load(Ordering::SeqCst) || Instant::now() >= self.deadline {
            return Err(refused());
        }
        Ok(self.deadline)
    }
}
type TestEngine = Engine<SqliteAccountStorage>;
async fn fixture() -> (TestEngine, TestEngine, GroupId, GroupId) {
    let (mut a, mut b, protected) = crate::private_roster_settlement::tests::complete_pair(
        SqliteAccountStorage::in_memory().unwrap(),
    )
    .await;
    b.peeler = Box::new(crate::device_group_genesis::tests::PassthroughPeeler);
    let kp = b.fresh_key_package().await.unwrap();
    let (ordinary, result) = a
        .create_group(CreateGroupRequest {
            name: "history fixture".into(),
            description: String::new(),
            members: vec![kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { mut welcomes } = result else {
        panic!("founding Current group");
    };
    assert_eq!(b.join_welcome(welcomes.remove(0)).await.unwrap(), ordinary);
    (a, b, protected, ordinary)
}
fn channels(
    a: &TestEngine,
    b: &TestEngine,
    protected: &GroupId,
    ordinary: &GroupId,
) -> (
    OwnedHistoryChannel,
    OwnedHistoryChannel,
    Arc<Lease>,
    Arc<Lease>,
) {
    let al = Lease::new();
    let bl = Lease::new();
    let mut source = a
        .begin_history_channel(ordinary, protected, b.identity.signer.public(), al.clone())
        .unwrap();
    let request = b
        .authenticate_history_request(&source.request_packet().unwrap())
        .unwrap();
    let recipient = b.approve_history_channel(&request, bl.clone()).unwrap();
    a.bind_history_consent(&mut source, &recipient.consent_packet().unwrap())
        .unwrap();
    (source, recipient, al, bl)
}
#[tokio::test]
async fn history_channel_real_pair_encrypts_body_and_ack_with_exact_retry() {
    let (a, b, p, o) = fixture().await;
    let (mut source, mut recipient, _, _) = channels(&a, &b, &p, &o);
    let wire = a
        .seal_history_body(&mut source, b"prejoin logical record", false)
        .unwrap();
    assert_eq!(
        b.open_history_body(&recipient, &wire).unwrap(),
        b"prejoin logical record"
    );
    assert_eq!(
        a.seal_history_body(&mut source, b"prejoin logical record", false)
            .unwrap(),
        wire
    );
    assert!(
        a.seal_history_body(&mut source, b"different archive", false)
            .is_err()
    );
    let ack = b
        .seal_history_body(&mut recipient, b"committed import receipt", true)
        .unwrap();
    assert_eq!(
        a.open_history_body(&source, &ack).unwrap(),
        b"committed import receipt"
    );
    assert_eq!(
        b.seal_history_body(&mut recipient, b"committed import receipt", true)
            .unwrap(),
        ack
    );
    // An independently generated HPKE key cannot decrypt this valid authenticated inner body.
    let f = decode(&wire).unwrap();
    let wrong = a.history_keys().unwrap();
    assert!(
        a.crypto
            .hpke_open(
                config(),
                &HpkeCiphertext {
                    kem_output: f.kem.into(),
                    ciphertext: f.ciphertext.into()
                },
                &wrong.private,
                HPKE_INFO,
                &f.binding
            )
            .is_err()
    );
}
fn substitute(frame: &mut Frame, change: u8) {
    match change {
        0 => frame.account[0] ^= 1,
        1 => frame.protected[0] ^= 1,
        2 => frame.protected_epoch += 1,
        3 => frame.protected_authenticator[0] ^= 1,
        4 => frame.roster[0] ^= 1,
        5 => frame.ordinary[0] ^= 1,
        6 => frame.ordinary_epoch += 1,
        7 => frame.ordinary_authenticator[0] ^= 1,
        8 => frame.source[0] ^= 1,
        9 => frame.recipient[0] ^= 1,
        10 => frame.transfer[0] ^= 1,
        _ => frame.binding[0] ^= 1,
    }
}
#[tokio::test]
async fn history_channel_fixed_context_rejects_every_substitution() {
    let (a, b, p, o) = fixture().await;
    for change in 0..12 {
        // One exact UNBOUND original per case: no unrelated transfer or prior
        // consent immutability can mask the context check under test.
        let mut source = a
            .begin_history_channel(&o, &p, b.identity.signer.public(), Lease::new())
            .unwrap();
        let request = b
            .authenticate_history_request(&source.request_packet().unwrap())
            .unwrap();
        let recipient = b.approve_history_channel(&request, Lease::new()).unwrap();
        let original = recipient.consent_packet().unwrap();
        let mut f = decode(&original).unwrap();
        f.signature.clear();
        substitute(&mut f, change);
        assert!(
            a.bind_history_consent(&mut source, &b.history_sign(f).unwrap())
                .is_err()
        );
        assert!(source.consent.is_none());
        a.bind_history_consent(&mut source, &original).unwrap();
        let body = a.seal_history_body(&mut source, b"archive", false).unwrap();
        let mut f = decode(&body).unwrap();
        f.signature.clear();
        substitute(&mut f, change);
        assert!(
            b.open_history_body(&recipient, &a.history_sign(f).unwrap())
                .is_err()
        );
        assert_eq!(b.open_history_body(&recipient, &body).unwrap(), b"archive");
    }
    // Canonical bad signatures, truncation and complete-frame bounds refuse
    // without consuming the same legitimate original consent.
    let mut source = a
        .begin_history_channel(&o, &p, b.identity.signer.public(), Lease::new())
        .unwrap();
    let request = b
        .authenticate_history_request(&source.request_packet().unwrap())
        .unwrap();
    let recipient = b.approve_history_channel(&request, Lease::new()).unwrap();
    let original = recipient.consent_packet().unwrap();
    let mut f = decode(&original).unwrap();
    f.signature[0] ^= 1;
    for wire in [
        encode(&f).unwrap(),
        original[..original.len() - 1].to_vec(),
        vec![0; MAX_HISTORY_CONTROL_BYTES + 1],
    ] {
        assert!(a.bind_history_consent(&mut source, &wire).is_err());
        assert!(source.consent.is_none());
    }
    a.bind_history_consent(&mut source, &original).unwrap();
}
#[tokio::test]
async fn history_channel_cross_transfer_consent_and_signed_generation_are_refused() {
    let (a, b, p, o) = fixture().await;
    let (mut source, recipient, _, _) = channels(&a, &b, &p, &o);
    let (other, other_recipient, _, _) = channels(&a, &b, &p, &o);
    assert!(
        a.bind_history_consent(&mut source, &other_recipient.consent_packet().unwrap())
            .is_err()
    );
    let wire = a.seal_history_body(&mut source, b"archive", false).unwrap();
    assert!(b.open_history_body(&other_recipient, &wire).is_err());
    let mut f = decode(&wire).unwrap();
    f.signature.clear();
    f.source_generation += 1;
    assert!(
        b.open_history_body(&recipient, &a.history_sign(f).unwrap())
            .is_err()
    );
    assert_ne!(source.scope().transfer, other.scope().transfer);
}
#[tokio::test]
async fn history_channel_cancel_expiry_retirement_and_engine_teardown_are_negative() {
    let (a, b, p, o) = fixture().await;
    let (mut source, recipient, al, bl) = channels(&a, &b, &p, &o);
    al.live.store(false, Ordering::SeqCst);
    assert!(source.request_packet().is_err());
    assert!(a.seal_history_body(&mut source, b"archive", false).is_err());
    bl.live.store(false, Ordering::SeqCst);
    assert!(recipient.consent_packet().is_err());
    let expired = Arc::new(Lease {
        deadline: Instant::now() - Duration::from_secs(1),
        live: AtomicBool::new(true),
    });
    assert!(
        a.begin_history_channel(&o, &p, b.identity.signer.public(), expired)
            .is_err()
    );
    let (mut source, recipient, _, _) = channels(&a, &b, &p, &o);
    source.retire();
    assert!(source.keys.is_none());
    assert!(source.request_packet().is_err());
    let (source, _, _, _) = channels(&a, &b, &p, &o);
    drop(a);
    assert!(source.request_packet().is_err());
    assert!(b.history_channel_fresh(&source).is_err());
    drop(b);
    assert!(recipient.consent_packet().is_err());
}
#[tokio::test]
async fn history_channel_fresh_ordinary_epoch_and_local_completed_generation_are_required() {
    let (mut a, b, p, o) = fixture().await;
    let (mut source, _, _, _) = channels(&a, &b, &p, &o);
    let SendResult::GroupEvolution { pending, .. } =
        a.do_send_self_update(o.clone()).await.unwrap()
    else {
        panic!("actual ordinary update")
    };
    a.confirm_published(pending).await.unwrap();
    assert!(a.seal_history_body(&mut source, b"archive", false).is_err());
    let (a, b, p, o) = fixture().await;
    let (mut source, _, _, _) = channels(&a, &b, &p, &o);
    a.select_private_roster_settlement(&p).unwrap();
    assert!(a.seal_history_body(&mut source, b"archive", false).is_err());
}
