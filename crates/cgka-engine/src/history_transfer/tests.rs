//! Real MLS/SQL plus injected fixed actor leases; not native consent or archive delivery.
use super::*;
use cgka_traits::GroupStorage;
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
async fn account_chat_catalog_discovers_actual_nonadmin_membership_without_grant() {
    let (mut a, b, protected, ordinary) = fixture().await;
    // Same-account siblings share account administrator identity. A separate
    // account must create the incoming chat to exercise actual non-admin scope.
    let mut d = crate::device_group_genesis::tests::current_test_engine_with_key(
        SqliteAccountStorage::in_memory().unwrap(),
        k256::schnorr::SigningKey::random(&mut rand::thread_rng()),
    );
    let package = a.fresh_key_package().await.unwrap();
    let (incoming, result) = d
        .create_group(CreateGroupRequest {
            name: "incoming fixture".into(),
            description: String::new(),
            members: vec![package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { mut welcomes } = result else {
        panic!("actual incoming group")
    };
    assert_eq!(a.join_welcome(welcomes.remove(0)).await.unwrap(), incoming);
    let before = b.storage.list_group_records().unwrap();
    let source = a.account_chat_catalog(&protected, None, 128).unwrap();
    let recipient = b.account_chat_catalog(&protected, None, 128).unwrap();
    assert_eq!(source.entries.len(), 2);
    assert_eq!(recipient.entries.len(), 1);
    assert_eq!(recipient.entries[0].group_id, ordinary);
    let own = source
        .entries
        .iter()
        .find(|entry| entry.group_id == ordinary)
        .unwrap();
    let nonadmin = source
        .entries
        .iter()
        .find(|entry| entry.group_id == incoming)
        .unwrap();
    assert!(own.local_is_admin);
    assert!(!nonadmin.local_is_admin);
    assert!(recipient.entries[0].local_is_admin);
    assert_ne!(own.local_leaf_index, recipient.entries[0].local_leaf_index);
    assert_eq!(recipient.protected.account, b.self_id());
    assert_eq!(before, b.storage.list_group_records().unwrap());
    assert!(b.account_chat_catalog(&ordinary, None, 128).is_err());
    assert!(b.account_chat_catalog(&protected, None, 0).is_err());
    assert!(b.account_chat_catalog(&protected, None, 129).is_err());
    assert!(
        b.account_chat_catalog(&protected, Some(&GroupId::new(vec![])), 1)
            .is_err()
    );
    assert!(d.account_chat_catalog(&protected, None, 1).is_err());
    let unpaired = crate::device_group_genesis::tests::current_test_engine(
        SqliteAccountStorage::in_memory().unwrap(),
    );
    assert!(unpaired.account_chat_catalog(&protected, None, 1).is_err());

    let removal = d
        .send(cgka_traits::SendIntent::RemoveMembers {
            group_id: incoming.clone(),
            members: vec![a.self_id()],
        })
        .await
        .unwrap();
    let SendResult::GroupEvolution { msg, pending, .. } = removal else {
        panic!("actual removal commit")
    };
    d.confirm_published(pending).await.unwrap();
    a.ingest(msg).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !a.group_record(&incoming).unwrap().removed {
            a.advance_convergence(&incoming).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("actual received removal must become canonical");
    assert!(
        a.account_chat_catalog(&protected, None, 128)
            .unwrap()
            .entries
            .iter()
            .all(|entry| entry.group_id != incoming)
    );
    let journal = a
        .account_chat_catalog_journal(&protected, None, 128)
        .unwrap();
    assert!(journal.entries.iter().any(|entry| matches!(entry,
        crate::account_chat_catalog::AccountChatCatalogObservation::Withdrawn {
            group_id, disbanded: false, ..
        } if group_id == &incoming)));
    assert!(journal.entries.iter().any(|entry| matches!(entry,
        crate::account_chat_catalog::AccountChatCatalogObservation::Active(entry)
        if entry.group_id == ordinary)));
    assert!(a.account_chat_catalog_journal(&protected, None, 0).is_err());
    assert!(
        a.account_chat_catalog_journal(&protected, None, 129)
            .is_err()
    );
    assert!(d.account_chat_catalog_journal(&protected, None, 1).is_err());
    // A retained identical tree does not replace a fresh Completed round.
    a.select_private_roster_settlement(&protected).unwrap();
    assert!(a.account_chat_catalog(&protected, None, 128).is_err());
    assert!(
        a.account_chat_catalog_journal(&protected, None, 128)
            .is_err()
    );
}

#[tokio::test]
async fn account_chat_catalog_pages_same_title_chats_by_canonical_identity() {
    let (mut a, mut b, protected, first) = fixture().await;
    let kp = b.fresh_key_package().await.unwrap();
    let (second, result) = a
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
        panic!("ordinary founding group")
    };
    assert_eq!(b.join_welcome(welcomes.remove(0)).await.unwrap(), second);
    assert_ne!(first, second);
    let page = b.account_chat_catalog(&protected, None, 1).unwrap();
    assert_eq!(page.entries.len(), 1);
    let next = b
        .account_chat_catalog(&protected, Some(&page.entries[0].group_id), 1)
        .unwrap();
    assert_eq!(next.entries.len(), 1);
    assert_ne!(page.entries[0].group_id, next.entries[0].group_id);
    assert!(page.entries[0].group_id.as_slice() < next.entries[0].group_id.as_slice());
    assert!(
        b.account_chat_catalog(&protected, Some(&next.entries[0].group_id), 1)
            .unwrap()
            .entries
            .is_empty()
    );
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

fn received_history(engine: &mut TestEngine, protected: &GroupId) -> Vec<u8> {
    use cgka_traits::app_event::MarmotAppEvent;
    use cgka_traits::engine::GroupEvent;
    let (payload, proof) = engine
        .drain_events()
        .into_iter()
        .find_map(|e| match e {
            GroupEvent::MessageReceived {
                group_id,
                source_leaf: Some(proof),
                payload,
                ..
            } if &group_id == protected => Some((payload, proof)),
            _ => None,
        })
        .expect("actual protected member application source");
    let event = MarmotAppEvent::decode(&payload).unwrap();
    assert_eq!(event.kind, HISTORY_CONTROL_KIND);
    let metadata = engine
        .authenticate_received_history_control(protected, &proof, event.content.as_bytes())
        .unwrap();
    assert_eq!(metadata.signer, proof.signature_public_key);
    let mut foreign = proof.clone();
    foreign.epoch.0 += 1;
    assert!(
        engine
            .authenticate_received_history_control(protected, &foreign, event.content.as_bytes())
            .is_err()
    );
    event.content.into_bytes()
}
async fn wrap_retry(
    engine: &mut TestEngine,
    channel: &mut OwnedHistoryChannel,
    kind: HistoryControl,
) -> cgka_traits::TransportMessage {
    let wire = engine
        .wrap_history_control(channel, kind)
        .await
        .expect("same original history request must wrap real protected MLS control");
    let retry = engine.wrap_history_control(channel, kind).await.unwrap();
    assert_eq!(wire.id, retry.id);
    assert_eq!(wire.payload, retry.payload);
    wire
}
#[tokio::test]
async fn history_channel_original_control_reaches_actual_mls_member_source() {
    let (mut a, mut b, p, o) = fixture().await;
    let al = Lease::new();
    let bl = Lease::new();
    let mut source = a
        .begin_history_channel(&o, &p, b.identity.signer.public(), al.clone())
        .unwrap();
    a.drain_events();
    b.drain_events();
    let wire = wrap_retry(&mut a, &mut source, HistoryControl::Request).await;
    b.ingest(wire).await.unwrap();
    let request_wire = received_history(&mut b, &p);
    let request = b.authenticate_history_request(&request_wire).unwrap();
    assert!(request.scope().protected == source.scope().protected);
    assert_eq!(request.scope().transfer, source.scope().transfer);
    let mut recipient = b.approve_history_channel(&request, bl).unwrap();
    assert!(
        b.wrap_history_control(&mut recipient, HistoryControl::Request)
            .await
            .is_err()
    );
    let consent = wrap_retry(&mut b, &mut recipient, HistoryControl::Consent).await;
    a.ingest(consent).await.unwrap();
    let consent_wire = received_history(&mut a, &p);
    a.bind_history_consent(&mut source, &consent_wire).unwrap();
    a.seal_history_body(&mut source, b"prejoin record bytes", false)
        .unwrap();
    let archive = wrap_retry(&mut a, &mut source, HistoryControl::Archive).await;
    b.ingest(archive).await.unwrap();
    let archive_wire = received_history(&mut b, &p);
    assert_eq!(
        b.open_history_body(&recipient, &archive_wire).unwrap(),
        b"prejoin record bytes"
    );
    b.seal_history_body(&mut recipient, b"receipt bytes", true)
        .unwrap();
    let ack = wrap_retry(&mut b, &mut recipient, HistoryControl::Acknowledgement).await;
    a.ingest(ack).await.unwrap();
    let ack_wire = received_history(&mut a, &p);
    assert_eq!(
        a.open_history_body(&source, &ack_wire).unwrap(),
        b"receipt bytes"
    );
    assert_eq!(source.outbound.len(), 2);
    assert_eq!(recipient.outbound.len(), 2);
    al.live.store(false, Ordering::SeqCst);
    assert!(
        a.wrap_history_control(&mut source, HistoryControl::Archive)
            .await
            .is_err()
    );
}

struct ControlledWrapPeeler {
    fail_once: AtomicBool,
    stall: bool,
    entered: Arc<AtomicBool>,
    inputs: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}
#[async_trait::async_trait]
impl cgka_traits::peeler::TransportPeeler for ControlledWrapPeeler {
    async fn peel_group_message(
        &self,
        msg: &cgka_traits::TransportMessage,
        context: &cgka_traits::group_context::GroupContextSnapshot,
    ) -> Result<cgka_traits::ingest::PeeledMessage, cgka_traits::error::PeelerError> {
        crate::device_group_genesis::tests::PassthroughPeeler
            .peel_group_message(msg, context)
            .await
    }
    async fn peel_welcome(
        &self,
        msg: &cgka_traits::TransportMessage,
    ) -> Result<cgka_traits::ingest::PeeledMessage, cgka_traits::error::PeelerError> {
        crate::device_group_genesis::tests::PassthroughPeeler
            .peel_welcome(msg)
            .await
    }
    async fn wrap_welcome(
        &self,
        payload: &cgka_traits::EncryptedPayload,
        recipient: &cgka_traits::MemberId,
    ) -> Result<cgka_traits::TransportMessage, cgka_traits::error::PeelerError> {
        crate::device_group_genesis::tests::PassthroughPeeler
            .wrap_welcome(payload, recipient)
            .await
    }
    async fn wrap_group_message(
        &self,
        payload: &cgka_traits::EncryptedPayload,
        context: &cgka_traits::group_context::GroupContextSnapshot,
    ) -> Result<cgka_traits::TransportMessage, cgka_traits::error::PeelerError> {
        self.entered.store(true, Ordering::SeqCst);
        self.inputs.lock().unwrap().push(payload.ciphertext.clone());
        if self.stall {
            return std::future::pending().await;
        }
        if self.fail_once.swap(false, Ordering::SeqCst) {
            return Err(cgka_traits::error::PeelerError::WrapFailed(
                "isolated first wrap failure".into(),
            ));
        }
        crate::device_group_genesis::tests::PassthroughPeeler
            .wrap_group_message(payload, context)
            .await
    }
}
#[tokio::test]
async fn history_channel_failed_wrap_retries_the_same_real_ratchet_ciphertext() {
    let (mut a, mut b, p, o) = fixture().await;
    let inputs = Arc::new(std::sync::Mutex::new(Vec::new()));
    a.peeler = Box::new(ControlledWrapPeeler {
        fail_once: AtomicBool::new(true),
        stall: false,
        entered: Arc::new(AtomicBool::new(false)),
        inputs: inputs.clone(),
    });
    let mut channel = a
        .begin_history_channel(&o, &p, b.identity.signer.public(), Lease::new())
        .unwrap();
    assert!(matches!(
        a.wrap_history_control(&mut channel, HistoryControl::Request)
            .await,
        Err(EngineError::Peeler(_))
    ));
    assert_eq!(channel.outbound.len(), 1);
    let wire = a
        .wrap_history_control(&mut channel, HistoryControl::Request)
        .await
        .unwrap();
    {
        let held = inputs.lock().unwrap();
        assert_eq!(held.len(), 2);
        assert_eq!(held[0], held[1]);
    }
    b.drain_events();
    b.ingest(wire).await.unwrap();
    let wire = received_history(&mut b, &p);
    b.authenticate_history_request(&wire).unwrap();
}
#[tokio::test]
async fn history_channel_original_fixed_expiry_ends_a_real_pending_wrap() {
    let (mut a, b, p, o) = fixture().await;
    let entered = Arc::new(AtomicBool::new(false));
    a.peeler = Box::new(ControlledWrapPeeler {
        fail_once: AtomicBool::new(false),
        stall: true,
        entered: entered.clone(),
        inputs: Arc::new(std::sync::Mutex::new(Vec::new())),
    });
    // Isolated injected Core actor policy, not a production SDK clock override.
    let deadline = Instant::now() + Duration::from_millis(300);
    let lease = Arc::new(Lease {
        deadline,
        live: AtomicBool::new(true),
    });
    let mut channel = a
        .begin_history_channel(&o, &p, b.identity.signer.public(), lease)
        .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            a.wrap_history_control(&mut channel, HistoryControl::Request)
        )
        .await
        .unwrap()
        .is_err()
    );
    assert!(entered.load(Ordering::SeqCst));
    assert_eq!(channel.original_deadline(), deadline);
    a.peeler = Box::new(crate::device_group_genesis::tests::PassthroughPeeler);
    assert!(
        a.wrap_history_control(&mut channel, HistoryControl::Request)
            .await
            .is_err()
    );
    assert!(channel.request_packet().is_err());
    channel.retire();
    assert!(channel.keys.is_none());
    assert!(channel.outbound.is_empty());
}

#[tokio::test]
async fn history_channel_ordered_chunks_hold_one_original_and_actual_maximum_frame() {
    let (mut a, mut b, p, o) = fixture().await;
    let (mut source, mut recipient, _, bl) = channels(&a, &b, &p, &o);
    let manifest: [u8; 32] = Sha256::digest(b"immutable original archive manifest").into();
    let first = vec![255; MAX_HISTORY_CHUNK_BYTES];
    let sealed = a
        .seal_history_chunk(&mut source, manifest, 0, &first, false)
        .expect("same original consent must authorize bounded indexed first chunk");
    assert_eq!(
        a.seal_history_chunk(&mut source, manifest, 0, &first, false)
            .unwrap(),
        sealed
    );
    assert!(
        a.seal_history_chunk(&mut source, manifest, 0, b"changed body", false)
            .is_err()
    );
    assert!(
        a.seal_history_chunk(&mut source, manifest, 1, b"before receipt", false)
            .is_err()
    );
    assert!(
        b.seal_history_chunk(&mut recipient, manifest, 0, b"before open", true)
            .is_err()
    );
    let wrapped = a
        .wrap_history_control(&mut source, HistoryControl::Chunk(0))
        .await
        .unwrap();
    assert!(wrapped.payload.len() <= MAX_HISTORY_CONTROL_BYTES);
    assert_eq!(
        a.wrap_history_control(&mut source, HistoryControl::Chunk(0))
            .await
            .unwrap()
            .payload,
        wrapped.payload
    );
    b.drain_events();
    b.ingest(wrapped).await.unwrap();
    let frame = received_history(&mut b, &p);
    let opened = b.open_history_chunk(&mut recipient, &frame).unwrap();
    assert_eq!(opened.ordinal, 0);
    assert_eq!(opened.body, first);
    assert_eq!(
        b.open_history_chunk(&mut recipient, &frame).unwrap().body,
        first
    );
    let receipt = b
        .seal_history_chunk(
            &mut recipient,
            manifest,
            0,
            b"fixture receipt, not SQL import",
            true,
        )
        .unwrap();
    assert_eq!(
        b.seal_history_chunk(
            &mut recipient,
            manifest,
            0,
            b"fixture receipt, not SQL import",
            true
        )
        .unwrap(),
        receipt
    );
    let wrapped = b
        .wrap_history_control(&mut recipient, HistoryControl::Receipt(0))
        .await
        .unwrap();
    a.drain_events();
    a.ingest(wrapped).await.unwrap();
    let frame = received_history(&mut a, &p);
    assert_eq!(
        a.open_history_chunk(&mut source, &frame).unwrap().ordinal,
        0
    );
    let second = a
        .seal_history_chunk(
            &mut source,
            manifest,
            1,
            b"next ordered record fragment",
            false,
        )
        .unwrap();
    assert!(
        a.seal_history_chunk(
            &mut source,
            [9; 32],
            1,
            b"next ordered record fragment",
            false
        )
        .is_err()
    );
    assert!(
        a.seal_history_chunk(
            &mut source,
            manifest,
            MAX_HISTORY_CHUNKS,
            b"over bound",
            false
        )
        .is_err()
    );
    assert!(
        a.seal_history_chunk(
            &mut source,
            manifest,
            2,
            &vec![0; MAX_HISTORY_CHUNK_BYTES + 1],
            false
        )
        .is_err()
    );
    let wrapped = a
        .wrap_history_control(&mut source, HistoryControl::Chunk(1))
        .await
        .unwrap();
    b.drain_events();
    b.ingest(wrapped).await.unwrap();
    let frame = received_history(&mut b, &p);
    assert_eq!(frame, second);
    assert_eq!(
        b.open_history_chunk(&mut recipient, &frame).unwrap().body,
        b"next ordered record fragment"
    );
    bl.live.store(false, Ordering::SeqCst);
    assert!(b.open_history_chunk(&mut recipient, &frame).is_err());
    assert!(
        b.seal_history_chunk(&mut recipient, manifest, 1, b"late receipt", true)
            .is_err()
    );
}

#[tokio::test]
async fn history_channel_chunk_substitution_cannot_bind_an_unopened_original() {
    let (a, b, p, o) = fixture().await;
    for case in 0..5 {
        let (mut source, mut recipient, _, _) = channels(&a, &b, &p, &o);
        let manifest: [u8; 32] = Sha256::digest(b"exact immutable manifest").into();
        let wire = a
            .seal_history_chunk(&mut source, manifest, 0, b"exact original archive", false)
            .unwrap();
        let mut frame = decode(&wire).unwrap();
        match case {
            0 => frame.manifest[0] ^= 1,
            1 => frame.ordinal = 1,
            2 => frame.ordinal = MAX_HISTORY_CHUNKS,
            3 => frame.phase = "receipt".into(),
            4 => frame.source_generation += 1,
            _ => unreachable!(),
        }
        frame.signature.clear();
        let altered = a.history_sign(frame).unwrap();
        b.history_verify(decode(&altered).unwrap())
            .expect("substitution must have a genuine current-leaf signature");
        assert!(
            b.open_history_chunk(&mut recipient, &altered).is_err(),
            "same unbound original case {case}"
        );
        assert!(recipient.chunk_manifest.is_none());
        assert!(recipient.opened_chunks.is_empty());
        assert_eq!(
            b.open_history_chunk(&mut recipient, &wire).unwrap().body,
            b"exact original archive"
        );
    }
}

#[tokio::test]
async fn history_channel_snapshot_descriptor_is_original_signed_context_and_fragment_bound() {
    let (a, b, p, o) = fixture().await;
    let body = vec![7; 1536];
    let descriptor = HistorySnapshotDescriptor {
        archive_digest: Sha256::digest(&body).into(),
        timestamp_ceiling: 123,
        encoded_bytes: body.len() as u32,
        fragment_count: 1,
        record_count: 1,
    };
    let mut source = a
        .begin_history_snapshot_channel(&o, &p, b.identity.signer.public(), Lease::new(), &|_| {
            Ok(descriptor.clone())
        })
        .unwrap();
    let request = b
        .authenticate_history_request(&source.request_packet().unwrap())
        .unwrap();
    assert!(request.scope().snapshot.as_ref() == Some(&descriptor));
    let mut recipient = b.approve_history_channel(&request, Lease::new()).unwrap();
    let consent = recipient.consent_packet().unwrap();
    let mut changed = decode(&consent).unwrap();
    changed.snapshot.as_mut().unwrap().record_count += 1;
    changed.signature.clear();
    let changed = b.history_sign(changed).unwrap();
    a.history_verify(decode(&changed).unwrap())
        .expect("descriptor substitution must remain genuinely signed");
    assert!(a.bind_history_consent(&mut source, &changed).is_err());
    assert!(source.consent.is_none());
    a.bind_history_consent(&mut source, &consent).unwrap();
    assert!(
        a.seal_history_chunk(&mut source, [8; 32], 0, &body, false)
            .is_err()
    );
    assert!(
        a.seal_history_chunk(
            &mut source,
            descriptor.archive_digest,
            0,
            &body[..1535],
            false
        )
        .is_err()
    );
    assert!(source.sealed_chunks.is_empty());
    let wire = a
        .seal_history_chunk(&mut source, descriptor.archive_digest, 0, &body, false)
        .unwrap();
    assert_eq!(
        b.open_history_chunk(&mut recipient, &wire).unwrap().body,
        body
    );
    let mut invalid = descriptor;
    invalid.fragment_count = 2;
    assert!(
        a.begin_history_snapshot_channel(
            &o,
            &p,
            b.identity.signer.public(),
            Lease::new(),
            &|_| Ok(invalid.clone())
        )
        .is_err()
    );
}

#[tokio::test]
async fn history_recipients_observe_exact_remote_leaf_without_creating_consent() {
    let (a, b, protected, ordinary) = fixture().await;
    let choices = a
        .history_recipients(&ordinary, &protected)
        .expect("eligible linked recipients must be observable");
    assert_eq!(choices.len(), 1);
    assert!(choices[0].device == b.identity.signer.public());
    assert!(choices[0].device != a.identity.signer.public());
    let actual = a
        .validated_settled_device_roster(&protected)
        .unwrap()
        .unwrap();
    assert!(
        actual
            .candidate()
            .leaves
            .iter()
            .any(|leaf| leaf.leaf_index == choices[0].leaf_index
                && leaf.signature_public_key == choices[0].device)
    );
    struct NoConsent;
    impl TrustedHistoryLease for NoConsent {}
    assert!(
        a.begin_history_channel(
            &ordinary,
            &protected,
            &choices[0].device,
            Arc::new(NoConsent)
        )
        .is_err()
    );
}

#[tokio::test]
async fn history_recipients_refuse_invalid_groups_and_unsettled_selection() {
    let (a, _, protected, ordinary) = fixture().await;
    assert!(a.history_recipients(&protected, &protected).is_err());
    assert!(a.history_recipients(&ordinary, &ordinary).is_err());
    let absent = GroupId::new(vec![9; 16]);
    assert!(a.history_recipients(&absent, &protected).is_err());
    assert!(a.history_recipients(&ordinary, &absent).is_err());
    assert_eq!(
        a.history_recipients(&ordinary, &protected).unwrap().len(),
        1
    );
    a.select_private_roster_settlement(&protected).unwrap();
    assert!(a.history_recipients(&ordinary, &protected).is_err());
}

#[tokio::test]
async fn history_recipients_do_not_keep_a_stale_ordinary_selection_alive() {
    let (mut a, b, protected, ordinary) = fixture().await;
    let choices = a.history_recipients(&ordinary, &protected).unwrap();
    let source = a
        .begin_history_channel(&ordinary, &protected, &choices[0].device, Lease::new())
        .unwrap();
    let SendResult::GroupEvolution { pending, .. } =
        a.do_send_self_update(ordinary.clone()).await.unwrap()
    else {
        panic!("actual ordinary update");
    };
    assert!(a.history_recipients(&ordinary, &protected).is_err());
    a.confirm_published(pending).await.unwrap();
    assert!(a.validate_history_channel(&source).is_err());
    let fresh = a.history_recipients(&ordinary, &protected).unwrap();
    assert!(fresh[0].device == b.identity.signer.public());
    assert!(
        a.begin_history_channel(&ordinary, &protected, &fresh[0].device, Lease::new())
            .is_ok()
    );
}
