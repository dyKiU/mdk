//! Real MLS/private SQL joins with injected Engine policies, not SDK consent/NIP59.
use super::*;
use cgka_engine::linking_welcome_policy::*;
use cgka_engine::private_device_invite::*;
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::device_linking_key_package::PurposeKeyPackage;
use cgka_traits::peeler::PrivateLinkingWelcomeContext;
use cgka_traits::private_device_invite::*;
use cgka_traits::storage::{MessageStorage, StorageProvider, WelcomeStorage};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct BatchPeeler;
#[async_trait]
impl TransportPeeler for BatchPeeler {
    async fn peel_group_message(
        &self,
        m: &TransportMessage,
        c: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        MockPeeler::default().peel_group_message(m, c).await
    }
    async fn peel_welcome(&self, m: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        MockPeeler::default().peel_welcome(m).await
    }
    async fn wrap_group_message(
        &self,
        p: &EncryptedPayload,
        c: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        MockPeeler::default().wrap_group_message(p, c).await
    }
    async fn wrap_welcome(
        &self,
        p: &EncryptedPayload,
        r: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        MockPeeler::default().wrap_welcome(p, r).await
    }
    async fn wrap_private_linking_welcome(
        &self,
        p: &EncryptedPayload,
        c: &PrivateLinkingWelcomeContext,
    ) -> Result<Vec<TransportMessage>, PeelerError> {
        Ok(vec![
            self.wrap_welcome(p, &MemberId::new(c.account.to_vec()))
                .await?,
        ])
    }
    async fn peel_private_linking_welcome_batch(
        &self,
        m: &[TransportMessage],
        _: &PrivateLinkingWelcomeContext,
    ) -> Result<Vec<u8>, PeelerError> {
        if m.len() != 1 {
            return Err(PeelerError::Malformed(
                "fixture complete batch required".into(),
            ));
        }
        Ok(m[0].payload.clone())
    }
}
fn batch_client(storage: SqliteAccountStorage) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .identity(pad32(ACCOUNT))
        .account_identity_proof_signer(proof_signer(ACCOUNT))
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(BatchPeeler))
        .build()
        .unwrap()
}
struct OutgoingPolicy(PrivateInviteConsent);
struct OutgoingLease(PrivateInviteConsent);
impl TrustedPrivateInvitePolicy for OutgoingPolicy {
    fn begin_prepare(
        &self,
        _: &AuthenticatedPrivateInvite,
    ) -> Result<Box<dyn PrivateInviteLease>, LinkingWelcomeDenied> {
        Ok(Box::new(OutgoingLease(self.0.clone())))
    }
}
impl PrivateInviteLease for OutgoingLease {
    fn consent(&self) -> &PrivateInviteConsent {
        &self.0
    }
    fn check_staged(&mut self, _: &AuthenticatedPrivateAdd) -> Result<(), LinkingWelcomeDenied> {
        Ok(())
    }
    fn check_live_before_commit(&mut self) -> Result<(), LinkingWelcomeDenied> {
        Ok(())
    }
    fn preparation_committed(&mut self, _: &PrivateInviteScope) {}
}
#[derive(Clone)]
struct IncomingPolicy {
    purpose: PurposeKeyPackage,
    context: PrivateLinkingWelcomeContext,
    predecessor: DeviceGroupAnchorRoster,
    successor: DeviceGroupAnchorRoster,
    live: Arc<AtomicBool>,
    consumed: Arc<AtomicUsize>,
    expire_after_predecessor: bool,
}
struct IncomingLease(IncomingPolicy);
impl LinkingWelcomePolicy for IncomingPolicy {
    fn begin_join(
        &self,
        purpose: &PurposeKeyPackage,
    ) -> Result<Box<dyn LinkingWelcomeLease>, LinkingWelcomeDenied> {
        if *purpose != self.purpose {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        Ok(Box::new(IncomingLease(self.clone())))
    }
}
impl LinkingWelcomeLease for IncomingLease {
    fn check_transport_context(
        &mut self,
        c: &PrivateLinkingWelcomeContext,
    ) -> Result<(), LinkingWelcomeDenied> {
        if *c != self.0.context {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        self.check_live_before_commit()
    }
    fn approved_predecessor(&mut self) -> Result<DeviceGroupAnchorRoster, LinkingWelcomeDenied> {
        self.check_live_before_commit()?;
        let predecessor = self.0.predecessor.clone();
        if self.0.expire_after_predecessor {
            self.0.live.store(false, Ordering::SeqCst);
        }
        Ok(predecessor)
    }
    fn check_authenticated(
        &mut self,
        actual: &AuthenticatedLinkingWelcome,
    ) -> Result<(), LinkingWelcomeDenied> {
        if actual.group_id != self.0.context.group_id
            || actual.joined_epoch != self.0.successor.epoch
            || actual.epoch_authenticator_digest != self.0.successor.epoch_authenticator_digest
            || actual.leaves.len() != self.0.successor.leaves.len()
            || actual
                .leaves
                .iter()
                .zip(&self.0.successor.leaves)
                .any(|(a, b)| {
                    a.leaf_index != b.leaf_index
                        || a.account.as_slice() != b.account
                        || a.signature_public_key != b.signature_public_key
                })
        {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        self.check_live_before_commit()
    }
    fn check_live_before_commit(&mut self) -> Result<(), LinkingWelcomeDenied> {
        if self.0.live.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(LinkingWelcomeDenied::Expired)
        }
    }
    fn commit_accepted(self: Box<Self>, _: &cgka_traits::accepted_welcome::AcceptedWelcomeReceipt) {
        self.0.consumed.fetch_add(1, Ordering::SeqCst);
    }
}
struct Fixture {
    creator: SqliteAccountStorage,
    recipient: Engine<SqliteAccountStorage>,
    storage: SqliteAccountStorage,
    package: cgka_traits::engine::KeyPackage,
    messages: Vec<TransportMessage>,
    policy: IncomingPolicy,
}
async fn fixture(storage: SqliteAccountStorage) -> Fixture {
    let mut recipient = batch_client(storage.clone());
    let (purpose, package) =
        super::purpose_welcome::verified_package(&storage, &mut recipient).await;
    let approver_storage = SqliteAccountStorage::in_memory().unwrap();
    let mut approver = batch_client(approver_storage.clone());
    let genesis = approver.create_private_device_group_genesis().unwrap();
    let account = purpose.scope.account;
    let device = genesis.birth().leaves[0].signature_public_key;
    approver_storage
        .ensure_account_projection_with_identity("private-batch-approver", &hex::encode(account))
        .unwrap();
    let generation = approver_storage
        .reserve_device_linking_attempt(&account, &device)
        .unwrap();
    let binding = storage_sqlite::DeviceLinkingBinding {
        generation,
        nonce: purpose.context.as_ref().unwrap().nonce,
        context_digest: purpose.context.as_ref().unwrap().context_digest,
    };
    approver_storage
        .bind_device_linking_context(&binding)
        .unwrap();
    approver_storage
        .bind_device_linking_flow(&binding, "isolated-outgoing-policy")
        .unwrap();
    approver_storage
        .finish_device_linking_attempt(
            generation,
            storage_sqlite::DeviceLinkingOutcome::PairingVerified,
        )
        .unwrap();
    approver.install_trusted_private_invite_policy(Arc::new(OutgoingPolicy(
        PrivateInviteConsent {
            approver_scope: cgka_traits::device_linking_key_package::PurposeAttemptScope {
                account,
                local_device: device,
                generation,
            },
            recipient_generation: purpose.scope.generation,
            origin: PrivateInviteOrigin::Genesis(genesis.scope().selection_generation),
            nonce: binding.nonce,
            context_digest: binding.context_digest,
        },
    )));
    let _prepared = approver
        .prepare_private_device_invite(genesis.group_id(), package.clone())
        .await
        .unwrap();
    let fact = approver_storage
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    let b = &fact.raw.binding;
    let context = PrivateLinkingWelcomeContext {
        account: b.approver_scope.account,
        approver: b.approver_scope.local_device,
        recipient: b.recipient,
        approver_generation: b.approver_scope.generation,
        recipient_generation: b.recipient_generation,
        group_id: b.group_id.clone(),
        nonce: b.nonce,
        context_digest: b.context_digest,
        key_package_reference: b.key_package_reference,
        key_package_digest: b.key_package_digest,
        commit_digest: b.commit_digest,
        welcome_digest: b.welcome_digest,
    };
    let policy = IncomingPolicy {
        purpose,
        context,
        predecessor: b.predecessor.clone(),
        successor: b.successor.clone(),
        live: Arc::new(AtomicBool::new(true)),
        consumed: Arc::new(AtomicUsize::new(0)),
        expire_after_predecessor: false,
    };
    Fixture {
        creator: approver_storage,
        recipient,
        storage,
        package,
        messages: fact.transport.unwrap().welcomes,
        policy,
    }
}
#[tokio::test]
async fn private_batch_join_installs_actual_successor_and_consumes_exact_purpose_atomically() {
    let mut f = fixture(SqliteAccountStorage::in_memory().unwrap()).await;
    f.recipient
        .install_trusted_linking_welcome_policy(Arc::new(f.policy.clone()));
    let group = f
        .recipient
        .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
        .await
        .unwrap();
    assert!(group == f.policy.context.group_id);
    assert!(
        !f.recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&f.package)
    );
    let receipt = f
        .recipient
        .accepted_welcome_receipt(&f.messages[0].id)
        .unwrap()
        .unwrap();
    assert!(
        receipt.group_id == group && receipt.consumed_key_package_ref == f.policy.purpose.reference
    );
    let anchor = f
        .storage
        .accepted_device_group_anchor_storage()
        .unwrap()
        .accepted_anchor()
        .unwrap()
        .unwrap();
    assert!(
        anchor.draft.successor == f.policy.successor
            && anchor.draft.predecessor == f.policy.predecessor
    );
    assert!(
        f.storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap()
            .consumed
    );
    assert_eq!(f.policy.consumed.load(Ordering::SeqCst), 1);
    let messages = f
        .storage
        .list_messages(&group, f.policy.successor.epoch)
        .unwrap();
    assert!(
        messages
            .iter()
            .all(|m| m.state == cgka_traits::message::MessageState::Processed)
    );
}

fn assert_unjoined(f: &Fixture) {
    assert!(f.recipient.epoch(&f.policy.context.group_id).is_err());
    assert!(
        f.recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&f.package)
    );
    assert!(
        f.storage
            .accepted_welcome_storage()
            .unwrap()
            .accepted_welcome_receipt(&f.messages[0].id)
            .unwrap()
            .is_none()
    );
    assert!(
        f.storage
            .accepted_device_group_anchor_storage()
            .unwrap()
            .accepted_anchor()
            .unwrap()
            .is_none()
    );
    assert!(
        !f.storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap()
            .consumed
    );
    assert!(
        !f.storage
            .has_ingress_dedup_marker(&f.messages[0].id)
            .unwrap()
    );
    assert_eq!(f.policy.consumed.load(Ordering::SeqCst), 0);
    assert!(f.storage.list_welcomes().unwrap().is_empty());
}

#[tokio::test]
async fn private_batch_no_policy_raw_bypass_and_incomplete_input_leave_exact_retry() {
    let mut f = fixture(SqliteAccountStorage::in_memory().unwrap()).await;
    assert!(matches!(
        f.recipient
            .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
            .await,
        Err(cgka_traits::EngineError::LinkingWelcomeDenied(
            LinkingWelcomeDenied::NoLiveVerifier
        ))
    ));
    assert_unjoined(&f);
    f.recipient
        .install_trusted_linking_welcome_policy(Arc::new(f.policy.clone()));
    assert!(matches!(
        f.recipient.join_welcome(f.messages[0].clone()).await,
        Err(cgka_traits::EngineError::LinkingWelcomeDenied(_))
    ));
    assert_unjoined(&f);
    assert!(
        f.recipient
            .join_private_linking_welcome_batch(vec![], &f.policy.context)
            .await
            .is_err()
    );
    let duplicate = vec![f.messages[0].clone(), f.messages[0].clone()];
    assert!(
        f.recipient
            .join_private_linking_welcome_batch(duplicate, &f.policy.context)
            .await
            .is_err()
    );
    assert_unjoined(&f);
    f.recipient
        .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
        .await
        .unwrap();
    assert!(f.storage.list_welcomes().unwrap().is_empty());
    assert!(matches!(
        f.recipient
            .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
            .await,
        Err(cgka_traits::EngineError::WelcomeAlreadyProcessed)
    ));
    assert_eq!(f.policy.consumed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn private_batch_context_and_approved_predecessor_mismatch_restore_bundle_and_dispositions() {
    let mut f = fixture(SqliteAccountStorage::in_memory().unwrap()).await;
    f.recipient
        .install_trusted_linking_welcome_policy(Arc::new(f.policy.clone()));
    let mut substitutions = Vec::new();
    for field in 0..12 {
        let mut c = f.policy.context.clone();
        match field {
            0 => c.account[0] ^= 1,
            1 => c.recipient[0] ^= 1,
            2 => c.approver[0] ^= 1,
            3 => c.recipient_generation += 1,
            4 => c.approver_generation += 1,
            5 => c.nonce[0] ^= 1,
            6 => c.context_digest[0] ^= 1,
            7 => c.key_package_reference[0] ^= 1,
            8 => c.key_package_digest[0] ^= 1,
            9 => c.commit_digest[0] ^= 1,
            10 => c.welcome_digest[0] ^= 1,
            _ => c.group_id = cgka_traits::GroupId::new(vec![7]),
        }
        substitutions.push(c);
    }
    for context in substitutions {
        assert!(
            f.recipient
                .join_private_linking_welcome_batch(f.messages.clone(), &context)
                .await
                .is_err()
        );
        assert_unjoined(&f);
    }
    let mut bad_policy = f.policy.clone();
    bad_policy.predecessor.leaves[0].signature_public_key[0] ^= 1;
    f.recipient
        .install_trusted_linking_welcome_policy(Arc::new(bad_policy));
    assert!(
        f.recipient
            .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
            .await
            .is_err()
    );
    assert_unjoined(&f);
    f.recipient
        .install_trusted_linking_welcome_policy(Arc::new(f.policy.clone()));
    f.recipient
        .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
        .await
        .unwrap();
}

#[tokio::test]
async fn private_batch_anchor_fault_rolls_back_consumption_then_encrypted_reopen_exact_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private-batch.db");
    let key = storage_sqlite::SqlCipherKey::new("06".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut f = fixture(storage).await;
    f.recipient
        .install_trusted_linking_welcome_policy(Arc::new(f.policy.clone()));
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER fail_private_anchor BEFORE INSERT ON accepted_device_group_anchor BEGIN SELECT RAISE(ABORT,'injected private anchor failure'); END;").unwrap();
    assert!(matches!(
        f.recipient
            .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
            .await,
        Err(cgka_traits::EngineError::Storage(_))
    ));
    assert_unjoined(&f);
    injector
        .execute_batch("DROP TRIGGER fail_private_anchor;")
        .unwrap();
    drop(injector);
    let Fixture {
        creator: _,
        recipient,
        storage,
        package,
        messages,
        policy,
    } = f;
    drop(recipient);
    drop(storage);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut recipient = batch_client(storage.clone());
    // This is a newly injected test lease, never consent reconstructed by SQL.
    recipient.install_trusted_linking_welcome_policy(Arc::new(policy.clone()));
    recipient
        .join_private_linking_welcome_batch(messages.clone(), &policy.context)
        .await
        .unwrap();
    assert!(
        !recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&package)
    );
    assert!(
        storage
            .accepted_device_group_anchor_storage()
            .unwrap()
            .accepted_anchor()
            .unwrap()
            .is_some()
    );
    assert_eq!(policy.consumed.load(Ordering::SeqCst), 1);
}

struct DefaultLeasePolicy {
    package: PurposeKeyPackage,
    omit_predecessor: bool,
    policy: IncomingPolicy,
}
struct DefaultContextLease;
impl LinkingWelcomeLease for DefaultContextLease {
    fn check_authenticated(
        &mut self,
        _: &AuthenticatedLinkingWelcome,
    ) -> Result<(), LinkingWelcomeDenied> {
        Ok(())
    }
    fn check_live_before_commit(&mut self) -> Result<(), LinkingWelcomeDenied> {
        Ok(())
    }
    fn commit_accepted(self: Box<Self>, _: &cgka_traits::accepted_welcome::AcceptedWelcomeReceipt) {
    }
}
struct DefaultPredecessorLease(IncomingLease);
impl LinkingWelcomeLease for DefaultPredecessorLease {
    fn check_transport_context(
        &mut self,
        c: &PrivateLinkingWelcomeContext,
    ) -> Result<(), LinkingWelcomeDenied> {
        self.0.check_transport_context(c)
    }
    fn check_authenticated(
        &mut self,
        a: &AuthenticatedLinkingWelcome,
    ) -> Result<(), LinkingWelcomeDenied> {
        self.0.check_authenticated(a)
    }
    fn check_live_before_commit(&mut self) -> Result<(), LinkingWelcomeDenied> {
        self.0.check_live_before_commit()
    }
    fn commit_accepted(self: Box<Self>, _: &cgka_traits::accepted_welcome::AcceptedWelcomeReceipt) {
    }
}
impl LinkingWelcomePolicy for DefaultLeasePolicy {
    fn begin_join(
        &self,
        p: &PurposeKeyPackage,
    ) -> Result<Box<dyn LinkingWelcomeLease>, LinkingWelcomeDenied> {
        if *p != self.package {
            return Err(LinkingWelcomeDenied::ContextMismatch);
        }
        if self.omit_predecessor {
            Ok(Box::new(DefaultPredecessorLease(IncomingLease(
                self.policy.clone(),
            ))))
        } else {
            Ok(Box::new(DefaultContextLease))
        }
    }
}
#[tokio::test]
async fn private_batch_default_lease_methods_deny_and_late_expiry_rolls_back_anchor() {
    let mut f = fixture(SqliteAccountStorage::in_memory().unwrap()).await;
    for omit_predecessor in [false, true] {
        f.recipient
            .install_trusted_linking_welcome_policy(Arc::new(DefaultLeasePolicy {
                package: f.policy.purpose.clone(),
                omit_predecessor,
                policy: f.policy.clone(),
            }));
        assert!(matches!(
            f.recipient
                .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
                .await,
            Err(cgka_traits::EngineError::LinkingWelcomeDenied(
                LinkingWelcomeDenied::NoLiveVerifier
            ))
        ));
        assert_unjoined(&f);
    }
    let mut expiring = f.policy.clone();
    expiring.expire_after_predecessor = true;
    f.recipient
        .install_trusted_linking_welcome_policy(Arc::new(expiring));
    assert!(matches!(
        f.recipient
            .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
            .await,
        Err(cgka_traits::EngineError::LinkingWelcomeDenied(
            LinkingWelcomeDenied::Expired
        ))
    ));
    assert_unjoined(&f);
}

#[tokio::test]
async fn private_batch_late_receipt_failure_rolls_back_already_inserted_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private-receipt-fault.db");
    let key = storage_sqlite::SqlCipherKey::new("08".repeat(32)).unwrap();
    let mut f = fixture(SqliteAccountStorage::open_encrypted(&path, &key).unwrap()).await;
    f.recipient
        .install_trusted_linking_welcome_policy(Arc::new(f.policy.clone()));
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER fail_private_receipt BEFORE INSERT ON accepted_welcome_receipts BEGIN SELECT RAISE(ABORT,'injected receipt failure after anchor'); END;").unwrap();
    assert!(matches!(
        f.recipient
            .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
            .await,
        Err(cgka_traits::EngineError::Storage(_))
    ));
    assert_unjoined(&f);
    injector
        .execute_batch("DROP TRIGGER fail_private_receipt;")
        .unwrap();
    f.recipient
        .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
        .await
        .unwrap();
}

/// A synthetic adversarial peer deliberately bypasses Engine's policy. Genuine
/// OpenMLS produces an alternate signed private-tree Welcome; no DTO grant.
#[tokio::test]
async fn private_batch_actual_active_branch_replacement_never_spills_ordinary_offer() {
    use cgka_traits::device_group_genesis::GenesisLeaf;
    use openmls::prelude::*;
    use openmls_basic_credential::SignatureKeyPair;
    use sha2::{Digest, Sha256};
    use tls_codec::{Deserialize as _, Serialize as _};
    let mut f = fixture(SqliteAccountStorage::in_memory().unwrap()).await;
    f.recipient
        .install_trusted_linking_welcome_policy(Arc::new(f.policy.clone()));
    f.recipient
        .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
        .await
        .unwrap();
    let previous = f
        .storage
        .accepted_device_group_anchor_storage()
        .unwrap()
        .accepted_anchor()
        .unwrap()
        .unwrap();
    f.storage
        .accepted_device_group_anchor_storage()
        .unwrap()
        .deny_accepted_anchor(&previous.scope, &previous.draft.group_id)
        .unwrap();
    let (purpose, package) =
        super::purpose_welcome::verified_package(&f.storage, &mut f.recipient).await;
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let provider = cgka_engine::provider::EngineOpenMlsProvider::<SqliteAccountStorage>::new(
        &crypto,
        f.creator.mls_storage(),
    );
    let mut source = MlsGroup::load(
        provider.storage(),
        &openmls::group::GroupId::from_slice(f.policy.context.group_id.as_slice()),
    )
    .unwrap()
    .unwrap();
    source.clear_pending_commit(provider.storage()).unwrap();
    let signer = SignatureKeyPair::read(
        provider.storage(),
        &f.policy.context.approver,
        SignatureScheme::ED25519,
    )
    .unwrap();
    let MlsMessageBodyIn::KeyPackage(package_in) =
        MlsMessageIn::tls_deserialize_exact(&package.bytes)
            .unwrap()
            .extract()
    else {
        panic!("actual KP expected")
    };
    let actual = package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    let (commit, welcome, _) = source.add_members(&provider, &signer, &[actual]).unwrap();
    let commit = commit.tls_serialize_detached().unwrap();
    let welcome = welcome.tls_serialize_detached().unwrap();
    source.merge_pending_commit(&provider).unwrap();
    let mut leaves = source
        .members()
        .map(|m| {
            assert_eq!(m.credential.serialized_content(), f.policy.context.account);
            GenesisLeaf {
                leaf_index: m.index.u32(),
                account: f.policy.context.account,
                signature_public_key: m.signature_key.try_into().unwrap(),
            }
        })
        .collect::<Vec<_>>();
    leaves.sort_by_key(|l| l.leaf_index);
    let mut context = f.policy.context.clone();
    context.recipient_generation = purpose.scope.generation;
    context.key_package_reference = purpose.reference.as_slice().try_into().unwrap();
    context.key_package_digest = Sha256::digest(&purpose.public_bytes).into();
    context.commit_digest = Sha256::digest(commit).into();
    context.welcome_digest = Sha256::digest(&welcome).into();
    let messages = BatchPeeler
        .wrap_private_linking_welcome(
            &EncryptedPayload {
                ciphertext: welcome,
                aad: vec![],
            },
            &context,
        )
        .await
        .unwrap();
    let policy = IncomingPolicy {
        purpose,
        context: context.clone(),
        predecessor: f.policy.predecessor.clone(),
        successor: DeviceGroupAnchorRoster {
            epoch: cgka_traits::EpochId(source.epoch().as_u64()),
            epoch_authenticator_digest: Sha256::digest(source.epoch_authenticator().as_slice())
                .into(),
            leaves,
        },
        live: Arc::new(AtomicBool::new(true)),
        consumed: Arc::new(AtomicUsize::new(0)),
        expire_after_predecessor: false,
    };
    f.recipient
        .install_trusted_linking_welcome_policy(Arc::new(policy.clone()));
    let result = f
        .recipient
        .join_private_linking_welcome_batch(messages.clone(), &context)
        .await;
    assert_eq!(
        f.storage.list_welcomes().unwrap().len(),
        0,
        "private replacement cannot enter ordinary rejoin offers"
    );
    assert!(matches!(
        result,
        Err(cgka_traits::EngineError::LinkingWelcomeDenied(
            LinkingWelcomeDenied::ContextMismatch
        ))
    ));
    assert!(
        f.recipient
            .durably_owned_key_packages()
            .unwrap()
            .contains(&package)
    );
    assert_eq!(
        f.recipient.epoch(&context.group_id).unwrap(),
        previous.draft.successor.epoch
    );
    assert!(
        f.storage
            .accepted_device_group_anchor_storage()
            .unwrap()
            .accepted_anchor()
            .unwrap()
            .unwrap()
            .draft
            == previous.draft
    );
    assert!(!f.storage.has_ingress_dedup_marker(&messages[0].id).unwrap());
}
