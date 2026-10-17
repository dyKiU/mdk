//! Real MLS/private SQL joins with injected Engine policies, not SDK consent/NIP59.
use super::*;
use cgka_engine::linking_welcome_policy::*;
use cgka_engine::private_device_invite::*;
use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
use cgka_traits::device_linking_key_package::PurposeKeyPackage;
use cgka_traits::peeler::PrivateLinkingWelcomeContext;
use cgka_traits::private_device_invite::*;
use cgka_traits::storage::{GroupStorage, MessageStorage, StorageProvider, WelcomeStorage};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

include!("../support/private_linking_receive_fixture.rs");
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
struct Fixture {
    approver: Engine<SqliteAccountStorage>,
    prepared: PreparedPrivateDeviceInvite,
    creator: SqliteAccountStorage,
    recipient: Engine<SqliteAccountStorage>,
    storage: SqliteAccountStorage,
    package: cgka_traits::engine::KeyPackage,
    messages: Vec<TransportMessage>,
    policy: IncomingPolicy,
}
async fn fixture(storage: SqliteAccountStorage) -> Fixture {
    fixture_with_creator(storage, SqliteAccountStorage::in_memory().unwrap()).await
}
async fn fixture_with_creator(
    storage: SqliteAccountStorage,
    approver_storage: SqliteAccountStorage,
) -> Fixture {
    let mut recipient = batch_client(storage.clone());
    let (purpose, package) =
        super::purpose_welcome::verified_package(&storage, &mut recipient).await;
    let mut approver = batch_client(approver_storage.clone());
    let genesis = approver.create_private_device_group_genesis().unwrap();
    let account = purpose.scope.account;
    let device = genesis.birth().leaves[0].signature_public_key;
    approver_storage
        .app_storage().ensure_account_projection_with_identity("private-batch-approver", &hex::encode(account))
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
    let prepared = approver
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
        approver,
        prepared,
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
        ..
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

#[tokio::test]
async fn private_batch_join_retires_only_unused_birth_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unused-birth.db");
    let key = storage_sqlite::SqlCipherKey::new("09".repeat(32)).unwrap();
    let mut f = fixture(SqliteAccountStorage::open_encrypted(&path, &key).unwrap()).await;
    let birth = f.recipient.create_private_device_group_genesis().unwrap();
    f.recipient
        .install_trusted_linking_welcome_policy(Arc::new(f.policy.clone()));
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER fail_private_receipt BEFORE INSERT ON accepted_welcome_receipts BEGIN SELECT RAISE(ABORT,'injected receipt failure after birth retirement'); END;").unwrap();
    assert!(matches!(
        f.recipient
            .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
            .await,
        Err(cgka_traits::EngineError::Storage(_))
    ));
    assert_unjoined(&f);
    assert!(
        f.recipient
            .validated_private_device_group_genesis(birth.group_id())
            .unwrap()
            .is_some()
    );
    injector
        .execute_batch("DROP TRIGGER fail_private_receipt;")
        .unwrap();
    let group = f
        .recipient
        .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
        .await
        .unwrap();
    let retired = f
        .storage
        .device_group_genesis_storage()
        .unwrap()
        .genesis_selection()
        .unwrap()
        .unwrap();
    assert!(retired.active_denied && retired.fact.birth == *birth.birth());
    assert!(
        f.recipient
            .candidate_device_group_snapshot(birth.group_id())
            .unwrap()
            .is_some()
    );
    assert!(f.storage.get_group(&group).is_ok());
    assert_eq!(f.policy.consumed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn private_batch_expired_join_keeps_unused_birth_selected() {
    let mut f = fixture(SqliteAccountStorage::in_memory().unwrap()).await;
    let birth = f.recipient.create_private_device_group_genesis().unwrap();
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
    assert!(
        f.recipient
            .validated_private_device_group_genesis(birth.group_id())
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn private_batch_unused_birth_retirement_preserves_historical_sharing_policy() {
    let mut f = fixture(SqliteAccountStorage::in_memory().unwrap()).await;
    let birth = f.recipient.create_private_device_group_genesis().unwrap();
    // Injected historical policy is only a negative guard fixture, never proof
    // of SDK approval or a usable sharing channel.
    let policy = cgka_traits::approved_account_sharing_policy::ApprovedAccountSharingPolicy {
        account: f.policy.purpose.scope.account,
        local_device: f.policy.purpose.scope.local_device,
        peer_device: f.policy.context.approver,
        protected_group: birth.group_id().clone(),
        approval_id: [9; 32],
        version: 1,
        capabilities: 0x0f,
        created_at: 1,
        approved_protected_epoch: 1,
        revoked: false,
    };
    let policies = f.storage.approved_account_sharing_policy_storage().unwrap();
    policies
        .put_approved_account_sharing_policy(&policy, &|| Ok(()))
        .unwrap();
    let id = cgka_traits::approved_account_sharing_policy::approved_account_sharing_identity(
        &policy.account,
        &policy.protected_group,
        &policy.local_device,
        &policy.peer_device,
        &policy.approval_id,
    )
    .unwrap();
    policies
        .revoke_account_sharing_policy(&id, &|| Ok(()))
        .unwrap();
    f.recipient
        .install_trusted_linking_welcome_policy(Arc::new(f.policy.clone()));
    assert!(matches!(
        f.recipient
            .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
            .await,
        Err(cgka_traits::EngineError::LinkingWelcomeDenied(_))
    ));
    assert_unjoined(&f);
    assert!(
        f.recipient
            .validated_private_device_group_genesis(birth.group_id())
            .unwrap()
            .is_some()
    );
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

struct ObservedPublisher(AtomicUsize);
#[async_trait]
impl TrustedPrivateInvitePublisher for ObservedPublisher {
    async fn publish_commit(&self, _: &TransportMessage) -> Result<(), cgka_traits::EngineError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
async fn confirm_fixture_and_join(f: &mut Fixture) {
    let fact = f
        .creator
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap();
    let echo = fact.transport.unwrap().commit;
    let publisher = ObservedPublisher(AtomicUsize::new(0));
    f.approver
        .dispatch_prepared_private_device_invite(&mut f.prepared, &publisher)
        .await
        .unwrap();
    assert_eq!(publisher.0.load(Ordering::SeqCst), 1);
    assert!(matches!(
        f.approver.ingest(echo).await.unwrap(),
        cgka_traits::IngestOutcome::Processed
    ));
    let confirmed = f
        .creator
        .private_device_invite_storage()
        .unwrap()
        .confirmed_private_invite()
        .unwrap()
        .unwrap();
    assert!(
        !confirmed.denied,
        "genuine expected private successor must remain active"
    );
    assert!(confirmed.binding.successor == f.policy.successor);
    f.recipient
        .install_trusted_linking_welcome_policy(Arc::new(f.policy.clone()));
    f.recipient
        .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
        .await
        .unwrap();
    assert!(
        !f.storage
            .accepted_device_group_anchor_storage()
            .unwrap()
            .accepted_anchor()
            .unwrap()
            .unwrap()
            .denied
    );
}
fn signed_unexpected_update(
    storage: &SqliteAccountStorage,
    group: &cgka_traits::GroupId,
    signer_key: &[u8],
) -> TransportMessage {
    use openmls::prelude::*;
    use openmls_basic_credential::SignatureKeyPair;
    use tls_codec::Serialize as _;
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let provider = cgka_engine::provider::EngineOpenMlsProvider::<SqliteAccountStorage>::new(
        &crypto,
        storage.mls_storage(),
    );
    let mut source = MlsGroup::load(
        provider.storage(),
        &openmls::group::GroupId::from_slice(group.as_slice()),
    )
    .unwrap()
    .unwrap();
    let signer =
        SignatureKeyPair::read(provider.storage(), signer_key, SignatureScheme::ED25519).unwrap();
    let (commit, _, _) = source
        .self_update(&provider, &signer, LeafNodeParameters::default())
        .unwrap()
        .into_contents();
    let bytes = commit.tls_serialize_detached().unwrap();
    source.merge_pending_commit(&provider).unwrap();
    TransportMessage {
        id: hash_id(&bytes),
        payload: bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("isolated-adversarial-private-peer".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group.as_slice().to_vec(),
        },
    }
}
async fn exercise_private_lineage_transition(accepted: bool, fault: bool) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("private-lineage-observer.sqlite");
    let key = storage_sqlite::SqlCipherKey::new("9a".repeat(32)).unwrap();
    let observer_storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut f = if accepted {
        fixture_with_creator(
            observer_storage.clone(),
            SqliteAccountStorage::in_memory().unwrap(),
        )
        .await
    } else {
        fixture_with_creator(
            SqliteAccountStorage::in_memory().unwrap(),
            observer_storage.clone(),
        )
        .await
    };
    confirm_fixture_and_join(&mut f).await;
    let group = f.policy.context.group_id.clone();
    observer_storage
        .create_group_snapshot(&group, "private-lineage-A")
        .unwrap();
    let original_accepted = f
        .storage
        .accepted_device_group_anchor_storage()
        .unwrap()
        .accepted_anchor()
        .unwrap()
        .unwrap();
    let original_confirmed = f
        .creator
        .private_device_invite_storage()
        .unwrap()
        .confirmed_private_invite()
        .unwrap()
        .unwrap();
    let message = if accepted {
        signed_unexpected_update(&f.creator, &group, &f.policy.context.approver)
    } else {
        signed_unexpected_update(&f.storage, &group, &f.policy.context.recipient)
    };
    let observer = if accepted {
        &mut f.recipient
    } else {
        &mut f.approver
    };
    observer
        .buffer_openmls_convergence_message_at(&group, message.clone(), 1_000)
        .unwrap();
    let selection = cgka_engine::openmls_projection::canonicalize_stored_openmls_messages(
        &observer_storage,
        &group,
        cgka_engine::canonicalization::CanonicalizationState {
            current_tip_epoch: 1,
            retained_anchor_epoch: 0,
            last_convergence_relevant_input_ms: 0,
            seen_message_ids: std::collections::BTreeSet::new(),
        },
        vec![],
        cgka_engine::canonicalization::CanonicalizationPolicy::default(),
        2_000_000,
    )
    .unwrap();
    assert_eq!(
        selection.selected_tip,
        Some(2),
        "real crypto candidate selection must see the changed tree"
    );
    assert_eq!(
        observer_storage.get_group(&group).unwrap().epoch.0,
        1,
        "candidate probing must restore actual A state"
    );
    if accepted {
        assert!(
            !observer_storage
                .accepted_device_group_anchor_storage()
                .unwrap()
                .accepted_anchor()
                .unwrap()
                .unwrap()
                .denied,
            "candidate probes must not revoke accepted lineage"
        );
    } else {
        assert!(
            !observer_storage
                .private_device_invite_storage()
                .unwrap()
                .confirmed_private_invite()
                .unwrap()
                .unwrap()
                .denied,
            "candidate probes must not revoke confirmed lineage"
        );
    }
    let injector = if fault {
        let connection = rusqlite::Connection::open(&path).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &connection,
            &key,
            storage_sqlite::SqlCipherHardening::default(),
        )
        .unwrap();
        let table = if accepted {
            "accepted_device_group_anchor"
        } else {
            "private_device_invite_confirmed"
        };
        connection.execute_batch(&format!("CREATE TRIGGER fail_lineage_denial BEFORE UPDATE ON {table} WHEN NEW.denied=1 BEGIN SELECT RAISE(ABORT,'isolated lineage denial fault'); END;")).unwrap();
        Some(connection)
    } else {
        None
    };
    let first = observer.ingest(message).await;
    let settle = observer
        .advance_convergence_inputs_until_settled(&group, 2_000_000)
        .await;
    if fault {
        assert!(
            first.is_err() || settle.is_err(),
            "real denial-write fault must abort apply"
        );
        assert_eq!(
            observer_storage.get_group(&group).unwrap().epoch.0,
            1,
            "failed denial must roll back actual MLS/projection advance"
        );
        if accepted {
            assert!(
                !observer_storage
                    .accepted_device_group_anchor_storage()
                    .unwrap()
                    .accepted_anchor()
                    .unwrap()
                    .unwrap()
                    .denied
            );
        } else {
            assert!(
                !observer_storage
                    .private_device_invite_storage()
                    .unwrap()
                    .confirmed_private_invite()
                    .unwrap()
                    .unwrap()
                    .denied
            );
        }
        injector
            .as_ref()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_lineage_denial")
            .unwrap();
        drop(injector);
        observer
            .advance_convergence_inputs_until_settled(&group, 3_000_000)
            .await
            .unwrap();
    } else {
        first.unwrap();
        settle.unwrap();
    }
    assert_eq!(
        observer.epoch(&group).unwrap().0,
        2,
        "actual selected apply must adopt the authenticated unexpected update"
    );
    if accepted {
        let fact = observer_storage
            .accepted_device_group_anchor_storage()
            .unwrap()
            .accepted_anchor()
            .unwrap()
            .unwrap();
        assert!(fact.scope == original_accepted.scope && fact.draft == original_accepted.draft);
        assert!(
            fact.denied,
            "accepted109 lineage must be permanently denied by actual unexpected selected tree"
        );
    } else {
        let fact = observer_storage
            .private_device_invite_storage()
            .unwrap()
            .confirmed_private_invite()
            .unwrap()
            .unwrap();
        assert!(
            fact.scope == original_confirmed.scope && fact.binding == original_confirmed.binding
        );
        assert!(
            fact.denied,
            "confirmed110 lineage must be permanently denied by actual unexpected selected tree"
        );
    }
    // Restore only the genuine retained A crypto/group snapshot; private denial
    // is not a reversible branch projection and cannot revive with a matching tree.
    observer_storage
        .rollback_group_to_snapshot(&group, "private-lineage-A")
        .unwrap();
    observer_storage
        .release_group_snapshot(&group, "private-lineage-A")
        .unwrap();
    drop(f);
    drop(observer_storage);
    let reopened_storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut reopened = batch_client(reopened_storage.clone());
    reopened.hydrate_all_stored_groups().unwrap();
    assert_eq!(reopened.epoch(&group).unwrap().0, 1);
    if accepted {
        let fact = reopened_storage
            .accepted_device_group_anchor_storage()
            .unwrap()
            .accepted_anchor()
            .unwrap()
            .unwrap();
        assert!(
            fact.scope == original_accepted.scope
                && fact.draft == original_accepted.draft
                && fact.denied
        );
    } else {
        let fact = reopened_storage
            .private_device_invite_storage()
            .unwrap()
            .confirmed_private_invite()
            .unwrap()
            .unwrap();
        assert!(
            fact.scope == original_confirmed.scope
                && fact.binding == original_confirmed.binding
                && fact.denied
        );
    }
}
#[tokio::test]
async fn private_lineage_accepted_selected_transition_cannot_revive_on_encrypted_a_reopen() {
    exercise_private_lineage_transition(true, false).await;
}
#[tokio::test]
async fn private_lineage_confirmed_selected_transition_cannot_revive_on_encrypted_a_reopen() {
    exercise_private_lineage_transition(false, false).await;
}

#[tokio::test]
async fn private_lineage_unrelated_actual_evolution_preserves_exact_selected_scopes() {
    use cgka_traits::engine::SendIntent;
    let mut f = fixture(SqliteAccountStorage::in_memory().unwrap()).await;
    confirm_fixture_and_join(&mut f).await;
    let accepted = f
        .storage
        .accepted_device_group_anchor_storage()
        .unwrap()
        .accepted_anchor()
        .unwrap()
        .unwrap();
    let confirmed = f
        .creator
        .private_device_invite_storage()
        .unwrap()
        .confirmed_private_invite()
        .unwrap()
        .unwrap();
    let (ordinary, _) = f
        .approver
        .create_group(CreateGroupRequest {
            name: "isolated-unrelated-group".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupEvolution { pending, .. } = f
        .approver
        .send(SendIntent::SelfUpdate {
            group_id: ordinary.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("actual ordinary update expected")
    };
    f.approver.confirm_published(pending).await.unwrap();
    assert_eq!(f.approver.epoch(&ordinary).unwrap().0, 1);
    assert!(
        f.creator
            .private_device_invite_storage()
            .unwrap()
            .confirmed_private_invite()
            .unwrap()
            .unwrap()
            == confirmed
    );
    assert!(
        f.storage
            .accepted_device_group_anchor_storage()
            .unwrap()
            .accepted_anchor()
            .unwrap()
            .unwrap()
            == accepted
    );
}

#[tokio::test]
async fn private_lineage_encrypted_denial_write_fault_rolls_back_and_retries_retained_crypto() {
    exercise_private_lineage_transition(true, true).await;
    exercise_private_lineage_transition(false, true).await;
}

fn signed_private_marker_removal(
    storage: &SqliteAccountStorage,
    group: &cgka_traits::GroupId,
    signer_key: &[u8],
) -> TransportMessage {
    use cgka_traits::app_components::{
        APP_COMPONENTS_COMPONENT_ID, decode_components_list, encode_components_list,
    };
    use cgka_traits::device_group_genesis::PRIVATE_DEVICE_GROUP_COMPONENT_ID;
    use openmls::component::ComponentData;
    use openmls::prelude::*;
    use openmls_basic_credential::SignatureKeyPair;
    use tls_codec::Serialize as _;
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let provider = cgka_engine::provider::EngineOpenMlsProvider::<SqliteAccountStorage>::new(
        &crypto,
        storage.mls_storage(),
    );
    let mut source = MlsGroup::load(
        provider.storage(),
        &openmls::group::GroupId::from_slice(group.as_slice()),
    )
    .unwrap()
    .unwrap();
    let signer =
        SignatureKeyPair::read(provider.storage(), signer_key, SignatureScheme::ED25519).unwrap();
    let dictionary = source
        .extensions()
        .app_data_dictionary()
        .unwrap()
        .dictionary();
    let mut required =
        decode_components_list(dictionary.get(&APP_COMPONENTS_COMPONENT_ID).unwrap()).unwrap();
    assert!(required.remove(&PRIVATE_DEVICE_GROUP_COMPONENT_ID));
    let list = encode_components_list(&required);
    let mut builder = source
        .commit_builder()
        .consume_proposal_store(false)
        .add_proposal(Proposal::AppDataUpdate(Box::new(
            AppDataUpdateProposal::update(APP_COMPONENTS_COMPONENT_ID, list.clone()),
        )))
        .add_proposal(Proposal::AppDataUpdate(Box::new(
            AppDataUpdateProposal::remove(PRIVATE_DEVICE_GROUP_COMPONENT_ID),
        )))
        .load_psks(provider.storage())
        .unwrap();
    let mut updates = builder.app_data_dictionary_updater();
    updates.set(ComponentData::from_parts(
        APP_COMPONENTS_COMPONENT_ID,
        list.into(),
    ));
    updates.remove(&PRIVATE_DEVICE_GROUP_COMPONENT_ID);
    builder.with_app_data_dictionary_updates(updates.changes());
    let (commit, _, _) = builder
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .unwrap()
        .stage_commit(&provider)
        .unwrap()
        .into_contents();
    let bytes = commit.tls_serialize_detached().unwrap();
    source.merge_pending_commit(&provider).unwrap();
    TransportMessage {
        id: hash_id(&bytes),
        payload: bytes,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("isolated-authenticated-marker-removal".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group.as_slice().to_vec(),
        },
    }
}

/// Actual MLS + encrypted SQL with injected trusted Engine policies. No SAS claim.
#[tokio::test]
async fn private_historical_marker_removal_and_selection_replacement_remains_hidden_after_reopen() {
    use cgka_traits::device_group_genesis::PRIVATE_DEVICE_GROUP_COMPONENT_ID;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("historical-private.sqlite");
    let key = storage_sqlite::SqlCipherKey::new("8b".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut first = fixture(storage.clone()).await;
    confirm_fixture_and_join(&mut first).await;
    let old_group = first.policy.context.group_id.clone();
    assert!(
        first
            .recipient
            .exclude_private_group_from_chat(&old_group)
            .unwrap()
    );
    let change =
        signed_private_marker_removal(&first.creator, &old_group, &first.policy.context.approver);
    first.recipient.ingest(change).await.unwrap();
    first
        .recipient
        .advance_convergence_inputs_until_settled(&old_group, 2_000_000)
        .await
        .unwrap();
    assert_eq!(first.recipient.epoch(&old_group).unwrap().0, 2);
    assert!(
        first
            .recipient
            .app_component(&old_group, PRIVATE_DEVICE_GROUP_COMPONENT_ID)
            .unwrap()
            .is_none(),
        "actual authenticated selected tree must remove private marker"
    );
    assert!(
        storage
            .accepted_device_group_anchor_storage()
            .unwrap()
            .accepted_anchor()
            .unwrap()
            .unwrap()
            .denied
    );
    drop(first);
    // A genuinely fresh selected private join is permitted after permanent denial.
    let mut second = fixture(storage.clone()).await;
    confirm_fixture_and_join(&mut second).await;
    assert!(second.policy.context.group_id != old_group);
    assert!(
        storage
            .accepted_device_group_anchor_storage()
            .unwrap()
            .accepted_anchor()
            .unwrap()
            .unwrap()
            .draft
            .group_id
            != old_group
    );
    drop(second);
    drop(storage);
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut observer = batch_client(reopened);
    observer.hydrate_all_stored_groups().unwrap();
    assert!(
        observer
            .app_component(&old_group, PRIVATE_DEVICE_GROUP_COMPONENT_ID)
            .unwrap()
            .is_none()
    );
    assert!(
        observer
            .exclude_private_group_from_chat(&old_group)
            .unwrap(),
        "private birth/join must permanently suppress chat after authenticated marker removal and selected-ledger replacement"
    );
}

#[tokio::test]
async fn private_batch_privacy_write_fault_rolls_back_crypto_anchor_and_exact_retry() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("private-privacy-join-fault.sqlite");
    let key = storage_sqlite::SqlCipherKey::new("7d".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut f = fixture(storage.clone()).await;
    // Genuine outgoing confirmation; the recipient is still unjoined.
    let group = f.policy.context.group_id.clone();
    let echo = f
        .creator
        .private_device_invite_storage()
        .unwrap()
        .private_invite()
        .unwrap()
        .unwrap()
        .transport
        .unwrap()
        .commit;
    let publisher = ObservedPublisher(AtomicUsize::new(0));
    f.approver
        .dispatch_prepared_private_device_invite(&mut f.prepared, &publisher)
        .await
        .unwrap();
    f.approver.ingest(echo).await.unwrap();
    f.recipient
        .install_trusted_linking_welcome_policy(Arc::new(f.policy.clone()));
    let injector = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &injector,
        &key,
        storage_sqlite::SqlCipherHardening::default(),
    )
    .unwrap();
    injector.execute_batch("CREATE TRIGGER fail_private_privacy BEFORE INSERT ON private_group_chat_exclusion BEGIN SELECT RAISE(ABORT,'isolated private privacy failure'); END;").unwrap();
    let result = f
        .recipient
        .join_private_linking_welcome_batch(f.messages.clone(), &f.policy.context)
        .await;
    assert!(
        matches!(result, Err(cgka_traits::EngineError::Storage(_))),
        "privacy persistence must preserve typed backend failure"
    );
    assert!(storage.list_groups().unwrap().is_empty());
    assert!(
        storage
            .accepted_device_group_anchor_storage()
            .unwrap()
            .accepted_anchor()
            .unwrap()
            .is_none()
    );
    assert!(
        storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .is_some()
    );
    assert!(
        !storage
            .private_group_privacy_storage()
            .unwrap()
            .private_group_chat_excluded(
                &f.policy.purpose.scope.account,
                &f.policy.purpose.scope.local_device,
                &group
            )
            .unwrap()
    );
    assert!(
        !storage
            .device_linking_key_package_storage()
            .unwrap()
            .purpose_key_package()
            .unwrap()
            .unwrap()
            .consumed
    );
    injector
        .execute_batch("DROP TRIGGER fail_private_privacy")
        .unwrap();
    let policy = f.policy.clone();
    let messages = f.messages.clone();
    drop(injector);
    drop(f);
    drop(storage);
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut recipient = batch_client(reopened);
    recipient.install_trusted_linking_welcome_policy(Arc::new(policy.clone()));
    recipient
        .join_private_linking_welcome_batch(messages, &policy.context)
        .await
        .unwrap();
    assert!(recipient.exclude_private_group_from_chat(&group).unwrap());
}
