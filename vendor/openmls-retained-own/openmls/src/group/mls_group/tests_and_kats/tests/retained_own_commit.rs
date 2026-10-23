use crate::{credentials::test_utils::new_credential, prelude::*};
use openmls_rust_crypto::OpenMlsRustCrypto;

#[test]
fn retained_own_commit_expired_add_is_authenticated_without_fresh_admission() {
    let provider = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let (alice, signer) = new_credential(&provider, b"retained-own-A", suite.signature_algorithm());
    let (bob, bob_signer) =
        new_credential(&provider, b"retained-own-B", suite.signature_algorithm());
    let lifetime = Lifetime::new(3);
    let package = KeyPackage::builder()
        .key_package_lifetime(lifetime)
        .build(suite, &provider, &bob_signer, bob)
        .unwrap();
    let mut group = MlsGroup::builder()
        .ciphersuite(suite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(&provider, &signer, alice)
        .unwrap();
    group.set_aad(b"retained-exact-aad".to_vec());
    let (commit, _, _) = group
        .add_members(
            &provider,
            &signer,
            std::slice::from_ref(package.key_package()),
        )
        .unwrap();
    let message = MlsMessageIn::from(commit).into_protocol_message().unwrap();
    while std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        <= lifetime.not_after()
    {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let (provider, mut group) = encrypted_reopen(provider, group);
    assert_expired(group.process_message(&provider, message.clone()));
    let processed = group
        .process_retained_own_commit(&provider, message)
        .expect("previously valid exact pending own Add must reconcile after expiry");
    assert_eq!(processed.aad(), b"retained-exact-aad");
    assert!(matches!(
        processed.into_content(),
        ProcessedMessageContent::OwnPendingCommit
    ));
    assert!(group.pending_commit().is_some());
    group.merge_pending_commit(&provider).unwrap();
    assert_eq!(group.members().count(), 2);
}

fn pending_add() -> (
    OpenMlsRustCrypto,
    openmls_basic_credential::SignatureKeyPair,
    MlsGroup,
    ProtocolMessage,
) {
    let provider = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let (alice, signer) = new_credential(&provider, b"pending-A", suite.signature_algorithm());
    let (bob, bob_signer) = new_credential(&provider, b"pending-B", suite.signature_algorithm());
    let package = KeyPackage::builder()
        .build(suite, &provider, &bob_signer, bob)
        .unwrap();
    let mut group = MlsGroup::builder()
        .ciphersuite(suite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(&provider, &signer, alice)
        .unwrap();
    let (commit, _, _) = group
        .add_members(
            &provider,
            &signer,
            std::slice::from_ref(package.key_package()),
        )
        .unwrap();
    (
        provider,
        signer,
        group,
        MlsMessageIn::from(commit).into_protocol_message().unwrap(),
    )
}

#[test]
fn retained_own_commit_clear_replace_merge_and_missing_receipt_deny_old_content() {
    let (provider, signer, mut group, old) = pending_add();
    let group_id = group.group_id().clone();
    group.clear_pending_commit(provider.storage()).unwrap();
    let mut reopened = MlsGroup::load(provider.storage(), &group_id)
        .unwrap()
        .unwrap();
    assert!(reopened
        .process_retained_own_commit(&provider, old.clone())
        .is_err());
    let suite = group.ciphersuite();
    let (bob, bob_signer) = new_credential(&provider, b"replacement", suite.signature_algorithm());
    let package = KeyPackage::builder()
        .build(suite, &provider, &bob_signer, bob)
        .unwrap();
    let (next, _, _) = reopened
        .add_members(
            &provider,
            &signer,
            std::slice::from_ref(package.key_package()),
        )
        .unwrap();
    let next = MlsMessageIn::from(next).into_protocol_message().unwrap();
    assert!(reopened
        .process_retained_own_commit(&provider, old)
        .is_err());
    assert!(reopened
        .process_retained_own_commit(&provider, next.clone())
        .is_ok());
    // Simulate an older pending row which never retained content: no reconstruction.
    if let MlsGroupState::PendingCommit(pending) = &mut reopened.group_state {
        if let crate::group::mls_group::PendingCommitState::Member(staged) = pending.as_mut() {
            staged.retained_own_content = None;
        }
    }
    assert!(reopened
        .process_retained_own_commit(&provider, next.clone())
        .is_err());
    assert!(reopened.process_message(&provider, next.clone()).is_ok());
    reopened.merge_pending_commit(&provider).unwrap();
    assert!(reopened
        .process_retained_own_commit(&provider, next)
        .is_err());
}

#[test]
fn retained_own_commit_rejects_membership_epoch_sender_and_confirmation_tampering() {
    let (provider, _, mut group, message) = pending_add();
    let ProtocolMessage::PublicMessage(original) = message.clone() else {
        panic!("public fixture");
    };
    let mut bad = original.clone();
    bad.unset_membership_tag();
    assert!(group
        .process_retained_own_commit(&provider, ProtocolMessage::PublicMessage(bad))
        .is_err());
    let mut bad = original.clone();
    bad.set_epoch(group.epoch().as_u64() + 1);
    assert!(group
        .process_retained_own_commit(&provider, ProtocolMessage::PublicMessage(bad))
        .is_err());
    let mut bad = original.clone();
    bad.set_sender(Sender::Member(LeafNodeIndex::new(44)));
    assert!(group
        .process_retained_own_commit(&provider, ProtocolMessage::PublicMessage(bad))
        .is_err());
    let mut bad = original;
    bad.set_confirmation_tag(None);
    assert!(group
        .process_retained_own_commit(&provider, ProtocolMessage::PublicMessage(bad))
        .is_err());
    assert!(group
        .process_retained_own_commit(&provider, message)
        .is_ok());
}

#[test]
fn own_echo_router_retained_receipt_never_falls_back_for_resigned_aad() {
    use crate::test_utils::frankenstein::FrankenPublicMessage;
    use tls_codec::{Deserialize as _, Serialize as _};
    let (provider, signer, mut group, message) = pending_add();
    let ProtocolMessage::PublicMessage(public) = message.clone() else {
        panic!("public fixture");
    };
    let bytes = public.tls_serialize_detached().unwrap();
    let original = FrankenPublicMessage::tls_deserialize_exact(&bytes).unwrap();
    let mut content = original.content.clone();
    content.authenticated_data = b"changed authenticated data".to_vec().into();
    let context = group.export_group_context().clone().into();
    let modified = FrankenPublicMessage::auth(
        &provider,
        group.ciphersuite(),
        &signer,
        content,
        Some(&context),
        Some(group.message_secrets().membership_key().as_slice()),
        original.auth.confirmation_tag.clone(),
    );
    let modified = ProtocolMessage::from(crate::framing::PublicMessage::from(modified));
    // The ordinary tag-only own-commit check accepts this correctly signed input.
    assert!(group.process_message(&provider, modified.clone()).is_ok());
    assert!(group
        .process_own_commit_echo(&provider, modified.clone())
        .is_err());
    assert!(group
        .process_retained_own_commit(&provider, modified)
        .is_err());
    assert!(group
        .process_retained_own_commit(&provider, message)
        .is_ok());
}

#[test]
fn retained_own_commit_encrypted_snapshot_reopen_preserves_exact_match() {
    let (provider, _, group, message) = pending_add();
    let (provider, mut group) = encrypted_reopen(provider, group);
    assert!(group
        .process_retained_own_commit(&provider, message)
        .is_ok());
    group.merge_pending_commit(&provider).unwrap();
    assert_eq!(group.members().count(), 2);
}

#[test]
fn retained_own_commit_verifies_signature_even_with_recomputed_membership_tag() {
    use crate::test_utils::frankenstein::FrankenPublicMessage;
    use tls_codec::{Deserialize as _, Serialize as _};
    let (provider, _, mut group, message) = pending_add();
    let ProtocolMessage::PublicMessage(public) = message.clone() else {
        panic!("public fixture");
    };
    let bytes = public.tls_serialize_detached().unwrap();
    let mut modified = FrankenPublicMessage::tls_deserialize_exact(&bytes).unwrap();
    let mut signature = Vec::from(modified.auth.signature.clone());
    signature[0] ^= 1;
    modified.auth.signature = signature.into();
    let ProtocolMessage::PublicMessage(mut modified) =
        ProtocolMessage::from(crate::framing::PublicMessage::from(modified))
    else {
        panic!("public fixture");
    };
    modified
        .set_membership_tag(
            &provider,
            group.ciphersuite(),
            group.message_secrets().membership_key(),
            group.message_secrets().serialized_context(),
        )
        .unwrap();
    let error = group
        .process_retained_own_commit(&provider, ProtocolMessage::PublicMessage(modified))
        .unwrap_err();
    assert!(matches!(
        error,
        ProcessMessageError::ValidationError(ValidationError::InvalidSignature)
    ));
    assert!(group
        .process_retained_own_commit(&provider, message)
        .is_ok());
}

#[test]
fn retained_own_commit_does_not_admit_nonown_expired_add() {
    use crate::group::mls_group::tests_and_kats::utils::setup_alice_bob_group;
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let (mut alice, alice_signer, mut bob, bob_signer, _, _) =
        setup_alice_bob_group(suite, &alice_provider, &bob_provider);
    let (carol, carol_signer) =
        new_credential(&alice_provider, b"fresh Carol", suite.signature_algorithm());
    let lifetime = Lifetime::new(3);
    let carol = KeyPackage::builder()
        .key_package_lifetime(lifetime)
        .build(suite, &alice_provider, &carol_signer, carol)
        .unwrap();
    let (alice_commit, _, _) = alice
        .add_members(
            &alice_provider,
            &alice_signer,
            std::slice::from_ref(carol.key_package()),
        )
        .unwrap();
    let (dave, dave_signer) =
        new_credential(&bob_provider, b"own Dave", suite.signature_algorithm());
    let dave = KeyPackage::builder()
        .build(suite, &bob_provider, &dave_signer, dave)
        .unwrap();
    let (bob_commit, _, _) = bob
        .add_members(
            &bob_provider,
            &bob_signer,
            std::slice::from_ref(dave.key_package()),
        )
        .unwrap();
    let foreign = MlsMessageIn::from(alice_commit)
        .into_protocol_message()
        .unwrap();
    while std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        <= lifetime.not_after()
    {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_expired(bob.process_message(&bob_provider, foreign.clone()));
    assert!(bob
        .process_own_commit_echo(&bob_provider, foreign.clone())
        .is_err());
    assert!(bob
        .process_retained_own_commit(&bob_provider, foreign)
        .is_err());
    let own = MlsMessageIn::from(bob_commit)
        .into_protocol_message()
        .unwrap();
    assert!(bob.process_retained_own_commit(&bob_provider, own).is_ok());
}

#[test]
fn retained_own_commit_rejects_private_own_ciphertext_and_oversized_content() {
    let provider = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let (alice, signer) = new_credential(&provider, b"private A", suite.signature_algorithm());
    let (bob, bob_signer) = new_credential(&provider, b"private B", suite.signature_algorithm());
    let bob = KeyPackage::builder()
        .build(suite, &provider, &bob_signer, bob)
        .unwrap();
    let mut private = MlsGroup::builder()
        .ciphersuite(suite)
        .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build(&provider, &signer, alice)
        .unwrap();
    let (commit, _, _) = private
        .add_members(&provider, &signer, std::slice::from_ref(bob.key_package()))
        .unwrap();
    let commit = MlsMessageIn::from(commit).into_protocol_message().unwrap();
    assert!(private
        .process_retained_own_commit(&provider, commit.clone())
        .is_err());
    assert!(matches!(
        private
            .process_message(&provider, commit)
            .unwrap()
            .into_content(),
        ProcessedMessageContent::OwnPrivateMessage
    ));
    let (provider, signer, mut group, _) = pending_add();
    group.clear_pending_commit(provider.storage()).unwrap();
    group.set_aad(vec![
        0;
        crate::group::mls_group::processing::MAX_RETAINED_OWN_CONTENT
            + 1
    ]);
    let (bob, bob_signer) = new_credential(&provider, b"bounded B", suite.signature_algorithm());
    let package = KeyPackage::builder()
        .build(suite, &provider, &bob_signer, bob)
        .unwrap();
    let (commit, _, _) = group
        .add_members(
            &provider,
            &signer,
            std::slice::from_ref(package.key_package()),
        )
        .unwrap();
    let commit = MlsMessageIn::from(commit).into_protocol_message().unwrap();
    assert!(group
        .process_retained_own_commit(&provider, commit.clone())
        .is_err());
    assert!(group.process_message(&provider, commit).is_ok());
}

fn encrypted_reopen(provider: OpenMlsRustCrypto, group: MlsGroup) -> (OpenMlsRustCrypto, MlsGroup) {
    use openmls_traits::{crypto::OpenMlsCrypto as _, random::OpenMlsRand as _, types::AeadType};
    let group_id = group.group_id().clone();
    let mut bytes = Vec::new();
    provider.storage().serialize(&mut bytes).unwrap();
    let key = provider.rand().random_vec(16).unwrap();
    let nonce = provider.rand().random_vec(12).unwrap();
    let aad = b"isolated provider encrypted reopen";
    let ciphertext = provider
        .crypto()
        .aead_encrypt(AeadType::Aes128Gcm, &key, &bytes, &nonce, aad)
        .unwrap();
    drop(group);
    drop(provider);
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), ciphertext).unwrap();
    let provider = OpenMlsRustCrypto::default();
    let ciphertext = std::fs::read(file.path()).unwrap();
    assert!(provider
        .crypto()
        .aead_decrypt(AeadType::Aes128Gcm, &key, &ciphertext, &nonce, b"wrong aad")
        .is_err());
    let plaintext = provider
        .crypto()
        .aead_decrypt(AeadType::Aes128Gcm, &key, &ciphertext, &nonce, aad)
        .unwrap();
    let restored =
        openmls_rust_crypto::MemoryStorage::deserialize(&mut plaintext.as_slice()).unwrap();
    *provider.storage().values.write().unwrap() = restored.values.into_inner().unwrap();
    let group = MlsGroup::load(provider.storage(), &group_id)
        .unwrap()
        .unwrap();
    (provider, group)
}

#[test]
fn retained_own_commit_rejects_resigned_path_proposal_and_group_substitution() {
    use crate::test_utils::frankenstein::{FrankenFramedContentBody, FrankenPublicMessage};
    use tls_codec::{Deserialize as _, Serialize as _};
    let (provider, signer, mut group, _) = pending_add();
    group.clear_pending_commit(provider.storage()).unwrap();
    let (bob, bob_signer) = new_credential(
        &provider,
        b"path B",
        group.ciphersuite().signature_algorithm(),
    );
    let package = KeyPackage::builder()
        .build(group.ciphersuite(), &provider, &bob_signer, bob)
        .unwrap();
    let commit = group
        .commit_builder()
        .consume_proposal_store(false)
        .force_self_update(true)
        .propose_adds([package.key_package().clone()])
        .load_psks(provider.storage())
        .unwrap()
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .unwrap()
        .stage_commit(&provider)
        .unwrap()
        .into_commit();
    let message = MlsMessageIn::from(commit).into_protocol_message().unwrap();
    let ProtocolMessage::PublicMessage(public) = message.clone() else {
        panic!("public fixture");
    };
    let bytes = public.tls_serialize_detached().unwrap();
    let original = FrankenPublicMessage::tls_deserialize_exact(&bytes).unwrap();
    let context = group.export_group_context().clone().into();
    for variant in 0..5 {
        let mut content = original.content.clone();
        let mut tag = original.auth.confirmation_tag.clone();
        let FrankenFramedContentBody::Commit(commit) = &mut content.body else {
            panic!("commit fixture");
        };
        assert!(commit.path.is_some(), "actual forced update path required");
        match variant {
            0 => commit.path = None,
            1 => commit.proposals.clear(),
            2 => content.group_id = b"other group".to_vec().into(),
            3 => {
                let mut bytes = Vec::from(tag.unwrap());
                bytes[0] ^= 1;
                tag = Some(bytes.into());
            }
            4 => {
                content.authenticated_data =
                    vec![0; crate::group::mls_group::processing::MAX_RETAINED_OWN_CONTENT + 1]
                        .into()
            }
            _ => unreachable!(),
        }
        let modified = FrankenPublicMessage::auth(
            &provider,
            group.ciphersuite(),
            &signer,
            content,
            Some(&context),
            Some(group.message_secrets().membership_key().as_slice()),
            tag,
        );
        let modified = ProtocolMessage::from(crate::framing::PublicMessage::from(modified));
        assert!(group
            .process_retained_own_commit(&provider, modified)
            .is_err());
    }
    assert!(group
        .process_retained_own_commit(&provider, message)
        .is_ok());
}

fn assert_expired<T>(
    result: Result<T, ProcessMessageError<openmls_rust_crypto::MemoryStorageError>>,
) {
    use crate::{key_packages::errors::KeyPackageVerifyError, treesync::errors::LifetimeError};
    assert!(
        matches!(
            result,
            Err(ProcessMessageError::ValidationError(
                ValidationError::KeyPackageVerifyError(KeyPackageVerifyError::LifetimeError(
                    LifetimeError::Expired { .. }
                ))
            ))
        ),
        "ordinary API must reject actual lifetime expiry"
    );
}

#[test]
fn retained_own_storage_ordinary_pending_commit_roundtrips_messagepack() {
    let (provider, signer, mut group, _) = pending_add();
    group.merge_pending_commit(&provider).unwrap();
    group
        .self_update(&provider, &signer, LeafNodeParameters::default())
        .unwrap();
    let staged = group.pending_commit().unwrap();
    assert!(staged.retained_own_content.is_none());
    let encoded = rmp_serde::to_vec(staged).unwrap();
    let decoded: StagedCommit = rmp_serde::from_slice(&encoded)
        .expect("ordinary pending commits must reopen without retained content");
    assert_eq!(&decoded, staged);
}

#[test]
fn retained_own_storage_legacy_pending_commit_decodes_without_inventing_receipt() {
    let (_, _, group, _) = pending_add();
    let staged = group.pending_commit().unwrap();
    // Stock StagedCommit was serialized as these two positional fields.
    let legacy = rmp_serde::to_vec(&(&staged.staged_proposal_queue, &staged.state)).unwrap();
    let decoded: StagedCommit = rmp_serde::from_slice(&legacy)
        .expect("the stock pending representation must remain readable");
    assert!(decoded.retained_own_content.is_none());
    assert_eq!(decoded.staged_proposal_queue, staged.staged_proposal_queue);
    assert_eq!(decoded.state, staged.state);
}

#[test]
fn retained_own_storage_exact_add_receipt_roundtrips_messagepack() {
    let (_, _, group, _) = pending_add();
    let staged = group.pending_commit().unwrap();
    assert!(staged.retained_own_content.is_some());
    let encoded = rmp_serde::to_vec(staged).unwrap();
    let decoded: StagedCommit = rmp_serde::from_slice(&encoded).unwrap();
    assert_eq!(&decoded, staged);
}

fn replace_with_stock_pending(group: &mut MlsGroup, provider: &OpenMlsRustCrypto) {
    let MlsGroupState::PendingCommit(pending) = &mut group.group_state else {
        panic!("actual pending fixture required");
    };
    let crate::group::mls_group::PendingCommitState::Member(staged) = pending.as_mut() else {
        panic!("actual member pending fixture required");
    };
    let stock = rmp_serde::to_vec(&(&staged.staged_proposal_queue, &staged.state)).unwrap();
    *staged = rmp_serde::from_slice(&stock).unwrap();
    assert!(staged.retained_own_content.is_none());
    group.store(provider.storage()).unwrap();
}

#[test]
fn own_echo_router_stock_pending_encrypted_reopen_validates_unexpired_echo() {
    let (provider, _, mut group, message) = pending_add();
    replace_with_stock_pending(&mut group, &provider);
    let (provider, mut group) = encrypted_reopen(provider, group);
    assert!(group
        .process_retained_own_commit(&provider, message.clone())
        .is_err());
    let processed = group.process_own_commit_echo(&provider, message).unwrap();
    assert!(matches!(
        processed.into_content(),
        ProcessedMessageContent::OwnPendingCommit
    ));
    group.merge_pending_commit(&provider).unwrap();
    assert_eq!(group.members().count(), 2);
}

#[test]
fn own_echo_router_stock_pending_rejects_expired_add_without_receipt() {
    let provider = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let (alice, signer) =
        new_credential(&provider, b"legacy lifetime A", suite.signature_algorithm());
    let (bob, bob_signer) =
        new_credential(&provider, b"legacy lifetime B", suite.signature_algorithm());
    let lifetime = Lifetime::new(3);
    let package = KeyPackage::builder()
        .key_package_lifetime(lifetime)
        .build(suite, &provider, &bob_signer, bob)
        .unwrap();
    let mut group = MlsGroup::builder()
        .ciphersuite(suite)
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build(&provider, &signer, alice)
        .unwrap();
    let (commit, _, _) = group
        .add_members(
            &provider,
            &signer,
            std::slice::from_ref(package.key_package()),
        )
        .unwrap();
    let message = MlsMessageIn::from(commit).into_protocol_message().unwrap();
    replace_with_stock_pending(&mut group, &provider);
    let (provider, mut group) = encrypted_reopen(provider, group);
    while std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        <= lifetime.not_after()
    {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_expired(group.process_own_commit_echo(&provider, message.clone()));
    assert!(group
        .process_retained_own_commit(&provider, message)
        .is_err());
    assert_eq!(group.epoch().as_u64(), 0);
    assert!(group.pending_commit().is_some());
}

#[test]
fn own_echo_router_stock_pending_rejects_signature_tag_epoch_and_missing_pending() {
    use crate::test_utils::frankenstein::FrankenPublicMessage;
    use tls_codec::{Deserialize as _, Serialize as _};
    let (provider, _, mut group, message) = pending_add();
    replace_with_stock_pending(&mut group, &provider);
    let ProtocolMessage::PublicMessage(original) = message.clone() else {
        panic!("public fixture");
    };
    let mut signed =
        FrankenPublicMessage::tls_deserialize_exact(original.tls_serialize_detached().unwrap())
            .unwrap();
    let mut signature = Vec::from(signed.auth.signature.clone());
    signature[0] ^= 1;
    signed.auth.signature = signature.into();
    let ProtocolMessage::PublicMessage(mut bad) =
        ProtocolMessage::from(crate::framing::PublicMessage::from(signed))
    else {
        panic!("public fixture");
    };
    bad.set_membership_tag(
        &provider,
        group.ciphersuite(),
        group.message_secrets().membership_key(),
        group.message_secrets().serialized_context(),
    )
    .unwrap();
    assert!(matches!(
        group.process_own_commit_echo(&provider, ProtocolMessage::PublicMessage(bad)),
        Err(ProcessMessageError::ValidationError(
            ValidationError::InvalidSignature
        ))
    ));
    let mut bad = original.clone();
    bad.set_confirmation_tag(None);
    assert!(group
        .process_own_commit_echo(&provider, ProtocolMessage::PublicMessage(bad))
        .is_err());
    let mut bad = original.clone();
    bad.set_epoch(group.epoch().as_u64() + 1);
    assert!(group
        .process_own_commit_echo(&provider, ProtocolMessage::PublicMessage(bad))
        .is_err());
    let mut bad = original;
    bad.set_sender(Sender::Member(LeafNodeIndex::new(44)));
    assert!(group
        .process_own_commit_echo(&provider, ProtocolMessage::PublicMessage(bad))
        .is_err());
    assert!(group
        .process_own_commit_echo(&provider, message.clone())
        .is_ok());
    group.clear_pending_commit(provider.storage()).unwrap();
    assert!(group.process_own_commit_echo(&provider, message).is_err());
}
