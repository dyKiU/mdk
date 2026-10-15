use super::*;
use crate::account_identity_proof::{validate_leaf_account_identity_proof_for_member_with_verifier, verify_proof_signature};
use cgka_traits::group::ProtocolProfile;
use nostr::prelude::{FinalizeEvent, Keys};

fn request(keys: &Keys, index: u16) -> AccountIdentityProofRequest {
    AccountIdentityProofRequest {
        account_identity: keys.public_key().to_bytes().to_vec(),
        mls_signature_public_key: index.to_be_bytes().repeat(16),
        ciphersuite: 1,
        signature_scheme: 0x0807,
        created_at: 1_700_000_000,
        protocol_profile: ProtocolProfile::Current,
    }
}

fn signature(keys: &Keys, request: &AccountIdentityProofRequest) -> [u8;64] {
    request.signature_from_signed_event(request.proof_event().unwrap().finalize(keys).unwrap()).unwrap()
}

#[test]
fn private_proof_memo_exact_positive_reuse_and_changed_signature_rejection() {
    let keys = Keys::generate();
    let request = request(&keys, 0);
    let signed = signature(&keys, &request);
    let memo = ProofSignatureMemo::default();
    memo.verify(&request, &signed).unwrap();
    memo.verify(&request, &signed).unwrap();
    assert_eq!(memo.cold_count(), 1, "exact positive proof must reuse actual verification");
    let mut altered = signed;
    altered[0] ^= 1;
    assert!(memo.verify(&request, &altered).is_err(), "changed signature must never reuse warmed proof");
    assert!(memo.verify(&request, &altered).is_err());
    assert_eq!(memo.cold_count(), 3, "negative verification results are never memoized");
}

#[test]
fn private_proof_memo_every_request_field_uses_exact_key_and_default_result() {
    let keys = Keys::generate();
    let original = request(&keys, 0);
    let signed = signature(&keys, &original);
    let mut changed = Vec::new();
    let mut value = original.clone(); value.account_identity = Keys::generate().public_key().to_bytes().to_vec(); changed.push(value);
    let mut value = original.clone(); value.mls_signature_public_key[0] ^= 1; changed.push(value);
    let mut value = original.clone(); value.ciphersuite ^= 1; changed.push(value);
    let mut value = original.clone(); value.signature_scheme ^= 1; changed.push(value);
    let mut value = original.clone(); value.created_at += 1; changed.push(value);
    let mut value = original.clone(); value.created_at = 0; changed.push(value);
    let mut value = original.clone(); value.protocol_profile = ProtocolProfile::Legacy; changed.push(value);
    for value in changed {
        let memo = ProofSignatureMemo::default();
        memo.verify(&original, &signed).unwrap();
        let expected = verify_proof_signature(&value, &signed).map_err(|err| err.to_string());
        let actual = memo.verify(&value, &signed).map_err(|err| err.to_string());
        assert_eq!(actual, expected, "each changed public request field retains original verifier behavior");
        assert_eq!(memo.cold_count(), 2, "each request field participates in exact positive key");
    }
}

#[test]
fn private_proof_memo_legacy_timestamp_is_keyed_without_new_rejection() {
    let keys = Keys::generate();
    let mut original = request(&keys, 0);
    original.protocol_profile = ProtocolProfile::Legacy;
    original.created_at = 0;
    let signed = signature(&keys, &original);
    let memo = ProofSignatureMemo::default();
    memo.verify(&original, &signed).unwrap();
    let mut changed = original.clone(); changed.created_at = 1;
    verify_proof_signature(&changed, &signed).unwrap();
    memo.verify(&changed, &signed).unwrap();
    memo.verify(&changed, &signed).unwrap();
    assert_eq!(memo.cold_count(), 2, "legacy time is an exact-key miss, not a new proof rejection");
}

#[test]
fn private_proof_memo_admission_limits_preserve_legitimate_oversized_verification() {
    let keys = Keys::generate();
    let mut request = request(&keys, 0);
    request.mls_signature_public_key = vec![7;129];
    let signed = signature(&keys, &request);
    let memo = ProofSignatureMemo::default();
    memo.verify(&request, &signed).unwrap();
    memo.verify(&request, &signed).unwrap();
    assert_eq!(memo.cold_count(), 2, "129-byte key bypasses memo but retains valid original proof");
    assert!(memo.entries.lock().unwrap().is_empty());
    request.account_identity.push(0);
    assert!(memo.verify(&request, &signed).is_err());
    assert!(memo.verify(&request, &signed).is_err());
    assert_eq!(memo.cold_count(), 4);
}

#[test]
fn private_proof_memo_capacity_is_bounded_and_fifo_eviction_reverifies() {
    let keys = Keys::generate();
    let memo = ProofSignatureMemo::default();
    let mut first = None;
    let mut last = None;
    for index in 0..=CAPACITY as u16 {
        let request = request(&keys, index);
        let signed = signature(&keys, &request);
        memo.verify(&request, &signed).unwrap();
        if index == 0 { first = Some((request.clone(), signed)); }
        if index == CAPACITY as u16 { last = Some((request, signed)); }
    }
    assert_eq!(memo.entries.lock().unwrap().len(), CAPACITY);
    assert_eq!(memo.cold_count(), CAPACITY + 1);
    let (last, last_signature) = last.unwrap();
    memo.verify(&last, &last_signature).unwrap();
    assert_eq!(memo.cold_count(), CAPACITY + 1, "newest exact signed tuple stays warm");
    let (first, first_signature) = first.unwrap();
    memo.verify(&first, &first_signature).unwrap();
    assert_eq!(memo.cold_count(), CAPACITY + 2, "oldest entry is actually evicted and reverified");
}

#[test]
fn private_proof_memo_poison_falls_back_to_original_verifier() {
    let keys = Keys::generate();
    let request = request(&keys, 0);
    let signed = signature(&keys, &request);
    let memo = ProofSignatureMemo::default();
    memo.verify(&request, &signed).unwrap();
    std::thread::scope(|scope| {
        assert!(scope.spawn(|| {
            let _entries = memo.entries.lock().unwrap();
            panic!("isolated proof memo poison control");
        }).join().is_err());
    });
    memo.verify(&request, &signed).unwrap();
    memo.verify(&request, &signed).unwrap();
    let mut altered = signed; altered[0] ^= 1;
    assert!(memo.verify(&request, &altered).is_err());
    assert_eq!(memo.cold_count(), 4, "poison never grants proof reuse or masks invalid signature");
}

#[tokio::test]
async fn private_proof_memo_is_engine_local_and_preserves_real_leaf_binding_guards() {
    let (first, second, group) = crate::private_roster_settlement::tests::complete_pair(storage_sqlite::SqliteAccountStorage::in_memory().unwrap()).await;
    let first_count = first.private_proof_signatures.cold_count();
    let second_count = second.private_proof_signatures.cold_count();
    assert!(first_count > 0 && second_count > 0, "each real Engine verifies its own actual protected leaves");
    assert!(first.validated_settled_device_roster(&group).unwrap().is_some());
    assert_eq!(first.private_proof_signatures.cold_count(), first_count);
    assert_eq!(second.private_proof_signatures.cold_count(), second_count, "another Engine never shares memo ownership");
    use cgka_traits::StorageProvider;
    let actual = openmls::group::MlsGroup::load(first.storage.mls_storage(), &openmls::group::GroupId::from_slice(group.as_slice())).unwrap().unwrap();
    let tree = actual.export_ratchet_tree();
    let leaf = tree.leaves().next().unwrap();
    let member = crate::identity::validated_member_id_of_leaf(leaf).unwrap();
    let verify = |request: &AccountIdentityProofRequest, signature: &[u8;64]| first.private_proof_signatures.verify(request, signature);
    assert_eq!(validate_leaf_account_identity_proof_for_member_with_verifier(leaf, actual.ciphersuite(), &member, "isolated memo binding", Some(&verify)).unwrap(), ProtocolProfile::Current);
    let wrong_member = cgka_traits::MemberId::new(vec![0;32]);
    assert!(matches!(validate_leaf_account_identity_proof_for_member_with_verifier(leaf, actual.ciphersuite(), &wrong_member, "isolated memo binding", Some(&verify)), Err(EngineError::InvalidAccountIdentityProof(reason)) if reason == "isolated memo binding credential identity does not match existing member identity"), "warm proof never bypasses expected-member comparison");
    assert_eq!(first.private_proof_signatures.cold_count(), first_count, "member comparison remains after the warmed pure-proof callback");
    let wrong_suite = openmls_traits::types::Ciphersuite::try_from(2_u16).unwrap();
    assert!(matches!(validate_leaf_account_identity_proof_for_member_with_verifier(leaf, wrong_suite, &member, "isolated memo binding", Some(&verify)), Err(EngineError::InvalidAccountIdentityProof(reason)) if reason == "proof ciphersuite does not match expected ciphersuite"), "warm proof never bypasses fresh ciphersuite binding");
}
