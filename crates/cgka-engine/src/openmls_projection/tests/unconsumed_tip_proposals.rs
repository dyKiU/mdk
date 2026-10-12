//! Real MLS branch-relative tip evidence and strict dependency controls.
use super::*;
use crate::openmls_projection::{
    OpenMlsCandidatePath, OpenMlsProjectionError, OpenMlsReplayObservation,
    materialize_openmls_candidate_paths,
};
use openmls::prelude::LeafNodeParameters;

fn update_proposal(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group: &GroupId,
) -> TransportMessage {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let binding = storage.account_device_signer(sender).unwrap().unwrap();
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        &binding.mls_signature_public_key,
        DEFAULT_CIPHERSUITE.signature_algorithm(),
    )
    .unwrap();
    let mut mls = MlsGroup::load(
        provider.storage(),
        &openmls::group::GroupId::from_slice(group.as_slice()),
    )
    .unwrap()
    .unwrap();
    let (proposal, _) = mls
        .propose_self_update(&provider, &signer, LeafNodeParameters::default())
        .unwrap();
    transport_message(
        &proposal.tls_serialize_detached().unwrap(),
        TransportEnvelope::GroupMessage {
            transport_group_id: group.as_slice().to_vec(),
        },
    )
}

fn materialize(
    storage: &SqliteAccountStorage,
    group: &GroupId,
    messages: Vec<TransportMessage>,
) -> Result<Vec<crate::openmls_projection::OpenMlsMaterializedCandidate>, OpenMlsProjectionError> {
    materialize_openmls_candidate_paths(
        storage,
        group,
        &[OpenMlsCandidatePath {
            branch_id: "actual-candidate".into(),
            messages,
        }],
    )
}

#[tokio::test]
async fn real_unmatched_tip_proposal_cannot_veto_a_rival_but_dependencies_remain_strict() {
    let (mut alice, alice_store) = build_client(b"tip-proposal-alice");
    let (mut bob, bob_store) = build_client(b"tip-proposal-bob");
    let (mut carol, carol_store) = build_client(b"tip-proposal-carol");
    let (mut observer, observer_store) = build_client(b"tip-proposal-observer");
    let group = group_with(&mut alice, &mut [&mut bob, &mut carol, &mut observer]).await;
    let initial = replay_state(&observer_store, &group);
    let a = rival_commit_inner(&alice_store, &alice.self_id(), &group, true);
    let b = rival_commit_inner(&carol_store, &carol.self_id(), &group, true);
    adopt_branch(&bob_store, &group, &b);
    let proposal = update_proposal(&bob_store, &bob.self_id(), &group);
    let proposal_id = hex::encode(proposal.id.as_slice());

    let rival = materialize(&observer_store, &group, vec![a.clone(), proposal.clone()]).unwrap();
    assert_eq!(rival.len(), 1);
    assert!(rival[0].observations.iter().any(|o| matches!(o, OpenMlsReplayObservation::Ignored { message_id, .. } if message_id == &proposal_id)));
    assert!(!rival[0].observations.iter().any(|o| matches!(o, OpenMlsReplayObservation::ProposalStored { message_id, .. } if message_id == &proposal_id)));
    assert_eq!(replay_state(&observer_store, &group), initial);

    let own_branch = materialize(&observer_store, &group, vec![b, proposal.clone()]).unwrap();
    assert!(own_branch[0].observations.iter().any(|o| matches!(o, OpenMlsReplayObservation::ProposalStored { message_id, .. } if message_id == &proposal_id)));
    assert_eq!(replay_state(&observer_store, &group), initial);

    let successor = rival_commit_inner(&alice_store, &alice.self_id(), &group, true);
    assert!(
        materialize(
            &observer_store,
            &group,
            vec![a.clone(), proposal.clone(), successor],
        )
        .is_ok(),
        "a later commit with no reference to this rival proposal cannot be vetoed"
    );
    assert_eq!(replay_state(&observer_store, &group), initial);

    let malformed = transport_message(&[0xff, 0x00], proposal.envelope.clone());
    assert!(
        materialize(
            &observer_store,
            &group,
            vec![a.clone(), proposal.clone(), malformed]
        )
        .is_err()
    );
    assert_eq!(replay_state(&observer_store, &group), initial);

    adopt_branch(&observer_store, &group, &a);
    let selected = replay_state(&observer_store, &group);
    assert!(matches!(
        materialize(&observer_store, &group, vec![proposal]),
        Err(OpenMlsProjectionError::Replay(_))
    ));
    assert_eq!(replay_state(&observer_store, &group), selected);
}

fn accept_proposal(storage: &SqliteAccountStorage, group: &GroupId, proposal: &TransportMessage) {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let mut mls = MlsGroup::load(
        provider.storage(),
        &openmls::group::GroupId::from_slice(group.as_slice()),
    )
    .unwrap()
    .unwrap();
    let protocol = MlsMessageIn::tls_deserialize_exact(&proposal.payload)
        .unwrap()
        .try_into_protocol_message()
        .unwrap();
    let ProcessedMessageContent::ProposalMessage(proposal) = mls
        .process_message(&provider, protocol)
        .unwrap()
        .into_content()
    else {
        panic!("real authenticated proposal required")
    };
    mls.store_pending_proposal(provider.storage(), *proposal)
        .unwrap();
}

#[tokio::test]
async fn unrelated_rival_proposal_cannot_veto_a_commit_with_a_real_authenticated_dependency() {
    let (mut alice, alice_store) = build_client(b"referenced-proposal-alice");
    let (mut bob, bob_store) = build_client(b"referenced-proposal-bob");
    let (mut carol, carol_store) = build_client(b"referenced-proposal-carol");
    let (mut observer, observer_store) = build_client(b"referenced-proposal-observer");
    let (mut dependency_author, dependency_store) = build_client(b"referenced-proposal-author");
    let group = group_with(
        &mut alice,
        &mut [&mut bob, &mut carol, &mut observer, &mut dependency_author],
    )
    .await;
    let initial = replay_state(&observer_store, &group);
    let a = rival_commit_inner(&alice_store, &alice.self_id(), &group, true);
    let b = rival_commit_inner(&carol_store, &carol.self_id(), &group, true);
    adopt_branch(&bob_store, &group, &b);
    adopt_branch(&dependency_store, &group, &a);
    let unrelated = update_proposal(&bob_store, &bob.self_id(), &group);
    let dependency = update_proposal(&dependency_store, &dependency_author.self_id(), &group);
    accept_proposal(&alice_store, &group, &dependency);
    let successor = rival_commit_inner(&alice_store, &alice.self_id(), &group, true);
    let valid = materialize(
        &observer_store,
        &group,
        vec![a.clone(), dependency.clone(), successor.clone()],
    )
    .unwrap();
    let dependency_id = hex::encode(dependency.id.as_slice());
    let reference = valid[0]
        .observations
        .iter()
        .find_map(|o| match o {
            OpenMlsReplayObservation::ProposalStored {
                message_id,
                proposal_ref,
                ..
            } if message_id == &dependency_id => Some(proposal_ref),
            _ => None,
        })
        .unwrap();
    assert!(
        valid[0].consumed_proposal_refs.contains(reference),
        "actual successor must cryptographically consume the actual dependency"
    );
    assert_eq!(replay_state(&observer_store, &group), initial);
    assert!(
        materialize(&observer_store, &group, vec![a.clone(), successor.clone()]).is_err(),
        "a missing referenced proposal must remain fatal"
    );
    assert!(
        materialize(
            &observer_store,
            &group,
            vec![a.clone(), unrelated.clone(), successor.clone()]
        )
        .is_err(),
        "unmatched evidence cannot substitute for the genuine dependency"
    );
    assert_eq!(replay_state(&observer_store, &group), initial);
    let with_rival = materialize(
        &observer_store,
        &group,
        vec![a, unrelated, dependency, successor],
    )
    .expect(
        "unrelated losing-branch evidence must not invalidate an authenticated dependent commit",
    );
    assert_eq!(with_rival[0].tip_epoch, valid[0].tip_epoch);
    assert_eq!(with_rival[0].tip_digest, valid[0].tip_digest);
    assert_eq!(replay_state(&observer_store, &group), initial);
}
