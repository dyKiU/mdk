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
    assert!(matches!(
        materialize(
            &observer_store,
            &group,
            vec![a.clone(), proposal.clone(), successor]
        ),
        Err(OpenMlsProjectionError::Replay(_))
    ));
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
