//! Real by-reference dependencies arriving through public collecting passes.
use super::*;
use cgka_traits::convergence_pass::ConvergencePassPhase;

fn proposal_refs(group: &MlsGroup) -> Vec<String> {
    let queued: Vec<_> = if let Some(commit) = group.pending_commit() {
        commit.queued_proposals().collect()
    } else {
        group.pending_proposals().collect()
    };
    queued
        .into_iter()
        .map(|proposal| {
            hex::encode(
                proposal
                    .proposal_reference_ref()
                    .tls_serialize_detached()
                    .unwrap(),
            )
        })
        .collect()
}

async fn required_proposal_public_pass(processed_first: bool) {
    let (mut first, first_storage) = build_client(b"alice");
    let (mut second, second_storage) = build_client(b"carol");
    let (mut leaver, _) = build_client(b"bob");
    let leaver_kp = leaver.fresh_key_package().await.unwrap();
    let second_kp = second.fresh_key_package().await.unwrap();
    let (group, create) = first
        .create_group(CreateGroupRequest {
            name: "required-proposal-public-pass".into(),
            description: String::new(),
            members: vec![leaver_kp, second_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        _ => panic!("actual create must publish real welcomes"),
    };
    first.confirm_published(pending).await.unwrap();
    leaver
        .join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    second
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    let leave = route(
        proposal(
            leaver
                .send(SendIntent::Leave {
                    group_id: group.clone(),
                })
                .await
                .unwrap(),
        ),
        &group,
    );
    second.ingest(leave.clone()).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    second.advance_convergence(&group).await.unwrap();
    let outgoing = second
        .drain_auto_publish()
        .into_iter()
        .next()
        .expect("real SelfRemove must yield a by-reference commit");
    let mls_id = openmls::group::GroupId::from_slice(group.as_slice());
    let second_mls = MlsGroup::load(second_storage.mls_storage(), &mls_id)
        .unwrap()
        .unwrap();
    let required_refs = proposal_refs(&second_mls);
    assert_eq!(
        required_refs.len(),
        1,
        "exact genuine SelfRemove reference is required"
    );
    let rival = route(outgoing.msg, &group);
    second.confirm_published(outgoing.pending).await.unwrap();
    let own_record = second_storage.get_message(&rival.id).unwrap();
    let own_payload = StoredMessagePayload::decode(&own_record.payload).unwrap();
    assert!(
        own_payload
            .own_commit_stamp()
            .unwrap()
            .consumed_proposal_refs
            == required_refs,
        "confirmed actual commit must consume the authenticated proposal reference"
    );

    if processed_first {
        first.ingest(leave.clone()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        first.advance_convergence(&group).await.unwrap();
        let own = first
            .drain_auto_publish()
            .into_iter()
            .next()
            .expect("public source must author its real commit");
        let first_mls = MlsGroup::load(first_storage.mls_storage(), &mls_id)
            .unwrap()
            .unwrap();
        assert!(
            proposal_refs(&first_mls) == required_refs,
            "both actual committers must authenticate exactly the same proposal"
        );
        first.confirm_published(own.pending).await.unwrap();
        assert_message_state(&first_storage, &leave, MessageState::Processed);
    }
    let first_mls = MlsGroup::load(first_storage.mls_storage(), &mls_id)
        .unwrap()
        .unwrap();
    let probe = cgka_engine::canonical_probe_observer::Probe::arm(
        group.clone(),
        first_mls.own_leaf_index().u32(),
        content_id(&rival),
    );
    first.ingest(rival.clone()).await.unwrap();
    let pass = first_storage
        .convergence_pass(&group)
        .unwrap()
        .expect("actual commit must open a public pass");
    assert_eq!(pass.phase, ConvergencePassPhase::Collecting);
    if !processed_first {
        first.ingest(leave.clone()).await.unwrap();
        let first_mls = MlsGroup::load(first_storage.mls_storage(), &mls_id)
            .unwrap()
            .unwrap();
        assert!(
            proposal_refs(&first_mls) == required_refs,
            "arrived real packet must authenticate to the exact consumed reference before freeze"
        );
    }
    let retained = first_storage.get_message(&content_id(&leave)).unwrap();
    assert!(
        retained
            .payload
            .as_ref()
            .unwrap()
            .as_openmls_wire()
            .unwrap()
            .payload
            == leave.payload,
        "retained dependency must be the exact genuine proposal packet"
    );
    eprintln!(
        "required_proposal_public_pass_exact_authenticated_reference_matched=true processed_first={processed_first}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    first.advance_convergence(&group).await.unwrap();
    let observation = probe.snapshot();
    eprintln!("required_proposal_public_pass_observation={observation:?}");
    assert!(
        observation.target_eligible,
        "actual by-reference rival must materialize with its exact retained authenticated dependency"
    );
    assert!(
        !first
            .members(&group)
            .unwrap()
            .iter()
            .any(|member| member.id == leaver.self_id()),
        "public convergence must remove the actual leaver"
    );
}

#[tokio::test]
async fn required_proposal_arriving_during_public_collecting_pass_is_admitted() {
    required_proposal_public_pass(false).await;
}

#[tokio::test]
async fn processed_required_proposal_is_collected_for_public_rival_pass() {
    required_proposal_public_pass(true).await;
}
