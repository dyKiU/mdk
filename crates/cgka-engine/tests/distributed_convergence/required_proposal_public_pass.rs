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

async fn required_proposal_public_pass(processed_first: bool, late_proposal: bool) {
    required_proposal_public_pass_with_tail(processed_first, late_proposal, false).await;
}

async fn required_proposal_public_pass_with_tail(
    processed_first: bool,
    late_proposal: bool,
    reopen_tail: bool,
) {
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
    let authenticated_packet = second_storage.get_message(&content_id(&leave)).unwrap();
    assert!(
        StoredMessagePayload::decode(&authenticated_packet.payload)
            .unwrap()
            .as_openmls_wire()
            .unwrap()
            .payload
            == leave.payload,
        "the sole authenticated queued reference must come from this exact genuine packet"
    );
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
    // Storage-only opaque transport decoys exercise the cursor budget, never
    // MLS membership or authenticated graph input. Keep them inert until the
    // genuine public pass has completed.
    let mut decoys = Vec::new();
    if reopen_tail {
        for index in 0u16..65 {
            let id = MessageId::new([b"wake-decoy-".as_slice(), &index.to_be_bytes()].concat());
            first_storage
                .put_message(&MessageRecord {
                    id: id.clone(),
                    group_id: group.clone(),
                    epoch: EpochId(first_mls.epoch().as_u64()),
                    state: MessageState::PeelDeferred,
                    payload: vec![0xff],
                    deferred_peel: None,
                })
                .unwrap();
            decoys.push(id);
        }
    }
    first.ingest(rival.clone()).await.unwrap();
    let pass = first_storage
        .convergence_pass(&group)
        .unwrap()
        .expect("actual commit must open a public pass");
    assert_eq!(pass.phase, ConvergencePassPhase::Collecting);
    if !processed_first && !late_proposal {
        let outcome = first.ingest(leave.clone()).await.unwrap();
        assert!(
            matches!(outcome, IngestOutcome::Processed),
            "the exact packet must pass actual direct Core authentication"
        );
        let collecting = first_storage.convergence_pass(&group).unwrap().unwrap();
        assert_eq!(collecting.phase, ConvergencePassPhase::Collecting);
        eprintln!(
            "required_proposal_direct_authenticated=true collecting_dependency_admitted={} members={}",
            collecting
                .members
                .iter()
                .any(|member| member.message_id == content_id(&leave)),
            collecting.members.len()
        );
        assert_message_state(&first_storage, &leave, MessageState::Created);
    }
    if !late_proposal {
        let retained = first_storage.get_message(&content_id(&leave)).unwrap();
        assert!(
            StoredMessagePayload::decode(&retained.payload)
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
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        first.advance_convergence(&group).await.unwrap();
        for outgoing in first.drain_auto_publish() {
            first.confirm_published(outgoing.pending).await.unwrap();
        }
        if first_storage
            .convergence_pass(&group)
            .unwrap()
            .is_some_and(|pass| pass.phase == ConvergencePassPhase::Completed)
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "public pass must finish through ordinary bounded maintenance"
        );
    }
    if late_proposal {
        let before = probe.snapshot();
        assert!(
            before.failure_category == Some("missing_proposal"),
            "the actual commit must be waiting for its withheld real dependency"
        );
        assert!(
            first
                .members(&group)
                .unwrap()
                .iter()
                .any(|member| member.id == leaver.self_id()),
            "the incomplete commit must not invent removal before its real proposal arrives"
        );
        for id in &decoys {
            first_storage
                .update_message_state(id, MessageState::ConvergenceDeferred)
                .unwrap();
        }
        let outcome = first.ingest(leave.clone()).await.unwrap();
        assert!(
            matches!(outcome, IngestOutcome::Processed),
            "late exact packet must pass genuine direct authentication"
        );
        let retained = first_storage.get_message(&content_id(&leave)).unwrap();
        assert!(
            StoredMessagePayload::decode(&retained.payload)
                .unwrap()
                .as_openmls_wire()
                .unwrap()
                .payload
                == leave.payload,
            "late retained packet must be the exact packet tied to the authenticated consumed reference"
        );
        eprintln!(
            "required_proposal_late_actual_authenticated_reference_matched=true completed_before_arrival=true"
        );
        if reopen_tail {
            let pass = first_storage.convergence_pass(&group).unwrap().unwrap();
            assert_eq!(
                pass.proposal_dependency_wakes.len(),
                1,
                "bounded scan must persist its unfinished job"
            );
            assert!(
                pass.proposal_dependency_wakes[0].after.is_some(),
                "first page must persist a cursor"
            );
            assert!(
                !probe.snapshot().target_eligible,
                "the genuine target lies beyond the first bounded page"
            );
            drop(first);
            first = build_client_with_storage(b"alice", first_storage.clone());
            eprintln!("required_proposal_tail_cursor_reopened=true decoys=65");
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            first.advance_convergence(&group).await.unwrap();
            for outgoing in first.drain_auto_publish() {
                first.confirm_published(outgoing.pending).await.unwrap();
            }
            if probe.snapshot().target_eligible
                && first_storage
                    .convergence_pass(&group)
                    .unwrap()
                    .is_some_and(|pass| pass.phase == ConvergencePassPhase::Completed)
            {
                break;
            }
        }
    }
    if reopen_tail {
        for id in &decoys {
            assert_ne!(
                first_storage.get_message(id).unwrap().state,
                MessageState::Retryable,
                "opaque decoy must never gain activation"
            );
        }
        assert!(
            first_storage
                .convergence_pass(&group)
                .unwrap()
                .unwrap()
                .proposal_dependency_wakes
                .is_empty(),
            "complete scan must retire its durable wake job"
        );
    }
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
    required_proposal_public_pass(false, false).await;
}

#[tokio::test]
async fn processed_required_proposal_is_collected_for_public_rival_pass() {
    required_proposal_public_pass(true, false).await;
}

#[tokio::test]
async fn required_proposal_arriving_after_public_pass_completion_reconsiders_its_commit() {
    required_proposal_public_pass(false, true).await;
}

#[tokio::test]
async fn late_required_proposal_wake_resumes_beyond_page_after_engine_reopen() {
    required_proposal_public_pass_with_tail(false, true, true).await;
}
