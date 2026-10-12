//! Canonical branch replacement and its durable leave marker share one transaction.
use super::*;

fn authenticator(storage: &SqliteAccountStorage, group: &GroupId) -> Vec<u8> {
    let group = openmls::group::MlsGroup::load(
        storage.mls_storage(),
        &openmls::group::GroupId::from_slice(group.as_slice()),
    )
    .unwrap()
    .unwrap();
    group.epoch_authenticator().as_slice().to_vec()
}

#[tokio::test]
async fn failed_same_epoch_leave_reanchor_rolls_back_branch_and_reopens_with_original_intent() {
    let identity = b"same-epoch-leave-bob";
    let fault = LeaveWriteFault::default();
    let (mut bob, handle) =
        build_leave_write_fault_client(identity, fault.clone(), Box::new(MockPeeler));
    let mut alice = (0..1024)
        .find_map(|n| {
            let alice = build_selfremove_client(format!("same-epoch-leave-alice-{n}").as_bytes());
            (alice.self_id().as_slice() < bob.self_id().as_slice()).then_some(alice)
        })
        .expect("bounded independent authenticated preferred committer");
    let package = bob.fresh_key_package().await.unwrap();
    let (group, created) = alice
        .create_group(CreateGroupRequest {
            name: "real leave reanchor rollback".into(),
            description: String::new(),
            members: vec![package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated {
        pending,
        mut welcomes,
    } = created
    else {
        panic!("real founding commit required")
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcomes.remove(0)).await.unwrap();
    let winning = next_routed_commit(&mut alice, &group).await;
    let SendResult::GroupEvolution { pending, .. } = bob
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("actual competing commit required")
    };
    bob.confirm_published(pending).await.unwrap();
    assert!(matches!(
        bob.send(SendIntent::Leave {
            group_id: group.clone()
        })
        .await
        .unwrap(),
        SendResult::Proposal { .. }
    ));
    let original = handle.leave_request(&group).unwrap().unwrap();
    let original_branch = authenticator(&handle, &group);
    assert_eq!(
        original.last_proposed_epoch,
        Some(handle.get_group(&group).unwrap().epoch)
    );
    assert!(matches!(
        bob.ingest(winning).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));
    let record = handle.get_group(&group).unwrap();
    fault.arm_on_reanchor();
    let failed = bob.converge_stored_openmls_messages_at(&group, u64::MAX);
    assert!(
        matches!(
            failed,
            Err(cgka_engine::openmls_projection::OpenMlsProjectionError::Storage(_))
        ),
        "actual journal write must fail inside canonical apply"
    );
    assert_eq!(
        fault.remaining(),
        0,
        "the targeted None-marker write was attempted exactly once"
    );
    assert_eq!(authenticator(&handle, &group), original_branch);
    assert_eq!(handle.get_group(&group).unwrap(), record);
    assert_eq!(
        handle.leave_request(&group).unwrap(),
        Some(original.clone())
    );
    assert!(bob.leave_in_progress(&group).unwrap());
    assert!(bob.drain_auto_proposals().is_empty());
    bob.converge_stored_openmls_messages_at(&group, u64::MAX)
        .unwrap();
    assert_ne!(authenticator(&handle, &group), original_branch);
    let reanchored = handle.leave_request(&group).unwrap().unwrap();
    assert_eq!(reanchored.group_id, original.group_id);
    assert_eq!(reanchored.requested_at_ms, original.requested_at_ms);
    assert_eq!(reanchored.last_proposed_epoch, None);
    assert!(bob.drain_auto_proposals().is_empty());
    drop(bob);
    let mut reopened = build_selfremove_client_on_storage(identity, handle.clone());
    reopened.hydrate_all_stored_groups().unwrap();
    assert_eq!(handle.leave_request(&group).unwrap(), Some(reanchored));
    assert!(reopened.leave_in_progress(&group).unwrap());
    assert!(matches!(
        reopened
            .send(SendIntent::Leave {
                group_id: group.clone()
            })
            .await
            .unwrap(),
        SendResult::Proposal { .. }
    ));
    assert_eq!(
        handle
            .leave_request(&group)
            .unwrap()
            .unwrap()
            .requested_at_ms,
        original.requested_at_ms
    );
}
