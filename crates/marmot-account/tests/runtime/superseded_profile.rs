// Force both real MLS edits to be staged from the same epoch. The host
// consumes only returned account effects, so a reissued edit must carry its
// scheduling edge in that same result, without another unrelated command.
#[tokio::test]
async fn superseded_profile_reissue_returns_its_original_queue_wakeup() {
    assert_profile_reissue_wakeup(false).await;
}

#[tokio::test]
async fn current_profile_reissue_returns_its_original_queue_wakeup() {
    assert_profile_reissue_wakeup(true).await;
}

async fn assert_profile_reissue_wakeup(current: bool) {
    use cgka_traits::engine::SupersededIntentOutcome;

    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("profile reissue scheduling test key").unwrap();
    let mut alice = if current {
        current_session(dir.path().join("alice.sqlite"), &key, b"alice")
    } else {
        session(dir.path().join("alice.sqlite"), &key, b"alice")
    };
    let mut bob = if current {
        current_session(dir.path().join("bob.sqlite"), &key, b"bob")
    } else {
        session(dir.path().join("bob.sqlite"), &key, b"bob")
    };
    let created = alice
        .create_group(CreateGroupRequest {
            name: "before".into(),
            description: "before".into(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let group = created.group_id;
    let welcome = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, welcomes } => {
            alice.confirm_published(*pending).await.unwrap();
            welcomes[0].clone()
        }
        PublishWork::FoundingGroupCreated { welcomes } => welcomes[0].clone(),
        other => panic!("expected group creation, got {other:?}"),
    };
    bob.ingest(welcome).await.unwrap();

    let left = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group.clone(),
            name: Some("alice renamed it".into()),
            description: None,
        })
        .await
        .unwrap();
    let right = bob
        .send(SendIntent::UpdateGroupData {
            group_id: group.clone(),
            name: None,
            description: Some("bob described it".into()),
        })
        .await
        .unwrap();
    let evolution = |effects: &cgka_session::SessionEffects| match &effects.publish[0] {
        PublishWork::GroupEvolution { msg, pending, .. } => (msg.clone(), *pending),
        other => panic!("expected staged profile commit, got {other:?}"),
    };
    let (left, left_pending) = evolution(&left);
    let (right, right_pending) = evolution(&right);
    alice.confirm_published(left_pending).await.unwrap();
    bob.confirm_published(right_pending).await.unwrap();
    alice.ingest(right).await.unwrap();
    bob.ingest(left).await.unwrap();
    // Keep the real pinned settlement window. Both commits exist before any
    // convergence advance; relay timing cannot linearize away this collision.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let mut reissued = 0;
    for session in [alice, bob] {
        let route = StaticTransportRouting::new(vec![]).with_group_route(
            group.clone(),
            group.as_slice().to_vec(),
            vec![TransportEndpoint("wss://profile-test.example".into())],
        );
        let mut runtime = AccountDeviceRuntime::new(
            session,
            RecordingAdapter::default(),
            route,
            RecordingKeyPackages::default(),
        );
        let effects = runtime.advance_convergence(&group).await.unwrap();
        if effects
            .superseded_intents
            .iter()
            .any(|report| report.outcome == SupersededIntentOutcome::Reissued)
        {
            reissued += 1;
            assert!(runtime.has_queued_outbound_intents(&group).unwrap());
            assert!(
                effects.pending_convergence.contains(&group),
                "a real reissued profile edit must return a wakeup in the same account effects"
            );
        }
    }
    assert_eq!(reissued, 1, "exactly the losing edit must be requeued");
}
