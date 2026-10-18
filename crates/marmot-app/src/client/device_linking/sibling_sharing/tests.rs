use super::*;
fn pending_control(wire: u8) -> PendingSiblingControl {
    PendingSiblingControl {
        group: cgka_traits::GroupId::new(vec![4; 16]),
        source: cgka_traits::source_leaf::SourceLeafProof {
            leaf_index: 1,
            signature_public_key: vec![8; 32],
            epoch: cgka_traits::EpochId(1),
            epoch_authenticator_digest: [5; 32],
        },
        wire: vec![wire],
    }
}
#[test]
fn recipient_opaque_buffer_retains_distinct_controls_from_same_peer() {
    let original = choice();
    assert!(original.retain_pending_observation(pending_control(1)));
    assert!(original.retain_pending_observation(pending_control(2)));
    assert!(original.retain_pending_observation(pending_control(1)));
    let pending = original.pending_controls.lock().unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].wire, vec![1]);
    assert_eq!(pending[1].wire, vec![2]);
}
#[test]
fn recipient_opaque_buffer_refuses_overflow_without_discarding_retained_controls() {
    let original = choice();
    for wire in 1..=MAX_PENDING_CONTROLS_PER_PEER as u8 {
        assert!(original.retain_pending_observation(pending_control(wire)));
    }
    assert!(!original.retain_pending_observation(pending_control(5)));
    #[cfg(feature = "test-policy-overrides")]
    assert_eq!(original.recipient_rejections_for_test(), [1, 0, 0, 0]);
    assert!(original.retain_pending_observation(pending_control(2)));
    assert_eq!(
        original.pending_controls.lock().unwrap().len(),
        MAX_PENDING_CONTROLS_PER_PEER
    );
    original.cancel();
    assert!(!original.retain_pending_observation(pending_control(1)));
    assert!(original.pending_controls.lock().unwrap().is_empty());
}
fn choice() -> Arc<OriginalEnrollmentSharingChoice> {
    let context = LinkingContext {
        version: 1,
        nonce: [1; 32],
        new_device_generation: 1,
        approver_generation: 1,
        account: [2; 32],
        exact_key_package: vec![0, 1, 255],
        key_package_reference: [3; 32],
        device_group: vec![4; 16],
        predecessor: crate::device_linking::PredecessorRoster {
            artifact_digest: None,
            epoch: 0,
            epoch_authenticator_digest: [5; 32],
            leaves: vec![crate::device_linking::PredecessorLeaf {
                leaf_index: 0,
                signature_public_key: [6; 32],
            }],
        },
        approver: [6; 32],
        recipient: [7; 32],
    };
    Arc::new(OriginalEnrollmentSharingChoice {
        scope: PurposeAttemptScope {
            account: context.account,
            local_device: context.recipient,
            generation: 1,
        },
        context,
        deadline: Instant::now() + std::time::Duration::from_secs(30),
        created_at: 1,
        legacy_capture: Mutex::new(None),
        lifetime: Arc::new(AtomicBool::new(true)),
        children: Mutex::new(Vec::new()),
        pending_controls: Mutex::new(Vec::new()),
        #[cfg(all(test, feature = "test-policy-overrides"))]
        native_observation_probe: Mutex::default(),
        #[cfg(all(test, feature = "experimental-device-sync", feature = "test-policy-overrides"))]
        receive_frontier: Arc::default(),
        #[cfg(all(test, feature = "test-policy-overrides"))]
        recipient_diagnostics: std::array::from_fn(|_| std::sync::atomic::AtomicUsize::new(0)),
        #[cfg(all(test, feature = "test-policy-overrides"))]
        received_requests: Mutex::new(Vec::new()),
        #[cfg(all(test, feature = "test-policy-overrides"))]
        received_control_events: Mutex::new(Vec::new()),
        #[cfg(all(test, feature = "test-policy-overrides"))]
        projection_observations: Arc::default(),
        #[cfg(all(test, feature = "test-policy-overrides"))]
        routing_probe: Mutex::new(None),
        #[cfg(all(test, feature = "test-policy-overrides"))]
        projection_head_probe: Mutex::new(None),
        progress: Mutex::new(ChoiceProgress {
            primary_committed: false,
            expected: Some(vec![[8; 32], [9; 32]]),
        }),
    })
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_choice_cancel_wakes_every_registered_child_without_actor_rpc() {
    let original = choice();
    let first = original.child().unwrap();
    let second = original.child().unwrap();
    let first_revoked = first.revoked.notified();
    let second_revoked = second.revoked.notified();
    tokio::pin!(first_revoked);
    tokio::pin!(second_revoked);
    first_revoked.as_mut().enable();
    second_revoked.as_mut().enable();
    let alias = original.clone();
    alias.cancel();
    tokio::time::timeout(std::time::Duration::from_millis(100), async {
        first_revoked.await;
        second_revoked.await;
    })
    .await
    .unwrap();
    assert!(!first.live() && !second.live());
    assert!(original.child().is_err());
}
#[test]
fn original_choice_completion_waits_for_primary_and_every_expected_sibling() {
    let original = choice();
    let first = original.child().unwrap();
    let second = original.child().unwrap();
    assert!(!original.complete());
    first.progress.lock().unwrap().complete = true;
    original.progress.lock().unwrap().primary_committed = true;
    assert!(!original.complete());
    second.progress.lock().unwrap().complete = true;
    assert!(original.complete());
}
#[test]
fn original_choice_children_do_not_extend_the_captured_deadline() {
    let original = choice();
    let first = original.child().unwrap();
    let second = original.child().unwrap();
    assert_eq!(first.deadline, original.deadline);
    assert_eq!(second.deadline, original.deadline);
    original.cancel();
    assert!(original.child().is_err());
}
