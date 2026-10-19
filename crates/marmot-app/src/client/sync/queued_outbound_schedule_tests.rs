//! Restart scheduling must separate required publication from secondary replication.
use super::*;
use crate::MarmotApp;
use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};
use cgka_traits::{
    MarmotAppEvent, MessageId, OutboundFanout, Timestamp, TransportEndpoint,
    TransportEndpointFailure, TransportEndpointFailureKind, TransportEnvelope, TransportMessage,
    TransportPublishRequest, TransportPublishTarget, TransportSource,
};
use marmot_account::AccountHome;
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restarted_safe_queued_send_does_not_inherit_secondary_retry_cutoff() {
    assert_restart_schedule(1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restarted_below_quorum_send_keeps_required_retry_cutoff() {
    assert_restart_schedule(2).await;
}

async fn assert_restart_schedule(required_acks: usize) {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client.create_group("queued restart", &[]).await.unwrap();
    let account = client.runtime.session().self_id();
    let payload = MarmotAppEvent::new(
        hex::encode(account.as_slice()),
        1_700_000_000,
        9,
        vec![],
        "queued restart",
    )
    .encode()
    .unwrap();
    client
        .runtime
        .session_mut()
        .queue_app_message_with_audit_context(group.clone(), payload, Default::default())
        .await
        .unwrap();
    let now = crate::unix_now_seconds() * 1_000;
    let secondary = TransportEndpoint("wss://secondary.example".into());
    let mut retained = OutboundFanout::stage(
        TransportPublishRequest {
            account_id: account,
            message: TransportMessage {
                id: MessageId::new(vec![0xa1; 32]),
                payload: vec![0xa1],
                timestamp: Timestamp(100),
                causal_deps: vec![],
                source: TransportSource("scheduler-fixture".into()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: group.as_slice().to_vec(),
                },
            },
            target: TransportPublishTarget::Group {
                group_id: group.clone(),
                transport_group_id: group.as_slice().to_vec(),
                endpoints: vec![
                    TransportEndpoint("wss://relay.example".into()),
                    secondary.clone(),
                ],
            },
            required_acks,
        },
        None,
        None,
        now,
    )
    .unwrap();
    retained.mark_attempt_started_at(0, now).unwrap();
    retained.mark_target_accepted(0).unwrap();
    retained.mark_attempt_started_at(1, now).unwrap();
    retained
        .record_target_failure(
            1,
            TransportEndpointFailure {
                endpoint: secondary,
                reason: "acknowledgement unknown".into(),
                kind: TransportEndpointFailureKind::PossiblyExposed,
                rejection_category: None,
            },
        )
        .unwrap();
    client
        .runtime
        .session()
        .put_outbound_fanout(&retained)
        .unwrap();
    drop(client);

    // Local reopen restores persisted work without an inbound event or network-maintenance drain.
    let mut reopened = app
        .local_client_with_relay_plane("alice", &app.relay_plane, None)
        .await
        .unwrap();
    assert!(
        !reopened
            .runtime
            .has_pending_convergence_inputs(&group)
            .unwrap()
    );
    assert!(
        reopened
            .runtime
            .outbound_fanout_retry_delay_ms(&group)
            .unwrap()
            .unwrap()
            > 20_000
    );
    let schedule = reopened.convergence_schedule_state(&group).unwrap();
    if required_acks == 1 {
        assert_eq!(
            schedule,
            ConvergenceScheduleState::PendingOutbound {
                retry_after_ms: None
            },
            "restart must arm the queued send independently of secondary replication"
        );
        reopened.prepare_transport().await.unwrap();
        let effects = reopened.runtime.advance_convergence(&group).await.unwrap();
        assert_eq!(effects.published_app_messages.len(), 1);
        assert!(
            !reopened
                .runtime
                .has_queued_outbound_intents(&group)
                .unwrap()
        );
        let fanouts = reopened
            .runtime
            .session()
            .outbound_fanouts_for_group(&group)
            .unwrap();
        assert!(
            fanouts.iter().any(|fanout| fanout == &retained),
            "the older exact-byte retry must remain unchanged"
        );
    } else {
        assert!(
            matches!(schedule, ConvergenceScheduleState::PendingOutbound { retry_after_ms: Some(ms) } if ms > 20_000)
        );
        let effects = reopened.runtime.advance_convergence(&group).await.unwrap();
        assert!(effects.published_app_messages.is_empty());
        assert!(
            reopened
                .runtime
                .has_queued_outbound_intents(&group)
                .unwrap()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publication_barrier_rejects_unhydrated_inventory() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client
        .create_group("deferred inventory", &[])
        .await
        .unwrap();
    drop(client);
    let mut reopened = app
        .local_client_with_relay_plane_and_hydration("alice", &app.relay_plane, None, true, None)
        .await
        .unwrap();
    assert!(
        reopened
            .runtime
            .session()
            .unhydrated_group_ids()
            .contains(&group)
    );
    assert!(
        reopened
            .runtime
            .queued_outbound_intents_blocked_by_fanouts(&group)
            .is_err(),
        "hidden fanouts must not certify an unhydrated group safe"
    );
    reopened
        .runtime
        .session_mut()
        .ensure_group_hydrated(&group)
        .unwrap();
    assert!(
        !reopened
            .runtime
            .queued_outbound_intents_blocked_by_fanouts(&group)
            .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publication_barrier_keeps_pending_mls_after_quorum() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client
        .create_group("pending confirmation", &[])
        .await
        .unwrap();
    let effects = client
        .runtime
        .session_mut()
        .send(cgka_traits::SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap();
    let (message, pending) = match &effects.publish[0] {
        cgka_session::PublishWork::GroupEvolution { msg, pending, .. } => (msg.clone(), *pending),
        other => panic!("expected staged evolution, got {other:?}"),
    };
    let transport_group_id = match &message.envelope {
        TransportEnvelope::GroupMessage { transport_group_id } => transport_group_id.clone(),
        other => panic!("expected group envelope, got {other:?}"),
    };
    let mut fanout = OutboundFanout::stage(
        TransportPublishRequest {
            account_id: client.runtime.session().self_id(),
            message,
            target: TransportPublishTarget::Group {
                group_id: group.clone(),
                transport_group_id,
                endpoints: vec![TransportEndpoint("wss://relay.example".into())],
            },
            required_acks: 1,
        },
        Some(pending),
        Some(group.clone()),
        crate::unix_now_seconds() * 1_000,
    )
    .unwrap();
    fanout.mark_attempt_started(0).unwrap();
    fanout.mark_target_accepted(0).unwrap();
    client
        .runtime
        .session()
        .put_outbound_fanout(&fanout)
        .unwrap();
    assert_eq!(fanout.outcome().outstanding_targets, 0);
    assert!(
        client
            .runtime
            .queued_outbound_intents_blocked_by_fanouts(&group)
            .unwrap(),
        "relay acknowledgement alone does not confirm the MLS transition"
    );
}

/// Input-only convergence may advance beyond our own published SelfRemove.
/// Once publication barriers clear, the worker must still schedule the normal
/// engine drain that re-proposes the original durable leave in the new epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_own_leave_after_input_only_convergence_keeps_worker_wake() {
    assert_stale_own_leave_wake(false).await;
}

/// An epoch change completed inside live ingest has no scheduled-pass caller
/// to re-arm it. Its effects must notify the worker about the stale leave.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inline_epoch_change_keeps_stale_own_leave_worker_wake() {
    assert_stale_own_leave_wake(true).await;
}

async fn assert_stale_own_leave_wake(require_inline_ingest_wake: bool) {
    use crate::relay_plane::{AccountDeliveryReceive, MarmotRelayPlane};
    use crate::tests::remember_test_member_inbox;
    use cgka_traits::storage::LeaveRequestStorage;

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob_account = home.create_account("bob").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let config = crate::MarmotAppConfig::default();
    #[cfg(feature = "test-policy-overrides")]
    let config = if require_inline_ingest_wake {
        config.with_dev_settlement_quiescence_ms(0)
    } else {
        config
    };
    let app = MarmotApp::with_relay_and_config(dir.path(), "wss://relay.example", config)
        .with_test_relay_client(relay.clone());
    remember_test_member_inbox(&app, &bob_account.account_id_hex, "wss://relay.example");
    let plane = MarmotRelayPlane::new(None, relay);
    let mut alice = app
        .client_with_relay_plane("alice", &plane, None)
        .await
        .unwrap();
    let mut bob = app
        .client_with_relay_plane("bob", &plane, None)
        .await
        .unwrap();
    bob.sync().await.unwrap();
    let group = alice
        .create_group("stale leave wake", &[&bob_account.account_id_hex])
        .await
        .unwrap();
    assert!(bob.sync().await.unwrap().joined_groups.contains(&group));
    bob.leave_group(&group).await.unwrap();
    let storage = app.account_storage("bob").unwrap();
    let original = storage.leave_request(&group).unwrap().unwrap();
    let prior = bob.runtime.group_record(&group).unwrap().epoch;
    assert_eq!(original.last_proposed_epoch, Some(prior));
    assert_eq!(
        bob.convergence_schedule_state(&group).unwrap(),
        ConvergenceScheduleState::Idle,
        "a current leave proposal must not keep the worker polling"
    );

    // Alice has not ingested Bob's proposal. Her real non-removing commit
    // advances the group while Bob is still an actual member.
    alice
        .update_group_profile(&group, Some("still includes bob"), None)
        .await
        .unwrap();
    let expected = alice.runtime.group_record(&group).unwrap().epoch;
    assert_eq!(expected.0, prior.0 + 1);
    let mut inline_epoch_change_observed = false;
    let mut inline_epoch_change_wake_retained = true;
    // Consume startup/send edges as the account worker does. They cannot
    // substitute for a new edge from the actual inline epoch transition.
    bob.take_pending_convergence_groups();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(delivery) =
                tokio::time::timeout(Duration::from_millis(25), bob.receive_next_delivery()).await
            {
                let AccountDeliveryReceive::Delivery(delivery) = delivery.unwrap() else {
                    panic!("synthetic test must not overflow its delivery queue");
                };
                bob.take_pending_convergence_groups();
                let summary = bob.ingest_received_delivery(*delivery).await.unwrap();
                if summary.events.iter().any(|event| {
                    matches!(event,
                    cgka_traits::engine::GroupEvent::EpochChanged { group_id, .. }
                        if group_id == &group)
                }) {
                    inline_epoch_change_observed = true;
                    inline_epoch_change_wake_retained &=
                        bob.take_pending_convergence_groups().contains(&group);
                }
            }
            // This is the actual narrow session entry point used behind a
            // required publication barrier: no ordinary send/leave drain.
            if !require_inline_ingest_wake {
                bob.runtime
                    .session_mut()
                    .advance_convergence_inputs(&group)
                    .await
                    .unwrap();
            }
            if bob.runtime.group_record(&group).unwrap().epoch == expected
                && !bob.runtime.has_pending_convergence_inputs(&group).unwrap()
            {
                break;
            }
        }
    })
    .await
    .expect("actual non-removing commit must settle through inputs-only convergence");
    let group_record = bob.runtime.group_record(&group).unwrap();
    assert!(!group_record.is_terminal());
    assert_eq!(group_record.members.len(), 2);
    assert!(matches!(
        bob.runtime.epoch_state(&group),
        Some(cgka_traits::EpochState::Stable { .. })
    ));
    assert!(!bob.runtime.has_pending_outbound_fanouts(&group).unwrap());
    assert!(!bob.runtime.has_queued_outbound_intents(&group).unwrap());
    assert_eq!(
        storage.leave_request(&group).unwrap().unwrap(),
        original,
        "inputs-only convergence must retain the same original leave, not create a new request"
    );
    assert_eq!(
        bob.convergence_schedule_state(&group).unwrap(),
        ConvergenceScheduleState::PendingOutbound {
            retry_after_ms: None
        },
        "a stale durable leave must retain a worker wake after input-only convergence"
    );

    bob.retry_group_convergence(&group).await.unwrap();
    let reissued = storage.leave_request(&group).unwrap().unwrap();
    assert_eq!(reissued.requested_at_ms, original.requested_at_ms);
    assert_eq!(reissued.last_proposed_epoch, Some(expected));
    assert_eq!(
        bob.convergence_schedule_state(&group).unwrap(),
        ConvergenceScheduleState::Idle,
        "the current re-proposal must disarm the extra wake"
    );
    drop(bob);
    drop(alice);
    storage.close().unwrap();
    if require_inline_ingest_wake {
        assert!(
            inline_epoch_change_observed,
            "the real commit must advance the epoch inside live ingest, without a scheduled pass"
        );
        assert!(
            inline_epoch_change_wake_retained,
            "inline epoch-change effects must notify the worker about the stale original leave"
        );
    }
}
