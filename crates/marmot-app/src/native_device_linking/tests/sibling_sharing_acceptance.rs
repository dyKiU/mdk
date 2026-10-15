//! Real public original approvals, protected MLS delivery and independent stores.
use super::actual::{ApprovalScenario, run_native_public_three_device_enrollment};
use super::*;
use cgka_traits::StorageProvider;

pub(super) async fn assert_bilateral_completion(
    apps: &[MarmotApp; 3],
    a: &DeviceLinkingSession,
    c: &DeviceLinkingSession,
    b: &DeviceLinkingApproval,
    broad_sibling: bool,
    pre_auth_probe: Option<
        &crate::client::device_linking::sibling_sharing::SiblingPreAuthFailureProbe,
    >,
    relay_observations: (
        &dyn nostr_relay_builder::prelude::NostrDatabase,
        &crate::MarmotRelayPlane,
    ),
) {
    let (relay_database, recipient_relay_plane) = relay_observations;
    let expected = if broad_sibling { [2, 2, 2] } else { [2, 1, 1] };
    let mut last_observation = None;
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let c_phase = c.snapshot().await.unwrap().phase;
            let b_phase = b.snapshot().await.unwrap().phase;
            let a_phase = a.snapshot().await.unwrap().phase;
            let counts = apps.each_ref().map(|app| {
                app.account_storage("test")
                    .unwrap()
                    .approved_account_sharing_policy_storage()
                    .unwrap()
                    .approved_account_sharing_policies()
                    .unwrap()
                    .len()
            });
            last_observation = Some((a_phase, c_phase, b_phase, counts));
            if c_phase == DeviceLinkingPhase::EnrollmentComplete {
                assert_eq!(
                    counts[2], expected[2],
                    "C completion must follow its durable handoff"
                );
                if broad_sibling {
                    assert_eq!(
                        counts[1], 2,
                        "C must observe B's authenticated durable commit"
                    );
                }
            }
            if b_phase == DeviceLinkingApprovalPhase::Settled {
                assert_eq!(
                    counts[1], expected[1],
                    "B settlement cannot precede its own durable handoff"
                );
                if broad_sibling {
                    assert_eq!(
                        counts[2], 2,
                        "B must observe C's authenticated durable commit"
                    );
                }
            }
            if a_phase == DeviceLinkingPhase::EnrollmentComplete
                && c_phase == DeviceLinkingPhase::EnrollmentComplete
                && b_phase == DeviceLinkingApprovalPhase::Settled
            {
                assert_eq!(counts, expected);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    if let Some(probe) = pre_auth_probe {
        eprintln!(
            "sibling exact injected-item normal/retained Core authentication routes, kind, captured: {:?}",
            probe.authentication_routes_for_test()
        );
        eprintln!(
            "sibling retained retry counts and channel state: {:?}",
            probe.snapshot_for_test()
        );
    }
    if outcome.is_err() {
        eprintln!(
            "sharing phase and durable policy-count observations: {:?}",
            last_observation
        );
        eprintln!(
            "C original intake aggregates: {:?}",
            c.sibling_recipient_diagnostics_for_test()
        );
        eprintln!(
            "C retention rejection aggregates: {:?}",
            c.sibling_recipient_rejections_for_test()
        );
        eprintln!(
            "C projection unique/total/maxrepeat/stale: {:?}",
            c.sibling_projection_aggregates_for_test()
        );
        if let Some(probe) = pre_auth_probe {
            eprintln!(
                "sibling auth retry aggregates: {:?}",
                probe.snapshot_for_test()
            );
            eprintln!(
                "B original request matches C local/context/approval/group/source: {:?}",
                probe
                    .request_scope_for_test()
                    .and_then(|scope| c.sibling_request_scope_matches_for_test(&scope))
            );
            eprintln!(
                "C context rejection aggregates: {:?}",
                c.sibling_context_rejections_for_test()
            );
            eprintln!(
                "C exact B-request observation: {:?}",
                probe
                    .request_nonce_for_test()
                    .and_then(|nonce| c.sibling_request_observation_for_test(nonce))
            );
            eprintln!(
                "B request transport aggregates: {:?}",
                probe.transport_snapshot_for_test()
            );
            if let Some((group, epoch, route)) = probe.request_route_for_test() {
                let storage = apps[2].account_storage("test").unwrap();
                let routes =
                    cgka_traits::storage::GroupStorage::list_transport_group_routes(&storage)
                        .unwrap();
                let group_record = cgka_traits::storage::GroupStorage::get_group(&storage, &group);
                eprintln!(
                    "C exact B-request route/group observations: {:?}",
                    (
                        routes.iter().any(|item| item.group_id == group),
                        routes
                            .iter()
                            .any(|item| item.group_id == group && item.transport_group_id == route),
                        group_record.as_ref().ok().map(|record| [
                            record.epoch == epoch,
                            record.removed,
                            record.unrecoverable,
                            record.disbanded.is_some()
                        ]),
                    )
                );
            }
            if let Some(id) = probe.request_message_id_for_test() {
                let event_id =
                    nostr_relay_builder::prelude::EventId::from_slice(id.as_slice()).unwrap();
                let retained = relay_database.event_by_id(&event_id).await;
                eprintln!(
                    "Relay exact B-request retained: {:?}",
                    retained.as_ref().ok().map(Option::is_some)
                );
                if let Ok(Some(event)) = retained {
                    let storage = apps[2].account_storage("test").unwrap();
                    let round = storage
                        .private_roster_settlement_storage()
                        .unwrap()
                        .read_round()
                        .unwrap()
                        .unwrap();
                    let account = cgka_traits::MemberId::new(round.anchor.account.to_vec());
                    eprintln!(
                        "C exact B-request Event/raw/zero/positive/error/router/missing/present: {:?}",
                        recipient_relay_plane.account_notification_disposition_for_test(
                            &account,
                            &event.id.to_string()
                        )
                    );
                    eprintln!(
                        "C exact B-request SDK cached/filter/untimed-filter: {:?}",
                        recipient_relay_plane
                            .account_sdk_event_observation_for_test(
                                &account,
                                &serde_json::to_string(&event).unwrap()
                            )
                            .await
                    );
                }
            }
            if let Some(id) = probe.request_content_id_for_test() {
                eprintln!(
                    "C exact B-request projected/kind/choice/group/proof: {:?}",
                    c.sibling_projection_event_for_test(&id)
                );
                let storage = apps[2].account_storage("test").unwrap();
                let stored = cgka_traits::storage::MessageStorage::get_message(&storage, &id);
                eprintln!("C exact B-request pending app event retained: {:?}", cgka_traits::storage::MessageStorage::list_pending_application_events(&storage).ok().map(|events| events.iter().any(|event| matches!(event, cgka_traits::GroupEvent::MessageReceived {message_id,..} if message_id == &id))));
                let state_flags = stored.as_ref().ok().map(|record| {
                    use cgka_traits::MessageState;
                    [
                        MessageState::Sent,
                        MessageState::Created,
                        MessageState::Processed,
                        MessageState::Failed,
                        MessageState::Retryable,
                        MessageState::ConvergenceDeferred,
                        MessageState::PeelDeferred,
                        MessageState::EpochInvalidated,
                    ]
                    .map(|state| record.state == state)
                });
                eprintln!(
                    "C exact B-request canonical state/event: {:?}",
                    (state_flags, c.sibling_source_event_for_test(&id))
                );
            }
            if let Some(id) = probe.request_message_id_for_test() {
                let storage = apps[2].account_storage("test").unwrap();
                let stored = cgka_traits::storage::MessageStorage::get_message(&storage, &id);
                eprintln!(
                    "C exact B-request stored/event/source-proof: {:?}",
                    (
                        stored.is_ok(),
                        matches!(stored, Err(cgka_traits::storage::StorageError::NotFound)),
                        c.sibling_source_event_for_test(&id),
                        cgka_traits::storage::MessageStorage::has_processed_transport_id(
                            &storage, &id
                        )
                        .ok()
                    )
                );
            }
        }
    }
    outcome.expect("actual bilateral B/C policies and encrypted confirmations must settle without another user action");
    if let Some(probe) = pre_auth_probe {
        assert!(
            probe.authentication_routes_for_test().0[1] > 0,
            "the exact injected control must authenticate on its retained original channel"
        );
    }
    let devices = apps.each_ref().map(|app| {
        app.account_storage("test")
            .unwrap()
            .private_roster_settlement_storage()
            .unwrap()
            .read_round()
            .unwrap()
            .unwrap()
            .anchor
            .local_device
    });
    let policies = apps.each_ref().map(|app| {
        app.account_storage("test")
            .unwrap()
            .approved_account_sharing_policy_storage()
            .unwrap()
            .approved_account_sharing_policies()
            .unwrap()
    });
    for (local, rows) in policies.iter().enumerate() {
        for row in rows {
            assert!(row.local_device == devices[local] && !row.revoked);
            assert_eq!(
                row.version,
                cgka_traits::approved_account_sharing_policy::ACCOUNT_SHARING_POLICY_VERSION
            );
            assert_eq!(
                row.capabilities,
                cgka_traits::approved_account_sharing_policy::ACCOUNT_SHARING_CAPABILITIES
            );
            let peer = devices
                .iter()
                .position(|device| *device == row.peer_device)
                .expect("policy must name an actual settled peer");
            assert_ne!(local, peer);
            let counterpart = policies[peer]
                .iter()
                .find(|other| other.peer_device == devices[local])
                .expect("each durable sharing relationship must be bilateral");
            assert!(
                row.approval_id == counterpart.approval_id
                    && row.account == counterpart.account
                    && row.protected_group == counterpart.protected_group
            );
        }
    }
    if !broad_sibling {
        assert!(!policies[1].iter().any(|row| row.peer_device == devices[2]));
        assert!(!policies[2].iter().any(|row| row.peer_device == devices[1]));
    }
}

#[tokio::test]
async fn public_three_device_broad_approvals_commit_each_bilateral_relationship() {
    run_native_public_three_device_enrollment(ApprovalScenario::BroadEnrollment).await;
}

#[tokio::test]
async fn public_third_device_plain_sibling_approval_does_not_share_its_chats() {
    run_native_public_three_device_enrollment(ApprovalScenario::BroadPairPlainSibling).await;
}

#[tokio::test]
async fn public_broad_sibling_cancellation_retires_the_exact_shared_original() {
    run_native_public_three_device_enrollment(ApprovalScenario::BroadSiblingCancel).await;
}

#[tokio::test]
async fn public_broad_sibling_core_authentication_failure_retries_same_original() {
    run_native_public_three_device_enrollment(ApprovalScenario::BroadPreAuthFailure).await;
}
