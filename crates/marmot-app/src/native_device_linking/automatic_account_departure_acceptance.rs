//! Genuine account-wide departure: A/B are independent ordinary MLS leaves,
//! C is mirrored-only, and unrelated administrator D performs public removals.
use super::automatic_two_source_leave_acceptance::{
    TwoSourcePeer, stored_indices, wait_for_paired_records,
};
use super::*;

#[test]
fn mirrored_account_departure_waits_for_offline_actual_source_and_public_removal() {
    crate::tests::run_composed_app_runtime_test("account-wide-two-source-departure", || async {
        Box::pin(actual::run_native_public_three_device_enrollment(
            actual::ApprovalScenario::AutomaticAccountDeparture,
        ))
        .await;
    });
}

pub(super) async fn verify(
    apps: &[MarmotApp; 3],
    runtimes: &[MarmotAppRuntime; 3],
    peer: &TwoSourcePeer,
) {
    wait_for_paired_records(&runtimes[2], &peer.group, &peer.initial_ids, None).await;
    assert_eq!(stored_indices(&peer.app, &peer.group).len(), 3);
    assert!(
        !apps[2]
            .load_state("test")
            .unwrap()
            .groups
            .iter()
            .any(|row| row.group_id_hex == hex::encode(peer.group.as_slice()))
    );
    tokio::time::timeout(std::time::Duration::from_secs(40), async {
        loop {
            let state = runtimes[2]
                .account_chat_departure_state("test", &peer.group)
                .await
                .unwrap();
            if state.status == crate::AccountChatDepartureStatus::Available {
                break;
            }
            assert!(state.status == crate::AccountChatDepartureStatus::Unavailable);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("actual two-source origin coverage must make mirrored departure available");
    runtimes[1].shutdown_and_close().await.unwrap();
    assert!(runtimes[1].storage_is_closed());
    let admitted = runtimes[2]
        .leave_account_chat("test", &peer.group)
        .await
        .unwrap();
    assert!(admitted.status == crate::AccountChatDepartureStatus::Pending);
    let operation = admitted
        .operation_id
        .expect("paired negative intent must be durable");
    tokio::time::timeout(std::time::Duration::from_secs(40), async {
        loop {
            let indices = stored_indices(&peer.app, &peer.group);
            if !indices.contains(&peer.a_index) && indices.contains(&peer.b_index) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("D must actually remove A while offline B ordinary leaf remains");
    let state = runtimes[2]
        .account_chat_departure_state("test", &peer.group)
        .await
        .unwrap();
    assert!(state.status == crate::AccountChatDepartureStatus::Pending);
    assert_eq!(state.operation_id.as_deref(), Some(operation.as_str()));
    assert!(matches!(
        runtimes[2]
            .submit_text(
                "test",
                &peer.group,
                "blocked departed chat".into(),
                "account-wide-c-denied".into()
            )
            .await,
        Err(crate::AppError::AccountChatDepartureDenied)
    ));
    // Reopen B's exact synthetic root through the ordinary public runtime. No
    // store is copied; the authenticated durable outbox must catch it up.
    let reopened = MarmotAppRuntime::new(apps[1].clone());
    reopened.reconcile_accounts().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(50), async {
        loop {
            let indices = stored_indices(&peer.app, &peer.group);
            let state = runtimes[2]
                .account_chat_departure_state("test", &peer.group)
                .await
                .unwrap();
            if indices.len() == 1
                && !indices.contains(&peer.a_index)
                && !indices.contains(&peer.b_index)
                && state.status == crate::AccountChatDepartureStatus::Completed
            {
                assert_eq!(state.operation_id.as_deref(), Some(operation.as_str()));
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("both genuine ordinary removals and peer receipts must precede completion");
    for (index, runtime) in [(0, &runtimes[0]), (1, &reopened), (2, &runtimes[2])] {
        assert!(matches!(
            runtime
                .submit_text(
                    "test",
                    &peer.group,
                    "blocked after completion".into(),
                    format!("account-wide-denied-{index}")
                )
                .await,
            Err(crate::AppError::AccountChatDepartureDenied)
        ));
    }
    reopened.shutdown_and_close().await.unwrap();
    assert!(reopened.storage_is_closed());
}
