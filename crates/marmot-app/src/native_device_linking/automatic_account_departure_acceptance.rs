//! Genuine account-wide departure: A/B are independent ordinary MLS leaves,
//! C is mirrored-only, and unrelated administrator D performs public removals.
use super::automatic_two_source_leave_acceptance::{
    TwoSourcePeer, stored_indices, wait_for_paired_records,
};
use super::*;
use cgka_traits::StorageProvider;
use cgka_traits::storage::{GroupStorage, LeaveRequestStorage};
use futures::FutureExt;

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
    relay_url: &str,
    relay_database: &dyn nostr_relay_builder::prelude::NostrDatabase,
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
    let reopened_app = MarmotApp::with_relay(apps[1].account_home().root(), relay_url);
    let reopened = MarmotAppRuntime::new(reopened_app.clone());
    let result =
        std::panic::AssertUnwindSafe(async {
            reopened.reconcile_accounts().await.unwrap();
            let completion = tokio::time::timeout(std::time::Duration::from_secs(50), async {
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
            .await;
            if completion.is_err() {
                let diagnostics = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                std::panic::AssertUnwindSafe(async {
            let indices = stored_indices(&peer.app, &peer.group);
            eprintln!("account_departure_public_leave_observation={:?}", observe_public_leave_failure(&reopened_app, peer, relay_database).await.map_err(|_| "Unknown"));
            eprintln!(
                "account_departure_timeout_d_leaves={} a_present={} b_present={}",
                indices.len(),
                indices.contains(&peer.a_index),
                indices.contains(&peer.b_index)
            );
            for (index, runtime) in [(0, &runtimes[0]), (1, &reopened), (2, &runtimes[2])] {
                let status = runtime
                    .account_chat_departure_state("test", &peer.group)
                    .await;
                eprintln!(
                    "account_departure_timeout_peer={index} status={:?}",
                    status
                        .as_ref()
                        .map(|state| state.status)
                        .map_err(|error| error.privacy_safe_kind())
                );
                let leaf = runtime
                    .account_departure_local_leaf_for_test("test", &peer.group)
                    .await;
                eprintln!(
                    "account_departure_timeout_peer={index} actual_local_leaf={:?}",
                    leaf.map_err(|error| error.privacy_safe_kind())
                );
                let app = if index == 1 { &reopened_app } else { &apps[index] };
                let store = app.account_storage("test").unwrap();
                let policies = store
                    .approved_account_sharing_policy_storage()
                    .unwrap()
                    .approved_account_sharing_policies()
                    .unwrap();
                let round = store
                    .private_roster_settlement_storage()
                    .unwrap()
                    .read_round()
                    .unwrap()
                    .unwrap();
                let progress = store
                    .account_chat_departure_progress(
                        &round.anchor.account,
                        &round.anchor.local_device,
                        &peer.group,
                    )
                    .unwrap();
                eprintln!(
                    "account_departure_timeout_peer={index} policy_count={} progress={:?}",
                    policies.len(),
                    progress.map(|p| (
                        p.local_complete,
                        p.pending_peers,
                        p.needs_administrator,
                        p.awaiting_sources,
                        p.global_complete
                    ))
                );
                let pending = store
                    .pending_local_account_chat_departures(
                        &round.anchor.account,
                        &round.anchor.local_device,
                        None,
                        16,
                    )
                    .unwrap();
                eprintln!(
                    "account_departure_timeout_peer={index} pending_local_count={}",
                    pending.len()
                );
                eprintln!("account_departure_timeout_peer={index} queued={} published={} stored_epoch={:?} leave_proposed_epoch={:?}",
                    pending.iter().filter(|(_, state)| *state == storage_sqlite::account_chat_departure::AccountChatDepartureLocalState::Queued).count(),
                    pending.iter().filter(|(_, state)| *state == storage_sqlite::account_chat_departure::AccountChatDepartureLocalState::Published).count(),
                    store.get_group(&peer.group).map(|row| row.epoch.0).map_err(|_| "Unknown"),
                    store.leave_request(&peer.group).map(|row| row.and_then(|request|request.last_proposed_epoch.map(|epoch|epoch.0))).map_err(|_| "Unknown")
                );
            }
                }).catch_unwind(),
            ).await;
                eprintln!(
                    "account_departure_diagnostics_completed={} unknown={}",
                    matches!(diagnostics, Ok(Ok(()))),
                    !matches!(diagnostics, Ok(Ok(())))
                );
            }
            completion
                .expect("both genuine ordinary removals and peer receipts must precede completion");
            tokio::time::timeout(std::time::Duration::from_secs(30), async {
                loop {
                    let mut complete = true;
                    for runtime in [&runtimes[0], &reopened, &runtimes[2]] {
                        let state = runtime
                            .account_chat_departure_state("test", &peer.group)
                            .await
                            .unwrap();
                        complete &= state.status == crate::AccountChatDepartureStatus::Completed;
                        assert_eq!(state.operation_id.as_deref(), Some(operation.as_str()));
                    }
                    if complete {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("authenticated completion notices must reach all real original participants");
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
        })
        .catch_unwind()
        .await;
    let closed = reopened.shutdown_and_close().await.is_ok() && reopened.storage_is_closed();
    eprintln!("account_departure_reopened_b_closed={closed}");
    if let Err(original) = result {
        std::panic::resume_unwind(original);
    }
    assert!(closed, "reopened B owner must positively close");
}

/// Observe the actual durable proposal and administrator queue, never a grant.
async fn observe_public_leave_failure(
    source: &MarmotApp,
    peer: &TwoSourcePeer,
    relay_database: &dyn nostr_relay_builder::prelude::NostrDatabase,
) -> Result<(u64, usize, usize, usize, usize, usize, usize), crate::AppError> {
    use cgka_traits::message::{MessageState, StoredMessagePayload};
    use cgka_traits::storage::{MessageStorage, OutboundFanoutStorage};
    use openmls::prelude::{ContentType, MlsMessageBodyIn, MlsMessageIn, ProtocolMessage};
    use tls_codec::Deserialize;
    let source = source.account_storage("test")?;
    let administrator = peer.app.account_storage("test")?;
    let (epoch, pending) = administrator.with_read_snapshot(|storage| {
        let group = openmls::group::MlsGroup::load(
            storage.mls_storage(),
            &openmls::group::GroupId::from_slice(peer.group.as_slice()),
        )
        .map_err(|_| cgka_traits::StorageError::Backend("diagnostic MLS read failed".into()))?
        .ok_or(cgka_traits::StorageError::NotFound)?;
        Ok((group.epoch().as_u64(), group.pending_proposals().count()))
    })?;
    let current = source.get_group(&peer.group)?.epoch;
    let records = source.list_messages(&peer.group, current)?;
    let (mut sent, mut received, mut processed, mut relay_retained) = (0, 0, 0, 0);
    for record in records
        .iter()
        .take(128)
        .filter(|row| row.state == MessageState::Sent)
    {
        let Ok(payload) = StoredMessagePayload::decode(&record.payload) else {
            continue;
        };
        let Some(wire) = payload.as_openmls_wire() else {
            continue;
        };
        let Ok(message) = MlsMessageIn::tls_deserialize_exact(&wire.payload) else {
            continue;
        };
        let protocol: ProtocolMessage = match message.extract() {
            MlsMessageBodyIn::PublicMessage(message) => message.into(),
            MlsMessageBodyIn::PrivateMessage(message) => message.into(),
            _ => continue,
        };
        if protocol.content_type() != ContentType::Proposal {
            continue;
        }
        sent += 1;
        if let Some(exact) = payload.as_exact_transport() {
            let id = nostr_relay_builder::prelude::EventId::from_slice(exact.id.as_slice())
                .map_err(|_| {
                    cgka_traits::StorageError::Serialization("diagnostic event unavailable".into())
                })?;
            relay_retained += usize::from(
                relay_database
                    .event_by_id(&id)
                    .await
                    .map_err(|_| {
                        cgka_traits::StorageError::Backend("diagnostic relay read failed".into())
                    })?
                    .is_some(),
            );
        }
        match administrator.get_message(&record.id) {
            Ok(row) => {
                received += 1;
                processed += usize::from(row.state == MessageState::Processed);
            }
            Err(cgka_traits::StorageError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let fanouts = source.list_outbound_fanouts_for_group(&peer.group)?.len();
    Ok((
        epoch,
        pending,
        sent,
        received,
        processed,
        fanouts,
        relay_retained,
    ))
}
