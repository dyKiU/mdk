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

#[test]
fn account_departure_reproposes_public_leave_after_same_epoch_branch_race() {
    crate::tests::run_composed_app_runtime_test("account-wide-departure-ordered", || async {
        Box::pin(actual::run_native_public_three_device_enrollment(
            actual::ApprovalScenario::AutomaticAccountDepartureOrdering,
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
    ordered: bool,
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
    let epoch_before = apps[1]
        .account_storage("test")
        .unwrap()
        .get_group(&peer.group)
        .unwrap()
        .epoch;
    if ordered {
        assert!(
            apps[1]
                .account_storage("test")
                .unwrap()
                .leave_request(&peer.group)
                .unwrap()
                .is_none()
        );
    }
    let mut held_commit_id = None;
    let mut publication_gate = if ordered {
        let account = peer.app.account_home().account("test").unwrap();
        Some(
            peer.runtime
                .relay_plane_for_test()
                .hold_next_ordinary_group_commit(
                    cgka_traits::MemberId::new(hex::decode(account.account_id_hex).unwrap()),
                    peer.group.clone(),
                    peer.app.account_storage("test").unwrap(),
                ),
        )
    } else {
        None
    };
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
    if let Some((held, _release)) = publication_gate.as_mut() {
        let held_message = tokio::time::timeout(std::time::Duration::from_secs(20), held)
            .await
            .expect("actual D original commit must reach publication gate")
            .unwrap();
        held_commit_id = Some(held_message.id);
        assert_administrator_holds_only_a(peer, epoch_before);
        assert!(runtimes[1].storage_is_closed());
        eprintln!("account_departure_ordering_a_only_commit_held=true b_not_yet_published=true");
    } else {
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
    }
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
            let mut published_branch = None;
            if ordered {
                tokio::time::timeout(std::time::Duration::from_secs(20), async {
                    loop {
                        let store = reopened_app.account_storage("test").unwrap();
                        let round = store.private_roster_settlement_storage().unwrap().read_round().unwrap().unwrap();
                        let work = store.pending_local_account_chat_departures(&round.anchor.account,&round.anchor.local_device,None,16).unwrap();
                        if work.iter().any(|(_,state)|*state==storage_sqlite::account_chat_departure::AccountChatDepartureLocalState::Published) {
                            let current = store.get_group(&peer.group).unwrap().epoch;
                            let proposed = store.leave_request(&peer.group).unwrap().unwrap().last_proposed_epoch;
                            if current.0 == epoch_before.0 + 1 && proposed == Some(current) {
                                let observation = observe_public_leave_failure(&reopened_app,peer,relay_database).await.unwrap();
                                if observation.source_sent_proposals > 0 && observation.relay_retained_proposals == observation.source_sent_proposals {
                                    published_branch = Some(current_branch_observation(&store,&peer.group).unwrap());
                                    break;
                                }
                            }
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }).await.expect("B must independently commit A and actually publish SelfRemove before the competing D commit");
                assert_administrator_holds_only_a(peer,epoch_before);
                eprintln!("account_departure_ordering_b_independent_next_epoch_proposal_retained=true");
                drop(publication_gate.take());
            }
            let mut observed_losing_branch = false;
            let completion = tokio::time::timeout(std::time::Duration::from_secs(50), async {
                loop {
                    if let Some(published) = &published_branch {
                        let current = current_branch_observation(&reopened_app.account_storage("test").unwrap(), &peer.group).unwrap();
                        observed_losing_branch |= current.epoch == published.epoch && current.authenticator_digest != published.authenticator_digest && current.selected_head_digest != published.selected_head_digest;
                    }
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
                        if ordered {
                            assert!(observed_losing_branch, "real competing D branch must replace B published proposal branch before qualifying this case");
                            eprintln!("account_departure_ordering_same_epoch_published_branch_replaced=true");
                        }
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
            if let Some(id) = &held_commit_id {
                use cgka_traits::storage::MessageStorage;
                let event = nostr_relay_builder::prelude::EventId::from_slice(id.as_slice()).unwrap();
                let retained_event = relay_database.event_by_id(&event).await;
                let retained = retained_event.as_ref().map(|row|row.is_some()).map_err(|_|"Unknown");
                if let Ok(Some(event)) = &retained_event {
                    let account = reopened_app.account_home().account("test").unwrap();
                    let account = cgka_traits::MemberId::new(hex::decode(account.account_id_hex).unwrap());
                    let plane = reopened.relay_plane_for_test();
                    eprintln!("account_departure_timeout_d_commit_notification_dispositions={:?}",plane.account_notification_disposition_for_test(&account,&event.id.to_string()));
                    eprintln!("account_departure_timeout_d_commit_sdk_cached_filter_untimed={:?}",plane.account_sdk_event_observation_for_test(&account,&serde_json::to_string(event).unwrap()).await);
                }
                let received = match reopened_app.account_storage("test").unwrap().get_message(id) { Ok(row)=>Ok(Some((row.epoch.0,row.state))), Err(cgka_traits::StorageError::NotFound)=>Ok(None), Err(_)=>Err("Unknown") };
                eprintln!("account_departure_timeout_exact_d_commit_relay={retained:?} b_outer_row={received:?}");
                let source_store = peer.app.account_storage("test").unwrap();
                let source = source_store.get_message(id).unwrap();
                let source_payload = cgka_traits::message::StoredMessagePayload::decode(&source.payload).unwrap();
                let source_wire = source_payload.as_openmls_wire().expect("actual D cached commit wire");
                use sha2::{Digest,Sha256};
                let content = cgka_traits::MessageId::new(Sha256::digest(&source_wire.payload).to_vec());
                let canonical = match reopened_app.account_storage("test").unwrap().get_message(&content) { Ok(row)=>Ok(Some((row.epoch.0,row.state))), Err(cgka_traits::StorageError::NotFound)=>Ok(None), Err(_)=>Err("Unknown") };
                eprintln!("account_departure_timeout_exact_d_commit_b_canonical_row={canonical:?}");
            }
            if let Some(published) = &published_branch {
                let observed = current_branch_observation(&reopened_app.account_storage("test").unwrap(),&peer.group).map(|current| (current.epoch==published.epoch,current.authenticator_digest==published.authenticator_digest,current.selected_head_digest==published.selected_head_digest)).map_err(|_|"Unknown");
                eprintln!("account_departure_timeout_b_current_matches_published_branch={observed:?}");
            }
            eprintln!("account_departure_public_leave_observation={:?}", observe_public_leave_failure(&reopened_app, peer, relay_database).await.map(|o| (o.administrator_epoch,o.administrator_pending_proposals,o.source_sent_proposals,o.administrator_received_proposals,o.administrator_processed_proposals,o.source_pending_fanouts,o.relay_retained_proposals,o.same_epoch,o.same_epoch_authenticator,o.same_selected_head,o.source_proposal_states)).map_err(|_| "Unknown"));
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
                let mls = runtime.group_mls_state("test", &peer.group).await;
                eprintln!("account_departure_timeout_peer={index} actual_mls_lifecycle={:?}",mls.map(|state|(state.lifecycle_state,state.epoch,state.unrecoverable,state.member_count)).map_err(|error|error.privacy_safe_kind()));
                let app = if index == 1 { &reopened_app } else { &apps[index] };
                let store = app.account_storage("test").unwrap();
                eprintln!("account_departure_timeout_peer={index} stored_group_flags={:?}",store.get_group(&peer.group).map(|row|(row.removed,row.unrecoverable,row.epoch.0)).map_err(|_|"Unknown"));
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
    drop(publication_gate.take());
    let closed = reopened.shutdown_and_close().await.is_ok() && reopened.storage_is_closed();
    eprintln!("account_departure_reopened_b_closed={closed}");
    if let Err(original) = result {
        std::panic::resume_unwind(original);
    }
    assert!(closed, "reopened B owner must positively close");
}

#[derive(Debug)]
struct PublicLeaveObservation {
    administrator_epoch: u64,
    administrator_pending_proposals: usize,
    source_sent_proposals: usize,
    administrator_received_proposals: usize,
    administrator_processed_proposals: usize,
    source_pending_fanouts: usize,
    relay_retained_proposals: usize,
    same_epoch: bool,
    same_epoch_authenticator: bool,
    same_selected_head: bool,
    source_proposal_states: [usize; 8],
}

/// Observe the actual durable proposal and administrator queue, never a grant.
async fn observe_public_leave_failure(
    source: &MarmotApp,
    peer: &TwoSourcePeer,
    relay_database: &dyn nostr_relay_builder::prelude::NostrDatabase,
) -> Result<PublicLeaveObservation, crate::AppError> {
    use cgka_traits::message::{MessageState, StoredMessagePayload};
    use cgka_traits::storage::{MessageStorage, OutboundFanoutStorage};
    use openmls::prelude::{ContentType, MlsMessageBodyIn, MlsMessageIn, ProtocolMessage};
    use tls_codec::Deserialize;
    let source = source.account_storage("test")?;
    let administrator = peer.app.account_storage("test")?;
    let (epoch, pending) =
        administrator.with_read_snapshot(|storage| -> Result<_, cgka_traits::StorageError> {
            let group = openmls::group::MlsGroup::load(
                storage.mls_storage(),
                &openmls::group::GroupId::from_slice(peer.group.as_slice()),
            )
            .map_err(|_| cgka_traits::StorageError::Backend("diagnostic MLS read failed".into()))?
            .ok_or(cgka_traits::StorageError::NotFound)?;
            Ok((group.epoch().as_u64(), group.pending_proposals().count()))
        })?;
    let source_branch = current_branch_observation(&source, &peer.group)?;
    let administrator_branch = current_branch_observation(&administrator, &peer.group)?;
    let current = source.get_group(&peer.group)?.epoch;
    let records = source.list_messages(&peer.group, current)?;
    let (mut sent, mut received, mut processed, mut relay_retained) = (0, 0, 0, 0);
    let mut source_proposal_states = [0; 8];
    for record in records.iter().take(128) {
        let Ok(payload) = StoredMessagePayload::decode(&record.payload) else {
            continue;
        };
        if payload.as_exact_transport().is_none() {
            continue;
        }
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
        let state_index = match record.state {
            MessageState::Sent => 0,
            MessageState::Created => 1,
            MessageState::Processed => 2,
            MessageState::Failed => 3,
            MessageState::Retryable => 4,
            MessageState::ConvergenceDeferred => 5,
            MessageState::PeelDeferred => 6,
            MessageState::EpochInvalidated => 7,
        };
        source_proposal_states[state_index] += 1;
        if record.state != MessageState::Sent {
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
        use sha2::{Digest, Sha256};
        let canonical_id = cgka_traits::MessageId::new(Sha256::digest(&wire.payload).to_vec());
        match administrator.get_message(&canonical_id) {
            Ok(row) => {
                received += 1;
                processed += usize::from(row.state == MessageState::Processed);
            }
            Err(cgka_traits::StorageError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let fanouts = source.list_outbound_fanouts_for_group(&peer.group)?.len();
    Ok(PublicLeaveObservation {
        administrator_epoch: epoch,
        administrator_pending_proposals: pending,
        source_sent_proposals: sent,
        administrator_received_proposals: received,
        administrator_processed_proposals: processed,
        source_pending_fanouts: fanouts,
        relay_retained_proposals: relay_retained,
        source_proposal_states,
        same_epoch: source_branch.epoch == administrator_branch.epoch,
        same_epoch_authenticator: source_branch.authenticator_digest
            == administrator_branch.authenticator_digest,
        same_selected_head: source_branch.selected_head_digest
            == administrator_branch.selected_head_digest,
    })
}

fn assert_administrator_holds_only_a(peer: &TwoSourcePeer, epoch: cgka_traits::EpochId) {
    use openmls::prelude::{Proposal, Sender};
    let store = peer.app.account_storage("test").unwrap();
    let observed = store
        .with_read_snapshot(|storage| -> Result<_, cgka_traits::StorageError> {
            let group = openmls::group::MlsGroup::load(
                storage.mls_storage(),
                &openmls::group::GroupId::from_slice(peer.group.as_slice()),
            )
            .unwrap()
            .unwrap();
            let staged = group
                .pending_commit()
                .expect("D actual Core pending commit must precede publication");
            let leaves: Vec<_> = staged
                .queued_proposals()
                .filter(|proposal| matches!(proposal.proposal(), Proposal::SelfRemove))
                .filter_map(|proposal| match proposal.sender() {
                    Sender::Member(index) => Some(index.u32()),
                    _ => None,
                })
                .collect();
            Ok((group.epoch().as_u64(), leaves))
        })
        .unwrap();
    assert_eq!(observed.0, epoch.0);
    assert_eq!(
        observed.1,
        vec![peer.a_index],
        "held genuine pending commit must remove A only, not B"
    );
    assert_eq!(stored_indices(&peer.app, &peer.group).len(), 3);
}

struct CurrentBranchObservation {
    epoch: u64,
    authenticator_digest: [u8; 32],
    selected_head_digest: [u8; 32],
}
fn current_branch_observation(
    storage: &storage_sqlite::SqliteAccountStorage,
    group: &cgka_traits::GroupId,
) -> Result<CurrentBranchObservation, cgka_traits::StorageError> {
    use openmls_traits::storage::{CURRENT_VERSION, StorageProvider as OpenMlsStorageProvider};
    use sha2::{Digest, Sha256};
    use tls_codec::Serialize;
    storage.with_read_snapshot(|storage| -> Result<_,cgka_traits::StorageError> {
        let id = openmls::group::GroupId::from_slice(group.as_slice());
        let group = openmls::group::MlsGroup::load(storage.mls_storage(),&id)
            .map_err(|_|cgka_traits::StorageError::Backend("diagnostic MLS branch unavailable".into()))?
            .ok_or(cgka_traits::StorageError::NotFound)?;
        let context: openmls::group::GroupContext = <<storage_sqlite::SqliteAccountStorage as cgka_traits::StorageProvider>::Mls as OpenMlsStorageProvider<CURRENT_VERSION>>::group_context(storage.mls_storage(), &id)
            .map_err(|_|cgka_traits::StorageError::Backend("diagnostic selected head unavailable".into()))?
            .ok_or(cgka_traits::StorageError::NotFound)?;
        let context = context.tls_serialize_detached().map_err(|_|cgka_traits::StorageError::Serialization("diagnostic selected head unavailable".into()))?;
        Ok(CurrentBranchObservation {epoch:group.epoch().as_u64(), authenticator_digest:Sha256::digest(group.epoch_authenticator().as_slice()).into(), selected_head_digest:Sha256::digest(context).into()})
    })
}
