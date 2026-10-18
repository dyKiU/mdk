//! Genuine account-wide departure: A/B are independent ordinary MLS leaves,
//! C is mirrored-only, and unrelated administrator D performs public removals.
use super::automatic_two_source_leave_acceptance::{
    TwoSourcePeer, stored_indices, wait_for_paired_records,
};
use super::*;
use cgka_traits::StorageProvider;
use cgka_traits::storage::{GroupStorage, LeaveRequestStorage, MessageStorage};
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

#[test]
fn account_departure_completes_when_source_branch_wins_same_epoch_race() {
    crate::tests::run_composed_app_runtime_test("account-wide-departure-source-wins", || async {
        Box::pin(actual::run_native_public_three_device_enrollment(
            actual::ApprovalScenario::AutomaticAccountDepartureSourceWins,
        ))
        .await;
    });
}

#[test]
fn authenticated_identical_departure_retry_preserves_completion_receipt_delivery() {
    crate::tests::run_composed_app_runtime_test(
        "account-wide-departure-duplicate-receipt",
        || async {
            Box::pin(actual::run_native_public_three_device_enrollment(
                actual::ApprovalScenario::AutomaticAccountDepartureDuplicateReceipt,
            ))
            .await;
        },
    );
}

pub(super) async fn verify(
    apps: &[MarmotApp; 3],
    runtimes: &[MarmotAppRuntime; 3],
    peer: &TwoSourcePeer,
    relay_url: &str,
    relay_database: &dyn nostr_relay_builder::prelude::NostrDatabase,
    ordered: bool,
    duplicate_probe: Option<&std::sync::Arc<crate::client::DuplicateDepartureProbe>>,
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
    let consent_rounds: [_; 3] = std::array::from_fn(|index| {
        apps[index]
            .account_storage("test")
            .unwrap()
            .private_roster_settlement_storage()
            .unwrap()
            .read_round()
            .unwrap()
            .unwrap()
    });
    assert!(
        consent_rounds.iter().all(
            |round| round.anchor.account == consent_rounds[0].anchor.account
                && round.anchor.group_id == consent_rounds[0].anchor.group_id
        ),
        "Consent diagnostics must observe the actual same-account protected group"
    );
    let consent_devices = std::array::from_fn(|index| consent_rounds[index].anchor.local_device);
    let consent_roots: [std::path::PathBuf; 3] =
        std::array::from_fn(|index| apps[index].account_home().root().to_path_buf());
    let consent_probe = crate::AppClient::test_capture_automatic_consent_delivery(
        consent_rounds[0].anchor.account,
        consent_rounds[0].anchor.group_id.clone(),
        std::array::from_fn(|index| consent_roots[index].as_path()),
        consent_devices,
    );
    eprintln!("account_departure_actual_consent_observer_armed=true");
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
    let expect_b_branch_switch = peer
        .app
        .account_home()
        .account("test")
        .unwrap()
        .account_id_hex
        < apps[0]
            .account_home()
            .account("test")
            .unwrap()
            .account_id_hex;
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
    let mut reopened_app = MarmotApp::with_relay(apps[1].account_home().root(), relay_url);
    let mut reopened = MarmotAppRuntime::new(reopened_app.clone());
    let result =
        std::panic::AssertUnwindSafe(async {
            let mut published_branch = None;
            let mut canonical_probe = None;
            let mut administrator_canonical_probe = None;
            let mut administrator_publication_observation = None;
            let mut leave_reproposal_hold = None;
            let mut reopened_after_branch_switch = false;
            let mut requested_before_reanchor = None;
            if !ordered {
                let administrator = peer.app.account_storage("test").unwrap();
                let identity = cgka_traits::MemberId::new(hex::decode(peer.app.account_home().account("test").unwrap().account_id_hex).unwrap());
                let content = actual_confirmed_commit_content(&administrator,&peer.group,epoch_before,&identity);
                canonical_probe = Some(cgka_engine::canonical_probe_observer::Probe::arm(peer.group.clone(),peer.b_index,content));
                let own_leaf = administrator.with_read_snapshot(|storage| -> Result<_, cgka_traits::StorageError> {
                    let group = openmls::group::MlsGroup::load(storage.mls_storage(), &openmls::group::GroupId::from_slice(peer.group.as_slice()))
                        .map_err(|_|cgka_traits::StorageError::Backend("fixture MLS read failed".into()))?
                        .ok_or(cgka_traits::StorageError::NotFound)?;
                    Ok(group.own_leaf_index().u32())
                }).unwrap();
                let source_account = cgka_traits::MemberId::new(hex::decode(reopened_app.account_home().account("test").unwrap().account_id_hex).unwrap());
                administrator_publication_observation = Some(reopened.relay_plane_for_test().observe_next_ordinary_commit(
                    source_account, peer.group.clone(), epoch_before.0, own_leaf,
                    reopened_app.account_storage("test").unwrap(),
                ));
                eprintln!("account_departure_nonordered_commit_observers_armed=true");
                if duplicate_probe.is_some() { eprintln!("account_departure_duplicate_actual_administrator_commit_observer_armed=true"); }
            }
            reopened.reconcile_accounts().await.unwrap();
            if ordered {
                let mut publication_wait_polls = 0_u64;
                let mut publication_wait_empty = 0_u64;
                let mut publication_wait_queued = 0_u64;
                let mut publication_wait_published = 0_u64;
                tokio::time::timeout(std::time::Duration::from_secs(20), async {
                    loop {
                        let store = reopened_app.account_storage("test").unwrap();
                        let round = store.private_roster_settlement_storage().unwrap().read_round().unwrap().unwrap();
                        let work = store.pending_local_account_chat_departures(&round.anchor.account,&round.anchor.local_device,None,16).unwrap();
                        publication_wait_polls += 1;
                        publication_wait_empty += u64::from(work.is_empty());
                        publication_wait_queued += work.iter().filter(|(_,state)|*state==storage_sqlite::account_chat_departure::AccountChatDepartureLocalState::Queued).count() as u64;
                        publication_wait_published += work.iter().filter(|(_,state)|*state==storage_sqlite::account_chat_departure::AccountChatDepartureLocalState::Published).count() as u64;
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
                }).await.expect(&format!("B must independently commit A and actually publish SelfRemove before the competing D commit: polls={publication_wait_polls}, empty={publication_wait_empty}, queued_rows={publication_wait_queued}, published_rows={publication_wait_published}"));
                assert_administrator_holds_only_a(peer,epoch_before);
                eprintln!("account_departure_ordering_b_independent_next_epoch_proposal_retained=true");
                {
                    use cgka_traits::storage::MessageStorage;
                    use sha2::{Digest, Sha256};
                    let source = peer.app.account_storage("test").unwrap().get_message(held_commit_id.as_ref().unwrap()).unwrap();
                    let payload = cgka_traits::message::StoredMessagePayload::decode(&source.payload).unwrap();
                    let wire = payload.as_openmls_wire().unwrap();
                    canonical_probe = Some(cgka_engine::canonical_probe_observer::Probe::arm(peer.group.clone(),peer.b_index,cgka_traits::MessageId::new(Sha256::digest(&wire.payload).to_vec())));
                }
                requested_before_reanchor = Some(reopened_app.account_storage("test").unwrap().leave_request(&peer.group).unwrap().unwrap().requested_at_ms);
                if expect_b_branch_switch {
                    leave_reproposal_hold = Some(canonical_probe.as_ref().unwrap().hold_leave_reproposal());
                } else {
                    let administrator = peer.app.account_storage("test").unwrap();
                    let own_leaf = administrator.with_read_snapshot(|storage| -> Result<_, cgka_traits::StorageError> {
                        let group = openmls::group::MlsGroup::load(storage.mls_storage(), &openmls::group::GroupId::from_slice(peer.group.as_slice())).map_err(|_|cgka_traits::StorageError::Backend("fixture MLS read failed".into()))?.ok_or(cgka_traits::StorageError::NotFound)?;
                        Ok(group.own_leaf_index().u32())
                    }).unwrap();
                    let source = reopened_app.account_storage("test").unwrap();
                    let content = actual_confirmed_commit_content(&source,&peer.group,epoch_before,&cgka_traits::MemberId::new(hex::decode(reopened_app.account_home().account("test").unwrap().account_id_hex).unwrap()));
                    administrator_canonical_probe = Some(cgka_engine::canonical_probe_observer::Probe::arm(peer.group.clone(),own_leaf,content));
                }
                drop(publication_gate.take());
            }
            let mut observed_losing_branch = false;
            let mut duplicate_deadline_expired=false;
            let completion = tokio::time::timeout(std::time::Duration::from_secs(50), async {
                loop {
                    if let Some(published) = &published_branch {
                        let current = current_branch_observation(&reopened_app.account_storage("test").unwrap(), &peer.group).unwrap();
                        observed_losing_branch |= current.epoch == published.epoch && current.authenticator_digest != published.authenticator_digest && current.selected_head_digest != published.selected_head_digest;
                    }
                    if ordered && expect_b_branch_switch && observed_losing_branch && !reopened_after_branch_switch {
                        let store = reopened_app.account_storage("test").unwrap();
                        let request = store.leave_request(&peer.group).unwrap().unwrap();
                        assert_eq!(request.group_id, peer.group);
                        assert_eq!(Some(request.requested_at_ms), requested_before_reanchor);
                        drop(store);
                        assert_eq!(request.last_proposed_epoch, None, "actual same-epoch branch replacement must durably reanchor the existing leave intent");
                        reopened.shutdown_and_close().await.unwrap();
                        assert!(reopened.storage_is_closed());
                        drop(leave_reproposal_hold.take());
                        reopened_app = MarmotApp::with_relay(apps[1].account_home().root(), relay_url);
                        reopened = MarmotAppRuntime::new(reopened_app.clone());
                        reopened.reconcile_accounts().await.unwrap();
                        reopened_after_branch_switch = true;
                        eprintln!("account_departure_ordering_losing_branch_closed_before_reproposal=true");
                    }
                    if let Some(probe)=duplicate_probe && probe.first_held().is_some_and(|held|held.elapsed()>=std::time::Duration::from_secs(30)) {
                        duplicate_deadline_expired=true;
                        break;
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
                        if ordered && expect_b_branch_switch {
                            assert!(reopened_after_branch_switch, "actual losing branch must survive fresh same-root reopening before departure completes");
                            assert!(observed_losing_branch, "real competing D branch must replace B published proposal branch before qualifying this case");
                            eprintln!("account_departure_ordering_same_epoch_published_branch_replaced=true");
                        }
                        if ordered && !expect_b_branch_switch {
                            let b = canonical_probe.as_ref().unwrap().snapshot();
                            let d = administrator_canonical_probe.as_ref().unwrap().snapshot();
                            assert!(b.target_lost_by_committer, "real equal-prior-score source winner must be observed on B");
                            assert!(d.target_won_by_committer, "D must actually select the authenticated source branch");
                            eprintln!("account_departure_ordering_real_source_branch_selected_by_committer=true");
                        }
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await;
            if completion.is_err() || duplicate_deadline_expired {
                let diagnostics = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                std::panic::AssertUnwindSafe(async {
            let indices = stored_indices(&peer.app, &peer.group);
            if let Some(probe) = &canonical_probe { eprintln!("account_departure_timeout_canonical_probe={:?}",probe.snapshot()); }
            if let Some(probe) = &administrator_canonical_probe { eprintln!("account_departure_timeout_administrator_canonical_probe={:?}",probe.snapshot()); }
            if let Some(observation) = &administrator_publication_observation {
                eprintln!("account_departure_timeout_administrator_publication_probe={:?}", observation.snapshot());
            }
            for (index, app) in [(1, &reopened_app), (3, &peer.app)] {
                use cgka_traits::storage::ConvergencePassStorage;
                let pass = app.account_storage("test").map_err(|_| "Unknown")
                    .and_then(|store| store.convergence_pass(&peer.group).map_err(|_| "Unknown"));
                eprintln!("account_departure_timeout_convergence_pass_peer={index} observation={:?}", pass.map(|pass| pass.map(|pass| {
                    let mut roles = [0usize; 3];
                    for member in &pass.members {
                        let index = match member.role {
                            cgka_traits::convergence_pass::ConvergencePassMemberRole::CommitEdge => 0,
                            cgka_traits::convergence_pass::ConvergencePassMemberRole::ProposalDependency => 1,
                            cgka_traits::convergence_pass::ConvergencePassMemberRole::AppWitnessCandidate => 2,
                        };
                        roles[index] += 1;
                    }
                    (pass.phase, pass.generation, pass.base_epoch.0, roles, pass.fairness_slot_available)
                })));
            }
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
                for policy in policies.iter().take(128) {
                    let actual_peer_index = [(0,&apps[0]),(1,&reopened_app),(2,&apps[2])].into_iter().find_map(|(candidate,app)| {
                        let storage = app.account_storage("test").ok()?;
                        let round = storage.private_roster_settlement_storage()?.read_round().ok()??;
                        (round.anchor.local_device==policy.peer_device).then_some(candidate)
                    });
                    let outbox = store.account_chat_departure_outbox(&round.anchor.account,&round.anchor.local_device,&policy.peer_device,None,16);
                    eprintln!("account_departure_timeout_peer={index} target_peer={actual_peer_index:?} outbox={:?}",outbox.map(|rows| {
                        let mut kinds=[0usize;4];
                        let(mut complete,mut needs_administrator,mut awaiting_sources)=(0,0,0);
                        for row in rows.iter().filter(|row|row.intent.group==peer.group) {
                            let kind=match row.kind {
                                storage_sqlite::account_chat_departure::AccountChatDepartureDeliveryKind::Intent=>0,
                                storage_sqlite::account_chat_departure::AccountChatDepartureDeliveryKind::StatusReceipt=>1,
                                storage_sqlite::account_chat_departure::AccountChatDepartureDeliveryKind::CompletionNotice=>2,
                                storage_sqlite::account_chat_departure::AccountChatDepartureDeliveryKind::CompletionAcknowledgement=>3,
                            };
                            kinds[kind]+=1;
                            complete+=usize::from(row.complete);
                            needs_administrator+=usize::from(row.needs_administrator);
                            awaiting_sources+=usize::from(row.awaiting_sources);
                        }
                        (kinds,complete,needs_administrator,awaiting_sources)
                    }).map_err(|_|"Unknown"));
                }
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
            if let Some(probe)=duplicate_probe {
                let counters=probe.counters();
                eprintln!("account_departure_duplicate_receipt captured={} first_hold={} counters={counters:?}",probe.captured(),probe.first_held().is_some());
                assert!(probe.captured() && probe.first_held().is_some() && counters.1>0 && counters.2>0,"real queued complete receipt and authenticated identical intent must execute");
                let indices=stored_indices(&peer.app,&peer.group);
                assert!(indices.len()==1 && !indices.contains(&peer.a_index) && !indices.contains(&peer.b_index),"real public removals must precede the completion receipt assertion");
                assert!(!duplicate_deadline_expired,"authenticated duplicate cut must not prevent actual completion receipt delivery within 30s");
            }
            eprintln!("account_departure_required_proposal_provenance={:?}", observed_required_proposal_provenance(&reopened_app,&peer.app,&peer.group,epoch_before));
            if !ordered {
                eprintln!("account_departure_nonordered_d_commit_at_b={:?}", canonical_probe.as_ref().map(|probe| probe.snapshot()));
                eprintln!("account_departure_nonordered_b_commit_at_d={:?}", administrator_publication_observation.as_ref().map(|observation| observation.snapshot()));
            }
            let consent_snapshot = consent_probe.snapshot();
            let consent_summary = consent_snapshot.summary();
            eprintln!("account_departure_actual_consent_summary prepared={} ack_unseen={} attempts={:?} dropped={:?} receive_attempts={:?} receive_dropped={:?} published={} expired={} details={consent_summary:?}",
                consent_summary.prepared, consent_summary.ack_unseen,
                consent_summary.attempts, consent_summary.dropped,
                consent_summary.receive_attempts, consent_summary.receive_dropped,
                consent_summary.published, consent_summary.expired);
            for (attempt, observed) in consent_snapshot.records.iter().enumerate() {
                let sender = consent_devices.iter().position(|device| *device == observed.publication.local_device).unwrap();
                let receiver = consent_devices.iter().position(|device| *device == observed.publication.peer_device).unwrap();
                eprintln!("account_departure_actual_consent_route={attempt} sender={sender} receiver={receiver} event_seen={} incomplete={} auth={:?} nonce_matches={} automatic_matched={} bound={} dispatch={:?}",
                    observed.event_seen, observed.observation_incomplete,
                    observed.authentication.map(|outcome| outcome.label()),
                    observed.authenticated_nonce_matches, observed.automatic_matched, observed.consent_bound,
                    observed.dispatch.map(|outcome| outcome.label()));
            }
            if completion.is_err() {
                let consent_diagnostics = tokio::time::timeout(std::time::Duration::from_secs(5),
                    std::panic::AssertUnwindSafe(async {
                for (attempt, observed) in consent_snapshot.records.iter().enumerate() {
                    let sender = consent_devices.iter().position(|device| *device == observed.publication.local_device).unwrap();
                    let receiver = consent_devices.iter().position(|device| *device == observed.publication.peer_device).unwrap();
                    // Compare the canonical MLS content ID and actual report ID
                    // in their separate domains. Missing observations under a
                    // truncated receive buffer remain explicitly unknown.
                    let app = if receiver == 1 { &reopened_app } else { &apps[receiver] };
                    assert!(app.account_home().root() == observed.receiver_root);
                    let store = app.account_storage("test").unwrap();
                    let row = |id: &cgka_traits::MessageId| match store.get_message(id) {
                        Ok(record) => Ok(Some((record.epoch.0, record.state))),
                        Err(cgka_traits::StorageError::NotFound) => Ok(None),
                        Err(_) => Err("Unknown"),
                    };
                    eprintln!("account_departure_actual_consent_attempt={attempt} sender={sender} receiver={receiver} raw_seen={} raw_input_hash_matches={} event_seen={} incomplete={} auth={:?} nonce_matches={} automatic_matched={} bound={} dispatch={:?} canonical_row={:?} report_row={:?}",
                        observed.raw_id_seen, observed.raw_payload_hash_matches, observed.event_seen,
                        observed.observation_incomplete, observed.authentication.map(|outcome| outcome.label()),
                        observed.authenticated_nonce_matches, observed.automatic_matched, observed.consent_bound,
                        observed.dispatch.map(|outcome| outcome.label()), row(&observed.publication.content_id), row(&observed.publication.outer_id));
                }
                    }).catch_unwind()).await;
                eprintln!("account_departure_consent_diagnostics_completed={} unknown={}",
                    matches!(consent_diagnostics, Ok(Ok(()))), !matches!(consent_diagnostics, Ok(Ok(()))));
            }
            if completion.is_ok() {
                assert!(consent_snapshot.records.iter().any(|record|
                    (record.publication.local_device == consent_devices[1] && record.publication.peer_device == consent_devices[2])
                    || (record.publication.local_device == consent_devices[2] && record.publication.peer_device == consent_devices[1])),
                    "actual fresh B/C Consent publication must execute the diagnostic body");
                eprintln!("account_departure_actual_b_c_consent_publication_observed=true");
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
    if let Some(probe) = duplicate_probe {
        eprintln!(
            "account_departure_duplicate_cleanup captured={} first_hold={} counters={:?}",
            probe.captured(),
            probe.first_held().is_some(),
            probe.counters()
        );
    }
    let closed = reopened.shutdown_and_close().await.is_ok() && reopened.storage_is_closed();
    eprintln!("account_departure_reopened_b_closed={closed}");
    if let Err(original) = result {
        std::panic::resume_unwind(original);
    }
    assert!(closed, "reopened B owner must positively close");
}

type RequiredProposalProvenance = (Option<[usize; 3]>, Option<bool>, [usize; 8]);

// Observation only: no packet/permission is reconstructed from these references.
fn observed_required_proposal_provenance(
    source: &MarmotApp,
    administrator: &MarmotApp,
    group: &cgka_traits::GroupId,
    epoch: cgka_traits::EpochId,
) -> Result<RequiredProposalProvenance, &'static str> {
    use cgka_traits::{
        message::{MessageState, StoredMessagePayload},
        storage::MessageStorage,
    };
    use openmls::prelude::{ContentType, MlsMessageBodyIn, MlsMessageIn, ProtocolMessage};
    use tls_codec::Deserialize;
    let mut reference_sets = Vec::new();
    let mut proposal_states = [0usize; 8];
    for (index, app) in [source, administrator].into_iter().enumerate() {
        let identity = cgka_traits::MemberId::new(
            hex::decode(
                app.account_home()
                    .account("test")
                    .map_err(|_| "account_read_failed")?
                    .account_id_hex,
            )
            .map_err(|_| "account_decode_failed")?,
        );
        let rows = app
            .account_storage("test")
            .map_err(|_| "storage_open_failed")?
            .list_messages(group, epoch)
            .map_err(|_| "message_read_failed")?;
        if rows.len() > 128 {
            return Err("observation_capacity");
        }
        let mut refs = None;
        for row in rows {
            let payload =
                StoredMessagePayload::decode(&row.payload).map_err(|_| "stored_decode_failed")?;
            let Some(wire) = payload.as_openmls_wire() else {
                continue;
            };
            let message = MlsMessageIn::tls_deserialize_exact(&wire.payload)
                .map_err(|_| "MLS_decode_failed")?;
            let protocol: ProtocolMessage = match message.extract() {
                MlsMessageBodyIn::PublicMessage(message) => message.into(),
                MlsMessageBodyIn::PrivateMessage(message) => message.into(),
                _ => continue,
            };
            if protocol.epoch().as_u64() != epoch.0 {
                continue;
            }
            if index == 0 && protocol.content_type() == ContentType::Proposal {
                let state = match row.state {
                    MessageState::Sent => 0,
                    MessageState::Created => 1,
                    MessageState::Processed => 2,
                    MessageState::Failed => 3,
                    MessageState::Retryable => 4,
                    MessageState::ConvergenceDeferred => 5,
                    MessageState::PeelDeferred => 6,
                    MessageState::EpochInvalidated => 7,
                };
                proposal_states[state] += 1;
            }
            if protocol.content_type() != ContentType::Commit {
                continue;
            }
            let Some(stamp) = payload.own_commit_stamp() else {
                continue;
            };
            if stamp.committer != identity
                || stamp.checkpoint_id.is_none()
                || stamp.resulting_epoch_authenticator.is_none()
            {
                continue;
            }
            if refs.is_some() {
                return Err("ambiguous_confirmed_commit");
            }
            refs = Some(
                stamp
                    .consumed_proposal_refs
                    .iter()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>(),
            );
        }
        reference_sets.push(refs);
    }
    match (&reference_sets[0], &reference_sets[1]) {
        (Some(source), Some(administrator)) => Ok((
            Some([
                source.len(),
                administrator.len(),
                source.intersection(administrator).count(),
            ]),
            Some(source == administrator),
            proposal_states,
        )),
        _ => Ok((None, None, proposal_states)),
    }
}

fn actual_confirmed_commit_content(
    storage: &storage_sqlite::SqliteAccountStorage,
    group: &cgka_traits::GroupId,
    epoch: cgka_traits::EpochId,
    identity: &cgka_traits::MemberId,
) -> cgka_traits::MessageId {
    use cgka_traits::{message::StoredMessagePayload, storage::MessageStorage};
    use openmls::prelude::{ContentType, MlsMessageBodyIn, MlsMessageIn, ProtocolMessage};
    use sha2::{Digest, Sha256};
    use tls_codec::Deserialize;
    let mut commits = Vec::new();
    for row in storage
        .list_messages(group, epoch)
        .unwrap()
        .iter()
        .take(128)
    {
        let payload = StoredMessagePayload::decode(&row.payload).unwrap();
        let Some(stamp) = payload.own_commit_stamp() else {
            continue;
        };
        if stamp.committer != *identity
            || stamp.checkpoint_id.is_none()
            || stamp.resulting_epoch_authenticator.is_none()
        {
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
        if protocol.content_type() == ContentType::Commit && protocol.epoch().as_u64() == epoch.0 {
            commits.push(cgka_traits::MessageId::new(
                Sha256::digest(&wire.payload).to_vec(),
            ));
        }
    }
    assert_eq!(
        commits.len(),
        1,
        "exact actual source commit must precede release"
    );
    commits.pop().unwrap()
}

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
    // Direction0 is B→D, direction1 is D→B. The ninth state is NotFound.
    confirmed_own_commits: [usize; 2],
    received_commit_states: [[usize; 9]; 2],
    relay_commits: [usize; 2],
}

impl std::fmt::Debug for PublicLeaveObservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublicLeaveObservation")
            .field("administrator_epoch", &self.administrator_epoch)
            .field(
                "administrator_pending_proposals",
                &self.administrator_pending_proposals,
            )
            .field("source_sent_proposals", &self.source_sent_proposals)
            .field(
                "administrator_received_proposals",
                &self.administrator_received_proposals,
            )
            .field(
                "administrator_processed_proposals",
                &self.administrator_processed_proposals,
            )
            .field("source_pending_fanouts", &self.source_pending_fanouts)
            .field("relay_retained_proposals", &self.relay_retained_proposals)
            .field("same_epoch", &self.same_epoch)
            .field("same_epoch_authenticator", &self.same_epoch_authenticator)
            .field("same_selected_head", &self.same_selected_head)
            .field("source_proposal_states", &self.source_proposal_states)
            .field("confirmed_own_commits", &self.confirmed_own_commits)
            .field("received_commit_states", &self.received_commit_states)
            .field("relay_commits", &self.relay_commits)
            .finish()
    }
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
    let source_identity = cgka_traits::MemberId::new(
        hex::decode(source.account_home().account("test")?.account_id_hex).map_err(|_| {
            cgka_traits::StorageError::Serialization("diagnostic owner unavailable".into())
        })?,
    );
    let administrator_identity = cgka_traits::MemberId::new(
        hex::decode(peer.app.account_home().account("test")?.account_id_hex).map_err(|_| {
            cgka_traits::StorageError::Serialization("diagnostic owner unavailable".into())
        })?,
    );
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
    let mut confirmed_own_commits = [0; 2];
    let mut received_commit_states = [[0; 9]; 2];
    let mut relay_commits = [0; 2];
    if current.0 > 0 {
        for (direction, (sender, receiver, identity)) in [
            (&source, &administrator, &source_identity),
            (&administrator, &source, &administrator_identity),
        ]
        .into_iter()
        .enumerate()
        {
            for record in sender
                .list_messages(&peer.group, cgka_traits::EpochId(current.0 - 1))?
                .iter()
                .take(128)
            {
                let Ok(payload) = StoredMessagePayload::decode(&record.payload) else {
                    continue;
                };
                let Some(stamp) = payload.own_commit_stamp() else {
                    continue;
                };
                if stamp.committer != *identity
                    || stamp.checkpoint_id.is_none()
                    || stamp.resulting_epoch_authenticator.is_none()
                {
                    continue;
                }
                let (Some(exact), Some(wire)) =
                    (payload.as_exact_transport(), payload.as_openmls_wire())
                else {
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
                if protocol.content_type() != ContentType::Commit
                    || protocol.epoch().as_u64() != current.0 - 1
                {
                    continue;
                }
                confirmed_own_commits[direction] += 1;
                let id = nostr_relay_builder::prelude::EventId::from_slice(exact.id.as_slice())
                    .map_err(|_| {
                        cgka_traits::StorageError::Serialization(
                            "diagnostic commit unavailable".into(),
                        )
                    })?;
                relay_commits[direction] += usize::from(
                    relay_database
                        .event_by_id(&id)
                        .await
                        .map_err(|_| {
                            cgka_traits::StorageError::Backend(
                                "diagnostic relay read failed".into(),
                            )
                        })?
                        .is_some(),
                );
                use sha2::{Digest, Sha256};
                let id = cgka_traits::MessageId::new(Sha256::digest(&wire.payload).to_vec());
                let state = match receiver.get_message(&id) {
                    Ok(row) => match row.state {
                        MessageState::Sent => 0,
                        MessageState::Created => 1,
                        MessageState::Processed => 2,
                        MessageState::Failed => 3,
                        MessageState::Retryable => 4,
                        MessageState::ConvergenceDeferred => 5,
                        MessageState::PeelDeferred => 6,
                        MessageState::EpochInvalidated => 7,
                    },
                    Err(cgka_traits::StorageError::NotFound) => 8,
                    Err(error) => return Err(error.into()),
                };
                received_commit_states[direction][state] += 1;
            }
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
        confirmed_own_commits,
        received_commit_states,
        relay_commits,
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
pub(super) fn compare_actual_branches_for_test(
    source: &storage_sqlite::SqliteAccountStorage,
    recipient: &storage_sqlite::SqliteAccountStorage,
    group: &cgka_traits::GroupId,
) -> Result<(u64, u64, bool, bool), cgka_traits::StorageError> {
    let source = current_branch_observation(source, group)?;
    let recipient = current_branch_observation(recipient, group)?;
    Ok((
        source.epoch,
        recipient.epoch,
        source.authenticator_digest == recipient.authenticator_digest,
        source.selected_head_digest == recipient.selected_head_digest,
    ))
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
