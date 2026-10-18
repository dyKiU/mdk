//! Five real local installations; no synthetic Core state, copied DB or implicit approvals.
use super::*;
use crate::AccountManager;
use cgka_traits::storage::{AccountDeviceSignerStorage, StorageProvider};
use cgka_traits::{MemberId, private_roster_settlement::PrivateSettlementPhase};
use futures::FutureExt;
use std::collections::BTreeSet;
use std::time::Duration;

// Cumulative for this recipient RuntimeShared (all its accounts), not this join.
// No hot-path hook, command, SQL or Core call. Snapshot fields are independently
// sampled; completed durations are wall time, not CPU or an exclusive breakdown.
#[cfg(feature = "test-policy-overrides")]
fn native5_runtime_report(runtime: Option<&crate::MarmotAppRuntime>) -> String {
    use crate::RuntimePerformanceOperation as Op;
    let observation = runtime
        .map(|runtime| {
            let snapshot = runtime.app_performance_snapshot();
            let operations = [
                Op::WorkerReceive,
                Op::Ingest,
                Op::WorkerMaintenance,
                Op::IngestEngine,
            ]
            .map(|operation| {
                snapshot
                    .runtime_operations
                    .iter()
                    .find(|row| row.operation == operation)
                    .map(|row| {
                        [
                            row.started,
                            row.completed,
                            row.in_flight,
                            row.duration_ms.sum_ms,
                            row.oldest_tracked_in_flight_ms,
                            row.untracked_in_flight,
                        ]
                    })
            });
            let projection = snapshot.inbound_delivery_projection;
            (
                operations,
                Some([
                    projection.attempts,
                    projection.failures,
                    projection.duration_ms.sum_ms,
                ]),
            )
        })
        .unwrap_or(([None; 4], None));
    // Core phase records are completed-only: zero active cannot exclude Core work.
    // Oldest age zero means no tracked start (or <1ms); untracked stays explicit.
    format!("native5-runtime observation={observation:?}\n")
}

// Read only the same actual recipient plane/account using the immutable first
// proof IDs supplied by native freeze. No worker ordinal or account-label guess.
#[cfg(feature = "test-policy-overrides")]
fn native5_prefix_report(
    plane: &transport_nostr::MarmotRelayPlane,
    account: &MemberId,
    origin: std::time::Instant,
    ids: &[Option<cgka_traits::MessageId>; 3],
) -> String {
    use std::fmt::Write as _;
    let keys = ids
        .each_ref()
        .map(|id| id.as_ref().map(|id| hex::encode(id.as_slice())));
    let snapshot = plane
        .account_notification_prefix_for_test(account, keys.each_ref().map(|key| key.as_deref()));
    let mut output = String::new();
    if let Some(snapshot) = snapshot {
        let _ = writeln!(
            &mut output,
            "native5-prefix observed=true entries=Some({}) at_capacity=Some({})",
            snapshot.entries, snapshot.at_capacity
        );
        for (index, row) in snapshot.rows.into_iter().enumerate() {
            let row = row.map(|row| {
                let mut invalid = row.invalid;
                let mut relative = |instant: std::time::Instant| {
                    let value = instant
                        .checked_duration_since(origin)
                        .and_then(|duration| u64::try_from(duration.as_micros()).ok())
                        .filter(|value| *value <= 600_000_000);
                    if value.is_none() {
                        invalid = true;
                    }
                    value
                };
                let anchor = relative(row.target_first_accepted);
                let first = row
                    .earliest_qualifying_first_dequeue
                    .and_then(&mut relative);
                let last = row.latest_qualifying_first_dequeue.and_then(&mut relative);
                (
                    anchor,
                    row.qualifying_distinct,
                    row.qualifying_callbacks,
                    row.older_without_dequeue,
                    row.older_first_dequeued_before_anchor,
                    first,
                    last,
                    invalid,
                )
            });
            let _ = writeln!(
                &mut output,
                "native5-prefix-row index={index} observation={row:?}"
            );
        }
    } else {
        let _ = writeln!(
            &mut output,
            "native5-prefix observed=false entries=None at_capacity=None"
        );
    }
    output
}

fn installation_signer(app: &MarmotApp, account: &MemberId) -> Vec<u8> {
    app.account_storage("test")
        .unwrap()
        .account_device_signer(account)
        .unwrap()
        .expect("actual installation must have its own Core signer")
        .mls_signature_public_key
}

// Read-only observations: neither the persisted round nor policies restore a live owner.
fn complete_roster_and_bilateral_policies(apps: &[MarmotApp], account: &MemberId) -> bool {
    let expected = apps
        .iter()
        .map(|app| installation_signer(app, account))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        expected.len(),
        apps.len(),
        "each installation must own a distinct real signer"
    );
    let first_storage = apps[0].account_storage("test").unwrap();
    let Some(reference) = first_storage
        .private_roster_settlement_storage()
        .unwrap()
        .read_round()
        .unwrap()
    else {
        return false;
    };
    for app in apps {
        let local = installation_signer(app, account);
        let storage = app.account_storage("test").unwrap();
        let settlement = storage.private_roster_settlement_storage().unwrap();
        let Some(round) = settlement.read_round().unwrap() else {
            return false;
        };
        let facts = settlement.read_facts().unwrap();
        let leaf_keys = round
            .anchor
            .successor
            .leaves
            .iter()
            .map(|leaf| leaf.signature_public_key.to_vec())
            .collect::<BTreeSet<_>>();
        if round.anchor.account.as_slice() != account.as_slice()
            || round.anchor.local_device.as_slice() != local.as_slice()
            || round.phase != PrivateSettlementPhase::Completed
            || round.anchor.group_id != reference.anchor.group_id
            || round.anchor.successor != reference.anchor.successor
            || round.anchor.successor.leaves.len() != apps.len()
            || leaf_keys != expected
            || round
                .anchor
                .successor
                .leaves
                .iter()
                .any(|leaf| leaf.account.as_slice() != account.as_slice())
            || facts.len() != apps.len()
            || facts.iter().any(|fact| {
                fact.generation != round.generation
                    || !round.anchor.successor.leaves.iter().any(|leaf| {
                        leaf.leaf_index == fact.leaf_index
                            && leaf.signature_public_key == fact.signature_public_key
                    })
            })
            || facts
                .iter()
                .map(|fact| fact.signature_public_key.to_vec())
                .collect::<BTreeSet<_>>()
                != expected
        {
            return false;
        }
        let policies = storage
            .approved_account_sharing_policy_storage()
            .unwrap()
            .approved_account_sharing_policies()
            .unwrap();
        let peers = expected
            .iter()
            .filter(|key| key.as_slice() != local.as_slice())
            .cloned()
            .collect::<BTreeSet<_>>();
        if policies.len() != apps.len() - 1
            || policies.iter().any(|policy| {
                policy.revoked
                    || policy.account.as_slice() != account.as_slice()
                    || policy.local_device.as_slice() != local.as_slice()
                    || policy.protected_group != round.anchor.group_id
            })
            || policies
                .iter()
                .map(|policy| policy.peer_device.to_vec())
                .collect::<BTreeSet<_>>()
                != peers
        {
            return false;
        }
    }
    true
}

// Every action below is the same explicit host API used by the original journey.
// Return owners so caller checks the full step before publicly cancelling any of them.
async fn join_installation(
    apps: &[MarmotApp],
    managers: &[AccountManager],
    account: &MemberId,
    sponsor: usize,
    newcomer: usize,
    // NATIVE5_TIMING_BEGIN
    #[cfg(feature = "test-policy-overrides")] timing: &mut Option<(
        usize,
        crate::client::device_linking::sibling_sharing::peer_proof_probe::native5_timing::Guard,
    )>,
    // NATIVE5_TIMING_END
) -> (
    DeviceLinkingSession,
    DeviceLinkingSession,
    Vec<DeviceLinkingApproval>,
) {
    assert!(sponsor < newcomer && newcomer < apps.len());
    let targets = managers[sponsor]
        .device_linking_targets("test")
        .await
        .unwrap();
    let selector = if newcomer == 1 {
        assert!(
            targets.is_empty(),
            "first sponsor must start from its actual fresh account"
        );
        None
    } else {
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].device_count as usize, newcomer);
        Some(targets[0].selector.clone())
    };
    let recipient = managers[newcomer]
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let source = managers[sponsor]
        .approve_automatic_device_linking_session(
            "test",
            recipient.automatic_pairing_code().await.unwrap(),
            selector,
        )
        .await
        .unwrap();
    source.automatic_pairing_code().await.unwrap();
    compare_and_confirm_pair(&source, &recipient).await;
    // NATIVE5_TIMING_BEGIN
    #[cfg(feature = "test-policy-overrides")]
    if newcomer == 3 || newcomer == 4 {
        *timing = Some((newcomer + 1, recipient.arm_native5_timing_for_test()));
    }
    // NATIVE5_TIMING_END
    recipient
        .continue_automatic_linking(recipient.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    source
        .continue_automatic_linking(source.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    let source_key = installation_signer(&apps[sponsor], account);
    let joining_key = installation_signer(&apps[newcomer], account);
    let mut approvals = Vec::new();
    for (index, manager) in managers[..newcomer].iter().enumerate() {
        if index == sponsor {
            continue;
        }
        let approval = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let mut pending = manager
                    .pending_device_linking_approvals("test")
                    .await
                    .unwrap();
                if !pending.is_empty() {
                    assert_eq!(
                        pending.len(),
                        1,
                        "single live join must have one exact pending approval"
                    );
                    break pending.pop().unwrap();
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("each other existing installation must receive the genuine proposal");
        let observed = approval.snapshot().await.unwrap();
        assert_eq!(observed.phase, DeviceLinkingApprovalPhase::AwaitingApproval);
        let reviewed = approval.review_metadata(observed.revision).await.unwrap();
        assert!(
            reviewed.revision == observed.revision
                && reviewed.source_device_public_key == source_key
                && reviewed.joining_device_public_key == joining_key
                && reviewed.existing_device_count as usize == newcomer,
            "review must authenticate this exact sponsor, newcomer and predecessor count"
        );
        approval
            .approve_and_share_chats(reviewed.revision)
            .await
            .unwrap();
        approvals.push(approval);
    }
    assert_eq!(approvals.len(), newcomer - 1);
    (source, recipient, approvals)
}

// Production scheduling uses two runtime workers. All original one-thread
// stress scenarios and their fixed deadlines remain separately required.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn five_installations_join_with_rotating_existing_sponsors_and_explicit_sharing() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let account = MemberId::new(keys.public_key().to_bytes().to_vec());
    let dirs: [tempfile::TempDir; 5] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
    let apps = dirs.each_ref().map(|dir| {
        AccountHome::open(dir.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        MarmotApp::with_relay(dir.path(), &url)
    });
    let runtimes = apps.clone().map(MarmotAppRuntime::new);
    let mut completed_steps = 0usize;
    let mut public_cancels = 0usize;
    let mut final_roster_and_policies = false;
    // NATIVE5_TIMING_BEGIN
    #[cfg(feature = "test-policy-overrides")]
    let mut native5_timing = None;
    #[cfg(feature = "test-policy-overrides")]
    let mut native5_timing_reports = Vec::with_capacity(2);
    // NATIVE5_TIMING_END
    let attempt = std::panic::AssertUnwindSafe(async {
        for runtime in &runtimes { runtime.reconcile_accounts().await.unwrap(); }
        let managers = runtimes.each_ref().map(|runtime| runtime.accounts());
        // New installations B,C,D,E join through already-authorized A,B,C,B.
        for (newcomer, sponsor) in [(1usize, 0usize), (2, 1), (3, 2), (4, 1)] {
            let (source, recipient, approvals) = join_installation(&apps, &managers, &account, sponsor, newcomer,
// NATIVE5_TIMING_BEGIN
                #[cfg(feature = "test-policy-overrides")]
                &mut native5_timing,
// NATIVE5_TIMING_END
            ).await;
            // Reuse the integration helper:15s for every phase;
            // no deadline override, packets or extra host finalization calls.
            wait_for_automatic_phase_with_approvals(&source, &recipient, DeviceLinkingPhase::EnrollmentComplete, &approvals).await;
// NATIVE5_TIMING_BEGIN
            #[cfg(feature = "test-policy-overrides")]
            if let Some((ordinal, guard)) = native5_timing.take() {
                let mut prefix_report = String::new();
                let mut report = guard.freeze(|origin, peer_outer_ids| {
                    prefix_report = native5_prefix_report(&apps[ordinal - 1].relay_plane, &account, origin, &peer_outer_ids);
                    std::array::from_fn(|plane| {
                        std::array::from_fn(|channel| {
                            peer_outer_ids[channel].as_ref().and_then(|message| {
                                apps[plane].relay_plane.account_notification_timing_for_test(
                                    &account, &hex::encode(message.as_slice()),
                                )
                            }).map(|(counts, instants, placements, placement_instants, queue)| {
                                let mut invalid = 0u8;
                                let times = std::array::from_fn(|stage| instants[stage].and_then(|instant| {
                                    let time = instant.checked_duration_since(origin)
                                        .and_then(|duration| u64::try_from(duration.as_micros()).ok())
                                        .filter(|time| *time <= 600_000_000);
                                    if time.is_none() { invalid |= 1 << stage; }
                                    time
                                }));
                                let mut placement_invalid = 0u8;
                                let placement_times = std::array::from_fn(|stage| placement_instants[stage].and_then(|instant| {
                                    let time = instant.checked_duration_since(origin)
                                        .and_then(|duration| u64::try_from(duration.as_micros()).ok())
                                        .filter(|time| *time <= 600_000_000);
                                    if time.is_none() { placement_invalid |= 1 << stage; }
                                    time
                                }));
                                {
                                    let (depths, dequeued, first_dequeued, mut queue_invalid) = queue;
                                    let first_dequeued_us = first_dequeued.and_then(|instant| {
                                        let time = instant.checked_duration_since(origin)
                                            .and_then(|duration| u64::try_from(duration.as_micros()).ok())
                                            .filter(|time| *time <= 600_000_000);
                                        if time.is_none() { queue_invalid = true; }
                                        time
                                    });
                                    (Some(counts), Some(times), Some(invalid), Some(placements), Some(placement_times), Some(placement_invalid), Some((depths, dequeued, first_dequeued_us, queue_invalid)))
                                }
                            }).unwrap_or((None, None, None, None, None, None, None))
                        })
                    })
                });
                // Keep every old ledger; an oversized optional appendix stays missing/unknown.
                if report.len() + prefix_report.len() <= 65536 { report.push_str(&prefix_report); }
                let runtime_report = native5_runtime_report(runtimes.get(ordinal - 1));
                // Retain every existing ledger if an optional appendix exceeds the cap.
                if report.len() + runtime_report.len() <= 65536 { report.push_str(&runtime_report); }
                native5_timing_reports.push((ordinal, report));
            }
// NATIVE5_TIMING_END
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    if complete_roster_and_bilateral_policies(&apps[..=newcomer], &account) { break; }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }).await.expect("every joined installation must settle the exact real roster and bilateral peer policies");
            for manager in &managers[..=newcomer] {
                let targets = manager.device_linking_targets("test").await.unwrap();
                assert_eq!(targets.len(), 1);
                assert_eq!(targets[0].device_count as usize, newcomer + 1);
            }
            if newcomer == 4 { final_roster_and_policies = true; }
            completed_steps += 1;
            // These actual original owners stayed alive through all step checks.
            source.cancel().await.unwrap(); public_cancels += 1;
            recipient.cancel().await.unwrap(); public_cancels += 1;
            for approval in approvals { approval.cancel().await.unwrap(); public_cancels += 1; }
        }
    }).catch_unwind().await;
    // NATIVE5_TIMING_BEGIN
    #[cfg(feature = "test-policy-overrides")]
    if let Some((ordinal, guard)) = native5_timing.take() {
        let mut prefix_report = String::new();
        let mut report = guard.freeze(|origin, peer_outer_ids| {
            prefix_report = native5_prefix_report(
                &apps[ordinal - 1].relay_plane,
                &account,
                origin,
                &peer_outer_ids,
            );
            std::array::from_fn(|plane| {
                std::array::from_fn(|channel| {
                    peer_outer_ids[channel]
                        .as_ref()
                        .and_then(|message| {
                            apps[plane]
                                .relay_plane
                                .account_notification_timing_for_test(
                                    &account,
                                    &hex::encode(message.as_slice()),
                                )
                        })
                        .map(
                            |(counts, instants, placements, placement_instants, queue)| {
                                let mut invalid = 0u8;
                                let times = std::array::from_fn(|stage| {
                                    instants[stage].and_then(|instant| {
                                        let time = instant
                                            .checked_duration_since(origin)
                                            .and_then(|duration| {
                                                u64::try_from(duration.as_micros()).ok()
                                            })
                                            .filter(|time| *time <= 600_000_000);
                                        if time.is_none() {
                                            invalid |= 1 << stage;
                                        }
                                        time
                                    })
                                });
                                let mut placement_invalid = 0u8;
                                let placement_times = std::array::from_fn(|stage| {
                                    placement_instants[stage].and_then(|instant| {
                                        let time = instant
                                            .checked_duration_since(origin)
                                            .and_then(|duration| {
                                                u64::try_from(duration.as_micros()).ok()
                                            })
                                            .filter(|time| *time <= 600_000_000);
                                        if time.is_none() {
                                            placement_invalid |= 1 << stage;
                                        }
                                        time
                                    })
                                });
                                {
                                    let (depths, dequeued, first_dequeued, mut queue_invalid) =
                                        queue;
                                    let first_dequeued_us = first_dequeued.and_then(|instant| {
                                        let time = instant
                                            .checked_duration_since(origin)
                                            .and_then(|duration| {
                                                u64::try_from(duration.as_micros()).ok()
                                            })
                                            .filter(|time| *time <= 600_000_000);
                                        if time.is_none() {
                                            queue_invalid = true;
                                        }
                                        time
                                    });
                                    (
                                        Some(counts),
                                        Some(times),
                                        Some(invalid),
                                        Some(placements),
                                        Some(placement_times),
                                        Some(placement_invalid),
                                        Some((depths, dequeued, first_dequeued_us, queue_invalid)),
                                    )
                                }
                            },
                        )
                        .unwrap_or((None, None, None, None, None, None, None))
                })
            })
        });
        if report.len() + prefix_report.len() <= 65536 {
            report.push_str(&prefix_report);
        }
        let runtime_report = native5_runtime_report(runtimes.get(ordinal - 1));
        // Retain every existing ledger if an optional appendix exceeds the cap.
        if report.len() + runtime_report.len() <= 65536 {
            report.push_str(&runtime_report);
        }
        native5_timing_reports.push((ordinal, report));
    }
    // NATIVE5_TIMING_END
    let mut runtime_closes = 0usize;
    for runtime in &runtimes {
        if runtime.shutdown_and_close().await.is_ok() && runtime.storage_is_closed() {
            runtime_closes += 1;
        }
    }
    let storages_closed = runtimes.iter().all(|runtime| runtime.storage_is_closed());
    let mut plane_shutdown_returns = 0usize;
    for app in &apps {
        app.relay_plane.shutdown().await;
        plane_shutdown_returns += 1;
    }
    relay.shutdown();
    let address = url.strip_prefix("ws://").unwrap().trim_end_matches('/');
    let listener_closed = owned_listener_closed(address).await;
    // NATIVE5_TIMING_BEGIN
    #[cfg(feature = "test-policy-overrides")]
    for (ordinal, report) in native5_timing_reports {
        eprintln!("native5-join-window begin ordinal={ordinal}");
        eprint!("{report}");
        eprintln!("native5-join-window end ordinal={ordinal}");
    }
    // NATIVE5_TIMING_END
    eprintln!(
        "sequential-installations completed_steps={} final_device_count={} final_roster_and_policies={} public_cancels={} runtime_closes={} storages_closed={} plane_shutdown_returns={} listener_closed={} attempt_completed={}",
        completed_steps,
        if final_roster_and_policies { 5 } else { 0 },
        final_roster_and_policies,
        public_cancels,
        runtime_closes,
        storages_closed,
        plane_shutdown_returns,
        listener_closed,
        attempt.is_ok()
    );
    assert!(
        attempt.is_ok()
            && completed_steps == 4
            && final_roster_and_policies
            && public_cancels == 14
            && runtime_closes == 5
            && storages_closed
            && plane_shutdown_returns == 5
            && listener_closed,
        "five_real_installations_require_exact_rosters_bilateral_policies_and_positive_owned_resource_closure"
    );
}

// Probe only the owned MockRelay loopback listener, never an external endpoint.
#[allow(clippy::disallowed_methods)]
async fn owned_listener_closed(address: &str) -> bool {
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Ok(socket) = tokio::net::TcpStream::connect(address).await {
            drop(socket);
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok()
}
