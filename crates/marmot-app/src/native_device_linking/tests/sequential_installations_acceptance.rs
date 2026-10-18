//! Five real local installations; no synthetic Core state, copied DB or implicit approvals.
use super::*;
use crate::AccountManager;
use cgka_traits::storage::{AccountDeviceSignerStorage, StorageProvider};
use cgka_traits::{MemberId, private_roster_settlement::PrivateSettlementPhase};
use futures::FutureExt;
use std::collections::BTreeSet;
use std::time::Duration;
use std::sync::Arc;
type TerminalProbe = super::super::enabled::terminal_diagnostic::Probe;

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
) -> (
    DeviceLinkingSession,
    DeviceLinkingSession,
    Vec<DeviceLinkingApproval>,
    Option<(Arc<TerminalProbe>, Arc<TerminalProbe>)>,
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
    let recipient_probe = (newcomer == 4).then(|| recipient.arm_terminal_diagnostic_for_test());
    let source = managers[sponsor]
        .approve_automatic_device_linking_session(
            "test",
            recipient.automatic_pairing_code().await.unwrap(),
            selector,
        )
        .await
        .unwrap();
    let source_probe = (newcomer == 4).then(|| source.arm_terminal_diagnostic_for_test());
    source.automatic_pairing_code().await.unwrap();
    compare_and_confirm_pair(&source, &recipient).await;
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
    (source, recipient, approvals, source_probe.zip(recipient_probe))
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
    let attempt = std::panic::AssertUnwindSafe(async {
        for runtime in &runtimes { runtime.reconcile_accounts().await.unwrap(); }
        let managers = runtimes.each_ref().map(|runtime| runtime.accounts());
        // New installations B,C,D,E join through already-authorized A,B,C,B.
        for (newcomer, sponsor) in [(1usize, 0usize), (2, 1), (3, 2), (4, 1)] {
            let (source, recipient, approvals, terminal_probes) = join_installation(&apps, &managers, &account, sponsor, newcomer).await;
            // Reuse the OWNER1611 helper:90s enrollment,15s earlier phases;
            // no deadline override, packets or extra host finalization calls.
            let completion = std::panic::AssertUnwindSafe(wait_for_automatic_phase(
                &source, &recipient, DeviceLinkingPhase::EnrollmentComplete,
            )).catch_unwind().await;
            if let Some((source_probe, recipient_probe)) = terminal_probes {
                for (side, probe, session) in [("source", source_probe, &source), ("recipient", recipient_probe, &recipient)] {
                    let (known, error, transition) = probe.snapshot();
                    eprintln!("owner-five-terminal side={} known={} pre_arm_unknown=true attempted_error={:?} accepted_terminal={:?} progress={:?}",
                        side, known, error, transition, session.enrollment_progress_for_test());
                }
            }
            if let Err(failure) = completion { std::panic::resume_unwind(failure); }
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
