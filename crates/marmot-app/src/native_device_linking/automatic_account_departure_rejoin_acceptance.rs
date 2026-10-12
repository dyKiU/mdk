//! A completed negative action does not grant or deny a genuinely new Welcome.
//! Both ordinary sources rejoin through exact lifecycle-owned public packages.
use super::automatic_two_source_leave_acceptance::{
    TwoSourcePeer, observe_confirmed_invite, stored_indices, wait_for_paired_records,
};
use super::*;
use cgka_traits::{StorageProvider, engine::SendIntent, mirrored_chat_catalog::AcceptedChatOrigin};
use futures::FutureExt;
use std::{panic::AssertUnwindSafe, time::Duration};

#[test]
fn completed_account_departure_requires_both_fresh_accepted_sources_before_a_new_operation() {
    crate::tests::run_composed_app_runtime_test("account-departure-fresh-both-sources", || async {
        Box::pin(actual::run_native_public_three_device_enrollment(
            actual::ApprovalScenario::AutomaticAccountDepartureFreshRejoin,
        ))
        .await;
    });
}

struct PriorSource {
    origin: AcceptedChatOrigin,
    device: [u8; 32],
    welcome: String,
}

struct InvitationContext<'a> {
    group: &'a crate::GroupId,
    url: &'a str,
    creator: &'a str,
    old_welcome: &'a str,
}

enum WelcomeDecision {
    Pending(String),
    Recovery(crate::GroupRejoinInvitation),
}

fn source_observation(app: &MarmotApp, group: &crate::GroupId) -> ([u8; 32], AcceptedChatOrigin) {
    let store = app.account_storage("test").unwrap();
    let round = store
        .private_roster_settlement_storage()
        .unwrap()
        .read_round()
        .unwrap()
        .unwrap();
    let origin = store
        .current_account_chat_source_origin(
            &round.anchor.account,
            &round.anchor.local_device,
            group,
        )
        .unwrap()
        .expect("only an actual accepted source origin qualifies");
    (round.anchor.local_device, origin)
}

pub(super) async fn verify_or_depart(
    fresh_rejoin: bool,
    apps: &[MarmotApp; 3],
    runtimes: &[MarmotAppRuntime; 3],
    peer: &TwoSourcePeer,
    url: &str,
    relay_database: &dyn nostr_relay_builder::prelude::NostrDatabase,
    ordered: bool,
) {
    let prior = fresh_rejoin.then(|| {
        std::array::from_fn::<_, 2, _>(|index| {
            let (device, origin) = source_observation(&apps[index], &peer.group);
            PriorSource {
                origin,
                device,
                welcome: apps[index]
                    .group("test", &hex::encode(peer.group.as_slice()))
                    .unwrap()
                    .unwrap()
                    .via_welcome_message_id_hex
                    .expect("actual initial Welcome"),
            }
        })
    });
    let replay = prior.as_ref().map(|prior| {
        crate::AppClient::test_capture_departure_replay(
            apps[2].account_home().root(),
            &peer.group,
            &[prior[0].device, prior[1].device],
        )
    });
    Box::pin(super::automatic_account_departure_acceptance::verify(
        apps,
        runtimes,
        peer,
        url,
        relay_database,
        ordered,
    ))
    .await;
    if let Some(prior) = prior {
        Box::pin(verify_fresh_sources(
            apps,
            runtimes,
            peer,
            url,
            prior,
            replay.unwrap(),
        ))
        .await;
    }
}

async fn verify_fresh_sources(
    apps: &[MarmotApp; 3],
    runtimes: &[MarmotAppRuntime; 3],
    peer: &TwoSourcePeer,
    url: &str,
    prior: [PriorSource; 2],
    replay: std::sync::Arc<crate::client::DepartureReplayProbe>,
) {
    let trace_roots: [std::path::PathBuf; 3] =
        std::array::from_fn(|index| apps[index].account_home().root().to_path_buf());
    let _a_trace = crate::AppClient::test_capture_account_chat_progress(&trace_roots[0], "source");
    let _b_trace = crate::AppClient::test_capture_account_chat_progress(&trace_roots[1], "source");
    let _c_trace =
        crate::AppClient::test_capture_account_chat_progress(&trace_roots[2], "recipient");
    assert_eq!(stored_indices(&peer.app, &peer.group).len(), 1);
    let old = runtimes[2]
        .account_chat_departure_state("test", &peer.group)
        .await
        .unwrap();
    assert!(old.status == crate::AccountChatDepartureStatus::Completed);
    let old_operation = old
        .operation_id
        .expect("genuine completed original operation");
    let group_hex = hex::encode(peer.group.as_slice());
    let roots = [
        apps[0].account_home().root().to_path_buf(),
        apps[1].account_home().root().to_path_buf(),
        peer.app.account_home().root().to_path_buf(),
    ];
    // Managed workers positively relinquish these SAME roots before standalone
    // owners admit each exact device. C remains live for negative observations.
    for runtime in [&runtimes[0], &peer.runtime] {
        runtime.shutdown_and_close().await.unwrap();
        assert!(runtime.storage_is_closed());
    }
    assert!(runtimes[1].storage_is_closed());
    let owners: [MarmotApp; 3] =
        std::array::from_fn(|index| MarmotApp::with_relay(&roots[index], url));
    let (mut a_owner, mut b_owner, mut d_owner) = (None, None, None);
    let creator = owners[2]
        .account_home()
        .account("test")
        .unwrap()
        .account_id_hex;
    let result = AssertUnwindSafe(async {
        a_owner = Some(Box::pin(owners[0].client("test")).await.unwrap());
        b_owner = Some(Box::pin(owners[1].client("test")).await.unwrap());
        d_owner = Some(Box::pin(owners[2].client("test")).await.unwrap());
        let a = a_owner.as_mut().unwrap();
        let b = b_owner.as_mut().unwrap();
        let d = d_owner.as_mut().unwrap();
        let first = invite_exact_source(
            &owners[2],
            &owners[0],
            a,
            d,
            InvitationContext {
                group: &peer.group,
                url,
                creator: &creator,
                old_welcome: &prior[0].welcome,
            },
        )
        .await;
        let second = invite_exact_source(
            &owners[2],
            &owners[1],
            b,
            d,
            InvitationContext {
                group: &peer.group,
                url,
                creator: &creator,
                old_welcome: &prior[1].welcome,
            },
        )
        .await;
        for _ in 0..20 {
            assert_mirror_absent(&runtimes[2], &peer.group).await;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        accept_welcome(&owners[0], a, &peer.group, first).await;
        accept_welcome(&owners[1], b, &peer.group, second).await;
        for (index, app) in owners[..2].iter().enumerate() {
            let (device, origin) = source_observation(app, &peer.group);
            assert!(
                device == prior[index].device
                    && origin.id != prior[index].origin.id
                    && origin.order > prior[index].origin.order
            );
        }
    })
    .catch_unwind()
    .await;
    drop((a_owner, b_owner, d_owner));
    let mut closed = true;
    for app in &owners {
        closed &= app.close_storage().is_ok() && app.storage_is_closed();
    }
    eprintln!("account_departure_rejoin_standalone_owners_closed={closed}");
    if let Err(original) = result {
        std::panic::resume_unwind(original);
    }
    assert!(closed);
    let reopened: [MarmotApp; 3] =
        std::array::from_fn(|index| MarmotApp::with_relay(&roots[index], url));
    let managed: [MarmotAppRuntime; 3] =
        std::array::from_fn(|index| MarmotAppRuntime::new(reopened[index].clone()));
    let result = AssertUnwindSafe(async {
        for runtime in &managed {
            runtime.reconcile_accounts().await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(30), async {
            while stored_indices(&reopened[2], &peer.group).len() != 3 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("D must retain both genuine fresh ordinary source leaves");
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                let state = runtimes[2]
                    .account_chat_departure_state("test", &peer.group)
                    .await
                    .unwrap();
                if state.status == crate::AccountChatDepartureStatus::Available {
                    assert!(state.operation_id.is_none());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("both fresh accepted origins must supersede the old operation");
        for index in 0..2 {
            let sent = managed[index]
                .send_message(
                    "test",
                    &peer.group,
                    format!("fresh actual source {index}").into_bytes(),
                )
                .await
                .unwrap();
            assert!(sent.published == 1 && sent.message_ids.len() == 1);
            tokio::time::timeout(Duration::from_secs(30), async {
                while reopened[2]
                    .account_storage("test")
                    .unwrap()
                    .app_message(&group_hex, &sent.message_ids[0])
                    .unwrap()
                    .is_none()
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("D must decrypt each actual fresh source ordinary send");
            let delivery = AssertUnwindSafe(wait_for_paired_records(
                &runtimes[2],
                &peer.group,
                &sent.message_ids,
                None,
            ))
            .catch_unwind()
            .await;
            if let Err(original) = delivery {
                let diagnostics = tokio::time::timeout(
                    Duration::from_secs(5),
                    AssertUnwindSafe(diagnose_delivery(
                        &apps[2],
                        &runtimes[2],
                        &peer.group,
                        &sent.message_ids[0],
                        &prior,
                    ))
                    .catch_unwind(),
                )
                .await;
                eprintln!(
                    "account_departure_rejoin_delivery_diagnostics_available={}",
                    matches!(diagnostics, Ok(Ok(())))
                );
                std::panic::resume_unwind(original);
            }
            // The unified window selects one attesting copy per logical event.
            // Independently require the actual source-scoped copy and lineage;
            // its chosen presentation source is not the original sending leaf.
            let (_, accepted_origin) = source_observation(&reopened[index], &peer.group);
            wait_for_exact_source_record(
                &apps[2],
                &peer.group,
                &sent.message_ids[0],
                &prior[index].device,
                accepted_origin,
            )
            .await;
        }
        assert_eq!(replay.captured_peer_count(), 2);
        replay.request_replay();
        tokio::time::timeout(Duration::from_secs(30), async {
            while replay.received_peer_count() != 2 { tokio::time::sleep(Duration::from_millis(20)).await; }
        }).await.expect("both real source peers must authenticate the exact old intent under fresh queued channel nonces");
        // The old authenticated negative cannot erase new source lineages.
        let after_replay = managed[0].send_message("test", &peer.group, b"fresh lineage survives genuine old negative replay".to_vec()).await.unwrap();
        assert!(after_replay.published == 1 && after_replay.message_ids.len() == 1);
        wait_for_paired_records(&runtimes[2], &peer.group, &after_replay.message_ids, None).await;
        let (_, origin) = source_observation(&reopened[0], &peer.group);
        wait_for_exact_source_record(&apps[2], &peer.group, &after_replay.message_ids[0], &prior[0].device, origin).await;
        let still_available = runtimes[2]
            .account_chat_departure_state("test", &peer.group)
            .await
            .unwrap();
        assert!(
            still_available.status == crate::AccountChatDepartureStatus::Available
                && still_available.operation_id.is_none()
        );
        let next = runtimes[2]
            .leave_account_chat("test", &peer.group)
            .await
            .unwrap();
        assert!(next.status == crate::AccountChatDepartureStatus::Pending);
        assert!(next.operation_id.is_some_and(|id| id != old_operation));
    })
    .catch_unwind()
    .await;
    let mut closed = true;
    for runtime in &managed {
        closed &= runtime.shutdown_and_close().await.is_ok() && runtime.storage_is_closed();
    }
    eprintln!("account_departure_rejoin_fresh_managed_owners_closed={closed}");
    if let Err(original) = result {
        std::panic::resume_unwind(original);
    }
    assert!(closed);
}

async fn invite_exact_source(
    administrator_app: &MarmotApp,
    source_app: &MarmotApp,
    source: &mut crate::AppClient,
    administrator: &mut crate::AppClient,
    context: InvitationContext<'_>,
) -> WelcomeDecision {
    let InvitationContext {
        group,
        url,
        creator,
        old_welcome,
    } = context;
    let package = Box::pin(source.publish_key_package()).await.unwrap();
    let publication = source.key_package_maintenance_status().unwrap().unwrap();
    assert!(
        publication.current_key_package.as_ref() == Some(&package)
            && publication.pending_replacement.is_none()
    );
    let actual_id = hex::encode(
        publication
            .authored_event_id
            .expect("acknowledged lifecycle publication")
            .as_slice(),
    );
    let account = source_app.account_home().account("test").unwrap();
    let records = administrator_app
        .fetch_key_package_events_for_account_id(
            &account.account_id_hex,
            &[cgka_traits::TransportEndpoint(url.to_owned())],
        )
        .await
        .unwrap();
    let record = records
        .into_iter()
        .find(|record| record.event.id == actual_id)
        .expect("exact acknowledged source publication must reach relay");
    let fetched = crate::key_package_records::key_package_from_record(record).unwrap();
    assert!(fetched.key_package.source.is_some());
    assert!(
        cgka_engine::key_package_metadata(&fetched.key_package)
            .unwrap()
            .key_package_ref_hex
            == cgka_engine::key_package_metadata(&package)
                .unwrap()
                .key_package_ref_hex
    );
    let effects = Box::pin(administrator.runtime.send(SendIntent::Invite {
        group_id: group.clone(),
        key_packages: vec![fetched.key_package],
        initial_admins: vec![],
    }))
    .await
    .unwrap();
    assert!(effects.failures.is_empty());
    observe_confirmed_invite(administrator, &effects)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            Box::pin(source.sync()).await.unwrap();
            if let Some(offer) = source
                .group_recovery_status(group)
                .unwrap()
                .rejoin_invitations
                .into_iter()
                .find(|offer| {
                    offer.welcome_id_hex != old_welcome && offer.welcomer_account_id_hex == creator
                })
            {
                break WelcomeDecision::Recovery(offer);
            }
            if let Some(row) = source_app
                .group("test", &hex::encode(group.as_slice()))
                .unwrap()
                && row.pending_confirmation
                && row.welcomer_account_id_hex.as_deref() == Some(creator)
                && let Some(welcome) = row
                    .via_welcome_message_id_hex
                    .filter(|id| id != old_welcome)
            {
                break WelcomeDecision::Pending(welcome);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("exact device must receive a genuinely new administrator Welcome")
}

async fn accept_welcome(
    app: &MarmotApp,
    client: &mut crate::AppClient,
    group: &crate::GroupId,
    decision: WelcomeDecision,
) {
    let welcome = match decision {
        WelcomeDecision::Pending(welcome) => {
            client.accept_group_invite(group).unwrap();
            welcome
        }
        WelcomeDecision::Recovery(offer) => {
            client
                .confirm_group_rejoin(
                    &cgka_traits::MessageId::new(hex::decode(&offer.welcome_id_hex).unwrap()),
                    &hex::decode(&offer.local_state_token).unwrap(),
                )
                .await
                .unwrap();
            offer.welcome_id_hex
        }
    };
    let row = app
        .group("test", &hex::encode(group.as_slice()))
        .unwrap()
        .unwrap();
    assert!(!row.pending_confirmation && row.self_membership == crate::SelfMembership::Member);
    assert!(row.via_welcome_message_id_hex.as_deref() == Some(welcome.as_str()));
}

async fn assert_mirror_absent(runtime: &MarmotAppRuntime, group: &crate::GroupId) {
    match runtime
        .open_account_conversation_window("test", group, 128)
        .await
    {
        Err(crate::AccountChatReadError::NotReady) => {}
        Ok(window) => {
            window.window_handle().cancel();
            panic!("an unaccepted Welcome must not restore the departed mirrored chat");
        }
        Err(_) => panic!("absence observation must not swallow an unrelated read failure"),
    }
}

// These retained rows are failure observations, never current Core approval or
// a permission/membership oracle. Only aggregates leave the synthetic fixture.
async fn diagnose_delivery(
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    group: &crate::GroupId,
    event: &str,
    prior: &[PriorSource; 2],
) {
    use cgka_traits::{
        approved_account_sharing_policy::approved_account_sharing_identity,
        mirrored_chat_catalog::MirroredChatScope,
    };
    let event_id: [u8; 32] = hex::decode(event).unwrap().try_into().unwrap();
    if let Ok(window) = runtime
        .open_account_conversation_window("test", group, 128)
        .await
    {
        let mut matching = [0usize; 3];
        for row in &window.snapshot.rows {
            if let crate::AccountConversationRow::PairedSource(row) = row
                && row.event_id == event_id
            {
                matching[0] += 1;
                for index in 0..2 {
                    matching[index + 1] += usize::from(row.source.device == prior[index].device);
                }
            }
        }
        window.window_handle().cancel();
        eprintln!("account_departure_rejoin_public_event_any_a_b_counts={matching:?}");
    } else {
        eprintln!("account_departure_rejoin_public_event_observation_unknown=true");
    }
    let storage = app.account_storage("test").unwrap();
    let round = storage
        .private_roster_settlement_storage()
        .unwrap()
        .read_round()
        .unwrap()
        .unwrap();
    let policies = storage
        .approved_account_sharing_policy_storage()
        .unwrap()
        .approved_account_sharing_policies()
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (index, source) in prior.iter().enumerate() {
        eprintln!(
            "account_departure_rejoin_source={index} live_recipient_is_default_initiator={}",
            round.anchor.local_device < source.device
        );
        let origin = storage
            .current_mirrored_chat_origin_observation(
                &round.anchor.account,
                &round.anchor.local_device,
                &source.device,
                group,
            )
            .unwrap();
        eprintln!(
            "account_departure_rejoin_source={index} retained_origin_present={} retained_origin_newer={}",
            origin.is_some(),
            origin.is_some_and(
                |origin| origin.id != source.origin.id && origin.order > source.origin.order
            )
        );
        for policy in policies
            .iter()
            .filter(|policy| policy.peer_device == source.device && !policy.revoked)
        {
            let scope = MirroredChatScope {
                account: policy.account,
                local_device: policy.local_device,
                source_device: policy.peer_device,
                policy_digest: approved_account_sharing_identity(
                    &policy.account,
                    &policy.protected_group,
                    &policy.local_device,
                    &policy.peer_device,
                    &policy.approval_id,
                )
                .unwrap(),
                protected_group: policy.protected_group.clone(),
                protected_generation: round.generation,
            };
            let rows = storage
                .mirrored_chat_message_storage()
                .unwrap()
                .mirrored_chat_message_page(&scope, group, None, 128, now);
            eprintln!(
                "account_departure_rejoin_source={index} scoped_event_present={:?}",
                rows.map(|rows| rows.iter().any(|row| row.event_id == event_id))
                    .map_err(|_| "Unknown")
            );
        }
    }
}

async fn wait_for_exact_source_record(
    app: &MarmotApp,
    group: &crate::GroupId,
    event: &str,
    source: &[u8; 32],
    origin: AcceptedChatOrigin,
) {
    use cgka_traits::{
        approved_account_sharing_policy::approved_account_sharing_identity,
        mirrored_chat_catalog::MirroredChatScope,
    };
    let event: [u8; 32] = hex::decode(event).unwrap().try_into().unwrap();
    let storage = app.account_storage("test").unwrap();
    let round = storage
        .private_roster_settlement_storage()
        .unwrap()
        .read_round()
        .unwrap()
        .unwrap();
    let policies = storage
        .approved_account_sharing_policy_storage()
        .unwrap()
        .approved_account_sharing_policies()
        .unwrap();
    let policy = policies
        .iter()
        .find(|policy| !policy.revoked && &policy.peer_device == source)
        .expect("genuine source approved policy must remain present");
    let scope = MirroredChatScope {
        account: policy.account,
        local_device: policy.local_device,
        source_device: policy.peer_device,
        policy_digest: approved_account_sharing_identity(
            &policy.account,
            &policy.protected_group,
            &policy.local_device,
            &policy.peer_device,
            &policy.approval_id,
        )
        .unwrap(),
        protected_group: policy.protected_group.clone(),
        protected_generation: round.generation,
    };
    tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let records = storage.mirrored_chat_message_storage().unwrap().mirrored_chat_message_page(&scope, group, None, 128, now).expect("after fresh public source readiness, storage failures must not masquerade as absent delivery");
            if records.iter().any(|record| record.event_id == event && record.accepted_origin == Some(origin)) { break; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.expect("C must retain the actual source-attested record under its genuine fresh accepted lineage");
}
