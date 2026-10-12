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
    super::automatic_account_departure_acceptance::verify(
        apps,
        runtimes,
        peer,
        url,
        relay_database,
        ordered,
    )
    .await;
    if let Some(prior) = prior {
        verify_fresh_sources(apps, runtimes, peer, url, prior).await;
    }
}

async fn verify_fresh_sources(
    apps: &[MarmotApp; 3],
    runtimes: &[MarmotAppRuntime; 3],
    peer: &TwoSourcePeer,
    url: &str,
    prior: [PriorSource; 2],
) {
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
        let mut a = a_owner.as_mut().unwrap();
        let mut b = b_owner.as_mut().unwrap();
        let mut d = d_owner.as_mut().unwrap();
        let first = invite_exact_source(
            &owners[2],
            &owners[0],
            &mut a,
            &mut d,
            &peer.group,
            url,
            &creator,
            &prior[0].welcome,
        )
        .await;
        let second = invite_exact_source(
            &owners[2],
            &owners[1],
            &mut b,
            &mut d,
            &peer.group,
            url,
            &creator,
            &prior[1].welcome,
        )
        .await;
        for _ in 0..20 {
            assert_mirror_absent(&runtimes[2], &peer.group).await;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        accept_welcome(&owners[0], &mut a, &peer.group, first).await;
        accept_welcome(&owners[1], &mut b, &peer.group, second).await;
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
            wait_for_paired_records(
                &runtimes[2],
                &peer.group,
                &sent.message_ids,
                Some(prior[index].device),
            )
            .await;
        }
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
    group: &crate::GroupId,
    url: &str,
    creator: &str,
    old_welcome: &str,
) -> WelcomeDecision {
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
