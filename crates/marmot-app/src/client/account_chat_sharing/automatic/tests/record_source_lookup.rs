//! Actual Core sources remain sources when another chat occupies a scan page.
use super::*;
use crate::{DeviceLinkingPhase, DeviceLinkingSession, MarmotApp, MarmotAppRuntime};
use futures::FutureExt;
use marmot_account::AccountHome;
use std::{panic::AssertUnwindSafe, time::Duration};

async fn wait_phase(a: &DeviceLinkingSession, b: &DeviceLinkingSession, phase: DeviceLinkingPhase) {
    let budget = if phase == DeviceLinkingPhase::EnrollmentComplete {
        Duration::from_secs(90)
    } else {
        Duration::from_secs(15)
    };
    tokio::time::timeout(budget, async {
        loop {
            let phases = [
                a.snapshot().await.unwrap().phase,
                b.snapshot().await.unwrap().phase,
            ];
            assert!(phases.iter().all(|phase| !matches!(
                phase,
                DeviceLinkingPhase::Failed
                    | DeviceLinkingPhase::Cancelled
                    | DeviceLinkingPhase::Expired
            )));
            if phases == [phase, phase] {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("actual two-device pairing must reach the required phase");
}

#[tokio::test(flavor = "current_thread")]
async fn record_source_epoch_is_independent_of_catalogue_position() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let apps = std::array::from_fn::<_, 2, _>(|index| {
        AccountHome::open(dirs[index].path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        MarmotApp::with_relay(dirs[index].path(), &url)
    });
    let runtimes = apps.clone().map(MarmotAppRuntime::new);
    let mut closed = [false; 2];
    let mut reopened = None;
    let outcome = AssertUnwindSafe(async {
        for runtime in &runtimes {
            runtime.reconcile_accounts().await.unwrap();
        }
        let managers = runtimes.each_ref().map(|runtime| runtime.accounts());
        let first = managers[0].create_group("test", "Source one", &[], None).await.unwrap();
        let second = managers[0].create_group("test", "Source two", &[], None).await.unwrap();
        assert_ne!(first, second);
        let recipient = managers[1].begin_device_linking_session("test").await.unwrap();
        let source = managers[0]
            .approve_automatic_device_linking_session(
                "test", recipient.automatic_pairing_code().await.unwrap(), None,
            )
            .await
            .unwrap();
        source.automatic_pairing_code().await.unwrap();
        wait_phase(&source, &recipient, DeviceLinkingPhase::ComparisonAvailable).await;
        let left = source.snapshot().await.unwrap();
        let right = recipient.snapshot().await.unwrap();
        assert!(left.decimals.is_some() && left.decimals == right.decimals);
        source.confirm_comparison(left.revision).await.unwrap();
        recipient.confirm_comparison(right.revision).await.unwrap();
        wait_phase(&source, &recipient, DeviceLinkingPhase::VerificationCompleteEnrollmentPending).await;
        recipient.continue_automatic_linking(recipient.snapshot().await.unwrap().revision, true).await.unwrap();
        source.continue_automatic_linking(source.snapshot().await.unwrap().revision, true).await.unwrap();
        wait_phase(&source, &recipient, DeviceLinkingPhase::EnrollmentComplete).await;
        source.cancel().await.unwrap();
        recipient.cancel().await.unwrap();
        for (index, runtime) in runtimes.iter().enumerate() {
            runtime.shutdown_and_close().await.unwrap();
            closed[index] = runtime.storage_is_closed();
            assert!(closed[index]);
        }
        eprintln!("record-source-control actual_pair_and_two_runtime_closes=true");

        reopened = Some(MarmotApp::with_relay(dirs[0].path(), &url));
        let app = reopened.as_ref().unwrap();
        let mut client = app.client("test").await.unwrap();
        client.sync().await.unwrap();
        let policies = app.account_storage("test").unwrap()
            .approved_account_sharing_policy_storage().unwrap()
            .approved_account_sharing_policies().unwrap();
        assert_eq!(policies.len(), 1);
        let policy = policies[0].clone();
        client.runtime.session_mut().ensure_group_hydrated(&policy.protected_group).unwrap();
        client.automatic_policy_current(&policy).unwrap();
        client.begin_automatic_channel(policy.clone(), None).unwrap();
        let id = AppClient::automatic_policy_id(&policy).unwrap();
        let entry = &client.account_sharing_owner.automatic[&id];
        assert!(entry.original.live() && entry.records.group_after.is_none());
        let page = client.runtime.session()
            .account_chat_catalog(&policy.protected_group, None, 128).unwrap();
        assert_eq!(page.entries.len(), 2);
        let earlier = &page.entries[0];
        let later = &page.entries[1];
        assert!(earlier.group_id.as_slice() < later.group_id.as_slice());
        assert!([&first, &second].contains(&&earlier.group_id));
        assert!([&first, &second].contains(&&later.group_id));
        assert!(client.runtime.session().canonical_group_membership(&later.group_id).unwrap().local_leaf_active);
        assert_eq!(client.automatic_record_source_epoch(entry, &earlier.group_id).unwrap(), Some(earlier.epoch));
        eprintln!("record-source-control two_actual_catalog_sources=true later_local_leaf_active=true first_source_lookup=true");
        let actual = client.automatic_record_source_epoch(entry, &later.group_id).unwrap();
        eprintln!("record-source-control later_source_lookup={}", actual == Some(later.epoch));
        assert_eq!(actual, Some(later.epoch), "an actual requested source must remain valid independently of its discovery-page position");
    }).catch_unwind().await;
    for (index, runtime) in runtimes.iter().enumerate() {
        if !closed[index] {
            runtime.shutdown_and_close().await.unwrap();
            closed[index] = runtime.storage_is_closed();
        }
        apps[index].relay_plane.shutdown().await;
    }
    let reopened_closed = reopened
        .as_ref()
        .is_some_and(|app| app.close_storage().is_ok() && app.storage_is_closed());
    if let Some(app) = &reopened {
        app.relay_plane.shutdown().await;
    }
    eprintln!(
        "record-source-control runtime_closes={} reopened_storage_closed={reopened_closed}",
        closed.iter().filter(|closed| **closed).count()
    );
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    assert!(closed.iter().all(|closed| *closed) && reopened_closed);
}
