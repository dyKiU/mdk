//! Genuine paired disclosure control; source MLS membership alone is insufficient.
use crate::{DeviceLinkingPhase, DeviceLinkingSession, MarmotApp, MarmotAppRuntime};
use std::time::Duration;

async fn exchange(from: &DeviceLinkingSession, to: &DeviceLinkingSession) {
    for packet in from.outgoing_packets().await.unwrap() {
        to.receive_packet(packet.bytes).await.unwrap();
        from.acknowledge_packet(packet.acknowledgement_id)
            .await
            .unwrap();
    }
}
async fn approve_pair(a: &DeviceLinkingSession, b: &DeviceLinkingSession) {
    b.receive_setup_packet(a.setup_packet()).await.unwrap();
    for _ in 0..8 {
        exchange(a, b).await;
        exchange(b, a).await;
    }
    let first = a.snapshot().await.unwrap();
    let second = b.snapshot().await.unwrap();
    assert!(
        first.phase == DeviceLinkingPhase::ComparisonAvailable && first.decimals == second.decimals
    );
    a.confirm_comparison(first.revision).await.unwrap();
    b.confirm_comparison(second.revision).await.unwrap();
    for _ in 0..8 {
        exchange(a, b).await;
        exchange(b, a).await;
    }
    a.continue_linking_and_share_chats(a.snapshot().await.unwrap().revision)
        .await
        .unwrap();
    b.continue_linking_and_share_chats(b.snapshot().await.unwrap().revision)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if a.snapshot().await.unwrap().phase == DeviceLinkingPhase::EnrollmentComplete
                && b.snapshot().await.unwrap().phase == DeviceLinkingPhase::EnrollmentComplete
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("actual broad pair enrollment completion");
    a.cancel().await.unwrap();
    b.cancel().await.unwrap();
}

async fn wait_history(runtime: &MarmotAppRuntime, group: &crate::GroupId, event: &str) -> bool {
    let event = hex::decode(event).unwrap();
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            if let Ok(page) = runtime
                .accounts()
                .paired_chat_message_page("test", group.clone(), None, 128)
                .await
                && page
                    .messages
                    .iter()
                    .any(|row| row.event_id.as_slice() == event.as_slice() && !row.deleted)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .is_ok()
}

async fn diagnose_history(
    apps: &[MarmotApp; 3],
    runtimes: &[MarmotAppRuntime; 3],
    group: &crate::GroupId,
    event: &str,
    stage: &str,
) {
    use cgka_traits::StorageProvider;
    let group_hex = hex::encode(group.as_slice());
    let raw = apps[0].message_by_id("test", &group_hex, event).unwrap();
    let timeline = apps[0].timeline_message("test", &group_hex, event).unwrap();
    let source = apps[0]
        .group("test", &hex::encode(group.as_slice()))
        .unwrap();
    let catalog = runtimes[1]
        .accounts()
        .paired_chat_list_page("test", None, 128)
        .await;
    let records = runtimes[1]
        .accounts()
        .paired_chat_message_page("test", group.clone(), None, 128)
        .await;
    let source_storage = apps[0].account_storage("test").unwrap();
    let policies = source_storage
        .approved_account_sharing_policy_storage()
        .unwrap()
        .approved_account_sharing_policies()
        .unwrap();
    let pending_batches: usize = policies
        .iter()
        .map(|policy| {
            let id =
                cgka_traits::approved_account_sharing_policy::approved_account_sharing_identity(
                    &policy.account,
                    &policy.protected_group,
                    &policy.local_device,
                    &policy.peer_device,
                    &policy.approval_id,
                )
                .unwrap();
            source_storage
                .account_chat_record_stream_storage()
                .unwrap()
                .pending_account_chat_record_batches(&id, group, None, 128)
                .unwrap()
                .len()
        })
        .sum();
    let recipient_storage = apps[1].account_storage("test").unwrap();
    let recipient_policies = recipient_storage
        .approved_account_sharing_policy_storage()
        .unwrap()
        .approved_account_sharing_policies()
        .unwrap();
    let mut raw_records = 0;
    let mut raw_deleted = 0;
    let mut raw_empty = 0;
    if let Ok(page) = &catalog {
        for row in page.chats.iter().filter(|row| &row.group_id == group) {
            for policy in &recipient_policies {
                let id = cgka_traits::approved_account_sharing_policy::approved_account_sharing_identity(&policy.account, &policy.protected_group, &policy.local_device, &policy.peer_device, &policy.approval_id).unwrap();
                if id != row.source.policy_digest {
                    continue;
                }
                // Observation-only scope for the storage read, never channel restoration.
                let scope = cgka_traits::mirrored_chat_catalog::MirroredChatScope {
                    account: policy.account,
                    local_device: policy.local_device,
                    source_device: policy.peer_device,
                    policy_digest: id,
                    protected_group: policy.protected_group.clone(),
                    protected_generation: row.source.protected_generation,
                };
                let observations = recipient_storage
                    .mirrored_chat_message_storage()
                    .unwrap()
                    .mirrored_chat_message_page(&scope, group, None, 128, crate::unix_now_seconds())
                    .unwrap();
                raw_records += observations.len();
                raw_deleted += observations.iter().filter(|row| row.deleted).count();
                raw_empty += observations
                    .iter()
                    .filter(|row| row.payload.is_empty())
                    .count();
            }
        }
    }
    eprintln!(
        "privacy source diagnostic raw_present={} timeline_present={} timeline_deleted={} pending_batches={} raw_records={} raw_deleted={} raw_empty={}",
        raw.is_some(),
        timeline.is_some(),
        timeline.as_ref().is_some_and(|row| row.deleted),
        pending_batches,
        raw_records,
        raw_deleted,
        raw_empty
    );
    eprintln!(
        "privacy history diagnostic stage={} source_present={} source_pending={} recipient_catalog_query={} recipient_group={} recipient_records_query={} recipient_records={} recipient_deleted={}",
        stage,
        source.is_some(),
        source.as_ref().is_some_and(|row| row.pending_confirmation),
        catalog.is_ok(),
        catalog
            .as_ref()
            .is_ok_and(|page| page.chats.iter().any(|row| &row.group_id == group)),
        records.is_ok(),
        records.as_ref().map_or(0, |page| page.messages.len()),
        records.as_ref().map_or(0, |page| page
            .messages
            .iter()
            .filter(|row| row.deleted)
            .count()),
    );
}

#[test]
fn paired_pending_stranger_never_discloses_before_actual_acceptance() {
    crate::tests::run_composed_app_runtime_test("paired-pending-source-privacy", || async {
        let relay =
            nostr_relay_builder::LocalRelay::new(nostr_relay_builder::RelayBuilder::default());
        relay.run().await.unwrap();
        let url = relay.url().await.to_string();
        let roots: [tempfile::TempDir; 3] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
        let keys = nostr::prelude::Keys::generate();
        let apps: [MarmotApp; 3] = std::array::from_fn(|i| {
            if i < 2 {
                marmot_account::AccountHome::open(roots[i].path())
                    .import_account("test", &keys.secret_key().to_secret_hex())
                    .unwrap();
            } else {
                marmot_account::AccountHome::open(roots[i].path())
                    .create_account("test")
                    .unwrap();
            }
            MarmotApp::with_relay(roots[i].path(), &url)
        });
        let runtimes = apps.clone().map(MarmotAppRuntime::new);
        runtimes[0].reconcile_accounts().await.unwrap();
        runtimes[2].reconcile_accounts().await.unwrap();
        let account = hex::encode(keys.public_key().to_bytes());
        crate::tests::remember_test_member_inbox(&apps[2], &account, &url);
        let mut groups = Vec::new();
        let mut events = Vec::new();
        for _ in 0..3 {
            runtimes[0].publish_key_package("test").await.unwrap();
            let group = runtimes[2]
                .create_group(
                    "test",
                    "real incoming privacy",
                    std::slice::from_ref(&account),
                    None,
                )
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    if apps[0]
                        .group("test", &hex::encode(group.as_slice()))
                        .unwrap()
                        .is_some_and(|row| row.pending_confirmation)
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("actual ordinary pending invitation");
            let sent = runtimes[2]
                .send_message("test", &group, b"synthetic source privacy witness".to_vec())
                .await
                .unwrap();
            let event = sent.message_ids.first().unwrap().clone();
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    if apps[0]
                        .account_storage("test")
                        .unwrap()
                        .timeline_message(&hex::encode(group.as_slice()), &event)
                        .unwrap()
                        .is_some()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("pending membership really decrypts the ordinary body");
            groups.push(group);
            events.push(event);
        }
        // Preserve actual group/event pairs while making the raw Core scan
        // encounter an unaccepted Welcome before the accepted source. These
        // are genuine creator-generated canonical IDs, never fixture rows.
        let mut actual_pairs: Vec<_> = groups.into_iter().zip(events).collect();
        actual_pairs.sort_by(|left, right| right.0.as_slice().cmp(left.0.as_slice()));
        let (groups, events): (Vec<_>, Vec<_>) = actual_pairs.into_iter().unzip();
        assert!(groups[1].as_slice() < groups[0].as_slice());
        assert!(groups[2].as_slice() < groups[0].as_slice());
        eprintln!("privacy source ordering pending_precedes_accepted=true");
        runtimes[0]
            .accept_group_invite("test", &groups[0])
            .await
            .unwrap();
        runtimes[1].reconcile_accounts().await.unwrap();
        let b = runtimes[1]
            .accounts()
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let a = runtimes[0]
            .accounts()
            .approve_device_linking_session("test", b.setup_packet(), None)
            .await
            .unwrap();
        approve_pair(&a, &b).await;
        let initial_history = wait_history(&runtimes[1], &groups[0], &events[0]).await;
        if !initial_history {
            diagnose_history(&apps, &runtimes, &groups[0], &events[0], "initial-accepted").await;
            for runtime in &runtimes {
                runtime.shutdown_and_close().await.unwrap();
            }
            assert!(apps.iter().all(MarmotApp::storage_is_closed));
            panic!(
                "initial accepted canonical paired history unavailable after three positive closes"
            );
        }
        let mut pending_disclosed = false;
        for _ in 0..60 {
            let page = runtimes[1]
                .accounts()
                .paired_chat_list_page("test", None, 128)
                .await
                .unwrap();
            pending_disclosed |= page
                .chats
                .iter()
                .any(|row| groups[1..].contains(&row.group_id));
            for group in &groups[1..] {
                let page = runtimes[1]
                    .accounts()
                    .paired_chat_message_page("test", group.clone(), None, 128)
                    .await
                    .unwrap();
                pending_disclosed |= !page.messages.is_empty();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        runtimes[0]
            .decline_group_invite("test", &groups[2])
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if runtimes[2]
                    .accounts()
                    .group_roster("test", &groups[2])
                    .await
                    .unwrap()
                    .members
                    .len()
                    == 1
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("independent creator must authenticate the actual declined member removal");
        runtimes[0]
            .accept_group_invite("test", &groups[1])
            .await
            .unwrap();
        let later_history = wait_history(&runtimes[1], &groups[1], &events[1]).await;
        if !later_history {
            diagnose_history(&apps, &runtimes, &groups[1], &events[1], "later-accepted").await;
        }
        let page = runtimes[1]
            .accounts()
            .paired_chat_list_page("test", None, 128)
            .await
            .unwrap();
        let declined_disclosed = page.chats.iter().any(|row| row.group_id == groups[2]);
        for runtime in &runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
        assert!(apps.iter().all(MarmotApp::storage_is_closed));
        assert!(
            later_history,
            "later accepted canonical paired history unavailable after three positive closes"
        );
        assert!(
            !pending_disclosed,
            "unaccepted stranger invitation must never cross the paired source channel"
        );
        assert!(
            !declined_disclosed,
            "actual explicit decline must not leave a visible paired source"
        );
    });
}
