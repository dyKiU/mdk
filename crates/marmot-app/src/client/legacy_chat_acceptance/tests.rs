//! Real legacy projection + pruned founding state, accepted by fresh originals.
//! No MLS row, acceptance row, owner, or receipt is fabricated.
use super::*;
use crate::{DeviceLinkingPhase, DeviceLinkingSession, MarmotApp, MarmotAppRuntime};
use cgka_traits::{
    engine::{CreateGroupRequest, SendIntent},
    storage::MessageStorage,
};
use std::time::Duration;

async fn exchange(from: &DeviceLinkingSession, to: &DeviceLinkingSession) {
    for packet in from.outgoing_packets().await.unwrap() {
        to.receive_packet(packet.bytes).await.unwrap();
        from.acknowledge_packet(packet.acknowledgement_id)
            .await
            .unwrap();
    }
}
async fn complete_pair(a: &DeviceLinkingSession, b: &DeviceLinkingSession, broad: bool) {
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
    if broad {
        a.continue_linking_and_share_chats(a.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        b.continue_linking_and_share_chats(b.snapshot().await.unwrap().revision)
            .await
            .unwrap();
    } else {
        a.continue_linking(a.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        b.continue_linking(b.snapshot().await.unwrap().revision)
            .await
            .unwrap();
    }
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
    .expect("actual completed original pair");
    a.cancel().await.unwrap();
    b.cancel().await.unwrap();
}

async fn exercise_original_legacy_acceptance(enrollment: bool) {
    let relay = nostr_relay_builder::LocalRelay::new(nostr_relay_builder::RelayBuilder::default());
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let roots: [tempfile::TempDir; 2] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
    let keys = nostr::prelude::Keys::generate();
    let apps: [MarmotApp; 2] = std::array::from_fn(|i| {
        marmot_account::AccountHome::open(roots[i].path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        MarmotApp::with_relay(roots[i].path(), &url)
    });
    // This is the old writer boundary: genuine Core creation/publish and the
    // ordinary App projection, before an acceptance ledger existed. There is
    // no deletion of an existing ledger or manual MLS/projection SQL.
    let mut client = apps[0].client("test").await.unwrap();
    let (group, _effects) = client
        .runtime
        .create_group(CreateGroupRequest {
            name: "real legacy source".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    client.add_group(&group).unwrap();
    client
        .save_state_with_pending_local_group_deletion_frontier_clears()
        .unwrap();
    let effects = client
        .runtime
        .send(SendIntent::UpdateGroupData {
            group_id: group.clone(),
            name: Some("real legacy source updated".into()),
            description: None,
        })
        .await
        .unwrap();
    client
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    let store = apps[0].account_storage("test").unwrap();
    for name in store.list_group_snapshots(&group).unwrap() {
        if name == "openmls-retained-anchor-0" {
            store.release_group_snapshot(&group, &name).unwrap();
        }
    }
    assert!(
        !client
            .runtime
            .session()
            .retained_local_group_creation(&group)
            .unwrap()
    );
    assert!(!client.automatic_chat_source_accepted(&group).unwrap());
    let identity = client.runtime.session().self_id();
    let signer = store.account_device_signer(&identity).unwrap().unwrap();
    let account: [u8; 32] = identity.as_slice().try_into().unwrap();
    let local: [u8; 32] = signer
        .mls_signature_public_key
        .as_slice()
        .try_into()
        .unwrap();
    assert!(
        store
            .current_account_chat_source(&account, &local, &group)
            .unwrap()
            .is_none()
    );
    drop(client);
    drop(store);
    let runtimes = apps.clone().map(MarmotAppRuntime::new);
    runtimes[0].reconcile_accounts().await.unwrap();
    let recipient = runtimes[1]
        .accounts()
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let sponsor = runtimes[0]
        .accounts()
        .approve_device_linking_session("test", recipient.setup_packet(), None)
        .await
        .unwrap();
    complete_pair(&sponsor, &recipient, enrollment).await;
    if !enrollment {
        let inventory = runtimes[0]
            .accounts()
            .account_chat_sharing_targets("test")
            .await
            .unwrap();
        let target = inventory.targets.first().unwrap().device.clone();
        let cancelled = runtimes[0]
            .accounts()
            .begin_account_chat_sharing("test", target.clone())
            .await
            .unwrap();
        let revision = cancelled.snapshot().unwrap().revision;
        cancelled.cancel();
        assert!(cancelled.approve(revision).await.is_err());
        assert!(
            apps[0]
                .account_storage("test")
                .unwrap()
                .current_account_chat_source(&account, &local, &group)
                .unwrap()
                .is_none()
        );
        let source = runtimes[0]
            .accounts()
            .begin_account_chat_sharing("test", target)
            .await
            .unwrap();
        let review = source.snapshot().unwrap();
        assert!(source.approve(review.revision + 1).await.is_err());
        source.approve(review.revision).await.unwrap();
        let pending = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let mut pending = runtimes[1]
                    .accounts()
                    .pending_account_chat_sharing("test")
                    .await
                    .unwrap();
                if !pending.is_empty() {
                    break pending.remove(0);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        pending
            .approve(pending.snapshot().unwrap().revision)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            while !source.snapshot().unwrap().complete || !pending.snapshot().unwrap().complete {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        source.cancel();
        pending.cancel();
    }
    let accepted = apps[0]
        .account_storage("test")
        .unwrap()
        .current_account_chat_source(&account, &local, &group)
        .unwrap();
    let visible = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            if runtimes[1]
                .accounts()
                .paired_chat_list_page("test", None, 128)
                .await
                .is_ok_and(|page| page.chats.iter().any(|row| row.group_id == group))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok();
    for runtime in &runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
    assert!(apps.iter().all(MarmotApp::storage_is_closed));
    assert!(accepted == Some(AccountChatSourceVerdict::Accepted));
    assert!(
        visible,
        "actual fresh original accepted legacy catalog did not reach peer"
    );
    // Hidden accepted continuity uses the same encrypted store, not a copied DB.
    let reopened = MarmotApp::with_relay(roots[0].path(), &url);
    let mut client = reopened.client("test").await.unwrap();
    assert!(client.automatic_chat_source_accepted(&group).unwrap());
    client.delete_group_local(&group).await.unwrap();
    drop(client);
    reopened.close_storage().unwrap();
    let reopened = MarmotApp::with_relay(roots[0].path(), &url);
    let client = reopened.client("test").await.unwrap();
    assert!(client.automatic_chat_source_accepted(&group).unwrap());
    drop(client);
    reopened.close_storage().unwrap();
    assert!(reopened.storage_is_closed());
}

#[test]
fn fresh_native_broad_original_accepts_pruned_legacy_without_created_inference() {
    crate::tests::run_composed_app_runtime_test("legacy-native-original", || async {
        exercise_original_legacy_acceptance(true).await
    });
}
#[test]
fn fresh_existing_pair_original_accepts_pruned_legacy_and_cancelled_original_cannot() {
    crate::tests::run_composed_app_runtime_test("legacy-existing-original", || async {
        exercise_original_legacy_acceptance(false).await
    });
}
