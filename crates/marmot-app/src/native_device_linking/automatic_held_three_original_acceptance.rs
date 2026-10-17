//! Fully broad actual ABC originals retained through automatic discovery.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_held_three_originals_allow_b_initiated_discovery() {
    actual::run_native_public_three_device_enrollment(
        actual::ApprovalScenario::AutomaticHeldThreeBInitiates,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_held_three_originals_allow_c_initiated_discovery() {
    actual::run_native_public_three_device_enrollment(
        actual::ApprovalScenario::AutomaticHeldThreeCInitiates,
    )
    .await;
}

pub(super) async fn order_actual_signers(
    apps: &mut [MarmotApp; 3],
    keys: &nostr::prelude::Keys,
    b_initiates: bool,
) {
    use cgka_traits::storage::AccountDeviceSignerStorage;
    let plane = crate::MarmotRelayPlane::full_history_with_loopback(true);
    let identity = cgka_traits::MemberId::new(keys.public_key().to_bytes().to_vec());
    let mut actual = Vec::new();
    for app in apps.iter() {
        // Initialize genuine local Core signers without network maintenance or
        // KeyPackage publication; each owning client drops before runtime start.
        let client = app
            .local_client_with_relay_plane("test", &plane, None)
            .await
            .unwrap();
        let signer = app
            .account_storage("test")
            .unwrap()
            .account_device_signer(&identity)
            .unwrap()
            .unwrap()
            .mls_signature_public_key;
        actual.push((signer, app.clone()));
        drop(client);
    }
    actual.sort_by(|left, right| left.0.cmp(&right.0));
    assert!(actual.windows(2).all(|pair| pair[0].0 != pair[1].0));
    // The actual automatic initiator is the lower signer. A remains sponsor;
    // B and C exchange their complete stores to select either request direction.
    *apps = [
        actual[2].1.clone(),
        actual[usize::from(!b_initiates)].1.clone(),
        actual[usize::from(b_initiates)].1.clone(),
    ];
}

pub(super) async fn create_real_b_source_and_wait(
    runtimes: &[MarmotAppRuntime; 3],
    source: &MarmotApp,
) -> bool {
    let group =
        Box::pin(runtimes[1].create_group("test", "Actual B-owned ordinary chat", &[], None))
            .await
            .unwrap();
    let roster = runtimes[1]
        .accounts()
        .group_roster("test", &group)
        .await
        .unwrap();
    assert_eq!(
        roster.members.len(),
        1,
        "actual B ordinary genesis is not protected roster membership"
    );
    let sent = Box::pin(runtimes[1].send_message(
        "test",
        &group,
        b"genuine B canonical history while ABC originals held".to_vec(),
    ))
    .await
    .unwrap();
    assert_eq!(sent.published, 1);
    assert_eq!(sent.message_ids.len(), 1);
    let event = &sent.message_ids[0];
    let storage = source.account_storage("test").unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(row) = storage
                .app_storage()
                .timeline_message(&hex::encode(group.as_slice()), event)
                .unwrap()
            {
                assert!(!row.deleted && row.invalidation_status.is_none());
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("actual B source canonical timeline must materialize");
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        loop {
            if let Ok(window) = runtimes[2].open_account_conversation_window("test", &group, 128).await {
                let present = matches!(window.snapshot.header, crate::AccountConversationHeader::PairedSource(_))
                    && window.snapshot.rows.iter().any(|row| matches!(row,
                        crate::AccountConversationRow::PairedSource(row) if hex::encode(row.event_id) == *event));
                window.window_handle().cancel();
                if present { return; }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }).await.is_ok()
}
