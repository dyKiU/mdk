//! Genuine signer ordering selects either automatic Request direction while
//! completed public pairing originals remain held, as in installed hosts.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_held_originals_allow_sponsor_initiated_discovery() {
    actual::run_native_public_three_device_enrollment(
        actual::ApprovalScenario::AutomaticHeldSponsorInitiates,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_held_originals_allow_recipient_initiated_discovery() {
    actual::run_native_public_three_device_enrollment(
        actual::ApprovalScenario::AutomaticHeldRecipientInitiates,
    )
    .await;
}

pub(super) async fn order_actual_signers(
    apps: &mut [MarmotApp; 3],
    keys: &nostr::prelude::Keys,
    sponsor_initiates: bool,
) {
    use cgka_traits::storage::AccountDeviceSignerStorage;
    let plane = crate::MarmotRelayPlane::full_history_with_loopback(true);
    let identity = cgka_traits::MemberId::new(keys.public_key().to_bytes().to_vec());
    let mut signers = Vec::new();
    for app in apps.iter().take(2) {
        // Actual local Core opening creates its ordinary device signer without
        // publishing a KeyPackage or starting network maintenance. No keys or
        // permission rows are fabricated. Drop before the worker takes custody.
        let client = app
            .local_client_with_relay_plane("test", &plane, None)
            .await
            .unwrap();
        signers.push(
            app.account_storage("test")
                .unwrap()
                .account_device_signer(&identity)
                .unwrap()
                .unwrap()
                .mls_signature_public_key,
        );
        drop(client);
    }
    assert_ne!(signers[0], signers[1]);
    if (signers[0] < signers[1]) != sponsor_initiates {
        apps.swap(0, 1);
    }
}

pub(super) async fn wait_record(
    source: &MarmotApp,
    recipient: &MarmotAppRuntime,
    incoming: &super::automatic_forwarding_non_admin_acceptance::IncomingPeer,
) -> bool {
    let group = hex::encode(incoming.group.as_slice());
    let storage = source.account_storage("test").unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(row) = storage
                .app_storage()
                .timeline_message(&group, &incoming.preapproval_message)
                .unwrap()
            {
                assert!(!row.deleted && row.invalidation_status.is_none());
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("actual accepted source canonical timeline must materialize");
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        loop {
            if let Ok(window) = recipient.open_account_conversation_window("test", &incoming.group, 128).await {
                let present = matches!(window.snapshot.header, crate::AccountConversationHeader::PairedSource(_))
                    && window.snapshot.rows.iter().any(|row| matches!(row,
                        crate::AccountConversationRow::PairedSource(row) if hex::encode(row.event_id) == incoming.preapproval_message));
                window.window_handle().cancel();
                if present { return; }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }).await.is_ok()
}
