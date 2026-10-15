use super::*;
#[cfg(not(feature = "experimental-device-sync"))]
use crate::conversions::PairedChatMessageCursorFfi;
use marmot_app::MarmotApp;

#[cfg(not(feature = "experimental-device-sync"))]
#[tokio::test]
async fn account_views_default_refuse_before_account_resolution_or_cursor_decode() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays(dir.path(), vec![]);
    let kit = Marmot {
        runtime: app.runtime(),
        app,
    };
    assert!(matches!(
        kit.open_account_chat_list_window("missing".into(), 0).await,
        Err(MarmotKitError::AccountSharingUnsupported)
    ));
    assert!(matches!(
        kit.open_account_conversation_window("missing".into(), "invalid".into(), 0)
            .await,
        Err(MarmotKitError::AccountSharingUnsupported)
    ));
    assert!(matches!(
        kit.paired_chat_list_page("missing".into(), Some("invalid".into()), 0)
            .await,
        Err(MarmotKitError::AccountSharingUnsupported)
    ));
    assert!(matches!(
        kit.paired_chat_message_page(
            "missing".into(),
            "invalid".into(),
            Some(PairedChatMessageCursorFfi {
                created_at: u64::MAX,
                message_id_hex: "invalid".into()
            }),
            0
        )
        .await,
        Err(MarmotKitError::AccountSharingUnsupported)
    ));
    kit.runtime.shutdown().await;
}

#[cfg(feature = "experimental-device-sync")]
#[tokio::test]
async fn account_view_original_commands_cancel_and_shutdown_during_native_receive() {
    use cgka_traits::TransportEndpoint;
    use marmot_app::AccountSetupRequest;
    use nostr_relay_builder::MockRelay;
    use std::{sync::Arc, time::Duration};
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays(dir.path(), vec![url.clone()]);
    let kit = Marmot {
        runtime: app.runtime(),
        app,
    };
    let endpoint = TransportEndpoint(url);
    let account = kit
        .runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint.clone()],
            bootstrap_relays: vec![endpoint],
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
            ..Default::default()
        })
        .await
        .unwrap()
        .account
        .account_id_hex;
    let group = kit
        .create_group(account.clone(), "Native fixture".into(), vec![], None)
        .await
        .unwrap();
    let list = kit
        .open_account_chat_list_window(account.clone(), 2)
        .await
        .unwrap();
    let initial = list.snapshot().unwrap();
    assert!(list.snapshot().is_none());
    assert_eq!(initial.rows.len(), 1);
    let waiter = Arc::clone(&list);
    let mut pending = pending_receive(|| waiter.next()).await;
    let page = tokio::time::timeout(
        Duration::from_secs(2),
        list.paired_page(initial.sequence, None),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(page.generation, initial.generation);
    list.cancel();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), &mut pending)
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        list.paired_page(page.sequence, None).await,
        Err(MarmotKitError::AccountSharingClosed)
    ));
    let conversation = kit
        .open_account_conversation_window(account.clone(), group, 2)
        .await
        .unwrap();
    assert!(conversation.snapshot().is_some());
    let mut pending = pending_receive(|| conversation.next()).await;
    conversation.cancel();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), &mut pending)
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    let list = kit.open_account_chat_list_window(account, 2).await.unwrap();
    list.snapshot();
    let mut pending = pending_receive(|| list.next()).await;
    kit.runtime.shutdown().await;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), &mut pending)
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
}

#[cfg(feature = "experimental-device-sync")]
async fn pending_receive<F, T>(mut receive: impl FnMut() -> F) -> std::pin::Pin<Box<F>>
where
    F: std::future::Future<Output = Result<Option<T>, MarmotKitError>>,
{
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let mut pending = Box::pin(receive());
        match tokio::time::timeout(Duration::from_millis(20), &mut pending).await {
            Err(_) => return pending,
            // Opening the genuine ordinary window may mark it read or refresh
            // its header. Drain those legitimate replacements before testing
            // a command against a genuinely waiting native receiver.
            Ok(Ok(Some(_))) => assert!(
                Instant::now() < deadline,
                "initial replacements must settle"
            ),
            Ok(_) => panic!("native receiver closed or failed before its original was cancelled"),
        }
    }
}
