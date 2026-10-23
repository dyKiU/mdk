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

#[cfg(feature = "experimental-device-sync")]
#[tokio::test]
async fn account_list_receive_cancellation_preserves_actual_command_update() {
    actual_window_receive_cancellation(false, false).await;
}

#[cfg(feature = "experimental-device-sync")]
#[tokio::test]
async fn account_conversation_receive_cancellation_preserves_actual_command_update() {
    actual_window_receive_cancellation(true, false).await;
}

#[cfg(feature = "experimental-device-sync")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn account_conversation_actual_stale_sequence_preserves_cancelled_command_update() {
    actual_window_receive_cancellation(true, true).await;
}

#[cfg(feature = "experimental-device-sync")]
async fn actual_window_receive_cancellation(conversation: bool, force_stale: bool) {
    use cgka_traits::TransportEndpoint;
    use marmot_app::AccountSetupRequest;
    use nostr_relay_builder::MockRelay;
    use std::{sync::Arc, time::Duration};
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays(dir.path(), vec![url.clone()]);
    let kit = Arc::new(Marmot {
        runtime: app.runtime(),
        app,
    });
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
        .create_group(
            account.clone(),
            "Actual receive cancellation".into(),
            vec![],
            None,
        )
        .await
        .unwrap();
    let mut stale_observed = false;
    let mut command_after_stale = false;
    let observed = if conversation {
        let sent = kit
            .send_text(
                account.clone(),
                group.clone(),
                "Actual native receive state".into(),
            )
            .await
            .unwrap();
        assert!(
            sent.message_ids.len() == 1,
            "real receive fixture must publish exactly one message"
        );
        let expected_message = &sent.message_ids[0];
        let window = kit
            .open_account_conversation_window(account, group.clone(), 2)
            .await
            .unwrap();
        let mut sequence = window.snapshot().unwrap().sequence;
        let drain_deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut force_stale_once = force_stale;
        let witness = loop {
            assert!(
                std::time::Instant::now() < drain_deadline,
                "actual initial window replacements must settle"
            );
            let mut pending = loop {
                let mut next = Box::pin(window.__ffi_next());
                match tokio::time::timeout(Duration::from_millis(20), &mut next).await {
                    Ok(Ok(Some(update))) => {
                        assert!(
                            std::time::Instant::now() < drain_deadline,
                            "actual initial window replacements must settle"
                        );
                        sequence = update.sequence;
                    }
                    Err(_) => break next,
                    _ => panic!("actual conversation closed before cancellation witness"),
                }
            };
            assert!(futures::poll!(&mut pending).is_pending());
            let completed_before = window.completed_receive_count_for_test();
            if force_stale_once {
                // The real actor publishes a new sequence while this native
                // receive stays unpolled. The next old-sequence command must
                // encounter the original production stale-window refusal.
                match window.older_page(sequence, None).await {
                    Ok(advanced) => {
                        assert!(advanced.sequence > sequence, "actual page command must advance sequence");
                        force_stale_once = false;
                    }
                    Err(MarmotKitError::ChatWindowStale) => {
                        drop(pending);
                        continue;
                    }
                    Err(_) => panic!("actual stale setup command failed"),
                }
            }
            match window.older_page(sequence, None).await {
                Ok(replacement) => {
                    command_after_stale = stale_observed;
                    break Some((pending, completed_before, replacement));
                }
                Err(MarmotKitError::ChatWindowStale) => {
                    // A real background replacement may advance the owner after
                    // the quiet receive. Consume it before arming a new witness;
                    // only a successful command begins the cancellation check.
                    stale_observed = true;
                    drop(pending);
                    // ACTUAL_STALE_COMMAND_RECOVERY_BEGIN
                    break None;
                    // ACTUAL_STALE_COMMAND_RECOVERY_END
                }
                Err(_) => panic!("actual conversation page command failed before cancellation witness"),
            }
        };
        let observed = if let Some((pending, completed_before, replacement)) = witness {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let completed_unpolled = window.completed_receive_count_for_test();
            let unpolled_consumption = completed_unpolled > completed_before;
            eprintln!(
                "private_conversation_receive_completion baseline_count={completed_before} unpolled_count={completed_unpolled} actual_unpolled_consumption={unpolled_consumption}"
            );
            drop(pending);
            let retained = tokio::time::timeout(Duration::from_secs(2), window.__ffi_next()).await;
            let (observed_sequence, same_generation, result_kind) = match &retained {
                Ok(Ok(Some(update))) => (
                    Some(update.sequence),
                    update.generation == replacement.generation,
                    "replacement",
                ),
                Ok(Ok(None)) => (None, false, "closed"),
                Ok(Err(_)) => (None, false, "error"),
                Err(_) => (None, false, "timeout"),
            };
            eprintln!(
                "private_conversation_receive_witness command_sequence={} observed_sequence={observed_sequence:?} same_generation={same_generation} result_kind={result_kind}",
                replacement.sequence
            );
            let valid_page = |update: &crate::conversions::AccountConversationWindowSnapshotFfi| {
                matches!(&update.header, crate::conversions::AccountConversationHeaderFfi::LocalMls { header }
                    if header.header.member_count == Some(1) && !header.header.archived && !header.header.unrecoverable)
                    && update.rows.len() <= 2
                    && update.rows.iter().all(|row| matches!(row, crate::conversions::AccountConversationRowFfi::LocalMls { row } if row.group_id_hex == group))
                    && update.rows.iter().any(|row| matches!(row, crate::conversions::AccountConversationRowFfi::LocalMls { row }
                        if row.message_id_hex == *expected_message && row.group_id_hex == group && !row.deleted && row.plaintext == "Actual native receive state"))
            };
            let command_valid = valid_page(&replacement);
            let observed = command_valid
                && !unpolled_consumption
                && matches!(retained, Ok(Ok(Some(update)))
                if update.generation == replacement.generation && update.sequence >= replacement.sequence && valid_page(&update));
            eprintln!(
                "private_conversation_receive_semantic command_valid={command_valid} retained_required_state={observed}"
            );
            observed
        } else {
            false
        };
        if force_stale {
            eprintln!(
                "private-stale-command-witness stale_observed={stale_observed} command_after_stale={command_after_stale} cancellation_retained={observed}"
            );
        }
        window.cancel();
        observed
    } else {
        let window = kit.open_account_chat_list_window(account, 2).await.unwrap();
        let mut sequence = window.snapshot().unwrap().sequence;
        let drain_deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut pending = loop {
            let mut next = Box::pin(window.__ffi_next());
            match tokio::time::timeout(Duration::from_millis(20), &mut next).await {
                Ok(Ok(Some(update))) => {
                    assert!(
                        std::time::Instant::now() < drain_deadline,
                        "actual initial window replacements must settle"
                    );
                    sequence = update.sequence;
                }
                Err(_) => break next,
                _ => panic!("actual account list closed before cancellation witness"),
            }
        };
        assert!(futures::poll!(&mut pending).is_pending());
        let replacement = window.paired_page(sequence, None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(pending);
        let retained = tokio::time::timeout(Duration::from_secs(2), window.__ffi_next()).await;
        let observed =
            matches!(retained, Ok(Ok(Some(update))) if update.sequence == replacement.sequence);
        window.cancel();
        observed
    };
    kit.runtime.shutdown_and_close().await.unwrap();
    eprintln!(
        "private_receive_positive_closes=1 actual_command_replacement=true conversation={conversation}"
    );
    if force_stale {
        assert!(
            stale_observed && command_after_stale && observed,
            "actual stale replacement must preserve the cancelled command update"
        );
    } else {
        assert!(
            observed,
            "cancelled private receive consumed the actual command replacement"
        );
    }
}
