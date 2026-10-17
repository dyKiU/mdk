use super::*;
#[path = "automatic_body_late_ack_relay.rs"]
mod relay;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_receipt_retires_final_catalog_body_before_late_backend_ack() {
    late_ack_trial(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unchanged_catalog_context_accepts_the_same_real_backend_ack() {
    late_ack_trial(true).await;
}
async fn wait_for(mut predicate: impl FnMut() -> bool) -> bool {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while !predicate() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}
async fn late_ack_trial(hold_receipt: bool) {
    use cgka_traits::StorageProvider;
    let backend = nostr_relay_builder::MockRelay::run().await.unwrap();
    let proxy = relay::AckProxy::start(backend.url().await.to_string()).await;
    let keys = nostr::prelude::Keys::generate();
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let apps = dirs.each_ref().map(|dir| {
        AccountHome::open(dir.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        MarmotApp::with_relay(dir.path(), &proxy.url)
    });
    let runtimes = apps.clone().map(MarmotAppRuntime::new);
    for runtime in &runtimes {
        runtime.reconcile_accounts().await.unwrap();
    }
    let managers = runtimes.each_ref().map(|runtime| runtime.accounts());
    let old_chat = managers[0]
        .create_group("test", "Settled ACK baseline", &[], None)
        .await
        .unwrap();
    let history = managers[0]
        .send_message("test", &old_chat, b"Synthetic ACK baseline".to_vec())
        .await
        .unwrap();
    assert_eq!(history.message_ids.len(), 1);
    let recipient = managers[1]
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let source = managers[0]
        .approve_automatic_device_linking_session(
            "test",
            recipient.automatic_pairing_code().await.unwrap(),
            None,
        )
        .await
        .unwrap();
    source.automatic_pairing_code().await.unwrap();
    compare_and_confirm_pair(&source, &recipient).await;
    for session in [&recipient, &source] {
        session
            .continue_automatic_linking(session.snapshot().await.unwrap().revision, true)
            .await
            .unwrap();
    }
    wait_for_automatic_phase(&source, &recipient, DeviceLinkingPhase::EnrollmentComplete).await;
    assert!(
        apps.iter().all(|app| {
            let policies = app
                .account_storage("test")
                .unwrap()
                .approved_account_sharing_policy_storage()
                .unwrap()
                .approved_account_sharing_policies()
                .unwrap();
            policies.len() == 1 && !policies[0].revoked
        }),
        "genuine bilateral completed policy required"
    );
    let history_id = hex::decode(&history.message_ids[0]).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let chats = managers[1]
                .paired_chat_list_page("test", None, 128)
                .await
                .unwrap();
            let messages = managers[1]
                .paired_chat_message_page("test", old_chat.clone(), None, 128)
                .await;
            if chats
                .chats
                .iter()
                .filter(|chat| chat.group_id == old_chat)
                .count()
                == 1
                && messages.is_ok_and(|page| {
                    page.messages
                        .iter()
                        .any(|message| message.event_id.as_slice() == history_id)
                })
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("actual existing chat and history must settle first");
    source.cancel().await.unwrap();
    recipient.cancel().await.unwrap();
    let probe = crate::client::AppClient::test_capture_automatic_body_late_ack(
        dirs[0].path(),
        dirs[1].path(),
        &old_chat,
        cgka_traits::TransportEndpoint(proxy.url.clone()),
        hold_receipt,
        proxy.armer(),
    );
    let new_chat = managers[0]
        .create_group("test", "Actual late ACK Catalog", &[], None)
        .await
        .unwrap();
    let held_ack =
        wait_for(|| proxy.observed().actual_ok_held > 0 && probe.observed().captured).await;
    let before = proxy.observed();
    let new_import = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let page = managers[1]
                .paired_chat_list_page("test", None, 128)
                .await
                .unwrap();
            if page
                .chats
                .iter()
                .filter(|chat| chat.group_id == new_chat)
                .count()
                == 1
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok();
    let receipt_ordered = wait_for(|| {
        if hold_receipt {
            probe.receipt_is_held()
        } else {
            let observation = probe.observed();
            observation.receipt_accepted > 0
                && observation.receipt_during_publication
                && observation.context_changed
        }
    })
    .await;
    let held = proxy.observed();
    // Release the original stored backend frames even if a mutant did not reject
    // the superseded context. Rejection is part of the final behavioral oracle.
    proxy.release_actual_ok();
    let exact_ack_forwarded = wait_for(|| {
        let wire = proxy.observed();
        wire.actual_ok_sent > 0 && wire.exact_ok_sent == wire.actual_ok_sent
    })
    .await;
    let disposed = wait_for(|| {
        let observation = probe.observed();
        observation.future_dropped > 0
            && (observation.context_rejected > 0
                || observation.successful_harvest > 0
                || observation.retired > 0)
    })
    .await;
    // This command runs after the observed disposition, so the serial owner has
    // completed the harvest turn before effects are inspected or shutdown begins.
    let actor_progress = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        managers[0].device_linking_targets("test"),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    let before_receipt_release = probe.observed();
    probe.release_receipt();
    let receipt_finished = wait_for(|| probe.observed().receipt_accepted > 0).await;
    // A subsequent real chat must discover and deliver through the SDK's
    // existing approved channel scheduling, without restoring caller authority.
    // This bounded outcome belongs to the final behavioral oracle, so a stale
    // context mutant cannot be misclassified as a prerequisite timeout.
    let followup = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let chat = managers[0]
            .create_group("test", "After ACK disposition", &[], None)
            .await
            .map_err(|_| ())?;
        let sent = managers[0]
            .send_message("test", &chat, b"Synthetic post-ACK message".to_vec())
            .await
            .map_err(|_| ())?;
        if sent.message_ids.len() != 1 {
            return Err(());
        }
        let message_id = hex::decode(&sent.message_ids[0]).map_err(|_| ())?;
        loop {
            let page = managers[1]
                .paired_chat_list_page("test", None, 128)
                .await
                .map_err(|_| ())?;
            let messages = managers[1]
                .paired_chat_message_page("test", chat.clone(), None, 128)
                .await;
            if page.chats.iter().filter(|row| row.group_id == chat).count() == 1
                && messages.is_ok_and(|page| {
                    page.messages
                        .iter()
                        .filter(|row| row.event_id.as_slice() == message_id)
                        .count()
                        == 1
                })
            {
                return Ok::<(), ()>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok_and(|result| result.is_ok());
    let pre_close = probe.observed();
    let mut closes = 0;
    for runtime in &runtimes {
        if runtime.shutdown_and_close().await.is_ok() {
            closes += 1;
        }
    }
    for app in &apps {
        app.relay_plane.shutdown().await;
    }
    let proxy_close = proxy.close().await;
    let after = probe.observed();
    let cleanup = closes == 2 && proxy_close.is_ok();
    let prerequisites = held_ack
        && before.wire_events > 0
        && before.actual_ok_sent == 0
        && new_import
        && receipt_ordered
        && held.actual_ok_held > 0
        && held.actual_ok_sent == 0
        && exact_ack_forwarded
        && disposed
        && actor_progress
        && receipt_finished
        && after.armed
        && after.final_fragment
        && after.captured
        && after.future_dropped > 0;
    let expected_effects = if hold_receipt {
        before_receipt_release.receipt_accepted == 0
            && before_receipt_release.sdk_success == 1
            && before_receipt_release.successful_harvest == 1
            && before_receipt_release.old_body_effects == 1
            && after.old_body_effects == 1
    } else {
        pre_close.context_changed
            && after.old_body_effects == 0
            && after.sdk_success <= 1
            && after.successful_harvest <= 1
            && after.context_rejected > 0
    };
    eprintln!(
        "body-late-ack-control hold_receipt={hold_receipt} prerequisites={prerequisites} cleanup={cleanup} followup={followup} old_body_effects={} sdk_success={} successful_harvest={} context_rejected={} future_dropped={} retired={}",
        after.old_body_effects,
        after.sdk_success,
        after.successful_harvest,
        after.context_rejected,
        after.future_dropped,
        after.retired
    );
    assert!(
        prerequisites,
        "real final Catalog, backend ACK, authenticated receipt and original disposition must execute"
    );
    assert!(
        cleanup,
        "both native runtimes and actual proxy sockets must positively close"
    );
    assert!(
        expected_effects && followup,
        "late Catalog ACK must not advance a superseded Body context; unchanged context must retain real ACK progress"
    );
}
