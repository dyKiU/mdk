use super::*;
use crate::{MarmotApp, MarmotAppRuntime};
use marmot_account::AccountHome;

#[tokio::test]
async fn automatic_pairing_requires_explicit_enrollment_and_shares_existing_and_later_chats() {
    use cgka_traits::StorageProvider;
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
    for runtime in &runtimes {
        runtime.reconcile_accounts().await.unwrap();
    }
    let managers = runtimes.each_ref().map(|runtime| runtime.accounts());
    let old_chat = managers[0]
        .create_group("test", "Existing automatic chat", &[], None)
        .await
        .unwrap();
    let history = managers[0]
        .send_message("test", &old_chat, b"Existing private message".to_vec())
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
    wait_for_automatic_phase(&source, &recipient, DeviceLinkingPhase::ComparisonAvailable).await;
    let a = source.snapshot().await.unwrap();
    let b = recipient.snapshot().await.unwrap();
    assert!(a.decimals == b.decimals && a.decimals.is_some());
    assert!(matches!(
        source.continue_automatic_linking(a.revision, true).await,
        Err(DeviceLinkingError::NotReady)
    ));
    source.confirm_comparison(a.revision).await.unwrap();
    recipient.confirm_comparison(b.revision).await.unwrap();
    wait_for_automatic_phase(
        &source,
        &recipient,
        DeviceLinkingPhase::VerificationCompleteEnrollmentPending,
    )
    .await;
    let no_policy = || {
        apps.iter().all(|app| {
            app.account_storage("test")
                .unwrap()
                .approved_account_sharing_policy_storage()
                .unwrap()
                .approved_account_sharing_policies()
                .unwrap()
                .is_empty()
        })
    };
    assert!(no_policy());
    let revision = source.snapshot().await.unwrap().revision;
    assert!(matches!(
        source.continue_automatic_linking(revision + 1, true).await,
        Err(DeviceLinkingError::StaleRevision)
    ));
    source
        .continue_automatic_linking(revision, true)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert!(no_policy(), "one side's approval cannot approve its peer");
    recipient
        .continue_automatic_linking(recipient.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    wait_for_automatic_phase(&source, &recipient, DeviceLinkingPhase::EnrollmentComplete).await;
    assert!(apps.iter().all(|app| {
        app.account_storage("test")
            .unwrap()
            .approved_account_sharing_policy_storage()
            .unwrap()
            .approved_account_sharing_policies()
            .unwrap()
            .len()
            == 1
    }));
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
            if chats.chats.iter().any(|chat| chat.group_id == old_chat)
                && let Ok(messages) = messages
                && messages
                    .messages
                    .iter()
                    .any(|message| message.event_id.as_slice() == history_id)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("one-scan approved pair did not discover existing chat and history");
    let later = managers[0]
        .create_group("test", "Later automatic chat", &[], None)
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if managers[1]
                .paired_chat_list_page("test", None, 128)
                .await
                .unwrap()
                .chats
                .iter()
                .any(|chat| chat.group_id == later)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("one-scan approved pair did not discover a later chat");
    source.cancel().await.unwrap();
    recipient.cancel().await.unwrap();
    for runtime in runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
}

#[tokio::test]
async fn dropped_scanner_factory_cannot_export_a_response_before_host_adoption() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let runtimes = std::array::from_fn::<_, 2, _>(|index| {
        AccountHome::open(dirs[index].path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        MarmotAppRuntime::new(MarmotApp::with_relay(dirs[index].path(), &url))
    });
    for runtime in &runtimes {
        runtime.reconcile_accounts().await.unwrap();
    }
    let displayed = runtimes[0]
        .accounts()
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let code = displayed.automatic_pairing_code().await.unwrap();
    let scanner = runtimes[1]
        .accounts()
        .approve_automatic_device_linking_session("test", code, None)
        .await
        .unwrap();
    let retired = scanner.automatic_retirement_probe_for_test();
    drop(scanner);
    assert!(retired());
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert_eq!(
        displayed.snapshot().await.unwrap().phase,
        DeviceLinkingPhase::AwaitingSetup
    );
    drop(retired);
    displayed.cancel().await.unwrap();
    for runtime in runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
}

#[tokio::test]
async fn automatic_one_scan_exchange_keeps_both_human_comparisons_required() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    for displaying_device in [0, 1] {
        let keys = nostr::prelude::Keys::generate();
        let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        let runtimes = std::array::from_fn::<_, 2, _>(|index| {
            AccountHome::open(dirs[index].path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
            MarmotAppRuntime::new(MarmotApp::with_relay(dirs[index].path(), &url))
        });
        for runtime in &runtimes {
            runtime.reconcile_accounts().await.unwrap();
        }
        let displayed = runtimes[displaying_device]
            .accounts()
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let code = displayed.automatic_pairing_code().await.unwrap();
        assert!(code.len() <= 1024);
        assert_eq!(displayed.automatic_pairing_code().await.unwrap(), code);
        // Exactly one bootstrap import; no manual packet reads/transfers/ACKs.
        let scanner = runtimes[1 - displaying_device]
            .accounts()
            .approve_automatic_device_linking_session("test", code, None)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(
            displayed.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::AwaitingSetup
        );
        // Activation is programmatic after host account-scope adoption,
        // never another QR scan or implicit comparison confirmation.
        scanner.automatic_pairing_code().await.unwrap();
        wait_for_automatic_phase(
            &displayed,
            &scanner,
            DeviceLinkingPhase::ComparisonAvailable,
        )
        .await;
        let a = displayed.snapshot().await.unwrap();
        let b = scanner.snapshot().await.unwrap();
        assert!(a.decimals.is_some());
        assert_eq!(a.decimals, b.decimals);
        assert!(matches!(
            displayed.continue_linking(a.revision).await,
            Err(DeviceLinkingError::NotReady)
        ));
        displayed.confirm_comparison(a.revision).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        assert_ne!(
            scanner.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending
        );
        scanner.confirm_comparison(b.revision).await.unwrap();
        wait_for_automatic_phase(
            &displayed,
            &scanner,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending,
        )
        .await;
        displayed.cancel().await.unwrap();
        scanner.cancel().await.unwrap();
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
    }
}

async fn wait_for_automatic_phase(
    a: &DeviceLinkingSession,
    b: &DeviceLinkingSession,
    phase: DeviceLinkingPhase,
) {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let ap = a.snapshot().await.unwrap().phase;
            let bp = b.snapshot().await.unwrap().phase;
            assert!(
                !matches!(
                    ap,
                    DeviceLinkingPhase::Failed
                        | DeviceLinkingPhase::Cancelled
                        | DeviceLinkingPhase::Expired
                ),
                "left expected={phase:?} observed={ap:?}"
            );
            assert!(
                !matches!(
                    bp,
                    DeviceLinkingPhase::Failed
                        | DeviceLinkingPhase::Cancelled
                        | DeviceLinkingPhase::Expired
                ),
                "right expected={phase:?} observed={bp:?}"
            );
            if ap == phase && bp == phase {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("automatic pairing did not reach required phase");
}

#[tokio::test]
async fn automatic_transport_cannot_keep_dropped_original_authority_alive() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .import_account(
            "test",
            &nostr::prelude::Keys::generate()
                .secret_key()
                .to_secret_hex(),
        )
        .unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(
        dir.path(),
        relay.url().await.to_string(),
    ));
    runtime.reconcile_accounts().await.unwrap();
    let original = runtime
        .accounts()
        .begin_device_linking_session("test")
        .await
        .unwrap();
    original.automatic_pairing_code().await.unwrap();
    let retired = original.automatic_retirement_probe_for_test();
    drop(original);
    assert!(retired());
    drop(retired);
    runtime.shutdown_and_close().await.unwrap();
}
