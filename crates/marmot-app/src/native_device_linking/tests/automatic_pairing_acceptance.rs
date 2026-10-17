use super::*;
use crate::{MarmotApp, MarmotAppRuntime};
use marmot_account::AccountHome;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_setup_can_reverse_roles_and_complete_enrollment() {
    cancelled_setup_role_reversal(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_setup_can_reverse_roles_after_restart_and_complete_enrollment() {
    cancelled_setup_role_reversal(true).await;
}

async fn cancelled_setup_role_reversal(reopen: bool) {
    use cgka_traits::storage::{GroupStorage, StorageProvider};
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let mut apps = dirs.each_ref().map(|dir| {
        AccountHome::open(dir.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        MarmotApp::with_relay(dir.path(), &url)
    });
    let mut runtimes = apps.clone().map(MarmotAppRuntime::new);
    for runtime in &runtimes {
        runtime.reconcile_accounts().await.unwrap();
    }
    let first = runtimes[1]
        .accounts()
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let response = runtimes[0]
        .accounts()
        .approve_device_linking_session("test", first.setup_packet(), None)
        .await
        .unwrap();
    response.cancel().await.unwrap();
    first.cancel().await.unwrap();
    drop(response);
    drop(first);
    let storage = apps[0].account_storage("test").unwrap();
    let birth = storage
        .device_group_genesis_storage()
        .unwrap()
        .genesis_selection()
        .unwrap()
        .expect("actual abandoned setup created a genesis");
    assert!(!birth.active_denied);
    assert_eq!(birth.fact.birth.leaves.len(), 1);
    assert!(
        storage
            .private_roster_settlement_storage()
            .unwrap()
            .read_round()
            .unwrap()
            .is_none()
    );
    drop(storage);
    if reopen {
        for runtime in &runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
        apps = dirs
            .each_ref()
            .map(|dir| MarmotApp::with_relay(dir.path(), &url));
        runtimes = apps.clone().map(MarmotAppRuntime::new);
        for runtime in &runtimes {
            runtime.reconcile_accounts().await.unwrap();
        }
    }
    let storage = apps[0].account_storage("test").unwrap();

    // The former approver now displays the QR and becomes the recipient. The
    // old one-device genesis must not veto this independently approved join.
    let display = runtimes[0]
        .accounts()
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let scanner = runtimes[1]
        .accounts()
        .approve_automatic_device_linking_session(
            "test",
            display.automatic_pairing_code().await.unwrap(),
            None,
        )
        .await
        .unwrap();
    scanner.automatic_pairing_code().await.unwrap();
    compare_and_confirm_pair(&display, &scanner).await;
    for session in [&display, &scanner] {
        session
            .continue_automatic_linking(session.snapshot().await.unwrap().revision, true)
            .await
            .unwrap();
    }
    wait_for_automatic_phase(&display, &scanner, DeviceLinkingPhase::EnrollmentComplete).await;
    let retired = storage
        .device_group_genesis_storage()
        .unwrap()
        .genesis_selection()
        .unwrap()
        .unwrap();
    assert!(retired.active_denied);
    assert!(
        retired.fact.birth == birth.fact.birth,
        "retain original birth provenance"
    );
    assert!(
        storage.get_group(&birth.fact.birth.group_id).is_ok(),
        "preserve old MLS group"
    );
    for runtime in &runtimes {
        let targets = runtime
            .accounts()
            .device_linking_targets("test")
            .await
            .unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].device_count, 2);
        runtime.shutdown_and_close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_enrollment_reaches_a_separate_account_inbox_relay() {
    let group_relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let inbox_relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let group_url = group_relay.url().await.to_string();
    let inbox_url = inbox_relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let apps = dirs.each_ref().map(|dir| {
        AccountHome::open(dir.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        MarmotApp::with_relay(dir.path(), &group_url)
    });
    for app in &apps {
        let lists = app
            .set_account_inbox_relays(
                "test",
                vec![cgka_traits::TransportEndpoint(inbox_url.clone())],
                vec![cgka_traits::TransportEndpoint(group_url.clone())],
            )
            .await
            .unwrap();
        assert_eq!(
            app.account_inbox_endpoints("test", &lists),
            vec![cgka_traits::TransportEndpoint(inbox_url.clone())]
        );
        assert_ne!(inbox_url, group_url);
    }
    let runtimes = apps.map(MarmotAppRuntime::new);
    for runtime in &runtimes {
        runtime.reconcile_accounts().await.unwrap();
    }
    let display = runtimes[0]
        .accounts()
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let scanner = runtimes[1]
        .accounts()
        .approve_automatic_device_linking_session(
            "test",
            display.automatic_pairing_code().await.unwrap(),
            None,
        )
        .await
        .unwrap();
    scanner.automatic_pairing_code().await.unwrap();
    compare_and_confirm_pair(&display, &scanner).await;
    for session in [&display, &scanner] {
        session
            .continue_automatic_linking(session.snapshot().await.unwrap().revision, true)
            .await
            .unwrap();
    }
    wait_for_automatic_phase(&display, &scanner, DeviceLinkingPhase::EnrollmentComplete).await;
    display.cancel().await.unwrap();
    scanner.cancel().await.unwrap();
    for runtime in &runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
}

// AUTOMATIC_BODY_TEST_BEGIN
#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn held_automatic_catalog_body_keeps_fresh_account_commands_responsive() {
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
        .create_group("test", "Body responsiveness baseline", &[], None)
        .await
        .unwrap();
    let history = managers[0]
        .send_message(
            "test",
            &old_chat,
            b"Body responsiveness baseline history".to_vec(),
        )
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
    recipient
        .continue_automatic_linking(recipient.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    source
        .continue_automatic_linking(source.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
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
        "actual bilateral completed policies are required"
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
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the real existing chat and history must be fully mirrored first");
    source.cancel().await.unwrap();
    recipient.cancel().await.unwrap();
    eprintln!("automatic-body-control stage=bilateral-pair-and-history-ready");

    let before = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        managers[0].device_linking_targets("test"),
    )
    .await
    .expect("the source actor must respond within the same bound before the hold")
    .expect("the pre-hold actor command must return actual targets");
    assert!(
        before.len() == 1 && before[0].device_count == 2,
        "the pre-hold control must observe the real two-device roster"
    );
    eprintln!("automatic-body-control stage=prehold-control");

    let (observed, release) = apps[0].relay_plane.hold_next_automatic_catalog_body_except(
        cgka_traits::MemberId::new(keys.public_key().to_bytes().to_vec()),
        old_chat.clone(),
    );
    struct BodyRelease(std::sync::Arc<tokio::sync::Notify>);
    impl Drop for BodyRelease {
        fn drop(&mut self) {
            self.0.notify_one();
        }
    }
    let release = BodyRelease(release);
    let fresh_chat = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        managers[0].create_group("test", "Body responsiveness new chat", &[], None),
    )
    .await
    .expect("the actual new-chat trigger must finish before its Catalog Body hold")
    .unwrap();
    let (held_group, held_message) =
        tokio::time::timeout(std::time::Duration::from_secs(30), observed)
            .await
            .expect("a genuine new-chat Catalog Body must reach transport")
            .expect("the genuine Catalog Body observer must remain alive");
    assert!(
        held_group == fresh_chat,
        "held cached catalog receipt must belong to the actual new chat"
    );
    assert!(
        held_message.id.as_slice().len() == 32 && !held_message.payload.is_empty(),
        "the held body must be an actual prepared transport message"
    );
    eprintln!("automatic-body-control stage=actual-new-chat-catalog-body-held");

    let peer = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        managers[1].device_linking_targets("test"),
    )
    .await
    .expect("the independent peer actor must respond while the actual body is held")
    .expect("the held-phase peer command must return actual targets");
    assert!(
        peer.len() == 1 && peer[0].device_count == 2,
        "the peer progress control must observe the real two-device roster"
    );
    eprintln!("automatic-body-control stage=peer-progress-control");

    let mut command = Box::pin(managers[0].device_linking_targets("test"));
    let first = tokio::time::timeout(std::time::Duration::from_secs(1), command.as_mut()).await;
    let responsive = first.is_ok();
    let early = first.ok();
    eprintln!("automatic-body-control stage=fresh-command-verdict-frozen responsive={responsive}");
    release.0.notify_one();
    eprintln!("automatic-body-control stage=actual-body-released");
    let targets = match early {
        Some(result) => result,
        None => tokio::time::timeout(std::time::Duration::from_secs(15), command.as_mut())
            .await
            .expect("the same fresh actor command must finish after body release"),
    }
    .expect("the same fresh actor command must return real targets");
    assert!(
        targets.len() == 1 && targets[0].device_count == 2,
        "the same command must observe the genuine two-device roster"
    );
    eprintln!("automatic-body-control stage=same-fresh-command-completed");
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let page = managers[1]
                .paired_chat_list_page("test", None, 128)
                .await
                .unwrap();
            let count = page
                .chats
                .iter()
                .filter(|chat| chat.group_id == fresh_chat)
                .count();
            assert!(
                count <= 1,
                "the actual new catalog effect must not be duplicated"
            );
            if count == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the released actual Catalog Body must discover the new chat exactly once");
    let page = managers[1]
        .paired_chat_list_page("test", None, 128)
        .await
        .unwrap();
    assert!(
        page.chats
            .iter()
            .filter(|chat| chat.group_id == fresh_chat)
            .count()
            == 1,
        "the released actual catalog effect must remain unique"
    );
    eprintln!("automatic-body-control stage=actual-new-chat-delivered-once");
    for (index, runtime) in runtimes.iter().enumerate() {
        runtime.shutdown_and_close().await.unwrap();
        assert!(
            runtime.storage_is_closed(),
            "the actual runtime must positively close storage"
        );
        eprintln!("automatic-body-control stage=positive-runtime-close index={index}");
    }
    assert!(
        responsive,
        "held automatic Catalog Body must not block a fresh account actor command"
    );
}
// AUTOMATIC_BODY_TEST_END

#[tokio::test]
async fn third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts() {
    four_device_enrollment(HeldPublication::None).await;
}

#[tokio::test]
async fn blocked_sibling_consent_does_not_starve_another_approved_peer() {
    four_device_enrollment(HeldPublication::SiblingConsent).await;
}

#[tokio::test]
async fn automatic_sync_does_not_block_foreground_enrollment_completion() {
    four_device_enrollment(HeldPublication::Automatic).await;
}

// COMPLETION_TEST_BEGIN
#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn completed_sibling_consent_services_initial_progress_without_periodic_tick() {
    four_device_enrollment(HeldPublication::CompletionWake).await;
}
// COMPLETION_TEST_END
#[derive(Clone, Copy, PartialEq, Eq)]
enum HeldPublication {
    None,

    // COMPLETION_TEST_BEGIN
    #[cfg(feature = "test-policy-overrides")]
    CompletionWake,
    // COMPLETION_TEST_END
    SiblingConsent,
    Automatic,
}

async fn four_device_enrollment(held_publication: HeldPublication) {
    #[cfg(feature = "test-policy-overrides")]
    install_publication_diagnostic_subscriber();
    use cgka_traits::StorageProvider;
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs: [tempfile::TempDir; 4] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
    let apps = std::array::from_fn::<_, 4, _>(|index| {
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
    let b = managers[1]
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let a = managers[0]
        .approve_automatic_device_linking_session(
            "test",
            b.automatic_pairing_code().await.unwrap(),
            None,
        )
        .await
        .unwrap();
    a.automatic_pairing_code().await.unwrap();
    eprintln!("automatic-enrollment-control stage=initial-two-comparison");
    compare_and_confirm_pair(&a, &b).await;
    b.continue_automatic_linking(b.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    a.continue_automatic_linking(a.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    eprintln!("automatic-enrollment-control stage=initial-two-completion");
    wait_for_automatic_phase(&a, &b, DeviceLinkingPhase::EnrollmentComplete).await;
    eprintln!("automatic-enrollment-control stage=initial-two-completed");
    a.cancel().await.unwrap();
    b.cancel().await.unwrap();
    let targets = managers[0].device_linking_targets("test").await.unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].device_count, 2);
    let c = managers[2]
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let a = managers[0]
        .approve_automatic_device_linking_session(
            "test",
            c.automatic_pairing_code().await.unwrap(),
            Some(targets[0].selector.clone()),
        )
        .await
        .unwrap();
    a.automatic_pairing_code().await.unwrap();
    eprintln!("automatic-enrollment-control stage=third-device-comparison");
    compare_and_confirm_pair(&a, &c).await;
    c.continue_automatic_linking(c.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    a.continue_automatic_linking(a.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    let approval = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            if let Some(approval) = managers[1]
                .pending_device_linking_approvals("test")
                .await
                .unwrap()
                .pop()
            {
                break approval;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("existing device must receive the genuine enrollment approval");
    let reviewed = approval.snapshot().await.unwrap();
    assert!(matches!(
        approval
            .approve_and_share_chats(reviewed.revision + 1)
            .await,
        Err(DeviceLinkingError::StaleRevision)
    ));
    approval.review_metadata(reviewed.revision).await.unwrap();
    let alias = managers[1]
        .pending_device_linking_approvals("test")
        .await
        .unwrap()
        .pop()
        .unwrap();
    let background_borrow = approval.automatic_retirement_probe_for_test();
    approval
        .approve_and_share_chats(reviewed.revision)
        .await
        .unwrap();
    // No enrollment_packet/receive_enrollment_packet/finalize calls by the host.
    // COMPLETION_TEST_BEGIN
    #[cfg(feature = "test-policy-overrides")]
    let roster_setup_only = held_publication == HeldPublication::CompletionWake;
    #[cfg(not(feature = "test-policy-overrides"))]
    let roster_setup_only = false;
    // This separate schedule test establishes real membership, not prior
    // B/C chat-sharing completion (the behavior under independent test).
    if !roster_setup_only {
        // COMPLETION_TEST_END
        eprintln!("automatic-enrollment-control stage=third-device-completion");
        wait_for_automatic_phase(&a, &c, DeviceLinkingPhase::EnrollmentComplete).await;
        eprintln!("automatic-enrollment-control stage=third-device-completed");
        // COMPLETION_TEST_BEGIN
    }
    // COMPLETION_TEST_END
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            if apps[..3].iter().all(|app| {
                let storage = app.account_storage("test").unwrap();
                let store = storage.private_roster_settlement_storage().unwrap();
                store.read_round().unwrap().is_some_and(|round| {
                    round.phase
                        == cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed
                        && round.anchor.successor.leaves.len() == 3
                        && store.read_facts().unwrap().len() == 3
                })
            }) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("automatic transport must settle all three real device leaves");
    // COMPLETION_TEST_BEGIN
    if roster_setup_only {
        eprintln!("completion-wake-control stage=third-roster-ready");
    }
    if !roster_setup_only {
        // COMPLETION_TEST_END
        assert!(apps[..3].iter().all(|app| {
            app.account_storage("test")
                .unwrap()
                .approved_account_sharing_policy_storage()
                .unwrap()
                .approved_account_sharing_policies()
                .unwrap()
                .len()
                == 2
        }));
        // COMPLETION_TEST_BEGIN
    }
    // COMPLETION_TEST_END
    a.cancel().await.unwrap();
    c.cancel().await.unwrap();
    drop(approval);
    assert!(
        !background_borrow(),
        "the public alias still owns this approval"
    );
    drop(alias);
    assert!(
        background_borrow(),
        "background transport must not keep the dropped original live"
    );
    drop(background_borrow);
    // COMPLETION_TEST_BEGIN
    if roster_setup_only {
        eprintln!("completion-wake-control stage=third-originals-retired");
    }
    // COMPLETION_TEST_END
    let targets = managers[0].device_linking_targets("test").await.unwrap();
    assert_eq!(targets[0].device_count, 3);
    let d = managers[3]
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let a = managers[0]
        .approve_automatic_device_linking_session(
            "test",
            d.automatic_pairing_code().await.unwrap(),
            Some(targets[0].selector.clone()),
        )
        .await
        .unwrap();
    a.automatic_pairing_code().await.unwrap();
    eprintln!("automatic-enrollment-control stage=fourth-device-comparison");
    compare_and_confirm_pair(&a, &d).await;
    let held_consent = (held_publication == HeldPublication::SiblingConsent).then(|| {
        apps[3]
            .relay_plane
            .hold_next_sibling_consent(cgka_traits::MemberId::new(
                keys.public_key().to_bytes().to_vec(),
            ))
    });
    let held_automatic = (held_publication == HeldPublication::Automatic).then(|| {
        apps[3]
            .relay_plane
            .hold_next_automatic_control(cgka_traits::MemberId::new(
                keys.public_key().to_bytes().to_vec(),
            ))
    });

    // COMPLETION_TEST_BEGIN
    #[cfg(feature = "test-policy-overrides")]
    let held_consent = if held_publication == HeldPublication::CompletionWake {
        Some(
            apps[3]
                .relay_plane
                .hold_next_sibling_consent(cgka_traits::MemberId::new(
                    keys.public_key().to_bytes().to_vec(),
                )),
        )
    } else {
        held_consent
    };
    // COMPLETION_TEST_END
    d.continue_automatic_linking(d.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    a.continue_automatic_linking(a.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    let mut approvals = Vec::new();
    for manager in &managers[1..3] {
        let approval = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if let Some(approval) = manager
                    .pending_device_linking_approvals("test")
                    .await
                    .unwrap()
                    .pop()
                {
                    break approval;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        let revision = approval.snapshot().await.unwrap().revision;
        approval.review_metadata(revision).await.unwrap();
        approval.approve_and_share_chats(revision).await.unwrap();
        approvals.push(approval);
    }

    // COMPLETION_TEST_BEGIN
    #[cfg(feature = "test-policy-overrides")]
    let mut completion_wake_result = None;
    #[cfg(feature = "test-policy-overrides")]
    let held_consent = if held_publication == HeldPublication::CompletionWake {
        // Real transport hold precedes the schedule gate; no fake consent or policy.
        let (observed, release) = held_consent.expect("completion test consent hold installed");
        struct ConsentHoldRelease(std::sync::Arc<tokio::sync::Notify>);
        impl Drop for ConsentHoldRelease {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }
        let release = ConsentHoldRelease(release);
        // Primary private settlement is independent of the held sibling Consent.
        // Keep every periodic arm ungated until its real four-leaf facts exist.
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if apps.iter().all(|app| {
                    let storage = app.account_storage("test").unwrap();
                    let store = storage.private_roster_settlement_storage().unwrap();
                    store.read_round().unwrap().is_some_and(|round| {
                        round.phase == cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed
                            && round.anchor.successor.leaves.len() == 4
                            && store.read_facts().unwrap().len() == 4
                    })
                }) {break;}
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        }).await.expect("four real primary settlement stores must be completed before the schedule gate");
        eprintln!("completion-wake-control stage=primary-round-ready");
        let held = tokio::time::timeout(std::time::Duration::from_secs(10), observed)
            .await
            .expect("actual sibling consent hold acquired")
            .expect("actual sibling consent publication observed");
        eprintln!("completion-wake-control stage=actual-consent-held");
        let periodic = runtimes[3].hold_periodic_linking_for_test("test");
        tokio::time::timeout(std::time::Duration::from_secs(10), periodic.observed())
            .await
            .expect("only recipient periodic arm must be gated");
        eprintln!("completion-wake-control stage=periodic-arm-gated");
        let mut success = false;
        let mut foreground = false;
        let mut durable_seen = false;
        let mut proof_seen = false;
        release.0.notify_one();
        let progress = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let policies = apps[3]
                    .account_storage("test")
                    .unwrap()
                    .approved_account_sharing_policy_storage()
                    .unwrap()
                    .approved_account_sharing_policies()
                    .unwrap();
                if let Some((durable, proof)) =
                    d.completed_consent_progress_for_test(&held.id, &policies)
                {
                    durable_seen |= durable;
                    proof_seen |= proof;
                    if !success {
                        success = true;
                        eprintln!("completion-wake-control stage=actual-consent-task-success");
                    }
                    if !foreground {
                        a.snapshot()
                            .await
                            .expect("foreground sponsor snapshot remains serviceable");
                        d.snapshot()
                            .await
                            .expect("foreground recipient snapshot remains serviceable");
                        foreground = true;
                        eprintln!("completion-wake-control stage=foreground-progress");
                        // COMPLETION_ACTOR_CHECK_BEGIN
                        let targets = managers[3]
                            .device_linking_targets("test")
                            .await
                            .expect("fresh recipient worker command remains serviceable");
                        assert!(
                            targets.len() == 1 && targets[0].device_count == 4,
                            "fresh recipient worker command must read the actual four-device roster"
                        );
                        eprintln!("completion-wake-control stage=fresh-actor-progress");
                        // COMPLETION_ACTOR_CHECK_END
                    }
                    if durable && proof {
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .is_ok();
        // Always release before normal completion, retirement and positive cleanup.
        drop(periodic);
        eprintln!("completion-wake-control stage=periodic-arm-released");
        drop(release);
        completion_wake_result = Some((success, foreground, progress, durable_seen, proof_seen));
        None
    } else {
        held_consent
    };
    // COMPLETION_TEST_END
    if let Some((observed, release)) = held_consent {
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            observed.await.expect("genuine sibling consent publication");
            eprintln!(
                "automatic-enrollment-control stage=sibling-consent-held-before-peer-progress"
            );
            loop {
                if apps[1..3].iter().any(|app| {
                    app.account_storage("test")
                        .unwrap()
                        .approved_account_sharing_policy_storage()
                        .unwrap()
                        .approved_account_sharing_policies()
                        .unwrap()
                        .len()
                        == 3
                }) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await;
        release.notify_one();
        assert!(
            result.is_ok(),
            "one blocked consent publication must not starve another approved sibling"
        );
    }
    let held_release = if let Some((observed, release)) = held_automatic {
        // Hold a genuine automatic publication before the unchanged completion
        // predicate. Release on unwind as well, without manufacturing consent.
        struct HeldPublicationRelease(std::sync::Arc<tokio::sync::Notify>);
        impl Drop for HeldPublicationRelease {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }
        let release = HeldPublicationRelease(release);
        tokio::time::timeout(std::time::Duration::from_secs(10), observed)
            .await
            .expect("the actual automatic publication must be held before completion")
            .expect("the actual automatic publication must be observed");
        eprintln!(
            "automatic-enrollment-control stage=automatic-publication-held-before-completion"
        );
        Some(release)
    } else {
        None
    };
    eprintln!("automatic-enrollment-control stage=fourth-device-completion");
    wait_for_automatic_phase_with_approvals(
        &a,
        &d,
        DeviceLinkingPhase::EnrollmentComplete,
        &approvals,
    )
    .await;
    eprintln!("automatic-enrollment-control stage=fourth-device-completed");
    // COMPLETION_TEST_BEGIN
    #[cfg(feature = "test-policy-overrides")]
    if completion_wake_result.is_some() {
        eprintln!("completion-wake-control stage=normal-completion");
    }
    // COMPLETION_TEST_END
    drop(held_release);
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            if apps.iter().all(|app| {
                let storage = app.account_storage("test").unwrap();
                let store = storage.private_roster_settlement_storage().unwrap();
                store.read_round().unwrap().is_some_and(|round| {
                    round.phase
                        == cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed
                        && round.anchor.successor.leaves.len() == 4
                        && store.read_facts().unwrap().len() == 4
                })
            }) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("later pairing must process every existing device automatically");
    a.cancel().await.unwrap();
    d.cancel().await.unwrap();
    for approval in approvals {
        approval.cancel().await.unwrap();
    }
    for runtime in runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
    // COMPLETION_TEST_BEGIN
    #[cfg(feature = "test-policy-overrides")]
    if let Some((success, foreground, progress, durable_seen, proof_seen)) = completion_wake_result
    {
        eprintln!("completion-wake-control stage=positive-cleanup-completed");
        eprintln!(
            "completion-wake-control result success={success} foreground={foreground} progress={progress} durable_policy_seen={durable_seen} proof_success_seen={proof_seen}"
        );
        assert!(
            success,
            "the held real consent task must successfully complete before the liveness oracle"
        );
        assert!(
            foreground,
            "foreground snapshots must complete while periodic maintenance is gated"
        );
        assert!(
            progress,
            "successful sibling consent must persist its real policy and publish its commit proof without a periodic tick"
        );
    }
    // COMPLETION_TEST_END
}

#[tokio::test]
async fn ordinary_one_scan_enrollment_has_original_cancellation_without_chat_sharing() {
    use cgka_traits::StorageProvider;
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs: [tempfile::TempDir; 3] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
    let apps = std::array::from_fn::<_, 3, _>(|index| {
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
    let b = managers[1]
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let a = managers[0]
        .approve_automatic_device_linking_session(
            "test",
            b.automatic_pairing_code().await.unwrap(),
            None,
        )
        .await
        .unwrap();
    a.automatic_pairing_code().await.unwrap();
    compare_and_confirm_pair(&a, &b).await;
    b.continue_automatic_linking(b.snapshot().await.unwrap().revision, false)
        .await
        .unwrap();
    a.continue_automatic_linking(a.snapshot().await.unwrap().revision, false)
        .await
        .unwrap();
    wait_for_automatic_phase(&a, &b, DeviceLinkingPhase::EnrollmentComplete).await;
    a.cancel().await.unwrap();
    b.cancel().await.unwrap();
    let targets = managers[0].device_linking_targets("test").await.unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].device_count, 2);
    let c = managers[2]
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let a = managers[0]
        .approve_automatic_device_linking_session(
            "test",
            c.automatic_pairing_code().await.unwrap(),
            Some(targets[0].selector.clone()),
        )
        .await
        .unwrap();
    a.automatic_pairing_code().await.unwrap();
    compare_and_confirm_pair(&a, &c).await;
    c.continue_automatic_linking(c.snapshot().await.unwrap().revision, false)
        .await
        .unwrap();
    a.continue_automatic_linking(a.snapshot().await.unwrap().revision, false)
        .await
        .unwrap();
    let approval = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            if let Some(approval) = managers[1]
                .pending_device_linking_approvals("test")
                .await
                .unwrap()
                .pop()
            {
                break approval;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("existing device must receive the genuine enrollment approval");
    let reviewed = approval.snapshot().await.unwrap();
    assert!(matches!(
        approval.approve(reviewed.revision + 1).await,
        Err(DeviceLinkingError::StaleRevision)
    ));
    approval.review_metadata(reviewed.revision).await.unwrap();
    let alias = managers[1]
        .pending_device_linking_approvals("test")
        .await
        .unwrap()
        .pop()
        .unwrap();
    let background_borrow = approval.automatic_retirement_probe_for_test();
    approval.approve(reviewed.revision).await.unwrap();
    // No enrollment_packet/receive_enrollment_packet/finalize calls by the host.
    wait_for_automatic_phase(&a, &c, DeviceLinkingPhase::EnrollmentComplete).await;
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            if apps[..3].iter().all(|app| {
                let storage = app.account_storage("test").unwrap();
                let store = storage.private_roster_settlement_storage().unwrap();
                store.read_round().unwrap().is_some_and(|round| {
                    round.phase
                        == cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed
                        && round.anchor.successor.leaves.len() == 3
                        && store.read_facts().unwrap().len() == 3
                })
            }) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("automatic transport must settle all three real device leaves");
    assert!(apps[..3].iter().all(|app| {
        app.account_storage("test")
            .unwrap()
            .approved_account_sharing_policy_storage()
            .unwrap()
            .approved_account_sharing_policies()
            .unwrap()
            .is_empty()
    }));
    a.cancel().await.unwrap();
    c.cancel().await.unwrap();
    drop(approval);
    assert!(
        !background_borrow(),
        "the public alias still owns this approval"
    );
    drop(alias);
    assert!(
        background_borrow(),
        "background transport must not keep the dropped original live"
    );
    drop(background_borrow);
    for runtime in runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
}

async fn compare_and_confirm_pair(a: &DeviceLinkingSession, b: &DeviceLinkingSession) {
    wait_for_automatic_phase(a, b, DeviceLinkingPhase::ComparisonAvailable).await;
    let left = a.snapshot().await.unwrap();
    let right = b.snapshot().await.unwrap();
    assert!(left.decimals.is_some() && left.decimals == right.decimals);
    a.confirm_comparison(left.revision).await.unwrap();
    b.confirm_comparison(right.revision).await.unwrap();
    wait_for_automatic_phase(
        a,
        b,
        DeviceLinkingPhase::VerificationCompleteEnrollmentPending,
    )
    .await;
}

#[tokio::test]
async fn automatic_pairing_requires_explicit_enrollment_and_shares_existing_and_later_chats() {
    automatic_pairing_with_recipient_approval_delay(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_pairing_delayed_recipient_approval_does_not_lose_welcome() {
    automatic_pairing_with_recipient_approval_delay(true).await;
}

async fn automatic_pairing_with_recipient_approval_delay(delay_recipient: bool) {
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
    // A person may approve the scanning/approver device several seconds before
    // the displayed/new device. Exercise actual relay receipt during that gap,
    // rather than approving the recipient before the first publication tick.
    let delay = if delay_recipient { 5_000 } else { 250 };
    let until = std::time::Instant::now() + std::time::Duration::from_millis(delay);
    let account_id = cgka_traits::MemberId::new(keys.public_key().to_bytes().to_vec());
    let mut early_welcome_cached = false;
    while std::time::Instant::now() < until {
        assert!(no_policy(), "one side's approval cannot approve its peer");
        if delay_recipient {
            let storage = apps[0].account_storage("test").unwrap();
            if let Some(fact) = storage
                .private_device_invite_storage()
                .unwrap()
                .private_invite()
                .unwrap()
                && let Some(transport) = fact.transport
            {
                for message in transport.welcomes {
                    if apps[1]
                        .relay_plane
                        .account_sdk_event_observation_for_test(
                            &account_id,
                            std::str::from_utf8(&message.payload).unwrap(),
                        )
                        .await
                        .is_some_and(|state| state[0])
                    {
                        early_welcome_cached = true;
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    if delay_recipient {
        eprintln!("automatic-approval-order-control early_welcome_cached={early_welcome_cached}");
    }
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
    automatic_comparison_trial(Vec::new()).await;
}

#[tokio::test]
#[ignore = "requires explicitly selected live public pairing relays"]
async fn public_one_scan_exchange_keeps_both_human_comparisons_required() {
    let urls = std::env::var("WN_PAIRING_TEST_RELAYS").expect("explicit test relay set required");
    let relays: Vec<_> = urls.split(',').map(str::to_owned).collect();
    assert!(!relays.is_empty() && relays.iter().all(|url| url.starts_with("wss://")));
    automatic_comparison_trial(relays).await;
}

async fn automatic_comparison_trial(pairing_relays: Vec<String>) {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    for displaying_device in [0, 1] {
        let keys = nostr::prelude::Keys::generate();
        let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        let runtimes = std::array::from_fn::<_, 2, _>(|index| {
            AccountHome::open(dirs[index].path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
            MarmotAppRuntime::new(MarmotApp::with_relay_and_config(
                dirs[index].path(),
                &url,
                crate::MarmotAppConfig::default()
                    .with_allow_loopback_relay_endpoints(true)
                    .with_open_ranking_provider(None, Vec::new())
                    .with_pairing_relay_urls(pairing_relays.clone()),
            ))
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
    eprintln!(
        "pairing_native_comparison display_directions=2 bilateral_explicit=true runtime_closes=4"
    );
}

async fn wait_for_automatic_phase(
    a: &DeviceLinkingSession,
    b: &DeviceLinkingSession,
    phase: DeviceLinkingPhase,
) {
    wait_for_automatic_phase_with_approvals(a, b, phase, &[]).await;
}

async fn wait_for_automatic_phase_with_approvals(
    a: &DeviceLinkingSession,
    b: &DeviceLinkingSession,
    phase: DeviceLinkingPhase,
    approvals: &[DeviceLinkingApproval],
) {
    let mut observed = None;
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let ap = a.snapshot().await.unwrap().phase;
            let bp = b.snapshot().await.unwrap().phase;
            observed = Some((ap, bp));
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
    .unwrap_or_else(|_| {
        #[cfg(feature = "test-policy-overrides")]
        for (side, original) in [("left", a), ("right", b)] {
            eprintln!(
                "automatic-enrollment-control side={side} primary/expected/children/completed={:?} intake={:?} rejections={:?} context_rejections={:?} projection={:?}",
                original.sibling_completion_aggregates_for_test(),
                original.sibling_recipient_diagnostics_for_test(),
                original.sibling_recipient_rejections_for_test(),
                original.sibling_context_rejections_for_test(),
                original.sibling_projection_aggregates_for_test(),
            );
            eprintln!(
                "automatic-enrollment-control side={side} child_channels={:?}",
                original.sibling_child_diagnostics_for_test(),
            );
            eprintln!(
                "automatic-enrollment-control side={side} native_rpc_counts/elapsed_ms/branch={:?}",
                original.native_observation_snapshot_for_test(),
            );
        }
        #[cfg(feature = "test-policy-overrides")]
        for (index, approval) in approvals.iter().enumerate() {
            eprintln!(
                "automatic-enrollment-control existing_index={index} child_channel={:?}",
                approval
                    .sharing_original_for_test()
                    .map(|original| original.channel_diagnostics_for_test()),
            );
        }
        #[cfg(not(feature = "test-policy-overrides"))]
        let _ = approvals;
        panic!("automatic pairing did not reach required phase: expected={phase:?} observed={observed:?}")
    });
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

#[path = "direct_contact_reuse_acceptance.rs"]
mod direct_contact_reuse_acceptance;

// The opt-in runner exports only this closed SDK diagnostic target. Never print
// arbitrary tracing fields: other targets can contain private test data.
#[cfg(feature = "test-policy-overrides")]
fn install_publication_diagnostic_subscriber() {
    if std::env::var("WN_UPSTREAM_PUBLICATION_DIAGNOSTICS").as_deref() != Ok("1") {
        return;
    }
    struct Subscriber;
    impl tracing::Subscriber for Subscriber {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.target() == "transport_nostr_adapter::sdk_client::test_publication"
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if !self.enabled(event.metadata()) {
                return;
            }
            struct Fields(Vec<String>);
            impl tracing::field::Visit for Fields {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if matches!(field.name(), "method" | "client_ordinal" | "stage") {
                        self.0.push(format!("{}={value:?}", field.name()));
                    }
                }
            }
            let mut fields = Fields(Vec::new());
            event.record(&mut fields);
            eprintln!("sdk-publication-control {}", fields.0.join(" "));
        }
    }
    tracing::subscriber::set_global_default(Subscriber)
        .expect("the isolated pairing diagnostic must own its tracing subscriber");
}

#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn completed_automatic_transport_keeps_public_cleanup_ownership() {
    use futures::FutureExt;
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs: [tempfile::TempDir; 2] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
    let runtimes = std::array::from_fn::<_, 2, _>(|index| {
        AccountHome::open(dirs[index].path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        MarmotAppRuntime::new(MarmotApp::with_relay(dirs[index].path(), &url))
    });
    for runtime in &runtimes {
        runtime.reconcile_accounts().await.unwrap();
    }
    let displayed = runtimes[1]
        .accounts()
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let display_exit = displayed.automatic_transport_exit_probe_for_test();
    let code = displayed.automatic_pairing_code().await.unwrap();
    let scanner = runtimes[0]
        .accounts()
        .approve_automatic_device_linking_session("test", code, None)
        .await
        .unwrap();
    let scanner_exit = scanner.automatic_transport_exit_probe_for_test();
    scanner.automatic_pairing_code().await.unwrap();
    compare_and_confirm_pair(&scanner, &displayed).await;
    displayed
        .continue_automatic_linking(displayed.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    scanner
        .continue_automatic_linking(scanner.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    let completed = std::panic::AssertUnwindSafe(wait_for_automatic_phase(
        &scanner,
        &displayed,
        DeviceLinkingPhase::EnrollmentComplete,
    ))
    .catch_unwind()
    .await
    .is_ok();
    let (display_report, scanner_report) = tokio::join!(
        tokio::time::timeout(std::time::Duration::from_secs(3), display_exit),
        tokio::time::timeout(std::time::Duration::from_secs(3), scanner_exit),
    );
    let reports = [
        display_report.ok().and_then(Result::ok),
        scanner_report.ok().and_then(Result::ok),
    ];
    // Collect both outcomes before any assertion can abort custody cleanup.
    let display_cancel_ok = displayed.cancel().await.is_ok();
    let scanner_cancel_ok = scanner.cancel().await.is_ok();
    let mut closed_runtimes = 0;
    for runtime in runtimes {
        if runtime.shutdown_and_close().await.is_ok() {
            closed_runtimes += 1;
        }
    }
    relay.shutdown();
    let address = url.strip_prefix("ws://").unwrap().trim_end_matches('/');
    let relay_closed = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while let Ok(socket) = tokio::net::TcpStream::connect(address).await {
            drop(socket);
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();
    assert!(
        completed
            && reports
                .iter()
                .all(|row| row.is_some_and(|row| row[0] && row[1]))
            && closed_runtimes == 2
            && relay_closed,
        "completed_driver_actual_exit_and_positive_cleanup_prerequisites"
    );
    eprintln!(
        "completed_driver_cleanup actual_completed=2 natural_closed_exits=2 runtime_closes=2 relay_closed=true"
    );
    assert!(
        reports.iter().all(|row| row.is_some_and(|row| !row[2]))
            && display_cancel_ok
            && scanner_cancel_ok,
        "completed_session_public_owner_retains_cleanup"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reopened_approved_pair_can_verify_another_installation() {
    reopened_pair_can_verify_another_installation(1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reopened_joined_device_can_verify_another_installation() {
    reopened_pair_can_verify_another_installation(0).await;
}

async fn reopened_pair_can_verify_another_installation(existing: usize) {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs: [tempfile::TempDir; 3] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
    for dir in &dirs {
        AccountHome::open(dir.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
    }
    let open = || {
        dirs.each_ref()
            .map(|dir| MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), &url)))
    };
    let runtimes = open();
    for runtime in &runtimes {
        runtime.reconcile_accounts().await.unwrap();
    }
    let requester = runtimes[0]
        .accounts()
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let approver = runtimes[1]
        .accounts()
        .approve_automatic_device_linking_session(
            "test",
            requester.automatic_pairing_code().await.unwrap(),
            None,
        )
        .await
        .unwrap();
    approver.automatic_pairing_code().await.unwrap();
    compare_and_confirm_pair(&requester, &approver).await;
    requester
        .continue_automatic_linking(requester.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    approver
        .continue_automatic_linking(approver.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    wait_for_automatic_phase(
        &requester,
        &approver,
        DeviceLinkingPhase::EnrollmentComplete,
    )
    .await;
    requester.cancel().await.unwrap();
    approver.cancel().await.unwrap();
    drop(requester);
    drop(approver);
    for runtime in runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
    // Match installed clients: reopen their own encrypted stores, never copy state.
    let runtimes = open();
    for runtime in &runtimes {
        runtime.reconcile_accounts().await.unwrap();
    }
    let targets = runtimes[existing]
        .accounts()
        .device_linking_targets("test")
        .await
        .unwrap();
    assert_eq!(
        targets.len(),
        1,
        "completed pair must remain selectable after restart"
    );
    assert_eq!(targets[0].device_count, 2);
    let requester = runtimes[2]
        .accounts()
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let approver = runtimes[existing]
        .accounts()
        .approve_automatic_device_linking_session(
            "test",
            requester.automatic_pairing_code().await.unwrap(),
            Some(targets[0].selector.clone()),
        )
        .await
        .unwrap();
    approver.automatic_pairing_code().await.unwrap();
    // Fresh human comparison is required; retained policy does not approve a new device.
    compare_and_confirm_pair(&requester, &approver).await;
    requester.cancel().await.unwrap();
    approver.cancel().await.unwrap();
    for runtime in runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_first_enrollment_can_start_fresh_comparison() {
    interrupted_first_enrollment_retries(false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_first_enrollment_same_peer_completes_after_restart() {
    interrupted_first_enrollment_retries(true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_first_enrollment_same_roles_completes_after_restart() {
    interrupted_first_enrollment_retries(true, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_enrollment_before_recipient_join_retries_after_restart() {
    interrupted_first_enrollment_retries_with_unjoined_recipient(true, true, true).await;
}

async fn interrupted_first_enrollment_retries(same_peer: bool, same_roles: bool) {
    interrupted_first_enrollment_retries_with_unjoined_recipient(same_peer, same_roles, false)
        .await;
}

async fn interrupted_first_enrollment_retries_with_unjoined_recipient(
    same_peer: bool,
    same_roles: bool,
    before_recipient_join: bool,
) {
    use cgka_traits::private_roster_settlement::PrivateSettlementPhase;
    use cgka_traits::{MemberId, StorageProvider};
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs: [tempfile::TempDir; 3] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
    let apps = dirs.each_ref().map(|dir| {
        AccountHome::open(dir.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        MarmotApp::with_relay(dir.path(), &url)
    });
    let runtimes = apps.clone().map(MarmotAppRuntime::new);
    for runtime in &runtimes {
        runtime.reconcile_accounts().await.unwrap();
    }
    let requester = runtimes[0]
        .accounts()
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let approver = runtimes[1]
        .accounts()
        .approve_automatic_device_linking_session(
            "test",
            requester.automatic_pairing_code().await.unwrap(),
            None,
        )
        .await
        .unwrap();
    approver.automatic_pairing_code().await.unwrap();
    compare_and_confirm_pair(&requester, &approver).await;
    let group = apps[1]
        .account_storage("test")
        .unwrap()
        .device_group_genesis_storage()
        .unwrap()
        .genesis_selection()
        .unwrap()
        .unwrap()
        .fact
        .birth
        .group_id;
    let release = if before_recipient_join {
        // Reproduce the older installed flow: explicit approver action publishes
        // its real Welcome before the recipient arms its own admission. Retain
        // that transport on the relay across cancellation and a fresh setup.
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let revision = approver.snapshot().await.unwrap().revision;
                match approver.continue_linking_and_share_chats(revision).await {
                    Ok(()) => break,
                    Err(DeviceLinkingError::NotReady | DeviceLinkingError::StaleRevision) => {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("actual approver publication failed: {error:?}"),
                }
            }
        })
        .await
        .expect("actual approved Add/Welcome must publish");
        let account_id = MemberId::new(keys.public_key().to_bytes().to_vec());
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let fact = apps[1]
                    .account_storage("test")
                    .unwrap()
                    .private_device_invite_storage()
                    .unwrap()
                    .private_invite()
                    .unwrap();
                let mut cached = false;
                if let Some(transport) = fact.and_then(|fact| fact.transport) {
                    for message in transport.welcomes {
                        cached |= apps[0]
                            .relay_plane
                            .account_sdk_event_observation_for_test(
                                &account_id,
                                std::str::from_utf8(&message.payload).unwrap(),
                            )
                            .await
                            .is_some_and(|state| state[0]);
                    }
                }
                if cached {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the first Welcome must actually reach the unarmed recipient SDK");
        assert!(
            apps[0]
                .account_storage("test")
                .unwrap()
                .accepted_device_group_anchor_storage()
                .unwrap()
                .accepted_anchor()
                .unwrap()
                .is_none(),
            "the first recipient must not have joined"
        );
        None
    } else {
        let (held, release) = apps[1].relay_plane.reject_private_confirmations(
            MemberId::new(keys.public_key().to_bytes().to_vec()),
            group.clone(),
        );
        requester
            .continue_automatic_linking(requester.snapshot().await.unwrap().revision, true)
            .await
            .unwrap();
        approver
            .continue_automatic_linking(approver.snapshot().await.unwrap().revision, true)
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(30), held)
            .await
            .expect("actual coordinator confirmation must reach publication rejection")
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let storage = apps[0].account_storage("test").unwrap();
                if storage
                    .accepted_device_group_anchor_storage()
                    .unwrap()
                    .accepted_anchor()
                    .unwrap()
                    .is_some()
                    && storage
                        .private_roster_settlement_storage()
                        .unwrap()
                        .read_round()
                        .unwrap()
                        .is_some_and(|round| round.phase == PrivateSettlementPhase::Pending)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("recipient must actually join while first settlement remains pending");
        Some(release)
    };
    requester.cancel().await.unwrap();
    runtimes[0].shutdown_and_close().await.unwrap();
    drop(release);
    approver.cancel().await.unwrap();
    for runtime in &runtimes[1..] {
        runtime.shutdown_and_close().await.unwrap();
    }
    drop(requester);
    drop(approver);
    drop(runtimes);
    drop(apps);
    let runtimes = dirs
        .each_ref()
        .map(|dir| MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), &url)));
    for runtime in &runtimes {
        runtime.reconcile_accounts().await.unwrap();
    }
    assert!(
        runtimes[0]
            .accounts()
            .device_linking_targets("test")
            .await
            .unwrap()
            .is_empty()
    );
    let display_index = if same_roles {
        0
    } else if same_peer {
        1
    } else {
        2
    };
    let scanner_index = if same_roles { 1 } else { 0 };
    let fresh = runtimes[display_index]
        .accounts()
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let retry = runtimes[scanner_index]
        .accounts()
        .approve_automatic_device_linking_session(
            "test",
            fresh.automatic_pairing_code().await.unwrap(),
            None,
        )
        .await;
    if let Ok(response) = &retry {
        response.automatic_pairing_code().await.unwrap();
        compare_and_confirm_pair(&fresh, response).await;
        if same_peer {
            fresh
                .continue_automatic_linking(fresh.snapshot().await.unwrap().revision, true)
                .await
                .unwrap();
            response
                .continue_automatic_linking(response.snapshot().await.unwrap().revision, true)
                .await
                .unwrap();
            wait_for_automatic_phase(&fresh, response, DeviceLinkingPhase::EnrollmentComplete)
                .await;
            for runtime in &runtimes[..2] {
                let targets = runtime
                    .accounts()
                    .device_linking_targets("test")
                    .await
                    .unwrap();
                assert_eq!(targets.len(), 1);
                assert_eq!(targets[0].device_count, 2);
            }
        }
        response.cancel().await.unwrap();
    }
    fresh.cancel().await.unwrap();
    for runtime in runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
    assert!(
        retry.is_ok(),
        "fresh comparison after interrupted first enrollment: {:?}",
        retry.err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_installations_private_welcome_cannot_abort_an_approved_recipient() {
    use cgka_traits::StorageProvider;
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let keys = nostr::prelude::Keys::generate();
    let dirs: [tempfile::TempDir; 4] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
    let apps = dirs.each_ref().map(|dir| {
        AccountHome::open(dir.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        MarmotApp::with_relay(dir.path(), &url)
    });
    let runtimes = apps.clone().map(MarmotAppRuntime::new);
    for runtime in &runtimes {
        runtime.reconcile_accounts().await.unwrap();
    }
    let mut pairs = Vec::new();
    for (recipient, source) in [(0, 1), (2, 3)] {
        let display = runtimes[recipient]
            .accounts()
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let scanner = runtimes[source]
            .accounts()
            .approve_automatic_device_linking_session(
                "test",
                display.automatic_pairing_code().await.unwrap(),
                None,
            )
            .await
            .unwrap();
        scanner.automatic_pairing_code().await.unwrap();
        compare_and_confirm_pair(&display, &scanner).await;
        pairs.push((display, scanner));
    }
    // Synchronously arm the first recipient's genuine explicit native action.
    // Its source has not approved, so it cannot publish the matching Welcome.
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let revision = pairs[0].0.snapshot().await.unwrap().revision;
            match pairs[0].0.continue_linking_and_share_chats(revision).await {
                Ok(()) => break,
                Err(DeviceLinkingError::NotReady | DeviceLinkingError::StaleRevision) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(error) => panic!("original recipient could not arm: {error:?}"),
            }
        }
    })
    .await
    .unwrap();
    // A different, independently approved pair shares the same account inbox,
    // but its authenticated Welcome must not revoke this recipient's owner.
    for session in [&pairs[1].0, &pairs[1].1] {
        session
            .continue_automatic_linking(session.snapshot().await.unwrap().revision, true)
            .await
            .unwrap();
    }
    wait_for_automatic_phase(
        &pairs[1].0,
        &pairs[1].1,
        DeviceLinkingPhase::EnrollmentComplete,
    )
    .await;
    let current = pairs[0]
        .0
        .snapshot()
        .await
        .expect("unrelated authenticated Welcome must preserve the actual owner");
    assert_eq!(
        current.phase,
        DeviceLinkingPhase::VerificationCompleteEnrollmentPending
    );
    assert!(
        apps[0]
            .account_storage("test")
            .unwrap()
            .accepted_device_group_anchor_storage()
            .unwrap()
            .accepted_anchor()
            .unwrap()
            .is_none(),
        "foreign Welcome cannot join another recipient"
    );
    pairs[0]
        .1
        .continue_automatic_linking(pairs[0].1.snapshot().await.unwrap().revision, true)
        .await
        .unwrap();
    wait_for_automatic_phase(
        &pairs[0].0,
        &pairs[0].1,
        DeviceLinkingPhase::EnrollmentComplete,
    )
    .await;
    for (display, scanner) in &pairs {
        display.cancel().await.unwrap();
        scanner.cancel().await.unwrap();
    }
    for runtime in &runtimes {
        runtime.shutdown_and_close().await.unwrap();
    }
}
// BODY_NEGATIVE_TEST_BEGIN
#[path = "automatic_body_negative_acceptance.rs"]
mod body_negative_acceptance;
// BODY_NEGATIVE_TEST_END

// BODY_LATE_ACK_TEST_BEGIN
#[cfg(feature = "test-policy-overrides")]
#[path = "automatic_body_late_ack_acceptance.rs"]
mod body_late_ack_acceptance;
// BODY_LATE_ACK_TEST_END
// PEER_PROOF_TEST_BEGIN
#[path = "late_peer_proof_acceptance.rs"]
mod late_peer_proof_acceptance;
// PEER_PROOF_TEST_END
