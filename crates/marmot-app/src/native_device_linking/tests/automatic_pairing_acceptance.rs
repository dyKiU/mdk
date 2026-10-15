use super::*;
use crate::{MarmotApp, MarmotAppRuntime};
use marmot_account::AccountHome;

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

#[derive(Clone, Copy, PartialEq, Eq)]
enum HeldPublication {
    None,
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
    eprintln!("automatic-enrollment-control stage=third-device-completion");
    wait_for_automatic_phase(&a, &c, DeviceLinkingPhase::EnrollmentComplete).await;
    eprintln!("automatic-enrollment-control stage=third-device-completed");
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
            .len()
            == 2
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
