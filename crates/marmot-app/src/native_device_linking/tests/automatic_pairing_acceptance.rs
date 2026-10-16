use super::*;
use crate::{MarmotApp, MarmotAppRuntime};
use marmot_account::AccountHome;

#[tokio::test]
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

#[tokio::test]
async fn third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts() {
    four_device_enrollment(HeldPublication::None, None, false).await;
}

#[tokio::test]
async fn blocked_sibling_consent_does_not_starve_another_approved_peer() {
    four_device_enrollment(HeldPublication::SiblingConsent, None, false).await;
}

#[tokio::test]
async fn automatic_sync_does_not_block_foreground_enrollment_completion() {
    four_device_enrollment(HeldPublication::Automatic, None, false).await;
}

#[tokio::test]
#[ignore = "explicit synthetic public-network deployment acceptance"]
async fn public_third_device_enrollment_with_existing_chat() {
    public_third_device_enrollment(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit synthetic public-network deployment acceptance"]
async fn public_third_device_enrollment_from_initial_joiner_with_existing_chat() {
    public_third_device_enrollment(true).await;
}

async fn public_third_device_enrollment(reverse_initial_roles: bool) {
    let relay =
        std::env::var("WN_PUBLIC_ENROLLMENT_RELAY").expect("explicit public chat relay required");
    assert!(matches!(
        relay.as_str(),
        "wss://relay.eu.whitenoise.chat" | "wss://relay.us.whitenoise.chat"
    ));
    four_device_enrollment(HeldPublication::None, Some(&relay), reverse_initial_roles).await;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HeldPublication {
    None,
    SiblingConsent,
    Automatic,
}

async fn public_onboarded_accounts(
    apps: &[MarmotApp; 4],
    runtimes: &[MarmotAppRuntime; 4],
    relay: &str,
) -> (String, String) {
    let request = || crate::AccountSetupRequest {
        identity: None,
        import_nsec: None,
        default_relays: vec![relay.into()],
        bootstrap_relays: vec![relay.into()],
        inbox_relays: vec![relay.into()],
        discovery_relays: vec![relay.into()],
        publish_missing_relay_lists: true,
        publish_initial_key_package: true,
    };
    let source = runtimes[0].create_identity(request()).await.unwrap();
    let keys = apps[0]
        .account_home()
        .load_signing_keys(&source.account.label)
        .unwrap();
    for runtime in &runtimes[1..3] {
        let accounts = runtime.accounts();
        let mut observation = accounts
            .begin_onboarding(
                zeroize::Zeroizing::new(keys.secret_key().to_secret_hex()),
                crate::OnboardingOptions {
                    default_relays: vec![relay.into()],
                    discovery_relays: vec![relay.into()],
                    inbox_relays: vec![relay.into()],
                },
            )
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(90), async {
            while !observation.ready {
                observation = if observation.steps.iter().any(|step| {
                    step.step == crate::OnboardingStep::SingleDevice
                        && step
                            .actions
                            .contains(&crate::OnboardingAction::ContinueAnyway)
                }) {
                    accounts
                        .acknowledge_onboarding_single_device(
                            &observation.account_id_hex,
                            observation.revision,
                        )
                        .await
                        .unwrap()
                } else {
                    accounts
                        .run_onboarding(&observation.account_id_hex)
                        .await
                        .unwrap()
                };
                if !observation.ready {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .expect("supported companion onboarding must become ready");
        assert!(observation.account_id_hex == source.account.account_id_hex);
    }
    let contact = runtimes[3].create_identity(request()).await.unwrap();
    (
        source.account.account_id_hex,
        contact.account.account_id_hex,
    )
}

async fn four_device_enrollment(
    held_publication: HeldPublication,
    public_relay: Option<&str>,
    reverse_initial_roles: bool,
) {
    use cgka_traits::StorageProvider;
    use nostr_relay_builder::prelude::NostrDatabase;
    // Match MockRelay's pinned default storage exactly, retaining an alias for
    // post-failure reads without introducing another observer connection.
    let relay_database =
        std::sync::Arc::new(nostr_relay_builder::prelude::MemoryDatabase::with_opts(
            nostr_relay_builder::prelude::MemoryDatabaseOptions {
                events: true,
                max_events: Some(75_000),
            },
        ));
    let relay = nostr_relay_builder::LocalRelay::new(
        nostr_relay_builder::RelayBuilder::default().database(relay_database.clone()),
    );
    relay.run().await.unwrap();
    let url = public_relay
        .map(str::to_owned)
        .unwrap_or(relay.url().await.to_string());
    let keys = nostr::prelude::Keys::generate();
    let dirs: [tempfile::TempDir; 4] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
    let apps = std::array::from_fn::<_, 4, _>(|index| {
        if public_relay.is_none() {
            AccountHome::open(dirs[index].path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
        }
        if public_relay.is_some() {
            // Use the production constructor: the relay-only test convenience
            // constructor silently selects zero-quiescence convergence.
            MarmotApp::try_with_relays_and_account_home_and_config(
                dirs[index].path(),
                vec![url.clone()],
                AccountHome::open(dirs[index].path()),
                crate::MarmotAppConfig::default()
                    .with_open_ranking_provider(None, Vec::new())
                    .with_pairing_relay_urls(vec![
                        "wss://nos.lol".into(),
                        "wss://relay.primal.net".into(),
                    ]),
            )
            .unwrap()
        } else {
            MarmotApp::with_relay(dirs[index].path(), &url)
        }
    });
    let runtimes = apps.clone().map(MarmotAppRuntime::new);
    for runtime in &runtimes {
        if public_relay.is_some() {
            runtime.start().await.unwrap();
        } else {
            runtime.reconcile_accounts().await.unwrap();
        }
    }
    let (account, contact) = if public_relay.is_some() {
        public_onboarded_accounts(&apps, &runtimes, &url).await
    } else {
        ("test".to_owned(), "test".to_owned())
    };
    let managers = runtimes.each_ref().map(|runtime| runtime.accounts());
    let existing_chat = if public_relay.is_some() {
        let group = managers[0]
            .create_group(&account, "", std::slice::from_ref(&contact), None)
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while !apps[3]
                .group(&contact, &hex::encode(group.as_slice()))
                .unwrap()
                .is_some_and(|row| row.pending_confirmation)
            {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("ordinary peer must receive the invitation");
        managers[3]
            .accept_group_invite(&contact, &group)
            .await
            .unwrap();
        let sent = managers[0]
            .send_message(&account, &group, b"Synthetic pre-pairing message".to_vec())
            .await
            .unwrap();
        assert_eq!(sent.message_ids.len(), 1);
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while !apps[3].messages(&contact).unwrap().iter().any(|message| {
                message.message_id_hex == sent.message_ids[0]
                    && message.plaintext == "Synthetic pre-pairing message"
            }) {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("ordinary peer must receive the pre-pairing message");
        Some((group, hex::decode(&sent.message_ids[0]).unwrap()))
    } else {
        None
    };
    let initial_display = usize::from(!reverse_initial_roles);
    let initial_scanner = 1 - initial_display;
    let display = managers[initial_display]
        .begin_device_linking_session(&account)
        .await
        .unwrap();
    let scanner = managers[initial_scanner]
        .approve_automatic_device_linking_session(
            &account,
            display.automatic_pairing_code().await.unwrap(),
            None,
        )
        .await
        .unwrap();
    scanner.automatic_pairing_code().await.unwrap();
    let (a, b) = if reverse_initial_roles {
        (display, scanner)
    } else {
        (scanner, display)
    };
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
    if let Some((group, event)) = &existing_chat {
        // Match the native host journey: adding the third installation starts
        // only after the first pair has actually exchanged existing chat data.
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let chats = managers[1]
                    .paired_chat_list_page(&account, None, 128)
                    .await
                    .unwrap();
                let messages = managers[1]
                    .paired_chat_message_page(&account, group.clone(), None, 128)
                    .await;
                if chats.chats.iter().any(|chat| &chat.group_id == group)
                    && let Ok(messages) = messages
                    && messages
                        .messages
                        .iter()
                        .any(|message| message.event_id.as_slice() == event.as_slice())
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("existing chat and history must mirror before third-device enrollment");
        eprintln!("automatic-enrollment-control stage=initial-chat-mirrored");
    }
    a.cancel().await.unwrap();
    b.cancel().await.unwrap();
    let targets = managers[0].device_linking_targets(&account).await.unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].device_count, 2);
    let c = managers[2]
        .begin_device_linking_session(&account)
        .await
        .unwrap();
    let a = managers[0]
        .approve_automatic_device_linking_session(
            &account,
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
                .pending_device_linking_approvals(&account)
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
        .pending_device_linking_approvals(&account)
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
    {
        use futures::FutureExt;
        let completion = std::panic::AssertUnwindSafe(wait_for_automatic_phase(
            &a,
            &c,
            DeviceLinkingPhase::EnrollmentComplete,
        ))
        .catch_unwind()
        .await;
        if let Err(failure) = completion {
            eprintln!(
                "third-device-progress source={:?} recipient={:?} sibling_phase={:?}",
                a.enrollment_progress_for_test(),
                c.enrollment_progress_for_test(),
                approval.snapshot().await.map(|snapshot| snapshot.phase)
            );
            for (index, app) in apps[..3].iter().enumerate() {
                let storage = app.account_storage(&account).unwrap();
                let settlement = storage.private_roster_settlement_storage().unwrap();
                let round = settlement.read_round().unwrap();
                let facts = settlement.read_facts().unwrap();
                let invite = storage
                    .private_device_invite_storage()
                    .unwrap()
                    .private_invite()
                    .unwrap();
                eprintln!(
                    "third-device-storage device={index} settlement={:?} leaves={} facts={} invite={:?}",
                    round.as_ref().map(|r| match r.phase {
                        cgka_traits::private_roster_settlement::PrivateSettlementPhase::Pending => "pending",
                        cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed => "completed",
                        cgka_traits::private_roster_settlement::PrivateSettlementPhase::Denied => "denied",
                    }),
                    round
                        .as_ref()
                        .map_or(0, |r| r.anchor.successor.leaves.len()),
                    facts.len(),
                    invite.as_ref().map(|i| i.phase)
                );
            }
            std::panic::resume_unwind(failure);
        }
    }
    eprintln!("automatic-enrollment-control stage=third-device-completed");
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            if apps[..3].iter().all(|app| {
                let storage = app.account_storage(&account).unwrap();
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
        app.account_storage(&account)
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
    let targets = managers[0].device_linking_targets(&account).await.unwrap();
    assert_eq!(targets[0].device_count, 3);
    if public_relay.is_some() {
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
        return;
    }
    let d = managers[3]
        .begin_device_linking_session(&account)
        .await
        .unwrap();
    let a = managers[0]
        .approve_automatic_device_linking_session(
            &account,
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
                    .pending_device_linking_approvals(&account)
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
        // Setup latency is distinct from fairness while publication is held.
        // Start the short progress clock only after the real gate is reached.
        let setup_started = std::time::Instant::now();
        let held = tokio::time::timeout(std::time::Duration::from_secs(90), observed).await;
        let setup_elapsed = setup_started.elapsed();
        if !matches!(held, Ok(Ok(_))) {
            release.notify_one();
            panic!("genuine sibling consent publication did not reach its hold");
        }
        let held_started = std::time::Instant::now();
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if apps[1..3].iter().any(|app| {
                    app.account_storage(&account)
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
        eprintln!(
            "held-consent-control setup-ms={} held-progress-ms={} other-peer-progress={}",
            setup_elapsed.as_millis(),
            held_started.elapsed().as_millis(),
            result.is_ok()
        );
        assert!(
            result.is_ok(),
            "one blocked consent publication must not starve another approved sibling"
        );
    }
    eprintln!("automatic-enrollment-control stage=fourth-device-completion");
    // Inspect only after the original bounded wait fails; keep the same failure
    // and deadline, and never print packet contents or device identities.
    use futures::FutureExt;
    let completion = std::panic::AssertUnwindSafe(wait_for_automatic_phase(
        &a,
        &d,
        DeviceLinkingPhase::EnrollmentComplete,
    ))
    .catch_unwind()
    .await;
    if let Err(failure) = completion {
        let failure_observed_at = std::time::Instant::now();
        if let Some((_, release)) = &held_automatic {
            release.notify_one();
        }
        for (index, app) in apps.iter().enumerate() {
            if let Ok(storage) = app.account_storage(&account)
                && let Some(store) = storage.private_roster_settlement_storage()
                && let Ok(Some(round)) = store.read_round()
                && let Ok(facts) = store.read_facts()
            {
                let phase = match round.phase {
                    cgka_traits::private_roster_settlement::PrivateSettlementPhase::Pending => {
                        "pending"
                    }
                    cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed => {
                        "completed"
                    }
                    cgka_traits::private_roster_settlement::PrivateSettlementPhase::Denied => {
                        "denied"
                    }
                };
                eprintln!(
                    "automatic-enrollment-control device={index} settlement={phase} leaves={} facts={}",
                    round.anchor.successor.leaves.len(),
                    facts.len()
                );
            } else {
                eprintln!("automatic-enrollment-control device={index} settlement=unavailable");
            }
        }
        eprintln!(
            "automatic-enrollment-control sibling-counts source={:?} recipient={:?}",
            a.sibling_recipient_diagnostics_for_test(),
            d.sibling_recipient_diagnostics_for_test()
        );
        eprintln!(
            "automatic-enrollment-control recipient-channel-stage-and-flags={:?} context-rejections={:?} retention-rejections={:?} projections={:?}",
            d.sibling_channel_progress_for_test(),
            d.sibling_context_rejections_for_test(),
            d.sibling_recipient_rejections_for_test(),
            d.sibling_projection_aggregates_for_test()
        );
        // Read only after the unchanged original wait has failed. IDs stay
        // private; a relay database row is not an approval or a peer receipt.
        let pending = d.sibling_publications_for_test().unwrap_or_default();
        let observed = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut retained = Vec::new();
            for id in &pending {
                let id = nostr_relay_builder::prelude::EventId::from_slice(id.as_slice())
                    .map_err(|_| "diagnostic event id unavailable")?;
                let event = relay_database
                    .event_by_id(&id)
                    .await
                    .map_err(|_| "diagnostic relay read unavailable")?;
                retained.push(event.is_some_and(|event| event.verify().is_ok()));
            }
            Ok::<_, &'static str>(retained)
        })
        .await;
        eprintln!(
            "automatic-enrollment-control post-failure-pending-count={} relay-database-retained-valid={observed:?} later-channel-progress={:?}",
            pending.len(),
            d.sibling_channel_progress_for_test()
        );
        if held_publication == HeldPublication::None {
            // Preserve the original failure. Observe only this already-approved
            // original through the existing controller's 90-second phase budget.
            let mut later = None;
            let late_completion = tokio::time::timeout(
                std::time::Duration::from_secs(75).saturating_sub(failure_observed_at.elapsed()),
                async {
                    loop {
                        let left = a.snapshot().await.ok()?;
                        let right = d.snapshot().await.ok()?;
                        let phases = (left.phase, right.phase);
                        let complete = phases
                            == (
                                DeviceLinkingPhase::EnrollmentComplete,
                                DeviceLinkingPhase::EnrollmentComplete,
                            );
                        later = Some(phases);
                        if complete {
                            return Some(());
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                },
            )
            .await;
            eprintln!(
                "automatic-enrollment-control post-failure-original-late-completion={} later-phases={later:?} post-failure-elapsed-ms={}",
                matches!(late_completion, Ok(Some(()))),
                failure_observed_at.elapsed().as_millis()
            );
        }
        std::panic::resume_unwind(failure);
    }
    eprintln!("automatic-enrollment-control stage=fourth-device-completed");
    assert_eq!(d.sibling_channel_progress_for_test().unwrap().len(), 2);
    assert_eq!(d.sibling_publications_for_test().unwrap().len(), 2);
    if let Some((observed, release)) = held_automatic {
        // Pairing has already completed while the background publication is held.
        // Now prove that ordinary automatic work resumes without another action.
        let resumed = tokio::time::timeout(std::time::Duration::from_secs(10), observed).await;
        release.notify_one();
        assert!(
            matches!(resumed, Ok(Ok(_))),
            "automatic sync must resume after enrollment handoff"
        );
    }
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            if apps.iter().all(|app| {
                let storage = app.account_storage(&account).unwrap();
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
}

async fn wait_for_automatic_phase(
    a: &DeviceLinkingSession,
    b: &DeviceLinkingSession,
    phase: DeviceLinkingPhase,
) {
    let mut observed = None;
    // Enrollment includes protected-roster settlement and authenticated sharing
    // with every already-approved device. Match the installed-app acceptance
    // controller's bounded phase budget (one_scan.py::wait_phase), rather than
    // imposing a fifteen-second contract on those real relay round trips.
    // Earlier comparison phases keep their short budget; failures, expiry and
    // cancellation remain immediate failures throughout the wait.
    let budget = if phase == DeviceLinkingPhase::EnrollmentComplete {
        std::time::Duration::from_secs(90)
    } else {
        std::time::Duration::from_secs(15)
    };
    let result = tokio::time::timeout(budget, async {
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
    .await;
    assert!(
        result.is_ok(),
        "automatic pairing did not reach required phase: expected={phase:?} observed={observed:?}"
    );
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

#[tokio::test]
async fn reopened_approved_pair_can_verify_another_installation() {
    reopened_pair_can_verify_another_installation(1).await;
}

#[tokio::test]
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

#[tokio::test]
async fn interrupted_first_enrollment_can_start_fresh_comparison() {
    interrupted_first_enrollment_retries(false).await;
}

#[tokio::test]
async fn interrupted_first_enrollment_same_peer_completes_after_restart() {
    interrupted_first_enrollment_retries(true).await;
}

async fn interrupted_first_enrollment_retries(same_peer: bool) {
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
    let fresh = runtimes[if same_peer { 1 } else { 2 }]
        .accounts()
        .begin_device_linking_session("test")
        .await
        .unwrap();
    let retry = runtimes[0]
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
