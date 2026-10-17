//! Actual self-removal, fresh Welcome/public acceptance and paired rejoin.
//! No source origin, grant, group row or native owner is manufactured here.
use super::*;
use futures::FutureExt;
use std::{panic::AssertUnwindSafe, time::Duration};

#[test]
fn automatic_fresh_accepted_rejoin_restores_only_the_new_source_lineage() {
    crate::tests::run_composed_app_runtime_test("actual-fresh-accepted-rejoin", || async {
        Box::pin(actual::run_native_public_three_device_enrollment(
            actual::ApprovalScenario::AutomaticFreshAcceptedRejoin,
        ))
        .await;
    });
}

#[test]
fn automatic_old_format_terminal_allows_only_fresh_explicit_accepted_rejoin() {
    crate::tests::run_composed_app_runtime_test("actual-old-format-accepted-rejoin", || async {
        Box::pin(actual::run_native_public_three_device_enrollment(
            actual::ApprovalScenario::AutomaticLegacyFormatAcceptedRejoin,
        ))
        .await;
    });
}

enum ActualWelcomeDecision {
    Pending(Box<crate::AppGroupRecord>),
    Recovery(crate::GroupRejoinInvitation),
}

pub(super) async fn verify_fresh_rejoin(
    peer: &super::automatic_forwarding_non_admin_acceptance::IncomingPeer,
    roots: [&std::path::Path; 2],
    url: &str,
    prior_provenance: &(String, String),
) {
    // The existing withdrawal/reopen control has positively closed these exact
    // two roots. Reopen them; no live DB, MLS state or credentials are copied.
    let _source_trace = crate::AppClient::test_capture_account_chat_progress(roots[0], "source");
    let _recipient_trace =
        crate::AppClient::test_capture_account_chat_progress(roots[1], "recipient");
    let source_app = MarmotApp::with_relay(roots[0], url);
    let recipient_app = MarmotApp::with_relay(roots[1], url);
    let source = MarmotAppRuntime::new(source_app.clone());
    let recipient = MarmotAppRuntime::new(recipient_app.clone());
    let mut source_events = source.subscribe();
    let mut recipient_events = recipient.subscribe();
    let result = AssertUnwindSafe(async {
        source.reconcile_accounts().await.unwrap();
        recipient.reconcile_accounts().await.unwrap();
        let group_hex = hex::encode(peer.group.as_slice());
        // Comparison only: captured from the actual accepted Welcome before
        // departure. A terminal projection need not retain this display data.
        let (old_welcome, actual_creator) = prior_provenance.clone();
        let account = source_app.account_home().account("test").unwrap();
        assert_no_mirror(&recipient, &peer.group).await;

        // D is the original actual Current administrator. A publishes its real
        // current package; D's ordinary public invitation performs Core checks.
        source.publish_key_package("test").await.unwrap();
        let invited = peer
            .runtime
            .invite_members("test", &peer.group, &[account.account_id_hex])
            .await
            .unwrap();
        assert!(invited.published > 0);
        let decision = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let recovery = source
                    .group_recovery_status("test", &peer.group)
                    .await
                    .unwrap();
                if let Some(offer) = recovery.rejoin_invitations.into_iter().find(|offer| {
                    offer.welcome_id_hex != old_welcome
                        && offer.welcomer_account_id_hex == actual_creator
                }) {
                    break ActualWelcomeDecision::Recovery(offer);
                }
                if let Some(row) = source_app.group("test", &group_hex).unwrap()
                    && row.pending_confirmation
                    && row
                        .via_welcome_message_id_hex
                        .as_ref()
                        .is_some_and(|id| id != &old_welcome)
                    && row.welcomer_account_id_hex.as_ref() == Some(&actual_creator)
                {
                    break ActualWelcomeDecision::Pending(Box::new(row));
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("actual new creator Welcome must reach A before any approval");

        // Receipt of a new real Welcome is not the user's source acceptance.
        // Poll actual public observations while the pending decision is held.
        for _ in 0..20 {
            assert_no_mirror(&recipient, &peer.group).await;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let accepted_welcome = match decision {
            ActualWelcomeDecision::Pending(row) => {
                let welcome = row.via_welcome_message_id_hex.unwrap();
                let accepted = source
                    .accept_group_invite("test", &peer.group)
                    .await
                    .unwrap();
                assert!(!accepted.pending_confirmation);
                assert!(accepted.via_welcome_message_id_hex.as_ref() == Some(&welcome));
                welcome
            }
            ActualWelcomeDecision::Recovery(offer) => {
                let id = cgka_traits::MessageId::new(hex::decode(&offer.welcome_id_hex).unwrap());
                let token = hex::decode(&offer.local_state_token).unwrap();
                source
                    .confirm_group_rejoin("test", &id, &token)
                    .await
                    .unwrap();
                offer.welcome_id_hex
            }
        };
        assert!(accepted_welcome != old_welcome);
        let accepted = source_app.group("test", &group_hex).unwrap().unwrap();
        assert!(!accepted.pending_confirmation);
        assert!(accepted.self_membership == crate::SelfMembership::Member);
        assert!(accepted.via_welcome_message_id_hex.as_ref() == Some(&accepted_welcome));

        let witness = peer
            .runtime
            .send_message(
                "test",
                &peer.group,
                b"actual fresh accepted rejoin witness".to_vec(),
            )
            .await
            .unwrap();
        assert!(witness.published == 1 && witness.message_ids.len() == 1);
        let event = &witness.message_ids[0];
        tokio::time::timeout(Duration::from_secs(30), async {
            while source_app
                .account_storage("test")
                .unwrap()
                .app_storage().app_message(&group_hex, event)
                .unwrap()
                .is_none()
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("A must actually decrypt D's new canonical ordinary witness");
        wait_for_mirrored_event(&recipient, &peer.group, event).await;
    })
    .catch_unwind()
    .await;
    if result.is_err() {
        let available = std::panic::catch_unwind(AssertUnwindSafe(|| {
            diagnose_rejoin(&source_app, &recipient_app, &peer.group)
        }))
        .is_ok();
        eprintln!("rejoin diagnostic observations_available={available}");
        for (label, events) in [
            ("source", &mut source_events),
            ("recipient", &mut recipient_events),
        ] {
            let mut errors = 0;
            let mut invalid_payloads = 0;
            let mut maintenance_payloads = 0;
            let mut convergence_payloads = 0;
            let mut storage_failures = 0;
            let mut other_categories = 0;
            for _ in 0..512 {
                let event = match events.try_recv() {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
                    Err(_) => break,
                };
                if let crate::MarmotAppEvent::AccountError(error) = event {
                    errors += 1;
                    match error.message.as_str() {
                        "runtime receive failed: invalid_app_message_payload" => {}
                        "scheduled maintenance failed: invalid_app_message_payload" => {
                            maintenance_payloads += 1
                        }
                        "scheduled convergence failed: invalid_app_message_payload"
                        | "scheduled convergence sync failed: invalid_app_message_payload" => {
                            convergence_payloads += 1
                        }
                        "scheduled maintenance failed: storage"
                        | "scheduled maintenance failed: storage_backend"
                        | "runtime receive failed: storage"
                        | "runtime receive failed: storage_backend" => storage_failures += 1,
                        _ => other_categories += 1,
                    }
                    invalid_payloads += usize::from(
                        error.message == "runtime receive failed: invalid_app_message_payload",
                    );
                }
            }
            eprintln!(
                "rejoin diagnostic {label}: account_errors={errors}, invalid_payload_errors={invalid_payloads}, maintenance_payload_errors={maintenance_payloads}, convergence_payload_errors={convergence_payloads}, storage_errors={storage_failures}, other_fixed_categories={other_categories}"
            );
        }
    }
    source.shutdown_and_close().await.unwrap();
    recipient.shutdown_and_close().await.unwrap();
    assert!(source.storage_is_closed() && recipient.storage_is_closed());
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }

    // The new accepted observation and old negative lineage must survive actual
    // encrypted reopening, rather than relying on the previous in-memory actor.
    let reopened_source = MarmotAppRuntime::new(MarmotApp::with_relay(roots[0], url));
    let reopened_recipient = MarmotAppRuntime::new(MarmotApp::with_relay(roots[1], url));
    let result = AssertUnwindSafe(async {
        reopened_source.reconcile_accounts().await.unwrap();
        reopened_recipient.reconcile_accounts().await.unwrap();
        let witness = peer
            .runtime
            .send_message(
                "test",
                &peer.group,
                b"actual encrypted-reopen rejoin witness".to_vec(),
            )
            .await
            .unwrap();
        assert!(witness.published == 1 && witness.message_ids.len() == 1);
        wait_for_mirrored_event(&reopened_recipient, &peer.group, &witness.message_ids[0]).await;
    })
    .catch_unwind()
    .await;
    reopened_source.shutdown_and_close().await.unwrap();
    reopened_recipient.shutdown_and_close().await.unwrap();
    assert!(reopened_source.storage_is_closed() && reopened_recipient.storage_is_closed());
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

async fn assert_no_mirror(runtime: &MarmotAppRuntime, group: &crate::GroupId) {
    let page = runtime
        .accounts()
        .paired_chat_list_page("test", None, 128)
        .await
        .unwrap();
    assert!(!page.chats.iter().any(|row| &row.group_id == group));
    match runtime
        .accounts()
        .paired_chat_message_page("test", group.clone(), None, 128)
        .await
    {
        Ok(page) => assert!(page.messages.is_empty()),
        Err(crate::AccountChatReadError::NotReady) => {}
        Err(_) => panic!("absence control must not swallow an unexpected public read refusal"),
    }
}

async fn wait_for_mirrored_event(runtime: &MarmotAppRuntime, group: &crate::GroupId, event: &str) {
    let event = hex::decode(event).unwrap();
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let page = runtime
                .accounts()
                .paired_chat_list_page("test", None, 128)
                .await
                .unwrap();
            let present = page.chats.iter().any(|row| &row.group_id == group);
            let page = runtime
                .accounts()
                .paired_chat_message_page("test", group.clone(), None, 128)
                .await;
            match page {
                Ok(page)
                    if present
                        && page
                            .messages
                            .iter()
                            .any(|row| row.event_id.as_slice() == event && !row.deleted) =>
                {
                    break;
                }
                Ok(_) | Err(crate::AccountChatReadError::NotReady) => {}
                Err(_) => panic!("fresh accepted rejoin must not hide another public read error"),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("fresh explicitly accepted source rejoin must restore its canonical paired record");
}

// Failure-only, bounded observation. No IDs, keys, names, content or packet bytes
// are logged, and no observation is used to manufacture authority or a retry.
fn diagnose_rejoin(source: &MarmotApp, recipient: &MarmotApp, group: &crate::GroupId) {
    use cgka_traits::storage::{AccountDeviceSignerStorage, StorageProvider};
    let account = source.account_home().account("test").unwrap();
    let account_id: [u8; 32] = hex::decode(account.account_id_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let storage = source.account_storage("test").unwrap();
    let signer = storage
        .account_device_signer(&cgka_traits::MemberId::new(account_id.to_vec()))
        .unwrap()
        .unwrap();
    let local: [u8; 32] = signer.mls_signature_public_key.try_into().unwrap();
    let accepted_origin = storage
        .current_account_chat_source_origin(&account_id, &local, group)
        .unwrap();
    let accepted = storage
        .current_account_chat_source(&account_id, &local, group)
        .unwrap()
        == Some(storage_sqlite::account_chat_source::AccountChatSourceVerdict::Accepted);
    eprintln!(
        "rejoin diagnostic source: accepted={accepted}, bound_origin={}",
        accepted_origin.is_some()
    );
    let storage = recipient.account_storage("test").unwrap();
    let round = storage
        .private_roster_settlement_storage()
        .unwrap()
        .read_round()
        .unwrap()
        .unwrap();
    let policies = storage
        .approved_account_sharing_policy_storage()
        .unwrap()
        .approved_account_sharing_policies()
        .unwrap();
    for policy in policies.iter().filter(|p| p.peer_device == local).take(1) {
        let mirror = cgka_traits::mirrored_chat_catalog::MirroredChatScope {
            account: policy.account,
            local_device: policy.local_device,
            source_device: policy.peer_device,
            policy_digest:
                cgka_traits::approved_account_sharing_policy::approved_account_sharing_identity(
                    &policy.account,
                    &policy.protected_group,
                    &policy.local_device,
                    &policy.peer_device,
                    &policy.approval_id,
                )
                .unwrap(),
            protected_group: policy.protected_group.clone(),
            protected_generation: round.generation,
        };
        let rows = storage
            .mirrored_chat_catalog_storage()
            .unwrap()
            .mirrored_chat_catalog_page(&mirror, None, 128)
            .unwrap();
        let row = rows.iter().find(|row| &row.group_id == group);
        let state = row
            .map(|row| match row.state {
                cgka_traits::mirrored_chat_catalog::MirroredChatState::Active => "Active",
                cgka_traits::mirrored_chat_catalog::MirroredChatState::Left => "Left",
                cgka_traits::mirrored_chat_catalog::MirroredChatState::Deleted => "Deleted",
            })
            .unwrap_or("Absent");
        let origin_matches = row.is_some_and(|row| row.accepted_origin == accepted_origin);
        let messages = storage
            .mirrored_chat_message_storage()
            .unwrap()
            .mirrored_chat_message_page(&mirror, group, None, 128, crate::unix_now_seconds());
        eprintln!(
            "rejoin diagnostic recipient: catalog_state={state}, origin_matches={origin_matches}, record_page_ready={}, record_count={}",
            messages.is_ok(),
            messages.map(|rows| rows.len()).unwrap_or(0)
        );
    }
}
