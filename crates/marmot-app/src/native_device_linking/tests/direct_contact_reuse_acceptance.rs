//! Genuine one-scan direct-contact routing, not synthetic catalog seeding.
use super::*;
use crate::{AccountSetupRequest, AppCreateGroupOptions, ExistingAccountDirectConversation};
use cgka_traits::{StorageError, TransportEndpoint, storage::GroupStorage};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_scan_direct_contact_reuses_source_chat_without_another_peer_invitation() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    for displaying_device in [0, 1] {
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
        let peer_dir = tempfile::tempdir().unwrap();
        let peer_app = MarmotApp::with_relay(peer_dir.path(), &url);
        let peer_runtime = MarmotAppRuntime::new(peer_app.clone());
        let endpoint = TransportEndpoint(url.clone());
        let peer_account = peer_runtime
            .create_identity(AccountSetupRequest {
                default_relays: vec![endpoint.clone()],
                bootstrap_relays: vec![endpoint],
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..Default::default()
            })
            .await
            .unwrap()
            .account;
        let managers = runtimes.each_ref().map(|runtime| runtime.accounts());
        let created = managers[0]
            .create_group_with_options_detailed(
                "test",
                "",
                std::slice::from_ref(&peer_account.account_id_hex),
                AppCreateGroupOptions::default(),
            )
            .await
            .unwrap();
        let group = created.group_id;
        let group_hex = hex::encode(group.as_slice());
        assert_eq!(
            created.chat_list_row.conversation_kind,
            crate::ChatConversationKind::Direct
        );
        let peer_name = "Named shared contact";
        apps[0]
            .directory()
            .remember_directory_profile(
                &peer_account.account_id_hex,
                &crate::UserProfileMetadata {
                    display_name: Some(peer_name.to_owned()),
                    ..Default::default()
                },
            )
            .unwrap();
        let source_row = runtimes[0]
            .presented_chat_list_row("test", &group_hex)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            source_row.presentation.title,
            storage_sqlite::PresentationText::Literal(name) if name == peer_name
        ));
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if peer_app
                    .load_state(&peer_account.label)
                    .unwrap()
                    .groups
                    .iter()
                    .any(|g| g.group_id_hex == group_hex)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("ordinary peer must receive the original invitation");
        peer_runtime
            .accounts()
            .accept_group_invite(&peer_account.label, &group)
            .await
            .unwrap();
        let peer_groups = peer_app
            .load_state(&peer_account.label)
            .unwrap()
            .groups
            .iter()
            .map(|g| g.group_id_hex.clone())
            .collect::<Vec<_>>();
        assert_eq!(peer_groups, vec![group_hex.clone()]);
        assert!(
            matches!(runtimes[0].existing_account_direct_conversation("test", &peer_account.account_id_hex).await.unwrap(),
            Some(ExistingAccountDirectConversation::LocalMls(row)) if row.group_id_hex == group_hex && row.reusable)
        );
        assert!(
            runtimes[1]
                .existing_account_direct_conversation("test", &peer_account.account_id_hex)
                .await
                .unwrap()
                .is_none()
        );
        let displayed = managers[displaying_device]
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let scanner = managers[1 - displaying_device]
            .approve_automatic_device_linking_session(
                "test",
                displayed.automatic_pairing_code().await.unwrap(),
                None,
            )
            .await
            .unwrap();
        scanner.automatic_pairing_code().await.unwrap();
        compare_and_confirm_pair(&displayed, &scanner).await;
        displayed
            .continue_automatic_linking(displayed.snapshot().await.unwrap().revision, true)
            .await
            .unwrap();
        scanner
            .continue_automatic_linking(scanner.snapshot().await.unwrap().revision, true)
            .await
            .unwrap();
        wait_for_automatic_phase(&displayed, &scanner, DeviceLinkingPhase::EnrollmentComplete)
            .await;
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let found = runtimes[1]
                    .existing_account_direct_conversation("test", &peer_account.account_id_hex)
                    .await
                    .unwrap();
                if let Some(ExistingAccountDirectConversation::PairedSource(row)) = found {
                    assert!(row.group_id == group);
                    assert_eq!(
                        row.direct_peer_account.map(hex::encode),
                        Some(peer_account.account_id_hex.clone())
                    );
                    assert_eq!(
                        row.name, peer_name,
                        "a linked device without the contact profile must receive the source's readable direct-chat title"
                    );
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("paired contact must resolve to the existing canonical direct chat");
        for _ in 0..3 {
            assert!(
                matches!(runtimes[1].existing_account_direct_conversation("test", &peer_account.account_id_hex).await.unwrap(),
                Some(ExistingAccountDirectConversation::PairedSource(row)) if row.group_id == group)
            );
        }
        let updated_peer_name = "Updated shared contact";
        let previous_profile_time = apps[0]
            .directory()
            .directory_entry_for_account_id(&peer_account.account_id_hex)
            .unwrap()
            .and_then(|entry| entry.profile)
            .map(|profile| profile.created_at)
            .unwrap_or(0);
        apps[0]
            .directory()
            .remember_directory_profile(
                &peer_account.account_id_hex,
                &crate::UserProfileMetadata {
                    display_name: Some(updated_peer_name.to_owned()),
                    created_at: previous_profile_time.checked_add(1).unwrap(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            apps[0]
                .directory()
                .directory_entry_for_account_id(&peer_account.account_id_hex)
                .unwrap()
                .unwrap()
                .profile
                .unwrap()
                .display_name
                .as_deref(),
            Some(updated_peer_name)
        );
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let source = runtimes[0]
                    .presented_chat_list_row("test", &group_hex)
                    .await
                    .unwrap()
                    .unwrap();
                if matches!(source.presentation.title,
                    storage_sqlite::PresentationText::Literal(name) if name == updated_peer_name)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the source's asynchronous native profile presentation must update first");
        let updated_in_time = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if matches!(
                    runtimes[1]
                        .existing_account_direct_conversation("test", &peer_account.account_id_hex)
                        .await
                        .unwrap(),
                    Some(ExistingAccountDirectConversation::PairedSource(row))
                        if row.group_id == group && row.name == updated_peer_name
                ) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await;
        let Some(ExistingAccountDirectConversation::PairedSource(updated)) = runtimes[1]
            .existing_account_direct_conversation("test", &peer_account.account_id_hex)
            .await
            .unwrap()
        else {
            panic!("the original paired chat must still exist after its source profile changes");
        };
        assert_eq!(updated.group_id, group);
        assert_eq!(
            updated.name, updated_peer_name,
            "existing chat name must refresh without pairing again"
        );
        assert!(
            updated_in_time.is_ok(),
            "the existing chat name arrived after its update deadline"
        );
        assert!(matches!(
            apps[1].account_storage("test").unwrap().get_group(&group),
            Err(StorageError::NotFound)
        ));
        let after = peer_app
            .load_state(&peer_account.label)
            .unwrap()
            .groups
            .iter()
            .map(|g| g.group_id_hex.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            after, peer_groups,
            "lookups must not create another invitation or conversation"
        );
        for session in [displayed, scanner] {
            assert!(matches!(
                session.cancel().await,
                Ok(()) | Err(DeviceLinkingError::Closed)
            ));
        }
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
        peer_runtime.shutdown_and_close().await.unwrap();
    }
}
