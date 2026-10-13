//! Actual independently stored ordinary Welcome/accept/hide/reopen controls.
//! These do not replace the paired disclosure regression or native SDK gate.
use crate::{MarmotApp, MarmotAppRuntime};
use std::time::Duration;

#[test]
fn actual_pending_invites_need_acceptance_and_hidden_decisions_survive_deferred_reopen() {
    crate::tests::run_composed_app_runtime_test("chat-source-pending-reopen", || async {
        let relay =
            nostr_relay_builder::LocalRelay::new(nostr_relay_builder::RelayBuilder::default());
        relay.run().await.unwrap();
        let url = relay.url().await.to_string();
        let roots: [tempfile::TempDir; 2] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
        let apps: [MarmotApp; 2] =
            std::array::from_fn(|i| MarmotApp::with_relay(roots[i].path(), &url));
        let a = apps[0].account_home().create_account("test").unwrap();
        let d = apps[1].account_home().create_account("test").unwrap();
        assert!(a.account_id_hex != d.account_id_hex);
        let runtimes = apps.clone().map(MarmotAppRuntime::new);
        for runtime in &runtimes {
            runtime.reconcile_accounts().await.unwrap();
        }
        crate::tests::remember_test_member_inbox(&apps[1], &a.account_id_hex, &url);
        let mut groups = Vec::new();
        for _ in 0..3 {
            runtimes[0].publish_key_package("test").await.unwrap();
            let group = runtimes[1]
                .create_group(
                    "test",
                    "incoming source acceptance",
                    std::slice::from_ref(&a.account_id_hex),
                    None,
                )
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    if apps[0]
                        .group("test", &hex::encode(group.as_slice()))
                        .unwrap()
                        .is_some_and(|row| row.pending_confirmation)
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("actual pending Welcome projection");
            groups.push(group);
        }
        for runtime in &runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
        assert!(apps.iter().all(MarmotApp::storage_is_closed));
        let app = MarmotApp::with_relay(roots[0].path(), &url);
        let mut client = app
            .local_client_with_relay_plane_and_hydration("test", &app.relay_plane, None, true, None)
            .await
            .unwrap();
        assert!(
            client
                .runtime
                .session()
                .unhydrated_group_ids()
                .contains(&groups[0]),
            "acceptance must exercise the real deferred-open group, not an already hydrated fixture"
        );
        for group in &groups {
            assert!(!client.automatic_chat_source_accepted(group).unwrap());
        }
        client.accept_group_invite(&groups[0]).unwrap();
        assert!(client.automatic_chat_source_accepted(&groups[0]).unwrap());
        // Acceptance above must work before transport activation. Later hide
        // and decline actions use the actual relay and need its registration.
        client.prepare_transport().await.unwrap();
        client.delete_group_local(&groups[0]).await.unwrap();
        client.delete_group_local(&groups[1]).await.unwrap();
        assert!(client.automatic_chat_source_accepted(&groups[0]).unwrap());
        assert!(!client.automatic_chat_source_accepted(&groups[1]).unwrap());
        client.decline_group_invite(&groups[2]).await.unwrap();
        assert!(!client.automatic_chat_source_accepted(&groups[2]).unwrap());
        drop(client);
        app.close_storage().unwrap();
        assert!(app.storage_is_closed());
        let reopened = MarmotApp::with_relay(roots[0].path(), &url);
        let client = reopened.client("test").await.unwrap();
        assert!(client.automatic_chat_source_accepted(&groups[0]).unwrap());
        assert!(!client.automatic_chat_source_accepted(&groups[1]).unwrap());
        assert!(!client.automatic_chat_source_accepted(&groups[2]).unwrap());
        drop(client);
        reopened.close_storage().unwrap();
        assert!(reopened.storage_is_closed());
    });
}

#[test]
fn actual_created_source_acceptance_survives_local_hide_and_encrypted_reopen() {
    crate::tests::run_composed_app_runtime_test("chat-source-created-reopen", || async {
        let root = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relay(root.path(), "wss://relay.example").with_test_relay_client(
            std::sync::Arc::new(crate::tests::ScriptedPushRelayClient::default()),
        );
        app.account_home().create_account("test").unwrap();
        let mut client = app.client("test").await.unwrap();
        let group = client
            .create_group("actual created lineage", &[])
            .await
            .unwrap();
        assert!(client.automatic_chat_source_accepted(&group).unwrap());
        client.delete_group_local(&group).await.unwrap();
        drop(client);
        app.close_storage().unwrap();
        assert!(app.storage_is_closed());
        let reopened = MarmotApp::with_relay(root.path(), "wss://relay.example")
            .with_test_relay_client(std::sync::Arc::new(
                crate::tests::ScriptedPushRelayClient::default(),
            ));
        let client = reopened.client("test").await.unwrap();
        assert!(client.automatic_chat_source_accepted(&group).unwrap());
        drop(client);
        reopened.close_storage().unwrap();
        assert!(reopened.storage_is_closed());
    });
}
