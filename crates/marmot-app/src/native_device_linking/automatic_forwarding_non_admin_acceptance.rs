//! A real incoming ordinary chat; the paired bridge has no administrator grant.
use super::*;
use marmot_account::AccountHome;

#[tokio::test]
async fn automatic_forwarding_reaches_independent_creator_through_non_admin_member() {
    actual::run_native_public_three_device_enrollment(
        actual::ApprovalScenario::AutomaticForwardingNonAdmin,
    )
    .await;
}

#[tokio::test]
async fn automatic_nonadmin_leave_withdraws_mirrors_without_turning_local_hide_into_departure() {
    actual::run_native_public_three_device_enrollment(
        actual::ApprovalScenario::AutomaticWithdrawal,
    )
    .await;
}

pub(super) struct IncomingPeer {
    _root: tempfile::TempDir,
    app: MarmotApp,
    pub(super) runtime: MarmotAppRuntime,
    pub(super) group: crate::GroupId,
    pub(super) preapproval_message: String,
}

impl IncomingPeer {
    pub(super) async fn create(
        url: &str,
        source_app: &MarmotApp,
        source: &MarmotAppRuntime,
        source_account: &str,
    ) -> Self {
        let root = tempfile::tempdir().unwrap();
        let keys = nostr::prelude::Keys::generate();
        let account = AccountHome::open(root.path())
            .import_account("test", &keys.secret_key().to_secret_hex())
            .unwrap();
        assert_ne!(account.account_id_hex, source_account);
        let app = MarmotApp::with_relay(root.path(), url);
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.reconcile_accounts().await.unwrap();
        crate::tests::remember_test_member_inbox(&app, source_account, url);
        source.publish_key_package("test").await.unwrap();
        let group = runtime
            .create_group(
                "test",
                "Incoming independent creator chat",
                &[source_account.to_owned()],
                Some("x".repeat(4096)),
            )
            .await
            .unwrap();
        let group_hex = hex::encode(group.as_slice());
        let pending = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if let Some(row) = source_app.group("test", &group_hex).unwrap() {
                    break row;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("real Welcome must reach the actual invited member");
        assert!(pending.pending_confirmation);
        let accepted = source.accept_group_invite("test", &group).await.unwrap();
        assert!(!accepted.pending_confirmation);
        assert!(
            !accepted
                .admin_policy
                .admins
                .iter()
                .any(|id| id == source_account)
        );
        assert!(
            accepted
                .admin_policy
                .admins
                .contains(&account.account_id_hex)
        );
        let members = source
            .accounts()
            .group_roster("test", &group)
            .await
            .unwrap();
        let members = members.members;
        assert_eq!(members.len(), 2);
        assert!(
            members
                .iter()
                .any(|m| m.member_id_hex == source_account && !m.is_admin)
        );
        assert!(
            members
                .iter()
                .any(|m| m.member_id_hex == account.account_id_hex && m.is_admin)
        );
        let history = runtime
            .send_message(
                "test",
                &group,
                b"independent creator before sharing".to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(history.published, 1);
        assert_eq!(history.message_ids.len(), 1);
        let preapproval_message = history.message_ids[0].clone();
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if source_app
                    .account_storage("test")
                    .unwrap()
                    .app_message(&group_hex, &preapproval_message)
                    .unwrap()
                    .is_some()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("independent creator's ordinary message must be genuinely received");
        Self {
            _root: root,
            app,
            runtime,
            group,
            preapproval_message,
        }
    }

    pub(super) async fn verify_forwarded_receipt(&self, origin: &MarmotAppRuntime) {
        let Some(crate::LocalSendStatus::Completed(summary)) = origin
            .local_send_status(
                "test",
                &self.group,
                "paired-source-forwarding-original-token",
            )
            .unwrap()
        else {
            panic!("origin must observe actual published receipt");
        };
        assert_eq!(summary.published, 1);
        assert_eq!(summary.message_ids.len(), 1);
        let group_hex = hex::encode(self.group.as_slice());
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if let Some(row) = self
                    .app
                    .account_storage("test")
                    .unwrap()
                    .app_message(&group_hex, &summary.message_ids[0])
                    .unwrap()
                {
                    assert_eq!(row.plaintext, "message from the paired mirror");
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("independent creator must receive the same canonical forwarded event");
    }
}

impl IncomingPeer {
    pub(super) async fn verify_withdrawal(
        &self,
        apps: &[MarmotApp; 3],
        runtimes: &[MarmotAppRuntime; 3],
        scope: &cgka_traits::mirrored_chat_catalog::MirroredChatScope,
    ) {
        use cgka_traits::{GroupStorage, StorageProvider};
        eprintln!("withdrawal-control stage=withdrawal-entered");
        let group_hex = hex::encode(self.group.as_slice());
        let mut window = runtimes[2]
            .open_account_chat_list_window("test", 128)
            .await
            .unwrap();
        assert!(window.snapshot.rows.iter().any(|row| matches!(row,
            crate::AccountChatRow::PairedSource(row) if row.group_id == self.group)));
        // Local hide is projection-only. Do not replace it with an account-wide tombstone.
        assert!(
            runtimes[0]
                .delete_group_local("test", &self.group)
                .await
                .unwrap()
        );
        assert!(apps[0].group("test", &group_hex).unwrap().is_none());
        assert!(
            !apps[0]
                .account_storage("test")
                .unwrap()
                .get_group(&self.group)
                .unwrap()
                .is_terminal()
        );
        let rows = apps[2]
            .account_storage("test")
            .unwrap()
            .mirrored_chat_catalog_storage()
            .unwrap()
            .mirrored_chat_catalog_page(scope, None, 128)
            .unwrap();
        assert!(rows.iter().any(|row| row.group_id == self.group
            && row.state == cgka_traits::mirrored_chat_catalog::MirroredChatState::Active));
        let fresh = self
            .runtime
            .send_message("test", &self.group, b"fresh after local-only hide".to_vec())
            .await
            .unwrap();
        assert!(fresh.published == 1 && fresh.message_ids.len() == 1);
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while apps[0]
                .account_storage("test")
                .unwrap()
                .app_message(&group_hex, &fresh.message_ids[0])
                .unwrap()
                .is_none()
            {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("actual fresh ordinary traffic must restore the local hidden projection");
        assert!(apps[0].group("test", &group_hex).unwrap().is_some());
        eprintln!("withdrawal-control stage=before-real-leave");
        let leave = runtimes[0].leave_group("test", &self.group).await.unwrap();
        eprintln!("withdrawal-control stage=real-leave-returned");
        assert!(leave.published == 1);
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let storage = apps[0].account_storage("test").unwrap();
                let removed = storage.get_group(&self.group).unwrap().removed;
                let peer = self
                    .app
                    .account_storage("test")
                    .unwrap()
                    .get_group(&self.group)
                    .unwrap();
                if removed && peer.members.len() == 1 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("real non-admin leave must become canonical at source and independent creator");
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let receiver = apps[2].account_storage("test").unwrap();
                let rows = receiver
                    .mirrored_chat_catalog_storage()
                    .unwrap()
                    .mirrored_chat_catalog_page(scope, None, 128)
                    .unwrap();
                if let Some(row) = rows.iter().find(|row| row.group_id == self.group)
                    && row.state == cgka_traits::mirrored_chat_catalog::MirroredChatState::Left
                {
                    assert!(row.name.is_empty() && row.description.is_empty());
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("actual approved source must deliver and commit an empty leave withdrawal");
        eprintln!("withdrawal-control stage=withdrawal-committed");
        tokio::time::timeout(std::time::Duration::from_secs(8), async {
            loop {
                let value = window
                    .recv()
                    .await
                    .unwrap()
                    .expect("original list owner remains live");
                if !value.rows.iter().any(|row| {
                    matches!(row,
                    crate::AccountChatRow::PairedSource(row) if row.group_id == self.group)
                }) {
                    break;
                }
            }
        })
        .await
        .expect("committed withdrawal must wake the held public list and remove the paired row");
        window.window_handle().cancel();
    }

    pub(super) async fn verify_withdrawal_reopen(
        &self,
        runtimes: &[MarmotAppRuntime; 3],
        roots: [&std::path::Path; 2],
        url: &str,
        still_active: &crate::GroupId,
    ) {
        eprintln!("withdrawal-control stage=encrypted-reopen-entered");
        runtimes[0].shutdown_and_close().await.unwrap();
        runtimes[2].shutdown_and_close().await.unwrap();
        eprintln!("withdrawal-control stage=old-runtimes-closed");
        assert!(runtimes[0].storage_is_closed() && runtimes[2].storage_is_closed());
        let source = MarmotAppRuntime::new(MarmotApp::with_relay(roots[0], url));
        let recipient = MarmotAppRuntime::new(MarmotApp::with_relay(roots[1], url));
        source.reconcile_accounts().await.unwrap();
        recipient.reconcile_accounts().await.unwrap();
        eprintln!("withdrawal-control stage=reopened-runtimes-reconciled");
        let fresh = source
            .send_message(
                "test",
                still_active,
                b"fresh renewal after genuine leave".to_vec(),
            )
            .await
            .unwrap();
        assert!(fresh.published == 1 && fresh.message_ids.len() == 1);
        let expected = &fresh.message_ids[0];
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                let window = recipient.open_account_conversation_window("test", still_active, 128).await.unwrap();
                let present = window.snapshot.rows.iter().any(|row| matches!(row,
                    crate::AccountConversationRow::PairedSource(row) if hex::encode(row.event_id) == *expected));
                window.window_handle().cancel();
                if present { break; }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }).await.expect("fresh approved-policy channel must deliver an unrelated ordinary message after encrypted reopen");
        let window = recipient
            .open_account_chat_list_window("test", 128)
            .await
            .unwrap();
        assert!(
            !window.snapshot.rows.iter().any(|row| matches!(row,
            crate::AccountChatRow::PairedSource(row) if row.group_id == self.group)),
            "retained old active catalog must not resurrect the left source route after renewal"
        );
        window.window_handle().cancel();
        eprintln!("withdrawal-control stage=before-reopened-close");
        source.shutdown_and_close().await.unwrap();
        recipient.shutdown_and_close().await.unwrap();
        eprintln!("withdrawal-control stage=reopened-runtimes-closed");
        assert!(source.storage_is_closed() && recipient.storage_is_closed());
    }
}
