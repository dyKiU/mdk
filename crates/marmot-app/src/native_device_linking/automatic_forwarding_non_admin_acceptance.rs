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
