use super::*;
use crate::{MarmotApp, MarmotAppRuntime};

#[cfg(not(feature = "experimental-device-sync"))]
#[tokio::test]
async fn default_native_verification_is_unsupported_before_account_or_worker_effects() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), "wss://relay.example"));
    let accounts = runtime.accounts();
    assert_eq!(
        accounts.device_linking_capabilities(),
        DeviceLinkingCapabilities {
            verification_supported: false,
            enrollment_supported: false
        }
    );
    assert!(matches!(
        accounts.begin_device_linking_session("missing").await,
        Err(DeviceLinkingError::Unsupported)
    ));
    assert!(matches!(
        accounts
            .approve_device_linking_session("missing", vec![0; 600_000], None)
            .await,
        Err(DeviceLinkingError::Unsupported)
    ));
    assert!(matches!(
        accounts
            .begin_account_chat_sharing("missing", vec![0; 32])
            .await,
        Err(crate::AccountSharingError::Unsupported)
    ));
    assert!(matches!(
        accounts.pending_account_chat_sharing("missing").await,
        Err(crate::AccountSharingError::Unsupported)
    ));
    assert!(matches!(
        accounts.account_chat_sharing_targets("missing").await,
        Err(crate::AccountSharingError::Unsupported)
    ));
    assert!(accounts.managed_accounts().unwrap().is_empty());
    runtime.shutdown_and_close().await.unwrap();
}

#[cfg(not(feature = "experimental-device-sync"))]
#[tokio::test]
async fn default_native_enrollment_is_unsupported_without_account_or_worker_effects() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), "wss://relay.example"));
    let accounts = runtime.accounts();
    assert!(matches!(
        accounts.device_linking_targets("missing").await,
        Err(DeviceLinkingError::Unsupported)
    ));
    assert!(matches!(
        accounts.pending_device_linking_approvals("missing").await,
        Err(DeviceLinkingError::Unsupported)
    ));
    let session = DeviceLinkingSession { _private: () };
    assert!(matches!(
        session.enrollment_packet(0).await,
        Err(DeviceLinkingError::Unsupported)
    ));
    assert!(matches!(
        session.receive_enrollment_packet(0, vec![0; 16_385]).await,
        Err(DeviceLinkingError::Unsupported)
    ));
    assert!(matches!(
        session.finalize_linking(0).await,
        Err(DeviceLinkingError::Unsupported)
    ));
    assert!(matches!(
        session.continue_linking_and_share_chats(0).await,
        Err(DeviceLinkingError::Unsupported)
    ));
    let approval = DeviceLinkingApproval { _private: () };
    assert!(matches!(
        approval.review_metadata(0).await,
        Err(DeviceLinkingError::Unsupported)
    ));
    assert!(matches!(
        approval.snapshot().await,
        Err(DeviceLinkingError::Unsupported)
    ));
    assert!(matches!(
        approval.approve(0).await,
        Err(DeviceLinkingError::Unsupported)
    ));
    assert!(matches!(
        approval.receive_enrollment_packet(0, vec![0; 16_385]).await,
        Err(DeviceLinkingError::Unsupported)
    ));
    assert!(matches!(
        approval.cancel().await,
        Err(DeviceLinkingError::Unsupported)
    ));
    assert!(accounts.managed_accounts().unwrap().is_empty());
    runtime.shutdown_and_close().await.unwrap();
}

#[cfg(all(
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
pub(super) mod actual {
    use super::*;
    use marmot_account::AccountHome;
    use std::sync::Arc;

    async fn workers() -> ([tempfile::TempDir; 2], [MarmotAppRuntime; 2]) {
        let keys = nostr::prelude::Keys::generate();
        let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        let runtimes = std::array::from_fn(|i| {
            AccountHome::open(dirs[i].path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
            MarmotAppRuntime::new(
                MarmotApp::with_relay(dirs[i].path(), "wss://relay.example")
                    .with_test_relay_client(Arc::new(
                        crate::tests::ScriptedPushRelayClient::default(),
                    )),
            )
        });
        for runtime in &runtimes {
            runtime.reconcile_accounts().await.unwrap();
        }
        (dirs, runtimes)
    }
    async fn drain(from: &DeviceLinkingSession, to: &DeviceLinkingSession) {
        for packet in from.outgoing_packets().await.unwrap() {
            to.receive_packet(packet.bytes).await.unwrap();
            from.acknowledge_packet(packet.acknowledgement_id)
                .await
                .unwrap();
        }
    }

    async fn verify_public_pair(a: &DeviceLinkingSession, c: &DeviceLinkingSession) {
        c.receive_setup_packet(a.setup_packet()).await.unwrap();
        for _ in 0..8 {
            drain(a, c).await;
            drain(c, a).await;
        }
        let ac = a.snapshot().await.unwrap();
        let cc = c.snapshot().await.unwrap();
        assert_eq!(ac.phase, DeviceLinkingPhase::ComparisonAvailable);
        assert_eq!(ac.decimals, cc.decimals);
        a.confirm_comparison(ac.revision).await.unwrap();
        c.confirm_comparison(cc.revision).await.unwrap();
        for _ in 0..8 {
            drain(a, c).await;
            drain(c, a).await;
        }
        assert_eq!(
            a.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending
        );
        assert_eq!(
            c.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending
        );
    }
    async fn wait_actual_roster(apps: &[MarmotApp], leaves: usize) {
        use cgka_traits::StorageProvider;
        use cgka_traits::private_roster_settlement::PrivateSettlementPhase;
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if apps.iter().all(|app| {
                    let storage = app.account_storage("test").unwrap();
                    let store = storage.private_roster_settlement_storage().unwrap();
                    store.read_round().unwrap().is_some_and(|r| {
                        r.phase == PrivateSettlementPhase::Completed
                            && r.anchor.successor.leaves.len() == leaves
                            && store.read_facts().unwrap().len() == leaves
                    })
                }) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("all original native devices must settle their actual complete indexed roster");
    }

    #[tokio::test]
    async fn native_public_original_three_device_enrollment_uses_opaque_approval_and_packets() {
        run_native_public_three_device_enrollment(ApprovalScenario::Enroll).await;
    }
    #[tokio::test]
    async fn native_public_original_approval_cancel_fences_shared_handles_and_packets() {
        run_native_public_three_device_enrollment(ApprovalScenario::Cancel).await;
    }
    #[tokio::test]
    async fn native_public_original_approval_review_identifies_authenticated_devices_without_approving()
     {
        run_native_public_three_device_enrollment(ApprovalScenario::ReviewThenEnroll).await;
    }
    #[tokio::test]
    async fn native_pairing_explicit_chat_sharing_persists_only_completed_original() {
        run_native_public_three_device_enrollment(ApprovalScenario::ShareChats).await;
    }
    #[tokio::test]
    async fn existing_pair_explicit_account_sharing_uses_original_relay_consent() {
        run_native_public_three_device_enrollment(ApprovalScenario::ExistingShare).await;
    }
    #[tokio::test]
    async fn automatic_sharing_request_before_source_policy_commit_retains_original_deadline() {
        run_native_public_three_device_enrollment(ApprovalScenario::AutomaticRace).await;
    }
    #[tokio::test]
    async fn automatic_catalog_channel_renewal_reaches_later_entries_without_manual_consent() {
        run_native_public_three_device_enrollment(ApprovalScenario::AutomaticRenewal).await;
    }
    #[tokio::test]
    async fn automatic_catalog_recipient_sql_failure_retries_without_manual_consent() {
        run_native_public_three_device_enrollment(ApprovalScenario::AutomaticCatalogRetry).await;
    }
    #[derive(Clone, Copy, PartialEq)]
    pub(super) enum ApprovalScenario {
        BroadEnrollment,
        BroadPreAuthFailure,
        BroadProjectionHeadFailure,
        BroadWrongRecipientRouting,
        BroadPairPlainSibling,
        BroadSiblingCancel,
        Enroll,
        Cancel,
        ReviewThenEnroll,
        ShareChats,
        ExistingShare,
        AutomaticRace,
        AutomaticRenewal,
        AutomaticCatalogRetry,
        AutomaticRecords,
        AutomaticRecordsWindow,
        AutomaticForwarding,
        AutomaticForwardingReply,
        AutomaticForwardingOffline,
        AutomaticForwardingNonAdmin,
        AutomaticForwardingReceiptRetry,
    }
    pub(super) async fn run_native_public_three_device_enrollment(scenario: ApprovalScenario) {
        use cgka_traits::StorageProvider;
        let relay_database = Arc::new(nostr_relay_builder::prelude::MemoryDatabase::with_opts(
            nostr_relay_builder::prelude::MemoryDatabaseOptions {
                events: true,
                max_events: Some(75_000),
            },
        ));
        let relay = nostr_relay_builder::LocalRelay::new(
            nostr_relay_builder::RelayBuilder::default().database(relay_database.clone()),
        );
        relay.run().await.unwrap();
        let url = relay.url().await.to_string();
        let keys = nostr::prelude::Keys::generate();
        let dirs: [tempfile::TempDir; 3] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
        let apps = std::array::from_fn::<_, 3, _>(|i| {
            AccountHome::open(dirs[i].path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
            MarmotApp::with_relay(dirs[i].path(), &url)
        });
        let runtimes = apps.clone().map(MarmotAppRuntime::new);
        runtimes[0].reconcile_accounts().await.unwrap();
        // Establish the real incoming chat while A is the sole active public
        // installation. Account-level invitations may select any later sibling.
        let incoming_peer = if scenario == ApprovalScenario::AutomaticForwardingNonAdmin {
            Some(
                super::automatic_forwarding_non_admin_acceptance::IncomingPeer::create(
                    &url,
                    &apps[0],
                    &runtimes[0],
                    &keys.public_key().to_hex(),
                )
                .await,
            )
        } else {
            None
        };
        for r in &runtimes[1..] {
            r.reconcile_accounts().await.unwrap();
        }
        let managers = runtimes.each_ref().map(|r| r.accounts());
        let b = managers[1]
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let initial_a = managers[0]
            .approve_device_linking_session("test", b.setup_packet(), None)
            .await
            .unwrap();
        verify_public_pair(&initial_a, &b).await;
        let broad_enrollment = matches!(
            scenario,
            ApprovalScenario::BroadEnrollment
                | ApprovalScenario::BroadPreAuthFailure
                | ApprovalScenario::BroadProjectionHeadFailure
                | ApprovalScenario::BroadWrongRecipientRouting
                | ApprovalScenario::BroadPairPlainSibling
                | ApprovalScenario::BroadSiblingCancel
        );
        if scenario == ApprovalScenario::ShareChats || broad_enrollment {
            let b_revision = b.snapshot().await.unwrap().revision;
            assert!(matches!(
                b.continue_linking_and_share_chats(b_revision + 1).await,
                Err(DeviceLinkingError::StaleRevision)
            ));
            b.continue_linking_and_share_chats(b_revision)
                .await
                .unwrap();
            initial_a
                .continue_linking_and_share_chats(initial_a.snapshot().await.unwrap().revision)
                .await
                .unwrap();
        } else {
            b.continue_linking(b.snapshot().await.unwrap().revision)
                .await
                .unwrap();
            initial_a
                .continue_linking(initial_a.snapshot().await.unwrap().revision)
                .await
                .unwrap();
        }
        wait_actual_roster(&apps[..2], 2).await;
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if initial_a.snapshot().await.unwrap().phase
                    == DeviceLinkingPhase::EnrollmentComplete
                    && b.snapshot().await.unwrap().phase == DeviceLinkingPhase::EnrollmentComplete
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("actual original enrollment completion must remain observable");
        // Completion is a synchronous durable handoff: the native UI may close
        // both originals immediately, without another background tick.
        let policies: Vec<_> = apps[..2]
            .iter()
            .map(|app| {
                app.account_storage("test")
                    .unwrap()
                    .approved_account_sharing_policy_storage()
                    .unwrap()
                    .approved_account_sharing_policies()
                    .unwrap()
            })
            .collect();
        if scenario == ApprovalScenario::ShareChats || broad_enrollment {
            use cgka_traits::approved_account_sharing_policy::approved_account_sharing_identity;
            assert!(policies.iter().all(|rows| rows.len() == 1));
            let ids: Vec<_> = policies
                .iter()
                .map(|rows| {
                    let p = &rows[0];
                    assert!(!p.revoked);
                    assert_eq!(p.approved_protected_epoch, 1);
                    approved_account_sharing_identity(
                        &p.account,
                        &p.protected_group,
                        &p.local_device,
                        &p.peer_device,
                        &p.approval_id,
                    )
                    .unwrap()
                })
                .collect();
            assert_eq!(ids[0], ids[1]);
            assert_eq!(policies[0][0].local_device, policies[1][0].peer_device);
            assert_eq!(policies[1][0].local_device, policies[0][0].peer_device);
        } else {
            assert!(policies.iter().all(Vec::is_empty));
        }
        initial_a.cancel().await.unwrap();
        b.cancel().await.unwrap();
        let targets = managers[0]
            .device_linking_targets("test")
            .await
            .expect("public discovery must authenticate the completed original two-device target");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].device_count, 2);
        let c = managers[2]
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let a = managers[0]
            .approve_device_linking_session(
                "test",
                c.setup_packet(),
                Some(targets[0].selector.clone()),
            )
            .await
            .unwrap();
        verify_public_pair(&a, &c).await;
        if broad_enrollment {
            c.continue_linking_and_share_chats(c.snapshot().await.unwrap().revision)
                .await
                .unwrap();
            a.continue_linking_and_share_chats(a.snapshot().await.unwrap().revision)
                .await
                .unwrap();
        } else {
            c.continue_linking(c.snapshot().await.unwrap().revision)
                .await
                .unwrap();
            a.continue_linking(a.snapshot().await.unwrap().revision)
                .await
                .unwrap();
        }
        let approval = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let mut pending = managers[1]
                    .pending_device_linking_approvals("test")
                    .await
                    .unwrap();
                if let Some(p) = pending.pop() {
                    break p;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("B must receive A's actual encrypted proposal as an opaque native action");
        let duplicate_handles = managers[1]
            .pending_device_linking_approvals("test")
            .await
            .unwrap();
        assert_eq!(duplicate_handles.len(), 1);
        assert!(Arc::ptr_eq(&approval.inner, &duplicate_handles[0].inner));
        drop(duplicate_handles);
        let observed = approval.snapshot().await.unwrap();
        if scenario == ApprovalScenario::ReviewThenEnroll {
            let reviewed = approval.review_metadata(observed.revision).await
                .expect("original B approval must expose authenticated sender and joining-device review metadata");
            assert_eq!(reviewed.revision, observed.revision);
            assert_eq!(reviewed.existing_device_count, 2);
            assert_eq!(reviewed.source_device_public_key.len(), 32);
            assert_eq!(reviewed.joining_device_public_key.len(), 32);
            assert_ne!(
                reviewed.source_device_public_key,
                reviewed.joining_device_public_key
            );
            // Independent public identity oracles: the actual existing A MLS
            // leaf and C's original public setup packet, not UI reconstruction.
            let storage = apps[0].account_storage("test").unwrap();
            let group = openmls::group::MlsGroup::load(
                storage.mls_storage(),
                &openmls::group::GroupId::from_slice(&targets[0].selector),
            )
            .unwrap()
            .unwrap();
            assert!(
                reviewed.source_device_public_key.as_slice()
                    == group.own_leaf_node().unwrap().signature_key().as_slice()
            );
            let original_setup: serde_json::Value =
                serde_json::from_slice(&c.setup_packet()[6..]).unwrap();
            let recipient: Vec<u8> = original_setup["recipient"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| u8::try_from(v.as_u64().unwrap()).unwrap())
                .collect();
            assert!(reviewed.joining_device_public_key == recipient);
            assert_eq!(
                approval.snapshot().await.unwrap(),
                observed,
                "review cannot implicitly approve the original proposal"
            );
            assert!(
                a.enrollment_packet(a.snapshot().await.unwrap().revision)
                    .await
                    .is_err()
            );
            assert!(matches!(
                approval.review_metadata(observed.revision + 1).await,
                Err(DeviceLinkingError::StaleRevision)
            ));
        }
        if scenario == ApprovalScenario::Cancel || scenario == ApprovalScenario::BroadSiblingCancel
        {
            let shared = managers[1]
                .pending_device_linking_approvals("test")
                .await
                .unwrap();
            if scenario == ApprovalScenario::BroadSiblingCancel {
                approval
                    .approve_and_share_chats(observed.revision)
                    .await
                    .unwrap();
                let original = approval.sharing_original_for_test().unwrap();
                assert!(original.status_for_test().0);
                approval.cancel().await.unwrap();
                assert!(
                    !original.status_for_test().0,
                    "native cancellation must synchronously retire the actual original"
                );
                assert!(!original.status_for_test().1);
                for app in &apps {
                    assert!(
                        app.account_storage("test")
                            .unwrap()
                            .approved_account_sharing_policy_storage()
                            .unwrap()
                            .approved_account_sharing_policies()
                            .unwrap()
                            .iter()
                            .all(|policy| policy.approved_protected_epoch == 1),
                        "cancelled B/C original must create no third-device policy"
                    );
                }
            }
            approval.cancel().await.unwrap();
            let cancelled = approval.snapshot().await.unwrap();
            assert_eq!(cancelled.phase, DeviceLinkingApprovalPhase::Cancelled);
            assert!(matches!(
                shared[0].review_metadata(cancelled.revision).await,
                Err(DeviceLinkingError::Closed)
            ));
            assert!(matches!(
                shared[0].approve(cancelled.revision).await,
                Err(DeviceLinkingError::Closed)
            ));
            assert!(matches!(
                shared[0]
                    .receive_enrollment_packet(cancelled.revision, vec![0; 16_385])
                    .await,
                Err(DeviceLinkingError::Closed)
            ));
            assert!(
                managers[1]
                    .pending_device_linking_approvals("test")
                    .await
                    .unwrap()
                    .is_empty()
            );
            a.cancel().await.unwrap();
            c.cancel().await.unwrap();
            wait_actual_roster(&apps[..2], 2).await;
            for runtime in runtimes {
                runtime.shutdown_and_close().await.unwrap();
            }
            relay.shutdown();
            return;
        }

        assert_eq!(observed.phase, DeviceLinkingApprovalPhase::AwaitingApproval);
        assert!(matches!(
            approval.approve(observed.revision + 1).await,
            Err(DeviceLinkingError::StaleRevision)
        ));
        let mut pre_auth_probe = None;
        if matches!(
            scenario,
            ApprovalScenario::BroadEnrollment
                | ApprovalScenario::BroadPreAuthFailure
                | ApprovalScenario::BroadProjectionHeadFailure
        ) {
            assert!(matches!(
                approval
                    .approve_and_share_chats(observed.revision + 1)
                    .await,
                Err(DeviceLinkingError::StaleRevision)
            ));
            approval
                .approve_and_share_chats(observed.revision)
                .await
                .unwrap();
            if scenario == ApprovalScenario::BroadPreAuthFailure {
                pre_auth_probe = Some(
                    managers[1]
                        .arm_sibling_pre_auth_failure_for_test(
                            "test",
                            approval.sharing_original_for_test().unwrap(),
                        )
                        .await
                        .unwrap(),
                );
            }
            let approved = approval.snapshot().await.unwrap();
            assert_eq!(
                approved.phase,
                DeviceLinkingApprovalPhase::ApprovedAwaitingPacket
            );
            assert!(
                approval.approve(approved.revision).await.is_err(),
                "ordinary retry cannot change the original broad choice"
            );
        } else {
            approval.approve(observed.revision).await.unwrap();
            if scenario == ApprovalScenario::BroadPairPlainSibling {
                let approved = approval.snapshot().await.unwrap();
                assert!(
                    approval
                        .approve_and_share_chats(approved.revision)
                        .await
                        .is_err(),
                    "a taken ordinary B approval cannot be upgraded"
                );
            }
        }
        let packet = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let revision = a.snapshot().await.unwrap().revision;
                if let Ok(p) = a.enrollment_packet(revision).await {
                    break p;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("A must export its original full all-leaf approval before Add lease transfer");
        assert!(packet.len() <= 16 * 1024);
        assert!(
            c.receive_enrollment_packet(c.snapshot().await.unwrap().revision, vec![0])
                .await
                .is_err()
        );
        c.receive_enrollment_packet(c.snapshot().await.unwrap().revision, packet.clone())
            .await
            .unwrap();
        approval
            .receive_enrollment_packet(approval.snapshot().await.unwrap().revision, packet)
            .await
            .unwrap();
        let projection_head_probe = (scenario == ApprovalScenario::BroadProjectionHeadFailure)
            .then(|| c.arm_sibling_projection_head_probe_for_test().unwrap());
        if let Some(head) = &projection_head_probe {
            managers[1]
                .arm_sibling_pre_auth_failure_for_test(
                    "test",
                    approval.sharing_original_for_test().unwrap(),
                )
                .await
                .unwrap()
                .hold_request_until_projection_head_for_test(head)
                .unwrap();
        }
        // Both actual original actors are armed before A moves its proposal
        // lease into Add; transporting/acknowledging bytes is never admission.
        a.finalize_linking(a.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        wait_actual_roster(&apps, 3).await;
        let projection_distractor = if projection_head_probe.is_some() {
            Some(
                super::sibling_sharing_projection_acceptance::begin_actual_approver_distractor(
                    &apps, &managers,
                )
                .await,
            )
        } else {
            None
        };
        if broad_enrollment {
            super::sibling_sharing_acceptance::assert_bilateral_completion(
                &apps,
                &a,
                &c,
                &approval,
                matches!(
                    scenario,
                    ApprovalScenario::BroadEnrollment
                        | ApprovalScenario::BroadPreAuthFailure
                        | ApprovalScenario::BroadProjectionHeadFailure
                ),
                pre_auth_probe.as_deref(),
                (relay_database.as_ref(), runtimes[2].relay_plane_for_test()),
            )
            .await;
        }
        if let Some(action) = projection_distractor {
            action.cancel();
        }
        if let Some(probe) = projection_head_probe {
            let counts = probe.snapshot_for_test();
            assert!(
                counts[0] > 0,
                "actual A control must fail before Core authentication"
            );
            assert!(
                counts[1] > 0,
                "same retained original must retry Core after actual B channel admission"
            );
        }
        if let Some(probe) = pre_auth_probe {
            assert_eq!(
                probe.failures(),
                1,
                "genuine MLS intake must encounter the one-shot failure"
            );
            assert!(
                probe.buffered() >= 1,
                "the original retains the unprocessed opaque control"
            );
            assert!(
                probe.authenticated_retries() >= 1,
                "retry must pass genuine Core authentication for the same channel"
            );
        }
        if scenario == ApprovalScenario::BroadWrongRecipientRouting {
            super::sibling_sharing_routing_acceptance::assert_wrong_recipient_request_is_not_pending(&apps, &managers, &c).await;
        }
        // Membership alone cannot silently broaden the original A/B choice
        // to C. Its separate ordinary pairing created no sharing approval.
        for (index, app) in apps.iter().enumerate() {
            let policies = app
                .account_storage("test")
                .unwrap()
                .approved_account_sharing_policy_storage()
                .unwrap()
                .approved_account_sharing_policies()
                .unwrap();
            if !broad_enrollment {
                assert_eq!(
                    policies.len(),
                    usize::from(scenario == ApprovalScenario::ShareChats && index < 2)
                );
            }
        }
        let initial_shared_chat = if matches!(
            scenario,
            ApprovalScenario::ExistingShare
                | ApprovalScenario::AutomaticRace
                | ApprovalScenario::AutomaticRenewal
                | ApprovalScenario::AutomaticCatalogRetry
                | ApprovalScenario::AutomaticRecords
                | ApprovalScenario::AutomaticRecordsWindow
                | ApprovalScenario::AutomaticForwarding
                | ApprovalScenario::AutomaticForwardingReply
                | ApprovalScenario::AutomaticForwardingOffline
                | ApprovalScenario::AutomaticForwardingNonAdmin
                | ApprovalScenario::AutomaticForwardingReceiptRetry
        ) {
            if scenario == ApprovalScenario::AutomaticForwardingNonAdmin {
                Some(incoming_peer.as_ref().unwrap().group.clone())
            } else {
                Some(
                    managers[0]
                        .create_group(
                            "test",
                            "Automatically discovered existing chat",
                            &[],
                            Some("x".repeat(4096)),
                        )
                        .await
                        .unwrap(),
                )
            }
        } else {
            None
        };
        let initial_record_ids = if matches!(
            scenario,
            ApprovalScenario::AutomaticRecords
                | ApprovalScenario::AutomaticRecordsWindow
                | ApprovalScenario::AutomaticForwarding
                | ApprovalScenario::AutomaticForwardingReply
                | ApprovalScenario::AutomaticForwardingOffline
                | ApprovalScenario::AutomaticForwardingNonAdmin
                | ApprovalScenario::AutomaticForwardingReceiptRetry
        ) {
            let mut ids = super::automatic_records_acceptance::seed(
                &managers[0],
                initial_shared_chat.as_ref().unwrap(),
            )
            .await;
            if let Some(peer) = &incoming_peer {
                ids.push(peer.preapproval_message.clone());
            }
            ids
        } else {
            Vec::new()
        };
        let mut renewal_chats = Vec::new();
        if scenario == ApprovalScenario::AutomaticRenewal {
            for index in 0..20 {
                renewal_chats.push(
                    managers[0]
                        .create_group(
                            "test",
                            &format!("Renewal chat {index}"),
                            &[],
                            Some("x".repeat(4096)),
                        )
                        .await
                        .unwrap(),
                );
            }
        }
        if matches!(
            scenario,
            ApprovalScenario::ExistingShare
                | ApprovalScenario::AutomaticRace
                | ApprovalScenario::AutomaticRenewal
                | ApprovalScenario::AutomaticCatalogRetry
                | ApprovalScenario::AutomaticRecords
                | ApprovalScenario::AutomaticRecordsWindow
                | ApprovalScenario::AutomaticForwarding
                | ApprovalScenario::AutomaticForwardingReply
                | ApprovalScenario::AutomaticForwardingOffline
                | ApprovalScenario::AutomaticForwardingNonAdmin
                | ApprovalScenario::AutomaticForwardingReceiptRetry
        ) {
            // Select C from actual settled protected tree, never invent a target.
            let c_key = apps[2]
                .account_storage("test")
                .unwrap()
                .private_roster_settlement_storage()
                .unwrap()
                .read_round()
                .unwrap()
                .unwrap()
                .anchor
                .local_device;
            let inventory = managers[0]
                .account_chat_sharing_targets("test")
                .await
                .unwrap();
            assert_eq!(inventory.targets.len(), 2);
            assert!(
                inventory
                    .targets
                    .windows(2)
                    .all(|pair| pair[0].leaf_index < pair[1].leaf_index)
            );
            assert!(
                managers[0]
                    .account_chat_sharing_targets("missing")
                    .await
                    .is_err()
            );
            let local = apps[0]
                .account_storage("test")
                .unwrap()
                .private_roster_settlement_storage()
                .unwrap()
                .read_round()
                .unwrap()
                .unwrap()
                .anchor
                .local_device;
            assert!(
                inventory
                    .targets
                    .iter()
                    .all(|target| target.device != local)
            );
            let chosen = inventory
                .targets
                .iter()
                .find(|target| target.device == c_key)
                .unwrap()
                .device
                .clone();
            let cancelled = managers[0]
                .begin_account_chat_sharing("test", chosen.clone())
                .await
                .unwrap();
            let cancelled_revision = cancelled.snapshot().unwrap().revision;
            cancelled.cancel();
            assert!(matches!(
                cancelled.approve(cancelled_revision).await,
                Err(crate::AccountSharingError::Closed)
            ));
            let source = managers[0]
                .begin_account_chat_sharing("test", chosen)
                .await
                .unwrap();
            let review = source.snapshot().unwrap();
            assert!(!review.approved && !review.complete);
            assert_eq!(review.protected_group, inventory.protected_group);
            assert_eq!(review.protected_epoch, inventory.protected_epoch);
            assert!(
                managers[2]
                    .pending_account_chat_sharing("test")
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(
                managers[0]
                    .begin_account_chat_sharing("missing", c_key.to_vec())
                    .await
                    .is_err()
            );
            assert!(matches!(
                source.approve(review.revision + 1).await,
                Err(crate::AccountSharingError::StaleRevision)
            ));
            let alias = source.clone();
            drop(alias);
            source.approve(review.revision).await.unwrap();
            let end = std::time::Instant::now() + std::time::Duration::from_secs(20);
            let recipient = loop {
                let mut pending = managers[2]
                    .pending_account_chat_sharing("test")
                    .await
                    .unwrap();
                if !pending.is_empty() {
                    break pending.remove(0);
                }
                assert!(
                    std::time::Instant::now() < end,
                    "real protected request did not arrive"
                );
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            };
            let recipient_review = recipient.snapshot().unwrap();
            assert_eq!(recipient_review.protected_group, review.protected_group);
            assert_eq!(recipient_review.protected_epoch, review.protected_epoch);
            assert_eq!(recipient_review.source_device, review.source_device);
            assert_eq!(recipient_review.recipient_device, review.recipient_device);
            assert!(
                managers[1]
                    .pending_account_chat_sharing("test")
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(matches!(
                recipient.approve(recipient_review.revision + 1).await,
                Err(crate::AccountSharingError::StaleRevision)
            ));
            let policy_injector = if scenario == ApprovalScenario::AutomaticRace {
                let path = apps[0].account_storage_path("test");
                let keys = apps[0].account_home().load_signing_keys("test").unwrap();
                let sql_key = apps[0]
                    .sqlcipher_key(
                        "test",
                        &keys,
                        &path,
                        crate::sqlcipher::SqlcipherDatabaseKind::Session,
                    )
                    .unwrap();
                let connection = rusqlite::Connection::open(&path).unwrap();
                storage_sqlite::open_hardened_sqlcipher(
                    &connection,
                    &sql_key,
                    storage_sqlite::SqlCipherHardening::cipher_only(),
                )
                .unwrap();
                connection.execute_batch("CREATE TRIGGER hold_original_sharing_policy BEFORE INSERT ON approved_account_sharing_policies BEGIN SELECT RAISE(ABORT,'isolated original sharing policy rollback'); END;").unwrap();
                Some(connection)
            } else {
                None
            };
            let mut catalog_errors = runtimes[2].subscribe();
            let catalog_injector = if scenario == ApprovalScenario::AutomaticCatalogRetry {
                let path = apps[2].account_storage_path("test");
                let keys = apps[2].account_home().load_signing_keys("test").unwrap();
                let sql_key = apps[2]
                    .sqlcipher_key(
                        "test",
                        &keys,
                        &path,
                        crate::sqlcipher::SqlcipherDatabaseKind::Session,
                    )
                    .unwrap();
                let connection = rusqlite::Connection::open(&path).unwrap();
                storage_sqlite::open_hardened_sqlcipher(
                    &connection,
                    &sql_key,
                    storage_sqlite::SqlCipherHardening::cipher_only(),
                )
                .unwrap();
                connection.execute_batch("CREATE TRIGGER hold_automatic_catalog BEFORE INSERT ON mirrored_chat_catalog BEGIN SELECT RAISE(ABORT,'isolated catalog commit rollback'); END;").unwrap();
                Some(connection)
            } else {
                None
            };
            recipient.approve(recipient_review.revision).await.unwrap();
            let retained_request = if let Some(connection) = policy_injector.as_ref() {
                assert!(recipient.snapshot().unwrap().complete);
                assert!(!source.snapshot().unwrap().complete);
                assert!(
                    apps[0]
                        .account_storage("test")
                        .unwrap()
                        .approved_account_sharing_policy_storage()
                        .unwrap()
                        .approved_account_sharing_policies()
                        .unwrap()
                        .is_empty()
                );
                // Change only scheduling: use the exact normal factory, durable
                // original-approved policy, Core validation and relay publisher.
                managers[2]
                    .kick_approved_automatic_channel("test")
                    .await
                    .unwrap();
                let pending = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    loop {
                        let pending = managers[0]
                            .pending_account_chat_sharing("test")
                            .await
                            .unwrap();
                        if let Some(original) = pending.into_iter().find(|original| {
                            original.snapshot().unwrap().source_device == review.recipient_device
                        }) {
                            break original;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                })
                .await
                .expect("actual encrypted request must precede source policy commit");
                let observed = pending.snapshot().unwrap();
                assert_eq!(observed.protected_group, review.protected_group);
                assert_eq!(observed.protected_epoch, review.protected_epoch);
                assert_eq!(observed.recipient_device, review.source_device);
                assert!(!observed.approved && !observed.complete);
                let deadline = pending.original.deadline;
                connection
                    .execute_batch("DROP TRIGGER hold_original_sharing_policy;")
                    .unwrap();
                Some((pending, deadline))
            } else {
                None
            };

            while !source.snapshot().unwrap().complete {
                assert!(
                    std::time::Instant::now() < end,
                    "real signed consent did not complete"
                );
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert!(recipient.snapshot().unwrap().complete);
            if let Some((pending, deadline)) = retained_request {
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    while pending.original.live() {
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }).await.expect("newly committed original policy must promote the retained authenticated request without another manual approval");
                assert_eq!(pending.original.deadline, deadline);
            }
            let facts: Vec<_> = apps
                .iter()
                .map(|app| {
                    app.account_storage("test")
                        .unwrap()
                        .approved_account_sharing_policy_storage()
                        .unwrap()
                        .approved_account_sharing_policies()
                        .unwrap()
                })
                .collect();
            assert_eq!(facts[0].len(), 1);
            assert!(facts[1].is_empty());
            assert_eq!(facts[2].len(), 1);
            assert_eq!(facts[0][0].approval_id, facts[2][0].approval_id);
            assert_eq!(facts[0][0].local_device, facts[2][0].peer_device);
            assert_eq!(facts[0][0].peer_device, facts[2][0].local_device);
            let policy = &facts[2][0];
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
                protected_generation: apps[2]
                    .account_storage("test")
                    .unwrap()
                    .private_roster_settlement_storage()
                    .unwrap()
                    .read_round()
                    .unwrap()
                    .unwrap()
                    .generation,
            };
            if let Some(connection) = catalog_injector {
                tokio::time::timeout(std::time::Duration::from_secs(20), async {
                    loop {
                        if let crate::MarmotAppEvent::AccountError(error) =
                            catalog_errors.recv().await.unwrap()
                            && error.message.starts_with("runtime receive failed")
                        {
                            assert_eq!(
                                error.message,
                                "runtime receive failed: invalid_app_message_payload"
                            );
                            break;
                        }
                    }
                })
                .await
                .expect("actual encrypted catalog must reach the injected SQL refusal");
                assert!(
                    apps[2]
                        .account_storage("test")
                        .unwrap()
                        .mirrored_chat_catalog_storage()
                        .unwrap()
                        .mirrored_chat_catalog_page(&mirror, None, 128)
                        .unwrap()
                        .is_empty(),
                    "failed recipient transaction must commit no mirrored catalog entry"
                );
                connection
                    .execute_batch("DROP TRIGGER hold_automatic_catalog;")
                    .unwrap();
            }
            let later = managers[0]
                .create_group("test", "Automatically discovered later chat", &[], None)
                .await
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(if scenario == ApprovalScenario::AutomaticRenewal {180} else {30}),async{
                loop{
                    let rows=apps[2].account_storage("test").unwrap().mirrored_chat_catalog_storage().unwrap().mirrored_chat_catalog_page(&mirror,None,128).unwrap();
                    if rows.len()==2 + renewal_chats.len() {
                        let old=rows.iter().find(|record|Some(&record.group_id)==initial_shared_chat.as_ref()).unwrap();
                        assert_eq!(old.description.len(),4096);
                        assert!(rows.iter().any(|record|record.group_id==later));
                        for group in &renewal_chats {assert!(rows.iter().any(|record|&record.group_id==group && record.description.len()==4096));}
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }).await.expect("approved policy must automatically discover existing and later chats without per-chat actions");
            assert!(
                apps[2].load_state("test").unwrap().groups.is_empty(),
                "a mirrored catalog is not MLS membership"
            );
            assert!(
                apps[1]
                    .account_storage("test")
                    .unwrap()
                    .mirrored_chat_catalog_storage()
                    .unwrap()
                    .mirrored_chat_catalog_page(&mirror, None, 128)
                    .is_err(),
                "unapproved B cannot read C-owned mirrors"
            );
            if matches!(
                scenario,
                ApprovalScenario::AutomaticRecords
                    | ApprovalScenario::AutomaticRecordsWindow
                    | ApprovalScenario::AutomaticForwarding
                    | ApprovalScenario::AutomaticForwardingReply
                    | ApprovalScenario::AutomaticForwardingOffline
                    | ApprovalScenario::AutomaticForwardingNonAdmin
                    | ApprovalScenario::AutomaticForwardingReceiptRetry
            ) {
                super::automatic_records_acceptance::verify(
                    &apps,
                    &managers[0],
                    initial_shared_chat.as_ref().unwrap(),
                    &mirror,
                    &initial_record_ids,
                    (scenario == ApprovalScenario::AutomaticRecordsWindow).then_some(&runtimes[2]),
                )
                .await;
            }
            if matches!(
                scenario,
                ApprovalScenario::AutomaticForwarding
                    | ApprovalScenario::AutomaticForwardingNonAdmin
            ) {
                super::automatic_forwarding_acceptance::verify(
                    &apps,
                    &runtimes[2],
                    initial_shared_chat.as_ref().unwrap(),
                    &mirror,
                )
                .await;
            }
            if let Some(peer) = &incoming_peer {
                peer.verify_forwarded_receipt(&runtimes[2]).await;
            }
            if scenario == ApprovalScenario::AutomaticForwardingReply {
                super::automatic_forwarding_acceptance::verify_reply(
                    &apps,
                    &runtimes[2],
                    initial_shared_chat.as_ref().unwrap(),
                    &mirror,
                    &initial_record_ids[0],
                )
                .await;
            }
            if scenario == ApprovalScenario::AutomaticForwardingReceiptRetry {
                super::automatic_forwarding_acceptance::verify_receipt_sql_retry(
                    &apps,
                    &runtimes[2],
                    initial_shared_chat.as_ref().unwrap(),
                    &mirror,
                )
                .await;
            }
            source.cancel();
            recipient.cancel();
            if scenario == ApprovalScenario::AutomaticForwardingOffline {
                for session in [&a, &c] {
                    assert_eq!(
                        session.snapshot().await.unwrap().phase,
                        DeviceLinkingPhase::EnrollmentComplete
                    );
                }
                super::automatic_forwarding_acceptance::verify_offline_reopen(
                    &apps,
                    &runtimes,
                    [dirs[0].path(), dirs[2].path()],
                    &url,
                    initial_shared_chat.as_ref().unwrap(),
                    &mirror,
                )
                .await;
                for runtime in runtimes {
                    runtime.shutdown_and_close().await.unwrap();
                }
                relay.shutdown();
                return;
            }
        }
        assert!(
            managers
                .iter()
                .all(|manager| manager.device_linking_capabilities().enrollment_supported),
            "the experimental build must advertise its qualified ready-account enrollment flow"
        );
        for session in [&a, &c] {
            let snapshot = session.snapshot().await.unwrap();
            assert_eq!(snapshot.phase, DeviceLinkingPhase::EnrollmentComplete);
            assert!(snapshot.decimals.is_none());
        }

        for manager in &managers {
            let final_targets = manager.device_linking_targets("test").await.unwrap();
            assert_eq!(final_targets.len(), 1);
            assert_eq!(final_targets[0].device_count, 3);
        }
        assert_eq!(
            approval.snapshot().await.unwrap().phase,
            DeviceLinkingApprovalPhase::Settled
        );
        let complete = a.snapshot().await.unwrap();
        assert!(matches!(
            a.continue_linking(complete.revision).await,
            Err(DeviceLinkingError::Closed)
        ));
        let settled = approval.snapshot().await.unwrap();
        if scenario == ApprovalScenario::ReviewThenEnroll {
            assert!(matches!(
                approval.review_metadata(settled.revision).await,
                Err(DeviceLinkingError::Closed)
            ));
        }
        assert!(matches!(
            approval.approve(settled.revision).await,
            Err(DeviceLinkingError::Closed)
        ));
        a.cancel().await.unwrap();
        approval.cancel().await.unwrap();
        assert_eq!(a.snapshot().await.unwrap(), complete);
        assert_eq!(approval.snapshot().await.unwrap(), settled);

        assert!(apps.iter().enumerate().all(|(index, app)| matches!(
            scenario,
            ApprovalScenario::ExistingShare
                | ApprovalScenario::AutomaticRace
                | ApprovalScenario::AutomaticRenewal
                | ApprovalScenario::AutomaticCatalogRetry
                | ApprovalScenario::AutomaticRecords
                | ApprovalScenario::AutomaticRecordsWindow
                | ApprovalScenario::AutomaticForwarding
                | ApprovalScenario::AutomaticForwardingReply
                | ApprovalScenario::AutomaticForwardingOffline
                | ApprovalScenario::AutomaticForwardingNonAdmin
                | ApprovalScenario::AutomaticForwardingReceiptRetry
        ) && index == 0
            || app.load_state("test").unwrap().groups.is_empty()));
        if matches!(
            scenario,
            ApprovalScenario::ExistingShare
                | ApprovalScenario::AutomaticRace
                | ApprovalScenario::AutomaticRenewal
                | ApprovalScenario::AutomaticCatalogRetry
                | ApprovalScenario::AutomaticRecords
                | ApprovalScenario::AutomaticRecordsWindow
                | ApprovalScenario::AutomaticForwarding
                | ApprovalScenario::AutomaticForwardingReply
                | ApprovalScenario::AutomaticForwardingOffline
                | ApprovalScenario::AutomaticForwardingNonAdmin
                | ApprovalScenario::AutomaticForwardingReceiptRetry
        ) {
            let old = managers[0]
                .account_chat_sharing_targets("test")
                .await
                .unwrap();
            let removed = apps[2]
                .account_storage("test")
                .unwrap()
                .private_roster_settlement_storage()
                .unwrap()
                .read_round()
                .unwrap()
                .unwrap()
                .anchor
                .local_device
                .to_vec();
            let action = managers[0]
                .begin_device_revocation("test", removed.clone())
                .await
                .unwrap();
            let review = action.snapshot().await.unwrap();
            assert!(review.ordinary_groups.is_empty());
            if matches!(scenario, ApprovalScenario::AutomaticRenewal) {
                // This fixture deliberately fills the real relay's publication
                // bucket. A transient refusal must retain the exact reviewed
                // original, including its prepared Commit and fixed deadline.
                tokio::time::timeout(std::time::Duration::from_secs(30), async {
                    loop {
                        match action.approve(review.revision).await {
                            Ok(()) => break,
                            Err(crate::device_revocation::GroupDeviceRevocationError::RuntimeUnavailable) => {
                                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            }
                            Err(error) => panic!("same-original revocation retry failed: {error:?}"),
                        }
                    }
                })
                .await
                .expect("same original revocation must recover after publication refusal");
            } else {
                action.approve(review.revision).await.unwrap();
            }
            wait_actual_roster(&apps[..2], 2).await;
            let fresh = managers[0]
                .account_chat_sharing_targets("test")
                .await
                .unwrap();
            assert_eq!(fresh.targets.len(), 1);
            assert!(fresh.targets.iter().all(|target| target.device != removed));
            assert_eq!(fresh.protected_group, old.protected_group);
            assert!(fresh.protected_epoch > old.protected_epoch);
            assert!(
                managers[0]
                    .begin_account_chat_sharing("test", removed)
                    .await
                    .is_err()
            );
        }
        if let Some(peer) = incoming_peer {
            peer.runtime.shutdown_and_close().await.unwrap();
            assert!(peer.runtime.storage_is_closed());
        }
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
        relay.shutdown();
    }

    #[tokio::test]
    async fn native_stalled_original_publication_timeout_is_nonterminal_and_cancel_fences_delivery()
    {
        use cgka_traits::StorageProvider;
        use cgka_traits::private_device_invite::PrivateInvitePhase;
        let keys = nostr::prelude::Keys::generate();
        let dirs: [tempfile::TempDir; 2] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
        let relays: [Arc<crate::tests::ScriptedPushRelayClient>; 2] =
            std::array::from_fn(|_| Arc::new(crate::tests::ScriptedPushRelayClient::default()));
        let apps = std::array::from_fn::<_, 2, _>(|i| {
            AccountHome::open(dirs[i].path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
            MarmotApp::with_relay(dirs[i].path(), "wss://relay.example")
                .with_test_relay_client(relays[i].clone())
        });
        let runtimes = apps.clone().map(MarmotAppRuntime::new);
        for runtime in &runtimes {
            runtime.reconcile_accounts().await.unwrap();
        }
        let c = runtimes[1]
            .accounts()
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let a = runtimes[0]
            .accounts()
            .approve_device_linking_session("test", c.setup_packet(), None)
            .await
            .unwrap();
        verify_public_pair(&a, &c).await;
        c.continue_linking(c.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        relays[0].block_next_publish();
        a.continue_linking(a.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            relays[0].wait_for_blocked_publish(),
        )
        .await
        .expect("the original native A action must stall in actual publication");
        let storage = apps[0].account_storage("test").unwrap();
        let invite = storage
            .private_device_invite_storage()
            .unwrap()
            .private_invite()
            .unwrap()
            .unwrap();
        assert_eq!(invite.phase, PrivateInvitePhase::Dispatching);
        let published_before = relays[0].published_event_ids();
        // Use the real production 120-second RPC wait. No global time advance,
        // artificial consent deadline, proof taking or reconstructed row grant.
        let observation = tokio::time::timeout(std::time::Duration::from_secs(135), a.snapshot())
            .await
            .expect("native observation must finish its bounded production RPC wait")
            .unwrap();
        assert_eq!(
            observation.phase,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending,
            "a temporary observation response timeout must not close the still-owned original publication"
        );
        assert!(observation.decimals.is_none());
        tokio::time::timeout(std::time::Duration::from_millis(500), a.cancel())
            .await
            .expect("exact native cancellation must bypass stalled publication and observation")
            .unwrap();
        assert_eq!(
            a.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::Cancelled
        );
        relays[0].release_publish();
        tokio::time::sleep(std::time::Duration::from_millis(1250)).await;
        assert!(
            relays[0].published_event_ids() == published_before,
            "cancelled original Commit/Welcome publication must not complete after the transport releases"
        );
        assert!(
            storage
                .private_device_invite_storage()
                .unwrap()
                .confirmed_private_invite()
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            a.continue_linking(observation.revision).await,
            Err(DeviceLinkingError::Closed)
        ));
        c.cancel().await.unwrap();
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn native_public_continuation_settles_actual_original_pair_over_live_relay() {
        use cgka_traits::StorageProvider;
        use cgka_traits::private_roster_settlement::PrivateSettlementPhase;

        let relay =
            nostr_relay_builder::LocalRelay::new(nostr_relay_builder::RelayBuilder::default());
        relay.run().await.unwrap();
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
        let c = runtimes[1]
            .accounts()
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let initial = c.snapshot().await.unwrap();
        assert!(matches!(
            c.continue_linking(initial.revision).await,
            Err(DeviceLinkingError::NotReady)
        ));
        let a = runtimes[0]
            .accounts()
            .approve_device_linking_session("test", c.setup_packet(), None)
            .await
            .unwrap();
        c.receive_setup_packet(a.setup_packet()).await.unwrap();
        for _ in 0..8 {
            drain(&a, &c).await;
            drain(&c, &a).await;
        }
        let ac = a.snapshot().await.unwrap();
        let cc = c.snapshot().await.unwrap();
        assert_eq!(ac.phase, DeviceLinkingPhase::ComparisonAvailable);
        assert_eq!(ac.decimals, cc.decimals);
        a.confirm_comparison(ac.revision).await.unwrap();
        c.confirm_comparison(cc.revision).await.unwrap();
        for _ in 0..8 {
            drain(&a, &c).await;
            drain(&c, &a).await;
        }
        let verified_c = c.snapshot().await.unwrap();
        let verified_a = a.snapshot().await.unwrap();
        assert_eq!(
            verified_c.phase,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending
        );
        assert_eq!(
            verified_a.phase,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending
        );
        // Only the public opaque sessions continue these exact SDK actions.
        // No internal scope, proof-taking, recipient arm or injected grant.
        assert!(matches!(
            c.continue_linking(verified_c.revision + 1).await,
            Err(DeviceLinkingError::StaleRevision)
        ));
        c.continue_linking(verified_c.revision)
            .await
            .expect("the original verified native recipient must continue enrollment");
        c.continue_linking(c.snapshot().await.unwrap().revision)
            .await
            .expect("a duplicate continuation must preserve the same original owner");
        a.continue_linking(verified_a.revision)
            .await
            .expect("the original verified native approver must continue enrollment");

        let result = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if apps.iter().all(|app| {
                    let storage = app.account_storage("test").unwrap();
                    let store = storage.private_roster_settlement_storage().unwrap();
                    store.read_round().unwrap().is_some_and(|round| {
                        round.phase == PrivateSettlementPhase::Completed
                            && round.anchor.successor.leaves.len() == 2
                            && store.read_facts().unwrap().len() == 2
                    })
                }) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        let hidden = apps
            .iter()
            .all(|app| app.load_state("test").unwrap().groups.is_empty());
        let completed = c.snapshot().await.unwrap();
        let recipient_revision = completed.revision;
        assert_eq!(completed.phase, DeviceLinkingPhase::EnrollmentComplete);
        c.cancel().await.unwrap();
        assert_eq!(c.snapshot().await.unwrap(), completed);
        assert!(matches!(
            c.continue_linking(recipient_revision).await,
            Err(DeviceLinkingError::Closed)
        ));
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
        relay.shutdown();
        assert!(hidden, "device-control enrollment must not project a chat");
        result.expect("public native continuation must settle both actual original device leaves");
    }

    #[tokio::test]
    async fn native_original_recipient_observation_survives_actual_sdk_handoff() {
        let (_dirs, runtimes) = workers().await;
        let manager = runtimes[1].accounts();
        let c = manager.begin_device_linking_session("test").await.unwrap();
        let a = runtimes[0]
            .accounts()
            .approve_device_linking_session("test", c.setup_packet(), None)
            .await
            .unwrap();
        c.receive_setup_packet(a.setup_packet()).await.unwrap();
        for _ in 0..8 {
            drain(&a, &c).await;
            drain(&c, &a).await;
        }
        let ac = a.snapshot().await.unwrap();
        let cc = c.snapshot().await.unwrap();
        assert_eq!(ac.phase, DeviceLinkingPhase::ComparisonAvailable);
        assert_eq!(ac.decimals, cc.decimals);
        a.confirm_comparison(ac.revision).await.unwrap();
        c.confirm_comparison(cc.revision).await.unwrap();
        for _ in 0..8 {
            drain(&a, &c).await;
            drain(&c, &a).await;
        }
        let verified = c.snapshot().await.unwrap();
        assert_eq!(
            verified.phase,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending
        );
        // The scoped internal actor command takes this same genuine SDK result.
        // It does not join a group, mint a new proof or reconstruct from SQL.
        let scope = c.original_scope_for_test().clone();
        manager
            .arm_singleton_device_welcome("test", &scope)
            .await
            .unwrap();
        let retained = c.snapshot().await.unwrap();
        assert_eq!(
            retained.phase,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending,
            "native observation must follow the original live guard after SDK custody moves"
        );
        assert!(
            retained.decimals.is_none(),
            "consumed comparison data must not be reconstructed"
        );
        assert!(manager.device_linking_capabilities().enrollment_supported);
        c.cancel().await.unwrap();
        assert_eq!(
            c.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::Cancelled
        );
        let fresh = manager.begin_device_linking_session("test").await.unwrap();
        assert!(
            c.cancel().await.is_err(),
            "old scope cannot cancel the fresh reservation"
        );
        assert_eq!(
            fresh.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::AwaitingSetup
        );
        fresh.cancel().await.unwrap();
        a.cancel().await.unwrap();
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn opaque_native_sessions_complete_real_sdk_with_revision_bound_human_actions() {
        let (_dirs, runtimes) = workers().await;
        let c = runtimes[1]
            .accounts()
            .begin_device_linking_session("test")
            .await
            .unwrap();
        assert_eq!(
            c.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::AwaitingSetup
        );
        let a = runtimes[0]
            .accounts()
            .approve_device_linking_session("test", c.setup_packet(), None)
            .await
            .unwrap();
        c.receive_setup_packet(a.setup_packet()).await.unwrap();
        assert!(c.receive_packet(vec![0; 600_000]).await.is_err());
        for _ in 0..8 {
            drain(&a, &c).await;
            drain(&c, &a).await;
        }
        let ac = a.snapshot().await.unwrap();
        let cc = c.snapshot().await.unwrap();
        assert_eq!(ac.phase, DeviceLinkingPhase::ComparisonAvailable);
        assert!(ac.decimals.is_some());
        assert_eq!(ac.decimals, cc.decimals);
        assert!(matches!(
            a.confirm_comparison(ac.revision + 1).await,
            Err(DeviceLinkingError::StaleRevision)
        ));
        assert_eq!(
            a.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::ComparisonAvailable
        );
        a.confirm_comparison(ac.revision).await.unwrap();
        c.confirm_comparison(cc.revision).await.unwrap();
        for _ in 0..8 {
            drain(&a, &c).await;
            drain(&c, &a).await;
        }
        assert_eq!(
            a.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending
        );
        assert_eq!(
            c.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::VerificationCompleteEnrollmentPending
        );
        assert!(
            runtimes[0]
                .accounts()
                .device_linking_capabilities()
                .enrollment_supported
        );
        a.continue_linking(a.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        a.cancel().await.unwrap();
        c.cancel().await.unwrap();
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn native_subscription_close_wakes_wait_and_exact_session_cancel_allows_new_attempt() {
        let (_dirs, runtimes) = workers().await;
        let manager = runtimes[1].accounts();
        let session = manager.begin_device_linking_session("test").await.unwrap();
        let subscription = Arc::new(session.subscribe());
        subscription.next().await.unwrap();
        let pending = {
            let sub = subscription.clone();
            tokio::spawn(async move { sub.next().await })
        };
        tokio::task::yield_now().await;
        subscription.close();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(2), pending)
                .await
                .unwrap()
                .unwrap(),
            Err(DeviceLinkingError::Closed)
        ));
        session.cancel().await.unwrap();
        assert!(matches!(
            session.outgoing_packets().await,
            Err(DeviceLinkingError::Closed)
        ));
        let next = manager.begin_device_linking_session("test").await.unwrap();
        assert_eq!(
            next.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::AwaitingSetup
        );
        next.cancel().await.unwrap();
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn native_drop_closes_observation_and_allows_fresh_original_purpose() {
        let (_dirs, runtimes) = workers().await;
        let manager = runtimes[1].accounts();
        let session = manager.begin_device_linking_session("test").await.unwrap();
        let old_setup = session.setup_packet();
        let subscription = session.subscribe();
        subscription.next().await.unwrap();
        drop(session);
        let closed = tokio::time::timeout(std::time::Duration::from_secs(2), subscription.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(closed.phase, DeviceLinkingPhase::Cancelled);
        assert!(closed.decimals.is_none());
        let next = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if let Ok(next) = manager.begin_device_linking_session("test").await {
                    break next;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_ne!(next.setup_packet(), old_setup);
        assert_eq!(
            next.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::AwaitingSetup
        );
        next.cancel().await.unwrap();
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn native_subscription_close_wakes_both_change_and_receiver_admission() {
        let (_dirs, runtimes) = workers().await;
        let session = runtimes[1]
            .accounts()
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let sub = Arc::new(session.subscribe());
        sub.next().await.unwrap();
        let first = {
            let sub = sub.clone();
            tokio::spawn(async move { sub.next().await })
        };
        tokio::task::yield_now().await;
        let second = {
            let sub = sub.clone();
            tokio::spawn(async move { sub.next().await })
        };
        tokio::task::yield_now().await;
        sub.close();
        for pending in [first, second] {
            assert!(matches!(
                tokio::time::timeout(std::time::Duration::from_secs(2), pending)
                    .await
                    .unwrap()
                    .unwrap(),
                Err(DeviceLinkingError::Closed)
            ));
        }
        assert_eq!(
            session.snapshot().await.unwrap().phase,
            DeviceLinkingPhase::AwaitingSetup
        );
        session.cancel().await.unwrap();
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn native_original_worker_expiry_cannot_revive_terminal_session() {
        let (_dirs, runtimes) = workers().await;
        let manager = runtimes[1].accounts();
        let session = manager.begin_device_linking_session("test").await.unwrap();
        let old_setup = session.setup_packet();
        manager
            .maintain_device_linking_at_for_test(
                "test",
                std::time::Instant::now() + std::time::Duration::from_secs(3600),
            )
            .await
            .unwrap();
        let terminal = session.snapshot().await.unwrap();
        assert!(matches!(
            terminal.phase,
            DeviceLinkingPhase::Expired
                | DeviceLinkingPhase::Cancelled
                | DeviceLinkingPhase::Failed
        ));
        assert!(terminal.decimals.is_none());
        assert!(matches!(
            session.confirm_comparison(terminal.revision).await,
            Err(DeviceLinkingError::Closed)
        ));
        assert!(matches!(
            session.outgoing_packets().await,
            Err(DeviceLinkingError::Closed)
        ));
        let next = manager.begin_device_linking_session("test").await.unwrap();
        assert_ne!(next.setup_packet(), old_setup);
        assert_eq!(session.snapshot().await.unwrap(), terminal);
        next.cancel().await.unwrap();
        for runtime in runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn native_shutdown_closes_original_session_without_a_new_worker() {
        let (_dirs, runtimes) = workers().await;
        let manager = runtimes[1].accounts();
        let session = manager.begin_device_linking_session("test").await.unwrap();
        runtimes[1].shutdown_and_close().await.unwrap();
        let terminal = session.snapshot().await.unwrap();
        assert!(matches!(
            terminal.phase,
            DeviceLinkingPhase::Cancelled | DeviceLinkingPhase::Failed
        ));
        assert!(matches!(
            session.continue_linking(terminal.revision).await,
            Err(DeviceLinkingError::Closed)
        ));
        assert!(manager.begin_device_linking_session("test").await.is_err());
        assert_eq!(session.snapshot().await.unwrap(), terminal);
        runtimes[0].shutdown_and_close().await.unwrap();
    }
}

#[cfg(all(
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
#[path = "sibling_sharing_acceptance.rs"]
mod sibling_sharing_acceptance;

#[cfg(all(
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
#[path = "sibling_sharing_routing_acceptance.rs"]
mod sibling_sharing_routing_acceptance;

#[cfg(all(
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
#[path = "automatic_records_acceptance.rs"]
mod automatic_records_acceptance;

#[cfg(all(
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
#[path = "automatic_forwarding_acceptance.rs"]
mod automatic_forwarding_acceptance;

#[cfg(all(
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
#[path = "automatic_forwarding_non_admin_acceptance.rs"]
mod automatic_forwarding_non_admin_acceptance;

#[cfg(all(
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
#[path = "sibling_sharing_projection_acceptance.rs"]
mod sibling_sharing_projection_acceptance;
