//! A real incoming ordinary chat; the paired bridge has no administrator grant.
use super::*;
use marmot_account::AccountHome;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_forwarding_reaches_independent_creator_through_non_admin_member() {
    actual::run_native_public_three_device_enrollment(
        actual::ApprovalScenario::AutomaticForwardingNonAdmin,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_nonadmin_leave_withdraws_mirrors_without_turning_local_hide_into_departure() {
    actual::run_native_public_three_device_enrollment(
        actual::ApprovalScenario::AutomaticWithdrawal,
    )
    .await;
}

pub(in crate::native_device_linking) struct IncomingPeer {
    _root: tempfile::TempDir,
    app: MarmotApp,
    pub(super) runtime: MarmotAppRuntime,
    pub(super) group: crate::GroupId,
    pub(super) preapproval_message: String,
}

impl IncomingPeer {
    pub(in crate::native_device_linking) async fn create(
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
                    .app_storage()
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
                    .app_storage()
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
        // Message projection precedes the later group/frontier checkpoint.
        // Require both real rows within the original restoration budget.
        let restoration = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let message_present = apps[0]
                    .account_storage("test")
                    .unwrap()
                    .app_storage()
                    .app_message(&group_hex, &fresh.message_ids[0])
                    .unwrap()
                    .is_some();
                if message_present && apps[0].group("test", &group_hex).unwrap().is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        #[cfg(feature = "test-policy-overrides")]
        {
            // Read only after the wait verdict is frozen; never extend its deadline.
            let storage = apps[0].account_storage("test").unwrap();
            let message_present = storage
                .app_storage()
                .app_message(&group_hex, &fresh.message_ids[0])
                .unwrap()
                .is_some();
            let group_present = apps[0].group("test", &group_hex).unwrap().is_some();
            let frontier_retained = storage
                .app_storage()
                .local_group_deletion_frontier(&group_hex)
                .unwrap()
                .is_some();
            crate::test_support::emit_line(format_args!(
                "local-hide-restoration-control message_present={} group_present={} frontier_retained={} wait_completed={}",
                message_present,
                group_present,
                frontier_retained,
                restoration.is_ok()
            ));
        }
        restoration
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
        eprintln!("withdrawal-control stage=source-runtime-constructed");
        let recipient = MarmotAppRuntime::new(MarmotApp::with_relay(roots[1], url));
        eprintln!("withdrawal-control stage=recipient-runtime-constructed");
        source.reconcile_accounts().await.unwrap();
        eprintln!("withdrawal-control stage=source-runtime-reconciled");
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

// A real unrelated ordinary publication; all identifiers stay inside this test module tree.
pub(in crate::native_device_linking) const ORDINARY_PROGRESS_TEXT: &str =
    "independent ordinary message after authenticated cancelled proof";

pub(in crate::native_device_linking) struct OrdinaryProgressPublication {
    pub(in crate::native_device_linking) group: crate::GroupId,
    pub(in crate::native_device_linking) app_id: Option<String>,
    pub(in crate::native_device_linking) packet_id: Option<String>,
    pub(in crate::native_device_linking) canonical_id: Option<String>,
    pub(in crate::native_device_linking) sender: String,
    pub(in crate::native_device_linking) published_once: bool,
    pub(in crate::native_device_linking) source_row_bound: bool,
}

impl IncomingPeer {
    pub(in crate::native_device_linking) async fn publish_ordinary_progress(
        &self,
    ) -> OrdinaryProgressPublication {
        use cgka_traits::storage::{MessageStorage, OutboundFanoutStorage};
        use sha2::{Digest, Sha256};
        // Observe this actual sender plane only. The callback captures no live
        // client/session, supplies no ACK, and retires after one bound application.
        let storage = self.app.account_storage("test").unwrap();
        let account = cgka_traits::MemberId::new(
            hex::decode(
                self.app
                    .account_home()
                    .account("test")
                    .unwrap()
                    .account_id_hex,
            )
            .unwrap(),
        );
        let group = self.group.clone();
        let binding = std::sync::Arc::new(std::sync::Mutex::new(None));
        let callback_binding = binding.clone();
        let observation = self
            .app
            .relay_plane
            .observe_publications_for_test(std::sync::Arc::new(move |request| {
                let bound = (|| -> Option<(String, String, String)> {
                    if request.account_id != account
                        || !matches!(&request.target,
                            cgka_traits::TransportPublishTarget::Group { group_id, .. }
                                if group_id == &group)
                        || request.validate_envelope_matches_target().is_err()
                    {
                        return None;
                    }
                    let fanout = storage.outbound_fanout(&request.message.id).ok()??;
                    let application = fanout.application_message()?;
                    if fanout.request() != request
                        || fanout.group_id() != Some(&group)
                        || application.group_id != group
                    {
                        return None;
                    }
                    // Applications have no pending_origin_message_id. Their
                    // own Sent record retains BOTH the exact outer and MLS wire.
                    let row = storage.get_message(&request.message.id).ok()?;
                    if row.id != request.message.id
                        || row.group_id != group
                        || row.epoch != application.source_epoch
                        || row.state != cgka_traits::message::MessageState::Sent
                    {
                        return None;
                    }
                    let payload =
                        cgka_traits::message::StoredMessagePayload::decode(&row.payload).ok()?;
                    if payload.as_exact_transport() != Some(&request.message)
                        || payload.own_application_stamp()?.sender != account
                    {
                        return None;
                    }
                    let wire = payload.as_openmls_wire()?;
                    let mut expected_wire = request.message.clone();
                    expected_wire.payload = wire.payload.clone();
                    if wire != &expected_wire {
                        return None;
                    }
                    Some((
                        application.app_event_id.clone(),
                        hex::encode(request.message.id.as_slice()),
                        hex::encode(Sha256::digest(&wire.payload)),
                    ))
                })();
                let Some(bound) = bound else {
                    return false;
                };
                *callback_binding.lock().unwrap() = Some(bound);
                true
            }));
        let sent = self
            .runtime
            .send_message(
                "test",
                &self.group,
                ORDINARY_PROGRESS_TEXT.as_bytes().to_vec(),
            )
            .await
            .unwrap();
        drop(observation);
        let observed = binding.lock().unwrap().take();
        let published_once = sent.published == 1 && sent.message_ids.len() == 1;
        let app_id = published_once.then(|| sent.message_ids[0].clone());
        let sender = self
            .app
            .account_home()
            .account("test")
            .unwrap()
            .account_id_hex;
        let group_hex = hex::encode(self.group.as_slice());
        // Raw projection and finalized timeline may become visible separately.
        // Wait for the exact real source mapping; absence remains a precondition
        // unknown and cannot manufacture an ordinary-receive timeout.
        let packet_id = if let Some(id) = app_id
            .as_ref()
            .filter(|id| *id != &self.preapproval_message)
        {
            tokio::time::timeout(std::time::Duration::from_secs(30), async {
                loop {
                    let storage = self.app.account_storage("test").unwrap();
                    let row = storage.app_storage().app_message(&group_hex, id).unwrap();
                    let timeline = storage
                        .app_storage()
                        .timeline_message(&group_hex, id)
                        .unwrap();
                    let packet = timeline
                        .as_ref()
                        .and_then(|row| row.source_message_id_hex.as_ref());
                    let canonical = packet.is_some_and(|packet| {
                        packet.len() == 64
                            && packet
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    });
                    let raw_bound = row.as_ref().is_some_and(|row| {
                        row.message_id_hex == *id
                            && row.group_id_hex == group_hex
                            && row.sender == sender
                            && row.direction == "sent"
                            && row.plaintext == ORDINARY_PROGRESS_TEXT
                            && !row.invalidated
                    });
                    let finalized = timeline.as_ref().is_some_and(|row| {
                        row.message_id_hex == *id
                            && row.group_id_hex == group_hex
                            && row.sender == sender
                            && row.direction == "sent"
                            && row.plaintext == ORDINARY_PROGRESS_TEXT
                            && !row.deleted
                            && canonical
                    });
                    if raw_bound && finalized {
                        break packet.unwrap().clone();
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .ok()
        } else {
            None
        };
        // The actual app result, exact frozen publication, sender's outer row
        // and carried MLS bytes must all name the same submission. Missing
        // evidence fails the existing prerequisite; no receive wait is invented.
        let canonical_id = observed.and_then(|(observed_app, outer, canonical)| {
            (app_id.as_ref() == Some(&observed_app) && packet_id.as_ref() == Some(&outer))
                .then_some(canonical)
        });
        let source_row_bound = packet_id.is_some() && canonical_id.is_some();
        OrdinaryProgressPublication {
            group: self.group.clone(),
            app_id,
            packet_id,
            canonical_id,
            sender,
            published_once,
            source_row_bound,
        }
    }

    pub(in crate::native_device_linking) async fn close_ordinary_progress_peer(
        &self,
    ) -> (bool, bool) {
        let closed =
            self.runtime.shutdown_and_close().await.is_ok() && self.runtime.storage_is_closed();
        self.app.relay_plane.shutdown().await;
        (closed, true)
    }
}
