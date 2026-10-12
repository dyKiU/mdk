//! Actual stalled-handshake restart regression. The higher owner approves X,
//! closes before Consent publication, then reopens the same store and sends Y.
use super::*;
use cgka_traits::storage::MessageStorage;
use futures::FutureExt;
use std::{panic::AssertUnwindSafe, time::Duration};

impl AppClient {
    pub(crate) async fn test_pending_lower_request_survives_higher_restart(
        roots: [&std::path::Path; 2],
        url: &str,
        ordinary_group: &crate::GroupId,
        source_event: &str,
    ) {
        let mut apps = roots.map(|root| crate::MarmotApp::with_relay(root, url));
        let mut clients: [Option<AppClient>; 2] = std::array::from_fn(|_| None);
        let outcome = AssertUnwindSafe(async {
            for i in 0..2 { clients[i] = Some(apps[i].client("test").await.unwrap()); }
            for client in &mut clients { client.as_mut().unwrap().sync().await.unwrap(); }
            let facts: Vec<_> = apps.iter().map(|app| app.account_storage("test").unwrap()
                .approved_account_sharing_policy_storage().unwrap()
                .approved_account_sharing_policies().unwrap()).collect();
            let mut pair = None;
            for a in &facts[0] {
                for b in &facts[1] {
                    if a.revoked || b.revoked || a.account != b.account
                        || a.protected_group != b.protected_group
                        || a.local_device != b.peer_device || a.peer_device != b.local_device
                        || a.approval_id != b.approval_id { continue; }
                    if current_policy_ready(clients[0].as_mut().unwrap(), a)
                        && current_policy_ready(clients[1].as_mut().unwrap(), b) {
                        pair = Some([a.clone(), b.clone()]);
                        break;
                    }
                }
                if pair.is_some() { break; }
            }
            let pair = pair.expect("actual current bilateral Core-qualified policy required before request creation");
            let lower = usize::from(pair[0].local_device > pair[1].local_device);
            let higher = 1 - lower;
            let ids = pair.each_ref().map(|policy| Self::automatic_policy_id(policy).unwrap());
            clients[lower].as_mut().unwrap().begin_automatic_channel(pair[lower].clone(), None).unwrap();
            let original_x = clients[lower].as_ref().unwrap().account_sharing_owner.automatic[&ids[lower]].channel.scope().nonce;
            let before_retry = std::time::Instant::now();
            tick(clients[lower].as_mut().unwrap(), ids[lower]).await;
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    clients[higher].as_mut().unwrap().sync().await.unwrap();
                    if clients[higher].as_ref().unwrap().account_sharing_owner.automatic.get(&ids[higher])
                        .is_some_and(|entry| entry.recipient && !entry.ready
                            && !entry.handshake_published && entry.channel.scope().nonce == original_x) { break; }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }).await.expect("actual higher Core approval of X before any Consent publication");
            let low = &clients[lower].as_ref().unwrap().account_sharing_owner.automatic[&ids[lower]];
            assert!(!low.recipient && !low.ready && low.handshake_published && low.original.live());
            assert_eq!(low.channel.scope().nonce, original_x);
            drop(clients[higher].take());
            let higher_closed = apps[higher].close_storage().is_ok() && apps[higher].storage_is_closed();
            eprintln!("pending_restart_first_higher_positive_close={higher_closed}");
            assert!(higher_closed);
            apps[higher] = crate::MarmotApp::with_relay(roots[higher], url);
            clients[higher] = Some(apps[higher].client("test").await.unwrap());
            assert!(current_policy_ready(clients[higher].as_mut().unwrap(), &pair[higher]), "same-root restarted higher must retain actual current Core-qualified policy");
            clients[higher].as_mut().unwrap().begin_automatic_channel(pair[higher].clone(), None).unwrap();
            tick(clients[higher].as_mut().unwrap(), ids[higher]).await;
            let actual_y_content = clients[higher].as_ref().unwrap().account_sharing_owner.automatic[&ids[higher]]
                .channel.outbound_content_id_for_test(AccountSharingControl::Request).expect("actual published Y canonical content");
            tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    clients[lower].as_mut().unwrap().sync().await.unwrap();
                    let processed = apps[lower].account_storage("test").unwrap().get_message(&actual_y_content)
                        .is_ok_and(|row| row.state == cgka_traits::message::MessageState::Processed);
                    if processed { break; }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }).await.expect("fresh actual Y reached lower through canonical MLS delivery before retry boundary");
            assert!(before_retry.elapsed() < Duration::from_secs(10), "fresh Y must be observed before the actual retry boundary");
            let low = &clients[lower].as_ref().unwrap().account_sharing_owner.automatic[&ids[lower]];
            assert_eq!(low.channel.scope().nonce, original_x);
            assert!(!low.recipient && !low.ready && low.original.live());
            clients[lower].as_ref().unwrap().runtime.session().validate_account_sharing_channel(&low.channel).unwrap();
            eprintln!("pending_restart_authenticated_y_retained_exact_live_x=true");
            let fresh_nonce = tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    for i in 0..2 {
                        clients[i].as_mut().unwrap().sync().await.unwrap();
                        clients[i].as_mut().unwrap().maintain_automatic_account_sharing().await.unwrap();
                    }
                    let low = &clients[lower].as_ref().unwrap().account_sharing_owner.automatic[&ids[lower]];
                    let high = &clients[higher].as_ref().unwrap().account_sharing_owner.automatic[&ids[higher]];
                    if low.channel.scope().nonce != original_x && low.ready && !low.recipient
                        && high.ready && high.recipient && low.channel.scope().nonce == high.channel.scope().nonce {
                        break low.channel.scope().nonce;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }).await.expect("stalled lower handshake must renew through fresh actual X2 and Consent");
            assert_ne!(fresh_nonce, original_x);
            assert!(apps[0].account_storage("test").unwrap()
                .timeline_message(&hex::encode(ordinary_group.as_slice()), source_event).unwrap()
                .is_some_and(|row| !row.deleted && row.invalidation_status.is_none()));
            let sent = clients[0].as_mut().unwrap().send(ordinary_group, b"ordinary witness after pending-owner restart").await.unwrap();
            assert_eq!(sent.published, 1);
            assert_eq!(sent.message_ids.len(), 1);
            let witness = &sent.message_ids[0];
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    for client in &mut clients {
                        client.as_mut().unwrap().sync().await.unwrap();
                        client.as_mut().unwrap().maintain_automatic_account_sharing().await.unwrap();
                    }
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                    let recipient = clients[1].as_ref().unwrap();
                    let record = ready_rows(recipient.current_mirrored_message_page(ordinary_group, None, 128, now))
                        .iter().any(|row| hex::encode(row.record.event_id) == *witness && !row.record.deleted && !row.record.payload.is_empty());
                    let catalog = ready_rows(recipient.current_mirrored_catalog_page(None, 128)).iter()
                        .any(|row| row.entry.group_id == *ordinary_group && row.entry.state == MirroredChatState::Active);
                    if catalog && record { break; }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }).await.expect("fresh restarted channel must deliver genuine ordinary catalog and canonical record");
        }).catch_unwind().await;
        drop(clients);
        let mut all_closed = true;
        for app in &apps {
            all_closed &= app.close_storage().is_ok() && app.storage_is_closed();
        }
        eprintln!("pending_restart_final_positive_closes={all_closed}");
        if let Err(original) = outcome {
            std::panic::resume_unwind(original);
        }
        assert!(all_closed, "all fixture owners must positively close");
    }
}

async fn tick(client: &mut AppClient, id: [u8; 32]) {
    let mut entry = client
        .account_sharing_owner
        .automatic
        .remove(&id)
        .expect("actual channel");
    let result = client.automatic_sharing_tick(&mut entry).await;
    client.account_sharing_owner.automatic.insert(id, entry);
    result.unwrap();
}
fn ready_rows<T>(result: Result<Vec<T>, AccountSharingError>) -> Vec<T> {
    match result {
        Ok(rows) => rows,
        Err(AccountSharingError::NotReady) => Vec::new(),
        Err(_) => panic!("unexpected typed sharing query error"),
    }
}

// Observation first preserves the actual Core error category that the App
// eligibility adapter otherwise maps to Closed. Only cheap-open hydration is
// retried through Core's supported stored-state hydration entry point.
fn current_policy_ready(client: &mut AppClient, policy: &ApprovedAccountSharingPolicy) -> bool {
    use cgka_traits::EngineError;
    let first = client
        .runtime
        .session()
        .account_chat_sharing_targets(&policy.protected_group);
    if matches!(first, Err(EngineError::GroupNotHydrated(_))) {
        eprintln!("pending_restart_core_targets_hydration_required=true");
        match client
            .runtime
            .session_mut()
            .ensure_group_hydrated(&policy.protected_group)
        {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("pending_restart_core_hydration_quarantined=true");
                return false;
            }
            Err(_) => panic!(
                "actual protected group hydration backend failed before request construction"
            ),
        }
    } else if let Err(error) = first {
        eprintln!(
            "pending_restart_core_targets_refusal={}",
            error.privacy_safe_kind()
        );
        if matches!(error, EngineError::Storage(_) | EngineError::Backend(_)) {
            panic!("backend failure cannot masquerade as policy ineligibility");
        }
        return false;
    }
    match client
        .runtime
        .session()
        .account_chat_sharing_targets(&policy.protected_group)
    {
        Ok(targets)
            if targets.protected_epoch >= policy.approved_protected_epoch
                && targets
                    .targets
                    .iter()
                    .any(|target| target.device == policy.peer_device) => {}
        Ok(_) => return false,
        Err(error) => {
            eprintln!(
                "pending_restart_fresh_core_targets_refusal={}",
                error.privacy_safe_kind()
            );
            if matches!(error, EngineError::Storage(_) | EngineError::Backend(_)) {
                panic!("fresh target backend failure cannot become an absent policy");
            }
            return false;
        }
    }
    match client.automatic_policy_current(policy) {
        Ok(()) => true,
        Err(AccountSharingError::Closed | AccountSharingError::NotReady) => false,
        Err(_) => panic!("unexpected typed policy query error before request construction"),
    }
}
