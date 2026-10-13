//! Genuine authenticated Records held before SQL, then refused by a public cut.
//! Registered as an automatic child for private test access; no owner is minted.
use super::*;
use futures::FutureExt;
use std::{
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};

struct Held {
    released: bool,
    event: Option<GroupEvent>,
    nonce: Option<[u8; 32]>,
    batch: Option<[u8; 32]>,
    committed: bool,
}
struct Probe {
    root: PathBuf,
    source: [u8; 32],
    protected: crate::GroupId,
    ordinary: crate::GroupId,
    deadline: Instant,
    held: Mutex<Held>,
}
type Registry = BTreeMap<PathBuf, Weak<Probe>>;
fn registry() -> &'static Mutex<Registry> {
    static ROOTS: OnceLock<Mutex<Registry>> = OnceLock::new();
    ROOTS.get_or_init(Default::default)
}
impl Drop for Probe {
    fn drop(&mut self) {
        registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.root);
    }
}
fn current(root: &Path) -> Option<Arc<Probe>> {
    let weak = registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(root)
        .cloned();
    weak.and_then(|weak| weak.upgrade())
        .filter(|probe| Instant::now() < probe.deadline)
}
pub(crate) fn observe_authenticated_records(
    root: &Path,
    event: &GroupEvent,
    received: &cgka_engine::account_chat_sharing::ReceivedAccountSharingControl,
) {
    let Some(probe) = current(root) else { return };
    if !matches!(received.control, AccountSharingControl::Body(_))
        || received.signer.as_slice() != probe.source
    {
        return;
    }
    let GroupEvent::MessageReceived {
        group_id,
        source_leaf: Some(source),
        payload,
        ..
    } = event
    else {
        return;
    };
    if group_id != &probe.protected
        || source.signature_public_key.as_slice() != probe.source
        || payload.len() > 64 * 1024
    {
        return;
    }
    let mut held = probe.held.lock().unwrap_or_else(|e| e.into_inner());
    if !held.released && held.batch.is_none() {
        held.event = Some(event.clone());
        held.nonce = Some(received.nonce);
    }
}
pub(crate) fn hold_complete_records(
    root: &Path,
    group: &crate::GroupId,
    batch_digest: [u8; 32],
) -> bool {
    let Some(probe) = current(root) else {
        return false;
    };
    if group != &probe.ordinary {
        return false;
    }
    let mut held = probe.held.lock().unwrap_or_else(|e| e.into_inner());
    if held.released || held.event.is_none() {
        return false;
    }
    if held.batch.is_none() {
        held.batch = Some(batch_digest);
    }
    held.batch == Some(batch_digest)
}
pub(crate) fn observe_committed_record_receipt(root: &Path, batch_digest: [u8; 32]) {
    if let Some(probe) = current(root) {
        let mut held = probe.held.lock().unwrap_or_else(|e| e.into_inner());
        if held.batch == Some(batch_digest) {
            held.committed = true;
        }
    }
}

impl AppClient {
    pub(crate) async fn test_records_cut_does_not_block_peer_consent(
        roots: [&Path; 3],
        url: &str,
        ordinary_group: &crate::GroupId,
        source_event: &str,
    ) {
        let apps = roots.map(|root| crate::MarmotApp::with_relay(root, url));
        let mut clients = Vec::new();
        let mut gate: Option<Arc<Probe>> = None;
        let outcome = AssertUnwindSafe(async {
            for app in &apps {
                clients.push(app.client("test").await.unwrap());
            }
            for client in &mut clients {
                client.sync().await.unwrap();
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
            let ac = bilateral(&mut clients, &facts, 0, 2);
            let bc = bilateral(&mut clients, &facts, 1, 2);
            assert_eq!(ac[0].protected_group, bc[0].protected_group);
            assert!(
                bc[1].local_device < bc[0].local_device,
                "actual C lower signer required for B Consent witness"
            );
            let trace = consent_delivery_probe::arm(
                ac[0].account,
                ac[0].protected_group.clone(),
                [
                    consent_delivery_probe::Peer {
                        root: roots[0].to_owned(),
                        device: ac[0].local_device,
                    },
                    consent_delivery_probe::Peer {
                        root: roots[1].to_owned(),
                        device: bc[0].local_device,
                    },
                    consent_delivery_probe::Peer {
                        root: roots[2].to_owned(),
                        device: ac[1].local_device,
                    },
                ],
            );
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    for client in &mut clients {
                        client.sync().await.unwrap();
                        client.maintain_automatic_account_sharing().await.unwrap();
                    }
                    let rows = clients[2]
                        .current_mirrored_message_page(
                            ordinary_group,
                            None,
                            128,
                            crate::unix_now_seconds(),
                        )
                        .unwrap();
                    if rows.iter().any(|row| {
                        hex::encode(row.record.event_id) == source_event && !row.record.deleted
                    }) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("genuine accepted history before holding any Records");
            assert_eq!(
                clients[2]
                    .account_chat_departure_state(ordinary_group)
                    .unwrap()
                    .status,
                crate::AccountChatDepartureStatus::Available
            );
            let probe = Arc::new(Probe {
                root: roots[2].to_owned(),
                source: ac[0].local_device,
                protected: ac[0].protected_group.clone(),
                ordinary: ordinary_group.clone(),
                deadline: Instant::now() + Duration::from_secs(120),
                held: Mutex::new(Held {
                    released: false,
                    event: None,
                    nonce: None,
                    batch: None,
                    committed: false,
                }),
            });
            {
                let mut registry = registry().lock().unwrap_or_else(|e| e.into_inner());
                registry.retain(|_, weak| weak.strong_count() > 0);
                assert!(registry.len() < 8 && !registry.contains_key(roots[2]));
                registry.insert(roots[2].to_owned(), Arc::downgrade(&probe));
            }
            gate = Some(probe.clone());
            let sent = clients[0]
                .send(ordinary_group, b"actual Records cut witness")
                .await
                .unwrap();
            assert_eq!(sent.published, 1);
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    clients[0].sync().await.unwrap();
                    clients[0]
                        .maintain_automatic_account_sharing()
                        .await
                        .unwrap();
                    let result = clients[2].sync().await;
                    if probe
                        .held
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .batch
                        .is_some()
                    {
                        assert!(result.is_err());
                        break;
                    }
                    result.unwrap();
                    clients[2]
                        .maintain_automatic_account_sharing()
                        .await
                        .unwrap();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("real complete A Records occupies projection retry head");
            let cut = clients[2].leave_account_chat(ordinary_group).await.unwrap();
            assert_eq!(cut.status, crate::AccountChatDepartureStatus::Pending);
            assert!(cut.operation_id.is_some());
            let id_c = Self::automatic_policy_id(&bc[1]).unwrap();
            clients[2]
                .begin_automatic_channel(bc[1].clone(), None)
                .unwrap();
            tick(&mut clients[2], id_c).await;
            let nonce = clients[2].account_sharing_owner.automatic[&id_c]
                .channel
                .scope()
                .nonce;
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    clients[1].sync().await.unwrap();
                    clients[1]
                        .maintain_automatic_account_sharing()
                        .await
                        .unwrap();
                    if trace.snapshot().records.iter().any(|row| {
                        row.publication.local_device == bc[0].local_device
                            && row.publication.peer_device == bc[1].local_device
                            && row.publication.nonce == nonce
                    }) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("actual B Consent published behind held Records");
            probe
                .held
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .released = true;
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    let result = clients[2].sync().await;
                    if result.is_ok() {
                        clients[2]
                            .maintain_automatic_account_sharing()
                            .await
                            .unwrap();
                    }
                    if trace.snapshot().records.iter().any(|row| {
                        row.publication.local_device == bc[0].local_device
                            && row.publication.peer_device == bc[1].local_device
                            && row.publication.nonce == nonce
                            && row.authenticated_nonce_matches
                            && row.automatic_matched
                            && row.consent_bound
                    }) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("permanent cut refusal cannot block actual later B Consent bind");
            assert!(
                !probe
                    .held
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .committed,
                "refused actual batch must not manufacture committed receipt"
            );
            let final_cut = clients[2]
                .account_chat_departure_state(ordinary_group)
                .unwrap();
            assert_eq!(final_cut.operation_id, cut.operation_id);
            assert_ne!(
                final_cut.status,
                crate::AccountChatDepartureStatus::Available
            );
            assert!(
                clients[2]
                    .current_mirrored_message_page(
                        ordinary_group,
                        None,
                        128,
                        crate::unix_now_seconds()
                    )
                    .unwrap()
                    .is_empty()
            );
            eprintln!(
                "records_cut_actual_negative_retained_no_receipt_and_later_consent_bound=true"
            );
        })
        .catch_unwind()
        .await;
        drop(gate);
        drop(clients);
        let mut close_failed = false;
        for app in &apps {
            let result = app.close_storage();
            close_failed |= result.is_err() || !app.storage_is_closed();
        }
        eprintln!("records_cut_three_positive_closes={}", !close_failed);
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
        assert!(!close_failed, "all same-root owners must positively close");
    }
}

fn bilateral(
    clients: &mut [AppClient],
    facts: &[Vec<ApprovedAccountSharingPolicy>],
    a: usize,
    b: usize,
) -> [ApprovedAccountSharingPolicy; 2] {
    for left in &facts[a] {
        for right in &facts[b] {
            if left.revoked
                || right.revoked
                || left.account != right.account
                || left.protected_group != right.protected_group
                || left.local_device != right.peer_device
                || left.peer_device != right.local_device
                || left.approval_id != right.approval_id
            {
                continue;
            }
            for index in [a, b] {
                let policy = if index == a { left } else { right };
                if matches!(
                    clients[index]
                        .runtime
                        .session()
                        .account_chat_sharing_targets(&policy.protected_group),
                    Err(cgka_traits::EngineError::GroupNotHydrated(_))
                ) {
                    assert!(
                        clients[index]
                            .runtime
                            .session_mut()
                            .ensure_group_hydrated(&policy.protected_group)
                            .unwrap()
                    );
                }
            }
            if clients[a].automatic_policy_current(left).is_ok()
                && clients[b].automatic_policy_current(right).is_ok()
            {
                return [left.clone(), right.clone()];
            }
        }
    }
    panic!("actual current bilateral approved policies required");
}
async fn tick(client: &mut AppClient, id: [u8; 32]) {
    let mut entry = client
        .account_sharing_owner
        .automatic
        .remove(&id)
        .expect("actual original channel");
    let result = client.automatic_sharing_tick(&mut entry).await;
    client.account_sharing_owner.automatic.insert(id, entry);
    result.unwrap();
}
