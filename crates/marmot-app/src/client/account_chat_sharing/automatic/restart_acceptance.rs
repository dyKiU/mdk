//! Source-only regression fixture: delay a genuine higher-device Request past
//! the lower-device Request's actual Consent. No permission DTO is constructed.
use super::*;
use futures_util::FutureExt;
use std::{
    panic::AssertUnwindSafe,
    path::PathBuf,
    sync::{Mutex, OnceLock},
    time::Duration,
};

type Retained = (
    cgka_engine::account_chat_sharing::ReceivedAccountSharingControl,
    Vec<u8>,
);
type HeldMap = BTreeMap<PathBuf, ([u8; 32], Option<Retained>)>;
fn held() -> &'static Mutex<HeldMap> {
    static HELD: OnceLock<Mutex<HeldMap>> = OnceLock::new();
    HELD.get_or_init(|| Mutex::new(BTreeMap::new()))
}

struct Hold(PathBuf);
impl Drop for Hold {
    fn drop(&mut self) {
        held()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.0);
    }
}

impl AppClient {
    /// Parent intake calls this only in test+policy builds. The event already
    /// came through genuine MLS delivery; authenticate it before retaining it.
    pub(crate) fn test_defer_delayed_higher_request(
        &self,
        wire: &[u8],
        received: cgka_engine::account_chat_sharing::ReceivedAccountSharingControl,
    ) -> Option<cgka_engine::account_chat_sharing::ReceivedAccountSharingControl> {
        let root = self.app.account_home().root().to_owned();
        if !held().lock().unwrap().contains_key(&root)
            || wire.len() > 64 * 1024
            || received.control != AccountSharingControl::Request
        {
            return Some(received);
        }
        let Ok(request) = self
            .runtime
            .session()
            .authenticate_account_sharing_request(wire)
        else {
            return Some(received);
        };
        if request.scope().source <= request.scope().recipient {
            return Some(received);
        }
        let mut guard = held().lock().unwrap();
        let Some((expected_nonce, slot)) = guard.get_mut(&root) else {
            return Some(received);
        };
        if received.nonce != *expected_nonce {
            return Some(received);
        }
        // One retained real authenticated observation only; no DTO is minted.
        if slot.is_none() {
            *slot = Some((received, wire.to_vec()));
        }
        None
    }

    /// Call only after the public broad-pairing fixture has positively closed
    /// both managed owners. Same-root reopening restores data, never an owner.
    pub(crate) async fn test_delayed_higher_request_collision(
        roots: [&std::path::Path; 2],
        url: &str,
        ordinary_group: &crate::GroupId,
        source_event: &str,
    ) {
        let apps = roots.map(|root| crate::MarmotApp::with_relay(root, url));
        let mut clients = Vec::new();
        let outcome = AssertUnwindSafe(async {
            clients.push(apps[0].client("test").await.unwrap());
            clients.push(apps[1].client("test").await.unwrap());
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
            let pair = facts[0]
                .iter()
                .find_map(|a| {
                    facts[1]
                        .iter()
                        .find(|b| {
                            !a.revoked
                                && !b.revoked
                                && a.local_device == b.peer_device
                                && a.peer_device == b.local_device
                                && a.approval_id == b.approval_id
                        })
                        .map(|b| [a.clone(), b.clone()])
                })
                .expect("actual bilateral approved policy");
            let lower = usize::from(pair[0].local_device > pair[1].local_device);
            let higher = 1 - lower;
            let ids = pair
                .each_ref()
                .map(|policy| Self::automatic_policy_id(policy).unwrap());
            let root = roots[lower].to_owned();

            let _hold = Hold(root.clone());
            for i in 0..2 {
                clients[i]
                    .begin_automatic_channel(pair[i].clone(), None)
                    .unwrap();
            }
            let original_lower = clients[lower].account_sharing_owner.automatic[&ids[lower]]
                .channel
                .scope()
                .nonce;
            let original_higher = clients[higher].account_sharing_owner.automatic[&ids[higher]]
                .channel
                .scope()
                .nonce;
            assert!(held().lock().unwrap().len() < 8);
            assert!(
                held()
                    .lock()
                    .unwrap()
                    .insert(root.clone(), (original_higher, None))
                    .is_none()
            );
            // Real Core Request Y is frozen and published before X. Only its
            // received decrypted GroupEvent is held, not the transport ratchet.
            tick(&mut clients[higher], ids[higher]).await;
            tick(&mut clients[lower], ids[lower]).await;
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    clients[lower].sync().await.unwrap();
                    clients[higher].sync().await.unwrap();
                    tick(&mut clients[higher], ids[higher]).await;
                    clients[lower].sync().await.unwrap();
                    if clients[lower].account_sharing_owner.automatic[&ids[lower]].ready
                        && held().lock().unwrap()[&root].1.is_some()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("actual Consent X bound while authenticated Y remains held");
            assert_eq!(
                clients[lower].account_sharing_owner.automatic[&ids[lower]]
                    .channel
                    .scope()
                    .nonce,
                original_lower
            );
            assert!(!clients[lower].account_sharing_owner.automatic[&ids[lower]].recipient);
            let (delayed, wire) = held().lock().unwrap().remove(&root).unwrap().1.unwrap();
            // Same actual received observation and signed bytes reach ordinary
            // authenticated dispatch; the original Core proof was not fabricated.
            clients[lower]
                .dispatch_authenticated_account_sharing_control(&delayed, &wire)
                .unwrap();
            let renewed = &clients[lower].account_sharing_owner.automatic[&ids[lower]];
            assert!(!renewed.recipient && !renewed.ready);
            assert_ne!(renewed.channel.scope().nonce, original_lower);
            let fresh_nonce = renewed.channel.scope().nonce;
            assert!(
                apps[0]
                    .account_storage("test")
                    .unwrap()
                    .timeline_message(&hex::encode(ordinary_group.as_slice()), source_event)
                    .unwrap()
                    .is_some_and(|row| !row.deleted && row.invalidation_status.is_none())
            );
            let sent = clients[0]
                .send(ordinary_group, b"fresh ordinary collision witness")
                .await
                .unwrap();
            assert_eq!(sent.published, 1);
            assert_eq!(sent.message_ids.len(), 1);
            let witness = &sent.message_ids[0];
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            tokio::time::timeout(Duration::from_secs(60), async {
                loop {
                    for i in 0..2 {
                        clients[i].sync().await.unwrap();
                        tick(&mut clients[i], ids[i]).await;
                    }
                    let low = &clients[lower].account_sharing_owner.automatic[&ids[lower]];
                    let high = &clients[higher].account_sharing_owner.automatic[&ids[higher]];
                    let record = ready_rows(clients[1].current_mirrored_message_page(
                        ordinary_group,
                        None,
                        128,
                        now,
                    ))
                    .iter()
                    .any(|row| {
                        hex::encode(row.record.event_id) == *witness
                            && !row.record.deleted
                            && !row.record.payload.is_empty()
                    });
                    let catalog = ready_rows(clients[1].current_mirrored_catalog_page(None, 128))
                        .iter()
                        .any(|row| {
                            row.entry.group_id == *ordinary_group
                                && row.entry.state == MirroredChatState::Active
                        });
                    if low.ready
                        && high.ready
                        && !low.recipient
                        && high.recipient
                        && low.channel.scope().nonce == fresh_nonce
                        && high.channel.scope().nonce == fresh_nonce
                        && catalog
                        && record
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("fresh canonical lower Request reaches genuine catalog and record delivery");
        })
        .catch_unwind()
        .await;
        drop(clients);
        let mut failed_close = false;
        for app in &apps {
            failed_close |= app.close_storage().is_err() || !app.storage_is_closed();
        }
        eprintln!("collision_fixture_positive_closes={}", !failed_close);
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
        assert!(
            !failed_close,
            "collision fixture requires both positive storage closes"
        );
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
        Err(_) => panic!("unexpected typed sharing query failure"),
    }
}
