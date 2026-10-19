//! Account-owned source-qualified chat windows. Mirror wakes carry no authority.
use super::{ChatListWindowSnapshot, MarmotAppRuntime};
use crate::{AccountChatReadError, GroupId, PairedChatSummary, PresentedChatRow};
use tokio::sync::{mpsc, oneshot, watch};

#[derive(Clone)]
pub enum AccountChatRow {
    LocalMls(Box<PresentedChatRow>),
    PairedSource(Box<PairedChatSummary>),
}

#[derive(Clone)]
pub struct AccountChatListWindowSnapshot {
    pub generation: String,
    pub sequence: u64,
    /// Original ordinary window metadata/anchors remain explicitly local.
    pub local: ChatListWindowSnapshot,
    pub rows: Vec<AccountChatRow>,
    pub next_paired_group: Option<GroupId>,
}

#[cfg_attr(
    not(feature = "experimental-device-sync"),
    allow(
        dead_code,
        reason = "Worker command executes only in the experimental source-qualified actor"
    )
)]
struct Command {
    sequence: u64,
    after: Option<GroupId>,
    reply: oneshot::Sender<Result<AccountChatListWindowSnapshot, AccountChatReadError>>,
}

#[derive(Clone)]
pub struct AccountChatListWindowHandle {
    commands: mpsc::Sender<Command>,
    cancelled: watch::Sender<bool>,
}
impl AccountChatListWindowHandle {
    pub fn cancel(&self) {
        self.cancelled.send_replace(true);
    }
    pub async fn paired_page(
        &self,
        sequence: u64,
        after: Option<GroupId>,
    ) -> Result<AccountChatListWindowSnapshot, AccountChatReadError> {
        if *self.cancelled.borrow() {
            return Err(AccountChatReadError::Closed);
        }
        let (reply, receive) = oneshot::channel();
        self.commands
            .send(Command {
                sequence,
                after,
                reply,
            })
            .await
            .map_err(|_| AccountChatReadError::Closed)?;
        let result = receive.await.map_err(|_| AccountChatReadError::Closed)?;
        if *self.cancelled.borrow() {
            return Err(AccountChatReadError::Closed);
        }
        result
    }
}

pub struct RuntimeAccountChatListWindowSubscription {
    pub snapshot: AccountChatListWindowSnapshot,
    handle: AccountChatListWindowHandle,
    updates: watch::Receiver<Result<AccountChatListWindowSnapshot, AccountChatReadError>>,
    stopping: watch::Receiver<bool>,
    cancelled: watch::Receiver<bool>,
}
impl RuntimeAccountChatListWindowSubscription {
    pub fn window_handle(&self) -> AccountChatListWindowHandle {
        self.handle.clone()
    }
    pub async fn recv(
        &mut self,
    ) -> Result<Option<AccountChatListWindowSnapshot>, AccountChatReadError> {
        tokio::select! { biased;
            _ = super::wait_for_runtime_shutdown(&mut self.stopping) => Ok(None),
            _ = super::wait_for_runtime_shutdown(&mut self.cancelled) => Ok(None),
            result = self.updates.changed() => {
                if result.is_err() { return Ok(None); }
                self.updates.borrow_and_update().clone().map(Some)
            }
        }
    }
}

impl MarmotAppRuntime {
    /// Two bounded source lanes; combined retained rows never exceed requested
    /// count. Ordinary ordering/anchors remain ordinary; mirror cursor is separate.
    pub async fn open_account_chat_list_window(
        &self,
        account_ref: &str,
        initial_rows: u32,
    ) -> Result<RuntimeAccountChatListWindowSubscription, AccountChatReadError> {
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account_ref, initial_rows);
            Err(AccountChatReadError::Unsupported)
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            if !(2..=128).contains(&initial_rows) {
                return Err(AccountChatReadError::InvalidQuery);
            }
            self.shared
                .lifecycle()
                .ensure_running()
                .map_err(|_| AccountChatReadError::Closed)?;
            let account = self
                .accounts
                .resolve(account_ref)
                .map_err(|_| AccountChatReadError::RuntimeUnavailable)?;
            let account_id = account.account_id_hex;
            let label = account.label;
            // Every source is attached before either initial read.
            let mut mirror = self.accounts.app.presentation_signals.mirrored.subscribe();
            let mut resets = self
                .accounts
                .app
                .presentation_signals
                .account_resets
                .subscribe();
            let mut events = self.events.subscribe();
            let mut stopping = self.shared.lifecycle().subscribe_shutdown();
            let mut local = self
                .open_chat_list_window(
                    &label,
                    super::ChatListView::Chats,
                    Some((initial_rows / 2) as usize),
                )
                .await
                .map_err(|_| AccountChatReadError::RuntimeUnavailable)?;
            let manager = self.accounts.clone();
            let mirror_limit = initial_rows - initial_rows / 2;
            let page = manager
                .paired_chat_list_page(&label, None, mirror_limit)
                .await?;
            let generation = hex::encode(rand::random::<[u8; 16]>());
            let mut snapshot = compose(generation, 0, local.snapshot.clone(), page);
            // A concurrent reset/shutdown during initial read never publishes rows.
            if *stopping.borrow() || account_reset_pending(&mut resets, &label) {
                return Err(AccountChatReadError::Closed);
            }
            let (updates, rx) = watch::channel(Ok(snapshot.clone()));
            let (commands, mut command_rx) = mpsc::channel::<Command>(8);
            let (cancelled, mut cancellation) = watch::channel(false);
            let handle = AccountChatListWindowHandle {
                commands,
                cancelled,
            };
            let cancelled_rx = cancellation.clone();
            let initial = snapshot.clone();
            tokio::spawn(async move {
                let mut after = None;
                let mut refresh_failed = false;
                loop {
                    let expiry = if refresh_failed {
                        std::time::Duration::from_secs(1)
                    } else {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        paired_expiry_delay(&snapshot.rows, now)
                    };
                    let reply = tokio::select! { biased;
                        _=updates.closed()=>break,
                        _=super::wait_for_runtime_shutdown(&mut stopping)=>break,
                        _=super::wait_for_runtime_shutdown(&mut cancellation)=>break,
                        reset=resets.recv()=> {match reset {Ok(ref reset) if reset!=&label=>continue,_=>break}},
                        command=command_rx.recv()=> {let Some(command)=command else {break};
                            if command.sequence!=snapshot.sequence {let _=command.reply.send(Err(AccountChatReadError::StaleWindow));continue;}
                            after=command.after; Some(command.reply)
                        },
                        changed=local.recv()=> {match changed {Ok(Some(value))=>snapshot.local=value,_=>break};None},
                        changed=mirror.recv()=> {if changed.is_ok_and(|changed|changed!=label){continue;} None},
                        event=events.recv()=> {match event {
                            Ok(event) if !super::event_routing::chat_list_event_route(&event).is_some_and(|(account,_)|account==account_id)=>continue,
                            Err(tokio::sync::broadcast::error::RecvError::Closed)=>break,
                            _=>{},
                        } None},
                        _=tokio::time::sleep(expiry)=>None,
                    };
                    let result = manager
                        .paired_chat_list_page(&label, after.clone(), mirror_limit)
                        .await
                        .and_then(|page| {
                            if *stopping.borrow()
                                || *cancellation.borrow()
                                || account_reset_pending(&mut resets, &label)
                            {
                                return Err(AccountChatReadError::Closed);
                            }
                            let sequence = snapshot
                                .sequence
                                .checked_add(1)
                                .ok_or(AccountChatReadError::Closed)?;
                            Ok(compose(
                                snapshot.generation.clone(),
                                sequence,
                                snapshot.local.clone(),
                                page,
                            ))
                        });
                    let terminal = matches!(result, Err(AccountChatReadError::Closed));
                    refresh_failed = result.is_err();
                    if let Ok(ref replacement) = result {
                        snapshot = replacement.clone();
                    }
                    // An eligibility/read failure publishes an error, never a stale positive replacement.
                    let _ = updates.send(result.clone());
                    if let Some(reply) = reply {
                        let _ = reply.send(result);
                    }
                    if terminal {
                        break;
                    }
                }
                let _ = updates.send(Err(AccountChatReadError::Closed));
            });
            Ok(RuntimeAccountChatListWindowSubscription {
                snapshot: initial,
                handle,
                updates: rx,
                stopping: self.shared.lifecycle().subscribe_shutdown(),
                cancelled: cancelled_rx,
            })
        }
    }
}

#[cfg(feature = "experimental-device-sync")]
fn compose(
    generation: String,
    sequence: u64,
    local: ChatListWindowSnapshot,
    paired: crate::PairedChatListPage,
) -> AccountChatListWindowSnapshot {
    let mut rows = local
        .rows
        .iter()
        .cloned()
        .map(|row| AccountChatRow::LocalMls(Box::new(row)))
        .collect::<Vec<_>>();
    rows.extend(
        paired
            .chats
            .into_iter()
            .map(|row| AccountChatRow::PairedSource(Box::new(row))),
    );
    AccountChatListWindowSnapshot {
        generation,
        sequence,
        local,
        rows,
        next_paired_group: paired.next_group,
    }
}

#[cfg(feature = "experimental-device-sync")]
fn account_reset_pending(
    resets: &mut tokio::sync::broadcast::Receiver<String>,
    label: &str,
) -> bool {
    loop {
        match resets.try_recv() {
            Ok(reset) if reset == label => return true,
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => return false,
            Err(_) => return true,
        }
    }
}

/// Only displayed paired payloads need this timer. Ordinary rows retain their
/// own window's retention scheduling; scrubbed records must not cause a spin.
#[cfg(feature = "experimental-device-sync")]
fn paired_expiry_delay(rows: &[AccountChatRow], now: u64) -> std::time::Duration {
    let next = rows
        .iter()
        .filter_map(|row| match row {
            AccountChatRow::PairedSource(row) => row
                .latest_message
                .as_ref()
                .filter(|message| !message.deleted)
                .and_then(|message| {
                    message
                        .expires_at
                        .into_iter()
                        .chain(message.next_edit_expiry)
                        .min()
                }),
            AccountChatRow::LocalMls(_) => None,
        })
        .min();
    std::time::Duration::from_secs(
        next.map(|expiry| expiry.saturating_sub(now))
            .unwrap_or(86400),
    )
}

#[cfg(all(test, feature = "experimental-device-sync"))]
mod tests {
    use super::*;

    #[test]
    fn paired_chat_list_expiry_tracks_visible_payload_without_hidden_row_spin() {
        let source = crate::PairedChatSource {
            device: [1; 32],
            policy_digest: [2; 32],
            protected_generation: 1,
            source_epoch: 2,
            source_sequence: 3,
            source_digest: [4; 32],
        };
        let mut summary = PairedChatSummary {
            group_id: GroupId::new(vec![5; 16]),
            name: String::new(),
            description: String::new(),
            source: source.clone(),
            direct_peer_account: None,
            latest_message: Some(crate::PairedChatMessage {
                content_kind: crate::PairedChatContent::CanonicalChat,
                event_id: [6; 32],
                author: [7; 32],
                created_at: 1,
                expires_at: Some(20),
                deleted: false,
                content: "synthetic".into(),
                tags: Vec::new(),
                media_attachments: Vec::new(),
                edit: None,
                next_edit_expiry: None,
                source,
            }),
        };
        let delay = |summary: &PairedChatSummary, now| {
            paired_expiry_delay(
                &[AccountChatRow::PairedSource(Box::new(summary.clone()))],
                now,
            )
        };
        summary.latest_message.as_mut().unwrap().next_edit_expiry = Some(17);
        assert_eq!(delay(&summary, 15), std::time::Duration::from_secs(2));
        summary.latest_message.as_mut().unwrap().next_edit_expiry = None;
        assert_eq!(delay(&summary, 15), std::time::Duration::from_secs(5));
        assert_eq!(delay(&summary, 20), std::time::Duration::ZERO);
        assert_eq!(delay(&summary, 25), std::time::Duration::ZERO);
        let message = summary.latest_message.as_mut().unwrap();
        message.deleted = true;
        message.content.clear();
        assert_eq!(delay(&summary, 25), std::time::Duration::from_secs(86400));
        summary.latest_message = None;
        assert_eq!(delay(&summary, 25), std::time::Duration::from_secs(86400));
        assert_eq!(
            paired_expiry_delay(&[], 25),
            std::time::Duration::from_secs(86400)
        );
    }
}
