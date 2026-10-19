//! Source-qualified bounded conversation owner; local authority is never synthesized.
use super::MarmotAppRuntime;
#[cfg(feature = "experimental-device-sync")]
use super::RuntimeConversationWindowSubscription;
#[cfg(feature = "experimental-device-sync")]
use crate::AccountConversationPage;
use crate::{
    AccountChatReadError, AccountConversationRow, GroupId, PairedChatMessageCursor,
    PairedChatSummary,
};
use tokio::sync::{mpsc, oneshot, watch};

#[derive(Clone)]
pub struct LocalAccountConversationHeader {
    pub revision: super::ConversationWindowRevision,
    pub presentation: crate::conversation_presentation::ConversationWindowPresentation,
    pub read_state: super::ConversationOpenReadState,
    pub draft: crate::SelectedMessageDraft,
    pub pending_confirmation: bool,
}
#[derive(Clone)]
pub enum AccountConversationHeader {
    LocalMls(Box<LocalAccountConversationHeader>),
    PairedSource(Box<PairedChatSummary>),
}
#[derive(Clone)]
pub struct AccountConversationWindowSnapshot {
    pub generation: String,
    pub sequence: u64,
    pub header: AccountConversationHeader,
    pub rows: Vec<AccountConversationRow>,
    pub next_before: Option<PairedChatMessageCursor>,
}
#[cfg_attr(
    not(feature = "experimental-device-sync"),
    allow(dead_code, reason = "Experimental worker command")
)]
struct Command {
    sequence: u64,
    before: Option<PairedChatMessageCursor>,
    reply: oneshot::Sender<Result<AccountConversationWindowSnapshot, AccountChatReadError>>,
}
#[derive(Clone)]
pub struct AccountConversationWindowHandle {
    commands: mpsc::Sender<Command>,
    cancelled: watch::Sender<bool>,
}
impl AccountConversationWindowHandle {
    pub fn cancel(&self) {
        self.cancelled.send_replace(true);
    }
    pub async fn older_page(
        &self,
        sequence: u64,
        before: Option<PairedChatMessageCursor>,
    ) -> Result<AccountConversationWindowSnapshot, AccountChatReadError> {
        if *self.cancelled.borrow() {
            return Err(AccountChatReadError::Closed);
        }
        let (reply, receive) = oneshot::channel();
        self.commands
            .send(Command {
                sequence,
                before,
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
pub struct RuntimeAccountConversationWindowSubscription {
    pub snapshot: AccountConversationWindowSnapshot,
    handle: AccountConversationWindowHandle,
    updates: watch::Receiver<Result<AccountConversationWindowSnapshot, AccountChatReadError>>,
    cancelled: watch::Receiver<bool>,
    stopping: watch::Receiver<bool>,
}
impl RuntimeAccountConversationWindowSubscription {
    pub fn window_handle(&self) -> AccountConversationWindowHandle {
        self.handle.clone()
    }
    pub async fn recv(
        &mut self,
    ) -> Result<Option<AccountConversationWindowSnapshot>, AccountChatReadError> {
        tokio::select! {biased;
          _=super::wait_for_runtime_shutdown(&mut self.stopping)=>Ok(None),
          _=super::wait_for_runtime_shutdown(&mut self.cancelled)=>Ok(None),
          changed=self.updates.changed()=> {
            if changed.is_err(){return Ok(None);}
            self.updates.borrow_and_update().clone().map(Some)
          }
        }
    }
}
impl MarmotAppRuntime {
    pub async fn open_account_conversation_window(
        &self,
        account_ref: &str,
        group: &GroupId,
        initial_rows: u32,
    ) -> Result<RuntimeAccountConversationWindowSubscription, AccountChatReadError> {
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account_ref, group, initial_rows);
            Err(AccountChatReadError::Unsupported)
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            if !(1..=128).contains(&initial_rows) {
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
            let label = account.label;
            let account_id = account.account_id_hex;
            let group = group.clone();
            let mut mirror = self.accounts.app.presentation_signals.mirrored.subscribe();
            let mut resets = self
                .accounts
                .app
                .presentation_signals
                .account_resets
                .subscribe();
            let mut events = self.events.subscribe();
            let mut stopping = self.shared.lifecycle().subscribe_shutdown();
            let manager = self.accounts.clone();
            let page = manager
                .account_conversation_page(&label, group.clone(), None, initial_rows)
                .await?;
            let mut local = if page.local_group {
                Some(
                    self.open_conversation_window(
                        &label,
                        &group,
                        super::ConversationOpenQuery {
                            target: super::ConversationOpenTarget::Latest,
                            limit: 1,
                        },
                    )
                    .await
                    .map_err(|_| AccountChatReadError::NotReady)?,
                )
            } else {
                None
            };
            // Opening the genuine ordinary authority owner may await; read the
            // source-qualified page again after that await before publishing.
            let page = if local.is_some() {
                manager
                    .account_conversation_page(&label, group.clone(), None, initial_rows)
                    .await?
            } else {
                page
            };
            let generation = hex::encode(rand::random::<[u8; 16]>());
            let mut snapshot = compose(generation, 0, page, local.as_ref())?;
            if *stopping.borrow() || reset_pending(&mut resets, &label) {
                return Err(AccountChatReadError::Closed);
            }
            let (updates, rx) = watch::channel(Ok(snapshot.clone()));
            let (commands, mut command_rx) = mpsc::channel::<Command>(8);
            let (cancelled, mut cancellation) = watch::channel(false);
            let handle = AccountConversationWindowHandle {
                commands,
                cancelled,
            };
            let cancelled = handle.cancelled.subscribe();
            let initial_snapshot = snapshot.clone();
            let subscription_stopping = stopping.clone();
            tokio::spawn(async move {
                let mut before = None;
                let mut refresh_failed = false;
                loop {
                    // A failed read must not repeatedly poll an overdue retained snapshot.
                    let expiry = if refresh_failed {
                        std::time::Duration::from_secs(1)
                    } else {
                        expiry_delay(&snapshot)
                    };
                    let mut reply = None;
                    tokio::select! {
                      _=updates.closed()=>break,
                      _=super::wait_for_runtime_shutdown(&mut stopping)=>break,
                      _=cancellation.changed()=>break,
                      reset=resets.recv()=>match reset {Ok(value) if value==label=>break,Err(_)=>break,_=>continue},
                      command=command_rx.recv()=> {
                        let Some(command)=command else {break};
                        if command.sequence!=snapshot.sequence{let _=command.reply.send(Err(AccountChatReadError::StaleWindow));continue;}
                        before=command.before;reply=Some(command.reply);
                      },
                      observed=local_changed(&mut local)=>{if observed.is_err(){break;}},
                      notification=mirror.recv()=>match notification{Ok(value) if value!=label=>continue,_=>{}},
                      event=events.recv()=>match event {
                        Ok(event)=>if super::event_routing::chat_list_event_route(&event).is_none_or(|(id,g)|id!=account_id || *g!=group){continue;},
                        Err(tokio::sync::broadcast::error::RecvError::Closed)=>break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_))=>{},
                      },
                      _=tokio::time::sleep(expiry)=>{},
                    }
                    let result = async {
                        let page = manager
                            .account_conversation_page(
                                &label,
                                group.clone(),
                                before.clone(),
                                initial_rows,
                            )
                            .await?;
                        if *cancellation.borrow()
                            || *stopping.borrow()
                            || reset_pending(&mut resets, &label)
                        {
                            return Err(AccountChatReadError::Closed);
                        }
                        let sequence = snapshot
                            .sequence
                            .checked_add(1)
                            .ok_or(AccountChatReadError::Closed)?;
                        compose(snapshot.generation.clone(), sequence, page, local.as_ref())
                    }
                    .await;
                    let terminal = matches!(result, Err(AccountChatReadError::Closed));
                    refresh_failed = result.is_err();
                    if let Ok(value) = &result {
                        snapshot = value.clone();
                    }
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
            Ok(RuntimeAccountConversationWindowSubscription {
                snapshot: initial_snapshot,
                handle,
                updates: rx,
                cancelled,
                stopping: subscription_stopping,
            })
        }
    }
}
#[cfg(feature = "experimental-device-sync")]
async fn local_changed(
    local: &mut Option<RuntimeConversationWindowSubscription>,
) -> Result<(), AccountChatReadError> {
    let Some(local) = local else {
        return std::future::pending().await;
    };
    match local
        .recv()
        .await
        .map_err(|_| AccountChatReadError::Closed)?
    {
        Some(snapshot) => {
            local.snapshot = snapshot;
            Ok(())
        }
        None => Err(AccountChatReadError::Closed),
    }
}
#[cfg(feature = "experimental-device-sync")]
fn reset_pending(receiver: &mut tokio::sync::broadcast::Receiver<String>, label: &str) -> bool {
    loop {
        match receiver.try_recv() {
            Ok(value) if value == label => return true,
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => return false,
            Err(_) => return true,
        }
    }
}
#[cfg(feature = "experimental-device-sync")]
fn compose(
    generation: String,
    sequence: u64,
    page: AccountConversationPage,
    local: Option<&RuntimeConversationWindowSubscription>,
) -> Result<AccountConversationWindowSnapshot, AccountChatReadError> {
    let header = if page.local_group {
        let local = local.ok_or(AccountChatReadError::Closed)?;
        AccountConversationHeader::LocalMls(Box::new(LocalAccountConversationHeader {
            revision: local.snapshot.revision.clone(),
            presentation: local.snapshot.presentation.clone(),
            read_state: local.snapshot.read_state.clone(),
            draft: local.snapshot.draft.clone(),
            pending_confirmation: local.snapshot.pending_confirmation,
        }))
    } else {
        if local.is_some() {
            return Err(AccountChatReadError::Closed);
        }
        AccountConversationHeader::PairedSource(Box::new(
            page.paired_header.ok_or(AccountChatReadError::Closed)?,
        ))
    };
    Ok(AccountConversationWindowSnapshot {
        generation,
        sequence,
        header,
        rows: page.rows,
        next_before: page.next_before,
    })
}
#[cfg(feature = "experimental-device-sync")]
fn expiry_delay(snapshot: &AccountConversationWindowSnapshot) -> std::time::Duration {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    expiry_delay_for_rows(&snapshot.rows, now)
}
#[cfg(feature = "experimental-device-sync")]
fn expiry_delay_for_rows(rows: &[AccountConversationRow], now: u64) -> std::time::Duration {
    let expiry = rows
        .iter()
        .filter_map(|row| match row {
            AccountConversationRow::LocalMls(row) => {
                (!row.deleted).then_some(row.retention_expires_at).flatten()
            }
            AccountConversationRow::PairedSource(row) => (!row.deleted)
                .then(|| row.expires_at.into_iter().chain(row.next_edit_expiry).min())
                .flatten(),
        })
        .min();
    std::time::Duration::from_secs(
        expiry
            .map(|expiry| expiry.saturating_sub(now))
            .unwrap_or(86400),
    )
}

#[cfg(all(test, feature = "experimental-device-sync"))]
mod tests {
    use super::*;
    /// Scheduling only: these synthetic display observations carry no SDK grant.
    #[test]
    fn paired_presentation_overdue_retention_wakes_before_unrelated_events() {
        let mut message = crate::PairedChatMessage {
            content_kind: crate::PairedChatContent::CanonicalChat,
            event_id: [1; 32],
            author: [2; 32],
            created_at: 5,
            expires_at: Some(10),
            deleted: false,
            content: "synthetic".into(),
            tags: Vec::new(),
            media_attachments: Vec::new(),
            edit: None,
            next_edit_expiry: None,
            source: crate::PairedChatSource {
                device: [3; 32],
                policy_digest: [4; 32],
                protected_generation: 1,
                source_epoch: 1,
                source_sequence: 1,
                source_digest: [5; 32],
            },
        };
        message.next_edit_expiry = Some(7);
        assert_eq!(
            expiry_delay_for_rows(
                &[AccountConversationRow::PairedSource(Box::new(
                    message.clone()
                ))],
                5
            ),
            std::time::Duration::from_secs(2)
        );
        message.next_edit_expiry = None;
        let rows = [AccountConversationRow::PairedSource(Box::new(
            message.clone(),
        ))];
        assert_eq!(
            expiry_delay_for_rows(&rows, 10),
            std::time::Duration::ZERO,
            "An overdue displayed payload must trigger the bounded privacy refresh immediately"
        );
        message.deleted = true;
        message.content.clear();
        let rows = [AccountConversationRow::PairedSource(Box::new(
            message.clone(),
        ))];
        assert_eq!(
            expiry_delay_for_rows(&rows, 10),
            std::time::Duration::from_secs(86400),
            "Already hidden payload must not cause a busy loop"
        );
        message.deleted = false;
        message.expires_at = Some(15);
        let rows = [AccountConversationRow::PairedSource(Box::new(message))];
        assert_eq!(
            expiry_delay_for_rows(&rows, 10),
            std::time::Duration::from_secs(5)
        );
    }
}
