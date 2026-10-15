//! Serial worker RPC; hosts supply cursors, never approval scopes.
use super::AccountManager;
#[cfg(feature = "experimental-device-sync")]
use super::AccountWorkerCommand;
use crate::{
    AccountChatReadError, GroupId, PairedChatListPage, PairedChatMessageCursor,
    PairedChatMessagePage,
};
#[cfg(feature = "experimental-device-sync")]
use tokio::sync::oneshot;

#[cfg(feature = "experimental-device-sync")]
type Reply<T> = oneshot::Sender<Result<T, AccountChatReadError>>;
#[cfg(feature = "experimental-device-sync")]
pub(crate) enum Command {
    DirectConversation {
        peer: [u8; 32],
        respond: Reply<Option<crate::PairedChatSummary>>,
    },
    Conversation {
        group: GroupId,
        before: Option<PairedChatMessageCursor>,
        limit: usize,
        respond: Reply<crate::AccountConversationPage>,
    },
    Chats {
        after: Option<GroupId>,
        limit: usize,
        respond: Reply<PairedChatListPage>,
    },
    Messages {
        group: GroupId,
        after: Option<PairedChatMessageCursor>,
        limit: usize,
        respond: Reply<PairedChatMessagePage>,
    },
}

impl super::MarmotAppRuntime {
    /// Resolve a contact to its existing direct conversation, with local MLS
    /// precedence and explicit paired-source provenance. Never creates an invite.
    pub async fn existing_account_direct_conversation(
        &self,
        account_ref: &str,
        peer_account_id: &str,
    ) -> Result<Option<crate::ExistingAccountDirectConversation>, AccountChatReadError> {
        let peer_hex = crate::ids::account_id_hex_from_ref(peer_account_id)
            .map_err(|_| AccountChatReadError::InvalidQuery)?;
        let account = self
            .accounts
            .resolve(account_ref)
            .map_err(|_| AccountChatReadError::RuntimeUnavailable)?;
        if peer_hex == account.account_id_hex {
            return Ok(None);
        }
        if let Some(local) = self
            .existing_direct_conversation(&account.label, &peer_hex)
            .await
            .map_err(|error| match error {
                crate::AppError::DirectConversationIndexNotReady => AccountChatReadError::NotReady,
                _ => AccountChatReadError::RuntimeUnavailable,
            })?
        {
            return Ok(Some(crate::ExistingAccountDirectConversation::LocalMls(
                Box::new(local),
            )));
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            Ok(None)
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            let peer = hex::decode(peer_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(AccountChatReadError::InvalidQuery)?;
            self.accounts
                .paired_direct_conversation(&account.label, peer)
                .await
                .map(|found| {
                    found.map(|row| {
                        crate::ExistingAccountDirectConversation::PairedSource(Box::new(row))
                    })
                })
        }
    }
}

impl AccountManager {
    #[cfg(feature = "experimental-device-sync")]
    async fn paired_direct_conversation(
        &self,
        account: &str,
        peer: [u8; 32],
    ) -> Result<Option<crate::PairedChatSummary>, AccountChatReadError> {
        self.send_paired_chat_read(account, |respond| Command::DirectConversation {
            peer,
            respond,
        })
        .await
    }

    pub async fn paired_chat_list_page(
        &self,
        account: &str,
        after: Option<GroupId>,
        limit: u32,
    ) -> Result<PairedChatListPage, AccountChatReadError> {
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account, after, limit);
            Err(AccountChatReadError::Unsupported)
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            if !(1..=128).contains(&limit)
                || after
                    .as_ref()
                    .is_some_and(|g| !(1..=255).contains(&g.as_slice().len()))
            {
                return Err(AccountChatReadError::InvalidQuery);
            }
            self.send_paired_chat_read(account, |respond| Command::Chats {
                after,
                limit: limit as usize,
                respond,
            })
            .await
        }
    }
    pub async fn paired_chat_message_page(
        &self,
        account: &str,
        group: GroupId,
        after: Option<PairedChatMessageCursor>,
        limit: u32,
    ) -> Result<PairedChatMessagePage, AccountChatReadError> {
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account, group, after, limit);
            Err(AccountChatReadError::Unsupported)
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            if !(1..=128).contains(&limit)
                || !(1..=255).contains(&group.as_slice().len())
                || after.as_ref().is_some_and(|cursor| {
                    cursor.created_at > i64::MAX as u64 || cursor.event_id == [0; 32]
                })
            {
                return Err(AccountChatReadError::InvalidQuery);
            }
            self.send_paired_chat_read(account, |respond| Command::Messages {
                group,
                after,
                limit: limit as usize,
                respond,
            })
            .await
        }
    }
    pub async fn account_conversation_page(
        &self,
        account: &str,
        group: GroupId,
        before: Option<PairedChatMessageCursor>,
        limit: u32,
    ) -> Result<crate::AccountConversationPage, AccountChatReadError> {
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (account, group, before, limit);
            Err(AccountChatReadError::Unsupported)
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            if !(1..=128).contains(&limit)
                || !(1..=255).contains(&group.as_slice().len())
                || before.as_ref().is_some_and(|cursor| {
                    cursor.created_at > i64::MAX as u64 || cursor.event_id == [0; 32]
                })
            {
                return Err(AccountChatReadError::InvalidQuery);
            }
            self.send_paired_chat_read(account, |respond| Command::Conversation {
                group,
                before,
                limit: limit as usize,
                respond,
            })
            .await
        }
    }

    #[cfg(feature = "experimental-device-sync")]
    async fn send_paired_chat_read<T>(
        &self,
        account: &str,
        build: impl FnOnce(Reply<T>) -> Command,
    ) -> Result<T, AccountChatReadError> {
        let commands = self
            .worker_commands(account)
            .await
            .map_err(|_| AccountChatReadError::RuntimeUnavailable)?;
        let (respond, receive) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::AccountChatPresentation(Box::new(
                build(respond),
            )))
            .await
            .map_err(|_| AccountChatReadError::RuntimeUnavailable)?;
        tokio::time::timeout(std::time::Duration::from_secs(30), receive)
            .await
            .map_err(|_| AccountChatReadError::RuntimeUnavailable)?
            .map_err(|_| AccountChatReadError::RuntimeUnavailable)?
    }
}

#[cfg(feature = "experimental-device-sync")]
pub(crate) fn handle(client: &crate::AppClient, command: Command) {
    match command {
        Command::DirectConversation { peer, respond } => {
            let result = client
                .current_mirrored_direct_conversation(&peer)
                .map(|row| row.map(Into::into))
                .map_err(AccountChatReadError::from);
            let _ = respond.send(result);
        }

        Command::Conversation {
            group,
            before,
            limit,
            respond,
        } => {
            let result = (|| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| AccountChatReadError::RuntimeUnavailable)?
                    .as_secs();
                let cursor =
                    before.map(
                        |v| cgka_traits::mirrored_chat_messages::MirroredChatCursor {
                            created_at: v.created_at,
                            event_id: v.event_id,
                        },
                    );
                let (local_group, header, rows) = client.current_account_conversation_page(
                    &group,
                    cursor.as_ref(),
                    limit,
                    now,
                )?;
                let rows = rows
                    .into_iter()
                    .map(|row| match row {
                        storage_sqlite::AccountConversationObservation::LocalMls(row) => {
                            Ok(crate::AccountConversationRow::LocalMls(row))
                        }
                        storage_sqlite::AccountConversationObservation::PairedSource(row) => {
                            crate::account_chat_presentation::present_message(
                                *row,
                                client.app.config.allow_loopback_blob_endpoints,
                            )
                            .map(|row| crate::AccountConversationRow::PairedSource(Box::new(row)))
                        }
                    })
                    .collect::<Result<Vec<_>, AccountChatReadError>>()?;
                let next_before = if rows.len() == limit {
                    rows.first()
                        .map(|row| match row {
                            crate::AccountConversationRow::LocalMls(row) => {
                                let bytes = hex::decode(&row.message_id_hex)
                                    .map_err(|_| AccountChatReadError::InvalidRecord)?;
                                let event_id = bytes
                                    .try_into()
                                    .map_err(|_| AccountChatReadError::InvalidRecord)?;
                                Ok::<_, AccountChatReadError>(PairedChatMessageCursor {
                                    created_at: row.timeline_at,
                                    event_id,
                                })
                            }
                            crate::AccountConversationRow::PairedSource(row) => {
                                Ok::<_, AccountChatReadError>(PairedChatMessageCursor {
                                    created_at: row.created_at,
                                    event_id: row.event_id,
                                })
                            }
                        })
                        .transpose()?
                } else {
                    None
                };
                let paired_header = header.map(Into::into);
                Ok(crate::AccountConversationPage {
                    local_group,
                    paired_header,
                    rows,
                    next_before,
                })
            })();
            let _ = respond.send(result);
        }
        Command::Chats {
            after,
            limit,
            respond,
        } => {
            let result = client
                .current_mirrored_catalog_page(after.as_ref(), limit)
                .map_err(AccountChatReadError::from)
                .map(|rows| {
                    let next_group = (rows.len() == limit)
                        .then(|| rows.last().map(|row| row.entry.group_id.clone()))
                        .flatten();
                    let chats = rows.into_iter().map(Into::into).collect();
                    PairedChatListPage { chats, next_group }
                });
            let _ = respond.send(result);
        }
        Command::Messages {
            group,
            after,
            limit,
            respond,
        } => {
            let result = (|| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| AccountChatReadError::RuntimeUnavailable)?
                    .as_secs();
                let cursor =
                    after.map(
                        |cursor| cgka_traits::mirrored_chat_messages::MirroredChatCursor {
                            created_at: cursor.created_at,
                            event_id: cursor.event_id,
                        },
                    );
                let rows =
                    client.current_mirrored_message_page(&group, cursor.as_ref(), limit, now)?;
                let next = (rows.len() == limit)
                    .then(|| {
                        rows.last().map(|row| PairedChatMessageCursor {
                            created_at: row.record.created_at,
                            event_id: row.record.event_id,
                        })
                    })
                    .flatten();
                let messages = rows
                    .into_iter()
                    .map(|row| {
                        crate::account_chat_presentation::present_message(
                            row,
                            client.app.config.allow_loopback_blob_endpoints,
                        )
                    })
                    .collect::<Result<_, _>>()?;
                Ok(PairedChatMessagePage { messages, next })
            })();
            let _ = respond.send(result);
        }
    }
}
