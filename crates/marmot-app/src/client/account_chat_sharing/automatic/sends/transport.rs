//! Authenticated delegation to an actual ordinary member, with exact receipts.
use super::*;
use cgka_traits::account_chat_send_queue::{
    AccountChatSendCursor, AccountChatSendReceipt, AccountChatSendState,
};
use cgka_traits::app_event::MarmotAppEvent;

const MAX_SEND_WIRE: usize = 96 * 1024;

#[derive(Default)]
pub(crate) struct SendProgress {
    cursor: Option<AccountChatSendCursor>,
    receipt_cursor: Option<[u8; 32]>,
    assembly: Option<Assembly>,
    pending: Option<([u8; 32], Option<std::time::Instant>)>,
}
impl SendProgress {
    pub(in crate::client::account_chat_sharing::automatic) fn publication_identity(&self) -> Option<([u8; 32], Option<std::time::Instant>)> {
        self.pending
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SendWire {
    version: u8,
    intent_id: [u8; 32],
    account: [u8; 32],
    originating_device: [u8; 32],
    group: String,
    ordinary_event_id: [u8; 32],
    payload: String,
    payload_digest: [u8; 32],
    created_at: u64,
}
impl SendWire {
    fn from_intent(intent: &AccountChatSendIntent) -> Self {
        Self {
            version: 1,
            intent_id: intent.intent_id,
            account: intent.account,
            originating_device: intent.originating_device,
            group: base64::engine::general_purpose::STANDARD.encode(intent.group.as_slice()),
            ordinary_event_id: intent.ordinary_event_id,
            payload: base64::engine::general_purpose::STANDARD.encode(&intent.event_payload),
            payload_digest: intent.payload_digest,
            created_at: intent.created_at,
        }
    }
    fn into_intent(self) -> Result<AccountChatSendIntent, AccountSharingError> {
        let decode = |s: &str| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|_| AccountSharingError::NotReady)?;
            if base64::engine::general_purpose::STANDARD.encode(&bytes) != s {
                return Err(AccountSharingError::NotReady);
            }
            Ok(bytes)
        };
        let group = decode(&self.group)?;
        if self.version != 1 || !(1..=255).contains(&group.len()) {
            return Err(AccountSharingError::NotReady);
        }
        Ok(AccountChatSendIntent {
            intent_id: self.intent_id,
            account: self.account,
            originating_device: self.originating_device,
            group: crate::GroupId::new(group),
            ordinary_event_id: self.ordinary_event_id,
            event_payload: decode(&self.payload)?,
            payload_digest: self.payload_digest,
            created_at: self.created_at,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum ReceiptWire {
    Committed {
        version: u8,
        receipt: AccountChatSendReceipt,
    },
    Acknowledged {
        version: u8,
        digest: [u8; 32],
    },
}

impl AppClient {
    fn automatic_send_original(
        &self,
        entry: &AutomaticChannel,
    ) -> cgka_traits::storage::StorageResult<()> {
        self.automatic_policy_current(&entry.policy)
            .and_then(|()| {
                self.runtime
                    .session()
                    .validate_account_sharing_channel(&entry.channel)
                    .map_err(|_| AccountSharingError::Closed)
            })
            .map_err(|_| {
                cgka_traits::storage::StorageError::Serialization(
                    "original forwarding channel unavailable".into(),
                )
            })
    }
    fn automatic_send_member(
        &self,
        entry: &AutomaticChannel,
        group: &crate::GroupId,
    ) -> Result<bool, AccountSharingError> {
        if !self
            .automatic_chat_source_accepted(group)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?
        {
            return Ok(false);
        }
        let mut after = None;
        loop {
            let page = self
                .runtime
                .session()
                .account_chat_catalog(&entry.policy.protected_group, after.as_ref(), 128)
                .map_err(|_| AccountSharingError::Closed)?;
            if page.entries.iter().any(|row| &row.group_id == group) {
                return Ok(true);
            }
            if page.entries.len() < 128
                || page
                    .entries
                    .last()
                    .is_some_and(|row| row.group_id.as_slice() > group.as_slice())
            {
                return Ok(false);
            }
            after = page.entries.last().map(|row| row.group_id.clone());
        }
    }
    pub(in crate::client::account_chat_sharing::automatic) fn accept_automatic_send_intent(
        &self,
        entry: &mut AutomaticChannel,
        body: &[u8],
    ) -> Result<(), AccountSharingError> {
        let fragment: CatalogFragment =
            serde_json::from_slice(body).map_err(|_| AccountSharingError::NotReady)?;
        if fragment.version != 1
            || fragment.count == 0
            || fragment.count > 120
            || fragment.ordinal >= fragment.count
        {
            return Err(AccountSharingError::NotReady);
        }
        let part = base64::engine::general_purpose::STANDARD
            .decode(&fragment.body)
            .map_err(|_| AccountSharingError::NotReady)?;
        if part.is_empty()
            || part.len() > FRAGMENT_BYTES
            || base64::engine::general_purpose::STANDARD.encode(&part) != fragment.body
        {
            return Err(AccountSharingError::NotReady);
        }
        if entry
            .sends
            .assembly
            .as_ref()
            .is_none_or(|a| a.digest != fragment.digest)
        {
            entry.sends.assembly = Some(Assembly {
                digest: fragment.digest,
                fragments: vec![None; fragment.count as usize],
            });
        }
        let assembly = entry.sends.assembly.as_mut().expect("send assembly");
        if assembly.fragments.len() != fragment.count as usize {
            return Err(AccountSharingError::NotReady);
        }
        let slot = &mut assembly.fragments[fragment.ordinal as usize];
        if slot.as_ref().is_some_and(|old| old != &part) {
            return Err(AccountSharingError::NotReady);
        }
        *slot = Some(part);
        if assembly.fragments.iter().any(Option::is_none) {
            return Ok(());
        }
        let bytes: Vec<u8> = assembly
            .fragments
            .iter()
            .flat_map(|part| part.as_ref().expect("complete send").iter().copied())
            .collect();
        if bytes.len() > MAX_SEND_WIRE
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != assembly.digest
        {
            return Err(AccountSharingError::NotReady);
        }
        let wire: SendWire =
            serde_json::from_slice(&bytes).map_err(|_| AccountSharingError::NotReady)?;
        if serde_json::to_vec(&wire).map_err(|_| AccountSharingError::NotReady)? != bytes {
            return Err(AccountSharingError::NotReady);
        }
        let intent = wire.into_intent()?;
        if intent.account != entry.policy.account
            || intent.originating_device != entry.policy.peer_device
            || !self.automatic_send_member(entry, &intent.group)?
        {
            return Err(AccountSharingError::NotReady);
        }
        let event = MarmotAppEvent::decode(&intent.event_payload)
            .map_err(|_| AccountSharingError::NotReady)?;
        if event.kind != 9 {
            return Err(AccountSharingError::NotReady);
        }
        crate::messages::validate_message_tags(&event.tags)
            .map_err(|_| AccountSharingError::NotReady)?;
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        storage
            .account_chat_send_queue_storage()
            .ok_or(AccountSharingError::NotReady)?
            .admit_account_chat_send_intent(
                &intent,
                &AccountChatSendRoute {
                    policy_id: Self::automatic_policy_id(&entry.policy)?,
                    local_device: entry.policy.local_device,
                    peer_device: entry.policy.peer_device,
                },
                &|| {
                    self.automatic_send_original(entry)?;
                    if !self
                        .automatic_send_member(entry, &intent.group)
                        .map_err(|_| {
                            cgka_traits::storage::StorageError::Backend(
                                "actual member validation unavailable".into(),
                            )
                        })?
                    {
                        return Err(cgka_traits::storage::StorageError::Serialization(
                            "actual member unavailable".into(),
                        ));
                    }
                    Ok(())
                },
            )
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        entry.sends.assembly = None;
        Ok(())
    }
    pub(in crate::client::account_chat_sharing::automatic) fn accept_automatic_send_receipt(
        &self,
        entry: &mut AutomaticChannel,
        body: &[u8],
    ) -> Result<(), AccountSharingError> {
        let wire: ReceiptWire =
            serde_json::from_slice(body).map_err(|_| AccountSharingError::NotReady)?;
        if serde_json::to_vec(&wire).map_err(|_| AccountSharingError::NotReady)? != body {
            return Err(AccountSharingError::NotReady);
        }
        let policy_id = Self::automatic_policy_id(&entry.policy)?;
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        let queue = storage
            .account_chat_send_queue_storage()
            .ok_or(AccountSharingError::NotReady)?;
        match wire {
            ReceiptWire::Committed {
                version: 1,
                mut receipt,
            } => {
                if receipt.route.policy_id != policy_id
                    || receipt.route.local_device != entry.policy.peer_device
                    || receipt.route.peer_device != entry.policy.local_device
                    || receipt.actual_member_device != entry.policy.peer_device
                    || !matches!(receipt.state, AccountChatSendState::Published { .. })
                {
                    return Err(AccountSharingError::NotReady);
                }
                let digest = receipt.digest();
                receipt.route = AccountChatSendRoute {
                    policy_id,
                    local_device: entry.policy.local_device,
                    peer_device: entry.policy.peer_device,
                };
                queue
                    .receive_account_chat_send_receipt(&entry.policy.account, &receipt, &|| {
                        self.automatic_send_original(entry)
                    })
                    .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
                if entry
                    .sends
                    .pending
                    .as_ref()
                    .is_some_and(|(id, _)| *id == receipt.intent_id)
                {
                    entry.sends.pending = None;
                }
                entry.pending.push_back(PendingBody {
                    kind: AccountSharedBodyKind::SendReceipt,
                    bytes: serde_json::to_vec(&ReceiptWire::Acknowledged { version: 1, digest })
                        .map_err(|_| AccountSharingError::NotReady)?,
                });
            }
            ReceiptWire::Acknowledged { version: 1, digest } => {
                let mut before = digest;
                let Some(index) = before.iter().rposition(|n| *n != 0) else {
                    return Err(AccountSharingError::NotReady);
                };
                before[index] -= 1;
                before[index + 1..].fill(255);
                let receipts = queue
                    .pending_account_chat_send_receipts(
                        &entry.policy.account,
                        &entry.policy.local_device,
                        Some(&before),
                        1,
                    )
                    .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
                if !receipts.first().is_some_and(|receipt| {
                    receipt.digest() == digest
                        && receipt.route.policy_id == policy_id
                        && receipt.route.peer_device == entry.policy.peer_device
                        && receipt.actual_member_device == entry.policy.local_device
                }) {
                    return Err(AccountSharingError::NotReady);
                }
                queue
                    .acknowledge_account_chat_send_receipt(
                        &entry.policy.account,
                        &entry.policy.local_device,
                        &digest,
                        &|| self.automatic_send_original(entry),
                    )
                    .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
            }
            _ => return Err(AccountSharingError::NotReady),
        }
        Ok(())
    }
    pub(in crate::client::account_chat_sharing::automatic) fn automatic_send_mark_published(
        &self,
        entry: &mut AutomaticChannel,
    ) {
        if entry.pending.is_empty()
            && let Some((_, published)) = entry.sends.pending.as_mut()
            && published.is_none()
        {
            *published = Some(std::time::Instant::now());
        }
    }
    pub(in crate::client::account_chat_sharing::automatic) async fn prepare_automatic_sends(
        &mut self,
        entry: &mut AutomaticChannel,
    ) -> Result<(), AccountSharingError> {
        if entry.next_body >= CHANNEL_BODY_BUDGET {
            entry.renew = true;
            return Ok(());
        }
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        let queue = storage
            .account_chat_send_queue_storage()
            .ok_or(AccountSharingError::NotReady)?;
        let policy_id = Self::automatic_policy_id(&entry.policy)?;
        let receipts = queue
            .pending_account_chat_send_receipts(
                &entry.policy.account,
                &entry.policy.local_device,
                entry.sends.receipt_cursor.as_ref(),
                128,
            )
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        for receipt in &receipts {
            entry.sends.receipt_cursor = Some(receipt.digest());
            if receipt.route.policy_id != policy_id {
                continue;
            }
            entry.pending.push_back(PendingBody {
                kind: AccountSharedBodyKind::SendReceipt,
                bytes: serde_json::to_vec(&ReceiptWire::Committed {
                    version: 1,
                    receipt: receipt.clone(),
                })
                .map_err(|_| AccountSharingError::NotReady)?,
            });
            return Ok(());
        }
        if receipts.len() < 128 {
            entry.sends.receipt_cursor = None;
        }
        if let Some((_, Some(published))) = entry.sends.pending.as_ref() {
            if published.elapsed() >= std::time::Duration::from_secs(10) {
                entry.renew = true;
            }
            return Ok(());
        }
        if entry.sends.pending.is_some() {
            return Ok(());
        }
        let sends = queue
            .pending_account_chat_sends(
                &entry.policy.account,
                &entry.policy.local_device,
                entry.sends.cursor.as_ref(),
                128,
            )
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        for send in &sends {
            entry.sends.cursor = Some(AccountChatSendCursor {
                intent_id: send.intent.intent_id,
                policy_id: send.route.policy_id,
            });
            if send.route.policy_id != policy_id {
                continue;
            }
            if send.intent.originating_device == entry.policy.peer_device {
                if !self.automatic_send_member(entry, &send.intent.group)? {
                    return Err(AccountSharingError::Closed);
                }
                let event = MarmotAppEvent::decode(&send.intent.event_payload)
                    .map_err(|_| AccountSharingError::NotReady)?;
                if event.kind != 9 {
                    return Err(AccountSharingError::NotReady);
                }
                crate::messages::validate_message_tags(&event.tags)
                    .map_err(|_| AccountSharingError::NotReady)?;
                self.automatic_send_original(entry)
                    .map_err(|_| AccountSharingError::Closed)?;
                let (_, summary) = self
                    .send_app_event_with_context(
                        &send.intent.group,
                        crate::messages::AppMessageIntent::TaggedChat {
                            content: event.content.clone(),
                            tags: event.tags.clone(),
                        },
                        |_| {},
                        None,
                        Some((event, send.intent.event_payload.clone())),
                    )
                    .await
                    .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
                self.automatic_send_original(entry)
                    .map_err(|_| AccountSharingError::Closed)?;
                if summary.published == 0 {
                    return Ok(());
                }
                if summary.message_ids != [hex::encode(send.intent.ordinary_event_id)] {
                    return Err(AccountSharingError::NotReady);
                }
                let receipt = AccountChatSendReceipt {
                    intent_id: send.intent.intent_id,
                    route: send.route.clone(),
                    actual_member_device: entry.policy.local_device,
                    state: AccountChatSendState::Published {
                        event_id: send.intent.ordinary_event_id,
                    },
                };
                queue
                    .stage_account_chat_send_receipt(&entry.policy.account, &receipt, &|| {
                        self.automatic_send_original(entry)
                    })
                    .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
                return Ok(());
            }
            if send.intent.originating_device != entry.policy.local_device {
                return Err(AccountSharingError::NotReady);
            }
            let bytes = serde_json::to_vec(&SendWire::from_intent(&send.intent))
                .map_err(|_| AccountSharingError::NotReady)?;
            let count = bytes.len().div_ceil(FRAGMENT_BYTES);
            if bytes.len() > MAX_SEND_WIRE || count as u64 > CHANNEL_BODY_BUDGET {
                return Err(AccountSharingError::NotReady);
            }
            if entry.next_body + count as u64 > CHANNEL_BODY_BUDGET {
                entry.renew = true;
                return Ok(());
            }
            let digest = Sha256::digest(&bytes).into();
            for (ordinal, part) in bytes.chunks(FRAGMENT_BYTES).enumerate() {
                entry.pending.push_back(PendingBody {
                    kind: AccountSharedBodyKind::SendIntent,
                    bytes: serde_json::to_vec(&CatalogFragment {
                        version: 1,
                        digest,
                        ordinal: ordinal as u32,
                        count: count as u32,
                        body: base64::engine::general_purpose::STANDARD.encode(part),
                    })
                    .map_err(|_| AccountSharingError::NotReady)?,
                });
            }
            entry.sends.pending = Some((send.intent.intent_id, None));
            return Ok(());
        }
        if sends.len() < 128 {
            entry.sends.cursor = None;
        }
        Ok(())
    }
}
