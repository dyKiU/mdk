//! Source-qualified observations for automatic paired chat presentation.
use crate::{GroupId, MediaAttachmentOutcome};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AccountChatReadError {
    #[error("Paired chat presentation is unsupported by this build")]
    Unsupported,
    #[error("Invalid paired chat query")]
    InvalidQuery,
    #[error("Paired chat presentation is not ready")]
    NotReady,
    #[error("Account chat window changed; use its current sequence")]
    StaleWindow,
    #[error("Paired chat presentation owner is closed")]
    Closed,
    #[error("Paired chat runtime is unavailable")]
    RuntimeUnavailable,
    #[error("Invalid source-attested logical record")]
    InvalidRecord,
}

/// Observation only: no media, MLS membership or message-authentication grant.
#[derive(Clone, PartialEq, Eq)]
pub struct PairedChatSource {
    pub device: [u8; 32],
    pub policy_digest: [u8; 32],
    pub protected_generation: u64,
    pub source_epoch: u64,
    pub source_sequence: u64,
    pub source_digest: [u8; 32],
}

#[derive(Clone)]
pub struct PairedChatSummary {
    pub group_id: GroupId,
    pub name: String,
    pub description: String,
    pub source: PairedChatSource,
}

/// Unsupported logical kinds remain visible placeholders without interpreting bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairedChatContent {
    CanonicalChat,
    UnsupportedKind(u16),
}

#[derive(Clone)]
pub struct PairedChatMessage {
    pub content_kind: PairedChatContent,
    pub event_id: [u8; 32],
    pub author: [u8; 32],
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub deleted: bool,
    pub content: String,
    pub tags: Vec<Vec<String>>,
    pub media_attachments: Vec<MediaAttachmentOutcome>,
    pub source: PairedChatSource,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PairedChatMessageCursor {
    pub created_at: u64,
    pub event_id: [u8; 32],
}

#[derive(Clone)]
pub struct PairedChatListPage {
    pub chats: Vec<PairedChatSummary>,
    pub next_group: Option<GroupId>,
}

#[derive(Clone)]
pub struct PairedChatMessagePage {
    pub messages: Vec<PairedChatMessage>,
    pub next: Option<PairedChatMessageCursor>,
}

#[derive(Clone)]
pub enum AccountConversationRow {
    LocalMls(Box<storage_sqlite::TimelineMessageRecord>),
    PairedSource(Box<PairedChatMessage>),
}

#[derive(Clone)]
pub struct AccountConversationPage {
    pub local_group: bool,
    pub paired_header: Option<PairedChatSummary>,
    pub rows: Vec<AccountConversationRow>,
    pub next_before: Option<PairedChatMessageCursor>,
}

#[cfg(feature = "experimental-device-sync")]
impl From<crate::AccountSharingError> for AccountChatReadError {
    fn from(error: crate::AccountSharingError) -> Self {
        match error {
            crate::AccountSharingError::Unsupported => Self::Unsupported,
            crate::AccountSharingError::NotReady => Self::NotReady,
            crate::AccountSharingError::Closed => Self::Closed,
            crate::AccountSharingError::RuntimeUnavailable => Self::RuntimeUnavailable,
            crate::AccountSharingError::StaleRevision => Self::Closed,
        }
    }
}

#[cfg(feature = "experimental-device-sync")]
pub(crate) fn present_message(
    row: storage_sqlite::MirroredMessageObservation,
    allow_loopback: bool,
) -> Result<PairedChatMessage, AccountChatReadError> {
    let record = row.record;
    if record.payload.len() > cgka_traits::mirrored_chat_messages::MAX_MIRRORED_MESSAGE_PAYLOAD {
        return Err(AccountChatReadError::InvalidRecord);
    }
    let (content, tags) = if record.deleted {
        if !record.payload.is_empty() {
            return Err(AccountChatReadError::InvalidRecord);
        }
        (String::new(), Vec::new())
    } else if record.kind != 9 {
        (String::new(), Vec::new())
    } else {
        let logical: (String, Vec<Vec<String>>) = serde_json::from_slice(&record.payload)
            .map_err(|_| AccountChatReadError::InvalidRecord)?;
        if serde_json::to_vec(&logical).map_err(|_| AccountChatReadError::InvalidRecord)?
            != record.payload
        {
            return Err(AccountChatReadError::InvalidRecord);
        }
        logical
    };
    let media_attachments = crate::media_attachment_outcomes_from_tags(&tags, None, allow_loopback);
    Ok(PairedChatMessage {
        content_kind: if record.kind == 9 {
            PairedChatContent::CanonicalChat
        } else {
            PairedChatContent::UnsupportedKind(record.kind)
        },
        event_id: record.event_id,
        author: record.author,
        created_at: record.created_at,
        expires_at: record.expires_at,
        deleted: record.deleted,
        content,
        tags,
        media_attachments,
        source: PairedChatSource {
            device: row.scope.source_device,
            policy_digest: row.scope.policy_digest,
            protected_generation: row.scope.protected_generation,
            source_epoch: record.source_epoch,
            source_sequence: record.source_sequence,
            source_digest: record.source_digest,
        },
    })
}

#[cfg(test)]
#[path = "account_chat_presentation/tests.rs"]
mod tests;
