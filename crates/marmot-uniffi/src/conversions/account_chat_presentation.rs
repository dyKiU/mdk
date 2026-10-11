//! Paired observations retain their source and never become MLS membership grants.
use super::{
    MediaAttachmentOutcomeFfi,
    common::{markdown_content_tokens, message_tags_ffi},
};
use crate::MarkdownDocumentFfi;
use marmot_app::{
    PairedChatContent, PairedChatListPage, PairedChatMessage, PairedChatMessageCursor,
    PairedChatMessagePage, PairedChatSource, PairedChatSummary,
};

#[derive(Clone, uniffi::Record)]
pub struct PairedChatSourceFfi {
    pub device_hex: String,
    pub policy_digest_hex: String,
    pub protected_generation: u64,
    pub source_epoch: u64,
    pub source_sequence: u64,
    pub source_digest_hex: String,
}
redact!(PairedChatSourceFfi);
impl From<PairedChatSource> for PairedChatSourceFfi {
    fn from(value: PairedChatSource) -> Self {
        Self {
            device_hex: hex::encode(value.device),
            policy_digest_hex: hex::encode(value.policy_digest),
            protected_generation: value.protected_generation,
            source_epoch: value.source_epoch,
            source_sequence: value.source_sequence,
            source_digest_hex: hex::encode(value.source_digest),
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct PairedChatSummaryFfi {
    pub group_id_hex: String,
    pub name: String,
    pub description: String,
    pub source: PairedChatSourceFfi,
}
redact!(PairedChatSummaryFfi);
impl From<PairedChatSummary> for PairedChatSummaryFfi {
    fn from(value: PairedChatSummary) -> Self {
        Self {
            group_id_hex: hex::encode(value.group_id.as_slice()),
            name: value.name,
            description: value.description,
            source: value.source.into(),
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct PairedChatMessageFfi {
    /// Unsupported kinds retain their identity and source but expose no interpreted content.
    pub kind: u16,
    pub canonical_chat: bool,
    pub message_id_hex: String,
    pub author_hex: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub deleted: bool,
    pub content: String,
    pub content_tokens: MarkdownDocumentFfi,
    pub tags: Vec<super::MessageTagFfi>,
    pub media_attachments: Vec<MediaAttachmentOutcomeFfi>,
    pub source: PairedChatSourceFfi,
}
redact!(PairedChatMessageFfi);
impl From<PairedChatMessage> for PairedChatMessageFfi {
    fn from(value: PairedChatMessage) -> Self {
        let (kind, canonical_chat) = match value.content_kind {
            PairedChatContent::CanonicalChat => (9, true),
            PairedChatContent::UnsupportedKind(kind) => (kind, false),
        };
        let content_tokens = markdown_content_tokens(u64::from(kind), &value.content);
        Self {
            kind,
            canonical_chat,
            message_id_hex: hex::encode(value.event_id),
            author_hex: hex::encode(value.author),
            created_at: value.created_at,
            expires_at: value.expires_at,
            deleted: value.deleted,
            content: value.content,
            content_tokens,
            tags: message_tags_ffi(value.tags),
            media_attachments: value
                .media_attachments
                .into_iter()
                .map(Into::into)
                .collect(),
            source: value.source.into(),
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct PairedChatMessageCursorFfi {
    pub created_at: u64,
    pub message_id_hex: String,
}
redact!(PairedChatMessageCursorFfi);
impl From<PairedChatMessageCursor> for PairedChatMessageCursorFfi {
    fn from(value: PairedChatMessageCursor) -> Self {
        Self {
            created_at: value.created_at,
            message_id_hex: hex::encode(value.event_id),
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct PairedChatListPageFfi {
    pub chats: Vec<PairedChatSummaryFfi>,
    pub next_group_id_hex: Option<String>,
}
redact!(PairedChatListPageFfi);
impl From<PairedChatListPage> for PairedChatListPageFfi {
    fn from(value: PairedChatListPage) -> Self {
        Self {
            chats: value.chats.into_iter().map(Into::into).collect(),
            next_group_id_hex: value.next_group.map(|group| hex::encode(group.as_slice())),
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct PairedChatMessagePageFfi {
    pub messages: Vec<PairedChatMessageFfi>,
    pub next: Option<PairedChatMessageCursorFfi>,
}
redact!(PairedChatMessagePageFfi);
impl From<PairedChatMessagePage> for PairedChatMessagePageFfi {
    fn from(value: PairedChatMessagePage) -> Self {
        Self {
            messages: value.messages.into_iter().map(Into::into).collect(),
            next: value.next.map(Into::into),
        }
    }
}
