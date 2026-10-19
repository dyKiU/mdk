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

/// Existing contact route; paired observations never assert local MLS membership.
#[allow(
    clippy::large_enum_variant,
    reason = "Bounded foreign DTO requires by-value UniFFI record payloads"
)]
#[derive(Clone, uniffi::Enum)]
pub enum ExistingAccountDirectConversationFfi {
    LocalMls {
        conversation: super::ExistingDirectConversationFfi,
    },
    PairedSource {
        conversation: PairedChatSummaryFfi,
    },
}
redact!(ExistingAccountDirectConversationFfi);
impl From<marmot_app::ExistingAccountDirectConversation> for ExistingAccountDirectConversationFfi {
    fn from(value: marmot_app::ExistingAccountDirectConversation) -> Self {
        match value {
            marmot_app::ExistingAccountDirectConversation::LocalMls(row) => Self::LocalMls {
                conversation: (*row).into(),
            },
            marmot_app::ExistingAccountDirectConversation::PairedSource(row) => {
                Self::PairedSource {
                    conversation: (*row).into(),
                }
            }
        }
    }
}

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
    #[uniffi(default = None)]
    pub direct_peer_account_id_hex: Option<String>,
    #[uniffi(default = None)]
    pub latest_message: Option<PairedChatMessageFfi>,
}
redact!(PairedChatSummaryFfi);
impl From<PairedChatSummary> for PairedChatSummaryFfi {
    fn from(value: PairedChatSummary) -> Self {
        Self {
            group_id_hex: hex::encode(value.group_id.as_slice()),
            name: value.name,
            description: value.description,
            source: value.source.into(),
            direct_peer_account_id_hex: value.direct_peer_account.map(hex::encode),
            latest_message: value.latest_message.map(Into::into),
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
    #[uniffi(default = None)]
    pub edit: Option<super::TimelineEditSummaryFfi>,
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
            edit: value.edit.map(Into::into),
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

#[cfg(test)]
mod direct_route_tests {
    use super::*;

    #[test]
    fn existing_account_direct_conversation_ffi_keeps_paired_provenance_and_redacts_debug() {
        let value = marmot_app::ExistingAccountDirectConversation::PairedSource(Box::new(
            marmot_app::PairedChatSummary {
                group_id: cgka_traits::GroupId::new(vec![7; 16]),
                name: "private title".into(),
                description: "private description".into(),
                direct_peer_account: Some([9; 32]),
                latest_message: Some(marmot_app::PairedChatMessage {
                    content_kind: PairedChatContent::CanonicalChat,
                    event_id: [10; 32],
                    author: [11; 32],
                    created_at: 123,
                    expires_at: Some(200),
                    deleted: false,
                    content: "private preview".into(),
                    tags: Vec::new(),
                    media_attachments: Vec::new(),
                    edit: Some(marmot_app::TimelineEditSummary {
                        edit_count: 2,
                        latest_edit_message_id_hex: "11".repeat(32),
                        edited_at: 150,
                    }),
                    next_edit_expiry: None,
                    source: PairedChatSource {
                        device: [12; 32],
                        policy_digest: [13; 32],
                        protected_generation: 3,
                        source_epoch: 4,
                        source_sequence: 15,
                        source_digest: [16; 32],
                    },
                }),
                source: marmot_app::PairedChatSource {
                    device: [1; 32],
                    policy_digest: [2; 32],
                    protected_generation: 3,
                    source_epoch: 4,
                    source_sequence: 5,
                    source_digest: [6; 32],
                },
            },
        ));
        let ffi = ExistingAccountDirectConversationFfi::from(value);
        let debug = format!("{ffi:?}");
        assert!(!debug.contains("private title"));
        assert!(!debug.contains("private preview"));
        assert!(!debug.contains(&"01".repeat(32)));
        assert!(!debug.contains(&"09".repeat(32)));
        match ffi {
            ExistingAccountDirectConversationFfi::PairedSource { conversation } => {
                assert_eq!(conversation.group_id_hex, "07".repeat(16));
                assert_eq!(
                    conversation.direct_peer_account_id_hex,
                    Some("09".repeat(32))
                );
                assert_eq!(conversation.source.protected_generation, 3);
                assert_eq!(conversation.source.source_sequence, 5);
                let latest = conversation.latest_message.unwrap();
                assert_eq!(latest.edit.as_ref().unwrap().edit_count, 2);
                assert_eq!(
                    latest.edit.as_ref().unwrap().latest_edit_message_id_hex,
                    "11".repeat(32)
                );
                assert_eq!(latest.edit.as_ref().unwrap().edited_at, 150);
                assert_eq!(latest.content, "private preview");
                assert_eq!(latest.created_at, 123);
                assert_eq!(latest.expires_at, Some(200));
                assert_eq!(latest.source.device_hex, "0c".repeat(32));
                assert_eq!(latest.source.source_sequence, 15);
            }
            ExistingAccountDirectConversationFfi::LocalMls { .. } => {
                panic!("paired route was mislabeled local")
            }
        }
    }
}
