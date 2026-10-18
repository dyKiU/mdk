//! Mechanical source-attested archive presentation; no permission reconstruction.
use super::{MediaAttachmentOutcomeFfi, MessageTagFfi};

#[derive(Clone, uniffi::Record)]
pub struct ArchivedHistoryRecordFfi {
    pub message_id_hex: String,
    pub author_pubkey: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub deleted: bool,
    pub content: String,
    pub tags: Vec<MessageTagFfi>,
    pub media_attachments: Vec<MediaAttachmentOutcomeFfi>,
    pub transfer_id: Vec<u8>,
    pub source_device: Vec<u8>,
    pub manifest_digest: Vec<u8>,
}
impl std::fmt::Debug for ArchivedHistoryRecordFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchivedHistoryRecordFfi")
            .finish_non_exhaustive()
    }
}
impl From<marmot_app::ArchivedHistoryRecord> for ArchivedHistoryRecordFfi {
    fn from(value: marmot_app::ArchivedHistoryRecord) -> Self {
        Self {
            message_id_hex: hex::encode(value.message_id),
            author_pubkey: hex::encode(value.author),
            created_at: value.created_at,
            expires_at: value.expires_at,
            deleted: value.deleted,
            content: value.content,
            tags: super::common::message_tags_ffi(value.tags),
            media_attachments: value
                .media_attachments
                .into_iter()
                .map(Into::into)
                .collect(),
            transfer_id: value.transfer_id.to_vec(),
            source_device: value.source_device.to_vec(),
            manifest_digest: value.manifest_digest.to_vec(),
        }
    }
}
/// Message-ID keyset cursor is a read observation, never a history grant.
#[derive(Clone, uniffi::Record)]
pub struct ArchivedHistoryPageFfi {
    pub records: Vec<ArchivedHistoryRecordFfi>,
    pub next_message_id_hex: Option<String>,
}
impl std::fmt::Debug for ArchivedHistoryPageFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchivedHistoryPageFfi")
            .finish_non_exhaustive()
    }
}
impl From<marmot_app::ArchivedHistoryPage> for ArchivedHistoryPageFfi {
    fn from(value: marmot_app::ArchivedHistoryPage) -> Self {
        Self {
            records: value.records.into_iter().map(Into::into).collect(),
            next_message_id_hex: value.next_message_id.map(hex::encode),
        }
    }
}
