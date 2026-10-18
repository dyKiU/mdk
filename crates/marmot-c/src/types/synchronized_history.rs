//! Owned source-attested pages, distinct from live authenticated conversations.
use crate::macros::c_mirror;
use crate::types::{common::MarmotMessageTag, media::MarmotMediaAttachmentOutcome};
use marmot_uniffi::conversions::{ArchivedHistoryPageFfi, ArchivedHistoryRecordFfi};

c_mirror! { MarmotArchivedHistoryRecord from ArchivedHistoryRecordFfi {
    str message_id_hex, str author_pubkey, copy created_at: u64,
    opt_copy has_expires_at/expires_at: u64, copy deleted: bool, str content,
    vec tags/tags_len: MarmotMessageTag,
    vec media_attachments/media_attachments_len: MarmotMediaAttachmentOutcome,
    bytes transfer_id/transfer_id_len, bytes source_device/source_device_len,
    bytes manifest_digest/manifest_digest_len,
} }
c_mirror! { MarmotArchivedHistoryPage from ArchivedHistoryPageFfi,
    free marmot_archived_history_page_free {
    vec records/records_len: MarmotArchivedHistoryRecord,
    opt_str next_message_id_hex,
} }
