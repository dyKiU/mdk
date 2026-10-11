//! Source-qualified paired observations, without ordinary MLS authority.
use super::{
    common::MarmotMessageTag, markdown::MarmotMarkdownDocument, media::MarmotMediaAttachmentOutcome,
};
use crate::macros::c_mirror;
use marmot_uniffi::conversions::*;

c_mirror! { MarmotPairedChatSource from PairedChatSourceFfi {
    str device_hex, str policy_digest_hex, copy protected_generation: u64,
    copy source_epoch: u64, copy source_sequence: u64, str source_digest_hex,
} }
c_mirror! { MarmotPairedChatSummary from PairedChatSummaryFfi {
    str group_id_hex, str name, str description, rec source: MarmotPairedChatSource,
} }
c_mirror! { MarmotPairedChatMessage from PairedChatMessageFfi {
    copy kind: u16, copy canonical_chat: bool, str message_id_hex, str author_hex,
    copy created_at: u64, opt_copy has_expires_at/expires_at: u64, copy deleted: bool,
    str content, rec content_tokens: MarmotMarkdownDocument,
    vec tags/tags_len: MarmotMessageTag,
    vec media_attachments/media_attachments_len: MarmotMediaAttachmentOutcome,
    rec source: MarmotPairedChatSource,
} }
c_mirror! { MarmotPairedChatMessageCursor from PairedChatMessageCursorFfi {
    copy created_at: u64, str message_id_hex,
} }
c_mirror! { MarmotPairedChatListPage from PairedChatListPageFfi, free marmot_paired_chat_list_page_free {
    vec chats/chats_len: MarmotPairedChatSummary, opt_str next_group_id_hex,
} }
c_mirror! { MarmotPairedChatMessagePage from PairedChatMessagePageFfi, free marmot_paired_chat_message_page_free {
    vec messages/messages_len: MarmotPairedChatMessage,
    opt_rec next: MarmotPairedChatMessageCursor,
} }
