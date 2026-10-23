//! Source-qualified paired observations, without ordinary MLS authority.
use super::{
    common::MarmotMessageTag, markdown::MarmotMarkdownDocument,
    media::MarmotMediaAttachmentOutcome, timeline::MarmotTimelineEditSummary,
};
use crate::macros::c_mirror;
use marmot_uniffi::conversions::*;

c_mirror! { MarmotPairedChatSource from PairedChatSourceFfi {
    str device_hex, str policy_digest_hex, copy protected_generation: u64,
    copy source_epoch: u64, copy source_sequence: u64, str source_digest_hex,
} }
c_mirror! { MarmotPairedChatSummary from PairedChatSummaryFfi {
    str group_id_hex, str name, str description, rec source: MarmotPairedChatSource,
    opt_str direct_peer_account_id_hex,
    opt_rec latest_message: MarmotPairedChatMessage,
} }
c_mirror! { MarmotPairedChatMessage from PairedChatMessageFfi {
    copy kind: u16, copy canonical_chat: bool, str message_id_hex, str author_hex,
    copy created_at: u64, opt_copy has_expires_at/expires_at: u64, copy deleted: bool,
    str content, rec content_tokens: MarmotMarkdownDocument,
    vec tags/tags_len: MarmotMessageTag,
    vec media_attachments/media_attachments_len: MarmotMediaAttachmentOutcome,
    rec source: MarmotPairedChatSource,
    opt_rec edit: MarmotTimelineEditSummary,
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

/// A deep-owned local MLS result or source-attested paired route.
#[repr(C)]
pub enum MarmotExistingAccountDirectConversation {
    LocalMls {
        conversation: *mut super::chat_list::MarmotExistingDirectConversation,
    },
    PairedSource {
        conversation: *mut MarmotPairedChatSummary,
    },
}
impl From<ExistingAccountDirectConversationFfi> for MarmotExistingAccountDirectConversation {
    fn from(value: ExistingAccountDirectConversationFfi) -> Self {
        match value {
            ExistingAccountDirectConversationFfi::LocalMls { conversation } => Self::LocalMls {
                conversation: crate::memory::boxed(conversation.into()),
            },
            ExistingAccountDirectConversationFfi::PairedSource { conversation } => {
                Self::PairedSource {
                    conversation: crate::memory::boxed(conversation.into()),
                }
            }
        }
    }
}
impl crate::memory::CFree for MarmotExistingAccountDirectConversation {
    unsafe fn free_in_place(&mut self) {
        match self {
            Self::LocalMls { conversation } => unsafe { crate::memory::free_boxed(*conversation) },
            Self::PairedSource { conversation } => unsafe {
                crate::memory::free_boxed(*conversation)
            },
        }
    }
}
/// Release an optional existing account direct-conversation result, including its payload.
/// # Safety
/// `value` is NULL or an unfreed value returned by this library, with no concurrent access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_existing_account_direct_conversation_free(
    value: *mut MarmotExistingAccountDirectConversation,
) {
    crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(value) });
}

#[cfg(all(test, feature = "alloc-audit"))]
mod direct_route_tests {
    use super::*;
    use crate::memory::{audit, boxed};

    #[test]
    fn existing_account_direct_conversation_deep_free_preserves_both_route_tags() {
        let _guard = audit::test_lock();
        let start = audit::live_allocations();
        let values = [
            ExistingAccountDirectConversationFfi::LocalMls {
                conversation: ExistingDirectConversationFfi {
                    group_id_hex: "11".into(),
                    reusable: true,
                    lifecycle_state: GroupLifecycleStateFfi::Stable,
                    self_membership: SelfMembershipFfi::Member,
                    pending_confirmation: false,
                    leave_request_pending: false,
                    disbanding: false,
                    archived: true,
                    activity_sort_at: 2,
                },
            },
            ExistingAccountDirectConversationFfi::PairedSource {
                conversation: PairedChatSummaryFfi {
                    group_id_hex: "22".into(),
                    name: "Fixture".into(),
                    description: "Test".into(),
                    direct_peer_account_id_hex: Some("99".repeat(32)),
                    latest_message: None,
                    source: PairedChatSourceFfi {
                        device_hex: "33".repeat(32),
                        policy_digest_hex: "44".repeat(32),
                        protected_generation: 1,
                        source_epoch: 2,
                        source_sequence: 3,
                        source_digest_hex: "55".repeat(32),
                    },
                },
            },
        ];
        for (index, value) in values.into_iter().enumerate() {
            let out = boxed(MarmotExistingAccountDirectConversation::from(value));
            assert!(audit::live_allocations() > start);
            unsafe {
                match &*out {
                    MarmotExistingAccountDirectConversation::LocalMls { conversation } => {
                        assert_eq!(index, 0);
                        assert!((**conversation).reusable);
                        assert!((**conversation).archived);
                    }
                    MarmotExistingAccountDirectConversation::PairedSource { conversation } => {
                        assert_eq!(index, 1);
                        assert_eq!((**conversation).source.protected_generation, 1);
                        assert_eq!(
                            std::ffi::CStr::from_ptr((**conversation).direct_peer_account_id_hex)
                                .to_str()
                                .unwrap(),
                            "99".repeat(32)
                        );
                    }
                }
                marmot_existing_account_direct_conversation_free(out);
                marmot_existing_account_direct_conversation_free(std::ptr::null_mut());
            }
            assert_eq!(audit::live_allocations(), start);
        }
    }
}
