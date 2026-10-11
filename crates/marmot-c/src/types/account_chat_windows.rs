//! Deep-owned snapshots of local MLS rows and authenticated paired observations.
use super::{
    account_chat_presentation::*, chat_window::MarmotChatListWindowSnapshot,
    conversation_window::*, presentation::MarmotPresentedChatRow,
    timeline::MarmotTimelineMessageRecord,
};
use crate::macros::c_mirror;
use crate::memory::{CFree, boxed, free_boxed};
use marmot_uniffi::conversions::*;

#[repr(C)]
pub enum MarmotAccountChatRow {
    LocalMls { row: *mut MarmotPresentedChatRow },
    PairedSource { row: *mut MarmotPairedChatSummary },
}
impl From<AccountChatRowFfi> for MarmotAccountChatRow {
    fn from(value: AccountChatRowFfi) -> Self {
        match value {
            AccountChatRowFfi::LocalMls { row } => Self::LocalMls {
                row: boxed(row.into()),
            },
            AccountChatRowFfi::PairedSource { row } => Self::PairedSource {
                row: boxed(row.into()),
            },
        }
    }
}
impl CFree for MarmotAccountChatRow {
    unsafe fn free_in_place(&mut self) {
        match self {
            Self::LocalMls { row } => unsafe { free_boxed(*row) },
            Self::PairedSource { row } => unsafe { free_boxed(*row) },
        }
    }
}

#[repr(C)]
pub enum MarmotAccountConversationHeader {
    LocalMls {
        header: *mut MarmotLocalAccountConversationHeader,
    },
    PairedSource {
        header: *mut MarmotPairedChatSummary,
    },
}
impl From<AccountConversationHeaderFfi> for MarmotAccountConversationHeader {
    fn from(value: AccountConversationHeaderFfi) -> Self {
        match value {
            AccountConversationHeaderFfi::LocalMls { header } => Self::LocalMls {
                header: boxed(header.into()),
            },
            AccountConversationHeaderFfi::PairedSource { header } => Self::PairedSource {
                header: boxed(header.into()),
            },
        }
    }
}
impl CFree for MarmotAccountConversationHeader {
    unsafe fn free_in_place(&mut self) {
        match self {
            Self::LocalMls { header } => unsafe { free_boxed(*header) },
            Self::PairedSource { header } => unsafe { free_boxed(*header) },
        }
    }
}

#[repr(C)]
pub enum MarmotAccountConversationRow {
    LocalMls {
        row: *mut MarmotTimelineMessageRecord,
    },
    PairedSource {
        row: *mut MarmotPairedChatMessage,
    },
}
impl From<AccountConversationRowFfi> for MarmotAccountConversationRow {
    fn from(value: AccountConversationRowFfi) -> Self {
        match value {
            AccountConversationRowFfi::LocalMls { row } => Self::LocalMls {
                row: boxed(row.into()),
            },
            AccountConversationRowFfi::PairedSource { row } => Self::PairedSource {
                row: boxed(row.into()),
            },
        }
    }
}
impl CFree for MarmotAccountConversationRow {
    unsafe fn free_in_place(&mut self) {
        match self {
            Self::LocalMls { row } => unsafe { free_boxed(*row) },
            Self::PairedSource { row } => unsafe { free_boxed(*row) },
        }
    }
}

c_mirror! { MarmotLocalAccountConversationHeader from LocalAccountConversationHeaderFfi {
    rec revision: MarmotConversationWindowRevision,
    rec header: MarmotConversationHeader,
    vec identities/identities_len: MarmotConversationIdentity,
    vec references/references_len: MarmotConversationMessageReferences,
    rec read_state: MarmotConversationOpenReadState,
    rec draft: MarmotSelectedMessageDraft,
    copy pending_confirmation: bool,
} }
c_mirror! { MarmotAccountChatListWindowSnapshot from AccountChatListWindowSnapshotFfi, free marmot_account_chat_list_window_snapshot_free {
    str generation, copy sequence: u64,
    rec local: MarmotChatListWindowSnapshot,
    vec rows/rows_len: MarmotAccountChatRow,
    opt_str next_paired_group_id_hex,
} }
c_mirror! { MarmotAccountConversationWindowSnapshot from AccountConversationWindowSnapshotFfi, free marmot_account_conversation_window_snapshot_free {
    str generation, copy sequence: u64,
    rec header: MarmotAccountConversationHeader,
    vec rows/rows_len: MarmotAccountConversationRow,
    opt_rec next_before: MarmotPairedChatMessageCursor,
} }

#[cfg(all(test, feature = "alloc-audit"))]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};

    #[test]
    fn paired_window_snapshot_deep_free_releases_header_rows_and_cursor() {
        let _guard = audit::test_lock();
        let start = audit::live_allocations();
        let source = PairedChatSourceFfi {
            device_hex: "11".repeat(32),
            policy_digest_hex: "22".repeat(32),
            protected_generation: 7,
            source_epoch: 2,
            source_sequence: 3,
            source_digest_hex: "33".repeat(32),
        };
        let snapshot = AccountConversationWindowSnapshotFfi {
            generation: "window".into(),
            sequence: 4,
            header: AccountConversationHeaderFfi::PairedSource {
                header: PairedChatSummaryFfi {
                    group_id_hex: "44".repeat(16),
                    name: "Fixture".into(),
                    description: "Fixture description".into(),
                    source: source.clone(),
                },
            },
            rows: vec![AccountConversationRowFfi::PairedSource {
                row: PairedChatMessageFfi {
                    kind: 9,
                    canonical_chat: true,
                    message_id_hex: "55".repeat(32),
                    author_hex: "66".repeat(32),
                    created_at: 1,
                    expires_at: Some(100),
                    deleted: false,
                    content: "fixture".into(),
                    content_tokens: Default::default(),
                    tags: vec![MessageTagFfi {
                        values: vec!["p".into(), "77".repeat(32)],
                    }],
                    media_attachments: vec![],
                    source,
                },
            }],
            next_before: Some(PairedChatMessageCursorFfi {
                created_at: 1,
                message_id_hex: "55".repeat(32),
            }),
        };
        let out = boxed(MarmotAccountConversationWindowSnapshot::from(snapshot));
        assert!(audit::live_allocations() > start);
        unsafe {
            assert_eq!((*out).rows_len, 1);
            assert!(!(*out).next_before.is_null());
            marmot_account_conversation_window_snapshot_free(out);
            marmot_account_conversation_window_snapshot_free(std::ptr::null_mut());
        }
        assert_eq!(audit::live_allocations(), start);
    }
}
