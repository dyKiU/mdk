//! Mechanical window conversion; local MLS and paired observations stay distinct.
use super::*;
use marmot_app as app;

// UniFFI 0.29 serializes record payloads by value; Box<Record> has no
// FfiConverter. App stores boxed variants and C mirrors use owned pointers.
#[allow(
    clippy::large_enum_variant,
    reason = "Bounded foreign DTO requires by-value UniFFI record payloads"
)]
#[derive(Clone, uniffi::Enum)]
pub enum AccountChatRowFfi {
    LocalMls { row: PresentedChatRowFfi },
    PairedSource { row: PairedChatSummaryFfi },
}
redact!(AccountChatRowFfi);
impl From<app::AccountChatRow> for AccountChatRowFfi {
    fn from(value: app::AccountChatRow) -> Self {
        match value {
            app::AccountChatRow::LocalMls(row) => Self::LocalMls { row: (*row).into() },
            app::AccountChatRow::PairedSource(row) => Self::PairedSource { row: (*row).into() },
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct AccountChatListWindowSnapshotFfi {
    pub generation: String,
    pub sequence: u64,
    pub local: ChatListWindowSnapshotFfi,
    pub rows: Vec<AccountChatRowFfi>,
    pub next_paired_group_id_hex: Option<String>,
}
redact!(AccountChatListWindowSnapshotFfi);
impl From<app::AccountChatListWindowSnapshot> for AccountChatListWindowSnapshotFfi {
    fn from(value: app::AccountChatListWindowSnapshot) -> Self {
        Self {
            generation: value.generation,
            sequence: value.sequence,
            local: value.local.into(),
            rows: value.rows.into_iter().map(Into::into).collect(),
            next_paired_group_id_hex: value
                .next_paired_group
                .map(|group| hex::encode(group.as_slice())),
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct LocalAccountConversationHeaderFfi {
    pub revision: ConversationWindowRevisionFfi,
    pub header: ConversationHeaderFfi,
    pub identities: Vec<ConversationIdentityFfi>,
    pub references: Vec<ConversationMessageReferencesFfi>,
    pub read_state: ConversationOpenReadStateFfi,
    pub draft: SelectedMessageDraftFfi,
    pub pending_confirmation: bool,
}
redact!(LocalAccountConversationHeaderFfi);
impl From<app::LocalAccountConversationHeader> for LocalAccountConversationHeaderFfi {
    fn from(value: app::LocalAccountConversationHeader) -> Self {
        Self {
            revision: value.revision.into(),
            header: value.presentation.header.into(),
            identities: value
                .presentation
                .identities
                .into_values()
                .map(Into::into)
                .collect(),
            references: value
                .presentation
                .messages
                .into_iter()
                .map(Into::into)
                .collect(),
            read_state: value.read_state.into(),
            draft: value.draft.into(),
            pending_confirmation: value.pending_confirmation,
        }
    }
}
// UniFFI 0.29 serializes record payloads by value; Box<Record> has no
// FfiConverter. App stores boxed variants and C mirrors use owned pointers.
#[allow(
    clippy::large_enum_variant,
    reason = "Bounded foreign DTO requires by-value UniFFI record payloads"
)]
#[derive(Clone, uniffi::Enum)]
pub enum AccountConversationHeaderFfi {
    LocalMls {
        header: LocalAccountConversationHeaderFfi,
    },
    PairedSource {
        header: PairedChatSummaryFfi,
    },
}
redact!(AccountConversationHeaderFfi);
impl From<app::AccountConversationHeader> for AccountConversationHeaderFfi {
    fn from(value: app::AccountConversationHeader) -> Self {
        match value {
            app::AccountConversationHeader::LocalMls(header) => Self::LocalMls {
                header: (*header).into(),
            },
            app::AccountConversationHeader::PairedSource(header) => Self::PairedSource {
                header: (*header).into(),
            },
        }
    }
}
// UniFFI 0.29 serializes record payloads by value; Box<Record> has no
// FfiConverter. App stores boxed variants and C mirrors use owned pointers.
#[allow(
    clippy::large_enum_variant,
    reason = "Bounded foreign DTO requires by-value UniFFI record payloads"
)]
#[derive(Clone, uniffi::Enum)]
pub enum AccountConversationRowFfi {
    LocalMls { row: TimelineMessageRecordFfi },
    PairedSource { row: PairedChatMessageFfi },
}
redact!(AccountConversationRowFfi);
impl From<marmot_app::AccountConversationRow> for AccountConversationRowFfi {
    fn from(value: marmot_app::AccountConversationRow) -> Self {
        match value {
            marmot_app::AccountConversationRow::LocalMls(row) => Self::LocalMls {
                row: super::conversation_window::presented_timeline(&row, false),
            },
            marmot_app::AccountConversationRow::PairedSource(row) => {
                Self::PairedSource { row: (*row).into() }
            }
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct AccountConversationWindowSnapshotFfi {
    pub generation: String,
    pub sequence: u64,
    pub header: AccountConversationHeaderFfi,
    pub rows: Vec<AccountConversationRowFfi>,
    pub next_before: Option<PairedChatMessageCursorFfi>,
}
redact!(AccountConversationWindowSnapshotFfi);
impl From<app::AccountConversationWindowSnapshot> for AccountConversationWindowSnapshotFfi {
    fn from(value: app::AccountConversationWindowSnapshot) -> Self {
        Self {
            generation: value.generation,
            sequence: value.sequence,
            header: value.header.into(),
            rows: value.rows.into_iter().map(Into::into).collect(),
            next_before: value.next_before.map(Into::into),
        }
    }
}
