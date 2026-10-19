//! # storage-sqlite
//!
//! SQLCipher-backed SQLite implementation of the Marmot storage aggregate.
//! The backend stores Marmot metadata and custom OpenMLS storage rows in the
//! same database so group snapshot and rollback can be atomic across both
//! layers.

mod app;
mod base;
mod cross;
#[cfg(feature = "media-store-benchmarks")]
pub mod media_store_bench;
mod protocol;

pub use app::group_system::{
    GroupSystemEventProjection, GroupSystemEventProvenance, group_system_event_from_message,
};
pub use app::handle::SqliteAppStorage;

pub use app::account_recovery::{
    ParkedRecoveryObligation, QualifiedRecoveryStallSample, RECOVERY_PARK_AFTER_QUIET_PASSES,
    RecoveryCause, RecoveryComparison, RecoveryComparisonOutcome, RecoveryComparisonPlan,
    RecoveryDemand, RecoveryDemandTicket, RecoveryDemandTransition, RecoveryEligibility,
    RecoveryEndpointCheckpoint, RecoveryLossCause, RecoveryLossImport, RecoveryLossSnapshot,
    RecoveryLossWatermark, RecoveryObligationState, RecoveryObligationStatus, RecoveryPassProgress,
    RecoveryPredicate, RecoveryRequest, RecoveryRetryState, RecoveryRevisionFence,
    RecoveryScopeCheckpoint, RecoveryScopeOutcome, RecoveryScopePlan, RecoveryScopeToken,
    StoredRecoveryScope,
};
#[cfg(feature = "experimental-device-sync")]
mod device_linking;
#[cfg(feature = "experimental-device-sync")]
pub use device_linking::{DeviceLinkingBinding, DeviceLinkingError, DeviceLinkingOutcome};
#[cfg(feature = "experimental-device-sync")]
mod synchronized_history;
pub use app::local_submissions::LocalSubmission;
pub use app::media_catalog::{SlotPublication, SqliteMediaCatalog, media_storage_error};
pub use app::transport::delivery_spill::{
    DeliverySpillDisposition, DeliverySpillLimits, SpilledDelivery, SpilledDeliveryBatch,
    SpilledDeliveryDeferral,
};
pub use app::transport::moderation_reports::{
    ModerationReportOutboxEntry, ModerationReportOutboxOutcome,
};
#[cfg(feature = "experimental-device-sync")]
pub use synchronized_history::{
    HistoryArchiveFragmentDisposition, HistoryArchiveFragmentReceipt,
    HistoryArchiveStagingManifest, MAX_HISTORY_ARCHIVE_BYTES, MAX_HISTORY_ARCHIVE_FRAGMENT_BYTES,
    MAX_SYNCHRONIZED_HISTORY_BYTES, MAX_SYNCHRONIZED_HISTORY_CHUNK_BYTES,
    MAX_SYNCHRONIZED_HISTORY_CHUNKS, MAX_SYNCHRONIZED_HISTORY_PAGE,
    MAX_SYNCHRONIZED_HISTORY_RECORDS_PER_CHUNK, MAX_SYNCHRONIZED_HISTORY_TRANSFERS,
    ProvenancedSynchronizedHistoryRecord, SynchronizedHistoryArchive, SynchronizedHistoryBinding,
    SynchronizedHistoryError, SynchronizedHistoryImportProgress, SynchronizedHistoryManifest,
    SynchronizedHistoryRecord, synchronized_history_chunk_digest,
};
mod shared;
pub use app::transport::user_blocks::{
    BlockListSnapshot, BlockedUser, PendingBlockPublication, StoredBlockList,
};

pub use app::account_projection::{
    AccountChatNotificationSettings, AccountDeliveryRecovery, AccountGroupPushToken,
    AccountNotificationSettings, AccountPendingPushRegistrationRemoval, AccountPushRegistration,
    AccountStoredPushRegistration, AppEventReplayCursor, DeleteLocalGroupDataResult,
    MAX_APP_MESSAGE_REPLAY_PAGE, SelfMembership, StoredAccountGroup, StoredAccountGroupComponent,
    StoredAccountState, StoredAppMessageQuery, StoredAppMessageRecord, StoredEpochBackfillIntent,
    StoredEpochStallEvidence, StoredNostrRoute, clamp_to_max_future_skew,
};
pub use app::attachment_acquisition::{
    ATTACHMENT_ACQUISITION_BATCH_LIMIT, ATTACHMENT_CHECKPOINT_BYTES, ATTACHMENT_REMOVAL_BATCH,
    ATTACHMENT_STAGING_CHUNK_BYTES, AttachmentAcquisition, AttachmentAcquisitionSource,
    AttachmentAcquisitionState, AttachmentAcquisitionStatus, AttachmentAssetRef,
    AttachmentCheckpoint, AttachmentDemand, AttachmentMigrationState, AttachmentPartial,
    AttachmentPartialIdentity, AttachmentPermissionCategory, AttachmentPublication,
    AttachmentPublishResult, AttachmentRemoval, AttachmentStorageUsage, AttachmentUploadOwner,
    AttachmentUploadPromotion, AttachmentUploadSource, AttachmentUploadStage,
    AttachmentWorkerDemand, ChatAttachmentUsage, ChatUsageCursor, LegacyAttachmentBody,
    LegacyBodyPublication, LegacyBodyReader, MAX_ATTACHMENT_LOCAL_READ_BYTES,
    MAX_RETAINED_ATTACHMENT_BYTES, MAX_RETAINED_FILE_ATTACHMENT_BYTES, RetainedAttachmentAsset,
    RetainedAttachmentEntry, RetainedAttachmentRead, RetainedSizeCursor,
};
pub use app::attachment_history::{
    AccountAttachmentCursor, AccountAttachmentEntry, AccountAttachmentHistoryError,
    AccountAttachmentPage, AccountAttachmentQuery, AccountAttachmentVersion,
    AttachmentHistoryCursor, AttachmentHistoryEntry, AttachmentHistoryError, AttachmentHistoryPage,
    AttachmentHistoryVersion, MAX_ATTACHMENT_HISTORY_PAGE,
};
pub use app::avatar_cache::{
    AVATAR_IDENTITY_BATCH_LIMIT, AvatarAcquisition, AvatarAcquisitionState,
    AvatarAssetPresentation, AvatarAssetRead, AvatarAssetRef, AvatarAssetStatus, AvatarAssetTarget,
    AvatarAvailability, AvatarCacheUsage, AvatarIdentityDemand, AvatarImage, AvatarImageFormat,
    AvatarPublishResult, MAX_AVATAR_BYTES, MAX_AVATAR_CACHE_BYTES, MAX_AVATAR_CACHE_ENTRIES,
    MAX_AVATAR_DIMENSION,
};
pub use app::chat_list::{
    AccountAttentionTotal, AccountUnreadTotal, ChatConversationKind, ChatListAttachmentKind,
    ChatListAvatar, ChatListCursor, ChatListMessageDeliveryState, ChatListMessagePreview,
    ChatListPage, ChatListPageDirection, ChatListPageError, ChatListPageQuery, ChatListQuery,
    ChatListRow, ChatListSelectionError, ChatListSelectionSnapshot, ChatListView,
    ChatListWindowQuery, ChatListWindowRead, ChatPinError, ChatPinState,
    ExistingDirectConversation, RetentionExpiryScan, conversation_kind,
    select_reusable_direct_conversation,
};
pub use app::chat_presentation::{
    CHAT_LIST_DRAFT_PREVIEW_CHARS, CHAT_PRESENTATION_BATCH_LIMIT, ChatListDraftPreview,
    ChatListRowActions, ChatPresentationActivePeer, ChatPresentationCatchUp,
    ChatPresentationCheckpoint, ChatPresentationInput, ChatPresentationRead,
    ChatPresentationVersion, ChatPresentationWrite, ConversationPresentation,
    PresentationResolution, PresentationSource, PresentationText, PresentedChatListSnapshot,
    PresentedChatRow, SelectedAvatar, SelectedChatPreview, StoredChatPresentation,
};
pub use app::message_drafts::{
    ChatListDraftVersion, MessageDraftRevision, MessageDraftRevisionError, SelectedMessageDraft,
    SelectedMessageDraftAttachment, SelectedMessageDraftContent, StoredMessageDraft,
    StoredMessageDraftAttachment, StoredMessageDraftAttachmentSummary, StoredMessageDraftSummary,
};
pub use app::pending_welcome_delivery::PendingWelcomeDeliveryRecord;
pub use app::timeline::{
    BRANCH_SELECTION_WITHDRAWAL_REASON, BranchSelectionWithdrawalDivergence,
    ConversationAccountSnapshot, ConversationAnchor, ConversationOpenAnchorOutcome,
    ConversationOpenError, ConversationOpenQuery, ConversationOpenReadState,
    ConversationOpenSnapshot, ConversationOpenTarget, ConversationPresentationPage,
    ConversationWindowQuery, DeletionSource, LOCAL_PUBLISH_FAILED_REASON, MAX_TIMELINE_LIMIT,
    SecurePruneAppEventsResult, StoredAppEvent, TimelineEditHistoryPage, TimelineEditSummary,
    TimelineEditVersion, TimelineMessageChange, TimelineMessageQuery, TimelineMessageRecord,
    TimelineMessageTarget, TimelinePage, TimelinePagination, TimelineProjectionUpdate,
    TimelineReactionSummary, TimelineRemoveReason, TimelineReplyPreview, TimelineUpdateTrigger,
    TimelineUserReaction,
};
pub use app::transport::prepared_group_image_upload::{
    ACTIVE_PREPARED_GROUP_IMAGE_UPLOAD_TTL_SECONDS,
    CONSUMED_PREPARED_GROUP_IMAGE_UPLOAD_TTL_SECONDS, MAX_ACTIVE_PREPARED_GROUP_IMAGE_UPLOADS,
    MAX_CONSUMED_PREPARED_GROUP_IMAGE_UPLOADS, PreparedGroupImageUploadRecord,
    PreparedGroupImageUploadState,
};
pub use app::transport::transport_reconciliation::{
    TRANSPORT_RECONCILIATION_MAX_ITEMS_PER_ROUTE, TRANSPORT_RECONCILIATION_RETENTION_SECS,
    TransportReconciliationInventory, TransportReconciliationItem, TransportReconciliationRoute,
};
pub use base::connection::{
    CloseableConnection, ConnectionGuard, DatabaseCloser, SqlCipherHardening, SqlCipherKey,
    SqliteJournalMode, SqliteStorageOptions, SqliteSynchronous, SqliteTimingObserver,
    SqliteTimingOperation, open_hardened_sqlcipher,
};
pub use cross::outbound::MessageDraftCommitObserver;
pub use protocol::handle::SqliteAccountStorage;
#[allow(deprecated)]
pub use protocol::handle::SqliteStorage;
pub use protocol::openmls_storage::SqliteOpenMlsStorageError;
pub use protocol::storage::messages::MessageFormatPromotionProgress;
#[cfg(feature = "storage-format-benchmarks")]
pub use protocol::storage::messages::StorageFormatBenchSizes;
pub use shared::{
    DirectoryPresentation, DirectoryPresentationChanges, PublicDirectoryProfileRecord,
    PublicDirectoryUserRecord, SqliteSharedStorage, StoredAuditLogSettings,
    StoredRelayTelemetrySettings, StoredUsageDiagnosticsSettings,
};

pub use app::transport::agent_stream_sequences::{
    AgentStreamPublisherReservation, AgentStreamPublisherReservationRequest,
    AgentStreamPublisherState, MAX_AGENT_STREAM_PUBLISHER_CONTEXTS,
};
pub(crate) use base::codec::{
    SQLITE_BIND_PARAMETER_CHUNK, SqliteResultExt, bool_i64, created_at_to_i64, deserialize,
    epoch_to_i64, i64_to_u64, i64_to_usize, message_state_from_i64, message_state_to_i64,
    optional_u64_to_i64, serialize, tags_from_json, u64_to_i64, unix_now_ms, unix_now_seconds,
    unix_now_seconds_i64, usize_to_i64,
};

pub use app::timeline::reports::{
    ContentReport, ContentReportPage, ReportDismissal, ReportDismissalPage,
};

pub use app::attachment_acquisition::{
    AttachmentDownloadPolicy, AttachmentTransferFrame, AttachmentTransferState,
    AttachmentTransferStatus, ReadmitAdmission, STORAGE_PARKED_PREFIX_MAX_AGE_SECONDS,
    STORAGE_READMIT_MARGIN_BYTES,
};

#[cfg(feature = "experimental-device-sync")]
mod accepted_welcome;

#[cfg(feature = "experimental-device-sync")]
mod device_linking_key_package;

#[cfg(feature = "experimental-device-sync")]
mod roster_ack_capture;

#[cfg(all(test, feature = "experimental-device-sync"))]
mod device_group_genesis_tests;

#[cfg(feature = "experimental-device-sync")]
mod device_group_genesis;
#[cfg(feature = "experimental-device-sync")]
mod private_group_privacy;

#[cfg(feature = "experimental-device-sync")]
mod accepted_device_group_anchor;
#[cfg(all(test, feature = "experimental-device-sync"))]
mod accepted_device_group_anchor_tests;
#[cfg(feature = "experimental-device-sync")]
mod existing_device_group_anchor;
mod mirrored_chat_edits;
#[cfg(feature = "experimental-device-sync")]
mod private_device_invite;
#[cfg(all(test, feature = "experimental-device-sync"))]
mod private_device_invite_tests;
#[cfg(feature = "experimental-device-sync")]
mod revoked_device_group_anchor;
#[cfg(feature = "experimental-device-sync")]
mod selected_chat_key_package;

#[cfg(feature = "experimental-device-sync")]
pub mod account_chat_departure;
#[cfg(feature = "experimental-device-sync")]
mod account_chat_legacy_acceptance;
#[cfg(feature = "experimental-device-sync")]
mod account_chat_origin_observation;
#[cfg(feature = "experimental-device-sync")]
mod account_chat_record_stream;
#[cfg(feature = "experimental-device-sync")]
mod account_chat_send_queue;
#[cfg(feature = "experimental-device-sync")]
pub mod account_chat_source;
#[cfg(feature = "experimental-device-sync")]
mod approved_account_sharing_policy;
#[cfg(feature = "experimental-device-sync")]
mod mirrored_chat_catalog;
#[cfg(feature = "experimental-device-sync")]
mod mirrored_chat_messages;
#[cfg(feature = "experimental-device-sync")]
mod mirrored_chat_presentation;
#[cfg(feature = "experimental-device-sync")]
pub use mirrored_chat_edits::MirroredMessageEdit;
#[cfg(feature = "experimental-device-sync")]
pub use mirrored_chat_presentation::{
    AccountConversationObservation, MirroredCatalogObservation, MirroredChatActivityObservation,
    MirroredMessageObservation,
};

#[cfg(feature = "experimental-device-sync")]
mod private_roster_settlement;

// Private ledger callers retain their internal paths; canonical ownership is
// base::migrations/base::open_progress, with one runner and one observer.
#[cfg(test)]
pub(crate) use base::migrations;
pub(crate) use base::open_progress;
pub use base::open_progress::{StorageOpenPhase, StorageOpenProgress};
