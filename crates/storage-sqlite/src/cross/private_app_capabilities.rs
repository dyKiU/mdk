//! Explicit protocol aggregate capabilities over the same App SQL connection.
//! These adapters retain borrowed provider slots and forward original callbacks
//! unchanged. App-owned SQL and transaction bodies stay on SqliteAppStorage.
use crate::SqliteAccountStorage;
use cgka_traits::{
    GroupId,
    account_chat_record_stream::{
        AccountChatRecordBatch, AccountChatRecordReceipt, AccountChatRecordStreamStorage,
    },
    account_chat_send_queue::{
        AccountChatQueuedSend, AccountChatSendCursor, AccountChatSendIntent,
        AccountChatSendIntentObservation, AccountChatSendQueueStorage, AccountChatSendReceipt,
        AccountChatSendRoute,
    },
    approved_account_sharing_policy::{
        ApprovedAccountSharingPolicy, ApprovedAccountSharingPolicyStorage,
    },
    mirrored_chat_catalog::{MirroredChatCatalogStorage, MirroredChatEntry, MirroredChatScope},
    mirrored_chat_messages::{MirroredChatCursor, MirroredChatMessageStorage, MirroredChatRecord},
    storage::StorageResult,
};

impl MirroredChatCatalogStorage for SqliteAccountStorage {
    fn apply_mirrored_chat_catalog(
        &self,
        scope: &MirroredChatScope,
        entries: &[MirroredChatEntry],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<usize> {
        self.app_storage()
            .apply_mirrored_chat_catalog(scope, entries, validate_original)
    }
    fn mirrored_chat_catalog_page(
        &self,
        scope: &MirroredChatScope,
        after: Option<&GroupId>,
        limit: usize,
    ) -> StorageResult<Vec<MirroredChatEntry>> {
        self.app_storage()
            .mirrored_chat_catalog_page(scope, after, limit)
    }
}

impl ApprovedAccountSharingPolicyStorage for SqliteAccountStorage {
    fn put_approved_account_sharing_policy(
        &self,
        policy: &ApprovedAccountSharingPolicy,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.app_storage()
            .put_approved_account_sharing_policy(policy, validate_original)
    }
    fn approved_account_sharing_policies(
        &self,
    ) -> StorageResult<Vec<ApprovedAccountSharingPolicy>> {
        self.app_storage().approved_account_sharing_policies()
    }
    fn revoke_account_sharing_policy(
        &self,
        policy_id: &[u8; 32],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.app_storage()
            .revoke_account_sharing_policy(policy_id, validate_original)
    }
    fn reserve_account_chat_sequence(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        digest: &[u8; 32],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<u64> {
        self.app_storage().reserve_account_chat_sequence(
            policy_id,
            group,
            digest,
            validate_original,
        )
    }
}

impl MirroredChatMessageStorage for SqliteAccountStorage {
    fn apply_mirrored_chat_messages(
        &self,
        scope: &MirroredChatScope,
        group: &GroupId,
        records: &[MirroredChatRecord],
        now: u64,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<usize> {
        self.app_storage().apply_mirrored_chat_messages(
            scope,
            group,
            records,
            now,
            validate_original,
        )
    }
    fn mirrored_chat_message_page(
        &self,
        scope: &MirroredChatScope,
        group: &GroupId,
        after: Option<&MirroredChatCursor>,
        limit: usize,
        now: u64,
    ) -> StorageResult<Vec<MirroredChatRecord>> {
        self.app_storage()
            .mirrored_chat_message_page(scope, group, after, limit, now)
    }
    fn purge_expired_mirrored_chat_messages(
        &self,
        scope: &MirroredChatScope,
        group: &GroupId,
        now: u64,
        limit: usize,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<usize> {
        self.app_storage().purge_expired_mirrored_chat_messages(
            scope,
            group,
            now,
            limit,
            validate_original,
        )
    }
}

impl AccountChatRecordStreamStorage for SqliteAccountStorage {
    fn reserve_account_chat_record_sequence(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        event_id: &[u8; 32],
        attestation_digest: &[u8; 32],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<u64> {
        self.app_storage().reserve_account_chat_record_sequence(
            policy_id,
            group,
            event_id,
            attestation_digest,
            validate_original,
        )
    }
    fn stage_account_chat_record_batch(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        batch: &AccountChatRecordBatch,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.app_storage().stage_account_chat_record_batch(
            policy_id,
            group,
            batch,
            validate_original,
        )
    }
    fn pending_account_chat_record_batches(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        after: Option<&[u8; 32]>,
        limit: usize,
    ) -> StorageResult<Vec<AccountChatRecordBatch>> {
        self.app_storage()
            .pending_account_chat_record_batches(policy_id, group, after, limit)
    }
    fn acknowledge_account_chat_record_batch(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        receipt: &AccountChatRecordReceipt,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.app_storage().acknowledge_account_chat_record_batch(
            policy_id,
            group,
            receipt,
            validate_original,
        )
    }
    fn account_chat_record_generation_receipt(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        batch_digest: &[u8; 32],
        peer_generation: u64,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<Option<AccountChatRecordReceipt>> {
        self.app_storage().account_chat_record_generation_receipt(
            policy_id,
            group,
            batch_digest,
            peer_generation,
            validate_original,
        )
    }
    fn acknowledge_account_chat_record_batch_for_generation(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        receipt: &AccountChatRecordReceipt,
        peer_generation: u64,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.app_storage()
            .acknowledge_account_chat_record_batch_for_generation(
                policy_id,
                group,
                receipt,
                peer_generation,
                validate_original,
            )
    }
    fn deny_account_chat_record_batch(
        &self,
        policy_id: &[u8; 32],
        group: &GroupId,
        batch_digest: &[u8; 32],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.app_storage().deny_account_chat_record_batch(
            policy_id,
            group,
            batch_digest,
            validate_original,
        )
    }
    fn apply_account_chat_record_batch(
        &self,
        scope: &MirroredChatScope,
        group: &GroupId,
        batch: &AccountChatRecordBatch,
        now: u64,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<AccountChatRecordReceipt> {
        self.app_storage().apply_account_chat_record_batch(
            scope,
            group,
            batch,
            now,
            validate_original,
        )
    }
}

impl AccountChatSendQueueStorage for SqliteAccountStorage {
    fn account_chat_send_intent(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        intent_id: &[u8; 32],
    ) -> StorageResult<Option<AccountChatSendIntentObservation>> {
        self.app_storage()
            .account_chat_send_intent(account, local_device, intent_id)
    }
    fn admit_account_chat_send_intent(
        &self,
        intent: &AccountChatSendIntent,
        route: &AccountChatSendRoute,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.app_storage()
            .admit_account_chat_send_intent(intent, route, validate_original)
    }
    fn pending_account_chat_sends(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        after: Option<&AccountChatSendCursor>,
        limit: usize,
    ) -> StorageResult<Vec<AccountChatQueuedSend>> {
        self.app_storage()
            .pending_account_chat_sends(account, local_device, after, limit)
    }
    fn stage_account_chat_send_receipt(
        &self,
        account: &[u8; 32],
        receipt: &AccountChatSendReceipt,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.app_storage()
            .stage_account_chat_send_receipt(account, receipt, validate_original)
    }
    fn receive_account_chat_send_receipt(
        &self,
        account: &[u8; 32],
        receipt: &AccountChatSendReceipt,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.app_storage()
            .receive_account_chat_send_receipt(account, receipt, validate_original)
    }
    fn pending_account_chat_send_receipts(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        after_digest: Option<&[u8; 32]>,
        limit: usize,
    ) -> StorageResult<Vec<AccountChatSendReceipt>> {
        self.app_storage().pending_account_chat_send_receipts(
            account,
            local_device,
            after_digest,
            limit,
        )
    }
    fn acknowledge_account_chat_send_receipt(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        receipt_digest: &[u8; 32],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.app_storage().acknowledge_account_chat_send_receipt(
            account,
            local_device,
            receipt_digest,
            validate_original,
        )
    }
    fn deny_account_chat_send_intent(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        intent_id: &[u8; 32],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.app_storage().deny_account_chat_send_intent(
            account,
            local_device,
            intent_id,
            validate_original,
        )
    }
}

#[cfg(test)]
mod tests;
