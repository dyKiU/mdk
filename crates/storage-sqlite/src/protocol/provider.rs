//! The engine's `StorageProvider` and `KeyPackageBundleStorage` impls for the account database.

use crate::SqliteAccountStorage;
use crate::base::connection::CachedSql;
use crate::protocol::openmls_storage::SqliteOpenMlsStorage;
use cgka_traits::storage::{
    KeyPackageBundleStorage, StorageError, StorageProvider, StorageResult, StoredKeyPackageBundle,
};
use cgka_traits::types::Backend;

impl StorageProvider for SqliteAccountStorage {
    type Mls = SqliteOpenMlsStorage;

    fn mls_storage(&self) -> &Self::Mls {
        &self.openmls
    }

    fn mls_write_generation(&self) -> Option<u64> {
        if self.connection.is_closed() {
            return None;
        }
        // `PRAGMA data_version` changes whenever another connection or process
        // commits to this database, which the in-process write counter cannot
        // see. Pack both so either kind of write invalidates a cached group.
        // Each half wraps at 2^32; a wrap between two reads of the same cache
        // entry is not a realistic event.
        let data_version: i64 = self
            .connection
            .lock()
            .ok()?
            .query_row_cached("PRAGMA data_version", [], |row| row.get(0))
            .ok()?;
        let own = self.connection.openmls_write_generation() & 0xffff_ffff;
        Some(((data_version as u64) << 32) | own)
    }

    fn with_read_snapshot<T, E, F>(&self, f: F) -> Result<T, E>
    where
        E: From<StorageError>,
        F: FnOnce(&Self) -> Result<T, E>,
    {
        self.connection
            .with_transaction_mode(true, || self.connection.with_query_only(|| f(self)))
    }

    fn maintenance_storage(&self) -> Option<&dyn cgka_traits::storage::MaintenanceStorage> {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn accepted_welcome_storage(
        &self,
    ) -> Option<&dyn cgka_traits::storage::AcceptedWelcomeStorage> {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn accepted_device_group_anchor_storage(
        &self,
    ) -> Option<&dyn cgka_traits::accepted_device_group_anchor::AcceptedDeviceGroupAnchorStorage>
    {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn existing_device_group_anchor_storage(
        &self,
    ) -> Option<&dyn cgka_traits::existing_device_group_anchor::ExistingDeviceGroupStorage> {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn revoked_device_group_anchor_storage(
        &self,
    ) -> Option<&dyn cgka_traits::revoked_device_group_anchor::RevokedDeviceGroupStorage> {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn private_group_privacy_storage(
        &self,
    ) -> Option<&dyn cgka_traits::private_group_privacy::PrivateGroupPrivacyStorage> {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn private_device_invite_storage(
        &self,
    ) -> Option<&dyn cgka_traits::private_device_invite::PrivateDeviceInviteStorage> {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn device_group_genesis_storage(
        &self,
    ) -> Option<&dyn cgka_traits::device_group_genesis::DeviceGroupGenesisStorage> {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn private_roster_settlement_storage(
        &self,
    ) -> Option<&dyn cgka_traits::private_roster_settlement::PrivateRosterSettlementStorage> {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn roster_ack_capture_storage(
        &self,
    ) -> Option<&dyn cgka_traits::roster_ack_capture::RosterAckCaptureStorage> {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn device_linking_key_package_storage(
        &self,
    ) -> Option<&dyn cgka_traits::device_linking_key_package::PurposeKeyPackageStorage> {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn selected_chat_key_package_storage(
        &self,
    ) -> Option<&dyn cgka_traits::selected_chat_key_package::SelectedChatKeyPackageStorage> {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn mirrored_chat_catalog_storage(
        &self,
    ) -> Option<&dyn cgka_traits::mirrored_chat_catalog::MirroredChatCatalogStorage> {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn approved_account_sharing_policy_storage(
        &self,
    ) -> Option<
        &dyn cgka_traits::approved_account_sharing_policy::ApprovedAccountSharingPolicyStorage,
    > {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn mirrored_chat_message_storage(
        &self,
    ) -> Option<&dyn cgka_traits::mirrored_chat_messages::MirroredChatMessageStorage> {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn account_chat_record_stream_storage(
        &self,
    ) -> Option<&dyn cgka_traits::account_chat_record_stream::AccountChatRecordStreamStorage> {
        Some(self)
    }

    #[cfg(feature = "experimental-device-sync")]
    fn account_chat_send_queue_storage(
        &self,
    ) -> Option<&dyn cgka_traits::account_chat_send_queue::AccountChatSendQueueStorage> {
        Some(self)
    }

    fn group_replay_state_fingerprint(
        &self,
        group_id: &cgka_traits::types::GroupId,
    ) -> StorageResult<Option<[u8; 32]>> {
        crate::protocol::storage::snapshots::replay_fingerprint(self, group_id).map(Some)
    }

    fn with_transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        E: From<StorageError>,
        F: FnOnce(&Self) -> Result<T, E>,
    {
        self.connection.with_transaction(|| f(self))
    }

    fn with_group_savepoint<T, E, F>(
        &self,
        _group_id: &cgka_traits::types::GroupId,
        _fallback_snapshot: &str,
        f: F,
    ) -> Result<T, E>
    where
        E: From<StorageError>,
        F: FnOnce(&Self) -> Result<T, E>,
    {
        self.connection.with_savepoint(|| f(self))
    }

    fn rollback_group_state_keeping_live_records(
        &self,
        group_id: &cgka_traits::types::GroupId,
        name: &str,
    ) -> StorageResult<()> {
        // Restores canonical state only, even from a full snapshot.
        cgka_traits::storage::MessageStorage::rollback_group_state_to_snapshot(self, group_id, name)
    }

    fn backend(&self) -> Backend {
        Backend::Sqlite
    }
}

impl KeyPackageBundleStorage for SqliteAccountStorage {
    fn stored_key_package_bundles(&self) -> StorageResult<Vec<StoredKeyPackageBundle>> {
        self.openmls.stored_key_package_bundles()
    }

    fn delete_stored_key_package_bundle(&self, storage_key: &[u8]) -> StorageResult<()> {
        self.openmls.delete_stored_key_package_bundle(storage_key)
    }
}
