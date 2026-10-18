//! `SqliteAppStorage`: the app side's handle on the account database.

use crate::base::connection::{ConnectionGuard, SharedConnection};
#[cfg(feature = "experimental-device-sync")]
use cgka_traits::storage::StorageError;
use cgka_traits::storage::StorageResult;

/// The app side's handle on an account database. It shares the account's
/// connection, so it opens nothing of its own, closes with the account
/// storage, and fails its calls the way the account storage does once closed.
/// Get one from [`crate::SqliteAccountStorage::app_storage`].
#[derive(Clone)]
pub struct SqliteAppStorage {
    pub(crate) connection: SharedConnection,
}

impl SqliteAppStorage {
    pub(crate) fn lock(&self) -> StorageResult<ConnectionGuard<'_>> {
        self.connection.lock()
    }

    /// A deferred, query-only snapshot over this same account connection.
    /// Nested calls retain the caller's transaction and restore query-only state.
    #[cfg(feature = "experimental-device-sync")]
    pub(crate) fn with_read_snapshot<T, E, F>(&self, f: F) -> Result<T, E>
    where
        E: From<StorageError>,
        F: FnOnce(&Self) -> Result<T, E>,
    {
        self.connection
            .with_transaction_mode(true, || self.connection.with_query_only(|| f(self)))
    }

    /// Whether the shared account connection has been closed.
    pub fn is_closed(&self) -> bool {
        self.connection.is_closed()
    }

    /// Whether `other` is a clone of this same opened database handle, not
    /// merely another connection to the same file.
    pub fn shares_connection_with(&self, other: &SqliteAppStorage) -> bool {
        self.connection.same_as(&other.connection)
    }
}
