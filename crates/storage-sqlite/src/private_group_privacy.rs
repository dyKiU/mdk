//! Permanent negative-only private presentation fences.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::{
    GroupId,
    private_group_privacy::PrivateGroupPrivacyStorage,
    storage::{StorageError, StorageResult},
};
use rusqlite::{OptionalExtension, params};
fn denied() -> StorageError {
    StorageError::Backend("private presentation fence unavailable".into())
}
fn validate(group: &GroupId) -> StorageResult<()> {
    if group.as_slice().is_empty() || group.as_slice().len() > 255 {
        return Err(denied());
    }
    Ok(())
}
impl PrivateGroupPrivacyStorage for SqliteAccountStorage {
    fn mark_private_group_for_chat_exclusion(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        group: &GroupId,
    ) -> StorageResult<()> {
        validate(group)?;
        let connection = self.lock()?;
        let existing: Option<(Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT account,local_device FROM private_group_chat_exclusion WHERE group_id=?1",
                params![group.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .storage()?;
        if let Some((stored_account, stored_device)) = existing {
            if stored_account != account || stored_device != local_device {
                return Err(denied());
            }
            return Ok(());
        }
        connection.execute("INSERT INTO private_group_chat_exclusion(group_id,account,local_device) VALUES(?1,?2,?3)",params![group.as_slice(),account,local_device]).storage()?;
        Ok(())
    }
    fn private_group_chat_excluded(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        group: &GroupId,
    ) -> StorageResult<bool> {
        validate(group)?;
        let connection = self.lock()?;
        let existing: Option<(Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT account,local_device FROM private_group_chat_exclusion WHERE group_id=?1",
                params![group.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .storage()?;
        match existing {
            None => Ok(false),
            Some((stored_account, stored_device))
                if stored_account == account && stored_device == local_device =>
            {
                Ok(true)
            }
            Some(_) => Err(denied()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::storage::StorageProvider;
    #[test]
    fn private_privacy_scopes_bounds_idempotence_and_immutable_fences() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let group = GroupId::new(vec![9; 19]);
        assert!(
            !storage
                .private_group_chat_excluded(&[1; 32], &[2; 32], &group)
                .unwrap()
        );
        storage
            .mark_private_group_for_chat_exclusion(&[1; 32], &[2; 32], &group)
            .unwrap();
        storage
            .mark_private_group_for_chat_exclusion(&[1; 32], &[2; 32], &group)
            .unwrap();
        assert!(
            storage
                .private_group_chat_excluded(&[1; 32], &[2; 32], &group)
                .unwrap()
        );
        assert!(
            storage
                .mark_private_group_for_chat_exclusion(&[3; 32], &[2; 32], &group)
                .is_err()
        );
        assert!(
            storage
                .private_group_chat_excluded(&[1; 32], &[3; 32], &group)
                .is_err()
        );
        for invalid in [GroupId::new(vec![]), GroupId::new(vec![7; 256])] {
            assert!(
                storage
                    .mark_private_group_for_chat_exclusion(&[1; 32], &[2; 32], &invalid)
                    .is_err()
            );
        }
        let connection = storage.lock().unwrap();
        assert!(
            connection
                .execute("DELETE FROM private_group_chat_exclusion", [])
                .is_err()
        );
        assert!(
            connection
                .execute(
                    "UPDATE private_group_chat_exclusion SET account=?1",
                    params![[3u8; 32]]
                )
                .is_err()
        );
        assert!(
            connection
                .execute(
                    "INSERT OR REPLACE INTO private_group_chat_exclusion VALUES(?1,?2,?3)",
                    params![group.as_slice(), [1u8; 32], [2u8; 32]]
                )
                .is_err()
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM private_group_chat_exclusion",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
    }
    #[test]
    fn private_privacy_transaction_rollback_and_encrypted_reopen_preserve_fence() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("privacy.sqlite");
        let key = crate::SqlCipherKey::new("6c".repeat(32)).unwrap();
        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let group = GroupId::new(vec![6; 11]);
        let result: StorageResult<()> = storage.with_transaction(|s| {
            s.mark_private_group_for_chat_exclusion(&[1; 32], &[2; 32], &group)?;
            Err(StorageError::Backend("isolated rollback".into()))
        });
        assert!(result.is_err());
        assert!(
            !storage
                .private_group_chat_excluded(&[1; 32], &[2; 32], &group)
                .unwrap()
        );
        storage
            .mark_private_group_for_chat_exclusion(&[1; 32], &[2; 32], &group)
            .unwrap();
        drop(storage);
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert!(
            reopened
                .private_group_chat_excluded(&[1; 32], &[2; 32], &group)
                .unwrap()
        );
    }
}
