//! Retained, authenticated source-lineage metadata for negative target checks.
//! Reading this metadata never grants sharing policy or ordinary MLS membership.
use crate::{SqliteAppStorage, SqliteResultExt};
use cgka_traits::{
    GroupId,
    mirrored_chat_catalog::AcceptedChatOrigin,
    storage::{StorageError, StorageResult},
};
use rusqlite::{OptionalExtension, params};

/// Connection-only form for callers already holding the account SQL connection.
/// This deliberately does not consult live-view eligibility or departure cuts:
/// a negative transaction must be able to revalidate the same immutable lineage
/// after its own cuts hide the visible row.
pub(crate) fn current_mirrored_chat_origin_observation_on_connection(
    conn: &rusqlite::Connection,
    account: &[u8; 32],
    local_device: &[u8; 32],
    source_device: &[u8; 32],
    group: &GroupId,
) -> StorageResult<Option<AcceptedChatOrigin>> {
    if !(1..=255).contains(&group.as_slice().len()) {
        return Err(invalid());
    }
    crate::approved_account_sharing_policy::check_configured_owner(conn, account, local_device)?;
    let value: Option<(Vec<u8>, i64)> = conn
        .query_row(
            "SELECT origin_id,origin_order FROM mirrored_chat_origin_current
         WHERE account=?1 AND local_device=?2 AND source_device=?3 AND group_id=?4",
            params![
                account.as_slice(),
                local_device.as_slice(),
                source_device.as_slice(),
                group.as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .storage()?;
    let Some((id, order)) = value else {
        return Ok(None);
    };
    if !(1..=8192).contains(&order) {
        return Err(invalid());
    }
    Ok(Some(AcceptedChatOrigin {
        id: id.try_into().map_err(|_| invalid())?,
        order: order as u64,
    }))
}

/// Local immutable current lineage, including pending/denied metadata. This
/// reader is exclusively for excluding stale negative-operation progress;
/// neither a pending row nor any observation grants accepted-source eligibility.
pub(crate) fn current_local_chat_origin_observation_on_connection(
    conn: &rusqlite::Connection,
    account: &[u8; 32],
    local_device: &[u8; 32],
    group: &GroupId,
) -> StorageResult<Option<AcceptedChatOrigin>> {
    if !(1..=255).contains(&group.as_slice().len()) {
        return Err(invalid());
    }
    crate::approved_account_sharing_policy::check_configured_owner(conn, account, local_device)?;
    let value:Option<(Vec<u8>,i64)>=conn.query_row(
        "SELECT o.origin_id,o.origin_order FROM account_chat_source_current c
         JOIN account_chat_source_origins o USING(origin_id)
         WHERE c.group_id=?1 AND o.account=?2 AND o.local_device=?3
           AND (substr(o.origin,1,1)!=X'02' OR EXISTS(
             SELECT 1 FROM account_chat_legacy_acceptance_evidence e WHERE e.origin_id=o.origin_id))",
        params![group.as_slice(),account.as_slice(),local_device.as_slice()],|row|Ok((row.get(0)?,row.get(1)?)),
    ).optional().storage()?;
    let Some((id, order)) = value else {
        return Ok(None);
    };
    if !(1..=8192).contains(&order) {
        return Err(invalid());
    }
    Ok(Some(AcceptedChatOrigin {
        id: id.try_into().map_err(|_| invalid())?,
        order: order as u64,
    }))
}

fn invalid() -> StorageError {
    StorageError::Serialization("invalid account chat origin observation".into())
}

impl SqliteAppStorage {
    /// Exact configured-owner/source/group observation, independent of whether
    /// the source is presently eligible. Callers must separately validate the
    /// actual approved policy and Core original before any state transition.
    pub fn current_mirrored_chat_origin_observation(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        source_device: &[u8; 32],
        group: &GroupId,
    ) -> StorageResult<Option<AcceptedChatOrigin>> {
        let conn = self.lock()?;
        current_mirrored_chat_origin_observation_on_connection(
            &conn,
            account,
            local_device,
            source_device,
            group,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
    use super::*;
    use cgka_traits::{
        MemberId,
        storage::{AccountDeviceSignerBinding, AccountDeviceSignerStorage},
    };

    #[test]
    fn retained_origin_observation_is_exactly_owner_source_and_group_bound() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        storage.lock().unwrap().execute("INSERT INTO account_state(label,updated_at,local_account_id_hex) VALUES('test',0,?1)",[hex::encode([1;32])]).unwrap();
        storage
            .put_account_device_signer(&AccountDeviceSignerBinding {
                marmot_identity: MemberId::new(vec![1; 32]),
                mls_signature_public_key: vec![2; 32],
            })
            .unwrap();
        let group = GroupId::new(vec![8; 16]);
        assert!(
            storage
                .app_storage().current_mirrored_chat_origin_observation(&[1; 32], &[2; 32], &[3; 32], &group)
                .unwrap()
                .is_none()
        );
        storage.lock().unwrap().execute("INSERT INTO mirrored_chat_origin_current(account,local_device,source_device,group_id,origin_id,origin_order,epoch) VALUES(?1,?2,?3,?4,?5,2,1)",params![[1u8;32].as_slice(),[2u8;32].as_slice(),[3u8;32].as_slice(),group.as_slice(),[4u8;32].as_slice()]).unwrap();
        let value = storage
            .app_storage().current_mirrored_chat_origin_observation(&[1; 32], &[2; 32], &[3; 32], &group)
            .unwrap()
            .unwrap();
        assert!(
            value
                == AcceptedChatOrigin {
                    id: [4; 32],
                    order: 2
                }
        );
        assert!(
            storage
                .app_storage().current_mirrored_chat_origin_observation(&[1; 32], &[2; 32], &[9; 32], &group)
                .unwrap()
                .is_none()
        );
        assert!(
            storage
                .app_storage().current_mirrored_chat_origin_observation(
                    &[1; 32],
                    &[2; 32],
                    &[3; 32],
                    &GroupId::new(vec![9; 16])
                )
                .unwrap()
                .is_none()
        );
        assert!(
            storage
                .app_storage().current_mirrored_chat_origin_observation(&[9; 32], &[2; 32], &[3; 32], &group)
                .is_err()
        );
        assert!(
            storage
                .app_storage().current_mirrored_chat_origin_observation(&[1; 32], &[9; 32], &[3; 32], &group)
                .is_err()
        );
        assert!(
            storage
                .app_storage().current_mirrored_chat_origin_observation(
                    &[1; 32],
                    &[2; 32],
                    &[3; 32],
                    &GroupId::new(vec![8; 256])
                )
                .is_err()
        );
        // SQL callers use the same bounded reader without recursively locking.
        let conn = storage.lock().unwrap();
        assert!(
            current_mirrored_chat_origin_observation_on_connection(
                &conn, &[1; 32], &[2; 32], &[3; 32], &group
            )
            .unwrap()
                == Some(value)
        );
    }
}
