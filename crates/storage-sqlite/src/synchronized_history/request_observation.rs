//! Cumulative negative replay fence, outside snapshots and import permissions.
use super::*;

impl SqliteAccountStorage {
    /// Atomically reserve an authenticated request identity. `false` means replay.
    /// This never loads an original owner, keys, consent or deadline from storage.
    pub fn observe_synchronized_history_request(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        transfer: &[u8; 32],
        digest: &[u8; 32],
    ) -> Result<bool> {
        self.connection.with_transaction(|| {
            use cgka_traits::storage::AccountDeviceSignerBinding;
            if [account, local_device, transfer, digest].into_iter().any(|v| *v == [0;32]) {
                return Err(SynchronizedHistoryError::InvalidManifest);
            }
            let conn = self.lock()?;
            let matches: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM account_state WHERE local_account_id_hex=?1)", [hex::encode(account)], |r| r.get(0)).storage()?;
            if !matches { return Err(SynchronizedHistoryError::WrongAccount); }
            let signer: Vec<u8> = conn.query_row("SELECT record FROM cgka_account_device_signers WHERE marmot_identity=?1", [account.as_slice()], |r| r.get(0)).storage()?;
            let signer: AccountDeviceSignerBinding = serde_json::from_slice(&signer).map_err(|_| SynchronizedHistoryError::InvalidManifest)?;
            if signer.marmot_identity.as_slice()!=account || signer.mls_signature_public_key!=local_device {
                return Err(SynchronizedHistoryError::WrongAccount);
            }
            let old: Option<(Vec<u8>,Vec<u8>,Vec<u8>)> = conn.query_row("SELECT account,local_device,request_digest FROM history_request_observations WHERE transfer_id=?1", [transfer.as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().storage()?;
            if let Some((a,d,h))=old {
                return if a==account && d==local_device && h==digest { Ok(false) } else { Err(SynchronizedHistoryError::TransferConflict) };
            }
            let count: i64=conn.query_row("SELECT count(*) FROM history_request_observations",[],|r|r.get(0)).storage()?;
            if count>=MAX_SYNCHRONIZED_HISTORY_TRANSFERS { return Err(SynchronizedHistoryError::LimitExceeded); }
            conn.execute("INSERT INTO history_request_observations(transfer_id,account,local_device,request_digest) VALUES(?1,?2,?3,?4)",params![transfer.as_slice(),account.as_slice(),local_device.as_slice(),digest.as_slice()]).storage()?;
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "experimental-device-sync")]
    fn store() -> SqliteAccountStorage {
        configured(SqliteAccountStorage::in_memory().unwrap())
    }
    #[cfg(feature = "experimental-device-sync")]
    fn configured(s: SqliteAccountStorage) -> SqliteAccountStorage {
        use cgka_traits::{
            MemberId,
            storage::{AccountDeviceSignerBinding, AccountDeviceSignerStorage},
        };
        s.app_storage().ensure_account_projection_with_identity("test", &hex::encode([1; 32]))
            .unwrap();
        s.put_account_device_signer(&AccountDeviceSignerBinding {
            marmot_identity: MemberId::new(vec![1; 32]),
            mls_signature_public_key: vec![2; 32],
        })
        .unwrap();
        s
    }
    #[cfg(feature = "experimental-device-sync")]
    #[test]
    fn history_request_observation_is_atomic_immutable_and_negative_only() {
        let s = store();
        assert!(
            s.observe_synchronized_history_request(&[1; 32], &[2; 32], &[3; 32], &[4; 32])
                .unwrap()
        );
        assert!(
            !s.observe_synchronized_history_request(&[1; 32], &[2; 32], &[3; 32], &[4; 32])
                .unwrap()
        );
        assert!(matches!(
            s.observe_synchronized_history_request(&[1; 32], &[2; 32], &[3; 32], &[5; 32]),
            Err(SynchronizedHistoryError::TransferConflict)
        ));
        for sql in [
            "DELETE FROM history_request_observations",
            "UPDATE history_request_observations SET request_digest=zeroblob(32)",
            "INSERT OR REPLACE INTO history_request_observations SELECT * FROM history_request_observations",
        ] {
            assert!(s.lock().unwrap().execute_batch(sql).is_err());
        }
        let result: Result<()> = s.connection.with_transaction(|| {
            assert!(
                s.observe_synchronized_history_request(&[1; 32], &[2; 32], &[6; 32], &[4; 32])?
            );
            Err(SynchronizedHistoryError::Cancelled)
        });
        assert!(result.is_err());
        assert!(
            s.observe_synchronized_history_request(&[1; 32], &[2; 32], &[6; 32], &[4; 32])
                .unwrap()
        );
    }
    #[cfg(feature = "experimental-device-sync")]
    #[test]
    fn history_request_observation_refuses_sql_fault_and_wrong_owner() {
        let s = store();
        for (a, d) in [([9; 32], [2; 32]), ([1; 32], [9; 32])] {
            assert!(matches!(
                s.observe_synchronized_history_request(&a, &d, &[3; 32], &[4; 32]),
                Err(SynchronizedHistoryError::WrongAccount)
            ));
        }
        s.lock().unwrap().execute_batch("CREATE TRIGGER fail_request BEFORE INSERT ON history_request_observations BEGIN SELECT RAISE(ABORT,'forced'); END;").unwrap();
        assert!(matches!(
            s.observe_synchronized_history_request(&[1; 32], &[2; 32], &[3; 32], &[4; 32]),
            Err(SynchronizedHistoryError::Storage(_))
        ));
        s.lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_request")
            .unwrap();
        assert!(
            s.observe_synchronized_history_request(&[1; 32], &[2; 32], &[3; 32], &[4; 32])
                .unwrap()
        );
    }
    #[cfg(feature = "experimental-device-sync")]
    #[test]
    fn history_request_observation_capacity_counts_all_retained_requests() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("retained-requests.sqlite");
        let key = crate::SqlCipherKey::new("isolated history request observation key").unwrap();
        let s = configured(SqliteAccountStorage::open_encrypted(&path, &key).unwrap());
        for n in 1..=128 {
            assert!(
                s.observe_synchronized_history_request(&[1; 32], &[2; 32], &[n; 32], &[4; 32])
                    .unwrap()
            );
        }
        drop(s);
        let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert!(matches!(
            s.observe_synchronized_history_request(&[1; 32], &[2; 32], &[129; 32], &[4; 32]),
            Err(SynchronizedHistoryError::LimitExceeded)
        ));
        assert!(
            !s.observe_synchronized_history_request(&[1; 32], &[2; 32], &[1; 32], &[4; 32])
                .unwrap()
        );
    }
}
