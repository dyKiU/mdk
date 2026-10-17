use cgka_traits::storage::StorageProvider;
use storage_sqlite::SqliteAccountStorage;

#[cfg(feature = "experimental-device-sync")]
mod feature {
    use super::*;
    use cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster;
    use cgka_traits::device_group_genesis::GenesisLeaf;
    use cgka_traits::selected_chat_key_package::*;
    use cgka_traits::storage::{
        AccountDeviceSignerBinding, AccountDeviceSignerStorage, StorageError, StorageResult,
    };
    use cgka_traits::types::{EpochId, GroupId, MemberId};

    fn package_fixture(storage: &SqliteAccountStorage) -> SelectedChatPurposeKeyPackage {
        storage
            .app_storage()
            .ensure_account_projection_with_identity(
                "isolated-selected-chat-purpose",
                &hex::encode([1; 32]),
            )
            .unwrap();
        storage
            .put_account_device_signer(&AccountDeviceSignerBinding {
                marmot_identity: MemberId::new(vec![1; 32]),
                mls_signature_public_key: vec![2; 32],
            })
            .unwrap();
        SelectedChatPurposeKeyPackage {
            scope: SelectedChatPurposeScope {
                account: [1; 32],
                local_device: [2; 32],
                generation: 1,
                request_binding: [3; 32],
            },
            context: SelectedChatPurposeContext {
                approved_response_digest: [4; 32],
                protected_group: GroupId::new(vec![5; 16]),
                protected_anchor: DeviceGroupAnchorRoster {
                    epoch: EpochId(2),
                    epoch_authenticator_digest: [6; 32],
                    leaves: vec![
                        GenesisLeaf {
                            leaf_index: 0,
                            account: [1; 32],
                            signature_public_key: [2; 32],
                        },
                        GenesisLeaf {
                            leaf_index: 1,
                            account: [1; 32],
                            signature_public_key: [7; 32],
                        },
                    ],
                },
                protected_settlement_generation: 1,
                ordinary_group: GroupId::new(vec![8; 16]),
                ordinary_epoch: EpochId(1),
                ordinary_own_leaf_index: 0,
                ordinary_own_leaf_hash: vec![9; 32],
                ordinary_roster_digest: [10; 32],
            },
            public_bytes: vec![11; 128],
            reference: [12; 32],
            signature_public_key: [2; 32],
            state: SelectedChatPurposeState::Pending,
        }
    }
    #[test]
    fn selected_chat_recipient_facts_retry_rollback_and_retain_terminal_references() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let package = package_fixture(&storage);
        let purpose = storage
            .selected_chat_key_package_storage()
            .expect("selected-chat recipient purpose storage must exist independently of pairing");
        let rollback: StorageResult<()> = storage.with_transaction(|_| {
            purpose.put_selected_chat_key_package(&package)?;
            Err(StorageError::Backend(
                "injected package write failure".into(),
            ))
        });
        assert!(rollback.is_err());
        assert!(
            purpose
                .selected_chat_key_package_by_ref(&package.reference)
                .unwrap()
                .is_none()
        );
        purpose.put_selected_chat_key_package(&package).unwrap();
        purpose.put_selected_chat_key_package(&package).unwrap();
        assert!(
            purpose.selected_chat_key_package(&package.scope).unwrap() == Some(package.clone())
        );
        assert!(
            storage
                .device_linking_key_package_storage()
                .unwrap()
                .purpose_key_package()
                .unwrap()
                .is_none()
        );

        let mut altered = package.clone();
        altered.context.approved_response_digest[0] ^= 1;
        assert!(purpose.put_selected_chat_key_package(&altered).is_err());
        altered = package.clone();
        altered.scope.generation += 1;
        altered.scope.request_binding = [13; 32];
        altered.reference = [14; 32];
        assert!(purpose.put_selected_chat_key_package(&altered).is_err());
        assert!(
            purpose
                .consume_selected_chat_key_package(&altered.scope, &package.reference)
                .is_err()
        );
        assert!(
            purpose
                .deny_selected_chat_key_package(&package.scope, &altered.reference)
                .is_err()
        );

        let rollback: StorageResult<()> = storage.with_transaction(|_| {
            purpose.consume_selected_chat_key_package(&package.scope, &package.reference)?;
            Err(StorageError::Backend("injected join tail failure".into()))
        });
        assert!(rollback.is_err());
        assert!(
            purpose.selected_chat_key_package(&package.scope).unwrap() == Some(package.clone())
        );
        purpose
            .consume_selected_chat_key_package(&package.scope, &package.reference)
            .unwrap();
        purpose
            .consume_selected_chat_key_package(&package.scope, &package.reference)
            .unwrap();
        let mut consumed = package.clone();
        consumed.state = SelectedChatPurposeState::Consumed;
        purpose
            .deny_selected_chat_key_package(&package.scope, &package.reference)
            .unwrap();
        assert!(
            purpose
                .selected_chat_key_package_by_ref(&package.reference)
                .unwrap()
                == Some(consumed)
        );
        assert!(purpose.put_selected_chat_key_package(&package).is_err());
        let mut reused_reference = altered.clone();
        reused_reference.reference = package.reference;
        assert!(
            purpose
                .put_selected_chat_key_package(&reused_reference)
                .is_err()
        );

        purpose.put_selected_chat_key_package(&altered).unwrap();
        purpose.deny_pending_selected_chat_key_packages().unwrap();
        altered.state = SelectedChatPurposeState::Denied;
        assert!(
            purpose
                .selected_chat_key_package_by_ref(&altered.reference)
                .unwrap()
                == Some(altered.clone())
        );
        assert!(
            purpose
                .consume_selected_chat_key_package(&altered.scope, &altered.reference)
                .is_err()
        );
        altered.state = SelectedChatPurposeState::Pending;
        assert!(purpose.put_selected_chat_key_package(&altered).is_err());
        assert_eq!(purpose.selected_chat_key_packages().unwrap().len(), 2);
    }

    #[test]
    fn terminal_reference_retains_original_owner_after_configured_identity_changes() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let mut package = package_fixture(&storage);
        let purpose = storage
            .selected_chat_key_package_storage()
            .expect("independent purpose store");
        purpose.put_selected_chat_key_package(&package).unwrap();
        purpose
            .deny_selected_chat_key_package(&package.scope, &package.reference)
            .unwrap();
        let original = purpose
            .selected_chat_key_package_by_ref(&package.reference)
            .unwrap();
        let mut pending = package.clone();
        pending.scope.generation = 2;
        pending.scope.request_binding = [19; 32];
        pending.reference = [20; 32];
        purpose.put_selected_chat_key_package(&pending).unwrap();

        storage
            .app_storage()
            .ensure_account_projection_with_identity(
                "isolated-selected-chat-purpose",
                &hex::encode([15; 32]),
            )
            .unwrap();
        storage
            .put_account_device_signer(&AccountDeviceSignerBinding {
                marmot_identity: MemberId::new(vec![15; 32]),
                mls_signature_public_key: vec![16; 32],
            })
            .unwrap();
        package.scope.account = [15; 32];
        package.scope.local_device = [16; 32];
        package.scope.generation = 2;
        package.scope.request_binding = [17; 32];
        package.signature_public_key = [16; 32];
        package.reference = [18; 32];
        for leaf in &mut package.context.protected_anchor.leaves {
            leaf.account = [15; 32];
        }
        package.context.protected_anchor.leaves[0].signature_public_key = [16; 32];
        assert!(purpose.put_selected_chat_key_package(&package).is_err());
        assert!(
            purpose
                .consume_selected_chat_key_package(&pending.scope, &pending.reference)
                .is_err()
        );
        assert!(
            purpose
                .deny_selected_chat_key_package(&package.scope, &pending.reference)
                .is_err()
        );
        purpose
            .deny_selected_chat_key_package(&pending.scope, &pending.reference)
            .unwrap();
        assert!(purpose.selected_chat_key_package_by_ref(&[12; 32]).unwrap() == original);
        assert_eq!(purpose.selected_chat_key_packages().unwrap().len(), 2);
    }

    #[test]
    fn bounded_store_refuses_overflow_without_retiring_terminal_references() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let baseline = package_fixture(&storage);
        let purpose = storage
            .selected_chat_key_package_storage()
            .expect("independent purpose store");
        for generation in 1_u64..=128 {
            let mut package = baseline.clone();
            package.scope.generation = generation;
            package.scope.request_binding[..8].copy_from_slice(&generation.to_be_bytes());
            package.reference[..8].copy_from_slice(&generation.to_be_bytes());
            purpose.put_selected_chat_key_package(&package).unwrap();
            if generation == 128 {
                purpose.put_selected_chat_key_package(&package).unwrap();
            }
            purpose
                .deny_selected_chat_key_package(&package.scope, &package.reference)
                .unwrap();
        }
        let mut overflow = baseline;
        overflow.scope.generation = 129;
        overflow.scope.request_binding[..8].copy_from_slice(&129_u64.to_be_bytes());
        overflow.reference[..8].copy_from_slice(&129_u64.to_be_bytes());
        assert!(purpose.put_selected_chat_key_package(&overflow).is_err());
        assert_eq!(purpose.selected_chat_key_packages().unwrap().len(), 128);
        let mut first = overflow.reference;
        first[..8].copy_from_slice(&1_u64.to_be_bytes());
        assert!(
            purpose
                .selected_chat_key_package_by_ref(&first)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn encrypted_reopen_keeps_terminal_reference_without_recreating_permission() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("selected-purpose.sqlite");
        let key = storage_sqlite::SqlCipherKey::new("isolated selected-purpose test key").unwrap();
        let package = {
            let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            let package = package_fixture(&storage);
            let purpose = storage
                .selected_chat_key_package_storage()
                .expect("independent purpose store");
            purpose.put_selected_chat_key_package(&package).unwrap();
            purpose
                .deny_selected_chat_key_package(&package.scope, &package.reference)
                .unwrap();
            package
        };
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let purpose = reopened
            .selected_chat_key_package_storage()
            .expect("independent purpose store");
        let mut terminal = package.clone();
        terminal.state = SelectedChatPurposeState::Denied;
        assert!(
            purpose
                .selected_chat_key_package_by_ref(&package.reference)
                .unwrap()
                == Some(terminal)
        );
        assert!(purpose.put_selected_chat_key_package(&package).is_err());
        assert!(
            purpose
                .consume_selected_chat_key_package(&package.scope, &package.reference)
                .is_err()
        );
    }

    #[test]
    fn recipient_facts_reject_reordered_rosters_and_terminal_inserts() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let package = package_fixture(&storage);
        let purpose = storage
            .selected_chat_key_package_storage()
            .expect("independent purpose store");
        let mut reordered = package.clone();
        reordered.context.protected_anchor.leaves.reverse();
        assert!(purpose.put_selected_chat_key_package(&reordered).is_err());
        for state in [
            SelectedChatPurposeState::Consumed,
            SelectedChatPurposeState::Denied,
        ] {
            let mut terminal = package.clone();
            terminal.state = state;
            assert!(purpose.put_selected_chat_key_package(&terminal).is_err());
        }
        let mut too_large = package.clone();
        too_large
            .public_bytes
            .resize(MAX_SELECTED_CHAT_KEY_PACKAGE_BYTES + 1, 0);
        assert!(purpose.put_selected_chat_key_package(&too_large).is_err());
        assert!(purpose.selected_chat_key_packages().unwrap().is_empty());
        purpose.put_selected_chat_key_package(&package).unwrap();
        purpose
            .consume_selected_chat_key_package(&package.scope, &package.reference)
            .unwrap();
        purpose.deny_pending_selected_chat_key_packages().unwrap();
        assert!(
            purpose
                .selected_chat_key_package_by_ref(&package.reference)
                .unwrap()
                .unwrap()
                .state
                == SelectedChatPurposeState::Consumed
        );
    }

    #[test]
    fn encrypted_sql_cannot_delete_replace_or_reactivate_terminal_references() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("retained-reference.sqlite");
        let key =
            storage_sqlite::SqlCipherKey::new("isolated retained-reference test key").unwrap();
        if let Ok(source) = std::env::var("WN_SELECTED_CHAT_PURPOSE_V12_FIXTURE_READ") {
            // Actual closed revision12 writer output, never a reconstructed ledger.
            std::fs::copy(source, &path).unwrap();
            let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            let purpose = storage.selected_chat_key_package_storage().unwrap();
            assert!(
                purpose
                    .selected_chat_key_package_by_ref(&[12; 32])
                    .unwrap()
                    .unwrap()
                    .state
                    == SelectedChatPurposeState::Denied
            );
            assert_eq!(purpose.selected_chat_key_packages().unwrap().len(), 1);
        } else {
            let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            let package = package_fixture(&storage);
            let purpose = storage
                .selected_chat_key_package_storage()
                .expect("independent purpose store");
            purpose.put_selected_chat_key_package(&package).unwrap();
            purpose
                .deny_selected_chat_key_package(&package.scope, &package.reference)
                .unwrap();
        }
        if let Ok(destination) = std::env::var("WN_SELECTED_CHAT_PURPOSE_V12_FIXTURE_WRITE") {
            std::fs::copy(&path, destination).unwrap();
        }
        {
            let raw = rusqlite::Connection::open(&path).unwrap();
            storage_sqlite::open_hardened_sqlcipher(
                &raw,
                &key,
                storage_sqlite::SqlCipherHardening::live_cache(),
            )
            .unwrap();
            for query in [
                "DELETE FROM selected_chat_key_packages",
                "UPDATE selected_chat_key_packages SET state=0",
                "UPDATE selected_chat_key_packages SET generation=2",
                "INSERT OR REPLACE INTO selected_chat_key_packages SELECT reference,account,local_device,generation,request_binding,record,0 FROM selected_chat_key_packages",
                "INSERT INTO selected_chat_key_packages SELECT NULL,account,local_device,2,zeroblob(32),record,0 FROM selected_chat_key_packages",
            ] {
                assert!(
                    raw.execute_batch(query).is_err(),
                    "terminal recipient metadata must survive SQL mutation"
                );
            }
        }
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let purpose = reopened
            .selected_chat_key_package_storage()
            .expect("independent purpose store");
        assert_eq!(purpose.selected_chat_key_packages().unwrap().len(), 1);
        assert!(
            purpose
                .selected_chat_key_package_by_ref(&[12; 32])
                .unwrap()
                .unwrap()
                .state
                == SelectedChatPurposeState::Denied
        );
        if let Ok(destination) = std::env::var("WN_SELECTED_CHAT_PURPOSE_TEST_FIXTURE") {
            // The fixture contains synthetic public metadata only, and is copied
            // after the last encrypted connection closes for the default-build probe.
            drop(reopened);
            std::fs::copy(&path, destination).unwrap();
        }
    }
}

#[cfg(not(feature = "experimental-device-sync"))]
#[test]
fn selected_chat_purpose_storage_is_unavailable_by_default() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    assert!(storage.selected_chat_key_package_storage().is_none());
}

#[cfg(not(feature = "experimental-device-sync"))]
#[test]
#[ignore = "requires a closed encrypted fixture from the feature-enabled writer"]
fn selected_chat_populated_cohort_is_unavailable_by_default() {
    let path = std::env::var("WN_SELECTED_CHAT_PURPOSE_TEST_FIXTURE")
        .expect("feature-enabled writer fixture is required");
    let key = storage_sqlite::SqlCipherKey::new("isolated retained-reference test key").unwrap();
    assert!(SqliteAccountStorage::open_encrypted(std::path::Path::new(&path), &key).is_err());
}
