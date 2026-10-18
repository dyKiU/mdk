use super::*;
use crate::{DeviceLinkingBinding, DeviceLinkingOutcome};
const ACCOUNT: [u8; 32] = [1; 32];
const DEVICE: [u8; 32] = [2; 32];
fn setup() -> (SqliteAccountStorage, PurposeKeyPackage) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    storage
        .app_storage()
        .ensure_account_projection_with_identity("isolated-purpose-test", &hex::encode(ACCOUNT))
        .unwrap();
    let generation = storage
        .app_storage().reserve_device_linking_attempt(&ACCOUNT, &DEVICE)
        .unwrap();
    let package = PurposeKeyPackage {
        scope: PurposeAttemptScope {
            account: ACCOUNT,
            local_device: DEVICE,
            generation,
        },
        public_bytes: vec![3; 123],
        reference: vec![4; 27],
        signature_public_key: DEVICE.to_vec(),
        context: None,
        consumed: false,
    };
    (storage, package)
}
#[test]
fn context_freezes_only_against_current_durable_binding_and_never_grants_membership() {
    let (storage, package) = setup();
    storage.put_purpose_key_package(&package).unwrap();
    let binding = PurposeContextBinding {
        nonce: [6; 32],
        context_digest: [7; 32],
    };
    assert!(
        storage
            .bind_purpose_context(&package.scope, &binding)
            .is_err()
    );
    storage
        .app_storage().bind_device_linking_context(&DeviceLinkingBinding {
            generation: package.scope.generation,
            nonce: binding.nonce,
            context_digest: binding.context_digest,
        })
        .unwrap();
    storage
        .bind_purpose_context(&package.scope, &binding)
        .unwrap();
    storage
        .bind_purpose_context(&package.scope, &binding)
        .unwrap();
    assert!(
        storage
            .bind_purpose_context(
                &package.scope,
                &PurposeContextBinding {
                    context_digest: [8; 32],
                    ..binding.clone()
                }
            )
            .is_err()
    );
    assert!(storage.consume_purpose_key_package(&package.scope).is_err());
    assert!(storage.retire_purpose_key_package(&package.scope).is_err());
    let conn = storage.lock().unwrap();
    let groups: i64 = conn
        .query_row("SELECT count(*) FROM cgka_groups", [], |row| row.get(0))
        .unwrap();
    let receipts: i64 = conn
        .query_row(
            "SELECT count(*) FROM accepted_welcome_receipts",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((groups, receipts), (0, 0));
}
#[test]
fn exact_retry_bounds_conflict_and_enclosing_rollback() {
    let (storage, package) = setup();
    let result: StorageResult<()> = storage.with_transaction(|storage| {
        storage.put_purpose_key_package(&package)?;
        Err(StorageError::Backend("injected enclosing failure".into()))
    });
    assert!(result.is_err());
    assert!(storage.purpose_key_package().unwrap().is_none());
    storage.put_purpose_key_package(&package).unwrap();
    storage.put_purpose_key_package(&package).unwrap();
    for mutation in 0..7 {
        let mut altered = package.clone();
        match mutation {
            0 => altered.public_bytes[0] ^= 1,
            1 => altered.reference[0] ^= 1,
            2 => altered.scope.account = [9; 32],
            3 => altered.scope.local_device = [9; 32],
            4 => altered.scope.generation += 1,
            5 => altered.signature_public_key[0] ^= 1,
            _ => altered.public_bytes = vec![0; 16385],
        }
        assert!(storage.put_purpose_key_package(&altered).is_err());
    }
    assert!(storage.purpose_key_package().unwrap().unwrap() == package);
    storage
        .app_storage().finish_device_linking_attempt(package.scope.generation, DeviceLinkingOutcome::Cancelled)
        .unwrap();
    assert!(storage.check_purpose_reservation(&package.scope).is_err());
    storage.retire_purpose_key_package(&package.scope).unwrap();
    assert!(storage.purpose_key_package().unwrap().is_none());
    assert_eq!(
        storage
            .app_storage().reserve_device_linking_attempt(&ACCOUNT, &DEVICE)
            .unwrap(),
        package.scope.generation + 1
    );
}
