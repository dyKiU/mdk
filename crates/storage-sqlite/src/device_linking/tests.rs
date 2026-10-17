use super::*;
use crate::SqlCipherKey;

const ACCOUNT: [u8; 32] = [1; 32];
const DEVICE: [u8; 32] = [2; 32];

fn prepare(storage: &SqliteAccountStorage) {
    storage
        .app_storage()
        .ensure_account_projection_with_identity("isolated-linking-test", &hex::encode(ACCOUNT))
        .unwrap();
}

fn binding(generation: u64) -> DeviceLinkingBinding {
    DeviceLinkingBinding {
        generation,
        nonce: [3; 32],
        context_digest: [4; 32],
    }
}

fn active(storage: &SqliteAccountStorage) -> DeviceLinkingBinding {
    let generation = storage
        .reserve_device_linking_attempt(&ACCOUNT, &DEVICE)
        .unwrap();
    let binding = binding(generation);
    storage.bind_device_linking_context(&binding).unwrap();
    storage
        .bind_device_linking_flow(&binding, "exact-flow")
        .unwrap();
    binding
}

#[test]
fn verifier_completion_is_terminal_and_never_creates_membership_evidence() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    prepare(&storage);
    let binding = active(&storage);
    storage
        .check_device_linking_flow(&binding, "exact-flow")
        .unwrap();
    storage
        .finish_device_linking_attempt(binding.generation, DeviceLinkingOutcome::PairingVerified)
        .unwrap();
    assert!(matches!(
        storage.check_device_linking_flow(&binding, "exact-flow"),
        Err(DeviceLinkingError::Terminal)
    ));
    let conn = storage.lock().unwrap();
    let evidence: i64 = conn
        .query_row("SELECT count(*) FROM cgka_messages", [], |row| row.get(0))
        .unwrap();
    assert_eq!(evidence, 0);
}

#[test]
fn exact_binding_retries_are_idempotent_but_substitution_is_rejected() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    prepare(&storage);
    let binding = active(&storage);
    storage.bind_device_linking_context(&binding).unwrap();
    storage
        .bind_device_linking_flow(&binding, "exact-flow")
        .unwrap();
    for altered in [
        DeviceLinkingBinding {
            nonce: [5; 32],
            ..binding.clone()
        },
        DeviceLinkingBinding {
            context_digest: [6; 32],
            ..binding.clone()
        },
    ] {
        assert!(matches!(
            storage.bind_device_linking_context(&altered),
            Err(DeviceLinkingError::BindingMismatch)
        ));
    }
    assert!(
        storage
            .bind_device_linking_flow(&binding, "Exact-flow")
            .is_err()
    );
    assert!(
        storage
            .check_device_linking_flow(&binding, "exact-flow ")
            .is_err()
    );
    storage
        .check_device_linking_flow(&binding, "exact-flow")
        .unwrap();
}

#[test]
fn repeated_reservations_keep_one_row_and_cannot_reactivate_old_generations() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    prepare(&storage);
    let old = active(&storage);
    storage
        .finish_device_linking_attempt(old.generation, DeviceLinkingOutcome::Cancelled)
        .unwrap();
    for expected in 2..=300 {
        let current = active(&storage);
        assert_eq!(current.generation, expected);
        assert!(matches!(
            storage.check_device_linking_flow(&old, "exact-flow"),
            Err(DeviceLinkingError::StaleGeneration)
        ));
        storage
            .finish_device_linking_attempt(current.generation, DeviceLinkingOutcome::Cancelled)
            .unwrap();
    }
    let count: i64 = storage
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM device_linking_attempt", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn cancellation_survives_encrypted_reopen_and_startup_cannot_revive_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("linking.db");
    let key = SqlCipherKey::new("09".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    prepare(&storage);
    let cancelled = active(&storage);
    storage
        .finish_device_linking_attempt(cancelled.generation, DeviceLinkingOutcome::Cancelled)
        .unwrap();
    storage.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(!reopened.abandon_device_linking_on_startup().unwrap());
    assert!(matches!(
        reopened.check_device_linking_flow(&cancelled, "exact-flow"),
        Err(DeviceLinkingError::Terminal)
    ));
    let fresh = active(&reopened);
    assert_eq!(fresh.generation, cancelled.generation + 1);
    assert!(matches!(
        reopened.finish_device_linking_attempt(
            cancelled.generation,
            DeviceLinkingOutcome::PairingVerified
        ),
        Err(DeviceLinkingError::StaleGeneration)
    ));
}

#[test]
fn startup_abandons_incomplete_verification_and_requires_fresh_generation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("restart.db");
    let key = SqlCipherKey::new("08".repeat(32)).unwrap();
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    prepare(&storage);
    let interrupted = active(&storage);
    storage.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(reopened.abandon_device_linking_on_startup().unwrap());
    assert!(!reopened.abandon_device_linking_on_startup().unwrap());
    assert!(
        reopened
            .bind_device_linking_flow(&interrupted, "exact-flow")
            .is_err()
    );
    let fresh = active(&reopened);
    assert_eq!(fresh.generation, interrupted.generation + 1);
}

#[test]
fn scope_mismatch_and_busy_reservations_do_not_replace_the_active_attempt() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    prepare(&storage);
    assert!(matches!(
        storage.reserve_device_linking_attempt(&[7; 32], &DEVICE),
        Err(DeviceLinkingError::WrongAccount)
    ));
    let binding = active(&storage);
    assert_eq!(binding.generation, 1);
    assert!(matches!(
        storage.reserve_device_linking_attempt(&ACCOUNT, &[8; 32]),
        Err(DeviceLinkingError::WrongDevice)
    ));
    assert!(matches!(
        storage.reserve_device_linking_attempt(&ACCOUNT, &DEVICE),
        Err(DeviceLinkingError::Busy)
    ));
    storage
        .check_device_linking_flow(&binding, "exact-flow")
        .unwrap();
}

#[test]
fn completion_requires_bound_flow_and_terminal_outcome_is_immutable() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    prepare(&storage);
    let generation = storage
        .reserve_device_linking_attempt(&ACCOUNT, &DEVICE)
        .unwrap();
    assert!(
        storage
            .finish_device_linking_attempt(generation, DeviceLinkingOutcome::PairingVerified)
            .is_err()
    );
    storage
        .finish_device_linking_attempt(generation, DeviceLinkingOutcome::Shutdown)
        .unwrap();
    storage
        .finish_device_linking_attempt(generation, DeviceLinkingOutcome::Shutdown)
        .unwrap();
    assert!(matches!(
        storage.finish_device_linking_attempt(generation, DeviceLinkingOutcome::PairingVerified),
        Err(DeviceLinkingError::Terminal)
    ));
}

#[test]
fn invalid_flow_bounds_and_generation_exhaustion_fail_without_reusing_identity() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    prepare(&storage);
    let generation = storage
        .reserve_device_linking_attempt(&ACCOUNT, &DEVICE)
        .unwrap();
    let binding = binding(generation);
    storage.bind_device_linking_context(&binding).unwrap();
    for flow in [String::new(), "x".repeat(129)] {
        assert!(matches!(
            storage.bind_device_linking_flow(&binding, &flow),
            Err(DeviceLinkingError::InvalidBinding)
        ));
    }
    let maximum_flow = "x".repeat(128);
    storage
        .bind_device_linking_flow(&binding, &maximum_flow)
        .unwrap();
    storage
        .check_device_linking_flow(&binding, &maximum_flow)
        .unwrap();
    storage
        .finish_device_linking_attempt(generation, DeviceLinkingOutcome::Expired)
        .unwrap();
    storage
        .lock()
        .unwrap()
        .execute(
            "UPDATE device_linking_attempt SET generation=?1",
            [i64::MAX],
        )
        .unwrap();
    assert!(matches!(
        storage.reserve_device_linking_attempt(&ACCOUNT, &DEVICE),
        Err(DeviceLinkingError::GenerationExhausted)
    ));
    storage.close().unwrap();
    assert!(
        storage
            .reserve_device_linking_attempt(&ACCOUNT, &DEVICE)
            .is_err()
    );
}
