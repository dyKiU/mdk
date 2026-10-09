fn legacy_prefix(connection: &mut Connection, last: usize) {
    run(connection, MIGRATIONS).unwrap();
    for migration in PRIVATE_MIGRATIONS.iter().take(last - 102) {
        let legacy = Migration {
            version: migration.version + 102,
            name: LEGACY_NAMES[(migration.version - 1) as usize],
            apply: migration.apply,
        };
        apply_migration(connection, &legacy).unwrap();
    }
}
const LEGACY_NAMES: [&str; 8] = [
    "0103_synchronized_history",
    "0104_device_linking_attempt",
    "0105_accepted_welcome_receipts",
    "0106_device_linking_key_package",
    "0107_roster_ack_capture",
    "0108_device_group_genesis",
    "0109_accepted_device_group_anchor",
    "0110_private_device_invite",
];
use super::*;
use crate::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};

fn encrypted(path: &std::path::Path) -> Connection {
    let connection = Connection::open(path).unwrap();
    let key = SqlCipherKey::new("isolated private ledger synthetic key").unwrap();
    open_hardened_sqlcipher(&connection, &key, SqlCipherHardening::live_cache()).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_ledger_encrypted_prefix_preserves_original_receipts_and_denial() {
    for last in 103..=110 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private-prefix.db");
        let mut connection = encrypted(&path);
        legacy_prefix(&mut connection, last);
        connection
            .execute(
                "UPDATE cgka_schema_migrations SET applied_at_unix_seconds=17 WHERE version>102",
                [],
            )
            .unwrap();
        connection.execute("INSERT INTO synchronized_history_retention_fences VALUES('opaque-group','abababababababababababababababababababababababababababababababab')", []).unwrap();
        drop(connection);
        let mut connection = encrypted(&path);
        run_all(&mut connection).unwrap();
        let count: i64 = connection
            .query_row(
                "SELECT count(*) FROM cgka_experimental_device_sync_schema_migrations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, PRIVATE_MIGRATIONS.len() as i64);
        let core_private: i64 = connection
            .query_row(
                "SELECT count(*) FROM cgka_schema_migrations WHERE version>102",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(core_private, 0);
        let audit: i64 = connection.query_row("SELECT count(*) FROM cgka_experimental_device_sync_migration_bridge_audit WHERE original_applied_at_unix_seconds=17", [], |row| row.get(0)).unwrap();
        assert_eq!(audit, last as i64 - 102);
        let retained: i64 = connection
            .query_row(
                "SELECT count(*) FROM synchronized_history_retention_fences",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, 1);
        run_all(&mut connection).unwrap();
    }
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_ledger_missing_denial_trigger_rejected_without_mutation() {
    let mut connection = Connection::open_in_memory().unwrap();
    legacy_prefix(&mut connection, 110);
    connection
        .execute_batch("DROP TRIGGER private_device_invite_group_deleted")
        .unwrap();
    let before: i64 = connection
        .query_row("SELECT count(*) FROM cgka_schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(
        run_all(&mut connection).is_err(),
        "missing permanent-denial trigger must not be accepted"
    );
    let after: i64 = connection
        .query_row("SELECT count(*) FROM cgka_schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(before, after);
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_ledger_unknown_receipt_rejected_before_schema_writes() {
    let mut connection = Connection::open_in_memory().unwrap();
    run(&mut connection, &MIGRATIONS[..102]).unwrap();
    connection
        .execute(
            "INSERT INTO cgka_schema_migrations VALUES(103,'0103_history_acquisition_holds',17)",
            [],
        )
        .unwrap();
    assert!(run_all(&mut connection).is_err());
    let private_tables: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='synchronized_history_transfers'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(private_tables, 0);
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_ledger_corrupt_audit_rejected_on_reopen() {
    let mut connection = Connection::open_in_memory().unwrap();
    legacy_prefix(&mut connection, 110);
    run_all(&mut connection).unwrap();
    assert!(connection.execute("UPDATE cgka_experimental_device_sync_migration_bridge_audit SET original_name='unrecognized' WHERE original_version=103",[]).is_err());
    run_all(&mut connection).unwrap();
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_ledger_future_private_revision_and_unknown_objects_fail_closed() {
    let mut connection = Connection::open_in_memory().unwrap();
    run_all(&mut connection).unwrap();
    connection
        .execute(
            "INSERT INTO cgka_experimental_device_sync_schema_migrations(version,name,applied_at_unix_seconds) VALUES(?1,'future',17)",
            params![PRIVATE_MIGRATIONS.len() as i64 + 1],
        )
        .unwrap();
    assert!(run_all(&mut connection).is_err());
    let mut connection = Connection::open_in_memory().unwrap();
    run_all(&mut connection).unwrap();
    connection
        .execute_batch("CREATE INDEX unknown_private_index ON private_device_invite_staging(phase)")
        .unwrap();
    assert!(run_all(&mut connection).is_err());
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_ledger_bridge_failure_after_partial_receipt_transfer_rolls_back() {
    let mut connection = Connection::open_in_memory().unwrap();
    legacy_prefix(&mut connection, 110);
    connection
        .execute_batch(super::private_migration_ledger::NAMESPACE_SQL)
        .unwrap();
    connection.execute_batch("CREATE TEMP TRIGGER injected_transfer_failure BEFORE INSERT ON cgka_experimental_device_sync_migration_bridge_audit WHEN NEW.original_version=105 BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(run_all(&mut connection).is_err());
    let old: i64 = connection
        .query_row(
            "SELECT count(*) FROM cgka_schema_migrations WHERE version>102",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let audit: i64 = connection
        .query_row(
            "SELECT count(*) FROM cgka_experimental_device_sync_migration_bridge_audit",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(old, 8);
    assert_eq!(audit, 0);
    connection
        .execute_batch("DROP TRIGGER injected_transfer_failure")
        .unwrap();
    run_all(&mut connection).unwrap();
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_ledger_encrypted_unknown_and_confirmed_bytes_never_reclassified() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unknown.db");
    let mut connection = encrypted(&path);
    legacy_prefix(&mut connection, 110);
    connection.execute_batch("INSERT INTO private_device_invite_counter VALUES(1,7);
        INSERT INTO private_device_invite_staging VALUES(1,7,zeroblob(32),zeroblob(32),x'11',x'aa',x'bb',x'cc',x'dd',3);
        INSERT INTO private_device_invite_confirmed VALUES(1,6,zeroblob(32),zeroblob(32),x'11',x'ee',1);
        INSERT INTO device_group_genesis_selection VALUES(1,4,zeroblob(32),zeroblob(32),x'11',x'ff',1);
        INSERT INTO openmls_values VALUES(1,x'aa',x'bb',x'11',x'01020304');").unwrap();
    drop(connection);
    let mut connection = encrypted(&path);
    run_all(&mut connection).unwrap();
    let pending:(i64,Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>)=connection.query_row("SELECT phase,binding,raw_commit,raw_welcome,transport FROM private_device_invite_staging",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
    assert_eq!(pending, (3, vec![0xaa], vec![0xbb], vec![0xcc], vec![0xdd]));
    let confirmed: (i64, Vec<u8>) = connection
        .query_row(
            "SELECT denied,binding FROM private_device_invite_confirmed",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(confirmed, (1, vec![0xee]));
    let crypto: Vec<u8> = connection
        .query_row("SELECT value FROM openmls_values", [], |r| r.get(0))
        .unwrap();
    assert_eq!(crypto, vec![1, 2, 3, 4]);
    let birth: i64 = connection
        .query_row(
            "SELECT active_denied FROM device_group_genesis_selection",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(birth, 1);
    // SQL-boundary opaque fixtures, not a claim these bytes are valid MLS or SDK state.
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_ledger_mixed_old_and_private_receipts_never_adopted() {
    let mut connection = Connection::open_in_memory().unwrap();
    run_all(&mut connection).unwrap();
    connection
        .execute(
            "INSERT INTO cgka_schema_migrations VALUES(103,'0103_synchronized_history',17)",
            [],
        )
        .unwrap();
    assert!(run_all(&mut connection).is_err());
    assert_eq!(
        applied_name(&connection, 103).unwrap().as_deref(),
        Some("0103_synchronized_history")
    );
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_ledger_changed_core_parent_schema_is_not_a_recognized_bridge() {
    let mut connection = Connection::open_in_memory().unwrap();
    legacy_prefix(&mut connection, 110);
    connection
        .execute_batch("ALTER TABLE cgka_groups ADD COLUMN unexpected_bridge_column TEXT")
        .unwrap();
    assert!(
        run_all(&mut connection).is_err(),
        "a receipt prefix alone must not establish parent-schema compatibility"
    );
    let remaining: i64 = connection
        .query_row(
            "SELECT count(*) FROM cgka_schema_migrations WHERE version>102",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(remaining, 8);
}

#[cfg(not(feature = "experimental-device-sync"))]
#[test]
fn private_ledger_default_ordinary_encrypted_reopen_remains_supported() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ordinary.db");
    let mut connection = encrypted(&path);
    run(&mut connection, MIGRATIONS).unwrap();
    drop(connection);
    let key = SqlCipherKey::new("isolated private ledger synthetic key").unwrap();
    let storage = crate::SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    storage.close().unwrap();
    let reopened = crate::SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    reopened.close().unwrap();
}

#[cfg(not(feature = "experimental-device-sync"))]
#[test]
fn private_ledger_default_legacy_prefix_refuses_bridge_before_writes() {
    let mut connection = Connection::open_in_memory().unwrap();
    legacy_prefix(&mut connection, 103);
    assert!(run_all(&mut connection).is_err());
    assert_eq!(
        applied_name(&connection, 103).unwrap().as_deref(),
        Some("0103_synchronized_history")
    );
    let ledger:i64=connection.query_row("SELECT count(*) FROM sqlite_master WHERE name='cgka_experimental_device_sync_schema_migrations'",[],|r|r.get(0)).unwrap();
    assert_eq!(ledger, 0);
}

#[cfg(not(feature = "experimental-device-sync"))]
#[test]
fn private_ledger_default_retired_protected_footprints_refuse_encrypted_open() {
    for insert in [
        "INSERT INTO device_linking_attempt(singleton,account_id,local_device,generation,state) VALUES(1,zeroblob(32),zeroblob(32),1,4)",
        "INSERT INTO device_group_genesis_selection VALUES(1,1,zeroblob(32),zeroblob(32),x'11',x'aa',1)",
        "INSERT INTO accepted_device_group_anchor VALUES(1,1,zeroblob(32),zeroblob(32),x'11',x'aa',1)",
        "INSERT INTO private_device_invite_staging VALUES(1,1,zeroblob(32),zeroblob(32),x'11',x'aa',x'bb',x'cc',NULL,4)",
        "INSERT INTO private_device_invite_confirmed VALUES(1,1,zeroblob(32),zeroblob(32),x'11',x'aa',1)",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cohort.db");
        let mut connection = encrypted(&path);
        run_all(&mut connection).unwrap();
        connection.execute_batch(insert).unwrap();
        let before: i64 = connection
            .query_row(
                "SELECT count(*) FROM cgka_experimental_device_sync_schema_migrations",
                [],
                |r| r.get(0),
            )
            .unwrap();
        drop(connection);
        let key = SqlCipherKey::new("isolated private ledger synthetic key").unwrap();
        assert!(
            crate::SqliteAccountStorage::open_encrypted(&path, &key).is_err(),
            "retired private footprint must remain a negative default-build fence"
        );
        let connection = encrypted(&path);
        let after: i64 = connection
            .query_row(
                "SELECT count(*) FROM cgka_experimental_device_sync_schema_migrations",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(before, after);
    }
}

#[cfg(not(feature = "experimental-device-sync"))]
#[test]
fn private_ledger_default_cleared_capture_cannot_hide_cohort_activation() {
    let mut connection = Connection::open_in_memory().unwrap();
    run_all(&mut connection).unwrap();
    connection.execute_batch("INSERT INTO roster_ack_capture VALUES(1,1,x'11',x'aa'); DELETE FROM roster_ack_capture;").unwrap();
    assert!(
        run_all(&mut connection).is_err(),
        "private scope cleanup cannot make the cohort ordinary again"
    );
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_ledger_activation_cannot_be_cleared_by_update_delete_or_replace() {
    let mut connection = Connection::open_in_memory().unwrap();
    run_all(&mut connection).unwrap();
    connection.execute_batch("INSERT INTO roster_ack_capture VALUES(1,1,x'11',x'aa');DELETE FROM roster_ack_capture;").unwrap();
    for statement in [
        "UPDATE cgka_experimental_device_sync_cohort SET activated=0",
        "DELETE FROM cgka_experimental_device_sync_cohort",
        "INSERT OR REPLACE INTO cgka_experimental_device_sync_cohort VALUES(1,0)",
    ] {
        assert!(connection.execute_batch(statement).is_err());
    }
    run_all(&mut connection).unwrap();
    let activated: i64 = connection
        .query_row(
            "SELECT activated FROM cgka_experimental_device_sync_cohort",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(activated, 1);
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_ledger_bridge_audit_is_immutable_and_complete() {
    let mut connection = Connection::open_in_memory().unwrap();
    legacy_prefix(&mut connection, 110);
    run_all(&mut connection).unwrap();
    for mutation in [
        "DELETE FROM cgka_experimental_device_sync_migration_bridge_audit",
        "UPDATE cgka_experimental_device_sync_migration_bridge_audit SET original_applied_at_unix_seconds=18",
        "INSERT OR REPLACE INTO cgka_experimental_device_sync_migration_bridge_audit VALUES(103,'0103_synchronized_history',18,1)",
    ] {
        assert!(
            connection.execute(mutation, []).is_err(),
            "original bridge provenance must be immutable"
        );
    }
    run_all(&mut connection).unwrap();
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM cgka_experimental_device_sync_migration_bridge_audit",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 8);
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_ledger_missing_bridge_audit_cannot_be_adopted() {
    let mut connection = Connection::open_in_memory().unwrap();
    legacy_prefix(&mut connection, 110);
    connection
        .execute_batch(super::private_migration_ledger::NAMESPACE_SQL)
        .unwrap();
    // Malformed migration metadata fixture: tagged original receipts without their audit.
    for migration in PRIVATE_MIGRATIONS {
        connection
            .execute(
                "INSERT INTO cgka_experimental_device_sync_schema_migrations VALUES(?1,?2,17,1)",
                params![migration.version, migration.name],
            )
            .unwrap();
    }
    connection
        .execute("DELETE FROM cgka_schema_migrations WHERE version>102", [])
        .unwrap();
    assert!(run_all(&mut connection).is_err());
    let audit: i64 = connection
        .query_row(
            "SELECT count(*) FROM cgka_experimental_device_sync_migration_bridge_audit",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(audit, 0);
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_ledger_origin_receipts_cannot_be_rewritten() {
    let mut connection = Connection::open_in_memory().unwrap();
    legacy_prefix(&mut connection, 110);
    run_all(&mut connection).unwrap();
    for mutation in [
        "UPDATE cgka_experimental_device_sync_schema_migrations SET legacy_origin=0",
        "DELETE FROM cgka_experimental_device_sync_schema_migrations",
        "INSERT OR REPLACE INTO cgka_experimental_device_sync_schema_migrations VALUES(1,'0001_synchronized_history',17,0)",
    ] {
        assert!(connection.execute(mutation, []).is_err());
    }
    run_all(&mut connection).unwrap();
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_ledger_partial_audit_unique_revision_cannot_be_replaced() {
    let mut connection = Connection::open_in_memory().unwrap();
    legacy_prefix(&mut connection, 103);
    run_all(&mut connection).unwrap();
    assert!(connection.execute("INSERT OR REPLACE INTO cgka_experimental_device_sync_migration_bridge_audit VALUES(104,'0104_device_linking_attempt',17,1)",[]).is_err());
    let original: i64=connection.query_row("SELECT original_version FROM cgka_experimental_device_sync_migration_bridge_audit WHERE private_version=1",[],|r|r.get(0)).unwrap();
    assert_eq!(original, 103);
    run_all(&mut connection).unwrap();
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_privacy_revision9_backfills_negative_identifiers_without_changing_legacy_audit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("old-selected-private.sqlite");
    let mut connection = encrypted(&path);
    legacy_prefix(&mut connection, 110);
    // Protected schema columns only, not a crypto/consent fixture.
    connection
        .execute(
            "INSERT INTO device_group_genesis_selection VALUES(1,1,?1,?2,?3,?4,1)",
            params![[1u8; 32], [2u8; 32], vec![3u8; 19], b"{}".as_slice()],
        )
        .unwrap();
    run_all(&mut connection).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM private_group_chat_exclusion",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT max(version) FROM cgka_experimental_device_sync_schema_migrations",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        PRIVATE_MIGRATIONS.len() as i64
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM cgka_experimental_device_sync_migration_bridge_audit",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        8
    );
    assert_eq!(
        connection
            .query_row("SELECT max(version) FROM cgka_schema_migrations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        102
    );
    run_all(&mut connection).unwrap();
    drop(connection);
    let mut connection = encrypted(&path);
    run_all(&mut connection).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM private_group_chat_exclusion",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
}

#[cfg(not(feature = "experimental-device-sync"))]
#[test]
fn private_privacy_default_build_refuses_only_populated_negative_cohort() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("private-negative-only.sqlite");
    let mut connection = encrypted(&path);
    run_all(&mut connection).unwrap();
    run_all(&mut connection).unwrap();
    connection
        .execute(
            "INSERT INTO private_group_chat_exclusion VALUES(?1,?2,?3)",
            params![vec![4u8; 19], [1u8; 32], [2u8; 32]],
        )
        .unwrap();
    drop(connection);
    let mut connection = encrypted(&path);
    assert!(run_all(&mut connection).is_err());
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM private_group_chat_exclusion",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
}

#[cfg(feature = "experimental-device-sync")]
#[test]
fn private_settlement_revision10_preserves_constructed_encrypted_revision9_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("revision9.sqlite");
    let mut conn = encrypted(&path);
    run(&mut conn, MIGRATIONS).unwrap();
    conn.execute_batch(super::private_migration_ledger::NAMESPACE_SQL)
        .unwrap();
    for migration in PRIVATE_MIGRATIONS.iter().take(9) {
        let tx = conn.transaction().unwrap();
        (migration.apply)(&tx).unwrap();
        tx.execute("INSERT INTO cgka_experimental_device_sync_schema_migrations(version,name,applied_at_unix_seconds) VALUES(?1,?2,17)",params![migration.version,migration.name]).unwrap();
        tx.commit().unwrap();
    }
    conn.execute("INSERT INTO synchronized_history_retention_fences VALUES('opaque-group','abababababababababababababababababababababababababababababababab')",[]).unwrap();
    let before:Vec<(i64,String,i64)>=conn.prepare("SELECT version,name,applied_at_unix_seconds FROM cgka_experimental_device_sync_schema_migrations ORDER BY version").unwrap().query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap().map(|r|r.unwrap()).collect();
    drop(conn);
    let mut conn = encrypted(&path);
    assert_eq!(run_all(&mut conn).unwrap(), PRIVATE_MIGRATIONS.len() - 9);
    assert_eq!(run_all(&mut conn).unwrap(), 0);
    let after:Vec<(i64,String,i64)>=conn.prepare("SELECT version,name,applied_at_unix_seconds FROM cgka_experimental_device_sync_schema_migrations WHERE version<=9 ORDER BY version").unwrap().query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap().map(|r|r.unwrap()).collect();
    assert_eq!(before, after);
    assert_eq!(
        conn.query_row("SELECT max(version) FROM cgka_schema_migrations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        102
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM synchronized_history_retention_fences",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM private_roster_settlement", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
}

#[cfg(not(feature = "experimental-device-sync"))]
#[test]
fn private_settlement_default_open_refuses_activated_rows_after_close() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("activated.sqlite");
    let key = crate::SqlCipherKey::new("isolated synthetic settlement key").unwrap();
    let storage = crate::SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    drop(storage);
    let storage = crate::SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    storage
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO private_roster_settlement VALUES(1,1,?1,?2,?3,?4)",
            params![[1u8; 32], [2u8; 32], vec![3u8; 19], b"{}".as_slice()],
        )
        .unwrap();
    drop(storage);
    assert!(crate::SqliteAccountStorage::open_encrypted(&path, &key).is_err());
}
