//! Separate experimental schema lineage and a recognized, audited legacy bridge.
//! No row in either ledger is consent, crypto evidence, or publication authority.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

type Schema = BTreeMap<String, (String, String)>;
pub(super) const NAMESPACE_SQL: &str =
    "CREATE TABLE IF NOT EXISTS cgka_experimental_device_sync_schema_migrations (
        version INTEGER PRIMARY KEY NOT NULL CHECK(version>0),
        name TEXT NOT NULL,
        applied_at_unix_seconds INTEGER NOT NULL,
        legacy_origin INTEGER NOT NULL DEFAULT 0 CHECK(legacy_origin IN(0,1))
    );
    CREATE TABLE IF NOT EXISTS cgka_experimental_device_sync_migration_bridge_audit (
        original_version INTEGER PRIMARY KEY NOT NULL CHECK(original_version BETWEEN 103 AND 110),
        original_name TEXT NOT NULL,
        original_applied_at_unix_seconds INTEGER NOT NULL,
        private_version INTEGER NOT NULL UNIQUE CHECK(private_version BETWEEN 1 AND 8)
    );
    CREATE TRIGGER IF NOT EXISTS cgka_experimental_device_sync_receipt_no_update
    BEFORE UPDATE ON cgka_experimental_device_sync_schema_migrations
    BEGIN SELECT RAISE(ABORT,'private migration provenance is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS cgka_experimental_device_sync_receipt_no_delete
    BEFORE DELETE ON cgka_experimental_device_sync_schema_migrations
    BEGIN SELECT RAISE(ABORT,'private migration provenance is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS cgka_experimental_device_sync_receipt_no_replace
    BEFORE INSERT ON cgka_experimental_device_sync_schema_migrations
    WHEN EXISTS(SELECT 1 FROM cgka_experimental_device_sync_schema_migrations WHERE version=NEW.version)
    BEGIN SELECT RAISE(ABORT,'private migration provenance is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS cgka_experimental_device_sync_audit_no_update
    BEFORE UPDATE ON cgka_experimental_device_sync_migration_bridge_audit
    BEGIN SELECT RAISE(ABORT,'private migration provenance is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS cgka_experimental_device_sync_audit_no_delete
    BEFORE DELETE ON cgka_experimental_device_sync_migration_bridge_audit
    BEGIN SELECT RAISE(ABORT,'private migration provenance is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS cgka_experimental_device_sync_audit_no_replace
    BEFORE INSERT ON cgka_experimental_device_sync_migration_bridge_audit
    WHEN EXISTS(SELECT 1 FROM cgka_experimental_device_sync_migration_bridge_audit WHERE original_version=NEW.original_version OR private_version=NEW.private_version)
    BEGIN SELECT RAISE(ABORT,'private migration provenance is immutable'); END;
    CREATE TABLE IF NOT EXISTS cgka_experimental_device_sync_cohort (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        activated INTEGER NOT NULL CHECK(activated IN(0,1))
    );
    CREATE TRIGGER IF NOT EXISTS cgka_experimental_device_sync_no_deactivate
    BEFORE UPDATE ON cgka_experimental_device_sync_cohort
    WHEN OLD.activated=1 AND NEW.activated!=1
    BEGIN SELECT RAISE(ABORT,'private cohort cannot be deactivated'); END;
    CREATE TRIGGER IF NOT EXISTS cgka_experimental_device_sync_no_delete
    BEFORE DELETE ON cgka_experimental_device_sync_cohort
    BEGIN SELECT RAISE(ABORT,'private cohort marker cannot be deleted'); END;
    CREATE TRIGGER IF NOT EXISTS cgka_experimental_device_sync_no_replace
    BEFORE INSERT ON cgka_experimental_device_sync_cohort
    WHEN NEW.activated!=1 AND EXISTS(SELECT 1 FROM cgka_experimental_device_sync_cohort WHERE activated=1)
    BEGIN SELECT RAISE(ABORT,'private cohort cannot be deactivated'); END;
    INSERT INTO cgka_experimental_device_sync_cohort SELECT 1,0 WHERE NOT EXISTS(SELECT 1 FROM cgka_experimental_device_sync_cohort);";

const LEDGER: &str = "cgka_experimental_device_sync_schema_migrations";
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

fn denied() -> StorageError {
    StorageError::Backend("unrecognized experimental schema lineage".into())
}

pub(super) fn run_all(connection: &mut Connection) -> StorageResult<usize> {
    ensure_ordered(MIGRATIONS)?;
    ensure_ordered(PRIVATE_MIGRATIONS)?;
    let schemas = expected_private_schemas()?;
    let tx = connection.transaction().storage()?;
    ensure_migration_table(&tx)?;
    // All bridge, schema and receipt writes commit together, including legacy9 repair.
    let old = legacy_receipts(&tx)?;
    let existing_namespace = table_exists(&tx, LEDGER)?;
    if existing_namespace {
        validate_namespace(&tx)?;
        cohort_activation(&tx)?;
    }
    #[cfg(not(feature = "experimental-device-sync"))]
    reject_disabled_cohort(
        &tx,
        !old.is_empty(),
        existing_namespace,
        schemas.last().unwrap(),
    )?;
    reconcile_legacy_name_in_transaction(&tx)?;
    if !old.is_empty() {
        for migration in MIGRATIONS
            .iter()
            .take_while(|migration| migration.version <= 102)
        {
            if applied_name(&tx, migration.version)?.as_deref() != Some(migration.name) {
                return Err(denied());
            }
        }
        validate_legacy_core_schema(&tx)?;
        validate_schema(&tx, &schemas[old.len() - 1], schemas.last().unwrap())?;
    }
    tx.execute_batch(NAMESPACE_SQL).storage()?;
    validate_namespace(&tx)?;
    let existing = private_receipts(&tx)?;
    if !old.is_empty() && !existing.is_empty() {
        return Err(denied());
    }
    if !existing.is_empty() {
        validate_schema(&tx, &schemas[existing.len() - 1], schemas.last().unwrap())?;
    } else if old.is_empty() {
        // Receipts are mandatory: never silently adopt unrecorded private objects.
        validate_schema(&tx, &Schema::new(), schemas.last().unwrap())?;
    }
    for (version, name, applied_at) in &old {
        let revision = version - 102;
        let migration = &PRIVATE_MIGRATIONS[(revision - 1) as usize];
        tx.execute(
            "INSERT INTO cgka_experimental_device_sync_schema_migrations(version,name,applied_at_unix_seconds,legacy_origin) VALUES(?1,?2,?3,1)",
            params![revision, migration.name, applied_at],
        )
        .storage()?;
        tx.execute(
            "INSERT INTO cgka_experimental_device_sync_migration_bridge_audit VALUES(?1,?2,?3,?4)",
            params![version, name, applied_at, revision],
        )
        .storage()?;
        tx.execute(
            "DELETE FROM cgka_schema_migrations WHERE version=?1 AND name=?2",
            params![version, name],
        )
        .storage()?;
    }
    reject_unknown_future_migrations(&tx, MIGRATIONS)?;
    let mut applied = 0;
    for migration in MIGRATIONS {
        match applied_name(&tx, migration.version)? {
            Some(name) if name == migration.name => {}
            Some(_) => return Err(denied()),
            None => {
                (migration.apply)(&tx)?;
                tx.execute("INSERT INTO cgka_schema_migrations VALUES(?1,?2,CAST(strftime('%s','now') AS INTEGER))",params![migration.version,migration.name]).storage()?;
                #[cfg(test)]
                migration_crash_pause(migration.version);
                applied += 1;
            }
        }
    }
    let count = private_receipts(&tx)?.len();
    for migration in PRIVATE_MIGRATIONS.iter().skip(count) {
        (migration.apply)(&tx)?;
        tx.execute("INSERT INTO cgka_experimental_device_sync_schema_migrations(version,name,applied_at_unix_seconds) VALUES(?1,?2,CAST(strftime('%s','now') AS INTEGER))",params![migration.version,migration.name]).storage()?;
        applied += 1;
    }
    install_activation_triggers(&tx, schemas.last().unwrap())?;
    if !old.is_empty() || has_private_rows(&tx, schemas.last().unwrap())? {
        tx.execute(
            "UPDATE cgka_experimental_device_sync_cohort SET activated=1 WHERE singleton=1",
            [],
        )
        .storage()?;
    }
    validate_schema(&tx, schemas.last().unwrap(), schemas.last().unwrap())?;
    validate_audit(&tx)?;
    tx.commit().storage()?;
    Ok(applied)
}

// Recognize the frozen experimental core-102 prefix by exact names. New upstream
// receipts share these numbers, but belong to the ordinary ledger, never the bridge.
fn legacy_receipts(connection: &Connection) -> StorageResult<Vec<(i64, String, i64)>> {
    let mut statement = connection.prepare("SELECT version,name,applied_at_unix_seconds FROM cgka_schema_migrations WHERE version>102 ORDER BY version").storage()?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .storage()?;
    let mut result = Vec::new();
    let mut upstream = false;
    for row in rows {
        let value: (i64, String, i64) = row.storage()?;
        if MIGRATIONS
            .iter()
            .any(|migration| migration.version == value.0 && migration.name == value.1)
        {
            if !result.is_empty() {
                return Err(denied());
            }
            upstream = true;
            continue;
        }
        let index = result.len();
        if upstream
            || index >= LEGACY_NAMES.len()
            || value.0 != 103 + index as i64
            || value.1 != LEGACY_NAMES[index]
        {
            return Err(denied());
        }
        result.push(value);
    }
    Ok(result)
}

fn private_receipts(connection: &Connection) -> StorageResult<Vec<i64>> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT version,name FROM {LEDGER} ORDER BY version"
        ))
        .storage()?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .storage()?;
    let mut result = Vec::new();
    for row in rows {
        let (version, name) = row.storage()?;
        let Some(expected) = PRIVATE_MIGRATIONS.get(result.len()) else {
            return Err(denied());
        };
        if version != expected.version || name != expected.name {
            return Err(denied());
        }
        result.push(version);
    }
    Ok(result)
}

fn schema(connection: &Connection) -> StorageResult<Schema> {
    let mut statement = connection.prepare("SELECT name,tbl_name,sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY name").storage()?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                (row.get::<_, String>(1)?, row.get::<_, String>(2)?),
            ))
        })
        .storage()?;
    rows.map(|row| row.storage()).collect()
}

fn expected_private_schemas() -> StorageResult<&'static Vec<Schema>> {
    static EXPECTED: OnceLock<Result<Vec<Schema>, ()>> = OnceLock::new();
    EXPECTED
        .get_or_init(|| {
            let result = (|| -> StorageResult<Vec<Schema>> {
                let mut reference = Connection::open_in_memory().storage()?;
                run_with_summary(&mut reference, MIGRATIONS)?;
                let core = schema(&reference)?;
                let mut schemas = Vec::new();
                for migration in PRIVATE_MIGRATIONS {
                    let tx = reference.transaction().storage()?;
                    (migration.apply)(&tx)?;
                    tx.commit().storage()?;
                    schemas.push(
                        schema(&reference)?
                            .into_iter()
                            .filter(|(name, _)| !core.contains_key(name))
                            .collect(),
                    );
                }
                Ok(schemas)
            })();
            result.map_err(|_| ())
        })
        .as_ref()
        .map_err(|_| StorageError::Backend("experimental schema reference unavailable".into()))
}

fn validate_schema(
    connection: &Connection,
    expected: &Schema,
    complete: &Schema,
) -> StorageResult<()> {
    let actual = schema(connection)?;
    let private_tables: BTreeSet<&str> = complete
        .iter()
        .filter(|(name, (table, _))| *name == table)
        .map(|(_, (table, _))| table.as_str())
        .collect();
    for (name, value) in expected {
        if actual.get(name) != Some(value) {
            return Err(denied());
        }
    }
    for (name, (table, sql)) in &actual {
        if name.starts_with("cgka_experimental_device_sync_activate_")
            && expected.contains_key(table)
        {
            let (known_name, known_sql) = activation_trigger(table);
            if *name != known_name || *sql != known_sql {
                return Err(denied());
            }
            continue;
        }
        if (complete.contains_key(name) || private_tables.contains(table.as_str()))
            && !expected.contains_key(name)
        {
            return Err(denied());
        }
    }
    Ok(())
}

fn validate_namespace(connection: &Connection) -> StorageResult<()> {
    let reference = Connection::open_in_memory().storage()?;
    reference.execute_batch(NAMESPACE_SQL).storage()?;
    let expected = schema(&reference)?;
    validate_schema(connection, &expected, &expected)
}

fn validate_audit(connection: &Connection) -> StorageResult<()> {
    let mut statement = connection.prepare("SELECT original_version,original_name,original_applied_at_unix_seconds,private_version FROM cgka_experimental_device_sync_migration_bridge_audit ORDER BY original_version").storage()?;
    let rows = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .storage()?;
    for row in rows {
        let (version, name, applied, revision) = row.storage()?;
        if !(1..=8).contains(&revision) {
            return Err(denied());
        }
        let index = usize::try_from(revision - 1).map_err(|_| denied())?;
        if !(103..=110).contains(&version)
            || revision != version - 102
            || LEGACY_NAMES
                .get(index)
                .map(|value| *value != name)
                .unwrap_or(true)
        {
            return Err(denied());
        }
        let recorded: Option<(i64,i64)> = connection.query_row("SELECT applied_at_unix_seconds,legacy_origin FROM cgka_experimental_device_sync_schema_migrations WHERE version=?1",params![revision],|r|Ok((r.get(0)?,r.get(1)?))).optional().storage()?;
        if recorded != Some((applied, 1)) {
            return Err(denied());
        }
    }
    let missing: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM cgka_experimental_device_sync_schema_migrations r WHERE r.legacy_origin=1 AND NOT EXISTS(SELECT 1 FROM cgka_experimental_device_sync_migration_bridge_audit a WHERE a.private_version=r.version))",
        [], |r| r.get(0),
    ).storage()?;
    if missing {
        return Err(denied());
    }
    Ok(())
}

fn validate_legacy_core_schema(connection: &Connection) -> StorageResult<()> {
    static CORE: OnceLock<Result<Schema, ()>> = OnceLock::new();
    let expected = CORE
        .get_or_init(|| {
            (|| -> StorageResult<Schema> {
                let mut reference = Connection::open_in_memory().storage()?;
                let frozen_core =
                    &MIGRATIONS[..MIGRATIONS.partition_point(|migration| migration.version <= 102)];
                run_with_summary(&mut reference, frozen_core)?;
                schema(&reference)
            })()
            .map_err(|_| ())
        })
        .as_ref()
        .map_err(|_| StorageError::Backend("legacy core schema reference unavailable".into()))?;
    let actual = schema(connection)?;
    for (name, value) in expected {
        if actual.get(name) != Some(value) {
            return Err(denied());
        }
    }
    Ok(())
}

fn table_exists(connection: &Connection, name: &str) -> StorageResult<bool> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            params![name],
            |row| row.get(0),
        )
        .storage()
}

fn private_tables(schema: &Schema) -> impl Iterator<Item = &str> {
    schema
        .iter()
        .filter(|(name, (table, _))| *name == table)
        .map(|(_, (table, _))| table.as_str())
}

fn activation_trigger(table: &str) -> (String, String) {
    let name = format!("cgka_experimental_device_sync_activate_{table}");
    let sql = format!(
        "CREATE TRIGGER {name} AFTER INSERT ON {table} BEGIN UPDATE cgka_experimental_device_sync_cohort SET activated=1 WHERE singleton=1; END"
    );
    (name, sql)
}

fn install_activation_triggers(connection: &Connection, complete: &Schema) -> StorageResult<()> {
    let objects = schema(connection)?;
    for table in private_tables(complete) {
        let (name, sql) = activation_trigger(table);
        match objects.get(&name) {
            Some((parent, actual)) if parent == table && actual == &sql => {}
            Some(_) => return Err(denied()),
            None => connection.execute_batch(&sql).storage()?,
        }
    }
    Ok(())
}

fn has_private_rows(connection: &Connection, complete: &Schema) -> StorageResult<bool> {
    for table in private_tables(complete) {
        if table_exists(connection, table)?
            && connection
                .query_row(
                    &format!("SELECT EXISTS(SELECT 1 FROM {table} LIMIT 1)"),
                    [],
                    |row| row.get::<_, bool>(0),
                )
                .storage()?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn cohort_activation(connection: &Connection) -> StorageResult<bool> {
    let activated: Option<i64> = connection
        .query_row(
            "SELECT activated FROM cgka_experimental_device_sync_cohort WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()
        .storage()?;
    match activated {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(denied()),
    }
}

#[cfg(not(feature = "experimental-device-sync"))]
fn reject_disabled_cohort(
    connection: &Connection,
    legacy: bool,
    namespace: bool,
    complete: &Schema,
) -> StorageResult<()> {
    if legacy
        || (namespace && cohort_activation(connection)?)
        || has_private_rows(connection, complete)?
    {
        return Err(StorageError::Backend(
            "experimental private cohort requires experimental-device-sync".into(),
        ));
    }
    Ok(())
}
