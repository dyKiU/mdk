//! Atomic purpose metadata; neither this record nor verifier facts authorize joins.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::device_linking_key_package::{
    PurposeAttemptScope, PurposeContextBinding, PurposeKeyPackage, PurposeKeyPackageStorage,
};
use cgka_traits::storage::{StorageError, StorageProvider, StorageResult};
use rusqlite::{OptionalExtension, params};

const SELECT: &str = "SELECT generation,account_id,local_device,public_bytes,key_package_ref,signature_key,nonce,context_digest,consumed FROM device_linking_key_package WHERE singleton=1";
const INSERT: &str = "INSERT INTO device_linking_key_package(singleton,generation,account_id,local_device,public_bytes,key_package_ref,signature_key,nonce,context_digest,consumed) VALUES(1,?1,?2,?3,?4,?5,?6,NULL,NULL,0)";
const CURRENT_ATTEMPT: &str = "SELECT state,nonce,context_digest FROM device_linking_attempt WHERE singleton=1 AND generation=?1 AND account_id=?2 AND local_device=?3";
const BIND_CONTEXT: &str =
    "UPDATE device_linking_key_package SET nonce=?1,context_digest=?2 WHERE singleton=1";
fn invalid() -> StorageError {
    StorageError::Serialization("invalid linking package ownership".into())
}
fn generation(scope: &PurposeAttemptScope) -> StorageResult<i64> {
    if scope.generation == 0 || scope.generation > i64::MAX as u64 {
        return Err(invalid());
    }
    Ok(scope.generation as i64)
}
fn validate(package: &PurposeKeyPackage) -> StorageResult<()> {
    generation(&package.scope)?;
    if package.public_bytes.is_empty()
        || package.public_bytes.len() > 16384
        || package.reference.is_empty()
        || package.reference.len() > 256
        || package.signature_public_key.is_empty()
        || package.signature_public_key.len() > 256
        || package.signature_public_key.as_slice() != package.scope.local_device
        || (package.consumed && package.context.is_none())
    {
        return Err(invalid());
    }
    if let Some(binding) = &package.context {
        validate_context(binding)?;
    }
    Ok(())
}
fn validate_context(binding: &PurposeContextBinding) -> StorageResult<()> {
    if binding.nonce == [0; 32] || binding.context_digest == [0; 32] {
        return Err(invalid());
    }
    Ok(())
}
fn read(conn: &rusqlite::Connection) -> StorageResult<Option<PurposeKeyPackage>> {
    let record = conn
        .query_row(SELECT, [], |row| {
            let generation: i64 = row.get(0)?;
            let account: Vec<u8> = row.get(1)?;
            let device: Vec<u8> = row.get(2)?;
            let nonce: Option<Vec<u8>> = row.get(6)?;
            let digest: Option<Vec<u8>> = row.get(7)?;
            let consumed: i64 = row.get(8)?;
            if generation <= 0 || !matches!(consumed, 0 | 1) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let context = match (nonce, digest) {
                (None, None) => None,
                (Some(nonce), Some(digest)) => Some(PurposeContextBinding {
                    nonce: nonce
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    context_digest: digest
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                }),
                _ => return Err(rusqlite::Error::InvalidQuery),
            };
            Ok(PurposeKeyPackage {
                scope: PurposeAttemptScope {
                    account: account
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    local_device: device
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    generation: generation as u64,
                },
                public_bytes: row.get(3)?,
                reference: row.get(4)?,
                signature_public_key: row.get(5)?,
                context,
                consumed: consumed == 1,
            })
        })
        .optional()
        .storage()?;
    if let Some(package) = &record {
        validate(package)?;
    }
    Ok(record)
}
struct AttemptState {
    state: i64,
    nonce: Option<Vec<u8>>,
    digest: Option<Vec<u8>>,
}
fn check(conn: &rusqlite::Connection, scope: &PurposeAttemptScope) -> StorageResult<AttemptState> {
    let generation = generation(scope)?;
    conn.query_row(
        CURRENT_ATTEMPT,
        params![
            generation,
            scope.account.as_slice(),
            scope.local_device.as_slice()
        ],
        |row| {
            Ok(AttemptState {
                state: row.get(0)?,
                nonce: row.get(1)?,
                digest: row.get(2)?,
            })
        },
    )
    .optional()
    .storage()?
    .ok_or(StorageError::NotFound)
}
impl PurposeKeyPackageStorage for SqliteAccountStorage {
    fn check_purpose_reservation(&self, scope: &PurposeAttemptScope) -> StorageResult<()> {
        let conn = self.lock()?;
        if check(&conn, scope)?.state != 0 {
            return Err(invalid());
        }
        Ok(())
    }
    fn purpose_key_package(&self) -> StorageResult<Option<PurposeKeyPackage>> {
        let conn = self.lock()?;
        read(&conn)
    }
    fn put_purpose_key_package(&self, package: &PurposeKeyPackage) -> StorageResult<()> {
        validate(package)?;
        if package.consumed || package.context.is_some() {
            return Err(invalid());
        }
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            if check(&conn, &package.scope)?.state != 0 {
                return Err(invalid());
            }
            if let Some(existing) = read(&conn)? {
                if existing == *package {
                    return Ok(());
                }
                if !existing.consumed || existing.scope.generation >= package.scope.generation {
                    return Err(StorageError::AlreadyExists);
                }
                conn.execute(
                    "DELETE FROM device_linking_key_package WHERE singleton=1",
                    [],
                )
                .storage()?;
            }
            conn.execute(
                INSERT,
                params![
                    generation(&package.scope)?,
                    package.scope.account.as_slice(),
                    package.scope.local_device.as_slice(),
                    &package.public_bytes,
                    &package.reference,
                    &package.signature_public_key
                ],
            )
            .storage()?;
            Ok(())
        })
    }
    fn bind_purpose_context(
        &self,
        scope: &PurposeAttemptScope,
        binding: &PurposeContextBinding,
    ) -> StorageResult<()> {
        validate_context(binding)?;
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let AttemptState {
                state,
                nonce,
                digest,
            } = check(&conn, scope)?;
            if !(1..=3).contains(&state)
                || nonce.as_deref() != Some(binding.nonce.as_slice())
                || digest.as_deref() != Some(binding.context_digest.as_slice())
            {
                return Err(invalid());
            }
            let existing = read(&conn)?.ok_or(StorageError::NotFound)?;
            if existing.scope != *scope || existing.consumed {
                return Err(invalid());
            }
            if let Some(previous) = existing.context {
                return if previous == *binding {
                    Ok(())
                } else {
                    Err(invalid())
                };
            }
            conn.execute(
                BIND_CONTEXT,
                params![binding.nonce.as_slice(), binding.context_digest.as_slice()],
            )
            .storage()?;
            Ok(())
        })
    }

    fn check_purpose_join(&self, scope: &PurposeAttemptScope) -> StorageResult<()> {
        let conn = self.lock()?;
        let AttemptState {
            state,
            nonce,
            digest,
        } = check(&conn, scope)?;
        let existing = read(&conn)?.ok_or(StorageError::NotFound)?;
        let binding = existing.context.ok_or_else(invalid)?;
        if state != 3
            || existing.scope != *scope
            || existing.consumed
            || nonce.as_deref() != Some(binding.nonce.as_slice())
            || digest.as_deref() != Some(binding.context_digest.as_slice())
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn check_purpose_commit(&self, scope: &PurposeAttemptScope) -> StorageResult<()> {
        let conn = self.lock()?;
        let AttemptState {
            state,
            nonce,
            digest,
        } = check(&conn, scope)?;
        let existing = read(&conn)?.ok_or(StorageError::NotFound)?;
        let binding = existing.context.ok_or_else(invalid)?;
        if state != 3
            || existing.scope != *scope
            || !existing.consumed
            || nonce.as_deref() != Some(binding.nonce.as_slice())
            || digest.as_deref() != Some(binding.context_digest.as_slice())
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn consume_purpose_key_package(&self, scope: &PurposeAttemptScope) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            let AttemptState {
                state,
                nonce,
                digest,
            } = check(&conn, scope)?;
            let existing = read(&conn)?.ok_or(StorageError::NotFound)?;
            let binding = existing.context.ok_or_else(invalid)?;
            if state != 3
                || existing.scope != *scope
                || nonce.as_deref() != Some(binding.nonce.as_slice())
                || digest.as_deref() != Some(binding.context_digest.as_slice())
            {
                return Err(invalid());
            }
            conn.execute(
                "UPDATE device_linking_key_package SET consumed=1 WHERE singleton=1",
                [],
            )
            .storage()?;
            Ok(())
        })
    }
    fn retire_purpose_key_package(&self, scope: &PurposeAttemptScope) -> StorageResult<()> {
        self.with_transaction(|storage| {
            let conn = storage.lock()?;
            if check(&conn, scope)?.state < 3 {
                return Err(invalid());
            }
            if let Some(existing) = read(&conn)? {
                if existing.scope != *scope {
                    return Err(invalid());
                }
                conn.execute(
                    "DELETE FROM device_linking_key_package WHERE singleton=1",
                    [],
                )
                .storage()?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
