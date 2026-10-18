//! Default-off device-local verification fences. No enrollment authorization.
//! The runtime supplies its independent device identity and the verifier's facts.
//! Before constructing a verifier on startup it must abandon pending attempts;
//! ephemeral verifier secrets are never persisted or restored by this module.
use crate::{SqliteAppStorage, SqliteResultExt};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};

#[derive(Debug, thiserror::Error)]
pub enum DeviceLinkingError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("linking account does not match this store")]
    WrongAccount,
    #[error("linking device does not match this store")]
    WrongDevice,
    #[error("a linking attempt is already active")]
    Busy,
    #[error("linking generation is no longer current")]
    StaleGeneration,
    #[error("invalid linking binding")]
    InvalidBinding,
    #[error("linking context or flow does not match")]
    BindingMismatch,
    #[error("linking attempt is terminal")]
    Terminal,
    #[error("linking generation is exhausted")]
    GenerationExhausted,
}
type Result<T> = std::result::Result<T, DeviceLinkingError>;

/// Opaque binding supplied by the exact per-device verifier context. No Debug.
#[derive(Clone)]
pub struct DeviceLinkingBinding {
    pub generation: u64,
    pub nonce: [u8; 32],
    pub context_digest: [u8; 32],
}

/// Terminal facts only. PairingVerified is not membership or history permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub enum DeviceLinkingOutcome {
    PairingVerified = 3,
    Cancelled = 4,
    Expired = 5,
    SimultaneousRequest = 6,
    Shutdown = 7,
    RestartAbandoned = 8,
    IntegrityFailure = 9,
}

const RESERVED: i64 = 0;
const BOUND: i64 = 1;
const FLOW_BOUND: i64 = 2;

struct CurrentAttempt {
    state: i64,
    nonce: Option<Vec<u8>>,
    digest: Option<Vec<u8>>,
    flow: Option<String>,
}

fn generation_sql(generation: u64) -> Result<i64> {
    if generation == 0 || generation > i64::MAX as u64 {
        return Err(DeviceLinkingError::InvalidBinding);
    }
    Ok(generation as i64)
}

fn current(conn: &rusqlite::Connection, generation: u64) -> Result<CurrentAttempt> {
    let generation = generation_sql(generation)?;
    conn.query_row(
        "SELECT state,nonce,context_digest,flow FROM device_linking_attempt WHERE singleton=1 AND generation=?1",
        [generation],
        |row| Ok(CurrentAttempt { state: row.get(0)?, nonce: row.get(1)?, digest: row.get(2)?, flow: row.get(3)? }),
    ).optional().storage()?.ok_or(DeviceLinkingError::StaleGeneration)
}

fn validate_binding(binding: &DeviceLinkingBinding) -> Result<()> {
    generation_sql(binding.generation)?;
    if binding.nonce == [0; 32] || binding.context_digest == [0; 32] {
        return Err(DeviceLinkingError::InvalidBinding);
    }
    Ok(())
}

fn check_binding(attempt: &CurrentAttempt, binding: &DeviceLinkingBinding) -> Result<()> {
    if attempt.state >= DeviceLinkingOutcome::PairingVerified as i64 {
        return Err(DeviceLinkingError::Terminal);
    }
    if attempt.nonce.as_deref() != Some(binding.nonce.as_slice())
        || attempt.digest.as_deref() != Some(binding.context_digest.as_slice())
    {
        return Err(DeviceLinkingError::BindingMismatch);
    }
    Ok(())
}

impl SqliteAppStorage {
    /// Reserve before exchanging verifier offers. Remote frames cannot allocate
    /// rows. The trusted runtime supplies the account and its local MLS identity.
    pub fn reserve_device_linking_attempt(
        &self,
        account: &[u8; 32],
        device: &[u8; 32],
    ) -> Result<u64> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let account_matches: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM account_state WHERE local_account_id_hex=?1)",
                [hex::encode(account)],
                |row| row.get(0),
            )
            .storage()?;
        if !account_matches {
            return Err(DeviceLinkingError::WrongAccount);
        }
        let previous: Option<(Vec<u8>, Vec<u8>, i64, i64)> = tx.query_row(
            "SELECT account_id,local_device,generation,state FROM device_linking_attempt WHERE singleton=1",
            [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional().storage()?;
        let next = match previous {
            Some((saved_account, saved_device, generation, state)) => {
                if saved_account.as_slice() != account {
                    return Err(DeviceLinkingError::WrongAccount);
                }
                if saved_device.as_slice() != device {
                    return Err(DeviceLinkingError::WrongDevice);
                }
                if state < DeviceLinkingOutcome::PairingVerified as i64 {
                    return Err(DeviceLinkingError::Busy);
                }
                generation
                    .checked_add(1)
                    .ok_or(DeviceLinkingError::GenerationExhausted)?
            }
            None => 1,
        };
        // A verifier terminal fact is not enrollment completion. Preserve the
        // exact recipient bundle until its owner consumes or atomically retires
        // it; a new generation must never orphan verified-but-unjoined material.
        let outstanding_purpose: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM device_linking_key_package WHERE singleton=1 AND consumed=0)",
            [], |row| row.get(0),
        ).storage()?;
        if outstanding_purpose {
            return Err(DeviceLinkingError::Busy);
        }
        if crate::private_device_invite::has_unresolved_invite(&tx).map_err(
            |error| match error {
                cgka_traits::private_device_invite::PrivateInviteStorageError::Storage(error) => {
                    DeviceLinkingError::Storage(error)
                }
                _ => DeviceLinkingError::InvalidBinding,
            },
        )? {
            return Err(DeviceLinkingError::Busy);
        }
        tx.execute(
            "INSERT INTO device_linking_attempt(singleton,account_id,local_device,generation,state) VALUES(1,?1,?2,?3,0)
             ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation,state=0,nonce=NULL,context_digest=NULL,flow=NULL",
            params![account.as_slice(), device.as_slice(), next],
        ).storage()?;
        tx.commit().storage()?;
        Ok(next as u64)
    }

    /// Freeze the final mutually agreed context before any verifier output.
    pub fn bind_device_linking_context(&self, binding: &DeviceLinkingBinding) -> Result<()> {
        validate_binding(binding)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let attempt = current(&tx, binding.generation)?;
        if attempt.state == RESERVED {
            tx.execute(
                "UPDATE device_linking_attempt SET state=1,nonce=?1,context_digest=?2 WHERE singleton=1",
                params![binding.nonce.as_slice(), binding.context_digest.as_slice()],
            ).storage()?;
        } else {
            check_binding(&attempt, binding)?;
        }
        tx.commit().storage()?;
        Ok(())
    }

    /// Bind the exact opaque SDK flow before delivering verification frames.
    pub fn bind_device_linking_flow(
        &self,
        binding: &DeviceLinkingBinding,
        flow: &str,
    ) -> Result<()> {
        validate_binding(binding)?;
        if flow.is_empty() || flow.len() > 128 {
            return Err(DeviceLinkingError::InvalidBinding);
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let attempt = current(&tx, binding.generation)?;
        check_binding(&attempt, binding)?;
        if attempt.state == BOUND {
            tx.execute(
                "UPDATE device_linking_attempt SET state=2,flow=?1 WHERE singleton=1",
                [flow],
            )
            .storage()?;
        } else if attempt.state != FLOW_BOUND || attempt.flow.as_deref() != Some(flow) {
            return Err(DeviceLinkingError::BindingMismatch);
        }
        tx.commit().storage()?;
        Ok(())
    }

    /// Read-only admission fence; the runtime must also verify cryptographic input.
    pub fn check_device_linking_flow(
        &self,
        binding: &DeviceLinkingBinding,
        flow: &str,
    ) -> Result<()> {
        validate_binding(binding)?;
        let conn = self.lock()?;
        let attempt = current(&conn, binding.generation)?;
        check_binding(&attempt, binding)?;
        if attempt.state != FLOW_BOUND || attempt.flow.as_deref() != Some(flow) {
            return Err(DeviceLinkingError::BindingMismatch);
        }
        Ok(())
    }

    /// Persist a verifier-owned terminal fact. This cannot grant enrollment.
    pub fn finish_device_linking_attempt(
        &self,
        generation: u64,
        outcome: DeviceLinkingOutcome,
    ) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let attempt = current(&tx, generation)?;
        if attempt.state >= DeviceLinkingOutcome::PairingVerified as i64 {
            if attempt.state != outcome as i64 {
                return Err(DeviceLinkingError::Terminal);
            }
        } else {
            if outcome == DeviceLinkingOutcome::PairingVerified && attempt.state != FLOW_BOUND {
                return Err(DeviceLinkingError::InvalidBinding);
            }
            tx.execute(
                "UPDATE device_linking_attempt SET state=?1 WHERE singleton=1",
                [outcome as i64],
            )
            .storage()?;
        }
        tx.commit().storage()?;
        Ok(())
    }

    /// Call once when the account runtime starts, before restoring any linking UI.
    /// Never call merely because another storage handle opens during a live flow.
    pub fn abandon_device_linking_on_startup(&self) -> StorageResult<bool> {
        Ok(self
            .lock()?
            .execute(
                "UPDATE device_linking_attempt SET state=8 WHERE singleton=1 AND state IN (0,1,2)",
                [],
            )
            .storage()?
            == 1)
    }
}

#[cfg(test)]
mod tests;
