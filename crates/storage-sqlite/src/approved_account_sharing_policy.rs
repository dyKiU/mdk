//! Durable facts and monotonic source observations. Never a live policy owner.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::{
    GroupId,
    approved_account_sharing_policy::*,
    storage::{AccountDeviceSignerBinding, StorageError, StorageResult},
};
use rusqlite::{Connection, OptionalExtension, params};

fn invalid() -> StorageError {
    StorageError::Serialization("invalid account sharing policy".into())
}

/// Exact configured identity and actual signer; reusable only as a storage fence.
pub(crate) fn check_configured_owner(
    conn: &Connection,
    account: &[u8; 32],
    local: &[u8; 32],
) -> StorageResult<()> {
    let mut statement = conn
        .prepare(
            "SELECT local_account_id_hex FROM account_state WHERE local_account_id_hex IS NOT NULL",
        )
        .storage()?;
    let accounts = statement
        .query_map([], |r| r.get::<_, String>(0))
        .storage()?;
    let mut found = false;
    for value in accounts {
        if hex::decode(value.storage()?).map_err(|_| invalid())? != *account {
            return Err(invalid());
        }
        found = true;
    }
    if !found {
        return Err(invalid());
    }
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT record FROM cgka_account_device_signers WHERE marmot_identity=?1",
            [account.as_slice()],
            |r| r.get(0),
        )
        .storage()?;
    let signer: AccountDeviceSignerBinding =
        serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if signer.marmot_identity.as_slice() != account || signer.mls_signature_public_key != *local {
        return Err(invalid());
    }
    Ok(())
}

fn identity(policy: &ApprovedAccountSharingPolicy) -> StorageResult<[u8; 32]> {
    if policy.version != ACCOUNT_SHARING_POLICY_VERSION
        || policy.capabilities != ACCOUNT_SHARING_CAPABILITIES
        || policy.created_at > i64::MAX as u64
        || policy.approved_protected_epoch > i64::MAX as u64
    {
        return Err(invalid());
    }
    approved_account_sharing_identity(
        &policy.account,
        &policy.protected_group,
        &policy.local_device,
        &policy.peer_device,
        &policy.approval_id,
    )
}

fn check_owner(conn: &Connection, policy: &ApprovedAccountSharingPolicy) -> StorageResult<()> {
    check_configured_owner(conn, &policy.account, &policy.local_device)?;
    let other:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM approved_account_sharing_policies WHERE account!=?1 OR local_device!=?2)",params![policy.account.as_slice(),policy.local_device.as_slice()],|r|r.get(0)).storage()?;
    if other {
        return Err(invalid());
    }
    Ok(())
}

fn decode(
    id: &[u8; 32],
    account: Vec<u8>,
    local: Vec<u8>,
    bytes: Vec<u8>,
    revoked: bool,
) -> StorageResult<ApprovedAccountSharingPolicy> {
    if bytes.len() > 4096 {
        return Err(invalid());
    }
    let mut policy: ApprovedAccountSharingPolicy =
        serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if identity(&policy)? != *id
        || policy.account.as_slice() != account
        || policy.local_device.as_slice() != local
        || policy.revoked
    {
        return Err(invalid());
    }
    policy.revoked = revoked;
    Ok(policy)
}

fn load(conn: &Connection, id: &[u8; 32]) -> StorageResult<ApprovedAccountSharingPolicy> {
    let (account,local,bytes,revoked)=conn.query_row("SELECT account,local_device,record,revoked FROM approved_account_sharing_policies WHERE policy_id=?1",[id.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).storage()?;
    let policy = decode(id, account, local, bytes, revoked)?;
    check_owner(conn, &policy)?;
    Ok(policy)
}

impl ApprovedAccountSharingPolicyStorage for SqliteAccountStorage {
    fn put_approved_account_sharing_policy(
        &self,
        policy: &ApprovedAccountSharingPolicy,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        let id = identity(policy)?;
        if policy.revoked {
            return Err(invalid());
        }
        let bytes = crate::serialize(policy)?;
        if bytes.len() > 4096 {
            return Err(invalid());
        }
        self.connection.with_transaction(|| {
            validate_original()?;
            let conn=self.lock()?;
            check_owner(&conn,policy)?;
            let exists:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM approved_account_sharing_policies WHERE policy_id=?1)",[id.as_slice()],|r|r.get(0)).storage()?;
            if exists {
                if load(&conn,&id)?!=*policy {return Err(invalid());}
            } else {
                conn.execute("INSERT INTO approved_account_sharing_policies(policy_id,account,local_device,record,revoked) VALUES(?1,?2,?3,?4,0)",params![id.as_slice(),policy.account.as_slice(),policy.local_device.as_slice(),bytes]).storage()?;
                conn.execute("INSERT INTO account_sharing_source_counters(policy_id,sequence) VALUES(?1,0)",[id.as_slice()]).storage()?;
            }
            drop(conn); validate_original()
        })
    }
    fn approved_account_sharing_policies(
        &self,
    ) -> StorageResult<Vec<ApprovedAccountSharingPolicy>> {
        let conn = self.lock()?;
        let mut statement=conn.prepare("SELECT policy_id,account,local_device,record,revoked FROM approved_account_sharing_policies ORDER BY policy_id LIMIT 129").storage()?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                ))
            })
            .storage()?;
        let mut result = Vec::new();
        for row in rows {
            let (id, account, local, bytes, revoked) = row.storage()?;
            let id: [u8; 32] = id.try_into().map_err(|_| invalid())?;
            let policy = decode(&id, account, local, bytes, revoked)?;
            check_owner(&conn, &policy)?;
            result.push(policy);
        }
        if result.len() > MAX_ACCOUNT_SHARING_POLICIES {
            return Err(invalid());
        }
        Ok(result)
    }
    fn revoke_account_sharing_policy(
        &self,
        id: &[u8; 32],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            validate_original()?;
            let conn = self.lock()?;
            if !load(&conn, id)?.revoked {
                conn.execute(
                    "UPDATE approved_account_sharing_policies SET revoked=1 WHERE policy_id=?1",
                    [id.as_slice()],
                )
                .storage()?;
            }
            drop(conn);
            validate_original()
        })
    }
    fn reserve_account_chat_sequence(
        &self,
        id: &[u8; 32],
        group: &GroupId,
        digest: &[u8; 32],
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<u64> {
        if !(1..=255).contains(&group.as_slice().len()) || *digest == [0; 32] {
            return Err(invalid());
        }
        self.connection.with_transaction(|| {
            validate_original()?; let conn=self.lock()?;
            let policy=load(&conn,id)?;
            if policy.revoked || group==&policy.protected_group {return Err(invalid());}
            let previous:Option<(Vec<u8>,i64)>=conn.query_row("SELECT digest,sequence FROM account_sharing_source_journal WHERE policy_id=?1 AND group_id=?2",params![id.as_slice(),group.as_slice()],|r|Ok((r.get(0)?,r.get(1)?))).optional().storage()?;
            let sequence=if let Some((body,seq))=previous.as_ref().filter(|(body,_)| body.as_slice()==digest) {
                if body.len()!=32 || *seq<=0 {return Err(invalid());} *seq
            } else {
                let counter:i64=conn.query_row("SELECT sequence FROM account_sharing_source_counters WHERE policy_id=?1",[id.as_slice()],|r|r.get(0)).storage()?;
                let next=counter.checked_add(1).filter(|n|*n>0).ok_or_else(invalid)?;
                conn.execute("UPDATE account_sharing_source_counters SET sequence=?2 WHERE policy_id=?1",params![id.as_slice(),next]).storage()?;
                if previous.is_some() {
                    conn.execute("UPDATE account_sharing_source_journal SET digest=?3,sequence=?4 WHERE policy_id=?1 AND group_id=?2",params![id.as_slice(),group.as_slice(),digest.as_slice(),next]).storage()?;
                } else {
                    conn.execute("INSERT INTO account_sharing_source_journal(policy_id,group_id,digest,sequence) VALUES(?1,?2,?3,?4)",params![id.as_slice(),group.as_slice(),digest.as_slice(),next]).storage()?;
                } next
            };
            drop(conn); validate_original()?; Ok(sequence as u64)
        })
    }
}

#[cfg(test)]
#[path = "approved_account_sharing_policy/tests.rs"]
mod tests;
