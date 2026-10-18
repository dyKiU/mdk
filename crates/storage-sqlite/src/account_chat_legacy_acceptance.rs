//! App-only human-original checkpoint. No owner, key or permission is restored.
use crate::account_chat_source::{
    AccountChatSourceChange, AccountChatSourceOperation, AccountChatSourceOrigin, identity,
};
use crate::{SqliteAppStorage, SqliteResultExt};
use cgka_traits::{
    approved_account_sharing_policy::{
        ApprovedAccountSharingPolicyStorage, approved_account_sharing_identity,
    },
    storage::{StorageError, StorageResult},
};
use rusqlite::{OptionalExtension, params};

#[cfg(test)]
mod tests;

fn denied() -> StorageError {
    StorageError::Serialization("explicit legacy chat acceptance unavailable".into())
}

impl SqliteAppStorage {
    /// Compose with the FIRST actual original approval-policy write in an outer
    /// transaction. The App validates its held human original and each captured
    /// existing nonpending Member group before/tail. A policy row is not that
    /// owner, and this method is never exposed as a host/native fact inlet.
    pub fn record_explicit_legacy_chat_acceptance(
        &self,
        policy_id: &[u8; 32],
        changes: &[AccountChatSourceChange],
        validate_original: &dyn Fn(&AccountChatSourceChange) -> StorageResult<()>,
    ) -> StorageResult<()> {
        if changes.is_empty() || changes.len() > 128 {
            return Err(denied());
        }
        let policies = self.approved_account_sharing_policies()?;
        let policy = policies
            .iter()
            .find(|policy| {
                approved_account_sharing_identity(
                    &policy.account,
                    &policy.protected_group,
                    &policy.local_device,
                    &policy.peer_device,
                    &policy.approval_id,
                )
                .is_ok_and(|id| &id == policy_id)
            })
            .ok_or_else(denied)?;
        if policy.revoked {
            return Err(denied());
        }
        for change in changes {
            if change.account != policy.account
                || change.local_device != policy.local_device
                || change.origin
                    != (AccountChatSourceOrigin::ExplicitLegacyAcceptance {
                        approval_id: policy.approval_id,
                    })
                || change.operation
                    != (AccountChatSourceOperation::Observe {
                        explicitly_accepted: true,
                    })
            {
                return Err(denied());
            }
        }
        self.connection.with_transaction(|| {
            for change in changes {
                validate_original(change)?;
                let conn = self.lock()?;
                let negative: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM account_chat_source_origins
                     WHERE group_id=?1 AND verdict IN (0,2))",
                    [change.group.as_slice()], |row| row.get(0),
                ).storage()?;
                drop(conn);
                if negative || (self.current_account_chat_source(
                    &change.account, &change.local_device, &change.group)?.is_some()
                    && !self.account_chat_source_is_current(change)?) {
                    return Err(denied());
                }
            }
            self.apply_account_chat_source_changes_original(changes, validate_original)?;
            for change in changes {
                let (origin_id, _) = identity(change)?;
                let conn=self.lock()?;
                let existing:Option<(Vec<u8>,Vec<u8>)>=conn.query_row(
                    "SELECT policy_id,approval_id FROM account_chat_legacy_acceptance_evidence WHERE origin_id=?1",
                    [origin_id.as_slice()], |row| Ok((row.get(0)?,row.get(1)?))) .optional().storage()?;
                if let Some((_stored_policy, stored_approval))=existing {
                    // One human original can settle more than one actual peer
                    // policy. Its first evidence stays immutable across these
                    // separately validated bilateral commits.
                    if stored_approval!=policy.approval_id.as_slice() {return Err(denied());}
                } else {
                    conn.execute("INSERT INTO account_chat_legacy_acceptance_evidence(origin_id,policy_id,approval_id) VALUES(?1,?2,?3)",params![origin_id.as_slice(),policy_id.as_slice(),policy.approval_id.as_slice()]).storage()?;
                }
            }
            for change in changes {validate_original(change)?;}
            Ok(())
        })
    }
}
