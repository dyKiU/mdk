//! Durable user acceptance observations, never MLS membership or restored consent.
//!
//! Only the App's actual create/join/accept reducer supplies these changes. The
//! projection checkpoint owns the outer transaction so acceptance cannot commit
//! independently of its displayed pending state. Local hiding retains this ledger.

use crate::{SqliteAppStorage, SqliteResultExt};
use cgka_traits::{
    GroupId, MessageId,
    storage::{StorageError, StorageResult},
};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

pub const MAX_ACCOUNT_CHAT_SOURCE_ORIGINS: usize = 8192;

#[derive(Clone, PartialEq, Eq)]
pub enum AccountChatSourceOrigin {
    Created,
    Joined {
        via_welcome: MessageId,
    },
    /// A fresh human broad-sharing original accepts an ambiguous existing
    /// ordinary Member chat. This never asserts historical creation.
    ExplicitLegacyAcceptance {
        approval_id: [u8; 32],
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AccountChatSourceVerdict {
    Pending,
    Accepted,
    Denied,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AccountChatSourceOperation {
    Observe { explicitly_accepted: bool },
    Accept,
    Deny,
}

/// Account-worker-only input. There is no native DTO or permission inlet.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountChatSourceChange {
    pub account: [u8; 32],
    pub local_device: [u8; 32],
    pub group: GroupId,
    pub origin: AccountChatSourceOrigin,
    pub operation: AccountChatSourceOperation,
}

fn invalid() -> StorageError {
    StorageError::Serialization("invalid chat acceptance observation".into())
}

fn origin_bytes(origin: &AccountChatSourceOrigin) -> StorageResult<Vec<u8>> {
    match origin {
        AccountChatSourceOrigin::Created => Ok(vec![0]),
        AccountChatSourceOrigin::Joined { via_welcome }
            if (1..=256).contains(&via_welcome.as_slice().len()) =>
        {
            let mut value = vec![1];
            value.extend_from_slice(via_welcome.as_slice());
            Ok(value)
        }
        AccountChatSourceOrigin::ExplicitLegacyAcceptance { approval_id }
            if *approval_id != [0; 32] =>
        {
            let mut value = vec![2];
            value.extend_from_slice(approval_id);
            Ok(value)
        }
        _ => Err(invalid()),
    }
}

pub(super) fn identity(change: &AccountChatSourceChange) -> StorageResult<([u8; 32], Vec<u8>)> {
    if change.account == [0; 32]
        || change.local_device == [0; 32]
        || !(1..=255).contains(&change.group.as_slice().len())
    {
        return Err(invalid());
    }
    let origin = origin_bytes(&change.origin)?;
    let mut hash = Sha256::new();
    hash.update(b"WN-account-chat-user-acceptance-v1");
    hash.update(change.account);
    hash.update(change.local_device);
    hash.update((change.group.as_slice().len() as u16).to_be_bytes());
    hash.update(change.group.as_slice());
    hash.update((origin.len() as u16).to_be_bytes());
    hash.update(&origin);
    Ok((hash.finalize().into(), origin))
}

impl SqliteAppStorage {
    /// Compose with the account projection save in the caller's transaction.
    /// The callback revalidates the actual event/action and fresh Core state;
    /// retained facts alone cannot authorize acceptance.
    pub fn apply_account_chat_source_changes(
        &self,
        changes: &[AccountChatSourceChange],
        validate_original: &dyn Fn(&AccountChatSourceChange) -> StorageResult<()>,
    ) -> StorageResult<()> {
        // Ordinary reducers cannot manufacture the fresh broad-approval
        // lineage. Its dedicated path also commits immutable approval evidence.
        if changes.iter().any(|change| {
            matches!(
                change.origin,
                AccountChatSourceOrigin::ExplicitLegacyAcceptance { .. }
            )
        }) {
            return Err(invalid());
        }
        self.apply_account_chat_source_changes_original(changes, validate_original)
    }

    pub(super) fn apply_account_chat_source_changes_original(
        &self,
        changes: &[AccountChatSourceChange],
        validate_original: &dyn Fn(&AccountChatSourceChange) -> StorageResult<()>,
    ) -> StorageResult<()> {
        if changes.len() > 128 {
            return Err(invalid());
        }
        self.connection.with_transaction(|| {
            for change in changes {
                validate_original(change)?;
                let (id, origin) = identity(change)?;
                {
                    let conn = self.lock()?;
                    crate::approved_account_sharing_policy::check_configured_owner(
                        &conn, &change.account, &change.local_device)?;
                    let stored: Option<(Vec<u8>, u8)> = conn.query_row(
                        "SELECT origin,verdict FROM account_chat_source_origins WHERE origin_id=?1",
                        [id.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))
                        .optional().storage()?;
                    let current: Option<Vec<u8>> = conn.query_row(
                        "SELECT origin_id FROM account_chat_source_current WHERE group_id=?1",
                        [change.group.as_slice()], |row| row.get(0))
                        .optional().storage()?;
                    if stored.as_ref().is_some_and(|(bytes, _)| bytes != &origin) {
                        return Err(invalid());
                    }
                    match &change.operation {
                        AccountChatSourceOperation::Observe { explicitly_accepted } => {
                            if stored.is_none() {
                                let count: i64 = conn.query_row(
                                    "SELECT count(*) FROM account_chat_source_origins", [],
                                    |row| row.get(0)).storage()?;
                                if count >= MAX_ACCOUNT_CHAT_SOURCE_ORIGINS as i64 {
                                    return Err(StorageError::Capacity("chat acceptance limit reached".into()));
                                }
                                let accepted = *explicitly_accepted;
                                if matches!(change.origin, AccountChatSourceOrigin::Created) && !accepted {
                                    return Err(invalid());
                                }
                                conn.execute("INSERT INTO account_chat_source_origins(origin_id,account,local_device,group_id,origin,verdict,origin_order) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                                    params![id.as_slice(), change.account.as_slice(), change.local_device.as_slice(), change.group.as_slice(), origin, u8::from(accepted), count+1]).storage()?;
                                if current.is_some() {
                                    conn.execute("UPDATE account_chat_source_current SET origin_id=?2 WHERE group_id=?1",
                                        params![change.group.as_slice(),id.as_slice()]).storage()?;
                                } else {
                                    conn.execute("INSERT INTO account_chat_source_current(group_id,origin_id) VALUES(?1,?2)",
                                        params![change.group.as_slice(),id.as_slice()]).storage()?;
                                }
                            } else if *explicitly_accepted && current.as_deref() == Some(id.as_slice()) {
                                // Authenticated explicitly-confirmed rejoin may resolve a
                                // pending origin, but cannot reopen a denied one.
                                if stored.as_ref().is_some_and(|(_, verdict)| *verdict == 2) {
                                    return Err(invalid());
                                }
                                conn.execute("UPDATE account_chat_source_origins SET verdict=1 WHERE origin_id=?1 AND verdict=0",[id.as_slice()]).storage()?;
                            }
                            // A retained older origin never switches the current pointer.
                        }
                        AccountChatSourceOperation::Accept | AccountChatSourceOperation::Deny => {
                            if stored.is_none() {
                                return Err(invalid());
                            }
                            let denied = matches!(change.operation, AccountChatSourceOperation::Deny);
                            if !denied && current.as_deref()!=Some(id.as_slice()) {
                                // An older explicitly accepted action cannot move the
                                // current pointer, and must not poison a new Welcome.
                                continue;
                            }
                            if !denied && stored.as_ref().is_some_and(|(_, verdict)| *verdict == 2) {
                                return Err(invalid());
                            }
                            conn.execute("UPDATE account_chat_source_origins SET verdict=?2 WHERE origin_id=?1",
                                params![id.as_slice(),if denied {2u8} else {1u8}]).storage()?;
                        }
                    }
                }
            }
            for change in changes {
                validate_original(change)?;
            }
            Ok(())
        })
    }

    /// Read-only observation. Every positive caller still checks live Core
    /// membership and its original approved sharing channel independently.
    pub fn current_account_chat_source(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        group: &GroupId,
    ) -> StorageResult<Option<AccountChatSourceVerdict>> {
        let conn = self.lock()?;
        crate::approved_account_sharing_policy::check_configured_owner(
            &conn,
            account,
            local_device,
        )?;
        let value: Option<u8> = conn.query_row(
            "SELECT o.verdict FROM account_chat_source_current c JOIN account_chat_source_origins o USING(origin_id)
             WHERE c.group_id=?1 AND o.account=?2 AND o.local_device=?3
               AND (substr(o.origin,1,1)!=X'02' OR EXISTS(
                 SELECT 1 FROM account_chat_legacy_acceptance_evidence e WHERE e.origin_id=o.origin_id))",
            params![group.as_slice(),account.as_slice(),local_device.as_slice()], |row| row.get(0)).optional().storage()?;
        value
            .map(|value| match value {
                0 => Ok(AccountChatSourceVerdict::Pending),
                1 => Ok(AccountChatSourceVerdict::Accepted),
                2 => Ok(AccountChatSourceVerdict::Denied),
                _ => Err(invalid()),
            })
            .transpose()
    }

    /// Metadata identity comparison for the same live original's transaction
    /// retry. It does not supply membership or an approval owner.
    pub fn account_chat_source_is_current(
        &self,
        change: &AccountChatSourceChange,
    ) -> StorageResult<bool> {
        let (id, _) = identity(change)?;
        let conn = self.lock()?;
        crate::approved_account_sharing_policy::check_configured_owner(
            &conn,
            &change.account,
            &change.local_device,
        )?;
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM account_chat_source_current c
             JOIN account_chat_source_origins o USING(origin_id)
             WHERE c.group_id=?1 AND o.origin_id=?2 AND o.verdict=1)",
            params![change.group.as_slice(), id.as_slice()],
            |row| row.get(0),
        )
        .storage()
    }
    /// Accepted-only immutable lineage metadata; never original consent or MLS
    /// membership. Tagged legacy lineages additionally require their original
    /// evidence row, under the same configured account/device ownership guard.
    pub fn current_account_chat_source_origin(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        group: &GroupId,
    ) -> StorageResult<Option<cgka_traits::mirrored_chat_catalog::AcceptedChatOrigin>> {
        self.account_chat_source_origin_for_verdict(account, local_device, group, 1)
    }

    /// Denied lineage metadata for a freshly authenticated terminal/explicit
    /// negative source observation; this never supplies a positive approval.
    pub fn current_account_chat_source_terminal_origin(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        group: &GroupId,
    ) -> StorageResult<Option<cgka_traits::mirrored_chat_catalog::AcceptedChatOrigin>> {
        self.account_chat_source_origin_for_verdict(account, local_device, group, 2)
    }

    /// Exact historical accepted/denied lineage observation. This is usable only
    /// as a negative target check; it never restores an original or membership.
    pub fn account_chat_source_origin_was_accepted(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        group: &GroupId,
        origin: cgka_traits::mirrored_chat_catalog::AcceptedChatOrigin,
    ) -> StorageResult<bool> {
        if !(1..=MAX_ACCOUNT_CHAT_SOURCE_ORIGINS as u64).contains(&origin.order) {
            return Err(invalid());
        }
        let conn = self.lock()?;
        crate::approved_account_sharing_policy::check_configured_owner(
            &conn,
            account,
            local_device,
        )?;
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM account_chat_source_origins o
             WHERE o.group_id=?1 AND o.account=?2 AND o.local_device=?3
               AND o.origin_id=?4 AND o.origin_order=?5 AND o.verdict IN(1,2)
               AND (substr(o.origin,1,1)!=X'02' OR EXISTS(
                 SELECT 1 FROM account_chat_legacy_acceptance_evidence e WHERE e.origin_id=o.origin_id)))",
            params![group.as_slice(),account.as_slice(),local_device.as_slice(),origin.id.as_slice(),origin.order as i64],
            |row|row.get(0),
        ).storage()
    }

    fn account_chat_source_origin_for_verdict(
        &self,
        account: &[u8; 32],
        local_device: &[u8; 32],
        group: &GroupId,
        verdict: u8,
    ) -> StorageResult<Option<cgka_traits::mirrored_chat_catalog::AcceptedChatOrigin>> {
        let conn = self.lock()?;
        crate::approved_account_sharing_policy::check_configured_owner(
            &conn,
            account,
            local_device,
        )?;
        let value: Option<(Vec<u8>, i64)> = conn.query_row(
            "SELECT o.origin_id,o.origin_order FROM account_chat_source_current c
             JOIN account_chat_source_origins o USING(origin_id)
             WHERE c.group_id=?1 AND o.account=?2 AND o.local_device=?3 AND o.verdict=?4
               AND (substr(o.origin,1,1)!=X'02' OR EXISTS(
                 SELECT 1 FROM account_chat_legacy_acceptance_evidence e WHERE e.origin_id=o.origin_id))",
            params![group.as_slice(), account.as_slice(), local_device.as_slice(), verdict],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().storage()?;
        let Some((id, order)) = value else {
            return Ok(None);
        };
        if !(1..=MAX_ACCOUNT_CHAT_SOURCE_ORIGINS as i64).contains(&order) {
            return Err(invalid());
        }
        Ok(Some(
            cgka_traits::mirrored_chat_catalog::AcceptedChatOrigin {
                id: id.try_into().map_err(|_| invalid())?,
                order: order as u64,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
    use super::*;
    use cgka_traits::{
        MemberId,
        storage::{AccountDeviceSignerBinding, AccountDeviceSignerStorage},
    };
    use std::cell::Cell;

    fn configure(storage: &SqliteAccountStorage) {
        storage.lock().unwrap().execute(
            "INSERT INTO account_state(label,updated_at,local_account_id_hex) VALUES('test',0,?1)",
            [hex::encode([1;32])]).unwrap();
        storage
            .put_account_device_signer(&AccountDeviceSignerBinding {
                marmot_identity: MemberId::new(vec![1; 32]),
                mls_signature_public_key: vec![2; 32],
            })
            .unwrap();
    }
    fn configured() -> SqliteAccountStorage {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        configure(&storage);
        storage
    }
    fn change(
        origin: AccountChatSourceOrigin,
        operation: AccountChatSourceOperation,
    ) -> AccountChatSourceChange {
        AccountChatSourceChange {
            account: [1; 32],
            local_device: [2; 32],
            group: GroupId::new(vec![8; 16]),
            origin,
            operation,
        }
    }
    fn joined(n: u8) -> AccountChatSourceOrigin {
        AccountChatSourceOrigin::Joined {
            via_welcome: MessageId::new(vec![n; 32]),
        }
    }
    fn verdict(storage: &SqliteAccountStorage) -> Option<AccountChatSourceVerdict> {
        storage
            .app_storage().current_account_chat_source(&[1; 32], &[2; 32], &GroupId::new(vec![8; 16]))
            .unwrap()
    }
    #[test]
    fn accepted_origin_reader_tracks_only_actual_current_accepted_lineage() {
        let storage = configured();
        let group = GroupId::new(vec![8; 16]);
        let read = || {
            storage
                .app_storage().current_account_chat_source_origin(&[1; 32], &[2; 32], &group)
                .unwrap()
        };
        let apply = |origin, operation| {
            storage
                .app_storage().apply_account_chat_source_changes(&[change(origin, operation)], &|_| Ok(()))
                .unwrap()
        };
        assert!(read().is_none());
        apply(
            joined(3),
            AccountChatSourceOperation::Observe {
                explicitly_accepted: false,
            },
        );
        assert!(read().is_none());
        apply(joined(3), AccountChatSourceOperation::Accept);
        let first = read().unwrap();
        assert_eq!(first.order, 1);
        apply(joined(3), AccountChatSourceOperation::Deny);
        assert!(read().is_none());
        assert!(
            storage
                .app_storage().current_account_chat_source_terminal_origin(&[1; 32], &[2; 32], &group)
                .unwrap()
                == Some(first)
        );
        apply(
            joined(4),
            AccountChatSourceOperation::Observe {
                explicitly_accepted: true,
            },
        );
        let second = read().unwrap();
        assert!(second.id != first.id && second.order > first.order);
        assert!(
            storage
                .app_storage().account_chat_source_origin_was_accepted(&[1; 32], &[2; 32], &group, first)
                .unwrap()
        );
        assert!(
            storage
                .app_storage().account_chat_source_origin_was_accepted(&[1; 32], &[2; 32], &group, second)
                .unwrap()
        );
        assert!(
            !storage
                .app_storage().account_chat_source_origin_was_accepted(
                    &[1; 32],
                    &[2; 32],
                    &group,
                    cgka_traits::mirrored_chat_catalog::AcceptedChatOrigin {
                        id: [9; 32],
                        order: first.order
                    }
                )
                .unwrap()
        );
        assert!(
            !storage
                .app_storage().account_chat_source_origin_was_accepted(
                    &[1; 32],
                    &[2; 32],
                    &group,
                    cgka_traits::mirrored_chat_catalog::AcceptedChatOrigin {
                        id: first.id,
                        order: 8192
                    }
                )
                .unwrap()
        );

        assert!(
            storage
                .app_storage().current_account_chat_source_origin(&[9; 32], &[2; 32], &group)
                .is_err()
        );
        assert!(
            storage
                .app_storage().current_account_chat_source_origin(&[1; 32], &[9; 32], &group)
                .is_err()
        );
    }

    #[test]
    fn actual_origin_observation_is_pending_until_explicit_accept_and_new_welcome_resets() {
        let storage = configured();
        let apply = |origin, operation| {
            storage
                .app_storage().apply_account_chat_source_changes(&[change(origin, operation)], &|_| Ok(()))
                .unwrap()
        };
        apply(
            joined(3),
            AccountChatSourceOperation::Observe {
                explicitly_accepted: false,
            },
        );
        assert!(verdict(&storage) == Some(AccountChatSourceVerdict::Pending));
        apply(joined(3), AccountChatSourceOperation::Accept);
        assert!(verdict(&storage) == Some(AccountChatSourceVerdict::Accepted));
        apply(
            joined(4),
            AccountChatSourceOperation::Observe {
                explicitly_accepted: false,
            },
        );
        apply(
            joined(3),
            AccountChatSourceOperation::Observe {
                explicitly_accepted: true,
            },
        );
        assert!(verdict(&storage) == Some(AccountChatSourceVerdict::Pending));
        apply(joined(4), AccountChatSourceOperation::Deny);
        assert!(
            storage
                .app_storage().apply_account_chat_source_changes(
                    &[change(joined(4), AccountChatSourceOperation::Accept)],
                    &|_| Ok(())
                )
                .is_err()
        );
        apply(
            joined(4),
            AccountChatSourceOperation::Observe {
                explicitly_accepted: false,
            },
        );
        assert!(verdict(&storage) == Some(AccountChatSourceVerdict::Denied));
    }
    #[test]
    fn acceptance_and_projection_are_one_atomic_original_guarded_unit() {
        let storage = configured();
        let source = change(
            AccountChatSourceOrigin::Created,
            AccountChatSourceOperation::Observe {
                explicitly_accepted: true,
            },
        );
        let calls = Cell::new(0);
        let result: StorageResult<()> = storage.connection.with_transaction(|| {
            storage
                .lock()?
                .execute(
                    "UPDATE account_state SET updated_at=99 WHERE label='test'",
                    [],
                )
                .storage()?;
            storage.app_storage().apply_account_chat_source_changes(&[source], &|_| {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err(invalid())
                } else {
                    Ok(())
                }
            })
        });
        assert!(result.is_err());
        assert!(verdict(&storage).is_none());
        let updated: i64 = storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT updated_at FROM account_state WHERE label='test'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(updated, 0);
    }
    #[test]
    fn source_lineage_never_resets_on_delete_replace_or_direct_negative_reversal() {
        let storage = configured();
        let source = change(
            joined(3),
            AccountChatSourceOperation::Observe {
                explicitly_accepted: false,
            },
        );
        storage
            .app_storage().apply_account_chat_source_changes(std::slice::from_ref(&source), &|_| Ok(()))
            .unwrap();
        storage
            .app_storage().apply_account_chat_source_changes(
                &[change(joined(3), AccountChatSourceOperation::Deny)],
                &|_| Ok(()),
            )
            .unwrap();
        let conn = storage.lock().unwrap();
        for sql in [
            "DELETE FROM account_chat_source_origins",
            "DELETE FROM account_chat_source_current",
            "UPDATE account_chat_source_origins SET verdict=1",
            "INSERT OR REPLACE INTO account_chat_source_origins SELECT * FROM account_chat_source_origins",
            "INSERT OR REPLACE INTO account_chat_source_current SELECT * FROM account_chat_source_current",
        ] {
            assert!(conn.execute_batch(sql).is_err());
        }
        drop(conn);
        let mut wrong = source;
        wrong.local_device = [9; 32];
        assert!(
            storage
                .app_storage().apply_account_chat_source_changes(&[wrong], &|_| Ok(()))
                .is_err()
        );
        assert!(verdict(&storage) == Some(AccountChatSourceVerdict::Denied));
    }
    #[test]
    fn source_origin_capacity_counts_all_accepted_and_denied_refs_and_rolls_back() {
        let storage = configured();
        for start in (0..MAX_ACCOUNT_CHAT_SOURCE_ORIGINS).step_by(128) {
            let changes = (start..start + 128)
                .map(|n| {
                    let origin = AccountChatSourceOrigin::Joined {
                        via_welcome: MessageId::new((n as u32).to_be_bytes().to_vec()),
                    };
                    change(
                        origin,
                        AccountChatSourceOperation::Observe {
                            explicitly_accepted: true,
                        },
                    )
                })
                .collect::<Vec<_>>();
            storage
                .app_storage().apply_account_chat_source_changes(&changes, &|_| Ok(()))
                .unwrap();
            let denied = changes
                .iter()
                .filter(|c| match &c.origin {
                    AccountChatSourceOrigin::Joined { via_welcome } => {
                        via_welcome.as_slice()[3] % 2 == 0
                    }
                    _ => false,
                })
                .map(|c| {
                    let mut c = c.clone();
                    c.operation = AccountChatSourceOperation::Deny;
                    c
                })
                .collect::<Vec<_>>();
            storage
                .app_storage().apply_account_chat_source_changes(&denied, &|_| Ok(()))
                .unwrap();
        }
        assert!(verdict(&storage) == Some(AccountChatSourceVerdict::Accepted));
        let last = AccountChatSourceOrigin::Joined {
            via_welcome: MessageId::new((8191u32).to_be_bytes().to_vec()),
        };
        let rejected = storage.app_storage().apply_account_chat_source_changes(
            &[
                change(last, AccountChatSourceOperation::Deny),
                change(
                    AccountChatSourceOrigin::Created,
                    AccountChatSourceOperation::Observe {
                        explicitly_accepted: true,
                    },
                ),
            ],
            &|_| Ok(()),
        );
        assert!(matches!(rejected, Err(StorageError::Capacity(_))));
        assert!(verdict(&storage) == Some(AccountChatSourceVerdict::Accepted));
        let count: i64 = storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM account_chat_source_origins",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 8192);
    }
    #[test]
    fn hidden_accepted_and_hidden_pending_decisions_survive_encrypted_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.db");
        let key = crate::SqlCipherKey::new("42".repeat(32)).unwrap();
        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        configure(&storage);
        let accepted = change(
            joined(3),
            AccountChatSourceOperation::Observe {
                explicitly_accepted: true,
            },
        );
        let mut pending = change(
            joined(4),
            AccountChatSourceOperation::Observe {
                explicitly_accepted: false,
            },
        );
        pending.group = GroupId::new(vec![9; 16]);
        storage
            .app_storage().apply_account_chat_source_changes(&[accepted.clone(), pending.clone()], &|_| Ok(()))
            .unwrap();
        for c in [&accepted, &pending] {
            storage
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0)",
                    [hex::encode(c.group.as_slice())],
                )
                .unwrap();
            storage
                .delete_local_group_data(&hex::encode(c.group.as_slice()))
                .unwrap();
        }
        storage.close().unwrap();
        assert!(matches!(
            storage.app_storage().current_account_chat_source(&[1; 32], &[2; 32], &accepted.group),
            Err(StorageError::Closed(_))
        ));
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert!(
            reopened
                .app_storage().current_account_chat_source(&[1; 32], &[2; 32], &accepted.group)
                .unwrap()
                == Some(AccountChatSourceVerdict::Accepted)
        );
        assert!(
            reopened
                .app_storage().current_account_chat_source(&[1; 32], &[2; 32], &pending.group)
                .unwrap()
                == Some(AccountChatSourceVerdict::Pending)
        );
        let count: i64 = reopened
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM account_groups", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
        reopened.close().unwrap();
    }
}
