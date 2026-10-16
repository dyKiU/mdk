//! Negative retirement of an abandoned first enrollment. No resumed consent.
use super::GenesisFactoryError;
use crate::Engine;
use cgka_traits::device_group_genesis::GenesisError;
use cgka_traits::private_device_invite::{PrivateInviteOrigin, PrivateInviteStorageError};
use cgka_traits::private_roster_settlement::PrivateSettlementPhase;
use cgka_traits::{EngineError, storage::StorageProvider};

fn invite_error(error: PrivateInviteStorageError) -> GenesisFactoryError {
    match error {
        PrivateInviteStorageError::Storage(error) => error.into(),
        _ => GenesisError::InvalidFact.into(),
    }
}

impl<S: StorageProvider> Engine<S> {
    /// Retire only the exact, abandoned two-leaf bootstrap selection. The caller
    /// must start a fresh verification; this never resumes settlement or grants
    /// access. Established sharing, larger rosters and active rounds are retained.
    pub fn retire_abandoned_private_bootstrap(&mut self) -> Result<bool, GenesisFactoryError> {
        let admission = self
            .settlement_admission
            .lock()
            .map_err(|_| EngineError::Other("private bootstrap admission unavailable".into()))?;
        if admission.as_ref().is_some_and(|owner| owner.is_live()) {
            return Ok(false);
        }
        let Some(round) = self
            .storage
            .private_roster_settlement_storage()
            .ok_or(GenesisError::Unsupported)?
            .read_round()?
            .filter(|round| round.phase == PrivateSettlementPhase::Denied)
        else {
            return Ok(false);
        };
        let anchor = &round.anchor;
        if anchor.account.as_slice() != self.identity.self_id().as_slice()
            || anchor.local_device.as_slice() != self.identity.signer.public()
            || anchor.successor.leaves.len() != 2
        {
            return Ok(false);
        }
        self.ensure_group_live(&anchor.group_id)?;
        self.storage.with_transaction(|storage| {
            if storage
                .private_roster_settlement_storage()
                .ok_or(GenesisError::Unsupported)?
                .read_round()?
                .as_ref()
                != Some(&round)
                || !storage
                    .approved_account_sharing_policy_storage()
                    .ok_or(GenesisError::Unsupported)?
                    .approved_account_sharing_policies()?
                    .is_empty()
            {
                return Ok(false);
            }
            // Denied alone is not enough: require the genuine unchanged tree and
            // its one unambiguous local origin. Historical policy, even revoked,
            // bars this initial-bootstrap recovery.
            let Some(successor) = self.validated_private_successor(&anchor.group_id)? else {
                return Ok(false);
            };
            if successor.settlement_anchor() != anchor {
                return Ok(false);
            }
            match anchor.origin {
                PrivateInviteOrigin::Accepted(generation) => {
                    let store = storage
                        .accepted_device_group_anchor_storage()
                        .ok_or(GenesisError::Unsupported)?;
                    let Some(fact) = store.accepted_anchor()? else {
                        return Ok(false);
                    };
                    if fact.denied
                        || fact.scope.selection_generation != generation
                        || fact.draft.predecessor.leaves.len() != 1
                        || fact.draft.predecessor.epoch.0 != 0
                        || fact.draft.successor.epoch.0 != 1
                    {
                        return Ok(false);
                    }
                    store.deny_accepted_anchor(&fact.scope, &anchor.group_id)?;
                }
                PrivateInviteOrigin::Confirmed(generation) => {
                    let store = storage
                        .private_device_invite_storage()
                        .ok_or(GenesisError::Unsupported)?;
                    let Some(fact) = store.confirmed_private_invite().map_err(invite_error)? else {
                        return Ok(false);
                    };
                    if fact.denied
                        || fact.scope.staging_generation != generation
                        || !matches!(fact.binding.origin, PrivateInviteOrigin::Genesis(_))
                        || fact.binding.predecessor.leaves.len() != 1
                        || fact.binding.predecessor.epoch.0 != 0
                        || fact.binding.successor.epoch.0 != 1
                    {
                        return Ok(false);
                    }
                    store
                        .deny_confirmed_private_invite(&fact.scope, &anchor.group_id)
                        .map_err(invite_error)?;
                }
                _ => return Ok(false),
            }
            // Keep MLS, chat data and negative provenance. Only the obsolete
            // selection is denied; future grants require new actual approvals.
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_successor::tests::joined_pair;
    use storage_sqlite::SqliteAccountStorage;

    #[tokio::test]
    async fn bootstrap_retirement_requires_cancelled_round_and_preserves_tree() {
        let (source, recipient, group) =
            joined_pair(SqliteAccountStorage::in_memory().unwrap()).await;
        for mut engine in [source, recipient] {
            // Real MLS/SQL join with injected test policy, not SDK acceptance.
            assert!(!engine.retire_abandoned_private_bootstrap().unwrap());
            engine.select_private_roster_settlement(&group).unwrap();
            assert!(!engine.retire_abandoned_private_bootstrap().unwrap());
            engine.cancel_private_roster_settlement(&group).unwrap();
            assert!(engine.retire_abandoned_private_bootstrap().unwrap());
            assert!(!engine.retire_abandoned_private_bootstrap().unwrap());
            assert!(
                engine
                    .candidate_device_group_snapshot(&group)
                    .unwrap()
                    .is_some()
            );
            assert!(
                engine
                    .validated_private_successor(&group)
                    .unwrap()
                    .is_none()
            );
            let fresh = engine.create_private_device_group_genesis().unwrap();
            assert_ne!(fresh.group_id(), &group);
        }
    }

    #[tokio::test]
    async fn bootstrap_retirement_preserves_completed_pair_without_sharing_policy() {
        let (source, recipient, group) = crate::private_roster_settlement::tests::complete_pair(
            SqliteAccountStorage::in_memory().unwrap(),
        )
        .await;
        for mut engine in [source, recipient] {
            engine.cancel_private_roster_settlement(&group).unwrap();
            assert!(!engine.retire_abandoned_private_bootstrap().unwrap());
            assert!(
                engine
                    .validated_settled_device_roster(&group)
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[tokio::test]
    async fn bootstrap_retirement_rolls_back_with_surrounding_sql_failure() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let (_, mut recipient, group) = joined_pair(storage.clone()).await;
        recipient.select_private_roster_settlement(&group).unwrap();
        recipient.cancel_private_roster_settlement(&group).unwrap();
        let result = storage.with_transaction(|_| {
            assert!(recipient.retire_abandoned_private_bootstrap().unwrap());
            Err::<(), _>(cgka_traits::storage::StorageError::Backend(
                "injected rollback".into(),
            ))
        });
        assert!(result.is_err());
        assert!(
            recipient
                .validated_private_successor(&group)
                .unwrap()
                .is_some()
        );
        assert!(recipient.retire_abandoned_private_bootstrap().unwrap());
    }

    #[tokio::test]
    async fn bootstrap_retirement_preserves_historical_sharing_policy() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let (_, mut recipient, group) = joined_pair(storage.clone()).await;
        recipient.select_private_roster_settlement(&group).unwrap();
        recipient.cancel_private_roster_settlement(&group).unwrap();
        let fact = storage
            .accepted_device_group_anchor_storage()
            .unwrap()
            .accepted_anchor()
            .unwrap()
            .unwrap();
        // Deliberately injected historical policy is a negative guard fixture;
        // it is not evidence of SDK approval or a usable sharing channel.
        let policy = cgka_traits::approved_account_sharing_policy::ApprovedAccountSharingPolicy {
            account: fact.scope.account,
            local_device: fact.scope.local_device,
            peer_device: fact.draft.approver,
            protected_group: group.clone(),
            approval_id: [9; 32],
            version: 1,
            capabilities: 0x0f,
            created_at: 1,
            approved_protected_epoch: 1,
            revoked: false,
        };
        let store = storage.approved_account_sharing_policy_storage().unwrap();
        store
            .put_approved_account_sharing_policy(&policy, &|| Ok(()))
            .unwrap();
        assert!(!recipient.retire_abandoned_private_bootstrap().unwrap());
        let id = cgka_traits::approved_account_sharing_policy::approved_account_sharing_identity(
            &policy.account,
            &group,
            &policy.local_device,
            &policy.peer_device,
            &policy.approval_id,
        )
        .unwrap();
        store
            .revoke_account_sharing_policy(&id, &|| Ok(()))
            .unwrap();
        assert!(!recipient.retire_abandoned_private_bootstrap().unwrap());
        assert!(
            recipient
                .validated_private_successor(&group)
                .unwrap()
                .is_some()
        );
    }
}
