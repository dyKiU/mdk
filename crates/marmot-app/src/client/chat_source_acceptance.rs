//! Actual user acceptance lineage for source disclosures, separate from MLS joins.
use super::AppClient;
use crate::AppError;
use cgka_traits::{
    GroupEvent, GroupId,
    storage::{AccountDeviceSignerStorage, StorageError, StorageResult},
};
use storage_sqlite::account_chat_source::{
    AccountChatSourceChange, AccountChatSourceOperation, AccountChatSourceOrigin,
    AccountChatSourceVerdict,
};

#[cfg(test)]
#[path = "chat_source_privacy_acceptance.rs"]
mod privacy_acceptance;
#[cfg(test)]
#[path = "chat_source_acceptance_tests.rs"]
mod tests;

impl AppClient {
    fn chat_source_change(
        &self,
        group: &GroupId,
        origin: AccountChatSourceOrigin,
        operation: AccountChatSourceOperation,
    ) -> Result<AccountChatSourceChange, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let identity = self.runtime.session().self_id();
        let signer = storage.account_device_signer(&identity)?.ok_or_else(|| {
            AppError::Storage(StorageError::Serialization(
                "chat source signer unavailable".into(),
            ))
        })?;
        let account = identity.as_slice().try_into().map_err(|_| {
            AppError::Storage(StorageError::Serialization(
                "chat source identity unavailable".into(),
            ))
        })?;
        let local_device = signer
            .mls_signature_public_key
            .as_slice()
            .try_into()
            .map_err(|_| {
                AppError::Storage(StorageError::Serialization(
                    "chat source signer unavailable".into(),
                ))
            })?;
        Ok(AccountChatSourceChange {
            account,
            local_device,
            group: group.clone(),
            origin,
            operation,
        })
    }

    pub(crate) fn observe_chat_source_origin(
        &mut self,
        event: &GroupEvent,
    ) -> Result<(), AppError> {
        let (group, origin, accepted) = match event {
            GroupEvent::GroupCreated { group_id } => {
                (group_id, AccountChatSourceOrigin::Created, true)
            }
            GroupEvent::GroupJoined {
                group_id,
                via_welcome,
                explicitly_confirmed,
                ..
            } => (
                group_id,
                AccountChatSourceOrigin::Joined {
                    via_welcome: via_welcome.clone(),
                },
                *explicitly_confirmed,
            ),
            _ => return Ok(()),
        };
        if self
            .runtime
            .session()
            .exclude_private_group_from_chat(group)
            .map_err(cgka_session::SessionError::from)?
        {
            return Ok(());
        }
        let change = self.chat_source_change(
            group,
            origin,
            AccountChatSourceOperation::Observe {
                explicitly_accepted: accepted,
            },
        )?;
        if self.pending_chat_source_changes.contains(&change) {
            return Ok(());
        }
        if self.pending_chat_source_changes.len() >= 128 {
            return Err(AppError::Storage(StorageError::Capacity(
                "chat acceptance checkpoint limit reached".into(),
            )));
        }
        self.pending_chat_source_changes.push(change);
        Ok(())
    }

    pub(crate) fn stage_chat_source_confirmation(
        &mut self,
        group: &GroupId,
        denied: bool,
    ) -> Result<(), AppError> {
        let row = self
            .app
            .group(&self.state.label, &hex::encode(group.as_slice()))?
            .ok_or(AppError::GroupInviteNotPending)?;
        let Some(id) = row.via_welcome_message_id_hex else {
            return Ok(());
        };
        let welcome = hex::decode(id).map_err(|_| {
            AppError::Storage(StorageError::Serialization(
                "chat source origin unavailable".into(),
            ))
        })?;
        let operation = if denied {
            AccountChatSourceOperation::Deny
        } else {
            AccountChatSourceOperation::Accept
        };
        let change = self.chat_source_change(
            group,
            AccountChatSourceOrigin::Joined {
                via_welcome: cgka_traits::MessageId::new(welcome),
            },
            operation,
        )?;
        let storage = self.app.account_storage(&self.state.label)?;
        let mut additions = Vec::new();
        if storage
            .current_account_chat_source(&change.account, &change.local_device, group)?
            .is_none()
        {
            // The persisted real Welcome projection supplies pending lineage
            // on upgrade; accepting it still needs this actual public action.
            let mut observed = change.clone();
            observed.operation = AccountChatSourceOperation::Observe {
                explicitly_accepted: false,
            };
            if !self.pending_chat_source_changes.contains(&observed) {
                additions.push(observed);
            }
        }
        if !self.pending_chat_source_changes.contains(&change) {
            additions.push(change);
        }
        if self.pending_chat_source_changes.len() + additions.len() > 128 {
            return Err(AppError::Storage(StorageError::Capacity(
                "chat acceptance checkpoint limit reached".into(),
            )));
        }
        self.pending_chat_source_changes.extend(additions);
        Ok(())
    }

    pub(crate) fn validate_chat_source_change(
        &self,
        change: &AccountChatSourceChange,
    ) -> StorageResult<()> {
        let actual = self
            .chat_source_change(&change.group, change.origin.clone(), change.operation)
            .map_err(|_| StorageError::Serialization("chat source owner unavailable".into()))?;
        if actual.account != change.account || actual.local_device != change.local_device {
            return Err(StorageError::Serialization(
                "chat source owner changed".into(),
            ));
        }
        // Denial remains legal after its actual self-removal has terminated MLS.
        if matches!(
            change.operation,
            AccountChatSourceOperation::Accept
                | AccountChatSourceOperation::Observe {
                    explicitly_accepted: true
                }
        ) {
            let authority = self
                .runtime
                .session()
                .group_authority(&change.group)
                .map_err(|_| {
                    StorageError::Serialization("chat source membership unavailable".into())
                })?;
            if !authority.facts.is_member
                || authority.facts.removed
                || authority.facts.disbanded
                || authority.facts.unrecoverable
            {
                return Err(StorageError::Serialization(
                    "chat source membership changed".into(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn automatic_chat_source_accepted(&self, group: &GroupId) -> Result<bool, AppError> {
        // Uncommitted changes never broaden disclosure. A new pending Welcome
        // closes the prior positive source while its atomic checkpoint retries.
        if self.pending_chat_source_changes.iter().any(|change| {
            &change.group == group
                && matches!(
                    change.operation,
                    AccountChatSourceOperation::Deny
                        | AccountChatSourceOperation::Observe {
                            explicitly_accepted: false
                        }
                )
        }) {
            return Ok(false);
        }
        let scope = self.chat_source_change(
            group,
            AccountChatSourceOrigin::Created,
            AccountChatSourceOperation::Observe {
                explicitly_accepted: true,
            },
        )?;
        let storage = self.app.account_storage(&self.state.label)?;
        let mut verdict =
            storage.current_account_chat_source(&scope.account, &scope.local_device, group)?;
        if verdict.is_none() {
            let persisted = self
                .app
                .group(&self.state.label, &hex::encode(group.as_slice()))?;
            let known_join = persisted
                .as_ref()
                .filter(|row| {
                    !row.pending_confirmation
                        && row.self_membership == crate::SelfMembership::Member
                })
                .and_then(|row| row.via_welcome_message_id_hex.as_ref());
            let origin = if let Some(welcome) = known_join {
                Some(AccountChatSourceOrigin::Joined {
                    via_welcome: cgka_traits::MessageId::new(hex::decode(welcome).map_err(
                        |_| {
                            AppError::Storage(StorageError::Serialization(
                                "chat source origin unavailable".into(),
                            ))
                        },
                    )?),
                })
            } else if persisted.as_ref().is_none_or(|row| {
                !row.pending_confirmation && row.self_membership == crate::SelfMembership::Member
            }) && self
                .runtime
                .session()
                .retained_local_group_creation(group)?
            {
                Some(AccountChatSourceOrigin::Created)
            } else {
                None
            };
            if let Some(origin) = origin {
                let observed = self.chat_source_change(
                    group,
                    origin,
                    AccountChatSourceOperation::Observe {
                        explicitly_accepted: true,
                    },
                )?;
                storage.apply_account_chat_source_changes(
                    std::slice::from_ref(&observed),
                    &|change| {
                        self.validate_chat_source_change(change)?;
                        match &change.origin {
                            AccountChatSourceOrigin::Created => {
                                if !self
                                    .runtime
                                    .session()
                                    .retained_local_group_creation(group)
                                    .map_err(|_| {
                                        StorageError::Serialization(
                                            "founding observation unavailable".into(),
                                        )
                                    })?
                                {
                                    return Err(StorageError::Serialization(
                                        "founding observation changed".into(),
                                    ));
                                }
                            }
                            AccountChatSourceOrigin::Joined { via_welcome } => {
                                let row = self
                                    .app
                                    .group(&self.state.label, &hex::encode(group.as_slice()))
                                    .map_err(|_| {
                                        StorageError::Serialization(
                                            "accepted projection unavailable".into(),
                                        )
                                    })?
                                    .ok_or_else(|| {
                                        StorageError::Serialization(
                                            "accepted projection unavailable".into(),
                                        )
                                    })?;
                                if row.pending_confirmation
                                    || row.self_membership != crate::SelfMembership::Member
                                    || row.via_welcome_message_id_hex.as_deref()
                                        != Some(hex::encode(via_welcome.as_slice()).as_str())
                                {
                                    return Err(StorageError::Serialization(
                                        "accepted projection changed".into(),
                                    ));
                                }
                            }
                        }
                        Ok(())
                    },
                )?;
                verdict = storage.current_account_chat_source(
                    &scope.account,
                    &scope.local_device,
                    group,
                )?;
            }
        }
        if verdict != Some(AccountChatSourceVerdict::Accepted) {
            return Ok(false);
        }
        let authority = self.runtime.session().group_authority(group)?;
        Ok(authority.facts.is_member
            && !authority.facts.removed
            && !authority.facts.disbanded
            && !authority.facts.unrecoverable)
    }

    pub(crate) fn automatic_chat_source_denied(&self, group: &GroupId) -> Result<bool, AppError> {
        let scope = self.chat_source_change(
            group,
            AccountChatSourceOrigin::Created,
            AccountChatSourceOperation::Observe {
                explicitly_accepted: true,
            },
        )?;
        Ok(self
            .app
            .account_storage(&self.state.label)?
            .current_account_chat_source(&scope.account, &scope.local_device, group)?
            == Some(AccountChatSourceVerdict::Denied))
    }
}
