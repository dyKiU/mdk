//! Existing Member chats accepted only at a fresh human broad-sharing action.
//! The captured list is private memory on that original, never a grant DTO.
use super::AppClient;
use cgka_traits::{
    GroupId, StorageProvider,
    approved_account_sharing_policy::{
        ApprovedAccountSharingPolicy, approved_account_sharing_identity,
    },
    storage::{AccountDeviceSignerStorage, StorageError, StorageResult},
};
use std::sync::Arc;
use storage_sqlite::account_chat_source::{
    AccountChatSourceChange, AccountChatSourceOperation, AccountChatSourceOrigin,
    AccountChatSourceVerdict, MAX_ACCOUNT_CHAT_SOURCE_ORIGINS,
};

#[cfg(all(test, feature = "test-policy-overrides"))]
mod tests;

pub(crate) struct CapturedLegacyChats {
    account: [u8; 32],
    local_device: [u8; 32],
    groups: Vec<LegacyMemberObservation>,
}
struct LegacyMemberObservation {
    group: GroupId,
    via_welcome: Option<String>,
}
fn denied() -> StorageError {
    StorageError::Serialization("fresh original legacy acceptance unavailable".into())
}

impl AppClient {
    /// Called only by the named human broad-approval transition, after its exact
    /// displayed revision check. Renewal and policy-row reads never call this.
    pub(crate) fn capture_legacy_chats(
        &self,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<Arc<CapturedLegacyChats>> {
        validate_original()?;
        if self.state.groups.len() > MAX_ACCOUNT_CHAT_SOURCE_ORIGINS {
            return Err(StorageError::Capacity(
                "legacy chat capture lifetime bound".into(),
            ));
        }
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| denied())?;
        let identity = self.runtime.session().self_id();
        let account = identity.as_slice().try_into().map_err(|_| denied())?;
        let binding = storage
            .account_device_signer(&identity)?
            .ok_or_else(denied)?;
        let local_device = binding
            .mls_signature_public_key
            .as_slice()
            .try_into()
            .map_err(|_| denied())?;
        let mut groups = Vec::new();
        for observed in &self.state.groups {
            validate_original()?;
            let group = GroupId::new(hex::decode(&observed.group_id_hex).map_err(|_| denied())?);
            let Some(fresh) = self
                .app
                .group(&self.state.label, &observed.group_id_hex)
                .map_err(|_| denied())?
            else {
                continue;
            };
            if fresh.pending_confirmation || fresh.self_membership != crate::SelfMembership::Member
            {
                continue;
            }
            if self
                .runtime
                .session()
                .exclude_private_group_from_chat(&group)
                .map_err(|_| denied())?
            {
                continue;
            }
            if self
                .pending_chat_source_changes
                .iter()
                .any(|change| change.group == group)
            {
                continue;
            }
            // Known lineage never becomes ambiguous again. In particular an
            // actual pending/denied Welcome cannot be promoted by this action.
            if storage
                .current_account_chat_source(&account, &local_device, &group)?
                .is_some()
            {
                continue;
            }
            // Reliable existing lineage remains the ordinary Source23 path.
            // Capture is observational: do not bootstrap a ledger write while
            // the fresh broad original has not committed its policy.
            if fresh.via_welcome_message_id_hex.is_some()
                || self
                    .runtime
                    .session()
                    .retained_local_group_creation(&group)
                    .map_err(|_| denied())?
            {
                continue;
            }
            let authority = self
                .runtime
                .session()
                .group_authority(&group)
                .map_err(|_| denied())?;
            if !authority.facts.is_member
                || authority.facts.removed
                || authority.facts.disbanded
                || authority.facts.unrecoverable
            {
                continue;
            }
            groups.push(LegacyMemberObservation {
                group,
                via_welcome: fresh.via_welcome_message_id_hex,
            });
        }
        groups.sort_by(|a, b| a.group.as_slice().cmp(b.group.as_slice()));
        groups.dedup_by(|a, b| a.group == b.group);
        validate_original()?;
        Ok(Arc::new(CapturedLegacyChats {
            account,
            local_device,
            groups,
        }))
    }

    fn validate_legacy_chat(
        &self,
        capture: &CapturedLegacyChats,
        change: &AccountChatSourceChange,
    ) -> StorageResult<()> {
        if capture.account != change.account || capture.local_device != change.local_device {
            return Err(denied());
        }
        let observed = capture
            .groups
            .iter()
            .find(|row| row.group == change.group)
            .ok_or_else(denied)?;
        self.validate_chat_source_change(change)?;
        if self
            .pending_chat_source_changes
            .iter()
            .any(|pending| pending.group == change.group)
        {
            return Err(denied());
        }
        let row = self
            .app
            .group(&self.state.label, &hex::encode(change.group.as_slice()))
            .map_err(|_| denied())?
            .ok_or_else(denied)?;
        if row.pending_confirmation
            || row.self_membership != crate::SelfMembership::Member
            || row.via_welcome_message_id_hex != observed.via_welcome
        {
            return Err(denied());
        }
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| denied())?;
        match storage.current_account_chat_source(
            &change.account,
            &change.local_device,
            &change.group,
        )? {
            None => Ok(()),
            Some(AccountChatSourceVerdict::Accepted)
                if storage.account_chat_source_is_current(change)? =>
            {
                Ok(())
            }
            _ => Err(denied()),
        }
    }

    /// Same original validator protects policy and every captured group, before
    /// and after the atomic SQL unit. Data cannot supply an owner or a new lease.
    pub(crate) fn commit_policy_with_legacy_chats(
        &self,
        policy: &ApprovedAccountSharingPolicy,
        capture: &CapturedLegacyChats,
        validate_original: &dyn Fn() -> StorageResult<()>,
    ) -> StorageResult<()> {
        if capture.account != policy.account || capture.local_device != policy.local_device {
            return Err(denied());
        }
        let policy_id = approved_account_sharing_identity(
            &policy.account,
            &policy.protected_group,
            &policy.local_device,
            &policy.peer_device,
            &policy.approval_id,
        )?;
        let changes: Vec<_> = capture
            .groups
            .iter()
            .map(|observed| AccountChatSourceChange {
                account: capture.account,
                local_device: capture.local_device,
                group: observed.group.clone(),
                origin: AccountChatSourceOrigin::ExplicitLegacyAcceptance {
                    approval_id: policy.approval_id,
                },
                operation: AccountChatSourceOperation::Observe {
                    explicitly_accepted: true,
                },
            })
            .collect();
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| denied())?;
        storage.with_transaction(|_| {
            validate_original()?;
            storage
                .approved_account_sharing_policy_storage()
                .ok_or_else(denied)?
                .put_approved_account_sharing_policy(policy, validate_original)?;
            for chunk in changes.chunks(128) {
                storage.record_explicit_legacy_chat_acceptance(&policy_id, chunk, &|change| {
                    validate_original()?;
                    self.validate_legacy_chat(capture, change)
                })?;
            }
            validate_original()
        })
    }
}
