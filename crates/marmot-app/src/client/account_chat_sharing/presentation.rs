//! Worker-local observation reads. Durable rows never substitute for fresh Core checks.
use super::*;
use cgka_traits::GroupStorage;
use cgka_traits::{
    approved_account_sharing_policy::{
        ApprovedAccountSharingPolicy, approved_account_sharing_identity,
    },
    mirrored_chat_catalog::MirroredChatScope,
    mirrored_chat_messages::MirroredChatCursor,
    private_roster_settlement::PrivateSettlementPhase,
};

impl AppClient {
    /// Called only after an actual mirror commit or loss of its eligibility.
    /// This wake is not authority: windows read fresh policy and Core state.
    pub(crate) fn notify_mirrored_presentation_changed(&self) {
        let _ = self
            .app
            .presentation_signals
            .mirrored
            .send(self.state.label.clone());
    }

    /// Called only inside the protected-event suppression path. Even before
    /// automatic-channel insertion, real lifecycle changes invalidate reads.
    pub(crate) fn notify_private_presentation_transition(&self, event: &cgka_traits::GroupEvent) {
        if matches!(
            event,
            cgka_traits::GroupEvent::EpochChanged { .. }
                | cgka_traits::GroupEvent::GroupMemberLeavesRemoved { .. }
                | cgka_traits::GroupEvent::LocalGroupCopyTerminated { .. }
                | cgka_traits::GroupEvent::LocalGroupCopyRestored { .. }
        ) {
            self.notify_mirrored_presentation_changed();
        }
    }

    fn current_presentation_scopes(&self) -> Result<Vec<MirroredChatScope>, AccountSharingError> {
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::NotReady)?;
        let policies = storage
            .approved_account_sharing_policy_storage()
            .ok_or(AccountSharingError::NotReady)?
            .approved_account_sharing_policies()
            .map_err(|_| AccountSharingError::NotReady)?;
        let mut scopes = Vec::new();
        for policy in policies {
            if policy.revoked {
                continue;
            }
            match self.automatic_policy_current(&policy) {
                Ok(()) => scopes.push(self.presentation_scope(&policy)?),
                Err(AccountSharingError::Closed) => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(scopes)
    }

    pub(super) fn presentation_scope(
        &self,
        policy: &ApprovedAccountSharingPolicy,
    ) -> Result<MirroredChatScope, AccountSharingError> {
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::NotReady)?;
        let round = storage
            .private_roster_settlement_storage()
            .ok_or(AccountSharingError::NotReady)?
            .read_round()
            .map_err(|_| AccountSharingError::NotReady)?
            .ok_or(AccountSharingError::Closed)?;
        if round.phase != PrivateSettlementPhase::Completed
            || round.anchor.account != policy.account
            || round.anchor.local_device != policy.local_device
            || round.anchor.group_id != policy.protected_group
        {
            return Err(AccountSharingError::Closed);
        }
        let policy_digest = approved_account_sharing_identity(
            &policy.account,
            &policy.protected_group,
            &policy.local_device,
            &policy.peer_device,
            &policy.approval_id,
        )
        .map_err(|_| AccountSharingError::NotReady)?;
        Ok(MirroredChatScope {
            account: policy.account,
            local_device: policy.local_device,
            source_device: policy.peer_device,
            policy_digest,
            protected_group: policy.protected_group.clone(),
            protected_generation: round.generation,
        })
    }

    pub(crate) fn current_mirrored_catalog_page(
        &self,
        after: Option<&crate::GroupId>,
        limit: usize,
    ) -> Result<Vec<storage_sqlite::MirroredCatalogObservation>, AccountSharingError> {
        let scopes = self.current_presentation_scopes()?;
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::NotReady)?;
        let rows = storage
            .app_storage().mirrored_catalog_observation_page(&scopes, after, limit)
            .map_err(|_| AccountSharingError::NotReady)?;
        if self.current_presentation_scopes()? != scopes {
            return Err(AccountSharingError::Closed);
        }
        Ok(rows)
    }

    pub(crate) fn current_mirrored_direct_conversation(
        &self,
        peer: &[u8; 32],
    ) -> Result<Option<storage_sqlite::MirroredCatalogObservation>, AccountSharingError> {
        let scopes = self.current_presentation_scopes()?;
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::NotReady)?;
        let row = storage
            .app_storage().mirrored_direct_conversation_observation(&scopes, peer)
            .map_err(|_| AccountSharingError::NotReady)?;
        if self.current_presentation_scopes()? != scopes {
            return Err(AccountSharingError::Closed);
        }
        Ok(row)
    }

    pub(crate) fn current_account_conversation_page(
        &self,
        group: &crate::GroupId,
        before: Option<&MirroredChatCursor>,
        limit: usize,
        now: u64,
    ) -> Result<
        (
            bool,
            Option<storage_sqlite::MirroredCatalogObservation>,
            Vec<storage_sqlite::AccountConversationObservation>,
        ),
        AccountSharingError,
    > {
        let scopes = self.current_presentation_scopes()?;
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::NotReady)?;
        let observed = cgka_traits::StorageProvider::with_read_snapshot(&storage, |store| {
            let local = match store.get_group(group) {
                Ok(_) => true,
                Err(cgka_traits::StorageError::NotFound) => false,
                Err(error) => return Err(error),
            };
            let header = store.app_storage().mirrored_catalog_observation(&scopes, group)?;
            if !local && header.is_none() {
                return Err(cgka_traits::StorageError::NotFound);
            }
            let rows = store
                .app_storage().account_conversation_observation_window(&scopes, group, before, limit, now)?;
            Ok((local, header, rows))
        })
        .map_err(|_| AccountSharingError::NotReady)?;
        if self.current_presentation_scopes()? != scopes {
            return Err(AccountSharingError::Closed);
        }
        Ok(observed)
    }

    pub(crate) fn current_mirrored_message_page(
        &self,
        group: &crate::GroupId,
        after: Option<&MirroredChatCursor>,
        limit: usize,
        now: u64,
    ) -> Result<Vec<storage_sqlite::MirroredMessageObservation>, AccountSharingError> {
        let scopes = self.current_presentation_scopes()?;
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| AccountSharingError::NotReady)?;
        let rows = storage
            .app_storage().mirrored_message_observation_page(&scopes, group, after, limit, now)
            .map_err(|_| AccountSharingError::NotReady)?;
        if self.current_presentation_scopes()? != scopes {
            return Err(AccountSharingError::Closed);
        }
        Ok(rows)
    }
}
