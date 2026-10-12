//! Authenticated local chat discovery for paired devices. Observations are not
//! sharing consent, remote membership, or authority to send through a sibling.
use crate::{Engine, device_group_snapshot::CandidateDeviceGroupSnapshot};
use cgka_traits::{
    EngineError, GroupId, GroupLifecycleState, group::ProtocolProfile, storage::StorageProvider,
};

/// One exact local membership; a remote catalog copy must not become an MLS row.
pub struct AccountChatCatalogEntry {
    pub group_id: GroupId,
    pub epoch: u64,
    pub profile: ProtocolProfile,
    pub local_leaf_index: u32,
    pub local_is_admin: bool,
}

/// Read-only snapshot bound to the actual local Completed protected roster.
pub struct AccountChatCatalog {
    pub protected: CandidateDeviceGroupSnapshot,
    pub settlement_generation: u64,
    pub entries: Vec<AccountChatCatalogEntry>,
}

/// A source-qualified negative observation, never a usable membership or rejoin.
pub enum AccountChatCatalogObservation {
    Active(AccountChatCatalogEntry),
    Withdrawn {
        group_id: GroupId,
        epoch: u64,
        profile: ProtocolProfile,
        disbanded: bool,
    },
}

pub struct AccountChatCatalogJournal {
    pub protected: CandidateDeviceGroupSnapshot,
    pub settlement_generation: u64,
    pub entries: Vec<AccountChatCatalogObservation>,
}

impl<S: StorageProvider> Engine<S> {
    /// Initial discovery only. No transport, policy allocation or membership
    /// mutation. Bound the returned page rather than the account's stored groups;
    /// canonical group-ID ordering provides an exclusive continuation cursor.
    pub fn account_chat_catalog(
        &self,
        protected: &GroupId,
        after: Option<&GroupId>,
        limit: usize,
    ) -> Result<AccountChatCatalog, EngineError> {
        let journal = self.account_chat_catalog_observations(protected, after, limit, false)?;
        Ok(AccountChatCatalog {
            protected: journal.protected,
            settlement_generation: journal.settlement_generation,
            entries: journal
                .entries
                .into_iter()
                .filter_map(|entry| match entry {
                    AccountChatCatalogObservation::Active(entry) => Some(entry),
                    AccountChatCatalogObservation::Withdrawn { .. } => None,
                })
                .collect(),
        })
    }

    /// Bounded source journal including only actual canonical terminal copies.
    /// Hidden local projections do not terminate MLS membership and are not withdrawals.
    pub fn account_chat_catalog_journal(
        &self,
        protected: &GroupId,
        after: Option<&GroupId>,
        limit: usize,
    ) -> Result<AccountChatCatalogJournal, EngineError> {
        self.account_chat_catalog_observations(protected, after, limit, true)
    }

    fn account_chat_catalog_observations(
        &self,
        protected: &GroupId,
        after: Option<&GroupId>,
        limit: usize,
        include_terminal: bool,
    ) -> Result<AccountChatCatalogJournal, EngineError> {
        if !(1..=128).contains(&limit)
            || after
                .is_some_and(|cursor| cursor.as_slice().is_empty() || cursor.as_slice().len() > 255)
        {
            return Err(EngineError::Other(
                "invalid account chat catalog limit".into(),
            ));
        }
        self.storage.with_read_snapshot(|storage| {
            let settled = self
                .validated_settled_device_roster(protected)?
                .ok_or_else(|| {
                    EngineError::Other("settled account chat roster unavailable".into())
                })?;
            let mut records = storage.list_group_records()?;
            records.sort_by(|a, b| a.id.as_slice().cmp(b.id.as_slice()));
            let mut entries = Vec::new();
            for record in records {
                if record.id == *protected
                    || after.is_some_and(|cursor| record.id.as_slice() <= cursor.as_slice())
                {
                    continue;
                }
                if record.is_terminal() {
                    if include_terminal && !self.exclude_private_group_from_chat(&record.id)? {
                        entries.push(AccountChatCatalogObservation::Withdrawn {
                            group_id: record.id,
                            epoch: record.epoch.0,
                            profile: record.protocol_profile,
                            disbanded: record.disbanded.is_some(),
                        });
                        if entries.len() == limit {
                            break;
                        }
                    }
                    continue;
                }
                let authority = self.group_authority(&record.id)?;
                if authority.lifecycle != GroupLifecycleState::Stable
                    || authority.disbanding
                    || !authority.facts.is_member
                {
                    continue;
                }
                if self.exclude_private_group_from_chat(&record.id)? {
                    continue;
                }
                let membership = self.canonical_group_membership(&record.id)?;
                if !membership.local_leaf_active {
                    continue;
                }
                entries.push(AccountChatCatalogObservation::Active(
                    AccountChatCatalogEntry {
                        local_leaf_index: self
                            .with_mls_group(&record.id, |group| Ok(group.own_leaf_index().u32()))?,
                        local_is_admin: authority.facts.is_admin,
                        group_id: record.id,
                        epoch: authority.facts.epoch.0,
                        profile: record.protocol_profile,
                    },
                ));
                if entries.len() == limit {
                    break;
                }
            }
            Ok(AccountChatCatalogJournal {
                protected: settled.candidate().clone(),
                settlement_generation: settled.settlement_generation(),
                entries,
            })
        })
    }
}
