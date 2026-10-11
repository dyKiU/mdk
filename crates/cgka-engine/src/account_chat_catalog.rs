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
                    || record.is_terminal()
                    || after.is_some_and(|cursor| record.id.as_slice() <= cursor.as_slice())
                {
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
                entries.push(AccountChatCatalogEntry {
                    local_leaf_index: self
                        .with_mls_group(&record.id, |group| Ok(group.own_leaf_index().u32()))?,
                    local_is_admin: authority.facts.is_admin,
                    group_id: record.id,
                    epoch: authority.facts.epoch.0,
                    profile: record.protocol_profile,
                });
                if entries.len() == limit {
                    break;
                }
            }
            Ok(AccountChatCatalog {
                protected: settled.candidate().clone(),
                settlement_generation: settled.settlement_generation(),
                entries,
            })
        })
    }
}
