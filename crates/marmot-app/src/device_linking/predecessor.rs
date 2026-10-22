//! Canonical predecessor contents bound by SAS, not an approved-roster grant.
//! Approval additionally requires an authoritative anchor in the account runtime.
use super::{LinkError, Result};
use cgka_engine::device_group_snapshot::CandidateDeviceGroupSnapshot;
use serde::Serialize;
use std::collections::HashSet;

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PredecessorLeaf {
    pub(crate) leaf_index: u32,
    pub(crate) signature_public_key: [u8; 32],
}

// Account and opaque group identity are bound by the enclosing LinkingContext.
// No Debug, native export or conversion to an approval token.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PredecessorRoster {
    pub(crate) epoch: u64,
    pub(crate) epoch_authenticator_digest: [u8; 32],
    pub(crate) leaves: Vec<PredecessorLeaf>,
}

impl PredecessorRoster {
    /// Copy actual indexed candidate contents without assigning authority.
    pub(crate) fn from_candidate(candidate: &CandidateDeviceGroupSnapshot) -> Result<Self> {
        Ok(Self {
            epoch: candidate.epoch.0,
            epoch_authenticator_digest: candidate.epoch_authenticator_digest,
            leaves: candidate
                .leaves
                .iter()
                .map(|leaf| {
                    Ok(PredecessorLeaf {
                        leaf_index: leaf.leaf_index,
                        signature_public_key: leaf
                            .signature_public_key
                            .as_slice()
                            .try_into()
                            .map_err(|_| LinkError::InvalidContext)?,
                    })
                })
                .collect::<Result<_>>()?,
        })
    }

    pub(super) fn validate(&self, approver: [u8; 32], recipient: [u8; 32]) -> Result<()> {
        // Reserve one slot for the recipient and a representable successor epoch.
        if self.leaves.is_empty() || self.leaves.len() >= 128 || self.epoch >= i64::MAX as u64 {
            return Err(LinkError::InvalidContext);
        }
        let mut keys = HashSet::new();
        let mut previous = None;
        for leaf in &self.leaves {
            if previous.is_some_and(|index| index >= leaf.leaf_index)
                || !keys.insert(leaf.signature_public_key)
                || leaf.signature_public_key == recipient
            {
                return Err(LinkError::InvalidContext);
            }
            previous = Some(leaf.leaf_index);
        }
        if !keys.contains(&approver) {
            return Err(LinkError::InvalidContext);
        }
        Ok(())
    }
}
