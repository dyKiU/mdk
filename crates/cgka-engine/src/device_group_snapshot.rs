//! Read-only candidates from the local indexed MLS tree for the private profile.
//!
//! Local stability cannot prove that another device selected the same branch.
//! These values are not an authoritative linked-device roster, an enrollment
//! grant, or permission to share chats/history. A future ACK gate must compare
//! authenticated source-leaf evidence and freshly read state on both devices.

use std::collections::HashSet;
use std::fmt;

use cgka_traits::engine_state::EpochState;
use cgka_traits::error::EngineError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::{EpochId, GroupId, MemberId};
use sha2::{Digest, Sha256};

use crate::Engine;
use crate::identity::validated_member_id;

// Private experimental profile bounds, not general Marmot group limits.
const MAX_DEVICE_LEAVES: usize = 128;
const DEVICE_SIGNATURE_KEY_BYTES: usize = 32;
const COMMITMENT_DOMAIN: &[u8] = b"whitenoise-private-device-roster-candidate-v1\0";

/// A real occupied leaf index, independent of the account credential identity.
#[derive(Clone, PartialEq, Eq)]
pub struct CandidateDeviceLeaf {
    pub leaf_index: u32,
    pub signature_public_key: Vec<u8>,
}

impl fmt::Debug for CandidateDeviceLeaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateDeviceLeaf")
            .field("leaf_index", &self.leaf_index)
            .finish_non_exhaustive()
    }
}

/// Bounded, same-account local-tree evidence. Never use this alone as a grant.
#[derive(Clone, PartialEq, Eq)]
pub struct CandidateDeviceGroupSnapshot {
    pub account: MemberId,
    pub group_id: GroupId,
    pub epoch: EpochId,
    pub epoch_authenticator_digest: [u8; 32],
    pub leaves: Vec<CandidateDeviceLeaf>,
    pub roster_commitment: [u8; 32],
}

impl fmt::Debug for CandidateDeviceGroupSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateDeviceGroupSnapshot")
            .field("epoch", &self.epoch)
            .field("leaf_count", &self.leaves.len())
            .finish_non_exhaustive()
    }
}

impl<S: StorageProvider> Engine<S> {
    /// Read an indexed candidate only when local MLS and durable state agree.
    ///
    /// Returns `None` for an incompatible group or unsettled local work. Missing,
    /// quarantined, or unhydrated groups and storage failures retain their typed
    /// errors. The read does not publish, advance convergence, or grant access.
    pub fn candidate_device_group_snapshot(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<CandidateDeviceGroupSnapshot>, EngineError> {
        #[cfg(feature = "test-policy-overrides")]
        let _sync_cost_candidate = crate::enrollment_sync_cost::Probe::start(crate::enrollment_sync_cost::Bucket::Candidate);
        self.ensure_group_live(group_id)?;
        let Some(EpochState::Stable { epoch }) = self.epoch_manager.state(group_id) else {
            return Ok(None);
        };
        if self.pending_convergence_groups.contains(group_id) {
            return Ok(None);
        }
        self.storage.with_read_snapshot(|storage| {
            let record = storage.get_group(group_id)?;
            if record.protocol_profile != ProtocolProfile::Current
                || record.removed
                || record.unrecoverable
                || record.disbanded.is_some()
                || record.epoch != *epoch
                || storage
                    .convergence_pass(group_id)?
                    .is_some_and(|pass| pass.is_active())
                || !storage.list_queued_outbound_intents(group_id)?.is_empty()
                || group_id.as_slice().is_empty()
                || group_id.as_slice().len() > 255
            {
                return Ok(None);
            }
            self.with_mls_group(group_id, |group| {
                if !group.is_active()
                    || group.pending_commit().is_some()
                    || group.epoch().as_u64() != epoch.0
                    || crate::account_identity_proof::protocol_profile_of_group(group)?
                        != ProtocolProfile::Current
                {
                    return Ok(None);
                }
                let account = self.identity.self_id();
                let mut leaves = Vec::new();
                let mut signature_keys = HashSet::new();
                for member in group.members() {
                    if leaves.len() == MAX_DEVICE_LEAVES
                        || validated_member_id(&member.credential)? != *account
                        || member.signature_key.len() != DEVICE_SIGNATURE_KEY_BYTES
                        || !signature_keys.insert(member.signature_key.clone())
                    {
                        return Ok(None);
                    }
                    leaves.push(CandidateDeviceLeaf {
                        leaf_index: member.index.u32(),
                        signature_public_key: member.signature_key,
                    });
                }
                if !leaves.iter().any(|leaf| {
                    leaf.leaf_index == group.own_leaf_index().u32()
                        && leaf.signature_public_key == self.identity.signer.public()
                }) {
                    return Ok(None);
                }
                leaves.sort_unstable_by_key(|leaf| leaf.leaf_index);
                let mut snapshot = CandidateDeviceGroupSnapshot {
                    account: account.clone(),
                    group_id: group_id.clone(),
                    epoch: *epoch,
                    epoch_authenticator_digest: Sha256::digest(
                        group.epoch_authenticator().as_slice(),
                    )
                    .into(),
                    leaves,
                    roster_commitment: [0; 32],
                };
                snapshot.roster_commitment = commitment(&snapshot);
                Ok(Some(snapshot))
            })
        })
    }
}

pub(crate) fn commitment(snapshot: &CandidateDeviceGroupSnapshot) -> [u8; 32] {
    // Canonical private-profile encoding: domain, u32-length-prefixed group and
    // account, u64 epoch, fixed digest, u32 leaf count, sorted u32 index +
    // u32-length-prefixed signature key. No exporter secret leaves the engine.
    let mut hash = Sha256::new();
    hash.update(COMMITMENT_DOMAIN);
    hash_bytes(&mut hash, snapshot.group_id.as_slice());
    hash_bytes(&mut hash, snapshot.account.as_slice());
    hash.update(snapshot.epoch.0.to_be_bytes());
    hash.update(snapshot.epoch_authenticator_digest);
    hash.update((snapshot.leaves.len() as u32).to_be_bytes());
    for leaf in &snapshot.leaves {
        hash.update(leaf.leaf_index.to_be_bytes());
        hash_bytes(&mut hash, &leaf.signature_public_key);
    }
    hash.finalize().into()
}

fn hash_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u32).to_be_bytes());
    hash.update(bytes);
}
