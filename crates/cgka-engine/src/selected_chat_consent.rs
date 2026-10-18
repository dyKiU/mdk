//! Signed selected-chat observations. Packets never grant recipient membership.
use crate::{Engine, device_group_snapshot::CandidateDeviceGroupSnapshot};
use cgka_traits::{
    EngineError, GroupId, GroupLifecycleState, group::ProtocolProfile, storage::StorageProvider,
};
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, types::SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub const MAX_SELECTED_CHAT_PACKET_BYTES: usize = 16_384;
const REQUEST: &str = "whitenoise.selected-chat-request-observation.v1";
const CONSENT: &str = "whitenoise.selected-chat-consent-observation.v1";
pub(crate) mod invite;
mod offer;
mod package;
mod welcome;
pub use invite::SelectedChatInviteLease;
pub use offer::AuthenticatedSelectedChatOffer;
pub use package::{SelectedChatPackageLease, SelectedChatPackageOffer};
pub use welcome::{SelectedChatWelcomeLease, SelectedChatWelcomePolicy};
fn denied() -> EngineError {
    EngineError::Other("selected chat observation unavailable".into())
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct IndexedOrdinaryLeaf {
    pub(crate) index: u32,
    pub(crate) account: Vec<u8>,
    pub(crate) signer: Vec<u8>,
    pub(crate) hash: [u8; 32],
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Ordinary {
    group: Vec<u8>,
    epoch: u64,
    own_index: u32,
    own_hash: Vec<u8>,
    roster: [u8; 32],
    leaves: Vec<IndexedOrdinaryLeaf>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    account: Vec<u8>,
    protected_group: Vec<u8>,
    protected_epoch: u64,
    protected_generation: u64,
    protected_authenticator: [u8; 32],
    protected_roster: [u8; 32],
    ordinary: Ordinary,
    nonce: [u8; 32],
    source_index: u32,
    source_key: Vec<u8>,
    signature: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    protocol: String,
    binding: [u8; 32],
    generation: u64,
    nonce: [u8; 32],
    source_index: u32,
    source_key: Vec<u8>,
    signature: Vec<u8>,
}
/// Authenticated metadata only. No constructor/serde/Clone or permission.
pub struct AuthenticatedSelectedChatRequest {
    frame: Request,
    wire: Vec<u8>,
    actual: CandidateDeviceGroupSnapshot,
    local_protected_generation: u64,
}
impl AuthenticatedSelectedChatRequest {
    pub fn ordinary_group(&self) -> GroupId {
        GroupId::new(self.frame.ordinary.group.clone())
    }
    pub fn protected_group(&self) -> GroupId {
        self.actual.group_id.clone()
    }
    pub fn source_key(&self) -> &[u8] {
        &self.frame.source_key
    }
    pub fn binding(&self) -> [u8; 32] {
        Sha256::digest(&self.wire).into()
    }
}
/// Verified indexed signature metadata only, not a live sibling consent lease.
pub struct AuthenticatedSelectedChatConsent {
    source_index: u32,
    source_key: Vec<u8>,
    generation: u64,
}
impl AuthenticatedSelectedChatConsent {
    pub fn source_index(&self) -> u32 {
        self.source_index
    }
    pub fn source_key(&self) -> &[u8] {
        &self.source_key
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, EngineError> {
    let bytes = serde_json::to_vec(value).map_err(|_| denied())?;
    if bytes.is_empty() || bytes.len() > MAX_SELECTED_CHAT_PACKET_BYTES {
        return Err(denied());
    }
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned + Serialize>(wire: &[u8]) -> Result<T, EngineError> {
    if wire.is_empty() || wire.len() > MAX_SELECTED_CHAT_PACKET_BYTES {
        return Err(denied());
    }
    let value = serde_json::from_slice(wire).map_err(|_| denied())?;
    if encode(&value)? != wire {
        return Err(denied());
    }
    Ok(value)
}
impl<S: StorageProvider> Engine<S> {
    fn selected_ordinary(&self, group: &GroupId) -> Result<Ordinary, EngineError> {
        self.ensure_group_live(group)?;
        let record = self.group_record(group)?;
        let authority = self.group_authority(group)?;
        let membership = self.canonical_group_membership(group)?;
        let own_index = self.do_own_leaf_index(group)?;
        if record.protocol_profile != ProtocolProfile::Current
            || authority.lifecycle != GroupLifecycleState::Stable
            || authority.disbanding
            || !authority.facts.is_admin
            || !membership.local_leaf_active
            || !membership
                .member_leaves
                .iter()
                .any(|leaf| leaf.leaf_index == own_index && &leaf.member == self.identity.self_id())
        {
            return Err(denied());
        }
        let mut leaves = membership.member_leaves;
        leaves.sort_by_key(|leaf| leaf.leaf_index);
        let mut hash = Sha256::new();
        hash.update(b"WN-selected-chat-original-roster-v1");
        hash.update((leaves.len() as u64).to_be_bytes());
        for leaf in leaves {
            hash.update(leaf.leaf_index.to_be_bytes());
            hash.update((leaf.member.as_slice().len() as u64).to_be_bytes());
            hash.update(leaf.member.as_slice());
        }
        Ok(Ordinary {
            group: group.as_slice().to_vec(),
            epoch: authority.facts.epoch.0,
            own_index,
            own_hash: self.own_leaf_hash(group)?,
            roster: hash.finalize().into(),
            leaves: self.selected_indexed_ordinary_leaves(group)?,
        })
    }
    /// Derive and sign actual metadata only; App must check its original request.
    pub fn selected_chat_request_observation(
        &self,
        ordinary: &GroupId,
        protected: &GroupId,
        nonce: [u8; 32],
    ) -> Result<Vec<u8>, EngineError> {
        self.ensure_group_live(ordinary)?;
        self.ensure_group_live(protected)?;
        self.storage.with_read_snapshot(|_| {
            if nonce == [0; 32] || ordinary == protected {
                return Err(denied());
            }
            let actual = self
                .validated_settled_device_roster(protected)?
                .ok_or_else(denied)?;
            let current = actual.candidate();
            let source_key = self.identity.signer.public().to_vec();
            let source = current
                .leaves
                .iter()
                .find(|leaf| leaf.signature_public_key == source_key)
                .ok_or_else(denied)?;
            let mut frame = Request {
                protocol: REQUEST.into(),
                account: current.account.as_slice().to_vec(),
                protected_group: protected.as_slice().to_vec(),
                protected_epoch: current.epoch.0,
                protected_generation: actual.settlement_generation(),
                protected_authenticator: current.epoch_authenticator_digest,
                protected_roster: current.roster_commitment,
                ordinary: self.selected_ordinary(ordinary)?,
                nonce,
                source_index: source.leaf_index,
                source_key,
                signature: vec![],
            };
            frame.signature = self
                .identity
                .signer
                .sign(&encode(&frame)?)
                .map_err(|_| denied())?;
            encode(&frame)
        })
    }
    pub fn authenticate_selected_chat_request(
        &self,
        wire: &[u8],
    ) -> Result<AuthenticatedSelectedChatRequest, EngineError> {
        let mut frame: Request = decode(wire)?;
        if frame.protocol != REQUEST
            || frame.nonce == [0; 32]
            || frame.protected_generation == 0
            || frame.account.len() != 32
            || frame.protected_group.is_empty()
            || frame.protected_group.len() > 256
            || frame.ordinary.group.is_empty()
            || frame.ordinary.group.len() > 256
            || frame.ordinary.group == frame.protected_group
            || frame.ordinary.own_hash.is_empty()
            || frame.ordinary.own_hash.len() > 512
            || frame.signature.len() != 64
        {
            return Err(denied());
        }
        let mut indices = std::collections::BTreeSet::new();
        let mut signers = std::collections::BTreeSet::new();
        if frame.ordinary.leaves.is_empty()
            || frame.ordinary.leaves.len() > 128
            || !frame
                .ordinary
                .leaves
                .windows(2)
                .all(|pair| pair[0].index < pair[1].index)
            || frame.ordinary.leaves.iter().any(|leaf| {
                leaf.account.len() != 32
                    || leaf.signer.len() != 32
                    || !indices.insert(leaf.index)
                    || !signers.insert(leaf.signer.clone())
            })
            || !frame.ordinary.leaves.iter().any(|leaf| {
                leaf.index == frame.ordinary.own_index
                    && leaf.account == frame.account
                    && leaf.signer == frame.source_key
                    && leaf.hash.as_slice() == frame.ordinary.own_hash
            })
        {
            return Err(denied());
        }
        let group = GroupId::new(frame.protected_group.clone());
        self.ensure_group_live(&group)?;
        let (actual, local_protected_generation) = self.storage.with_read_snapshot(|_| {
            let selected = self
                .validated_settled_device_roster(&group)?
                .ok_or_else(denied)?;
            let actual = selected.candidate();
            if (frame.source_key == self.identity.signer.public()
                && selected.settlement_generation() != frame.protected_generation)
                || actual.account.as_slice() != frame.account
                || actual.epoch.0 != frame.protected_epoch
                || actual.epoch_authenticator_digest != frame.protected_authenticator
                || actual.roster_commitment != frame.protected_roster
                || !actual.leaves.iter().any(|leaf| {
                    leaf.leaf_index == frame.source_index
                        && leaf.signature_public_key == frame.source_key
                })
            {
                return Err(denied());
            }
            let signature = std::mem::take(&mut frame.signature);
            self.crypto
                .verify_signature(
                    SignatureScheme::ED25519,
                    &encode(&frame)?,
                    &frame.source_key,
                    &signature,
                )
                .map_err(|_| denied())?;
            frame.signature = signature;
            Ok((actual.clone(), selected.settlement_generation()))
        })?;
        Ok(AuthenticatedSelectedChatRequest {
            frame,
            wire: wire.to_vec(),
            actual,
            local_protected_generation,
        })
    }
    /// Response signatures are observations; only App's explicit live owner approves.
    pub fn selected_chat_consent_observation(
        &self,
        request: &AuthenticatedSelectedChatRequest,
        generation: u64,
        nonce: [u8; 32],
    ) -> Result<Vec<u8>, EngineError> {
        self.storage.with_read_snapshot(|_| {
            let current = self.authenticate_selected_chat_request(&request.wire)?;
            if current.actual != request.actual || generation == 0 || nonce == [0; 32] {
                return Err(denied());
            }
            let source_key = self.identity.signer.public().to_vec();
            if source_key == request.frame.source_key {
                return Err(denied());
            }
            let source = current
                .actual
                .leaves
                .iter()
                .find(|leaf| leaf.signature_public_key == source_key)
                .ok_or_else(denied)?;
            let mut frame = Response {
                protocol: CONSENT.into(),
                binding: request.binding(),
                generation,
                nonce,
                source_index: source.leaf_index,
                source_key,
                signature: vec![],
            };
            frame.signature = self
                .identity
                .signer
                .sign(&encode(&frame)?)
                .map_err(|_| denied())?;
            encode(&frame)
        })
    }
    pub fn authenticate_selected_chat_consent(
        &self,
        request_wire: &[u8],
        wire: &[u8],
    ) -> Result<AuthenticatedSelectedChatConsent, EngineError> {
        self.storage.with_read_snapshot(|_| {
            let request = self.authenticate_selected_chat_request(request_wire)?;
            let mut frame: Response = decode(wire)?;
            if frame.protocol != CONSENT
                || frame.binding != request.binding()
                || frame.generation == 0
                || frame.nonce == [0; 32]
                || frame.signature.len() != 64
                || frame.source_key == request.frame.source_key
                || !request.actual.leaves.iter().any(|leaf| {
                    leaf.leaf_index == frame.source_index
                        && leaf.signature_public_key == frame.source_key
                })
            {
                return Err(denied());
            }
            let signature = std::mem::take(&mut frame.signature);
            self.crypto
                .verify_signature(
                    SignatureScheme::ED25519,
                    &encode(&frame)?,
                    &frame.source_key,
                    &signature,
                )
                .map_err(|_| denied())?;
            Ok(AuthenticatedSelectedChatConsent {
                source_index: frame.source_index,
                source_key: frame.source_key,
                generation: frame.generation,
            })
        })
    }
}
