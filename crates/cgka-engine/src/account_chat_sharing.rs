//! Explicit original paired-device policy channels. Catalog observations and
//! serialized requests never grant ordinary MLS membership or forwarding rights.
use crate::{Engine, device_group_snapshot::CandidateDeviceGroupSnapshot};
use cgka_traits::{EngineError, GroupId, storage::StorageProvider};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    signatures::Signer,
    types::{Ciphersuite, HpkeCiphertext, HpkeKeyPair, SignatureScheme},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};
use web_time::Instant;
use zeroize::Zeroizing;

const PROTOCOL: &str = "whitenoise.experimental.automatic-account-chat-sharing.v1";
const HPKE_INFO: &[u8] = b"WN-original-account-chat-sharing-v1";
pub const MAX_ACCOUNT_SHARED_BODY_BYTES: usize = 1536;
const MAX_WIRE_BYTES: usize = 16384;
const MAX_ORIGINAL_BODIES: usize = 128;
/// Private experimental protected-group control, never an ordinary chat event.
pub const ACCOUNT_SHARING_CONTROL_KIND: u64 = 38178;
mod transport;
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AccountSharingControl {
    Request,
    Consent,
    Body(u64),
}
/// Current authenticated paired-device selectors; never a sharing grant.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountSharingTarget {
    pub leaf_index: u32,
    pub device: Vec<u8>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct AccountSharingTargets {
    pub protected_group: GroupId,
    pub protected_epoch: u64,
    pub targets: Vec<AccountSharingTarget>,
}
/// Authenticated observation from the actual protected MLS source leaf.
pub struct ReceivedAccountSharingControl {
    pub nonce: [u8; 32],
    pub control: AccountSharingControl,
    pub signer: Vec<u8>,
    /// Authenticated routing observations, never local sharing approval.
    pub source: Vec<u8>,
    pub recipient: Vec<u8>,
    pub approval_id: [u8; 32],
}
fn refused() -> EngineError {
    EngineError::Other("original account sharing policy unavailable".into())
}
fn config() -> openmls_traits::types::HpkeConfig {
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.hpke_config()
}

/// One fixed local original. A peer's generation number is never a local grant.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountSharingScope {
    pub protected: CandidateDeviceGroupSnapshot,
    pub local_generation: u64,
    pub source: Vec<u8>,
    pub recipient: Vec<u8>,
    pub nonce: [u8; 32],
    /// Stable explicit approval identity; unlike the ephemeral transcript hash,
    /// this survives fresh keys, clocks and ordinary channel renewal.
    pub approved_policy_identity: [u8; 32],
    pub approval_id: [u8; 32],
}
// Stable persistence identity is independent of local role, keys, nonce and clock.
fn approved_policy_identity(scope: &AccountSharingScope) -> Result<[u8; 32], EngineError> {
    cgka_traits::approved_account_sharing_policy::approved_account_sharing_identity(
        &scope
            .protected
            .account
            .as_slice()
            .try_into()
            .map_err(|_| refused())?,
        &scope.protected.group_id,
        &scope.source.as_slice().try_into().map_err(|_| refused())?,
        &scope
            .recipient
            .as_slice()
            .try_into()
            .map_err(|_| refused())?,
        &scope.approval_id,
    )
    .map_err(|_| refused())
}

/// Installed by the account actor after explicit existing/future-chat approval.
pub trait TrustedAccountSharingLease: Send + Sync {
    fn approved_policy_id(&self, _scope: &AccountSharingScope) -> Result<[u8; 32], EngineError> {
        Err(refused())
    }
    fn validate(&self, _scope: &AccountSharingScope) -> Result<Instant, EngineError> {
        Err(refused())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountSharedBodyKind {
    Catalog,
    CatalogReceipt,
    PairPolicyCommitted,
    Records,
    RecordReceipt,
    SendIntent,
    SendReceipt,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    protocol: String,
    phase: String,
    account: Vec<u8>,
    protected: Vec<u8>,
    epoch: u64,
    authenticator: [u8; 32],
    roster: [u8; 32],
    source: Vec<u8>,
    recipient: Vec<u8>,
    nonce: [u8; 32],
    approved_policy_identity: [u8; 32],
    approval_id: [u8; 32],
    signer: Vec<u8>,
    generation: u64,
    binding: [u8; 32],
    public_key: Vec<u8>,
    kind: Option<AccountSharedBodyKind>,
    sequence: u64,
    body_digest: [u8; 32],
    kem: Vec<u8>,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
}

#[cfg(test)]
#[path = "account_chat_sharing/tests.rs"]
mod tests;
fn encode(frame: &Frame) -> Result<Vec<u8>, EngineError> {
    let wire = serde_json::to_vec(frame).map_err(|_| refused())?;
    if wire.len() > MAX_WIRE_BYTES {
        return Err(refused());
    }
    Ok(wire)
}
fn decode(wire: &[u8]) -> Result<Frame, EngineError> {
    if wire.is_empty() || wire.len() > MAX_WIRE_BYTES {
        return Err(refused());
    }
    let frame: Frame = serde_json::from_slice(wire).map_err(|_| refused())?;
    if encode(&frame)? != wire {
        return Err(refused());
    }
    Ok(frame)
}
/// Authenticated metadata only; no public constructor or serialization.
pub struct AuthenticatedAccountSharingRequest {
    frame: Frame,
    wire: Vec<u8>,
    scope: AccountSharingScope,
}
impl AuthenticatedAccountSharingRequest {
    pub fn scope(&self) -> &AccountSharingScope {
        &self.scope
    }
    pub fn request_digest(&self) -> [u8; 32] {
        Sha256::digest(&self.wire).into()
    }
}
/// Holds private HPKE keys and the exact two-party explicit policy transcript.
/// No Clone/Deserialize: persistence cannot reconstruct an original owner.
pub struct OwnedAccountSharingChannel {
    owner: Weak<crate::private_enrollment_endorsement::Lifetime>,
    scope: AccountSharingScope,
    lease: Arc<dyn TrustedAccountSharingLease>,
    deadline: Instant,
    keys: Option<HpkeKeyPair>,
    request: Vec<u8>,
    consent: Option<Vec<u8>>,
    peer_key: Option<Vec<u8>>,
    recipient_role: bool,
    sealed: BTreeMap<u64, (AccountSharedBodyKind, [u8; 32], Vec<u8>)>,
    outbound: Vec<transport::FrozenSharingControl>,
}
impl OwnedAccountSharingChannel {
    pub fn scope(&self) -> &AccountSharingScope {
        &self.scope
    }
    pub fn request_packet(&self) -> Result<Vec<u8>, EngineError> {
        self.live()?;
        Ok(self.request.clone())
    }
    pub fn consent_packet(&self) -> Result<Vec<u8>, EngineError> {
        self.live()?;
        self.consent.clone().ok_or_else(refused)
    }
    /// The peer's signed projection generation is an observation of this
    /// authenticated original transcript, never a local settlement grant.
    pub fn authenticated_peer_generation(&self) -> Result<u64, EngineError> {
        self.live()?;
        let frame = decode(if self.recipient_role {
            &self.request
        } else {
            self.consent.as_ref().ok_or_else(refused)?
        })?;
        Ok(frame.generation)
    }
    pub fn original_deadline(&self) -> Instant {
        self.deadline
    }
    pub fn policy_digest(&self) -> Result<[u8; 32], EngineError> {
        self.live()?;
        let mut digest = Sha256::new();
        digest.update(b"WN-original-account-sharing-policy-v1");
        digest.update(Sha256::digest(&self.request));
        digest.update(Sha256::digest(self.consent.as_ref().ok_or_else(refused)?));
        Ok(digest.finalize().into())
    }
    /// HpkePrivateKey uses SecretVLBytes with ZeroizeOnDrop.
    pub fn retire(&mut self) {
        self.keys = None;
        self.peer_key = None;
        self.sealed.clear();
        self.outbound.clear();
    }
    fn live(&self) -> Result<(), EngineError> {
        if self.keys.is_none()
            || !self.owner.upgrade().is_some_and(|owner| owner.is_open())
            || Instant::now() >= self.deadline
            || self.lease.validate(&self.scope)? != self.deadline
            || self.lease.approved_policy_id(&self.scope)? != self.scope.approval_id
        {
            return Err(refused());
        }
        Ok(())
    }
}
impl<S: StorageProvider> Engine<S> {
    /// Read only the current settled account-owned protected roster. No owner,
    /// consent, channel, ordinary membership or transport mutation is created.
    pub fn account_chat_sharing_targets(
        &self,
        protected: &GroupId,
    ) -> Result<AccountSharingTargets, EngineError> {
        self.storage.with_read_snapshot(|_| {
            let roster = self
                .validated_settled_device_roster(protected)?
                .ok_or_else(refused)?;
            let snapshot = roster.candidate();
            if &snapshot.account != self.identity.self_id()
                || !snapshot
                    .leaves
                    .iter()
                    .any(|leaf| leaf.signature_public_key == self.identity.signer.public())
                || snapshot.leaves.len() > 128
            {
                return Err(refused());
            }
            let mut targets = Vec::new();
            for leaf in &snapshot.leaves {
                if leaf.signature_public_key == self.identity.signer.public() {
                    continue;
                }
                if leaf.signature_public_key.len() != 32 {
                    return Err(refused());
                }
                targets.push(AccountSharingTarget {
                    leaf_index: leaf.leaf_index,
                    device: leaf.signature_public_key.clone(),
                });
            }
            targets.sort_by_key(|target| target.leaf_index);
            Ok(AccountSharingTargets {
                protected_group: snapshot.group_id.clone(),
                protected_epoch: snapshot.epoch.0,
                targets,
            })
        })
    }
    pub fn validate_account_sharing_channel(
        &self,
        channel: &OwnedAccountSharingChannel,
    ) -> Result<(), EngineError> {
        self.storage
            .with_read_snapshot(|_| self.sharing_channel_fresh(channel))
    }
    /// Trusted actor intake must retain the genuine MessageReceived source proof.
    /// A signed packet alone cannot substitute for protected MLS delivery.
    pub fn authenticate_received_account_sharing_control(
        &self,
        protected: &GroupId,
        source: &cgka_traits::source_leaf::SourceLeafProof,
        wire: &[u8],
    ) -> Result<ReceivedAccountSharingControl, EngineError> {
        self.storage.with_read_snapshot(|_| {
            let frame = self.sharing_verify(wire)?;
            if frame.protected != protected.as_slice()
                || frame.epoch != source.epoch.0
                || frame.authenticator != source.epoch_authenticator_digest
                || frame.signer != source.signature_public_key
                || !self
                    .validated_settled_device_roster(protected)?
                    .ok_or_else(refused)?
                    .candidate()
                    .leaves
                    .iter()
                    .any(|leaf| {
                        leaf.leaf_index == source.leaf_index
                            && leaf.signature_public_key == frame.signer
                    })
            {
                return Err(refused());
            }
            let control = match frame.phase.as_str() {
                "request" if frame.signer == frame.source => AccountSharingControl::Request,
                "consent" if frame.signer == frame.recipient => AccountSharingControl::Consent,
                "body" => AccountSharingControl::Body(frame.sequence),
                _ => return Err(refused()),
            };
            Ok(ReceivedAccountSharingControl {
                nonce: frame.nonce,
                control,
                signer: frame.signer,
                source: frame.source,
                recipient: frame.recipient,
                approval_id: frame.approval_id,
            })
        })
    }
    fn sharing_scope_fresh(&self, scope: &AccountSharingScope) -> Result<(), EngineError> {
        let current = self
            .validated_settled_device_roster(&scope.protected.group_id)?
            .ok_or_else(refused)?;
        if current.candidate() != &scope.protected
            || current.settlement_generation() != scope.local_generation
            || !scope
                .protected
                .leaves
                .iter()
                .any(|leaf| leaf.signature_public_key == self.identity.signer.public())
        {
            return Err(refused());
        }
        Ok(())
    }
    fn sharing_channel_fresh(
        &self,
        channel: &OwnedAccountSharingChannel,
    ) -> Result<(), EngineError> {
        channel.live()?;
        if !self.enrollment_endorsements.owns_lifetime(&channel.owner) {
            return Err(refused());
        }
        self.sharing_scope_fresh(&channel.scope)
    }
    fn sharing_frame(&self, scope: &AccountSharingScope, phase: &str) -> Frame {
        Frame {
            protocol: PROTOCOL.into(),
            phase: phase.into(),
            account: scope.protected.account.as_slice().to_vec(),
            protected: scope.protected.group_id.as_slice().to_vec(),
            epoch: scope.protected.epoch.0,
            authenticator: scope.protected.epoch_authenticator_digest,
            roster: scope.protected.roster_commitment,
            source: scope.source.clone(),
            recipient: scope.recipient.clone(),
            nonce: scope.nonce,
            approved_policy_identity: scope.approved_policy_identity,
            approval_id: scope.approval_id,
            signer: self.identity.signer.public().to_vec(),
            generation: scope.local_generation,
            binding: [0; 32],
            public_key: vec![],
            kind: None,
            sequence: 0,
            body_digest: [0; 32],
            kem: vec![],
            ciphertext: vec![],
            signature: vec![],
        }
    }
    fn sharing_sign(&self, mut frame: Frame) -> Result<Vec<u8>, EngineError> {
        frame.signature = self
            .identity
            .signer
            .sign(&encode(&frame)?)
            .map_err(|_| refused())?;
        encode(&frame)
    }
    fn sharing_fixed_context(
        frame: &Frame,
        scope: &AccountSharingScope,
    ) -> Result<(), EngineError> {
        if frame.account != scope.protected.account.as_slice()
            || frame.protected != scope.protected.group_id.as_slice()
            || frame.epoch != scope.protected.epoch.0
            || frame.authenticator != scope.protected.epoch_authenticator_digest
            || frame.roster != scope.protected.roster_commitment
            || frame.source != scope.source
            || frame.recipient != scope.recipient
            || frame.nonce != scope.nonce
            || frame.approved_policy_identity != scope.approved_policy_identity
            || frame.approval_id != scope.approval_id
        {
            return Err(refused());
        }
        Ok(())
    }
    fn sharing_verify(&self, wire: &[u8]) -> Result<Frame, EngineError> {
        let mut frame = decode(wire)?;
        if frame.protocol != PROTOCOL
            || frame.source.len() != 32
            || frame.recipient.len() != 32
            || frame.signer.len() != 32
            || frame.signature.len() != 64
            || frame.source == frame.recipient
            || frame.nonce == [0; 32]
            || frame.generation == 0
            || frame.approved_policy_identity == [0; 32]
            || frame.approval_id == [0; 32]
            || frame.protected.is_empty()
            || frame.protected.len() > 255
        {
            return Err(refused());
        }
        let current = self
            .validated_settled_device_roster(&GroupId::new(frame.protected.clone()))?
            .ok_or_else(refused)?;
        let scope = AccountSharingScope {
            protected: current.candidate().clone(),
            local_generation: current.settlement_generation(),
            source: frame.source.clone(),
            recipient: frame.recipient.clone(),
            nonce: frame.nonce,
            approved_policy_identity: frame.approved_policy_identity,
            approval_id: frame.approval_id,
        };
        if scope.approved_policy_identity != approved_policy_identity(&scope)? {
            return Err(refused());
        }
        Self::sharing_fixed_context(&frame, &scope)?;
        if ![&frame.source, &frame.recipient, &frame.signer]
            .iter()
            .all(|key| {
                scope
                    .protected
                    .leaves
                    .iter()
                    .any(|leaf| &leaf.signature_public_key == *key)
            })
        {
            return Err(refused());
        }
        let signature = std::mem::take(&mut frame.signature);
        self.crypto
            .verify_signature(
                SignatureScheme::ED25519,
                &encode(&frame)?,
                &frame.signer,
                &signature,
            )
            .map_err(|_| refused())?;
        frame.signature = signature;
        Ok(frame)
    }
    fn sharing_keys(&self) -> Result<HpkeKeyPair, EngineError> {
        let mut ikm = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), ikm.as_mut());
        self.crypto
            .derive_hpke_keypair(config(), ikm.as_ref())
            .map_err(|_| refused())
    }
    pub fn begin_account_sharing_policy(
        &self,
        protected: &GroupId,
        recipient: &[u8],
        lease: Arc<dyn TrustedAccountSharingLease>,
    ) -> Result<OwnedAccountSharingChannel, EngineError> {
        self.storage.with_read_snapshot(|_| {
            let settled = self
                .validated_settled_device_roster(protected)?
                .ok_or_else(refused)?;
            if recipient == self.identity.signer.public()
                || !settled
                    .candidate()
                    .leaves
                    .iter()
                    .any(|leaf| leaf.signature_public_key == recipient)
            {
                return Err(refused());
            }
            let mut nonce = [0; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
            let mut scope = AccountSharingScope {
                protected: settled.candidate().clone(),
                local_generation: settled.settlement_generation(),
                source: self.identity.signer.public().to_vec(),
                recipient: recipient.to_vec(),
                nonce,
                approved_policy_identity: [0; 32],
                approval_id: [0; 32],
            };
            scope.approval_id = lease.approved_policy_id(&scope)?;
            scope.approved_policy_identity = approved_policy_identity(&scope)?;
            if scope.approval_id == [0; 32] {
                return Err(refused());
            }
            let deadline = lease.validate(&scope)?;
            let keys = self.sharing_keys()?;
            let mut frame = self.sharing_frame(&scope, "request");
            frame.public_key = keys.public.clone();
            let channel = OwnedAccountSharingChannel {
                owner: self.enrollment_endorsements.owner_lifetime(),
                scope,
                lease,
                deadline,
                keys: Some(keys),
                request: self.sharing_sign(frame)?,
                consent: None,
                peer_key: None,
                recipient_role: false,
                sealed: BTreeMap::new(),
                outbound: vec![],
            };
            self.sharing_channel_fresh(&channel)?;
            Ok(channel)
        })
    }
    pub fn authenticate_account_sharing_request(
        &self,
        wire: &[u8],
    ) -> Result<AuthenticatedAccountSharingRequest, EngineError> {
        self.storage.with_read_snapshot(|_| {
            let frame = self.sharing_verify(wire)?;
            if frame.phase != "request"
                || frame.signer != frame.source
                || frame.recipient != self.identity.signer.public()
                || frame.public_key.len() != 32
                || frame.binding != [0; 32]
                || frame.kind.is_some()
                || frame.sequence != 0
                || frame.body_digest != [0; 32]
                || !frame.kem.is_empty()
                || !frame.ciphertext.is_empty()
            {
                return Err(refused());
            }
            let settled = self
                .validated_settled_device_roster(&GroupId::new(frame.protected.clone()))?
                .ok_or_else(refused)?;
            let scope = AccountSharingScope {
                protected: settled.candidate().clone(),
                local_generation: settled.settlement_generation(),
                source: frame.source.clone(),
                recipient: frame.recipient.clone(),
                nonce: frame.nonce,
                approved_policy_identity: frame.approved_policy_identity,
                approval_id: frame.approval_id,
            };
            Ok(AuthenticatedAccountSharingRequest {
                frame,
                wire: wire.to_vec(),
                scope,
            })
        })
    }
    pub fn approve_account_sharing_policy(
        &self,
        request: &AuthenticatedAccountSharingRequest,
        lease: Arc<dyn TrustedAccountSharingLease>,
    ) -> Result<OwnedAccountSharingChannel, EngineError> {
        self.storage.with_read_snapshot(|_| {
            let fresh = self.authenticate_account_sharing_request(&request.wire)?;
            if fresh.scope != request.scope {
                return Err(refused());
            }
            let deadline = lease.validate(&fresh.scope)?;
            let keys = self.sharing_keys()?;
            let mut frame = self.sharing_frame(&fresh.scope, "consent");
            frame.binding = request.request_digest();
            frame.public_key = keys.public.clone();
            let channel = OwnedAccountSharingChannel {
                owner: self.enrollment_endorsements.owner_lifetime(),
                scope: fresh.scope,
                lease,
                deadline,
                keys: Some(keys),
                request: request.wire.clone(),
                consent: Some(self.sharing_sign(frame)?),
                peer_key: Some(request.frame.public_key.clone()),
                recipient_role: true,
                sealed: BTreeMap::new(),
                outbound: vec![],
            };
            self.sharing_channel_fresh(&channel)?;
            Ok(channel)
        })
    }
    pub fn bind_account_sharing_consent(
        &self,
        channel: &mut OwnedAccountSharingChannel,
        wire: &[u8],
    ) -> Result<(), EngineError> {
        self.sharing_channel_fresh(channel)?;
        if channel.recipient_role {
            return Err(refused());
        }
        let frame = self.sharing_verify(wire)?;
        Self::sharing_fixed_context(&frame, &channel.scope)?;
        if frame.phase != "consent"
            || frame.signer != channel.scope.recipient
            || frame.binding != Sha256::digest(&channel.request).as_slice()
            || frame.public_key.len() != 32
            || frame.kind.is_some()
            || frame.sequence != 0
            || frame.body_digest != [0; 32]
            || !frame.kem.is_empty()
            || !frame.ciphertext.is_empty()
        {
            return Err(refused());
        }
        if let Some(consent) = &channel.consent {
            if consent != wire {
                return Err(refused());
            }
            return Ok(());
        }
        channel.peer_key = Some(frame.public_key);
        channel.consent = Some(wire.to_vec());
        Ok(())
    }
    pub fn seal_account_shared_body(
        &self,
        channel: &mut OwnedAccountSharingChannel,
        kind: AccountSharedBodyKind,
        sequence: u64,
        body: &[u8],
    ) -> Result<Vec<u8>, EngineError> {
        self.sharing_channel_fresh(channel)?;
        if body.is_empty() || body.len() > MAX_ACCOUNT_SHARED_BODY_BYTES {
            return Err(refused());
        }
        let digest: [u8; 32] = Sha256::digest(body).into();
        if let Some((old_kind, old_digest, wire)) = channel.sealed.get(&sequence) {
            if *old_kind != kind || *old_digest != digest {
                return Err(refused());
            }
            return Ok(wire.clone());
        }
        if channel.sealed.len() >= MAX_ORIGINAL_BODIES {
            return Err(refused());
        }
        let binding = channel.policy_digest()?;
        let ciphertext = self
            .crypto
            .hpke_seal(
                config(),
                channel.peer_key.as_ref().ok_or_else(refused)?,
                HPKE_INFO,
                &binding,
                body,
            )
            .map_err(|_| refused())?;
        let mut frame = self.sharing_frame(&channel.scope, "body");
        frame.binding = binding;
        frame.kind = Some(kind);
        frame.sequence = sequence;
        frame.body_digest = digest;
        frame.kem = ciphertext.kem_output.as_slice().to_vec();
        frame.ciphertext = ciphertext.ciphertext.as_slice().to_vec();
        let wire = self.sharing_sign(frame)?;
        self.sharing_channel_fresh(channel)?;
        channel
            .sealed
            .insert(sequence, (kind, digest, wire.clone()));
        Ok(wire)
    }
    pub fn open_account_shared_body(
        &self,
        channel: &OwnedAccountSharingChannel,
        wire: &[u8],
    ) -> Result<(AccountSharedBodyKind, u64, Vec<u8>), EngineError> {
        self.sharing_channel_fresh(channel)?;
        let frame = self.sharing_verify(wire)?;
        Self::sharing_fixed_context(&frame, &channel.scope)?;
        let original = decode(if channel.recipient_role {
            &channel.request
        } else {
            channel.consent.as_ref().ok_or_else(refused)?
        })?;
        if frame.phase != "body"
            || frame.signer != original.signer
            || frame.generation != original.generation
            || frame.binding != channel.policy_digest()?
            || !frame.public_key.is_empty()
            || frame.kem.len() != 32
            || frame.ciphertext.len() > MAX_ACCOUNT_SHARED_BODY_BYTES + 16
        {
            return Err(refused());
        }
        let kind = frame.kind.ok_or_else(refused)?;
        let ciphertext = HpkeCiphertext {
            kem_output: frame.kem.into(),
            ciphertext: frame.ciphertext.into(),
        };
        let body = self
            .crypto
            .hpke_open(
                config(),
                &ciphertext,
                &channel.keys.as_ref().ok_or_else(refused)?.private,
                HPKE_INFO,
                &frame.binding,
            )
            .map_err(|_| refused())?;
        if Sha256::digest(&body).as_slice() != frame.body_digest {
            return Err(refused());
        }
        self.sharing_channel_fresh(channel)?;
        Ok((kind, frame.sequence, body))
    }
}
