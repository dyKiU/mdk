//! Original history channels. Signed observations and HPKE keys are not consent.
use crate::{
    Engine, device_group_snapshot::CandidateDeviceGroupSnapshot,
    private_roster_settlement::ValidatedSettledDeviceRoster,
};
use cgka_traits::{
    EngineError, GroupId, GroupLifecycleState, group::ProtocolProfile, storage::StorageProvider,
};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    signatures::Signer,
    types::{Ciphersuite, HpkeCiphertext, HpkeKeyPair, SignatureScheme},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Weak};
use web_time::Instant;
use zeroize::Zeroizing;

mod chunks;
mod transport;
pub use chunks::{MAX_HISTORY_CHUNK_BYTES, MAX_HISTORY_CHUNKS, OpenedHistoryChunk};

pub const HISTORY_CONTROL_KIND: u64 = 38177;
pub const MAX_HISTORY_CONTROL_BYTES: usize = 16384;
const PROTOCOL: &str = "whitenoise.experimental.opt-in-history.v1";
const HPKE_INFO: &[u8] = b"whitenoise-recipient-only-history-v1";
fn refused() -> EngineError {
    EngineError::Other("original history channel unavailable".into())
}
fn config() -> openmls_traits::types::HpkeConfig {
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.hpke_config()
}

/// Selects only a frame already owned by this original channel.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HistoryControl {
    Request,
    Consent,
    Archive,
    Acknowledgement,
    Chunk(u32),
    Receipt(u32),
}

/// Exporter snapshot facts, not a consent grant. The trusted actor constructs
/// these from an immutable actual logical export after Core derives transfer IDs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySnapshotDescriptor {
    pub archive_digest: [u8; 32],
    pub timestamp_ceiling: u64,
    pub encoded_bytes: u32,
    pub fragment_count: u32,
    pub record_count: u32,
}
impl HistorySnapshotDescriptor {
    fn validate(&self) -> Result<(), EngineError> {
        if self.archive_digest == [0; 32]
            || self.timestamp_ceiling == 0
            || self.encoded_bytes == 0
            || self.encoded_bytes > 128 * 1536
            || self.fragment_count != self.encoded_bytes.div_ceil(1536)
            || self.record_count == 0
            || self.record_count > 200
        {
            return Err(refused());
        }
        Ok(())
    }
}
type HistorySnapshotBuilder<'a> =
    dyn Fn(&HistoryScope) -> Result<HistorySnapshotDescriptor, EngineError> + 'a;

/// Authenticated delivery metadata; never a continuation or consent grant.
pub struct ReceivedHistoryControl {
    pub transfer: [u8; 32],
    pub control: HistoryControl,
    pub signer: Vec<u8>,
}
/// Read-only captured scope; cannot construct a channel or recipient consent.
#[derive(Clone, PartialEq, Eq)]
pub struct HistoryScope {
    pub protected: CandidateDeviceGroupSnapshot,
    pub local_generation: u64,
    pub ordinary_group: GroupId,
    pub ordinary_epoch: u64,
    pub ordinary_authenticator: [u8; 32],
    pub source: Vec<u8>,
    pub recipient: Vec<u8>,
    pub transfer: [u8; 32],
    pub snapshot: Option<HistorySnapshotDescriptor>,
}
/// Installed trusted actor continuation. Implementations must not restore it from rows.
pub trait TrustedHistoryLease: Send + Sync {
    fn validate(&self, _scope: &HistoryScope) -> Result<Instant, EngineError> {
        Err(refused())
    }
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Frame {
    protocol: String,
    phase: String,
    account: Vec<u8>,
    protected: Vec<u8>,
    protected_epoch: u64,
    protected_authenticator: [u8; 32],
    roster: [u8; 32],
    ordinary: Vec<u8>,
    ordinary_epoch: u64,
    ordinary_authenticator: [u8; 32],
    transfer: [u8; 32],
    snapshot: Option<HistorySnapshotDescriptor>,
    source: Vec<u8>,
    recipient: Vec<u8>,
    signer: Vec<u8>,
    source_generation: u64,
    binding: [u8; 32],
    manifest: [u8; 32],
    ordinal: u32,
    public_key: Vec<u8>,
    kem: Vec<u8>,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, EngineError> {
    let wire = serde_json::to_vec(value).map_err(|_| refused())?;
    if wire.is_empty() || wire.len() > MAX_HISTORY_CONTROL_BYTES {
        return Err(refused());
    }
    Ok(wire)
}
fn decode(wire: &[u8]) -> Result<Frame, EngineError> {
    if wire.is_empty() || wire.len() > MAX_HISTORY_CONTROL_BYTES {
        return Err(refused());
    }
    let frame: Frame = serde_json::from_slice(wire).map_err(|_| refused())?;
    if encode(&frame)? != wire {
        return Err(refused());
    }
    Ok(frame)
}
/// No constructor, Clone or serialization; authentication metadata, not an owner.
pub struct AuthenticatedHistoryRequest {
    frame: Frame,
    wire: Vec<u8>,
    scope: HistoryScope,
}
impl AuthenticatedHistoryRequest {
    pub fn scope(&self) -> &HistoryScope {
        &self.scope
    }
    pub fn binding(&self) -> [u8; 32] {
        Sha256::digest(&self.wire).into()
    }
}
/// Core-private recipient-only secret tied to one original actor and Engine lifetime.
pub struct OwnedHistoryChannel {
    owner: Weak<crate::private_enrollment_endorsement::Lifetime>,
    scope: HistoryScope,
    lease: Arc<dyn TrustedHistoryLease>,
    deadline: Instant,
    // Pinned HpkePrivateKey wraps tls_codec::SecretVLBytes (ZeroizeOnDrop).
    keys: Option<HpkeKeyPair>,
    request: Vec<u8>,
    consent: Option<Vec<u8>>,
    peer_key: Option<Vec<u8>>,
    recipient_role: bool,
    sealed: Option<([u8; 32], Vec<u8>)>,
    outbound: Vec<transport::FrozenHistoryControl>,
    chunk_manifest: Option<[u8; 32]>,
    sealed_chunks: Vec<chunks::SealedChunk>,
    opened_chunks: Vec<[u8; 32]>,
}
impl OwnedHistoryChannel {
    pub fn scope(&self) -> &HistoryScope {
        &self.scope
    }
    pub fn original_deadline(&self) -> Instant {
        self.deadline
    }
    pub fn request_packet(&self) -> Result<Vec<u8>, EngineError> {
        self.live()?;
        Ok(self.request.clone())
    }
    pub fn consent_packet(&self) -> Result<Vec<u8>, EngineError> {
        self.live()?;
        self.consent.clone().ok_or_else(refused)
    }
    /// Retire the original channel; dropping SecretVLBytes zeroizes its HPKE key.
    pub fn retire(&mut self) {
        self.keys = None;
        self.peer_key = None;
        self.sealed = None;
        self.outbound.clear();
        self.chunk_manifest = None;
        self.sealed_chunks.clear();
        self.opened_chunks.clear();
    }
    fn live(&self) -> Result<(), EngineError> {
        if self.keys.is_none()
            || !self.owner.upgrade().is_some_and(|o| o.is_open())
            || Instant::now() >= self.deadline
            || self.lease.validate(&self.scope)? != self.deadline
        {
            return Err(refused());
        }
        Ok(())
    }
    fn transcript(&self) -> Result<[u8; 32], EngineError> {
        let consent = self.consent.as_ref().ok_or_else(refused)?;
        let mut h = Sha256::new();
        h.update(b"WN-history-original-transcript-v1");
        h.update(Sha256::digest(&self.request));
        h.update(Sha256::digest(consent));
        Ok(h.finalize().into())
    }
}
/// Bounded current linked-recipient observation; no consent, lease or channel.
#[derive(Clone, PartialEq, Eq)]
pub struct HistoryRecipient {
    pub leaf_index: u32,
    pub device: Vec<u8>,
}
impl<S: StorageProvider> Engine<S> {
    /// Read eligible actual linked devices for an ordinary chat. Observation only.
    pub fn history_recipients(
        &self,
        ordinary: &GroupId,
        protected: &GroupId,
    ) -> Result<Vec<HistoryRecipient>, EngineError> {
        self.storage.with_read_snapshot(|_| {
            let (actual, _, _) = self.history_selection(ordinary, protected)?;
            let mut recipients: Vec<_> = actual
                .candidate()
                .leaves
                .iter()
                .filter(|leaf| leaf.signature_public_key != self.identity.signer.public())
                .map(|leaf| HistoryRecipient {
                    leaf_index: leaf.leaf_index,
                    device: leaf.signature_public_key.clone(),
                })
                .collect();
            recipients.sort_unstable_by_key(|recipient| recipient.leaf_index);
            Ok(recipients)
        })
    }

    // Shared fresh eligibility checks for observation and actual transfer creation.
    // Call only inside the caller's storage read snapshot.
    fn history_selection(
        &self,
        ordinary: &GroupId,
        protected: &GroupId,
    ) -> Result<(ValidatedSettledDeviceRoster, u64, [u8; 32]), EngineError> {
        if ordinary == protected {
            return Err(refused());
        }
        let actual = self
            .validated_settled_device_roster(protected)?
            .ok_or_else(refused)?;
        let ordinary_epoch = self.history_ordinary_epoch(ordinary)?;
        let ordinary_authenticator = self.history_ordinary_authenticator(ordinary)?;
        Ok((actual, ordinary_epoch, ordinary_authenticator))
    }

    fn history_ordinary_epoch(&self, group: &GroupId) -> Result<u64, EngineError> {
        self.ensure_group_live(group)?;
        let record = self.group_record(group)?;
        let authority = self.group_authority(group)?;
        let membership = self.canonical_group_membership(group)?;
        if record.protocol_profile != ProtocolProfile::Current
            || authority.lifecycle != GroupLifecycleState::Stable
            || authority.disbanding
            || !membership.local_leaf_active
            || record.removed
            || record.unrecoverable
            || record.disbanded.is_some()
            || self.with_mls_group(group, crate::device_group_genesis::has_private_component)?
        {
            return Err(refused());
        }
        Ok(record.epoch.0)
    }
    fn history_ordinary_authenticator(&self, group: &GroupId) -> Result<[u8; 32], EngineError> {
        self.ensure_group_live(group)?;
        self.with_mls_group(group, |actual| {
            Ok::<_, EngineError>(Sha256::digest(actual.epoch_authenticator().as_slice()).into())
        })
    }
    fn history_scope_fresh(&self, scope: &HistoryScope) -> Result<(), EngineError> {
        let current = self
            .validated_settled_device_roster(&scope.protected.group_id)?
            .ok_or_else(refused)?;
        if current.candidate() != &scope.protected
            || current.settlement_generation() != scope.local_generation
            || self.history_ordinary_epoch(&scope.ordinary_group)? != scope.ordinary_epoch
            || self.history_ordinary_authenticator(&scope.ordinary_group)?
                != scope.ordinary_authenticator
        {
            return Err(refused());
        }
        Ok(())
    }
    fn history_channel_fresh(&self, channel: &OwnedHistoryChannel) -> Result<(), EngineError> {
        channel.live()?;
        if !self.enrollment_endorsements.owns_lifetime(&channel.owner) {
            return Err(refused());
        }
        self.history_scope_fresh(&channel.scope)
    }
    fn history_sign(&self, mut frame: Frame) -> Result<Vec<u8>, EngineError> {
        frame.signature = self
            .identity
            .signer
            .sign(&encode(&frame)?)
            .map_err(|_| refused())?;
        encode(&frame)
    }
    fn history_frame(&self, scope: &HistoryScope, phase: &str) -> Frame {
        Frame {
            protocol: PROTOCOL.into(),
            phase: phase.into(),
            account: scope.protected.account.as_slice().to_vec(),
            protected: scope.protected.group_id.as_slice().to_vec(),
            protected_epoch: scope.protected.epoch.0,
            protected_authenticator: scope.protected.epoch_authenticator_digest,
            roster: scope.protected.roster_commitment,
            ordinary: scope.ordinary_group.as_slice().to_vec(),
            ordinary_epoch: scope.ordinary_epoch,
            ordinary_authenticator: scope.ordinary_authenticator,
            transfer: scope.transfer,
            snapshot: scope.snapshot.clone(),
            source: scope.source.clone(),
            recipient: scope.recipient.clone(),
            signer: self.identity.signer.public().to_vec(),
            source_generation: scope.local_generation,
            binding: [0; 32],
            manifest: [0; 32],
            ordinal: 0,
            public_key: vec![],
            kem: vec![],
            ciphertext: vec![],
            signature: vec![],
        }
    }
    fn history_fixed_context(frame: &Frame, scope: &HistoryScope) -> Result<(), EngineError> {
        if frame.snapshot != scope.snapshot
            || frame.account != scope.protected.account.as_slice()
            || frame.protected != scope.protected.group_id.as_slice()
            || frame.protected_epoch != scope.protected.epoch.0
            || frame.protected_authenticator != scope.protected.epoch_authenticator_digest
            || frame.roster != scope.protected.roster_commitment
            || frame.ordinary != scope.ordinary_group.as_slice()
            || frame.ordinary_epoch != scope.ordinary_epoch
            || frame.ordinary_authenticator != scope.ordinary_authenticator
            || frame.source != scope.source
            || frame.recipient != scope.recipient
            || frame.transfer != scope.transfer
        {
            return Err(refused());
        }
        Ok(())
    }
    fn history_keys(&self) -> Result<HpkeKeyPair, EngineError> {
        let mut ikm = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(ikm.as_mut());
        self.crypto
            .derive_hpke_keypair(config(), ikm.as_ref())
            .map_err(|_| refused())
    }
    /// Fresh actual group reads plus an original trusted actor, never a consent DTO.
    pub fn begin_history_channel(
        &self,
        ordinary: &GroupId,
        protected: &GroupId,
        recipient: &[u8],
        lease: Arc<dyn TrustedHistoryLease>,
    ) -> Result<OwnedHistoryChannel, EngineError> {
        self.begin_history_channel_selected(ordinary, protected, recipient, lease, None)
    }
    /// Snapshot builder is a trusted actor closure over freshly Core-derived
    /// identities/scope; the host supplies neither scope nor signed packet.
    pub fn begin_history_snapshot_channel(
        &self,
        ordinary: &GroupId,
        protected: &GroupId,
        recipient: &[u8],
        lease: Arc<dyn TrustedHistoryLease>,
        build: &dyn Fn(&HistoryScope) -> Result<HistorySnapshotDescriptor, EngineError>,
    ) -> Result<OwnedHistoryChannel, EngineError> {
        self.begin_history_channel_selected(ordinary, protected, recipient, lease, Some(build))
    }
    fn begin_history_channel_selected(
        &self,
        ordinary: &GroupId,
        protected: &GroupId,
        recipient: &[u8],
        lease: Arc<dyn TrustedHistoryLease>,
        build: Option<&HistorySnapshotBuilder<'_>>,
    ) -> Result<OwnedHistoryChannel, EngineError> {
        self.storage.with_read_snapshot(|_| {
            if recipient.len() != 32 || recipient == self.identity.signer.public() {
                return Err(refused());
            }
            let (actual, ordinary_epoch, ordinary_authenticator) =
                self.history_selection(ordinary, protected)?;
            if !actual
                .candidate()
                .leaves
                .iter()
                .any(|l| l.signature_public_key == recipient)
            {
                return Err(refused());
            }
            let mut transfer = [0; 32];
            rand::thread_rng().fill_bytes(&mut transfer);
            let mut scope = HistoryScope {
                protected: actual.candidate().clone(),
                local_generation: actual.settlement_generation(),
                ordinary_group: ordinary.clone(),
                ordinary_epoch,
                ordinary_authenticator,
                source: self.identity.signer.public().to_vec(),
                recipient: recipient.to_vec(),
                transfer,
                snapshot: None,
            };
            if let Some(build) = build {
                let snapshot = build(&scope)?;
                snapshot.validate()?;
                scope.snapshot = Some(snapshot);
            }
            let deadline = lease.validate(&scope)?;
            if Instant::now() >= deadline {
                return Err(refused());
            }
            let keys = self.history_keys()?;
            let mut frame = self.history_frame(&scope, "request");
            frame.public_key = keys.public.clone();
            let request = self.history_sign(frame)?;
            let channel = OwnedHistoryChannel {
                owner: self.enrollment_endorsements.owner_lifetime(),
                scope,
                lease,
                deadline,
                keys: Some(keys),
                request,
                consent: None,
                peer_key: None,
                recipient_role: false,
                sealed: None,
                outbound: Vec::new(),
                chunk_manifest: None,
                sealed_chunks: Vec::new(),
                opened_chunks: Vec::new(),
            };
            self.history_channel_fresh(&channel)?;
            Ok(channel)
        })
    }
    fn history_verify(&self, mut frame: Frame) -> Result<Frame, EngineError> {
        if let Some(snapshot) = &frame.snapshot {
            snapshot.validate()?;
        }
        if frame.protocol != PROTOCOL
            || frame.transfer == [0; 32]
            || frame.source_generation == 0
            || frame.source.len() != 32
            || frame.recipient.len() != 32
            || frame.signer.len() != 32
            || frame.signature.len() != 64
            || frame.source == frame.recipient
            || frame.ordinary.is_empty()
            || frame.ordinary.len() > 255
            || frame.protected.is_empty()
            || frame.protected.len() > 255
        {
            return Err(refused());
        }
        let protected = GroupId::new(frame.protected.clone());
        let actual = self
            .validated_settled_device_roster(&protected)?
            .ok_or_else(refused)?;
        let current = actual.candidate();
        if current.account.as_slice() != frame.account
            || current.epoch.0 != frame.protected_epoch
            || current.epoch_authenticator_digest != frame.protected_authenticator
            || current.roster_commitment != frame.roster
            || !current
                .leaves
                .iter()
                .any(|l| l.signature_public_key == frame.signer)
            || !current
                .leaves
                .iter()
                .any(|l| l.signature_public_key == frame.source)
            || !current
                .leaves
                .iter()
                .any(|l| l.signature_public_key == frame.recipient)
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
    /// Called only with the real MessageReceived source proof by the trusted
    /// actor. The leaf-signed frame still independently verifies against the
    /// full actual settled tree; observation alone cannot create an owner.
    pub fn authenticate_received_history_control(
        &self,
        protected: &GroupId,
        source: &cgka_traits::source_leaf::SourceLeafProof,
        wire: &[u8],
    ) -> Result<ReceivedHistoryControl, EngineError> {
        let frame = self.history_verify(decode(wire)?)?;
        if frame.protected != protected.as_slice()
            || frame.protected_epoch != source.epoch.0
            || frame.protected_authenticator != source.epoch_authenticator_digest
            || frame.signer != source.signature_public_key
        {
            return Err(refused());
        }
        let actual = self
            .validated_settled_device_roster(protected)?
            .ok_or_else(refused)?;
        if !actual.candidate().leaves.iter().any(|leaf| {
            leaf.leaf_index == source.leaf_index && leaf.signature_public_key == frame.signer
        }) {
            return Err(refused());
        }
        let control = match frame.phase.as_str() {
            "request" => HistoryControl::Request,
            "consent" => HistoryControl::Consent,
            "archive" => HistoryControl::Archive,
            "ack" => HistoryControl::Acknowledgement,
            "chunk" => HistoryControl::Chunk(frame.ordinal),
            "receipt" => HistoryControl::Receipt(frame.ordinal),
            _ => return Err(refused()),
        };
        Ok(ReceivedHistoryControl {
            transfer: frame.transfer,
            control,
            signer: frame.signer,
        })
    }
    pub fn authenticate_history_request(
        &self,
        wire: &[u8],
    ) -> Result<AuthenticatedHistoryRequest, EngineError> {
        self.storage.with_read_snapshot(|_| {
            let frame = self.history_verify(decode(wire)?)?;
            if frame.manifest != [0; 32]
                || frame.ordinal != 0
                || frame.phase != "request"
                || frame.signer != frame.source
                || frame.recipient != self.identity.signer.public()
                || frame.public_key.len() != 32
                || frame.binding != [0; 32]
                || !frame.kem.is_empty()
                || !frame.ciphertext.is_empty()
            {
                return Err(refused());
            }
            let ordinary = GroupId::new(frame.ordinary.clone());
            if self.history_ordinary_epoch(&ordinary)? != frame.ordinary_epoch
                || self.history_ordinary_authenticator(&ordinary)? != frame.ordinary_authenticator
            {
                return Err(refused());
            }
            let protected = GroupId::new(frame.protected.clone());
            let actual = self
                .validated_settled_device_roster(&protected)?
                .ok_or_else(refused)?;
            let scope = HistoryScope {
                protected: actual.candidate().clone(),
                local_generation: actual.settlement_generation(),
                ordinary_group: ordinary,
                ordinary_epoch: frame.ordinary_epoch,
                ordinary_authenticator: frame.ordinary_authenticator,
                source: frame.source.clone(),
                recipient: frame.recipient.clone(),
                transfer: frame.transfer,
                snapshot: frame.snapshot.clone(),
            };
            Ok(AuthenticatedHistoryRequest {
                frame,
                wire: wire.to_vec(),
                scope,
            })
        })
    }
    pub fn approve_history_channel(
        &self,
        request: &AuthenticatedHistoryRequest,
        lease: Arc<dyn TrustedHistoryLease>,
    ) -> Result<OwnedHistoryChannel, EngineError> {
        self.storage.with_read_snapshot(|_| {
            self.history_scope_fresh(&request.scope)?;
            let fresh = self.authenticate_history_request(&request.wire)?;
            if fresh.scope != request.scope {
                return Err(refused());
            }
            let deadline = lease.validate(&request.scope)?;
            if Instant::now() >= deadline {
                return Err(refused());
            }
            let keys = self.history_keys()?;
            let mut frame = self.history_frame(&request.scope, "consent");
            frame.binding = request.binding();
            frame.public_key = keys.public.clone();
            let consent = self.history_sign(frame)?;
            let channel = OwnedHistoryChannel {
                owner: self.enrollment_endorsements.owner_lifetime(),
                scope: request.scope.clone(),
                lease,
                deadline,
                keys: Some(keys),
                request: request.wire.clone(),
                consent: Some(consent),
                peer_key: Some(request.frame.public_key.clone()),
                recipient_role: true,
                sealed: None,
                outbound: Vec::new(),
                chunk_manifest: None,
                sealed_chunks: Vec::new(),
                opened_chunks: Vec::new(),
            };
            self.history_channel_fresh(&channel)?;
            Ok(channel)
        })
    }
    pub fn bind_history_consent(
        &self,
        channel: &mut OwnedHistoryChannel,
        wire: &[u8],
    ) -> Result<(), EngineError> {
        self.history_channel_fresh(channel)?;
        if channel.recipient_role {
            return Err(refused());
        }
        let frame = self.history_verify(decode(wire)?)?;
        Self::history_fixed_context(&frame, &channel.scope)?;
        let request: Frame = decode(&channel.request)?;
        if frame.manifest != [0; 32]
            || frame.ordinal != 0
            || frame.phase != "consent"
            || frame.signer != channel.scope.recipient
            || frame.source != channel.scope.source
            || frame.recipient != channel.scope.recipient
            || frame.transfer != channel.scope.transfer
            || frame.ordinary != request.ordinary
            || frame.ordinary_epoch != request.ordinary_epoch
            || frame.ordinary_authenticator != request.ordinary_authenticator
            || frame.binding != Sha256::digest(&channel.request).as_slice()
            || frame.public_key.len() != 32
            || !frame.kem.is_empty()
            || !frame.ciphertext.is_empty()
        {
            return Err(refused());
        }
        if channel.consent.as_ref().is_some_and(|old| old != wire) {
            return Err(refused());
        }
        self.history_channel_fresh(channel)?;
        channel.peer_key = Some(frame.public_key);
        channel.consent = Some(wire.to_vec());
        Ok(())
    }
    pub fn validate_history_channel(
        &self,
        channel: &OwnedHistoryChannel,
    ) -> Result<(), EngineError> {
        self.history_channel_fresh(channel)
    }
    /// Caller is the trusted original actor; only archive/receipt roles are signed.
    pub fn seal_history_body(
        &self,
        channel: &mut OwnedHistoryChannel,
        body: &[u8],
        acknowledgement: bool,
    ) -> Result<Vec<u8>, EngineError> {
        self.history_channel_fresh(channel)?;
        if acknowledgement != channel.recipient_role
            || body.len() > 4096
            || channel.chunk_manifest.is_some()
        {
            return Err(refused());
        }
        let body_digest: [u8; 32] = Sha256::digest(body).into();
        if let Some((digest, wire)) = &channel.sealed {
            if digest != &body_digest {
                return Err(refused());
            }
            self.history_channel_fresh(channel)?;
            return Ok(wire.clone());
        }
        let binding = channel.transcript()?;
        let peer = channel.peer_key.as_ref().ok_or_else(refused)?;
        let ciphertext = self
            .crypto
            .hpke_seal(config(), peer, HPKE_INFO, &binding, body)
            .map_err(|_| refused())?;
        let mut frame = self.history_frame(
            &channel.scope,
            if acknowledgement { "ack" } else { "archive" },
        );
        frame.binding = binding;
        frame.kem = ciphertext.kem_output.as_slice().to_vec();
        frame.ciphertext = ciphertext.ciphertext.as_slice().to_vec();
        let wire = self.history_sign(frame)?;
        self.history_channel_fresh(channel)?;
        channel.sealed = Some((body_digest, wire.clone()));
        Ok(wire)
    }
    pub fn open_history_body(
        &self,
        channel: &OwnedHistoryChannel,
        wire: &[u8],
    ) -> Result<Vec<u8>, EngineError> {
        self.history_channel_fresh(channel)?;
        let frame = self.history_verify(decode(wire)?)?;
        Self::history_fixed_context(&frame, &channel.scope)?;
        let original = decode(if channel.recipient_role {
            &channel.request
        } else {
            channel.consent.as_ref().ok_or_else(refused)?
        })?;
        if frame.source_generation != original.source_generation {
            return Err(refused());
        }
        let expected = if channel.recipient_role {
            "archive"
        } else {
            "ack"
        };
        let signer = if channel.recipient_role {
            &channel.scope.source
        } else {
            &channel.scope.recipient
        };
        if frame.manifest != [0; 32]
            || frame.ordinal != 0
            || frame.phase != expected
            || &frame.signer != signer
            || frame.transfer != channel.scope.transfer
            || frame.source != channel.scope.source
            || frame.recipient != channel.scope.recipient
            || frame.ordinary != channel.scope.ordinary_group.as_slice()
            || frame.ordinary_epoch != channel.scope.ordinary_epoch
            || frame.ordinary_authenticator != channel.scope.ordinary_authenticator
            || frame.binding != channel.transcript()?
            || !frame.public_key.is_empty()
            || frame.kem.len() != 32
            || frame.ciphertext.len() > 4112
        {
            return Err(refused());
        }
        let ciphertext = HpkeCiphertext {
            kem_output: frame.kem.into(),
            ciphertext: frame.ciphertext.into(),
        };
        let result = self
            .crypto
            .hpke_open(
                config(),
                &ciphertext,
                &channel.keys.as_ref().ok_or_else(refused)?.private,
                HPKE_INFO,
                &frame.binding,
            )
            .map_err(|_| refused())?;
        self.history_channel_fresh(channel)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
