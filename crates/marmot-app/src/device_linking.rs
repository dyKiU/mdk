//! Private experimental linking adapter; not adopted Marmot framing or enrollment.
//! Stock Matrix SAS verifies the per-attempt contextual SDK keys. MLS membership,
//! exact Welcome validation and settled device-roster authorization are separate.
use matrix_sdk_crypto::types::requests::{
    AnyOutgoingRequest, OutgoingVerificationRequest, ToDeviceRequest,
};
use matrix_sdk_crypto::{
    DecryptionSettings, EncryptionSyncChanges, OlmMachine, Sas, TrustRequirement,
};
use ruma::api::client::{
    keys::get_keys::v3::Response as KeysResponse, sync::sync_events::DeviceLists,
    to_device::send_event_to_device::v3::Response as SentResponse,
};
use ruma::events::{AnyToDeviceEvent, key::verification::VerificationMethod};
use ruma::serde::Raw;
use ruma::{OwnedDeviceId, OwnedUserId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use tracing::instrument::WithSubscriber;

const ATTEMPT_LIFETIME: Duration = Duration::from_secs(600);
const MAX_FRAME_BYTES: usize = 32768;
const MAX_PENDING_FRAMES: usize = 64;
pub(crate) mod diagnostics;
pub(crate) mod network;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkError {
    InvalidContext,
    BindingMismatch,
    InvalidFrame,
    StaleFlow,
    SimultaneousRequest,
    Expired,
    Cancelled,
    Closed,
    LimitExceeded,
    NotReady,
    AlreadyConsumed,
    Sdk,
}
type Result<T> = std::result::Result<T, LinkError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    NewDevice,
    Approver,
}
impl Role {
    fn label(self) -> &'static str {
        match self {
            Self::NewDevice => "new",
            Self::Approver => "approver",
        }
    }
    fn peer(self) -> Self {
        match self {
            Self::NewDevice => Self::Approver,
            Self::Approver => Self::NewDevice,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinkingContext {
    pub(crate) version: u32,
    pub(crate) nonce: [u8; 32],
    pub(crate) new_device_generation: u64,
    pub(crate) approver_generation: u64,
    pub(crate) account: [u8; 32],
    pub(crate) exact_key_package: Vec<u8>,
    pub(crate) key_package_reference: [u8; 32],
    pub(crate) device_group: Vec<u8>,
    pub(crate) predecessor: PredecessorRoster,
    pub(crate) approver: [u8; 32],
    pub(crate) recipient: [u8; 32],
}
impl LinkingContext {
    pub(crate) fn digest(&self) -> Result<[u8; 32]> {
        let domain: &[u8] = match (self.version, self.predecessor.artifact_digest) {
            (1, None) => b"whitenoise-private-link-context-v1\0",
            (2, Some(digest))
                if digest != [0; 32]
                    && self.predecessor.epoch > 0
                    && self.predecessor.leaves.len() >= 2 =>
            {
                b"whitenoise-private-link-context-v2\0"
            }
            _ => return Err(LinkError::InvalidContext),
        };
        if self.new_device_generation == 0
            || self.approver_generation == 0
            || self.new_device_generation > i64::MAX as u64
            || self.approver_generation > i64::MAX as u64
            || self.nonce == [0; 32]
            || self.approver == self.recipient
            || self.device_group.is_empty()
            || self.device_group.len() > 255
            || self.exact_key_package.is_empty()
            || self.exact_key_package.len() > 16384
        {
            return Err(LinkError::InvalidContext);
        }
        self.predecessor.validate(self.approver, self.recipient)?;
        let bytes = serde_json::to_vec(self).map_err(|_| LinkError::InvalidContext)?;
        let mut h = Sha256::new();
        h.update(domain);
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
        Ok(h.finalize().into())
    }
    pub(crate) fn local_generation(&self, role: Role) -> u64 {
        match role {
            Role::NewDevice => self.new_device_generation,
            Role::Approver => self.approver_generation,
        }
    }
    fn ids(&self, role: Role) -> Result<(OwnedUserId, OwnedDeviceId)> {
        let digest = hex::encode(self.digest()?);
        Ok((
            format!("@marmot_{digest}:invalid")
                .try_into()
                .map_err(|_| LinkError::InvalidContext)?,
            format!("{}_{digest}", role.label()).into(),
        ))
    }
}
// No Debug implementation on data-bearing records or SAS state.
pub(crate) struct PeerOffer {
    binding: [u8; 32],
    role: Role,
    keys_json: Vec<u8>,
}
#[derive(Clone)]
pub(crate) struct LinkFrame {
    binding: [u8; 32],
    token: String,
    event_json: Vec<u8>,
}
impl LinkFrame {
    pub(crate) fn acknowledgement_token(&self) -> &str {
        &self.token
    }
}
struct Attempt {
    context: LinkingContext,
    role: Role,
    machine: OlmMachine,
    own_keys: Value,
    flow: Option<String>,
    sas: Option<Sas>,
    local_confirmed: bool,
    consumed: bool,
    response_deadline: Option<Instant>,
    setup_deadline: Instant,
    outbox: VecDeque<LinkFrame>,
    seen: HashSet<[u8; 32]>,
    peer_admitted: bool,
}
// Private, non-clone, one-shot pairing evidence. No caller-set verified fields;
// this type has no conversions to chat/history authorization or MLS membership.
pub(crate) struct VerifiedPairing {
    context: LinkingContext,
    role: Role,
    // Only the durable account owner can stamp its original reservation bound.
    // Raw SDK evidence cannot arm a runtime Welcome policy.
    owner_deadline: Option<Instant>,
}
impl VerifiedPairing {
    /// Public exact metadata retained by the coordinator, never a permission.
    pub(crate) fn context(&self) -> &LinkingContext {
        &self.context
    }
    pub(crate) fn original_deadline(&self) -> Option<Instant> {
        self.owner_deadline
    }
    pub(crate) fn device_group(&self) -> &[u8] {
        &self.context.device_group
    }
}
pub(crate) struct DeviceLinker {
    attempt: Option<Attempt>,
    highest_generation: u64,
    closed: bool,
}
impl DeviceLinker {
    pub(crate) fn new() -> Self {
        Self {
            attempt: None,
            highest_generation: 0,
            closed: false,
        }
    }
    async fn quiet<T>(future: impl std::future::Future<Output = T>) -> T {
        future
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
    }
    fn quiet_sync<T>(f: impl FnOnce() -> T) -> T {
        tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), f)
    }
    fn live(&mut self, now: Instant) -> Result<&mut Attempt> {
        if self.closed {
            return Err(LinkError::Closed);
        }
        if self
            .attempt
            .as_ref()
            .is_some_and(|a| now >= a.response_deadline.unwrap_or(a.setup_deadline))
        {
            self.terminate();
            return Err(LinkError::Expired);
        }
        self.attempt.as_mut().ok_or(LinkError::Cancelled)
    }
    fn terminate(&mut self) {
        if let Some(a) = self.attempt.take() {
            self.highest_generation = self
                .highest_generation
                .max(a.context.local_generation(a.role));
        }
    }
    pub(crate) async fn begin(
        &mut self,
        context: LinkingContext,
        role: Role,
        reserved_generation: u64,
        now: Instant,
    ) -> Result<()> {
        context.digest()?;
        if reserved_generation != context.local_generation(role) {
            return Err(LinkError::BindingMismatch);
        }
        if self.closed {
            return Err(LinkError::Closed);
        }
        if self.attempt.is_some() {
            self.terminate();
            self.highest_generation = self.highest_generation.max(context.local_generation(role));
            return Err(LinkError::SimultaneousRequest);
        }
        if context.local_generation(role) <= self.highest_generation {
            return Err(LinkError::Cancelled);
        }
        // This generation must come from the durable owner reservation, never
        // from a remote frame. The current slice enforces it in process only.
        self.highest_generation = context.local_generation(role);
        let (user, device) = context.ids(role)?;
        let machine = Self::quiet(OlmMachine::new(&user, &device)).await;
        let (_, keys) = Self::quiet(machine.upload_device_keys())
            .await
            .map_err(|_| LinkError::Sdk)?
            .ok_or(LinkError::Sdk)?;
        let keys = keys.device_keys.ok_or(LinkError::Sdk)?;
        let own_keys = serde_json::from_str(keys.json().get()).map_err(|_| LinkError::Sdk)?;
        self.attempt = Some(Attempt {
            context,
            role,
            machine,
            own_keys,
            flow: None,
            sas: None,
            local_confirmed: false,
            consumed: false,
            response_deadline: None,
            setup_deadline: now + ATTEMPT_LIFETIME,
            outbox: VecDeque::new(),
            seen: HashSet::new(),
            peer_admitted: false,
        });
        Ok(())
    }
    pub(crate) fn offer(&mut self, now: Instant) -> Result<PeerOffer> {
        let a = self.live(now)?;
        Ok(PeerOffer {
            binding: a.context.digest()?,
            role: a.role,
            keys_json: serde_json::to_vec(&a.own_keys).map_err(|_| LinkError::Sdk)?,
        })
    }
    pub(crate) async fn admit_peer(&mut self, offer: &PeerOffer, now: Instant) -> Result<()> {
        let a = self.live(now)?;
        if offer.binding != a.context.digest()? || offer.role != a.role.peer() {
            return Err(LinkError::BindingMismatch);
        }
        if offer.keys_json.len() > MAX_FRAME_BYTES {
            return Err(LinkError::LimitExceeded);
        }
        let value: Value =
            serde_json::from_slice(&offer.keys_json).map_err(|_| LinkError::InvalidFrame)?;
        if serde_json::to_vec(&value).map_err(|_| LinkError::InvalidFrame)? != offer.keys_json {
            return Err(LinkError::InvalidFrame);
        }
        let (peer_user, peer_device) = a.context.ids(a.role.peer())?;
        if value["user_id"] != peer_user.as_str() || value["device_id"] != peer_device.as_str() {
            return Err(LinkError::BindingMismatch);
        }
        // SDK validates self signatures. These records remain untrusted until
        // local SAS confirmation and peer MAC/done verification.
        let mut response = KeysResponse::default();
        response.device_keys.insert(
            peer_user.clone(),
            BTreeMap::from([
                (
                    peer_device.clone(),
                    Raw::from_json_string(
                        serde_json::to_string(&value).map_err(|_| LinkError::InvalidFrame)?,
                    )
                    .map_err(|_| LinkError::InvalidFrame)?,
                ),
                (
                    a.machine.device_id().to_owned(),
                    Raw::from_json_string(
                        serde_json::to_string(&a.own_keys).map_err(|_| LinkError::Sdk)?,
                    )
                    .map_err(|_| LinkError::Sdk)?,
                ),
            ]),
        );
        let (id, _) = Self::quiet_sync(|| a.machine.query_keys_for_users([peer_user.as_ref()]));
        Self::quiet(a.machine.mark_request_as_sent(&id, &response))
            .await
            .map_err(|_| LinkError::Sdk)?;
        let peer = Self::quiet(a.machine.get_device(&peer_user, &peer_device, None))
            .await
            .map_err(|_| LinkError::Sdk)?
            .ok_or(LinkError::BindingMismatch)?;
        // Compare the actual accepted SDK record against the supplied signed
        // identity: SDK may retain an old key after rejecting a tampered update.
        let accepted = serde_json::to_value(peer.as_device_keys()).map_err(|_| LinkError::Sdk)?;
        if accepted != value {
            return Err(LinkError::BindingMismatch);
        }
        a.peer_admitted = true;
        Ok(())
    }
    fn enqueue(a: &mut Attempt, request: OutgoingVerificationRequest) -> Result<()> {
        let OutgoingVerificationRequest::ToDevice(body) = request else {
            return Err(LinkError::InvalidFrame);
        };
        Self::enqueue_body(a, &body)
    }
    fn enqueue_body(a: &mut Attempt, body: &ToDeviceRequest) -> Result<()> {
        if a.outbox.iter().any(|f| f.token == body.txn_id.as_str()) {
            return Ok(());
        }
        if a.outbox.len() >= MAX_PENDING_FRAMES {
            return Err(LinkError::LimitExceeded);
        }
        let (user, device) = a.context.ids(a.role.peer())?;
        if body.messages.len() != 1 {
            return Err(LinkError::InvalidFrame);
        }
        let devices = body.messages.get(&user).ok_or(LinkError::BindingMismatch)?;
        if devices.len() != 1 {
            return Err(LinkError::InvalidFrame);
        }
        let raw = devices
            .get(&ruma::to_device::DeviceIdOrAllDevices::DeviceId(device))
            .ok_or(LinkError::BindingMismatch)?;
        let content: Value =
            serde_json::from_str(raw.json().get()).map_err(|_| LinkError::InvalidFrame)?;
        let event_json=serde_json::to_vec(&json!({"type":body.event_type.to_string(),"sender":a.machine.user_id(),"content":content})).map_err(|_|LinkError::InvalidFrame)?;
        if event_json.len() > MAX_FRAME_BYTES {
            return Err(LinkError::LimitExceeded);
        }
        a.outbox.push_back(LinkFrame {
            binding: a.context.digest()?,
            token: body.txn_id.to_string(),
            event_json,
        });
        Ok(())
    }
    async fn collect(a: &mut Attempt) -> Result<()> {
        for request in Self::quiet(a.machine.outgoing_requests())
            .await
            .map_err(|_| LinkError::Sdk)?
        {
            if let AnyOutgoingRequest::ToDeviceRequest(body) = request.request() {
                Self::enqueue_body(a, body)?;
            }
            // Keys/query/upload do not become network operations. The adapter
            // has no Olm/room/session-key transport and no key-sharing intent.
        }
        Ok(())
    }
    pub(crate) async fn start_verification(&mut self, now: Instant) -> Result<()> {
        let a = self.live(now)?;
        if a.role != Role::NewDevice || !a.peer_admitted || a.flow.is_some() {
            return Err(LinkError::NotReady);
        }
        let (user, device) = a.context.ids(a.role.peer())?;
        let peer = Self::quiet(a.machine.get_device(&user, &device, None))
            .await
            .map_err(|_| LinkError::Sdk)?
            .ok_or(LinkError::NotReady)?;
        let (request, message) = Self::quiet_sync(|| {
            peer.request_verification_with_methods(vec![VerificationMethod::SasV1])
        });
        a.flow = Some(request.flow_id().as_str().to_owned());
        Self::enqueue(a, message)
    }
    pub(crate) async fn receive(&mut self, frame: &LinkFrame, now: Instant) -> Result<()> {
        let a = self.live(now)?;
        if frame.binding != a.context.digest()? {
            return Err(LinkError::BindingMismatch);
        }
        if frame.event_json.len() > MAX_FRAME_BYTES || frame.token.len() > 128 {
            return Err(LinkError::LimitExceeded);
        }
        if frame.token.is_empty() {
            return Err(LinkError::InvalidFrame);
        }
        let event: Value =
            serde_json::from_slice(&frame.event_json).map_err(|_| LinkError::InvalidFrame)?;
        if serde_json::to_vec(&event).map_err(|_| LinkError::InvalidFrame)? != frame.event_json {
            return Err(LinkError::InvalidFrame);
        }
        let (user, device) = a.context.ids(a.role.peer())?;
        if event["sender"] != user.as_str() {
            return Err(LinkError::BindingMismatch);
        }
        let kind = event["type"].as_str().ok_or(LinkError::InvalidFrame)?;
        if !matches!(
            kind,
            "m.key.verification.request"
                | "m.key.verification.ready"
                | "m.key.verification.start"
                | "m.key.verification.accept"
                | "m.key.verification.key"
                | "m.key.verification.mac"
                | "m.key.verification.done"
                | "m.key.verification.cancel"
        ) {
            return Err(LinkError::InvalidFrame);
        }
        let flow = event["content"]["transaction_id"]
            .as_str()
            .ok_or(LinkError::InvalidFrame)?;
        if flow.is_empty() || flow.len() > 128 {
            return Err(LinkError::InvalidFrame);
        }
        if let Some(from) = event["content"].get("from_device")
            && from != device.as_str()
        {
            return Err(LinkError::BindingMismatch);
        }
        if a.flow.as_deref().is_some_and(|existing| existing != flow)
            && kind == "m.key.verification.request"
        {
            self.terminate();
            return Err(LinkError::SimultaneousRequest);
        }
        let a = self.live(now)?;
        match a.flow.as_deref() {
            Some(existing) if existing != flow => return Err(LinkError::StaleFlow),
            None if kind == "m.key.verification.request"
                && a.role == Role::Approver
                && a.peer_admitted =>
            {
                a.flow = Some(flow.to_owned())
            }
            None => return Err(LinkError::StaleFlow),
            _ => (),
        }
        let hash: [u8; 32] = Sha256::digest(&frame.event_json).into();
        if a.seen.contains(&hash) {
            return Ok(());
        }
        if a.seen.len() >= MAX_PENDING_FRAMES {
            return Err(LinkError::LimitExceeded);
        }
        let raw = Raw::<AnyToDeviceEvent>::from_json_string(
            String::from_utf8(frame.event_json.clone()).map_err(|_| LinkError::InvalidFrame)?,
        )
        .map_err(|_| LinkError::InvalidFrame)?;
        Self::quiet(a.machine.receive_sync_changes(
            EncryptionSyncChanges {
                to_device_events: vec![raw],
                changed_devices: &DeviceLists::default(),
                one_time_keys_counts: &BTreeMap::new(),
                unused_fallback_keys: None,
                next_batch_token: None,
            },
            &DecryptionSettings {
                sender_device_trust_requirement: TrustRequirement::Untrusted,
            },
        ))
        .await
        .map_err(|_| LinkError::Sdk)?;
        if kind == "m.key.verification.request" {
            let request = a
                .machine
                .get_verification_request(&user, flow)
                .ok_or(LinkError::InvalidFrame)?;
            let message =
                Self::quiet_sync(|| request.accept_with_methods(vec![VerificationMethod::SasV1]))
                    .ok_or(LinkError::InvalidFrame)?;
            if a.response_deadline.is_none() {
                a.response_deadline = Some(now + ATTEMPT_LIFETIME);
            }
            Self::enqueue(a, message)?;
        } else if kind == "m.key.verification.ready" && a.role == Role::NewDevice {
            if a.response_deadline.is_none() {
                a.response_deadline = Some(now + ATTEMPT_LIFETIME);
            }
            let request = a
                .machine
                .get_verification_request(&user, flow)
                .ok_or(LinkError::InvalidFrame)?;
            if let Some((sas, message)) = Self::quiet(request.start_sas())
                .await
                .map_err(|_| LinkError::Sdk)?
            {
                a.sas = Some(sas);
                Self::enqueue(a, message)?;
            }
        } else if kind == "m.key.verification.start" && a.role == Role::Approver {
            let sas = a
                .machine
                .get_verification(&user, flow)
                .and_then(|v| v.sas_v1())
                .ok_or(LinkError::InvalidFrame)?;
            let message = Self::quiet_sync(|| sas.accept()).ok_or(LinkError::InvalidFrame)?;
            a.sas = Some(*sas);
            Self::enqueue(a, message)?;
        }
        a.seen.insert(hash);
        Self::collect(a).await?;
        if kind == "m.key.verification.cancel" || a.sas.as_ref().is_some_and(Sas::is_cancelled) {
            self.terminate();
            return Err(LinkError::Cancelled);
        }
        Ok(())
    }
    pub(crate) fn native_observation(
        &mut self,
        now: Instant,
    ) -> Result<(
        crate::DeviceLinkingPhase,
        Option<crate::DeviceLinkingDecimals>,
    )> {
        let a = self.live(now)?;
        let decimals = a
            .sas
            .as_ref()
            .and_then(Sas::decimals)
            .map(|(first, second, third)| crate::DeviceLinkingDecimals {
                first,
                second,
                third,
            });
        let phase = if !a.peer_admitted {
            crate::DeviceLinkingPhase::AwaitingPeer
        } else if a.local_confirmed
            && a.sas.as_ref().is_some_and(Sas::is_done)
            && a.outbox.is_empty()
        {
            crate::DeviceLinkingPhase::VerificationCompleteEnrollmentPending
        } else if a.local_confirmed {
            crate::DeviceLinkingPhase::AwaitingPeerVerification
        } else if decimals.is_some() {
            crate::DeviceLinkingPhase::ComparisonAvailable
        } else {
            crate::DeviceLinkingPhase::AwaitingPeerVerification
        };
        Ok((phase, decimals))
    }

    pub(crate) fn outgoing(&mut self, now: Instant) -> Result<Vec<LinkFrame>> {
        Ok(self.live(now)?.outbox.iter().cloned().collect())
    }
    pub(crate) async fn acknowledge(&mut self, token: &str, now: Instant) -> Result<()> {
        let a = self.live(now)?;
        let index = a
            .outbox
            .iter()
            .position(|f| f.token == token)
            .ok_or(LinkError::StaleFlow)?;
        Self::quiet(
            a.machine
                .mark_request_as_sent(token.into(), &SentResponse::new()),
        )
        .await
        .map_err(|_| LinkError::Sdk)?;
        a.outbox.remove(index);
        Ok(())
    }
    pub(crate) fn decimals(&mut self, now: Instant) -> Result<Option<(u16, u16, u16)>> {
        Ok(self.live(now)?.sas.as_ref().and_then(Sas::decimals))
    }
    pub(crate) async fn confirm(&mut self, now: Instant) -> Result<()> {
        let a = self.live(now)?;
        let sas = a.sas.as_ref().ok_or(LinkError::NotReady)?;
        if sas.decimals().is_none() {
            return Err(LinkError::NotReady);
        }
        let messages = Self::quiet(sas.confirm())
            .await
            .map_err(|_| LinkError::Sdk)?
            .0;
        a.local_confirmed = true;
        for message in messages {
            Self::enqueue(a, message)?;
        }
        Self::collect(a).await
    }
    pub(crate) async fn take_verified(&mut self, now: Instant) -> Result<VerifiedPairing> {
        let a = self.live(now)?;
        if a.consumed {
            return Err(LinkError::AlreadyConsumed);
        }
        if !a.local_confirmed || !a.sas.as_ref().is_some_and(Sas::is_done) {
            return Err(LinkError::NotReady);
        }
        let (user, device) = a.context.ids(a.role.peer())?;
        let peer = Self::quiet(a.machine.get_device(&user, &device, None))
            .await
            .map_err(|_| LinkError::Sdk)?
            .ok_or(LinkError::NotReady)?;
        if !peer.is_verified() {
            return Err(LinkError::NotReady);
        }
        a.consumed = true;
        Ok(VerifiedPairing {
            context: a.context.clone(),
            role: a.role,
            owner_deadline: None,
        })
    }
    pub(crate) fn cancel(&mut self) {
        self.terminate();
    }
    pub(crate) fn shutdown(&mut self) {
        self.terminate();
        self.closed = true;
    }
}
#[cfg(test)]
#[path = "device_linking/tests.rs"]
mod tests;

#[path = "device_linking/predecessor.rs"]
mod predecessor;
#[cfg(test)]
pub(crate) use predecessor::PredecessorLeaf;
pub(crate) use predecessor::PredecessorRoster;

#[path = "device_linking/owner.rs"]
mod owner;
pub(crate) use owner::{LinkingOwner, OwnerError};

#[path = "device_linking/runtime_gate.rs"]
pub(crate) mod runtime_gate;

#[path = "device_linking/invite_gate.rs"]
pub(crate) mod invite_gate;

#[path = "device_linking/wire.rs"]
mod wire;
pub(crate) use wire::MAX_PACKET_BYTES as MAX_VERIFIER_PACKET_BYTES;

#[path = "device_linking/welcome_collection.rs"]
pub(crate) mod welcome_collection;

pub(crate) mod settlement;
