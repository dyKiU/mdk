//! Actor-owned setup packets. Neither packet nor opaque reservation grants membership.

use super::{AppClient, ClientLinkingError, actual_recipient_purpose};
use crate::device_linking::{LinkError, LinkingContext, OwnerError, PredecessorRoster, Role};
use base64::Engine as _;
use cgka_traits::device_linking_key_package::PurposeAttemptScope;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::{GroupId, KeyPackage};
use rand::RngCore;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

const PREFIX: &[u8] = b"WNLB\x01";
const REQUEST: u8 = 1;
const CHALLENGE: u8 = 2;
pub(crate) const MAX_SETUP_PACKET_BYTES: usize = 512 * 1024;
pub(crate) const MAX_REQUEST_PACKET_BYTES: usize = 100_000;
const MAX_PACKAGE_BYTES: usize = 16_384;
const MAX_ARTIFACT_BYTES: usize = 256 * 1024;

/// Packet metadata is not a permission; the actor retains the original request.
pub(crate) struct SetupPacket {
    pub(crate) scope: PurposeAttemptScope,
    pub(crate) packet: Vec<u8>,
}

// No Clone/Deserialize/Debug: callers retain this process-local request; packets
// cannot recreate its original purpose or the actor's actual verifier lifetime.
pub(crate) struct NewDeviceSetup {
    scope: PurposeAttemptScope,
    packet: Vec<u8>,
    accepted_challenge: Option<[u8; 32]>,
}
impl NewDeviceSetup {
    pub(crate) fn scope(&self) -> &PurposeAttemptScope {
        &self.scope
    }
    pub(crate) fn packet(&self) -> &[u8] {
        &self.packet
    }
}

pub(crate) struct ApproverSetup {
    scope: PurposeAttemptScope,
    packet: Vec<u8>,
}
impl ApproverSetup {
    pub(crate) fn scope(&self) -> &PurposeAttemptScope {
        &self.scope
    }
    pub(crate) fn packet(&self) -> &[u8] {
        &self.packet
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestPacket {
    account: [u8; 32],
    recipient: [u8; 32],
    generation: u64,
    package: KeyPackage,
    reference: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengePacket {
    request_digest: [u8; 32],
    context: LinkingContext,
    artifact: String,
}

fn invalid() -> ClientLinkingError {
    ClientLinkingError::Owner(OwnerError::Verifier(LinkError::InvalidFrame))
}
fn encode_packet<T: Serialize>(value: &T, kind: u8) -> Result<Vec<u8>, ClientLinkingError> {
    let body = serde_json::to_vec(value).map_err(|_| invalid())?;
    let mut packet = Vec::with_capacity(PREFIX.len() + 1 + body.len());
    packet.extend_from_slice(PREFIX);
    packet.push(kind);
    packet.extend_from_slice(&body);
    let limit = if kind == REQUEST {
        MAX_REQUEST_PACKET_BYTES
    } else {
        MAX_SETUP_PACKET_BYTES
    };
    if packet.len() > limit {
        return Err(invalid());
    }
    Ok(packet)
}
fn decode_packet<T: DeserializeOwned + Serialize>(
    packet: &[u8],
    kind: u8,
) -> Result<T, ClientLinkingError> {
    let limit = if kind == REQUEST {
        MAX_REQUEST_PACKET_BYTES
    } else {
        MAX_SETUP_PACKET_BYTES
    };
    if packet.len() > limit
        || !packet.starts_with(PREFIX)
        || packet.get(PREFIX.len()) != Some(&kind)
    {
        return Err(invalid());
    }
    let value: T = serde_json::from_slice(&packet[PREFIX.len() + 1..]).map_err(|_| invalid())?;
    if encode_packet(&value, kind)?.as_slice() != packet {
        return Err(invalid());
    }
    Ok(value)
}

impl AppClient {
    pub(crate) fn linking_native_observation(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<
        (
            crate::DeviceLinkingPhase,
            Option<crate::DeviceLinkingDecimals>,
        ),
        ClientLinkingError,
    > {
        if let Some(attempt) = self
            .linking_owner
            .settlement_attempt
            .as_ref()
            .filter(|attempt| attempt.guard.scope() == scope)
        {
            // Observation follows the same original memory owner after SDK
            // custody moves. Neither stored facts nor this phase grant access.
            if !attempt.guard.is_live() {
                let error = if std::time::Instant::now() >= attempt.guard.deadline() {
                    LinkError::Expired
                } else {
                    LinkError::Cancelled
                };
                return Err(ClientLinkingError::Owner(OwnerError::Verifier(error)));
            }
            return Ok((
                crate::DeviceLinkingPhase::VerificationCompleteEnrollmentPending,
                None,
            ));
        }
        self.scoped_linking_verifier(scope)?
            .native_observation_for_scope(scope, std::time::Instant::now())
            .map_err(ClientLinkingError::Owner)
    }
    pub(crate) async fn reserve_owned_linking_setup_request(
        &mut self,
    ) -> Result<SetupPacket, ClientLinkingError> {
        let request = self.reserve_linking_setup_request().await?;
        let packet = SetupPacket {
            scope: request.scope.clone(),
            packet: request.packet.clone(),
        };
        self.linking_owner.native_setup_request = Some(request);
        Ok(packet)
    }

    pub(crate) async fn approve_owned_linking_setup_request(
        &mut self,
        packet: &[u8],
        target: Option<&GroupId>,
    ) -> Result<SetupPacket, ClientLinkingError> {
        let challenge = self.begin_linking_setup_request(packet, target).await?;
        Ok(SetupPacket {
            scope: challenge.scope,
            packet: challenge.packet,
        })
    }

    pub(crate) async fn accept_owned_linking_setup_challenge(
        &mut self,
        scope: &PurposeAttemptScope,
        packet: &[u8],
    ) -> Result<(), ClientLinkingError> {
        if self
            .linking_owner
            .native_setup_request
            .as_ref()
            .is_none_or(|request| &request.scope != scope)
        {
            return Err(invalid());
        }
        let mut request = self
            .linking_owner
            .native_setup_request
            .take()
            .ok_or_else(invalid)?;
        let result = self
            .accept_linking_setup_challenge(&mut request, packet)
            .await;
        // Rejected metadata must not discard the original request or its valid retry.
        self.linking_owner.native_setup_request = Some(request);
        result
    }

    pub(crate) async fn reserve_linking_setup_request(
        &mut self,
    ) -> Result<NewDeviceSetup, ClientLinkingError> {
        let prepared = self.prepare_device_linking().await?;
        let result = (|| {
            self.scoped_linking_verifier(&prepared.scope)?;
            let storage = self
                .app
                .account_storage(&self.state.label)
                .map_err(|e| ClientLinkingError::Runtime(Box::new(e)))?;
            let purpose = actual_recipient_purpose(&storage, &prepared.scope)
                .map_err(ClientLinkingError::Collection)?;
            if purpose.public_bytes != prepared.package.bytes
                || purpose.signature_public_key.as_slice() != prepared.scope.local_device
            {
                return Err(invalid());
            }
            let request = RequestPacket {
                account: prepared.scope.account,
                recipient: prepared.scope.local_device,
                generation: prepared.scope.generation,
                package: prepared.package,
                reference: purpose.reference.try_into().map_err(|_| invalid())?,
            };
            self.validate_setup_request(&request)?;
            Ok(NewDeviceSetup {
                scope: prepared.scope.clone(),
                packet: encode_packet(&request, REQUEST)?,
                accepted_challenge: None,
            })
        })();
        if result.is_err() {
            self.cancel_device_linking_scope(&prepared.scope).await?;
        }
        result
    }

    fn validate_setup_request(&self, request: &RequestPacket) -> Result<(), ClientLinkingError> {
        if request.generation == 0
            || request.generation > i64::MAX as u64
            || request.package.bytes.is_empty()
            || request.package.bytes.len() > MAX_PACKAGE_BYTES
            || request.package.source.is_some()
            || request.package.protocol_profile != ProtocolProfile::Current
        {
            return Err(invalid());
        }
        let metadata = self
            .runtime
            .session()
            .key_package_metadata(&request.package)
            .map_err(ClientLinkingError::Engine)?;
        if metadata.credential_identity_hex != hex::encode(request.account)
            || metadata.signature_public_key_hex != hex::encode(request.recipient)
            || metadata.key_package_ref_hex != hex::encode(request.reference)
            || cgka_engine::key_package::is_last_resort_key_package(&request.package)
                .map_err(ClientLinkingError::Engine)?
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Target selection is metadata. Fresh protected reads inside this actor
    /// decide whether the target can participate; an ordinary group never can.
    pub(crate) async fn begin_linking_setup_request(
        &mut self,
        packet: &[u8],
        target: Option<&GroupId>,
    ) -> Result<ApproverSetup, ClientLinkingError> {
        let request: RequestPacket = decode_packet(packet, REQUEST)?;
        self.validate_setup_request(&request)?;
        let account = self
            .app
            .account_home()
            .account(&self.state.label)
            .map_err(|e| ClientLinkingError::Runtime(Box::new(e.into())))?;
        if account.account_id_hex != hex::encode(request.account) {
            return Err(invalid());
        }
        let scope = self
            .reserve_device_linking()
            .map_err(ClientLinkingError::Owner)?;
        let result = self
            .construct_setup_challenge(&scope, &request, packet, target)
            .await;
        if result.is_err() {
            self.cancel_device_linking_scope(&scope).await?;
        }
        result
    }

    async fn construct_setup_challenge(
        &mut self,
        scope: &PurposeAttemptScope,
        request: &RequestPacket,
        request_bytes: &[u8],
        target: Option<&GroupId>,
    ) -> Result<ApproverSetup, ClientLinkingError> {
        if scope.account != request.account || scope.local_device == request.recipient {
            return Err(invalid());
        }
        let group = match target {
            Some(group) => group.clone(),
            None => self
                .create_private_device_group_genesis()?
                .group_id()
                .clone(),
        };
        let (version, predecessor, artifact) = match self
            .runtime
            .session()
            .validated_private_device_group_genesis(&group)
            .map_err(ClientLinkingError::Genesis)?
        {
            Some(origin) => {
                if origin.scope().account != scope.account
                    || origin.scope().local_device != scope.local_device
                {
                    return Err(invalid());
                }
                (
                    1,
                    PredecessorRoster::from_candidate(origin.current()).map_err(|_| invalid())?,
                    Vec::new(),
                )
            }
            None => {
                let mut predecessor = self.settled_linking_predecessor(scope, &group)?;
                let artifact = self
                    .runtime
                    .session()
                    .export_settled_device_predecessor(&group)
                    .map_err(ClientLinkingError::Engine)?
                    .ok_or_else(invalid)?;
                if artifact.is_empty() || artifact.len() > MAX_ARTIFACT_BYTES {
                    return Err(invalid());
                }
                predecessor.artifact_digest = Some(Sha256::digest(&artifact).into());
                (2, predecessor, artifact)
            }
        };
        let mut nonce = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let context = LinkingContext {
            version,
            nonce,
            new_device_generation: request.generation,
            approver_generation: scope.generation,
            account: scope.account,
            exact_key_package: request.package.bytes.clone(),
            key_package_reference: request.reference,
            device_group: group.as_slice().to_vec(),
            predecessor,
            approver: scope.local_device,
            recipient: request.recipient,
        };
        context.digest().map_err(|_| invalid())?;
        let challenge = ChallengePacket {
            request_digest: Sha256::digest(request_bytes).into(),
            context,
            artifact: base64::engine::general_purpose::STANDARD.encode(&artifact),
        };
        let packet = encode_packet(&challenge, CHALLENGE)?;
        if version == 1 {
            self.begin_device_linking(scope, challenge.context, Role::Approver)
                .await?;
        } else {
            self.begin_device_linking_with_predecessor(
                scope,
                challenge.context,
                Role::Approver,
                &artifact,
            )
            .await?;
        }
        Ok(ApproverSetup {
            scope: scope.clone(),
            packet,
        })
    }

    pub(crate) async fn accept_linking_setup_challenge(
        &mut self,
        request: &mut NewDeviceSetup,
        packet: &[u8],
    ) -> Result<(), ClientLinkingError> {
        let challenge: ChallengePacket = decode_packet(packet, CHALLENGE)?;
        let digest: [u8; 32] = Sha256::digest(packet).into();
        self.scoped_linking_verifier(&request.scope)?;
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|e| ClientLinkingError::Runtime(Box::new(e)))?;
        let purpose = actual_recipient_purpose(&storage, &request.scope)
            .map_err(ClientLinkingError::Collection)?;
        if challenge.request_digest != Sha256::digest(&request.packet).as_slice()
            || challenge.context.account != request.scope.account
            || challenge.context.recipient != request.scope.local_device
            || challenge.context.new_device_generation != request.scope.generation
            || challenge.context.exact_key_package != purpose.public_bytes
            || challenge.context.key_package_reference.as_slice() != purpose.reference
        {
            return Err(invalid());
        }
        challenge.context.digest().map_err(|_| invalid())?;
        if challenge.artifact.len() > MAX_ARTIFACT_BYTES.div_ceil(3) * 4 {
            return Err(invalid());
        }
        let artifact = base64::engine::general_purpose::STANDARD
            .decode(&challenge.artifact)
            .map_err(|_| invalid())?;
        if artifact.len() > MAX_ARTIFACT_BYTES
            || base64::engine::general_purpose::STANDARD.encode(&artifact) != challenge.artifact
        {
            return Err(invalid());
        }
        match (challenge.context.version, artifact.len()) {
            (1, 0) => (),
            (2, 1..=MAX_ARTIFACT_BYTES) => (),
            _ => return Err(invalid()),
        }
        if let Some(accepted) = request.accepted_challenge {
            if accepted != digest {
                return Err(invalid());
            }
            self.device_linking_offer(&request.scope)?;
            return Ok(());
        }
        if challenge.context.version == 1 {
            self.begin_device_linking(&request.scope, challenge.context, Role::NewDevice)
                .await?;
        } else {
            self.begin_device_linking_with_predecessor(
                &request.scope,
                challenge.context,
                Role::NewDevice,
                &artifact,
            )
            .await?;
        }
        request.accepted_challenge = Some(digest);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
