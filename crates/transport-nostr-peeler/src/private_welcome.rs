//! Private experimental enrollment transport; never ordinary Welcome admission.
use crate::peeler::ensure_welcome_routing_matches;
use crate::{KIND_NIP59_GIFT_WRAP, NostrMlsPeeler, NostrTransportEvent, SdkSigner};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use cgka_traits::{
    error::PeelerError,
    peeler::PrivateLinkingWelcomeContext,
    private_device_invite::MAX_PRIVATE_INVITE_WELCOME_BYTES,
    transport::{EncryptedPayload, TransportMessage},
};
use nostr::{
    nips::nip59::GiftWrapBuilder,
    prelude::{EventBuilder, FinalizeEventAsync, FinalizeUnsignedEvent, Kind, PublicKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Local draft kind/profile, not an adopted Marmot transport specification.
const PRIVATE_WELCOME_KIND: u16 = 38174;
const PROFILE: &str = "whitenoise.experimental.linking-welcome.v1";
const CHUNK_BYTES: usize = 24 * 1024;
const MAX_CHUNKS: usize = MAX_PRIVATE_INVITE_WELCOME_BYTES.div_ceil(CHUNK_BYTES);
const MAX_EVENT_BYTES: usize = 128 * 1024;
const MAX_RUMOR_BYTES: usize = 40 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Chunk {
    profile: String,
    context: PrivateLinkingWelcomeContext,
    index: usize,
    count: usize,
    total: usize,
    data: String,
}

/// Authenticated transport metadata from one bounded chunk, not a complete
/// Welcome or pairing permission. Compare its known bindings with the live SDK
/// context before collecting; post-preparation hashes remain observations.
pub struct PrivateWelcomeObservation {
    pub context: PrivateLinkingWelcomeContext,
    pub index: usize,
    pub count: usize,
    pub total: usize,
}
struct AuthenticatedChunk {
    observation: PrivateWelcomeObservation,
    bytes: Vec<u8>,
}
fn malformed() -> PeelerError {
    PeelerError::Malformed("invalid private Welcome batch".into())
}
fn validate_context(context: &PrivateLinkingWelcomeContext) -> Result<PublicKey, PeelerError> {
    if context.group_id.as_slice().is_empty()
        || context.group_id.as_slice().len() > 255
        || context.approver == context.recipient
        || context.approver_generation == 0
        || context.approver_generation > i64::MAX as u64
        || context.recipient_generation == 0
        || context.recipient_generation > i64::MAX as u64
        || [
            &context.approver,
            &context.recipient,
            &context.nonce,
            &context.context_digest,
            &context.key_package_reference,
            &context.key_package_digest,
            &context.commit_digest,
            &context.welcome_digest,
        ]
        .iter()
        .any(|value| **value == [0; 32])
    {
        return Err(malformed());
    }
    PublicKey::from_slice(&context.account).map_err(|_| malformed())
}
impl NostrMlsPeeler {
    /// Authenticate one bounded chunk without presupposing hashes created after
    /// pairing. The observation is not a complete Welcome or SDK consent.
    pub async fn observe_private_linking_welcome(
        &self,
        message: &TransportMessage,
    ) -> Result<PrivateWelcomeObservation, PeelerError> {
        if message.payload.len() > MAX_EVENT_BYTES {
            return Err(malformed());
        }
        let account = self
            .welcome_signer()?
            .get_public_key()
            .await
            .map_err(|_| PeelerError::DecryptFailed)?;
        Ok(self
            .authenticate_private_chunk(message, account)
            .await?
            .observation)
    }

    async fn authenticate_private_chunk(
        &self,
        message: &TransportMessage,
        account: PublicKey,
    ) -> Result<AuthenticatedChunk, PeelerError> {
        if message.payload.len() > MAX_EVENT_BYTES {
            return Err(malformed());
        }
        let event =
            NostrTransportEvent::from_transport_message(message).map_err(|_| malformed())?;
        if event.kind != KIND_NIP59_GIFT_WRAP {
            return Err(malformed());
        }
        let canonical = event.to_transport_message().map_err(|_| malformed())?;
        if canonical.id != message.id {
            return Err(malformed());
        }
        if event
            .tags
            .iter()
            .any(|tag| tag.first().is_some_and(|name| name == "p") && tag.len() != 2)
        {
            return Err(malformed());
        }
        ensure_welcome_routing_matches(&event, message)?;
        if event.single_tag_value("p").map_err(|_| malformed())? != account.to_hex() {
            return Err(PeelerError::WrongRecipient);
        }
        let gift = event
            .to_verified_nostr_event()
            .map_err(|_| PeelerError::DecryptFailed)?;
        let unwrapped = nostr::nips::nip59::extract_rumor_async(
            &SdkSigner(self.welcome_signer()?.clone()),
            &gift,
        )
        .await
        .map_err(|_| PeelerError::DecryptFailed)?;
        let rumor = unwrapped.rumor;
        if unwrapped.sender != account
            || rumor.kind != Kind::Custom(PRIVATE_WELCOME_KIND)
            || !rumor.tags.is_empty()
            || rumor.content.len() > MAX_RUMOR_BYTES
        {
            return Err(malformed());
        }
        let chunk: Chunk = serde_json::from_str(&rumor.content).map_err(|_| malformed())?;
        if chunk.profile != PROFILE
            || validate_context(&chunk.context)? != account
            || chunk.count == 0
            || chunk.count > MAX_CHUNKS
            || chunk.index >= chunk.count
            || chunk.total == 0
            || chunk.total > MAX_PRIVATE_INVITE_WELCOME_BYTES
            || chunk.total.div_ceil(CHUNK_BYTES) != chunk.count
            || chunk.data.len() > CHUNK_BYTES.div_ceil(3) * 4
        {
            return Err(malformed());
        }
        let bytes = BASE64.decode(&chunk.data).map_err(|_| malformed())?;
        let expected_len = if chunk.index + 1 == chunk.count {
            chunk.total - chunk.index * CHUNK_BYTES
        } else {
            CHUNK_BYTES
        };
        if bytes.len() != expected_len || BASE64.encode(&bytes) != chunk.data {
            return Err(malformed());
        }
        Ok(AuthenticatedChunk {
            observation: PrivateWelcomeObservation {
                context: chunk.context,
                index: chunk.index,
                count: chunk.count,
                total: chunk.total,
            },
            bytes,
        })
    }

    pub(crate) async fn wrap_private_welcome_batch(
        &self,
        payload: &EncryptedPayload,
        context: &PrivateLinkingWelcomeContext,
    ) -> Result<Vec<TransportMessage>, PeelerError> {
        let account = validate_context(context)?;
        if !payload.aad.is_empty()
            || payload.ciphertext.is_empty()
            || payload.ciphertext.len() > MAX_PRIVATE_INVITE_WELCOME_BYTES
            || Sha256::digest(&payload.ciphertext).as_slice() != context.welcome_digest
        {
            return Err(malformed());
        }
        let signer = self.welcome_signer()?;
        if signer
            .get_public_key()
            .await
            .map_err(|_| PeelerError::WrapFailed("private Welcome signer unavailable".into()))?
            != account
        {
            return Err(PeelerError::WrongRecipient);
        }
        let count = payload.ciphertext.len().div_ceil(CHUNK_BYTES);
        let mut batch = Vec::with_capacity(count);
        for (index, data) in payload.ciphertext.chunks(CHUNK_BYTES).enumerate() {
            let content = serde_json::to_string(&Chunk {
                profile: PROFILE.into(),
                context: context.clone(),
                index,
                count,
                total: payload.ciphertext.len(),
                data: BASE64.encode(data),
            })
            .map_err(|_| malformed())?;
            if content.len() > MAX_RUMOR_BYTES {
                return Err(malformed());
            }
            let rumor = EventBuilder::new(Kind::Custom(PRIVATE_WELCOME_KIND), content)
                .finalize_unsigned(account);
            let gift = GiftWrapBuilder::new(account, rumor)
                .finalize_async(&SdkSigner(signer.clone()))
                .await
                .map_err(|_| PeelerError::WrapFailed("private Welcome encryption failed".into()))?;
            let message = NostrTransportEvent::from_nostr_event(&gift)
                .and_then(|event| event.to_transport_message())
                .map_err(|_| malformed())?;
            if message.payload.len() > MAX_EVENT_BYTES {
                return Err(malformed());
            }
            batch.push(message);
        }
        Ok(batch)
    }

    /// Authenticate and reassemble one bounded complete batch against an exact
    /// caller-owned pairing context. This returns bytes, never join permission.
    /// Arrival order may differ; duplicates, missing parts and mixtures fail.
    pub async fn peel_private_linking_welcome_batch(
        &self,
        messages: &[TransportMessage],
        expected: &PrivateLinkingWelcomeContext,
    ) -> Result<Vec<u8>, PeelerError> {
        let account = validate_context(expected)?;
        if messages.is_empty() || messages.len() > MAX_CHUNKS {
            return Err(malformed());
        }
        let signer = self.welcome_signer()?;
        if signer
            .get_public_key()
            .await
            .map_err(|_| PeelerError::DecryptFailed)?
            != account
        {
            return Err(PeelerError::WrongRecipient);
        }
        let mut parts: Vec<Option<Vec<u8>>> = vec![None; messages.len()];
        let mut total = None;
        for message in messages {
            let chunk = self.authenticate_private_chunk(message, account).await?;
            let observed = chunk.observation;
            if observed.context != *expected
                || observed.count != messages.len()
                || total.is_some_and(|value| value != observed.total)
                || parts[observed.index].is_some()
            {
                return Err(malformed());
            }
            total = Some(observed.total);
            parts[observed.index] = Some(chunk.bytes);
        }
        let mut bytes = Vec::with_capacity(total.ok_or_else(malformed)?);
        for part in parts {
            bytes.extend(part.ok_or_else(malformed)?);
        }
        if Sha256::digest(&bytes).as_slice() != expected.welcome_digest {
            return Err(malformed());
        }
        Ok(bytes)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::{GroupId, peeler::TransportPeeler};
    use nostr::prelude::Keys;
    use sha2::{Digest, Sha256};
    fn fixture() -> (
        NostrMlsPeeler,
        PrivateLinkingWelcomeContext,
        EncryptedPayload,
    ) {
        let keys = Keys::generate();
        let payload = EncryptedPayload {
            ciphertext: vec![17; 100_000],
            aad: vec![],
        };
        let context = PrivateLinkingWelcomeContext {
            account: keys.public_key().to_bytes(),
            approver: [2; 32],
            recipient: [3; 32],
            approver_generation: 1,
            recipient_generation: 2,
            group_id: GroupId::new(vec![4; 16]),
            nonce: [5; 32],
            context_digest: [6; 32],
            key_package_reference: [7; 32],
            key_package_digest: [8; 32],
            commit_digest: [9; 32],
            welcome_digest: Sha256::digest(&payload.ciphertext).into(),
        };
        (
            NostrMlsPeeler::new().with_welcome_signer(keys),
            context,
            payload,
        )
    }

    async fn signed_test_chunk(
        peeler: &NostrMlsPeeler,
        chunk: &Chunk,
        other_author: bool,
    ) -> TransportMessage {
        let local = peeler.welcome_signer().unwrap();
        let account = local.get_public_key().await.unwrap();
        let author: std::sync::Arc<dyn crate::MarmotNostrSigner> = if other_author {
            std::sync::Arc::new(Keys::generate())
        } else {
            local.clone()
        };
        let rumor = EventBuilder::new(
            Kind::Custom(PRIVATE_WELCOME_KIND),
            serde_json::to_string(chunk).unwrap(),
        )
        .finalize_unsigned(author.get_public_key().await.unwrap());
        let gift = GiftWrapBuilder::new(account, rumor)
            .finalize_async(&SdkSigner(author))
            .await
            .unwrap();
        NostrTransportEvent::from_nostr_event(&gift)
            .unwrap()
            .to_transport_message()
            .unwrap()
    }

    #[tokio::test]
    async fn private_observation_rejects_signed_invalid_chunks_and_foreign_seal_author() {
        let (peeler, context, _) = fixture();
        for invalid in 0..9 {
            let mut chunk = Chunk {
                profile: PROFILE.into(),
                context: context.clone(),
                index: 0,
                count: 1,
                total: 1,
                data: BASE64.encode([17]),
            };
            match invalid {
                0 => chunk.profile = "unknown".into(),
                1 => chunk.context.account = Keys::generate().public_key().to_bytes(),
                2 => chunk.context.recipient_generation = 0,
                3 => chunk.count = 0,
                4 => chunk.count = MAX_CHUNKS + 1,
                5 => chunk.index = 1,
                6 => chunk.total = MAX_PRIVATE_INVITE_WELCOME_BYTES + 1,
                7 => chunk.data = BASE64.encode([17, 18]),
                8 => chunk.data = "%%%".into(),
                _ => unreachable!(),
            }
            let message = signed_test_chunk(&peeler, &chunk, false).await;
            assert!(
                peeler
                    .observe_private_linking_welcome(&message)
                    .await
                    .is_err()
            );
        }
        let chunk = Chunk {
            profile: PROFILE.into(),
            context,
            index: 0,
            count: 1,
            total: 1,
            data: BASE64.encode([17]),
        };
        let foreign = signed_test_chunk(&peeler, &chunk, true).await;
        assert!(
            peeler
                .observe_private_linking_welcome(&foreign)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn private_observation_rejects_substituted_identity_routing_and_oversize_packet() {
        let (peeler, context, payload) = fixture();
        let batch = peeler
            .wrap_private_linking_welcome(&payload, &context)
            .await
            .unwrap();
        let mut altered = batch[0].clone();
        altered.id = cgka_traits::MessageId::new(vec![0; 32]);
        assert!(
            peeler
                .observe_private_linking_welcome(&altered)
                .await
                .is_err()
        );
        altered = batch[0].clone();
        altered.envelope = cgka_traits::transport::TransportEnvelope::Welcome {
            recipient: cgka_traits::MemberId::new(vec![0; 32]),
        };
        assert!(
            peeler
                .observe_private_linking_welcome(&altered)
                .await
                .is_err()
        );
        altered = batch[0].clone();
        altered.payload = vec![0; MAX_EVENT_BYTES + 1];
        assert!(matches!(
            NostrMlsPeeler::new()
                .observe_private_linking_welcome(&altered)
                .await,
            Err(PeelerError::Malformed(_))
        ));
    }
    #[tokio::test]
    async fn private_batch_authentication_survives_transport_trait_dispatch() {
        let (peeler, context, payload) = fixture();
        let transport: &dyn TransportPeeler = &peeler;
        let mut batch = transport
            .wrap_private_linking_welcome(&payload, &context)
            .await
            .unwrap();
        batch.reverse();
        assert_eq!(
            transport
                .peel_private_linking_welcome_batch(&batch, &context)
                .await
                .unwrap(),
            payload.ciphertext
        );
        assert!(
            transport
                .peel_private_linking_welcome_batch(&batch[..1], &context)
                .await
                .is_err()
        );
        let mut wrong_context = context.clone();
        wrong_context.nonce[0] ^= 1;
        assert!(
            transport
                .peel_private_linking_welcome_batch(&batch, &wrong_context)
                .await
                .is_err()
        );
        assert!(transport.peel_welcome(&batch[0]).await.is_err());
    }

    #[tokio::test]
    async fn private_context_can_be_observed_before_post_preparation_hashes_are_known() {
        let (peeler, context, payload) = fixture();
        let batch = peeler
            .wrap_private_linking_welcome(&payload, &context)
            .await
            .unwrap();
        let observed = peeler.observe_private_linking_welcome(&batch[1]).await;
        assert!(
            observed.is_ok(),
            "authenticate metadata without presupposing artifact hashes"
        );
        let observed = observed.unwrap();
        assert!(observed.context == context);
        assert_eq!(observed.index, 1);
        assert_eq!(observed.count, batch.len());
        assert_eq!(observed.total, payload.ciphertext.len());
        assert!(
            peeler
                .peel_private_linking_welcome_batch(&batch[..1], &observed.context)
                .await
                .is_err()
        );
        assert_eq!(
            peeler
                .peel_private_linking_welcome_batch(&batch, &observed.context)
                .await
                .unwrap(),
            payload.ciphertext
        );
    }
    #[tokio::test]
    async fn large_private_welcome_wraps_without_public_key_package_event() {
        let (peeler, context, payload) = fixture();
        let batch = peeler
            .wrap_private_linking_welcome(&payload, &context)
            .await;
        assert!(
            batch.is_ok(),
            "real private welcome transport must wrap without a public KeyPackage event"
        );
        let mut batch = batch.unwrap();
        assert!(batch.len() > 1);
        assert!(peeler.peel_welcome(&batch[0]).await.is_err());
        batch.reverse();
        let recovered = peeler
            .peel_private_linking_welcome_batch(&batch, &context)
            .await;
        assert!(recovered.is_ok());
        assert_eq!(recovered.unwrap(), payload.ciphertext);
    }
    #[tokio::test]
    async fn incomplete_duplicate_and_context_substituted_batches_are_denied() {
        let (peeler, context, payload) = fixture();
        let batch = peeler
            .wrap_private_linking_welcome(&payload, &context)
            .await
            .unwrap();
        assert!(
            peeler
                .peel_private_linking_welcome_batch(&batch[..batch.len() - 1], &context)
                .await
                .is_err()
        );
        let mut duplicate = batch.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(
            peeler
                .peel_private_linking_welcome_batch(&duplicate, &context)
                .await
                .is_err()
        );
        let mut altered = context.clone();
        altered.recipient[0] ^= 1;
        assert!(
            peeler
                .peel_private_linking_welcome_batch(&batch, &altered)
                .await
                .is_err()
        );
        altered = context.clone();
        altered.context_digest[0] ^= 1;
        assert!(
            peeler
                .peel_private_linking_welcome_batch(&batch, &altered)
                .await
                .is_err()
        );
        altered = context.clone();
        altered.welcome_digest[0] ^= 1;
        assert!(
            peeler
                .peel_private_linking_welcome_batch(&batch, &altered)
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn signer_mismatch_and_oversize_inputs_are_denied_before_wrapping() {
        let (peeler, mut context, mut payload) = fixture();
        context.account = Keys::generate().public_key().to_bytes();
        assert!(
            peeler
                .wrap_private_linking_welcome(&payload, &context)
                .await
                .is_err()
        );
        let (peeler, mut context, _) = fixture();
        payload.ciphertext = vec![17; MAX_PRIVATE_INVITE_WELCOME_BYTES + 1];
        context.welcome_digest = Sha256::digest(&payload.ciphertext).into();
        assert!(
            peeler
                .wrap_private_linking_welcome(&payload, &context)
                .await
                .is_err()
        );
        let huge = vec![TransportMessage {
            payload: vec![0; MAX_EVENT_BYTES + 1],
            ..super_dummy_message()
        }];
        assert!(
            peeler
                .peel_private_linking_welcome_batch(&huge, &context)
                .await
                .is_err()
        );
        context.recipient_generation = 0;
        assert!(
            peeler
                .wrap_private_linking_welcome(&payload, &context)
                .await
                .is_err()
        );
    }
    fn super_dummy_message() -> TransportMessage {
        use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportSource};
        TransportMessage {
            id: cgka_traits::MessageId::new(vec![1; 32]),
            payload: vec![],
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("nostr".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: cgka_traits::MemberId::new(vec![1; 32]),
            },
        }
    }
    #[tokio::test]
    async fn maximum_bounded_welcome_round_trips_with_real_nip59() {
        let (peeler, mut context, mut payload) = fixture();
        payload.ciphertext = vec![17; MAX_PRIVATE_INVITE_WELCOME_BYTES];
        context.welcome_digest = Sha256::digest(&payload.ciphertext).into();
        let batch = peeler
            .wrap_private_linking_welcome(&payload, &context)
            .await
            .unwrap();
        assert_eq!(batch.len(), MAX_CHUNKS);
        let recovered = peeler
            .peel_private_linking_welcome_batch(&batch, &context)
            .await
            .unwrap();
        assert_eq!(recovered, payload.ciphertext);
    }
    #[tokio::test]
    async fn substituted_transport_identity_is_denied() {
        let (peeler, context, payload) = fixture();
        let mut batch = peeler
            .wrap_private_linking_welcome(&payload, &context)
            .await
            .unwrap();
        batch[0].id = cgka_traits::MessageId::new(vec![0; 32]);
        assert!(
            peeler
                .peel_private_linking_welcome_batch(&batch, &context)
                .await
                .is_err(),
            "transport identity must match the verified Nostr event"
        );
    }
}
