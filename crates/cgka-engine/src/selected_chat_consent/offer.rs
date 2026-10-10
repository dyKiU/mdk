//! Authenticated offer observations, never recipient consent or membership.
use super::*;
use cgka_traits::engine::KeyPackage;

pub(super) const OFFER: &str = "whitenoise.selected-chat-key-package-offer-observation.v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Offer {
    pub(super) protocol: String,
    pub(super) binding: [u8; 32],
    pub(super) approved_response_digest: [u8; 32],
    pub(super) generation: u64,
    pub(super) source_index: u32,
    pub(super) source_key: Vec<u8>,
    pub(super) package: Vec<u8>,
    pub(super) signature: Vec<u8>,
}

/// Verified immutable bytes. No host constructor, serde, or live authority.
pub struct AuthenticatedSelectedChatOffer {
    source_index: u32,
    source_key: Vec<u8>,
    generation: u64,
    reference: [u8; 32],
    key_package: KeyPackage,
}
impl AuthenticatedSelectedChatOffer {
    pub fn source_index(&self) -> u32 {
        self.source_index
    }
    pub fn source_key(&self) -> &[u8] {
        &self.source_key
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn reference(&self) -> &[u8; 32] {
        &self.reference
    }
    pub fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }
}
impl<S: StorageProvider> Engine<S> {
    /// Verify canonical signatures and the exact Current single-use package.
    /// This metadata has no original recipient lease or membership authority.
    pub fn authenticate_selected_chat_offer(
        &self,
        request_wire: &[u8],
        approved_response: &[u8],
        offer_wire: &[u8],
    ) -> Result<AuthenticatedSelectedChatOffer, EngineError> {
        self.storage.with_read_snapshot(|_| {
            let request = self.authenticate_selected_chat_request(request_wire)?;
            let consent =
                self.authenticate_selected_chat_consent(request_wire, approved_response)?;
            let mut frame: Offer = decode(offer_wire)?;
            let response_digest: [u8; 32] = Sha256::digest(approved_response).into();
            if frame.protocol != OFFER
                || frame.binding != request.binding()
                || frame.approved_response_digest != response_digest
                || frame.generation != consent.generation
                || frame.source_index != consent.source_index
                || frame.source_key != consent.source_key
                || frame.signature.len() != 64
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
            let key_package =
                KeyPackage::new(frame.package).with_protocol_profile(ProtocolProfile::Current);
            let parsed = self.parse_key_package(&key_package)?;
            if parsed.last_resort()
                || parsed.leaf_node().signature_key().as_slice() != frame.source_key
                || crate::identity::validated_member_id_of_leaf(parsed.leaf_node())?.as_slice()
                    != request.frame.account
            {
                return Err(denied());
            }
            let reference = parsed
                .hash_ref(&self.crypto)
                .map_err(|_| denied())?
                .as_slice()
                .try_into()
                .map_err(|_| denied())?;
            Ok(AuthenticatedSelectedChatOffer {
                source_index: frame.source_index,
                source_key: frame.source_key,
                generation: frame.generation,
                reference,
                key_package,
            })
        })
    }
}
