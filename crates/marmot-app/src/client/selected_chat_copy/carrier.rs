//! Private transport metadata carried alongside the intact leaf-signed offer.
//! No directory publication, endpoint selection, or membership authority.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cgka_engine::{
    key_package::key_package_metadata, selected_chat_consent::AuthenticatedSelectedChatOffer,
};
use cgka_traits::MessageId;
use serde::{Deserialize, Serialize};
use transport_nostr_peeler::NostrTransportEvent;

const PROTOCOL: &str = "whitenoise.selected-chat-private-package-transport.v1";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Carrier {
    protocol: String,
    pub(super) offer: Box<serde_json::value::RawValue>,
    pub(super) event: NostrTransportEvent,
}
pub(super) fn decode(packet: &[u8]) -> Result<Carrier, SelectedChatCopyError> {
    if packet.is_empty()
        || packet.len() > cgka_engine::selected_chat_consent::MAX_SELECTED_CHAT_PACKET_BYTES
    {
        return Err(SelectedChatCopyError::InvalidPacket);
    }
    let carrier: Carrier =
        serde_json::from_slice(packet).map_err(|_| SelectedChatCopyError::InvalidPacket)?;
    if carrier.protocol != PROTOCOL
        || serde_json::to_vec(&carrier).map_err(|_| SelectedChatCopyError::InvalidPacket)? != packet
    {
        return Err(SelectedChatCopyError::InvalidPacket);
    }
    Ok(carrier)
}
fn unsigned(
    package: &cgka_traits::engine::KeyPackage,
    created_at: u64,
) -> Result<NostrTransportEvent, SelectedChatCopyError> {
    let metadata =
        key_package_metadata(package).map_err(|_| SelectedChatCopyError::InvalidPacket)?;
    if metadata.protocol_profile != ProtocolProfile::Current {
        return Err(SelectedChatCopyError::InvalidPacket);
    }
    let values = |name: &str, ids: &[u16]| {
        std::iter::once(name.to_owned())
            .chain(ids.iter().map(|id| format!("0x{id:04x}")))
            .collect::<Vec<_>>()
    };
    let components: Vec<_> = metadata
        .app_components
        .into_iter()
        .filter(|id| *id >= cgka_traits::app_components::PRIVATE_USE_APP_COMPONENT_ID_START)
        .collect();
    let tags = vec![
        vec!["d".into(), metadata.key_package_ref_hex.clone()],
        vec!["mls_protocol_version".into(), "1.0".into()],
        vec!["i".into(), metadata.key_package_ref_hex],
        vec![
            "mls_ciphersuite".into(),
            format!("0x{:04x}", metadata.ciphersuite),
        ],
        values("mls_extensions", &metadata.mls_extensions),
        values("mls_proposals", &metadata.mls_proposals),
        values("app_components", &components),
    ];
    Ok(NostrTransportEvent::new_unsigned_at(
        metadata.credential_identity_hex,
        30_443,
        tags,
        STANDARD.encode(package.bytes()),
        created_at,
    ))
}
pub(super) fn verify(
    event: &NostrTransportEvent,
    offer: &AuthenticatedSelectedChatOffer,
) -> Result<MessageId, SelectedChatCopyError> {
    let expected = unsigned(offer.key_package(), event.created_at)?;
    let json = serde_json::to_string(event).map_err(|_| SelectedChatCopyError::InvalidPacket)?;
    if event.kind != expected.kind
        || event.pubkey != expected.pubkey
        || event.tags != expected.tags
        || event.content != expected.content
        || event.id != expected.id
        || !crate::nostr_verification::verify_public_nostr_event_json(&json)
    {
        return Err(SelectedChatCopyError::InvalidPacket);
    }
    let reference = key_package_metadata(offer.key_package())
        .map_err(|_| SelectedChatCopyError::InvalidPacket)?
        .key_package_ref_hex;
    if reference != hex::encode(offer.reference()) {
        return Err(SelectedChatCopyError::InvalidPacket);
    }
    Ok(MessageId::new(
        hex::decode(&event.id).map_err(|_| SelectedChatCopyError::InvalidPacket)?,
    ))
}
impl AppClient {
    pub(super) async fn sign_selected_offer_carrier(
        &self,
        original: &crate::selected_chat_copy::enabled::ConsentState,
        response: &[u8],
        wire: &[u8],
    ) -> Result<Vec<u8>, SelectedChatCopyError> {
        let offer = self.runtime.session().authenticate_selected_chat_offer(
            &original.packet,
            response,
            wire,
        )?;
        let event = unsigned(
            offer.key_package(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?
                .as_secs(),
        )?;
        if event.pubkey != hex::encode(self.runtime.session().self_id().as_slice()) {
            return Err(SelectedChatCopyError::InvalidPacket);
        }
        let signed = transport_nostr_adapter::sign_transport_event_for_publish(
            self.transport_signer.clone(),
            &event,
        )
        .await
        .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?;
        verify(&signed, &offer)?;
        let carrier = Carrier {
            protocol: PROTOCOL.into(),
            offer: serde_json::value::RawValue::from_string(
                std::str::from_utf8(wire)
                    .map_err(|_| SelectedChatCopyError::InvalidPacket)?
                    .to_owned(),
            )
            .map_err(|_| SelectedChatCopyError::InvalidPacket)?,
            event: signed,
        };
        let packet =
            serde_json::to_vec(&carrier).map_err(|_| SelectedChatCopyError::InvalidPacket)?;
        decode(&packet)?;
        Ok(packet)
    }
}
