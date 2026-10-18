use super::AppClient;
use crate::selected_chat_copy::{
    SelectedChatCopyError,
    enabled::{CollectedOffer, RequestState},
};
use cgka_traits::EngineError;
use std::sync::Arc;

impl AppClient {
    pub(crate) fn selected_request_collect_offer(
        &self,
        original: &Arc<RequestState>,
        revision: u64,
        packet: &[u8],
    ) -> Result<(), SelectedChatCopyError> {
        self.fresh_selected_request(original, revision)?;
        if packet.is_empty()
            || packet.len() > cgka_engine::selected_chat_consent::MAX_SELECTED_CHAT_PACKET_BYTES
        {
            return Err(SelectedChatCopyError::InvalidPacket);
        }
        let carrier = super::carrier::decode(packet)?;
        let inner = carrier.offer.get().as_bytes();
        let progress = original.progress.lock().expect("selected offer collection");
        let request = progress
            .packet
            .clone()
            .ok_or(SelectedChatCopyError::NotReady)?;
        let responses: Vec<_> = progress
            .receipts
            .iter()
            .map(|(index, (_, response))| (*index, response.clone()))
            .collect();
        drop(progress);
        if responses.is_empty() {
            return Err(SelectedChatCopyError::NotReady);
        }
        // Try only retained authenticated responses; never parse host-supplied
        // indices into a grant or accept an unapproved sibling's package.
        let mut authenticated = None;
        for (index, response) in responses {
            match self
                .runtime
                .session()
                .authenticate_selected_chat_offer(&request, &response, inner)
            {
                Ok(offer) if offer.source_index() == index => {
                    authenticated = Some(offer);
                    break;
                }
                Err(EngineError::Storage(_)) => {
                    return Err(SelectedChatCopyError::RuntimeUnavailable);
                }
                _ => {}
            }
        }
        let offer = authenticated.ok_or(SelectedChatCopyError::InvalidPacket)?;
        let package_event_id = super::carrier::verify(&carrier.event, &offer)?;
        self.fresh_selected_request(original, revision)?;
        let mut progress = original.progress.lock().expect("selected offer collection");
        if let Some(prior) = progress.offers.get(&offer.source_index()) {
            return if prior.wire == packet && prior.observation.reference() == offer.reference() {
                Ok(())
            } else {
                Err(SelectedChatCopyError::InvalidPacket)
            };
        }
        if progress.offers.len() >= original._protected.leaves.len().saturating_sub(1) {
            return Err(SelectedChatCopyError::InvalidPacket);
        }
        progress.offers.insert(
            offer.source_index(),
            CollectedOffer {
                wire: packet.to_vec(),
                observation: Arc::new(offer),
                package_event_id,
            },
        );
        Ok(())
    }
}
