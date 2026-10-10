//! Original protected control ciphertexts; no ordinary Sent or restart intent.
use super::*;
use cgka_traits::TransportMessage;
use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider;
use tls_codec::Serialize;

pub(super) struct FrozenHistoryControl {
    kind: HistoryControl,
    ciphertext: Vec<u8>,
    wrapped: Option<TransportMessage>,
}
impl OwnedHistoryChannel {
    fn control_wire(&self, kind: HistoryControl) -> Result<Vec<u8>, EngineError> {
        self.live()?;
        match (self.recipient_role, kind) {
            (false, HistoryControl::Request) => Ok(self.request.clone()),
            (true, HistoryControl::Consent) => self.consent.clone().ok_or_else(refused),
            (false, HistoryControl::Archive) | (true, HistoryControl::Acknowledgement) => self
                .sealed
                .as_ref()
                .map(|(_, wire)| wire.clone())
                .ok_or_else(refused),
            (false, HistoryControl::Chunk(ordinal)) | (true, HistoryControl::Receipt(ordinal)) => {
                self.sealed_chunks
                    .get(ordinal as usize)
                    .map(|chunk| chunk.wire.clone())
                    .ok_or_else(refused)
            }
            _ => Err(refused()),
        }
    }
}
impl<S: StorageProvider> Engine<S> {
    /// Freeze the actual send ratchet once under the same original lease. Every
    /// retry revalidates actual trees/generations and retains exact ciphertext.
    pub async fn wrap_history_control(
        &mut self,
        channel: &mut OwnedHistoryChannel,
        kind: HistoryControl,
    ) -> Result<TransportMessage, EngineError> {
        self.history_channel_fresh(channel)?;
        let wire = channel.control_wire(kind)?;
        let frame = self.history_verify(decode(&wire)?)?;
        Self::history_fixed_context(&frame, &channel.scope)?;
        if frame.signer != self.identity.signer.public()
            || frame.source_generation != channel.scope.local_generation
        {
            return Err(refused());
        }
        let group_id = channel.scope.protected.group_id.clone();
        let position = channel.outbound.iter().position(|entry| entry.kind == kind);
        if let Some(position) = position
            && let Some(message) = &channel.outbound[position].wrapped
        {
            return Ok(message.clone());
        }
        let context = self.storage.with_read_snapshot(|storage| {
            let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
                &self.crypto,
                storage.mls_storage(),
            );
            self.with_mls_group(&group_id, |mls| {
                crate::group_lifecycle::build_group_context_snapshot(mls, &provider)
            })
        })?;
        let position = if let Some(position) = position {
            position
        } else {
            if channel.outbound.len() > MAX_HISTORY_CHUNKS as usize {
                return Err(refused());
            }
            let payload = cgka_traits::app_event::MarmotAppEvent::new(
                hex::encode(self.identity.self_id().as_slice()),
                0,
                HISTORY_CONTROL_KIND,
                vec![],
                String::from_utf8(wire).map_err(|_| refused())?,
            )
            .encode()
            .map_err(|_| refused())?;
            if payload.len() > MAX_HISTORY_CONTROL_BYTES {
                return Err(refused());
            }
            let encrypted = self.storage.with_transaction(|storage| {
                self.history_channel_fresh(channel)?;
                let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
                    &self.crypto,
                    storage.mls_storage(),
                );
                let mut group = MlsGroup::load(
                    provider.storage(),
                    &openmls::group::GroupId::from_slice(group_id.as_slice()),
                )
                .map_err(|_| refused())?
                .ok_or_else(refused)?;
                let bytes = group
                    .create_message(&provider, &self.identity.signer, &payload)
                    .map_err(|_| refused())?
                    .tls_serialize_detached()
                    .map_err(|_| refused())?;
                self.history_channel_fresh(channel)?;
                Ok::<_, EngineError>(bytes)
            });
            self.mls_group_cache.forget_group(&group_id);
            channel.outbound.push(FrozenHistoryControl {
                kind,
                ciphertext: encrypted?,
                wrapped: None,
            });
            channel.outbound.len() - 1
        };
        let payload = cgka_traits::EncryptedPayload {
            ciphertext: channel.outbound[position].ciphertext.clone(),
            aad: vec![],
        };
        let remaining = channel.deadline.saturating_duration_since(Instant::now());
        let mut operation = self.peeler.wrap_group_message(&payload, &context);
        let wrapping = std::future::poll_fn(|cx| {
            if let Err(error) = channel.live() {
                return std::task::Poll::Ready(Err(error));
            }
            operation
                .as_mut()
                .poll(cx)
                .map(|result| result.map_err(EngineError::Peeler))
        });
        let wrapped = crate::deadline::timeout(remaining, wrapping)
            .await
            .map_err(|_| refused())??;
        self.history_channel_fresh(channel)?;
        let wrapped = crate::message_processor::route_wrapped_group_message(wrapped, &context);
        channel.outbound[position].wrapped = Some(wrapped.clone());
        Ok(wrapped)
    }
}
