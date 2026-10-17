//! Exact original sharing controls over the real protected MLS send ratchet.
use super::*;
use cgka_traits::TransportMessage;
use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider;
use tls_codec::Serialize;

pub(super) struct FrozenSharingControl {
    kind: AccountSharingControl,
    ciphertext: Vec<u8>,
    wrapped: Option<TransportMessage>,
    #[cfg(feature = "test-policy-overrides")]
    control_wire_digest: [u8; 32],
}
impl OwnedAccountSharingChannel {
    // RECIPIENT_ADMISSION_TEST_BEGIN
    /// Pure test observation of the actual already-wrapped transport identity.
    #[cfg(feature = "test-policy-overrides")]
    pub fn outbound_transport_message_id_for_test(
        &self,
        kind: AccountSharingControl,
    ) -> Option<cgka_traits::MessageId> {
        self.outbound
            .iter()
            .find(|entry| entry.kind == kind)
            .and_then(|entry| entry.wrapped.as_ref())
            .map(|message| message.id.clone())
    }
    // RECIPIENT_ADMISSION_TEST_END
    /// Test observation of already-frozen MLS bytes, never permission evidence.
    #[cfg(feature = "test-policy-overrides")]
    pub fn outbound_content_id_for_test(
        &self,
        kind: AccountSharingControl,
    ) -> Option<cgka_traits::MessageId> {
        self.outbound
            .iter()
            .find(|entry| entry.kind == kind)
            .map(|entry| crate::message_processor::content_dedup_id(&entry.ciphertext))
    }
    /// Read-only identity of the already-produced, authenticated control wire.
    #[cfg(feature = "test-policy-overrides")]
    pub fn outbound_control_wire_digest_for_test(
        &self,
        kind: AccountSharingControl,
    ) -> Option<[u8; 32]> {
        self.outbound
            .iter()
            .find(|entry| entry.kind == kind)
            .map(|entry| entry.control_wire_digest)
    }

    fn control_wire(&self, kind: AccountSharingControl) -> Result<Vec<u8>, EngineError> {
        self.live()?;
        match (self.recipient_role, kind) {
            (false, AccountSharingControl::Request) => Ok(self.request.clone()),
            (true, AccountSharingControl::Consent) => self.consent.clone().ok_or_else(refused),
            (_, AccountSharingControl::Body(sequence)) => self
                .sealed
                .get(&sequence)
                .map(|(_, _, wire)| wire.clone())
                .ok_or_else(refused),
            _ => Err(refused()),
        }
    }
}
impl<S: StorageProvider> Engine<S> {
    /// Freeze the actual send ratchet once under the same original lease. Every
    /// retry revalidates actual trees/generations and retains exact ciphertext.
    pub async fn wrap_account_sharing_control(
        &mut self,
        channel: &mut OwnedAccountSharingChannel,
        kind: AccountSharingControl,
    ) -> Result<TransportMessage, EngineError> {
        self.sharing_channel_fresh(channel)?;
        let wire = channel.control_wire(kind)?;
        let frame = self.sharing_verify(&wire)?;
        Self::sharing_fixed_context(&frame, &channel.scope)?;
        if frame.signer != self.identity.signer.public()
            || frame.generation != channel.scope.local_generation
        {
            return Err(refused());
        }
        #[cfg(feature = "test-policy-overrides")]
        let control_wire_digest: [u8; 32] = Sha256::digest(&wire).into();
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
            if channel.outbound.len() > MAX_ORIGINAL_BODIES + 1 {
                return Err(refused());
            }
            let payload = cgka_traits::app_event::MarmotAppEvent::new(
                hex::encode(self.identity.self_id().as_slice()),
                0,
                ACCOUNT_SHARING_CONTROL_KIND,
                vec![],
                String::from_utf8(wire).map_err(|_| refused())?,
            )
            .encode()
            .map_err(|_| refused())?;
            if payload.len() > MAX_WIRE_BYTES {
                return Err(refused());
            }
            let encrypted = self.storage.with_transaction(|storage| {
                self.sharing_channel_fresh(channel)?;
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
                self.sharing_channel_fresh(channel)?;
                Ok::<_, EngineError>(bytes)
            });
            self.mls_group_cache.forget_group(&group_id);
            channel.outbound.push(FrozenSharingControl {
                kind,
                ciphertext: encrypted?,
                wrapped: None,
                #[cfg(feature = "test-policy-overrides")]
                control_wire_digest,
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
        self.sharing_channel_fresh(channel)?;
        let wrapped = crate::message_processor::route_wrapped_group_message(wrapped, &context);
        channel.outbound[position].wrapped = Some(wrapped.clone());
        Ok(wrapped)
    }
}
