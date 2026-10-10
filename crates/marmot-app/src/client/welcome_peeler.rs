//! Actual account Welcome peeling; transport provenance can only narrow an
//! original selected consent, and remains independent of optional audit rows.
use async_trait::async_trait;
#[cfg(feature = "experimental-device-sync")]
use cgka_traits::MessageId;
use cgka_traits::TransportMessage;
use cgka_traits::error::PeelerError;
use cgka_traits::ingest::PeeledMessage;
use cgka_traits::peeler::TransportPeeler;
use transport_nostr_peeler::{NostrMlsPeeler, WelcomePeelProvenance};

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub(crate) trait WelcomePeeler: TransportPeeler {
    async fn peel_welcome_with_provenance(
        &self,
        message: &TransportMessage,
    ) -> Result<(PeeledMessage, WelcomePeelProvenance), PeelerError>;
}
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl WelcomePeeler for NostrMlsPeeler {
    async fn peel_welcome_with_provenance(
        &self,
        message: &TransportMessage,
    ) -> Result<(PeeledMessage, WelcomePeelProvenance), PeelerError> {
        NostrMlsPeeler::peel_welcome_with_provenance(self, message).await
    }
}

#[cfg(feature = "experimental-device-sync")]
mod selected {
    use super::*;
    use cgka_traits::engine::WelcomeMetadata;
    use cgka_traits::group_context::GroupContextSnapshot;
    use cgka_traits::peeler::GroupMessageMetadata;
    use cgka_traits::transport::EncryptedPayload;
    use cgka_traits::types::MemberId;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    pub(crate) struct SelectedWelcomeProvenance {
        source: Option<MessageId>,
        authenticated: Option<WelcomePeelProvenance>,
    }
    pub(crate) struct WelcomeEpisode(Arc<Mutex<SelectedWelcomeProvenance>>);
    impl Drop for WelcomeEpisode {
        fn drop(&mut self) {
            let mut slot = self.0.lock().expect("selected Welcome episode");
            slot.source = None;
            slot.authenticated = None;
        }
    }
    impl SelectedWelcomeProvenance {
        pub(crate) fn begin(slot: &Arc<Mutex<Self>>, source: &MessageId) -> WelcomeEpisode {
            let mut value = slot.lock().expect("selected Welcome episode");
            value.source = Some(source.clone());
            value.authenticated = None;
            WelcomeEpisode(slot.clone())
        }
        pub(crate) fn matches(&self, expected: &[u8; 32]) -> bool {
            self.source.is_some()
                && self
                    .authenticated
                    .as_ref()
                    .is_some_and(|actual| &actual.key_package_event_id == expected)
        }
    }
    pub(crate) struct SelectedWelcomePeeler {
        pub(crate) inner: NostrMlsPeeler,
        pub(crate) slot: Arc<Mutex<SelectedWelcomeProvenance>>,
    }
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl WelcomePeeler for SelectedWelcomePeeler {
        async fn peel_welcome_with_provenance(
            &self,
            message: &TransportMessage,
        ) -> Result<(PeeledMessage, WelcomePeelProvenance), PeelerError> {
            let result = self.inner.peel_welcome_with_provenance(message).await;
            let mut slot = self.slot.lock().map_err(|_| {
                PeelerError::Backend("selected Welcome provenance unavailable".into())
            })?;
            if slot.source.as_ref() == Some(&message.id) {
                slot.authenticated = result
                    .as_ref()
                    .ok()
                    .map(|(_, provenance)| provenance.clone());
            }
            result
        }
    }
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl TransportPeeler for SelectedWelcomePeeler {
        #[cfg(feature = "experimental-device-sync")]
        async fn observe_private_linking_welcome(
            &self,
            message: &TransportMessage,
        ) -> Result<cgka_traits::peeler::PrivateLinkingWelcomeObservation, PeelerError> {
            self.inner.observe_private_linking_welcome(message).await
        }

        #[cfg(feature = "experimental-device-sync")]
        async fn peel_private_linking_welcome_batch(
            &self,
            messages: &[TransportMessage],
            context: &cgka_traits::peeler::PrivateLinkingWelcomeContext,
        ) -> Result<Vec<u8>, PeelerError> {
            self.inner
                .peel_private_linking_welcome_batch(messages, context)
                .await
        }

        #[cfg(feature = "experimental-device-sync")]
        async fn wrap_private_linking_welcome(
            &self,
            payload: &EncryptedPayload,
            context: &cgka_traits::peeler::PrivateLinkingWelcomeContext,
        ) -> Result<Vec<TransportMessage>, PeelerError> {
            self.inner
                .wrap_private_linking_welcome(payload, context)
                .await
        }

        async fn peel_group_message(
            &self,
            msg: &TransportMessage,
            ctx: &GroupContextSnapshot,
        ) -> Result<PeeledMessage, PeelerError> {
            self.inner.peel_group_message(msg, ctx).await
        }

        async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
            self.peel_welcome_with_provenance(msg)
                .await
                .map(|(peeled, _)| peeled)
        }

        async fn wrap_group_message(
            &self,
            payload: &EncryptedPayload,
            ctx: &GroupContextSnapshot,
        ) -> Result<TransportMessage, PeelerError> {
            self.inner.wrap_group_message(payload, ctx).await
        }

        async fn wrap_group_message_with_metadata(
            &self,
            payload: &EncryptedPayload,
            ctx: &GroupContextSnapshot,
            metadata: &GroupMessageMetadata,
        ) -> Result<TransportMessage, PeelerError> {
            self.inner
                .wrap_group_message_with_metadata(payload, ctx, metadata)
                .await
        }

        async fn wrap_welcome(
            &self,
            payload: &EncryptedPayload,
            recipient: &MemberId,
        ) -> Result<TransportMessage, PeelerError> {
            self.inner.wrap_welcome(payload, recipient).await
        }

        async fn wrap_welcome_with_metadata(
            &self,
            payload: &EncryptedPayload,
            recipient: &MemberId,
            metadata: &WelcomeMetadata,
        ) -> Result<TransportMessage, PeelerError> {
            self.inner
                .wrap_welcome_with_metadata(payload, recipient, metadata)
                .await
        }
    }
}
#[cfg(feature = "experimental-device-sync")]
pub(crate) use selected::{SelectedWelcomePeeler, SelectedWelcomeProvenance};
