use super::AppClient;
use crate::selected_chat_copy::{
    SelectedChatCopyError,
    enabled::{PreparedSelectedInvite, RequestState},
};
use cgka_engine::selected_chat_consent::{
    AuthenticatedSelectedChatOffer, AuthenticatedSelectedChatRequest, SelectedChatInviteLease,
};
use cgka_traits::{
    EngineError, SendResult, TransportEnvelope, TransportPublishRequest, TransportPublishTarget,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

struct OriginalInviteLease {
    original: Arc<RequestState>,
    revision: u64,
}
impl SelectedChatInviteLease for OriginalInviteLease {
    fn key_package_event_id(
        &mut self,
        request: &AuthenticatedSelectedChatRequest,
        offer: &AuthenticatedSelectedChatOffer,
    ) -> Result<cgka_traits::MessageId, EngineError> {
        self.original
            .check_live_revision(self.revision)
            .map_err(|_| EngineError::Other("selected chat original owner unavailable".into()))?;
        let progress = self
            .original
            .progress
            .lock()
            .expect("selected package transport identity");
        let binding: [u8; 32] = Sha256::digest(progress.packet.as_ref().ok_or_else(|| {
            EngineError::Other("selected chat original owner unavailable".into())
        })?)
        .into();
        let stored = progress
            .offers
            .get(&offer.source_index())
            .filter(|stored| {
                binding == request.binding() && std::ptr::eq(stored.observation.as_ref(), offer)
            })
            .ok_or_else(|| EngineError::Other("selected chat original owner unavailable".into()))?;
        Ok(stored.package_event_id.clone())
    }

    fn check_original(
        &mut self,
        request: &AuthenticatedSelectedChatRequest,
        offers: &[&AuthenticatedSelectedChatOffer],
    ) -> Result<(), EngineError> {
        let denied = || EngineError::Other("selected chat original owner unavailable".into());
        self.original
            .check_live_revision(self.revision)
            .map_err(|_| denied())?;
        let progress = self
            .original
            .progress
            .lock()
            .expect("selected original lease");
        let packet = progress.packet.as_ref().ok_or_else(denied)?;
        let binding: [u8; 32] = Sha256::digest(packet).into();
        if binding != request.binding()
            || offers.len() != progress.offers.len()
            || offers.len() != self.original._protected.leaves.len().saturating_sub(1)
            || offers.iter().any(|offer| {
                !progress
                    .offers
                    .get(&offer.source_index())
                    .is_some_and(|stored| std::ptr::eq(stored.observation.as_ref(), *offer))
            })
        {
            return Err(denied());
        }
        Ok(())
    }
}
impl AppClient {
    pub(crate) async fn maintain_selected_chat_pending(
        &mut self,
    ) -> Result<(), cgka_session::SessionError> {
        for (pending, origin, group) in self.selected_chat_copy_owner.pending_to_retire() {
            self.runtime
                .session_mut()
                .retire_selected_chat_pending(pending, &origin, &group)
                .await?;
            self.selected_chat_copy_owner.clear_pending_cleanup(pending);
        }
        Ok(())
    }
    pub(crate) async fn selected_request_continue(
        &mut self,
        original: &Arc<RequestState>,
        revision: u64,
    ) -> Result<(), SelectedChatCopyError> {
        if !self.selected_chat_copy_owner.owns(original) {
            return Err(SelectedChatCopyError::Closed);
        }
        original.check_live_revision(revision)?;
        let (packet, mut offers, prepared) = {
            let progress = original
                .progress
                .lock()
                .expect("selected original publication");
            (
                progress
                    .packet
                    .clone()
                    .ok_or(SelectedChatCopyError::NotReady)?,
                progress
                    .offers
                    .values()
                    .map(|offer| offer.observation.clone())
                    .collect::<Vec<_>>(),
                progress.invite.is_some(),
            )
        };
        offers.sort_by_key(|offer| offer.source_index());
        if offers.len() != original._protected.leaves.len().saturating_sub(1) {
            return Err(SelectedChatCopyError::NotReady);
        }
        let observation = self
            .runtime
            .session()
            .authenticate_selected_chat_request(&packet)?;
        let borrowed: Vec<_> = offers.iter().map(Arc::as_ref).collect();
        let mut lease = OriginalInviteLease {
            original: original.clone(),
            revision,
        };
        lease.check_original(&observation, &borrowed)?;
        if !prepared {
            self.fresh_selected_request(original, revision)?;
            self.selected_chat_copy_owner.check_pending_capacity()?;
            let result = self
                .runtime
                .session_mut()
                .prepare_selected_chat_invite(&observation, &borrowed, &mut lease)
                .await?;
            let SendResult::GroupEvolution {
                msg,
                welcomes,
                pending,
            } = result
            else {
                return Err(SelectedChatCopyError::NotReady);
            };
            let origin = msg.id.clone();
            self.selected_chat_copy_owner.register_pending_cleanup(
                original,
                pending,
                origin.clone(),
                observation.ordinary_group(),
            )?;
            original
                .progress
                .lock()
                .expect("selected prepared invite")
                .invite = Some(PreparedSelectedInvite {
                pending,
                origin,
                message: msg,
                welcomes,
                commit_report: None,
                confirmed_effects: None,
                confirmed: false,
                next_welcome: 0,
            });
        }
        let component = self
            .runtime
            .session()
            .app_component(
                &observation.ordinary_group(),
                crate::NOSTR_ROUTING_COMPONENT_ID,
            )?
            .ok_or(SelectedChatCopyError::InvalidSelection)?;
        let route = cgka_traits::app_components::decode_nostr_routing_v1(&component)
            .map_err(|_| SelectedChatCopyError::InvalidSelection)?;
        let endpoints: Vec<_> = route
            .relays
            .into_iter()
            .map(cgka_traits::TransportEndpoint)
            .collect();
        let (pending, origin, message, acknowledged, confirmed) = {
            let p = original
                .progress
                .lock()
                .expect("selected prepared publication");
            let invite = p.invite.as_ref().ok_or(SelectedChatCopyError::NotReady)?;
            (
                invite.pending,
                invite.origin.clone(),
                invite.message.clone(),
                invite.commit_report.is_some(),
                invite.confirmed,
            )
        };
        if !confirmed {
            lease.check_original(&observation, &borrowed)?;
            self.runtime
                .session()
                .validate_prepared_selected_chat_invite(
                    &observation,
                    &borrowed,
                    pending,
                    &origin,
                )?;
            if !acknowledged {
                let report = self
                    .adapter
                    .publish_selected_chat(TransportPublishRequest {
                        account_id: self.runtime.session().self_id(),
                        message,
                        target: TransportPublishTarget::Group {
                            group_id: observation.ordinary_group(),
                            transport_group_id: route.nostr_group_id.to_vec(),
                            endpoints: endpoints.clone(),
                        },
                        required_acks: 1,
                    })
                    .await
                    .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?;
                lease.check_original(&observation, &borrowed)?;
                if !report.met_required_acks() {
                    return Err(SelectedChatCopyError::RuntimeUnavailable);
                }
                original
                    .progress
                    .lock()
                    .expect("selected commit ack")
                    .invite
                    .as_mut()
                    .unwrap()
                    .commit_report = Some(report);
            }
            self.runtime
                .session()
                .validate_prepared_selected_chat_invite(
                    &observation,
                    &borrowed,
                    pending,
                    &origin,
                )?;
            lease.check_original(&observation, &borrowed)?;
            // Ordinary publish-before-apply confirmation, independent of private
            // protected-group echo rules. Never release Welcome on an ACK alone.
            let effects = self
                .runtime
                .session_mut()
                .confirm_published(pending)
                .await?;
            // Keep the actual successful confirmation in the original memory
            // before any fallible read; a SQL read retry must not re-confirm an
            // already consumed pending reference. No Welcome permission here.
            lease.check_original(&observation, &borrowed)?;
            {
                let mut progress = original.progress.lock().expect("selected confirmed invite");
                let invite = progress.invite.as_mut().unwrap();
                invite.confirmed = true;
                invite.confirmed_effects = Some(effects);
            }
            lease.revision = original.snapshot().revision;
            self.selected_chat_copy_owner.clear_pending_cleanup(pending);
        }
        let confirmed_effects = {
            let progress = original
                .progress
                .lock()
                .expect("selected original confirmed effects");
            let invite = progress.invite.as_ref().unwrap();
            invite
                .confirmed_effects
                .clone()
                .map(|effects| (effects, invite.commit_report.clone()))
        };
        if let Some((effects, report)) = confirmed_effects {
            // Retain unexpected publish work in the original memory rather than
            // silently dropping it or handing selected authority to a replay queue.
            if !effects.publish.is_empty() {
                return Err(SelectedChatCopyError::NotReady);
            }
            lease.check_original(&observation, &borrowed)?;
            let effects = marmot_account::AccountDeviceEffects {
                events: effects.events,
                queued: effects.queued,
                pending_convergence: effects.pending_convergence,
                reports: vec![report.ok_or(SelectedChatCopyError::NotReady)?],
                ..Default::default()
            };
            // Observe the actual outbound effects, including EpochChanged. The
            // native-only observer deliberately filters those ordinary chat events.
            // This projection queue carries facts, never selected publish authority.
            self.observe_send_applied_effects(&effects)
                .await
                .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?;
            self.save_state_with_pending_local_group_deletion_frontier_clears()
                .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?;
            original
                .progress
                .lock()
                .expect("selected observed effects")
                .invite
                .as_mut()
                .unwrap()
                .confirmed_effects = None;
            lease.check_original(&observation, &borrowed)?;
        }
        loop {
            lease.check_original(&observation, &borrowed)?;
            self.runtime
                .session()
                .confirmed_selected_chat_successor(&observation, &borrowed)?;
            let next = {
                let p = original
                    .progress
                    .lock()
                    .expect("selected original welcomes");
                let invite = p.invite.as_ref().unwrap();
                invite.welcomes.get(invite.next_welcome).cloned()
            };
            let Some(message) = next else {
                break;
            };
            let TransportEnvelope::Welcome { recipient } = &message.envelope else {
                return Err(SelectedChatCopyError::InvalidPacket);
            };
            if recipient != &self.runtime.session().self_id() {
                return Err(SelectedChatCopyError::InvalidPacket);
            }
            let target = TransportPublishTarget::Inbox {
                recipient: recipient.clone(),
                endpoints: endpoints.clone(),
            };
            let report = self
                .adapter
                .publish_selected_chat(TransportPublishRequest {
                    account_id: self.runtime.session().self_id(),
                    message,
                    target,
                    required_acks: 1,
                })
                .await
                .map_err(|_| SelectedChatCopyError::RuntimeUnavailable)?;
            lease.check_original(&observation, &borrowed)?;
            self.runtime
                .session()
                .confirmed_selected_chat_successor(&observation, &borrowed)?;
            if !report.met_required_acks() {
                return Err(SelectedChatCopyError::RuntimeUnavailable);
            }
            original
                .progress
                .lock()
                .expect("selected welcome ack")
                .invite
                .as_mut()
                .unwrap()
                .next_welcome += 1;
        }
        Ok(())
    }
}
