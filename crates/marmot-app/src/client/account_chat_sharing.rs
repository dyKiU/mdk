//! Real protected-source intake and original pair-wide policy custody.
use super::AppClient;
pub(crate) mod automatic;
mod presentation;
use crate::{
    AccountSharingError,
    account_chat_sharing::enabled::{Entry, MAX_OWNERS, OriginalLease, State},
};
use cgka_engine::account_chat_sharing::{ACCOUNT_SHARING_CONTROL_KIND, AccountSharingControl};
use cgka_traits::{GroupEvent, StorageProvider, app_event::MarmotAppEvent};
#[cfg(all(test, feature = "test-policy-overrides"))]
use sha2::Digest as _;
use std::sync::Arc;
impl AppClient {
    pub(crate) fn account_sharing_targets(
        &self,
    ) -> Result<crate::AccountSharingTargets, AccountSharingError> {
        let protected = self
            .runtime
            .session()
            .private_transport_evidence(crate::NOSTR_ROUTING_COMPONENT_ID)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?
            .ok_or(AccountSharingError::NotReady)?
            .group_id()
            .clone();
        let current = self
            .runtime
            .session()
            .account_chat_sharing_targets(&protected)
            .map_err(|_| AccountSharingError::NotReady)?;
        Ok(crate::AccountSharingTargets {
            protected_group: current.protected_group,
            protected_epoch: current.protected_epoch,
            targets: current
                .targets
                .into_iter()
                .map(|target| crate::AccountSharingTarget {
                    leaf_index: target.leaf_index,
                    device: target.device,
                })
                .collect(),
        })
    }

    pub(crate) fn begin_existing_pair_sharing(
        &mut self,
        recipient: &[u8],
    ) -> Result<Arc<State>, AccountSharingError> {
        if self.account_sharing_owner.seen.len() >= MAX_OWNERS {
            return Err(AccountSharingError::NotReady);
        }
        let protected = self
            .runtime
            .session()
            .private_transport_evidence(crate::NOSTR_ROUTING_COMPONENT_ID)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?
            .ok_or(AccountSharingError::NotReady)?
            .group_id()
            .clone();
        let mut approval_id = [0; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut approval_id);
        #[cfg(all(test, feature = "test-policy-overrides"))]
        let original = self
            .account_sharing_owner
            .next_original_lifetime_for_test
            .take()
            .map_or_else(
                || State::new(&self.account_sharing_owner.lifetime, approval_id),
                |lifetime| {
                    State::new_until(
                        &self.account_sharing_owner.lifetime,
                        approval_id,
                        std::time::Instant::now() + lifetime,
                    )
                },
            );
        #[cfg(not(all(test, feature = "test-policy-overrides")))]
        let original = State::new(&self.account_sharing_owner.lifetime, approval_id);
        let channel = self
            .runtime
            .session()
            .begin_account_sharing_policy(
                &protected,
                recipient,
                Arc::new(OriginalLease(Arc::downgrade(&original))),
            )
            .map_err(|_| AccountSharingError::NotReady)?;
        let nonce = channel.scope().nonce;
        self.account_sharing_owner.seen.insert(nonce);
        self.account_sharing_owner.entries.insert(
            nonce,
            Entry {
                original: Arc::downgrade(&original),
                pending: None,
                request: None,
                channel: Some(channel),
                recipient: false,
                consent_ready: false,
            },
        );
        Ok(original)
    }
    pub(crate) fn observe_account_sharing_control(
        &mut self,
        event: &GroupEvent,
    ) -> Result<(), AccountSharingError> {
        #[cfg(all(test, feature = "test-policy-overrides"))]
        self.observe_sibling_event_diagnostic_for_test(event);
        let GroupEvent::MessageReceived {
            group_id,
            source_leaf: Some(source),
            payload,
            ..
        } = event
        else {
            return Ok(());
        };
        let Ok(app) = MarmotAppEvent::decode(payload) else {
            return Ok(());
        };
        if app.kind != ACCOUNT_SHARING_CONTROL_KIND {
            return Ok(());
        }
        let wire = app.content.as_bytes();
        #[cfg(all(test, feature = "test-policy-overrides"))]
        self.test_trace_catalog_stage("outer_intake", "private_control", None);
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let GroupEvent::MessageReceived { message_id, .. } = event {
            automatic::consent_delivery_probe::event_received(
                self.app.account_home().root(),
                group_id,
                message_id,
                source,
                sha2::Sha256::digest(wire).into(),
            );
        }
        let received = ingest_phase_sync!(
            4,
            self.authenticate_sharing_control_intake(group_id, source, wire)
        );
        #[cfg(all(test, feature = "test-policy-overrides"))]
        automatic::consent_delivery_probe::authenticated(
            self.app.account_home().root(),
            group_id,
            source,
            sha2::Sha256::digest(wire).into(),
            received.as_ref().ok(),
            match &received {
                Ok(_) => automatic::consent_delivery_probe::Outcome::Success,
                Err(AccountSharingError::NotReady) => {
                    automatic::consent_delivery_probe::Outcome::NotReady
                }
                Err(AccountSharingError::Closed) => {
                    automatic::consent_delivery_probe::Outcome::Closed
                }
                Err(AccountSharingError::RuntimeUnavailable) => {
                    automatic::consent_delivery_probe::Outcome::RuntimeUnavailable
                }
                Err(_) => automatic::consent_delivery_probe::Outcome::Refused,
            },
        );

        let received = match received {
            Ok(received) => received,
            Err(error) => {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                self.test_trace_catalog_stage(
                    "outer_authentication",
                    automatic::diagnostics::sharing_category(&error),
                    None,
                );
                if self.retain_pending_sibling_control(group_id, source, wire) {
                    #[cfg(all(test, feature = "test-policy-overrides"))]
                    self.test_trace_catalog_stage("outer_retention", "auth_failure_retained", None);
                    return Ok(());
                }
                return Err(error);
            }
        };
        #[cfg(all(test, feature = "test-policy-overrides"))]
        automatic::records_cut_acceptance::observe_authenticated_records(
            self.app.account_home().root(),
            event,
            &received,
        );
        #[cfg(all(test, feature = "test-policy-overrides"))]
        let Some(received) = self.test_defer_delayed_higher_request(wire, received) else {
            return Ok(());
        };
        let result = self.dispatch_authenticated_account_sharing_control(&received, wire);
        #[cfg(all(test, feature = "test-policy-overrides"))]
        automatic::consent_delivery_probe::dispatched(
            self.app.account_home().root(),
            &received,
            sha2::Sha256::digest(wire).into(),
            Self::test_consent_outcome(&result),
        );
        if result.is_err() && self.retain_pending_sibling_control(group_id, source, wire) {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.test_trace_catalog_stage("outer_retention", "dispatch_failure_retained", None);
            return Ok(());
        }
        result
    }
    /// Retry only an actual Core-authenticated observation; this creates no grant.
    pub(crate) fn dispatch_authenticated_account_sharing_control(
        &mut self,
        received: &cgka_engine::account_chat_sharing::ReceivedAccountSharingControl,
        wire: &[u8],
    ) -> Result<(), AccountSharingError> {
        let sibling = ingest_phase_sync!(5, self.observe_sibling_sharing_control(received, wire));
        #[cfg(all(test, feature = "test-policy-overrides"))]
        self.test_trace_catalog_stage(
            "sibling_dispatch",
            match &sibling {
                Ok(true) => "consumed",
                Ok(false) => "not_consumed",
                Err(error) => automatic::diagnostics::sharing_category(error),
            },
            None,
        );
        if sibling? {
            return Ok(());
        }
        let automatic =
            ingest_phase_sync!(6, self.observe_automatic_sharing_control(received, wire));
        #[cfg(all(test, feature = "test-policy-overrides"))]
        self.test_trace_catalog_stage(
            "automatic_dispatch_result",
            match &automatic {
                Ok(true) => "consumed",
                Ok(false) => "not_consumed",
                Err(error) => automatic::diagnostics::sharing_category(error),
            },
            None,
        );
        if automatic? {
            return Ok(());
        }
        match received.control {
            AccountSharingControl::Request => {
                if self.account_sharing_owner.seen.contains(&received.nonce) {
                    return Ok(());
                }
                let Ok(request) = self
                    .runtime
                    .session()
                    .authenticate_account_sharing_request(wire)
                else {
                    return Ok(());
                };
                if self.account_sharing_owner.seen.len() >= MAX_OWNERS {
                    return Err(AccountSharingError::NotReady);
                }
                let original = State::new(
                    &self.account_sharing_owner.lifetime,
                    request.scope().approval_id,
                );
                *original.scope.lock().expect("sharing scope") = Some(request.scope().clone());
                self.account_sharing_owner.seen.insert(received.nonce);
                self.account_sharing_owner.entries.insert(
                    received.nonce,
                    Entry {
                        original: Arc::downgrade(&original),
                        pending: Some(original),
                        request: Some(request),
                        channel: None,
                        recipient: true,
                        consent_ready: false,
                    },
                );
            }
            AccountSharingControl::Consent => {
                let Some(entry) = self.account_sharing_owner.entries.get_mut(&received.nonce)
                else {
                    return Ok(());
                };
                if entry.recipient || !entry.original.upgrade().is_some_and(|x| x.live()) {
                    return Ok(());
                }
                let channel = entry
                    .channel
                    .as_mut()
                    .ok_or(AccountSharingError::NotReady)?;
                self.runtime
                    .session()
                    .bind_account_sharing_consent(channel, wire)
                    .map_err(|_| AccountSharingError::NotReady)?;
                entry.consent_ready = true;
            }
            AccountSharingControl::Body(_) => {}
        }
        Ok(())
    }
    pub(crate) async fn approve_existing_pair_sharing(
        &mut self,
        original: &Arc<State>,
        revision: u64,
    ) -> Result<(), AccountSharingError> {
        original.check(revision)?;
        let scope = original
            .scope
            .lock()
            .expect("sharing scope")
            .clone()
            .ok_or(AccountSharingError::NotReady)?;
        let mut entry = self
            .account_sharing_owner
            .entries
            .remove(&scope.nonce)
            .ok_or(AccountSharingError::Closed)?;
        let result=async {
 if !entry.original.upgrade().is_some_and(|x|Arc::ptr_eq(&x,original)){return Err(AccountSharingError::Closed)}
 if entry.recipient&&entry.channel.is_none(){
 entry.channel=Some(self.runtime.session().approve_account_sharing_policy(entry.request.as_ref().ok_or(AccountSharingError::NotReady)?,Arc::new(OriginalLease(Arc::downgrade(original)))).map_err(|_|AccountSharingError::NotReady)?);
 }
 let channel=entry.channel.as_mut().ok_or(AccountSharingError::NotReady)?;
 if original.legacy_capture.lock().expect("legacy capture").is_none(){
 let capture=self.capture_legacy_chats(&||{
 original.check(revision).map_err(|_|cgka_traits::storage::StorageError::Serialization("sharing original unavailable".into()))?;
 self.runtime.session().validate_account_sharing_channel(channel).map_err(|_|cgka_traits::storage::StorageError::Serialization("sharing original changed".into()))
 }).map_err(|_|AccountSharingError::RuntimeUnavailable)?;
 *original.legacy_capture.lock().expect("legacy capture")=Some(capture);
 }
 {let mut p=original.progress.lock().expect("sharing progress");if !p.approved {p.approved=true;p.revision+=1;}}
 let kind=if entry.recipient{AccountSharingControl::Consent}else{AccountSharingControl::Request};
 let message=self.runtime.session_mut().wrap_account_sharing_control(channel,kind).await.map_err(|_|AccountSharingError::NotReady)?;
 if !original.live(){return Err(AccountSharingError::Closed)}
 let evidence=self.runtime.session().private_transport_evidence(crate::NOSTR_ROUTING_COMPONENT_ID).map_err(|_|AccountSharingError::RuntimeUnavailable)?.ok_or(AccountSharingError::NotReady)?;
 if evidence.group_id()!=&scope.protected.group_id{return Err(AccountSharingError::Closed)}
 let route=cgka_traits::app_components::decode_nostr_routing_v1(evidence.component()).map_err(|_|AccountSharingError::NotReady)?;
 let request=cgka_traits::TransportPublishRequest{account_id:self.runtime.session().self_id(),message,target:cgka_traits::TransportPublishTarget::Group{group_id:evidence.group_id().clone(),transport_group_id:route.nostr_group_id.to_vec(),endpoints:route.relays.into_iter().map(cgka_traits::TransportEndpoint).collect()},required_acks:1};
 let revoked=original.revoked.notified();tokio::pin!(revoked);revoked.as_mut().enable();if !original.live(){return Err(AccountSharingError::Closed)}
 tokio::select!{biased;()=&mut revoked=>return Err(AccountSharingError::Closed),()=tokio::time::sleep_until(original.deadline.into())=>return Err(AccountSharingError::Closed),report=self.adapter.publish_selected_chat(request)=>{let report=report.map_err(|_|AccountSharingError::RuntimeUnavailable)?;if !report.met_required_acks(){return Err(AccountSharingError::NotReady)}}}
 self.runtime.session().validate_account_sharing_channel(channel).map_err(|_|AccountSharingError::Closed)?;
 if entry.recipient{entry.consent_ready=true;self.persist_existing_pair_policy(original,channel,true)?;}
 Ok(())
 }.await;
        self.account_sharing_owner
            .entries
            .insert(scope.nonce, entry);
        result
    }
    fn persist_existing_pair_policy(
        &self,
        original: &Arc<State>,
        channel: &cgka_engine::account_chat_sharing::OwnedAccountSharingChannel,
        recipient: bool,
    ) -> Result<(), AccountSharingError> {
        if !original.live() {
            return Err(AccountSharingError::Closed);
        }
        channel
            .policy_digest()
            .map_err(|_| AccountSharingError::NotReady)?;
        let scope = channel.scope();
        let local = if recipient {
            scope.recipient.clone()
        } else {
            scope.source.clone()
        };
        let peer = if local == scope.source {
            &scope.recipient
        } else {
            &scope.source
        };
        let policy = cgka_traits::approved_account_sharing_policy::ApprovedAccountSharingPolicy {
            account: scope
                .protected
                .account
                .as_slice()
                .try_into()
                .map_err(|_| AccountSharingError::NotReady)?,
            local_device: local
                .as_slice()
                .try_into()
                .map_err(|_| AccountSharingError::NotReady)?,
            peer_device: peer
                .as_slice()
                .try_into()
                .map_err(|_| AccountSharingError::NotReady)?,
            protected_group: scope.protected.group_id.clone(),
            approval_id: scope.approval_id,
            version: 1,
            capabilities: 0x0f,
            created_at: original.created_at,
            approved_protected_epoch: scope.protected.epoch.0,
            revoked: false,
        };
        let validate = || {
            if !original.live() {
                return Err(cgka_traits::storage::StorageError::Serialization(
                    "sharing original closed".into(),
                ));
            }
            self.runtime
                .session()
                .validate_account_sharing_channel(channel)
                .map_err(|_| {
                    cgka_traits::storage::StorageError::Serialization(
                        "sharing original changed".into(),
                    )
                })
        };
        let capture = original
            .legacy_capture
            .lock()
            .expect("legacy capture")
            .as_ref()
            .cloned()
            .ok_or(AccountSharingError::NotReady)?;
        self.commit_policy_with_legacy_chats(&policy, &capture, &validate)
            .map_err(|_| AccountSharingError::RuntimeUnavailable)?;
        let mut p = original.progress.lock().expect("sharing progress");
        if !p.complete {
            p.complete = true;
            p.revision += 1;
        }
        Ok(())
    }
    pub(crate) fn maintain_existing_pair_sharing(&mut self) -> Result<(), AccountSharingError> {
        let nonces: Vec<_> = self.account_sharing_owner.entries.keys().copied().collect();
        for nonce in nonces {
            let Some(entry) = self.account_sharing_owner.entries.remove(&nonce) else {
                continue;
            };
            let live = entry.original.upgrade().filter(|x| x.live());
            if let Some(original) = live {
                let result = if entry.consent_ready {
                    self.persist_existing_pair_policy(
                        &original,
                        entry
                            .channel
                            .as_ref()
                            .ok_or(AccountSharingError::NotReady)?,
                        entry.recipient,
                    )
                } else {
                    Ok(())
                };
                self.account_sharing_owner.entries.insert(nonce, entry);
                result?;
            }
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "test-policy-overrides"))]
pub(crate) use automatic::departure_replay_probe::DepartureReplayProbe;

#[cfg(all(test, feature = "test-policy-overrides"))]
pub(crate) use automatic::duplicate_departure_probe::{
    DuplicateDepartureBinding, DuplicateDepartureProbe,
};
