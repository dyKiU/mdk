//! Actual private MessageReceived intake; metadata cannot recreate consent or keys.
use super::AppClient;
mod archive;
use crate::history_transfer::{
    HistoryTransferError,
    enabled::{ChannelEntry, MAX_HISTORY_OWNERS, State},
};
use cgka_engine::history_transfer::{
    HISTORY_CONTROL_KIND, HistoryControl, MAX_HISTORY_CONTROL_BYTES,
};
use cgka_traits::{GroupEvent, app_event::MarmotAppEvent};
use sha2::Digest;
use std::sync::Arc;

impl AppClient {
    pub(crate) fn observe_history_control(
        &mut self,
        event: &GroupEvent,
    ) -> Result<(), HistoryTransferError> {
        let GroupEvent::MessageReceived {
            group_id,
            source_leaf: Some(source),
            payload,
            ..
        } = event
        else {
            return Ok(());
        };
        let Ok(app_event) = MarmotAppEvent::decode(payload) else {
            return Ok(());
        };
        if app_event.kind != HISTORY_CONTROL_KIND {
            return Ok(());
        }
        let wire = app_event.content.as_bytes();
        if wire.len() > MAX_HISTORY_CONTROL_BYTES {
            return Err(HistoryTransferError::NotReady);
        }
        let received = self
            .runtime
            .session()
            .authenticate_received_history_control(group_id, source, wire)
            .map_err(|_| HistoryTransferError::NotReady)?;
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if matches!(received.control, HistoryControl::Chunk(_)) {
            self.history_owner.authenticated_chunk_observations += 1;
        }
        if received.control == HistoryControl::Request {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            {
                self.history_owner.authenticated_request_observations += 1;
            }
            if self
                .history_owner
                .seen_transfers
                .contains(&received.transfer)
            {
                return Ok(());
            }
            if self.history_owner.seen_transfers.len() >= MAX_HISTORY_OWNERS {
                return Err(HistoryTransferError::NotReady);
            }
            let Ok(request) = self.runtime.session().authenticate_history_request(wire) else {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                {
                    self.history_owner.refused_original_requests += 1;
                }
                // Other genuine protected members can read the outer request;
                // only its exact recipient may construct an original action.
                return Ok(());
            };
            if request.scope().snapshot.is_none() {
                return Err(HistoryTransferError::NotReady);
            }
            let scope = request.scope();
            let account: [u8; 32] = scope
                .protected
                .account
                .as_slice()
                .try_into()
                .map_err(|_| HistoryTransferError::NotReady)?;
            let device: [u8; 32] = scope
                .recipient
                .as_slice()
                .try_into()
                .map_err(|_| HistoryTransferError::NotReady)?;
            let storage = self
                .app
                .account_storage(&self.state.label)
                .map_err(|_| HistoryTransferError::RuntimeUnavailable)?;
            if !storage
                .observe_synchronized_history_request(
                    &account,
                    &device,
                    &received.transfer,
                    &sha2::Sha256::digest(wire).into(),
                )
                .map_err(|_| HistoryTransferError::RuntimeUnavailable)?
            {
                return Ok(());
            }
            self.history_owner.seen_transfers.insert(received.transfer);
            let original = State::new(&self.history_owner.lifetime);
            *original
                .scope
                .lock()
                .expect("history authenticated request") = Some(request.scope().clone());
            self.history_owner.channels.insert(
                received.transfer,
                ChannelEntry {
                    original: Arc::downgrade(&original),
                    pending_original: Some(original),
                    request: Some(request),
                    channel: None,
                    archive: Vec::new(),
                    next_chunk: 0,
                    complete: false,
                    continue_reply: None,
                    receipt_to_publish: None,
                    staging: None,
                    max_record_lifetime_seconds: None,
                    incoming: Default::default(),
                },
            );
        } else if let Some(entry) = self.history_owner.channels.get_mut(&received.transfer) {
            if entry
                .original
                .upgrade()
                .is_none_or(|original| !original.live())
            {
                return Ok(());
            }
            if entry
                .incoming
                .iter()
                .any(|(kind, pending)| *kind == received.control && pending.as_slice() == wire)
            {
                return Ok(());
            }
            if entry.incoming.len() >= 128 {
                return Err(HistoryTransferError::NotReady);
            }
            entry.incoming.push_back((received.control, wire.to_vec()));
        }
        Ok(())
    }
}

impl AppClient {
    pub(crate) async fn begin_original_history(
        &mut self,
        ordinary: &cgka_traits::GroupId,
        recipient: &[u8],
    ) -> Result<Arc<State>, HistoryTransferError> {
        if self.history_owner.seen_transfers.len() >= MAX_HISTORY_OWNERS {
            return Err(HistoryTransferError::NotReady);
        }
        let protected = self
            .runtime
            .session()
            .private_transport_evidence(crate::NOSTR_ROUTING_COMPONENT_ID)
            .map_err(|_| HistoryTransferError::RuntimeUnavailable)?
            .ok_or(HistoryTransferError::NotReady)?
            .group_id()
            .clone();
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|_| HistoryTransferError::RuntimeUnavailable)?;
        // Read the entire selected logical snapshot; reject the whole transfer
        // when its reviewable bound is exceeded, never trim an archive silently.
        let rows = storage
            .app_messages(storage_sqlite::StoredAppMessageQuery {
                group_id_hex: Some(hex::encode(ordinary.as_slice())),
                kinds: Some(vec![9]),
                limit: Some(201),
            })
            .map_err(|_| HistoryTransferError::RuntimeUnavailable)?;
        if rows.len() > 200 {
            return Err(HistoryTransferError::NotReady);
        }
        // Capture source visibility before serializing any logical plaintext.
        // Recipient retention cannot undo disclosure of already-expired data.
        let ceiling = crate::unix_now_seconds();
        let records = rows
            .into_iter()
            .map(|row| {
                let visible = storage
                    .timeline_message(&row.group_id_hex, &row.message_id_hex)
                    .map_err(|_| HistoryTransferError::RuntimeUnavailable)?;
                let created_at = visible
                    .as_ref()
                    .map_or(row.recorded_at, |message| message.timeline_at);
                let expires_at = visible
                    .as_ref()
                    .and_then(|message| message.retention_expires_at)
                    .or(row.retention.and_then(|decision| decision.expires_at));
                let deleted = row.invalidated
                    || expires_at.is_some_and(|expiry| expiry <= ceiling)
                    || visible.as_ref().is_none_or(|message| {
                        message.deleted || message.invalidation_status.is_some()
                    });
                let payload = if deleted {
                    Vec::new()
                } else {
                    let visible = visible.as_ref().expect("visible logical history record");
                    serde_json::to_vec(&(&visible.plaintext, &visible.tags))
                        .map_err(|_| HistoryTransferError::NotReady)?
                };
                Ok(storage_sqlite::SynchronizedHistoryRecord {
                    message_id: hex::decode(row.message_id_hex)
                        .map_err(|_| HistoryTransferError::NotReady)?
                        .as_slice()
                        .try_into()
                        .map_err(|_| HistoryTransferError::NotReady)?,
                    author: hex::decode(row.sender)
                        .map_err(|_| HistoryTransferError::NotReady)?
                        .as_slice()
                        .try_into()
                        .map_err(|_| HistoryTransferError::NotReady)?,
                    created_at,
                    kind: row.kind,
                    payload,
                    expires_at,
                    deleted,
                })
            })
            .collect::<Result<Vec<_>, HistoryTransferError>>()?;
        #[cfg(all(test, feature = "test-policy-overrides"))]
        let original = self
            .history_owner
            .next_original_lifetime_for_test
            .take()
            .map_or_else(
                || State::new(&self.history_owner.lifetime),
                |lifetime| State::new_with_test_lifetime(&self.history_owner.lifetime, lifetime),
            );
        #[cfg(not(all(test, feature = "test-policy-overrides")))]
        let original = State::new(&self.history_owner.lifetime);
        let frozen = std::sync::Mutex::new(None);
        let build = |scope: &cgka_engine::history_transfer::HistoryScope| {
            let (descriptor, wire) = archive::snapshot(scope, &records, ceiling).map_err(|_| {
                cgka_traits::EngineError::Other("history whole snapshot unavailable".into())
            })?;
            *frozen.lock().expect("history original snapshot") = Some(wire);
            Ok(descriptor)
        };
        let channel = self
            .runtime
            .session()
            .begin_history_snapshot_channel(
                ordinary,
                &protected,
                recipient,
                Arc::new(crate::history_transfer::enabled::OriginalLease(
                    Arc::downgrade(&original),
                )),
                &build,
            )
            .map_err(|_| HistoryTransferError::NotReady)?;
        let transfer = channel.scope().transfer;
        self.history_owner.seen_transfers.insert(transfer);
        self.history_owner.channels.insert(
            transfer,
            ChannelEntry {
                original: Arc::downgrade(&original),
                pending_original: None,
                request: None,
                channel: Some(channel),
                archive: frozen
                    .into_inner()
                    .expect("history snapshot capture")
                    .ok_or(HistoryTransferError::NotReady)?,
                incoming: Default::default(),
                next_chunk: 0,
                complete: false,
                continue_reply: None,
                receipt_to_publish: None,
                staging: None,
                max_record_lifetime_seconds: None,
            },
        );
        self.publish_original_history_control(transfer, HistoryControl::Request)
            .await?;
        Ok(original)
    }

    async fn publish_original_history_control(
        &mut self,
        transfer: [u8; 32],
        kind: HistoryControl,
    ) -> Result<(), HistoryTransferError> {
        // The entry moves into the original future; cancellation drops its
        // channel keys instead of leaving a queued positive continuation.
        let mut runtime_shutdown = self.history_owner.runtime_shutdown.clone();
        let mut entry = self
            .history_owner
            .channels
            .remove(&transfer)
            .ok_or(HistoryTransferError::Closed)?;
        let result = async {
            let original = entry
                .original
                .upgrade()
                .filter(|state| state.live())
                .ok_or(HistoryTransferError::Closed)?;
            let channel = entry
                .channel
                .as_mut()
                .ok_or(HistoryTransferError::NotReady)?;
            let message = self
                .runtime
                .session_mut()
                .wrap_history_control(channel, kind)
                .await
                .map_err(|_| HistoryTransferError::NotReady)?;
            if message.payload.len() > cgka_engine::history_transfer::MAX_HISTORY_CONTROL_BYTES {
                return Err(HistoryTransferError::NotReady);
            }
            if !original.live() {
                return Err(HistoryTransferError::Closed);
            }
            let evidence = self
                .runtime
                .session()
                .private_transport_evidence(crate::NOSTR_ROUTING_COMPONENT_ID)
                .map_err(|_| HistoryTransferError::RuntimeUnavailable)?
                .ok_or(HistoryTransferError::NotReady)?;
            if evidence.group_id() != &channel.scope().protected.group_id {
                return Err(HistoryTransferError::Closed);
            }
            let route = cgka_traits::app_components::decode_nostr_routing_v1(evidence.component())
                .map_err(|_| HistoryTransferError::NotReady)?;
            let request = cgka_traits::TransportPublishRequest {
                    account_id: self.runtime.session().self_id(),
                    message,
                    target: cgka_traits::TransportPublishTarget::Group {
                        group_id: evidence.group_id().clone(),
                        transport_group_id: route.nostr_group_id.to_vec(),
                        endpoints: route
                            .relays
                            .into_iter()
                            .map(cgka_traits::TransportEndpoint)
                            .collect(),
                    },
                    required_acks: 1,
                };
            let revoked = original.revoked.notified();
            tokio::pin!(revoked);
            // Register before the live check so notify_waiters cannot race it.
            revoked.as_mut().enable();
            if !original.live() {
                return Err(HistoryTransferError::Closed);
            }
            let abandoned_reply = async {
                if let Some(reply) = entry.continue_reply.as_mut() {
                    reply.closed().await;
                } else {
                    std::future::pending::<()>().await;
                }
            };
            let stopping = async {
                if let Some(stopping) = runtime_shutdown.as_mut() {
                    if *stopping.borrow() {
                        return;
                    }
                    while stopping.changed().await.is_ok() {
                        if *stopping.borrow() {
                            return;
                        }
                    }
                } else {
                    std::future::pending::<()>().await;
                }
            };
            let report = tokio::select! {
                biased;
                () = stopping => {
                    original.cancel();
                    return Err(HistoryTransferError::Closed);
                },
                () = &mut revoked => return Err(HistoryTransferError::Closed),
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(original.deadline)) => {
                    original.cancel();
                    return Err(HistoryTransferError::Closed);
                },
                () = abandoned_reply => {
                    original.cancel();
                    return Err(HistoryTransferError::Closed);
                },
                report = self.adapter.publish_selected_chat(request) => {
                    report.map_err(|_| HistoryTransferError::RuntimeUnavailable)?
                },
            };
            if !report.met_required_acks() {
                return Err(HistoryTransferError::RuntimeUnavailable);
            }
            self.runtime
                .session()
                .validate_history_channel(channel)
                .map_err(|_| HistoryTransferError::Closed)?;
            Ok(())
        }
        .await;
        self.history_owner.channels.insert(transfer, entry);
        result
    }
}

impl AppClient {
    pub(crate) async fn approve_original_history(
        &mut self,
        original: &Arc<State>,
        revision: u64,
    ) -> Result<(), HistoryTransferError> {
        original.check(revision)?;
        let scope = original
            .scope
            .lock()
            .expect("history approval scope")
            .clone()
            .ok_or(HistoryTransferError::NotReady)?;
        let entry = self
            .history_owner
            .channels
            .get_mut(&scope.transfer)
            .ok_or(HistoryTransferError::Closed)?;
        if !entry
            .original
            .upgrade()
            .is_some_and(|owned| Arc::ptr_eq(&owned, original))
        {
            return Err(HistoryTransferError::Closed);
        }
        if entry.channel.is_none() {
            let request = entry
                .request
                .as_ref()
                .ok_or(HistoryTransferError::NotReady)?;
            let channel = self
                .runtime
                .session()
                .approve_history_channel(
                    request,
                    Arc::new(crate::history_transfer::enabled::OriginalLease(
                        Arc::downgrade(original),
                    )),
                )
                .map_err(|_| HistoryTransferError::NotReady)?;
            original.check(revision)?;
            let retention = self
                .runtime
                .session()
                .app_component(
                    &scope.ordinary_group,
                    crate::GROUP_MESSAGE_RETENTION_COMPONENT_ID,
                )
                .map_err(|_| HistoryTransferError::RuntimeUnavailable)?;
            entry.max_record_lifetime_seconds = match retention {
                Some(bytes) => {
                    let encoded: [u8; 8] = bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| HistoryTransferError::NotReady)?;
                    let seconds = u64::from_be_bytes(encoded);
                    (seconds != 0).then_some(seconds)
                }
                None => None,
            };
            entry.channel = Some(channel);
            original
                .progress
                .lock()
                .expect("history approval revision")
                .revision += 1;
        }
        self.publish_original_history_control(scope.transfer, HistoryControl::Consent)
            .await?;
        self.history_owner
            .channels
            .get_mut(&scope.transfer)
            .ok_or(HistoryTransferError::Closed)?
            .pending_original = None;
        Ok(())
    }
    pub(crate) fn continue_original_history(
        &mut self,
        original: Arc<State>,
        revision: u64,
        respond: tokio::sync::oneshot::Sender<Result<(), HistoryTransferError>>,
    ) {
        let result = (|| {
            original.check(revision)?;
            let scope = original
                .scope
                .lock()
                .expect("history continuation scope")
                .clone()
                .ok_or(HistoryTransferError::NotReady)?;
            let entry = self
                .history_owner
                .channels
                .get_mut(&scope.transfer)
                .ok_or(HistoryTransferError::Closed)?;
            if entry.archive.is_empty()
                || !entry
                    .original
                    .upgrade()
                    .is_some_and(|owned| Arc::ptr_eq(&owned, &original))
                || entry.continue_reply.is_some()
            {
                return Err(HistoryTransferError::NotReady);
            }
            Ok(scope.transfer)
        })();
        match result {
            Ok(transfer) => {
                self.history_owner
                    .channels
                    .get_mut(&transfer)
                    .expect("same history owner")
                    .continue_reply = Some(respond)
            }
            Err(error) => {
                let _ = respond.send(Err(error));
            }
        }
    }
}

impl AppClient {
    // Work is bounded by original owners and fragments; no durable row can
    // schedule a fresh positive action after those original owners disappear.
    pub(crate) async fn maintain_original_history(&mut self) -> Result<(), HistoryTransferError> {
        let transfers: Vec<_> = self.history_owner.channels.keys().copied().collect();
        for transfer in transfers {
            let mut entry = self
                .history_owner
                .channels
                .remove(&transfer)
                .expect("history maintenance owner");
            let original = entry.original.upgrade();
            if original.as_ref().is_none_or(|state| !state.live())
                || entry
                    .continue_reply
                    .as_ref()
                    .is_some_and(|reply| reply.is_closed())
            {
                if let Some(original) = original {
                    original.cancel();
                }
                if let Some(channel) = entry.channel.as_mut() {
                    channel.retire();
                }
                if !entry.complete
                    && let Some(staging) = &entry.staging
                {
                    #[cfg(all(test, feature = "test-policy-overrides"))]
                    {
                        self.history_owner.cleanup_attempts_for_test += 1;
                    }
                    let cleanup = self
                        .app
                        .account_storage(&self.state.label)
                        .map_err(|_| HistoryTransferError::RuntimeUnavailable)
                        .and_then(|storage| {
                            storage
                                .cancel_synchronized_history_archive(staging)
                                .map_err(|_| HistoryTransferError::RuntimeUnavailable)
                        });
                    if let Err(error) = cleanup {
                        // Retain only the exact negative cleanup identity. Its
                        // original is cancelled and its channel keys retired.
                        self.history_owner.channels.insert(transfer, entry);
                        return Err(error);
                    }
                }
                if let Some(reply) = entry.continue_reply.take() {
                    let _ = reply.send(Err(HistoryTransferError::Closed));
                }
                continue;
            }
            let original = original.expect("live original history owner");
            let result = self.advance_original_history(&mut entry, &original);
            // Failed SQL/crypto work retains exactly the old frame and channel,
            // never reopens the worker or replaces its consent/deadline.
            if result.is_err() {
                self.history_owner.channels.insert(transfer, entry);
                continue;
            }
            let publish = if let Some(ordinal) = entry.receipt_to_publish {
                Some(HistoryControl::Receipt(ordinal))
            } else if !entry.archive.is_empty() && entry.continue_reply.is_some() {
                let channel = entry
                    .channel
                    .as_mut()
                    .ok_or(HistoryTransferError::NotReady)?;
                let descriptor = channel
                    .scope()
                    .snapshot
                    .clone()
                    .ok_or(HistoryTransferError::NotReady)?;
                let ordinal = entry.next_chunk;
                if ordinal < descriptor.fragment_count {
                    let start =
                        ordinal as usize * storage_sqlite::MAX_HISTORY_ARCHIVE_FRAGMENT_BYTES;
                    let end = (start + storage_sqlite::MAX_HISTORY_ARCHIVE_FRAGMENT_BYTES)
                        .min(entry.archive.len());
                    match self.runtime.session().seal_history_chunk(
                        channel,
                        descriptor.archive_digest,
                        ordinal,
                        &entry.archive[start..end],
                        false,
                    ) {
                        Ok(_) => Some(HistoryControl::Chunk(ordinal)),
                        Err(_) => None, // Consent/previous committed receipt has not arrived yet.
                    }
                } else {
                    None
                }
            } else {
                None
            };
            self.history_owner.channels.insert(transfer, entry);
            if let Some(kind) = publish
                && self
                    .publish_original_history_control(transfer, kind)
                    .await
                    .is_ok()
                && let Some(entry) = self.history_owner.channels.get_mut(&transfer)
                && matches!(kind, HistoryControl::Receipt(_))
            {
                entry.receipt_to_publish = None;
            }
        }
        Ok(())
    }

    fn advance_original_history(
        &mut self,
        entry: &mut ChannelEntry,
        original: &Arc<State>,
    ) -> Result<(), HistoryTransferError> {
        let Some(channel) = entry.channel.as_mut() else {
            return Ok(());
        };
        while let Some((kind, wire)) = entry.incoming.front() {
            self.runtime
                .session()
                .validate_history_channel(channel)
                .map_err(|_| HistoryTransferError::Closed)?;
            match *kind {
                HistoryControl::Consent if !entry.archive.is_empty() => {
                    self.runtime
                        .session()
                        .bind_history_consent(channel, wire)
                        .map_err(|_| HistoryTransferError::NotReady)?;
                    original
                        .progress
                        .lock()
                        .expect("history authenticated consent revision")
                        .revision += 1;
                }
                HistoryControl::Chunk(ordinal) if entry.archive.is_empty() => {
                    let opened = self
                        .runtime
                        .session()
                        .open_history_chunk(channel, wire)
                        .map_err(|_| HistoryTransferError::NotReady)?;
                    let descriptor = channel
                        .scope()
                        .snapshot
                        .clone()
                        .ok_or(HistoryTransferError::NotReady)?;
                    let request = channel
                        .request_packet()
                        .map_err(|_| HistoryTransferError::Closed)?;
                    let staging = storage_sqlite::HistoryArchiveStagingManifest {
                        binding: archive::binding(channel.scope(), descriptor.timestamp_ceiling)?,
                        request_digest: <[u8; 32]>::from(sha2::Sha256::digest(&request)),
                        archive_digest: descriptor.archive_digest,
                        encoded_bytes: descriptor.encoded_bytes,
                        fragment_count: descriptor.fragment_count,
                        record_count: descriptor.record_count,
                        retain_since: 0,
                        max_record_lifetime_seconds: entry.max_record_lifetime_seconds,
                    };
                    let storage = self
                        .app
                        .account_storage(&self.state.label)
                        .map_err(|_| HistoryTransferError::RuntimeUnavailable)?;
                    let cancelled = || {
                        !original.live()
                            || self
                                .runtime
                                .session()
                                .validate_history_channel(channel)
                                .is_err()
                    };
                    let receipt = storage
                        .stage_synchronized_history_archive_fragment(
                            &staging,
                            ordinal,
                            &opened.body,
                            crate::unix_now_seconds(),
                            &cancelled,
                        )
                        .map_err(|_| HistoryTransferError::RuntimeUnavailable)?;
                    entry.staging = Some(staging.clone());
                    if !entry.complete
                        && receipt.disposition
                            == storage_sqlite::HistoryArchiveFragmentDisposition::Imported
                    {
                        let mut progress = original
                            .progress
                            .lock()
                            .expect("history committed import receipt");
                        progress.imported_records = receipt.imported_records;
                        progress.complete = true;
                        progress.revision += 1;
                        entry.complete = true;
                    }
                    #[cfg(all(test, feature = "test-policy-overrides"))]
                    if self.history_owner.cancel_after_stage_for_test
                        == Some(
                            receipt.disposition
                                == storage_sqlite::HistoryArchiveFragmentDisposition::Imported,
                        )
                    {
                        self.history_owner.cancel_after_stage_for_test = None;
                        original.cancel();
                    }

                    let body =
                        serde_json::to_vec(&receipt).map_err(|_| HistoryTransferError::NotReady)?;
                    self.runtime
                        .session()
                        .seal_history_chunk(
                            channel,
                            descriptor.archive_digest,
                            ordinal,
                            &body,
                            true,
                        )
                        .map_err(|_| HistoryTransferError::NotReady)?;
                    entry.receipt_to_publish = Some(ordinal);
                }
                HistoryControl::Receipt(ordinal) if !entry.archive.is_empty() => {
                    let opened = self
                        .runtime
                        .session()
                        .open_history_chunk(channel, wire)
                        .map_err(|_| HistoryTransferError::NotReady)?;
                    let receipt: storage_sqlite::HistoryArchiveFragmentReceipt =
                        serde_json::from_slice(&opened.body)
                            .map_err(|_| HistoryTransferError::NotReady)?;
                    let descriptor = channel
                        .scope()
                        .snapshot
                        .as_ref()
                        .ok_or(HistoryTransferError::NotReady)?;
                    let start =
                        ordinal as usize * storage_sqlite::MAX_HISTORY_ARCHIVE_FRAGMENT_BYTES;
                    let end = (start + storage_sqlite::MAX_HISTORY_ARCHIVE_FRAGMENT_BYTES)
                        .min(entry.archive.len());
                    if ordinal != entry.next_chunk
                        || receipt.ordinal != ordinal
                        || serde_json::to_vec(&receipt)
                            .map_err(|_| HistoryTransferError::NotReady)?
                            != opened.body
                        || receipt.body_digest
                            != <[u8; 32]>::from(sha2::Sha256::digest(&entry.archive[start..end]))
                    {
                        return Err(HistoryTransferError::NotReady);
                    }
                    let final_fragment = ordinal + 1 == descriptor.fragment_count;
                    if final_fragment
                        != (receipt.disposition
                            == storage_sqlite::HistoryArchiveFragmentDisposition::Imported)
                        || (final_fragment
                            && receipt
                                .imported_records
                                .checked_add(receipt.skipped_records)
                                != Some(descriptor.record_count))
                    {
                        return Err(HistoryTransferError::NotReady);
                    }
                    entry.next_chunk += 1;
                    if final_fragment {
                        let mut progress = original
                            .progress
                            .lock()
                            .expect("history authenticated final receipt");
                        progress.imported_records = receipt.imported_records;
                        progress.complete = true;
                        progress.revision += 1;
                        entry.complete = true;
                        drop(progress);
                        entry.complete = true;
                        channel.retire();
                        if let Some(reply) = entry.continue_reply.take()
                            && reply.send(Ok(())).is_err()
                        {
                            original.cancel();
                        }
                    }
                }
                _ => return Err(HistoryTransferError::NotReady),
            }
            entry.incoming.pop_front();
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "test-policy-overrides"))]
impl AppClient {
    pub(crate) async fn republish_original_history_request_for_test(
        &mut self,
        original: &Arc<State>,
    ) -> Result<(), HistoryTransferError> {
        let scope = original
            .scope
            .lock()
            .expect("same original history request")
            .clone()
            .ok_or(HistoryTransferError::Closed)?;
        let entry = self
            .history_owner
            .channels
            .get_mut(&scope.transfer)
            .ok_or(HistoryTransferError::Closed)?;
        if !entry
            .original
            .upgrade()
            .is_some_and(|owned| Arc::ptr_eq(&owned, original))
        {
            return Err(HistoryTransferError::Closed);
        }
        self.runtime
            .session()
            .discard_original_history_request_ciphertext_for_test(
                entry.channel.as_mut().ok_or(HistoryTransferError::Closed)?,
            )
            .map_err(|_| HistoryTransferError::Closed)?;
        self.publish_original_history_control(scope.transfer, HistoryControl::Request)
            .await
    }
}

#[cfg(all(test, feature = "test-policy-overrides"))]
impl AppClient {
    pub(crate) fn inspect_original_history_record_for_test(
        &self,
        original: &Arc<State>,
        message_id: [u8; 32],
    ) -> Result<(bool, usize), HistoryTransferError> {
        let scope = original
            .scope
            .lock()
            .expect("original frozen archive witness")
            .clone()
            .ok_or(HistoryTransferError::Closed)?;
        let entry = self
            .history_owner
            .channels
            .get(&scope.transfer)
            .ok_or(HistoryTransferError::Closed)?;
        if !entry
            .original
            .upgrade()
            .is_some_and(|state| Arc::ptr_eq(&state, original))
        {
            return Err(HistoryTransferError::Closed);
        }
        let archive: storage_sqlite::SynchronizedHistoryArchive =
            serde_json::from_slice(&entry.archive).map_err(|_| HistoryTransferError::NotReady)?;
        let record = archive
            .chunks
            .iter()
            .flatten()
            .find(|record| record.message_id == message_id)
            .ok_or(HistoryTransferError::NotReady)?;
        Ok((record.deleted, record.payload.len()))
    }
}
