//! Control actual A→B proposal arrival without changing either leave owner.
//! The original publication predicate and its total twenty-second budget remain
//! in the caller; input-control failures must not masquerade as protocol failures.
use super::*;
use cgka_traits::message::{MessageState, StoredMessagePayload};
use cgka_traits::{EpochId, MessageId};
use openmls::prelude::{
    ContentType, MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent, Proposal,
    ProtocolMessage, Sender,
};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize, Serialize};

pub(super) struct HeldProposal {
    hold: crate::relay_plane::held_delivery::Hold,
    outer: MessageId,
    canonical: MessageId,
    prior: EpochId,
    own_leave_before_arrival: bool,
    actual_proposal_received: bool,
    native_completion: Option<([u64; 3], [bool; 4])>,
    authentication: std::sync::Arc<cgka_engine::canonical_probe_observer::Probe>,
}

impl HeldProposal {
    pub(super) async fn arm(
        source: &MarmotApp,
        recipient: &MarmotApp,
        runtime: &MarmotAppRuntime,
        peer: &TwoSourcePeer,
        prior: EpochId,
        relay: &dyn nostr_relay_builder::prelude::NostrDatabase,
    ) -> Self {
        super::assert_administrator_holds_only_a(peer, prior);
        let rows = source
            .account_storage("test")
            .unwrap()
            .list_messages(&peer.group, prior)
            .unwrap();
        assert!(rows.len() <= 128, "arrival fixture source bound");
        let mut candidates = Vec::new();
        for row in rows {
            if row.state != MessageState::Sent {
                continue;
            }
            let payload = StoredMessagePayload::decode(&row.payload).unwrap();
            let (Some(exact), Some(wire)) =
                (payload.as_exact_transport(), payload.as_openmls_wire())
            else {
                continue;
            };
            let message = MlsMessageIn::tls_deserialize_exact(&wire.payload).unwrap();
            let protocol: ProtocolMessage = match message.extract() {
                MlsMessageBodyIn::PublicMessage(message) => message.into(),
                MlsMessageBodyIn::PrivateMessage(message) => message.into(),
                _ => continue,
            };
            if protocol.content_type() != ContentType::Proposal
                || protocol.epoch().as_u64() != prior.0
            {
                continue;
            }
            let canonical = MessageId::new(Sha256::digest(&wire.payload).to_vec());
            let administrator = peer.app.account_storage("test").unwrap();
            let retained = administrator.get_message(&canonical).unwrap();
            assert!(
                StoredMessagePayload::decode(&retained.payload)
                    .unwrap()
                    .as_openmls_wire()
                    .is_some_and(|message| message.payload == wire.payload),
                "D must retain the exact A public proposal wire"
            );
            administrator.with_read_snapshot(|storage| -> Result<(), cgka_traits::StorageError> {
                let crypto = openmls_rust_crypto::RustCrypto::default();
                let provider = cgka_engine::provider::EngineOpenMlsProvider::<storage_sqlite::SqliteAccountStorage>::new(
                    &crypto, storage.mls_storage(),
                );
                let mut group = openmls::group::MlsGroup::load(
                    storage.mls_storage(), &openmls::group::GroupId::from_slice(peer.group.as_slice()),
                ).unwrap().unwrap();
                assert_eq!(group.epoch().as_u64(),prior.0);
                // Public-only authentication reads no receive ratchet and the
                // query-only snapshot refuses writes. Never store or apply it.
                let public = match MlsMessageIn::tls_deserialize_exact(&wire.payload).unwrap().extract() {
                    MlsMessageBodyIn::PublicMessage(public) => public,
                    _ => panic!("arrival fixture requires a public SelfRemove"),
                };
                let processed = group.process_message(&provider, ProtocolMessage::from(public)).unwrap();
                let ProcessedMessageContent::ProposalMessage(proposal) = processed.into_content() else {
                    panic!("arrival fixture requires an authenticated proposal");
                };
                assert!(matches!(proposal.proposal(),Proposal::SelfRemove));
                assert!(matches!(proposal.sender(),Sender::Member(index) if index.u32()==peer.a_index));
                let reference = proposal.proposal_reference_ref().tls_serialize_detached().unwrap();
                let staged = group.pending_commit().unwrap();
                let references:Vec<_> = staged.queued_proposals()
                    .filter(|proposal|matches!((proposal.proposal(),proposal.sender()),
                        (Proposal::SelfRemove,Sender::Member(index)) if index.u32()==peer.a_index))
                    .map(|proposal|proposal.proposal_reference_ref().tls_serialize_detached().unwrap())
                    .collect();
                assert!(references.len()==1 && references[0]==reference,
                    "D actual pending commit must consume this exact authenticated A proposal");
                Ok(())
            }).unwrap();
            eprintln!(
                "account_departure_arrival_d_exact_authenticated_pending_proposal=true canonical_state={:?}",
                retained.state
            );
            let event =
                nostr_relay_builder::prelude::EventId::from_slice(exact.id.as_slice()).unwrap();
            assert!(
                relay.event_by_id(&event).await.unwrap().is_some(),
                "actual A proposal must remain on the relay"
            );
            candidates.push((exact.id.clone(), canonical));
        }
        assert_eq!(
            candidates.len(),
            1,
            "arrival fixture requires one exact actual A proposal"
        );
        let (outer, canonical) = candidates.pop().unwrap();
        let authentication = cgka_engine::canonical_probe_observer::Probe::arm(
            peer.group.clone(),
            peer.b_index,
            canonical.clone(),
        );
        let account = cgka_traits::MemberId::new(
            hex::decode(
                recipient
                    .account_home()
                    .account("test")
                    .unwrap()
                    .account_id_hex,
            )
            .unwrap(),
        );
        let hold = runtime
            .relay_plane_for_test()
            .hold_account_delivery_for_test(account, outer.clone());
        let fixture = Self {
            hold,
            outer,
            canonical,
            prior,
            own_leave_before_arrival: false,
            actual_proposal_received: false,
            native_completion: None,
            authentication,
        };
        fixture.assert_not_received(recipient);
        eprintln!("account_departure_arrival_exact_a_proposal_armed=true");
        fixture
    }

    fn assert_not_received(&self, app: &MarmotApp) {
        let store = app.account_storage("test").unwrap();
        for id in [&self.outer, &self.canonical] {
            assert!(
                matches!(
                    store.get_message(id),
                    Err(cgka_traits::StorageError::NotFound)
                ),
                "arrival fixture bypass: A must not enter B through another intake path while held"
            );
        }
    }

    pub(super) async fn advance(
        &mut self,
        app: &MarmotApp,
        peer: &TwoSourcePeer,
        relay: &dyn nostr_relay_builder::prelude::NostrDatabase,
    ) {
        if self.actual_proposal_received {
            return;
        }
        let store = app.account_storage("test").unwrap();
        if !self.own_leave_before_arrival {
            self.assert_not_received(app);
            let current = store.get_group(&peer.group).unwrap().epoch;
            let proposed = store
                .leave_request(&peer.group)
                .unwrap()
                .and_then(|request| request.last_proposed_epoch);
            let (native_held, native, native_unknown) = self.hold.native_observed();
            let actual_native_held_input = native_held > 0
                && !native_unknown
                && native.as_ref().is_some_and(|(counts, facts)| {
                    counts[0] > 0
                        && counts[1] == 0
                        && counts[2] == 0
                        && facts[0]
                        && facts[1]
                        && !facts[2]
                        && !facts[3]
                });
            let actual_held_input = self.hold.observed().0 > 0 || actual_native_held_input;
            if !actual_held_input || current != self.prior || proposed != Some(self.prior) {
                return;
            }
            let leave = super::observe_public_leave_failure(app, peer, relay)
                .await
                .unwrap();
            if leave.source_sent_proposals == 0
                || leave.relay_retained_proposals != leave.source_sent_proposals
            {
                return;
            }
            // Check the genuine own leave and absence again after the relay read.
            assert_eq!(store.get_group(&peer.group).unwrap().epoch, self.prior);
            assert_eq!(
                store
                    .leave_request(&peer.group)
                    .unwrap()
                    .unwrap()
                    .last_proposed_epoch,
                Some(self.prior)
            );
            self.assert_not_received(app);
            super::assert_administrator_holds_only_a(peer, self.prior);
            self.own_leave_before_arrival = true;
            eprintln!(
                "account_departure_arrival_b_old_epoch_self_remove_relay_retained_before_a=true"
            );
            // The relay read above awaited: revalidate the actual held loan
            // at this final ordering boundary, without requiring future ingest
            // or ACK completion flags before the hold has been released.
            let (native_held, native, native_unknown) = self.hold.native_observed();
            let actual_native_held_input = native_held > 0
                && !native_unknown
                && native.as_ref().is_some_and(|(counts, facts)| {
                    counts[0] > 0
                        && counts[1] == 0
                        && counts[2] == 0
                        && facts[0]
                        && facts[1]
                        && !facts[2]
                        && !facts[3]
                });
            assert!(
                self.hold.observed().0 > 0 || actual_native_held_input,
                "arrival fixture requires a current unconsumed held input before release"
            );
            self.hold.release();
        }
        match store.get_message(&self.canonical) {
            Ok(_) => {
                let authenticated = self.authentication.snapshot();
                if authenticated.authenticated_self_remove == 0
                    || !authenticated.self_remove_scheduling_refused_for_own_leave
                {
                    return;
                }
                let (held, finished, enqueued) = self.hold.observed();
                // Each route must independently prove actual custody through
                // its own completion, followed by the same real canonical Core
                // authentication above. Never combine partial queue/native facts.
                let queue_complete = held > 0 && finished > 0 && enqueued > 0;
                let (native_held, native, native_unknown) = self.hold.native_observed();
                let native_complete = native_held > 0
                    && !native_unknown
                    && native.as_ref().is_some_and(|(counts, facts)| {
                        counts.iter().all(|count| *count > 0) && facts.iter().all(|fact| *fact)
                    });
                if !queue_complete && !native_complete {
                    return;
                }
                if native_complete {
                    self.native_completion = native;
                }
                assert_eq!(store.get_group(&peer.group).unwrap().epoch, self.prior);
                assert_eq!(
                    store
                        .leave_request(&peer.group)
                        .unwrap()
                        .unwrap()
                        .last_proposed_epoch,
                    Some(self.prior)
                );
                self.actual_proposal_received = true;
                eprintln!("account_departure_arrival_a_authenticated_after_b_own_leave=true");
            }
            Err(cgka_traits::StorageError::NotFound) => {}
            Err(_) => panic!("arrival fixture received storage state Unknown"),
        }
    }

    pub(super) fn assert_actual_order(&self) {
        eprintln!(
            "account_departure_arrival_inputs own_leave_before_arrival={} actual_proposal_received={} hold_counts={:?}",
            self.own_leave_before_arrival,
            self.actual_proposal_received,
            self.hold.observed()
        );
        eprintln!(
            "account_departure_arrival_recovered_deferrals={}",
            self.hold.recovered_deferrals()
        );
        let (native_held, _, native_unknown) = self.hold.native_observed();
        eprintln!(
            "account_departure_arrival_native held={} completed_snapshot={:?} unknown={}",
            native_held, self.native_completion, native_unknown
        );
        let authenticated = self.authentication.snapshot();
        eprintln!(
            "account_departure_arrival_actual_engine_authentications={} own_leave_schedule_refused={}",
            authenticated.authenticated_self_remove,
            authenticated.self_remove_scheduling_refused_for_own_leave
        );
        assert!(
            self.own_leave_before_arrival && self.actual_proposal_received,
            "arrival fixture did not establish the actual controlled order; no protocol failure claim"
        );
    }
}
