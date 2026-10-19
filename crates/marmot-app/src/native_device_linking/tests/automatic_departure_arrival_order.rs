//! Control actual A→B proposal arrival without changing either leave owner.
//! The original publication predicate and its total twenty-second budget remain
//! in the caller; input-control failures must not masquerade as protocol failures.
use super::*;
use cgka_traits::message::{MessageState, StoredMessagePayload};
use cgka_traits::{EpochId, MessageId};
use openmls::prelude::{ContentType, MlsMessageBodyIn, MlsMessageIn, ProtocolMessage};
use sha2::{Digest, Sha256};
use tls_codec::Deserialize;

pub(super) struct HeldProposal {
    hold: crate::relay_plane::held_delivery::Hold,
    outer: MessageId,
    canonical: MessageId,
    prior: EpochId,
    own_leave_before_arrival: bool,
    actual_proposal_received: bool,
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
            assert_eq!(
                peer.app
                    .account_storage("test")
                    .unwrap()
                    .get_message(&canonical)
                    .unwrap()
                    .state,
                MessageState::Processed,
                "D must have authenticated A's actual proposal before its held A-only commit"
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
            if self.hold.observed().0 == 0 || current != self.prior || proposed != Some(self.prior)
            {
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
            self.hold.release();
        }
        match store.get_message(&self.canonical) {
            Ok(row) if row.state == MessageState::Processed => {
                let (held, finished, enqueued) = self.hold.observed();
                // Another runtime worker may finish ingest immediately after
                // send, before the routing task publishes its final counters.
                if finished == 0 || enqueued == 0 {
                    return;
                }
                assert!(
                    held > 0,
                    "arrival fixture requires the original queue delivery"
                );
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
            Ok(_) | Err(cgka_traits::StorageError::NotFound) => {}
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
        assert!(
            self.own_leave_before_arrival && self.actual_proposal_received,
            "arrival fixture did not establish the actual controlled order; no protocol failure claim"
        );
    }
}
