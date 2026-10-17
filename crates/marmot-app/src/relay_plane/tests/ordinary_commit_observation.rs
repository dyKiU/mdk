//! Read-only, one-publication fixture observation before actual relay delivery.
use super::*;
use cgka_traits::storage::{MessageStorage, OutboundFanoutStorage};
use cgka_traits::{FanoutPendingKind, GroupId, message::StoredMessagePayload};
use cgka_traits::{MemberId, MessageId, TransportPublishRequest};
use openmls::prelude::{ContentType, MlsMessageBodyIn, MlsMessageIn, ProtocolMessage};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tls_codec::Deserialize;

pub(crate) type Snapshot = (
    Result<Option<cgka_engine::canonical_probe_observer::Observation>, &'static str>,
    [u64; 8],
);

pub(super) struct Watch {
    account: MemberId,
    group: GroupId,
    source_epoch: u64,
    recipient_leaf: u32,
    storage: storage_sqlite::SqliteAccountStorage,
    stages: std::sync::Mutex<[u64; 8]>,
    result: std::sync::Mutex<
        Result<Option<Arc<cgka_engine::canonical_probe_observer::Probe>>, &'static str>,
    >,
}

pub(crate) struct Observation {
    _registration: transport_nostr::PublicationObservationGuard,
    watch: Arc<Watch>,
}
impl Observation {
    pub(crate) fn snapshot(&self) -> Snapshot {
        let result = self
            .watch
            .result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|probe| probe.as_ref().map(|probe| probe.snapshot()))
            .map_err(|e| *e);
        let stages = *self.watch.stages.lock().unwrap_or_else(|e| e.into_inner());
        (result, stages)
    }
}
pub(crate) fn observe_next_ordinary_commit(
    plane: &MarmotRelayPlane,
    account: MemberId,
    group: GroupId,
    source_epoch: u64,
    recipient_leaf: u32,
    storage: storage_sqlite::SqliteAccountStorage,
) -> Observation {
    let watch = Arc::new(Watch {
        account,
        group,
        source_epoch,
        recipient_leaf,
        storage,
        result: std::sync::Mutex::new(Ok(None)),
        stages: std::sync::Mutex::new([0; 8]),
    });
    let callback_watch = watch.clone();
    let registration = plane
        .observe_publications_for_test(Arc::new(move |request| observe(&callback_watch, request)));
    Observation {
        _registration: registration,
        watch,
    }
}

fn observe(watch: &Arc<Watch>, request: &TransportPublishRequest) -> bool {
    if watch.account != request.account_id
        || !matches!(&request.target,
        cgka_traits::TransportPublishTarget::Group { group_id, .. } if *group_id == watch.group)
    {
        return false;
    }
    // account/group visits, no fanout, kind mismatch, missing pending owner,
    // wrong frozen request, no MLS wire, not Commit, wrong source epoch.
    let note = |index: usize| {
        let mut stages = watch.stages.lock().unwrap_or_else(|e| e.into_inner());
        stages[index] = stages[index].saturating_add(1);
    };
    note(0);
    let content = (|| -> Result<Option<MessageId>, &'static str> {
        let Some(fanout) = watch
            .storage
            .outbound_fanout(&request.message.id)
            .map_err(|_| "fanout_read_failed")?
        else {
            note(1);
            return Ok(None);
        };
        if fanout.group_id() != Some(&watch.group)
            || fanout.pending_kind() != Some(FanoutPendingKind::GroupEvolution)
        {
            note(2);
            return Ok(None);
        }
        if fanout.request() != request {
            note(4);
            return Ok(None);
        }
        if fanout.pending_ref().is_none() {
            note(3);
            return Ok(None);
        }
        let Some(origin) = fanout.pending_origin_message_id() else {
            note(3);
            return Ok(None);
        };
        let row = watch
            .storage
            .get_message(origin)
            .map_err(|_| "canonical_row_read_failed")?;
        if row.group_id != watch.group {
            return Err("canonical_row_group_mismatch");
        }
        let payload =
            StoredMessagePayload::decode(&row.payload).map_err(|_| "payload_decode_failed")?;
        let Some(wire) = payload.as_openmls_wire() else {
            note(5);
            return Ok(None);
        };
        let message =
            MlsMessageIn::tls_deserialize_exact(&wire.payload).map_err(|_| "MLS_decode_failed")?;
        let protocol: ProtocolMessage = match message.extract() {
            MlsMessageBodyIn::PublicMessage(message) => message.into(),
            MlsMessageBodyIn::PrivateMessage(message) => message.into(),
            _ => return Ok(None),
        };
        if protocol.content_type() != ContentType::Commit {
            note(6);
            return Ok(None);
        }
        if protocol.epoch().as_u64() != watch.source_epoch {
            note(7);
            return Ok(None);
        }
        Ok(Some(MessageId::new(Sha256::digest(&wire.payload).to_vec())))
    })();
    if matches!(content, Ok(None)) {
        return false;
    }
    eprintln!(
        "account_departure_nonordered_b_commit_before_publish_observed={}",
        content.is_ok()
    );
    let result = content.map(|content| {
        content.map(|content| {
            cgka_engine::canonical_probe_observer::Probe::arm(
                watch.group.clone(),
                watch.recipient_leaf,
                content,
            )
        })
    });
    *watch.result.lock().unwrap_or_else(|e| e.into_inner()) = result;
    true
}
