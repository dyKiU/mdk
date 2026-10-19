//! Real signed malformed transport retention: selector/edge tests, not history delivery.
use super::*;
use crate::tests::{ScriptedPushRelayClient, epoch_gap_probe};
use cgka_traits::storage::MessageStorage;
use cgka_traits::{MessageId, MessageRecord, MessageState};
use marmot_account::AccountHome;
use std::sync::Arc;

async fn fixture() -> (
    tempfile::TempDir,
    crate::MarmotApp,
    AppClient,
    Arc<ScriptedPushRelayClient>,
    [GroupId; 2],
) {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let mut groups = [
        client.create_group("selector first", &[]).await.unwrap(),
        client.create_group("selector second", &[]).await.unwrap(),
    ];
    groups.sort_by(|left, right| left.as_slice().cmp(right.as_slice()));
    (dir, app, client, relay, groups)
}

async fn retain_real_probe(
    client: &mut AppClient,
    app: &crate::MarmotApp,
    group: &GroupId,
    marker: &str,
) -> MessageId {
    let route = app
        .group("alice", &hex::encode(group.as_slice()))
        .unwrap()
        .unwrap()
        .nostr_routing
        .nostr_group_id_hex;
    let event = epoch_gap_probe(&route, unix_now_seconds(), marker);
    let message = event.to_transport_message().unwrap();
    let id = message.id.clone();
    let delivery = cgka_traits::TransportDelivery {
        account_id: client.runtime.session().self_id(),
        group_id_hint: Some(group.clone()),
        received_at: cgka_traits::Timestamp(unix_now_seconds()),
        message,
        source: cgka_traits::TransportDeliverySource {
            transport: cgka_traits::transport::TransportSource("nostr".into()),
            plane: cgka_traits::TransportDeliveryPlane::Group,
            endpoint: None,
            subscription_id: None,
            wire: None,
        },
    };
    let ingested = client.runtime.ingest_delivery(delivery).await.unwrap();
    assert!(
        matches!(&ingested.outcome, IngestOutcome::TransportDeferred { group_id, .. } if group_id == group),
        "real signed malformed envelope must reach transport deferral"
    );
    assert!(!ingested.left_object_unpersisted);
    client.remember_pending_convergence_groups(&ingested.effects);
    client
        .observe_drained_session_events(&ingested.effects)
        .await
        .unwrap();
    let record = app
        .account_storage("alice")
        .unwrap()
        .get_message(&id)
        .unwrap();
    assert_eq!(record.state, MessageState::PeelDeferred);
    assert_eq!(record.group_id, *group);
    let lifecycle = record.deferred_peel.unwrap();
    assert_eq!(lifecycle.distinct_context_attempts, 0);
    assert!(lifecycle.last_context_fingerprint.is_none());
    assert!(client.pending_convergence_groups.contains(group));
    assert!(matches!(
        client.convergence_schedule_state(group).unwrap(),
        ConvergenceScheduleState::Ready
    ));
    id
}

async fn retain_both(
    client: &mut AppClient,
    app: &crate::MarmotApp,
    groups: &[GroupId; 2],
) -> [MessageId; 2] {
    let ids = [
        retain_real_probe(client, app, &groups[0], "first real row").await,
        retain_real_probe(client, app, &groups[1], "second real row").await,
    ];
    for group in groups {
        assert!(matches!(
            client.convergence_schedule_state(group).unwrap(),
            ConvergenceScheduleState::Ready
        ));
    }
    ids
}

fn rows(app: &crate::MarmotApp, ids: &[MessageId; 2]) -> [MessageRecord; 2] {
    let storage = app.account_storage("alice").unwrap();
    [
        storage.get_message(&ids[0]).unwrap(),
        storage.get_message(&ids[1]).unwrap(),
    ]
}

fn actual_attempt(record: &MessageRecord) -> bool {
    record.state == MessageState::Failed
        || record.deferred_peel.as_ref().is_some_and(|lifecycle| {
            lifecycle.distinct_context_attempts > 0 && lifecycle.last_context_fingerprint.is_some()
        })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_ready_turn_advances_only_one_real_retained_group() {
    let (_dir, app, mut client, _relay, groups) = fixture().await;
    let ids = retain_both(&mut client, &app, &groups).await;
    let before = rows(&app, &ids);
    client
        .advance_one_ready_explicit_sync_group()
        .await
        .unwrap();
    let after = rows(&app, &ids);
    assert!(
        actual_attempt(&after[0]),
        "selected real retained row was not retried"
    );
    assert_eq!(
        after[1], before[1],
        "one owner turn must not retry the second group"
    );
    assert!(client.pending_convergence_groups.contains(&groups[1]));
    assert!(
        app.messages("alice").unwrap().is_empty(),
        "malformed input grants no plaintext"
    );

    // The unchanged fingerprint normally parks the first probe. Do not move a
    // clock or manufacture readiness if the real Core says otherwise.
    assert!(!matches!(
        client.convergence_schedule_state(&groups[0]).unwrap(),
        ConvergenceScheduleState::Ready
    ));
    client
        .advance_one_ready_explicit_sync_group()
        .await
        .unwrap();
    assert!(
        actual_attempt(&rows(&app, &ids)[1]),
        "next ready group must get its turn"
    );
}
