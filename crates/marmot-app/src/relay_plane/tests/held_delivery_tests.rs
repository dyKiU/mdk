//! The arrival fixture must preserve scope, retained packets and cursor safety.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_delivery_limits_scope_and_drop_releases_original_packet() {
    let (plane, adapter, alice) = cursor_floor_adapter(None, None);
    let bob = MemberId::new(vec![0xB2; 32]);
    let bob_adapter = plane.account_adapter(bob.clone(), Arc::new(RecordingRelayClient::default()));
    let (other_plane, other_adapter, other_alice) = cursor_floor_adapter(None, None);
    assert_eq!(alice, other_alice);
    let packet = cursor_floor_delivery(
        &alice,
        1,
        OPENED_CURSOR + 100,
        TransportDeliveryPlane::Group,
    );
    let held = plane.hold_account_delivery_for_test(alice.clone(), packet.message.id.clone());
    plane.route_account_delivery_for_test(packet.clone());
    plane.route_account_delivery_for_test(cursor_floor_delivery(
        &alice,
        2,
        OPENED_CURSOR + 101,
        TransportDeliveryPlane::Group,
    ));
    plane.route_account_delivery_for_test(cursor_floor_delivery(
        &bob,
        1,
        OPENED_CURSOR + 100,
        TransportDeliveryPlane::Group,
    ));
    other_plane.route_account_delivery_for_test(packet.clone());
    assert_eq!(
        take_queued(&adapter).message.id,
        MessageId::new(vec![2; 32])
    );
    assert_eq!(take_queued(&bob_adapter).message, packet.message);
    assert_eq!(take_queued(&other_adapter).message, packet.message);
    assert!(adapter.try_receive_account_delivery().is_none());
    assert_eq!(held.observed(), (1, 0, 0));
    drop(held);
    let received = timeout(Duration::from_secs(2), adapter.receive_account_delivery())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let AccountDeliveryReceive::Delivery(received) = received else {
        panic!("arrival hold must not fabricate overflow");
    };
    assert_eq!(received.message, packet.message);
    adapter.release_account_delivery(&received.message.id);
    plane.shutdown().await;
    other_plane.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_delivery_retains_cursor_pins_for_every_duplicate_until_real_receipt() {
    let (plane, adapter, alice) = cursor_floor_adapter(None, None);
    let packet = cursor_floor_delivery(
        &alice,
        1,
        OPENED_CURSOR + 100,
        TransportDeliveryPlane::Group,
    );
    let held = plane.hold_account_delivery_for_test(alice, packet.message.id.clone());
    plane.route_account_delivery_for_test(packet.clone());
    plane.route_account_delivery_for_test(packet.clone());
    assert_eq!(held.observed(), (2, 0, 0));
    let candidate = Some(OPENED_CURSOR + 1_000);
    assert_eq!(
        adapter.seal_transport_cursor(candidate),
        Some(OPENED_CURSOR + 100 + CURSOR_LOOKBACK)
    );
    held.release();
    timeout(Duration::from_secs(2), async {
        while held.observed().1 != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(held.observed(), (2, 2, 2));
    assert_eq!(take_queued(&adapter).message, packet.message);
    assert_eq!(take_queued(&adapter).message, packet.message);
    assert_eq!(
        adapter.seal_transport_cursor(candidate),
        Some(OPENED_CURSOR + 100 + CURSOR_LOOKBACK)
    );
    adapter.release_account_delivery(&packet.message.id);
    assert_eq!(adapter.seal_transport_cursor(candidate), candidate);
    drop(held);
    plane.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_delivery_cannot_enter_or_unpin_a_replacement_queue() {
    let (plane, old_adapter, alice) = cursor_floor_adapter(None, None);
    let old_packet = cursor_floor_delivery(
        &alice,
        1,
        OPENED_CURSOR + 100,
        TransportDeliveryPlane::Group,
    );
    let held = plane.hold_account_delivery_for_test(alice.clone(), old_packet.message.id.clone());
    plane.route_account_delivery_for_test(old_packet);
    old_adapter.delivery_rx.lock().await.close();
    let replacement =
        plane.account_adapter(alice.clone(), Arc::new(RecordingRelayClient::default()));
    replacement.open_transport_cursor(Some(OPENED_CURSOR));
    plane.route_account_delivery_for_test(cursor_floor_delivery(
        &alice,
        2,
        OPENED_CURSOR + 200,
        TransportDeliveryPlane::Group,
    ));
    held.release();
    timeout(Duration::from_secs(2), async {
        while held.observed().1 != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(held.observed(), (1, 1, 0));
    let candidate = Some(OPENED_CURSOR + 1_000);
    assert_eq!(
        replacement.seal_transport_cursor(candidate),
        Some(OPENED_CURSOR + 200 + CURSOR_LOOKBACK)
    );
    let received = take_queued(&replacement);
    assert_eq!(received.message.id, MessageId::new(vec![2; 32]));
    replacement.release_account_delivery(&received.message.id);
    assert!(replacement.try_receive_account_delivery().is_none());
    assert_eq!(replacement.seal_transport_cursor(candidate), candidate);
    drop(held);
    plane.shutdown().await;
}

/// Fault-fixture scope/cursor control only, not an MLS or recipient-join proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_delivery_defers_recovery_without_unpinning_or_consuming_original() {
    let (plane, adapter, alice) = cursor_floor_adapter(None, None);
    let (other_plane, other_adapter, _) = cursor_floor_adapter(None, None);
    let packet = cursor_floor_delivery(
        &alice,
        1,
        OPENED_CURSOR + 100,
        TransportDeliveryPlane::Group,
    );
    let held = plane.hold_account_delivery_for_test(alice.clone(), packet.message.id.clone());
    assert!(adapter.defer_held_recovery_for_test(&packet));
    assert_eq!(held.recovered_deferrals(), 1);
    assert_eq!(held.observed(), (0, 0, 0));
    assert!(!other_adapter.defer_held_recovery_for_test(&packet));
    let mut unrelated = packet.clone();
    unrelated.message.id = MessageId::new(vec![2; 32]);
    assert!(!adapter.defer_held_recovery_for_test(&unrelated));
    let mut other_account = packet.clone();
    other_account.account_id = MemberId::new(vec![0xB2; 32]);
    assert!(!adapter.defer_held_recovery_for_test(&other_account));
    // Preserve the exact account, event and GroupMessage envelope; vary only
    // the source plane so the recovery hold has the live hold's scope.
    for wrong_plane in [
        TransportDeliveryPlane::Discovery,
        TransportDeliveryPlane::AccountInbox,
        TransportDeliveryPlane::Ephemeral,
    ] {
        let mut wrong_source_plane = packet.clone();
        wrong_source_plane.source.plane = wrong_plane;
        assert!(!adapter.defer_held_recovery_for_test(&wrong_source_plane));
    }
    assert_eq!(held.recovered_deferrals(), 1);
    let welcome = cursor_floor_delivery(
        &alice,
        1,
        OPENED_CURSOR + 100,
        TransportDeliveryPlane::AccountInbox,
    );
    assert!(!adapter.defer_held_recovery_for_test(&welcome));
    plane.route_account_delivery_for_test(packet.clone());
    assert_eq!(held.observed(), (1, 0, 0));
    let candidate = Some(OPENED_CURSOR + 1_000);
    assert!(adapter.defer_held_recovery_for_test(&packet));
    assert_eq!(held.recovered_deferrals(), 2);
    assert_eq!(
        adapter.seal_transport_cursor(candidate),
        Some(OPENED_CURSOR + 100 + CURSOR_LOOKBACK)
    );
    assert!(adapter.try_receive_account_delivery().is_none());
    held.release();
    assert!(!adapter.defer_held_recovery_for_test(&packet));
    let received = timeout(Duration::from_secs(2), adapter.receive_account_delivery())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let AccountDeliveryReceive::Delivery(received) = received else {
        panic!("arrival hold must retain real delivery")
    };
    assert_eq!(received.message, packet.message);
    assert_eq!(
        adapter.seal_transport_cursor(candidate),
        Some(OPENED_CURSOR + 100 + CURSOR_LOOKBACK)
    );
    adapter.release_account_delivery(&packet.message.id);
    assert_eq!(adapter.seal_transport_cursor(candidate), candidate);
    drop(held);
    assert!(!adapter.defer_held_recovery_for_test(&packet));
    plane.shutdown().await;
    other_plane.shutdown().await;
}
