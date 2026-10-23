//! Actual Tokio channel behavior of the private selector used by the worker.
//! These are polling/cancellation tests, not protocol or native replay evidence.
use super::super::wait_for_worker_input;
use futures::future::Either;
use tokio::sync::{mpsc, watch};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn owed_offer_selects_ready_delivery_and_preserves_replay() {
    let (delivery_tx, mut delivery_rx) = mpsc::channel::<u8>(1);
    let (replay_tx, mut replay_rx) = watch::channel(0_u8);
    delivery_tx.send(7).await.unwrap();
    replay_tx.send(1).unwrap();
    let selected = timeout(Duration::from_secs(2), wait_for_worker_input(
        delivery_rx.recv(), replay_rx.changed(), true, true,
    )).await.expect("ready input selector is bounded");
    let delivery_selected = matches!(selected, Either::Right(Some(7)));
    let replay_unconsumed = replay_rx.has_changed().unwrap();
    let delivery_consumed = matches!(delivery_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty));
    // Both channel owners stay live through the discriminating reads; then
    // release every local resource before the sole intended counterfactual site.
    drop((delivery_tx, delivery_rx, replay_tx, replay_rx));
    assert!(
        delivery_selected && replay_unconsumed && delivery_consumed,
        "owed input offer must select ready delivery and preserve the replay version"
    );
}

#[tokio::test]
async fn ordinary_turn_selects_ready_replay_and_preserves_delivery() {
    let (delivery_tx, mut delivery_rx) = mpsc::channel::<u8>(1);
    let (replay_tx, mut replay_rx) = watch::channel(0_u8);
    delivery_tx.send(7).await.unwrap();
    replay_tx.send(1).unwrap();
    let selected = timeout(Duration::from_secs(2), wait_for_worker_input(
        delivery_rx.recv(), replay_rx.changed(), true, false,
    )).await.expect("ready input selector is bounded");
    let replay_selected = matches!(selected, Either::Left(Ok(())));
    let replay_consumed = !replay_rx.has_changed().unwrap();
    let delivery_retained = delivery_rx.try_recv() == Ok(7);
    drop((delivery_tx, delivery_rx, replay_tx, replay_rx));
    assert!(replay_selected && replay_consumed && delivery_retained);
}

#[tokio::test]
async fn owed_pending_receive_allows_replay_and_later_real_delivery() {
    let (delivery_tx, mut delivery_rx) = mpsc::channel::<u8>(1);
    let (replay_tx, mut replay_rx) = watch::channel(0_u8);
    // The live sender keeps this genuinely empty receive Pending, not closed.
    replay_tx.send(1).unwrap();
    let selected = timeout(Duration::from_secs(2), wait_for_worker_input(
        delivery_rx.recv(), replay_rx.changed(), true, true,
    )).await.expect("ready replay progresses past an empty open receive");
    let replay_selected = matches!(selected, Either::Left(Ok(())));
    let replay_consumed = !replay_rx.has_changed().unwrap();
    delivery_tx.send(7).await.unwrap();
    let later_delivery = delivery_rx.try_recv() == Ok(7);
    drop((delivery_tx, delivery_rx, replay_tx, replay_rx));
    assert!(replay_selected && replay_consumed && later_delivery);
}

#[tokio::test]
async fn disabled_receive_selects_replay_and_retains_ready_packet() {
    let (delivery_tx, mut delivery_rx) = mpsc::channel::<u8>(1);
    let (replay_tx, mut replay_rx) = watch::channel(0_u8);
    delivery_tx.send(7).await.unwrap();
    replay_tx.send(1).unwrap();
    let selected = timeout(Duration::from_secs(2), wait_for_worker_input(
        delivery_rx.recv(), replay_rx.changed(), false, true,
    )).await.expect("ready replay progresses with receive disabled");
    let replay_selected = matches!(selected, Either::Left(Ok(())));
    let replay_consumed = !replay_rx.has_changed().unwrap();
    let delivery_retained = delivery_rx.try_recv() == Ok(7);
    drop((delivery_tx, delivery_rx, replay_tx, replay_rx));
    assert!(replay_selected && replay_consumed && delivery_retained);
}
