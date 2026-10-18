use super::*;
use crate::{AppClient, MarmotApp};
use cgka_traits::device_linking_key_package::PurposeAttemptScope;
use marmot_account::AccountHome;
use std::sync::Arc;

async fn client(directory: &tempfile::TempDir, keys: &nostr::prelude::Keys) -> AppClient {
    AccountHome::open(directory.path())
        .import_account("test", &keys.secret_key().to_secret_hex())
        .unwrap();
    MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()))
        .client("test")
        .await
        .unwrap()
}

async fn drain(
    from: &mut AppClient,
    to: &mut AppClient,
    a: &PurposeAttemptScope,
    b: &PurposeAttemptScope,
) {
    for frame in from.device_linking_outgoing(a).unwrap() {
        to.receive_device_linking_frame(b, &frame).await.unwrap();
        from.acknowledge_device_linking_frame(a, frame.acknowledgement_token())
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_factories_bind_real_purpose_and_complete_original_sdk() {
    let keys = nostr::prelude::Keys::generate();
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let mut a = client(&directories[0], &keys).await;
    let mut c = client(&directories[1], &keys).await;
    let mut request = c.reserve_linking_setup_request().await.unwrap();
    let challenge = a
        .begin_linking_setup_request(request.packet(), None)
        .await
        .unwrap();
    c.accept_linking_setup_challenge(&mut request, challenge.packet())
        .await
        .unwrap();
    // An exact retransmission observes the existing SDK flow rather than restarting it.
    c.accept_linking_setup_challenge(&mut request, challenge.packet())
        .await
        .unwrap();
    let a_offer = a.device_linking_offer(challenge.scope()).unwrap();
    let c_offer = c.device_linking_offer(request.scope()).unwrap();
    a.admit_device_linking_peer(challenge.scope(), &c_offer)
        .await
        .unwrap();
    c.admit_device_linking_peer(request.scope(), &a_offer)
        .await
        .unwrap();
    assert!(
        a.start_device_linking_verification(challenge.scope())
            .await
            .is_err()
    );
    c.start_device_linking_verification(request.scope())
        .await
        .unwrap();
    for _ in 0..8 {
        drain(&mut a, &mut c, challenge.scope(), request.scope()).await;
        drain(&mut c, &mut a, request.scope(), challenge.scope()).await;
    }
    let decimals = a.device_linking_decimals(challenge.scope()).unwrap();
    assert!(decimals.is_some());
    assert_eq!(
        decimals,
        c.device_linking_decimals(request.scope()).unwrap()
    );
    assert!(
        a.take_device_linking_verified(challenge.scope())
            .await
            .is_err()
    );
    assert!(
        c.take_device_linking_verified(request.scope())
            .await
            .is_err()
    );
    a.confirm_device_linking(challenge.scope()).await.unwrap();
    c.confirm_device_linking(request.scope()).await.unwrap();
    for _ in 0..4 {
        drain(&mut a, &mut c, challenge.scope(), request.scope()).await;
        drain(&mut c, &mut a, request.scope(), challenge.scope()).await;
    }
    a.take_device_linking_verified(challenge.scope())
        .await
        .unwrap();
    c.take_device_linking_verified(request.scope())
        .await
        .unwrap();
    assert!(a.state.groups.is_empty());
    assert!(c.state.groups.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_challenge_substitution_preserves_original_purpose_and_valid_retry() {
    let keys = nostr::prelude::Keys::generate();
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let mut a = client(&directories[0], &keys).await;
    let mut c = client(&directories[1], &keys).await;
    let mut request = c.reserve_linking_setup_request().await.unwrap();
    let challenge = a
        .begin_linking_setup_request(request.packet(), None)
        .await
        .unwrap();
    let mut altered: ChallengePacket = decode_packet(challenge.packet(), CHALLENGE).unwrap();
    altered.context.exact_key_package[0] ^= 1;
    let wrong = encode_packet(&altered, CHALLENGE).unwrap();
    assert!(
        c.accept_linking_setup_challenge(&mut request, &wrong)
            .await
            .is_err()
    );
    c.accept_linking_setup_challenge(&mut request, challenge.packet())
        .await
        .unwrap();
    c.cancel_device_linking_scope(request.scope())
        .await
        .unwrap();
    assert!(
        c.accept_linking_setup_challenge(&mut request, challenge.packet())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_ordinary_group_is_not_promoted_to_protected_predecessor() {
    let keys = nostr::prelude::Keys::generate();
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let mut a = client(&directories[0], &keys).await;
    let mut c = client(&directories[1], &keys).await;
    let ordinary = a.create_group("ordinary", &[]).await.unwrap();
    let request = c.reserve_linking_setup_request().await.unwrap();
    assert!(
        a.begin_linking_setup_request(request.packet(), Some(&ordinary))
            .await
            .is_err()
    );
    // Refusing the target cleans only A's new reservation, so a proper retry still works.
    a.begin_linking_setup_request(request.packet(), None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_request_framing_and_crypto_substitution_are_rejected_before_reservation() {
    let keys = nostr::prelude::Keys::generate();
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let mut a = client(&directories[0], &keys).await;
    let mut c = client(&directories[1], &keys).await;
    let request = c.reserve_linking_setup_request().await.unwrap();
    let mut wrong: RequestPacket = decode_packet(request.packet(), REQUEST).unwrap();
    wrong.package.bytes[0] ^= 1;
    assert!(
        a.begin_linking_setup_request(&encode_packet(&wrong, REQUEST).unwrap(), None)
            .await
            .is_err()
    );
    let mut trailing = request.packet().to_vec();
    trailing.push(b' ');
    assert!(
        a.begin_linking_setup_request(&trailing, None)
            .await
            .is_err()
    );
    assert!(
        a.begin_linking_setup_request(&vec![0; MAX_SETUP_PACKET_BYTES + 1], None)
            .await
            .is_err()
    );
    a.begin_linking_setup_request(request.packet(), None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_foreign_account_request_cannot_replace_original_approver_flow() {
    let keys = nostr::prelude::Keys::generate();
    let directories = [
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    ];
    let mut a = client(&directories[0], &keys).await;
    let mut c = client(&directories[1], &keys).await;
    let mut foreign = client(&directories[2], &nostr::prelude::Keys::generate()).await;
    let request = c.reserve_linking_setup_request().await.unwrap();
    let challenge = a
        .begin_linking_setup_request(request.packet(), None)
        .await
        .unwrap();
    let old_offer = a
        .device_linking_offer(challenge.scope())
        .unwrap()
        .encode_wire()
        .unwrap();
    let wrong = foreign.reserve_linking_setup_request().await.unwrap();
    assert!(
        a.begin_linking_setup_request(wrong.packet(), None)
            .await
            .is_err()
    );
    assert_eq!(
        old_offer,
        a.device_linking_offer(challenge.scope())
            .unwrap()
            .encode_wire()
            .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_encrypted_reopen_cannot_recreate_the_original_request_owner() {
    let keys = nostr::prelude::Keys::generate();
    let directories = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let mut a = client(&directories[0], &keys).await;
    let mut c = client(&directories[1], &keys).await;
    let mut request = c.reserve_linking_setup_request().await.unwrap();
    let challenge = a
        .begin_linking_setup_request(request.packet(), None)
        .await
        .unwrap();
    drop(c);
    let mut reopened = MarmotApp::with_relay(directories[1].path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()))
        .client("test")
        .await
        .unwrap();
    assert!(
        reopened
            .accept_linking_setup_challenge(&mut request, challenge.packet())
            .await
            .is_err()
    );
}
