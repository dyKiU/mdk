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

// Real public SDK/Core enrollment; no synthetic roster, original, policy or clock.
#[cfg(feature = "test-policy-overrides")]
use crate::{DeviceLinkingPhase, DeviceLinkingSession, MarmotAppRuntime};
#[cfg(feature = "test-policy-overrides")]
use std::time::Duration;

#[cfg(feature = "test-policy-overrides")]
async fn predecessor_exchange(from: &DeviceLinkingSession, to: &DeviceLinkingSession) {
    for packet in from.outgoing_packets().await.unwrap() {
        to.receive_packet(packet.bytes).await.unwrap();
        from.acknowledge_packet(packet.acknowledgement_id)
            .await
            .unwrap();
    }
}
#[cfg(feature = "test-policy-overrides")]
async fn predecessor_complete_pair(a: &DeviceLinkingSession, b: &DeviceLinkingSession, broad: bool) {
    b.receive_setup_packet(a.setup_packet()).await.unwrap();
    for _ in 0..8 {
        predecessor_exchange(a, b).await;
        predecessor_exchange(b, a).await;
    }
    let first = a.snapshot().await.unwrap();
    let second = b.snapshot().await.unwrap();
    assert!(
        first.phase == DeviceLinkingPhase::ComparisonAvailable && first.decimals == second.decimals
    );
    a.confirm_comparison(first.revision).await.unwrap();
    b.confirm_comparison(second.revision).await.unwrap();
    for _ in 0..8 {
        predecessor_exchange(a, b).await;
        predecessor_exchange(b, a).await;
    }
    if broad {
        a.continue_linking_and_share_chats(a.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        b.continue_linking_and_share_chats(b.snapshot().await.unwrap().revision)
            .await
            .unwrap();
    } else {
        a.continue_linking(a.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        b.continue_linking(b.snapshot().await.unwrap().revision)
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if a.snapshot().await.unwrap().phase == DeviceLinkingPhase::EnrollmentComplete
                && b.snapshot().await.unwrap().phase == DeviceLinkingPhase::EnrollmentComplete
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("actual completed original pair");
    a.cancel().await.unwrap();
    b.cancel().await.unwrap();
}

#[cfg(feature = "test-policy-overrides")]
#[test]
fn native_pair_sharing_waits_for_exact_predecessor_before_persistence() {
    crate::tests::run_composed_app_runtime_test("native-predecessor-readiness", || async {
        let relay =
            nostr_relay_builder::LocalRelay::new(nostr_relay_builder::RelayBuilder::default());
        relay.run().await.unwrap();
        let url = relay.url().await.to_string();
        let roots: [tempfile::TempDir; 3] = std::array::from_fn(|_| tempfile::tempdir().unwrap());
        let keys = nostr::prelude::Keys::generate();
        let apps: [MarmotApp; 3] = std::array::from_fn(|i| {
            marmot_account::AccountHome::open(roots[i].path())
                .import_account("test", &keys.secret_key().to_secret_hex())
                .unwrap();
            MarmotApp::with_relay(roots[i].path(), &url)
        });
        let runtimes = apps.clone().map(MarmotAppRuntime::new);
        runtimes[0].reconcile_accounts().await.unwrap();
        let b = runtimes[1]
            .accounts()
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let initial_a = runtimes[0]
            .accounts()
            .approve_device_linking_session("test", b.setup_packet(), None)
            .await
            .unwrap();
        predecessor_complete_pair(&initial_a, &b, false).await;
        let targets = runtimes[0]
            .accounts()
            .device_linking_targets("test")
            .await
            .unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].device_count, 2);
        let c = runtimes[2]
            .accounts()
            .begin_device_linking_session("test")
            .await
            .unwrap();
        let a = runtimes[0]
            .accounts()
            .approve_device_linking_session(
                "test",
                c.setup_packet(),
                Some(targets[0].selector.clone()),
            )
            .await
            .unwrap();
        // Decode only the genuine source-generated challenge. It is not a grant.
        let challenge: ChallengePacket = decode_packet(&a.setup_packet(), CHALLENGE).unwrap();
        assert_eq!(challenge.context.version, 2);
        assert_eq!(challenge.context.predecessor.leaves.len(), 2);
        let approval_id = challenge.context.digest().unwrap();
        let no_new_policy = |index: usize| {
            !apps[index]
                .account_storage("test")
                .unwrap()
                .approved_account_sharing_policy_storage()
                .unwrap()
                .approved_account_sharing_policies()
                .unwrap()
                .iter()
                .any(|policy| policy.approval_id == approval_id)
        };
        c.receive_setup_packet(a.setup_packet()).await.unwrap();
        for _ in 0..8 {
            predecessor_exchange(&a, &c).await;
            predecessor_exchange(&c, &a).await;
        }
        let sa = a.snapshot().await.unwrap();
        let sc = c.snapshot().await.unwrap();
        assert!(sa.phase == DeviceLinkingPhase::ComparisonAvailable && sa.decimals == sc.decimals);
        a.confirm_comparison(sa.revision).await.unwrap();
        c.confirm_comparison(sc.revision).await.unwrap();
        for _ in 0..8 {
            predecessor_exchange(&a, &c).await;
            predecessor_exchange(&c, &a).await;
        }
        a.continue_linking_and_share_chats(a.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        c.continue_linking_and_share_chats(c.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        let approval = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let mut pending = runtimes[1]
                    .accounts()
                    .pending_device_linking_approvals("test")
                    .await
                    .unwrap();
                if let Some(original) = pending.pop() {
                    break original;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        // B has not approved C. The existing command runs normal maintenance;
        // the getter only reports the owner-bound observation made at its actual
        // fresh Core read. No second client or fabricated roster is introduced.
        let waiting = runtimes[0]
            .accounts()
            .maintain_device_linking_at_for_test("test", std::time::Instant::now())
            .await;
        let native_denial = matches!(
            &waiting,
            Err(crate::client::device_linking::ClientLinkingError::Engine(
                cgka_traits::EngineError::Storage(cgka_traits::storage::StorageError::Serialization(message))
            )) if message == "original pairing sharing approval unavailable"
        );
        let predecessor = a.predecessor_readiness_for_test();
        let no_policy_while_waiting = no_new_policy(0) && no_new_policy(2);
        let pending = a.snapshot().await.unwrap().phase
            == DeviceLinkingPhase::VerificationCompleteEnrollmentPending;
        let review = approval.snapshot().await.unwrap();
        assert!(
            approval
                .approve_and_share_chats(review.revision + 1)
                .await
                .is_err()
        );
        approval
            .approve_and_share_chats(review.revision)
            .await
            .unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Ok(packet) = a
                    .enrollment_packet(a.snapshot().await.unwrap().revision)
                    .await
                {
                    break packet;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        c.receive_enrollment_packet(c.snapshot().await.unwrap().revision, packet.clone())
            .await
            .unwrap();
        approval
            .receive_enrollment_packet(approval.snapshot().await.unwrap().revision, packet)
            .await
            .unwrap();
        a.finalize_linking(a.snapshot().await.unwrap().revision)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                if c.snapshot().await.unwrap().phase == DeviceLinkingPhase::EnrollmentComplete
                    && approval.snapshot().await.unwrap().phase
                        == crate::DeviceLinkingApprovalPhase::Settled
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        a.cancel().await.unwrap();
        c.cancel().await.unwrap();
        approval.cancel().await.unwrap();
        let successor_policies = !no_new_policy(0) && !no_new_policy(2);
        for runtime in &runtimes {
            runtime.shutdown_and_close().await.unwrap();
        }
        let storage_closed = apps.iter().all(MarmotApp::storage_is_closed);
        println!(
            "native-predecessor-readiness exact={} live={} primary={} pending={} no_policy={} successor_policies={} shutdown_returns=3 storage_closed={} native_denial={} waiting_ok={}",
            predecessor.is_some_and(|v| v.0),
            predecessor.is_some_and(|v| v.1),
            predecessor.is_some_and(|v| v.2),
            pending,
            no_policy_while_waiting,
            successor_policies,
            storage_closed,
            native_denial,
            waiting.is_ok(),
        );
        assert!(predecessor == Some((true, true, false)));
        assert!(pending && no_policy_while_waiting);
        assert!(successor_policies && storage_closed);
        assert!(
            waiting.is_ok() || native_denial,
            "maintenance failed outside the original pairing policy boundary"
        );
        assert!(
            waiting.is_ok(),
            "live exact predecessor must wait without committing the new pairing policy"
        );
    });
}
