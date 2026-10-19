//! Real stock SDK verification into the private policy boundary. Opaque package
//! fixtures here test context binding; real MLS parsing/join is covered by the
//! engine purpose-Welcome suite, not claimed by these verifier-only fixtures.
use super::*;
use crate::device_linking::owner::LinkingOwner;
use crate::device_linking::{DeviceLinker, Role, VerifiedPairing};
use std::sync::Arc;
use std::time::Instant;
async fn drain(from: &mut LinkingOwner, to: &mut LinkingOwner, now: Instant) {
    for frame in from.outgoing(now).unwrap() {
        to.receive(&frame, now).await.unwrap();
        from.acknowledge(&frame.token, now).await.unwrap();
    }
}
fn storage() -> Arc<storage_sqlite::SqliteAccountStorage> {
    let storage = Arc::new(storage_sqlite::SqliteAccountStorage::in_memory().unwrap());
    storage
        .app_storage()
        .ensure_account_projection_with_identity("isolated-real-gate-test", &hex::encode([2; 32]))
        .unwrap();
    storage
}
async fn verified() -> (VerifiedPairing, VerifiedPairing) {
    verified_for_context(
        crate::device_linking::tests::context(),
        storage(),
        storage(),
    )
    .await
}
pub(in crate::device_linking) async fn verified_for_context(
    context: crate::device_linking::LinkingContext,
    new_storage: Arc<storage_sqlite::SqliteAccountStorage>,
    approver_storage: Arc<storage_sqlite::SqliteAccountStorage>,
) -> (VerifiedPairing, VerifiedPairing) {
    let now = Instant::now();
    let mut a = LinkingOwner::startup(new_storage, context.account, context.recipient).unwrap();
    let mut b = LinkingOwner::startup(approver_storage, context.account, context.approver).unwrap();
    assert_eq!(a.reserve().unwrap(), context.new_device_generation);
    assert_eq!(b.reserve().unwrap(), context.approver_generation);
    a.begin(context.clone(), Role::NewDevice, now)
        .await
        .unwrap();
    b.begin(context, Role::Approver, now).await.unwrap();
    let ao = a.offer(now).unwrap();
    let bo = b.offer(now).unwrap();
    a.admit_peer(&bo, now).await.unwrap();
    b.admit_peer(&ao, now).await.unwrap();
    a.start_verification(now).await.unwrap();
    for _ in 0..8 {
        drain(&mut a, &mut b, now).await;
        drain(&mut b, &mut a, now).await;
    }
    assert!(a.decimals(now).unwrap().is_some());
    assert!(a.decimals(now).unwrap() == b.decimals(now).unwrap());
    a.confirm(now).await.unwrap();
    b.confirm(now).await.unwrap();
    for _ in 0..8 {
        drain(&mut a, &mut b, now).await;
        drain(&mut b, &mut a, now).await;
    }
    (
        a.take_verified(now).await.unwrap(),
        b.take_verified(now).await.unwrap(),
    )
}
async fn raw_verified() -> VerifiedPairing {
    let now = Instant::now();
    let mut a = DeviceLinker::new();
    let mut b = DeviceLinker::new();
    let context = crate::device_linking::tests::context();
    a.begin(context.clone(), Role::NewDevice, 1, now)
        .await
        .unwrap();
    b.begin(context, Role::Approver, 1, now).await.unwrap();
    let ao = a.offer(now).unwrap();
    let bo = b.offer(now).unwrap();
    a.admit_peer(&bo, now).await.unwrap();
    b.admit_peer(&ao, now).await.unwrap();
    a.start_verification(now).await.unwrap();
    for _ in 0..8 {
        for frame in a.outgoing(now).unwrap() {
            b.receive(&frame, now).await.unwrap();
            a.acknowledge(&frame.token, now).await.unwrap();
        }
        for frame in b.outgoing(now).unwrap() {
            a.receive(&frame, now).await.unwrap();
            b.acknowledge(&frame.token, now).await.unwrap();
        }
    }
    a.confirm(now).await.unwrap();
    b.confirm(now).await.unwrap();
    for _ in 0..8 {
        for frame in a.outgoing(now).unwrap() {
            b.receive(&frame, now).await.unwrap();
            a.acknowledge(&frame.token, now).await.unwrap();
        }
        for frame in b.outgoing(now).unwrap() {
            a.receive(&frame, now).await.unwrap();
            b.acknowledge(&frame.token, now).await.unwrap();
        }
    }
    a.take_verified(now).await.unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_gate_accepts_only_owner_stamped_new_device_sdk_result() {
    let (new_device, approver) = verified().await;
    assert!(new_device.owner_deadline.is_some());
    let gate = RuntimeWelcomeGate::new();
    assert!(gate.arm(approver).is_err());
    gate.arm(new_device).unwrap();
    let raw = raw_verified().await;
    assert!(raw.owner_deadline.is_none());
    assert!(RuntimeWelcomeGate::new().arm(raw).is_err());
}

use cgka_engine::linking_welcome_policy::{AuthenticatedLinkingWelcome, LinkingWelcomePolicy};
use cgka_traits::device_linking_key_package::{
    PurposeAttemptScope, PurposeContextBinding, PurposeKeyPackage,
};
fn purpose(context: &crate::device_linking::LinkingContext) -> PurposeKeyPackage {
    PurposeKeyPackage {
        scope: PurposeAttemptScope {
            account: context.account,
            local_device: context.recipient,
            generation: context.new_device_generation,
        },
        public_bytes: context.exact_key_package.clone(),
        reference: context.key_package_reference.to_vec(),
        signature_public_key: context.recipient.to_vec(),
        context: Some(PurposeContextBinding {
            nonce: context.nonce,
            context_digest: context.digest().unwrap(),
        }),
        consumed: false,
    }
}
fn authenticated(context: &crate::device_linking::LinkingContext) -> AuthenticatedLinkingWelcome {
    AuthenticatedLinkingWelcome {
        group_id: cgka_traits::GroupId::new(context.device_group.clone()),
        own_account: cgka_traits::MemberId::new(context.account.to_vec()),
        own_signature_public_key: context.recipient.to_vec(),
        own_leaf_index: 1,
        welcomer_account: cgka_traits::MemberId::new(context.account.to_vec()),
        welcomer_signature_public_key: context.approver.to_vec(),
        welcomer_leaf_index: 0,
        joined_epoch: cgka_traits::EpochId(context.predecessor.epoch + 1),
        protocol_profile: cgka_traits::group::ProtocolProfile::Current,
        private_device_profile: true,
        epoch_authenticator_digest: [42; 32],
        leaves: vec![
            cgka_engine::linking_welcome_policy::AuthenticatedLinkingLeaf {
                leaf_index: 0,
                account: cgka_traits::MemberId::new(context.account.to_vec()),
                signature_public_key: context.approver.to_vec(),
            },
            cgka_engine::linking_welcome_policy::AuthenticatedLinkingLeaf {
                leaf_index: 1,
                account: cgka_traits::MemberId::new(context.account.to_vec()),
                signature_public_key: context.recipient.to_vec(),
            },
        ],
    }
}

fn transport_context(
    context: &crate::device_linking::LinkingContext,
) -> cgka_traits::peeler::PrivateLinkingWelcomeContext {
    use sha2::{Digest, Sha256};
    cgka_traits::peeler::PrivateLinkingWelcomeContext {
        account: context.account,
        approver: context.approver,
        recipient: context.recipient,
        approver_generation: context.approver_generation,
        recipient_generation: context.new_device_generation,
        group_id: cgka_traits::GroupId::new(context.device_group.clone()),
        nonce: context.nonce,
        context_digest: context.digest().unwrap(),
        key_package_reference: context.key_package_reference,
        key_package_digest: Sha256::digest(&context.exact_key_package).into(),
        commit_digest: [31; 32],
        welcome_digest: [32; 32],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_gate_transport_matches_real_sdk_and_predecessor_requires_authenticated_tree() {
    let (token, _) = verified().await;
    let context = token.context.clone();
    let gate = RuntimeWelcomeGate::new();
    gate.arm(token).unwrap();
    let expected = purpose(&context);
    let mut lease = gate.begin_join(&expected).unwrap();
    assert!(lease.approved_predecessor().is_err());
    assert!(lease.check_authenticated(&authenticated(&context)).is_err());
    lease
        .check_transport_context(&transport_context(&context))
        .unwrap();
    assert!(lease.approved_predecessor().is_err());
    let mut ordinary = authenticated(&context);
    ordinary.private_device_profile = false;
    assert!(lease.check_authenticated(&ordinary).is_err());
    assert!(lease.check_live_before_commit().is_err());
    assert!(lease.approved_predecessor().is_err());
    lease.check_authenticated(&authenticated(&context)).unwrap();
    lease.check_live_before_commit().unwrap();
    let predecessor = lease.approved_predecessor().unwrap();
    assert_eq!(predecessor.epoch.0, context.predecessor.epoch);
    assert_eq!(
        predecessor.epoch_authenticator_digest,
        context.predecessor.epoch_authenticator_digest
    );
    assert_eq!(predecessor.leaves.len(), context.predecessor.leaves.len());
    for (actual, expected) in predecessor.leaves.iter().zip(&context.predecessor.leaves) {
        assert_eq!(actual.account, context.account);
        assert_eq!(actual.leaf_index, expected.leaf_index);
        assert_eq!(actual.signature_public_key, expected.signature_public_key);
    }
    let mut substituted = transport_context(&context);
    substituted.nonce[0] ^= 1;
    assert!(lease.check_transport_context(&substituted).is_err());
    assert!(lease.approved_predecessor().is_err());
    assert!(lease.check_live_before_commit().is_err());
    assert!(lease.check_authenticated(&authenticated(&context)).is_err());
    lease
        .check_transport_context(&transport_context(&context))
        .unwrap();
    lease.check_authenticated(&authenticated(&context)).unwrap();
    let mut wrong = authenticated(&context);
    wrong.leaves[0].signature_public_key[0] ^= 1;
    assert!(lease.check_authenticated(&wrong).is_err());
    assert!(lease.approved_predecessor().is_err());
    assert!(lease.check_live_before_commit().is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_gate_transport_rejects_every_substituted_sdk_binding_without_consuming_token() {
    let (token, _) = verified().await;
    let context = token.context.clone();
    let gate = RuntimeWelcomeGate::new();
    gate.arm(token).unwrap();
    let expected = purpose(&context);
    let original = transport_context(&context);
    for mutation in 0..10 {
        let mut altered = original.clone();
        match mutation {
            0 => altered.account[0] ^= 1,
            1 => altered.approver[0] ^= 1,
            2 => altered.recipient[0] ^= 1,
            3 => altered.approver_generation += 1,
            4 => altered.recipient_generation += 1,
            5 => altered.group_id = cgka_traits::GroupId::new(vec![99; 16]),
            6 => altered.nonce[0] ^= 1,
            7 => altered.context_digest[0] ^= 1,
            8 => altered.key_package_reference[0] ^= 1,
            _ => altered.key_package_digest[0] ^= 1,
        }
        let mut lease = gate.begin_join(&expected).unwrap();
        assert!(lease.check_transport_context(&altered).is_err());
        assert!(lease.approved_predecessor().is_err());
    }
    let mut lease = gate.begin_join(&expected).unwrap();
    let mut post_preparation_metadata = original;
    post_preparation_metadata.commit_digest[0] ^= 1;
    post_preparation_metadata.welcome_digest[0] ^= 1;
    lease
        .check_transport_context(&post_preparation_metadata)
        .unwrap();
    assert!(lease.approved_predecessor().is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_gate_transport_and_predecessor_preserve_original_expiry_and_shutdown() {
    let (token, _) = verified().await;
    let context = token.context.clone();
    let deadline = token.owner_deadline.unwrap();
    let clock = Arc::new(ManualClock(std::sync::Mutex::new(Instant::now())));
    let gate = RuntimeWelcomeGate::with_clock(clock.clone());
    gate.arm(token).unwrap();
    let mut lease = gate.begin_join(&purpose(&context)).unwrap();
    lease
        .check_transport_context(&transport_context(&context))
        .unwrap();
    lease.check_authenticated(&authenticated(&context)).unwrap();
    lease.approved_predecessor().unwrap();
    *clock.0.lock().unwrap() = deadline;
    assert!(matches!(
        lease.approved_predecessor(),
        Err(LinkingWelcomeDenied::Expired)
    ));
    assert!(matches!(
        lease.check_transport_context(&transport_context(&context)),
        Err(LinkingWelcomeDenied::Expired)
    ));
    drop(lease);

    let (token, _) = verified().await;
    let context = token.context.clone();
    let gate = RuntimeWelcomeGate::new();
    gate.arm(token).unwrap();
    let mut lease = gate.begin_join(&purpose(&context)).unwrap();
    lease
        .check_transport_context(&transport_context(&context))
        .unwrap();
    lease.check_authenticated(&authenticated(&context)).unwrap();
    gate.shutdown();
    assert!(matches!(
        lease.approved_predecessor(),
        Err(LinkingWelcomeDenied::Cancelled)
    ));
    assert!(matches!(
        lease.check_transport_context(&transport_context(&context)),
        Err(LinkingWelcomeDenied::Cancelled)
    ));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_gate_shutdown_revokes_outstanding_lease_and_retained_policy() {
    let (token, _) = verified().await;
    let expected = purpose(&token.context);
    let gate = Arc::new(RuntimeWelcomeGate::new());
    gate.arm(token).unwrap();
    let mut lease = gate.begin_join(&expected).unwrap();
    gate.shutdown();
    assert!(
        matches!(
            lease.check_live_before_commit(),
            Err(cgka_engine::linking_welcome_policy::LinkingWelcomeDenied::Cancelled)
        ),
        "shutdown must revoke even while an owned join lease holds the gate mutex"
    );
    drop(lease);
    assert!(gate.begin_join(&expected).is_err());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_gate_context_substitution_and_failed_authenticated_check_preserve_only_exact_retry()
 {
    let (token, _) = verified().await;
    let context = token.context.clone();
    let expected = purpose(&context);
    let gate = RuntimeWelcomeGate::new();
    gate.arm(token).unwrap();
    for mutation in 0..7 {
        let mut altered = expected.clone();
        match mutation {
            0 => altered.public_bytes[0] ^= 1,
            1 => altered.reference[0] ^= 1,
            2 => altered.scope.generation += 1,
            3 => altered.scope.account[0] ^= 1,
            4 => altered.scope.local_device[0] ^= 1,
            5 => altered.context.as_mut().unwrap().nonce[0] ^= 1,
            _ => altered.context.as_mut().unwrap().context_digest[0] ^= 1,
        }
        assert!(gate.begin_join(&altered).is_err());
    }
    let mut lease = gate.begin_join(&expected).unwrap();
    let mut wrong = authenticated(&context);
    wrong.welcomer_signature_public_key[0] ^= 1;
    lease
        .check_transport_context(&transport_context(&context))
        .unwrap();
    assert!(lease.check_authenticated(&wrong).is_err());
    drop(lease);
    let mut retry = gate.begin_join(&expected).unwrap();
    retry
        .check_transport_context(&transport_context(&context))
        .unwrap();
    retry.check_authenticated(&authenticated(&context)).unwrap();
    retry.check_live_before_commit().unwrap();
    // Only exercise the memory notification boundary; this synthetic receipt
    // is not claimed as a real MLS join (the engine suite owns that proof).
    retry.commit_accepted(&cgka_traits::accepted_welcome::AcceptedWelcomeReceipt {
        welcome_id: cgka_traits::MessageId::new(vec![1]),
        content_id: cgka_traits::MessageId::new(vec![2]),
        group_id: cgka_traits::GroupId::new(context.device_group),
        consumed_key_package_ref: context.key_package_reference.to_vec(),
        own_account: cgka_traits::MemberId::new(context.account.to_vec()),
        own_signature_public_key: context.recipient.to_vec(),
        welcomer_account: cgka_traits::MemberId::new(context.account.to_vec()),
        welcomer_signature_public_key: context.approver.to_vec(),
        joined_epoch: cgka_traits::EpochId(0),
        joined_epoch_authenticator_digest: [42; 32],
    });
    assert!(gate.begin_join(&expected).is_err());
}

struct ManualClock(std::sync::Mutex<Instant>);
impl Clock for ManualClock {
    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_gate_original_expiry_revokes_a_held_lease_and_cancel_is_serial() {
    let (token, _) = verified().await;
    let deadline = token.owner_deadline.unwrap();
    let context = token.context.clone();
    let expected = purpose(&context);
    let clock = Arc::new(ManualClock(std::sync::Mutex::new(Instant::now())));
    let gate = RuntimeWelcomeGate::with_clock(clock.clone());
    gate.arm(token).unwrap();
    let mut lease = gate.begin_join(&expected).unwrap();
    assert!(gate.has_retained_token_for_negative_completion(), "busy real join lease must deny negative completion");
    assert!(
        gate.cancel().is_err(),
        "busy cancellation must not mutate the lease"
    );
    assert!(gate.has_retained_token_for_negative_completion());
    lease
        .check_transport_context(&transport_context(&context))
        .unwrap();
    lease.check_authenticated(&authenticated(&context)).unwrap();
    lease.check_live_before_commit().unwrap();
    *clock.0.lock().unwrap() = deadline;
    assert!(matches!(
        lease.check_live_before_commit(),
        Err(LinkingWelcomeDenied::Expired)
    ));
    drop(lease);
    assert!(matches!(
        gate.begin_join(&expected),
        Err(LinkingWelcomeDenied::Expired)
    ));
    gate.cancel().unwrap();
    assert!(matches!(
        gate.begin_join(&expected),
        Err(LinkingWelcomeDenied::Cancelled)
    ));
}
mod real_mls;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_gate_maintenance_discards_original_expired_approval() {
    let (token, _) = verified().await;
    let deadline = token.owner_deadline.unwrap();
    let expected = purpose(&token.context);
    let clock = Arc::new(ManualClock(std::sync::Mutex::new(Instant::now())));
    let gate = RuntimeWelcomeGate::with_clock(clock.clone());
    gate.arm(token).unwrap();
    assert!(gate.maintain().unwrap());
    let lease = gate.begin_join(&expected).unwrap();
    assert!(gate.maintain().is_err());
    drop(lease);
    *clock.0.lock().unwrap() = deadline;
    assert!(!gate.maintain().unwrap());
    assert!(!gate.maintain().unwrap());
    assert!(matches!(
        gate.begin_join(&expected),
        Err(LinkingWelcomeDenied::Expired)
    ));
}
