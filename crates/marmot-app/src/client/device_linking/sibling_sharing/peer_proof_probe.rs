//! Test-only passive snapshots and one original recipient's real publication hold.
// COMMAND_BACKLOG_TEST_BEGIN
#[cfg(all(
    test,
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
pub(crate) mod command_backlog;
// COMMAND_BACKLOG_TEST_END
use super::*;
// REQUEST_RETRY_TEST_BEGIN
#[cfg(all(test, feature = "test-policy-overrides"))]
pub(crate) mod retry_completion;
// REQUEST_RETRY_TEST_END
// PEER_NEGATIVE_TEST_BEGIN
pub(crate) mod negative;
// PEER_NEGATIVE_TEST_END
#[cfg(all(test, feature = "test-policy-overrides"))]
pub(crate) mod recipient_retry_priority;
use std::sync::{OnceLock, Weak};
use tokio::sync::Notify;

type Existing = crate::client::private_enrollment_proposal::OriginalSiblingSharingApproval;

pub(crate) struct Snapshot {
    // Non-owning actor-receiver identity and frozen channel group; never serialized.
    pub(crate) receiver_identity: transport_nostr::AccountReceiverIdentityForTest,
    pub(crate) protected_group: cgka_traits::GroupId,
    pub(crate) nonce: [u8; 32],
    // Original live, state live, policy, own proof harvested, peer proof,
    // publication present, complete, exact durable policy. These are fresh actor-owned values.
    pub(crate) flags: [bool; 8],
    // PEER_NEGATIVE_TEST_BEGIN
    pub(crate) deadline: Instant,
    pub(crate) pending_controls: usize,
    // PEER_NEGATIVE_TEST_END
    // LATE_CONSENT_TEST_BEGIN
    // Fresh Core-bound consent readiness and actual owned Request ACK harvest.
    pub(crate) consent_ordering: [bool; 2],
    // LATE_CONSENT_TEST_END
}

pub(crate) struct ProofGate {
    owner: Weak<OriginalEnrollmentSharingChoice>,
    fired: AtomicBool,
    nonce: Mutex<Option<[u8; 32]>>,
    // PEER_NEGATIVE_TEST_BEGIN
    prepared: Mutex<Vec<([u8; 32], [u8; 32])>>,
    // PEER_NEGATIVE_TEST_END
    observed: Notify,
    release: Notify,
}

pub(crate) struct Guard(Arc<ProofGate>);
impl Guard {
    // PEER_NEGATIVE_TEST_BEGIN
    pub(crate) fn prepared_digest(&self, nonce: [u8; 32]) -> Option<[u8; 32]> {
        self.0
            .prepared
            .lock()
            .expect("prepared peer proof")
            .iter()
            .find(|row| row.0 == nonce)
            .map(|row| row.1)
    }
    // PEER_NEGATIVE_TEST_END
    pub(crate) async fn observed(&self) -> Option<[u8; 32]> {
        self.0.observed.notified().await;
        *self.0.nonce.lock().expect("peer proof nonce")
    }
    pub(crate) fn release(&self) {
        self.0.release.notify_one();
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.release();
    }
}

fn registry() -> &'static Mutex<Vec<Weak<ProofGate>>> {
    static REGISTRY: OnceLock<Mutex<Vec<Weak<ProofGate>>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

pub(crate) fn arm(owner: &Arc<OriginalEnrollmentSharingChoice>) -> Guard {
    let gate = Arc::new(ProofGate {
        owner: Arc::downgrade(owner),
        fired: AtomicBool::new(false),
        nonce: Mutex::new(None),
        // PEER_NEGATIVE_TEST_BEGIN
        prepared: Mutex::new(Vec::new()),
        // PEER_NEGATIVE_TEST_END
        observed: Notify::new(),
        release: Notify::new(),
    });
    let mut gates = registry().lock().expect("peer proof gates");
    gates.retain(|gate| gate.strong_count() != 0);
    assert!(gates.len() < 4, "bounded test publication holds");
    assert!(
        !gates
            .iter()
            .filter_map(Weak::upgrade)
            .any(|old| old.owner.ptr_eq(&gate.owner))
    );
    gates.push(Arc::downgrade(&gate));
    Guard(gate)
}

// Called only inside the original publication's cancellation/deadline select.
pub(super) async fn hold(original: &Arc<SiblingOriginal>, nonce: [u8; 32]) {
    let SiblingOriginal::Recipient { choice, .. } = original.as_ref() else {
        return;
    };
    let gate = {
        let gates = registry().lock().expect("peer proof gates");
        gates.iter().filter_map(Weak::upgrade).find(|gate| {
            gate.owner.ptr_eq(&Arc::downgrade(choice)) && !gate.fired.swap(true, Ordering::AcqRel)
        })
    };
    if let Some(gate) = gate {
        *gate.nonce.lock().expect("peer proof nonce") = Some(nonce);
        gate.observed.notify_one();
        gate.release.notified().await;
    }
}

impl AppClient {
    pub(crate) fn peer_proof_snapshot_for_test(&self, owner: &Weak<Existing>) -> Option<Snapshot> {
        let owner = owner.upgrade()?;
        let mut matches = self.linking_owner.sibling_channels.iter().filter(|entry| {
            matches!(entry.original.as_ref(), SiblingOriginal::Existing { original, .. } if Arc::ptr_eq(original, &owner))
        });
        let entry = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        let scope = entry.channel.scope();
        let durable = self
            .app
            .account_storage(&self.state.label)
            .ok()?
            .approved_account_sharing_policy_storage()?
            .approved_account_sharing_policies()
            .ok()?
            .iter()
            .any(|policy| {
                policy.local_device.as_slice() == scope.source.as_slice()
                    && policy.peer_device.as_slice() == scope.recipient.as_slice()
                    && policy.protected_group == scope.protected.group_id
                    && policy.approval_id == scope.approval_id
                    && !policy.revoked
            });
        Some(Snapshot {
            receiver_identity: self.adapter.receiver_snapshot_for_test().1,
            protected_group: scope.protected.group_id.clone(),
            // PEER_NEGATIVE_TEST_BEGIN
            deadline: entry.state.deadline,
            pending_controls: entry.pending_controls.len()
                + entry
                    .pending_opaque
                    .lock()
                    .expect("sibling pending opaque")
                    .len(),
            // PEER_NEGATIVE_TEST_END
            // LATE_CONSENT_TEST_BEGIN
            consent_ordering: [entry.ready, entry.handshake_published],
            // LATE_CONSENT_TEST_END
            nonce: entry.channel.scope().nonce,
            flags: [
                entry.original.live(),
                entry.state.live(),
                entry.policy_committed,
                entry.proof_published,
                entry.peer_committed,
                entry.publication.is_some(),
                entry
                    .state
                    .progress
                    .lock()
                    .expect("sharing progress")
                    .complete,
                durable,
            ],
        })
    }
}
// RECIPIENT_ADMISSION_TEST_BEGIN
/// Passive observation of Core-approved recipient channel admission only.
pub(crate) mod recipient_admission {
    use super::*;

    #[derive(Clone, Copy)]
    pub(crate) struct Admission {
        pub(crate) nonce: [u8; 32],
        // Original live, child live, recipient, ready, handshake ACK harvested,
        // publication present: copied synchronously immediately after admission.
        pub(crate) flags: [bool; 6],
    }
    struct Probe {
        owner: Weak<OriginalEnrollmentSharingChoice>,
        admitted: Mutex<Option<Admission>>,
        observed: Notify,
    }
    pub(crate) struct AdmissionGuard(Arc<Probe>);
    impl AdmissionGuard {
        pub(crate) async fn observed(&self) -> Admission {
            self.0.observed.notified().await;
            self.0
                .admitted
                .lock()
                .expect("recipient admission")
                .expect("actual admitted child")
        }
    }
    fn registry() -> &'static Mutex<Vec<Weak<Probe>>> {
        static REGISTRY: OnceLock<Mutex<Vec<Weak<Probe>>>> = OnceLock::new();
        REGISTRY.get_or_init(Default::default)
    }
    impl Guard {
        pub(crate) fn arm_recipient_admission_for_test(&self) -> AdmissionGuard {
            let probe = Arc::new(Probe {
                owner: self.0.owner.clone(),
                admitted: Mutex::new(None),
                observed: Notify::new(),
            });
            let mut probes = registry().lock().expect("recipient admission probes");
            probes.retain(|probe| probe.strong_count() != 0);
            assert!(probes.len() < 4, "bounded recipient admission probes");
            assert!(
                !probes
                    .iter()
                    .filter_map(Weak::upgrade)
                    .any(|old| old.owner.ptr_eq(&probe.owner))
            );
            probes.push(Arc::downgrade(&probe));
            AdmissionGuard(probe)
        }
    }
    #[derive(Clone)]
    pub(crate) struct HeldRequest {
        pub(crate) owner: Weak<Existing>,
        pub(crate) nonce: [u8; 32],
        pub(crate) message_id: cgka_traits::MessageId,
        pub(crate) payload_nonempty: bool,
    }
    struct RequestGate {
        owner: Weak<OriginalEnrollmentSharingChoice>,
        fired: AtomicBool,
        request: Mutex<Option<HeldRequest>>,
        observed: Notify,
        release: Notify,
    }
    pub(crate) struct RequestGuard(Arc<RequestGate>);
    impl RequestGuard {
        pub(crate) async fn observed(&self) -> HeldRequest {
            self.0.observed.notified().await;
            self.0
                .request
                .lock()
                .expect("held actual Request")
                .clone()
                .expect("actual Request observed")
        }
    }
    impl Drop for RequestGuard {
        fn drop(&mut self) {
            self.0.release.notify_one();
        }
    }
    fn request_registry() -> &'static Mutex<Vec<Weak<RequestGate>>> {
        static REGISTRY: OnceLock<Mutex<Vec<Weak<RequestGate>>>> = OnceLock::new();
        REGISTRY.get_or_init(Default::default)
    }
    impl Guard {
        pub(crate) fn hold_recipient_request_for_test(&self) -> RequestGuard {
            let gate = Arc::new(RequestGate {
                owner: self.0.owner.clone(),
                fired: AtomicBool::new(false),
                request: Mutex::new(None),
                observed: Notify::new(),
                release: Notify::new(),
            });
            let mut gates = request_registry().lock().expect("recipient Request gates");
            gates.retain(|gate| gate.strong_count() != 0);
            assert!(gates.len() < 4, "bounded actual Request gates");
            assert!(
                !gates
                    .iter()
                    .filter_map(Weak::upgrade)
                    .any(|old| old.owner.ptr_eq(&gate.owner))
            );
            gates.push(Arc::downgrade(&gate));
            RequestGuard(gate)
        }
    }
    // Called only for a genuine Request inside its existing original-owned
    // publication cancellation/deadline select. This is not a relay ACK.
    pub(in super::super) async fn hold_request(
        source: &Arc<SiblingOriginal>,
        nonce: [u8; 32],
        request: &cgka_traits::TransportPublishRequest,
    ) {
        let SiblingOriginal::Existing {
            original,
            source: device,
            recipient,
            account,
            ..
        } = source.as_ref()
        else {
            return;
        };
        let gate = {
            let gates = request_registry().lock().expect("recipient Request gates");
            gates.iter().filter_map(Weak::upgrade).find(|gate| {
                gate.owner.upgrade().is_some_and(|choice| {
                    choice.live()
                        && source.live()
                        && choice.scope.local_device == choice.context.recipient
                        && *recipient == choice.context.recipient
                        && *account == choice.context.account
                        && choice.context.digest().ok().is_some_and(|approval| approval == original.state.approval_id)
                        && request.account_id.as_slice() == choice.context.account
                        && *device != choice.context.approver
                        && choice.context.predecessor.leaves.iter().any(|leaf| leaf.signature_public_key == *device)
                        && matches!(&request.target, cgka_traits::TransportPublishTarget::Group { group_id, .. }
                            if group_id.as_slice() == choice.context.device_group)
                }) && !gate.fired.swap(true, Ordering::AcqRel)
            })
        };
        if let Some(gate) = gate {
            *gate.request.lock().expect("held actual Request") = Some(HeldRequest {
                owner: Arc::downgrade(original),
                nonce,
                message_id: request.message.id.clone(),
                payload_nonempty: !request.message.payload.is_empty(),
            });
            gate.observed.notify_one();
            gate.release.notified().await;
        }
    }
    pub(in super::super) fn admitted(entry: &SiblingChannel) {
        let SiblingOriginal::Recipient { choice, .. } = entry.original.as_ref() else {
            return;
        };
        let probes = registry().lock().expect("recipient admission probes");
        for probe in probes.iter().filter_map(Weak::upgrade) {
            if !probe.owner.ptr_eq(&Arc::downgrade(choice)) {
                continue;
            }
            let mut admitted = probe.admitted.lock().expect("recipient admission");
            if admitted.is_none() {
                *admitted = Some(Admission {
                    nonce: entry.channel.scope().nonce,
                    flags: [
                        entry.original.live(),
                        entry.state.live(),
                        entry.recipient,
                        entry.ready,
                        entry.handshake_published,
                        entry.publication.is_some(),
                    ],
                });
                probe.observed.notify_one();
            }
        }
    }
}
// RECIPIENT_ADMISSION_TEST_END
