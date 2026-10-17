//! Test-only passive snapshots and one original recipient's real publication hold.
use super::*;
// PEER_NEGATIVE_TEST_BEGIN
pub(crate) mod negative;
// PEER_NEGATIVE_TEST_END
use std::sync::{OnceLock, Weak};
use tokio::sync::Notify;

type Existing = crate::client::private_enrollment_proposal::OriginalSiblingSharingApproval;

pub(crate) struct Snapshot {
    pub(crate) nonce: [u8; 32],
    // Original live, state live, policy, own proof harvested, peer proof,
    // publication present, complete, exact durable policy. These are fresh actor-owned values.
    pub(crate) flags: [bool; 8],
// PEER_NEGATIVE_TEST_BEGIN
    pub(crate) deadline: Instant,
    pub(crate) pending_controls: usize,
// PEER_NEGATIVE_TEST_END
}

pub(crate) struct ProofGate {
    owner: Weak<OriginalEnrollmentSharingChoice>,
    fired: AtomicBool,
    nonce: Mutex<Option<[u8; 32]>>,
    observed: Notify,
    release: Notify,
}

pub(crate) struct Guard(Arc<ProofGate>);
impl Guard {
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
// PEER_NEGATIVE_TEST_BEGIN
            deadline: entry.state.deadline,
            pending_controls: entry.pending_controls.len()
                + entry.pending_opaque.lock().expect("sibling pending opaque").len(),
// PEER_NEGATIVE_TEST_END
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
