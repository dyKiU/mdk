//! Bilateral sibling handoff retained by the actual enrollment originals.
// PEER_PROOF_TEST_BEGIN
#[cfg(all(test, feature = "test-policy-overrides"))]
pub(crate) mod peer_proof_probe;
// PEER_PROOF_TEST_END
#[cfg(test)]
mod tests;
use super::*;
use crate::account_chat_sharing::enabled::State;
use crate::device_linking::settlement::SettlementGuard;
use cgka_engine::account_chat_sharing::{AccountSharingScope, TrustedAccountSharingLease};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

#[cfg(all(test, feature = "test-policy-overrides"))]
#[derive(Clone, Copy, Debug)]
pub(crate) enum NativeObservationStage {
    DispatchStarted,
    WorkerStarted,
    WorkerReturned,
    FacadeReturned,
    AutomaticEntered,
    AutomaticExited,
}
#[cfg(all(test, feature = "test-policy-overrides"))]
#[derive(Clone, Copy, Debug)]
pub(crate) enum NativeObservationReason {
    VerifierFallback,
    NoRound,
    GuardInvalid,
    NoSettledRoster,
    SharingPending,
    Complete,
}
#[cfg(all(test, feature = "test-policy-overrides"))]
pub(crate) type NativeObservationSnapshot =
    ([usize; 6], [u64; 6], Option<(NativeObservationReason, u64)>);
#[cfg(all(test, feature = "test-policy-overrides"))]
struct NativeObservationProbe {
    origin: Instant,
    counts: [usize; 6],
    elapsed_ms: [u64; 6],
    reason: Option<(NativeObservationReason, u64)>,
}
#[cfg(all(test, feature = "test-policy-overrides"))]
impl Default for NativeObservationProbe {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
            counts: [0; 6],
            elapsed_ms: [0; 6],
            reason: None,
        }
    }
}
pub(crate) struct OriginalEnrollmentSharingChoice {
    pub(super) scope: PurposeAttemptScope,
    pub(super) context: LinkingContext,
    pub(super) deadline: Instant,
    pub(super) created_at: u64,
    pub(super) legacy_capture:
        Mutex<Option<Arc<crate::client::legacy_chat_acceptance::CapturedLegacyChats>>>,
    lifetime: Arc<AtomicBool>,
    children: Mutex<Vec<Arc<State>>>,
    progress: Mutex<ChoiceProgress>,
    pending_controls: Mutex<Vec<PendingSiblingControl>>,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    native_observation_probe: Mutex<NativeObservationProbe>,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    recipient_diagnostics: [std::sync::atomic::AtomicUsize; 19],
    #[cfg(all(test, feature = "test-policy-overrides"))]
    received_requests: Mutex<Vec<([u8; 32], [bool; 3])>>,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    received_control_events: Mutex<Vec<(cgka_traits::MessageId, bool)>>,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    projection_observations:
        Arc<Mutex<std::collections::HashMap<cgka_traits::MessageId, [usize; 6]>>>,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    routing_probe: Mutex<Option<Arc<SiblingRoutingProbe>>>,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    projection_head_probe: Mutex<Option<Arc<SiblingProjectionHeadProbe>>>,
}
struct PendingSiblingControl {
    group: cgka_traits::GroupId,
    source: cgka_traits::source_leaf::SourceLeafProof,
    wire: Vec<u8>,
}
const MAX_PENDING_CONTROLS_PER_PEER: usize = 4;
const MAX_PENDING_RECIPIENT_CONTROLS: usize = 128 * MAX_PENDING_CONTROLS_PER_PEER;
#[cfg(all(test, feature = "test-policy-overrides"))]
pub(crate) struct SiblingRoutingProbe {
    nonce: [u8; 32],
    observed: std::sync::atomic::AtomicUsize,
    local_auth_attempts: std::sync::atomic::AtomicUsize,
}
#[cfg(all(test, feature = "test-policy-overrides"))]
impl SiblingRoutingProbe {
    pub(crate) fn snapshot_for_test(&self) -> [usize; 2] {
        [
            self.observed.load(Ordering::Acquire),
            self.local_auth_attempts.load(Ordering::Acquire),
        ]
    }
}
#[cfg(all(test, feature = "test-policy-overrides"))]
pub(crate) struct SiblingProjectionHeadProbe {
    owner: std::sync::Weak<OriginalEnrollmentSharingChoice>,
    failures: std::sync::atomic::AtomicUsize,
    core_retries: std::sync::atomic::AtomicUsize,
}
#[cfg(all(test, feature = "test-policy-overrides"))]
impl SiblingProjectionHeadProbe {
    pub(crate) fn snapshot_for_test(&self) -> [usize; 2] {
        [
            self.failures.load(Ordering::Acquire),
            self.core_retries.load(Ordering::Acquire),
        ]
    }
}
// One negative observation of actual intake; weak identities never retain authority.
#[cfg(all(test, feature = "test-policy-overrides"))]
struct InjectedSiblingControl {
    group: cgka_traits::GroupId,
    source: cgka_traits::source_leaf::SourceLeafProof,
    wire: zeroize::Zeroizing<Vec<u8>>,
    original: std::sync::Weak<SiblingOriginal>,
    state: std::sync::Weak<State>,
    nonce: [u8; 32],
    authenticated_kind: Option<&'static str>,
}
#[cfg(all(test, feature = "test-policy-overrides"))]
#[derive(Default)]
pub(crate) struct SiblingPreAuthFailureProbe {
    armed: AtomicBool,
    injected_control: Mutex<Option<InjectedSiblingControl>>,
    exact_authentication_routes: [std::sync::atomic::AtomicUsize; 2],
    failures: std::sync::atomic::AtomicUsize,
    authenticated_retries: std::sync::atomic::AtomicUsize,
    buffered: std::sync::atomic::AtomicUsize,
    retry_attempts: std::sync::atomic::AtomicUsize,
    retry_auth_failures: std::sync::atomic::AtomicUsize,
    retry_observation_failures: std::sync::atomic::AtomicUsize,
    maintenance_visits: std::sync::atomic::AtomicUsize,
    channel_status: std::sync::atomic::AtomicUsize,
    request_nonce: Mutex<Option<[u8; 32]>>,
    request_scope: Mutex<Option<cgka_engine::account_chat_sharing::AccountSharingScope>>,
    request_message: Mutex<Option<cgka_traits::MessageId>>,
    request_content: Mutex<Option<cgka_traits::MessageId>>,
    request_route: Mutex<Option<(cgka_traits::GroupId, cgka_traits::EpochId, Vec<u8>)>>,
    transport_counts: [std::sync::atomic::AtomicUsize; 4],
    projection_head_barrier: Mutex<Option<std::sync::Weak<SiblingProjectionHeadProbe>>>,
}
#[cfg(all(test, feature = "test-policy-overrides"))]
impl SiblingPreAuthFailureProbe {
    pub(crate) fn hold_request_until_projection_head_for_test(
        &self,
        head: &Arc<SiblingProjectionHeadProbe>,
    ) -> Result<(), crate::AccountSharingError> {
        let mut held = self
            .projection_head_barrier
            .lock()
            .expect("projection head barrier");
        if held.is_some() || !head.owner.upgrade().is_some_and(|choice| choice.live()) {
            return Err(crate::AccountSharingError::Closed);
        }
        // This probe now controls ordering only, rather than consent failure.
        self.armed.store(false, Ordering::Release);
        *held = Some(Arc::downgrade(head));
        Ok(())
    }
    fn wait_for_projection_head_for_test(
        &self,
        entry: &SiblingChannel,
    ) -> Result<bool, ClientLinkingError> {
        let held = self
            .projection_head_barrier
            .lock()
            .expect("projection head barrier")
            .clone();
        let Some(held) = held else {
            return Ok(false);
        };
        let head = held.upgrade().ok_or_else(denied)?;
        let choice = head
            .owner
            .upgrade()
            .filter(|choice| choice.live())
            .ok_or_else(denied)?;
        let scope = entry.channel.scope();
        if entry.recipient
            || !entry.original.live()
            || !entry.state.live()
            || scope.protected.account.as_slice() != choice.context.account
            || scope.recipient.as_slice() != choice.context.recipient
            || scope.protected.group_id.as_slice() != choice.context.device_group
            || !choice
                .context
                .predecessor
                .leaves
                .iter()
                .any(|leaf| leaf.signature_public_key.as_slice() == scope.source)
        {
            return Err(denied());
        }
        Ok(head.failures.load(Ordering::Acquire) == 0)
    }
    pub(crate) fn request_scope_for_test(
        &self,
    ) -> Option<cgka_engine::account_chat_sharing::AccountSharingScope> {
        self.request_scope
            .lock()
            .expect("sibling request scope")
            .clone()
    }
    pub(crate) fn request_message_id_for_test(&self) -> Option<cgka_traits::MessageId> {
        self.request_message
            .lock()
            .expect("sibling request transport")
            .clone()
    }
    pub(crate) fn request_route_for_test(
        &self,
    ) -> Option<(cgka_traits::GroupId, cgka_traits::EpochId, Vec<u8>)> {
        self.request_route
            .lock()
            .expect("sibling request route")
            .clone()
    }
    pub(crate) fn request_content_id_for_test(&self) -> Option<cgka_traits::MessageId> {
        self.request_content
            .lock()
            .expect("sibling request content")
            .clone()
    }
    pub(crate) fn request_nonce_for_test(&self) -> Option<[u8; 32]> {
        *self.request_nonce.lock().expect("sibling request nonce")
    }
    pub(crate) fn transport_snapshot_for_test(&self) -> [usize; 4] {
        std::array::from_fn(|index| self.transport_counts[index].load(Ordering::Acquire))
    }
    pub(crate) fn armed() -> Self {
        Self {
            armed: AtomicBool::new(true),
            ..Self::default()
        }
    }
    fn capture_injected_control(
        &self,
        entry: &SiblingChannel,
        group: &cgka_traits::GroupId,
        source: &cgka_traits::source_leaf::SourceLeafProof,
        wire: &[u8],
    ) {
        let mut captured = self
            .injected_control
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if captured.is_none() && !wire.is_empty() && wire.len() <= 16 * 1024 {
            *captured = Some(InjectedSiblingControl {
                group: group.clone(),
                source: source.clone(),
                wire: zeroize::Zeroizing::new(wire.to_vec()),
                original: Arc::downgrade(&entry.original),
                state: Arc::downgrade(&entry.state),
                nonce: entry.channel.scope().nonce,
                authenticated_kind: None,
            });
        }
    }
    fn observe_exact_authentication(
        &self,
        entry: &SiblingChannel,
        item: (
            &cgka_traits::GroupId,
            &cgka_traits::source_leaf::SourceLeafProof,
            &[u8],
        ),
        received: &cgka_engine::account_chat_sharing::ReceivedAccountSharingControl,
        retained_retry: bool,
    ) {
        use cgka_engine::account_chat_sharing::AccountSharingControl;
        let mut captured = self
            .injected_control
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(captured) = captured.as_mut() else {
            return;
        };
        if !entry.original.live()
            || !entry.state.live()
            || !captured.original.ptr_eq(&Arc::downgrade(&entry.original))
            || !captured.state.ptr_eq(&Arc::downgrade(&entry.state))
            || &captured.group != item.0
            || &captured.source != item.1
            || captured.wire.as_slice() != item.2
            || captured.nonce != entry.channel.scope().nonce
            || received.nonce != captured.nonce
            || received.signer != entry.channel.scope().recipient
        {
            return;
        }
        captured.authenticated_kind = Some(match received.control {
            AccountSharingControl::Request => "request",
            AccountSharingControl::Consent => "consent",
            AccountSharingControl::Body(_) => "body",
        });
        self.exact_authentication_routes[usize::from(retained_retry)]
            .fetch_add(1, Ordering::AcqRel);
    }
    /// Exact injected-item Core successes by normal intake / retained retry.
    pub(crate) fn authentication_routes_for_test(
        &self,
    ) -> ([usize; 2], Option<&'static str>, bool) {
        let captured = self
            .injected_control
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        (
            std::array::from_fn(|index| {
                self.exact_authentication_routes[index].load(Ordering::Acquire)
            }),
            captured.as_ref().and_then(|item| item.authenticated_kind),
            captured.is_some(),
        )
    }
    pub(crate) fn failures(&self) -> usize {
        self.failures.load(Ordering::Acquire)
    }
    pub(crate) fn authenticated_retries(&self) -> usize {
        self.authenticated_retries.load(Ordering::Acquire)
    }
    pub(crate) fn buffered(&self) -> usize {
        self.buffered.load(Ordering::Acquire)
    }
    /// Aggregate counts and state bits only; no account or wire evidence.
    pub(crate) fn snapshot_for_test(&self) -> [usize; 8] {
        [
            self.failures(),
            self.buffered(),
            self.retry_attempts.load(Ordering::Acquire),
            self.authenticated_retries(),
            self.retry_auth_failures.load(Ordering::Acquire),
            self.retry_observation_failures.load(Ordering::Acquire),
            self.maintenance_visits.load(Ordering::Acquire),
            self.channel_status.load(Ordering::Acquire),
        ]
    }
    fn observe_channel(&self, entry: &SiblingChannel) {
        self.maintenance_visits.fetch_add(1, Ordering::AcqRel);
        let bits = [
            entry.original.live(),
            entry.state.live(),
            entry.ready,
            entry.handshake_published,
            entry.policy_committed,
            entry.proof_published,
            entry.peer_committed,
            entry
                .state
                .progress
                .lock()
                .expect("sharing progress")
                .complete,
        ];
        self.channel_status.store(
            bits.into_iter()
                .enumerate()
                .fold(0, |mask, (index, value)| {
                    mask | (usize::from(value) << index)
                }),
            Ordering::Release,
        );
    }
}
#[derive(Default)]
struct ChoiceProgress {
    primary_committed: bool,
    expected: Option<Vec<[u8; 32]>>,
}
impl OriginalEnrollmentSharingChoice {
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn record_observation_stage_for_test(&self, stage: NativeObservationStage) {
        let mut probe = self
            .native_observation_probe
            .lock()
            .expect("native observation probe");
        let elapsed_ms = probe.origin.elapsed().as_millis() as u64;
        probe.counts[stage as usize] += 1;
        probe.elapsed_ms[stage as usize] = elapsed_ms;
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn record_observation_reason_for_test(&self, reason: NativeObservationReason) {
        let mut probe = self
            .native_observation_probe
            .lock()
            .expect("native observation probe");
        probe.reason = Some((reason, probe.origin.elapsed().as_millis() as u64));
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn observation_snapshot_for_test(&self) -> NativeObservationSnapshot {
        let probe = self
            .native_observation_probe
            .lock()
            .expect("native observation probe");
        (probe.counts, probe.elapsed_ms, probe.reason)
    }

    // COMPLETION_TEST_BEGIN
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn completed_consent_progress_for_test(
        &self,
        identity: &cgka_traits::MessageId,
        policies: &[cgka_traits::approved_account_sharing_policy::ApprovedAccountSharingPolicy],
    ) -> Option<(bool, bool)> {
        use cgka_traits::approved_account_sharing_policy::{
            ACCOUNT_SHARING_CAPABILITIES, ACCOUNT_SHARING_POLICY_VERSION,
            ApprovedAccountSharingPolicy,
        };
        for state in self.children.lock().expect("sibling children").iter() {
            let proof = {
                let observation = state
                    .sibling_diagnostics
                    .lock()
                    .expect("sibling completion test observation");
                if observation.successful_consent_message.as_ref() != Some(identity) {
                    continue;
                }
                observation.successful_commit_proof
            };
            let scope = state.scope.lock().expect("sibling scope").clone()?;
            let expected = ApprovedAccountSharingPolicy {
                account: scope.protected.account.as_slice().try_into().ok()?,
                local_device: scope.recipient.as_slice().try_into().ok()?,
                peer_device: scope.source.as_slice().try_into().ok()?,
                protected_group: scope.protected.group_id.clone(),
                approval_id: scope.approval_id,
                version: ACCOUNT_SHARING_POLICY_VERSION,
                capabilities: ACCOUNT_SHARING_CAPABILITIES,
                created_at: state.created_at,
                approved_protected_epoch: scope.protected.epoch.0,
                revoked: false,
            };
            return Some((policies.iter().any(|policy| policy == &expected), proof));
        }
        None
    }

    // COMPLETION_TEST_END
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn child_diagnostics_for_test(
        &self,
    ) -> Vec<crate::account_chat_sharing::enabled::SiblingMaintenanceSnapshot> {
        self.children
            .lock()
            .expect("sibling children")
            .iter()
            .map(|state| {
                state
                    .sibling_diagnostics
                    .lock()
                    .expect("sibling diagnostics")
                    .snapshot()
            })
            .collect()
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn completion_aggregates_for_test(&self) -> (bool, Option<usize>, usize, usize) {
        let progress = self.progress.lock().expect("sharing choice");
        let children = self.children.lock().expect("sibling children");
        (
            progress.primary_committed,
            progress.expected.as_ref().map(Vec::len),
            children.len(),
            children
                .iter()
                .filter(|state| state.progress.lock().expect("sharing progress").complete)
                .count(),
        )
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn projection_aggregates_for_test(&self) -> [usize; 4] {
        let observations = self
            .projection_observations
            .lock()
            .expect("sibling projection observations");
        [
            observations.len(),
            observations.values().map(|counts| counts[0]).sum(),
            observations
                .values()
                .map(|counts| counts[0])
                .max()
                .unwrap_or(0),
            observations.values().map(|counts| counts[5]).sum(),
        ]
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn projection_event_for_test(
        &self,
        id: &cgka_traits::MessageId,
    ) -> Option<[usize; 6]> {
        self.projection_observations
            .lock()
            .expect("sibling projection observations")
            .get(id)
            .copied()
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn request_scope_matches_for_test(
        &self,
        scope: &cgka_engine::account_chat_sharing::AccountSharingScope,
    ) -> [bool; 5] {
        [
            scope.recipient.as_slice() == self.scope.local_device,
            scope.recipient.as_slice() == self.context.recipient,
            self.context.digest().ok() == Some(scope.approval_id),
            scope.protected.group_id.as_slice() == self.context.device_group,
            self.progress
                .lock()
                .expect("sharing choice")
                .expected
                .as_ref()
                .is_some_and(|expected| {
                    expected.iter().any(|peer| peer.as_slice() == scope.source)
                }),
        ]
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn source_event_for_test(&self, id: &cgka_traits::MessageId) -> Option<bool> {
        self.received_control_events
            .lock()
            .expect("sibling control events")
            .iter()
            .find(|(observed, _)| observed == id)
            .map(|(_, proof)| *proof)
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn request_observation_for_test(&self, nonce: [u8; 32]) -> Option<[bool; 3]> {
        self.received_requests
            .lock()
            .expect("sibling request observations")
            .iter()
            .find(|(observed, _)| *observed == nonce)
            .map(|(_, facts)| *facts)
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn recipient_context_rejections_for_test(&self) -> [usize; 9] {
        std::array::from_fn(|index| self.recipient_diagnostics[index + 10].load(Ordering::Acquire))
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn arm_projection_head_probe_for_test(
        self: &Arc<Self>,
    ) -> Result<Arc<SiblingProjectionHeadProbe>, crate::AccountSharingError> {
        let mut held = self
            .projection_head_probe
            .lock()
            .expect("projection head probe");
        if !self.live() || self.scope.local_device != self.context.recipient || held.is_some() {
            return Err(crate::AccountSharingError::Closed);
        }
        let probe = Arc::new(SiblingProjectionHeadProbe {
            owner: Arc::downgrade(self),
            failures: std::sync::atomic::AtomicUsize::new(0),
            core_retries: std::sync::atomic::AtomicUsize::new(0),
        });
        *held = Some(probe.clone());
        Ok(probe)
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn arm_wrong_recipient_probe_for_test(
        &self,
        nonce: [u8; 32],
    ) -> Result<Arc<SiblingRoutingProbe>, crate::AccountSharingError> {
        let mut held = self.routing_probe.lock().expect("sibling routing probe");
        if !self.live() || held.is_some() {
            return Err(crate::AccountSharingError::Closed);
        }
        let probe = Arc::new(SiblingRoutingProbe {
            nonce,
            observed: std::sync::atomic::AtomicUsize::new(0),
            local_auth_attempts: std::sync::atomic::AtomicUsize::new(0),
        });
        *held = Some(probe.clone());
        Ok(probe)
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn recipient_snapshot_for_test(&self) -> [usize; 8] {
        std::array::from_fn(|index| match index {
            6 => self
                .pending_controls
                .lock()
                .expect("sibling pending controls")
                .len(),
            7 => self.children.lock().expect("sibling children").len(),
            _ => self.recipient_diagnostics[index].load(Ordering::Acquire),
        })
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn recipient_channel_progress_for_test(&self) -> Vec<(usize, [bool; 11])> {
        self.children
            .lock()
            .expect("sibling children")
            .iter()
            .map(|child| {
                let observed = child.sibling_progress_for_test.load(Ordering::Acquire);
                (
                    observed >> 16,
                    std::array::from_fn(|index| observed & (1 << index) != 0),
                )
            })
            .collect()
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn recipient_publications_for_test(&self) -> Vec<cgka_traits::MessageId> {
        self.children
            .lock()
            .expect("sibling children")
            .iter()
            .filter_map(|child| {
                child
                    .sibling_publication_for_test
                    .lock()
                    .expect("sibling publication")
                    .clone()
            })
            .collect()
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn recipient_rejections_for_test(&self) -> [usize; 4] {
        std::array::from_fn(|index| self.recipient_diagnostics[index + 6].load(Ordering::Acquire))
    }
    fn retain_pending_observation(&self, item: PendingSiblingControl) -> bool {
        if !self.live() || item.wire.is_empty() || item.wire.len() > 16 * 1024 {
            return false;
        }
        let mut pending = self
            .pending_controls
            .lock()
            .expect("sibling pending controls");
        if !self.live() {
            return false;
        }
        if pending.iter().any(|old| {
            old.group == item.group && old.source == item.source && old.wire == item.wire
        }) {
            return true;
        }
        // A different control from this peer is not a duplicate. Overflow is
        // explicit refusal, never a claim that an unretained request was kept.
        if pending.len() >= MAX_PENDING_RECIPIENT_CONTROLS {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.recipient_diagnostics[7].fetch_add(1, Ordering::AcqRel);
            return false;
        }
        if pending
            .iter()
            .filter(|old| old.source.signature_public_key == item.source.signature_public_key)
            .count()
            >= MAX_PENDING_CONTROLS_PER_PEER
        {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            self.recipient_diagnostics[6].fetch_add(1, Ordering::AcqRel);
            return false;
        }
        pending.push(item);
        #[cfg(all(test, feature = "test-policy-overrides"))]
        self.recipient_diagnostics[1].fetch_add(1, Ordering::AcqRel);
        true
    }
    pub(crate) fn cancel(&self) {
        self.lifetime.store(false, Ordering::Release);
        self.pending_controls
            .lock()
            .expect("sibling pending controls")
            .clear();
        for state in self.children.lock().expect("sibling children").iter() {
            state.cancel();
        }
    }
    pub(crate) fn complete(&self) -> bool {
        let progress = self.progress.lock().expect("sharing choice");
        progress.primary_committed
            && progress.expected.as_ref().is_some_and(|expected| {
                let children = self.children.lock().expect("sibling children");
                children.len() == expected.len()
                    && children
                        .iter()
                        .all(|state| state.progress.lock().expect("sharing progress").complete)
            })
    }
    pub(super) fn live(&self) -> bool {
        self.lifetime.load(Ordering::Acquire) && Instant::now() < self.deadline
    }
    pub(super) fn primary_committed(&self) -> bool {
        self.progress
            .lock()
            .expect("sharing choice")
            .primary_committed
    }
    fn child(&self) -> Result<Arc<State>, ClientLinkingError> {
        if !self.live() {
            return Err(denied());
        }
        let mut children = self.children.lock().expect("sibling children");
        if children.len() >= 128 {
            return Err(denied());
        }
        let state = State::new_until(
            &self.lifetime,
            self.context.digest().map_err(|_| denied())?,
            self.deadline,
        );
        children.push(state.clone());
        if !self.live() {
            state.cancel();
            return Err(denied());
        }
        Ok(state)
    }
}
impl Drop for OriginalEnrollmentSharingChoice {
    fn drop(&mut self) {
        self.cancel();
    }
}
fn denied() -> ClientLinkingError {
    ClientLinkingError::Gate(
        cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
    )
}

impl AppClient {
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn native_observation_original_for_test(
        &self,
        scope: &PurposeAttemptScope,
    ) -> Option<Arc<OriginalEnrollmentSharingChoice>> {
        self.linking_owner
            .sharing_approval
            .as_ref()
            .filter(|choice| choice.scope == *scope)
            .cloned()
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn observe_sibling_event_diagnostic_for_test(
        &self,
        event: &cgka_traits::GroupEvent,
    ) {
        let cgka_traits::GroupEvent::MessageReceived {
            group_id,
            message_id,
            source_leaf,
            payload,
            ..
        } = event
        else {
            return;
        };
        {
            let mut observations = self
                .linking_owner
                .sibling_projection_observations
                .lock()
                .expect("sibling projection observations");
            if observations.len() < 256 || observations.contains_key(message_id) {
                let counts = observations.entry(message_id.clone()).or_default();
                counts[0] += 1;
                counts[1] += usize::from(
                    cgka_traits::app_event::MarmotAppEvent::decode(payload).is_ok_and(|app| {
                        app.kind == cgka_engine::account_chat_sharing::ACCOUNT_SHARING_CONTROL_KIND
                    }),
                );
                counts[2] += usize::from(self.linking_owner.sharing_approval.is_some());
                counts[3] += usize::from(
                    self.linking_owner
                        .sharing_approval
                        .as_ref()
                        .is_some_and(|choice| group_id.as_slice() == choice.context.device_group),
                );
                counts[4] += usize::from(source_leaf.is_some());
                counts[5] += usize::from(source_leaf.as_ref().is_some_and(|source| {
                    self.runtime
                        .session()
                        .validated_settled_device_roster(group_id)
                        .ok()
                        .flatten()
                        .is_some_and(|roster| source.epoch < roster.candidate().epoch)
                }));
            }
        }
        let Some(choice) = &self.linking_owner.sharing_approval else {
            return;
        };
        if group_id.as_slice() != choice.context.device_group
            || choice.scope.local_device != choice.context.recipient
        {
            return;
        }
        let Ok(app) = cgka_traits::app_event::MarmotAppEvent::decode(payload) else {
            return;
        };
        if app.kind != cgka_engine::account_chat_sharing::ACCOUNT_SHARING_CONTROL_KIND {
            return;
        }
        let mut observations = choice
            .received_control_events
            .lock()
            .expect("sibling control events");
        if observations.len() < 128 && !observations.iter().any(|(id, _)| id == message_id) {
            observations.push((message_id.clone(), source_leaf.is_some()));
        }
    }
    pub(crate) fn authenticate_sharing_control_intake(
        &self,
        group: &cgka_traits::GroupId,
        source: &cgka_traits::source_leaf::SourceLeafProof,
        wire: &[u8],
    ) -> Result<
        cgka_engine::account_chat_sharing::ReceivedAccountSharingControl,
        crate::AccountSharingError,
    > {
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(choice) = &self.linking_owner.sharing_approval
            && choice.scope.local_device == choice.context.recipient
            && group.as_slice() == choice.context.device_group
        {
            choice.recipient_diagnostics[0].fetch_add(1, Ordering::AcqRel);
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        for entry in &self.linking_owner.sibling_channels {
            let scope = entry.channel.scope();
            if entry.recipient
                || !entry.original.live()
                || !entry.state.live()
                || &scope.protected.group_id != group
                || scope.recipient != source.signature_public_key
                || scope.protected.epoch != source.epoch
                || scope.protected.epoch_authenticator_digest != source.epoch_authenticator_digest
                || !scope.protected.leaves.iter().any(|leaf| {
                    leaf.leaf_index == source.leaf_index
                        && leaf.signature_public_key == source.signature_public_key
                })
                || wire.is_empty()
                || wire.len() > 16 * 1024
            {
                continue;
            }
            if let Some(probe) = &entry.pre_auth_failure
                && probe.armed.load(Ordering::Acquire)
            {
                // MLS delivery broadcasts controls for every sibling channel.
                // Select the exact fault target through read-only Core authentication;
                // a matching protected source alone can belong to another nonce.
                // This test-only preflight grants no channel authority. The retained
                // retry still authenticates the same bytes through the ordinary path.
                let matches_channel = self
                    .runtime
                    .session()
                    .authenticate_received_account_sharing_control(group, source, wire)
                    .is_ok_and(|received| {
                        received.nonce == scope.nonce && received.signer == scope.recipient
                    });
                if matches_channel && probe.armed.swap(false, Ordering::AcqRel) {
                    probe.capture_injected_control(entry, group, source, wire);
                    probe.failures.fetch_add(1, Ordering::AcqRel);
                    return Err(crate::AccountSharingError::NotReady);
                }
            }
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(choice) = &self.linking_owner.sharing_approval
            && choice.live()
            && choice.scope.local_device == choice.context.recipient
            && group.as_slice() == choice.context.device_group
            && source.signature_public_key.as_slice() == choice.context.approver
            && source.epoch.0 <= choice.context.predecessor.epoch + 1
            && choice
                .context
                .predecessor
                .leaves
                .iter()
                .any(|leaf| leaf.signature_public_key.as_slice() == source.signature_public_key)
            && !wire.is_empty()
            && wire.len() <= 16 * 1024
            && let Some(probe) = choice
                .projection_head_probe
                .lock()
                .expect("projection head probe")
                .clone()
            && probe
                .owner
                .upgrade()
                .is_some_and(|owner| Arc::ptr_eq(&owner, choice))
        {
            let admitted = self.linking_owner.sibling_channels.iter().any(|entry| {
                entry.recipient && entry.original.live() && entry.state.live()
                    && matches!(entry.original.as_ref(), SiblingOriginal::Recipient { choice: owner, peer, .. }
                        if Arc::ptr_eq(owner, choice)
                        && choice.progress.lock().expect("sharing choice").expected.as_ref()
                            .is_some_and(|expected| expected.contains(peer)))
            });
            if !admitted {
                probe.failures.fetch_add(1, Ordering::AcqRel);
                return Err(crate::AccountSharingError::NotReady);
            }
            if probe.failures.load(Ordering::Acquire) > 0 {
                probe.core_retries.fetch_add(1, Ordering::AcqRel);
            }
        }
        let result = self
            .runtime
            .session()
            .authenticate_received_account_sharing_control(group, source, wire)
            .map_err(|_| crate::AccountSharingError::NotReady);
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Ok(received) = &result {
            for entry in &self.linking_owner.sibling_channels {
                if let Some(probe) = &entry.pre_auth_failure {
                    probe.observe_exact_authentication(
                        entry,
                        (group, source, wire),
                        received,
                        false,
                    );
                }
            }
        }
        result
    }
    /// Bounded negative observation under an existing B channel or actual C choice.
    /// No frame parsing or fresh owner construction; Core must authenticate it.
    pub(crate) fn retain_pending_sibling_control(
        &self,
        group: &cgka_traits::GroupId,
        source: &cgka_traits::source_leaf::SourceLeafProof,
        wire: &[u8],
    ) -> bool {
        if !wire.is_empty() && wire.len() <= 16 * 1024 {
            for entry in &self.linking_owner.sibling_channels {
                let scope = entry.channel.scope();
                if entry.recipient
                    || !entry.original.live()
                    || !entry.state.live()
                    || &scope.protected.group_id != group
                    || scope.recipient != source.signature_public_key
                    || scope.protected.epoch != source.epoch
                    || scope.protected.epoch_authenticator_digest
                        != source.epoch_authenticator_digest
                    || !scope.protected.leaves.iter().any(|leaf| {
                        leaf.leaf_index == source.leaf_index
                            && leaf.signature_public_key == source.signature_public_key
                    })
                {
                    continue;
                }
                let mut pending = entry
                    .pending_opaque
                    .lock()
                    .expect("sibling opaque controls");
                if !entry.original.live() || !entry.state.live() {
                    return false;
                }
                if pending
                    .iter()
                    .any(|item| item.wire == wire && item.source == *source && item.group == *group)
                {
                    return true;
                }
                if pending.len() >= 2 {
                    return false;
                }
                pending.push(PendingSiblingControl {
                    group: group.clone(),
                    source: source.clone(),
                    wire: wire.to_vec(),
                });
                #[cfg(all(test, feature = "test-policy-overrides"))]
                if let Some(probe) = &entry.pre_auth_failure
                    && probe.failures() > 0
                {
                    probe.buffered.fetch_add(1, Ordering::AcqRel);
                }
                return true;
            }
        }
        let Some(choice) = &self.linking_owner.sharing_approval else {
            return false;
        };
        if !choice.live()
            || choice.scope.local_device != choice.context.recipient
            || group.as_slice() != choice.context.device_group
            // The original approver can have an older in-flight control. Keep
            // it as a bounded negative observation so it cannot block the
            // sibling request's projection. Core still authenticates every retry.
            || (source.epoch.0 != choice.context.predecessor.epoch + 1
                && !(source.signature_public_key.as_slice() == choice.context.approver
                    && source.epoch.0 <= choice.context.predecessor.epoch + 1))
            || wire.is_empty()
            || wire.len() > 16 * 1024
            || !choice
                .context
                .predecessor
                .leaves
                .iter()
                .any(|leaf| leaf.signature_public_key.as_slice() == source.signature_public_key)
        {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            {
                let reason =
                    if !choice.live() {
                        10
                    } else if choice.scope.local_device != choice.context.recipient {
                        11
                    } else if group.as_slice() != choice.context.device_group {
                        12
                    } else if wire.is_empty() || wire.len() > 16 * 1024 {
                        14
                    } else if source.signature_public_key.as_slice() == choice.context.approver {
                        15
                    } else if !choice.context.predecessor.leaves.iter().any(|leaf| {
                        leaf.signature_public_key.as_slice() == source.signature_public_key
                    }) {
                        16
                    } else {
                        13
                    };
                choice.recipient_diagnostics[reason].fetch_add(1, Ordering::AcqRel);
            }
            #[cfg(all(test, feature = "test-policy-overrides"))]
            if choice.live()
                && choice.scope.local_device == choice.context.recipient
                && group.as_slice() == choice.context.device_group
                && source.signature_public_key.as_slice() != choice.context.approver
                && choice
                    .context
                    .predecessor
                    .leaves
                    .iter()
                    .any(|leaf| leaf.signature_public_key.as_slice() == source.signature_public_key)
                && source.epoch.0 != choice.context.predecessor.epoch + 1
            {
                choice.recipient_diagnostics[8].fetch_add(1, Ordering::AcqRel);
            } else {
                choice.recipient_diagnostics[9].fetch_add(1, Ordering::AcqRel);
            }
            return false;
        }
        choice.retain_pending_observation(PendingSiblingControl {
            group: group.clone(),
            source: source.clone(),
            wire: wire.to_vec(),
        })
    }
    fn retry_existing_sibling_opaque_controls(&mut self) {
        let mut pending = Vec::new();
        for entry in &self.linking_owner.sibling_channels {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            if let Some(probe) = &entry.pre_auth_failure {
                probe.observe_channel(entry);
            }
            if entry.recipient || !entry.original.live() || !entry.state.live() {
                entry
                    .pending_opaque
                    .lock()
                    .expect("sibling opaque controls")
                    .clear();
                continue;
            }
            for item in std::mem::take(
                &mut *entry
                    .pending_opaque
                    .lock()
                    .expect("sibling opaque controls"),
            ) {
                pending.push((
                    entry.original.clone(),
                    entry.state.clone(),
                    entry.channel.scope().nonce,
                    item,
                ));
            }
        }
        for (original, state, nonce, item) in pending {
            let Some(entry) = self.linking_owner.sibling_channels.iter().find(|entry| {
                !entry.recipient
                    && entry.channel.scope().nonce == nonce
                    && Arc::ptr_eq(&entry.original, &original)
                    && Arc::ptr_eq(&entry.state, &state)
                    && original.live()
                    && state.live()
            }) else {
                continue;
            };
            let peer = entry.channel.scope().recipient.clone();
            #[cfg(all(test, feature = "test-policy-overrides"))]
            let probe = entry.pre_auth_failure.clone();
            #[cfg(all(test, feature = "test-policy-overrides"))]
            if let Some(probe) = &probe {
                probe.retry_attempts.fetch_add(1, Ordering::AcqRel);
            }
            match self
                .runtime
                .session()
                .authenticate_received_account_sharing_control(
                    &item.group,
                    &item.source,
                    &item.wire,
                ) {
                Ok(received) => {
                    // Only authenticated controls for this same original may enter
                    // the channel; unrelated opaque input is never rerouted.
                    if received.nonce == nonce && received.signer == peer {
                        #[cfg(all(test, feature = "test-policy-overrides"))]
                        if let Some(probe) = &probe
                            && probe.failures() > 0
                        {
                            probe.authenticated_retries.fetch_add(1, Ordering::AcqRel);
                            probe.observe_exact_authentication(
                                entry,
                                (&item.group, &item.source, &item.wire),
                                &received,
                                true,
                            );
                        }
                        // A downstream failure transfers to the bounded authenticated
                        // queue; no new approval or transport redelivery is needed.
                        let result = self.observe_sibling_sharing_control(&received, &item.wire);
                        #[cfg(all(test, feature = "test-policy-overrides"))]
                        if result.is_err()
                            && let Some(probe) = &probe
                        {
                            probe
                                .retry_observation_failures
                                .fetch_add(1, Ordering::AcqRel);
                        }
                        #[cfg(not(all(test, feature = "test-policy-overrides")))]
                        let _ = result;
                    }
                }
                Err(_) => {
                    #[cfg(all(test, feature = "test-policy-overrides"))]
                    if let Some(probe) = &probe {
                        probe.retry_auth_failures.fetch_add(1, Ordering::AcqRel);
                    }
                    if let Some(entry) = self.linking_owner.sibling_channels.iter().find(|entry| {
                        !entry.recipient
                            && entry.channel.scope().nonce == nonce
                            && Arc::ptr_eq(&entry.original, &original)
                            && Arc::ptr_eq(&entry.state, &state)
                            && original.live()
                            && state.live()
                    }) {
                        let mut retry = entry
                            .pending_opaque
                            .lock()
                            .expect("sibling opaque controls");
                        if original.live() && state.live() && retry.len() < 2 {
                            retry.push(item);
                        }
                    }
                }
            }
        }
    }
    fn retry_pending_sibling_controls(&mut self) {
        let Some(choice) = self
            .linking_owner
            .sharing_approval
            .as_ref()
            .cloned()
            .filter(|choice| choice.live())
        else {
            return;
        };
        let pending = std::mem::take(
            &mut *choice
                .pending_controls
                .lock()
                .expect("sibling pending controls"),
        );
        for item in pending {
            if !choice.live() {
                break;
            }
            #[cfg(all(test, feature = "test-policy-overrides"))]
            choice.recipient_diagnostics[2].fetch_add(1, Ordering::AcqRel);
            let retained = match self.authenticate_sharing_control_intake(
                &item.group,
                &item.source,
                &item.wire,
            ) {
                Ok(received) => {
                    let result =
                        self.dispatch_authenticated_account_sharing_control(&received, &item.wire);
                    #[cfg(all(test, feature = "test-policy-overrides"))]
                    if result.is_err() {
                        choice.recipient_diagnostics[5].fetch_add(1, Ordering::AcqRel);
                    }
                    result.is_err()
                }
                Err(_) => {
                    #[cfg(all(test, feature = "test-policy-overrides"))]
                    choice.recipient_diagnostics[3].fetch_add(1, Ordering::AcqRel);
                    true
                }
            };
            if retained && choice.live() {
                let _ = choice.retain_pending_observation(item);
            }
        }
    }
    /// Negative control captured before any blocked publication; never a grant from rows.
    pub(crate) fn capture_owned_native_sharing_choice(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<Arc<OriginalEnrollmentSharingChoice>, ClientLinkingError> {
        if let Some(original) = &self.linking_owner.sharing_approval {
            if original.scope != *scope || !original.live() {
                return Err(denied());
            }
            return Ok(original.clone());
        }
        let (context, deadline) = self
            .scoped_linking_verifier(scope)?
            .native_sharing_context(scope, Instant::now())
            .map_err(ClientLinkingError::Owner)?;
        let expected =
            (scope.local_device == context.approver || context.version == 1).then(Vec::new);
        let original = Arc::new(OriginalEnrollmentSharingChoice {
            scope: scope.clone(),
            context,
            deadline,
            created_at: crate::unix_now_seconds(),
            legacy_capture: Mutex::new(None),
            lifetime: Arc::new(AtomicBool::new(true)),
            children: Mutex::new(Vec::new()),
            progress: Mutex::new(ChoiceProgress {
                primary_committed: false,
                expected,
            }),
            pending_controls: Mutex::new(Vec::new()),
            #[cfg(all(test, feature = "test-policy-overrides"))]
            native_observation_probe: Mutex::default(),
            #[cfg(all(test, feature = "test-policy-overrides"))]
            recipient_diagnostics: std::array::from_fn(|_| std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(all(test, feature = "test-policy-overrides"))]
            received_requests: Mutex::new(Vec::new()),
            #[cfg(all(test, feature = "test-policy-overrides"))]
            received_control_events: Mutex::new(Vec::new()),
            #[cfg(all(test, feature = "test-policy-overrides"))]
            projection_observations: self.linking_owner.sibling_projection_observations.clone(),
            #[cfg(all(test, feature = "test-policy-overrides"))]
            routing_probe: Mutex::new(None),
            #[cfg(all(test, feature = "test-policy-overrides"))]
            projection_head_probe: Mutex::new(None),
        });
        let capture = self
            .capture_legacy_chats(&|| {
                if !original.live() {
                    return Err(cgka_traits::storage::StorageError::Serialization(
                        "pairing original unavailable".into(),
                    ));
                }
                Ok(())
            })
            .map_err(|error| ClientLinkingError::Engine(error.into()))?;
        *original.legacy_capture.lock().expect("legacy capture") = Some(capture);
        self.linking_owner.sharing_approval = Some(original.clone());
        Ok(original)
    }
    pub(super) fn mark_primary_sharing_committed(&self) {
        if let Some(choice) = &self.linking_owner.sharing_approval {
            choice
                .progress
                .lock()
                .expect("sharing choice")
                .primary_committed = true;
        }
    }
    pub(super) fn capture_recipient_sharing_devices(
        &self,
        devices: &[[u8; 32]],
    ) -> Result<(), ClientLinkingError> {
        let Some(choice) = &self.linking_owner.sharing_approval else {
            return Ok(());
        };
        if !choice.live() || choice.scope.local_device != choice.context.recipient {
            return Err(denied());
        }
        let mut expected: Vec<_> = devices
            .iter()
            .copied()
            .filter(|device| *device != choice.context.approver)
            .collect();
        expected.sort();
        expected.dedup();
        if expected.len() > 128
            || expected.iter().any(|device| {
                *device == choice.context.recipient
                    || !choice
                        .context
                        .predecessor
                        .leaves
                        .iter()
                        .any(|leaf| leaf.signature_public_key == *device)
            })
        {
            return Err(denied());
        }
        let mut progress = choice.progress.lock().expect("sharing choice");
        if progress
            .expected
            .as_ref()
            .is_some_and(|old| old != &expected)
        {
            return Err(denied());
        }
        progress.expected = Some(expected);
        Ok(())
    }
}

pub(crate) enum SiblingOriginal {
    Existing {
        original: Arc<super::super::private_enrollment_proposal::OriginalSiblingSharingApproval>,
        guard: Arc<cgka_engine::private_enrollment_endorsement::OwnedExistingEnrollmentTransition>,
        source: [u8; 32],
        recipient: [u8; 32],
        account: [u8; 32],
    },
    Recipient {
        choice: Arc<OriginalEnrollmentSharingChoice>,
        guard: Arc<SettlementGuard>,
        peer: [u8; 32],
    },
}
impl SiblingOriginal {
    fn live(&self) -> bool {
        match self {
            Self::Existing {
                original, guard, ..
            } => original.state.live() && guard.is_live(),
            Self::Recipient { choice, guard, .. } => {
                choice.live() && guard.is_live() && guard.matches_original_context(&choice.context)
            }
        }
    }
    fn matches(&self, scope: &AccountSharingScope) -> bool {
        match self {
            Self::Existing {
                guard,
                source,
                recipient,
                account,
                ..
            } => {
                guard.group() == &scope.protected.group_id
                    && scope.protected.account.as_slice() == account
                    && scope.source.as_slice() == source
                    && scope.recipient.as_slice() == recipient
            }
            Self::Recipient { choice, peer, .. } => {
                scope.protected.group_id.as_slice() == choice.context.device_group
                    && scope.protected.account.as_slice() == choice.context.account
                    && scope.source.as_slice() == peer
                    && scope.recipient.as_slice() == choice.scope.local_device
            }
        }
    }
}
struct SiblingLease {
    original: Arc<SiblingOriginal>,
    state: Arc<State>,
}
impl TrustedAccountSharingLease for SiblingLease {
    fn approved_policy_id(
        &self,
        scope: &AccountSharingScope,
    ) -> Result<[u8; 32], cgka_traits::EngineError> {
        if !self.original.live() || !self.state.live() || !self.original.matches(scope) {
            return Err(cgka_traits::EngineError::Other(
                "sibling original unavailable".into(),
            ));
        }
        Ok(self.state.approval_id)
    }
    fn validate(&self, scope: &AccountSharingScope) -> Result<Instant, cgka_traits::EngineError> {
        self.approved_policy_id(scope)?;
        let mut fixed = self.state.scope.lock().expect("sibling scope");
        if fixed.as_ref().is_some_and(|old| old != scope) {
            return Err(cgka_traits::EngineError::Other(
                "sibling scope changed".into(),
            ));
        }
        *fixed = Some(scope.clone());
        Ok(self.state.deadline)
    }
}

// Network waits never borrow the account worker or create another original.
// Dropping the exact channel cancels its one in-flight publication.
struct SiblingPublication {
    proof: bool,
    result: tokio::sync::oneshot::Receiver<Result<(), ClientLinkingError>>,
    outcome: Option<Result<(), ClientLinkingError>>,
    task: tokio::task::JoinHandle<()>,
    // NATIVE5_TIMING_BEGIN
    #[cfg(all(test, feature = "test-policy-overrides"))]
    native5_timing: Option<peer_proof_probe::native5_timing::Token>,
    // NATIVE5_TIMING_END
}
impl Drop for SiblingPublication {
    fn drop(&mut self) {
        self.task.abort();
    }
}
const MAX_SIBLING_PUBLICATIONS: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum SiblingAdvanceMode {
    Periodic,
    Initial,
}

pub(super) struct SiblingChannel {
    original: Arc<SiblingOriginal>,
    state: Arc<State>,
    channel: cgka_engine::account_chat_sharing::OwnedAccountSharingChannel,
    recipient: bool,
    ready: bool,
    consent_progress_due: bool,
    initial_source_due: bool,
    publication: Option<SiblingPublication>,
    handshake_attempted: bool,
    deferred_initial_error: Option<ClientLinkingError>,
    handshake_published: bool,
    handshake_retry_at: Option<Instant>,
    policy_committed: bool,
    proof_published: bool,
    proof_retry_at: Option<Instant>,
    peer_committed: bool,
    pending_controls: Vec<(
        cgka_engine::account_chat_sharing::AccountSharingControl,
        Vec<u8>,
        Vec<u8>,
    )>,
    pending_opaque: Mutex<Vec<PendingSiblingControl>>,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pre_auth_failure: Option<Arc<SiblingPreAuthFailureProbe>>,
}
#[cfg(all(test, feature = "test-policy-overrides"))]
impl SiblingChannel {
    fn observe_progress_for_test(&self, stage: usize) {
        let bits = [
            self.original.live(),
            self.state.live(),
            self.ready,
            self.handshake_published,
            self.policy_committed,
            self.proof_published,
            self.peer_committed,
            self.publication.is_some(),
            self.publication
                .as_ref()
                .is_some_and(|p| p.task.is_finished()),
            self.state
                .progress
                .lock()
                .expect("sibling progress")
                .complete,
            !self.pending_controls.is_empty(),
        ];
        let mask = bits
            .into_iter()
            .enumerate()
            .fold(0, |mask, (i, value)| mask | (usize::from(value) << i));
        self.state
            .sibling_progress_for_test
            .store((stage << 16) | mask, Ordering::Release);
    }
}
impl Drop for SiblingChannel {
    fn drop(&mut self) {
        self.state.cancel();
        self.channel.retire();
    }
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CommitProof {
    version: u8,
    policy_identity: [u8; 32],
    transcript_digest: [u8; 32],
    device: [u8; 32],
}
impl AppClient {
    /// A wake only asks the serial owner to recheck its retained original.
    /// Neither an ingest result nor a watch notification grants sharing authority.
    pub(crate) fn note_owned_sibling_source_readiness(&self) {
        if self.linking_owner.pending_sibling_source.is_some() {
            self.linking_owner
                .sibling_publication_completions
                .send_replace(());
        }
    }

    pub(crate) fn sibling_publication_completions(&self) -> tokio::sync::watch::Receiver<()> {
        self.linking_owner
            .sibling_publication_completions
            .subscribe()
    }

    /// A completion is a scheduling hint for already-owned channels, never an
    /// authority inlet or a reason to retry another failed publication.
    pub(crate) async fn service_sibling_publication_completions(
        &mut self,
    ) -> Result<(), ClientLinkingError> {
        let previous_channels = self.linking_owner.sibling_channels.len();
        let mut failure = None;
        match self.recheck_owned_sibling_source_readiness() {
            Ok(Some(original)) => {
                let mut actual_channel = false;
                for (index, entry) in self.linking_owner.sibling_channels.iter_mut().enumerate() {
                    if !entry.recipient
                        && matches!(entry.original.as_ref(),
                        SiblingOriginal::Existing { original: held, .. } if Arc::ptr_eq(held, &original))
                    {
                        actual_channel = true;
                        // Only a newly created exact source gets this first shot.
                        // A consumed or failed attempt can never be revived here.
                        if index >= previous_channels
                            && !entry.handshake_attempted
                            && entry.deferred_initial_error.is_none()
                        {
                            entry.initial_source_due = true;
                        }
                    }
                }
                if actual_channel {
                    self.linking_owner.pending_sibling_source = None;
                }
            }
            Ok(None) => {}
            Err(error) => failure = Some(error),
        }
        let mut channels = std::mem::take(&mut self.linking_owner.sibling_channels);
        let mut in_flight = channels
            .iter()
            .filter(|entry| entry.publication.is_some())
            .count();
        let mut initial = Vec::with_capacity(MAX_SIBLING_PUBLICATIONS);
        let mut harvested_success = false;
        // Harvest every owned result before a successful channel reuses a slot.
        for (index, entry) in channels.iter_mut().enumerate() {
            if entry.deferred_initial_error.is_some() {
                entry.consent_progress_due = false;
                continue;
            }
            match self.harvest_sibling_publication(
                entry,
                &mut in_flight,
                SiblingAdvanceMode::Initial,
            ) {
                Ok(true) => {
                    harvested_success = true;
                    Self::complete_sibling_sharing(entry);
                    if entry.ready && (!entry.policy_committed || !entry.proof_published) {
                        initial.push(index);
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    if failure.is_none() {
                        failure = Some(error);
                    }
                }
            }
            // A late first Consent may have no Request result left to harvest.
            // Select only its exact retained hint after a genuine Request ACK;
            // unrelated ready peers and failed attempts remain periodic work.
            if entry.consent_progress_due
                && !entry.recipient
                && entry.ready
                && entry.handshake_published
                && entry.publication.is_none()
                && !initial.contains(&index)
            {
                initial.push(index);
            }
        }
        let mut starts_left = MAX_SIBLING_PUBLICATIONS;
        // Fresh recipients and exact newly ready sources own one first attempt.
        // All other sources still require a successful harvest. Attempts are
        // consumed before awaiting; periodic retries keep their existing rules.
        for entry in &mut channels {
            if starts_left == 0 || in_flight >= MAX_SIBLING_PUBLICATIONS {
                break;
            }
            if (harvested_success || entry.recipient || entry.initial_source_due)
                && entry.publication.is_none()
                && !entry.handshake_attempted
                && entry.deferred_initial_error.is_none()
                && entry.original.live()
                && entry.state.live()
            {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                match Self::sibling_publication_held_for_test(entry) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(error) => {
                        starts_left -= 1;
                        entry.initial_source_due = false;
                        entry.handshake_attempted = true;
                        entry.deferred_initial_error = Some(error);
                        continue;
                    }
                }
                starts_left -= 1;
                entry.initial_source_due = false;
                entry.handshake_attempted = true;
                match self.start_sibling_publication(entry, None).await {
                    Ok(()) => in_flight += 1,
                    Err(error) => {
                        entry.deferred_initial_error = Some(error);
                    }
                }
            }
        }
        for index in initial.into_iter().take(MAX_SIBLING_PUBLICATIONS) {
            if starts_left == 0 || in_flight >= MAX_SIBLING_PUBLICATIONS {
                break;
            }
            starts_left -= 1;
            let consent_progress = std::mem::take(&mut channels[index].consent_progress_due);
            if consent_progress
                && let Err(error) = self.validate_sibling_publication(&channels[index])
            {
                channels[index].deferred_initial_error = Some(error);
                continue;
            }
            if let Err(error) = self
                .advance_sibling_sharing(
                    &mut channels[index],
                    &mut in_flight,
                    SiblingAdvanceMode::Initial,
                )
                .await
            {
                // This includes policy persistence and Core wrapping failures.
                // Preserve their exact error for the ordinary periodic turn;
                // a different peer's success cannot turn them into hot retries.
                if channels[index].publication.is_none() {
                    channels[index].deferred_initial_error = Some(error);
                } else if failure.is_none() {
                    failure = Some(error);
                }
            }
        }
        self.linking_owner.sibling_channels = channels;
        failure.map_or(Ok(()), Err)
    }

    pub(crate) fn begin_sibling_source_channel(
        &mut self,
        original: Arc<SiblingOriginal>,
        group: &cgka_traits::GroupId,
        recipient: [u8; 32],
        approval_id: [u8; 32],
        deadline: Instant,
    ) -> Result<(), ClientLinkingError> {
        if self.linking_owner.sibling_channels.iter().any(|entry| {
            !entry.recipient
                && entry.state.approval_id == approval_id
                && entry.channel.scope().recipient.as_slice() == recipient
        }) {
            return Ok(());
        }
        if !original.live() || self.linking_owner.sibling_channels.len() >= 128 {
            return Err(denied());
        }
        let state = match original.as_ref() {
            SiblingOriginal::Existing { original, .. } => original.state.clone(),
            _ => State::new_until(&self.account_sharing_owner.lifetime, approval_id, deadline),
        };
        let channel = self
            .runtime
            .session()
            .begin_account_sharing_policy(
                group,
                &recipient,
                Arc::new(SiblingLease {
                    original: original.clone(),
                    state: state.clone(),
                }),
            )
            .map_err(ClientLinkingError::Engine)?;
        #[cfg(all(test, feature = "test-policy-overrides"))]
        let pre_auth_failure = match original.as_ref() {
            SiblingOriginal::Existing {
                original: actual, ..
            } => self
                .linking_owner
                .sibling_pre_auth_probe
                .as_ref()
                .and_then(|(held, probe)| {
                    held.upgrade()
                        .filter(|held| Arc::ptr_eq(held, actual) && actual.state.live())
                        .map(|_| probe.clone())
                }),
            _ => None,
        };
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(probe) = &pre_auth_failure {
            *probe.request_scope.lock().expect("sibling request scope") =
                Some(channel.scope().clone());
            *probe.request_nonce.lock().expect("sibling request nonce") =
                Some(channel.scope().nonce);
        }
        self.linking_owner.sibling_channels.push(SiblingChannel {
            original,
            state,
            channel,
            recipient: false,
            ready: false,
            consent_progress_due: false,
            initial_source_due: false,
            publication: None,
            handshake_attempted: false,
            deferred_initial_error: None,
            handshake_published: false,
            handshake_retry_at: None,
            policy_committed: false,
            proof_published: false,
            proof_retry_at: None,
            peer_committed: false,
            pending_controls: Vec::new(),
            pending_opaque: Mutex::new(Vec::new()),
            #[cfg(all(test, feature = "test-policy-overrides"))]
            pre_auth_failure,
        });
        Ok(())
    }
    pub(crate) fn observe_sibling_sharing_control(
        &mut self,
        received: &cgka_engine::account_chat_sharing::ReceivedAccountSharingControl,
        wire: &[u8],
    ) -> Result<bool, crate::AccountSharingError> {
        use crate::AccountSharingError as Error;
        use cgka_engine::account_chat_sharing::{AccountSharedBodyKind, AccountSharingControl};
        if received.control == AccountSharingControl::Request {
            let Some(choice) = self.linking_owner.sharing_approval.as_ref().cloned() else {
                return Ok(false);
            };
            // Only the original recipient can collect sibling B/C requests.
            // A retained sponsor original must let the independent automatic
            // policy authenticate an addressed peer request instead.
            if choice.scope.local_device != choice.context.recipient {
                return Ok(false);
            }
            // The approver's primary pair uses its own original permission or
            // durable automatic policy; it is never a sibling B/C approval.
            if received.source.as_slice() == choice.context.approver {
                return Ok(false);
            }
            #[cfg(all(test, feature = "test-policy-overrides"))]
            {
                let mut observations = choice
                    .received_requests
                    .lock()
                    .expect("sibling request observations");
                if observations.len() < 32
                    && !observations
                        .iter()
                        .any(|(nonce, _)| *nonce == received.nonce)
                {
                    let source_is_expected = choice
                        .progress
                        .lock()
                        .expect("sharing choice")
                        .expected
                        .as_ref()
                        .is_some_and(|expected| {
                            expected
                                .iter()
                                .any(|peer| peer.as_slice() == received.source)
                        });
                    observations.push((
                        received.nonce,
                        [
                            received.recipient.as_slice() == choice.scope.local_device,
                            received.approval_id
                                == choice.context.digest().map_err(|_| Error::NotReady)?,
                            source_is_expected,
                        ],
                    ));
                }
            }
            #[cfg(all(test, feature = "test-policy-overrides"))]
            let routing_probe = choice
                .routing_probe
                .lock()
                .expect("sibling routing probe")
                .as_ref()
                .filter(|probe| probe.nonce == received.nonce)
                .cloned();
            #[cfg(all(test, feature = "test-policy-overrides"))]
            if let Some(probe) = &routing_probe {
                probe.observed.fetch_add(1, Ordering::AcqRel);
            }
            // Protected group delivery also carries requests addressed to other
            // devices. Verified routing facts only exclude unrelated intake;
            // intended requests still require Core's addressed original API.
            if received.recipient.as_slice() != choice.scope.local_device
                || received.approval_id != choice.context.digest().map_err(|_| Error::NotReady)?
            {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                choice.recipient_diagnostics[if received.recipient.as_slice()
                    != choice.scope.local_device
                {
                    17
                } else {
                    18
                }]
                .fetch_add(1, Ordering::AcqRel);
                return Ok(false);
            }
            if self
                .linking_owner
                .sibling_channels
                .iter()
                .any(|entry| entry.channel.scope().nonce == received.nonce)
            {
                return Ok(true);
            }
            // Exact original nonce retries remain on their retained channel.
            // Once its full handoff completes, a fresh Request belongs to the
            // independent automatic policy, which performs its own live checks.
            if choice.complete() {
                return Ok(false);
            }
            #[cfg(all(test, feature = "test-policy-overrides"))]
            if let Some(probe) = &routing_probe {
                probe.local_auth_attempts.fetch_add(1, Ordering::AcqRel);
            }
            let request = self
                .runtime
                .session()
                .authenticate_account_sharing_request(wire)
                .map_err(|_| Error::NotReady)?;
            let scope = request.scope();
            // A request without the original enrollment identity belongs to a different flow.
            if scope.approval_id != choice.context.digest().map_err(|_| Error::NotReady)? {
                return Ok(false);
            }
            let peer: [u8; 32] = scope
                .source
                .as_slice()
                .try_into()
                .map_err(|_| Error::NotReady)?;
            if !choice.live()
                || !choice
                    .progress
                    .lock()
                    .expect("sharing choice")
                    .expected
                    .as_ref()
                    .is_some_and(|expected| expected.contains(&peer))
            {
                return Err(Error::Closed);
            }
            if self
                .linking_owner
                .sibling_channels
                .iter()
                .any(|entry| entry.recipient && entry.channel.scope().source.as_slice() == peer)
            {
                return Err(Error::NotReady);
            }
            let guard = self
                .linking_owner
                .settlement_attempt
                .as_ref()
                .map(|attempt| attempt.guard.clone())
                .ok_or(Error::NotReady)?;
            self.validate_c_sibling_original(&choice, &guard)
                .map_err(|_| Error::Closed)?;
            let original = Arc::new(SiblingOriginal::Recipient {
                choice: choice.clone(),
                guard,
                peer,
            });
            let state = choice.child().map_err(|_| Error::Closed)?;
            let channel = self
                .runtime
                .session()
                .approve_account_sharing_policy(
                    &request,
                    Arc::new(SiblingLease {
                        original: original.clone(),
                        state: state.clone(),
                    }),
                )
                .map_err(|_| Error::NotReady);
            let channel = match channel {
                Ok(channel) => channel,
                Err(error) => {
                    state.cancel();
                    choice
                        .children
                        .lock()
                        .expect("sibling children")
                        .retain(|child| !Arc::ptr_eq(child, &state));
                    return Err(error);
                }
            };
            self.linking_owner.sibling_channels.push(SiblingChannel {
                original,
                state,
                channel,
                recipient: true,
                ready: true,
                consent_progress_due: false,
                initial_source_due: false,
                publication: None,
                handshake_attempted: false,
                deferred_initial_error: None,
                handshake_published: false,
                handshake_retry_at: None,
                policy_committed: false,
                proof_published: false,
                proof_retry_at: None,
                peer_committed: false,
                pending_controls: Vec::new(),
                pending_opaque: Mutex::new(Vec::new()),
                #[cfg(all(test, feature = "test-policy-overrides"))]
                pre_auth_failure: None,
            });
            // RECIPIENT_ADMISSION_TEST_BEGIN
            #[cfg(all(test, feature = "test-policy-overrides"))]
            peer_proof_probe::recipient_admission::admitted(
                self.linking_owner
                    .sibling_channels
                    .last()
                    .expect("just admitted recipient channel"),
            );
            // RECIPIENT_ADMISSION_TEST_END
            // Core approved this exact owned channel. Wake its first Consent;
            // the completion service still freshly validates before publishing.
            self.linking_owner
                .sibling_publication_completions
                .send_replace(());
            return Ok(true);
        }
        let Some(index) = self
            .linking_owner
            .sibling_channels
            .iter()
            .position(|entry| entry.channel.scope().nonce == received.nonce)
        else {
            return Ok(false);
        };
        let mut entry = self.linking_owner.sibling_channels.remove(index);
        // PEER_NEGATIVE_TEST_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        peer_proof_probe::negative::routed(&entry, received, wire);
        // PEER_NEGATIVE_TEST_END
        let result = (|| {
            if !entry.original.live() || !entry.state.live() {
                // PEER_NEGATIVE_TEST_BEGIN
                #[cfg(all(test, feature = "test-policy-overrides"))]
                peer_proof_probe::negative::closed(&entry, received, wire);
                // PEER_NEGATIVE_TEST_END
                return Err(Error::Closed);
            }
            match received.control {
                AccountSharingControl::Consent if !entry.recipient => {
                    let first_consent = !entry.ready;
                    self.runtime
                        .session()
                        .bind_account_sharing_consent(&mut entry.channel, wire)
                        .map_err(|_| Error::NotReady)?;
                    entry.ready = true;
                    if first_consent {
                        // Keep the initial Request ACK; only its superseded retry is obsolete.
                        if entry.handshake_published
                            && entry
                                .publication
                                .as_ref()
                                .is_some_and(|pending| !pending.proof)
                        {
                            drop(entry.publication.take());
                        }
                        // A one-shot scheduling hint, not authority or a retry.
                        // Core has bound this real Consent to this owned channel.
                        entry.consent_progress_due = true;
                        self.linking_owner
                            .sibling_publication_completions
                            .send_replace(());
                    }
                }
                AccountSharingControl::Body(_) if entry.ready => {
                    // PEER_NEGATIVE_TEST_BEGIN
                    #[cfg(all(test, feature = "test-policy-overrides"))]
                    peer_proof_probe::negative::opened(&entry);
                    // PEER_NEGATIVE_TEST_END
                    let (kind, _, body) = self
                        .runtime
                        .session()
                        .open_account_shared_body(&entry.channel, wire)
                        .map_err(|_| Error::NotReady)?;
                    if kind != AccountSharedBodyKind::PairPolicyCommitted || body.len() > 1024 {
                        return Err(Error::NotReady);
                    }
                    let proof: CommitProof =
                        serde_json::from_slice(&body).map_err(|_| Error::NotReady)?;
                    let scope = entry.channel.scope();
                    let peer = if entry.recipient {
                        &scope.source
                    } else {
                        &scope.recipient
                    };
                    if proof.version != 1
                        || proof.policy_identity != scope.approved_policy_identity
                        || proof.transcript_digest
                            != entry.channel.policy_digest().map_err(|_| Error::NotReady)?
                        || proof.device.as_slice() != peer
                    {
                        return Err(Error::NotReady);
                    }
                    entry.peer_committed = true;
                    // NATIVE5_PROOF_TIMING_BEGIN
                    #[cfg(all(test, feature = "test-policy-overrides"))]
                    peer_proof_probe::native5_timing::progress(&entry, 3);
                    // NATIVE5_PROOF_TIMING_END
                    // PEER_NEGATIVE_TEST_BEGIN
                    #[cfg(all(test, feature = "test-policy-overrides"))]
                    peer_proof_probe::negative::accepted(&entry);
                    // PEER_NEGATIVE_TEST_END
                    // The peer proof can arrive after our own ACK was harvested.
                    // Keep its authenticated fact on this original if fresh parent
                    // or channel validation fails; periodic maintenance retries
                    // completion without reopening the already-consumed wire.
                    if entry.policy_committed && entry.proof_published {
                        match self.validate_sibling_publication(&entry) {
                            Ok(()) => Self::complete_sibling_sharing(&entry),
                            Err(_) => {
                                tracing::debug!(
                                    target: "marmot_app::device_linking",
                                    method = "sibling_peer_proof_completion",
                                    "authenticated peer proof retained for fresh completion validation"
                                );
                            }
                        }
                    }
                }
                _ => return Err(Error::NotReady),
            }
            Ok(true)
        })();
        if result.is_err()
            && entry.original.live()
            && entry.state.live()
            && wire.len() <= 16 * 1024
            && entry.pending_controls.len() < 2
            && !entry
                .pending_controls
                .iter()
                .any(|(kind, _, _)| *kind == received.control)
        {
            entry
                .pending_controls
                .push((received.control, received.signer.clone(), wire.to_vec()));
        }
        self.linking_owner.sibling_channels.push(entry);
        result
    }
    fn validate_c_sibling_original(
        &self,
        choice: &OriginalEnrollmentSharingChoice,
        guard: &SettlementGuard,
    ) -> Result<(), ClientLinkingError> {
        use cgka_engine::private_roster_settlement::TrustedPrivateSettlementGuard;
        if !choice.live() || !guard.matches_original_context(&choice.context) {
            return Err(denied());
        }
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        let round = storage
            .private_roster_settlement_storage()
            .ok_or_else(denied)?
            .read_round()
            .map_err(|error| ClientLinkingError::Engine(error.into()))?
            .ok_or_else(denied)?;
        guard
            .validate(&round.anchor)
            .map_err(ClientLinkingError::Engine)?;
        self.runtime
            .session()
            .validated_settled_device_roster(&guard.group())
            .map_err(ClientLinkingError::Engine)?
            .ok_or_else(denied)?;
        Ok(())
    }
    pub(crate) async fn maintain_sibling_sharing(&mut self) -> Result<(), ClientLinkingError> {
        self.retry_existing_sibling_opaque_controls();
        let mut pending = Vec::new();
        for entry in &mut self.linking_owner.sibling_channels {
            for (control, signer, wire) in std::mem::take(&mut entry.pending_controls) {
                pending.push((
                    cgka_engine::account_chat_sharing::ReceivedAccountSharingControl {
                        nonce: entry.channel.scope().nonce,
                        control,
                        signer,
                        source: entry.channel.scope().source.clone(),
                        recipient: entry.channel.scope().recipient.clone(),
                        approval_id: entry.channel.scope().approval_id,
                    },
                    wire,
                ));
            }
        }
        for (received, wire) in pending {
            // A failed retry remains bounded on this exact original channel;
            // maintenance must not recreate consent or require MLS redelivery.
            let _ = self.observe_sibling_sharing_control(&received, &wire);
        }
        self.retry_pending_sibling_controls();
        self.linking_owner
            .sibling_channels
            .retain(|entry| entry.original.live() && entry.state.live());
        self.begin_completed_sibling_sharing()?;
        let mut channels = std::mem::take(&mut self.linking_owner.sibling_channels);
        let mut in_flight = channels
            .iter()
            .filter(|entry| entry.publication.is_some())
            .count();
        let mut failure = None;
        for entry in &mut channels {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            {
                entry
                    .state
                    .sibling_diagnostics
                    .lock()
                    .expect("sibling diagnostics")
                    .visits += 1;
            }
            if let Err(error) = self
                .advance_sibling_sharing(entry, &mut in_flight, SiblingAdvanceMode::Periodic)
                .await
            {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                {
                    use crate::account_chat_sharing::enabled::SiblingMaintenanceFailure as Failure;
                    let mut diagnostic = entry
                        .state
                        .sibling_diagnostics
                        .lock()
                        .expect("sibling diagnostics");
                    diagnostic.failures += 1;
                    diagnostic.last_failure = Some(match &error {
                        ClientLinkingError::Owner(_) => Failure::Owner,
                        ClientLinkingError::Collection(_) => Failure::Collection,
                        ClientLinkingError::Runtime(_) => Failure::Runtime,
                        ClientLinkingError::Engine(_) => Failure::Engine,
                        ClientLinkingError::Genesis(_) => Failure::Genesis,
                        ClientLinkingError::Gate(_) => Failure::Gate,
                        ClientLinkingError::PrivateInvite(_) => Failure::PrivateInvite,
                    });
                }
                // One refused or unavailable publication cannot starve another original.
                if failure.is_none() {
                    failure = Some(error);
                }
            }
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        {
            for entry in &channels {
                let bits = [
                    entry.original.live(),
                    entry.state.live(),
                    entry.ready,
                    entry.handshake_published,
                    entry.policy_committed,
                    entry.proof_published,
                    entry.peer_committed,
                    entry
                        .state
                        .progress
                        .lock()
                        .expect("sibling progress")
                        .complete,
                ];
                let mask = bits
                    .into_iter()
                    .enumerate()
                    .fold(0, |mask, (index, value)| {
                        mask | (usize::from(value) << index)
                    });
                entry
                    .state
                    .sibling_diagnostics
                    .lock()
                    .expect("sibling diagnostics")
                    .channel_bits = mask;
            }
        }
        self.linking_owner.sibling_channels = channels;
        failure.map_or(Ok(()), Err)
    }
    fn harvest_sibling_publication(
        &mut self,
        entry: &mut SiblingChannel,
        in_flight: &mut usize,
        mode: SiblingAdvanceMode,
    ) -> Result<bool, ClientLinkingError> {
        if let Some(pending) = entry.publication.as_mut() {
            if pending.outcome.is_none() {
                pending.outcome = Some(match pending.result.try_recv() {
                    Ok(result) => {
                        // NATIVE5_TIMING_BEGIN
                        #[cfg(all(test, feature = "test-policy-overrides"))]
                        if let Some(token) = &pending.native5_timing {
                            token.stage(7, Some((3, result.is_ok())));
                        }
                        // NATIVE5_TIMING_END
                        result
                    }
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty) => return Ok(false),
                    Err(tokio::sync::oneshot::error::TryRecvError::Closed) => Err(denied()),
                });
            }
            if mode == SiblingAdvanceMode::Initial {
                // Another peer's success must not consume a failure early and
                // let the next periodic turn retry it sooner. A failed fresh
                // validation also retains the original Ok, not that transient
                // error: the periodic turn performs its original fresh checks.
                if pending.outcome.as_ref().is_some_and(Result::is_err)
                    || self.validate_sibling_publication(entry).is_err()
                {
                    return Ok(false);
                }
            }
            let mut pending = entry
                .publication
                .take()
                .expect("finished sibling publication");
            *in_flight -= 1;
            pending
                .outcome
                .take()
                .expect("received sibling publication outcome")?;
            #[cfg(all(test, feature = "test-policy-overrides"))]
            if !pending.proof
                && !entry.recipient
                && let Some(probe) = &entry.pre_auth_failure
            {
                probe.transport_counts[1].fetch_add(1, Ordering::AcqRel);
            }
            if mode == SiblingAdvanceMode::Periodic {
                self.validate_sibling_publication(entry)?;
            }
            let retry_at = Some(Instant::now() + std::time::Duration::from_secs(1));
            if pending.proof {
                entry.proof_published = true;
                entry.proof_retry_at = retry_at;
            } else {
                entry.handshake_published = true;
                entry.handshake_retry_at = retry_at;
            }
            // NATIVE5_TIMING_BEGIN
            #[cfg(all(test, feature = "test-policy-overrides"))]
            if let Some(token) = &pending.native5_timing {
                token.stage(8, Some((4, true)));
            }
            // NATIVE5_TIMING_END
            return Ok(true);
        }
        Ok(false)
    }

    fn validate_sibling_publication(
        &self,
        entry: &SiblingChannel,
    ) -> Result<(), ClientLinkingError> {
        if !entry.original.live() || !entry.state.live() {
            return Err(denied());
        }
        // PEER_NEGATIVE_TEST_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if peer_proof_probe::negative::reject(entry) {
            // Explicitly injected validation rejection, not a database fault.
            return Err(ClientLinkingError::Runtime(Box::new(
                crate::AppError::InvalidAppMessagePayload(
                    "injected completion validation rejection".into(),
                ),
            )));
        }
        // PEER_NEGATIVE_TEST_END
        self.validate_sibling_parent(&entry.original)?;
        self.runtime
            .session()
            .validate_account_sharing_channel(&entry.channel)
            .map_err(ClientLinkingError::Engine)
    }

    #[cfg(all(test, feature = "test-policy-overrides"))]
    fn sibling_publication_held_for_test(
        entry: &SiblingChannel,
    ) -> Result<bool, ClientLinkingError> {
        entry.pre_auth_failure.as_ref().map_or(Ok(false), |probe| {
            probe.wait_for_projection_head_for_test(entry)
        })
    }

    async fn advance_sibling_sharing(
        &mut self,
        entry: &mut SiblingChannel,
        in_flight: &mut usize,
        mode: SiblingAdvanceMode,
    ) -> Result<(), ClientLinkingError> {
        if mode == SiblingAdvanceMode::Periodic {
            // The ordinary turn owns progress now, including failure deferral.
            // Another peer's later wake cannot revive this old one-shot hint.
            entry.consent_progress_due = false;
        }
        if mode == SiblingAdvanceMode::Periodic
            && let Some(error) = entry.deferred_initial_error.take()
        {
            return Err(error);
        }
        if mode == SiblingAdvanceMode::Initial {
            // Only successful result owners from this bounded pass are eligible.
            // Initial progress cannot restart a failed or peer-only publication.
            if entry.publication.is_some()
                || entry.deferred_initial_error.is_some()
                || !entry.handshake_published
                || !entry.ready
            {
                return Ok(());
            }
        } else if entry.publication.is_some() {
            if !self.harvest_sibling_publication(entry, in_flight, mode)? {
                return Ok(());
            }
            if !entry.policy_committed || !entry.proof_published || !entry.peer_committed {
                return Ok(());
            }
        }
        if !entry.original.live() || !entry.state.live() {
            return Ok(());
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if Self::sibling_publication_held_for_test(entry)? {
            // Delay only this genuine source's Request; normal maintenance
            // cadence, cancellation and fixed original deadline still apply.
            return Ok(());
        }
        let awaiting_handshake = if entry.recipient {
            !entry.peer_committed
        } else {
            !entry.ready
        };
        if !entry.handshake_published
            || (mode == SiblingAdvanceMode::Periodic && awaiting_handshake
                && entry
                    .handshake_retry_at
                    .is_some_and(|next| Instant::now() >= next)
                // Initial policy/proof progress must precede another consent.
                // Once both were sent, retry the older publication first: the
                // one-second worker cadence can otherwise starve proof forever.
                && (!entry.ready
                    || (entry.proof_published
                        && entry.handshake_retry_at <= entry.proof_retry_at)))
        {
            if *in_flight < MAX_SIBLING_PUBLICATIONS {
                entry.initial_source_due = false;
                entry.handshake_attempted = true;
                self.start_sibling_publication(entry, None).await?;
                *in_flight += 1;
            }
            return Ok(());
        }
        if !entry.ready {
            return Ok(());
        }
        if !entry.policy_committed {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            entry.observe_progress_for_test(5);
            // NATIVE5_PROOF_TIMING_BEGIN
            #[cfg(all(test, feature = "test-policy-overrides"))]
            peer_proof_probe::native5_timing::progress(entry, 0);
            // NATIVE5_PROOF_TIMING_END
            self.persist_sibling_policy(entry)?;
            entry.policy_committed = true;
            // NATIVE5_PROOF_TIMING_BEGIN
            #[cfg(all(test, feature = "test-policy-overrides"))]
            peer_proof_probe::native5_timing::progress(entry, 1);
            // NATIVE5_PROOF_TIMING_END
        }
        if !entry.proof_published
            || (mode == SiblingAdvanceMode::Periodic
                && !entry.peer_committed
                && entry
                    .proof_retry_at
                    .is_some_and(|next| Instant::now() >= next))
        {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            entry.observe_progress_for_test(6);
            // NATIVE5_PROOF_TIMING_BEGIN
            #[cfg(all(test, feature = "test-policy-overrides"))]
            peer_proof_probe::native5_timing::progress(entry, 2);
            // NATIVE5_PROOF_TIMING_END
            let scope = entry.channel.scope();
            let device = if entry.recipient {
                &scope.recipient
            } else {
                &scope.source
            };
            let proof = CommitProof {
                version: 1,
                policy_identity: scope.approved_policy_identity,
                transcript_digest: entry
                    .channel
                    .policy_digest()
                    .map_err(ClientLinkingError::Engine)?,
                device: device.as_slice().try_into().map_err(|_| denied())?,
            };
            let bytes = serde_json::to_vec(&proof).map_err(|_| denied())?;
            if *in_flight < MAX_SIBLING_PUBLICATIONS {
                self.start_sibling_publication(entry, Some(&bytes)).await?;
                *in_flight += 1;
            }
            return Ok(());
        }
        if entry.peer_committed {
            self.validate_sibling_publication(entry)?;
            Self::complete_sibling_sharing(entry);
        }
        Ok(())
    }

    fn complete_sibling_sharing(entry: &SiblingChannel) {
        if entry.policy_committed
            && entry.proof_published
            && entry.peer_committed
            && entry.original.live()
            && entry.state.live()
        {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            entry.observe_progress_for_test(7);
            let mut progress = entry.state.progress.lock().expect("sibling progress");
            if !progress.complete {
                progress.complete = true;
                progress.revision += 1;
                // NATIVE5_PROOF_TIMING_BEGIN
                #[cfg(all(test, feature = "test-policy-overrides"))]
                peer_proof_probe::native5_timing::progress(entry, 4);
                // NATIVE5_PROOF_TIMING_END
            }
        }
    }
    fn persist_sibling_policy(&self, entry: &SiblingChannel) -> Result<(), ClientLinkingError> {
        use cgka_traits::approved_account_sharing_policy::{
            ACCOUNT_SHARING_CAPABILITIES, ACCOUNT_SHARING_POLICY_VERSION,
            ApprovedAccountSharingPolicy,
        };
        let scope = entry.channel.scope();
        let (local, peer) = if entry.recipient {
            (&scope.recipient, &scope.source)
        } else {
            (&scope.source, &scope.recipient)
        };
        let policy = ApprovedAccountSharingPolicy {
            account: scope
                .protected
                .account
                .as_slice()
                .try_into()
                .map_err(|_| denied())?,
            local_device: local.as_slice().try_into().map_err(|_| denied())?,
            peer_device: peer.as_slice().try_into().map_err(|_| denied())?,
            protected_group: scope.protected.group_id.clone(),
            approval_id: scope.approval_id,
            version: ACCOUNT_SHARING_POLICY_VERSION,
            capabilities: ACCOUNT_SHARING_CAPABILITIES,
            created_at: entry.state.created_at,
            approved_protected_epoch: scope.protected.epoch.0,
            revoked: false,
        };
        let validate = || {
            if !entry.original.live() || !entry.state.live() {
                return Err(cgka_traits::storage::StorageError::Serialization(
                    "sibling original unavailable".into(),
                ));
            }
            self.validate_sibling_parent(&entry.original).map_err(|_| {
                cgka_traits::storage::StorageError::Serialization("sibling original changed".into())
            })?;
            self.runtime
                .session()
                .validate_account_sharing_channel(&entry.channel)
                .map_err(|_| {
                    cgka_traits::storage::StorageError::Serialization(
                        "sibling channel changed".into(),
                    )
                })
        };
        let capture = match entry.original.as_ref() {
            SiblingOriginal::Existing { original, .. } => original
                .state
                .legacy_capture
                .lock()
                .expect("legacy capture")
                .clone(),
            SiblingOriginal::Recipient { choice, .. } => choice
                .legacy_capture
                .lock()
                .expect("legacy capture")
                .clone(),
        }
        .ok_or_else(denied)?;
        self.commit_policy_with_legacy_chats(&policy, &capture, &validate)
            .map_err(|error| ClientLinkingError::Engine(error.into()))
    }
    async fn start_sibling_publication(
        &mut self,
        entry: &mut SiblingChannel,
        body: Option<&[u8]>,
    ) -> Result<(), ClientLinkingError> {
        use cgka_engine::account_chat_sharing::{AccountSharedBodyKind, AccountSharingControl};
        if !entry.original.live() || !entry.state.live() {
            return Err(denied());
        }
        self.validate_sibling_parent(&entry.original)?;
        // NATIVE5_PROOF_TIMING_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        let native5_proof_attempt =
            body.and_then(|_| peer_proof_probe::native5_timing::begin_proof(entry));
        // NATIVE5_PROOF_TIMING_END
        let kind = if let Some(body) = body {
            self.runtime
                .session()
                .seal_account_shared_body(
                    &mut entry.channel,
                    AccountSharedBodyKind::PairPolicyCommitted,
                    0,
                    body,
                )
                .map_err(ClientLinkingError::Engine)?;
            // NATIVE5_PROOF_TIMING_BEGIN
            #[cfg(all(test, feature = "test-policy-overrides"))]
            if let Some(attempt) = &native5_proof_attempt {
                attempt.boundary(1);
            }
            // NATIVE5_PROOF_TIMING_END
            AccountSharingControl::Body(0)
        } else if entry.recipient {
            AccountSharingControl::Consent
        } else {
            AccountSharingControl::Request
        };
        let state = entry.state.clone();
        let revoked_wrap = state.revoked.notified();
        tokio::pin!(revoked_wrap);
        revoked_wrap.as_mut().enable();
        let mut shutdown = self.history_owner.runtime_shutdown.clone();
        let stopping = async {
            if let Some(watch) = shutdown.as_mut() {
                if *watch.borrow() {
                    return;
                }
                while watch.changed().await.is_ok() {
                    if *watch.borrow() {
                        return;
                    }
                }
            } else {
                std::future::pending::<()>().await
            }
        };
        tokio::pin!(stopping);
        if !entry.original.live() || !state.live() {
            return Err(denied());
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        {
            use crate::account_chat_sharing::enabled::SiblingPublicationStage as Stage;
            entry
                .state
                .sibling_diagnostics
                .lock()
                .expect("sibling diagnostics")
                .publication_stage = Some(Stage::BeforeCoreWrap);
        }
        // NATIVE5_PROOF_TIMING_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(attempt) = &native5_proof_attempt {
            attempt.boundary(2);
        }
        // NATIVE5_PROOF_TIMING_END
        let message = tokio::select! { biased;
            () = &mut stopping => return Err(denied()),
            () = &mut revoked_wrap => return Err(denied()),
            () = tokio::time::sleep_until(state.deadline.into()) => return Err(denied()),
            message = self.runtime.session_mut().wrap_account_sharing_control(&mut entry.channel, kind) => message.map_err(ClientLinkingError::Engine)?,
        };
        // NATIVE5_PROOF_TIMING_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(attempt) = &native5_proof_attempt {
            attempt.boundary(3);
        }
        // NATIVE5_PROOF_TIMING_END
        #[cfg(all(test, feature = "test-policy-overrides"))]
        {
            use crate::account_chat_sharing::enabled::SiblingPublicationStage as Stage;
            entry
                .state
                .sibling_diagnostics
                .lock()
                .expect("sibling diagnostics")
                .publication_stage = Some(Stage::AfterCoreWrap);
        }
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if kind == AccountSharingControl::Request
            && let Some(probe) = &entry.pre_auth_failure
        {
            probe.transport_counts[0].fetch_add(1, Ordering::AcqRel);
            if let cgka_traits::TransportEnvelope::GroupMessage { transport_group_id } =
                &message.envelope
            {
                *probe.request_route.lock().expect("sibling request route") = Some((
                    entry.channel.scope().protected.group_id.clone(),
                    entry.channel.scope().protected.epoch,
                    transport_group_id.clone(),
                ));
            }
            *probe
                .request_content
                .lock()
                .expect("sibling request content") =
                entry.channel.outbound_content_id_for_test(kind);
            let mut cached = probe
                .request_message
                .lock()
                .expect("sibling request transport");
            if let Some(previous) = cached.as_ref() {
                probe.transport_counts[if previous == &message.id { 2 } else { 3 }]
                    .fetch_add(1, Ordering::AcqRel);
            } else {
                *cached = Some(message.id.clone());
            }
        }
        let evidence = self
            .runtime
            .session()
            .private_transport_evidence(crate::NOSTR_ROUTING_COMPONENT_ID)
            .map_err(ClientLinkingError::Engine)?
            .ok_or_else(denied)?;
        if evidence.group_id() != &entry.channel.scope().protected.group_id {
            return Err(denied());
        }
        let route = cgka_traits::app_components::decode_nostr_routing_v1(evidence.component())
            .map_err(|_| denied())?;
        let request = cgka_traits::TransportPublishRequest {
            account_id: self.runtime.session().self_id(),
            message,
            target: cgka_traits::TransportPublishTarget::Group {
                group_id: evidence.group_id().clone(),
                transport_group_id: route.nostr_group_id.to_vec(),
                endpoints: route
                    .relays
                    .into_iter()
                    .map(cgka_traits::TransportEndpoint)
                    .collect(),
            },
            required_acks: 1,
        };
        if !entry.original.live() || !entry.state.live() || entry.publication.is_some() {
            return Err(denied());
        }
        self.validate_sibling_parent(&entry.original)?;
        #[cfg(all(test, feature = "test-policy-overrides"))]
        {
            use crate::account_chat_sharing::enabled::SiblingPublicationStage as Stage;
            entry
                .state
                .sibling_diagnostics
                .lock()
                .expect("sibling diagnostics")
                .publication_stage = Some(Stage::BeforeRelayPublication);
        }
        // NATIVE5_TIMING_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        let native5_timing = peer_proof_probe::native5_timing::prepared(
            entry,
            &request,
            kind,
            native5_proof_attempt.as_ref(),
        );
        // NATIVE5_TIMING_END
        self.runtime
            .session()
            .validate_account_sharing_channel(&entry.channel)
            .map_err(ClientLinkingError::Engine)?;
        // NATIVE5_TIMING_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(token) = &native5_timing {
            token.stage(1, None);
        }
        // NATIVE5_TIMING_END
        let adapter = self.adapter.clone();
        // REQUEST_RETRY_TEST_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        let adapter = peer_proof_probe::retry_completion::Adapter::capture(adapter, entry, kind);
        // REQUEST_RETRY_TEST_END
        let original = entry.original.clone();
        let state = entry.state.clone();
        let mut shutdown = self.history_owner.runtime_shutdown.clone();
        let proof = body.is_some();

        // NATIVE5_SPAWN_TIMING_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(token) = &native5_timing { token.spawn_boundary(0); }
        // NATIVE5_SPAWN_TIMING_END
        // PEER_NEGATIVE_TEST_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if proof {
            peer_proof_probe::negative::prepared(
                &entry.original,
                entry.channel.scope().nonce,
                entry.channel.outbound_control_wire_digest_for_test(kind),
            );
        }
        // PEER_NEGATIVE_TEST_END

        // NATIVE5_SPAWN_TIMING_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(token) = &native5_timing { token.spawn_boundary(1); }
        // NATIVE5_SPAWN_TIMING_END
        let consent = entry.recipient && !proof;
        // NATIVE5_SPAWN_TIMING_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(token) = &native5_timing { token.spawn_boundary(2); }
        // NATIVE5_SPAWN_TIMING_END

        #[cfg(all(test, feature = "test-policy-overrides"))]
        {
            *entry
                .state
                .sibling_publication_for_test
                .lock()
                .expect("sibling publication") = Some(request.message.id.clone());
        }


        // NATIVE5_SPAWN_TIMING_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(token) = &native5_timing { token.spawn_boundary(3); }
        // NATIVE5_SPAWN_TIMING_END
        // COMPLETION_TEST_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        let completion_consent_identity = consent.then(|| request.message.id.clone());
        // COMPLETION_TEST_END
        // PEER_PROOF_TEST_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        let peer_proof_nonce = entry.channel.scope().nonce;
        // PEER_PROOF_TEST_END
        let completion = self.linking_owner.sibling_publication_completions.clone();
        let (result_tx, result) = tokio::sync::oneshot::channel();
        // NATIVE5_TIMING_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        let native5_timing_task = native5_timing.clone();
        // NATIVE5_TIMING_END

        // NATIVE5_SPAWN_TIMING_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(token) = &native5_timing { token.spawn_boundary(4); }
        // NATIVE5_SPAWN_TIMING_END
        let task = tokio::spawn(async move {
            // NATIVE5_TIMING_BEGIN
            #[cfg(all(test, feature = "test-policy-overrides"))]
            if let Some(token) = &native5_timing_task {
                token.stage(2, None);
            }
            // NATIVE5_TIMING_END
            let outcome = async {
            let revoked = state.revoked.notified();
            tokio::pin!(revoked);
            revoked.as_mut().enable();
            let stopping = async {
                if let Some(watch) = shutdown.as_mut() {
                    if *watch.borrow() {
                        return;
                    }
                    while watch.changed().await.is_ok() {
                        if *watch.borrow() {
                            return;
                        }
                    }
                } else {
                    std::future::pending::<()>().await
                }
            };
            tokio::pin!(stopping);
            if !original.live() || !state.live() {
                return Err(denied());
            }
            let report = tokio::select! { biased;
                () = &mut stopping => return Err(denied()),
                () = &mut revoked => return Err(denied()),
                () = tokio::time::sleep_until(state.deadline.into()) => return Err(denied()),
                report = async {
// PEER_PROOF_TEST_BEGIN
                    #[cfg(all(test, feature = "test-policy-overrides"))]
                    if proof { peer_proof_probe::hold(&original, peer_proof_nonce).await; }
// PEER_PROOF_TEST_END
// RECIPIENT_ADMISSION_TEST_BEGIN
                    #[cfg(all(test, feature = "test-policy-overrides"))]
                    if kind == AccountSharingControl::Request {
                        peer_proof_probe::recipient_admission::hold_request(&original, peer_proof_nonce, &request).await;
                    }
// RECIPIENT_ADMISSION_TEST_END
                    if consent {
// NATIVE5_TIMING_BEGIN
                        #[cfg(all(test, feature = "test-policy-overrides"))]
                        if let Some(token) = &native5_timing_task { token.stage(3, None); }
// NATIVE5_TIMING_END
                        let consent_result = adapter.publish_sibling_consent(request).await;
// NATIVE5_TIMING_BEGIN
                        #[cfg(all(test, feature = "test-policy-overrides"))]
                        if let Some(token) = &native5_timing_task {
                            token.report(consent_result.is_ok(), consent_result.as_ref().ok().map(|report| report.met_required_acks()));
                        }
// NATIVE5_TIMING_END
                        consent_result
                    }
                    else {
// NATIVE5_PROOF_TIMING_BEGIN
                        #[cfg(all(test, feature = "test-policy-overrides"))]
                        if let Some(token) = &native5_timing_task { token.stage(3, None); }
// NATIVE5_PROOF_TIMING_END
                        let publication_result = adapter.publish_selected_chat(request).await;
// NATIVE5_PROOF_TIMING_BEGIN
                        #[cfg(all(test, feature = "test-policy-overrides"))]
                        if let Some(token) = &native5_timing_task { token.report(publication_result.is_ok(), publication_result.as_ref().ok().map(|report| report.met_required_acks())); }
// NATIVE5_PROOF_TIMING_END
                        publication_result
                    }
                } => report.map_err(|error| ClientLinkingError::Runtime(Box::new(error.into())))?,
            };
            if !original.live() || !state.live() || !report.met_required_acks() {
                return Err(denied());
            }
// NATIVE5_TIMING_BEGIN
            #[cfg(all(test, feature = "test-policy-overrides"))]
            if let Some(token) = &native5_timing_task { token.stage(5, None); }
// NATIVE5_TIMING_END
            #[cfg(all(test, feature = "test-policy-overrides"))]
            {
                use crate::account_chat_sharing::enabled::SiblingPublicationStage as Stage;
                state
                    .sibling_diagnostics
                    .lock()
                    .expect("sibling diagnostics")
                    .publication_stage = Some(Stage::AfterRelayPublication);
            }

            // COMPLETION_TEST_BEGIN
            #[cfg(all(test, feature = "test-policy-overrides"))]
            {
                let mut observation = state
                    .sibling_diagnostics
                    .lock()
                    .expect("sibling completion test observation");
                if observation.successful_consent_message.is_none()
                    && let Some(identity) = completion_consent_identity
                {
                    observation.successful_consent_message = Some(identity);
                }
                if proof {
                    observation.successful_commit_proof = true;
                }
            }
            // COMPLETION_TEST_END
            Ok(())
            }.await;
            let success = outcome.is_ok();
            // Queue the actual result before signalling; a JoinHandle may not
            // yet be marked finished when the account worker receives a wake.
            let sent = result_tx.send(outcome).is_ok();
            // NATIVE5_TIMING_BEGIN
            #[cfg(all(test, feature = "test-policy-overrides"))]
            if let Some(token) = &native5_timing_task {
                token.stage(6, Some((2, sent)));
            }
            // NATIVE5_TIMING_END
            if sent && success {
                completion.send_replace(());
            }
        });

        // NATIVE5_SPAWN_TIMING_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        if let Some(token) = &native5_timing { token.spawn_boundary(5); }
        // NATIVE5_SPAWN_TIMING_END
        entry.publication = Some(SiblingPublication {
            proof,
            result,
            outcome: None,
            task,
            // NATIVE5_TIMING_BEGIN
            #[cfg(all(test, feature = "test-policy-overrides"))]
            native5_timing,
            // NATIVE5_TIMING_END
        });
        // PEER_NEGATIVE_TEST_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        peer_proof_probe::negative::started(entry, proof);
        // PEER_NEGATIVE_TEST_END
        Ok(())
    }
    fn validate_sibling_parent(
        &self,
        original: &SiblingOriginal,
    ) -> Result<(), ClientLinkingError> {
        use cgka_engine::private_roster_settlement::TrustedPrivateSettlementGuard;
        if !original.live() {
            return Err(denied());
        }
        match original {
            SiblingOriginal::Recipient { choice, guard, .. } => {
                self.validate_c_sibling_original(choice, guard)
            }
            SiblingOriginal::Existing { guard, .. } => {
                let storage = self
                    .app
                    .account_storage(&self.state.label)
                    .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
                let round = storage
                    .private_roster_settlement_storage()
                    .ok_or_else(denied)?
                    .read_round()
                    .map_err(|error| ClientLinkingError::Engine(error.into()))?
                    .ok_or_else(denied)?;
                guard
                    .validate(&round.anchor)
                    .map_err(ClientLinkingError::Engine)?;
                self.runtime
                    .session()
                    .validated_settled_device_roster(guard.group())
                    .map_err(ClientLinkingError::Engine)?
                    .ok_or_else(denied)?;
                Ok(())
            }
        }
    }
}
