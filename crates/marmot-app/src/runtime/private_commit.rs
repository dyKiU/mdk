//! Actor-owned private commit publication; the shared control can only revoke.
use crate::device_linking::invite_gate::RuntimeInviteGate;
use cgka_traits::device_linking_key_package::PurposeAttemptScope;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

enum PublicationGate {
    Revoked(Arc<cgka_engine::device_leaf_revocation::DeviceRevocationSettlementControl>),
    Invite(Arc<RuntimeInviteGate>),
    Settlement(Arc<crate::device_linking::settlement::SettlementGuard>),
    Endorsement(cgka_engine::private_enrollment_endorsement::EnrollmentEndorsementCancellation),
}
impl PublicationGate {
    fn cancel(&self) {
        match self {
            Self::Revoked(control) => control.cancel(),
            Self::Invite(gate) => gate.cancel(),
            Self::Settlement(guard) => guard.revoke(),
            Self::Endorsement(control) => control.cancel(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum PublicationIdentity {
    Scoped(PurposeAttemptScope),
    Endorsement([u8; 32]),
    Revoked([u8; 32]),
}

struct ActiveControl {
    identity: PublicationIdentity,
    gate: PublicationGate,
    revoked: bool,
    negative_invite_revision: Option<crate::device_linking::settlement::SdkCancellationFence>,
}

/// One bounded negative slot, never a consent or transport inlet. Only the
/// account actor installs an already-owned exact attempt; callers may revoke it.
#[derive(Default)]
pub(super) struct PublicationControl {
    active: Mutex<Option<ActiveControl>>,
    shutdown: AtomicBool,
    wake: Notify,
    #[cfg(all(test, feature = "test-policy-overrides"))]
    prepare_reply_observation: Mutex<(u64, bool, Option<(PurposeAttemptScope, bool)>)>,
}
impl PublicationControl {
    pub(super) fn install(&self, scope: PurposeAttemptScope, gate: Arc<RuntimeInviteGate>) {
        self.install_gate(
            PublicationIdentity::Scoped(scope),
            PublicationGate::Invite(gate),
        );
    }
    fn install_gate(&self, identity: PublicationIdentity, gate: PublicationGate) {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let revoked = self.shutdown.load(Ordering::Acquire)
            || active
                .as_ref()
                .is_some_and(|active| active.identity == identity && active.revoked);
        if revoked {
            gate.cancel();
        }
        *active = Some(ActiveControl {
            identity,
            gate,
            revoked,
            negative_invite_revision: None,
        });
    }
    pub(super) fn revoke(&self, scope: &PurposeAttemptScope) {
        self.revoke_identity(&PublicationIdentity::Scoped(scope.clone()));
    }
    pub(super) fn revoke_endorsement(&self, binding: &[u8; 32]) {
        self.revoke_identity(&PublicationIdentity::Endorsement(*binding));
    }
    fn revoke_identity(&self, identity: &PublicationIdentity) {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(active) = active
            .as_mut()
            .filter(|active| active.identity == *identity)
        {
            if !active.revoked {
                active.revoked = true;
                active.gate.cancel();
                if let PublicationGate::Invite(gate) = &active.gate {
                    // Capture after the actual first revocation. Inherited
                    // installation/repeated revocation must never renew this.
                    active.negative_invite_revision = Some(gate.cancellation_fence());
                }
            }
            self.wake.notify_one();
        }
    }
    fn matches_negative_invite(
        &self,
        active: &ActiveControl,
        scope: &PurposeAttemptScope,
        gate: &Arc<RuntimeInviteGate>,
    ) -> bool {
        !self.shutdown.load(Ordering::Acquire)
            && active.identity == PublicationIdentity::Scoped(scope.clone())
            && active.revoked
            && matches!(&active.gate, PublicationGate::Invite(own) if Arc::ptr_eq(own, gate))
            && active
                .negative_invite_revision
                .as_ref()
                .is_some_and(|revision| revision.revision_matches_for_negative_completion())
    }
    fn has_negative_invite(
        &self,
        scope: &PurposeAttemptScope,
        gate: &Arc<RuntimeInviteGate>,
    ) -> bool {
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|active| self.matches_negative_invite(active, scope, gate))
    }
    fn consume_negative_invite(
        &self,
        scope: &PurposeAttemptScope,
        gate: &Arc<RuntimeInviteGate>,
    ) -> bool {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if !active
            .as_ref()
            .is_some_and(|active| self.matches_negative_invite(active, scope, gate))
        {
            return false;
        }
        *active = None;
        true
    }
    /// Bounded actual handler result, only for the dropped-response regression.
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(super) fn record_prepare_reply_for_test(&self, scope: &PurposeAttemptScope, succeeded: bool) {
        let mut value = self.prepare_reply_observation.lock().unwrap_or_else(|e| e.into_inner());
        if value.1 { return; }
        if let Some(next) = value.0.checked_add(1) {
            value.0 = next;
            value.2 = Some((scope.clone(), succeeded));
        } else {
            value.1 = true;
            value.2 = None;
        }
    }
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(super) fn prepare_reply_for_test(&self, scope: &PurposeAttemptScope) -> Option<(u64, bool)> {
        let value = self.prepare_reply_observation.lock().unwrap_or_else(|e| e.into_inner());
        if value.1 { return None; }
        value.2.as_ref().filter(|(own, _)| own == scope).map(|(_, succeeded)| (value.0, *succeeded))
    }

    /// Opaque revision observation only; no SDK owner, epoch, or identity export.
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(super) fn unrevoked_invite_revision_for_test(
        &self, scope: &PurposeAttemptScope,
    ) -> Option<crate::device_linking::settlement::SdkCancellationFence> {
        let active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let active = active.as_ref().filter(|active|
            active.identity == PublicationIdentity::Scoped(scope.clone()) && !active.revoked)?;
        match &active.gate {
            PublicationGate::Invite(gate) => Some(gate.cancellation_fence()),
            _ => None,
        }
    }

    pub(super) fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(active) = active.as_mut() {
            active.revoked = true;
            active.gate.cancel();
        }
        self.wake.notify_one();
    }
    fn revoked(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
            || self
                .active
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .is_some_and(|active| active.revoked || matches!(&active.gate, PublicationGate::Revoked(control) if !control.is_live()))
    }
    fn clear(&self) {
        *self.active.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// Acknowledge only an already-retired original after exact caller revocation.
/// No await, new authority, or broad cancellation occurs in the fallback.
pub(super) async fn cancel_scope(
    client: &mut crate::client::AppClient,
    scope: &PurposeAttemptScope,
    control: &PublicationControl,
) -> Result<(), crate::client::device_linking::ClientLinkingError> {
    use crate::client::device_linking::ClientLinkingError;
    let stale = match client.cancel_device_linking_scope(scope).await {
        Err(
            error @ ClientLinkingError::Owner(crate::device_linking::OwnerError::Verifier(
                crate::device_linking::LinkError::StaleFlow,
            )),
        ) => error,
        result => return result,
    };
    let Some(gate) = client.retired_invite_cancel_candidate(scope)? else {
        return Err(stale);
    };
    if !control.has_negative_invite(scope, &gate) {
        return Err(stale);
    }
    client.finish_retired_invite_negative_cleanup(scope)?;
    if !control.consume_negative_invite(scope, &gate) {
        return Err(stale);
    }
    Ok(())
}

fn snapshot_read(
    command: super::AccountWorkerCommand,
    snapshot: Option<&crate::client::GroupReadSnapshot>,
    app: &crate::MarmotApp,
    account_label: &str,
) -> Option<super::AccountWorkerCommand> {
    use super::AccountWorkerCommand as Command;
    let Some(snapshot) = snapshot else {
        return Some(command);
    };
    match command {
        Command::Members { group_id, respond } => {
            let _ = respond.send(snapshot.members(&group_id));
        }
        Command::MemberIdsPage { group_ids, respond } => {
            let _ = respond.send(snapshot.member_ids_page(&group_ids));
        }
        Command::GroupMlsState { group_id, respond } => {
            let _ = respond.send(snapshot.group_mls_state(&group_id));
        }
        Command::GroupRoster { group_id, respond } => {
            let _ = respond.send(super::account_worker::group_roster_from_snapshot(
                app,
                account_label,
                snapshot,
                &group_id,
            ));
        }
        Command::QuarantinedGroups { respond } => {
            let _ = respond.send(Ok(snapshot.quarantined_groups()));
        }
        other => return Some(other),
    }
    None
}

#[derive(Clone, Copy)]
pub(super) enum PublicationKind {
    Proposal,
    Commit,
    Welcomes,
    Settlement,
}
enum Publication {
    Scoped {
        scope: PurposeAttemptScope,
        kind: PublicationKind,
    },
    Endorsement([u8; 32]),
    ExistingSettlement([u8; 32]),
    RevokedSettlement([u8; 32]),
}
impl Publication {
    fn identity(&self) -> PublicationIdentity {
        match self {
            Self::RevokedSettlement(binding) => PublicationIdentity::Revoked(*binding),
            Self::Scoped { scope, .. } => PublicationIdentity::Scoped(scope.clone()),
            Self::Endorsement(binding) | Self::ExistingSettlement(binding) => {
                PublicationIdentity::Endorsement(*binding)
            }
        }
    }
    fn owned_control(
        &self,
        client: &crate::client::AppClient,
    ) -> Result<
        (std::time::Instant, PublicationGate),
        crate::client::device_linking::ClientLinkingError,
    > {
        match self {
            Self::Scoped {
                scope,
                kind: PublicationKind::Proposal,
            } => client
                .enrollment_proposal_control(scope)
                .map(|(deadline, gate)| (deadline, PublicationGate::Invite(gate))),
            Self::Scoped {
                scope,
                kind: PublicationKind::Settlement,
            } => client
                .private_settlement_control(scope)
                .map(|guard| (guard.deadline(), PublicationGate::Settlement(guard))),
            Self::Scoped {
                scope,
                kind: PublicationKind::Commit | PublicationKind::Welcomes,
            } => client
                .private_commit_control(scope)
                .map(|(deadline, gate)| (deadline, PublicationGate::Invite(gate))),
            Self::RevokedSettlement(binding) => client
                .revoked_settlement_control(binding)
                .map(|guard| (guard.deadline(), PublicationGate::Revoked(guard))),
            Self::ExistingSettlement(binding) => {
                client.existing_settlement_control(binding).map(|guard| {
                    (
                        guard.deadline(),
                        PublicationGate::Endorsement(guard.cancellation_handle()),
                    )
                })
            }
            Self::Endorsement(binding) => client
                .enrollment_endorsement_control(binding)
                .map(|(deadline, control)| (deadline, PublicationGate::Endorsement(control))),
        }
    }
    async fn dispatch(
        &self,
        client: &mut crate::client::AppClient,
    ) -> Result<(), crate::client::device_linking::ClientLinkingError> {
        match self {
            Self::RevokedSettlement(binding) => client.dispatch_revoked_settlement(binding).await,
            Self::Scoped {
                scope,
                kind: PublicationKind::Proposal,
            } => client.dispatch_owned_enrollment_proposal(scope).await,
            Self::Scoped {
                scope,
                kind: PublicationKind::Commit,
            } => client.dispatch_owned_private_commit(scope).await,
            Self::Scoped {
                scope,
                kind: PublicationKind::Welcomes,
            } => client.dispatch_owned_private_welcomes(scope).await,
            Self::Scoped {
                scope,
                kind: PublicationKind::Settlement,
            } => client.dispatch_owned_private_settlement(scope).await,
            Self::ExistingSettlement(binding) => {
                client.dispatch_existing_private_settlement(binding).await
            }
            Self::Endorsement(binding) => {
                client
                    .dispatch_received_enrollment_endorsement(binding)
                    .await
            }
        }
    }
    async fn interrupt(
        &self,
        client: &mut crate::client::AppClient,
    ) -> Result<(), crate::client::device_linking::ClientLinkingError> {
        match self {
            Self::RevokedSettlement(binding) => {
                if let Ok(control) = client.revoked_settlement_control(binding) {
                    control.cancel();
                }
                Ok(())
            }
            Self::Scoped {
                scope,
                kind: PublicationKind::Proposal,
            } => client.cancel_device_linking_scope(scope).await,
            Self::Scoped {
                kind: PublicationKind::Settlement,
                ..
            } => client.revoke_owned_private_settlement(),
            Self::Scoped {
                scope,
                kind: PublicationKind::Commit | PublicationKind::Welcomes,
            } => client.finish_private_commit_interruption(scope),
            Self::Endorsement(binding) | Self::ExistingSettlement(binding) => {
                client.cancel_received_enrollment_endorsement(binding)
            }
        }
    }
}
fn observe_revocation(control: &PublicationControl, command: &super::AccountWorkerCommand) {
    match command {
        super::AccountWorkerCommand::CancelDeviceLinking { scope, .. } => control.revoke(scope),
        super::AccountWorkerCommand::DeviceLinkingVerifier(command) => {
            if let super::device_linking::VerifierCommand::CancelReceivedEnrollmentEndorsement {
                binding,
                ..
            } = command.as_ref()
            {
                control.revoke_endorsement(binding);
            }
        }
        _ => {}
    }
}
const DEFERRED_LIMIT: usize = 8;
/// The Engine borrow and original nonclone lease stay on this account actor.
/// Bounded deferral backpressures the ordinary queue; revocation bypasses it.
#[allow(clippy::too_many_arguments)]
pub(super) async fn publish(
    client: &mut crate::client::AppClient,
    scope: PurposeAttemptScope,
    kind: PublicationKind,
    respond: Option<
        tokio::sync::oneshot::Sender<Result<(), crate::client::device_linking::ClientLinkingError>>,
    >,
    commands: &mut tokio::sync::mpsc::Receiver<super::AccountWorkerCommand>,
    pending: &mut std::collections::VecDeque<super::AccountWorkerCommand>,
    control: &PublicationControl,
    shared: &super::RuntimeSharedServices,
    app: &crate::MarmotApp,
    account_label: &str,
) {
    publish_operation(
        client,
        Publication::Scoped { scope, kind },
        respond,
        commands,
        pending,
        control,
        shared,
        app,
        account_label,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_endorsement(
    client: &mut crate::client::AppClient,
    binding: [u8; 32],
    respond: Option<
        tokio::sync::oneshot::Sender<Result<(), crate::client::device_linking::ClientLinkingError>>,
    >,
    commands: &mut tokio::sync::mpsc::Receiver<super::AccountWorkerCommand>,
    pending: &mut std::collections::VecDeque<super::AccountWorkerCommand>,
    control: &PublicationControl,
    shared: &super::RuntimeSharedServices,
    app: &crate::MarmotApp,
    account_label: &str,
) {
    publish_operation(
        client,
        Publication::Endorsement(binding),
        respond,
        commands,
        pending,
        control,
        shared,
        app,
        account_label,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_existing_settlement(
    client: &mut crate::client::AppClient,
    binding: [u8; 32],
    respond: Option<
        tokio::sync::oneshot::Sender<Result<(), crate::client::device_linking::ClientLinkingError>>,
    >,
    commands: &mut tokio::sync::mpsc::Receiver<super::AccountWorkerCommand>,
    pending: &mut std::collections::VecDeque<super::AccountWorkerCommand>,
    control: &PublicationControl,
    shared: &super::RuntimeSharedServices,
    app: &crate::MarmotApp,
    account_label: &str,
) {
    publish_operation(
        client,
        Publication::ExistingSettlement(binding),
        respond,
        commands,
        pending,
        control,
        shared,
        app,
        account_label,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_revoked_settlement(
    client: &mut crate::client::AppClient,
    binding: [u8; 32],
    respond: Option<
        tokio::sync::oneshot::Sender<Result<(), crate::client::device_linking::ClientLinkingError>>,
    >,
    commands: &mut tokio::sync::mpsc::Receiver<super::AccountWorkerCommand>,
    pending: &mut std::collections::VecDeque<super::AccountWorkerCommand>,
    control: &PublicationControl,
    shared: &super::RuntimeSharedServices,
    app: &crate::MarmotApp,
    account_label: &str,
) {
    publish_operation(
        client,
        Publication::RevokedSettlement(binding),
        respond,
        commands,
        pending,
        control,
        shared,
        app,
        account_label,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn publish_operation(
    client: &mut crate::client::AppClient,
    operation: Publication,
    mut respond: Option<
        tokio::sync::oneshot::Sender<Result<(), crate::client::device_linking::ClientLinkingError>>,
    >,
    commands: &mut tokio::sync::mpsc::Receiver<super::AccountWorkerCommand>,
    pending: &mut std::collections::VecDeque<super::AccountWorkerCommand>,
    control: &PublicationControl,
    shared: &super::RuntimeSharedServices,
    app: &crate::MarmotApp,
    account_label: &str,
) {
    use crate::client::device_linking::ClientLinkingError;
    use cgka_traits::device_linking_key_package::LinkingWelcomeDenied;
    let owned_control = operation.owned_control(client);
    let (deadline, gate) = match owned_control {
        Ok(value) => value,
        Err(error) => {
            if let Some(respond) = respond {
                let _ = respond.send(Err(error));
            }
            return;
        }
    };
    let identity = operation.identity();
    control.install_gate(identity.clone(), gate);
    let snapshot = client.group_read_snapshot().ok();
    let mut deferred = std::collections::VecDeque::new();
    // Examine already-queued controls before the dispatch future's first poll.
    for _ in 0..DEFERRED_LIMIT {
        let command = pending.pop_front().or_else(|| commands.try_recv().ok());
        let Some(command) = command else {
            break;
        };
        observe_revocation(control, &command);
        if let Some(command) = snapshot_read(command, snapshot.as_ref(), app, account_label) {
            deferred.push_back(command);
        }
    }
    let mut shutdown = shared.lifecycle().subscribe_shutdown();
    let mut work = Box::pin(operation.dispatch(client));
    let (result, interrupted) = loop {
        let notified = control.wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if control.revoked() {
            break (
                Err(ClientLinkingError::Gate(LinkingWelcomeDenied::Cancelled)),
                true,
            );
        }
        tokio::select! {
            biased;
            _ = super::wait_for_runtime_shutdown(&mut shutdown) => {
                control.revoke_identity(&identity);
                break (Err(ClientLinkingError::Gate(LinkingWelcomeDenied::Cancelled)), true);
            }
            _ = async {
                match respond.as_mut() {
                    Some(respond) => respond.closed().await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                control.revoke_identity(&identity);
                break (Err(ClientLinkingError::Gate(LinkingWelcomeDenied::Cancelled)), true);
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                control.revoke_identity(&identity);
                break (Err(ClientLinkingError::Gate(LinkingWelcomeDenied::Expired)), true);
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(25)), if matches!(operation, Publication::RevokedSettlement(_)) => continue,
            _ = &mut notified => continue,
            result = &mut work => break (result, false),
            command = commands.recv(), if pending.is_empty() && deferred.len() < DEFERRED_LIMIT => {
                if let Some(command) = command {
                    observe_revocation(control, &command);
                    if let Some(command) = snapshot_read(command, snapshot.as_ref(), app, account_label) {
                        deferred.push_back(command);
                    }
                } else {
                    control.revoke_identity(&identity);
                    break (Err(ClientLinkingError::Gate(LinkingWelcomeDenied::Cancelled)), true);
                }
            }
        }
    };
    // Release exclusive client borrow before exact durable negative cleanup.
    drop(work);
    let result = if interrupted {
        operation.interrupt(client).await.and(result)
    } else {
        result
    };
    control.clear();
    // Commands removed from pending precede commands that were still queued.
    deferred.append(pending);
    *pending = deferred;
    if let Some(respond) = respond
        && respond.send(result).is_err()
        && operation.owned_control(client).is_ok()
        && operation.interrupt(client).await.is_err()
    {
        tracing::debug!(target: "marmot_app::device_linking", method = "worker_abandoned_private_dispatch", "device linking cleanup deferred");
    }
}

#[cfg(test)]
mod negative_cancel_tests {
    use super::*;
    fn scope(generation: u64) -> PurposeAttemptScope {
        PurposeAttemptScope {
            account: [1; 32],
            local_device: [2; 32],
            generation,
        }
    }
    // These exercise only negative slot custody, never SDK consent or enrollment.
    #[test]
    fn first_revocation_is_not_renewed_by_repeats() {
        let control = PublicationControl::default();
        let gate = Arc::new(RuntimeInviteGate::new());
        let original = scope(1);
        control.install(original.clone(), gate.clone());
        control.revoke(&original);
        assert!(control.has_negative_invite(&original, &gate));
        let after_first = gate.cancellation_fence();
        control.revoke(&original);
        assert!(after_first.revision_matches_for_negative_completion());
        assert!(control.has_negative_invite(&original, &gate));
    }
    #[test]
    fn foreign_gate_and_later_revision_cannot_acknowledge() {
        let control = PublicationControl::default();
        let gate = Arc::new(RuntimeInviteGate::new());
        let foreign = Arc::new(RuntimeInviteGate::new());
        let original = scope(1);
        control.install(original.clone(), gate.clone());
        control.revoke(&original);
        assert!(!control.has_negative_invite(&original, &foreign));
        assert!(!control.has_negative_invite(&scope(2), &gate));
        assert!(control.has_negative_invite(&original, &gate));
        // Actual gate invalidation used by a new reservation; the separate real
        // Runtime test exercises reservation followed by terminal completion.
        gate.cancel();
        let next_revision = gate.cancellation_fence();
        control.revoke(&original);
        assert!(next_revision.revision_matches_for_negative_completion());
        assert!(!control.has_negative_invite(&original, &gate));
    }
    #[test]
    fn shutdown_and_inherited_install_cannot_refresh_witness() {
        let control = PublicationControl::default();
        let gate = Arc::new(RuntimeInviteGate::new());
        let original = scope(1);
        control.install(original.clone(), gate.clone());
        control.revoke(&original);
        control.install(original.clone(), gate.clone());
        control.revoke(&original);
        assert!(!control.has_negative_invite(&original, &gate));
        let control = PublicationControl::default();
        control.install(original.clone(), gate.clone());
        control.revoke(&original);
        control.shutdown();
        assert!(!control.has_negative_invite(&original, &gate));
    }
    #[test]
    fn exact_current_slot_is_consumed_only_once() {
        let control = PublicationControl::default();
        let gate = Arc::new(RuntimeInviteGate::new());
        let original = scope(1);
        control.install(original.clone(), gate.clone());
        control.revoke(&original);
        assert!(!control.consume_negative_invite(&scope(2), &gate));
        assert!(control.has_negative_invite(&original, &gate));
        assert!(control.consume_negative_invite(&original, &gate));
        assert!(!control.consume_negative_invite(&original, &gate));
    }
}

#[cfg(test)]
mod late_revoke_tests {
    use super::*;
    #[test]
    fn first_stale_revoke_cannot_cancel_a_later_gate_revision_or_create_ack_witness() {
        let control = PublicationControl::default();
        let gate = Arc::new(RuntimeInviteGate::new());
        let old = PurposeAttemptScope { account: [1; 32], local_device: [2; 32], generation: 1 };
        control.install(old.clone(), gate.clone());
        // This is only negative custody, not SDK/native enrollment evidence.
        // The separate actual Runtime case performs new reservation+terminal.
        gate.cancel();
        let later_revision = gate.cancellation_fence();
        control.revoke(&old); // FIRST old-slot revoke, after the revision advanced.
        let revision_unchanged = later_revision.revision_matches_for_negative_completion();
        let no_ack_witness = !control.has_negative_invite(&old, &gate);
        assert!(revision_unchanged && no_ack_witness,
            "a first stale control must neither cancel the later revision nor mint an acknowledgement witness");
    }
}
