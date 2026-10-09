//! Actor-owned private commit publication; the shared control can only revoke.
use crate::device_linking::invite_gate::RuntimeInviteGate;
use cgka_traits::device_linking_key_package::PurposeAttemptScope;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

enum PublicationGate {
    Invite(Arc<RuntimeInviteGate>),
    Settlement(Arc<crate::device_linking::settlement::SettlementGuard>),
}
impl PublicationGate {
    fn cancel(&self) {
        match self {
            Self::Invite(gate) => gate.cancel(),
            Self::Settlement(guard) => guard.revoke(),
        }
    }
}

struct ActiveControl {
    scope: PurposeAttemptScope,
    gate: PublicationGate,
    revoked: bool,
}

/// One bounded negative slot, never a consent or transport inlet. Only the
/// account actor installs an already-owned exact attempt; callers may revoke it.
#[derive(Default)]
pub(super) struct PublicationControl {
    active: Mutex<Option<ActiveControl>>,
    shutdown: AtomicBool,
    wake: Notify,
}
impl PublicationControl {
    pub(super) fn install(&self, scope: PurposeAttemptScope, gate: Arc<RuntimeInviteGate>) {
        self.install_gate(scope, PublicationGate::Invite(gate));
    }
    fn install_gate(&self, scope: PurposeAttemptScope, gate: PublicationGate) {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let revoked = self.shutdown.load(Ordering::Acquire)
            || active
                .as_ref()
                .is_some_and(|active| active.scope == scope && active.revoked);
        if revoked {
            gate.cancel();
        }
        *active = Some(ActiveControl {
            scope,
            gate,
            revoked,
        });
    }
    pub(super) fn revoke(&self, scope: &PurposeAttemptScope) {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(active) = active.as_mut().filter(|active| active.scope == *scope) {
            active.revoked = true;
            active.gate.cancel();
            self.wake.notify_one();
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
                .is_some_and(|active| active.revoked)
    }
    fn clear(&self) {
        *self.active.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
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
const DEFERRED_LIMIT: usize = 8;
/// The Engine borrow and original nonclone lease stay on this account actor.
/// Bounded deferral backpressures the ordinary queue; revocation bypasses it.
#[allow(clippy::too_many_arguments)]
pub(super) async fn publish(
    client: &mut crate::client::AppClient,
    scope: PurposeAttemptScope,
    kind: PublicationKind,
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
    let owned_control = match kind {
        PublicationKind::Proposal => client
            .enrollment_proposal_control(&scope)
            .map(|(deadline, gate)| (deadline, PublicationGate::Invite(gate))),
        PublicationKind::Settlement => client
            .private_settlement_control(&scope)
            .map(|guard| (guard.deadline(), PublicationGate::Settlement(guard))),
        PublicationKind::Commit | PublicationKind::Welcomes => client
            .private_commit_control(&scope)
            .map(|(deadline, gate)| (deadline, PublicationGate::Invite(gate))),
    };
    let (deadline, gate) = match owned_control {
        Ok(value) => value,
        Err(error) => {
            if let Some(respond) = respond {
                let _ = respond.send(Err(error));
            }
            return;
        }
    };
    control.install_gate(scope.clone(), gate);
    let snapshot = client.group_read_snapshot().ok();
    let mut deferred = std::collections::VecDeque::new();
    // Examine already-queued controls before the dispatch future's first poll.
    for _ in 0..DEFERRED_LIMIT {
        let command = pending.pop_front().or_else(|| commands.try_recv().ok());
        let Some(command) = command else {
            break;
        };
        if let super::AccountWorkerCommand::CancelDeviceLinking { scope: queued, .. } = &command {
            control.revoke(queued);
        }
        if let Some(command) = snapshot_read(command, snapshot.as_ref(), app, account_label) {
            deferred.push_back(command);
        }
    }
    let mut shutdown = shared.lifecycle().subscribe_shutdown();
    let mut work = Box::pin(async {
        match kind {
            PublicationKind::Proposal => client.dispatch_owned_enrollment_proposal(&scope).await,
            PublicationKind::Commit => client.dispatch_owned_private_commit(&scope).await,
            PublicationKind::Welcomes => client.dispatch_owned_private_welcomes(&scope).await,
            PublicationKind::Settlement => client.dispatch_owned_private_settlement(&scope).await,
        }
    });
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
                control.revoke(&scope);
                break (Err(ClientLinkingError::Gate(LinkingWelcomeDenied::Cancelled)), true);
            }
            _ = async {
                match respond.as_mut() {
                    Some(respond) => respond.closed().await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                control.revoke(&scope);
                break (Err(ClientLinkingError::Gate(LinkingWelcomeDenied::Cancelled)), true);
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                control.revoke(&scope);
                break (Err(ClientLinkingError::Gate(LinkingWelcomeDenied::Expired)), true);
            }
            _ = &mut notified => continue,
            result = &mut work => break (result, false),
            command = commands.recv(), if pending.is_empty() && deferred.len() < DEFERRED_LIMIT => {
                if let Some(command) = command {
                    if let super::AccountWorkerCommand::CancelDeviceLinking { scope: queued, .. } = &command {
                        control.revoke(queued);
                    }
                    if let Some(command) = snapshot_read(command, snapshot.as_ref(), app, account_label) {
                        deferred.push_back(command);
                    }
                } else {
                    control.revoke(&scope);
                    break (Err(ClientLinkingError::Gate(LinkingWelcomeDenied::Cancelled)), true);
                }
            }
        }
    };
    // Release exclusive client borrow before exact durable negative cleanup.
    drop(work);
    let result = if interrupted {
        match kind {
            PublicationKind::Proposal => {
                client.cancel_device_linking_scope(&scope).await.and(result)
            }
            PublicationKind::Settlement => client.revoke_owned_private_settlement().and(result),
            PublicationKind::Commit | PublicationKind::Welcomes => client
                .finish_private_commit_interruption(&scope)
                .and(result),
        }
    } else {
        result
    };
    control.clear();
    // Commands removed from pending precede commands that were still queued.
    deferred.append(pending);
    *pending = deferred;
    if let Some(respond) = respond
        && respond.send(result).is_err()
        && (client.private_commit_control(&scope).is_ok()
            || client.enrollment_proposal_control(&scope).is_ok())
    {
        // A reply can close just after a pre-intent error completed. Revoke that
        // still-owned preparation too, while retaining it if cleanup SQL fails.
        let cleanup = match kind {
            PublicationKind::Proposal => client.cancel_device_linking_scope(&scope).await,
            _ => client.finish_private_commit_interruption(&scope),
        };
        if cleanup.is_err() {
            tracing::debug!(target: "marmot_app::device_linking", method = "worker_abandoned_private_dispatch", "device linking cleanup deferred");
        }
    }
}
