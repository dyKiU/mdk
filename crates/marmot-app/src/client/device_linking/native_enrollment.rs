//! Ephemeral native intent follows the original SDK continuation only.
use super::{AppClient, ClientLinkingError};
use cgka_traits::private_device_invite::PrivateInvitePhase;
use cgka_traits::{
    StorageProvider,
    device_linking_key_package::{LinkingWelcomeDenied, PurposeAttemptScope},
};
use std::time::{Duration, Instant};

pub(super) struct NativeEnrollmentIntent {
    scope: PurposeAttemptScope,
    recipient: bool,
    welcomes_published: bool,
    retry_at: Instant,
}

pub(crate) enum NativeInvitePublication {
    Commit,
    Welcomes,
}

impl AppClient {
    pub(crate) async fn continue_owned_native_linking(
        &mut self,
        scope: &PurposeAttemptScope,
        new_device: bool,
    ) -> Result<(), ClientLinkingError> {
        if let Some(intent) = &self.linking_owner.native_enrollment {
            if intent.scope != *scope || intent.recipient != new_device {
                return Err(ClientLinkingError::Gate(
                    LinkingWelcomeDenied::ContextMismatch,
                ));
            }
            // An operation marker cannot authorize a replay. Retain exactly
            // the live SDK-derived settlement continuation on both roles.
            if !self
                .linking_owner
                .settlement_attempt
                .as_ref()
                .is_some_and(|a| a.guard.scope() == scope && a.guard.is_live())
            {
                return Err(ClientLinkingError::Gate(
                    LinkingWelcomeDenied::NoLiveVerifier,
                ));
            }
            return Ok(());
        }
        // These existing paths independently validate the actual SDK role and
        // original purpose before taking its non-clone proof.
        if new_device {
            self.arm_singleton_device_welcome(scope).await?;
        } else {
            self.prepare_private_device_invite(scope).await?;
        }
        self.linking_owner.native_enrollment = Some(NativeEnrollmentIntent {
            scope: scope.clone(),
            recipient: new_device,
            welcomes_published: false,
            retry_at: Instant::now(),
        });
        Ok(())
    }

    pub(super) fn prune_native_enrollment_intent(&mut self) {
        if self
            .linking_owner
            .native_enrollment
            .as_ref()
            .is_some_and(|intent| {
                !self
                    .linking_owner
                    .settlement_attempt
                    .as_ref()
                    .is_some_and(|attempt| {
                        attempt.guard.scope() == &intent.scope && attempt.guard.is_live()
                    })
            })
        {
            self.linking_owner.native_enrollment = None;
        }
    }

    pub(crate) fn pending_native_private_publication(
        &mut self,
    ) -> Result<Option<(PurposeAttemptScope, NativeInvitePublication)>, ClientLinkingError> {
        let Some(intent) = &self.linking_owner.native_enrollment else {
            return Ok(None);
        };
        if intent.recipient || intent.welcomes_published || Instant::now() < intent.retry_at {
            return Ok(None);
        }
        let scope = intent.scope.clone();
        self.private_commit_control(&scope)?;
        let attempt =
            self.linking_owner
                .invite_attempt
                .as_mut()
                .ok_or(ClientLinkingError::Gate(
                    LinkingWelcomeDenied::NoLiveVerifier,
                ))?;
        let prepared = attempt.prepared.as_mut().ok_or(ClientLinkingError::Gate(
            LinkingWelcomeDenied::NoLiveVerifier,
        ))?;
        prepared
            .check_live_permission()
            .map_err(ClientLinkingError::Gate)?;
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|e| ClientLinkingError::Runtime(Box::new(e)))?;
        let phase = storage
            .private_device_invite_storage()
            .ok_or(ClientLinkingError::Gate(
                LinkingWelcomeDenied::UnsupportedStorage,
            ))?
            .private_invite()
            .map_err(|e| ClientLinkingError::PrivateInvite(e.into()))?
            .filter(|row| row.scope == *prepared.scope())
            .map(|row| row.phase);
        let kind = match phase {
            Some(PrivateInvitePhase::Wrapped) => NativeInvitePublication::Commit,
            // Only actual authenticated echo installs Confirmed. Reading this
            // phase chooses scheduling; dispatch still requires original lease.
            Some(PrivateInvitePhase::Confirmed) => NativeInvitePublication::Welcomes,
            _ => return Ok(None),
        };
        self.linking_owner
            .native_enrollment
            .as_mut()
            .unwrap()
            .retry_at = Instant::now() + Duration::from_secs(1);
        Ok(Some((scope, kind)))
    }

    pub(super) fn native_welcomes_published(&mut self, scope: &PurposeAttemptScope) {
        if let Some(intent) = self
            .linking_owner
            .native_enrollment
            .as_mut()
            .filter(|i| i.scope == *scope)
        {
            intent.welcomes_published = true;
        }
    }
}
