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
    existing: bool,
    proposal_published: bool,
    welcomes_published: bool,
    retry_at: Instant,
}

pub(crate) enum NativeInvitePublication {
    Proposal,
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
            if intent.recipient && intent.existing {
                let scope = scope.clone();
                if self.scoped_linking_verifier(&scope).is_ok_and(|v| {
                    v.validate_endorsed_recipient(&scope, Instant::now())
                        .is_ok()
                }) {
                    return Ok(());
                }
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
        let existing = self
            .scoped_linking_verifier(scope)?
            .native_context_version(scope, Instant::now())
            .map_err(ClientLinkingError::Owner)?
            == 2;
        if new_device {
            if existing {
                // Preserve the original verified SDK and exact purpose until
                // complete all-leaf packet admission. No token is taken here.
                self.scoped_linking_verifier(scope)?
                    .validate_endorsed_recipient(scope, Instant::now())
                    .map_err(ClientLinkingError::Owner)?;
            } else {
                self.arm_singleton_device_welcome(scope).await?;
            }
        } else if existing {
            self.prepare_owned_enrollment_proposal(scope).await?;
        } else {
            self.prepare_private_device_invite(scope).await?;
        }
        self.linking_owner.native_enrollment = Some(NativeEnrollmentIntent {
            scope: scope.clone(),
            recipient: new_device,
            existing,
            proposal_published: false,
            welcomes_published: false,
            retry_at: Instant::now(),
        });
        Ok(())
    }

    pub(super) fn prune_native_enrollment_intent(&mut self) {
        let Some(intent) = self.linking_owner.native_enrollment.as_ref() else {
            return;
        };
        let scope = intent.scope.clone();
        let waiting = intent.existing && intent.recipient;
        let retained = self
            .linking_owner
            .settlement_attempt
            .as_ref()
            .is_some_and(|a| a.guard.scope() == &scope && a.guard.is_live());
        let original_waiting = waiting
            && self.scoped_linking_verifier(&scope).is_ok_and(|v| {
                v.validate_endorsed_recipient(&scope, Instant::now())
                    .is_ok()
            });
        if !retained && !original_waiting {
            self.linking_owner.native_enrollment = None;
        }
    }

    pub(crate) async fn native_receive_enrollment_packet(
        &mut self,
        scope: &PurposeAttemptScope,
        packet: &[u8],
    ) -> Result<(), ClientLinkingError> {
        if !self
            .linking_owner
            .native_enrollment
            .as_ref()
            .is_some_and(|i| i.scope == *scope && i.recipient && i.existing)
        {
            return Err(ClientLinkingError::Gate(
                LinkingWelcomeDenied::ContextMismatch,
            ));
        }
        self.arm_endorsed_enrollment_recipient(scope, packet).await
    }

    pub(crate) async fn native_finalize_enrollment(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<(), ClientLinkingError> {
        if !self
            .linking_owner
            .native_enrollment
            .as_ref()
            .is_some_and(|i| i.scope == *scope && !i.recipient && i.existing)
        {
            return Err(ClientLinkingError::Gate(
                LinkingWelcomeDenied::ContextMismatch,
            ));
        }
        self.prepare_owned_endorsed_enrollment_invite(scope).await?;
        Ok(())
    }
    pub(super) fn native_proposal_published(&mut self, scope: &PurposeAttemptScope) {
        if let Some(i) = self
            .linking_owner
            .native_enrollment
            .as_mut()
            .filter(|i| i.scope == *scope)
        {
            i.proposal_published = true;
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
        if intent.existing
            && self
                .linking_owner
                .invite_attempt
                .as_ref()
                .is_some_and(|a| a.prepared.is_none())
        {
            if intent.proposal_published {
                return Ok(None);
            }
            self.enrollment_proposal_control(&scope)?;
            self.linking_owner
                .native_enrollment
                .as_mut()
                .unwrap()
                .retry_at = Instant::now() + Duration::from_secs(1);
            return Ok(Some((scope, NativeInvitePublication::Proposal)));
        }
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

impl AppClient {
    pub(crate) fn native_device_linking_targets(
        &self,
    ) -> Result<Vec<crate::DeviceLinkingTarget>, ClientLinkingError> {
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|e| ClientLinkingError::Runtime(Box::new(e)))?;
        let Some(round) = storage
            .private_roster_settlement_storage()
            .ok_or(ClientLinkingError::Gate(
                LinkingWelcomeDenied::UnsupportedStorage,
            ))?
            .read_round()
            .map_err(|e| ClientLinkingError::Engine(e.into()))?
        else {
            return Ok(Vec::new());
        };
        let Some(roster) = self
            .runtime
            .session()
            .validated_settled_device_roster(&round.anchor.group_id)
            .map_err(ClientLinkingError::Engine)?
        else {
            return Ok(Vec::new());
        };
        Ok(vec![crate::DeviceLinkingTarget {
            selector: round.anchor.group_id.as_slice().to_vec(),
            device_count: roster.candidate().leaves.len() as u32,
        }])
    }
}
