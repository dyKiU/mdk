//! Original SDK lease custody across Add staging and exact raw retry.
use super::{OwnedLocalEnrollmentProposal, unavailable};
use crate::private_device_invite::{
    AuthenticatedPrivateInvite, PreparedPrivateDeviceInvite, PrivateInviteConsent,
    PrivateInviteError, TrustedPrivateInvitePolicy,
};
use crate::private_enrollment_endorsement::{AuthenticatedEnrollmentEndorsement, Lifetime};
use crate::private_enrollment_predecessor::AuthenticatedPrivatePredecessor;
use crate::{Engine, device_group_snapshot::CandidateDeviceGroupSnapshot};
use base64::Engine as _;
use cgka_traits::GroupId;
use cgka_traits::device_linking_key_package::LinkingWelcomeDenied;
use cgka_traits::private_device_invite::{
    PrivateInviteFact, PrivateInvitePhase, PrivateInviteScope,
};
use cgka_traits::private_roster_settlement::PrivateSettlementAnchor;
use cgka_traits::storage::StorageProvider;
use openmls::group::MlsGroup;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Weak};
use web_time::Instant;

/// No constructor, Clone or serialization. These attestations are metadata;
/// the preparation helper separately borrows the same original SDK lease.
pub(crate) struct OriginalEnrollmentPreparation {
    owner: Weak<Lifetime>,
    policy: Arc<dyn TrustedPrivateInvitePolicy>,
    deadline: Instant,
    predecessor: CandidateDeviceGroupSnapshot,
    anchor: PrivateSettlementAnchor,
    generation: u64,
    consent: PrivateInviteConsent,
    package_digest: [u8; 32],
    binding: [u8; 32],
    artifact: AuthenticatedPrivatePredecessor,
    packets: Vec<(Vec<u8>, Instant)>,
    staged: Option<(PrivateInviteScope, [u8; 32], [u8; 32])>,
}
impl OriginalEnrollmentPreparation {
    pub(crate) fn deadline(&self) -> Instant {
        self.packets
            .iter()
            .fold(self.deadline, |deadline, (_, observed)| {
                deadline.min(*observed)
            })
    }
    pub(crate) fn check_clock(&self) -> Result<(), LinkingWelcomeDenied> {
        if !self.owner.upgrade().is_some_and(|owner| owner.is_open()) {
            return Err(LinkingWelcomeDenied::Cancelled);
        }
        if Instant::now() >= self.deadline() {
            return Err(LinkingWelcomeDenied::Expired);
        }
        Ok(())
    }
    pub(crate) fn check_owner<S: StorageProvider>(
        &self,
        engine: &Engine<S>,
    ) -> Result<(), LinkingWelcomeDenied> {
        self.check_clock()?;
        if !engine.enrollment_endorsements.owns_lifetime(&self.owner)
            || !engine
                .private_invite_policy
                .as_ref()
                .is_some_and(|policy| Arc::ptr_eq(policy, &self.policy))
        {
            return Err(LinkingWelcomeDenied::Cancelled);
        }
        Ok(())
    }
    pub(crate) fn validate<S: StorageProvider>(
        &self,
        engine: &Engine<S>,
        storage: &S,
        group: &MlsGroup,
        input: &AuthenticatedPrivateInvite,
        issued: Option<&PrivateInviteFact>,
    ) -> Result<(), PrivateInviteError> {
        if !engine.enrollment_endorsements.owns_lifetime(&self.owner)
            || !self.owner.upgrade().is_some_and(|owner| owner.is_open())
            || !engine
                .private_invite_policy
                .as_ref()
                .is_some_and(|policy| Arc::ptr_eq(policy, &self.policy))
        {
            return Err(LinkingWelcomeDenied::Cancelled.into());
        }
        if Instant::now() >= self.deadline
            || self
                .packets
                .iter()
                .any(|(_, deadline)| Instant::now() >= *deadline)
        {
            return Err(LinkingWelcomeDenied::Expired.into());
        }
        if input.predecessor != self.predecessor
            || Sha256::digest(input.exact_key_package.bytes()).as_slice() != self.package_digest
        {
            return Err(LinkingWelcomeDenied::ContextMismatch.into());
        }
        if group.pending_commit().is_some() {
            let fact = storage
                .private_device_invite_storage()
                .ok_or(LinkingWelcomeDenied::UnsupportedStorage)?
                .private_invite()?
                .ok_or(LinkingWelcomeDenied::ContextMismatch)?;
            if !matches!(
                fact.phase,
                PrivateInvitePhase::RawStaged
                    | PrivateInvitePhase::Wrapped
                    | PrivateInvitePhase::Dispatching
                    | PrivateInvitePhase::PublicationUnknown
            ) {
                return Err(LinkingWelcomeDenied::ContextMismatch.into());
            }
            if let Some((scope, commit, welcome)) = &self.staged {
                if fact.scope != *scope
                    || fact.raw.binding.commit_digest != *commit
                    || fact.raw.binding.welcome_digest != *welcome
                {
                    return Err(LinkingWelcomeDenied::ContextMismatch.into());
                }
            } else if !issued
                .is_some_and(|issued| issued.scope == fact.scope && issued.raw == fact.raw)
            {
                return Err(LinkingWelcomeDenied::ContextMismatch.into());
            }
            let binding = &fact.raw.binding;
            if binding.approver_scope != self.consent.approver_scope
                || binding.recipient_generation != self.consent.recipient_generation
                || binding.origin != self.consent.origin
                || binding.nonce != self.consent.nonce
                || binding.context_digest != self.consent.context_digest
                || binding.group_id != self.predecessor.group_id
                || binding.key_package_digest != self.package_digest
                || binding.key_package_reference != input.key_package_reference
                || binding.recipient != input.recipient_signature_public_key
                || binding.predecessor != self.anchor.successor
                || Sha256::digest(&fact.raw.commit).as_slice() != binding.commit_digest
                || Sha256::digest(&fact.raw.welcome).as_slice() != binding.welcome_digest
            {
                return Err(LinkingWelcomeDenied::ContextMismatch.into());
            }
            let actual = engine.validate_private_staged_add(
                group,
                group.pending_commit().unwrap(),
                input,
            )?;
            if actual.successor != binding.successor {
                return Err(LinkingWelcomeDenied::ContextMismatch.into());
            }
        } else if self.staged.is_some() || issued.is_some() {
            return Err(LinkingWelcomeDenied::ContextMismatch.into());
        }
        let state = crate::private_roster_settlement::completed_round_for_predecessor_tree(
            storage,
            &self.predecessor.group_id,
            group,
        )?
        .ok_or(LinkingWelcomeDenied::ContextMismatch)?;
        if state.generation != self.generation || state.anchor != self.anchor {
            return Err(LinkingWelcomeDenied::ContextMismatch.into());
        }
        let packets = self
            .packets
            .iter()
            .map(|(wire, _)| wire.as_slice())
            .collect::<Vec<_>>();
        engine.authenticate_all_private_enrollment_endorsements(
            &self.artifact,
            &self.binding,
            &packets,
        )?;
        Ok(())
    }
    pub(crate) fn record_staged(
        &mut self,
        fact: &PrivateInviteFact,
    ) -> Result<(), PrivateInviteError> {
        let issued = (
            fact.scope.clone(),
            fact.raw.binding.commit_digest,
            fact.raw.binding.welcome_digest,
        );
        if self
            .staged
            .as_ref()
            .is_some_and(|original| original != &issued)
        {
            return Err(LinkingWelcomeDenied::ContextMismatch.into());
        }
        self.staged = Some(issued);
        Ok(())
    }
}

impl<S: StorageProvider> Engine<S> {
    /// Scope/permission inputs come only from the original SDK producer and
    /// actual sealed receipts. Never reacquire its held policy mutex.
    pub async fn prepare_private_invite_from_owned_enrollment_proposal(
        &mut self,
        proposal: &mut OwnedLocalEnrollmentProposal,
        receipts: &[&AuthenticatedEnrollmentEndorsement],
    ) -> Result<PreparedPrivateDeviceInvite, PrivateInviteError> {
        if proposal.handoff.is_none() {
            self.authenticate_owned_local_enrollment_endorsements(proposal, receipts)?;
            let group = &proposal.predecessor.group_id;
            let state = self
                .with_mls_group(group, |actual| {
                    crate::private_roster_settlement::completed_round_for_tree(
                        &self.storage,
                        group,
                        actual,
                    )
                })?
                .ok_or_else(unavailable)?;
            let encoded = &proposal
                .frame
                .proposal
                .as_ref()
                .ok_or_else(unavailable)?
                .artifact_base64;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| unavailable())?;
            let artifact = self.validate_private_device_predecessor(
                &bytes,
                &proposal.predecessor.account,
                group,
                proposal.predecessor.epoch,
                &proposal.predecessor.leaves,
            )?;
            let mut packets = vec![(
                proposal
                    .own_endorsement
                    .as_ref()
                    .ok_or_else(unavailable)?
                    .clone(),
                proposal.deadline,
            )];
            packets.extend(
                receipts
                    .iter()
                    .map(|receipt| (receipt.wire.clone(), receipt.deadline)),
            );
            let consent = proposal
                .lease
                .as_ref()
                .ok_or_else(unavailable)?
                .consent()
                .clone();
            self.check_local_enrollment_proposal(proposal)?;
            if state.generation != proposal.selection_generation
                || state.anchor.origin != consent.origin
                || artifact.artifact_digest() != &proposal.frame.artifact_digest
            {
                return Err(unavailable().into());
            }
            proposal.handoff = Some(OriginalEnrollmentPreparation {
                owner: proposal.owner.clone(),
                policy: proposal.policy.clone(),
                deadline: proposal.deadline,
                predecessor: proposal.predecessor.clone(),
                anchor: state.anchor,
                generation: state.generation,
                consent,
                package_digest: Sha256::digest(proposal.package.bytes()).into(),
                binding: super::super::request_binding_digest(&proposal.frame)?,
                artifact,
                packets,
                staged: None,
            });
        }
        proposal.check_live()?;
        let group: GroupId = proposal.predecessor.group_id.clone();
        let package = proposal.package.clone();
        let (retry, input) = self.private_invite_preparation_inputs(&group, &package)?;
        let mut prepared = self
            .prepare_private_device_invite_with_owned_lease(
                &group,
                input,
                retry,
                &mut proposal.lease,
                proposal.handoff.as_mut(),
            )
            .await?;
        prepared.retain_original_enrollment(proposal.handoff.take().ok_or_else(unavailable)?);
        Ok(prepared)
    }
}
