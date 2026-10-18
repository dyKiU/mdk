//! Ephemeral transport correlation on genuine MLS observations, never consent.
use super::*;

fn rejected() -> ClientLinkingError {
    ClientLinkingError::Owner(OwnerError::Verifier(
        crate::device_linking::LinkError::InvalidContext,
    ))
}
fn validate(tags: &[Vec<String>]) -> Result<(), ClientLinkingError> {
    crate::device_linking::network::PeerHint::from_tags(
        tags,
        ::nostr::prelude::Timestamp::now().as_secs(),
    )
    .map_err(|_| rejected())?
    .ok_or_else(rejected)?;
    Ok(())
}
impl AppClient {
    pub(crate) fn prepare_pairing_metadata(
        &mut self,
        scope: &PurposeAttemptScope,
        tags: Vec<Vec<String>>,
    ) -> Result<(), ClientLinkingError> {
        self.check_private_invite_attempt_scope(scope)?;
        validate(&tags)?;
        if let Some((owner, prior)) = &self.linking_owner.pairing_metadata
            && owner == scope
        {
            return if prior == &tags {
                Ok(())
            } else {
                Err(rejected())
            };
        }
        // No action is reconstructed: the existing continue command still
        // consumes its actual verified original and explicit choice.
        self.linking_owner.pairing_metadata = Some((scope.clone(), tags));
        Ok(())
    }
    pub(crate) fn approval_pairing_metadata(
        &mut self,
        binding: &[u8; 32],
        attach: Option<Vec<Vec<String>>>,
    ) -> Result<Vec<Vec<String>>, ClientLinkingError> {
        let request = self
            .linking_owner
            .received_enrollment_proposals
            .iter()
            .find(|request| request.binding_digest().ok().as_ref() == Some(binding))
            .ok_or_else(rejected)?;
        self.authenticate_received_enrollment_proposal(request)?;
        let tags = request.metadata_tags().to_vec();
        if let Some(attach) = attach {
            validate(&attach)?;
            if let Some((owner, prior)) = &self.linking_owner.approval_pairing_metadata
                && owner == binding
                && prior != &attach
            {
                return Err(rejected());
            }
            // A later genuine observed request may replace routing metadata.
            // This slot grants no action; any already-owned endorsement retains
            // its immutable original tags and still checks its own binding.
            self.linking_owner.approval_pairing_metadata = Some((*binding, attach));
        }
        Ok(tags)
    }
    pub(crate) fn sibling_pairing_metadata(
        &mut self,
        scope: &PurposeAttemptScope,
    ) -> Result<Vec<Vec<Vec<String>>>, ClientLinkingError> {
        self.check_private_invite_attempt_scope(scope)?;
        let attempt = self
            .linking_owner
            .invite_attempt
            .as_mut()
            .ok_or_else(rejected)?;
        let proposal = attempt.proposal.as_mut().ok_or_else(rejected)?;
        attempt
            .endorsements
            .iter()
            .map(|receipt| {
                self.runtime
                    .session()
                    .authenticate_owned_local_enrollment_endorsement(proposal, receipt)
                    .map_err(ClientLinkingError::Engine)?
                    .ok_or_else(rejected)?;
                Ok(receipt.metadata_tags().to_vec())
            })
            .collect()
    }
}
