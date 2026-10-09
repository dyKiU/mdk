//! Separate original-purpose recipient admission; singleton bootstrap remains strict.
use super::*;
impl AppClient {
    pub(crate) async fn arm_endorsed_enrollment_recipient(
        &mut self,
        scope: &PurposeAttemptScope,
        packet: &[u8],
    ) -> Result<(), ClientLinkingError> {
        let context = self
            .linking_owner
            .verifier
            .validate_endorsed_recipient(scope, std::time::Instant::now())
            .map_err(ClientLinkingError::Owner)?;
        let evidence = self
            .runtime
            .session()
            .authenticate_original_recipient_enrollment_evidence(scope, packet)
            .map_err(ClientLinkingError::Engine)?;
        let original_json = serde_json::to_vec(&context).map_err(|_| {
            ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
            )
        })?;
        let artifact = evidence.predecessor();
        let invalid = || {
            ClientLinkingError::Gate(
                cgka_traits::device_linking_key_package::LinkingWelcomeDenied::ContextMismatch,
            )
        };
        if original_json != evidence.context_json().as_bytes()
            || context.digest().map_err(|_| invalid())? != *evidence.context_digest()
            || artifact.account().as_slice() != context.account
            || artifact.group_id().as_slice() != context.device_group
            || artifact.epoch().0 != context.predecessor.epoch
            || context.predecessor.artifact_digest != Some(*artifact.artifact_digest())
            || artifact.leaves().len() != context.predecessor.leaves.len()
            || !artifact
                .leaves()
                .iter()
                .zip(&context.predecessor.leaves)
                .all(|(a, b)| {
                    a.leaf_index == b.leaf_index && a.signature_public_key == b.signature_public_key
                })
        {
            return Err(invalid());
        }
        use sha2::{Digest, Sha256};
        let metadata = cgka_traits::peeler::PrivateLinkingWelcomeContext {
            account: context.account,
            approver: context.approver,
            recipient: context.recipient,
            approver_generation: context.approver_generation,
            recipient_generation: context.new_device_generation,
            group_id: cgka_traits::GroupId::new(context.device_group.clone()),
            nonce: context.nonce,
            context_digest: context.digest().map_err(|_| invalid())?,
            key_package_reference: context.key_package_reference,
            key_package_digest: Sha256::digest(&context.exact_key_package).into(),
            commit_digest: [0; 32],
            welcome_digest: [0; 32],
        };
        let predecessor = cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster {
            epoch: cgka_traits::EpochId(context.predecessor.epoch),
            epoch_authenticator_digest: context.predecessor.epoch_authenticator_digest,
            leaves: context
                .predecessor
                .leaves
                .iter()
                .map(|leaf| cgka_traits::device_group_genesis::GenesisLeaf {
                    account: context.account,
                    leaf_index: leaf.leaf_index,
                    signature_public_key: leaf.signature_public_key,
                })
                .collect(),
        };
        self.runtime
            .session()
            .validate_owned_recipient_evidence(&evidence, &metadata, &predecessor)
            .map_err(ClientLinkingError::Engine)?;
        // All negative metadata checks precede the one-shot original SDK release.
        let token = self.take_device_linking_verified(scope).await?;
        let guard = Arc::new(
            crate::device_linking::settlement::SettlementGuard::from_verified(
                &token,
                scope,
                self.linking_owner.welcome.cancellation_fence(),
            )
            .map_err(ClientLinkingError::Engine)?,
        );
        self.linking_owner
            .welcome
            .arm(token)
            .map_err(ClientLinkingError::Gate)?;
        self.linking_owner.recipient_enrollment = Some(evidence);
        self.linking_owner.settlement_attempt =
            Some(super::super::private_settlement::OwnedSettlementAttempt::new(guard));
        Ok(())
    }
}
