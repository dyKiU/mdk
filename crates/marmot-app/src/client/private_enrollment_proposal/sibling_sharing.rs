//! Existing-member channel initiation is derived only from the retained original.
use super::*;
use cgka_traits::StorageProvider;
impl AppClient {
    #[cfg(all(test, feature = "test-policy-overrides"))]
    pub(crate) fn arm_sibling_pre_auth_failure(
        &mut self,
        original: &std::sync::Arc<OriginalSiblingSharingApproval>,
    ) -> Result<
        std::sync::Arc<super::super::device_linking::sibling_sharing::SiblingPreAuthFailureProbe>,
        crate::AccountSharingError,
    > {
        let action = self
            .linking_owner
            .received_endorsement
            .as_ref()
            .ok_or(crate::AccountSharingError::NotReady)?;
        if action.cancelled
            || !original.state.live()
            || !action
                .sharing
                .as_ref()
                .is_some_and(|held| std::sync::Arc::ptr_eq(held, original))
            || self.linking_owner.sibling_pre_auth_probe.is_some()
        {
            return Err(crate::AccountSharingError::NotReady);
        }
        let probe = std::sync::Arc::new(
            super::super::device_linking::sibling_sharing::SiblingPreAuthFailureProbe::armed(),
        );
        self.linking_owner.sibling_pre_auth_probe =
            Some((std::sync::Arc::downgrade(original), probe.clone()));
        Ok(probe)
    }
    pub(crate) fn begin_completed_sibling_sharing(&mut self) -> Result<(), ClientLinkingError> {
        use cgka_engine::private_roster_settlement::TrustedPrivateSettlementGuard;
        let Some(action) = self.linking_owner.received_endorsement.as_ref() else {
            return Ok(());
        };
        let Some(original) = action.sharing.as_ref() else {
            return Ok(());
        };
        if !original.state.live() || action.cancelled || original.complete() {
            return Ok(());
        }
        let Some(attempt) = self
            .linking_owner
            .existing_settlement_attempt
            .as_ref()
            .filter(|attempt| {
                attempt.guard.binding() == &action.binding && attempt.guard.is_live()
            })
        else {
            return Ok(());
        };
        let storage = self
            .app
            .account_storage(&self.state.label)
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        let Some(round) = storage
            .private_roster_settlement_storage()
            .ok_or_else(rejected)?
            .read_round()
            .map_err(|error| ClientLinkingError::Engine(error.into()))?
        else {
            return Ok(());
        };
        attempt
            .guard
            .validate(&round.anchor)
            .map_err(ClientLinkingError::Engine)?;
        if
        // COMPLETION_DIAGNOSTIC_BEGIN
        {
            #[cfg(all(test, feature = "test-policy-overrides"))]
            let _measurement =
                crate::account_chat_sharing::enabled::completion_diagnostics::BEGIN_ROSTER.start();
            // COMPLETION_DIAGNOSTIC_END
            self.runtime
                .session()
                .validated_settled_device_roster(&action.group)
            // COMPLETION_DIAGNOSTIC_BEGIN
        }
        // COMPLETION_DIAGNOSTIC_END
        .map_err(ClientLinkingError::Engine)?
        .is_none()
        {
            return Ok(());
        }
        let request = self
            .linking_owner
            .received_enrollment_proposals
            .iter()
            .find(|request| request.binding_digest().ok() == Some(action.binding))
            .ok_or_else(rejected)?;
        let source = round.anchor.local_device;
        let parent = std::sync::Arc::new(
            super::super::device_linking::sibling_sharing::SiblingOriginal::Existing {
                original: original.clone(),
                guard: attempt.guard.clone(),
                source,
                recipient: *request.recipient(),
                account: round.anchor.account,
            },
        );
        self.begin_sibling_source_channel(
            parent,
            &action.group.clone(),
            *request.recipient(),
            original.state.approval_id,
            original.state.deadline,
        )
    }
}
