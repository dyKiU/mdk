//! Existing-member channel initiation is derived only from the retained original.
use super::*;
use cgka_traits::StorageProvider;
// BROAD_TRACE_BEGIN
#[cfg(all(test, feature = "test-policy-overrides"))]
use super::super::device_linking::sibling_sharing::broad_trace;
// BROAD_TRACE_END
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
        // BROAD_TRACE_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        self.broad_trace_for_test(73);
        // BROAD_TRACE_END
        let Some(action) = self.linking_owner.received_endorsement.as_ref() else {
            // BROAD_TRACE_BEGIN
            #[cfg(all(test, feature = "test-policy-overrides"))]
            broad_trace::global(74);
            // BROAD_TRACE_END
            return Ok(());
        };
        let Some(original) = action.sharing.as_ref() else {
            // BROAD_TRACE_BEGIN
            #[cfg(all(test, feature = "test-policy-overrides"))]
            broad_trace::global(75);
            // BROAD_TRACE_END
            return Ok(());
        };
        // BROAD_TRACE_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        broad_trace::channel(&original.state, 76, 0);
        // BROAD_TRACE_END
        if !original.state.live() || action.cancelled || original.complete() {
            // BROAD_TRACE_BEGIN
            #[cfg(all(test, feature = "test-policy-overrides"))]
            broad_trace::channel(&original.state, 77, 0);
            // BROAD_TRACE_END
            return Ok(());
        }
        // BROAD_TRACE_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        {
            broad_trace::channel(&original.state, 78, 0);
            broad_trace::channel(&original.state, 79, 0);
        }
        // BROAD_TRACE_END
        let Some(attempt) = self
            .linking_owner
            .existing_settlement_attempt
            .as_ref()
            .filter(|attempt| {
                attempt.guard.binding() == &action.binding && attempt.guard.is_live()
            })
        else {
            // BROAD_TRACE_BEGIN
            #[cfg(all(test, feature = "test-policy-overrides"))]
            broad_trace::channel(&original.state, 80, 0);
            // BROAD_TRACE_END
            return Ok(());
        };
        // BROAD_TRACE_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        {
            broad_trace::channel(&original.state, 81, 0);
            broad_trace::channel(&original.state, 91, 0);
        }
        // BROAD_TRACE_END
        let storage = self
            .app
            .account_storage(&self.state.label)
            // BROAD_TRACE_BEGIN
            .inspect(|_| {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                broad_trace::channel(&original.state, 92, 0);
            })
            .inspect_err(|_| {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                broad_trace::channel(&original.state, 92, 1);
            })
            // BROAD_TRACE_END
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        // BROAD_TRACE_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        broad_trace::channel(&original.state, 82, 0);
        // BROAD_TRACE_END
        let Some(round) = storage
            .private_roster_settlement_storage()
            .ok_or_else(rejected)?
            .read_round()
            // BROAD_TRACE_BEGIN
            .inspect(|round| {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                broad_trace::channel(&original.state, 83, match round.as_ref().map(|round| round.phase) {
                    None => 0,
                    Some(cgka_traits::private_roster_settlement::PrivateSettlementPhase::Pending) => 1,
                    Some(cgka_traits::private_roster_settlement::PrivateSettlementPhase::Completed) => 2,
                    Some(cgka_traits::private_roster_settlement::PrivateSettlementPhase::Denied) => 3,
                });
                let _ = round;
            })
            .inspect_err(|_| { #[cfg(all(test, feature = "test-policy-overrides"))] broad_trace::channel(&original.state, 83, 4); })
            // BROAD_TRACE_END
            .map_err(|error| ClientLinkingError::Engine(error.into()))?
        else {
            return Ok(());
        };
        // BROAD_TRACE_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        broad_trace::channel(&original.state, 84, 0);
        // BROAD_TRACE_END
        attempt
            .guard
            .validate(&round.anchor)
            // BROAD_TRACE_BEGIN
            .inspect(|_| {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                broad_trace::channel(&original.state, 85, 0);
            })
            .inspect_err(|_| {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                broad_trace::channel(&original.state, 85, 1);
            })
            // BROAD_TRACE_END
            .map_err(ClientLinkingError::Engine)?;
        // BROAD_TRACE_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        broad_trace::channel(&original.state, 86, 0);
        // BROAD_TRACE_END
        if self
            .runtime
            .session()
            .validated_settled_device_roster(&action.group)
            // BROAD_TRACE_BEGIN
            .inspect(|roster| {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                broad_trace::channel(&original.state, 87, u64::from(roster.is_some()));
                let _ = roster;
            })
            .inspect_err(|_| {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                broad_trace::channel(&original.state, 87, 2);
            })
            // BROAD_TRACE_END
            .map_err(ClientLinkingError::Engine)?
            .is_none()
        {
            return Ok(());
        }
        // BROAD_TRACE_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        broad_trace::channel(&original.state, 88, 0);
        // BROAD_TRACE_END
        let request = self
            .linking_owner
            .received_enrollment_proposals
            .iter()
            .find(|request| request.binding_digest().ok() == Some(action.binding))
            // BROAD_TRACE_BEGIN
            .inspect(|_| {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                broad_trace::channel(&original.state, 89, 1);
            })
            .or_else(|| {
                #[cfg(all(test, feature = "test-policy-overrides"))]
                broad_trace::channel(&original.state, 89, 0);
                None
            })
            // BROAD_TRACE_END
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
        // BROAD_TRACE_BEGIN
        #[cfg(all(test, feature = "test-policy-overrides"))]
        broad_trace::channel(&original.state, 90, 0);
        // BROAD_TRACE_END
        self.begin_sibling_source_channel(
            parent,
            &action.group.clone(),
            *request.recipient(),
            original.state.approval_id,
            original.state.deadline,
        )
    }
}
