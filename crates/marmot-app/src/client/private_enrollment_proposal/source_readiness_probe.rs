//! Read-only actual source prerequisites; never creates channels or schedules work.
use super::*;
use cgka_engine::private_roster_settlement::TrustedPrivateSettlementGuard;
use cgka_traits::{StorageProvider, private_roster_settlement::PrivateSettlementPhase};
use std::sync::Weak;
pub(crate) struct Snapshot {
    // exact owner, eligible live original, actual matching live attempt,
    // freshCompleted, fresh guard validated, validated rosterSome,
    // actual retained request, still live before unchanged deadline.
    pub(crate) facts: [bool; 8],
    pub(crate) deadline: std::time::Instant,
}
impl AppClient {
    pub(crate) fn source_readiness_snapshot_for_test(&self, owner: &Weak<OriginalSiblingSharingApproval>)
        -> Result<Option<Snapshot>, ClientLinkingError>
    {
        let Some(held) = owner.upgrade() else { return Ok(None); };
        let Some(action) = self.linking_owner.received_endorsement.as_ref() else { return Ok(None); };
        let Some(original) = action.sharing.as_ref().filter(|original| Arc::ptr_eq(original, &held)) else { return Ok(None); };
        let mut snapshot = Snapshot { facts: [false; 8], deadline: original.state.deadline };
        snapshot.facts[0] = true;
        snapshot.facts[1] = original.state.live() && !action.cancelled && !original.complete();
        if !snapshot.facts[1] { return Ok(Some(snapshot)); }
        let Some(attempt) = self.linking_owner.existing_settlement_attempt.as_ref()
            .filter(|attempt| attempt.guard.binding() == &action.binding && attempt.guard.is_live())
        else { return Ok(Some(snapshot)); };
        snapshot.facts[2] = true;
        let storage = self.app.account_storage(&self.state.label)
            .map_err(|error| ClientLinkingError::Runtime(Box::new(error)))?;
        let round = storage.private_roster_settlement_storage().ok_or_else(rejected)?
            .read_round().map_err(|error| ClientLinkingError::Engine(error.into()))?;
        let Some(round) = round else { return Ok(Some(snapshot)); };
        snapshot.facts[3] = round.phase == PrivateSettlementPhase::Completed;
        if !snapshot.facts[3] { return Ok(Some(snapshot)); }
        snapshot.facts[4] = attempt.guard.validate(&round.anchor).is_ok();
        if !snapshot.facts[4] { return Ok(Some(snapshot)); }
        snapshot.facts[5] = self.runtime.session().validated_settled_device_roster(&action.group)
            .map_err(ClientLinkingError::Engine)?.is_some();
        snapshot.facts[6] = self.linking_owner.received_enrollment_proposals.iter()
            .any(|request| request.binding_digest().ok() == Some(action.binding));
        snapshot.facts[7] = original.state.live() && !action.cancelled && !original.complete()
            && attempt.guard.is_live() && std::time::Instant::now() < snapshot.deadline;
        Ok(Some(snapshot))
    }
}
