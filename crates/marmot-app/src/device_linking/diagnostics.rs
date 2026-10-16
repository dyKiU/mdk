//! Opt-in fixed-code observations. No identity, packet, or authority is retained.
use std::io::Write;

pub(crate) fn report(stage: &'static str, cause: &'static str) {
    if std::env::var_os("WN_PAIRING_DIAGNOSTICS").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    let _ = writeln!(
        std::io::stderr().lock(),
        "target=marmot_app::device_linking method=pairing_diagnostic stage={stage} cause={cause}"
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnrollmentObservation {
    Verifier,
    RoundMissing,
    AnchorMismatch,
    SettlementPending,
    SettlementDenied,
    CompletedRosterUnavailable,
    SharingCommitPending,
    SiblingSharingPending,
    Complete,
}

impl EnrollmentObservation {
    fn code(self) -> &'static str {
        match self {
            Self::Verifier => "verifier",
            Self::RoundMissing => "settlement_round_missing",
            Self::AnchorMismatch => "settlement_anchor_mismatch",
            Self::SettlementPending => "settlement_pending",
            Self::SettlementDenied => "settlement_denied",
            Self::CompletedRosterUnavailable => "completed_roster_unavailable",
            Self::SharingCommitPending => "sharing_commit_pending",
            Self::SiblingSharingPending => "sibling_sharing_pending",
            Self::Complete => "complete",
        }
    }
}

#[derive(Default)]
pub(crate) struct EnrollmentDiagnostics {
    last: Option<EnrollmentObservation>,
    transitions: u8,
}

impl EnrollmentDiagnostics {
    fn change(&mut self, observation: EnrollmentObservation) -> Option<&'static str> {
        if self.last == Some(observation) || self.transitions >= 64 {
            return None;
        }
        self.last = Some(observation);
        self.transitions += 1;
        Some(observation.code())
    }

    pub(crate) fn observe(&mut self, observation: EnrollmentObservation) {
        if let Some(code) = self.change(observation) {
            report("enrollment_observation", code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_diagnostics_distinguish_waits_and_bound_transitions() {
        let mut diagnostics = EnrollmentDiagnostics::default();
        assert_eq!(
            diagnostics.change(EnrollmentObservation::SettlementPending),
            Some("settlement_pending")
        );
        assert_eq!(
            diagnostics.change(EnrollmentObservation::SettlementPending),
            None
        );
        assert_eq!(
            diagnostics.change(EnrollmentObservation::SharingCommitPending),
            Some("sharing_commit_pending")
        );
        assert_eq!(
            diagnostics.change(EnrollmentObservation::SiblingSharingPending),
            Some("sibling_sharing_pending")
        );
        assert_eq!(
            diagnostics.change(EnrollmentObservation::Complete),
            Some("complete")
        );
        for index in 4..64 {
            let observation = if index % 2 == 0 {
                EnrollmentObservation::Verifier
            } else {
                EnrollmentObservation::RoundMissing
            };
            assert!(diagnostics.change(observation).is_some());
        }
        assert_eq!(diagnostics.change(EnrollmentObservation::Complete), None);
    }
}
