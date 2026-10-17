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

#[derive(Clone, Copy)]
pub(crate) enum EnrollmentDelivery {
    CommitPending,
    CommitConfirmed,
    WelcomePublishStarted,
    WelcomePublishAccepted,
    WelcomePublishFailed,
    WelcomeAuthenticated,
    WelcomeBuffered,
    WelcomeJoined,
    WelcomeRejected,
    WelcomeUnrelated,
}

impl EnrollmentDelivery {
    fn code(self) -> &'static str {
        match self {
            Self::CommitPending => "commit_pending",
            Self::CommitConfirmed => "commit_confirmed",
            Self::WelcomePublishStarted => "welcome_publish_started",
            Self::WelcomePublishAccepted => "welcome_publish_accepted",
            Self::WelcomePublishFailed => "welcome_publish_failed",
            Self::WelcomeAuthenticated => "welcome_authenticated",
            Self::WelcomeBuffered => "welcome_buffered",
            Self::WelcomeJoined => "welcome_joined",
            Self::WelcomeRejected => "welcome_rejected",
            Self::WelcomeUnrelated => "welcome_unrelated",
        }
    }
}

#[derive(Default)]
pub(crate) struct EnrollmentDiagnostics {
    last: Option<EnrollmentObservation>,
    transitions: u8,
    delivery_seen: u16,
}

impl EnrollmentDiagnostics {
    fn delivery_change(&mut self, observation: EnrollmentDelivery) -> Option<&'static str> {
        let bit = 1_u16 << observation as u8;
        if self.delivery_seen & bit != 0 {
            return None;
        }
        self.delivery_seen |= bit;
        Some(observation.code())
    }

    pub(crate) fn delivery(&mut self, observation: EnrollmentDelivery) {
        if let Some(code) = self.delivery_change(observation) {
            report("enrollment_delivery", code);
        }
    }

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
    fn enrollment_delivery_reports_each_fixed_code_only_once() {
        let mut diagnostics = EnrollmentDiagnostics::default();
        let observations = [
            EnrollmentDelivery::CommitPending,
            EnrollmentDelivery::CommitConfirmed,
            EnrollmentDelivery::WelcomePublishStarted,
            EnrollmentDelivery::WelcomePublishAccepted,
            EnrollmentDelivery::WelcomePublishFailed,
            EnrollmentDelivery::WelcomeAuthenticated,
            EnrollmentDelivery::WelcomeBuffered,
            EnrollmentDelivery::WelcomeJoined,
            EnrollmentDelivery::WelcomeRejected,
            EnrollmentDelivery::WelcomeUnrelated,
        ];
        for observation in observations {
            let code = diagnostics.delivery_change(observation).unwrap();
            assert!(code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        }
        for _ in 0..100 {
            for observation in observations {
                assert!(diagnostics.delivery_change(observation).is_none());
            }
        }
    }

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
