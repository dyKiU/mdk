//! Opt-in local target-read observations. Never format associated error data.
use super::ClientLinkingError;
use std::io::Write;

pub(crate) enum TargetRead<'a> {
    Begin,
    Ready,
    WorkerAcquired,
    WorkerHandling,
    Failed(&'a ClientLinkingError),
}

impl TargetRead<'_> {
    fn code(&self) -> &'static str {
        match self {
            Self::Begin => "begin",
            Self::Ready => "ready",
            Self::WorkerAcquired => "worker_acquired",
            Self::WorkerHandling => "worker_handling",
            Self::Failed(ClientLinkingError::Runtime(error)) => error.privacy_safe_kind(),
            Self::Failed(ClientLinkingError::Engine(error)) => error.privacy_safe_kind(),
            Self::Failed(ClientLinkingError::Owner(_)) => "owner",
            Self::Failed(ClientLinkingError::Collection(_)) => "collection",
            Self::Failed(ClientLinkingError::Genesis(_)) => "genesis",
            Self::Failed(ClientLinkingError::Gate(_)) => "welcome_gate",
            Self::Failed(ClientLinkingError::PrivateInvite(_)) => "private_invite",
        }
    }
}

pub(crate) fn targets_read(observation: TargetRead<'_>) {
    let enabled =
        std::env::var_os("WN_PAIRING_DIAGNOSTICS").as_deref() == Some(std::ffi::OsStr::new("1"));
    if enabled {
        write_observation(true, &mut std::io::stderr().lock(), observation);
    }
}

fn write_observation(enabled: bool, output: &mut impl Write, observation: TargetRead<'_>) {
    if enabled {
        let cause = observation.code();
        let _ = writeln!(
            output,
            "target=marmot_app::device_linking method=pairing_diagnostic stage=targets_read cause={cause}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::{EngineError, GroupId};

    #[test]
    fn target_read_diagnostics_preserve_failure_kind_without_associated_data() {
        let sensitive = "private-account-packet-and-storage-detail";
        let cases = [
            (
                ClientLinkingError::Engine(EngineError::Backend(sensitive.into())),
                "backend",
            ),
            (
                ClientLinkingError::Engine(EngineError::UnknownGroup(GroupId::new(
                    sensitive.as_bytes().to_vec(),
                ))),
                "unknown_group",
            ),
            (
                ClientLinkingError::Engine(EngineError::GroupNotHydrated(GroupId::new(
                    sensitive.as_bytes().to_vec(),
                ))),
                "group_not_hydrated",
            ),
            (
                ClientLinkingError::Runtime(Box::new(
                    crate::AppError::AccountWorkerResponseTimedOut,
                )),
                "account_worker_response_timed_out",
            ),
        ];
        for (error, expected) in cases {
            let mut output = Vec::new();
            write_observation(true, &mut output, TargetRead::Failed(&error));
            assert_eq!(
                String::from_utf8(output).unwrap(),
                format!(
                    "target=marmot_app::device_linking method=pairing_diagnostic stage=targets_read cause={expected}\n"
                )
            );
        }
    }

    #[test]
    fn target_read_worker_boundaries_have_fixed_codes() {
        for (observation, code) in [
            (TargetRead::WorkerAcquired, "worker_acquired"),
            (TargetRead::WorkerHandling, "worker_handling"),
        ] {
            let mut output = Vec::new();
            write_observation(true, &mut output, observation);
            assert_eq!(
                String::from_utf8(output).unwrap(),
                format!(
                    "target=marmot_app::device_linking method=pairing_diagnostic stage=targets_read cause={code}\n"
                )
            );
        }
    }

    #[test]
    fn target_read_diagnostics_are_silent_without_opt_in() {
        let error = ClientLinkingError::Engine(EngineError::Other("private detail".into()));
        let mut output = Vec::new();
        for observation in [
            TargetRead::Begin,
            TargetRead::Ready,
            TargetRead::WorkerAcquired,
            TargetRead::WorkerHandling,
            TargetRead::Failed(&error),
        ] {
            write_observation(false, &mut output, observation);
        }
        assert!(output.is_empty());
    }
}
