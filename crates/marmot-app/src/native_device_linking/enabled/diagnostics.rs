//! Opt-in local diagnostics for experimental pairing; never format error payloads.
use super::*;
pub(super) use crate::device_linking::diagnostics::report;
use cgka_engine::device_group_genesis::GenesisFactoryError;
use cgka_traits::device_group_genesis::GenesisError;

pub(super) fn client_kind(error: &ClientLinkingError) -> &'static str {
    match error {
        ClientLinkingError::Runtime(error) => error.privacy_safe_kind(),
        ClientLinkingError::Engine(error) => error.privacy_safe_kind(),
        ClientLinkingError::Owner(OwnerError::Storage) => "owner_storage",
        ClientLinkingError::Owner(OwnerError::Verifier(LinkError::SimultaneousRequest)) => {
            "owner_simultaneous_request"
        }
        ClientLinkingError::Owner(OwnerError::Verifier(LinkError::Sdk)) => "verifier_sdk",
        ClientLinkingError::Owner(OwnerError::Verifier(_)) => "verifier_state",
        ClientLinkingError::Genesis(GenesisFactoryError::Engine(error)) => {
            error.privacy_safe_kind()
        }
        ClientLinkingError::Genesis(GenesisFactoryError::Genesis(error)) => match error {
            GenesisError::SelectionBusy => "genesis_selection_busy",
            GenesisError::ScopeMismatch => "genesis_scope_mismatch",
            GenesisError::InvalidFact => "genesis_invalid_fact",
            GenesisError::GenerationExhausted => "genesis_generation_exhausted",
            GenesisError::Unsupported => "genesis_unsupported",
            GenesisError::Storage(_) => "genesis_storage",
        },
        ClientLinkingError::Genesis(GenesisFactoryError::Anchor(_)) => "genesis_anchor",
        ClientLinkingError::Collection(_) => "collection",
        ClientLinkingError::Gate(_) => "welcome_gate",
        ClientLinkingError::PrivateInvite(_) => "private_invite",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::{EngineError, GroupId};

    #[test]
    fn native_error_taxonomy_preserves_kind_without_sensitive_details() {
        let sentinel = "must-not-leak-private-detail";
        for error in [
            ClientLinkingError::Engine(EngineError::Backend(sentinel.into())),
            ClientLinkingError::Runtime(Box::new(crate::AppError::AccountWorkerResponseTimedOut)),
            ClientLinkingError::Genesis(GenesisFactoryError::Genesis(GenesisError::SelectionBusy)),
            ClientLinkingError::Engine(EngineError::GroupNotHydrated(GroupId::new(
                sentinel.as_bytes().to_vec(),
            ))),
        ] {
            let kind = client_kind(&error);
            assert!(!kind.contains(sentinel));
            assert!(kind.bytes().all(|c| c.is_ascii_lowercase() || c == b'_'));
            assert!(!kind.is_empty());
        }
        assert_eq!(
            client_kind(&ClientLinkingError::Runtime(Box::new(
                crate::AppError::AccountWorkerResponseTimedOut
            ))),
            "account_worker_response_timed_out"
        );
        assert_eq!(
            client_kind(&ClientLinkingError::Genesis(GenesisFactoryError::Genesis(
                GenesisError::SelectionBusy
            ))),
            "genesis_selection_busy"
        );
    }
}
