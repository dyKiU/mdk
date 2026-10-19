//! App-owned encrypted protocol fixtures and authoritative publication observations.
#[cfg(all(
    test,
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
#[path = "tests/ordinary_commit_observation.rs"]
pub(crate) mod ordinary_commit_observation;
// The live mailbox comes from transport-nostr; encrypted protocol fixtures
// belong to App and must not shadow that transport module.
#[cfg(all(test, feature = "experimental-device-sync"))]
#[path = "tests/pairing.rs"]
mod pairing_protocol_tests;

#[cfg(all(
    test,
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
#[path = "tests/held_delivery.rs"]
pub(crate) mod held_delivery;
