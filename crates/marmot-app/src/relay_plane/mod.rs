//! Compatibility paths for the generic transport plane and app-owned private fixtures.
pub use transport_nostr::*;
#[cfg(all(
    test,
    feature = "experimental-device-sync",
    feature = "test-policy-overrides"
))]
#[path = "tests/ordinary_commit_observation.rs"]
pub(crate) mod ordinary_commit_observation;
#[cfg(feature = "experimental-device-sync")]
pub(crate) mod pairing;
