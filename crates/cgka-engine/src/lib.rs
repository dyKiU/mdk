//! # cgka-engine
//!
//! OpenMLS-backed implementation of [`cgka_traits::CgkaEngine`].
//!
//! The engine is generic over any `S: StorageProvider`; storage dispatch is
//! static. OpenMLS owns MLS validation and key schedule state. Marmot owns the
//! application-facing state machine, durable message records, convergence
//! policy, feature negotiation, and transport wrapping boundary.
//!
//! The state machine lives above OpenMLS; MLS semantics stay inside OpenMLS
//! (`docs/marmot-architecture/further-context/cgka-engine-design.md:52`).
//!
//! ## Module layout
//!
//! - [`engine`] — the [`Engine<S>`] struct + its [`EngineBuilder`].
//! - [`engine_metrics`] — diagnostic post-settle reorg telemetry.
//! - [`identity`] — local signer + credential bundle.
//! - [`account_identity_proof`] — account-key proof binding credentials to MLS leaves.
//! - [`feature_registry`] — runtime feature registry (replaces static constants).
//! - [`wire_format`] - `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` and review marker.
//! - [`provider`] - `OpenMlsProvider` adapter composed from crypto + storage.
//! - [`group_lifecycle`] - `create_group`, `join_welcome`, group records.
//! - [`message_processor`] - inbound `ingest` and outbound `send`.
//! - [`distributed_convergence`] - stored-message convergence entry points.
//! - `convergence_input` - role-aware convergence scheduling classification.
//! - [`canonicalization`] and [`convergence`] - executable policy model.
//! - [`openmls_projection`] - bytes-first bridge between OpenMLS and the model.
//! - [`epoch_manager`] - per-group state transitions and pending references.
//! - [`publish`] - publish-confirm and publish-failed lifecycle.
//! - [`capability_manager`], [`capabilities`], [`upgrade`] - capability policy.
//! - [`auto_committer`] - SelfRemove auto-commit eligibility policy.
//! - [`app_components`] - Marmot app-component state in `app_data_dictionary`.

pub mod account_identity_proof;
pub mod app_components;

pub(crate) mod app_payload;
pub(crate) mod audit_helpers;
pub mod auto_committer;
pub(crate) mod bounded_id_set;
#[cfg(feature = "test-policy-overrides")]
pub mod canonical_probe_observer;
pub mod canonicalization;
pub mod capabilities;
pub mod capability_manager;
#[cfg(feature = "test-conformance-snapshot")]
pub mod conformance_snapshot;
pub mod convergence;
pub mod convergence_clock;
pub(crate) mod convergence_input;
mod deadline;
#[cfg(feature = "experimental-device-sync")]
pub mod device_group_genesis;
#[cfg(feature = "experimental-device-sync")]
mod device_group_lineage;
#[cfg(feature = "experimental-device-sync")]
pub mod device_group_snapshot;
#[cfg(feature = "experimental-device-sync")]
pub mod device_leaf_revocation;
pub mod disband;
pub mod distributed_convergence;
pub mod engine;
pub mod engine_metrics;
pub mod epoch_manager;
pub mod feature_registry;
pub mod group_authority;
pub mod group_context_view;
#[cfg(feature = "experimental-device-sync")]
mod group_creation_origin;
pub mod group_lifecycle;
pub mod group_state_changes;
pub mod identity;
pub mod key_package;
pub mod leaf_advertisement;
pub mod maintenance;
mod membership_effects;
pub(crate) mod message_disposition;
pub mod message_processor;
pub(crate) mod mls_group_cache;
pub mod openmls_projection;
pub mod own_commit_intent;
pub mod pending_commit_guard;
#[cfg(feature = "experimental-device-sync")]
pub mod private_device_invite;
#[cfg(feature = "experimental-device-sync")]
pub mod private_enrollment_predecessor;
#[cfg(feature = "experimental-device-sync")]
pub mod private_roster_settlement;
#[cfg(feature = "experimental-device-sync")]
mod private_successor;
#[cfg(feature = "experimental-device-sync")]
pub mod private_transport;
pub mod provider;
pub mod publish;
pub mod self_update;
pub mod snapshot_guard;
pub(crate) mod test_crash_hooks;
pub mod update_group_data;
pub mod upgrade;
pub mod wire_format;

pub use convergence_clock::{
    ConvergenceClock, ConvergenceTime, ManualConvergenceClock, SystemConvergenceClock,
};
pub use engine::{Ciphersuite, DEFAULT_CIPHERSUITE, Engine, EngineBuilder};
pub use engine_metrics::{
    EngineMetrics, EngineMetricsSnapshot, HistogramBucket, HistogramSnapshot,
};
pub use feature_registry::FeatureRegistry;
pub use key_package::{KeyPackageMetadata, KeyPackageRetirementReport, key_package_metadata};
pub use wire_format::{
    DEFAULT_MAX_PAST_EPOCHS, PURE_PLAINTEXT_WIRE_FORMAT_POLICY, WIRE_FORMAT_POLICY_REVIEW_REQUIRED,
    default_join_config, join_config,
};

// ── Compile-time witnesses ──────────────────────────────────────────────────

const _: fn(Box<dyn cgka_traits::CgkaEngine + Send + Sync>) = |_| {};

#[cfg(feature = "experimental-device-sync")]
pub mod linking_welcome_policy;

#[cfg(feature = "experimental-device-sync")]
mod roster_ack_capture;

#[cfg(feature = "experimental-device-sync")]
mod private_linking_join;

#[cfg(feature = "experimental-device-sync")]
mod private_roster_settlement_receive;
#[cfg(all(
    feature = "experimental-device-sync",
    any(
        test,
        feature = "test-policy-overrides",
        all(feature = "test-crash-hooks", debug_assertions)
    )
))]
#[doc(hidden)]
pub mod private_settlement_test_observation;

#[cfg(feature = "experimental-device-sync")]
pub mod private_enrollment_request;

#[cfg(feature = "experimental-device-sync")]
pub mod private_enrollment_endorsement;

#[cfg(feature = "experimental-device-sync")]
pub mod account_chat_catalog;
#[cfg(feature = "experimental-device-sync")]
pub mod account_chat_sharing;
#[cfg(feature = "experimental-device-sync")]
pub mod history_transfer;
#[cfg(feature = "experimental-device-sync")]
pub mod selected_chat_consent;

// PROOF_DIAGNOSTIC_MODULE_BEGIN
#[cfg(all(feature = "experimental-device-sync", feature = "test-policy-overrides"))]
pub mod proof_memo_diagnostics;
// PROOF_DIAGNOSTIC_MODULE_END
