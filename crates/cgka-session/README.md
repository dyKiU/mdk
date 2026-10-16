# cgka-session

Production-shaped account-device wrapper around `Engine<SqliteAccountStorage>`. This is where app integration starts to
become concrete: one `AccountDeviceSession` per Marmot account-device identity, returning app events plus publishable
transport work from each lifecycle method.

## Opening a session

`SessionConfig::new(database_path, database_key, identity, peeler)` takes the SQLCipher database path and key, the
local identity, and a `TransportPeeler`. `AccountDeviceSession::open` also requires an account identity-proof signer
(`SessionConfig::account_identity_proof_signer`). Optional builder methods set the feature registry, supported
app-component set, protocol profile, storage options, convergence policy, forensic recorder, and maintenance clock/RNG
sources. `SessionConfig::with_storage(storage, opened_in, identity, peeler)` instead runs the session on a connection the host has
already opened, for hosts that must close every connection at a known instant (an iOS app before suspension).

Open fails closed before touching storage if the convergence policy is unacceptable or a legacy protocol profile is
requested without `legacy_compatibility_profile()`. It then opens encrypted storage, builds the engine, retires (for
the current profile) non-current local KeyPackages, and hydrates stored groups. By default hydration is eager: every
group is fully hydrated (or quarantined) before `open` returns. `defer_group_hydration()` runs only the cheap seed
pass; groups are listed but return `GroupNotHydrated` until the host calls `hydrate_next_groups` /
`ensure_group_hydrated` or a send or ingest promotes them on demand. Embedders without a background pipeline should keep
the default.

## What this crate does

- Opens one encrypted SQLite database for one Marmot account-device identity.
- Builds `Engine<SqliteAccountStorage>` with an injected `TransportPeeler`.
- Surfaces `GroupEvent`s and publishable transport work as `SessionEffects`.
- Preserves the publish-before-apply contract: callers confirm or fail pending group operations after transport
  publish, including auto-publish work created while ingesting inbound messages.
- Exposes convergence advancement (`advance_convergence`, `advance_convergence_inputs`) so queued outbound work can be
  regenerated from canonical state.
- Exposes durable maintenance, KeyPackage-lifecycle, group-evolution, and transport-fanout records for the account
  layer above it.
- Provides compact `group_authority` reads and `with_group_authority_snapshot` for composing host-owned persisted
  reads with current engine facts on this session's store. The callback is synchronous and read-only; unhydrated groups
  return `GroupNotHydrated`. It does not serve a frozen startup snapshot or start relay work.
- Provides `canonical_group_membership` for startup reconciliation: authenticated leaf indexes and account
  identities, plus whether this device's own leaf is active. Pending roster projections do not replace those facts.
  Live termination and token cleanup use immutable engine effects captured at apply, rather than this reader.
- Offers `promote_legacy_message_rows` for host-scheduled, bounded promotion of legacy stored rows after readiness.

It does **not** do account key derivation, recovery, or key rotation; relay sync, network publish, or transport
adaptation; or UI projection and application databases. Those live above this crate (see
[`marmot-account`](../marmot-account/) and [`marmot-app`](../marmot-app/)).

## Tests

```sh
cargo test -p cgka-session
```

- `tests/session_lifecycle.rs` — encrypted open/create/confirm/close/reopen, Welcome and app-message ingest,
  auto-publish and SelfRemove re-proposal work, convergence releasing queued outbound work, disband requests, compact authority
  capture, KeyPackage cutover on open, and the legacy-row promotion facade (using
  [`fixtures/session-promotion-v1.bin`](fixtures/README.md)).
- `tests/nostr_stack.rs` — the production-shaped non-relay stack: SQLCipher storage, the real `NostrMlsPeeler`, and
  `NostrTransportAdapter` over an in-memory relay client. Covers inbox and group subscription routing, NIP-59 Welcome
  and kind `445` group delivery, routing-component-driven `h` tags and publish targets (the transport id is not the MLS
  group id), publish ack/insufficient-ack/error resolution, duplicate and out-of-order delivery, and invite evolution
  with commit and Welcome outputs.
- `tests/nostr_stack_chaos.rs` — seeded no-network delivery-chaos scripts against the same stack, including invite
  lifecycle chaos (wrong-route drops, Welcome replay, shared commit fanout, Welcome/commit ordering). Reports go to
  `target/session-stack-chaos/`.

Test placement rules: [`tests/AGENTS.md`](tests/AGENTS.md).

With the default-off `experimental-device-sync` feature,
`accepted_welcome_receipt` forwards the engine's read-only exact accepted-join
facts. A receipt does not establish a settled device roster or authorize
enrollment, chat, or history transfer. Unsupported storage yields no receipt.

Under default-off `experimental-device-sync`, `fresh_linking_key_package`
creates a private non-last-resort package without transport or publication.
An accepted Welcome consumes that exact private bundle; public last-resort
packages keep their normal behavior. This generator alone provides no bounded
cleanup lifecycle or enrollment permission. The account owner must bind exact
attempt provenance, fence generic Welcome admission, and clean unused packages.
`tests/session_lifecycle/single_use_key_packages.rs` covers encrypted reopen,
exact consumption and refusal of reuse through the public session boundary.

The experimental session forwards exact purpose resolution/retirement and the
synchronous exclusive-startup cleanup seam. A trusted account runtime may install
a Welcome policy holding a real opaque verifier result; native hosts receive no
approval boolean or enrollment grant from these methods. Purpose-owned material
must not use the public last-resort publication lifecycle.
`candidate_device_group_snapshot` forwards bounded, indexed local-tree evidence;
it requires a compatible, locally stable same-account group and conveys no
approved-roster, enrollment or history permission.

### Experimental private-group origin lifecycle

With `experimental-device-sync`, `AccountDeviceSession` delegates private
self-only creation, fresh persisted-origin validation and exact generation
retirement to the engine. These methods produce neither publish work nor SDK
consent, enrollment or settled-roster permission. Ordinary one-member groups
remain candidates and cannot be promoted into creation origins. Session reopen
validates the actual stored tree and account-device signer; retirement permanently
fences the selected birth while preserving its immutable provenance. Physical
cleanup of the old private MLS/group projection remains a coordinator concern.

`tests/session_lifecycle/private_device_genesis.rs` covers reopen and exact
retirement, ordinary-group rejection and independent device signers for the same
account through the public session boundary. The full test harness uses
`experimental-device-sync,test-policy-overrides`; never enable the latter in
native development/release artifacts.


The experimental private-genesis components variant forwards validated initial
App components to Engine creation, before protected birth capture. Dedicated
private invite preparation, borrowed dispatch and borrowed cleanup are thin
Engine forwarders; Session neither wraps Nostr events nor owns SDK consent.
Raw-only retirement requires the exact active attempt. Borrowed dispatch and
retirement preserve the caller's opaque preparation after a pre-intent storage
failure. Dispatch accepts only a trusted core publisher and retains the original
lease across its await; it never delivers a private Welcome batch or confirms
publication. Durable intent prevents redispatch.

Experimental private Welcome chunk observation is a read-only Engine forwarder.
The configured transport peeler authenticates metadata; it does not arm or restore
recipient consent. The App owns bounded collection and original verifier lifetime.

`dispatch_confirmed_private_welcomes` is a dedicated thin Engine forwarder with
the original borrowed preparation and trusted publisher. Engine validates actual
confirmed membership and live delivery consent; Session derives no authority
from the caller or a receipt and does not settle the linked-device roster.

Experimental predecessor export and validation are thin Engine forwards. Export
requires fresh protected completed lineage. Portable validation checks bounded
signed public metadata in separate scratch storage, without installing an MLS
member or granting consent. Neither method authorizes native enrollment or history.

`prepare_private_enrollment_proposal` and `wrap_private_enrollment_proposal` are
feature-only thin Core forwarders. The caller retains the nonclone original-owner
producer; Session supplies no SDK evidence, transport policy, Add or approval.

The experimental Session endorsement methods are thin Core forwards: source-bound received-artifact validation, explicit endorsement creation, fresh owned-endorsement validation and negative cancellation. They accept the actual opaque Core observation and retain Core ownership checks; they provide no transport, serialized permission, native proof or admission bypass.

Feature-only endorsement wrapping, actual receipt draining and original local
proposal signature/collection are thin Core forwards. The caller retains opaque
original actions; Session provides no SDK evidence or transition permission.

Experimental `account_chat_sharing` methods forward the actual Core-owned policy channel, fresh validation, signed control authentication and wrapping. Session owns neither broad approval nor a relay actor; durable policy data never reconstructs an old channel.

The feature-only `endorse_private_enrollment_request_and_share_chats` forwards
the named original Core action. Its signed broader terms are separate from the
ordinary unmarked enrollment endorsement. Original recipient evidence reports
verified sharing signers without granting a bilateral policy or join. Native
approval and policy handoff must still preserve both actual originals.
