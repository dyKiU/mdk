# cgka-engine

OpenMLS-backed implementation of the [`CgkaEngine`](../traits/src/engine.rs) trait — the local group state machine
for Marmot. Read this if you are building on the engine directly or changing how groups evolve, converge, or recover.

The engine sits above OpenMLS, governs commit sequencing, adjudicates forks through distributed convergence, enforces
MIP-03 admin rules, and returns typed outcomes for every ingest path.

## Contents

- [What this crate does](#what-this-crate-does)
- [KeyPackage validation before membership changes](#keypackage-validation-before-membership-changes)
- [Promoting state-bearing app components](#promoting-state-bearing-app-components)
- [Background recovery](#background-recovery)
- [Tests and measurements](#tests-and-measurements)
- [Reading order](#reading-order)
- [Status](#status)

## What this crate does

- Wraps `MlsGroup` for each joined group and manages its `EpochState` lifecycle (`Stable`, `PendingPublish`, `Merging`,
  `Recovering`, `Unrecoverable`, `Disbanded`).
- Translates `SendIntent`s (app message, invite, remove members, leave, self-update, update app components, update
  group data) into MLS commits or messages. Group creation and capability upgrade are separate trait calls
  (`create_group`, `upgrade_group_capabilities`). Inbound `TransportMessage`s become typed `IngestOutcome`s and
  `GroupEvent`s.
- Stages local group changes publish-before-apply: the caller publishes, then confirms or reports failure.
- Stores inbound payloads as typed raw-transport or peeled-OpenMLS records so peel-deferred messages can be retried
  without polluting convergence replay.
- Resolves same-epoch forks deterministically through stored-message distributed convergence.
- Retains a small, configurable OpenMLS past-epoch window for delayed application messages.
- Maintains a per-leaf capability cache so `feature_status` lookups do not walk the ratchet tree.
- Stages SelfRemove-only commits for eligible remaining members, keeps durable local leave requests gated, and
  re-proposes stale SelfRemove proposals for newer epochs.

It does **not** do transport (plug in a `TransportPeeler`), persistence beyond `StorageProvider` (pair with
[`storage-sqlite`](../storage-sqlite/README.md); tests use its in-memory mode), CLI, FFI, or application logic.

## KeyPackage validation before membership changes

Create and Invite validate transported KeyPackages through OpenMLS and the Marmot identity/profile checks before
adding members. They also reject LeafNode capabilities that explicitly advertise RFC 9420 section 7.2 default
extension or proposal types. Unknown capability values remain accepted for protocol extensibility.

This is an explicit admission policy beyond the
[RFC 9420 section 7.3 validation checks](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.3): OpenMLS accepts
these advertisements, but MDK keeps known nonconforming signed leaves out of new membership state. An inviter cannot
repair a signed advertisement, so Create/Invite to a peer still publishing an affected package fails with
`InvalidKeyPackageCapabilities` until that peer publishes a conforming package. The refusal carries an authenticated
member id for typed callers and identity-free diagnostic text, and is classified as an expected refusal rather than a
resource failure.

Peers whose published packages carry the former default-capability advertisement must generate a fresh package with
the corrected client. The account runtime records a per-account-device generator revision, and MarmotApp attempts a
one-time fresh publication on activation after upgrading; offline or signing failures remain retryable, and the
revision advances only with an acknowledged replacement. This cannot repair packages on peers that have not upgraded.

The check does not change local private-bundle retention or historical Welcome processing. Directory metadata can still
describe an older package; that does not make it eligible for a new membership operation.

## Promoting state-bearing app components

`upgrade_group_capabilities` only promotes state-bearing app components whose optional state already exists in the
GroupContext. Use two published commits:

1. send `SendIntent::UpdateAppComponents` to install the optional component state, then confirm that commit was
   published;
2. call `upgrade_group_capabilities`, then publish and confirm its promotion commit.

The upgrade fails closed without staging a commit when required state is missing. MDK does not currently expose an
atomic require-and-populate API.

## Background recovery

**Resumable candidate reconstruction.** Live convergence and background deferred peeling retain candidate-search
progress between calls. Each evaluator slice admits at most 32 probes and observes the caller's cooperative time
budget; a started probe always finishes. Live state is restored before the evaluator returns pending work, and
selection and input dispositions are published only after the complete search and application-witness replay finish.
Scratch progress is memory-only and tied to the exact inputs, group state, retained snapshots, policy, and pass
generation. SQLCipher fingerprints live canonical/OpenMLS state and retained snapshots/checkpoints, so unrelated app
writes through another connection do not discard progress; other tracking backends use strict MLS-write-generation
equality, and backends without mutation tracking use the synchronous evaluator. Invalidation or restart discards
scratch work while durable input remains available. Explicit-time convergence entry points and foreground preflight
keep their existing semantics.

**Buffered application handoff.** A frozen convergence batch can advance one epoch beyond its admission ceiling.
Already-unwrapped applications at that new tip remain durable input even when no commit can open another pass.
Background advancement drains them against the stable canonical state after convergence and deferred peeling finish,
sharing the 64-row allowance and cooperative 500 ms background budget; a started MLS operation completes before
yielding, and once reached the drain processes at least one candidate. This is scheduling work, not branch ambiguity:
it opens no convergence pass, gates no foreground send, and consumes no queued-intent fairness slot.
`prepare_convergence_cutoff_delay_ms` reports remaining work ready independently of `has_pending_convergence_inputs`,
which keeps its branch-ambiguity safety-gate meaning. An advance may report branch settlement while application work
remains. Future-epoch input waits for canonical state to advance.

The drain uses the same OpenMLS sender/payload validation and source-state retention decision as canonical replay.
Direct ingestion and replay attribute applications using the authenticated source-epoch credential carried by OpenMLS,
so a later removal or leaf reuse cannot erase or substitute the original author: a valid, retained application authored
before removal can still be delivered after the sender is removed, without authorizing that sender in a later epoch.
Proposals and commits keep live-tree authorization, and the inner app author must still match the credential. Ratchet
writes, the terminal input disposition, and pending app output commit in one storage transaction, so crash recovery
either retries an untouched input or recovers its durable app output, and never reopens a processed or terminally
invalidated input.

## Tests and measurements

```sh
cargo test -p cgka-engine
```

These tests cover the engine boundary with one or a few `Engine<SqliteAccountStorage>` instances over in-memory
SQLite and a mock peeler: command validation, snapshot persistence, processed-message idempotency, restart behavior,
and the exact outputs of a single engine call. [`tests/AGENTS.md`](tests/AGENTS.md) maps the files.

Multi-client behavior is covered by the [conformance simulator](../cgka-conformance-simulator/README.md), which drives
real engines through an in-memory transport bus with the Nostr peeler and checks they converge after realistic delivery
faults. Use this crate's tests to prove an engine method does the right thing; use the simulator to prove many engines still
agree after the world gets messy.

**Speculative replay transactions and resumable reconstruction.** Regression, crash, and paired measurement runs:

```sh
cargo test --locked -p cgka-engine --lib replay_transaction_preserves
cargo test --locked -p cgka-engine --features test-policy-overrides,test-conformance-snapshot --lib resumable_
cargo test --locked -p cgka-engine --features test-crash-hooks,test-policy-overrides --test crash_recovery_sqlite
cargo test --locked -p cgka-engine --lib replay_transaction_measurement -- --ignored --nocapture
cargo test --locked --release -p cgka-engine --config 'profile.release.package.cgka-engine.debug-assertions=true' --lib replay_transaction_measurement -- --ignored --nocapture
cargo test --locked --release -p cgka-engine --config 'profile.release.package.cgka-engine.debug-assertions=true' --lib candidate_reconstruction_measurement -- --ignored --nocapture
```

The replay-transaction measurement alternates the previous unbatched probe body and transactional replay on identical
20-member inputs over encrypted file storage with production WAL/FULL defaults, three candidate probes per sample, and
checks restoration. The reconstruction measurement varies group size, fork width, and history depth, comparing sliced
and uninterrupted search. Neither has a timing threshold; they are microbenchmarks (the simulator's 50-member public
app canary measures runtime contention). The optimized commands keep engine debug assertions because legacy-profile
test helpers require them; production app measurements should use a normal release build.

**Negative application-discovery scan.** The drain's stopping visitor bounds returned candidates, but a negative query
still reads and decodes every retained pending non-application record:

```sh
cargo test -p cgka-engine --release --locked \
  --config profile.release.package.cgka-engine.debug-assertions=true \
  --lib measure_negative_application_discovery_prefix -- --ignored --nocapture
```

The synthetic fixture copies one valid commit into distinct pending rows, takes ten negative-query samples per size,
then adds an unseen old application and verifies its `BeyondAnchor` disposition even with an expired drain allowance.
It does not model distinct commit histories, network behavior, or app end-to-end latency. A local run on 2026-09-14
(593-byte payloads):

| Pending commit rows | Decoded rows per negative query | Mean query time | Late-arrival drain time |
| --- | --- | --- | --- |
| 0 | 0 | 0.025 ms | 0.225 ms |
| 100 | 100 | 0.271 ms | 0.698 ms |
| 1,000 | 1,000 | 2.402 ms | 5.084 ms |
| 10,000 | 10,000 | 33.178 ms | 66.962 ms |

These are diagnostic samples, not thresholds. The late-arrival drain visits `2 * rows + 1` records (discover the
candidate, then check for remaining work). A content-kind index or invalidation-safe classifier/cache remains open
performance work; it must preserve late arrivals, payload replacement, restart, foreign-connection writes, and terminal
dispositions.

## Reading order

1. [Target architecture](../../docs/marmot-architecture/overview/target-architecture.md)
2. [Engine spec](../../docs/marmot-architecture/cgka-engine-spec.md)
3. [Post-peeling canonicalization contract](../../docs/marmot-architecture/cgka-engine-canonicalization-contract.md)
4. [Branch selection and distributed convergence](../../docs/marmot-architecture/distributed-convergence.md)
5. [`AGENTS.md`](AGENTS.md) — module map, design deviations, and invariants

For the Marmot app-component model used by new groups, see
[marmot-protocol/marmot](https://github.com/marmot-protocol/marmot) and [`src/app_components.rs`](src/app_components.rs).

## Status

Single internal consumer; not semver-stable. Versioned with the workspace. For readiness and open production work, see
[`current-state.md`](../../docs/marmot-architecture/overview/current-state.md).

## Experimental accepted-join evidence

`experimental-device-sync` exposes a read-only accepted-Welcome receipt query.
On capable stores, real joins persist exact Welcome/content/group/consumed
KeyPackage and receiver/welcomer MLS signer bindings in the same transaction as
all accepted-join writes. Errors roll back private KeyPackage consumption and
leave the identical Welcome retryable. Unsupported stores provide no receipt.
These facts grant no enrollment, settled roster, messaging, or history access.
The receipt accessor enforces the existing live-group hydration/quarantine gate.
No adopted wire identifiers or conformance versions change.

The same experimental feature captures `MessageReceived.source_leaf` only
while authenticated OpenMLS application processing still holds the exact source
epoch tree. One helper serves direct ingestion and stored replay. It binds the
actual leaf index/signature key to the source epoch and a SHA-256 epoch
authenticator digest. Direct delayed applications yield no proof instead of
looking up an old leaf index in the current tree. Replay may yield an exact
historical proof after reauthenticating that tree; consumers must reject it for
current enrollment acknowledgments when its epoch or branch differs from the
authoritative settlement. Ordinary historical account attribution is unchanged.

The optional event field decodes legacy absence and omits `None`, so default
serialized events stay unchanged. Capture is off by default. Synthetic fixtures
and recovered moderation-only application events carry `None`. Debug output
redacts all evidence. These facts do not provide a settled roster or permission
for enrollment, messages or archive import.

`Engine::candidate_device_group_snapshot` reads a bounded same-account candidate
from the actual OpenMLS tree, preserving occupied leaf indices rather than
enumerating the account-level projected member vector. It requires matching
local stable epochs, a current-profile live group, distinct device signature
keys, no pending commit, no active convergence pass or scheduled convergence,
and no queued outbound intent. Durable reads share a read snapshot. The private
domain-separated commitment includes group/account, epoch, epoch authenticator
digest, and sorted indexed leaves. Debug output redacts identities and hashes.
This candidate is not an authoritative device roster or grant: devices at
different stable epochs produce different commitments until an authenticated
settlement exchange is implemented.

Focused synthetic real-MLS checks:

```sh
cargo test --locked -p cgka-engine --features experimental-device-sync --test accepted_welcome_receipts
cargo test --locked -p cgka-engine --features experimental-device-sync --test device_group_snapshot
```

With the default-off `experimental-device-sync` feature,
`resolve_linking_key_package` atomically creates or resolves one exact single-use
package owned by a checked local reservation. `retire_linking_key_package`
removes only its terminal attempt's exact private bundle and public ownership,
including expired packages without treating cleanup as fresh admission.
`cleanup_unjoined_linking_key_package_on_startup` is a synchronous exclusive-open
seam after durable verifier abandonment; it also removes verified-but-unjoined
material. The existing standalone private generator remains an unbounded lower
level experiment and is not the purpose factory.

Purpose-owned Welcomes require an injected trusted runtime policy. Its one-shot
lease checks authenticated staged group/receiver/welcomer facts and the original
live deadline before SQL commit. Commit notification consumes memory-only verifier
evidence after storage commits; it grants no settled roster or history access.
Without a live policy, generic inbox ingestion excludes the object without a
dedup marker, preserving exact later retry. The injected policy contract is private
experimental integration, not adopted Marmot framing or a host approval boolean.

### Experimental private device-group genesis

With `experimental-device-sync`, `create_private_device_group_genesis` creates a fresh solo Current-profile MLS group, projection, capability cache, and immutable birth fact in one SQL transaction. It explicitly requires private application component `0xf574` with the fixed `whitenoise.experimental.device-group.v1` payload. The optional feature/component is advertised only when all required experimental storage capabilities exist: accepted Welcome receipts, purpose-owned KeyPackages, authenticated ACK capture, genesis provenance, accepted successor anchors and outgoing private-invite staging. A backend missing outgoing staging cannot advertise the private component in signed KeyPackages or allocate genesis. It is not a Marmot interoperability allocation. Generic solo candidates cannot become genesis, and generic private-group sends remain denied pending trusted SDK-held outgoing and control paths.

After normal reopen hydration, `validated_private_device_group_genesis` can return fresh opaque evidence only for the protected birth matching actual local identity and the original authenticated tree/profile/epoch. This evidence never arms a verifier, grants enrollment, proves settled membership, or permits history. Birth metadata stays immutable; actual unexpected adopted transitions and deletion permanently deny active use, including after crypto A-to-B-to-A rewind. Explicit retirement permits a fresh checked local selection generation. Accepted recipient successor provenance is a separate store and is never fabricated as locally created genesis.

### Private invitation metadata validation

The experimental `validate_private_invite_input` and `validate_private_staged_add` helpers inspect real signed single-use packages and actual OpenMLS source/staged trees. They enforce the exact private profile, local source signer, same account, indexed predecessor preservation and precisely one approved Add. The construction fixture explicitly excludes stored proposals with `consume_proposal_store(false)`. Returned metadata cannot authorize an invitation or reconstruct SAS consent. Trusted private preparation and retained outgoing staging are described below; metadata alone never authorizes publication.

## Experimental trusted private Add preparation

`prepare_private_device_invite` requires a trusted core policy holding an owned,
original-deadline Approver verification lease. The engine derives the actual
private-profile predecessor and validates one exact single-use KeyPackage; it
stages only that Add with `consume_proposal_store(false)`. The actual MLS pending
commit and bounded raw commit/Welcome ledger entry share one SQL transaction.
Async wrapping retains the lease, revalidates the actual staged successor, and
caches transport only in the dedicated outgoing ledger. Neither ordinary
`MessageState::Sent` replay nor an accessor exposes a deliverable Welcome.

The opaque prepared value retains the same lease through a dedicated trusted
publisher invocation. Dispatch intent precedes the side effect, with the same original lease checked
before each publisher-future poll; cancellation
before intent atomically retires the draft and clears MLS pending state. Once
dispatch may have happened, the fact remains publication-unknown and generic
confirm/fail paths are denied. A reopened ledger never reconstructs consent.
Exact authenticated own-echo reconciliation and protected successor installation
are described below. Dedicated Welcome delivery and complete restart/publication
coordination remain required; this foundation does not grant enrollment, settled
membership, chat or history. The App's genuine SDK adapter is a separate check.

Private preparation uses `TransportPeeler::wrap_private_linking_welcome`, whose
default is unsupported. It derives the full private context from validated actual
Add bindings and freezes the exact bounded Welcome batch only in110. It never
falls back to an ordinary public-KeyPackage Welcome or invents a public event ID.
The batch is still withheld pending authenticated membership confirmation.

The account actor may check the opaque prepared lease for negative housekeeping
and borrow it for atomic retirement, retaining it after SQL failure. Raw-only
retirement before a prepared continuation exists requires the exact active
approver scope; absent/terminal work is a no-op and Wrapped/uncertain work is
refused. These cleanup APIs never recreate permission or schedule publication.
Genuine SQL-fault tests distinguish MLS Backend/Serialize errors from consent
denial. Dedicated Welcome delivery remains separate unfinished integration;
authenticated confirmation has the partial checkpoint described below.

`create_private_device_group_genesis_with_components` accepts bounded, validated
transport-neutral initial bytes while injecting the mandatory private profile
internally. The empty variant remains available for transport-neutral tests.
Caller routing must be real authenticated MLS dictionary state before birth
capture; the factory generates no Nostr identity/routing data and assumes no
universal GroupId length. It writes the durable opaque route projection with
creation/birth and updates the memory resolver only after commit. A genuine
SQL-fault/encrypted-reopen regression proves atomic rollback and signed route
roundtrip; actual App Nostr integration is verified separately.

### Partial authenticated private confirmation

The experimental ingress recognizes the exact retained private commit before
ordinary dedup and held-publish gates. Cached transport identity is only a hint:
fresh actual OpenMLS processing must produce `OwnPendingCommit` with the exact
source epoch, own indexed leaf, MLS signer and account credential. The actual
retained staged single Add supplies the package and full successor; no public
source-proof DTO, caller success flag or saved verifier fact authorizes a merge.

One SQL unit performs the protected outgoing origin CAS before the actual merge,
then verifies the actual merged full tree and atomically writes birth/ACK denial,
projections/capabilities, processed commit evidence, retained anchors and immutable
checkpoint. Failure discards the fresh MLS object and rolls back the whole unit.
The matching private batch remains in the dedicated ledger, never ordinary Sent
or OutboundWelcome rows. Early cached echo refusal writes no dedup marker. Reopen
preserves uncertain actual staged Add and a negative held-publication barrier;
it does not reconstruct SDK consent or make a Welcome deliverable.

Six focused crypto-ingest tests pass, including genuine post-CAS MLS/projection
SQL faults, exact encrypted-reopen retry, denied-origin preservation and byte/
route substitution. The desired seventh test remains failing: pinned OpenMLS
validates an Add package's current lifetime before producing its own-pending
signal. A previously dispatched Add whose package expires therefore remains
uncertain and blocked. Do not count the six-test run (which explicitly skips this
known failure) as complete reconciliation. A reviewed authenticated retained-own-
commit library seam is required; no clocks, validation flags or forged
OwnPendingCommit result are substituted. Ordinary fresh package validation
continues enforcing lifetime. Recipient admission, settlement, history and
native integration remain separate requirements.

The default-off `join_private_linking_welcome_batch` accepts only a complete
transport-authenticated private batch (1–86 messages, at most 16 MiB encoded,
at most 2 MiB raw Welcome). It requires the actual single-use purpose package
and a trusted live lease: transport-context checks precede private-key
consumption, followed by authenticated private-profile/full-tree checks and the
lease's verified predecessor. Accepted receipt105, purpose consumption106,
independently derived successor109, MLS/group writes and complete-batch ingress
dispositions share one transaction. A backend or lease failure restores the
package and leaves the exact input retryable. Raw/ordinary private-profile
Welcomes cannot substitute for this route; established ordinary profiles keep
existing behavior. Neither these facts nor the crypto-derived
`private_device_profile` metadata settle the roster or grant history access.
Integration tests in `accepted_welcome_receipts/private_batch.rs` use injected
Engine policies and pass-through batch transport, not genuine SDK consent or
NIP59; the App owns that further integration. SQLCipher reopen tests explicitly
inject a new test lease and never reconstruct consent from persisted facts.
