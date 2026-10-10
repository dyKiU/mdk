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

### Terminal chat classification

With `experimental-device-sync`, historical private-group fences remain authoritative
after disband deletes live MLS state. If those fences do not classify the group,
the engine uses retained canonical capabilities only when the authenticated group
record is disbanded. A private component keeps the group hidden; a retained ordinary
record permits terminal chat projection and push cleanup. Missing metadata, a
tombstone alone, or nonterminal missing MLS state cannot classify a group as
ordinary. Storage failures propagate. The regression checks live classification,
authenticated disband, reopen, and removal of full metadata.

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
publisher invocation. `dispatch_prepared_private_device_invite` borrows that value
mutably: a pre-intent SQL failure leaves it owned by the account actor for an exact
still-live retry. It cannot recreate or extend consent. Durable dispatch intent
prevents redispatch, even if the caller still holds the opaque value. Dispatch intent precedes the side effect, with the same original lease checked
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

### Experimental private lineage denial

Actual adopted MLS trees permanently fence an accepted109 or confirmed110
selection when its exact owner, indexed successor roster, epoch/authenticator or
private profile no longer matches. The denial shares the MLS/projection SQL unit;
failed writes leave the original state retryable. Candidate probes do not revoke
lineage, and restoring an older genuine crypto snapshot cannot clear denial.
Expected dedicated private-confirmation successors remain active. These are
negative facts, never reconstructed SDK consent or enrollment/history grants.

The isolated076+12e test checkpoint reproduced an independent MessagePack
ordinary-pending decoding failure in the unrelated-group control. Its private
fence/rollback tests pass, but12e is not qualified for a native cohort; the
reviewed library storage fix and fresh gates are required separately.

A fresh companion checkpoint with reviewed library storage correction410b6be9
passes the unchanged unrelated-group control and all11 private-batch tests,
plus18 private-invite controls. The original12e source and failing evidence
remain preserved separately; this does not qualify12e-authored databases for
upgrade or replace the full cohort integration gates.


### Legacy private own-echo compatibility

The experimental private confirmation path uses the library's explicit
`process_own_commit_echo` receipt selection. Pending content with a retained
receipt stays on exact retained authentication, without falling back after an
error. Stock legacy pending content without a receipt uses ordinary MLS
signature, membership, pending-tag and current KeyPackage lifetime validation.
Both paths must establish an actual own pending commit and satisfy the Engine's
exact private staging/transport/source/tree checks before the atomic110 CAS and
merge. Expired legacy Add proposals are denied; no retained receipt, SDK consent,
lease, or delivery permission is reconstructed from migrated storage.

Experimental private chunk observation delegates to the configured transport
peeler and returns authentication metadata only. It neither creates a verifier
lease nor accepts membership; complete batch joining independently revalidates
the original live runtime lease and actual Welcome/tree in its SQL unit.
The account actor can use `finish_interrupted_private_device_invite` for negative
cleanup of its exact retained preparation. Wrapped work is retired only through
the existing undispatched cleanup. Dispatching becomes Unknown; Unknown remains
idempotent; terminal facts are untouched. Uncertain actual MLS pending state is
never cleared. SQL failure requires retaining the opaque continuation for retry
with permission already revoked. This API cannot reconstruct consent or grant
Welcome delivery.

### Experimental hidden private transport

`private_transport::PrivateTransportEvidence` is fresh, read-only routing
metadata derived from the protected selected lineage and actual current MLS
profile, indexed tree, own identity, and requested authenticated component.
It remains available for a matching unresolved private Add so its exact echo can
reconcile, without reconstructing SAS consent or admitting delivery/history.
The account host maintains one hidden subscription separately from chat state.
`exclude_private_group_from_chat` is a negative presentation check; protected
historical identifiers can suppress projection, but never authorize membership.
Lookup errors propagate rather than falling back to ordinary chat projection.

Permanent per-group privacy fences supplement retained lineage and actual private
profile checks, so marker removal and selection replacement do not expose an
already fenced group as a conversation. Hidden-route live/reopen tests do not
establish historical server retrieval of an older Unknown commit.


Private ledger revision9 now persists negative chat exclusion during actual genesis
and accepted join transactions. Private profile support requires that optional
backend capability. Historical marker removal plus accepted-selection replacement
has a real encrypted MLS regression; new fences survive those transitions and
reopen. The fence is never route, membership or consent evidence. Migration can
backfill retained protected identifiers but cannot recover older already-lost
identifiers/markers from unpublished prior cohorts.

Dedicated `dispatch_confirmed_private_welcomes` validates the protected confirmed
fact against the actual selected MLS successor/profile and the original opaque
lease before publishing only the frozen batch. It preserves original deadlines
and cancellation, creates no ordinary replay obligation and does not establish
recipient join, settled roster or history permission from relay acknowledgments.

### Experimental all-leaf settlement observation

`validated_settled_device_roster` returns an opaque, nonserializable observation
only after fresh actual private lineage/tree and every indexed encrypted
confirmation match the protected completed round. Its `candidate()` and
`origin()` accessors expose read-only metadata. There is no public constructor,
mutable accessor or standalone approval inlet. The original account-owned SDK
lease remains required for a new invite; Engine preparation revalidates the same
protected accepted/confirmed origin and exact predecessor in its atomic unit.
This observation does not authorize history, native enrollment, another member's
approval or restoration of an expired/cancelled continuation.


### Experimental predecessor artifact

With `experimental-device-sync`, `export_settled_device_predecessor` exports
actual signed MLS GroupInfo with its ratchet tree only after fresh protected
all-leaf settlement validation in the same read snapshot. The bounded artifact
is at most 256 KiB. Storage errors propagate; ordinary, unfinished or denied
lineage does not qualify. OpenMLS includes its standard external public key
extension; these transport bytes contain no SDK permission and cannot admit
an external commit or replace the dedicated private Add/Welcome path.

Portable OpenMLS public-tree verification must use isolated scratch storage,
never the account's MLS storage. It authenticates the signed tree, not remote
protected SQL provenance, explicit sibling approval or the secret epoch
authenticator. Recipient enrollment still requires a separately reviewed
original-SDK-context-bound artifact digest, every existing leaf's explicit
approval, exact purpose ownership and actual successor validation. This API
is not yet forwarded to Session, bindings or native applications.


Portable predecessor validation (`validate_private_device_predecessor`) uses a
fresh scratch `MemoryStorage` and real `PublicGroup::from_external` authentication.
It requires exact TLS framing, at most 256 KiB, 1..128 canonical occupied leaves,
Current profile and per-leaf account proof, exact required F574 payload, and exact
known account/group/epoch/indexed signer expectations. Its opaque result contains
only authenticated public metadata and the artifact digest; it has no constructor,
serialization or admission authority. Never install scratch public state in
account storage or infer completed settlement, sibling consent, secret epoch
authenticator or an enrollment grant from this result. Tests additionally use
actual signed ordinary/Legacy/mixed-account/wrong-payload trees, not positive
approval rows. No Session/native export is provided by this checkpoint.

## Private enrollment-request metadata inlet (experimental)

Kind 38175 / `whitenoise.experimental.enrollment-request.v1` is a separate private, default-off control. It does not reuse capture 38173 or settlement 38174. `ingest_private_enrollment_delivery` accepts newly delivered encrypted input through the same audited MLS ingest pipeline; ordinary ingest, history and reconstructed rows supply no fresh eligibility. Metadata is sealed from actual Member source and Current/F574 tree plus freshly validated Completed predecessor, then queued only after the crypto/disposition/projection transaction commits. It supplies no enrollment consent, SDK admission, artifact validation, protected sibling transition, native API or chat/history grant.

The intake has at most 128 exact live identities and 128 opaque observations. Its initial 600-second monotonic observation deadline is not SDK consent, never renews on retry or drain, and is not serialized. Request correlation nonce is metadata only; enrollment nonce remains the original SDK context nonce. Queue overflow is typed/transient and commits no positive disposition. Unpersisted expired identities remain bounded negative-only until exact terminal classification or owner close; only durable/obsolete entries can be reclaimed without renewing a clock. `drain_authenticated_enrollment_requests` is fallible, and proofs have no Clone/Serde/constructor. Ordinary account routing has not been wired to this dedicated live inlet.

Exact encrypted request content aliases share the earliest original observation deadline under one intake lock. Created/retryable expired rows retain that negative clock until terminal classification; a new transport wrapper cannot renew it. This is metadata freshness only, never SDK approval.


### Original-owner local enrollment proposal

The experimental Core API `prepare_private_enrollment_proposal` takes an actual
private group and recipient KeyPackage under an installed trusted owner policy.
It derives a bounded v2 declaration from the fresh completed predecessor and
returns an opaque, nonclone local continuation. `wrap_private_enrollment_proposal`
encrypts once and preserves exact retry bytes while the original Core, policy
and lease remain live. Reopening with the same policy cannot use the old owner,
and teardown invalidates it even if the lease remains allocated.

The default lease metadata accessor refuses this operation. The isolated Core
tests inject policy; App's genuine SDK producer and automatic publication remain
separate work. A wrapped declaration is metadata, not sibling approval, Add or
recipient admission. See `docs/device-sync-local-proposal-verification.json` for
actual regression counts and limits.

### Received-request endorsement ownership

`validate_private_enrollment_request_predecessor` verifies the exact GroupInfo signature under the occupied MLS request carrier, after portable tree authentication. The opaque received request retains its original protected origin and Completed selection generation. A replacement Completed round, even with an unchanged tree, denies both first endorsement and later handoff. `OwnedEnrollmentEndorsement` also retains the original Engine identity, cancellation generation and observation deadline. Packets remain signature metadata; they cannot recreate the owned action or permit an Add.

The portable all-leaf signature fixture signs A's public packet with its actual key and exercises B's genuine received action. It explicitly rejects passing B's opaque observation into A's action; it does not qualify an original-SDK A approval. Focused evidence is in `docs/device-sync-b-endorsement-verification.json`.

The default-off Core endorsement transport uses kind38176. The original B action
retains one MLS ciphertext and exact wrapped transport for retry; SQL failure
rolls back the send ratchet, and cancellation wakes a stalled wrap. Fresh intake
produces an opaque authenticated receipt without a chat event. A can sign its own
approval and verify all occupied leaves only through its original local proposal
lease, under the same protected selection. The result remains metadata; these
Core methods do not perform App publication, Add admission or ABC settlement.
