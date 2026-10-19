# storage-sqlite

SQLCipher-backed implementation of the `cgka_traits::StorageProvider` aggregate, plus the app-facing projections and
durable account state that live in the same encrypted account database. Read this if you open, migrate, or reason
about Marmot's on-disk state.

Marmot metadata tables and a custom OpenMLS `StorageProvider<CURRENT_VERSION>` share one SQLite connection on purpose:
group snapshots and rollback must be atomic across Marmot records and group-scoped OpenMLS state.

## Contents

- [Layout](#layout)
- [Operational boundary](#operational-boundary)
- [Migrations](#migrations)
- [Experimental synchronized history](#experimental-synchronized-history)
- [Experimental device linking fences](#experimental-device-linking-fences)
- [Recovery semantics](#recovery-semantics)
- [Conversation reads](#conversation-reads)
- [Account recovery ledger](#account-recovery-ledger)
- [Tests and benchmarks](#tests-and-benchmarks)

## Layout

- `connection.rs` — SQLCipher keying, connection setup, options, and the aggregate `SqliteAccountStorage` handle.
- `storage/` — Marmot engine tables by concern (groups, messages, snapshots, outbound intents, Welcomes, capabilities,
  convergence policy and passes, deferred-peel generations, maintenance, transport routes, and more).
- `openmls_storage/` — the custom OpenMLS adapter (`provider.rs`, `value_store.rs`, `labels.rs`).
- App-facing projections and account state: account event projection, chat list (including avatar URLs), the
  materialized timeline and conversation opening, message drafts, attachments, avatar cache, encrypted-media secrets,
  account recovery, delivery spill, transport reconciliation, user blocks, and more.
- `shared.rs` — `SqliteSharedStorage`, a separate, non-account-scoped database for cross-identity state: the
  public-directory user cache and presentation, relay-telemetry, usage-diagnostics and audit-log settings, and the
  telemetry install id.
- `migrations.rs` + `migrations/` — account/session migration runner and numbered bodies; `shared/migrations.rs` —
  the independent shared-store runner.

The complete module map is in [`AGENTS.md`](AGENTS.md).

## Operational boundary

Callers provide a non-empty raw SQLCipher key. The crate applies it and verifies the database opens, but never derives,
rotates, escrows, recovers, or prompts for keys; those policies belong to the account/session layer above.

One database belongs to exactly one Marmot account-device identity. Separate encrypted files per account/device make
deletion and account separation straightforward and avoid cross-identity state sharing.

Default connection settings are privacy/durability oriented:

- raw SQLCipher key provided by the caller
- `journal_mode=WAL`
- `synchronous=FULL`
- `busy_timeout=5000`
- `foreign_keys=ON`
- `secure_delete=ON`
- `temp_store=MEMORY`
- `trusted_schema=OFF`
- `cipher_memory_security=ON` process-wide; Android reports a once-per-process `platform_limited` diagnostic because
  its finite `mlock` budget makes memory residency best effort, while SQLCipher still sanitizes allocations on free

Override with `open_encrypted_with_options` or `in_memory_with_options`. There is no first-class key rotation: create a
new encrypted database, migrate data, and replace the old file.

Long-lived connections are closeable so a host can release file locks before suspending; closing is terminal and
surviving clones return `StorageError::Closed`.

The shared store is unencrypted and owner-only, with WAL, `synchronous=NORMAL`, a 5-second busy timeout, foreign keys
ON, `trusted_schema=OFF`, `temp_store=MEMORY`, and terminal close. See the
[app storage boundaries](../../docs/marmot-architecture/further-context/app-sqlite-storage-boundaries.md).

## Migrations

Account/session schema changes are Rust migrations: the ordered registry lives in `src/migrations.rs` and bodies in
numbered files like `src/migrations/0001_initial_schema.rs`. Each has a monotonically increasing version, a matching
padded name, and an `apply` function run inside a SQLite transaction, which can execute DDL, rewrite rows, or perform
larger data-shape changes. Applied migrations are recorded in `cgka_schema_migrations`; opening an encrypted database
applies missing migrations after SQLCipher keying and before storage handles are exposed. Message rows follow
[storage format v2](../../docs/marmot-architecture/storage-format-v2.md).

The three app database categories have independent histories. The account database
additionally uses a separate experimental schema ledger; no runner reads another
database's ledger:

| Database | Ledger |
| --- | --- |
| `session.sqlite` (per account-device) | `cgka_schema_migrations` and `cgka_experimental_device_sync_schema_migrations` |
| `app-cache.sqlite3` (per account, owned by `marmot-app`) | `app_cache_schema_migrations` |
| `shared.sqlite3` (per installation) | `shared_schema_migrations` |

**Experimental device sync.** Core migration numbers follow the selected upstream
ledger (currently102). Private revisions1–8 have an independent ordered registry;
the frozen bodies retain their original file prefixes103–110. Opening a recognized
old draft database atomically transfers its exact receipts into the private ledger,
retaining original version/name/time in
`cgka_experimental_device_sync_migration_bridge_audit`. Exact private schema
objects, prefix identity and audit bindings are checked. Each bridged receipt has an
immutable legacy-origin tag; audit and receipt update/delete/replace attempts are
rejected, and every tagged receipt must retain its exact original audit row.
The legacy version>102 recognition is valid only for this selected core102 base;
future upstream103 adoption requires a separately reviewed bridge. Unknown/mixed receipts,
missing denial triggers and unsupported future private revisions fail closed.
Bridge, core/private DDL and receipts commit together. A permanent negative
cohort marker activates atomically on insertion into any private data table;
cleanup cannot clear it. Default builds refuse old private lineage and activated
cohorts before migration writes, while ordinary empty additive schemas reopen.
The marker is never consent or a grant. No archive, crypto, consent, lineage, or
publication-state rows are reinterpreted. A namespace is not permission
for stock/older cores to operate on this database: isolated cohort storage and
no downgrade remain mandatory. This isolated f8b checkpoint does not resolve
upstream membership integration or authorize native cohort rollout.

**Shared store.** Version `1 / 0001_shared_store` establishes the five original live tables (frozen in
`shared/v1.sql`); later versions add usage diagnostics and directory presentation. Each body and its ledger row commit
in one immediate transaction; failure rolls back both. Recorded versions and names must be an exact prefix of the
compiled registry, and future versions return `StorageError::UnsupportedSchemaVersion`. A pending opener rechecks the
prefix under the write lock; an already-current opener validates history using reads only.

Unversioned shared tables must match frozen current or verified historical definitions (`shared/legacy.sql`) before
adoption. Validation covers columns, types, nullability, defaults, primary and foreign keys, CHECK expressions,
collations, and indexes. Conservative DDL comparison can refuse equivalent but unrecognized SQL; incompatible shapes
fail with static errors and no version row. Missing tables are created. Public users, ordered follows, live settings,
timestamps, installation identity, and rowids are preserved. Existing unused directory tables stay untouched, and
their pre-existing orphaned rows do not gate adoption. The recognized nullable `otlp_endpoint` column (inline or
appended) is retained but non-NULL values are cleared transactionally; retained audit `data_mode` columns stay inert.
No full-data audit mode is reintroduced. SQLite errors keep extended result codes and transient BUSY/LOCKED
classification without SQLite's database-controlled message. Fixture provenance and assurance limits:
[`src/shared/fixtures/README.md`](src/shared/fixtures/README.md).

Account-database compatibility fixtures are described in [`fixtures/README.md`](fixtures/README.md). Old binaries
refuse an upgraded schema; downgrading a binary requires a pre-upgrade backup.

## Experimental synchronized history

Private revision17 adds a separate paired-source chat catalog. The default-off
`MirroredChatCatalogStorage` capability accepts bounded pages only after the
trusted original policy owner validates before work and before SQL commit.
Configured account and local signer must match. Canonical group IDs distinguish
same-title chats; exact retries are idempotent, conflicting sequences are refused,
and retained Left/Deleted observations cannot become Active under the same scope.
The catalog never writes live MLS groups or membership. Paging returns
observations, not consent. Limits are 128 entries per page, 128 retained scopes
and 8,192 retained rows, including terminal references. Database reopen does not
restore a channel, approval or permission. Automatic transport and normal app
projection remain separate integration work.

Private revision27 adds an indexed, optional source-attested direct-peer account
for resolving an existing paired-source conversation. Reads accept only the
caller's freshly validated scope set, retain live-catalog departure/terminal
fences, and return source provenance without creating MLS membership. Legacy
records remain unknown; migration does not infer a peer from titles or content.

The default-off `experimental-device-sync` feature exposes a bounded account-history archive importer on
`SqliteAccountStorage`. This storage integration is not a pairing protocol, a continuous replication journal, or an
end-to-end multi-device client implementation. The caller must authenticate the device-group roster, user consent,
source and recipient device identities, and complete manifest before admitting a transfer. SHA-256 bindings here
check the admitted manifest and chunks; they are not signatures or enrollment proofs.

Archive records retain opaque logical bytes and source-device/transfer provenance in separate tables. Import never
creates engine messages, marks messages processed, writes live app events, advances recovery cursors, or applies
membership or moderation changes. Reads return completed transfers only, with live authenticated app events taking
precedence. Client presentation and export are deliberately not integrated yet.

A manifest binds account, group, source and recipient devices, transfer identity, snapshot timestamp ceiling, ordered
chunk digests, and receiving retention policy. The snapshot timestamp ceiling bounds record timestamps; it is not a
replication sequence checkpoint. Imports commit each bounded chunk and its retry receipt atomically. Completion alone
publishes records, tombstones and retention-fence intents. Callback cancellation rolls back the current chunk;
explicit cancellation permanently fences an incomplete transfer and removes its staged payloads. Both receipts and
cancellation fences survive encrypted close/reopen.

Private revision14 adds a compact version1 transport archive and ordered fragment
staging. The logical record/chunk integrity encoding stays unchanged; transport
payloads use canonical base64. A captured request digest, exact archive digest,
source/recipient/account/group binding and recipient retention policy are immutable.
Each fragment is at most1,536 bytes; the entire archive is at most196,608 bytes
and128 fragments. Oversized archives must be rejected before recipient consent,
without truncating records. Intermediate receipts report durable `Staged` only.
The final `Imported` receipt, complete logical import, retention effects and
fragment payload retirement share one SQL transaction. Exact retries retain the
original receipt; the older logical importer also refuses archive-reserved or
cancelled transfer IDs. Changed scope/body, out-of-order fragments and noncanonical or
corrupt archives are refused. Permanent cancellation clears unfinished payloads;
completed imports remain. The128 lifetime staging references include terminal
rows, and encrypted reopen never restores original consent or its deadline.

Receiving retention can shorten source expiry or require expiry when an exporter omits it. Overlapping immutable
records converge to the earliest local expiry, and retention fences prevent replay resurrection. Conflicting logical
bodies fail without exposing contents. Reads use bounded keyset pages.

This initial archive implementation caps admission at 128 lifetime transfers per account database, each with at most
128 chunks of 200 records and a 1 MiB encoded chunk. Current retained record bytes are capped at 512 MiB; cancellation,
pruning and completed tombstones release that payload quota. Permanent manifest/receipt/fence metadata remains
bounded by archive admission and is not recycled. Continuous syncing still needs a separately reviewed monotonic
journal checkpoint and authenticated receipt/fence compaction lifecycle; restarting with arbitrary new transfer IDs
is not that lifecycle.

Private revision1 (formerly provisional core103) creates the additive archive schema in every build, independent of the experimental API feature.
Opening an existing database upgrades its schema even with the feature off. Do not run an older core against that
upgraded database; reverting the binary requires a pre-upgrade backup. Tests use only synthetic in-memory stores and
temporary encrypted files, never production account storage.

## Experimental device linking fences

The default-off `experimental-device-sync` feature also exposes device-local
verification attempt storage. Migration 104 creates its additive schema in every
build. Keep experimental account databases isolated: do not reopen them with an
older core that cannot read the upgraded schema.

The runtime reserves a checked monotonically increasing local generation before
any verifier offer. One singleton row belongs to the account and independent local
device identity; further reservations require a terminal prior attempt. The final
context nonce/digest and opaque SDK flow are immutable, with exact retries allowed.
Every command checks the current generation. Old attempts cannot replace a current
binding or turn a terminal cancellation into successful verification. Generations
fail closed on integer exhaustion; the row does not impose a lifetime pairing-count
limit or grow with peer-supplied nonces.

`abandon_device_linking_on_startup` is an explicit account-runtime startup hook,
called before constructing or restoring a linking flow. It changes pending
Reserved/Bound/Flow attempts to RestartAbandoned. Do not call it merely when an
additional storage handle opens during an active attempt. Ephemeral verifier keys
are not stored, so restart requires a fresh context and verification exchange.

`PairingVerified` records only a verifier-owned terminal fact. It does not prove
Marmot membership, an accepted Welcome, settled roster authorization, or permission
to import history. The trusted runtime must validate the local device identity,
cryptographic input, and those independent enrollment gates. Storage never writes
live app events, MLS evidence, or roster state for these facts.

## Recovery semantics

**Retained anchors** are engine/group policy, not hidden SQLite policy. `max_rewind_commits` defaults to `5` when no
group policy is stored, and the engine persists negotiated policy bytes per group. Retained anchor snapshots are pruned
after successful stable canonicalization advances the tip. Invalidated message records are kept as audit/debug
evidence so applications can decide whether to surface them.

**OpenMLS proposal queues** are recoverable cached state. If `queued_proposals()` finds a `ProposalQueueRefs` entry
whose `QueuedProposal` is missing (a dangling ref) or undeserializable (truncation, partial write, format skew), the
backend clears the whole proposal queue for that group and returns it empty. It never loads a partial subset: a later
commit must start from current MLS group state and require proposals to be re-enqueued. Only deserialize failures are
treated as recoverable; SQLite/lock failures propagate so a transient fault is never mistaken for corruption.

**Bounded raw-event paging.** `app_messages_page(query, after)` reads forward in
the local `(recorded_at, message_id_hex, insert_order)` replay order. Supply
`Some(1..=128)` as the limit and continue with the last record's `replay_cursor()`.
Group/kind filters apply before the limit; at most 128 kind filters are accepted.
Unlike the existing newest-window query, this can traverse older retained history
without an unbounded read. Invalidated and expired rows remain available for
authenticated source export. This cursor is local durable observation, not peer
ordering, complete coverage or authority. Callers must re-scan changed retention
and late older inserts, validate source authority, and bound encoded payload bytes.

**Replay-state validation.** `group_replay_state_fingerprint` takes a consistent read of live canonical/OpenMLS state
(as a state-scoped snapshot) plus all retained snapshot/checkpoint bytes and epochs. It excludes live message,
outbound, and app-projection rows, which the engine validates separately. The fingerprint stays in engine memory and
is never logged or persisted. It lets resumable reconstruction ignore unrelated writes through another app connection;
the `mls_write_generation` contract for cached `MlsGroup` objects is unchanged.

**Deferred recovery preparation.** `MessageStorage::list_deferred_message_metadata` preserves insertion order and exact
encoded payload lengths while omitting payload blobs. The engine uses it for sweep preparation and readiness, then
fetches full records only for selected attempts, retirement, or bounded lifecycle normalization. Legacy format-1 rows
still need their record blob until bounded promotion converts them. The default trait implementation remains
compatible with other backends.

## Conversation reads

`conversation_open` composes a bounded canonical timeline page with retained read state in one read-only snapshot,
supporting first-unread/latest opening and scoped anchor recovery; dirty projections return `ReadStateNotReady` for the
existing owner to refresh. `conversation_window` adds explicit context placement around a retained anchor (latest
targets always read the tail). `conversation_account_snapshot` captures that window, system provenance, presentation
inputs, draft descriptors, and persisted controls in one deferred read. `StorageProvider::with_read_snapshot` composes
public storage calls under one deferred transaction, enforcing and restoring SQLite query-only mode even when nested.
See the [opening contract](../../docs/marmot-architecture/further-context/conversation-opening.md).

Selected composer reads and revision-checked mutations share the encrypted draft tables; migration 0073 tracks legacy
writes too, and queued/fanout acceptance clears only its submitted revision atomically. See the
[draft contract](../../docs/marmot-architecture/further-context/conversation-drafts.md).

The [local avatar storage contract](../../docs/marmot-architecture/further-context/avatar-cache-storage.md) covers
account-encrypted bytes, generation-scoped references, atomic publication, offline local reads, bounded eviction, and
durable acquisition intent; selected presentation and source demand commit together.

## Account recovery ledger

`account_recovery.rs` and `account_recovery/` own the durable account recovery ledger, evidence import, and retry
reservations. The app-side owner supplies validated facts and owns execution policy. Design:
[account recovery](../../docs/marmot-architecture/further-context/account-recovery.md); ownership history: the
[#1946 ownership design](https://github.com/marmot-protocol/mdk/blob/9489bb091/docs/marmot-architecture/further-context/account-recovery-ownership.md).

- **Loss evidence.** The overflow marker task writes loss evidence only; the owner imports it transactionally. A NULL
  imported count means not yet imported, including a valid zero-count loss marker. Zero-count loss is evidence.
- **Reservations.** Attempt reservations fence selected demand and imported loss, survive reopen, and refuse unknown
  scope versions. They do not certify coverage. Repeated serialized callers reuse the explicit-history row without
  resetting retry, and a stale detach cannot clear the current caller's urgency.
- **Frozen scopes (`account_recovery/plan.rs`).** Versioned frozen scopes accept owner-validated endpoint/admission
  checkpoints. History requires all designated scopes/endpoints; exclusions, EOSE, and SDK seen state are insufficient.
  Known-event retention and the limited first maintenance boundary use separate predicates. A stale scope token
  rejects a multi-scope checkpoint before any progress is written. Domain updates may share one `with_transaction`.
- **Loss acknowledgment (`account_recovery/loss.rs`).** Qualified loss completion is separate from external plane
  acknowledgment. Capture exact token/count watermarks before execution; after qualified completion, acknowledge the
  matching live generation and finish its writers before calling `acknowledge_recovery_loss`. The runtime uses
  `recovery_loss_snapshot` / `acknowledge_recovery_loss_snapshot`: a constant-size SHA-256 commitment to the complete
  ordered token/count set, streamed under the connection lock, so unbounded unresolved evidence is never copied into
  active grants, capped, or deleted. Both forms share the same transaction and revision/qualification checks. SQL
  cannot establish the external acknowledgment prerequisite. New evidence or a persistence failure prevents
  reclamation; the owner must compensate the live acknowledgment and call `restore_unacknowledged_recovery_loss`
  before new work, and also when constructing an owner.
- **Legacy adapters.** Legacy clear methods are caller-directed retirement adapters, not completion proofs; retained
  legacy watermarks do not recreate explicitly retired demand. Token-only overflow retirement records a per-token
  retired watermark separately from import: clearing one token restores other joined generations and returns `false`
  while loss remains, preserving the runtime's pending flag across reopen. Late duplicate writers cannot resurrect a
  retired generation; increased counts can.
- **Comparison plans.** Format-1 plans still accept the retired optional `live_since_seconds` field from older
  databases, but recovery ignores it and new writes omit it. A normal settlement rewrites a legacy plan without
  changing its fence, route scopes, retry cost, or uncovered demand. Other unknown fields and malformed legacy values
  remain errors; no schema migration or plan-format change is required.
- **Inventory revision.** Inventory expiration, compaction, message release, and route/group deletion bump the account
  inventory revision in the same transaction; reservations and plan installation check it. Installed proof is
  invalidated only for overlapping route/window scopes (and the exact event for known-event predicates), so unrelated or
  out-of-window retention churn cannot invalidate bounded completion or loss acknowledgment. Removing the last
  qualified proof reopens satisfied demand in the same transaction without forgiving account retry cost; an
  alternative known-event copy or independent maintenance boundary remains valid. Receipt release records scoped
  invalidation before deleting inventory; consumption falls back to conservative invalidation only if neither
  inventory bounds nor that durable flag exist (including journal rows migrated from older schemas). No-op admission
  never scans recovery scopes, and idempotent deletes do not invalidate proof.
- **Retention.** `retained_recovery_event` checks exact route, event, and frozen window membership after the caller
  synchronizes release receipts; it does not certify successful decryption or engine readiness. Completed known-event
  rows need owner-managed reclamation once no ticket or grant can reference them. An unbounded `since = None` includes
  older retained input, so its retirement must invalidate proof. The owner must use finite automatic goals, preserve
  uncovered older-history debt, and never silently clip an explicit full-history request to the retention floor.
- **Migrations.** 0092 replaced the overflow and epoch-demand tables while keeping their Rust storage methods as
  adapters; 0093 added the route-policy snapshot, a unique explicit-history row, and a receipt-journal invalidation
  flag, preserving populated obligations, loss evidence, retry state, receipts, maintenance, inventory, and cursors.
  Unexpected duplicate explicit rows make migration fail atomically; no demand is silently discarded. Later
  migrations add stall observations, recovery comparison, the loss `created_at` bound, and history notices.

## Tests and benchmarks

```sh
cargo test -p storage-sqlite
just bench-storage-upgrade   # ignored file-backed format v1 -> v2 operational benchmark
```

**Deferred recovery preparation benchmark** (opt-in, paired, encrypted temporary files):

```sh
MDK_DEFERRED_PREPARATION_BENCHMARK_OUT=target/deferred-preparation.json \
  CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false cargo test --release --locked -p storage-sqlite \
  --lib deferred_metadata_file_backed_benchmark -- --ignored --nocapture
```

It generates 0/4,096 processed and 0/64/512/2,048 deferred rows with 4 KiB payloads over 17 epochs, includes
persisted lifecycle fields, alternates query order, and writes ten warmed samples (after two warmups) to the requested
private JSON file. Reported blob bytes count full-record values materialized in Rust, excluding SQLite pages, metadata
values, and filesystem cache. It measures storage enumeration, not retained MLS context construction or scheduler
wake pressure, and asserts no timing threshold. A 2026-09-06 local run with 4,096 processed plus 2,048 deferred rows
took about 29.8 ms for the full-row query versus 15.1 ms for metadata, avoiding 8 MiB of payload copies per query. The
query still enumerates all deferred metadata so an unattempted row beyond a previously attempted prefix stays visible.

### Experimental accepted-Welcome receipts

Migration 105 adds immutable facts for fully accepted Welcome joins. With
`experimental-device-sync`, SQLite exposes the optional
`AcceptedWelcomeStorage` capability. The engine writes the exact transport and
peeled-content IDs, group, consumed KeyPackage reference, own and authenticated
welcomer account/signature keys, joined epoch, and a SHA256 commitment to the
joined epoch authenticator in the existing atomic join transaction. Supported
write failures roll back the entire join, including private KeyPackage consumption.
Exact retries are idempotent; conflicting records cannot replace earlier facts.
Group IDs, KeyPackage references, and signature keys use explicit variable-length
bounds. No exporter secret or replay-state fingerprint is stored.

Unsupported backends and feature-off SQLite expose no receipt capability. A
receipt is accepted-join evidence, and grants no enrollment, roster settlement,
messaging, or synchronized-history authorization. Imported archives cannot
write it. The engine read accessor checks live-group hydration/quarantine before
returning a found fact. Reset or later branch changes require fresh gate checks;
a historical receipt never proves the current roster.

Private revision3 (formerly provisional core105) is additive and applied even with the feature off. As with the other private revisions,
keep a pre-upgrade backup and do not run an older core against the upgraded
database. Tests use isolated synthetic databases only.

Receipt rows remain immutable historical facts across group deletion and rejoin;
there is no group foreign key that silently rewrites their lifecycle. A query
through the engine refuses a deleted, unhydrated, or quarantined group. If a later
copy rejoins the same group, its new receipt coexists with older ones; an old
receipt remains historical evidence only. The future enrollment owner must bind
the exact expected Welcome to its current pairing generation and independently
check the current authoritative per-leaf roster/branch. It must invalidate pending
readiness across deletion, removal, rejoin, or branch changes. Merely retaining or
reading any receipt can never reopen those gates.

Experimental schema 106 adds one generation-owned private-linking KeyPackage
metadata row per account-device, separate from public key publication slots.
The optional storage capability is default-off; factory and retirement writes
share the private OpenMLS bundle's transaction. Creating the package precedes
freezing the canonical context, which includes its exact bytes/reference. The
frozen nonce/digest must equal the current durable verifier attempt. Unconsumed
ownership prevents a new reservation, including after verified-but-unjoined
pairing. These records and terminal verifier facts never authorize a Welcome.
The trusted runtime must supply a live ephemeral verification lease, with its
original deadline; accepted receipt and consumption are committed atomically.
The additive migration also runs when the feature is off. Do not open an
upgraded database with an older core. No production databases were used here.

### Experimental roster ACK capture (schema 107)

The default-off `experimental-device-sync` capability stores one locally selected
same-account group/round and at most 128 occupied-leaf ACK facts. Its checked
local generation replaces the current round rather than accumulating an
unbounded peer-nonce ledger. Version-1 state/fact artifacts retain public scope
metadata only. An exact prepared MLS ciphertext (at most 16 KiB) commits with
its sender ratchet before asynchronous transport wrapping. The final bounded
publication and ordinary sent-content markers commit together and clear the
prepared slot. Current source-epoch/tree bindings and the original selected
round must agree before the private engine can write a receive fact; a public
`SourceLeafProof`, copied application event, or synchronized archive is not an
input to that constructor.

This is fact capture, not a settled roster or an authorization store. There is
no approved-leaf consent anchor, complete ACK barrier, history/chat grant, or
continuous replication journal here. A locally stable candidate, SQL verifier
fact, accepted-Welcome receipt, or these ACK records alone grants nothing.
Remote challenges cannot allocate a capture scope: a responder must explicitly
select the same local group first. Replacing the local round retires old facts;
reopening preserves the selected round, while deleted, incompatible, or changed
live groups cannot yield current capture facts. The capture remains bounded even
when a group is deleted because there is only one account-device singleton.
An actual adopted epoch/branch transition or local group deletion permanently
invalidates that round and purges its facts and prepared publication. Returning
to its old tree cannot revive it; only an explicit fresh local selection creates
a new generation. Read-only branch probes and snapshot restoration do not grant
or reset this denial. Stored-replay parity is a separate acceptance requirement;
direct-ingest coverage alone does not establish it.
Selected apply examines at most 128 additional policy-admitted inputs from its frozen
selection for private controls. Each uses a fresh MLS object and a temporary
canonical-state snapshot within the outer SQL unit. A nonprivate or invalid
attempt explicitly restores its ratchets and releases that snapshot, retaining
the ordinary disposition; nested transactions alone are not savepoints.
Only genuine receiver classification can
produce the private handled identifiers that suppress application invalidation.
This bounded scan can leave a capture incomplete; overflow is never evidence of
settlement. Complete branch-selection coverage and a complete ACK barrier remain
separate acceptance requirements.
Earlier epochs or permanently invalidated rounds can classify authenticated
private controls only to suppress ordinary application invalidation. They derive
no leaf authority, apply no capture effects, and cannot write facts or reset the
round. Losing-branch and beyond-policy inputs are excluded from this scan.

Migration 107 is additive and unconditional, including feature-off builds.
Never run an older core against an upgraded account database. Tests use isolated
synthetic SQLCipher databases; no existing account database is opened for this
experiment. Private control framing is explicitly experimental and does not
adopt new Marmot wire identifiers, conformance values, or protocol versions.

### Experimental private-group birth provenance (migration 108)

The unconditional additive migration creates one selected birth-provenance row with immutable account/device scope and a checked locally assigned generation. Runtime capability access is default-off behind `experimental-device-sync`. The protected core factory supplies actual creation metadata within the same transaction as new MLS values and the group projection; the storage DTO alone is never permission or proof of SDK approval.

Birth bytes remain immutable for the selected lineage. Explicit retirement, actual adopted-tree changes, and group deletion set permanent denial without erasing birth. Crypto snapshots do not restore this denial state. A fresh explicit selection replaces the retired row with a checked next generation, keeping the store bounded rather than retaining unlimited historical selections; old generation commands reject. Completed origin can be revalidated against actual original crypto state after reopen, but pending verifier permission is never reconstructed. Accepted successor selection (migration 109) remains distinct. Do not run an older core against an upgraded database.


## Experimental accepted device-group anchors

Schema109 stores one account-device selected accepted-successor fact separately
from immutable local genesis. The default-off storage capability records the exact
purpose scope, contextual binding, KeyPackage/Welcome digests, canonical
predecessor and successor indexed rosters, and a checked local selection
generation. Exact retries retain identity; denial and group deletion permanently
fence that generation. Installation rejects an active local genesis selection and
retained owner identity changes. Fresh selections require a newer local pairing
generation and keep storage bounded without a lifetime allocation cap.

These are trusted-core persistence inputs, never native or wire DTO ingestion.
The backend participates in the enclosing cryptoSQL transaction but does not
verify SDK consent, prove the original MLS acceptance, settle the roster or grant
chat/history access. Actual trusted Welcome integration remains required.

## Experimental outgoing device invites

Provisional migration110 separates the bounded pending Add from the last confirmed
successor. The optional `experimental-device-sync` storage capability binds raw
Commit/Welcome digests, exact origin and pairing generations, canonical indexed
rosters and cached transport bytes. Exact retries reuse the staged identity;
retiring an undispatched next invite preserves the previous confirmed anchor.
Dispatch intent and uncertain publication prevent ordinary retirement or
replacement. Confirmation requires the exact successor and updates both slots in
one transaction; it cannot clear denial of a confirmed origin.

Unresolved raw/wrapped/dispatched/unknown work blocks a new pairing generation
and allocation of a replacement genesis or accepted selection. An active
confirmed lineage also blocks replacement selection. Exact retries of an existing
accepted fact remain read-only and preserve pending work. These fences do not
perform startup cleanup or reconcile uncertain publication.

These methods store trusted-core facts. They do not authenticate a supplied MLS
tree, recreate SDK approval, establish complete roster settlement or make a cached
Welcome deliverable. The Engine/App coordinator must supply genuine evidence and
retain the original consent deadline. Actual private Add, publication integration,
restart reconciliation and adopted-tree denial remain integration requirements.
The migration numbering is unpublished and conflicts with upstream's proposed
history-acquisition migration103; reconcile the ledger before native artifacts.

The unpublished110 wrapped artifact now freezes an ordered `welcomes` batch:
1–86 messages, unique bounded transport IDs (including the commit), exact Welcome
account envelopes and a 16 MiB total JSON ceiling. Chunk count follows the pinned
private transport's 24 KiB resource policy for a 2 MiB raw MLS Welcome; it is not a
universal NIP44 protocol limit. The real peeler authenticates chunk indices and
context before reassembly. SQLite freezes exact output order/bytes and rejects
changed retries; these cached events remain unavailable for delivery until actual
membership confirmation. Old singleton `welcome` JSON fails closed. This local
schema110 remains provisional; no production database has been upgraded.

### Permanent experimental private-chat exclusion

Private ledger revision9 (`private_migrations/0009_private_group_chat_exclusion.rs`)
is separate from upstream core102 and the original103–110 audit. Its per-group
negative fact binds the account and local MLS device identity. Exact repeats are
idempotent; identity mismatch errors, and update/delete/replace are forbidden.
No foreign-key cascade or group snapshot restores these facts. Actual private
birth and accepted joins write them inside their crypto/metadata SQL units.
One small row remains per locally created or consented private group, including
after selection replacement or group deletion; there is no peer-driven admission
or finite lifetime attempt cap. The fact grants no membership or consent.

Upgrade backfills only existing protected selected identifiers as negative
suppression, preserving all old receipts and facts. It cannot reconstruct an
older identifier already lost before upgrade when its private marker was also
removed. Such unpublished historical cohorts cannot claim retroactive privacy
qualification. Existing strict disabled-feature cohort refusal remains active;
empty ordinary schemas continue to open normally.

Experimental anchored roster settlement is a separate optional persistence capability
(`private_roster_settlement.rs`), not generic ACK capture or authorization. It stores
one checked-generation owner-bound round, at most 128 occupied leaf facts, exact
prepared ciphertext/outbound retries and atomic last-slot completion. Completed
metadata never mints live admission; Engine must independently validate protected
origin/current tree and a fixed monotonic live round. No deadline or SDK permission
is serialized. The account owner must explicitly abandon unfinished rounds on
authoritative exclusive startup; storage does not run that lifecycle hook itself.

## Selected-chat recipient storage foundation

The private experimental profile adds independent per-chat recipient facts in
private revision12. They retain exact account/device/request ownership, bounded
public package metadata and terminal references separately from pairing packages
and group snapshots. Exact Pending retries and transaction rollback are supported;
configured identity replacement cannot reuse a retained original owner. Default
`StorageProvider` access is unavailable. Rows do not grant admission or recreate
consent. Core must separately qualify fresh MLS package creation, exact private
key cleanup and original-action guarded Welcome joining.

This foundation passes four feature tests, one default-denial test and all167
traits tests. Full backend qualification is still running. Additional SQL mutation
guards and canonical roster validation are a separate pending hardening slice.
See [focused verification](../../docs/selected-chat-recipient-storage-focused-verification.json)
for the original RED, frozen inputs, commands, counts and remaining checks.

Private revision13 adds terminal-reference SQL guards without changing the
frozen revision12 schema or receipts. Delete, replace, immutable context changes
and terminal reactivation are rejected; reservations remain bounded and
account/device-specific. Protected rosters require canonical indexed ordering.
An exact retained original owner may deny its Pending reservation after configured
identity changes, but cannot reactivate it or mint new consent. These facts never
grant Welcome permission or restore a live action.

The focused hardening regression is actual RED4/6 → GREEN6/6. Default denial1
and the explicitly executed populated encrypted-cohort refusal1 pass; traits167
pass. The latter test is normally ignored and is only qualified with its actual
feature-writer fixture. Original closed revision12 fixture bytes remain unchanged
while an upgrade copy exercises revision13. Full backend/production checks remain
pending: see `docs/selected-chat-recipient-storage-hardening-focused-verification.json`
from the repository root.

### Experimental Remove-successor metadata

Private revision16 retains up to128 immutable Remove-successor references, including
denied rows. Installation checks the exact active predecessor and Completed local
settlement, canonical single-Remove successor, and any present account/signer
projections. The authenticated Core caller must still own the original action and
actual MLS transition. Successive installation denies the preceding generation in
the same SQL transaction; insert failure rolls back that denial. Group deletion
denies retained records. Snapshot rollback cannot restore positive metadata.

The separate `PrivateInviteOrigin::Revoked` generation supports a fresh settlement
and subsequent Add while preserving old denial fences. No persisted consent, lease,
or original guard is supplied. Core integration and full workspace qualification
are required separately from the synthetic storage contracts.

Private revision 18 persists immutable explicit account/device pairing approvals
and monotonic local-source chat observations. Approval revocation is permanent;
renewed recipient-only channels do not reset the policy's source sequences.
Original-owner callbacks run before work and before the same transaction commits.
The protected epoch is retained for revocation checks, never to restore a live
permission. These tables remain separate from ordinary MLS and Group state.

Private revision 19 adds source-attested logical message storage for automatic
paired-device catch-up. Payloads are separate raw bounded blobs; no ordinary
`app_events`, MLS ratchets or Group rows are manufactured. Active catalog
observations and original-owner transaction checks guard imports. Immutable event
identity/body checks span sources; deletions and expiry cannot be undone by a
renewed policy. Chronological pages never return expired contents. Bounded purge
retains identity/digest/source sequence while releasing payload bytes. The account
payload budget is 64 MiB; lifetime references are bounded at 100,000 rows.

Private revision20 (`account_chat_send_queue.rs`) retains4096 lifetime logical
intent identities,8192 route references and32768 exact receipt outbox references,
including terminal/acknowledged rows. Active payload budget16MiB, body64KiB and
page128. Immutable canonical event/account/origin/time/digest survives clearing;
genuine Published ID must equal the ordinary event ID, never intent ID. Route
Denied is local; original-origin cancellation is global and permanent. A revoked
old route cannot be rebound under a new approval. Existing preapproved alternatives
remain independently valid. Transition+outbox and original before/tail checks share
SQL. Cursor reads are observations only; no persisted deadline/keys/permissions.
Preserve core102/private1–19 and configured account/signer/terminal-close fences.

Private revision21 provides the optional `AccountChatRecordStreamStorage`
capability. Its record counter is independent of catalog counters and chronology.
The current exact event attestation retries its sequence; changed retention facts
advance it. Canonical ordered batches are retained before publication, up to
128 records and 1 MiB each, with 64 MiB active bytes and 4,096 lifetime outbox
references. A fresh authenticated peer acknowledgment clears bytes; source
deletion/expiry/revocation instead permanently denies the batch without claiming
delivery. Neither terminal state reopens through retry.

Recipient record apply, immutable receipt and maximum observed stream sequence
commit together. Out-of-order batches remain admissible through per-event fences;
the maximum is an observation, not completeness. Exact duplicate delivery returns
the original receipt even after a fresh authenticated projection scope, while
applying observations to that scope. Retained approvals do not supply original
authority, keys or a deadline. The journal has 100,000 lifetime references and
incoming receipts/progress each have 8,192. Core102 and private1–20 remain frozen.

Private revision22 separately retains at most8,192 immutable acknowledgments
keyed by stable policy, group, canonical batch digest and authenticated peer
projection generation. An older global acknowledgment is not coverage of a new
projection generation. Generation acknowledgment and the original global receipt
commit atomically under original before/tail checks; global terminal payload is
never reopened. The read returns receipt metadata only, including absence for an
unacknowledged generation. That absence grants no replay authority: App must
freshly encode current source records through a freshly authorized channel.
Denied batches, revoked policies, owner mismatch and conflicting receipts are
refused. The lifetime budget survives encrypted reopen. Core102 and private1–21
are unchanged; no keys, deadlines, plaintext duplicates or original owners are
retained by this table.

Experimental paired-chat presentation reads accept at most128 caller-validated
source scopes and return at most128 total observations across them. Catalog
pages use canonical group order; message pages use canonical event time/ID.
Ordinary stored groups and live event identities take precedence over mirrors.
Cross-source terminal and restrictive expiry fences still hide mirrored payloads.
These read-only scopes and cursors carry no membership, consent or media grant.
`mirrored_catalog_activity_page` adds each catalog row's latest eligible message
in the same query-only snapshot, preserving the catalog page bound/order and
source deduplication, block, ordinary-identity, terminal and expiry fences.
Expired/deleted tails expose scrubbed markers; this read creates no unread state.
See `docs/account-chat-presentation-storage-verification.json` for the synthetic
storage controls; App worker and native presentation require separate qualification.

The experimental account conversation observation window selects at most128
rows total across actual ordinary timeline and eligible mirrored scopes in one
canonical event-time/ID query. Local event identity wins; block filtering occurs
before LIMIT. Materialized edits/deletions, retention and reply/media privacy
remain observational, with no canonical schema change or synthesized group.
App window and synthetic storage proof boundaries are recorded in
`docs/account-chat-presentation-app-windows-verification.json`.

Private revision23 retains ordinary-chat user-acceptance lineage separately from
MLS and presentation rows. At most8,192 lifetime origin references bind configured
account, local signer, canonical group and Created or actual Welcome origin. Each
origin progresses Pending→Accepted→Denied; denied origins cannot reaccept. Fresh
Welcome origins begin Pending, and stale observations cannot move the current
origin pointer backward. Atomic batches of at most128 changes validate their
original before mutation and again at transaction tail, allowing App projections
and acceptance to roll back together. SQL guards reject identity replacement,
regression and deletion. Local hiding does not remove lineage. These rows contain
no channel owner, consent capability, key or membership; positive source admission
still requires fresh Core and original-channel validation. Core102 and private1–22
remain unchanged.
