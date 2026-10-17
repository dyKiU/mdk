# AGENTS.md - crates/storage-sqlite

Agent map for the SQLCipher-backed storage backend. Human overview, connection defaults, migration ledgers, and
recovery-ledger contracts: [`README.md`](README.md).

## Scope

`SqliteAccountStorage` implements `cgka_traits::StorageProvider` with Marmot metadata and custom OpenMLS storage in one
encrypted SQLite database. One database file belongs to one Marmot account-device identity. `shared.rs`'s
`SqliteSharedStorage` is a deliberate exception: a separate, non-account-scoped database for cross-identity state — do
not "fix" it into the per-account database.

## Layout

The crate is split by which side owns each table; see the
[step 4 brief](../../docs/marmot-architecture/review/brief-storage-boundaries.md).

| Folder | Holds |
| --- | --- |
| `src/base/` | Connection, codec, migration runner and bodies, open progress, test support. Both sides build on it. |
| `src/protocol/` | The engine's storage: the `StorageProvider` impls (`provider.rs`), `storage/` and `openmls_storage/`. |
| `src/app/` | App storage: projections, timeline, chat list, recovery ledger, drafts, attachments, avatars, media catalog. |
| `src/app/transport/` | App storage specific to one transport (NIP-77, NIP-51, relay-plane spill, NIP-59 outbox, QUIC sequences, prepared Blossom uploads), kept together for a later move. |
| `src/shared.rs`, `src/shared/` | The separate shared database. |

Existing private feature modules retain their root paths during this integration; canonical upstream modules remain
in `base/`, `protocol/` and `app/`. Private provider hooks are implemented only in `protocol/provider.rs`. The private
migration ledger is wired by the base runner; it does not grant consent or replay authority.

Put new code on the side that owns its tables. `src/base/boundary_tests.rs` fails on any crossing between the sides
(SQL naming the other side's tables, a `crate::` path or a `self` call into the other side, or a cross-side foreign key
or trigger) that is missing from `src/cross/allow-list.txt`, and on a listed one that no longer occurs. Do not add a
line to make a change pass: code that must touch both sides goes in `cross/` once step 4 PR 3 adds it, and until then
a new line needs its reason in the PR description. A new table needs an owner in `src/base/table_owners.rs`.

## Key files

| Path | Owns |
| --- | --- |
| `src/base/connection.rs` | SQLCipher key application, operational PRAGMAs, options, aggregate handle. |
| `src/base/codec.rs` | JSON serialization helpers and SQLite error mapping. |
| `src/base/migrations.rs` | Upstream core and separate private registry, migration runner and tests. |
| `src/base/test_support.rs` | Shared storage test fixtures for both sides' tests. |
| `src/base/table_owners.rs`, `src/base/boundary_tests.rs`, `src/cross/allow-list.txt` | The owning side of every table; the boundary tests and the crossings still to move. |
| `src/base/migrations/` | Numbered Rust migration bodies plus upgrade/query-work tests; see its local `AGENTS.md`. |
| `src/protocol/storage/` | Marmot engine storage tables by concern; see its local `AGENTS.md`. |
| `src/protocol/storage/snapshots/` | Snapshot/checkpoint capture, restoration and the consistent replay-state fingerprint; see its local `AGENTS.md`. |
| `src/protocol/openmls_storage/` | Custom OpenMLS storage adapter; see its local `AGENTS.md`. |
| `src/app/account_recovery.rs` | Account-private recovery ledger, evidence import and durable retry reservations; `account_recovery/` holds typed joins, frozen scope checkpoints, loss acknowledgment and (`notice.rs`) parked "history may be incomplete" occurrences with their explicit retirement (`state = 2`, never coverage), (`stall.rs`) qualified stall observations, (`comparison.rs`) bounded operational comparison (never a coverage predicate), (`demand.rs`) typed joins for non-legacy callers, and (`observe.rs`) read-only transition facts for the owner's audit rows: a demand write's `RecoveryDemandTransition` read before and after it in the same transaction, and `recovery_obligation_status`. Transition reporting never changes demand. The app owner supplies validated facts and owns execution policy. |
| `src/app/transport/delivery_spill.rs` | Durable overflow tail of the in-memory account delivery queue: bounded spill, seen/released dedup, oldest-first reads and per-row removal after ingest. |
| `src/app/recovery_health.rs` | Durable reports of unsuccessful automatic synchronization recovery. |
| `src/app/transport/transport_reconciliation.rs` | Account-private NIP-77 set-reconciliation inventory. |
| `src/app/pending_welcome_delivery.rs` | Durable pointer to a confirmed create/invite whose Welcome publish failed, for re-delivery (mdk#352). |
| `src/app/local_submissions.rs` | Device-local submission identity and durable admission before engine work. |
| `src/app/transport/agent_stream_sequences.rs` | Durable, fail-closed publisher sequence reservations for QUIC previews. |
| `src/app/account_projection.rs` | Account-level event projection. |
| `src/app/chat_list.rs` | Chat-list projection, including avatar URLs; `chat_list/` holds attention, pages, and windows. |
| `src/app/chat_presentation.rs` | Durable selected-presentation foundation (runtime orchestration owns hydration). |
| `src/app/group_system.rs` | Local presentation of kind-1210 content (not a wire-format change). |
| `src/app/transport/user_blocks.rs` | Account-private NIP-51 block state; never stored in the shared database. |
| `src/app/transport/moderation_reports.rs` | Account-private outbox of signed NIP-59 moderation-report wraps: idempotency and rate-limit metadata, retry state, purge. Never stores the reported key or explanation in the clear. |
| `src/app/message_drafts.rs` | Revisioned encrypted composer drafts (`message_drafts/revisioned.rs`). |
| `src/app/transport/prepared_group_image_upload.rs` | Staged founding-image upload (component data + Blossom upload secret; keep both out of diagnostics). |
| `src/app/attachment_acquisition.rs` | Source-bound durable acquisition jobs, leased attempts, protected retained bytes, bounded worker demand and explicit-removal suppression. Network orchestration stays in marmot-app. |
| `src/app/attachment_acquisition/access.rs` | Read-only source-bound retained-asset lookup and opaque reference encoding; no demand registration. |
| `src/app/attachment_acquisition/controls.rs` | Durable user intent and coalesced transfer metadata in the job store. |
| `src/app/attachment_acquisition/partial.rs` | Attempt-fenced checkpoint rows: identity, recorded length, progress floor and the media store `.wire` file id (the ciphertext lives in that file, mdk#2314). Row operations only; abandoned-partial cleanup. |
| `src/app/attachment_acquisition/outgoing_media.rs` | File-backed outgoing uploads on the media store (mdk#2314 step 3): `reserve_attachment_upload`, `AttachmentUploadStage` (the upload row as the staged file's owner) and `AttachmentUploadPromotion` (the message's slot fences, attaching the file instead of copying bytes). Rows with `file_id` carry no bytes; legacy rows keep `outgoing.rs`'s promotion until they expire. No retained-byte budget. |
| `src/app/attachment_acquisition/checkpoint.rs` | `AttachmentCheckpoint`: a claimed job's checkpoint as the media store's `CheckpointTarget`. The store drives the file and the order of steps; each target call is one transaction under the job's fences. |
| `src/app/media_catalog.rs` | The account database's side of the [`media-store`](../media-store/AGENTS.md) crate: `media_files`/`media_file_refs` rows (migration 0110), the `MediaCatalog` impl, per-use `PublishTarget`s and their one-transaction ready commits, reference release. Runs the crate's catalog conformance suite. No media file I/O here. |
| `src/app/media_store_bench.rs`, `examples/media_store_bench.rs` | `media-store-benchmarks` feature: the `media-store` file format against the SQLCipher retained path, runnable on devices (mdk#2314 step 0). |
| `src/app/attachment_history.rs` | Bounded canonical attachment-slot discovery and per-group revision-fenced cursors; source/visibility triggers maintain the derived index. |
| `src/app/timeline.rs` | Materialized message-timeline aggregation; `timeline/` holds capture, edits, opening (`conversation_open` / `conversation_window`), presentation, and reports. |
| `src/app/avatar_cache.rs` | Account-scoped encoded avatar storage, source generations, local reads and eviction; `avatar_cache/acquisition.rs` owns durable demand/retry state and `avatar_cache/access.rs` owns opaque screen targets/local metadata. |
| `src/app/encrypted_media_secrets.rs` | Per-group encrypted-media secret storage. |
| `src/private_migration_ledger.rs`, `src/private_migration_ledger_tests.rs` | Single-transaction core/private upgrade, exact old103–110 receipt/schema bridge and immutable original receipt audit; no state reinterpretation or permission. |
| `src/synchronized_history.rs`, `src/synchronized_history/tests.rs` | Default-off experimental archive import with separate provenance, staged completion, bounded receipts and retention fences; never engine evidence or live app-event projection. |
| `src/mirrored_chat_catalog.rs`, `src/mirrored_chat_catalog/tests.rs` | Private revision17 paired-source sidebar observations, original-owner transaction callbacks, exact local account/signer binding and retained terminal/replay fences; never live Group rows or membership. |
| `src/accepted_device_group_anchor.rs`, `src/accepted_device_group_anchor_tests.rs` | Schema109 bounded accepted-successor facts, exact local selection/owner/purpose fences and permanent denial; separate from genesis, never SDK reconstruction or settlement authority. |
| `src/private_device_invite.rs`, `src/private_device_invite_tests.rs` | Provisional schema110 outgoing raw/wrapped/dispatch/unknown/confirmed facts with separate retained confirmed lineage, exact retries and transactional transitions. Trusted-core persistence only; never SDK consent, publication proof or native draft admission. |
| `src/accepted_welcome.rs`, `src/accepted_welcome/tests.rs` | Default-off immutable accepted-join facts in schema105; exact Welcome/KPref/signers/epoch, atomic with real join, never enrollment or settled-roster permission. |
| `src/device_group_genesis.rs` | Schema108 bounded selected immutable local birth, checked generation, account/device scope and permanent active denial; metadata never verifier permission. |
| `src/device_linking_key_package.rs` | Schema106 singleton purpose ownership, exact reserved scope and frozen context, same-transaction factory/cleanup and commit fences; never verifier permission. |
| `src/device_linking.rs`, `src/device_linking/tests.rs` | Default-off device-local verifier generation/context/flow fencing and terminal facts; no verifier secrets, roster authorization, or membership evidence. The runtime explicitly abandons pending attempts on startup. |
| `src/shared/error.rs` | Shared-store redacting SQLite error mapper and result extension. |
| `src/shared/migrations.rs`, `src/shared/v*.sql`, `src/shared/legacy.sql` | Independent `shared_schema_migrations` runner, frozen per-version schemas, and recognized retired columns. |
| `src/shared/presentation.rs` | Accepted directory profile bytes and local revision under one shared-store transaction. |
| `src/shared/migration_tests.rs`, `src/shared/assurance_tests.rs`, `src/shared/fixtures/` | Shared migration contract, populated historical upgrades and bounded interrupted-transaction recovery. |
| `src/shared.rs` | `SqliteSharedStorage`: a separate non-account-scoped database for cross-identity state (public-directory cache and presentation, relay-telemetry/usage-diagnostics/audit-log settings, telemetry install id). |
| `fixtures/` | Immutable account-database compatibility fixtures; see `fixtures/README.md`. |

## Invariants

- Accept raw SQLCipher keys only. Key derivation and recovery live above this crate.
- Apply privacy/durability defaults unless callers opt out with `SqliteStorageOptions`.
- Keep invalidated message records. Applications decide whether to show them.
- `app_messages_page` is raw local replay paging, not presentation or permission.
  Require a limit in 1..=128 and use the complete `AppEventReplayCursor` order.
  Keep invalidated/expired rows for authenticated retention export. Cursors do
  not prove coverage; older inserts and changed retention require a fresh scan.
- Prepare every database file with `fs_private::ensure_private_db_files` before `Connection::open`, and never open,
  read or copy a database or `-wal`/`-shm`/`-journal` sidecar through `std::fs` while this process may hold a
  connection to it: closing that descriptor drops the connection's POSIX locks and lets another process take the
  database under it. `connection::tests::reopening_a_live_database_keeps_its_posix_locks` guards this. See
  `docs/marmot-architecture/overview/local-artifact-safety.md`.
- Build every long-lived connection on `CloseableConnection` so a host can release the database's file locks at a known
  instant, and give its handle a `closer()` (`DatabaseCloser`, a weak reference) so a host can close it without keeping
  it open. Closing is terminal: surviving clones return `StorageError::Closed`, and nothing reopens implicitly. See
  `docs/marmot-architecture/overview/local-artifact-safety.md`.
- The media file lifecycle belongs to the `media-store` crate; this crate holds its metadata and never touches media
  files. Every `PublishTarget::commit_ready`/`commit_existing` is one transaction (fences, presence-checked reuse,
  ready, attach), and the catalog must keep passing the crate's conformance suite. Deleting a `media_files` row is the
  key erase (`secure_delete`); the file is unlinked afterwards by the store. See
  `docs/marmot-architecture/overview/local-artifact-safety.md#encrypted-media-files`.
- Retained-anchor policy is engine/group policy. SQLite stores snapshots and policy bytes; the engine decides when to
  prune.
- Follow `docs/marmot-architecture/storage-format-v2.md`: numbered schema migrations gate database compatibility;
  independently decoded blobs carry artifact-local versions; new `cgka_messages` writes use normalized format 2;
  legacy format-1 rows remain readable and promote atomically on mutation.
- Keep history-wide format promotion out of account open. The app runtime owns bounded post-readiness scheduling;
  storage owns only the atomic, idempotent batch and aggregate progress result.
- Never make `record` and normalized message columns competing authorities. In format 2, scalar columns, `payload`,
  and `deferred_peel` are authoritative and `record` is `NULL`.
- Migration file names use padded numeric prefixes, for example `0001_initial_schema.rs`. Never regenerate a
  version-named fixture with a later writer.
- Recovery-ledger, conversation-read, and replay-fingerprint contracts are stated in README.md; keep code and that text
  in sync. Never log or persist replay fingerprints.

## Verification

```sh
cargo test -p storage-sqlite
cargo clippy -p storage-sqlite --all-targets -- -D warnings
# Ignored file-backed v1 -> v2 operational benchmark:
just bench-storage-upgrade
# Media file format vs SQLCipher retained path (mdk#2314):
just bench-media-store
```

The separate experimental ledger records private revisions1–9; frozen body file
prefixes103–110 are historical and must not be adopted as upstream core numbers.
Receipt/audit rows reject update/delete/replace; immutable legacy-origin tags
require complete matching audit rows on reopen. Recognition is selected core102
only, not permission to adopt future upstream103. Keep audited receipt identity/time and exact denial/crypto/publication data
unchanged across the bridge. Test partial encrypted prefixes, schema/receipt
mismatch, mid-transfer faults, idempotence and genuine old-writer pending-MLS
reopen. The ignored Engine two-writer operational fixture requires explicitly
recorded original/new runner stages; do not count its default ignored run as proof.

Private-data insert triggers activate an irreversible negative cohort marker in
the same SQL unit. Never clear it during retirement/snapshot restore or use it
as an authorization input. Default builds refuse activated cohorts and old
private lineage before writes; empty ordinary schemas must still reopen.

`src/private_migrations/0009_private_group_chat_exclusion.rs` uses private revision9,
not upstream core111. `src/private_group_privacy.rs` owns immutable account/device/
opaque-group negative chat exclusion. Birth/join Engine writes share actual SQL
transactions; fences never enter rollback snapshots or membership/consent checks.
Backfill retained protected identifiers only; do not invent lost history or grants.

Private revision10 (`src/private_migrations/0010_private_roster_settlement.rs`)
adds `src/private_roster_settlement.rs`/`tests.rs`. Keep core102 and historical
103–110/audit unchanged. Last-slot completion, local cipher/fact and ratchets
share the caller's SQL transaction. No public DTO or persisted completion mints
a live round, enrollment consent or permission. Denied blocks positive writes;
only Pending is abandoned by explicit startup. Capability is feature-only.

Private revision11 (`src/private_migrations/0011_existing_device_group_anchor.rs`)
adds bounded `existing_device_group_anchor` metadata for guarded existing-member
apply. Install before retiring the exact active predecessor and its Completed
round, inside authenticated single-Add crypto SQL. Require exact owner, origin,
full indexed predecessor and settlement generation; preserve exact retry and
rollback. Denied generations cannot reactivate through changed action bindings
or older same-group predecessors. Ordinary selection cannot orphan an active
existing origin. Group deletion denies the retained row in its SQL transaction.
The automatic private-table trigger activates the irreversible negative cohort
marker; no metadata row reconstructs consent. Core102 and original103–110 stay
unchanged. Synthetic persistence tests are separate from genuine SDK B proof.

Settlement JSON retains at most one deferred ACK per actual remote non-coordinator leaf. Exact generation, indexed signer, message bounds and nonzero claimed nonce are checked. Deferral never binds nonce or adds counted facts; denial/startup abandonment/reselection clears it. Only trusted Core under original live admission promotes nonce-matching receipts after the genuine coordinator Challenge in the same crypto SQL transaction. Legacy JSON without the field remains readable.

`src/selected_chat_key_package.rs` holds independent selected-chat recipient facts
in private revision12. Terminal rows count toward the128-row capacity and retain
the original owner across configured identity changes. Metadata never grants
joining or reconstructs consent. Core owns exact private-bundle cleanup within
the same SQL transaction. Do not alias pairing-purpose storage or group snapshots.

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

Private revision14 adds `synchronized_history/archive.rs` and immutable bounded
archive scope/fragment receipts. Keep base64 transport encoding separate from
frozen logical chunk integrity. Exact original request/account/source/recipient/
group binding and recipient policy are required; persisted scope cannot restore
consent or deadlines. Only final Imported receipt and all logical/retention writes
commit together; Staged receipts never imply imported history. Retain128 lifetime
references including terminal rows; permanently deny cancellation and erase opaque
payloads after cancellation/completion. Activation triggers cover both new tables.
Preserve core102, original103–110 audit and private1–13 migration bodies.

The logical importer and archive staging share transfer-ID fences: public logical
admission cannot claim an archive reservation or cancelled ID. Only the private
final-archive path crosses its exact Pending scope inside the same SQL transaction.

Private revision15 retains immutable authenticated history request identities outside
group snapshots. This is a negative replay fence, never a consent/keys/deadline
restore API. Preserve account/local-device/transfer/request digest and irreversible
cohort activation; reject deletion, replacement, mutation and conflicting retry.
The cumulative account-device budget is128 including terminal requests and remains
exhausted after encrypted reopen. Do not prune or reset it silently. Exact duplicate
observation is negative; a distinct request requires fresh original authentication.
Keep revision14 prefix, default populated-cohort refusal, SQL rollback/fault, owner
identity and encrypted capacity controls. Preserve core102/private1–14 bodies.

For the upstream integration, core103–113 retain their exact upstream identities; the core102 restriction above describes the frozen legacy bridge. Preserve its single core/private transaction while using declared upstream FK scopes before BEGIN and validating affected references before commit. Delay positive core progress until the shared commit. Observer failures cannot change migration outcomes or consent.
Private revision16 adds bounded immutable `revoked_device_group_anchor` references
including denied generations. Install only before retiring the exact active
predecessor/Completed local round, within original authenticated Remove SQL.
Atomic successor selection retains and denies the old generation; failed insertion
restores it. Owner/signer projection mismatches reject, exact retry cannot reopen
a denied fact, and delete/replace/mutation/reactivation are blocked by SQL guards.
Keep all128 lifetime references outside group snapshot rollback. Group deletion
denies them; bounded historical reads are negative privacy observation only.
Core/Session/App integration, full workspace and native qualification remain
separate from the synthetic storage proof in
`docs/revoked-device-anchor-storage-verification.json`. Preserve core102/private1–15.

Private revision 18 (`approved_account_sharing_policy.rs`) retains at most 128
immutable approvals including revoked references, plus 8192 latest group-digest
observations. Counters, observations and original before/tail checks share SQL;
exact current retries retain sequence, historical bodies after changes get fresh
sequence. Never reconstruct positive original ownership or channel crypto from
facts. Preserve core102/private1–17 and configured identity/signer fences. Closed
storage is terminal; encrypted restart retains revocation and replay state.

Private revision 19 (`mirrored_chat_messages.rs`) imports already-authenticated
logical messages only under active source catalog/account/signer scope with
original before/tail checks. Payloads are separate bounded blobs; 64 MiB checked in
the same batch transaction and 100,000 lifetime references enforced on insert.
Immutable author/time/kind/content digest and global event-ID terminal fences span
source/policy renewal. Expiry only tightens. Local purge changes no source sequence
and retains identity; expired read views must never be re-exported as original
source attestations. Preserve core102/private1–18 and all receipt/cohort fences.

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

Private revision21 (`account_chat_record_stream.rs`) keeps a separate source
record journal, canonical delivery outbox and immutable committed receipts.
Logical apply, receipt and maximum observed sequence share one SQL transaction;
earlier batches still apply through per-event fences. Receipt identity is stable
policy/group/digest across current projection scopes. Source ACK and permanent
denial are distinct; both erase encoded bytes without deleting lifetime identity.
The exact configured owner may negatively retire a revoked policy's pending batch.
Limits: 100,000 journal refs, 4,096 outbox refs, 8,192 receipts/progress refs,
64 MiB active outbox bytes, 1 MiB canonical batch and 128 records. Original
before/tail guards remain mandatory; no keys/lease or permission is restored.
Preserve core102/private1–20 bodies and the irreversible cohort marker.
