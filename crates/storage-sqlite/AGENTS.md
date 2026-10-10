# AGENTS.md - crates/storage-sqlite

Agent map for the SQLCipher-backed storage backend. Human overview, connection defaults, migration ledgers, and
recovery-ledger contracts: [`README.md`](README.md).

## Scope

`SqliteAccountStorage` implements `cgka_traits::StorageProvider` with Marmot metadata and custom OpenMLS storage in one
encrypted SQLite database. One database file belongs to one Marmot account-device identity. `shared.rs`'s
`SqliteSharedStorage` is a deliberate exception: a separate, non-account-scoped database for cross-identity state — do
not "fix" it into the per-account database.

## Key files

| Path | Owns |
| --- | --- |
| `src/connection.rs` | SQLCipher key application, operational PRAGMAs, options, aggregate handle. |
| `src/codec.rs` | JSON serialization helpers and SQLite error mapping. |
| `src/migrations.rs` | Upstream core and separate private registry, migration tests. |
| `src/private_migration_ledger.rs`, `src/private_migration_ledger_tests.rs` | Single-transaction core/private upgrade, exact old103–110 receipt/schema bridge and immutable original receipt audit; no state reinterpretation or permission. |
| `src/migrations/` | Numbered Rust migration bodies plus upgrade/query-work tests; see its local `AGENTS.md`. |
| `src/storage/` | Marmot engine storage tables by concern; see its local `AGENTS.md`. |
| `src/storage/snapshots/` | Snapshot/checkpoint capture, restoration and the consistent replay-state fingerprint; see its local `AGENTS.md`. |
| `src/openmls_storage/` | Custom OpenMLS storage adapter; see its local `AGENTS.md`. |
| `src/account_recovery.rs` | Account-private recovery ledger, evidence import and durable retry reservations; `account_recovery/` holds typed joins, frozen scope checkpoints, loss acknowledgment and (`notice.rs`) parked "history may be incomplete" occurrences with their explicit retirement (`state = 2`, never coverage), (`stall.rs`) qualified stall observations, (`comparison.rs`) bounded operational comparison (never a coverage predicate), (`demand.rs`) typed joins for non-legacy callers, and (`observe.rs`) read-only transition facts for the owner's audit rows: a demand write's `RecoveryDemandTransition` read before and after it in the same transaction, and `recovery_obligation_status`. Transition reporting never changes demand. The app owner supplies validated facts and owns execution policy. |
| `src/delivery_spill.rs` | Durable overflow tail of the in-memory account delivery queue: bounded spill, seen/released dedup, oldest-first reads and per-row removal after ingest. |
| `src/recovery_health.rs` | Durable reports of unsuccessful automatic synchronization recovery. |
| `src/synchronized_history.rs`, `src/synchronized_history/tests.rs` | Default-off experimental archive import with separate provenance, staged completion, bounded receipts and retention fences; never engine evidence or live app-event projection. |
| `src/accepted_device_group_anchor.rs`, `src/accepted_device_group_anchor_tests.rs` | Schema109 bounded accepted-successor facts, exact local selection/owner/purpose fences and permanent denial; separate from genesis, never SDK reconstruction or settlement authority. |
| `src/private_device_invite.rs`, `src/private_device_invite_tests.rs` | Provisional schema110 outgoing raw/wrapped/dispatch/unknown/confirmed facts with separate retained confirmed lineage, exact retries and transactional transitions. Trusted-core persistence only; never SDK consent, publication proof or native draft admission. |
| `src/accepted_welcome.rs`, `src/accepted_welcome/tests.rs` | Default-off immutable accepted-join facts in schema105; exact Welcome/KPref/signers/epoch, atomic with real join, never enrollment or settled-roster permission. |
| `src/device_group_genesis.rs` | Schema108 bounded selected immutable local birth, checked generation, account/device scope and permanent active denial; metadata never verifier permission. |
| `src/device_linking_key_package.rs` | Schema106 singleton purpose ownership, exact reserved scope and frozen context, same-transaction factory/cleanup and commit fences; never verifier permission. |
| `src/device_linking.rs`, `src/device_linking/tests.rs` | Default-off device-local verifier generation/context/flow fencing and terminal facts; no verifier secrets, roster authorization, or membership evidence. The runtime explicitly abandons pending attempts on startup. |
| `src/transport_reconciliation.rs` | Account-private NIP-77 set-reconciliation inventory. |
| `src/pending_welcome_delivery.rs` | Durable pointer to a confirmed create/invite whose Welcome publish failed, for re-delivery (mdk#352). |
| `src/local_submissions.rs` | Device-local submission identity and durable admission before engine work. |
| `src/agent_stream_sequences.rs` | Durable, fail-closed publisher sequence reservations for QUIC previews. |
| `src/account_projection.rs` | Account-level event projection. |
| `src/chat_list.rs` | Chat-list projection, including avatar URLs; `chat_list/` holds attention, pages, and windows. |
| `src/chat_presentation.rs` | Durable selected-presentation foundation (runtime orchestration owns hydration). |
| `src/group_system.rs` | Local presentation of kind-1210 content (not a wire-format change). |
| `src/user_blocks.rs` | Account-private NIP-51 block state; never stored in the shared database. |
| `src/message_drafts.rs` | Revisioned encrypted composer drafts (`message_drafts/revisioned.rs`). |
| `src/prepared_group_image_upload.rs` | Staged founding-image upload (component data + Blossom upload secret; keep both out of diagnostics). |
| `src/attachment_acquisition.rs` | Source-bound durable acquisition jobs, leased attempts, protected retained bytes, bounded worker demand and explicit-removal suppression. Network orchestration stays in marmot-app. |
| `src/attachment_acquisition/access.rs` | Read-only source-bound retained-asset lookup and opaque reference encoding; no demand registration. |
| `src/attachment_acquisition/controls.rs` | Durable user intent and coalesced transfer metadata in the job store. |
| `src/attachment_acquisition/partial.rs` | Attempt-fenced SQLCipher ciphertext checkpoints, combined retained/partial byte accounting, bounded writes and abandoned-partial cleanup. |
| `src/attachment_history.rs` | Bounded canonical attachment-slot discovery and per-group revision-fenced cursors; source/visibility triggers maintain the derived index. |
| `src/timeline.rs` | Materialized message-timeline aggregation; `timeline/` holds capture, edits, opening (`conversation_open` / `conversation_window`), presentation, and reports. |
| `src/avatar_cache.rs` | Account-scoped encoded avatar storage, source generations, local reads and eviction; `avatar_cache/acquisition.rs` owns durable demand/retry state and `avatar_cache/access.rs` owns opaque screen targets/local metadata. |
| `src/encrypted_media_secrets.rs` | Per-group encrypted-media secret storage. |
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
- Build every long-lived connection on `CloseableConnection` so a host can release the database's file locks at a known
  instant. Closing is terminal: surviving clones return `StorageError::Closed`, and nothing reopens implicitly. See
  `docs/marmot-architecture/overview/local-artifact-safety.md`.
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
while an upgrade copy exercises revision13. Full backend checks pass: experimental1076/default978 with zero failures;
traits167 and production Clippy/default check pass. The initial formatting failure
was only module declaration order; the exact nonsemantic move passed repeated
production checks and formatting. See
`docs/selected-chat-recipient-storage-full-verification.json` from the repository
root. This storage checkpoint does not qualify ordinary joining or message delivery.
