# AGENTS.md — cgka-engine

Agent map for the OpenMLS-backed `cgka_traits::CgkaEngine` implementation. For the human overview, test tiers, and
background-recovery concepts, read [`README.md`](README.md). Test file map: [`tests/AGENTS.md`](tests/AGENTS.md).
Source-local rules: [`src/AGENTS.md`](src/AGENTS.md).

The engine is a **thin coordinator** above OpenMLS (pinned fork, workspace `Cargo.toml`), not a re-implementation of
MLS. It owns what OpenMLS does not enforce: commit sequencing, fork adjudication through distributed convergence,
capability negotiation, and MIP-03 admin policy.

## Contents

- [Where to start](#where-to-start)
- [Module map](#module-map)
- [Design deviations](#design-deviations)
- [Publish-before-apply](#publish-before-apply)
- [Fork resolution and branch-relative peel](#fork-resolution-and-branch-relative-peel)
- [Invariants](#invariants)
- [Regression-pinned rules](#regression-pinned-rules)
- [Verification](#verification)

## Where to start

| Task | Open |
| --- | --- |
| Public surface | `src/engine.rs` (`Engine<S>`, `EngineBuilder`); every `CgkaEngine` method dispatches from here |
| State machine | `src/epoch_manager.rs` + `cgka_traits::engine_state` |
| Inbound message | `message_processor/mod.rs::do_ingest` → `message_processor/ingest.rs::ingest_group_message` (peel → classify → apply) |
| Outbound intent | `message_processor/mod.rs::do_send` → matching `do_send_*` in `message_processor/send.rs` (or `do_*` in `group_lifecycle.rs` / `upgrade.rs`) |
| Feature capability | `src/feature_registry.rs` + `tests/capabilities.rs` |
| Fork handling | `commit_should_enter_convergence` in `message_processor/ingest.rs` + `src/distributed_convergence.rs`; see [Fork resolution](#fork-resolution-and-branch-relative-peel) |
| SelfRemove auto-commit eligibility | `src/auto_committer.rs` |
| Wire-format policy | `src/wire_format.rs` (read the module comment first; known revisit point) |

## Module map

Each module's top-level rustdoc is the source of truth; this is an index.

| Module | Owns |
| --- | --- |
| `engine.rs` | `Engine<S>`, `EngineBuilder`, `CgkaEngine` impl, `drain_events` / `drain_auto_publish` / `drain_auto_proposals` queues |
| `account_chat_catalog.rs` | Experimental read-only initial paged discovery from fresh Completed protected roster and actual local ordinary membership; observations only, no automatic sharing policy, transport or remote membership |
| `account_chat_sharing.rs` | Experimental original fixed-lease two-device signed policy transcript and recipient-only HPKE bodies; actual Completed roster/generation/Engine custody, bounded exact retries and actual protected MLS carrier/source-leaf intake; no automatic actor or ordinary membership grant |
| `history_transfer.rs` | Default-off original fixed-lease recipient-only HPKE channel; exact signed request/consent/context and Engine ownership; one immutable archive/ACK body, no MLS transport or history import permission |
| `identity.rs` | Local signer + credential bundle; `member_id_of_processed_message` / `member_id_of_sender` chokepoints |
| `device_group_lineage.rs` | Default-off permanent109/confirmed110 denial from the actual applied indexed tree, scoped owner/group/generation and full successor; no probe revocation or permission |
| `device_group_genesis.rs` | Default-off atomic private-profile MLS birth factory, fresh protected original-tree evidence, permanent active-denial fencing; no SDK/settlement/chat/history permission |
| `device_group_snapshot.rs` | Default-off bounded same-account candidate from actual indexed MLS leaves, local epoch/convergence gates and private commitment; no settled roster or grants |
| `private_linking_join.rs` | Default-off complete private batch route and purpose/full-tree successor validation; live lease transport checks before private consumption;105/106/109 plus crypto/group/dispositions atomic; raw private bypass denied; injected-policy tests separate from genuine SDK consent |
| `private_device_invite.rs`, `private_device_invite/preparation.rs`, `private_device_invite/confirmation.rs` | Default-off actual single-use KP/single-Add validators and trusted owned-lease preparation; raw/final110-only bytes, no ordinary Sent replay; dedicated exact-confirmed Welcome dispatch checks the original live lease; generic confirm/fail stay denied; sealed exact own-echo reconciles atomically, with exclusive actual-receipt retained verification or stock legacy verification; no error fallback/consent reconstruction |
| `private_enrollment_predecessor.rs` | Default-off fresh protected Completed read plus actual signed GroupInfo/ratchet-tree export, bounded256KiB; metadata only, no SDK/sibling approval/recipient admission; portable verification uses separate scratch storage |
| `private_enrollment_endorsement.rs` | Default-off explicit request-bound current-leaf signatures, complete indexed-leaf verification and engine-owned cancellation/expiry fencing; packets remain metadata, no SAS/join/native grants |
| `private_device_invite_prepare_tests.rs` | Genuine isolated MLS Add, injected encrypted SQL rollback/exact retry, original-lease cancellation and dedicated commit-only dispatch; injected policy is not the App SDK proof |
| `provider.rs` | Ad-hoc `OpenMlsProvider` adapter composed from crypto + storage |
| `feature_registry.rs` | Runtime feature → capability-requirement registry |
| `capabilities.rs` | `cgka_traits::Capability` ↔ OpenMLS `Capabilities` translation |
| `capability_manager.rs` | `feature_status`, `upgradeable_capabilities`, write-through per-leaf cache population |
| `linking_welcome_policy.rs` | Default-off trusted runtime lease injection; authenticated staged facts, original deadline/one-shot memory consumption, no enrollment/history grants |
| `leaf_advertisement.rs` | What the own leaf advertises: `own_leaf_refresh_extensions` (a self-update re-advertises every supported component, keeping every other leaf byte), `own_leaf_missing_app_components` (stale only when a self-update would change the leaf), per-component leaf-support blockers |
| `key_package.rs` | `fresh_key_package`, KeyPackage parse-time lifetime / OpenMLS accepted-range checks (refresh scheduling is a higher-layer concern) |
| `group_lifecycle.rs` | `do_create_group`, `do_join_welcome`, `retry_rejoins_after_trusted_removal` |
| `message_processor/` | `mod.rs`: entry points (`do_ingest`, `do_send`, convergence/queue drains, `replay_buffered_messages`), shared helpers, re-exports. `ingest.rs`: inbound path, peel/snapshot recovery, `convergence_ingest_outcome`. `send.rs`: `do_send_*` incl. `do_send_invite` / `do_send_leave`, MIP-03 guards. `store.rs`: durable persistence, dedup classification, stored-message transitions, `retire_raw_wrapper`. `application_replay.rs`: bounded background drain of retained canonical applications |
| `message_disposition.rs` | Closed classification of why a raw inbound message was not applied; shared by both seams and the deferred-peel lifecycle |
| `epoch_manager.rs` | Only mutator of `EpochState`; `PendingMeta` (group_id + prior_epoch + kind) |
| `group_state_changes.rs` | Pure before/after diffs (admins, profile name, avatar) → `GroupStateChange` / `GroupEvent::GroupStateChanged` |
| `publish.rs` | `do_confirm_published` (merge staged commit + mirror Marmot/cache) and `do_publish_failed` (`clear_pending_commit` + re-derive) |
| `pending_commit_guard.rs` | `PendingCommitCleanupGuard`: clears an orphaned OpenMLS pending commit if a commit-producing send path exits before handing off a `PendingStateRef` |
| `auto_committer.rs` | `decide_with_reason(mls_group, proposal) -> AutoCommitDecisionReport` (SelfRemove auto-commit eligibility + stable `reason`) |
| `self_update.rs` | Pure own-leaf rotation for `SendIntent::SelfUpdate` (`force_self_update`, no proposal-store consumption) |
| `upgrade.rs` | `do_upgrade_group_capabilities` (MLS primitives via `GroupContextExtensions`, app components via `AppDataUpdate`) |
| `update_group_data.rs` | `SendIntent::UpdateGroupData`: stages an `AppDataUpdate` for `marmot.group.profile.v1`; admin-policy and routing updates are out of scope |
| `disband.rs` | Durable terminal group-disband workflow |
| `own_commit_intent.rs` | `OwnCommitIntent` records and re-issue of own commits superseded by branch selection (mdk#1734) |
| `maintenance.rs` | Persistence helpers for account-device maintenance orchestration (scheduling lives above the engine) |
| `group_authority.rs` | Advisory live-engine authority facts for conversation capture; mutations still validate authority |
| `app_components.rs` | `app_data_dictionary` helpers, LeafNode/group `app_components` bytes, group profile and admin-policy bytes |
| `account_identity_proof.rs` | Legacy LeafNode identity-proof extension + current app-data component; strict profile classification (mixed rejected) |
| `app_payload.rs` | `validate_app_payload_for_sender`: `MarmotAppEvent` sender validation |
| `group_context_view.rs` | `GroupContext` snapshot view; `exporter_secret(label, length)` returns `None` rather than truncating |
| `snapshot_guard.rs` | `SnapshotRollbackGuard` (roll back + release on `Drop`) and `RewindSite`, the closed set of guard sites that `openmls_projection::recover_interrupted_rewind_guard` classifies at open |
| `mls_group_cache.rs` | Loaded `MlsGroup`s reused only while the backend's OpenMLS write generation is unchanged |
| `bounded_id_set.rs` | Capacity-bounded FIFO caches (`seen_message_ids`, `sent_message_ids`); durable `MessageRecord` store stays authoritative |
| `wire_format.rs` | `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` + `WIRE_FORMAT_POLICY_REVIEW_REQUIRED` grep marker |
| `canonicalization.rs` | Executable post-peeling canonicalization-contract model |
| `convergence.rs` | Candidate-state-graph deterministic branch selection |
| `convergence_input.rs` | Role-aware scheduling classification (commit edges, proposal deps, app witnesses); `PASS_OPENING_STATES`, `OUTBOUND_GATING_STATES` |
| `convergence_clock.rs` | Injectable dual clock: monotonic for live scheduling, persisted wall clock for restart deadlines |
| `deadline.rs` | Portable native/browser-WASM deadlines |
| `distributed_convergence.rs` | Engine entry point for stored-message distributed convergence and its event emitters |
| `openmls_projection.rs` | Bytes-first OpenMLS projection/replay, Marmot record refresh on replay, `candidate_branch_peel`. `openmls_projection/resumable.rs`: shared candidate search + slice continuations. `openmls_projection/tests/candidate_replay.rs`: forked-graph, restoration, parity and measurement fixtures |
| `engine_metrics.rs` | Diagnostic telemetry for post-settle convergence reorgs |
| `audit_helpers.rs` | Stable, low-cardinality forensic audit-log strings |
| `conformance_snapshot.rs` | Feature `test-conformance-snapshot` only: privacy-safe canonical-state and aggregate pending-work projections for the simulator. Structural progress counts completed distinct-context attempts; terminal equality excludes device-local authorship metadata. Never feeds protocol selection or production telemetry |
| `test_crash_hooks.rs` | Feature `test-crash-hooks` only: subprocess pause points selected by `MDK_CGKA_TEST_CRASH_POINT` |

Features (`Cargo.toml`): `test-policy-overrides`, `test-crash-hooks`, `test-conformance-snapshot`. All three are
test-only; production/app consumers must not enable them.

The default-off `experimental-device-sync` feature additionally captures accepted-Welcome
facts through an optional storage capability and exposes a read-only receipt query. It is
not enrollment, settled-roster authorization, or adopted wire framing. `tests/accepted_welcome_receipts.rs`
owns exact signer/KPref bindings, failure rollback/retry, and encrypted reopen.

## Design deviations

Load-bearing departures from the original plan; each is also documented at its site.

1. **Storage aggregate uses accessor composition.** `cgka_traits::StorageProvider` exposes `type Mls;
   fn mls_storage(&self) -> &Self::Mls` instead of being `: openmls_traits::storage::StorageProvider<CURRENT_VERSION>`
   (avoids hand-forwarding 50+ OpenMLS methods). Site: `crates/traits/src/storage.rs`.
2. **Founding creation never invents a group-message publication.** Current-profile creation returns
   `SendResult::FoundingGroupCreated { welcomes }`: epoch 0 and the optional founding Add are already canonical, and
   each Welcome is an independent delivery obligation. The temporary explicit-legacy path keeps
   `SendResult::GroupCreated { welcomes, pending }`. Neither carries a `msg: TransportMessage`. Site:
   `crates/traits/src/engine.rs::SendResult`.
3. **`CreateGroupRequest::initial_admins: Vec<MemberId>`** bootstraps multi-admin groups so admins can later
   self-remove (MIP-03 "not the last admin"). The creator is implicitly an admin.
4. **The per-leaf capability cache is required for correctness.** `MlsGroup::public_group()` is `pub(crate)`, so there
   is no public way to reach a specific leaf's capabilities. The cache is populated from KeyPackages we handle (invite
   parses, `StagedCommit::add_proposals`) plus `MlsGroup::own_leaf_node()`. Read `capability_manager.rs` before
   changing it.
5. **Group state is app-component state.** New groups never create or read the legacy `marmot_group_data` extension;
   the engine writes `app_data_dictionary`, advertises component ids in LeafNode `app_components`, records required ids
   in GroupContext `app_components`, and reads admin/profile state from component bytes.
6. **Test identities are 32 bytes via `pad32`.** Admin-policy pubkeys MUST be 32-byte x-only secp256k1; the engine
   strict-fails non-32-byte member identities at admin-set time.
7. **Two-layer addressing.** `StaleReason::NotForThisClient` is engine-layer identity filtering as well as transport
   defense.

## Publish-before-apply

`do_send_invite`, `do_upgrade_group_capabilities`, `UpdateGroupData`, and auto-commit stage their commits and defer
merge until `CgkaEngine::confirm_published`; `CgkaEngine::publish_failed` discards via
`MlsGroup::clear_pending_commit` + Marmot re-derive. Auto-publish work carries a `PendingStateRef` and uses the same
lifecycle. While an evolution is pending, the Marmot record holds the _projected post-merge_ `members` so `members()`
and `feature_status` reflect it. Current-profile `do_create_group` is the founding exception (deviation 2): it publishes
no ordinary group commit and persists each Welcome as independent retryable work. Tests: `tests/publish_lifecycle.rs`,
`tests/group_creation.rs`, `tests/invite_leave.rs`.

## Fork resolution and branch-relative peel

**One route.** Same-epoch rival commits are adjudicated by distributed convergence for every member — committer,
observer, or restarted committer. The durable source-epoch anchor (`openmls-retained-anchor-{epoch}`, retained on
every canonical advance) admits an in-horizon rival into the pass; own commits materialize from commit-addressed
checkpoints (#1285). A missing in-horizon anchor fails closed: ingest retains and schedules the rival, and the
coordinator issues the durable `Unrecoverable` + `GroupEvent::GroupUnrecoverable` from the authenticated
`MissingRetainedAnchor` pass. The former pairwise fast path (`ForkRecoveryManager`, `committed_from` routing,
`fork-` snapshots, `GroupEvent::ForkRecovered`) is deleted; do not reintroduce it. The deterministic ordering key
(source epoch, `privileged` before `ordinary`, authenticated committer identity, digest fallback) survives inside
branch selection, where valid branch depth outranks it. Tests: `tests/fork_detection.rs` and the simulator's
route-equivalence family.

**Branch-relative peel.** Selection ranks on valid commit depth and app witnesses over *stored* inputs, and a group
message is sealed under the sender's current-epoch exporter secret with no epoch hint. Without help, each branch's
later traffic stays `PeelDeferred` on devices that adopted the other branch, contributes nothing, and the fork never
heals. So candidate branch states are part of a group's *peel context*:
`openmls_projection::candidate_branch_peel` materializes each candidate under a `SnapshotRollbackGuard`, captures its
tip's owned `GroupContextSnapshot` (exporter secret derived while the state exists), and rolls back before any async
peel runs. `Engine::retry_deferred_peels` offers those contexts to every retained row through the ordinary ingest seam.

- **Gating.** The sweep returns before context work on an empty backlog; collection stops at the cheap "two commits
  share a source epoch" check before any replay; at most `MAX_CANDIDATE_BRANCH_PEEL_CONTEXTS` branches are
  materialized, one bounded replay each. Apply that cap to candidates ranked by tip epoch then branch id
  (content-derived, so peers with the same evidence keep the same branches) — never to BFS completion order, or a
  wide shallow fork evicts the deep branch carrying post-fork traffic. Branch *selection* is uncapped.
- **No verdicts here.** Failure to enumerate branches (missing anchor, missing own-commit checkpoint, exhausted budget)
  yields no contexts, never an error; the pass owns every verdict.
- **Two counters, kept apart.** `deferred_peel_context` folds in the stored commit graph, so a newly retained rival adds
  a context even when live epoch and anchor set are unchanged; that full fingerprint gates re-attempts and counts work
  in `distinct_context_attempts` (the conformance snapshot's progress witness). The retry budget
  `MAX_DEFERRED_PEEL_ATTEMPTS` is spent per distinct *live* context (live epoch + retained-anchor set) in
  `live_context_attempts`, never per stored commit — otherwise a victim wedged on its own branch, reaching a rival row
  one commit per sweep, releases deep rows before the crawl arrives (field case `8413db02`, 616 retry-budget
  releases). Collapsing the counters either over-charges the victim or leaves a draining generation with no durable
  progress witness (the simulator's 8-pass drain guard reads that as a stalled scheduler). `distinct_context_attempts`
  is a durable serde name; read its doc comment, not the name. Pinned by
  `tests/deferred_peel_lifecycle.rs::wedged_victim_crawl_outlives_the_retry_budget` and
  `::advancing_live_epoch_spends_the_retry_budget_once_per_epoch`.
- **Contested-ness and contexts are separate answers.** The shared-source-epoch check alone decides contested-ness;
  `CandidateBranchPeel` carries it independently of captured contexts, because every later path (released anchor,
  missing checkpoint, exhausted budget, < 2 surviving paths, no tip) loses contexts without saying anything about the
  split. Never infer "healed" from an empty context set. Routing live-readable application traffic into the
  convergence seam keys on `has_branch_contexts`.
- **Every deferred-peel generation drains as a complete batch.** Contested and uncontested sweeps persist a
  `DeferredPeelGeneration` barrier before recovering rows; it survives slices, cancellation, and restart, and clears
  only after every retained row tried the final fingerprint (uncontested per-row convergence can otherwise prune the
  only epoch state that decrypts later rows). Live ingest keeps its immediate drain. Regression: the simulator's
  `tests/offline_catchup_regression.rs`.
- **Provenance.** A message readable *only* under a candidate context belongs to an unadopted lineage:
  `ingest_group_message` routes it to the convergence seam, never to direct apply, and derives nothing from it. The
  next pass's OpenMLS replay authenticates it; a failed peel is silence, never a verdict. Tests:
  `tests/epoch_sealed_transport.rs` and the simulator's `convergence-e2e-delivery/v1` and
  `adversarial-reliability/app-witness-value/v1` families.

**Background budgets and resumable reconstruction** (concepts in README).

- One host background advance shares a 64-row allowance and cooperative 500-ms budget. Explicit-time entry points keep
  the row allowance without a wall deadline; foreground preflight and send budgets keep their own semantics. Return
  pending only at complete operation boundaries; never cancel a snapshot guard or advance a partially tried generation.
- Historical anchor peel contexts live lazily in `DeferredPeelGroupState::past_peel_contexts`, shared by the sweep and
  `replay_buffered_messages`, fetched per row, and dropped with the candidate cache (every canonical change and every
  candidate-generation turnover — read that field's doc). Restore live state before awaiting a peeler. Never persist
  this secret-bearing cache or extend epoch retention.
- Readiness queries all deferred rows via the storage state filter; never limit it to an already-attempted prefix.
- `message_processor/application_replay.rs` spends the remaining allowance on retained canonical applications after
  selection and deferred peeling settle. Its signal is independent of branch ambiguity (no app-only pass, no
  foreground gate, no queued-intent fairness cost). MLS ratchet writes, disposition, and pending app output are atomic.
  Do not start the negative discovery scan at the retained anchor: a newly arrived below-anchor application still needs
  its terminal invalidation.
- `openmls_projection/resumable.rs` is shared by selection and branch peeling. Its memory-only frontier keeps
  cumulative replay-budget accounting across slices; the 32-probe slice allowance is not a selection cap or exhaustion
  verdict. Restore the outer retained-anchor guard and the inner transaction before returning pending; never expose a
  partial candidate set. Reuse requires exact graph/group/snapshot/policy/pass identity: SQLCipher supplies a content
  fingerprint of live canonical/OpenMLS state and retained snapshots/checkpoints; other tracking backends require
  strict MLS-write-generation equality; untracked backends evaluate synchronously. Never log or persist replay
  fingerprints; keep the cached-`MlsGroup` generation contract separate. Restart discards scratch work. The original
  BFS is a test-only differential reference.

## Invariants

- **Mirror every ingest invariant on every inbound seam.** An inbound MLS message reaches application-visible state
  through two seams — **direct ingest** (`message_processor/ingest.rs::ingest_group_message`) and
  **stored-convergence/replay** (`openmls_projection.rs::process_openmls_messages_inner`, materialization and apply;
  also the fork-resolution seam). Every sender-authentication, admin/identity-proof, app-payload, and
  component-retention check MUST run identically on both, through the *same* shared helper — never a seam-local
  re-implementation. Shared chokepoints: `identity::member_id_of_processed_message` (authenticated application
  credential → source-epoch `MemberId`; proposals/commits keep the current-tree lookup via
  `identity::member_id_of_sender`) and `app_payload::validate_app_payload_for_sender` (rejects an empty id). Never
  resolve a historical application's author against the current member leaf: removal or leaf reuse can erase or
  substitute that identity. An application whose sender cannot resolve to a validated member id is never surfaced as
  `MessageReceived` and never accepted into canonical state on any seam (direct: `Failed`; replay: `Ignored` →
  terminal). Fork-resolution paths fail closed with typed errors — never `unreachable!`/`panic!` — on
  attacker-influenced input. A guard on one seam only is a bug (mdk#707): add it to the shared helper and extend the
  parity tests.
- **Never derive durable terminal group state from unauthenticated inbound bytes.** "Fail closed" means refuse the
  input, not punish the group. The sharp case is the `WrongEpoch` arm in `message_processor/ingest.rs`: OpenMLS raises
  it from `validate_framing`, the first statement of `decrypt_message`, upstream of membership-tag and signature
  verification, so the claimed epoch is raw attacker input and, for a past epoch, unverifiable in principle. A durable
  `unrecoverable` marker written from that claim let any member freeze a group with one datagram. Correct response:
  retention, an audit row, and a scheduled convergence pass; the terminal verdict belongs to a seam with authenticated
  material (the coordinator's `MissingRetainedAnchor` halt). The same applies to durable *inputs*: a row keyed by an
  unverified claimed epoch steers a later pass as effectively as a flag. A hard stop for a genuine local anchor gap
  must be evaluated on a seam that reads no inbound bytes (session open / per-group full hydration).
- **The retained rival stays pass-opening, so the verified repair must retire it.** Ingest leaves the rival `Created`,
  and the pass seeder re-derives each retained commit's source epoch from its wire bytes, so an anchor-less rival keeps
  steering `openmls_projection::historical_replay_start_epoch` (the `min` over unresolved rows) back into
  `MissingRetainedAnchor`. The eviction belongs to the authenticated Welcome join: alongside
  `delete_convergence_pass`, `do_join_welcome` calls
  `openmls_projection::retire_commits_superseded_by_replacement_welcome` in the same transaction, terminalizing
  unresolved *commits* below the new copy's `MlsGroup::epoch()`. Bound it by locally derived authenticated epochs only,
  keep it to commits (prior-interval applications may still decrypt, which is why a replacement Welcome records
  `join_epoch = 0`), and never move it to a seam that reads inbound claims.
- **Commit-derived group records and capability caches are atomic with the MLS apply.** Every durable projection of an
  accepted commit (Marmot group record, capabilities from added KeyPackages, post-path self-capability refresh) shares
  the transaction that mutates OpenMLS state, and every projection read/write error propagates. On a failed direct
  apply, release its unowned recovery snapshot and schedule the retained commit for stored convergence; redelivery
  deduplicates against the retained content row and cannot repair the apply.
- **Hydration quarantine is enforced through `Engine::ensure_group_live`** (mdk#364 / #365). Every public accessor that
  reads durable or MLS group state (`members`, `group_record`, `group_context`, `admin_pubkeys`, `app_component`,
  `app_components`, `feature_status`, capability queries, the safe-export family, `own_leaf_index`) calls it first and
  returns `UnknownGroup`; `do_send` and `converge_and_drain_queued_outbound_intents` refuse; `ingest_group_message`
  retains input as `PeelDeferred`, classified `Stale { reason: Quarantined }`; `converge_stored_openmls_messages`
  reports `Blocked` without touching state; `retry_deferred_peels` skips the group. Those retained rows (like an
  `Unrecoverable` group's) are bounded by per-group deferred-peel caps alone and never charge the account-wide byte
  budget. Any new accessor or data path that reads group state needs the gate — a bypass can silently un-quarantine
  via `set_stable`. Quarantine clears only through `retry_hydrate_quarantined_group` or an authenticated re-join
  Welcome, both of which schedule retained input for replay.
- **Two-phase hydration (mdk#1161): session open seeds, full hydration promotes.**
  `hydrate_stable_groups_from_storage` is the cheap seed: per stored group it reads only the durable record (no MLS
  load, snapshot list, or message scan), seeds a provisional `Stable(record.epoch)` so `live_group_ids` keeps listing
  the group (unless this device was removed), restores disband/unrecoverable terminal state, seeds the inbound routing
  index from durable `transport_group_routes`, and adds the group to `unhydrated_groups`. An unhydrated group fails
  closed through `ensure_group_live` with retryable `GroupNotHydrated` (never a partial view); `&mut` entry points
  (send, ingest, convergence drains) call `ensure_hydrated`, which retracts the seed, runs full hydration, and on
  failure quarantines with exact open-time parity (including removing the epoch entry — a quarantined group never
  holds one). `hydrate_all_stored_groups` is the eager path (seed + drain-all) used by `AccountDeviceSession::open`; it
  drains every seeded group, including unrecoverable ones, whose halt re-emits exactly once per open. Durable route
  rows carry a `source_epoch` stamp refreshed at every commit apply; the seed trusts a route set only when a stamp
  matches the record epoch, and stale/route-less groups sit in `route_backfill_pending`. Ingest probes at most
  `ROUTE_BACKFILL_PROBES_PER_MISS` pending groups per unknown route (mdk#408's O(groups) amplification stays closed),
  removing an id only on successful indexing or the terminal no-routing-component disposition; MLS-load failures stay
  owned by hydration/quarantine. Route refreshes retire rows the retained-history window (pinned v1
  `max_rewind_commits`) has moved past, per routing-v1's overlap rule.
- **A removed copy is seeded, audited apart, and is not a live member.** `Group.removed` is terminal for outbound work
  but not inert like a disband tombstone: the re-add path (`group_lifecycle::retry_rejoins_after_trusted_removal`)
  calls `ensure_hydrated` before `do_join_welcome`, #1858 keeps the copy's refused rows `Retryable`, and the #1840
  ingest gate answers `Removed` off the durable record. So the cheap pass seeds a departed copy exactly like a live
  one (epoch entry and routing included) and full hydration still promotes it. Two differences: its hydration rows
  carry `hydrate_removed_group` instead of `hydrate_seed_group` / `hydrate_stable_group` (a copy that is removed *and*
  unrecoverable takes `hydrate_unrecoverable_group` — the halt is the stronger fact); and it is absent from
  `live_group_ids` (both terminal reasons excluded, not just `Disbanded`), because a copy that cannot send, rotate, or
  converge owes no periodic maintenance. The app's `reconcile_live_engine_groups` therefore neither re-adds nor repairs
  an unprojected removed copy; it resurfaces on re-add only.
- **Both legs of the account maintenance sweep skip a group the engine will not serve.** In
  `marmot-account::run_due_maintenance`, the per-group rotation pass and the account-wide obligation pass both *skip*
  rather than abort on `GroupNotHydrated` (seeded-but-unhydrated under `defer_group_hydration`) and `UnknownGroup`
  (quarantined): both are retryable, and one dead group must not stop work for every group behind it. The obligation
  pass fails an obligation terminally with `local_member_removed` when the durable record has gone terminal, and
  `schedule_manual_self_update` refuses a terminal record — otherwise a lost removal event leaves an uncapped
  `SelfUpdate` refused every tick (the field's `UseAfterEviction` loop). A group with `leave_in_progress` or
  `disbanding_in_progress` refuses the same `SelfUpdate`, but its obligation *waits* rather than fails: the removal
  ends it through the terminal verdict, and a reorg or acknowledged disband failure must find its rotation still owed.
- **The durable `Group::epoch` mirrors the epoch manager, and hydration seeds the epoch manager from it.** Every mirror
  write belongs to the same durable unit as the MLS change it projects, and every mirror failure propagates. Write the
  record inside the merging transaction (`publish::do_confirm_published`, the inbound apply in
  `message_processor/ingest.rs`) or compensate the in-memory transition explicitly
  (`stage_auto_commit_for_queued_proposals`). A swallowed mirror error resurfaces as a wrong epoch on the next open. A
  failed inbound apply must also hand the retained commit back via `schedule_pending_convergence_group`, or the group
  parks one epoch behind a commit nothing will apply.
- **A branch-selection withdrawal is provisional: announced once, and reversible.** A losing commit is parked
  `ConvergenceDeferred` (still a canonicalization input) so a later pass with deeper evidence can re-adopt it. Both
  halves of `distributed_convergence.rs` key on the commit's stored state *before* the pass's disposition persistence
  (`pre_apply_commit_states`, captured outside the apply transaction): `emit_rolled_back_commits` announces
  `CommitRolledBack` + `GroupStateInvalidated` only for a commit this pass is parking, and `emit_revalidated_commits`
  emits `GroupStateRevalidated` when an accepted commit entered the pass parked. Post-apply state cannot tell these
  apart. The app mirrors the asymmetry: its tombstone is terminal by default (#1608) and only the evidenced
  `GroupStateRevalidated` path clears a `SupersededByBranchSelection` row. Withdrawals under every other reason stay
  terminal on both sides.
- **An application moves with the branch it rode.** A never-delivered application that decrypts only on non-selected
  branches is parked `ConvergenceDeferred` under `NonSelectedEligibleBranch` while any of those branches is eligible
  (`handle_app_message`'s losing arm mirrors `classify_losing_materialized_candidate_commits`). Graph seeding re-admits
  it, so the pass that revives the commits also delivers it; parking keeps the branch's witness weight, making
  selection independent of arrival order. A parked application is announced to nobody. Terminal
  `AppMessageInvalidationReason::LosingBranch` is reserved for an application no branch it decrypts on can be
  reconsidered, and an already-delivered application a reorg takes back (mdk#965).
  - The background drain honours the park: while the group holds a parked commit, `pending_canonical_applications`
    reports no parked application as drainable, so the drain cannot hand it the `UndecryptableInCanonicalState`
    verdict the pass withheld or rearm on it. Gate on "parked", not "pending": an unadjudicated commit already gates
    unconditionally (`ConvergenceInputContext::gates_outbound`, `CommitEdge => true`), and widening to any pending
    commit lets one forged beyond-ceiling row hold every parked application back.
  - Keep in step: `handle_app_message` parks on exactly the materialized/eligible/non-selected branches for which
    `handle_commit` answers `NonSelectedEligibleBranch`, so a branch-parked application always has a parked commit
    beside it. The branchless park `NoCanonicalBranchSelected` (a pass that selected nothing may not answer
    `UndecryptableInCanonicalState`) is meant to reach the drain.
  - The gate cannot see *why* a row is parked (`FutureEpoch`, `NonSelectedEligibleBranch`, `NoCanonicalBranchSelected`
    share `ConvergenceDeferred`; the only stored epoch authenticator, `OwnApplicationConvergenceStamp`, is on local rows
    the drain skips). Withholding all three is safe only because a pass re-seeds and re-evaluates every parked
    application above the anchor before `advance_convergence_inputs` reaches the drain. If that ordering ever changes,
    distinguish by outcome (a matured application decrypts against canonical state), not by state.
  - Terminalization is owed to a later pass and the horizon arms (`BeyondAnchor`, `BeyondAppRetention`); a parked row
    opens no pass (`ConvergenceDeferred` is in neither `PASS_OPENING_STATES` nor `OUTBOUND_GATING_STATES`).
  - Pinned by `tests/distributed_convergence.rs::a_reorg_delivers_the_application_that_rode_the_revived_branch`,
    `::a_parked_application_whose_branch_never_wins_is_terminalized_undelivered`,
    `::a_commit_awaiting_adjudication_is_adjudicated_before_the_application_drain`, and
    `::an_application_parked_ahead_of_its_commit_is_delivered_beside_a_parked_rival` (blast-radius guard).
- **A pass holds only the delivered applications that can witness (mdk#2330).** Every candidate a pass materializes
  forks at its replay start, `attach_app_witnesses` counts only epochs strictly after a candidate's fork, and an
  application at or below the replay start is probed on the shared base, so it decrypts on every candidate or none. A
  `Processed` application at or below the pass's witness floor (lowest unresolved commit source epoch in the window,
  capped by both tip authorities) is therefore inert: seeding leaves it out
  (`ClassifiedConvergenceInput::is_inert_delivered_witness`) and storage never reads it (`OpenMlsContentFilter`). An
  admitted commit forking below the floor lowers it, and admission takes the delivered applications in between back
  into the collecting pass; without that top-up a deeper rival wins over witnessed history. Inert for selection is not
  inert for replay: decrypting a delivered application steps its sender's receive ratchet in the anchor state, and
  OpenMLS refuses a generation more than 1,000 ahead, so a pass that holds an unresolved, non-own application at or
  below the floor keeps every delivered application of that epoch (seeding and admission alike;
  `ClassifiedConvergenceInput::replays_after_delivered_applications`). If replay ever starts below the lowest
  unresolved commit, or witnesses start counting shared-prefix epochs, revisit the floor. Pinned by
  `tests/distributed_convergence/delivered_witnesses.rs`.
- **Only `NonSelectedEligibleBranch` may drive a withdrawal.** `handle_commit` also returns `MissingCandidateParent`
  when the pass selected no branch at all (the common case); withdrawing there would tombstone a device's applied
  history on a pass that decided nothing — the hazard `emit_superseded_processed_commits` guards with its
  `selected_tip.is_none()` early return.
- **Announce-once is paid for by derived-state reconciliation, not a durable event queue.** `events_buf` is in-memory,
  so a crash between the convergence apply and the app projection loses an announcement. A commit's branch-selection
  tombstone state is derivable from `cgka_messages.state`, and engine messages and `app_events` share one account
  database: `SqliteAppStorage::diverged_branch_selection_withdrawals` reports disagreements (`ConvergenceDeferred`
  with live rows owes a withdrawal; `Processed` with a `SupersededByBranchSelection` tombstone owes a revival) and
  `AppClient::reconcile_branch_selection_withdrawals` applies them on every account open. Keep that derivation total;
  a withdrawal the stored disposition cannot express needs its own durable evidence. The maintenance consumer has the
  same gap across awaited relay publishes: `AccountDeviceRuntime::reconcile_superseded_maintenance_from_state` treats a
  `DurableGroupEvolution` whose `signed_message_id` reads `ConvergenceDeferred` or `EpochInvalidated` as superseded.
  `emit_superseded_processed_commits` already announces once by durably flipping its record to `EpochInvalidated`.
  Both repairs flip forward only; `GroupStateRevalidated` has no account-layer consumer.
- **Every own group evolution keeps its intent until the commit is beyond the rewind horizon.** `do_send_ready`
  records an `OwnCommitIntent` (kind, pre-staging baseline of edited fields, source epoch, attempt count) for
  `Invite`, `RemoveMembers`, `UpdateGroupData`, and `UpdateAppComponents`, keyed by the commit's message id;
  `publish_failed` deletes it, confirmation does not, and `reissue_superseded_own_commits_from_state` garbage-collects
  a `Processed` record once `group.epoch > source_epoch + max_rewind_commits`. On withdrawal,
  `reissue_superseded_own_commit` (event path: the account `GroupStateInvalidated` reconciler; derived path:
  `run_due_maintenance`) decides from the record, never the losing branch's bytes: re-queue an edit only when every
  changed field's canonical value still equals the baseline, else `Conflict`; re-queue a removal for targets still on
  the roster; an invite keeps a durable `ReinviteRequired` record until the host supplies fresh KeyPackages (never
  replay consumed material). Active recipients get bounded durable offers and require explicit branch-bound consent
  via `confirm_group_rejoin`; local history remains, discarded-branch anchors do not. At most
  `MAX_OWN_COMMIT_REISSUE_ATTEMPTS` re-issues, then `Abandoned`; the decision returns as a `SupersededIntentReport`
  (mdk#1734). Tests: `tests/distributed_convergence.rs::superseded_profile_edit_*`.
- **A commit row's `epoch` column is the epoch the commit forks FROM, at every inbound door that has parsed the content
  type.** Pre-parse persists (peel failure, non-MLS or Welcome body in a group envelope) stamp `current_epoch`. The
  convergence door stamps the projected `source_epoch`; direct ingest stamps the commit's wire epoch (always below
  `current_epoch` there, since `commit_should_enter_convergence` routes every commit at or above the live epoch into
  convergence). `distributed_convergence.rs` and `openmls_projection.rs`'s own-checkpoint prefix
  (`resulting_epoch = record.epoch + 1`) both read rows this way. Hazard from a device-epoch stamp (derived from
  `apply_start_epoch_for_canonicalization_result`, not pinned by a test): a direct-path row becomes the first
  non-prefix commit, `apply_start_epoch >= current_epoch`, `rewind_to_retained_anchor` stays false, and replay runs
  against live state (`WrongEpoch`, failed apply, rollback). The stamp is a stored-input shape, not a verdict. Forensics
  is decoupled on purpose: the persist's audit row and every direct-path error arm that writes the row keep reporting
  `current_epoch` (via `update_stored_message_state_reported_at`), and the pass's disposition transitions report the
  device's pre-apply tip, because `incident-replay` reads `MessageStateChanged.epoch` as where the engine was. Tests
  in `tests/fork_detection.rs`: `restarted_committer_without_source_anchor_halts_through_convergence`,
  `stale_commit_outside_rewind_horizon_is_not_treated_as_recoverable_fork`,
  `canonicalization_transition_reports_the_device_tip_not_the_rival_source_epoch`,
  `inbound_commit_at_the_live_epoch_takes_the_convergence_door`,
  `commit_refused_by_the_incoming_wire_format_policy_reports_the_device_epoch`.
- **A retained anchor for epoch E is the state of E as the device *left* E.** `retain_current_group_epoch_snapshot`
  runs before an advance past E and immediately after a replayed proposal enters the store at E
  (`process_openmls_messages_inner`'s `ProposalMessage` arm, same `retain_replayed_anchors` gate). A rival at E may
  name proposals *by reference* (SelfRemove auto-commit shape); once the adopted branch merges, that proposal record
  is `Processed` and the seeder no longer re-supplies it, so the anchor is the only surviving copy. Capture it before
  the proposal arrives and the rival fails `InvalidCommit(MissingProposal)`, never becomes a candidate, and the device
  keeps the first-arrived branch while reporting `Settled`. Tests:
  `tests/distributed_convergence.rs::by_reference_rival_that_wins_the_tiebreak_displaces_the_adopted_branch` and its
  losing-direction control.
- **Only `EpochManager` may construct non-`Stable` `EpochState` variants** (enforced by private fields). Never add a
  public constructor elsewhere.
- **`EpochManager::set_stable` only overwrites `Stable` and `Recovering`.** Other states owe their exit to a specific
  transition: `Unrecoverable` → `repair_to_stable` after a verified repair; `PendingPublish`/`Merging` →
  `confirm_publish` or `rollback_publish` (the only transitions that retire the `pending` entry; a blind overwrite
  strands that entry so both exits fail `InvalidTransition`); `Disbanded` → nothing. Legitimate callers come from the
  two overwritable states or no state (inbound apply behind `can_ingest`, the outbound drain behind its `Stable`-only
  re-check, hydration on fresh state, create/join), so a fired refusal means a new caller lost that gate — fix the
  caller, don't relax the refusal.
- **A held publication and an unresolved convergence input are mutually exclusive**, which is why
  `converge_stored_openmls_messages*` needs no held-publication gate. Outbound: `should_queue_outbound_intent` settles
  convergence before staging, so an unresolved input diverts the intent to the retention queue and `begin_pending` is
  never reached. Inbound: once a publication is held, `can_ingest` is false, so an arriving commit is persisted as
  `Retryable` transport bytes, never buffered as a convergence input. Pinned by
  `tests/publish_lifecycle.rs::a_publication_is_never_staged_while_a_convergence_input_is_unresolved` and
  `::an_inbound_commit_under_a_held_publication_is_retained_not_converged`.
- **A refusal for lack of room is never a verdict.** `IngestOutcome::ResourceRefused` has one mint site
  (`peel_deferred_capacity_refused`): the group's deferred-peel cap had no slot. Every seam leaves the row as it was
  (live ingest keeps the id redeliverable, `replay_buffered_messages` leaves `Retryable`, the sweep leaves
  `PeelDeferred`) and none stamps `Processed` — a terminal state makes `recorded_message_outcome` answer `Duplicate`
  forever. Pinned by `tests/deferred_peel_lifecycle.rs::replay_keeps_a_row_refused_for_lack_of_room_redeliverable`.
- **A `Buffered` outcome never lets the caller retire the wrapper; ingest owns retirement.** Every post-peel `Buffered`
  site retires its own raw wrapper through `Engine::retire_raw_wrapper` (grep it for the current call sites). The
  **pre-peel** halt gate (`!can_ingest`) retires nothing: it parked bytes nobody opened, so the row is their only
  redelivery source. `replay_buffered_messages` and `reingest_deferred_peel_row` therefore stamp nothing on `Buffered`
  and read the row's current state. (`do_ingest`'s durable dedup seam also answers `Buffered`, pre-peel, for an
  existing `Created`/`Retryable` row; internal replay enters below it.) The halt gate is write-once, because internal
  replay re-enters below that dedup seam and re-stamping a `PeelDeferred` row `Retryable` would drop its deferred-peel
  lifecycle. The flood-cap slot belongs to the `PeelDeferred` *state*, not the stamp, so both callers release it via
  `release_cap_slot_if_row_left_peel_deferred` (on the direct path a content row replaces the deferred row under the
  same id without `retire_raw_wrapper` running). Pinned by
  `tests/deferred_peel_lifecycle.rs::replay_keeps_a_row_the_halt_gate_never_peeled_redeliverable`, its controls
  `::replay_still_retires_a_deferred_row_it_resolves` and
  `::unchanged_192_row_contested_backlog_enumerates_candidates_once`,
  and `tests/mip03_guards.rs::a_retained_wrapper_is_retired_when_its_proposal_waits_for_its_fork_parent`.
- **No new Nostr dependencies.** Keep transport-specific code out of this crate. The only `nostr` crate use is
  `account_identity_proof.rs` (event-shaped proof construction/verification), a known layering exception tracked by its
  `TODO(mdk#755)`; don't extend it. Referencing the `marmot.transport.nostr.routing.v1` component by id
  (`NOSTR_ROUTING_COMPONENT_ID`, `NostrRoutingV1`) and naming Nostr concepts in comments is fine.
- **No `leave_group()` (legacy MLS path).** Always `leave_group_via_self_remove` per MIP-03. Enforced by
  `tests/invite_leave.rs::no_legacy_leave_group_call_in_engine_source`.
- **OpenMLS family is pinned to one fork revision** in workspace `Cargo.toml`. Move all `openmls*` crates together;
  companion-crate skew has broken this stack before.
- **Wire format is `PURE_PLAINTEXT_WIRE_FORMAT_POLICY`.** Read `src/wire_format.rs`'s module comment and its three
  alternatives before changing it.

## Regression-pinned rules

From the 2026-05-09 engine audit and follow-ups. Grep the rule when touching the area.

| Rule | Test |
| --- | --- |
| Convergence-side replay refreshes the recipient's Marmot record (`required_capabilities`, `name`, `description`) via `update_group_record_from_replay` | `tests/update_group_data.rs::convergence_refreshes_recipient_marmot_record_name_and_description`, `tests/capabilities.rs::convergence_refreshes_recipient_required_capabilities_on_upgrade` |
| `GroupContextView::exporter_secret` returns `None` when asked for more bytes than cached | `tests/group_context_view.rs` |
| Snapshot names never embed plaintext group ids (hash to a digest) | `tests/snapshot_privacy.rs` |
| Every admitted message gets a current disposition; a child commit missing its frozen-batch parent is explicitly `deferred` and the pass reaches its fixed point | simulator `canonicalization_contract.rs::frozen_batch_defers_orphan_commit_and_settles_at_fixed_point` |
| No `MessageReceived` with an empty/unresolvable sender on either seam (direct: `Failed`; replay: `Ignored`; `emit_application_replay_events` skips empty senders as a backstop) | `app_payload::tests`; `tests/distributed_convergence.rs::terminal_undecryptable_app_emits_invalidation_without_message_received` |
| `EpochManager::confirm_publish` / `rollback_publish` / `begin_pending` run the fallible transition before mutating maps (mdk#146); auto-commit ingest staging requires `EpochState::is_stable` | `epoch_manager::tests::begin_pending_failure_leaves_state_intact`, `begin_pending_success_records_all_bookkeeping` |
| `convergence_ingest_outcome` reports `Stale` for terminal dispositions and `Buffered` only for retryable ones. A future-epoch app message whose commit hasn't arrived gets an explicit `deferred` disposition, is not marked seen, and emits no `AppMessageInvalidated` (mdk#144); legacy results encoding it as `UndecryptableInCanonicalState` keep the `Retryable` compatibility path. At or below the tip it is terminal and emits invalidation (mdk#995), but only from a pass that selected a branch; otherwise it is deferred `NoCanonicalBranchSelected` | `tests/distributed_convergence.rs::future_epoch_app_message_stays_deferred_until_commit_arrives`, `::terminal_undecryptable_app_emits_invalidation_without_message_received` |
| `cache_self_capabilities` errors `EngineError::Backend` if `own_leaf_node()` disagrees with `self_id` | existing cache tests |
| `do_join_welcome` rejects a repeated Welcome via `seen_message_ids` and stored-message state | `tests/group_creation.rs::join_welcome_called_twice_for_same_welcome_errors_on_second_call` |
| `FeatureRegistry::register` warns on a conflicting duplicate (last write wins) | tracing audit |
| Replay swallows only `ProcessMessageError::ValidationError` for application messages; `LibraryError` and structural failures propagate | replay tests |
| `auto_committer::decide_with_reason` refuses to auto-commit a SelfRemove whose leaver credential is not 32 bytes | MIP-03 guard tests |
| `SnapshotRollbackGuard` rolls back + releases on `Drop` for peel/replay probes | structural |
| Every rewind onto a retained anchor (probes and the reorg apply) uses `rollback_group_state_keeping_live_records`, never `rollback_group_to_snapshot` plus a re-put: a legacy full anchor must not drop a pending application event or restore a removed row or queued intent, and on SQLite the rewind must not read or write the ledger (mdk#2330) | `tests/record_write_atomicity.rs::reorg_onto_a_legacy_full_anchor_keeps_live_records`, `::a_failed_generic_rewind_keeps_pending_app_output`, `storage-sqlite` `snapshots::tests::rewind_keeping_live_records_does_not_grow_with_history` |

Deliberately deferred: **H2** (AAD-binding transport wraps to group_id + epoch) — exporter secrets already differ per
(group, epoch); revisit if a transport reuses exporter material across contexts. **H3** (zeroize `SignatureKeyPair`) —
`openmls_basic_credential` doesn't expose private bytes; needs upstream change or a custom `Signer`.

## Verification

```sh
cargo test -p cgka-engine
cargo test -p cgka-engine --features test-policy-overrides   # suites that install custom policies
just test-convergence-policy-pin                            # default-build v1 policy pin; never with overrides
```

For convergence, delivery, branch-selection, group-data, or multi-client changes, also run the simulator's PR-lane
selection, or the narrowest simulator gate `crates/cgka-conformance-simulator/AGENTS.md` names:

```sh
just simulator-smoke
```

`--features conformance-slow` is a pre-release pass; run it locally only when asked.

Benchmarks and per-file targets are in [`README.md`](README.md#tests-and-measurements) and
[`tests/AGENTS.md`](tests/AGENTS.md).

Borrowed private dispatch must retain the caller's original opaque lease on a
pre-intent SQL error; never recreate that lease from110 or restart. Durable
Dispatching/Unknown state rejects a second invocation. Actual SDK/NIP59/SQLCipher
regression in App covers exact retry and expiry/cancel/shutdown without network
effects after terminal consent.

Unexpected actual selected-tree transitions deny accepted109 and confirmed110
inside the adopting crypto/SQL unit. Candidate materialization must restore the
original tree without touching these denial facts. Expected dedicated private
confirmation writes its successor before merge in the same unit; that exact new
confirmed successor remains live. Denial writes must roll back with failed MLS
apply and survive return to an older genuine crypto snapshot/reopen. Coverage:
`tests/accepted_welcome_receipts/private_batch.rs` private_lineage tests. They use
injected Engine policies/pass-through batch transport, not genuine SDK consent.

Dedicated private Welcome delivery must independently match confirmed110, actual
selected MLS successor/profile, exact owned scope and the original live lease.
Check negative lease controls on every publisher poll. No ordinary replay row,
receipt, snapshot or restart can reconstruct delivery consent or settle a roster.


Predecessor GroupInfo export must freshly validate actual protected completed
settlement and serialize the real MLS public tree in the same read snapshot.
Its bytes are metadata, never an enrollment token. Standard ExternalPub presence
does not authorize external joins. Do not install portable PublicGroup scratch
state in account MLS storage, skip account proof/private-profile validation,
infer the secret epoch authenticator, or append artifact authority after SDK
confirmation. The original live SDK context must bind any future artifact digest
before verification, with explicit all-current-leaf approvals and atomic trusted
successor handoff independently required.


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

The separately versioned v2 enrollment-request metadata frame carries bounded
base64 artifact and canonical-context declarations within the unchanged16KiB
complete payload limit. V1 must omit proposal parts; v2 must include both. Each
version has its own binding domain. Received parts remain opaque metadata until
App canonical/context validation and Core portable artifact authentication;
neither decoding, receipt nor a digest constructs owner consent or Add permission.
Larger proposals require separately qualified transport/aggregate byte bounds.


## Original local enrollment proposal owner

`private_enrollment_request/producer.rs` derives metadata from the installed
trusted private invite lease and fresh Completed actual tree, selected generation,
purpose package and own signed artifact. Its default-deny lease accessor provides
only original context/artifact/clock metadata. Retain the exact nonclone lease and
weak originating Core lifetime; neither shared policy Arc nor reopened protected
SQL state may transfer the owned proposal. Core teardown permanently ends it.
Recheck actual tree/generation/origin, policy identity, cancellation and original
deadline even for cached wrapper retries. Commit the real send ratchet once and
keep exact cipher/wrapper bytes in the owner. The proposal producer never stages Add or ordinary Sent work, and cannot
reconstruct consent. Only the dedicated original-lease handoff below may stage
an endorsed Add. App must separately supply genuine
original SDK metadata, explicit all-current-leaf approval and guarded publication.
The three Core tests inject policy and minimal context; they are not SDK proof.

## Received endorsement fences

`private_enrollment_request.rs` seals the actual protected origin and Completed generation into each opaque observation. `private_enrollment_predecessor.rs::validate_private_enrollment_request_predecessor` authenticates the artifact against that original selection and its occupied carrier via public OpenMLS `Verifiable` APIs. `private_enrollment_endorsement.rs` requires the same fresh selection before creating or validating an owned action. Keep the portable signature test separate from original-SDK local approval; its test-only signer creates no owned continuation.

## Private endorsement publication and original local collection

Kind38176 is the separately classified encrypted endorsement control. Its actual
MLS receipt shares the bounded128 intake queue and transactional direct/replay
effect seam with requests; ordinary/history ingestion cannot mint receipts.
`wrap_private_enrollment_endorsement` retains exact ciphertext after wrap failure,
rolls ratchets back on SQL failure and rechecks the original protected selection
after awaits/cached retry. The exact-generation cancellation handle only revokes
and wakes a stalled wrap; stale handles must not cancel later generations.
`endorse_owned_local_enrollment_proposal` signs only through the original trusted
lease. Collection accepts actual received sibling receipts plus that local signature
under fresh origin/generation/tree checks. It returns authentication metadata,
never an Add, sibling transition or recipient admission capability. Core fixture
policies are not stock SDK proof; App publication and ABC settlement are separate.


## Original endorsed proposal to Add handoff

`producer/add_handoff.rs` authenticates actual sealed sibling receipts plus the
original local signature, then borrows the same SDK-owned lease slot through
shared private preparation. Never swap policy, drop/recreate the lease, begin a
second verifier or turn collection counts into permission. The nonclone guard
retains original owner/policy, protected Completed generation/origin, exact
predecessor/artifact/binding and original observation clocks. Pending MLS is
allowed only for its remembered exact raw staging scope/digests; the internal
predecessor-tree helper does not widen public Completed/candidate queries.
Raw SQL rollback preserves original custody; cache failure retries the same raw
ciphertexts/generation. On success the same guard moves into Prepared and the
producer loses its lease. Dispatch rechecks inside intent SQL and network polls;
Welcome delivery retains original owner/clocks plus actual110 confirmation.
`preparation_has_started` and the retained minimum deadline are observation-only
metadata, never positive capabilities. Core expiry fixtures inject a trusted
policy/attempt; stock SDK proof lives in the separate real App worker tests.

Original recipient evidence never replaces the SDK lease. Check the same Core
lifetime/exact purpose before and after peeling and inside actual join SQL;
compare the declared predecessor to the original lease-approved descriptor.
Preserve the existing atomic crypto/109/purpose transaction.

Protected successor and route reads also recognize the distinct private11
Existing origin, always under exact actual indexed tree/owner checks. A matching
Existing origin conflicts with any other matching live successor origin; no
precedence grants settlement. Actual changed-tree apply permanently denies its
retained generation in the adopting crypto SQL unit. Retained provenance may
exclude hidden groups from chat, including denied rows, without granting a route.

The sealed original B endorsement continuation checks exact original owner,
generation, deadline, protected Completed predecessor and all-leaf evidence.
Only canonical actual single-Add apply installs private11 before old-origin
fences in the same crypto/SQL transaction. Preserve Storage error classification
through replay so App can retain that same live action after rollback.

Original existing-member Add apply stages its settlement admission inside the crypto SQL transaction and installs memory authority only after commit. Maintenance reuses a round only with the identical original live guard, deadline, anchor and protected generation. ACKs may arrive before the coordinator Challenge: retain bounded sealed receipt metadata without binding nonce or counting a fact; promote matching receipts only under the same live admission and genuine coordinator Challenge in crypto SQL. Cancellation and rollback cannot reconstruct authority.

### Selected-chat consent observations

`selected_chat_consent` exposes only bounded canonical request/response metadata signed by the actual protected indexed device leaf. Fresh completed protected full-tree checks and exact source signatures authenticate observations, not membership. Request export also derives the actual Current/admin ordinary anchor. No arbitrary signing API, account-shared signer, MLS mutation or SQL permission is added. Future recipient joining must check its original live purpose and the actual decrypted Current/admin/full tree through the transaction tail; signed remote ordinary claims alone cannot grant admission.

Selected-chat private packages use a trusted original process lease, with bundle, independent purpose row, bounded signed offer and final lease check in one transaction. Scan all exact selected Welcome refs including terminal tombstones before generic usable-bundle fallback. SQL metadata never grants admission; package-only success is not chat delivery. Exact cleanup must verify actual bundle bytes/account/device/ref before deletion.


Selected ordinary-chat staging and joining require a separately retained original request/consent lease, fresh exact protected full tree plus device-local Completed generation, actual Current/admin ordinary state, exact consecutive two-Add successor and unchanged indexed predecessor identities. The source's signed protected generation is local to that source; receivers independently capture/recheck their own local generation. Private KeyPackage transport identity is a default-denying trusted lease accessor, never a constructor/grant from imported metadata. Scan all Welcome references for independent terminal/pending purposes before generic bundle fallback; keep actual private bundle consumption, purpose transition, full decrypted Current/admin/tree validation and original lease tail in one SQL transaction. Selected guarded staging creates no generic durable Welcome fanout. Preserve ordinary unguarded Invite behavior. Actual four-leaf delivery is qualified through the App regression; broader current-source conformance and fault retry remain independent gates.

## Opt-in history channel foundation

HistoryScope and authenticated requests are observations, never consent grants.
Retain each original trusted lease, deadline and originating Engine identity; check
fresh actual protected Completed generation/full tree and ordinary Current epoch
and authenticator before and after crypto. Every frame binds the complete original
context plus the exact signed request/consent transcript. Device-local generations
remain independent. Same-body encryption retries return frozen bytes; a different
body is refused. HpkePrivateKey contains pinned SecretVLBytes with ZeroizeOnDrop;
explicit channel retirement drops the retained key. Never serialize or clone an
owned channel or restore its original lease from history rows. This checkpoint is
one-body inner encryption only; real MLS transport, third-member privacy, ordered
manifest/chunks, committed import ACK and native adoption remain separate gates.

History control MLS wrapping freezes its actual ratchet in the crypto SQL unit
with the original lease tail, invalidates loaded group caches on both outcomes,
and retains exact ciphertext across wrapping retries. At most two own controls
per original channel; every cached/awaited return rechecks the same actual scope.
Never create ordinary Sent, generic fanout or restart-reconstructed publication
permission. Pair controls qualify MLS framing only, not committed history import.

### Ordered history original-state bounds

`history_transfer/chunks.rs` retains at most128 sealed/opened indexed chunks and
129 exact outbound controls per original (request/consent plus chunks/receipts).
Each plaintext chunk is at most2048 bytes, each canonical wire at most16KiB.
This process-local owner resource is separate from convergence policy: fixed
original lease/Engine ownership, no SQL resurrection, renewal or per-chunk new
consent. Retire/drop clears ciphertext/peer state and zeroizes the HPKE secret.
Core receipt framing cannot prove committed import; trusted App importer must
validate manifest/count/receipt semantics. Production Nostr size remains a
separate actual-wrapper gate; Passthrough tests do not qualify relay envelopes.

Exact device-leaf review capture derives the Current/Stable ordinary full indexed tree, actual admin/own leaf, epoch authenticator and same-account non-self target under a fresh protected Completed roster/generation read. The opaque selection is tied to the originating Engine; every review read revalidates all captured state. Public review metadata grants no Remove and cannot reconstruct the original. Reuse the canonical selected-chat indexed leaf validator rather than inventing a host tree inlet.

Exact ordinary sibling removal now stages one real Remove under a fresh Core selection and trusted original runtime lease. Pending and confirmed validators require exact indexed successor, unchanged survivor identities/leaf commitments (sender path may refresh), original protected Completed generation and originating Engine. The generic account removal path remains separate; no selected Invite or protected-group removal grant is created.


### Exact-device captured-scope removal checkpoint

Device-wide exact-leaf removal captures fresh protected Completed generation and actual indexed trees. Ordinary groups precede the protected group; ordinary-only selection still refuses protected groups. Pending protected predecessor validation requires the same original memory lease and exact staged single Remove. It never fabricates Existing/Add provenance. Fresh successor settlement is a separate required step.

### Original protected Remove successor settlement

`device_leaf_revocation/transition.rs` stages Revoked metadata and the actual live settlement admission atomically with the authenticated sole Remove. Source admission retains the explicitly approved original admin action; recipient admission requires its exact live transport receipt and canonical MLS digest after durable content dedup. Stored canonical replay after Engine/encrypted reopen can apply negative membership but cannot allocate a new positive deadline/guard. Every old origin remains permanently denied. The actual public survivor history import and restart refusal pass; same-client transient storage retry and post-revocation new-device enrollment remain separate. See `docs/device-sync-revocation-successor-settlement-verification.json`.

Same-client protected Remove storage retry is now qualified: a negative observer requires the already captured live received intent plus its exact retained receipt/deadline, unresolved input, and actual Completed predecessor/tree/generation. It creates no permission. The worker preserves this originating Engine across typed Storage rollback; encrypted reopen still cannot reconstruct its original receipt. See `docs/device-sync-revocation-storage-retry-verification.json`.

### Original enrollment sharing terms

`private_enrollment_endorsement` keeps ordinary v1 byte shape and a distinct
signed sharing protocol/domain for the named broader received-request action.
Bind fixed policy version/capabilities, exact request and indexed signer; preserve
the same original owner/deadline/cancellation. Changing terms requires a new
protocol/domain, not reinterpretation of old signatures. All-leaf and original
recipient `sharing_devices()` are authenticated observations only, never policy
or admission. `private_enrollment_sharing_tests.rs` reuses genuine received B
fixtures and real private carrier; portable A signatures are explicitly metadata.

Initial-bootstrap recovery is negative only: require a Denied original settlement,
no live admission, no retained sharing policy (including revoked), an exact fresh
private successor matching that round, and genuine epoch-0 one-leaf → epoch-1
two-leaf provenance. Retire the accepted/confirmed selection in that same SQL
transaction; never delete MLS/chat state, reconstruct consent, retire Completed
or larger rosters, or infer recovery eligibility from native/wire fields.
Core controls use genuine MLS with injected policies; App interrupted enrollment
acceptance supplies actual SDK, encrypted relay and restart coverage.

Switching roles after cancelled setup may leave an unchanged epoch-0 singleton
genesis on the new recipient. Only the authenticated private join may retire
that selection: validate the live lease and incoming full tree first, revalidate
the original local birth, refuse any historical sharing policy or settlement for
that birth, then deny it in the same SQL transaction as accepted-anchor admission.
Preserve all competing-origin/pending-invite checks and rollback on later failure
or expiry. Keep old MLS state and immutable provenance; never extend this path to
an established or advanced group. Hydration before the transaction is observation
only. Controls live in `accepted_welcome_receipts/private_batch.rs`; the genuine
App regression reverses roles after actual public setup and cancellation.
