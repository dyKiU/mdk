# Account-wide departure source checkpoint

## Current scoped qualification (2026-10-12)

The preparation sections below are historical. Private25 is now the signed
qualified source78a8b58d43407299c9913ae87fb1253ebe736cfb and the retained-origin
reader is integrated. Current diagnostic source is
05b707e61a24be7317cfc8ea8161addfffa1b301; its production inputs match
388b6735fe1c100ca3095ca3f5fa5b59fb9136f9. This remains an unfinished departure
slice, with native C/UniFFI, strict/static, fresh-origin lifecycle and final
integration qualification pending. No SDK, installed host or fork-promotion
claim is made.

Actual scoped evidence uses the exclusive M5 target986, Rust1.97.1, jobs1,
debug0, incremental0, minimum20GiB free and test-thread stack4MiB. These are
fixture-profile results, not shipping default-stack qualification.

- SQL18 passed on e92c19629139eb623e89b6b19cfba91a31e04133; the relevant
  SQL/migration inputs are unchanged. This includes raw replacement controls,
  exact retained-origin reads and strict25→26 migration/fingerprint checks.
- Core real branch/dependency controls2 and targeted transaction rollback1
  passed on388b. Actual consumed proposal references remain required;
  mismatching evidence never supplies a proposal or permission. Failed journal
  writes preserve actual MLS state, group projection and original leave intent;
  fresh hydration preserves the reanchored intent before public reproposal.
- Genuine ordered account-wide departure passed on388b: actual same-epoch
  losing-branch switch, checked B close/reopen before retry, actual independent
  D removal of both A/B leaves, all three completion receipts and typed send
  refusal. Default ordinary wire and standard SelfRemove are retained.
- Unchanged device-only survivor and original offline account-wide journey
  passed on05b. A preceding survivor run on identical production388b timed out
  waiting for D to decrypt B's next ordinary send. That intermittent delivery
  concern remains unresolved; a successful diagnostic rerun does not fix it.
- Affected Core replay suites passed14 default and14 experimental (the two
  opt-in measurements were explicitly excluded). Full default atomicity suite
  passed23, zero ignored; the runner's expected25 count was incorrect and its
  count-mismatch result is preserved. Experimental atomicity passed26, zero ignored. Total affected Core tests77.
  Strict lint first found a collapsible test-observer conditional; its equivalent
  let-chain correction is being qualified. Native binding acceptance is pending.

Causal failures are retained: exact D competing commit was rejected by an
unrelated B proposal's InvalidMembershipTag before materialization; after the
first repair selected D branch, the durable same-epoch leave marker suppressed
reproposal; after reanchor/reopen, another unrelated proposal vetoed the actual
referenced removal commit. Real Core regression and final ordered journey cover
these repairs. Only branch-relative InvalidMembershipTag is ignored after an
actual replayed commit established the proposal epoch. Proposal-only replay,
missing/wrong consumed references, malformed input, authorization, other
validation and storage errors remain strict.

Raw immutable inputs/results/logs are under `/Users/pj/project/build/results/`:
`account-wide-departure-e92c1962-sql-v2`,
`account-wide-departure-01c9a118-ordered-v8`,
`account-wide-departure-abff34d2-ordered-v9`,
`account-wide-departure-2dc70186-core-reference-red`,
`account-wide-departure-388b6735-core-guards-green-v1`,
`account-wide-departure-388b6735-ordered-v11`,
`account-wide-departure-05b707e6-survivor-diagnostic-v1`, and
`account-wide-departure-05b707e6-core-affected-v1`, and
`account-wide-departure-05b707e6-core-atomicity-exp-v2`.
Each prefix has its source/blob manifest and results with exact command, count,
duration and raw log hash. Preserve the real failures and fixture-prerequisite
failures separately. Outer Nostr wrapper retirement is not missing intake;
canonical-content lookup corrected that earlier diagnostic inference.

## Historical source preparation

This is an unqualified source capture on the qualified legacy source parent
160f34641df79c660022cc86bad7caaef273e05e and shared origin-reader capture
4032c748fe1c1a13c652cb1c5a5ccce1f8af4a21. It is not a passing delivery,
SDK promotion, installed app, or interoperability claim.

Authored scope: public AppRuntime, UniFFI and C account-wide departure APIs;
explicit pending/completed/readiness DTOs and C denial status 133; private26
negative intents, exact source-origin cuts and durable transport receipts;
automatic actor dispatch and maintenance; standard public device SelfRemove
reuse; local and mirrored send denial; genuine A/B ordinary-source, mirrored-C
caller, independent-D administrator/offline acceptance fixture; storage
rollback, scope, offline-receipt and encrypted-reopen controls. Existing
device-only leave behavior is preserved.

Checks performed: changed Rust sources formatted with rustfmt edition 2024
(skip_children enabled), and git diff --check. No compilation or runtime tests
have been run for this source capture.

Missing coordinated inputs before coherent compilation:

- Passing private25 accepted-origin catalog/record fields and migration.
- Retained-origin observation reader
  current_mirrored_chat_origin_observation(account, local, source, group),
  returning only configured-owner checked id/order metadata, independent of
  live-view filtering; it does not grant policy or MLS membership.
- Private26 migration registration after the real private25 migration, and
  connection-only negative-cut checks in the rejoin-owned SQL read/append paths.
- Separate agent-owned genuine FFI producer/consumer child modules. The additive
  registrations are captured here, but those child source files are not yet
  present.

Remaining qualification: genuine runtime RED/GREEN, authenticated replay and
rollback controls, affected default/experimental tests and strict checks,
native bindings tests, authored API guidance/parity and generated C header.
No compiler/cache lane was used; private25 diagnostics currently own 986.

## Subsequent source-only audit

The retained-origin metadata reader was added as separate signed source capture
ca6078800afbfe8d8c952c8bb998dc6a8762adbd after the private25 owner supplied
its exact schema and explicitly loaned the new module. It remains uncompiled
until the real private25 migration is adopted.

The follow-up state audit prevents an active ordinary leaf with incomplete
origin discovery from inheriting an old Completed API state. Fresh observed
origins already take precedence over old group-ID-only operation progress. A
removed local leaf's old tree is deliberately not treated as a current census
of other ordinary sources: it cannot decrypt their subsequent removals.

Publishing a leave clears actionable local administrator/source-discovery
refusals without marking local removal complete. Added storage test source
requires actual local-complete progress before global finalization and checks
that a fresh accepted lineage can create a distinct operation after an older
one completed. The genuine two-source fixture now waits for all participant
completion notices as well as independent D's canonical A/B leaf absence.

New fixture originals are cancelled before workers are closed/reopened;
behavioral assertions unwind through checked closure of every registered owner,
including reopened B, before the original failure is resumed. The C fixture
uses the existing fs-private workspace dependency only in dev dependencies.

All these are source-only corrections. No compiler or test lane was used;
formatting and whitespace checks do not establish behavioral qualification.

## Origin-correlated progress audit

Progress no longer selects the newest row merely by canonical group ID. The
bounded journal scan compares each exact source's retained private25/local23
current id/order with the operation's negative targets, independently of
cut-filtered live rows. Entirely superseded operations are excluded; missing
or inconsistent observations return unavailable progress. Pending operations
for a current lineage take precedence over completed concurrent operations,
with stable action identity only as a tie-break. Counters from different
sources are never compared to determine freshness. Pending/denied local
metadata is used only to exclude stale progress, never as positive permission.

Added storage regression source covers a delayed old completed intent arriving
after fresh pending work, concurrent same-lineage pending/completed operations,
missing metadata, fresh origins without an operation, and unrelated sources
with different local origin counters. These checks remain uncompiled and
unrun pending the actual private25 schema and a coordinated compiler loan.

## Separate candidate integration

Branch `codex/account-wide-departure-candidate-eae759` combines exact source
eae759e966a3050e98689d9afeb6ec5122ee7a06 with the preserved 0da8 departure
checkpoint. The original departure branch remains unchanged. Merge conflicts
were confined to additive automatic actor module/maintenance hooks and native
test child registrations; both rejoin and departure behavior was retained.
The genuine FFI child source8c953e36086be2459524dd13e98bd4c064137549 is adopted
as861a5e91 on this candidate.

The real private25 migration now precedes private26. Private26 extends the
shared live-catalog SQL view with exact account/local/group/source negative
cuts, so existing locked list/header/history reads and message lineage triggers
all honor departure. Explicit connection-only checks also refuse cut Active
catalog writes and message appends, without recursively acquiring a SQL lock.
Added synthetic storage acceptance source checks existing disclosure removal,
late-record refusal, retained-origin observations, and fresh-lineage reopening
without disclosing old records. This is not transport or membership evidence.

Catalog origin/count and every canonical record origin use the exact adopted
optional serde contracts; no private25 live worktree or compiler/cache lane was
changed. Candidate integration remains unqualified: no compilation, native ABI
acceptance, SDK generation/promotion or fork passing publication has occurred.

## Immutable SQL replacement audit

Private26 now refuses duplicate identity inserts for intents, cuts and routes
with BEFORE INSERT guards, including OR REPLACE when recursive triggers are
disabled. Newly inserted route progress must start unconfirmed; route identity,
acknowledgement, completion and final acknowledgement cannot regress or be
deleted. Existing exact App retries read rows before insertion and remain
idempotent. Intent global completion cannot be downgraded.

Raw SQL regression source exercises OR REPLACE and UPSERT under default, off
and on recursive-trigger settings, checks exact retained payload/cut/confirmed
route values, rejects initially forged-complete routes, and retries the real
journal API. These are unrun storage controls, not authenticated peer evidence.

The private migration fingerprint implementation is unchanged. Its existing
per-revision reference snapshots validate the old25 view before upgrade and
the exact26 view afterward. Added upgrade test source requires25→26 success
then rejects restoration of the old view under a26 ledger, retaining strict
schema validation without exclusions.

The exact private25 snapshot-test correction was adopted from file blob
401ffa62b23ef96e4ac959df4cd48d76fea1106a as signed one-file commit
d534f4c244bf4eeb8d8dc14c95b7f32ec58f5675. No other inputs from that capture
were imported. No compiler or qualification lane was used for these changes.
