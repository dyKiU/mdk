# Account-wide departure source checkpoint

## Account-owned submission repair (2026-10-13)

Signed runtime/test source `a750af7e27ed8af14cd55d24c9ae7bb53f7a6b68`
moves experimental local-versus-forwarded group classification into the existing
account-gated blocking admission. An owned continuation survives host cancellation
through forwarding; the default path still awaits directly. Queue timing,
projection updates, lifecycle checks and normal forwarding authority are preserved.
No wire, schema, binding declaration or production thread-stack setting changed.

The frozen `e07071ab` backend passed default tests (4,240 passed) but failed
experimental tests (4,889 passed,4 failed). Its four subsequent static gates and
all SDK gates were not executed. Two initial departure failures retain an active B
leaf on a different epoch3 branch from D; the sibling retained-authentication retry
assertion also remains unresolved. This submission component does not fix them.

All prefixes below are under `/Users/pj/project/build/results/`.

| Scope | Actual result | Prefix |
|---|---|---|
| Existing unchanged admission fixture against preserved e070 executable |0 passed,1 failed,0 ignored; fixed2s gate timeout|`account-submission-e07071ab-blocking-admission-red-v1`|
| Same admission fixture on a750 |1 passed,0 failed/ignored|`account-submission-a750af7e-focused-v5`|
| Real forwarded send after host waiter cancellation |1 passed,0 failed/ignored; actual caller held before SQL, host aborted before release, source publication1 and exact canonical mirrored record|same v5 prefix|
| Experimental queue/removal timing controls |2 passed,0 failed/ignored|same v5 prefix|
| Forwarded reply, offline/reopen, recipient SQL rollback controls |3 passed,0 failed/ignored|`account-submission-a750af7e-affected-v6`|
| Default queue controls |2 passed,0 failed/ignored|same v6 prefix|
| App all-targets Clippy default and experimental, including test-policy/exports |both exit0, `-D warnings`, no exemptions|same v6 prefix|
| Whole-workspace formatting |exit0|same v6 prefix|

The original admission fixture is byte-identical to e070. Focused tests use one
libtest thread versus the full cohort's two, the same App experimental/OTLP/analytics/
test-policy features, Rust1.97.1, debug0, incremental0, jobs1 and4MiB test stack.
The new cancellation fixture uses a bounded cfg-test-only caller hold with RAII
release; it is not a database-blocking regression. Its genuine source/canonical
record assertions and body marker executed. The composed fixture checks normal
ABC shutdown results, without additional storage-closed flags. All frozen inputs
remained unchanged; the original executable is separately hash-preserved.

Earlier v1 missing-import compilation, v2 zero forwarding selection and v3
single-thread fixture database starvation are retained nonqualifying attempts.
The corrected cancellation hold changes only test behavior. Final full fast-ci,
six-package backend qualification, generated SDK and installed-host acceptance
remain required; this component authorizes no SDK/app promotion or fork publication.

## Current component checkpoint (2026-10-12)

Signed component source `430be45ea43045f7115fac9c52d657d04cda2255` includes
`9158365351319d8c0f0e672cf933e6af5f89ec98`: an authenticated, byte-identical
already-committed departure retries its durable receipt without retiring the
receipt channel again. Fresh cuts still invalidate/renew; the existing Core,
policy, roster and SQL before/tail checks remain unchanged. No wire, schema or
binding declaration changed.

All prefixes below are under `/Users/pj/project/build/results/`.

| Scope | Actual result | Immutable source / prefix |
|---|---|---|
| Authenticated identical intent while actual complete receipt is held |0 passed,1 failed; actual removals complete,8 held contexts/6 queued retries/5 authenticated duplicate SQL applies, completion misses fixed30s|e9b6c208 / `account-wide-departure-e9b6c208-duplicate-receipt-commit-diagnostic-v36`|
| Same fixture and deadlines after inserted-only renewal guard |1 passed,0 failed/ignored; actual held/queued/applied counts1/1/1, actual ordinary removals and all participant completion/denials/closures|42aaa99c / `account-wide-departure-42aaa99c-commit-rejection-diagnostic-v41`|
| Ordinary offline departure, both fresh accepted sources and old intent replay, actual administrator/source winning branches |4 passed,0 failed/ignored|42aaa99c / `account-wide-departure-42aaa99c-duplicate-receipt-affected-v38`|
| App default strict |exit0, no exemptions|42aaa99c / `account-wide-departure-42aaa99c-duplicate-receipt-strict-v39`|
| App experimental strict |exit0, no exemptions; manual aggregate Debug only corrects diagnostic dead-code lint|430be45e / `account-wide-departure-430be45e-duplicate-receipt-strict-v42`|
| Actual C→UniFFI→App boundary |consumer1+producer1 passed,0 failed/ignored; real two-source removals/receipts, same-root durable completion and positive owner closures|430be45e / `account-wide-departure-430be45e-native-ffi-v43`|

Receipt SQL20, storage strict2, no-policy default/experimental2, original SDK
approval/cancellation controls and delayed Request evidence in the historical
records below are retained
against unchanged relevant inputs. The current guard does not fix public MLS
convergence: attempts35/37 failed before the receipt body (no held or applied
duplicate), with an active B leaf and an exact rival commit rejected against
candidate state. They remain unresolved prerequisite failures, not receipt REDs
or GREENs. Earlier33/34 similarly failed forced-fork prerequisites. The
experimental strict attempt39 failed diagnostic dead-code checks and is retained;
42 fixes only the aggregate formatter. Source430 otherwise preserves the tested
42 runtime and fixture predicates.

Native43 uses the existing4MiB test-thread/8MiB composed-producer profiles;
shipping default-stack, full final CI, generated SDK and installed-app acceptance
remain required. Whole-workspace `cargo fmt --all -- --check` passed at430
(empty log SHA256e3b0c442…). Component results authorize no SDK or app promotion by
themselves. The docs-only205 integration ancestry is preserved.

Full workspace fast-ci at009b0862 stopped in `check-default` with a missing
exhaustive simulator error arm (0 Rust tests; retained raw SHA256cf62c5df…).
Signed4b88bf8b adds only the conformance adapter's permanent ExpectedRefusal,
nonretryable, static-label mapping for AccountChatDepartureDenied. Its existing
privacy/error-classification test passed1 default +1 experimental,0 failed or
ignored, under `automatic-final-4b88bf8b-simulator-classifier-v2`; whole-workspace
fmt passed. App, Core, native declarations and the component runtime remain
unchanged. Full CI restarts on this documented source, followed sequentially by
six-package backend and Apple SDK qualification.

## Historical receipt-snapshot checkpoint (76f7e9e6)

Runtime source: `76f7e9e60ef25195521e45acc980808022e9d22f`; its only change from
`8e108b30460f0fdb1c13cfb2f5ca1723c68aba2e` is borrowing existing SQL test scopes
instead of cloning them. Full final integration CI, SDK generation and shipping
native/installed-app qualification remain required. No deployment or fork
publication is implied by these component results.

All evidence prefixes below are under `/Users/pj/project/build/results/`.

| Scope | Actual result | Immutable source / prefix |
|---|---|---|
| Published receipt snapshot regression |0 passed,1 failed: stale incomplete publication erased newer completion receipt|7240b815 / `account-wide-departure-7240b815-stale-receipt-red-v17`|
| Receipt flags/phase fencing, guard rollback, negative journal and25→26 migration controls |20 passed,0 failed/ignored|76f7e9e6 / `account-wide-departure-76f7e9e6-receipt-sql-v22`|
| Latest real C→UniFFI→App departure |consumer1+producer1 passed,0 failed/ignored; actual two removals, completion receipts, durable same-root reopen and all checked closures|8e108b30 / `account-wide-departure-8e108b30-native-ffi-v19`|
| Storage/App strict default and experimental |4 passed, no warning exemptions|76f7e9e6 / `account-wide-departure-76f7e9e6-receipt-strict-v23`|
| Initial departure before fresh-rejoin/replay |0 passed,1 failed: B still active, same epoch but different B/D branch, real B proposal retained/received|76f7e9e6 / `account-wide-departure-76f7e9e6-receipt-affected-v24`|
| Ordered branch/reopen |0 passed,1 failed after real branch switch/reopen and both removals: coordinator still awaited one peer receipt|76f7e9e6 / `account-wide-departure-76f7e9e6-receipt-controls-v25`|
| No-policy refusal default/experimental |2 passed,0 failed/ignored|76f7e9e6 / `account-wide-departure-76f7e9e6-no-policy-v27`|
| Genuine pending-handshake restart functional regression |matched0/1→1/0; identical source-scoped exact-record predicate, only37 actor lines differ|a5005561→4935e208 / `pending-scoped-baseline-v9` and `pending-scoped-green-v10` (account-wide-departure prefixes)|
| Actual delayed higher Request after real Consent, original broad/plain/cancel/authentication retry, fresh-rejoin/replay and branch-equal device-only survivor |7 passed,0 failed/ignored; required body markers independently audited|26214d0b / `account-wide-departure-26214d0b-required-residual-v11`|

Publication now retains the actually serialized reply kind and progress flags.
The owner-checked before/tail SQL transaction clears pending work only if those
flags and the coordinator phase are still current. A stale snapshot is a
successful no-op; it does not erase newer work or assert remote commitment.
This fences changed payload/phase, not arbitrary ABA revisions. The earlier
nativec102 completion timeout and all invalid fixture-oracle/compiler attempts
remain retained; the SQL regression proves the receipt race independently,
while the latest native journey establishes the repaired source's boundary.

Earlier setup-only collision/restart passes did not execute their intended bodies.
Nonce-change requirements and unified-view private-arrival requirements were
invalid oracles; their failures do not establish private-delivery regressions.
Current tests require actual authenticated current Core channels and exact
source-scoped private catalog/record delivery. The device-only survivor requires
bounded actual branch convergence before its ordinary send; this establishes
that steady-state case, not a fix for every historical convergence timeout.

Binding parity400, UniFFI413/C618 callable references and all17 binding-doc
regressions pass on unchanged exported API/header inputs. Native v19 used the
existing4MiB test-thread and8MiB composed-producer profiles; shipping default
thread stacks remain a final SDK/host gate. Jobs1/debug0/incremental0 and the
20GiB pre-gate disk floor were preserved. Final formatting is pending.

The component is not ready for promotion: the native receipt journey passed,
but the current composed App failures above remain unresolved. The natural
21cd diagnostic run passed1/0 and establishes no causal repair. Diagnostic
captureae22 failed compilation (tuple Debug limit,0 tests); the real source-
preferred fixture6f failed its own Sent-only commit lookup before branch
selection. Confirmed own commits intentionally become Processed, so that lookup
and Sent-only absence observations are invalid ownership oracles. Both attempts
and positive cleanup evidence remain retained. No shipping behavior changed in
these diagnostic/fixture captures. A removed leaf's epoch authenticator cannot
establish post-removal disagreement with the administrator; v25 is a receipt
failure, not proof of a new post-removal convergence defect.

## Historical scoped qualification (c7b0150a)

At this checkpoint, signed local candidate:
c7b0150a (signed source-only diagnostic follow-up to 8a597c57). Passing private25 parent is
78a8b58d43407299c9913ae87fb1253ebe736cfb. This is an unfinished departure
slice: genuine account-wide departure→fresh accepted rejoin/late-negative
lifecycle controls, final required full CI, SDK/language/host promotion and the
installed three-device demo remain pending. No fork or SDK passing publication
is implied. The preparation sections below describe historical captures.

Actual scope and immutable evidence (all prefixes under
`/Users/pj/project/build/results/`):

| Scope | Actual results | Source / artifact prefix |
|---|---|---|
| Source26 SQL, raw OR REPLACE/UPSERT guards, origin observation, strict25→26 fingerprint |18 passed,0 failed/ignored|66dd2720 / `account-wide-departure-66dd2720-sql-v3`|
| Real proposal dependencies and branch-relative evidence; durable failed reanchor rollback/restart |2+1 passed|388b6735 / `account-wide-departure-388b6735-core-guards-green-v1`|
| Affected Core replay default/experimental |14+14 passed; two opt-in measurements explicitly excluded|05b707e6 / `account-wide-departure-05b707e6-core-affected-v1`|
| Full named atomicity default/experimental |23+26 passed,0 ignored|05b707e6 / previous prefix and `account-wide-departure-05b707e6-core-atomicity-exp-v2`|
| Genuine ordered departure |1 passed: actual losing same-epoch branch, checked B close before retry, fresh same-root reopen, D actual A+B removals, ABC receipts and denial|388b6735 / `account-wide-departure-388b6735-ordered-v11`|
| Original offline departure and device-only survivor |1+1 passed; prior intermittent survivor timeout remains unresolved|05b707e6 / `account-wide-departure-05b707e6-survivor-diagnostic-v1`|
| No-policy refusal default/experimental; ordinary creation and separate device-only leave unchanged |1+1 passed|48a78851 / `account-wide-departure-48a78851-no-policy-green-v2`|
| Genuine C→UniFFI→App boundary on real A/B sources,C mirror,D admin |consumer1+producer1 passed,all owners checked-closed,artifact bytes unchanged|5dbba5a0 / `account-wide-departure-5dbba5a0-native-ffi-v6`|
| Status mappings default/experimental |3+3 passed;133 appended,older values preserved|8a597c57 / `account-wide-departure-8a597c57-native-status-v1`|

The native journey proves real ordinary sends from both reopened native source
clients, mirrored initiator readiness, offline B Pending, both actual independent
D removals, completion receipts, typed A/B/C token-send refusal, and durable same
operation/fence after C closes and reopens its original root. No live databases
were copied and no native original or ordinary membership was created from
metadata. The producer and consumer use a bounded private0700/0600 Unix socket.

Strict Core/App and UniFFI/C default+experimental `--all-targets -D warnings`
gates passed without `dead_code` or `linker_messages` exemptions. Their raw
source receipts are in `66dd2720-core-app-strict-v3`, `bdb1d400-app-strict-v5`,
`48a78851-app-strict-v7`, `0b14d649-native-strict-v1` and
`8a597c57-native-strict-v2` (all with the `account-wide-departure-` prefix).
Only unchanged relevant inputs retain earlier passing scope; genuine failures
and intermediate static/fixture failures are preserved separately.

The C header was generated by actual M5 cbindgen, then authored contracts and
all source/header anchors were refreshed: parity400 exports, UniFFI413/C618
callables and all17 binding-document regression tests pass. Exact generated
header/log are `account-wide-departure-5dbba5a0-native-ffi-v6-marmot.generated.h`
and `account-wide-departure-5dbba5a0-header-generation.log`.

Rust1.97.1, jobs1, debug0, incremental0, minimum20GiB free and test-thread
stack4MiB were used. Composed App producer tests use their existing8MiB runner.
These are fixture-profile results, not shipping default-stack qualification.

Causal runtime failures are retained: an unrelated B proposal's membership tag
rejected D's competing commit before materialization; after selection, a durable
same-epoch marker suppressed leave reproposal; another unrelated proposal then
vetoed a commit with its real referenced dependency. Only branch-relative
InvalidMembershipTag is ignored after an actual authenticated replayed commit
established this proposal epoch. Ignoring supplies no proposal/reference or
permission; missing/wrong consumed refs, proposal-only replay, malformed input,
authorization, all other validation and storage errors remain strict.

The first affected default count prediction25 was wrong: the full harness
actually ran and passed23. Its count-mismatch driver result remains preserved;
it is not a Rust/runtime failure. Outer Nostr wrapper retirement is not missing
intake; exact canonical-content lookup corrected that earlier inference. Native
feature-selection/nonce-export/private-mode/nonblocking fixture prerequisites
are not SDK behavioral REDs or acceptance. The former device-only survivor
failure waiting for D decryption remains a specific intermittent concern even
though the later diagnostic and genuine native ordinary-send controls passed.

## Historical both-source departure/rejoin failures

The new genuine fixture selects each actual A/B lifecycle-owned acknowledged
package through its exact authored relay event and normal parser, uses D's
ordinary Invite, holds both new Welcomes before explicit acceptance/recovery
confirmation, and checks each local accepted origin has a distinct ID and a
higher source-local order. Managed owners close before standalone same-root
owners; all owners positively close on failure. No database or original is
copied or synthesized.

Actual lifecycle sources2ce46164 and3b08094a failed0/1 after the original
account departure completed, D removed both old leaves, both fresh Welcomes
were genuinely accepted, and D decrypted a fresh ordinary send. C still
retained both old origins and had no live mirrored event. This rules out a
mere unified-timeline source choice as the current cause. Raw prefixes are
`account-wide-departure-2ce46164-fresh-both-rejoin-v1` (SHA256
b1ceaed101162f972c5909bb49fcfbf4804ebdc6a703a2ddaec0ed3cab46526a) and
`account-wide-departure-3b08094a-fresh-both-rejoin-v2` (SHA256
5aa63ea579e7cf0a356170f5287c61813b610557b02ac320aff93ced94d65c03).

Existing bounded catalog traces at921dd763 also failed0/1. A/B established
fresh automatic channels and exchanged new Active catalogs between themselves;
C retained its old channels and received no new catalog. This is a restart
handoff diagnosis, not yet a proven initiator-order defect or repaired runtime.
Raw `account-wide-departure-921dd763-fresh-both-rejoin-v4` hash is
da3661cc57d9e861a94bf1dfbf05c76b38f2461bbf318607038add0a6d81f025.
All checked closures succeeded. Sourcec7b0150a adds only a failure-observation
boolean for actual automatic initiator ordering; its run is pending.

The intermediate35df563e capture failed compilation with a temporary-path
lifetime error in the test trace guard (0 tests);921dd763 keeps those owned
paths alive. Neither is a product behavioral RED. The pinned full formatting
check on2ce46164 passed. Runtime test linking emits the Apple unwind-table-size
warning; no warning exemption is used by the earlier strict compile gates.

Fresh C visibility, current Available/no old operation, a distinct new departure,
and retained authenticated old-intent replay remain unqualified. The latter must
requeue exact captured original outgoing fragments on a genuinely fresh validated
automatic channel; repeating an old Nostr wrapper or rebuilding an Intent from
SQL is not equivalent. No production behavior changed in these lifecycle captures.

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
