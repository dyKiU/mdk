# Supplemental acceptance using an existing Apple SDK

`Upstream supplemental native acceptance` runs only for pushes to dedicated
`ci/upstream-acceptance-*` branches or an explicit manual dispatch. Opening its
review PR does not trigger a second supplemental run. The committed
`acceptance-cohort.json` supplies exact SDK producer, SDK source and app commit
identities for push mode. Manual inputs can specify a different immutable
cohort explicitly.

The Linux preparation job waits for the named artifact from the existing SDK
producer. It does not dispatch, rebuild, cancel or retry that producer. The
Apple jobs validate its package provenance using the original producer run ID
and source SHA; the supplemental workflow/tool commit remains a distinct
identity. These helpers do not change any running qualification checkout.

The hosted lanes establish separate evidence:

- Published 0.13.0 versus experimental iOS SDK interoperability: separately
  compiled simulator workers on two isolated simulators, independent accounts,
  invitation receipt/acceptance, authenticated messages in both directions,
  original-store restart, offline messages and offline invitations. The published
  native archive must match the app's immutable release checksum and the
  generated Swift must match the pinned app source.
- Hosted native history and lifecycle scenarios from `hosted_history.py`, using
  unchanged committed acceptance helpers with their recorded source hashes.
- The final iOS full experimental suite with the same existing SDK, followed by
  a missing-German-translation mutant against two already built native catalog
  tests. Exact catalog bytes are restored before the passing controls. Empty
  filtered runs or compile failures do not count as mutation detection.
- The final Mac full experimental suite, Release build and static analysis,
  consuming the existing matching Mac SDK package.
- The original one-scan native scenarios, including existing/new direct chats,
  discovery, history and offline recovery, using the original frozen controller
  and the same existing SDK source. Producer identity remains the original
  `sdk_run_id`, even when that producer's obsolete app jobs were cancelled.

After each full app suite passes, the missing-key classification gates compile
and run focused obsolete-publication tests against reason-wildcard mutants:
one Mac classifier and two independent iOS classifiers. Each must execute
exactly one failing runtime regression, restore the source bytes, and execute
one passing control with no skips. Compile failures and empty filtered runs
do not kill these mutants. Their aggregate reports and explicitly named logs
contain only synthetic classifier fixtures; native worker logs and stores
remain excluded from upload.

Only aggregate native/controller results and provenance are uploaded. Native
worker IPC, private stderr, credential keys and account stores are excluded.
The final iOS XCTest result bundle and its execution summary are retained as
standard app-test evidence. The simulator and native SDK journeys establish no
installed TestFlight UI, physical-device or APNS claim. See the hosted history
result's explicit remaining limitations before treating a scenario as qualified.

`acceptance-lanes.json` freezes the explicit lanes selected for this run. A scoped
repair run is not a full qualification by itself: reuse earlier passing lanes only
when their product, SDK, test body and relevant configuration are unchanged, and
retain their exact original source/run identities. The separate pagination push does not rerun the ongoing five-lane cohort.
One-scan diagnostics observe original commands without changing deadlines,
comparison, approval or sharing requirements.


The separate `history-pagination` lane sends 199 actual prejoin messages through
an ordinary member, then preserves the original explicit selected-chat consent
and admission actions. One postjoin message remains live. An explicit history
original reviews all 200 source records; after recipient approval, its 199
historical records must enumerate in six pages of 37/37/37/37/37/14 with exact
canonical IDs, contents, tags and source/transfer/manifest provenance. A second
complete enumeration must match exactly, with no nonrecipient archive disclosure.
Worker stores and messages remain private; only aggregate results and derived
source provenance are uploaded. The added native command is read-only, fixes its
page size to 37, and validates the optional cursor. A separate read-only exact-ID
observation command scans this fixture's complete live kind-9 set (query limit
201, reject more than 200), so the frozen 128-row message tail cannot hide early
records. Only this fixture wraps original message observations with that command.
The unchanged request/consent/import deadline remains 30 seconds. The archive
API uses message-ID keyset order, so the expected canonical IDs are sorted by
ID, independently of event timestamps. Plain seeded texts contain no mentions;
the source Chat intent adds only mention tags, so their expected tags are empty.
Frozen sources are unchanged.

This is a representative bounded pagination gate. The SDK rejects the entire
source snapshot above 200 records with `NotReady`; this lane does not remove that
limit or establish full-history replacement equivalence, transferred retention,
expiry or message-deletion behavior. Existing two-record archive scenarios remain
unchanged. Push scope is frozen in `acceptance-lanes.json`; manual dispatch can
select one lane or `all` without changing that committed push scope.


Pagination diagnostics retain only a fixed phase, per-role last command names,
command counts, sent/observed record counts and page lengths. They observe the
original RPCs without adding SDK calls or extending any deadline. The initial
199-record attempt timed out with four positive worker closes; its phase was
not observable and that failed attempt must remain separate evidence.

The Mac storage gate independently mutates `canRetry` true to false and
`needsRearmToDownload` false to true. Each runs the same checkpoint regression,
requires one actual runtime failure, restores exact source bytes and requires
one passing control. Compile failures and zero-test results cannot kill either
mutant. The rearm report is exported separately from the retry report.


The iOS attachment gates independently mutate parked-state awaiting and remove
the running subscription loop's stop guard. The terminal-state regression and
the queued→parked→ready stream regression must each fail at runtime, then pass
after exact source restoration. The latter requires two snapshots and no byte
read, preserving cancellation ownership in the caller. A separate ready-stream
control exercises successful byte reading in both app SDK cohorts.

Published interoperability diagnostics wrap the pinned app controller without
changing its bytes, commands or 45-second waits. They retain only fixed sponsor/
SDK labels, stage and RPC counts, existing reply counts and positive worker
closure counts. No IDs, IPC fields, raw SDK stderr or account data are exported.
The first attempt failed offline-invitation replay in the published-sponsor
cohort; earlier steps do not count as a completed direction.


The separate `automatic-history` lane is a representative 205-record acceptance
for the automatic AccountRecords path. It seeds actual ordinary messages before
pairing, retains comparison and bilateral sharing approval, checks absence on an
unenrolled companion, and verifies the exact history on both approved B/C devices
through chronological paired pages of 37. It then reopens C's original store,
checks a future message and discovers a later chat absent from both companions.
Read-only derived commands bind message source evidence to the current paired
catalog. The existing automatic controller's 90-second per-message observation
bound and original RPC/owner deadlines remain unchanged. Only aggregate evidence
and source hashes leave the private runner; all workers must close positively.

This lane uses the automatic replay cursor and original channel renewal, not the
explicit archive importer. It does not change or bypass the explicit 200-record
snapshot refusal. Automatic storage also has finite journal/outbox/receipt/byte
quotas; 205 records do not establish unbounded history, every user/topology, or
transferred retention/deletion equivalence. Select and qualify this lane only
against the exact new SDK artifact intended by the integration owner.

The iOS timestamp gate independently restores literal fallback rendering on the
display and plain-preview surfaces. Each unchanged upstream regression must
execute once and pass before mutation, fail at runtime under its mutant, then
pass after exact committed-byte restoration. Counts must be one test with zero
skips; compile failures and empty runs cannot qualify a mutant. The original
locale, clock, cache and formatting assertions remain unchanged.
