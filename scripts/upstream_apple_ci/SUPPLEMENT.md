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

## Coverage and remaining qualification

The matrix describes scenario assertions, not a passing receipt. Check the exact
SDK source, app/tool commits, executed bodies, counts and positive worker closes
in each result. The publication/runtime changes require these existing native
lanes to run against their new matching SDK; earlier 3f18 results do not qualify
the changed runtime. Preserve failed and intermittent attempts separately.

| Requirement | Existing hosted gate | Scope and remaining limit |
| --- | --- | --- |
| Enrollment, comparison and sharing consent | `one-scan` in two directions; first/third pairing reused by the four lifecycle journeys | Original SAS comparison, bilateral enrollment/sharing and existing-device review remain explicit. Stale approval is refused. These are SDK workers on one host, not application UI acceptance. |
| Historical messages and original ownership | `native-history` archive journey | Two source records, one tagged prejoin import, one retained live record; recipient query, no preconsent disclosure, alias cancellation and final-alias drop. Cancellation cannot restore original authority. |
| Bounded archive pagination | `history-pagination` | All 199 prejoin messages must be observed through the ordinary peer, then enumerate exactly after consent. The recorded 200-record/59-fragment attempt timed out before enumeration and reported failed cleanup; it remains unqualified. The explicit source cap stays 200. |
| Larger automatic history and missing chats | `automatic-history`; complementary existing/new direct-chat checks in `one-scan` | Prepared 205-record, six-page catch-up on both approved B/C companions, unapproved-recipient negative, original-store reopen, future message and later absent-chat discovery. Execution is still required on the new SDK. This is representative intended-recipient coverage, not every user or topology. |
| Departure, withdrawal and revocation | `native-history` departure, withdrawal and revocation journeys | Offline pending/completed departure, reopen and denied sends; local hide and non-admin leave; six revocation stages including surviving-source delivery, no new disclosure to the revoked device and refused forwarding. These are distinct from message deletion. |
| Retention, expiry, message tombstones and replay/authentication | Committed Rust tests below; no equivalent native lifecycle body currently selected | Existing native records assert no expiry and no deletion. Native stale-review/cancellation negatives do not by themselves prove cross-transfer cryptographic replay refusal or transferred retention/tombstone propagation. |

The full experimental workspace archive includes the following source-level
invariants. Confirm their actual inclusion and passing execution in the final
nextest inventory; source presence and a green default-feature suite are not
execution evidence. Reuse passing final-cohort results instead of launching a
second copy of the same matrix.

| Source | Representative committed tests |
| --- | --- |
| `crates/storage-sqlite/src/synchronized_history/tests.rs` | `tombstones_and_retention_never_resurrect_on_new_transfer_or_retry`; `receiving_retention_ceiling_does_not_trust_exporter_expiry`; `history_archive_recipient_retention_cannot_be_loosened_by_exporter` |
| `crates/storage-sqlite/src/mirrored_chat_messages/tests.rs` | `mirrored_messages_retention_only_tightens_and_purge_keeps_replay_fence`; `mirrored_messages_terminal_before_body_fences_all_sources_policies_and_renewals`; `mirrored_messages_source_replays_epochs_and_cross_source_immutable_identity` |
| `crates/marmot-app/src/synchronized_history/tests.rs` and `src/account_chat_presentation/tests.rs` | `expiry_retention_fences_and_payload_free_tombstones_survive_reads`; `paired_presentation_canonical_decode_keeps_ordered_rejections_and_tombstone_privacy` |
| `crates/marmot-app/src/selected_chat_copy/tests.rs` (`actual` module) | `history_transfer_expired_unpruned_source_never_serializes_plaintext`; `history_transfer_cancelled_original_cannot_restart_from_fresh_outer_request`; `history_transfer_cancelled_original_cannot_restart_after_encrypted_recipient_reopen` |
| `crates/cgka-engine/src/history_transfer/tests.rs` | `history_channel_cross_transfer_consent_and_signed_generation_are_refused`; `history_channel_cancel_expiry_retirement_and_engine_teardown_are_negative` |

Run the existing four hosted lifecycle bodies, two one-scan directions, bounded
pagination and automatic-205 body once for the final matching SDK. Keep the
separate published/experimental independent-account interoperability evidence and
both app cohorts. No additional fixture or physical installation is required
merely to restate an invariant covered by the final Rust suites. If a final
behavior change exposes an uncovered lifecycle failure, add only the focused
native journey needed to reproduce it. Until then, explicitly retain the missing
native retention/expiry/message-deletion evidence and the finite history limits;
do not claim full-history replacement or retention/deletion equivalence.

Hosted fixture-root guards also require three independent runtime mutations per
app: accepting an unclosed producer, accepting the wrong SDK source, and accepting
broad filesystem permissions. Each selected synthetic guard regression must pass
once, fail once under its mutant, and pass once after exact byte restoration,
with no skips. These tests qualify fixture validation only; actual app ownership
and history acceptance still require the live, platform-native fixture lanes.
