# Bounded opt-in logical history transfer

Source audit: signed runtime `83f5a82d80c9f53bdcbab602f349544397ba07f6`, 2026-10-10.
This is an implementation plan, not an adopted Marmot wire specification or a
claim that native history transfer is available. Final Apple outputs remain pinned
to that source and immutable while this work proceeds on `codex/history-transfer`.

## Existing boundaries

`crates/storage-sqlite/src/synchronized_history.rs` supplies experimental archive
storage: immutable recipient-specific manifests, digest-bound ordered chunks,
atomic import receipts, exact retry, cancellation, retention and provenance pages.
Staged records are invisible until the final chunk commits. Authentic live
`app_events` shadow archived records; archive records never become MLS evidence,
moderation authority, membership, ratchets or recovery-cursor inputs. At the audited83 runtime, no
Core, Session or App caller authenticated or transported those manifests.

Current storage bounds are 128 chunks, 200 records/chunk, 1 MiB/chunk, 64 KiB/record,
128 retained transfers and 512 MiB total archive charge. The first transport slice
will use smaller encrypted frames (at most 16 KiB), preserving these upper limits.
Large records require bounded fragmentation or explicit refusal; the first slice
may refuse records that cannot fit rather than invent an unbounded assembler.
A complete logical snapshot is immutable before transport and bounded; no database,
MLS state, epoch secret, init key or ratchet material is copied.

## Original authorization

History consent is a new process-local action independent of the consumed linking
SDK continuation and selected-chat admission request. The source chooses one
ordinary Current group and one exact enrolled sibling device. The recipient
explicitly approves that source/group and a retention floor/lifetime ceiling.
The host sees opaque handles, review metadata, revisions and progress; it cannot
construct a grant, manifest authority or raw signing input.

The actor captures an original fixed monotonic deadline and cancellation owner,
actual local account/device identities, fresh protected Completed generation/full
indexed roster and actual ordinary group leaf identities. Every positive action
rechecks those facts against current Core state. Cached snapshots, matching SQL
rows, account-shared signatures or copied selectors cannot create consent.
Cancellation, last-handle Drop, abandoned replies, account teardown and expiry
revoke before awaited publication or SQL writes. No reopen restores positive
permission. Storage rows remain integrity/progress facts only.

## Transport and receipts

Use the actual protected group application channel through configured Session,
peeler and transport adapter, with device-leaf authenticated source provenance.
Bind canonical private frames to the transfer ID, exact source/recipient device,
account, ordinary group, original protected generation/anchor, immutable snapshot
ceiling, recipient retention policy and manifest digest. The protected group authenticates the request/consent transcript, but does not
provide recipient-only confidentiality by itself. The original A/B actors create
fresh process-local HPKE keys, bind their public keys to that exact authenticated
transcript and explicit recipient consent, and additionally encrypt manifest,
logical chunk and ACK bodies to the addressed peer. Other protected siblings may
authenticate and decrypt the outer MLS frame but must be unable to decrypt B
archive plaintext or forge a committed ACK. Keep private keys inside the original
Core owner, zeroize on retirement and never expose a host key/grant DTO. Exact
transfer/transcript/ordinal identity is inner authenticated data. Include a genuine
C-member wrong-key decryption refusal, not merely address filtering. Do not project
control frames into chat.

The minimum sequence is request, explicit recipient consent, source manifest,
ordered chunk, committed recipient ACK and completion. Exact canonical signed
and encrypted bytes are retained by the original live owner for retry. An ACK
contains transfer/manifest/chunk identity and committed next ordinal; it is emitted
only after the import transaction and final same-original-owner tail check commit.
A relay publish receipt is not an import ACK. An exporter-supplied timestamp cannot
extend recipient retention or the original lease. An ACK cannot bind a manifest
or authorize a later transfer by itself.

For one-record acceptance, the source exports the exact authenticated logical
record from bounded `SqliteAccountStorage::app_messages` queries at a frozen ceiling.
Recipient import calls the existing archive transaction under a freshly validated
original consent, including its cancellation callback at the SQL tail. A cancelled
chunk rolls back its records and receipt. Committed earlier chunks remain archive
facts; restart may expose completed archives but cannot resume transport without
new explicit authorization. Native presentation integration is a later slice;
never call generic ingest on an archived record.

## Genuine first regression and checkpoints

Reuse the actual public A/B/C linking and A/D Current-group fixture. Keep the real
prejoin A-to-D message and complete four-leaf admission. B must initially have no
prejoin live message or archive. Begin a new A-to-B history request; an unapproved
recipient refuses it without publication/import effects. Approve B's original
revision, transfer the actual prejoin record through real encrypted relay delivery,
and require a committed receipt and a provenance page containing that record.
Assert unchanged ordinary/protected MLS epochs and leaf state, unchanged live
message inventory, no history-driven recovery watermark changes, and successful
new A/B/C/D delivery afterward. The missing production operation must be a runtime
behavioral refusal, not a compile failure or a test-disabled implementation.

Checkpoint 1 is the concrete design/audit. Checkpoint 2 qualifies original request
and recipient consent ownership with default Unsupported-before-effects. Checkpoint
3 transfers one bounded real record and commits its receipt. Later chunks, resume,
retention/deletion conflicts and native presentation follow in tested signed slices.
Do not claim full transport from a constructor or archive-storage test alone.

## Upstream overlap verified 2026-10-10

[MDK PR #2153](https://github.com/marmot-protocol/mdk/pull/2153) is OPEN at
`7ee25adb4df7c9b7a15dce9931e7e88dbfb5a098`. It holds MLS epoch advancement for
exact relay events an already-member recovery comparison knows it still owes.
It is useful for decryptable relay catch-up, but cannot supply prejoin plaintext
history to an independent new leaf. Imported archives must not clear its debt,
certify its comparison coverage or move its admission cursors. Its head changed
from earlier audits; do not integrate an old hash or broad upstream merge casually.

[Closed discussion PR #1549](https://github.com/marmot-protocol/mdk/pull/1549)
proposes mesh/TCP category synchronization and conflict merging. It supplies no
merged authenticated snapshot/chunk/ACK implementation to adopt. Existing relay
history acquisition/recovery and logical archive transfer remain separate domains.

## Resource and artifact limits

Use one bounded actor owner/active transfer per account initially, bounded original
frame/receipt slots and account-lifetime replay tombstones; document concrete counts
in runtime-state-bounds when implemented. Network waits must preserve command
cancellation and shutdown. Reuse the existing Collection debug cache with jobs2,
incremental disabled and full frozen input manifests. Preserve the qualified static
App baseline before recompilation. Never mutate the final83f SDK worktree/output,
replace native artifacts, publish MDK or infer native multi-host acceptance from
these Rust actor tests.

## Qualified Core foundation checkpoint

The first Core slice provides original fixed-lease, Engine-owned recipient-only
HPKE request/consent and one immutable archive/ACK body. Five real MLS/SQL pair
controls plus production lint, default compilation and formatting pass. The
corrected context matrix uses the same unbound original source and proves genuine
consent/body success after each refusal. The original public ABC/four-leaf App
history test still reaches the explicit NotReady boundary. No transfer, import
receipt, third-member outer-MLS privacy or history UI is claimed by this slice.
See [the scoped evidence](device-sync-history-channel-verification.json).

The dedicated Core MLS-control wrapper now passes genuine missing-wrapper RED
and six final pair controls (actual request/consent/archive/reply plus source
proofs), production lint/default compilation/formatting. It retains two exact
original-owned control ciphertexts and creates no generic replay permission.
This adds no actor import or committed receipt, and does not yet qualify the
third-member outer-MLS privacy control or ordered chunks. See
[the transport evidence](device-sync-history-control-transport-verification.json).

The test-only wrapper checkpoint now passes eight real Core controls, production
lint/default compilation/formatting. It verifies a failed peeler retry uses the
exact committed MLS ciphertext and a fixed original fixture lease ends a pending
wrap. No production lifetime changed. Ordered manifest/chunks, a maximum actual
wrapped-frame control, third-member inner privacy and committed App imports remain
open. See [the control evidence](device-sync-history-wrap-controls-verification.json).

## Qualified ordered Core framing

Ten real Core controls now pass with production lint/default compilation/format.
Each original channel binds one immutable manifest digest and at most128 ordered
2048-byte chunks under the same recipient consent/deadline; receipt gating and
exact retries never reconstruct authority. The maximum-frame test measures real
Core MLS bytes using PassthroughPeeler, not production Nostr relay envelope size.
App must fragment complete logical records and manifest within the256KiB total,
reject oversize snapshots before consent, and derive receipt bytes only from
committed import facts. No App history delivery or third-member privacy result is
claimed. See [the scoped evidence](device-sync-history-ordered-framing-verification.json).

## Qualified original actor transport checkpoint

Core/Session `643261a7` and App `fc43b1f7` now freeze an authenticated snapshot
review, obtain explicit original recipient consent, transport a bounded canonical
archive over actual recipient-only encrypted protected MLS/Nostr frames, and
complete on committed import receipts. The actual public ABC/Current AD/four-leaf
fixture imports the prejoin record and transfers a multi-fragment snapshot with
an8192-byte ordinary record, preserving ordinary MLS state and live projections.
The recipient sees authenticated group/device/count/byte/fragment review metadata.
A source query reads at most201 rows and rejects whole snapshots above200 records
or196608 encoded bytes before consent. Fragments are1536 bytes, at most128.

Evidence: [original actor qualification](device-sync-history-original-actors-verification.json).
The corrected Core matrix verifies actual signatures before context refusals; its
older ordered matrix could previously mask substitutions through a stale signature.
C's actual outer-frame observation/request refusal and absent archive are actor
exclusion evidence, not a literal C HPKE wrong-key open in this fixture.

This is a transport checkpoint, not lifecycle or native adoption acceptance.
Known immediate repairs are same-Request fresh-outer replay fencing, source expiry
filtering before plaintext transfer, retryable negative staging cleanup on SQL
failure, and committed-import observation before fallible receipt sealing.
Blocked-network cancellation/deadline/shutdown controls and full backend/App
qualification remain pending. Native user-visible provenance queries/bindings are
separate; imported records remain source-attested and never become MLS proof,
membership, moderation, ratchet state or recovery-cursor/debt authority.

### Same-request fresh-outer replay repair

The actual canceled-recipient regression failed at a renewed pending owner, then
passed unchanged after bounded account-lifetime transfer-ID retention. Active and
terminal IDs share128 entries; exact old requests cannot restart receiver clocks
after retirement. Real source ratchet/Nostr rewrapping preserves the original
signed request, scope, keys and deadline, and a receiver authentication witness
proves fresh delivery. This is not durable restart qualification. Evidence:
[replay repair](device-sync-history-fresh-outer-replay-verification.json). Source
expiry privacy and faulted staging cleanup/bookkeeping are still immediate repairs.

### Source expiry serialization repair

The actual expired-but-unpruned source regression exposed8199 bytes of encoded
plaintext in the original frozen canonical archive. It now passes unchanged:
source visibility time is captured before serialization, and expired records
become zero-payload tombstones. This proves source-side non-disclosure rather
than recipient-side hiding. Actual decrypted8192-byte ordinary MLS data is used;
only its persisted retention deadline is controlled in the isolated SQLCipher
fixture. Normal multi-fragment import and replay controls remain green. Evidence:
[source expiry](device-sync-history-source-expiry-verification.json). Later expiry
during delayed publication, faulted cleanup and committed-receipt bookkeeping
still require separate acceptance before native adoption.

### Committed staging cancellation repair

Two real multi-fragment actor regressions reproduced lost SQL cleanup and hidden
committed import completion. The actor now retains exact negative staging cleanup
after SQL failure with keys retired, and records Imported completion before
fallible receipt sealing. Original cancellation cannot grant receipt publication
or source completion. Five history controls and production/default/format gates
pass. See [staging cancellation proof](device-sync-history-stage-cancellation-verification.json).
Blocked publication, delayed source expiry, durable restart and native acceptance
remain separate.

### Original blocked publication cancellation

Actual first encrypted history Chunk gates reproduced stuck cancellation and lost
RPC custody. Both pass unchanged after publication waits select on the original
revocation, fixed deadline and continuation reply closure. The same source handle
remains retained for lost-reply testing; releasing the gate cannot deliver canceled
archive data. Seven history controls and production/default/format gates pass.
See [publication proof](device-sync-history-blocked-publication-verification.json).
Expiry and runtime shutdown at this gate still require separate acceptance.

### Original publication expiry and runtime shutdown

Expiry at the actual encrypted Chunk gate already passed the fixed-deadline
publisher. A once-consumed constructor-only five-second test policy leaves the
production600-second lifetime unchanged. Runtime shutdown genuinely failed before
forced worker abort; the publisher now observes the existing terminal lifecycle
watch and cancels its same original owner before transport can resume. All nine
history controls plus production/default/format gates pass. See
[expiry/shutdown proof](device-sync-history-publication-expiry-shutdown-verification.json).
Durable fresh-outer restart denial and later source retention expiry remain open.
