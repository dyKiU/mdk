# Native SDK acceptance harness

This standalone Swift program links the qualified experimental SDK83 macOS static
archive and generated Swift. It does not compile Rust, install an application,
access production storage, or qualify the development application's UI.

The initial `api` gate uses a new task-only directory (0700), a thread-safe
in-memory `SecretStore`, and the private loopback relay. It creates a fresh account,
checks actual capabilities and empty protected targets, creates one original
session, reads its phase, explicitly cancels it, and closes the runtime. No
signing secret, account identifier, SAS, packet, or message content is printed.
Failures expose only a static stage and `sdk`/`harness` category. Cleanup failure
is reported independently without replacing the original failure.

```sh
./tools/native-sync-acceptance/build.sh \
  /absolute/path/to/validated-sdk-output /absolute/path/to/native-acceptance
/absolute/path/to/native-acceptance api /absolute/path/to/new-task-state
```

The SDK output must contain `MarmotKit.swift` and
`macos/MarmotKit.xcframework/macos-arm64/{Headers,libmarmot_uniffi.a}`. Run with
`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`. The relay is
`ws://127.0.0.1:18181`; M1 uses the existing SSH tunnel to the private M5 relay.
Never reuse a live application root. Keep task logs private (0600).

The initial API-feasibility gate alone does not prove pairing completion. Later
sections describe the qualified pair and cross-host enrollment gates. Delivery,
restart/offline and iOS simulator-native acceptance are documented below. No
gate copies account databases or reconstructs permission.

The `pair` gate now completes first-device enrollment through public native APIs:

```sh
/absolute/path/to/native-acceptance pair /absolute/path/to/new-approver-state
```

It creates an independent sibling `new-approver-state-recipient` root. The fresh
identity's signing key passes only between task-owned in-memory stores. Onboarding
uses offered public actions and current revisions, never direct account-home or
SQL checkpoint insertion. The gate checks matching actual comparison values,
confirms both original revisions, continues both original enrollment actions and
requires both SDK phases to be `enrollmentComplete` with two-device targets.
Packet acknowledgements occur only after actual delivery. Each runtime closes
and each original session is cancelled. `first-pair-evidence.json` records real
M1 and M5 passes; both peers are still local to their respective host for this
slice. The later cross-host gate adds peers on separate hosts; restart, messages
and simulator-native gates are documented below.


The `cross_host.py` controller drives one real original session per host. Its
`serve` agent is private IPC: run it only through this controller's captured
stdin/stdout pipes, never with stdout attached to a terminal or tool transcript.
The fresh `create.secret` reply travels only in these internal pipes to the
recipient's public onboarding action; raw replies are never logged, including
on timeout or error. Output contains aggregate results and static failure stages.

Each task root has a dedicated marker and isolated runtime directory. The
credential callback encrypts synthetic signing credentials with AES-GCM, using a
separate task-only 0600 key; the root and credential directory are 0700. This is a
local test store, not a production secret-store or Keychain replacement. Loads
require the exact account ID and never fall back to a matching label. No session,
approval, permission, snapshot, or packet is persisted by the controller.

```sh
python3 tools/native-sync-acceptance/cross_host.py \
  --binary /absolute/local/native-acceptance \
  --remote-binary /absolute/remote/native-acceptance \
  --local-state /absolute/new-task-m1-root \
  --remote-state /absolute/new-task-m5-root \
  --output /absolute/new-private-result.json
/absolute/path/to/native-acceptance store /absolute/path/to/new-task-store-root
```

The `store` gate uses an actual SDK-created identity and encrypted runtime reopen.
It checks secret preservation with no original session reconstructed, mismatched
account refusal, modes, ciphertext tamper refusal and missing-key refusal. The
cross-host gate requires real two-sided comparison, explicit original enrollment,
and actual two-device protected targets on both hosts. Restarted delivery,
third-device enrollment, selected-chat consent and simulator-native acceptance
are documented below. Installed application UI acceptance remains separate.


Optional `--third-state /absolute/new-m5-third-root` extends the cross-host gate
with a third independent runtime. It privately onboards C with the same fresh
synthetic identity, uses the actual protected two-device target for A/C setup,
checks their genuine comparison and requires B's original pending approval.
The packet export is denied before B explicitly approves its authenticated
original review. Exact opaque enrollment packets then reach C and B, A finalizes,
and all three actual targets must contain three devices. No packet is parsed into
permission, and all original handles are cancelled independently at teardown.
`three-device-evidence.json` records the actual native cross-host result.


Optional `--chat-state /absolute/new-m5-ordinary-recipient-root` (with
`--third-state`) creates a different fresh D identity and real ordinary A/D chat.
The actual D key package and group membership come through public APIs. A retains
one original selected-copy handle; B/C retain independent original consent
handles and review the exact authenticated chat selector. Each explicitly
approves and supplies its original response and exact retryable offer before A
continues. All four current MLS states must have four members. A new B message
must arrive on all four runtimes with the exact SDK message ID and plaintext
checked privately. The pre-join A message must reach D first and remain absent
from B/C before and after their selected admission. No old history, packet-derived
permission or implicit protected-roster consent substitutes for chat consent.
`selected-delivery-evidence.json` records both actual gate versions; restart,
offline and simulator-native acceptance remain separate.


`--restart-offline` (with the third/chat roots) closes B's exact original handles
and Core before A sends another message. It requires live A/C/D receipt, reopens
B's same isolated encrypted root, discovers its account through public
`listAccounts`, and checks actual retained roster, MLS membership and prior
message. The offline message must arrive through the SDK's relay recovery, then
B must send a new message to all four runtimes. No original session, approval,
copy or consent is reconstructed. `restart-evidence.json` records the actual runs.

Controller cleanup requires a successful explicit close reply and exit0. A prior
unexpected worker exit fails even with exit0, and close followed by nonzero fails.
Only a previously acknowledged successful close may be retried idempotently.
`python3 tools/native-sync-acceptance/test_controller.py` exercises five real
subprocess lifecycle cases; these fixtures establish no SDK permissions. All
private pipes close at terminal cleanup. The following simulator gate adds concurrency, separately from installed
application UI acceptance.


`build-simulator.sh` links the existing qualified iOS arm64-simulator archive and
same generated Swift into one standalone iOS18+ executable. Pass the existing
module cache as its third argument. It uses `xcrun --sdk iphonesimulator`, an
explicit simulator target and ad-hoc signing; it neither rebuilds Rust nor installs
or modifies an app. The dedicated simulator must already be booted.

With `--simulator-binary /absolute/m5/simulator-executable` and
`--simulator-device 3F79E967-EE79-4A0E-BCF6-BCC4FE4A2ECC`, the controller runs C
through `simctl spawn` using the actual iOS SDK. A remains on M1 and B/D on M5.
Add `--concurrent` to send one message independently from each of the four peers,
then require every exact SDK ID and private content on all four. One thread uses
each private pipe, and all send futures complete before reads resume. This can
combine with `--restart-offline`. `simulator-evidence.json` records the real API
and compound pairing/consent/delivery/recovery/concurrency gates. These establish
standalone native SDK acceptance; installed application UI and physical-phone
acceptance remain separate.

## Matched-SDK native history acceptance

`--history --sdk-source <exact-40-character-source-commit>` adds an original-owner
history gate after genuine selected-chat admission. Build it only against a
qualified SDK containing `HistoryTransfer`, `HistoryConsent` and
`synchronizedHistoryPage`, with `NATIVE_HISTORY_ACCEPTANCE=1` on `build.sh` or
`build-simulator.sh`. The existing SDK83 baseline remains the default. Initial source preparation was
parser/controller-only; the subsequent SDK84113 Mac gate now executes these
original methods. Parser checks alone never constitute native ABI qualification.

The fixture enrolls C with B as the real approver and A as the existing sibling.
A's original authenticated review supplies B's occupied device signer for the
history factory; no opaque packet is parsed to obtain it. Account equality is
established by the original fresh identity import, followed by actual three-leaf
settlement. The new gate sends an 8192-byte tagged prejoin text through the public
SDK, verifies D receives it before B/C join, and preserves the existing no-history
before/after selected admission checks. Then two actual pending-request calls
must alias the same original consent: cancelling one denies the other and leaves
B/C archives empty. A fresh original transfer requires explicit B approval at its
actual displayed revision and A continuation; source/recipient snapshots and
committed import counts must match. B's successful public archive query must
retain the exact old content/tags/author and source-attested transfer provenance;
C's archive must remain empty. None of those observations are reconstructed into
permission or restored original handles.

`test_history_controller.py` uses actual subprocess pipes and fixed wire replies
to check action ordering, exact revision forwarding, preapproval emptiness,
provenance refusal, nonrecipient isolation and retained-original cancellation.
These are controller controls, not evidence of SDK approval or crypto success.
The SDK84113 Mac gate now executes original alias cancellation, final-alias drop
and explicit import. A later dedicated simulator gate now participates as C (nonrecipient archive
isolation), with B Mac history import plus restart/offline/concurrent delivery.
iOS recipient import and ordered media remain pending. Matched inputs needed are the exact
shared generated Swift/header/modulemap and macOS15 arm64 static archive; the
simulator gate additionally needs its same-source iOS18 arm64-simulator archive.
No Rust rebuild or SDK transfer is performed by this harness slice.

### Final original alias-drop gate

The additive history gate now creates a separate original request for final-drop
acceptance. B obtains two wrappers through two actual `pendingHistoryRequests`
calls. The Swift helper keeps only snapshot values across releases: the second
wrapper batch is dropped, the remaining original's snapshot must still succeed,
then the held final wrapper is dropped with no explicit cancellation or approval.
The helper and command frame return before a separate controller RPC requires an
empty pending list. A's retained original must remain incomplete and B/C public
archive pages must remain empty. Only then is A negatively reset and the fresh
explicit-consent import exercised.

App's actual `retain_host`/`release_host` protocol cancels the original when the
last native host alias drops, even if its internal pending `Arc` remains. Merely
assigning a Swift display variable is not accepted as proof of this behavior.
The new two controller regressions demonstrate missing orchestration RED and
exact private-wire action ordering/refusal GREEN; all ten prior controls remain.
Total controller result is 12/12. Swift parses/formats in both build modes, but
SDK84113 Mac execution subsequently passes the actual ARC/FFI final-drop and
fresh-import gate; its simulator counterpart remains pending. No generated binding was edited and no SDK,
Core, account, cache, installation or publication operation was performed.

### Exact import counts and live-record precedence

The initial SDK84113 native history gate failed because it required every
manifest record to become an archive row. A fresh diagnostic run preserved that
assertion and first checked the exact imported old record: source manifest2,
committed import1, archive page1, and the known postjoin message still present
through B's live message query. Both original owners were complete and C's
archive was empty. Storage intentionally skips IDs already in the live store;
App completes only when imported plus skipped equals the manifest count.

The corrected gate accepts only this exact isolated fixture: one verified old
record imported and one known live postjoin record account for exactly two
manifest records. It refuses unexplained deficits and requires the archive page
to contain exactly the prejoin record; live-store precedence cannot be asserted
merely from a lower import count. Controller regression13pass/1intended error
became14/14. Fresh M1/M5 native SDK84113 execution then passed1/1 using unchanged
67d00f binary bytes on both hosts. The earlier two native failures remain retained.
This proves standalone native SDK history behavior, not installed app UI adoption.

### Dedicated simulator participant on SDK84113

The same-source standalone native gate passed with A on M1, B/D on M5 and C on
the dedicated iOS simulator. It includes original history alias cancellation,
final-alias drop and fresh explicit consent/import; then B's public account
reopen/offline recovery and four-peer concurrent sends. B is the actual Mac
history recipient. C's successful public archive page remains empty while it
receives new/recovered/concurrent chat messages; this does not prove iOS
recipient import. The simulator binary was linked once using the existing
`whitenoise-sync-ios-build/ModuleCache.noindex` and exact qualified SDK84113
Swift/header/modulemap/archive. No installed app or account data was touched.

The compile wrapper failed after compilation in its own hash verification
(`str.read_bytes`), so its exit1 is retained and compiler exit is not claimed as
durably captured. Independent validation verifies a freshly created signed
binary, no compiler errors and all eight input hashes unchanged. Actual native
execution then passed1/1; both binaries and the controller remain unchanged.
See `history-simulator-participant-verification.json` for exact hashes/paths.

### Explicit simulator history recipient routing

`--simulator-role recipient` places B's original runtime on the dedicated
simulator, including public account reopen after close. The default remains
`third`, placing C on the simulator and B on Mac. A single route function is
used for initial B acquisition and B reopen. Role selection changes executable
placement only; it creates no session, consent, or history authority.

Controller routing regression1pass/1fail became16/16 across all existing and
new controller checks. These routing tests use injected transport endpoints
without claiming SDK behavior. Fresh iOS-recipient import/restart execution then passed1/1 using the unchanged
Mac and simulator binaries; no native or SDK rebuild was needed.

### Actual iOS recipient history import on SDK84113

Fresh B simulator execution passed1/1: A M1, B dedicated simulator, C/D Mac.
The original B consent approved one exact tagged8192-byte prejoin record;
committed archive query contains that one record, while the known postjoin
record remains in the live message store. Source manifest2 equals imported1
plus that exact known live record. C's successful archive query stays empty.
Original alias cancellation and final alias drop precede fresh explicit consent.
B then closes and reopens through the simulator's public account discovery,
recovers an offline message, sends after restart, and receives all four
concurrent message IDs with exact private contents. No session or approval
is restored from disk. All13 frozen controller/source/SDK/binary hashes remain
unchanged after successful explicit worker cleanup. This is standalone native
SDK acceptance, not installed application UI acceptance or ordered media coverage.
See `history-simulator-recipient-verification.json`.

### Private handoff to the actual iOS reader

The optional `--ios-reader-handoff` is restricted to a real history recipient on
the dedicated simulator. It writes a fresh mode-0600 observation file only after
the original transfer and consent report committed completion and every worker
has acknowledged close and exited successfully. The descriptor contains the
task-only recipient root, account/chat references and the already-verified old
record plus known live-message ID. It contains no credentials, permission or
original handle. It must never be used to construct approval.

This supports a subsequent hosted app test which publicly reopens that same
isolated recipient root using its original encrypted task credential callback;
storage is not copied. The account-owned app model and pane must then read the
actual committed archive. Controller controls pass18/18, including refusal
before verified shutdown and refusal to overwrite an earlier handoff. The new
handoff and hosted reader have not yet been executed together against the SDK;
original-recipient approval UI and ordered-media/retention acceptance remain
separate required gates.

### Live iOS original-consent bridge (native execution pending)

`--ios-history-approval-bridge <new-private-M5-directory>` closes the standalone
recipient after real selected-chat admission and the negative original-alias
controls, while its archive is still empty. The application must publicly reopen
that exact task root and report readiness before the source creates a new original
history request. The app discovers its own pending original through its real
account-owned model; no original handle or approval is transferred in the fixture.
After an explicit hosted action, source continuation and committed recipient import
must complete, and the app must retire its owner before successful aggregation.

The private exchange contains observations only. It does not restore an approval
on reopen. Controller tests qualify the worker-close/fresh-file boundary; actual
hosted approval, relay import and app shutdown remain pending until that gate runs.

`--reader-handoff` is the transport-neutral name for the completed-import reader
fixture. The old `--ios-reader-handoff` remains an alias. A genuine `--history`
recipient may run on macOS or the dedicated simulator; both require the same
positive original-worker close and complete-import checks. The CLI regression
qualifies preflight only; it deliberately stops at the worker boundary and does
not simulate an SDK import.


For matched SDK987 recipient observations, build with
`NATIVE_HISTORY_ACCEPTANCE=1 NATIVE_HISTORY_RECIPIENT_QUERY=1`. The extra flag is
explicit so earlier qualified binding cohorts can still compile unchanged.
Add `--recipient-query` to a genuine `--history` controller run. Before any
history request, this gate checks two distinct eligible device/leaf observations,
the authenticated original recipient’s presence, and no pending requests on B/C.
Observations never supply a native original or permission. The subsequent
history request still calls the fresh Core factory. Private IPC replies remain
inside controller pipes; the report contains counts only.

`history-recipient-query-harness-verification.json` records compilation with the
exact SDK987 generated Swift/archive and 28 controller checks. Fresh real-device
execution is a separate gate and is not established by these scripted RPC tests.

### App source-picker handoff

With `--history --recipient-query`, `--source-picker-handoff <private-path>`
writes a new mode-0600 observation contract only after all original peers have
positively closed. The recipient B root is then available to an app source picker.
The contract contains root/account/chat and the observed eligible-device count;
it contains no original handle, consent revision, device selection or credential.
The app must query its actual Core roster again, explicitly select a returned
candidate and create a fresh original. This does not qualify a completed app
transfer or a UI button press. Controller controls cover live-owner refusal,
private exclusive creation and unqualified-roster refusal (31 controls total).

### Complete app source-model transfer

`--source-m5-state <fresh-source-root> --mac-history-source-bridge <new-private-dir>`
with `--history --recipient-query` places source A on M5 and the ordinary chat
peer D on M1. The controller closes A positively before publishing a private
version-2 observation descriptor. Its expected receiving device is selected from
the genuine enrollment review; it supplies no consent, revision or original.
The app must query Core, explicitly select the observed listed device, create a
fresh original and display its review. The native recipient reviews its own
original before explicit approval. The app then refreshes and continues its held
original using its current displayed revision. Completion requires app-original
retirement/runtime close and the exact recipient pre-join import, source
attestation and live-row precedence; non-recipient history must remain empty.
This model lane does not count as UI-button or installed-navigation acceptance.

For the iOS model lane, use `--ios-history-source-bridge` instead of the Mac
bridge and supply `--simulator-role source`, the matched simulator executable
and the dedicated simulator device. Only fresh source A runs inside the
simulator; B/C stay native Mac peers and D stays on M1. The same positive source
shutdown, version-2 observation handoff, original recipient approval and exact
import gates apply. Reopen A's original simulator-created root with the task's
read-only credential callback; never use a Mac-created source root or copy its
account/MLS storage into the simulator. Platform flags are mutually exclusive.
Routing controls alone do not qualify the native iOS transfer.

To diagnose an enrollment prerequisite failure, retain the same native platform
and fresh-root flags and add `--enrollment-diagnostic`. This stops after the
three original enrollment actors; it never creates the chat, app fixture or
history original. The report is explicitly an enrollment diagnostic, even when
it passes. It records bounded phase/revision transitions, public roster counts
before shutdown, and positive-close/failure counts for all original runtimes.
Cleanup failures remain visible alongside an earlier enrollment failure.
Recovery and recipient handoff flags are refused in this lane. Diagnostic
controller tests establish routing/reporting only; they do not prove settlement.

For the both-app lane, combine the iOS source bridge with
`--mac-history-approval-bridge <new-private-directory>`. B's native worker must
have no pending original and positively close before the actual Mac Session
model opens the same root. Only after that model reports readiness does the iOS
source receive its handoff and create a new request. The controller crosschecks
all immutable review fields and requires explicit recipient approval, actual
source completion and positive closure of both app runtimes. B stays alive until
A completes its final receipt. A fresh native B reader then resumes without
reconstructing any consent original and independently verifies the committed
archive, provenance, live-row precedence and empty non-recipient archive.
Private marker files synchronize observations; they grant no authority. Separate
actual XCTest/UI results are required to qualify the apps and public buttons.
The controller's ordering tests alone do not establish native acceptance.

## Automatic native source preparation

`NATIVE_AUTOMATIC_ACCEPTANCE=1 ./tools/native-sync-acceptance/build.sh` enables
new Agent commands against a matched automatic-sharing SDK. Set
`NATIVE_MODULE_CACHE_PATH` to an existing dedicated Mac module cache to reuse it
explicitly; the simulator builder already requires its existing cache argument. The matched de38 SDK compiled both native targets and passed the actual
M1/M5/iOS-simulator flow 1/0 with five positive closes; see
`automatic-qualification.json`. Python controls alone do not qualify native
transport or installed applications.
The existing selected/manual history protocol remains available unchanged.

`automatic_chat.py --commands private-commands.json --sdk-source FULL_SHA
--output NEW_PRIVATE_DIRECTORY` uses four independent `serve` roots: source,
recipient, third, and an unrelated ordinary-chat peer. The private commands
manifest has `sdk_source` and `roles`; each role contains `argv`, `binary` (an
explicit executable in argv), and `sha256`. The final native controller requires a local and a remote host plus an actual
simulator third peer. It rejects an all-Mac surrogate topology. Both builders
honor `NATIVE_AUTOMATIC_ACCEPTANCE=1`; default builds retain their previous flags.
Remote argv begins with
`["ssh", "HOST", "BINARY", ...]`; simulator spawn argv must include its actual
native executable, for example `["xcrun", "simctl", "spawn", "UDID", "BINARY",
"serve", "ISOLATED_ROOT"]` or the same arguments after `"ssh", "HOST"`.
Remote arguments are individually shell-quoted. Worker SSH is noninteractive, with a10-second
connection timeout and two missed5-second liveness probes; remote executable
hash checks have a30-second process timeout. A transport failure stays failed;
these bounds do not extend protocol deadlines or automatically restart workers. The two same-name ordinary chats
must have distinct canonical group IDs. The controller verifies executable bytes before launching.
Run only after matching signed source/artifact provenance has been independently
checked on every host. Use the existing isolated loopback relay/tunnel.

The flow creates an ordinary chat and message before pairing, onboards companions
with offered displayed-revision acknowledgements, preserves the actual public
package slot-set, and chooses original broad-sharing actions for AB and ABC.
It then verifies automatic chat/history windows, later chat discovery, canonical
client-token forwarding to the unrelated peer, and queued retry while the sole
actual member is offline followed by encrypted same-store reopen. No per-chat
copy/history approval is invoked, and source-qualified rows never become MLS
memberships. Runtime closing/cancellation releases retained originals; opaque
sharing snapshot/approve commands also support one-time existing-pair review.
Only aggregate pass/fail/close counts reach stdout. IPC/stderr/state stay private.

Both generated-API compiles and the complete native M1/M5/iOS simulator flow
passed on the pinned SDK. The remaining full backend matrix must pass before
promotion; installed UI, background delivery, retention withdrawals, media and
revocation retain separate acceptance requirements.

## Real setup-packet QR transport

Opt in with `NATIVE_PAIRING_QR_ACCEPTANCE=1` and
`NATIVE_PAIRING_QR_CODEC_SOURCE=/normal/mac/whitenoise-mac/Core/PairingQRCode.swift`
when building the native Mac harness. The builder compiles that actual unchanged
app file directly, with its hash frozen alongside the SDK. It requires a readable
codec source and retains default build behavior. Reuse an existing module cache.
Run the resulting binary as `qr NEW_PRIVATE_ROOT`.

The gate creates independent A/B/C runtimes and a synthetic identity, uses supported
companion onboarding, obtains the actual held B request, passes it through the
app QR pages/owner-scoped reassembly and authenticates the decoded bytes at A's original factory.
It repeats that for A's actual challenge and B's original receive, then drives
real proof exchange and broad AB enrollment. It then repeats C setup against
the actual two-leaf target, approves B's fresh original at its reviewed revision,
reassembles the actual enrollment packet and requires all three settled. All
originals cancel and three runtimes close with `storageIsClosed`. The actual
C challenge (4,690 bytes) uses four frames, and enrollment (8,186 bytes) six;
no frame exceeded 2,149 UTF-8 bytes. See `qr-qualification.json`. Output contains only packet roles, lengths,
bounded/round-trip flags and aggregate closes/pass/fail. No packets, signing keys,
QR text or images are printed or saved. This does not establish physical camera
scanning or the independent iOS app codec until its actual host test passes.

## Extended reconciliation acceptance (prepared; native execution pending)

Add `--extended-reconciliation` to a fresh `automatic_chat.py` invocation using
same pinned de38 SDK binaries, topology and independent roots. The default
controller preserves the passing native1 sequence. The extension then creates
same-title chats concurrently through A and B's actual public `createGroup`
paths, requires distinct canonical IDs, and explicitly accepts each invitation
at unrelated D. It checks both directions of paired-source discovery and exact
canonical history on the other installation and C. Repeated fresh public window
reads require exactly one matching group and event, proving read/rescan dedup;
this does not inject duplicate encrypted catalog announcements.

B positively closes before A creates another chat and sends a real ordinary
message. The same B root reopens through supported public resume and must
observe the exact source-attested canonical event. Every reopened peer remains
in positive-close accounting. No new Agent commands, compiler, relay or SDK
change is required. The extension is source-prepared with 61 protocol controls
passing; no additional native execution is claimed yet.

Remaining distinct acceptance gaps include initial chats already owned by B,
interrupted fragment transfer, explicit duplicate announcement/reordered frame
injection, multiple-account switching, declined stranger invitations,
leave/delete withdrawals, revoked-device access and Legacy ordinary groups.
Read-only metadata or backend storage controls alone do not close these native
journeys. Existing native1 and QR proof remain separate immutable results.

### Leave withdrawal regression (source-prepared, uncompiled/unrun)

`--withdrawal-probe` adds a real incoming chat created by independent D and
explicitly accepted by A before pairing; no account role or MLS rows are edited.
After genuine automatic history is visible, public `deleteGroupLocal` hides a
separate chat on A only, while its actual membership and B/C mirrors remain.
Public `leaveGroup` acts on the incoming non-admin chat. D must observe canonical
membership removal before the probe requires the paired-source chat to disappear
on B/C. A and B positively close/reopen their own stores. A fresh message in the
unrelated still-member chat witnesses resumed automatic transport; the old left
chat must remain absent. New Agent commands are compile-pending against unchanged
de38, and the controller remains runtime-pending until host lane release.

Source audit of de38/aa78 found that Core catalog excludes terminal local copies
and the sender only produces Active entries. The authenticated receiver, committed
receipt and source-scoped cross-generation SQL terminal fences already support
withdrawal records. Local projection hiding is deliberately not account-wide
leave/deletion; an independently valid actual-member source remains distinct.
A fresh authenticated rejoin must not be inferred from stored Active catalog data;
positive rejoin/lifecycle generation admission requires its own qualified design.

`automatic_chat.py --pending-stranger-probe` keeps the normal genuine broad-pair
journey, then has independent D invite actual A without accepting it. A must
observe a pending invitation and decrypt a real ordinary message while remaining
pending; that Welcome membership must not expose a paired-source chat on B/C.
Only after the observation interval does A explicitly call `declineGroupInvite`,
and D must observe canonical member removal. The probe never calls Accept for
this group. Protocol controls qualify command ordering and refusal, not native
behavior; compile and real-relay results must be recorded separately.

The withdrawal local-hide control uses fresh D traffic and actual A decryption
plus local-row recreation. It does not query a hidden group's projection-bound
MLS-state API: a missing projection after local hide is neither an accepted
invitation nor evidence of lost MLS membership.

### Retained completed pairing handles

Use `automatic_chat.py --retain-completed-originals` with the existing qualified
commands/SDK pin and a fresh output directory for native parity with the apps.
AB discovery must deliver the exact canonical pre-pair event while both original
sessions still observe `enrollmentComplete`; they close only before the separate
third-device ceremony. After full ABC settlement, A/C sessions and B's sibling
approval stay retained while normal history, later chats, forwarding, and a new
B-owned ordinary chat deliver. Independent D must receive B's canonical message;
A/C must each expose that exact paired event, and all three original observations
must remain completed. Known old nonce retries remain separate from fresh
policy-authenticated automatic requests. The report includes the flag and hashes
of both controller modules.

The controller controls do not run SDKs or prove native/installed behavior.
The new retained-handle journey still requires execution with the final qualified
SDK; the real Rust App regressions alone do not establish FFI or installed UI
parity. Default controller behavior still closes completed A/C originals as
before, and existing commands/results remain available for comparison.


Exact-device revocation can be exercised with
`NATIVE_DEVICE_REVOCATION_ACCEPTANCE=1` in either native build script, using a
matching SDK that exports `DeviceRevocation`. This selector defaults off so
older SDK cohorts keep their existing driver surface. Private IPC commands
`revocation-begin`, `revocation-snapshot`, `revocation-approve`,
`revocation-cancel` and `revocation-drop` retain or release the same opaque SDK
original. Begin accepts one exact32-byte base64 device selector; it does not
approve. Approval requires the revision actually read from that original.
Snapshot data is an observation, never a permission constructor. Cancel keeps
the alias available for refusal checks; drop releases the final foreign alias.
Driver closure cancels the original before closing Core storage.

These commands are preparation for final native revocation acceptance. Swift
syntax and controller controls do not prove SDK type checking, actual removal,
post-removal access refusal or installed-app behavior. Run those checks against
the regenerated immutable SDK; no historical result qualifies this driver.

`automatic_chat.py --device-revocation-probe --retain-completed-originals`
uses those commands before source shutdown on a fresh three-device journey.
The source and companion enrollment originals stay alive; cold reopening must
not reconstruct their admission from persisted facts. Offline forwarding remains
a separate baseline journey. All worker binaries must
enable the revocation flag. Read-only A/B/C target sets identify the exact third
device, then the same SDK original is reviewed and approved at its current
revision. Enrollment-complete snapshots and three-device membership alone do
not establish private roster settlement. Each target-view prerequisite has a
20-second bounded read-only wait, tolerating only typed AccountSharingNotReady;
other errors refuse immediately. It never retries approval or constructs an
owner from stored facts. The controller separately requires survivor target settlement, fresh
ordinary delivery through B's paired copy, and no new chat/message disclosure
to C over a bounded observation interval. Old history may remain on C.
The module hash is included in the result. Run this lifecycle probe alone;
it does not prove revoked-device forwarding refusal, post-revocation enrollment,
storage-fault recovery, installed UI or APNS. Controller controls are not native
acceptance; current native execution remains pending.

### Fresh rejoin and account-wide departure preparation

`automatic_chat.py --fresh-rejoin-probe` uses the independent ordinary
administrator's public invitation method to rejoin the same canonical chat after
actual member removal. It checks pending-invitation isolation, explicit
acceptance, exact canonical messages, an offline recipient and encrypted reopen.
Use a matching rejoin-capable SDK; controller tests do not establish this journey.

`--account-departure-probe` additionally requires both
`NATIVE_AUTOMATIC_ACCEPTANCE=1` and `NATIVE_ACCOUNT_DEPARTURE_ACCEPTANCE=1` when
building each worker. The latter defaults off until the matching generated SDK
exports the departure methods and typed send refusal. This separate journey
checks durable Pending while a known peer is offline, actual ordinary member
removal, all-peer receipts, reopen and typed send denial. It covers one actual
non-admin ordinary source and two mirrored recipients; two ordinary source
devices remain a separate qualification requirement. Do not infer account-wide
departure from the unchanged device-only `--withdrawal-probe`.

Run only one of these three lifecycle probes per fresh isolated journey. Tooling
source `298b421` retains75 passing controller controls plus Swift grammar and
shell checks; SDK typechecking and real native execution remain pending.

### One-scan Apple SDK acceptance

Build against the matching validated SDK output and run with absolute paths:

```sh
NATIVE_AUTOMATIC_ACCEPTANCE=1 NATIVE_ONE_SCAN_ACCEPTANCE=1 \
  tools/native-sync-acceptance/build.sh /absolute/sdk-output /absolute/agent
python3 tools/native-sync-acceptance/one_scan.py \
  --agent /absolute/agent --agent-sha256 SHA256 \
  --relay /absolute/test-relay --sdk-source FULL_SOURCE_COMMIT \
  --output /absolute/fresh-private-output
```

It owns a fresh loopback relay on port18485 (`--port` selects another unused port)
and fresh synthetic account stores. Existing relays and account data remain intact.

Both scan directions pass exactly one bootstrap through private controller IPC.
The SDK transports every subsequent encrypted packet itself. The controller
compares independently derived numbers, checks refusal before both confirmations,
and explicitly approves sharing on both originals. These synthetic controller
actions never substitute for human comparison or approval in the apps. Three
controller refusal controls are separate from the real compiled-SDK acceptance.
Only aggregate `result.json` is public evidence; keep worker state, logs and IPC
private. This does not establish app navigation, camera hardware, platform
credential-store access, iPhone behavior or APNS delivery.

Add `--contacts` to check the account's public Nostr kind-3 contact list across
three independent installations in each scan direction. Each installation must
originate a follow/unfollow change, all three must observe it through the SDK's
network-free cached reads, and a stopped installation must recover a change on
reopen. No peer invitation or forced directory refresh is sent. The third
installation is signed in but unpaired: public follow lists propagate through
Nostr independently of private device pairing. This does not establish private
nickname synchronization, live refresh of an already-open contact screen, or
three-device pairing. The controller emits only aggregate results; synthetic
credentials and public-key lists stay inside its private worker pipes.

`--contacts --three-device-chats` also enrolls the third installation into the
existing two-device group. Each new installation consumes one bootstrap; no
verification/enrollment packet is copied by the controller. The existing sibling
must review and explicitly approve chat sharing; a stale review must be refused.
The gate requires three-device roster settlement, a chat created before pairing,
a later chat created by the second device, canonical delivery from all three,
and chat/contact catch-up after the third installation stops and reopens. Each
ordinary chat is accepted once by the independent peer; that peer never invites
each installation separately. Both initial scan directions run with fresh stores.
Cleanup remains part of the gate. Only the SDK's typed `DeviceLinkingClosed`
result from cancelling an already-retired original counts as finished cleanup;
runtime failures, missing close acknowledgements and nonzero exits still fail.

For a deployment probe, explicitly pass
`--public-chat-relay wss://relay.eu.whitenoise.chat` (or the US White Noise relay)
instead of `--relay`. This mode uses that public relay for ordinary chat and
enrollment, and `nos.lol` plus `relay.primal.net` for encrypted pairing packets.
It requires the SDK's optional pairing-route configuration. Every worker still
uses fresh synthetic accounts and private stores; no installed account is read.
Both scan directions and the same comparison/approval assertions execute.
Add the existing chat/contact flags to exercise those flows through the real
deployment routes. Public relay availability is a separate limit from local
protocol correctness. The default loopback mode explicitly clears inherited
public routing, including on worker restart. Record actual execution separately
from controller unit checks and physical-app acceptance.


Add `--direct-chats` with `--contacts --three-device-chats` to create the initial
conversation through the same unnamed direct-group API used by iOS. In addition
to actual chat/message delivery, the source and both paired installations must
resolve the independent peer to that exact reusable conversation. A missing
lookup fails before any duplicate invitation can be created. The source must
resolve as local MLS and the two mirrored installations as paired sources. The
controller accepts only the fixed boolean response shape and emits role labels
and those booleans; unexpected reply fields are refused before reporting.

This mode requires the account-level lookup added in SDK source159d1bca or newer.
The retained ff26 regression used the earlier local-only lookup and immutable
`agent-direct-lookup` binary; its source hashes and failing receipt remain the
baseline. Passing named-group forwarding does not qualify direct-contact reuse.
The updated consumer still needs compilation and execution against a matching
qualified SDK.
