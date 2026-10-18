# Native device verification

`device_linking_capabilities()` reports the Rust runtime's actual support. Default
builds expose the same public shapes and return `DeviceLinkingUnsupported` before
account lookup or purpose reservation. The experimental feature supports
verification and revision-bound singleton continuation: `enrollment_supported`
is true in the experimental profile; matched artifacts and application acceptance
are separate qualification gates. Ready-account
three-device enrollment is available through the original opaque actions. After genuine
verification, `continue_linking` schedules the original actor-owned singleton
actions; before verification it returns `DeviceLinkingNotReady`. `VerificationCompleteEnrollmentPending` describes the
completed comparison, not membership, delivery or synchronized history.

## Session and transport

Reserve a session with `begin_device_linking_session(account_ref)` on the new
device. Transfer its `setup_packet()` to the existing device and call
`approve_device_linking_session(account_ref, request, None)` there. Return the
approver's setup packet through `receive_setup_packet`. For an existing protected group, obtain `device_linking_targets(account_ref)`
and pass its opaque selector as the target. This is observation only: the actor
freshly revalidates the selected full tree and the original actions. These bounded packets bind actual actor-created identities and
purposes; the host never supplies a context, generation, protected predecessor,
verifier proof or caller deadline.

Exchange `outgoing_packets()` using the host's transport. Deliver each packet
with `receive_packet`, then acknowledge its opaque identifier with
`acknowledge_packet`. Acknowledgement records transport progress only. Retry the
same original session; returned bytes cannot recreate an owner after cancel,
expiry or runtime restart. Keep transport buffers bounded and private; do not
log packet content, verification identity or account secrets. The protocol is a
private experimental profile, with no claimed interoperability.

## One-scan automatic transport

Use `automatic_pairing_code()` after adopting the initiating original into its
current host account/runtime scope. Display the compact `WNPAIR1` bootstrap once.
The other device scans it and calls `approve_automatic_device_linking_session`.
After exact host adoption it calls `automatic_pairing_code()` to activate the
paused response, without displaying a second QR. Native App transport exchanges
setup, verifier packets, bounded fragments and authenticated processing receipts
using separate ephemeral NIP-44 keys and app-configured safe relays. A relay ACK
is never a recipient-processing ACK. QR carries public attempt binding, digest
and expiry, never the account private key or arbitrary network endpoints.

Configure `MarmotOptions.pairingRelayUrls` with matching general-purpose relays
on the participating devices when their operational inbox relays restrict event
kinds. The private pairing transport uses kind 21194; White Noise's EU/US inbox
relays reject this kind. Omitted/empty pairing routes retain operational routing,
so custom isolated runtimes do not silently acquire public fallback endpoints.
App host-safety validation still applies to every configured endpoint. This
option does not publish relay lists or change ordinary chat routing.

Mailbox setup waits for actual subscription acceptance. A `CLOSED` rejection
removes that route; losing every route reports transport unavailability. An
offline or rejecting route must not discard another relay's successful publish
acknowledgement. None of these transport results substitute for authenticated
peer receipts, human number comparison or explicit enrollment/sharing approval.

Continue to display and compare standard SAS numbers and explicitly confirm on
both devices. Sending these numbers over the same channel is not an independent
human comparison. After comparison, display enrollment/sharing terms and submit
`continue_automatic_linking(displayed_revision, share_chats)`. Existing protected
devices retain their own explicit revision-bound review and approval. Genuine MLS
proposal/endorsement metadata authenticates temporary sibling mailbox addresses;
metadata never changes inner signed terms or grants enrollment/sharing. Native
transport waits for every required device to process the enrollment artifact
before finalizing. It never manufactures approval from a transport receipt.

Do not expose manual packet receive/export/delivery buttons in this flow. The
lower-level transport APIs below remain supported for controlled integrations.
Original cancellation, drop, account/runtime retirement and the original bounded
deadline retire mailboxes and keys. Retries cannot renew that deadline or restore
an original after restart. Keep all packet/QR buffers out of logs and analytics.
The experimental source tests are separate from matched Apple artifacts and the
installed three-device demo; those gates are required before claiming app readiness.

## Human comparison and observations

Display the standard three SAS decimal values from `snapshot()` and retain that
snapshot's revision. Submit an explicit human comparison using
`confirm_comparison(displayed_revision)`; stale revisions are refused before SDK
confirmation. Both devices must confirm, and authenticated peer MACs must finish.
Never infer approval from a local Boolean or from a durable historical row.

`subscribe()` supplies coalesced observations, including an initial snapshot.
Await `next()` on one consumer. `close()` independently wakes pending reads with
`DeviceLinkingClosed`; it does not cancel the session. Cancel the exact session
when its UI/account scope ends, then close its streams and discard callbacks.
The App sets negative state before waiting for actor cleanup. Dropping the final
session schedules the same exact cleanup; prefer awaited `cancel()` when possible.
A fresh runtime needs fresh verification.

The original SDK and purpose remain in the serial account worker. Native objects
retain opaque selectors and display/transport metadata only. An App-owned cheap
probe observes original SDK/purpose expiry without a full MLS projection scan or
reconstructing permission from SQL. Native UI countdowns must remain display-only.

## C ownership

The [C guide](../marmot-c/README.md#device-verification) describes opaque handle
lifetimes, blocking calls, preflight, timeouts and deep frees. Match source,
generated Swift/Kotlin, C header and native library feature cohorts. Source tests
do not establish native artifact or app adoption; validate the matched generated
bindings and actual applications before offering enrollment.

The host Swift ABI checks run with `./crates/marmot-uniffi/device-linking-smoke.sh`
and `EXPERIMENTAL_DEVICE_SYNC=1 ./crates/marmot-uniffi/device-linking-smoke.sh`.
They generate Swift from the matching host library, compile/run record and binary
packet round trips, verify capability/typed factory gates and close the runtime.
Actual SDK session exchange is separately exercised by the Rust binding tests.
These checks do not package Apple artifacts or demonstrate chat synchronization.

## Existing protected groups and completion

After both devices finish comparison, call revision-bound `continue_linking` on
the original new-device and approver sessions. Other current devices poll
`pending_device_linking_approvals(account_ref)`, display each approval snapshot
and call `review_metadata(displayed_revision)` before explicitly submitting
`approve(displayed_revision)`. Review metadata authenticates the originating and
joining device signature public keys and the existing protected roster count.
These are device identities, not account keys; copying or displaying them grants
no permission. Review is available only on the same original pending action and
refuses a changed revision or later approval phase. It leaves the snapshot and
revision unchanged. Repeated polls share the
same original action; a retained handle grants no permission after its original
receipt expires, is cancelled or its worker closes.

The approver polls `enrollment_packet(displayed_revision)` until all original
leaf approvals are available (`DeviceLinkingNotReady` permits retry). Deliver the
same bounded packet through the new session's and each existing approval's
`receive_enrollment_packet` with their displayed revisions. Only then explicitly
call the approver's `finalize_linking`. All authentication, guarded Add, echo,
Welcome admission and protected settlement remain inside Rust. The host cannot
construct approval from a roster or serialized historical records.

`EnrollmentComplete` is appended after the existing session phases; existing
ordinals remain unchanged. Approval snapshots separately report `Settled`.
These terminal historical observations require actual original-owner protected
settlement before being cached. They remain readable after cleanup and expiry;
positive actions are closed. `VerificationCompleteEnrollmentPending` is only
comparison progress. Protected enrollment does not admit an ordinary chat,
deliver a message or synchronize history.

Rust binding relay tests use independently isolated ready accounts and real
original SDK actions. This does not qualify fresh identity-only onboarding.
Matched generated-language ABI, Apple artifacts and native application behavior
require separate checks before enrollment is advertised.
