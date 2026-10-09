# Native device verification

`device_linking_capabilities()` reports the Rust runtime's actual support. Default
builds expose the same public shapes and return `DeviceLinkingUnsupported` before
account lookup or purpose reservation. The experimental feature supports
verification and revision-bound singleton continuation: `enrollment_supported`
remains false while the full public three-device flow is gated. After genuine
verification, `continue_linking` schedules the original actor-owned singleton
actions; before verification it returns `DeviceLinkingNotReady`. `VerificationCompleteEnrollmentPending` describes the
completed comparison, not membership, delivery or synchronized history.

## Session and transport

Reserve a session with `begin_device_linking_session(account_ref)` on the new
device. Transfer its `setup_packet()` to the existing device and call
`approve_device_linking_session(account_ref, request, None)` there. Return the
approver's setup packet through `receive_setup_packet`. Existing-group targets
remain gated. These bounded packets bind actual actor-created identities and
purposes; the host never supplies a context, generation, protected predecessor,
verifier proof or caller deadline.

Exchange `outgoing_packets()` using the host's transport. Deliver each packet
with `receive_packet`, then acknowledge its opaque identifier with
`acknowledge_packet`. Acknowledgement records transport progress only. Retry the
same original session; returned bytes cannot recreate an owner after cancel,
expiry or runtime restart. Keep transport buffers bounded and private; do not
log packet content, verification identity or account secrets. The protocol is a
private experimental profile, with no claimed interoperability.

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

Singleton continuation is checked through genuine SDK verification and opaque
A/C binding handles. Close wakes pending observations; the C boundary also
checks callback re-entry and deep-free accounting. Eight focused controls across
default and experimental cohorts pass. This binding slice does not expose a
settlement-complete observation or prove chat/history delivery; actual protected
settlement has separate App relay evidence. See
[qualification](../../docs/device-sync-native-singleton-binding-parity-verification.json).
