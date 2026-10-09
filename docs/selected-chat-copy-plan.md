# Selected ordinary-chat delivery after protected device linking

Status: implementation boundary prepared on signed `b14decf2`; the genuine missing-request RED has reached its final `NotReady` assertion. This is an MDK implementation plan, not a new wire
profile. Protected roster completion does not grant ordinary-chat membership or
historical message access.

## First test boundary

`selected_chat_copy::tests::actual::selected_chat_copy_requires_explicit_request_after_public_three_device_linking`
uses three independent device homes and the real public A/B/C verification,
approval and packet flow. It requires actual three-leaf Completed protected
rounds and native terminal observations. A separate account D publishes its
ordinary KeyPackage; A creates a Current A/D chat over the live relay. Both
ordinary MLS states must have two members, and D must project a prejoin message.
B/C must have neither that ordinary group nor the prejoin message. The retained RED then
expected an opaque explicit request from
`AccountManager::begin_selected_chat_copy(account_ref, group_id, linked_roster_selector)`.

The new boundary deliberately returns feature `NotReady`, default `Unsupported`
before account lookup, worker startup, KeyPackage creation or transport. The
observed RED is the final observable unavailable-request assertion, not a compile
failure or a fabricated MLS/storage fixture. Setup/compilation failures must be
recorded separately until the final assertion is reached. The committed GREEN control instead asserts `NotReady`, unchanged private bundle
inventory and outbound fanouts, absent B/C copies and unchanged two-member chat.
This qualifies only the denying boundary; it does not implement the request.
The default test also
uses an absent account and oversized selector and verifies no managed accounts.

## Smallest subsequent implementation

1. A explicitly selects one ordinary Current group and a fresh protected roster.
   Refresh actual Stable MLS state, local leaf/admin role, and exact linked-device
   identities. Reject Legacy and nonadmin requests. Existing Current identity
   proofs already support distinct device leaves with the same account credential;
   no optional capability upgrade or new `0x800a` wire component is implied.
2. Create a separate process-local selected-chat request/consent owner. Never reuse
   the consumed linking purpose102, SDK verification scope or cached Completed
   observation. Bound its original monotonic deadline, generation and cancellation
   independently. A roster selector is only a lookup observation.
3. Each selected sibling explicitly consents under that same request and creates a
   private, single-use KeyPackage bound to the exact ordinary group, intended device,
   package reference, request and original lifetime. Do not publish these packages
   through the normal public directory or copy an existing device's MLS state.
4. A authenticates actual sibling offers and performs one batch ordinary Invite,
   using the existing admin/profile/identity-proof machinery. Preserve original
   request ownership across frozen publication and unknown transport outcomes;
   publish recipient Welcomes only after actual authenticated commit confirmation.
5. Core/Session need a dedicated selected-chat recipient-purpose/join guard. Check
   it before consuming a reserved bundle and revalidate the decrypted actual group,
   welcomer/admin/full-tree identity and original lifetime through the SQL tail.
   Existing generic single-use joining does not supply this explicit consent fence.
   SQL rollback must retain the same original owner and exact ciphertext retry.

The acceptance test must obtain four independently held ordinary MLS leaves
(A,D,B,C), distinct sibling own-leaf indexes and exact accepted package references.
New messages from D and each linked device must project once with matching event
IDs/text on all intended devices. The old prejoin message remains absent on B/C;
full history transfer and a delivery journal are a later boundary. Add controls for
unselected groups, wrong device, nonadmin/Legacy, stale anchors, original expiry,
exact cancellation and package/join rollback before claiming ordinary delivery.

## Separate native observation lifecycle fix

The publication wait loop serves a limited frozen group-read snapshot while it
holds the client; native Setup Observe is deferred. A slow real publication can
therefore exhaust the bounded account response wait. Native `SessionState::refresh`
previously treated RuntimeUnavailable as terminal Failed/closed even when the
original actor intent was still live. The native stalled-publication regression
reproduced that mismatch after the real production 120-second observation wait.

The qualified fix preserves the latest cached observation only for the typed
AccountWorkerResponseTimedOut error. TransportClosed, owner/SDK loss and all
other errors retain their terminal behavior; the cache supplies no permission.
The actual original stalled publication now remains Pending, exact cancellation
completes within 500 ms, and releasing transport cannot publish its cancelled
Commit/Welcome. All eleven native feature tests and two default controls passed,
including actual public ABC settlement, expiry, Drop, shutdown and subscriptions.
See `device-sync-native-stalled-observation-verification.json` for source/log hashes.
This lifecycle fix remains separate from selected-chat permission and delivery.
