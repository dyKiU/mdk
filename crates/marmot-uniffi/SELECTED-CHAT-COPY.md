# Explicit selected-chat copies

The experimental `begin_selected_chat_copy` and
`receive_selected_chat_copy_request` methods expose opaque original actions for
admitting linked sibling devices to one explicitly selected ordinary chat.
Default builds return `SelectedChatCopyUnsupported` before account lookup or
effects. This surface is separate from protected-device verification and
enrollment. It transfers no prior chat history and advertises no capability.

## Selection and consent

On the source device, select a Current ordinary chat in which the local device
is an administrator. Obtain the opaque selector of an actually completed
protected linked-device roster from `device_linking_targets`, then call
`begin_selected_chat_copy(account_ref, group_id_hex, linked_roster_selector)`.
The group identifier is the ordinary chat's opaque MLS identifier, not its
Nostr routing identifier. Rust freshly validates actual group state and the
original selection; host-supplied observations cannot authorize membership.

Retain the returned `SelectedChatCopy`. Read its snapshot and use that exact
revision with `request_packet`. Privately transfer the bounded packet to each
sibling and call `receive_selected_chat_copy_request` there. Each original
`SelectedChatConsent` snapshot supplies a binary `chat_selector` for the
selected chat. Display the selection and obtain explicit approval before
calling `approve(displayed_revision)`. A stale revision is rejected.

Return each approved `response_packet` to the source through
`receive_consent_packet`, using the source's current displayed revision.
Export the same sibling's `offer_packet` and collect it with
`receive_offer_packet`. Exact duplicate offers are idempotent; rejected packets
do not advance the source revision or collected count. Packets are limited to
16 KiB and remain private. Do not log them or publish their contained package
event to a public directory. Retry the same original handles and bytes.

## Continuation and observations

When every selected sibling has explicitly consented and its offer is
collected, call `continue_copy(current_revision)`. Rust owns authenticated
package validation, the original lease, Commit publication and confirmation,
fresh successor validation, and Welcome publication. `InviteConfirmed` means
the source's ordinary Add was confirmed. It does not establish that every
recipient joined, received a message, or has historical messages. Use normal
chat projections and messages to observe recipient delivery.

Snapshots and selectors are observations only. They contain no proof, grant,
caller deadline, serialized cryptographic state or reconstructible lease.
Cancellation, original expiry and account-runtime shutdown deny further
positive actions. Cancel each original handle when its UI/account scope ends;
dropping its last shared reference schedules the same negative cleanup.
Dropping one alias does not cancel other aliases. Restart requires new
selection and consent; persisted package tombstones never recreate permission.

## Foreign ownership

Swift/Kotlin use the generated opaque objects and display records from the
matching native library. Do not infer support from type availability alone.
The [C guide](../marmot-c/README.md#selected-chat-copies) describes blocking
calls, explicit handle clones, output preflight and matching deep frees.
Source tests do not establish packaged native artifacts or application adoption.
