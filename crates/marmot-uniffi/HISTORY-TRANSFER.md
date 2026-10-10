# Original history transfer actions

The default-off `experimental-device-sync` surface forwards original App-owned
history actions. Enrollment and ordinary chat membership do not approve an
archive. This is a bounded logical snapshot, not an MLS state backup or a
continuous synchronization journal.

`begin_history_transfer(account_ref, group_id_hex, recipient_device)` selects
one ordinary chat and one exact linked recipient. The recipient polls
`pending_history_requests(account_ref)` and retains the returned `HistoryConsent`
object while presenting its authenticated snapshot. Display the source device,
chat, snapshot timestamp ceiling, record count and encoded size before calling
`approve(snapshot.revision)`. Observation records cannot reconstruct an action.

The source retains its original `HistoryTransfer` and calls
`continue_transfer(snapshot.revision)`. App owns transport and retries. Successful
continuation observes the authenticated final committed-import receipt; it does
not merely report local publication. Intermediate fragment acknowledgments mean
durable staging. `snapshot.complete` is an observation of committed completion,
not permission for a new transfer. An expired or cancelled original cannot begin
another positive action even when its prior completion remains readable.

Both objects have explicit synchronous `cancel()`. Retained aliases share their
original action; releasing the last original owner cancels unfinished work.
Keep handles with their originating account/runtime. Shutdown and reopen do not
restore consent from stored manifests, receipts or membership. Cancellation does
not remove already admitted device membership or erase completed retained history.

The captured snapshot contains at most 200 logical kind 9 records and 196,608
encoded bytes, split into at most 128 fragments of 1,536 bytes. Source rejects an
oversized snapshot before recipient consent; it never silently truncates history.
Record payloads contain logical content/tags, with source-attested provenance;
they are not independently MLS-verified messages on the receiving device.
Imports remain separate from live app-event and moderation projections. These
control objects do not supply a conversation rendering query. The separate
[committed-history reader](SYNCHRONIZED-HISTORY.md) exposes retained logical
records and provenance; native acceptance must qualify actual chat presentation.

Errors are typed `HistoryTransferUnsupported`, `HistoryTransferNotReady`,
`HistoryTransferClosed`, `HistoryTransferStaleRevision`, or
`HistoryTransferRuntimeUnavailable`; no error carries archive content or keys.
Default builds reject factories before parsing input or starting account workers.
A runtime failure never authorizes reconstructing an original object from a DTO.

Build the native library and generated Swift/Kotlin source from the same feature
and source cohort. Source support alone does not establish generated-language ABI,
matched Apple artifacts, installed application acceptance, or complete history sync.
