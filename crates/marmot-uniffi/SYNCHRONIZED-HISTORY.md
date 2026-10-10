# Read committed synchronized history

The default-off `experimental-device-sync` method
`synchronized_history_page(account_ref, group_id_hex, after_message_id_hex, limit)`
reads retained committed logical history through App's existing projection policy.
It is synchronous local storage work; call it off the UI thread. It does not send
relay requests, acknowledge transfers, acquire media, or change moderation state.
Normal account/storage initialization can still occur. The page and cursor are
observations and confer no enrollment, membership, consent or history-transfer
permission.

Use a nonempty opaque MLS group ID encoded as hex (at most 255 bytes), not a
Nostr route ID. A 16-byte MLS group ID is valid. `limit` is 1 through 200. Omit
`after_message_id_hex` for the first page; later cursors are exact 32-byte message
IDs encoded as 64 hex characters. Pages use message-ID keyset order, not timestamp
order. A full page may return a cursor even when the following page is empty.
Reload from the first page when the view needs to reflect current retention,
expiry, live-message precedence or new imports.

`ArchivedHistoryPageFfi.records` contains logical content/tags and source-attested
transfer, source-device and manifest-digest provenance. Imported records are
separate from live conversation and moderation projections. Label their source;
do not present provenance as independent verification of the original author's
MLS message. App preserves empty deleted/expired tombstones and filters records
under current retention/expiry and live-message precedence. Ordered media outcomes
retain rejected entries; an accepted descriptor grants no epoch key or download
permission. Debug formatting omits record contents and provenance.

Default builds return `SynchronizedHistoryUnsupported` before parsing inputs or
performing account/storage work. Experimental builds distinguish
`SynchronizedHistoryInvalidQuery`, `SynchronizedHistoryUnavailable` and
`SynchronizedHistoryInvalidRecord`. These typed errors expose no account details,
message content or private keys. This query does not reconstruct an original
history action from a stored manifest or completion receipt.

## C ownership

`marmot_synchronized_history_page` requires a writable output pointer and clears
it before input reads or effects. Borrow the live client, NUL-terminated account
and group strings, and optional cursor for the duration of the call; NULL cursor
means the first page. Do not free the client concurrently. On success, the caller
owns one `MarmotArchivedHistoryPage`; release it with
`marmot_archived_history_page_free`, which accepts NULL and releases all nested
records, strings, tags, media outcomes, provenance buffers and cursor exactly
once. Embedded records have no standalone free. Status values 117 through 120
append the four query errors without renumbering existing statuses.

Use matching generated Swift/Kotlin source or C header and the library built from
the same feature/source cohort. Source guards, empty-archive forwarding and C
allocation controls do not qualify actual native history import, alias lifetimes,
Apple deployment artifacts or conversation rendering.
