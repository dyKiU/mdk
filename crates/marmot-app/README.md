# marmot-app

`marmot-app` is the multi-account app runtime for Marmot clients. It wires the app-owned `AccountHome` to encrypted
session storage, the Nostr MLS peeler, the Nostr transport adapter, and relay-backed transport state, and exposes the
result as `MarmotApp` / `MarmotAppRuntime`. It sits below presentation layers (`wn`, the UniFFI and C bindings) and above
the generic account, session, and engine crates. Read this if you are building a host app or binding on top of MDK.

## Contents

- [Runtime overview](#runtime-overview)
- [SOCKS5 routing](#socks5-routing)
- [Local storage](#local-storage)
- [Account bootstrap and KeyPackages](#account-bootstrap-and-keypackages)
- [User directory and search](#user-directory-and-search)
- [Groups and invitations](#groups-and-invitations)
- [Conversations](#conversations)
- [Encrypted media endpoints](#encrypted-media-endpoints)
- [Application-owned group state](#application-owned-group-state)
- [History transfer recipient selection](#history-transfer-recipient-selection)
- [Read-only synchronized logical history](#read-only-synchronized-logical-history)
- [Explicit full-history repair](#explicit-full-history-repair)
- [History may be incomplete notices](#history-may-be-incomplete-notices)
- [User blocking](#user-blocking)
- [Group reports and admin deletion](#group-reports-and-admin-deletion)
- [Moderation reports to the operator](#moderation-reports-to-the-operator)
- [Audit v5 Welcome evidence](#audit-v5-welcome-evidence)
- [Run the tests](#run-the-tests)

## Runtime overview
The opt-in native startup recorder distinguishes task dispatch, account/key lookup, store-opening waits, SQLCipher phases, schema inspection and each migration transaction. `set_startup_diagnostics_enabled` and `startup_diagnostics_snapshot` change only bounded process-local diagnostic memory. Snapshots use their own short lock and remain readable while an account open is blocked; they do not open storage or query the keystore. Successful cached attachment reads and account-store lookups omit history events so ordinary reads preserve first-open evidence. An attachment read shares one active scope across queueing, account opening and result delivery; cache/admission waits remain visible, and misses, failures or unwinds retain evidence. Dropping its host future leaves running native work observable until the worker exits. Normal construction leaves capture disabled. Host exports must be explicitly requested and serialized within a separate size bound.


`MarmotAppRuntime` owns restored signing accounts, a shared relay plane, live per-account workers, runtime event hubs,
and the shared agent stream watch manager. The relay plane also owns shared directory discovery fetches for relay lists,
profiles, follow lists, and KeyPackages, including endpoint safety and in-flight coalescing. The daemon path is
runtime-owned subscriptions plus typed events; explicit catch-up remains available for repair and tests.

The runtime exposes account status, group listing/showing, message listing, and snapshot-plus-live subscription APIs,
so CLI, TUI, and native surfaces never open the databases directly.

**Startup.** `MarmotAppRuntime::start()` returns at local readiness: persisted account sessions are hydrated and
worker-routed local reads are available. Relay activation, group-subscription registration, shared-directory
synchronization, and initial catch-up continue asynchronously. Hosts should render local chat projections at that
point, show network progress separately, and let later relay events refresh or reorder rows. Mutating worker commands
received during initial catch-up are deferred and replayed in order once the live client is ready. While an owned
comparison's network request runs outside the worker, an empty deferred queue permits both direct sends and durable
local submissions to use the live client. Durable submissions retain the same completion, retry and projection path
as steady-state sends; they do not bypass an earlier deferred command. Automatic push-registration gossip after startup
or a receive/recovery pass arms the durable retry timer rather than awaiting the gossip batch before servicing sends.
Inline activation, KeyPackage maintenance, explicit push commands and a running scheduled push retry can still delay
sends.

Engine-queued sends receive an ordinary worker wakeup when their group's required publication acknowledgements and
MLS confirmation are complete, even if a secondary relay still has a later replication retry scheduled. The runtime
keeps the original relay event and retry deadline. Unmet required acknowledgements and pending MLS confirmation keep
their publication barrier.

A new same-account durable admission also lets the managed worker yield a scheduled secondary retry that is already
waiting on a relay. This applies only after required acknowledgements and MLS confirmation are complete. Unfinished
attempts remain conservatively recorded as possibly exposed and retry their exact saved bytes after backoff. The
worker finishes its current local effects before servicing the new send; required publication and confirmation work
is not cancelled. After a yielded pass, one durable submission receives service ahead of overdue secondary retry
passes once the finite backlog of deferred and buffered worker commands has drained. Earlier blocked commands keep
their ordering, and a temporarily unavailable submission keeps its existing retry deadline. This does not prioritize
durable sends over an indefinitely replenished command stream.

For new durable admissions in the current runtime, `send_queue` and `outbound_message_queue_wait` measure the interval
from the committed admission to its first worker execution. Execution and publication remain separate measurements.
Repeated tokens and completion retries do not restart that observation. The private correlation map is bounded to
1,024 observations per runtime; capacity omissions and shutdown cancellation count as cancelled observations, without
a successful queue-duration sample. A retained admission can remain observed across sign-out within the same runtime.
Permanent account removal cancels its remaining observations. Admission and selection use per-account gates;
observing a send does not add a cross-account database lock.
Rows restored in a new runtime have no original monotonic admission instant and produce no fabricated queue-duration
sample. These measurements do not include host rendering or every subsequent engine/retry wait.

**Per-account worker isolation.** A failed account open does not discard a sibling that reached local readiness.

- A failed account gets an in-memory retry delay starting at one second and doubling to a 60-second cap. The next
  reconcile or worker request after expiry admits one attempt; there is no background retry timer.
- `restart_account` explicitly retries an eligible account. Successful sign-in, signer registration, and committed
  setup/onboarding transitions reset that account's delay; successful startup clears its failure record; account
  removal, deactivation, and runtime shutdown discard it.
- Reconcile and start still report an error if any eligible account failed or is cooling down, while healthy workers
  stay usable through account-scoped commands.
- Signed-out, missing-signer, and onboarding-gated accounts remain ineligible even after a reset.

**Shutdown.** Hosts whose process can be suspended must call `MarmotAppRuntime::shutdown_and_close`, which closes every
database and releases file locks; `shutdown` alone does not. See
[local artifact safety](../../docs/marmot-architecture/overview/local-artifact-safety.md).

For where the code lives (`src/runtime/`, `src/client/`, `src/directory/`, `src/media/`, and so on) see
[`AGENTS.md`](AGENTS.md).

## SOCKS5 routing

Set the process environment before the first network-policy use (including runtime or NIP-46 client construction):

| Variable | Value |
| --- | --- |
| `WN_SOCKS5_PROXY` | Numeric IP address and nonzero port, such as `127.0.0.1:9050` or `[::1]:9050`. |
| `WN_SOCKS5_USERNAME` | Optional SOCKS5 username. |
| `WN_SOCKS5_PASSWORD` | Optional SOCKS5 password. |

Unset or empty values select direct routing when all three variables are empty. With a proxy endpoint, leave both
credential variables empty for anonymous SOCKS5, or supply both for RFC 1929 username/password authentication. Each
credential must contain 1 to 255 UTF-8 bytes without NUL. Partial credentials, credentials without an endpoint,
hostnames, URL-form endpoints, and zero ports are rejected. The first use snapshots the policy for the entire process,
including invalid configuration. Later environment changes, including clearing these variables, do not change routing
or unblock an invalid policy. Restart the process to apply a different configuration.

The policy covers relay publishing, account receive/history pools, directory relay clients (including completion-aware
reads), C NIP-46 signer sessions, and the shared HTTP clients for media, Open Ranking, and collectors (including audit
uploads). Completion-aware reads retain pre-admission wire-event counts under the proxy transport. Relay hostnames are
resolved by the proxy. HTTP clients still resolve and validate destinations locally, then send the pinned IP through
SOCKS5 while retaining the original HTTP Host header and TLS identity. The proxy is an explicitly trusted egress.

`ALL_PROXY` cannot replace this policy and `NO_PROXY` cannot bypass it. Invalid configuration, connection failure,
and authentication rejection do not fall back to direct connections. QUIC agent preview publishing and watching
are unavailable with SOCKS5 enabled because this TCP proxy path cannot carry QUIC.

## Local storage

The runtime owns these local SQLite stores:

- **Per-account session database** (`accounts/<label>/session.sqlite`, SQLCipher): authoritative protocol and recovery
  state plus app projections: joined groups, app-component profile/image/admin/Nostr-routing projections, pending invite
  confirmation state, seen relay events, and sent/received message projections. It has a numbered migration history.
  The older `accounts/<label>/app.sqlite3` legacy projection database is imported once (tracked by the
  `legacy-account-projection-v1` marker) and then superseded.
- **Per-account directory cache** (`accounts/<label>/app-cache.sqlite3`, SQLCipher): the Nostr user directory —
  local-account links, profile metadata, follow-list caches, bounded search-graph edges, discovered user relay lists,
  and KeyPackages. A root-level `app-cache.sqlite3` is a legacy location that is migrated and then removed.
- **Installation-wide `shared.sqlite3`** (owner-only, unencrypted): a provenance-stripped public-directory mirror,
  relay-telemetry and audit-log preferences, and the telemetry installation id.

For `N` active signing accounts whose stores have been opened, this is up to `2N + 1` current SQLite files.

The two directory tiers are reconcilable caches, but normal upgrades should preserve them, and `shared.sqlite3` also
holds durable installation settings that are not disposable. The per-account cache has its own numbered
`app_cache_schema_migrations` ledger and refuses versions newer than the binary supports. Each migration commits its
schema/data changes and ledger row atomically; version 1 validates and adopts existing unversioned tables and converts
legacy JSON records without discarding directory or search data. Invalid shapes or migration names fail closed. The
shared store still initializes tables without a numbered ledger; neither tier uses the session database's migration
version.

## Account bootstrap and KeyPackages

Interactive imported-account sign-in pauses at `SingleDevice`. Continuing after
possible or inconclusive other-installation discovery persists a companion
publication hold, skips the public KeyPackage step and completes local setup.
Complete empty discovery retains ordinary publication unless a hold already
exists. Reopening applies the hold before activation; it blocks manual publication
and retained maintenance fanout, without copying MLS state or pairing devices.
Existing public slots and invitations already encrypted for another installation
are not repaired by this policy. See the [native onboarding contract](../marmot-uniffi/README.md#single-device-notice).

**New accounts.** Bootstrap publishes the required NIP-65 kind `10002` and inbox kind `10050` relay-list events, a
kind `0` profile, and an initial last-resort Marmot kind `30443` KeyPackage from a default relay set. Account setup
requires acknowledgements from its operational relays.

- KeyPackages are published to (and fetched from) the account's NIP-65 relays; there is no dedicated KeyPackage relay
  list.
- Generated account setup can supply public indexers for copies of the relay lists and kind `0` metadata. Indexers are
  publication-only: they are not declared in NIP-65, used for KeyPackages, or recorded as bootstrap relays. Indexer
  copies are best-effort per endpoint, start after operational bootstrap confirmation and before initial KeyPackage
  publication, never delay account readiness, and are cancelled on runtime shutdown or account removal.
- Import flows can check whether those lists already exist before writing local account state. The same status API can
  fetch relay-list events from supplied bootstrap relays and store discovered user relay/KeyPackage data for
  deterministic CLI/TUI development.

**Publication.** KeyPackage publication keeps a stable replaceable `d` tag per account and tracks the decoded
KeyPackage ref separately. Normal publish reuses only a cached current-profile last-resort package; explicit rotate, a
legacy cache entry, or a lifetime-policy rejection creates a new current-profile package under the same slot.

**Inventory.** `account_key_package_records` / `account_key_packages` expose one current relay event per addressable
slot in the validated fetch window. `account_key_package_relay_events` returns that window's current and superseded
public events, so a client can delete a superseded event id without targeting the current winner or inventing a second
Published row.

Local-first hosts should call `local_account_key_packages` immediately, then independently await
`refresh_account_key_packages` and replace the displayed snapshot.

- The local read is storage-only: it does not wait for network startup, start a worker, or query relays. It is
  synchronous SQLCipher I/O on the caller's thread, so keep it off a UI or main thread. All local rows have
  `relay == false`.
- `local_state` is the durable lifecycle (`Current`, `PendingReplacement`, `RetainedPrivateMaterial`, `OtherOwned`);
  `record.relay` is a validated relay observation. Do not infer lifecycle from empty event IDs or `published_at`. A
  retained row stays `RetainedPrivateMaterial` even when that exact event is observed (`record.relay` becomes true).
- A failed or cancelled refresh must keep the local result. Empty bootstrap relays remain network-enabled. After a
  mutation, re-read local inventory rather than applying an older refresh.

**Legacy cutover.** Account open performs the strict profile cutover before transport processing: the encrypted session
transactionally retires every locally stored legacy KeyPackage private bundle, then the app best-effort deletes cached
and relay-discoverable legacy kind `30443` events. A private owner-only retry marker is written before relay cleanup, so
a crash or relay failure cannot restore legacy join capability or lose the obligation to publish a current replacement.
Legacy Welcomes are terminally rejected. Already-joined legacy groups remain usable by their existing members,
including their Media V1 state, but membership additions and re-additions are refused.

## User directory and search

The user directory is keyed by Nostr pubkey. Account setup and the daemon can refresh a local account's contact-list
event, pre-cache direct follows, and cache profile metadata for those likely contacts. Runtime startup builds chunked
directory subscriptions for local accounts and known users so profile, follow-list, relay-list, and KeyPackage updates
keep warming the cache.

**Profile sanitization.** Incoming kind `0` strings are sanitized in `directory/records.rs` before they are cached:

- `about` keeps normalized line breaks: adjacent CRLF and a lone CR become LF, U+2028 and U+2029 become LF, and interior
  blank lines stay. Every other known string (`name`, `display_name` / `displayName`, `picture`, `banner`, `nip05`,
  `lud16`) stays single-line.
- Both modes remove tab and every other control, including NUL, ESC, BEL, DEL, and C1 (U+0085 is removed, not treated as
  a newline). Ends are trimmed after filtering, the value is capped at 4,096 Unicode scalars, and any trailing whitespace
  exposed by that cap is trimmed.
- A previously cached bio that already lost its line breaks stays until a newer event is accepted; an equal
  `created_at` does not replace the cached row. Publishing a local profile caches the submitted value directly without
  reparsing it.

**Cache-only search.** `search_cached_users(searcher, query, limit)` searches public profiles learned through **any
connected account**, including un-promoted profiles from previous searches, without relay access or group membership
reads. A profile learned during a search under one account is intentionally searchable under another. Private
labels/nicknames do not participate. `is_followed_by_searcher` is relative only to the selected account; another
account's follows never confer that label. The older `search_user_directory` remains the explicit offline graph-radius
query.

**Streaming search.** `search_users` emits a `CachedResultsFound` batch, then streams Vertex (Open Ranking) profile
discovery independently of the bounded follow-graph traversal. The runtime resolves group co-members on the graph path,
after the subscription is returned.

- Consumers insert `new_results` and replace `updated_results` by `account_id_hex`, then re-sort. `total_result_count`
  counts unique people. Deduplicate by account ID across searches and pages as well as within a stream.
- Radius 255 means no established graph distance yet; one may arrive later. Radius 1 also includes group co-members, so
  only the explicit follow flag means "You follow". Requested radius windows filter known distances; other
  cached/provider identities remain discoverable and can recur on later pages.
- Cache materialization is capped at 10,000 distinct identities per account cache (in account-ID order), matching the
  shared directory's cap; the cache-only API and the stream's initial cache batch return at most 10,000 results. At that
  scale local results can be partial; network enrichment remains available.

Hosts should run the cache-only call off the UI thread on each query change, debounce network searches separately, and
discard results when the query or selected account changes. Dropping the streaming subscription cancels both network
sources, including blocked membership reads. A failed cache read or unavailable group membership is an optional-source
failure: search continues without that input rather than emitting a terminal error. Vertex's signed profiles are cached
only in the un-promoted search tier; discovering a stranger never creates a live per-author subscription. Traversal
keeps its radius, candidate, batch, and timeout bounds. Aggregate `search_stage` timings separate cache reads,
membership, provider response, profile hydration, and network completion, without logging queries or identities.

## Groups and invitations

**Creating and inviting.** Group creation and invites take pubkeys at the action boundary. The app canonicalizes and
deduplicates the requested roster and fetches current KeyPackages in bounded multi-author relay batches before building
the MLS add.

- Cached packages are useful for discovery, but cannot authorize an invitation or substitute for a failed relay lookup.
  This also applies to another account on the same installation: its local package record is not an invitation
  shortcut, and its published package must be reachable on relays. Relay freshness is not proof that the recipient still
  owns private material; it avoids authorizing from a stale local copy.
- Hosts may prewarm the same bounded composition lookup without reserving packages or durably admitting strangers; the
  final action reuses discovery routes but fetches packages again before the mutation validates them. Each prewarm call
  requests a fresh readiness signal, so debounce roster changes. The process-local prewarm cache keeps only bounded
  relay metadata; only completed discovery and advertised-outbox metadata hops renew its freshness deadline, and a
  usable package returned after an incomplete metadata hop does not make previously cached routes fresh.
- Directory diagnostics (such as `wn keys check` / `keys fetch`) may still describe cached public packages. Their availability
  result is advisory and does not guarantee a fresh relay lookup or acceptance by the create/invite admission policy.

When advertised outboxes have no usable invitation package, lookup makes one supplementary pass over up to eight
safe configured discovery endpoints that were not already searched. Explicit bootstrap endpoints supply this set for
direct directory lookups. Successful advertised lookups skip the supplementary pass. Recovery keeps observed
replacement barriers and requires complete package coverage and completed deletion queries for each usable candidate
across the searched routes. Separate exact-event and timestamp-scoped coordinate filters ask for one signed deletion;
unrelated deleted posts cannot fill their limits. Any verified matching deletion rejects the candidate, even when
another route is incomplete. Accepting a candidate requires complete empty queries on every required route; unknown
coverage and the twelve-candidate budget remain retryable. Signed deletions cannot revive an older slot version.
For direct diagnostics, the existing future-record cache fallback also requires this proof for its cached public
metadata. Incomplete recovery refuses that fallback; a revoked or superseded cache entry is never returned.
Cached entries without a usable public event identifier are ineligible for this fallback.
Member resolution and direct lookup each have a 50-second overall deadline. Relay visibility still cannot prove that
the recipient retains the private package, or that every relay disclosed all replacements and deletions.

**Routing.** New Nostr-routed groups generate `marmot.transport.nostr.routing.v1` at creation, store the component bytes
in signed MLS app data, and project the decoded `nostr_group_id` plus relay list into group subscriptions and publish
targets.

**Welcomes.** Incoming welcomes are joined automatically at the MLS/session layer, then projected as pending local
chats. Clients render accept/decline UI from the group record: accept clears `pending_confirmation`; decline publishes a
leave, clears the pending flag, and archives the local projection so normal chat lists hide it.

**Committed group activity.** Commands and maintenance retain native cleanup and commit activity before subscription
work can suspend. Manual and scheduled convergence retain subscriber deltas through route refresh, checkpoints,
notifications and invitation recovery. Quiet observations return repaired deltas once without republishing the accepted
MLS commit. Cancellation preserves the owning client's pending work; these queues are session-local, not a crash-durable
event journal.

## Conversations

- **Drafts.** Rust app/runtime draft commands expose selected metadata, conditional save/clear, keyed attachment bytes,
  and revision-bound sends. Post-commit invalidations let conversation owners reload the selected composer; durable
  outbox acceptance clears only the submitted revision. See the
  [draft lifecycle contract](../../docs/marmot-architecture/further-context/conversation-drafts.md).
- **Presentation.** The shared conversation presentation builds a compact header, shared capability hints, and a
  complete dictionary for its bounded visible identity references from local caches. Native management policy delegates
  to the same Rust selector. See the
  [conversation presentation contract](../../docs/marmot-architecture/further-context/conversation-presentation.md).
- **Live window.** `MarmotAppRuntime::open_conversation_window` combines that presentation with bounded history,
  retained read state, and the selected draft in one initial/live handle. It opens at first unread or latest, follows
  new arrivals in latest mode, preserves explicit/history anchors, and serializes paging with refreshes. Capture
  failures keep timed retries; account teardown and subscription drop close the handle. It never marks read or loads
  attachment bytes. UniFFI and C expose the same handle. See the
  [live conversation contract](../../docs/marmot-architecture/further-context/conversation-live-window-plan.md).

## Encrypted media endpoints

Encrypted media and encrypted group images are uploaded as opaque `application/octet-stream` blobs. A compatible Blossom
server must accept arbitrary binary data rather than only recognizable image, audio, or video payloads. New groups use
the ordered built-in ciphertext-compatible endpoint list unless the host build supplies
`MARMOT_ENCRYPTED_MEDIA_BLOB_ENDPOINTS`. Encrypted media uploads try those endpoints in order; encrypted group-image
uploads use only the primary (first) endpoint.

The endpoint list is embedded in the signed `marmot.group.encrypted-media.v1` component. Changing application defaults
does not rewrite existing group state. An active group admin can migrate an existing group with
`replace_encrypted_media_blob_endpoints` through the app runtime or UniFFI API.

Encrypted group images differ: no endpoint is stored in group state, so upload and fetch both resolve against the
build's primary endpoint. Clients compiled with different defaults therefore look for group images in different places;
re-setting the group image on a current build republishes it to the current primary endpoint.

## Application-owned group state

`MarmotAppRuntime::group_app_component` reads opaque application-owned component bytes from local MLS state;
`update_app_component` replaces one optional component through an admin-authorized MLS commit. The same methods are
exported by UniFFI and C. Updates to required components are rejected; use the existing typed APIs for protocol
settings.

Applications allocate their own component ids at or above `APP_OWNED_APP_COMPONENT_ID_START` (`0xf000`) and version
their own payloads. Ids below that boundary are refused. The boundary exists because the protocol registry allocates
upward from `0x8001` and is still growing: an application that picked the next unassigned private-use id would have that
id assigned out from under it by a later registry entry, which both breaks its own writes and starts applying protocol
format validation to bytes already committed in live groups. Nothing coordinates ids between applications, so treat the
range as first-come and version the payload.

Payloads are capped at `APP_COMPONENT_DATA_MAX_LEN` (4096 bytes). Before staging an application update, MDK limits the
resulting application-owned state to 32 entries and 8192 encoded bytes, including each entry's id and TLS length prefix.
Replacements count once; empty values still occupy a slot. These are local authoring limits; unknown optional state
received from peers stays opaque. Component state is re-encoded into the GroupContext of every later commit and into the
GroupInfo of every Welcome, so an oversized value inflates every commit and can push a Welcome past a relay's event-size
limit — after the commit is already staged. This is a settings channel, not a blob store; put bulk data behind a
reference.

An absent component returns `None`; a present empty payload returns `Some(Vec::new())`. Empty payloads do not remove a
component. The state survives message expiry and reaches newly invited members in their Welcome, without sharing earlier
application-message history. Unsupported clients preserve optional component bytes without interpreting them.

Refresh on runtime group events (including `EpochChanged` and convergence) and after local updates. Reads are serialized
through the account worker and may wait behind an in-flight mutation. Updates use existing publication and convergence
semantics; hosts must handle publication uncertainty and `GroupChangeSuperseded` rather than assuming a successful local
change wins every later concurrent commit. This API does not add automatic retries of an application's desired value.

## History transfer recipient selection

With `experimental-device-sync`,
`AccountManager::history_transfer_recipients(account_ref, group_id)` lists
current linked-device choices for one ordinary chat. Core freshly checks the
selected protected completed roster and the ordinary Current-profile state in
one storage read snapshot. Results contain exact occupied leaf indices and
public device identities, ordered by index, excluding the local device and
bounded by the private roster's 128-leaf limit. Debug output omits identities.
The account worker serializes the query; it creates no transfer, pending request,
consent, lease, archive or network publication.

Pass a selected device identity to `begin_history_transfer`; Core independently
revalidates the current selection. A successful list is an observation, not a
promise that a transfer can start or that the recipient has approved it. The
recipient must review and explicitly approve its original received request at
the displayed revision. Refresh choices when the linked roster or chat changes.
Default builds return `Unsupported` before account or worker effects; invalid
MLS group lengths return `NotReady`, and an unavailable account worker returns
`RuntimeUnavailable`. UniFFI/C export and matched host adoption require separate
qualification.

## Read-only synchronized logical history

With `experimental-device-sync`, `MarmotApp::synchronized_history_page` reads
completed logical archive records from one account's encrypted storage. Select
an opaque MLS group ID and a page limit from 1 to 200. Results use message-ID
keyset order; pass `next_message_id` for the following page. A full last page
may require an additional empty read. Default builds return typed `Unsupported`
before account or storage effects.

Each `ArchivedHistoryRecord` carries logical content and tags, captured expiry,
source device, transfer ID and manifest digest. This is source-attested history.
It does not independently authenticate the original author's MLS message or
supply permission for another transfer. Live authenticated events shadow archive
copies. Completed-import retention fences and captured expiry govern visibility;
tombstones contain no content or attachments. Invalid logical payloads fail the
page with a typed error. Media outcomes preserve the shared parser's ordered
accepted/rejected verdicts without initiating downloads.

The query performs no relay I/O, read acknowledgment, moderation or media
acquisition. It remains separate from the existing live conversation projection.
Hosts must keep provenance visible when presenting archive records; native ABI,
conversation integration and installed-app history acceptance require separate
qualification. Storage-seeded query tests alone do not prove original history
transport or consent.

## Explicit full-history repair

`MarmotAppRuntime::repair_full_history` requests one owner-authorized explicit-history obligation and runs the account's
one recovery job for it in place: a NIP-77 comparison of every route over the retained-inventory window, then bounded
admission of what it fetched through ordinary ingest. It installs and replays no subscription. It never reports
complete: full history has no lower bound, and no comparison searches below the inventory floor. When every required
relay certified its route's window and every difference was durably admitted, the repair returns `BelowRetentionWindow`,
naming the unsearched older history, and closes its request: it leaves no explicit-history debt, raises no "history may
be incomplete" notice and records no coverage. Otherwise it returns `CoverageUnproven` and its debt stays open for the
owner's ordinary retries. Each pass fetches at most 16 missing events per relay, so a large gap can take further repairs
or automatic passes. Known-event recovery can instead complete from a validated retained copy. Maintenance uses its
separately fenced boundary.

The Rust `AppError::FullHistoryRepairIncomplete` preserves a bounded `FullHistoryRepairIncompleteReason` and an
independent `delivery_loss_pending` flag. Worker/binding calls retain their existing error channel; their safe error
code reports outstanding delivery loss when present, with cancellation taking precedence. No incomplete attempt is
converted to a success. Rust callers can inspect `AppError::full_history_repair_incomplete()` for the typed reason and
independent loss flag, including through `AccountCatchUp`. It never parses display strings. The API shape for repair
calls is unchanged.

The explicit attempt may wait up to 60 seconds for a process credit, then gets its own 60-second cooperative budget for
setup, comparison and admission. The comparison gets the first 50 seconds: a route still comparing then times out, and
the routes that finished are admitted and checkpointed in the remaining 10, stopping at a turn boundary if the whole
budget runs out. Cancellation discards a comparison in flight and also stops admission at a turn boundary. A started
ingest/checkpoint finishes first, so this is not a hard bound on an individual storage operation. A certified window
still wins over the clock: the attempt reports `Cancelled` if cancelled, `Deadline` if admission ran out or the cutoff
left the window uncertified, and otherwise `BelowRetentionWindow` or `CoverageUnproven`. Partial progress remains
durable, outstanding loss survives reopen, and only qualified completion plus the exact live acknowledgment can reclaim
captured loss evidence. The only other way to release its cursor fence is the user dismissing that loss's "history may
be incomplete" notice (below), which is never coverage.

The account remains serialized during repair. The worker can serve committed member/roster snapshots while the
comparison runs off the worker; mutations, subsequent repair requests, and reads behind queued mutations retain FIFO
order. Send fairness remains #1947 work. All automatic history triggers use the same owner, job and durable pacing;
bounded investigation can leave unresolved debt parked for new evidence or explicit repair.

## History may be incomplete notices

Recovery parks an obligation after its fixed budget of fruitless attempts instead of retrying forever.
`MarmotAppRuntime::history_notices(account_ref)` lists each parked occurrence as a `HistoryNotice`: an opaque
`notice_id`, a `HistoryNoticeCause` (delivery loss, notification loss, a group's epoch gap, incremental or explicit
history), the group for a group-scoped occurrence, and when it parked. Show it as "history may be incomplete". A group's
own occurrences also set `GroupRecoveryStatus::history_may_be_incomplete` and list their ids in `history_notice_ids`;
account-wide ones (loss, incremental and explicit history) appear only in the list.
`MarmotAppEvent::HistoryNoticesChanged` announces any change, and a group whose own notices changed also gets
`GroupStateUpdated`.

`dismiss_history_notice(account_ref, notice_id)` runs on the account worker. After the user accepts that the history may
be incomplete, it durably retires exactly that occurrence as its own outcome (`state = 2`), never as coverage. A retired
loss keeps its evidence as a watermark, so a delayed duplicate cannot rearm it, and releases the transport-cursor fence
once no loss obligation remains pending, without counting a recovery success. It returns false for a stale id. New
evidence re-arms recovery under a new revision, so the notice disappears and a later parking is a new notice with a new
id. New loss, a higher missing epoch, each startup's incremental comparison, or a new explicit repair reopens retired
demand as fresh debt. A malformed id is `AppError::Hex`.

## User blocking

`MarmotAppRuntime` exposes `block_user`, `unblock_user`, `get_blocked_users`, `is_user_blocked`, and
`subscribe_blocked_users`. The same API is available in UniFFI (Swift/Kotlin) and the C ABI. All calls resolve an
existing account reference; user keys use the existing public-key parser. Blocking yourself and repeating an already
completed operation succeed without changing state.

Reads use the account's SQLCipher database. Lists contain `public_key`, `is_private`, and local `created_at_ms`, sorted
newest first with public key as the tie-breaker. The subscription supplies an initial snapshot and subsequent complete
snapshots with a durable revision. Intermediate revisions may coalesce; subscribers replace their local list with each
snapshot.

Changes fetch the latest readable [NIP-51 kind 10000 list](https://github.com/nostr-protocol/nips/blob/master/51.md)
from the account's NIP-65 relays (or configured discovery relays). New entries are private NIP-44 tags; legacy NIP-04
content remains readable. Other public and private tags retain their placement. Startup, reconnect, and owned-account
subscriptions synchronize published lists. Whole-list replacement can still cause independent cross-device edits to
compete.

`BlockListUnavailable` means synchronization or definite publication failed; changes learned during the preceding fetch
are retained. `BlockPublicationUncertain` means delivery or local completion is unresolved. The exact signed event
remains in the account database. While it is unresolved, other edits return the same uncertainty error. Retrying the
original operation reuses it after fetching again; a newer remote replacement supersedes the old intent. Startup
reconciles retained intents against relays. A definite rejection on a later retry cannot disprove delivery of the
original attempt: the intent still fences other edits until that original operation succeeds or a current relay
replacement resolves it. Restoring relay write access may be necessary; retrying alone does not guarantee recovery.
Success requires relay acceptance and committed local state. An unreadable authenticated replacement prevents edits
until a readable replacement catches up, including after restart. Private plaintext never enters the shared directory.

Blocking retains history and existing DMs, disables their user-authored sends, and rejects new DMs with `UserBlocked`.
It hides blocked authors from app message reads, search, timelines, media lists, reactions, quotes, previews, and
attention counts. Chat-list activity ordering deliberately still advances on blocked traffic; when the latest message's
author is blocked, its preview is blank and no older visible message is substituted. Manual-unread reminders remain
independent. Shared groups continue to process MLS state and permit communication with other members. Pending
invitations from blocked inviters remain stored but hidden; new Welcomes are checked against their authenticated sender
before admission and durably dismissed. Unblocking refreshes retained content and invitations without replaying
suppressed notifications. Raw storage and the runtime diagnostic event stream remain separate from these presentation
APIs. Notification suppression records are removed when their source event or group is physically deleted. Dismissed
Welcome IDs remain for the account's lifetime: they have no admitted group or event to attach retention to, and
forgetting them would allow an old relay delivery to create an invitation after unblocking.

Native screens and imports of old White Noise local databases are outside this feature. Existing published lists migrate
through relay synchronization.

## Group reports and admin deletion

`report_message` sends a kind-1984 NIP-56 report with a category and optional explanation. It references a message event
directly, without a revision tag or per-reporter deduplication. Admins use `dismiss_reports` to label specific report
events with kind 1985 and an optional explanation. Each label is independent.

The existing `delete_message` API sends kind 4891 for admin deletion of a whole chat, including an unreported message or
the admin's own message. Kind 5 remains author-only retraction. Admin authorization comes from authenticated source
state; later demotion does not revoke an established verdict. Group size and name do not affect authorization.

`content_reports` lists individual reports, optionally filtered to a message. `report_dismissals` lists admin labels.
`reported_message` returns a reported target's current deletion-masked projection, bypassing personal blocking. Timeline
records expose `has_reports` through existing subscriptions. There is no shared queue, counter, or aggregate review
status. Hosts choose review UI and notifications. Report explanations follow their own retention and survive target
deletion while retained.

See [the implementation contract](../../docs/marmot-architecture/overview/content-moderation.md) for source-state
authorization, durable recovery, retention, and client compatibility.

## Moderation reports to the operator

`MarmotAppRuntime::submit_moderation_report` privately reports an account to the deployment's moderation team. It
sends a kind-1984 NIP-56 rumor, sealed by the account key and gift-wrapped per NIP-59 to the configured reports key.
The rumor carries the reported key, its report type, a `chat.whitenoise.report` origin label (`report` or `block`) and
the optional explanation. It never carries conversation identifiers. This channel is additive: `report_message` and
the rest of group moderation are unchanged.

The destination is `MarmotAppConfig::moderation_report_config` or `MarmotApp::set_moderation_report_config`. An
invalid key or any unsafe relay rejects it whole. Wraps go only to the configured relays, through a publisher that
never authenticates as the account. The signed wrap is staged in the account database first. `AcceptedPending` and
`CompletionUnknown` outcomes are retried in the background after `catch_up_accounts`, or on demand with
`retry_pending_moderation_reports`. Repeats within 10 minutes return the existing outcome. Each account may send 20
reports per hour. Sign-out and wipe delete the account's queued reports.

See [moderation reports](../../docs/marmot-architecture/moderation-reports.md) for the wire format and reader steps.

## Audit v5 Welcome evidence

Opt-in audit recording writes v5 files (see [`marmot-forensics`](../marmot-forensics/README.md)); historical v4 files
keep their separate legacy whole-file upload path. With audit logging enabled, the app records v5 Welcome evidence from
real founding, publication, receipt, peel, join and checkpoint boundaries. The
[Welcome probe notes](tests/audit-v5-welcome-probe.md) describe those boundaries and the unit tests that exercise them:

```sh
cargo test -p marmot-app --lib audit_v5_probe -- --nocapture --test-threads=1
```

## Run the tests

```sh
cargo test -p marmot-app
# Accelerated recovery/retry scenarios (also enabled by workspace CI):
cargo test -p marmot-app --features test-policy-overrides
# Opt-in OTLP exporter wire encoding and push:
cargo test -p marmot-app --features otlp-export
```

See [`AGENTS.md`](AGENTS.md) for the module map, invariants, and privacy-safe telemetry rules.

## Experimental device verification

`experimental-device-sync` enables a private per-device adapter using the stock
Matrix SDK 0.19.1 SAS request/commitment/key/MAC/done flow and standard decimal
display. It binds the exact account, device identities, KeyPackage bytes and
reference, device group, canonical indexed predecessor roster, nonce, and both durable reservation
generations to contextual verifier identities. No Matrix server is contacted.
Private context version 2 additionally binds a nonzero predecessor-artifact digest
for a nonzero-epoch roster with at least two occupied leaves, under a separate
hash domain. Version 1 retains its original serialization and domain and rejects
that added field. The raw SDK adapter checks this binding; it does not authenticate
the artifact or authorize multi-leaf enrollment. Account-runtime setup and recipient
admission remain separate gates.

Sibling chat-sharing publication prepares the exact control under its account
worker, then waits for the relay in at most four original-owned jobs per account.
An unfinished relay publication does not block inbound handshakes or another
approved sibling. The worker revalidates the live parent and channel before
recording publication; a relay ACK never substitutes for the peer's authenticated
consent or policy proof. Channel retirement cancels its pending publication.

The private framing is not an adopted Marmot wire protocol. Offers and verifier
frames have a versioned, kind-separated binary envelope with a bounded canonical
JSON body. Decoders reject oversized, truncated, trailing and cross-kind packets;
frames also bound their UTF-8 acknowledgement token. Decoding does not assign
trust: live context, signed-key-directory and stock verifier checks still run
before accepting peer data. The codec does not expose enrollment permissions or
provide a relay/QR transport on its own.

Each instance requires its own confirmation and a verified peer MAC before
producing an internal, one-shot pairing result. That result does not authorize
enrollment, messaging, or history. Exact device-group Welcome validation and an
authoritative settled roster remain separate integration requirements. The
adapter has an isolated account-scoped owner using storage 104: it reserves the
local generation and binds the exact context and SDK flow before output, abandons
interrupted flows on runtime startup, and persists terminal facts before releasing
a result. It never restores verifier secrets. Stock Done frames must be delivered
within the owner's fixed ten-minute deadline, which starts before reservation
storage or SDK setup and is not extended by request/response timers. Delivery
must also be explicitly acknowledged before terminal completion. Restart fencing also runs
through real local-client startup, after exclusive account-session ownership,
including the managed worker's deferred-hydration/reconnect path. A competing open
cannot abandon a live flow, and another account's attempts remain untouched.
The actual account client owns the verifier using its session identity and stored
MLS signer, installs its private Welcome policy, and revokes retained policy handles
before releasing the session. Its private prepare/cancel operations reserve exact
generation-owned material and retire only unjoined purpose packages after terminal
fencing. Private managed-worker lifecycle commands prepare and cancel exact scoped
attempts. An independent feature-only timer expires the original reservation or
sealed approval and retries unjoined package cleanup after storage failure.
An undeliverable prepared result cancels its exact attempt immediately. A failed
terminal write retains cancellation for maintenance to retry before expiry;
discarded verifier secrets are never restored by that retry.
Private account-client verifier operations bind the exact owned package and
scope before exchanging offers, frames and two-sided confirmations. Their
one-shot result leaves Welcome admission closed pending approved-roster
validation. Private serial-worker commands also exchange scoped offers, frames
and confirmations between independently managed account sessions. Roster
enrollment and native bindings remain separate integration requirements.
The private context includes the predecessor epoch, epoch-authenticator digest
and strictly ordered indexed device signers. The approver must be present and the
recipient absent. The join policy compares the authenticated Current-profile tree
against exactly that predecessor plus the recipient at the next epoch, including
real leaf indices and account credentials. These checks bind intended contents;
a durable approved predecessor anchor and complete settlement remain required.

Run the adapter and genuine managed-worker linking tests with:

```sh
cargo test --locked --lib -p marmot-app --features experimental-device-sync,test-policy-overrides device_linking
```

The optional verifier requires newer shared dependencies in Cargo.lock; default
builds also use those pins and need validation. Package and conformance versions
remain unchanged.

### Experimental private origin bootstrap

The default-off device-linking core creates a protected self-only private group
through its serial account worker. Approver pairing setup freshly validates the
actual selected genesis or opaque completed settled predecessor, account-device
signer and exact indexed predecessor before
starting verification. An ordinary one-member conversation cannot serve as this
origin. A completed birth persists across a dropped reply or restart without
reconstructing verifier consent.

The private account runtime also owns an Approver consent policy for the
dedicated Engine Add-preparation path. It accepts the completed stock SAS result
and fresh private-origin evidence, retains the original deadline through staging
and wrapping, and consumes permission when committed preparation is dropped.
Cancellation and account teardown revoke retained policies and held leases.
Durable facts cannot recreate this permission.

This remains an internal, default-off path. Settled successor bootstrap,
publication confirmation, Welcome promotion, complete ACK settlement, native
commands and chat/history authorization remain integration requirements.


### Experimental owned invite preparation

The serial account worker consumes Approver evidence internally, refreshes the
selected protected origin and retains one opaque preparation under the original
SDK deadline. Repeated preparation resolves that same attempt; another
reservation is refused while it is owned. Scoped cancellation validates identity
and generation first. Expiry and dropped RPC replies revoke the lease and retry
exact cleanup without reconstructing permission. Prepared cleanup retains the
opaque object when its durable rollback fails.

Private genesis creation supplies authenticated Nostr routing through the
existing App relay policy before birth capture. `ProbePeeler` forwards private
batch wrapping and authenticated single-chunk metadata to the actual injected
Nostr implementation; its observation layer does
not replace that implementation. The private batch remains in its dedicated
outgoing ledger. Preparation alone does not publish it, settle membership or
start history transfer. Native enrollment bindings remain absent.

The private recipient collector bounds authenticated NIP59 chunks and transport
hints, checks the actual live purpose/SAS context before retaining each chunk,
and preserves the original owner deadline across authentication. Exact duplicates
are harmless; conflicting artifacts, indices and mixed contexts are refused.
An unrelated rejected purpose does not erase the live collection. Complete
batches still require fresh Engine lease/full-tree validation and atomic SQL
admission. The module is not wired to the serial recipient coordinator yet;
collector tests and real MLS admission fixtures do not prove relay delivery,
settled device-roster authority, chat/history authorization or native adoption.

Experimental recipient bootstrap currently admits only a fresh epoch-zero singleton
predecessor after real two-sided SAS and exact owned purpose checks. Arming exposes
only the next transport/tree validation phase, never a chat/history grant. Later
multi-leaf enrollment, runtime collection/join and settlement remain separate.

### Experimental private commit publication

The internal account worker publishes one exact frozen private commit through
the actual relay adapter. The original owned consent lease remains live until
durable intent and the network boundary. Pre-intent SQL failure preserves exact
still-live retry; uncertain publication preserves the MLS pending commit and
never recreates consent. Cancellation, shutdown, lost replies and the original
deadline interrupt a stalled publisher independently of serial queue saturation.
Only eight ordinary commands may be deferred while publication waits.

The actor derives routes from authenticated private-group components without
creating a conversation projection. A relay acknowledgment leaves publication
Unknown, with no confirmed successor and no Welcome delivery. One hidden
subscription now derives from freshly checked protected lineage and actual MLS
state; exact authenticated echo intake may reconcile the staged Add without
creating a chat. Private publication withholds the ordinary local mirror, so an
acknowledgment cannot fabricate its own confirmation. Recipient delivery and
complete roster/history settlement remain separate integration work.

A permanent account/device/group negative privacy fence now survives marker
removal and selection replacement for actual private births and joins. Historical
relay retrieval still needs qualification before native integration; identifiers
already lost before the fence upgrade cannot be reconstructed.

### Experimental uncertain private-commit acquisition

`client/private_echo.rs` adds a bounded exact-ID fallback only for a protected
`PublicationUnknown` private commit whose actual selected MLS state and signed
routing component still authenticate. Normal recovery compares that same route
first; the fallback never races an account comparison job. It shares process
recovery credits and runs network acquisition off-worker, leaving cancellation,
shutdown, and ordinary actor commands responsive. One request has at most four
checked endpoints, one event ID, two received items / one MiB per endpoint, and a
two-second deadline. A single five-second retry slot bounds repeated attempts.

The actor rechecks full protected scope, binding, exact signed transport and
current crypto route after the await, then uses ordinary recovered-delivery
admission. Only actual Engine own-echo validation may confirm membership;
neither fetching bytes nor relay ACK restores SAS, delivery, roster or history
permission. Empty, unavailable, truncated or failed requests preserve Unknown.
Account shutdown aborts the task. The request deadline is not an aggregate
startup-latency bound: comparison route rotation and resource credits can delay
its start. Endpoint sets beyond the bounded first four and comparison overflow
are not proof of complete retrieval or history coverage. Native rollout remains
unqualified.

The bounded exact-ID reconciliation inlet accepts durable Dispatching as well as
Unknown after restart. This supplies no live publisher or SDK lease and cannot
redispatch. Genuine intent interruption, encrypted reopen, ordinary cursor
advancement and real unsupported-Negentropy relay acquisition are regression
controls; authenticated Engine own-echo processing alone confirms membership.

A fresh completed settled predecessor may start a new Approver SAS exchange only
after protected lineage, actual tree and every indexed confirmation revalidate.
Invite arming refreshes that opaque proof after SDK completion and binds its
protected accepted/confirmed origin to the original live Approver token. Engine
preparation independently checks the same origin, exact predecessor and one-recipient
Add under the original deadline. Public metadata or persisted completion alone
cannot arm consent. Recipient multi-leaf admission and existing-sibling protected
successor handoff remain unimplemented; three-device enrollment is not complete.

The internal artifact-backed pairing setup authenticates bounded public predecessor
metadata before beginning version-2 SDK verification. The Approver additionally
rechecks its complete protected local roster, full epoch-authenticator descriptor
and exact fresh own export. Session forwards metadata checks into scratch Core
storage. Rejected metadata does not bind the purpose or start the SDK; a dropped
successful setup reply cancels that exact reservation. This setup does not arm
multi-leaf Welcome admission, gather existing-member approval or grant history.


The default-off private enrollment proposal validator runs inside the serial
account worker. It authenticates the received v2 canonical context, actual package
and signed predecessor artifact against the crypto request and fresh local
protected tree, retaining the original bounded observation lifetime. V1 remains
metadata only. Successful validation supplies no SDK consent, endorsement, new
membership, native API or history grant. Account-owner approval and atomic sibling
transition remain separate work.

The internal scope-only enrollment proposal producer now uses the original
Approver SDK token after a fresh artifact-bound A/C verification over an actual
completed A/B predecessor. The account worker retains the opaque Core producer
and its original deadline; private control publication uses the existing bounded
cancellation/shutdown loop and suppresses local chat mirroring. B authenticates
the received proposal with the existing strict validator. Exact retry retains the
original owner, and a proposal continuation cannot become an Add continuation.
This creates metadata only: all-current-leaf endorsement, recipient admission and
atomic sibling transition remain separate requirements.

The serial account worker now supports an explicit B endorsement action selected by an actual retained request's binding hash. It authenticates only that selected request, so unrelated invalid proposals do not block a valid choice. The one account-owned continuation retains the original observation deadline and exact Core ownership/selection fences. Exact retries reuse it; wrong cancellation selectors cannot affect it. Cancellation and abandoned replies burn the original receipt's action, and encrypted reopen restores neither the observation nor the action. Cancelled receipt identities are bounded to 128 within their original lifetimes.

The internal worker also publishes B's owned endorsement through the private
route. A collects actual source-authenticated MLS receipts together with its
signature from the original local SDK lease. Complete collection reports
authentication progress; Add, recipient admission, atomic sibling transition,
ABC settlement and native integration remain separate work. The genuine worker
regression uses the stock SDK and a real relay; see
`docs/device-sync-b-publication-collection-verification.json` for its scope.

### Private device setup packets

The default-off account client creates bounded canonical setup packets from its
actual reserved purpose KeyPackage and live identity. The approver chooses a
protected singleton genesis or an actual completed predecessor; native callers
cannot supply a linking context, generation, verifier proof or protected origin.
The original recipient request binds the challenge and starts the stock SDK
NewDevice flow. Exact challenge retry observes that same live flow; cancellation
or encrypted reopen cannot recreate it from packet bytes.

These factories remain internal. They do not export a native session, authorize
Add, admit a multi-leaf Welcome or report chat/history synchronization. The scoped
qualification record is `docs/device-sync-native-setup-verification.json`.


The internal account-worker setup bridge retains the original recipient request
in the serial actor and returns packet metadata only. Bounded RPCs create the
request/challenge and accept a challenge under the original scope. Invalid input
preserves a valid retry; exact cancellation clears custody before durable cleanup.
A lost successful reply cancels its exact reservation. The worker regression
uses the original stock SDK through both confirmations and peer MACs. Public
native sessions and cancellation during stalled setup remain separate gates; see
`docs/device-sync-native-worker-setup-verification.json`.

### Opaque native verification sessions

`AccountManager::begin_device_linking_session` and
`approve_device_linking_session` return process-local session objects. Callers
exchange bounded setup/SDK packets, observe standard SAS decimals and confirm
the revision actually displayed. They cannot supply context, purpose generation,
protected predecessor or proof. The actor retains the original SDK/request;
packet acknowledgement is transport progress only.

Experimental native callers can use `DeviceLinkingSession::automatic_pairing_code`
on the joining device and import that one code with
`AccountManager::approve_automatic_device_linking_session`. The bootstrap binds a
fresh ephemeral transport key and the exact native request, without an account
private key. Setup and SAS packets travel through signed NIP-44 envelopes over
host-configured, safety-filtered relays. Fragments are bounded and ordered; native
packet acknowledgement follows authenticated processing receipts, not relay ACKs.
The relay can still deny service and observe transport metadata.

The scanner factory returns an original with its response transport paused.
After admitting that exact original into a still-live host account scope, call
`automatic_pairing_code` on it to activate the response transport; do not display
or scan the returned bootstrap again. Dropping or canceling an unadopted original
retires its pending transport. Each device must still confirm the displayed SAS
revision. Verification alone does not enroll a device or approve chat sharing.
`continue_automatic_linking(displayed_revision, share_chats)` captures a separate
explicit choice on that exact original. It waits for the stock SAS done packets
to drain, then continues the original SDK action. Singleton enrollment uses Core's
existing automatic Add/Welcome path. Existing-roster setup uses bounded encrypted
recipient artifacts and authenticated processing receipts; independent existing
device approvals remain required. An original automatic finalization choice never
replaces Core's fresh live-owner and protected-roster checks. Full third-device
automatic transport requires separate qualification from first-pair enrollment.

Subscriptions coalesce observations and `close()` wakes pending reads. Exact
session cancellation revokes native operations before waiting for actor cleanup;
drop schedules the same cleanup. A one-second probe observes the original SDK and bounded purpose checks for
expiry/shutdown; it does not rescan MLS or restore permission from SQL. The worker
address is the resolved account storage label, while the original private scope
checks actual account/device identity on every command.

Default builds expose the same shapes but return `Unsupported` before account
resolution or reservation. Experimental builds advertise enrollment support for
ready imported development accounts. This reports an available API; it grants no
membership or approval. Existing account readiness and original-owner checks
still govern every operation. Identity-only unfinished onboarding remains a
separate boundary.

Revision-bound public actions support singleton enrollment and explicit
existing-sibling approval for a third device. Singleton Add preparation refuses
a multi-device predecessor before consuming the original SDK result; the same
original action can use the all-leaf proposal path. `EnrollmentComplete` observes
actual protected settlement. Packet transfer and pending verification alone
prove neither membership nor synchronized chat/history. Selected ordinary-chat
copy consent and history transfer remain separate from this capability.
See `docs/device-sync-native-enrollment-capability-verification.json` and
`docs/device-sync-singleton-pre-take-refusal-verification.json` for focused
qualification. Full integrated regression and matched artifacts have separate
gates.

Original B enrollment actions can now arm an exact bounded all-leaf packet,
bridge the actual single C Add inside MLS/SQL, and select a new private settlement
round through that same live memory owner. Storage failure retains the owning
client and schedules its exact group retry; reopening cannot restore this action.
Actual worker coverage injects B transition and C join SQL faults, verifies atomic
rollback and autonomous same-owner retry, then verifies exact B cancellation.
The original-action three-device backend regression establishes actual ABC
settlement, including both SQL rollback retries. Public native singleton
continuation is separately qualified; public three-device enrollment and app
adoption remain separate gates.

### Native approval review

With `experimental-device-sync`, the original `DeviceLinkingApproval` exposes
`review_metadata(displayed_revision)` while awaiting explicit approval. The
record contains the exact revision, authenticated source and joining device
public keys (32 bytes each), and existing device count. These are device signing
keys, not account display names or account identity keys.

The serial account worker revalidates the original received proposal against
fresh protected predecessor and Current KeyPackage state. The native handle
checks its original owner, pending phase and displayed revision before and after
awaits. Reading this record leaves approval pending and creates no endorsement,
Add or permission. Stale revisions and cancelled/settled owners refuse; default
builds return `Unsupported` before account or worker effects.

The genuine public three-device regression compares identities to A's actual
MLS leaf and C's original setup, checks unchanged pending state, then completes
ABC. Native binding/artifact adoption, approval UI and installed application
delivery remain separate from this read-only App API checkpoint.

### Explicit pairing-wide chat sharing approval

`DeviceLinkingSession::continue_linking_and_share_chats(displayed_revision)` forwards the exact held verified pairing original. This action approves sharing existing and future chats, history and messaging with that paired device. Durable policy is recorded only after the same SDK-derived original and fresh all-leaf Completed settlement validate; the public EnrollmentComplete observation waits for that write. Ordinary `continue_linking` does not approve broad sharing, and the default build returns Unsupported before effects. Adding another device does not implicitly grant it an existing pair's policy.

This checkpoint qualifies original A/B approval and durable handoff, not automatic catalog exchange, mirrored conversation presentation or bridge sends. Existing pairs still need a fresh explicit pair-wide approval. See [qualification](../../docs/automatic-pairing-chat-sharing-verification.json).

### Existing paired-device broad approval

`AccountManager::begin_account_chat_sharing(account, recipient_device)` creates a fresh opaque review for an already paired device. Its `approve(displayed_revision)` publishes the genuine protected Request; `pending_account_chat_sharing(account)` exposes the addressed recipient's authenticated original for its own explicit approval. The read-only snapshot identifies both devices and the protected group/epoch. Neither a snapshot nor a device selector grants access. Signed Request/Consent and fresh Core context checks precede each peer's immutable durable policy write. Default builds return Unsupported before account effects.

This source checkpoint does not yet exchange automatic catalogs/messages or populate ordinary conversation views. No packets, channel keys or grant DTOs are exposed. See [acceptance and limits](../../docs/automatic-existing-pair-sharing-verification.json).

### Approved-policy catalog exchange (experimental checkpoint)

Account workers now negotiate fresh encrypted channels under the original pair-wide approval and import initial and later source catalogs into separate source-attested mirror storage. The independent-store relay regression preserves canonical chat IDs and a fragmented 4096-byte description; a protected member without the addressed pair policy remains excluded. Receiving metadata does not create ordinary MLS membership.

This checkpoint does not populate normal conversation views or forward messages. Catalog delivery receipts, loss/reordering, withdrawals, large-catalog renewal and retired-request replay controls remain pending. See [acceptance and limits](../../docs/automatic-approved-policy-catalog-actor-verification.json).

Catalog scheduling now reserves a whole entry before exhausting a channel and resumes the scan under a newly validated channel. The real 22-chat renewal regression and earlier policy SQL-race/default controls pass. Recipient committed catalog acknowledgements and loss/reorder recovery remain separate; see `docs/automatic-catalog-renewal-verification.json`.

### Automatic paired-source text sends

With `experimental-device-sync`, an approved mirrored-only chat can use the existing runtime `submit_text` client-token API. Admission verifies the fresh pair policy and active mirrored catalog inside the queue transaction. The queued intent retains its exact ordinary inner event; an actual member publishes it through the ordinary send pipeline. `local_send_status` stays `Queued` until an authenticated publication receipt confirms that canonical event ID. Mirror rows never become ordinary MLS membership, and ordinary member sends retain their existing path.

The scoped relay acceptance covers plain text, same-token retry, conflicting-body refusal, genuine publication receipts and automatic record import. Mirrored `submit_message_draft`, media and edits explicitly remain unavailable; reply, offline/restart recovery and blocked publication require their next controls. No installed automatic feature or SDK adoption is implied. See [checkpoint and limits](../../docs/automatic-account-chat-forwarding-verification.json).

### Source-qualified automatic chat observations

Experimental `paired_chat_list_page`, `paired_chat_message_page`, and
`account_conversation_page` read already-authenticated mirror storage through the
serial account worker. Current durable approvals and fresh protected roster state
are checked before and after each read. `LocalMls` and `PairedSource` remain
distinct; mirror rows create no MLS membership or media download permission.

`existing_account_direct_conversation` resolves a peer to a reusable local MLS
conversation or a current approved paired-source route, preserving that provenance
in its tagged result. Local membership uses the ordinary indexed reuse policy;
paired identity comes from the source's direct-chat classification and canonical
roster. Reads never create invitations or fabricate local membership. Transient
index, policy or runtime errors must not be treated as a missing conversation.

`open_account_chat_list_window` combines bounded ordinary and mirror lanes; its
ordinary metadata/anchors and separate mirror cursor do not imply global activity
ordering. `open_account_conversation_window` merges canonical event time/ID with
ordinary precedence and a total 128-row SQL bound. Captured sequence, cancellation,
account reset, runtime shutdown, committed catalog wakes and retention refresh
keep owners current. Unsupported logical kinds remain visible placeholders.
Local-to-paired membership changes require reopening the conversation window.

The focused proof in `docs/account-chat-presentation-app-windows-verification.json`
covers real original approval/catalog/window custody and separate storage privacy
controls. Records-actor message delivery, native bindings/views, normal forwarding
and full integration acceptance require their own qualification.

Merged ordinary rows do not carry the original conversation page
`authenticated_system_content` proof. Native conversion must keep their system
content untrusted; authenticated system/reference/action presentation still uses
the genuine ordinary conversation owner. Stored fields and tags are not proof.

### Ordinary-chat acceptance before automatic disclosure

Experimental automatic catalog, history and member-forwarding admission share a
fresh source-eligibility check. Actual public creation and explicit incoming
invitation acceptance persist their origin with the App checkpoint; an unaccepted
Welcome remains ineligible even when its MLS membership and message projection
are already present. Explicit decline retains a negative origin and withdraws that
source's advertised catalog. Local hide preserves accepted lineage without
authorizing pending invitations. Stored lineage still requires current Core
membership and the genuine approved sharing channel.

Existing incoming chats can bootstrap only from their retained nonpending Member
projection and actual Welcome identity. Existing created chats require the actual
local signer's retained epoch-zero founding leaf; the observational rewind restores
and checks live state before any positive checkpoint. Missing projections,
messages, administrator status and default installation epochs are not acceptance.
Pruned ambiguous legacy chats need a separate fresh original human approval path.
The current source-terminal mirror fence does not yet allow a fresh accepted
rejoin after decline; account-wide principal leave remains separate from device
SelfRemove. No new SDK or installed-app qualification follows from these APIs.
