# AGENTS.md - crates/marmot-app

Multi-account app runtime bridge (`MarmotApp`, `MarmotAppRuntime`) beneath `wn`, `marmot-uniffi`, and `marmot-c`. For
the human overview and host-facing API contracts (storage tiers, KeyPackage inventory, directory search, app-owned
components, full-history repair, notices, blocking, moderation) see [`README.md`](README.md); do not restate them here.

Implement shared behavior here, following [MDK's host boundary](../../docs/marmot-architecture/overview/app-core-boundary.md#host-app-boundary).

## Scope and module rules

- Own the app-facing runtime that ties `AccountHome`, SQLCipher session storage, Nostr peeling, and Nostr transport
  adapter support together.
- Keep runtime orchestration, managed account workers, subscriptions, and live agent stream watches in the `src/runtime/`
  module instead of regrowing `src/lib.rs`. The module splits along these seams: `mod.rs` (the `MarmotAppRuntime`
  orchestration core — construction/start/shutdown, shared services, lifecycle, module wiring and re-exports),
  `account_worker.rs` (the per-account worker: command enum, worker loop, reconnect backoff, runtime-event publishers),
  `subscriptions.rs` (the `Runtime*Subscription` handles and the materialized-timeline window), `commands.rs` (the
  `AccountManager` command-RPC wrappers that send a worker command and await its oneshot reply), `agent_stream_watch.rs`
  (agent-text-stream discovery and the brokered-QUIC watch machinery), `onboarding.rs` and `onboarding/` (durable
  preflight, cancellation, and advisory installation detection), `audit_tracker.rs` (the forensic audit-log tracker
  upload worker), `audit_otlp_delivery.rs` (the explicit one-account v5 OTLP attempt), `event_routing.rs` (pure
  `MarmotAppEvent` classification/routing helpers), `avatar.rs` (local identity-avatar demand and bounded maintenance),
  `avatar_access.rs` (bounded local native batches), `attachment_history.rs` (bounded local attachment discovery and
  shared-parser presentation), `attachment_access.rs` (read-only source-slot availability and verified local byte
  ranges), and `account_worker/attachments.rs` (durable attachment demand admission, fair background transfer capacity
  and retained-byte publication). Other runtime modules are listed in the Code map below. Keep `mod.rs` re-exporting the
  moved public types so `crate::runtime::Item` and the `marmot_app::...` paths stay stable.
- Keep app-client commands and query methods in the `src/client/` module; the crate root should construct clients but
  not absorb their behavior again. The `AppClient` inherent impl is split across the module along these seams: `mod.rs`
  (the `AppClient` struct plus the broadly-shared command/query API — key-package, group lifecycle, message/media/agent
  send commands, and the lifecycle helpers and encrypted-media helpers they share), `sync.rs` (transport sync: `sync`,
  `next_event`, `sync_sdk_relay`, `ingest_delivery`, `sync_runtime_groups`, the relay-echo/transport-cursor helpers, and
  the cursor unit tests; `sync/full_history_tests.rs` covers explicit repair), `projection.rs`
  (timeline/group projection accessors, the `*_for_group` component reads, the
  kind-1210 group-system row synthesis, and the local-send projection helpers), `receipts.rs` (the synchronized
  transport receipt view, release-journal consumption, and seen-index maintenance), `push.rs` (push-token registration
  and notification-trigger publishing), `retention.rs` (the engine-owned retention sweep policy, bounded timeline scan,
  per-group outcome orchestration, and classifier tests), `history_notices.rs` ("history may be incomplete"
  notices, their worker-owned dismissal and the notice-change baseline; the public DTOs and opaque id codec live
  in the crate-root `src/history_notices.rs`), and `audit.rs` (audit-context construction, the local/observed
  `human_action` recorders, and the `ObservedHumanActionAudit` descriptor). Private items referenced across these files
  are widened to `pub(crate)`; `pub` items keep stable `marmot_app::...` paths via the crate-root re-export.
  Steady-state sync passes must not rescan full retained state (no full `MlsGroup::load` sweeps, no full
  account-projection loads; cheap per-group probes are acceptable): the encrypted-media epoch-secret warm pass
  skips authoritative (`MlsGroup::load`) component re-checks at an unchanged group epoch
  (`encrypted_media_not_required_epochs`, mdk#1380), and the sync checkpoint skips its second
  `refresh_group_routes` when the drained prefix carried zero deliveries and clean routes.
- Keep app-defined custom events on the `AppMessageIntent::Custom` path in `src/messages/intents.rs`: kind, tags, and
  content pass through verbatim, and kinds MDK owns (`is_reserved_app_event_kind`: chat, reaction, edit, delete,
  agent, group system, push token) are rejected with `AppError::InvalidAppMessagePayload` so apps cannot forge
  protocol-owned events. Custom kinds project as standalone timeline rows under
  `TimelineUpdateTrigger::CustomEvent` (never folding onto a target message like reactions/deletes) and are queryable
  by kind through `AppMessageQuery::kinds`.
- Keep group DTOs, component projections, and group event projection helpers in `src/groups.rs`.
  `AppCreateGroupOptions::relays` overrides founding group routing only; validate through `RelaySafetyPolicy`
  before member resolution or group mutation, and preserve app-configured relays when omitted.
- Keep encrypted-media DTOs, exporter labels, and Blossom upload/download helpers in the `src/media/` module
  (`blossom.rs`, `crypto.rs`, `group_image.rs`, `host_safety.rs`, `avatar.rs` for downloaded avatar admission).
  `media/attachment_resume.rs` adapts attempt-fenced storage checkpoints to the shared safe HTTP path;
  keep Range validation, protected partials and complete-body authentication separate from native progress/access.
- Never discard the shared `imeta` parser's verdict in a projection (mdk#1787). `parse_media_attachment` returns a
  typed `MediaAttachmentRejection` whose `kind` is judged version-first so it does not depend on field order, and
  `media_attachment_outcomes_from_tags` / `media_attachment_outcomes_from_media_json` yield ordered per-attachment
  outcomes indexed by position among the message's `imeta` tags. Bindings surface `Rejected` entries in place; tracing
  logs only aggregate counts and kinds. Keep the three download error classes distinct: `MediaAttachmentRejected`
  (structural), `MediaUnfetchable` (valid reference, no locator fetchable under group/client policy, nothing dialed),
  and `MediaDownloadFailed` (transport, integrity, or decryption after a locator was selected).
- Keep the mechanical `storage_sqlite` `Stored*` <-> app-DTO mapper free functions (account state, groups, components,
  messages, app events, push registrations, telemetry/audit settings) in `src/conversions.rs`. They hold no `MarmotApp`
  state.
- Keep the forensic audit-log feature in `src/audit_log.rs`: the `AuditLog*` DTOs, salted-hash identity derivation,
  the per-attempt pinned upload path, the per-account upload checkpoint (`audit-upload-checkpoint.json`), and the
  `MarmotApp` methods for audit settings, recorder open/build, file enumeration, path validation/resolution/removal, and
  HTTP upload. Audit-log unit tests live in its own `#[cfg(test)] mod tests`.
- Keep the bounded live v5 Welcome capture in `src/client/audit_v5_probe.rs`. It records actual retained founding
  preparation, receipt/peel, app join/checkpoint, and bounded stored-group snapshots through the installed recorder;
  tests retain an in-memory probe for focused product-boundary assertions. Do not infer ACKs, recipient joins, or
  durable writes from another boundary. See `tests/audit-v5-welcome-probe.md` for historical subset measurements.
- Keep the v5-only recovery-owner and transport-cursor audit rows in `src/client/audit_recovery.rs`
  (`recovery_need_changed`, `recovery_attempt_started`, `recovery_attempt_finished`,
  `recovery_obligation_reassessed`, `transport_cursor_advanced`). Record at owner seams only: loss import through
  `synchronize_recovery_loss` (never call the storage import directly from client code), the shared execution
  bracket (`begin_recovery_execution` / `finish_recovery_execution`, which the comparison job uses), settlement after
  the checkpoint commits, the notice publication seam and dismissal, and cursor commits after their save succeeds.
  Never add a row per scheduler evaluation, per live ingest, or on the router path; the router only counts
  placements. Rows are best effort: an audit-only read that fails skips the row, never the recovery step. The
  relay plane's lag-lost EOSE repair only queues a bounded `EoseRepairReport`; the worker's
  `publish_history_notice_changes` seam records it as `subscription_eose_repaired`. Scenario tests live in
  `src/client/audit_recovery/scenario_tests.rs` and `sync/comparison_job.rs`.
- Keep the configured audit OTLP/HTTP sender in `src/audit_otlp_sender.rs`. It accepts an owned local-delivery batch,
  checks the prepared destination, preserves each original v5 JSON body inside the restricted OTLP JSON envelope,
  and maps only complete, partial, and retryable receiver outcomes to local finish actions. Blocked and unknown
  outcomes retain the prepared range. Runtime tracker/manual triggers and additive native bindings configure it;
  there is no default v5 destination.
- Keep process-local audit export admission in `src/audit_export_lifecycle.rs`: one active attempt per account, short
  local admission under `storage_lifecycle`, and cancellation on consent, deletion, account removal, destination change,
  or close. Never hold local guards across HTTP or wait for HTTP before releasing the root lease on terminal close.
- Record new opt-in sessions into distinct v5 files and deliver strictly validated v5 JSONL through OTLP. Historical
  v4 files retain their separate v4-only Goggles whole-file path. Never migrate or send v1-v3
  or key-reveal files. Reject removed/unknown fields and duplicate keys before HTTP; cache ineligible file verdicts
  by size and mtime without retry cooldowns. On exclusive-root startup, `audit_log/legacy_cleanup.rs` deletes
  reserved v1-v3 filenames and their segments from `accounts/` and failed-wipe `.wipe-tombstones/` remnants
  without reading payloads, even when recording is disabled. Match the frozen 32-lowercase-hex legacy engine ID,
  not the current audit ID width; pin the live layout through AccountHome-backed tests.
  Keep this after lease acquisition and before exposing the app; never traverse symlinks or delete v4/future
  filenames, names outside the reserved legacy forms, or the separate key-reveal log. Unexpected containers
  and other cleanup errors are reported with aggregate counts, are nonfatal, and retry on next open.
  Account/device names are forbidden in rows and headers; hardware model is system-sourced, never a label.
- Keep audit uploads incremental (mdk#1181). An audit file whose size and mtime still match its checkpoint entry is
  never re-read or re-posted; only the growing active file re-transfers, bounded by the recorder's segment threshold.
  Checkpoint only complete immutable upload snapshots after successful upload.
  Defer an unfinished trailing JSONL row and preserve it for a later upload; an HTTP length limit alone is insufficient.
  Automatic triggers use a fixed 30-second window and the size-1 coalescing queue in `runtime/audit_tracker.rs`.
  Later triggers cannot postpone that window or shorten a failure cooldown. Manual upload APIs remain immediate.
  Incomplete snapshots wait for the next trigger. Automatic failures retry after 60 seconds, doubling up to five
  minutes; authentication failures wait at least five minutes, and Retry-After can extend the delay up to five minutes.
  Stop automatic passes on endpoint-wide failures
  (authentication, rate limits, server/transport failures); file-specific failures and oversized files must not block
  the files behind them.
  Treat a `413` with no `Retry-After` as the endpoint's verdict on that file (RFC 9110 15.5.14 has a server send the
  header when the refusal is temporary): acknowledge it as too-large so it is reported once and never re-posted. Unlike
  the local ceiling this verdict is escapable: it is keyed on the file's size and mtime, deleting the sidecar clears it,
  and a manual per-file upload never consults it. A `413` carrying any `Retry-After`, parseable or not, is a cooldown
  and retries like any other rejection.
  Shutdown cancels pending or in-flight automatic work; unacknowledged files remain on disk.
  Tests may shorten the window per runtime via `test-policy-overrides`; paused-clock tests pin the production default.
  Retention/deletion of v4 sealed segments is mdk#1014, not this contract.
- Keep the upload checkpoint's cost proportional to the account's *live* audit files, not to its history. `retain_present`
  prunes entries for files that are gone, so the sidecar is O(live `audit-*.jsonl` files) — but nothing deletes sealed
  segments (mdk#1014), so that bound grows with cumulative audit volume, and each tracker run stats every file and
  rewrites the whole sidecar. Do not add a per-upload or per-line entry, and do not treat the sidecar as durable state:
  losing it costs one repeat transfer per file and nothing else.
- A file above `AUDIT_LOG_UPLOAD_MAX_BYTES` has no app-level transfer path. `post_audit_log_file` enforces the same
  ceiling, so the tracker's skip is the whole story: the file stays on disk for manual handling. Do not document an
  escape hatch that does not exist, and do not widen the ceiling to invent one.
- Keep SQLCipher key derivation, per-database salt persistence, legacy-key migration/recovery, and the in-process
  v2-open probe-verdict cache (mdk#1439) in `src/sqlcipher.rs`. The verdict cache is advisory only: a durable
  migration marker or a missing verdict always re-runs the recovery probe, so the mdk#568 crash windows keep their
  self-heal. Key presentation and the passphrase KDF work factor follow the decision record in
  `docs/marmot-architecture/storage-format-v2.md`.
- Keep the user-directory domain in the `src/directory/` module instead of regrowing `src/lib.rs`. It splits along these
  seams: `records.rs` (the public `UserDirectory*`/`UserProfileMetadata`/`DirectoryKeyPackage` DTOs surfaced to
  `marmot-uniffi`/`cli`, plus the stateless record helpers — cached <-> shared record conversion, recency selection,
  Nostr profile/follow-list parsing, search-match ranking, and `profile_content_json` — which hold no `MarmotApp`
  state), `methods.rs` (the split `impl MarmotApp` block: relay-list/profile/key-package/follow-list fetches, the
  public `directory_*`/`*_user_directory` API, directory-cache lifecycle, and in-memory directory-record hydration),
  `cache.rs` (the per-account SQLCipher directory cache, with its independent numbered migration runner in
  `cache/migrations.rs`, frozen initial schema in `cache/v1.sql`, and populated/interrupted-upgrade
  tests in `cache/assurance_tests.rs` using the historical `cache/fixtures/pre_ledger.sql` fixture), and `sync.rs` (the directory-subscription sync worker and
  plan). `mod.rs` re-exports the DTOs so the `marmot_app::...` paths stay stable; private items referenced across these
  files (and from `tests.rs`/sibling test modules) are widened to `pub(crate)`, never narrowed.
- Keep stateless account relay-list and KeyPackage parsing/validation (relay-list status, KeyPackage tag/metadata
  validation, fresh-vs-cached reconciliation, record merge, publish-endpoint selection) in
  `src/key_package_records.rs`. They hold no `MarmotApp` state.
- Keep the crate root focused on app construction, shared state, storage/projector wiring, account relay-list helpers,
  the shared directory-record selection primitives (`DirectoryFreshness`, `DirectorySelection`, `sort_directory_records`)
  reused by `key_package_records.rs`, and public re-exports.
- Keep CLI/TUI presentation out of this crate.
- Keep the Nostr user directory app-facing and pubkey-keyed. It may cache local-account links, profile metadata, follow
  lists, relay lists, and KeyPackages. Web-of-trust search may traverse the live follow graph, but traversal is bounded
  by construction: a capped search radius, a per-radius candidate cap, a per-radius fetch timeout, batched
  author-scoped fetches, and a per-search lifecycle — traversal runs only while a search
  subscription is live and stops as soon as its consumer drops. There is no background or open-ended crawl.
- Keep web-of-trust search results un-promoted. Strangers discovered by search are never written to `directory_users`
  and must never reach `directory_sync_plan` or live per-author subscriptions (mdk#418); cache them only in the
  un-promoted `directory_search_graph_users` tier, which directory sync never reads.
- Keep runtime directory subscriptions chunked and privacy-safe. Subscription identifiers must not embed raw pubkeys.
- Treat Marmot kind `30443` KeyPackages as cached last-resort packages. Normal publish should reuse the cached valid
  package and stable replaceable d-tag; expired or policy-invalid packages rotate to a fresh package ref.
- Incoming welcomes may auto-join MLS state, but app projections must preserve local confirmation state. Pending invites
  should stay visible until accepted, and decline should leave the group before archiving the local projection.
- Keep protocol engine behavior in `cgka-engine` and session ownership in `cgka-session`.
- Every recovery cause and caller runs the one comparison job in `src/client/sync/comparison_job.rs`; there is
  no inline executor. Runtime catch-ups (`SyncMode::Drain`) only drain the live queue and never run a job, so
  they cross a worker-owned job (mdk#2110); `sync()` drains, then runs one job in place; nothing
  re-subscribes to recover history, and only startup, a frozen wake or an unactivated client installs live
  subscriptions. Explicit full-history repair runs the job in place: one comparison pass over every route of its
  grant inside the repair budget. It never reports complete: history below the retained window is unsearched
  (`BelowRetentionWindow` when the window certified), so never certify explicit history from a window; that
  result closes the request (`close_explicit_history_request`, revision-checked) instead of leaving debt that parks
  into a notice; an explicit scope whose window certified reports `RecoveryPassProgress::WindowCertified`, never
  `Quiet`, and the checkpoint that finds every scope certified closes the request from any pass,
  while `CoverageUnproven`, `Cancelled` and `Deadline` keep it open. Keep
  the budget split: the network pass ends at `FullHistoryRepairControl::network_deadline` and returns its finished
  routes for admission; only cancellation aborts the request at the poll; `stopped` ends admission at a turn
  boundary, keeping the admitted prefix; and
  preserve generation-checked overflow marker clearing. The account worker can serve committed snapshot reads
  while repair waits; mutations retain FIFO order, and repair waits while a worker-owned job
  is in flight. Client continuation tests live in `src/client/sync/full_history_tests.rs`; worker
  cancellation/read-order tests stay in `src/runtime/account_worker.rs`. See the README for the
  automatic-recovery and send-fairness limits.
- A dismissed "history may be incomplete" notice is the one user-authorized ending for parked recovery debt
  besides qualified completion. Record it only through `retire_parked_recovery_obligation` (its own outcome,
  never coverage) and release the delivery-loss fence through `release_retired_delivery_loss`, which keeps the
  fence while any loss obligation is pending, clears the plane only against the exact observed generation, and
  never counts a recovery success. Notice ids are opaque and must not be logged.
- Keep an account's delivery route open when its relay notification consumer lags: charge the lag as notification
  loss with the REQ floor its SDK context reported at the lag, and enqueue the generation's control record. Only an
  unexpected consumer exit closes the route and sends the worker through reconnect (mdk#2070). The worker persists
  notification loss before waiting for its control record.
- A lag may also lose end-of-stored-events. Never mark EOSE complete at a lag: live cursor promotion
  would advance the cursor while a relay was still sending history. The lag schedules the adapter's `reissue_subscriptions_awaiting_eose` for its
  receiver's scope, marked at the lag, to run once the receiver has gone `NOTIFICATION_LAG_EOSE_REPAIR_SETTLE`
  without another lag. A later lag postpones it. Re-issuing earlier restarts replays still arriving. A repair that
  leaves relays unrepaired (`EoseReissueSummary::failed_relays`) schedules itself again the same way, for the same lag
  mark.
- Move `checkpointed_transport_timestamp` only through `AppClient::seal_transport_cursor`, never straight to
  `state.last_transport_timestamp`. The seal runs under the lock the router places each delivery under, so it is the
  commit's one decision point: it returns nothing while loss or a spill hand-off is pending, caps the commit at the
  lowest delivery a restart still fetches that is queued or taken and not yet released, and raises the restart floor
  before the save, so the router spills a delivery that arrives during the save and falls below it; before the
  account's first settled floor that is every older delivery. A live ingest promotes with its own save only after every
  account subscription reported EOSE and once the account has a settled floor, and leaves the floor raised. A drain
  checkpoint, settled loss or retired notice confirms what its seal reached with `settle_transport_cursor` once its save
  succeeds, which ends the spilling. Every failed save undoes its seal with `abandon_transport_cursor`. Keep every
  condition cursor safety relies on inside the seal: anything read before an `.await` or a save is stale by the time
  that save commits. See `docs/marmot-architecture/further-context/account-recovery.md` section 6.
- Every path that takes a delivery from the account queue calls `release_account_delivery` once its ingest returns
  `Ok`, or when it skips the delivery as already held, and before the save that follows. Never release on an ingest
  error: the key must keep capping the checkpoint that failure runs, because newest-first replay has usually remembered
  a newer cursor. A new consumer of the queue that forgets to release holds the cursor back until the queue generation
  ends; one that releases early lets a failed ingest's checkpoint pass the delivery.
- Keep Nostr group routing sourced from `marmot.transport.nostr.routing.v1` component bytes; relay filtering may affect
  connections, but must not rewrite signed routing state. Relay endpoints pass through the `RelaySafetyPolicy`
  host-safety chokepoint (`src/relay_plane/safety.rs`), and agent-stream broker candidates through
  `src/runtime/agent_stream_watch.rs`, before any connect; both follow the one dial discipline in
  `docs/marmot-architecture/overview/dial-safety.md` (validate + pin, trust from config, loopback only under an explicit
  dev flag). Do not add an outbound relay/broker path that bypasses them.
- Floor every history REQ at an anchor, less `HISTORY_FLOOR_CLOCK_SKEW_ALLOWANCE` (`history_floor`, ledger A14): the
  post-join maintenance REQ at the Welcome that installed the copy (`Group::local_copy_welcome_created_at`, never the
  local join time, which an offline member reaches long after the Welcome), and a retained route at the moment
  `refresh_from_group` saw it replaced (`AppPriorNostrRoute::replaced_at`). A retained route stored before switch times
  were kept is stamped by the first `load_state` that finds it, and the stamp is persisted at once
  (`stamp_unrecorded_prior_route_switches`) so later launches never move its floor forward. Keep each group's current
  route first in the routing table (`replace_group_routes` preserves the caller's order; a new lead is a change): the
  adapter reads the lead as the route that resumes from the cursor. A locally deleted group lists its current route
  first too, never its frontier copy. See `docs/marmot-architecture/further-context/account-recovery.md` section 5.
- Keep `MarmotAppRuntime::shutdown_and_close` the one terminal teardown for hosts whose process can be suspended: it
  closes admission, closes every SQLite database and releases the root runtime lease first, then gives graceful worker
  cleanup a bounded budget. The terminal operation must outlive cancellation of its caller. `shutdown` alone does not
  release file locks. Closing is terminal — do not add a path that transparently reopens a database afterwards, and
  put shutdown checks at engine-step boundaries (never inside a step, where a snapshot guard may be live). See
  `docs/marmot-architecture/overview/local-artifact-safety.md`.
- Keep legacy message-format promotion after account readiness and bounded to
  one small transaction per steady-state maintenance tick. Log aggregate
  progress only, retry transient contention, and halt durable decode failures
  without disabling legacy reads.
- Keep local test relay code in tests; production app runtime should talk to Nostr relay URLs through the adapter.
- Do not print or log account ids, group ids, relay URLs, message ids, pubkeys, payloads, ciphertext, plaintext, or key
  material.
- Keep the relay-telemetry export path in the `src/relay_plane/` module (rollup in `relay_plane/telemetry.rs`) and
  `relay_telemetry_export.rs` (exporter, including the `MarmotRelayPlane::telemetry_exporter` constructor). It is
  opt-in and off by default: `MarmotRelayPlane::telemetry_exporter` is the single construction gate, relay-identity
  resolution requires it, and export points carry only a `relay` label. Keep the OTLP wire encoding and HTTP push behind
  the `otlp-export` feature; keep the privacy-critical mapping (`build_export_batch`) and the opt-in gate in the default
  build. Keep per-attempt collector DNS validation and pinning in `collector_host_safety.rs`: validate
  every address, pin reqwest, disable redirects/proxies, and retain TLS verification. Only exact `localhost` or a
  loopback IP literal is a local-test endpoint, and all its addresses must be loopback. The default build includes this
  helper so forensic audit uploads share it; do not feature-gate the module or introduce a second uploader. See
  `docs/marmot-architecture/relay-observability.md`, `audit-logging.md`, and `overview/dial-safety.md`.

## Code map (modules not covered above)

- Crate root `src/`: `config.rs` (`MarmotAppConfig`, service endpoints, attachment acquisition policy), `error.rs`,
  `ids.rs` (npub/nprofile/account-ref helpers), `drafts.rs` (encrypted per-account composer drafts),
  `chat_presentation.rs` + `chat_presentation/` (shared selected-chat presentation policy and maintenance),
  `conversation_presentation/` (C5 header, capability, and window selectors; they never subscribe, acknowledge
  reads, or fetch media), `local_submissions.rs` + `local_submissions/` (durable device-local send admission and host
  correlation; no relay I/O),
  `user_blocks.rs` (block policy and NIP-51 sync), `history_notices.rs` (public notice DTOs and opaque id codec),
  `notifications.rs` (push platform, triggers, settings), `external_signer.rs` (`ExternalAccountSigner` and the
  internal `AccountSigner`), `nostr_secret.rs` (secret-key shape classification shared with CLI/UniFFI),
  `nostr_verification.rs` (stateless public-event verification), `profile_pseudonyms.rs` (cosmetic display names; not a
  security primitive), `publisher_sequences.rs` (QUIC preview publisher lifecycle state), `agent_streams.rs` (agent
  stream watch DTOs and manager), `root_runtime_lease.rs` (cross-process exclusive root lease), `app_telemetry.rs` +
  `app_telemetry/` (aggregate app-performance telemetry; same privacy model as relay telemetry), `product_analytics/`
  (opt-in bounded product observations; export behind `product-analytics-export`), `projection.rs` (legacy account
  projection import), `messages/` (`AppMessageIntent` and custom-event intents), `local_open_test_gate.rs` and
  `test_support.rs` (test-only gates/helpers).
- `src/runtime/`: `worker_startup.rs` (per-account startup admission and retry backoff),
  `account_worker/recovery_credits.rs` (process-wide recovery credit pool), `conversation_window.rs`, `chat_list_window.rs`,
  `presentation.rs`, `presented_chat_list.rs`, `account_attention.rs` (presentation windows and account-switcher
  attention), `user_blocks.rs`, `moderation.rs` (reports and admin labels), `local_submissions.rs`,
  `agent_publisher.rs` (host-driven agent publishing), `attachment_controls.rs`, `attachment_permission.rs`
  (runtime-only network approval; never restore it from disk).
- `src/client/`: `recovery.rs` (recovery grant authorization), `invite_recovery.rs` (durable invitation recovery),
  `epoch_stall.rs` (epoch-gap backfill detection), `delivery_spill.rs` (worker side of the durable delivery spill),
  `audit_v5_app_update.rs` (bounded app-boundary audit rows), `sync/comparison_job.rs` (the one recovery comparison
  job).
- `src/relay_plane/`: `mod.rs` (shared relay plane), `safety.rs` (relay dial chokepoint), `directory.rs` (directory
  fetches/subscriptions), `delivery_spill.rs` (durable overflow tail for a full account queue), `telemetry.rs`.
- `src/directory/`: also `cached_search.rs` (network-free cross-account search), `search.rs` (streaming web-of-trust
  search), `open_ranking.rs` (bounded Vertex Open Ranking discovery), `member_key_packages.rs` (set-oriented roster
  KeyPackage resolution for create/invite).
- `src/sqlcipher/open_lock.rs`: in-process same-file open exclusion (the root lease covers cross-process).
- Integration tests in `tests/` (with `tests/support/` and `tests/fixtures/`); media benchmarks in `benches/` (require
  `media-benchmarks`); `examples/usage_diagnostics_staging/`.

## Features

- `experimental-device-sync`: private stock Matrix SAS adapter in `src/device_linking.rs`
  and synthetic tests in `src/device_linking/tests.rs`. Default off; no enrollment,
  history authorization, native enrollment, or adopted Marmot framing. Verified results
  remain internal and one-shot. `device_linking/owner.rs` couples real SAS with
  storage 104 restart/terminal fences. Private verifier commands run through the
  serial account worker; native verification bindings forward opaque App sessions,
  while native roster enrollment remains gated.
  Its fixed monotonic deadline starts before reservation storage/setup and bounds
  every SDK operation; a delayed setup or request/response must never extend it.
  `lib.rs` successful exclusive local-client open abandons pending durable attempts
  on startup/reconnect and synchronously retires any exact unjoined purpose bundle.
  `client/device_linking.rs` attaches its account-owned verifier from actual session
  identity and stored MLS signer after that cleanup. Both open-account and client
  fields drop the verifier before the runtime and exclusive session guard.
  Private client preparation reserves and resolves exact purpose-owned material.
  Client verifier operations validate actual account/device/generation on every
  call. New-device setup matches the exact owned package, reference and signer
  before SDK setup, then durably freezes its context before exposing an offer.
  Failed context freezing terminally fences and discards the verifier. Taking
  private one-shot evidence must not arm Welcome admission before approved-roster
  validation; no native proof/approval flag is exported.
  `device_linking/wire.rs` bounds versioned offer/frame packets and canonical JSON
  before allocation or SDK input. Preserve kind separation, exact lengths and
  acknowledgement-token limits; decoded objects still require live context and
  SDK validation, and cannot carry permission or reconstruct verifier evidence.
  `device_linking/predecessor.rs` binds canonical indexed predecessor contents,
  epoch and authenticator digest into the context. A descriptor copied from a
  candidate is not an approved anchor. Version 2 binds a nonzero artifact digest only
  for a nonzero-epoch multi-leaf descriptor in a distinct hash domain. Version 1
  must omit it and preserve its existing domain. Raw SDK binding is not artifact
  authentication, protected settlement or all-leaf approval; runtime setup and
  strict singleton recipient admission remain independent. Reject noncanonical/duplicate indices,
  duplicate signers, absent approvers, already-present recipients and exhausted
  leaf/epoch bounds before SDK setup. Welcome validation checks the actual full
  authenticated tree against exactly predecessor plus recipient at the next epoch;
  preserve tentative crypto/package/receipt rollback on any mismatch.
  Cancellation revokes Welcome admission before terminal fencing and exact unjoined
  package retirement; consumed/joined purpose state is preserved. Failed preparation
  must clean up before another attempt; cleanup failures take precedence.
  Scoped cancellation validates actual identity and generation before gate mutation.
  `runtime/device_linking.rs` routes private prepare/cancel and scoped SDK verifier RPCs
  through the serial worker. Keep their internal one-shot proof out of native APIs;
  a successful SDK exchange must not itself arm Welcome admission. Read-only
  candidate queries remain observations, never approved-roster authority. Original-deadline maintenance prunes only live internal
  verifier/token state and retries exact unjoined cleanup after transient failure.
  The feature-only worker tick is independent of optional network recovery; never
  export its test-only clock helper or enable test-policy-overrides in app artifacts.
  Failed prepared-result delivery cancels its exact scope in the serial turn.
  Preserve the first pending terminal-write intent across storage failures;
  maintenance retries it before expiry, without recreating verifier secrets.
  The failed-open path must never abandon an active flow.
  Raw SDK verified evidence has no owner stamp; only the durable owner carries
  its original reservation deadline through successful verification. Welcome
  admission must reject unstamped, expired or Approver-role evidence.
  `device_linking/runtime_gate.rs` holds a per-join phase under the original
  owned lease: exact SDK-known transport binding precedes actual private-profile
  and full indexed-tree validation. Only then may it expose the SDK predecessor
  to Engine or pass the final pre-commit check. Failed revalidation revokes that
  phase; dropping a failed join preserves only the same still-live token.
  Artifact hashes are independently authenticated/checked by peeler and Engine;
  they are not SDK consent or native approval data.
  `src/tests/device_linking_startup.rs` covers the real deferred-hydration open,
  session contention, monotonic generation, and per-account isolation.
  Startup is an authoritative account-runtime action, never another handle open.
  SDK tracing is suppressed to protect contextual IDs.
  Private genesis creation runs through the serial worker and delegates atomic
  creation to Session. Approver pairing setup freshly authenticates either that
  selected genesis or a sealed completed settled predecessor, actual account/device
  and exact predecessor before beginning the SDK flow. Settled invite arming must
  refresh that opaque proof after SDK completion and retain its actual protected
  origin with the original token. Recipient/sibling handoff remains absent.
  Generic solo groups cannot substitute for a genesis. This bootstrap check does
  not establish a settled successor; accepted/confirmed lineage and final consent
  consumption still require their coordinator. Do not restore verifier approval
  when a genesis RPC reply is dropped or after account reopen.
  `device_linking/invite_gate.rs` owns the Approver policy for dedicated Engine
  preparation. Arm only with non-clone owner-stamped SDK evidence and fresh typed
  genesis or completed settled-origin evidence; actual storage CAS remains independent. Hold the owned lease
  across wrapping, use its original deadline, and consume rollback permission
  after final preparation commit. Cancellation generations are captured before
  arming and rechecked under the lock. Cancellation/account teardown must revoke
  even held leases without waiting for their mutex. Account attachment installs
  the policy; it does not restore consent. The internal client inlet refreshes
  genuine origin evidence; no native flag/proof or serialized token is exported.
  `device_linking/invite_gate/tests.rs` combines stock SDK verification with real
  private MLS input/preparation and isolated 104/108/110 storage. Synthetic wrappers
  do not prove real relay acceptance, successor settlement or history permission.

- `test-policy-overrides`: test-only convergence timing/rewind overrides. Never enable in app artifacts.
- `otlp-export`: OTLP protobuf encoding and HTTP push for relay telemetry (the privacy mapping stays in the default
  build).
- `product-analytics-export`: product analytics export path.
- `media-benchmarks`: internal surface for the media transport benchmarks.

## Verification

```sh
cargo test -p marmot-app
# Accelerated recovery/retry scenarios (also enabled by workspace CI):
cargo test -p marmot-app --features test-policy-overrides
# Opt-in OTLP exporter wire encoding and push (heavy deps behind a feature):
cargo test -p marmot-app --features otlp-export
```

Tests that require shortened production policy intervals must use
`#[cfg(feature = "test-policy-overrides")]`; normal test builds deliberately
ignore those configuration overrides.


### Private invite coordinator map

`client/device_linking.rs` owns the exact Approver attempt and its opaque
preparation. Retained invite operations match the actual SDK-owned attempt scope
before owner checks. Historical consumed purpose rows cannot veto that original
continuation after verifier consumption; unconsumed conflicts and storage errors
still deny. No caller scope or durable row can construct or restore the token. `runtime/device_linking.rs` exposes only internal scoped preparation
metadata through serial commands. Copy the original owner-stamped deadline;
maintenance may revoke early but never extend or restore consent. Preserve the
attempt on cleanup failure. Lost result delivery cancels the exact attempt even
when preparation returned an error. The abandoned-response regression must prove
successful frozen private transport before retirement, not just a failed wrap.

`client/audit_v5_probe.rs::ProbePeeler` decorates the actual product peeler. Forward
new supported transport operations to its concrete inner implementation; do not
silently inherit a default-deny method. The complete linking test selection needs
`experimental-device-sync,test-policy-overrides`; omit test-policy-overrides from
native artifacts.


`device_linking/welcome_collection.rs` is a bounded transient collection helper,
not a consent issuer. Reopening starts empty. Wire it to exactly one live account
attempt only after approved-predecessor checks; serial owner cancellation,
expiry and teardown must clear it. Validate known SDK bindings before buffering,
use the original deadline for async observation, and revalidate after the await.
Never derive permission from authenticated metadata, durable facts or complete
batch shape. Engine must independently authenticate full MLS/tree/receipt state.

Initial recipient arming must validate the live owned singleton context and actual
purpose before consuming SDK evidence. Reject nonzero-epoch/multi-leaf bootstrap
without consuming the continuation. Never infer the remote protected genesis from
a context DTO. Engine/Session chunk observation is authentication metadata only;
collection and actual join still require the original live gate and full tree.

### Private commit publication map

`runtime/private_commit.rs` owns the bounded publication wait loop and the
negative-only exact account/device/generation control slot. The account actor
retains the original opaque preparation and deadline; queued ordinary commands
use a maximum eight-entry deferred FIFO. Cancellation, reply closure, deadline
and shutdown independently wake stalled publication. Never rebuild consent from
rows or retire uncertain MLS pending state. `client/device_linking.rs` publishes
only the frozen commit through the real relay adapter using authenticated route
components; it does not add a chat projection or expose the Welcome batch.
Relay acknowledgment leaves the durable phase Unknown. `client/private_transport.rs`
maintains one hidden route derived from fresh protected lineage plus actual MLS
state, independently of AccountState groups. The concrete account adapter private
commit method withholds ordinary local mirroring; only actual relay intake can
confirm. Startup reconciliation and both event projection loops must keep private
events out of chat projections. Classification errors propagate; protected
historical identifiers supply negative suppression only, never membership or
consent. Permanent negative privacy fences from actual birth/join SQL now supplement
selected metadata. Do not treat them as permission or restore them with snapshots.
Historical cursor retrieval remains a separate required checkpoint.


### Private recipient ingress map

The internal scoped singleton arming command delegates approved-predecessor and
actual-purpose checks to the account client; lost response delivery cancels that
exact scope. `client/sync.rs` routes actual Welcome deliveries into the account's
one transient collection only under its original live gate. Bounds precede input
cloning; complete batch joining remains the configured Session/Engine operation.
A private observer rejection delegates to ordinary Engine validation, whose
strict ordinary kind/profile and purpose rules independently reject private
bypasses. Context/lease/storage failures do not delegate. Incomplete chunks stay
fetchable and are not marked seen; only the atomic complete join is durable.
No scoped command, metadata or storage row can construct an approval token.

### Experimental private exact-ID recovery

`client/private_echo.rs` owns one nonserializable acquisition plan derived from
fresh protected lineage/current MLS route plus the exact uncertain110 commit.
`sync/comparison_job.rs` records only actual attempted-route scheduling metadata;
this is not permission or a durable capability. Require the same full private
scope and route before the fallback starts. `account_worker.rs` keeps at most one
abort-on-drop acquisition, serialized with ordinary comparison and charged to
its process recovery credits. Network waits stay off-worker. Revalidate protected
state and exact signed bytes before each normal recovered-delivery admission;
never directly confirm or promote the private group into chat state.

Keep the two-second per-request resource deadline separate from startup rotation
latency, and preserve the original Dispatching/Unknown phase on unavailable/empty/error outcomes. No timestamp
or observer metadata is consent. Retry state is one ephemeral five-second slot;
restart must freshly authenticate state and run comparison, never restore SDK
leases. Tests use actual websocket REQs, real SDK pairing/MLS and ordinary cursor
advancement; Negentropy rejection and stalled-ID controls must retain their
actual request evidence. Do not describe frozen earlier supported-relay passes
as a fallback regression RED.

The bounded exact-ID reconciliation inlet accepts durable Dispatching as well as
Unknown after restart. This supplies no live publisher or SDK lease and cannot
redispatch. Genuine intent interruption, encrypted reopen, ordinary cursor
advancement and real unsupported-Negentropy relay acquisition are regression
controls; authenticated Engine own-echo processing alone confirms membership.

A typed Engine storage error with a complete recipient batch keeps the original
live client. The feature tick retries through the configured atomic join under
the unchanged deadline; cancellation and success release any remaining queue
pins. Shape alone cannot authorize retry, and reopen still starts empty.

The dedicated private Welcome command uses the same bounded worker publication
wait loop and exact negative control as commit dispatch. Keep kind separation.
It forwards the original opaque preparation to Engine, uses authenticated inbox
routing, and suppresses local mirroring. Frozen publication receipts do not prove
recipient joins, ACK settlement, native support or history authorization.

Artifact-backed setup is a separate internal serial-worker inlet. Require version
2, original scope identity, exact authenticated public tree/digest and unchanged
owner purpose checks before SDK binding. The Approver must independently refresh
complete protected local lineage/full epoch authenticator and its exact own
export. Rejected metadata cannot mutate purpose/settlement or burn the reservation.
Cancel an exact successful setup when its reply is dropped. Keep the old singleton
recipient inlet strict; portable metadata and SDK setup alone grant no new join,
sibling approval, settled roster or history authority.


### Received enrollment proposal metadata

`client/private_enrollment_proposal.rs` validates only actual crypto-sealed v2
requests drained through the configured Session. Its no-input serial verifier
command incrementally fills only available App slots through bounded Core
drains; never drain into a full App retention queue. Preserve each original observation deadline and
opaque request, and revalidate fresh Completed actual tree/received artifact on
retry. Private context parsing rejects unknown/duplicate fields and noncanonical
JSON/base64. Compare every source/context/package binding before retaining usable
metadata. V1 cannot become proposal validation input. Cancellation clears memory;
reopen does not restore observations or ownership. This command returns aggregate
metadata only: no SDK consent, endorsement, transition, native proof or permission.
Original selection-generation and artifact-signer policy remain separate approval
requirements; do not infer them from tree equality or a successful count.

Original SDK proposal production is scope-only inside `runtime/device_linking.rs`.
`client/device_linking.rs` shares genuine token take/fresh predecessor arming with
invite preparation, then retains the opaque Core producer under that exact owner.
`RuntimeInviteGate::Lease::enrollment_proposal_metadata` reads only the live sealed
SDK token, original deadline and cancellation fence; never accept a host context
DTO as consent. `PublicationKind::Proposal` uses the existing bounded worker
negative controls. It publishes private control metadata without an Add, Welcome,
chat mirror or sibling approval. The genuine regression branches after fresh
artifact-bound A/C SDK completion over a completed A/B predecessor.

### Explicit received endorsement action

`client/private_enrollment_proposal.rs` separates bounded observation retention and hash selectors from selected-request authentication. The worker's internal `EndorseReceivedEnrollmentProposal` action holds a nonserialized Core continuation in `AccountLinkingOwner`; it accepts no context/artifact/package approval DTO. Preserve the original observed deadline, exact protected origin/generation, abandoned-reply cleanup and bounded cancelled-receipt fence. Do not expose the packet as SDK consent or use count validation to authorize a choice. Publication and A-owned collection remain separate.

`PublishReceivedEnrollmentEndorsement` uses the bounded private dispatcher with
an exact binding identity distinct from SDK scope identities. Cancellation must
revoke that exact action before blocked queue admission. `CollectOwnedEnrollmentEndorsements`
uses only the original local proposal lease and actual receipts, authenticating
each packet before retaining its occupied leaf. Received requests and receipts
share the App retention allowance of 128; the independent Core shared queue is
128, for an aggregate bound of 256. Bounded drains preserve excess original
proofs and clocks in Core. No collection count constructs Add/C/B authority.


### Actor-created setup packets

`client/device_linking/setup.rs` creates request/challenge packets internally
from the actual reserved purpose and fresh protected genesis or Completed
predecessor. Preserve canonical bounded decoding and actual signed single-use
KeyPackage checks before approver reservation. The process-local recipient handle
retains its original scope and challenge digest; exact retry must recheck the
actual SDK lifetime instead of restarting it. Never expose these internal
handles, `LinkingContext`, artifacts or proof-taking as a host approval API.
The stock SDK starts SAS from NewDevice, with both local confirmations and peer
MACs required. Setup success is verification only, not membership or history.


`runtime/device_linking/setup.rs` routes bounded setup commands through the serial
worker. `AccountLinkingOwner::native_setup_request` retains the original request;
never reconstruct it from returned packet metadata or durable facts. Reject
wrong scopes before taking custody, preserve it after invalid challenge input,
and clear it before cancellation's durable cleanup. Lost setup replies must
cancel only their exact newly owned scope; durable cleanup failure remains typed
negative state for existing maintenance, with no permission restoration.


### Original SDK endorsed Add preparation

`PrepareEndorsedEnrollmentInvite` accepts only the original scope and calls Core
with the same retained local producer and actual opaque sibling receipts. It
never begins a new SDK verifier or promotes a received request/count. Incomplete
preparation must keep automatic later collection live; use only Core's negative
owner-progress observation for raw retries, not a prematurely latched App flag
or durable-row reconstruction. Carry the earliest original receipt deadline
into the actor's publication timer without extending any clock. Lost replies
cancel that exact original scope. SQL/raw retry and cancellation stay on the
same continuation. This milestone stages exact C Add only; C original-purpose
admission, B protected transition, real ABC settlement and native enrollment
adoption remain independently gated.

### Native verification-only facade

`native_device_linking` exports opaque process-local sessions, bounded packets,
SAS observations, revision-bound human confirmation and closeable subscriptions.
Keep setup/SDK secrets and original scopes private in the actor. Route through
the resolved account address and retain exact scope checks; do not assume a
public-key hex string identifies a legacy label-directory account. Observations
must not consume proofs or reconstruct authority from durable rows. Preserve
negative cancellation before positive-operation lock acquisition, terminal state
against late replies and exact asynchronous Drop cleanup. Subscription close must
wake both waiting receiver admission and a pending change read.

Keep enrollment capability false and existing-group target selection unavailable
until the public original-action three-device flow qualifies. Revision-bound
singleton continuation is qualified through the original A/C actors. Its private
scheduling intent is ephemeral and never permission: check the original live
owner, cancel exact scopes on lost replies, publish Welcomes only after the
authenticated Add echo, and prune on revocation, expiry or cancellation. Never report partial verification/publication as synchronized. Default
methods remain typed Unsupported before account or worker effects. Future native
bindings must expose the same shapes in both feature cohorts without exporting
internal context, proof-taking or raw purpose selection.

Endorsed recipient arming compares the actor's original NewDevice context and
actual unused purpose before SDK take. Keep singleton arming strict. Retain
sealed evidence through exact SQL/Welcome retry; clear on exact cancellation
and collection retirement. Lost replies cancel their original scope. Native
three-device enrollment stays unavailable until its public opaque B transition
and actual ABC settlement qualify.

B existing-member transition retry must preserve the original armed action on a
typed storage error and schedule its exact group's retained convergence input.
Never reopen a client and rebuild that continuation from private11 or a packet.
B settlement uses its own original binding/guard, never a fabricated SDK scope.

The original A SDK token retains its settlement continuation before moving into proposal/Add ownership; received observation bounds only shorten its clock. The genuine three-device regression requires A/B/C actual epoch-2 three-leaf Completed rounds, three facts each and validated settled predecessor exports, including B/C SQL rollback retries. Native enrollment/UI/artifact adoption remain separate gates; verification-only native capability does not imply enrollment.

### Opaque native original three-device enrollment

Target selectors and received-approval handles are observations, never grants.
A/C setup and context role remain actor-owned. Existing-roster A first publishes
its original SDK-owned proposal; C keeps its original unconsumed verifier and
purpose until the complete, at-most-16-KiB endorsed packet validates. B approval
retains the original received action. Export A's packet before transferring its
lease into Add; admit it on C and the same B handle before explicit A finalize.
The worker publishes Commit then Welcomes only after actual confirmed echo.
Repeated B listing must share the same process-local Arc and bounded weak cache;
last-handle drop/exact cancellation fences that original action. Never recreate a
handle from a dropped weak entry while its original receipt remains live.
`EnrollmentComplete`/`Settled` are historical observations cached only after the
original live guard and fresh actual protected Completed full tree validate;
they cannot authorize another mutation. Preserve prior phase ordinals. The
capability remains unadvertised until native onboarding/artifact acceptance.
Bounds/reclamation are in `docs/marmot-architecture/runtime-state-bounds.md`.

### Native observational response timeout

A typed `AppError::AccountWorkerResponseTimedOut` from the bounded native Observe
RPC preserves the latest cached snapshot; it must not close a still-owned
publication or extend its original deadline. No cached phase grants permission.
Keep TransportClosed and actual owner/SDK failures terminal, preserve exact
cancellation against late replies, and test the real production wait with an
original blocked publication rather than advancing consent clocks.


Selected ordinary-chat requests retain a separate process-local owner after fresh
Current/Stable indexed local-leaf/admin and protected Completed roster reads.
A request snapshot or cached roster is never sibling consent or recipient admission.
Preserve original monotonic expiry, exact cancellation, generation and account
teardown fences; create no private package, fanout or transport before explicit
sibling consent. Keep the real public ABC+A/D ownership regression and default
Unsupported-before-effects control when extending this path.

### Independent selected-chat sibling consent

Selected-chat packet import creates review metadata plus a new bounded process-local consent owner; approval requires the same original owner, current revision, fixed 600-second monotonic deadline and fresh exact protected roster. Export/collection revalidate original owners and anchors before and after crypto. Reimport shares the exact public handle owner; dropping an alias must not cancel another retained alias. The last public handle, exact cancellation, expiry, account-client Drop and abandoned RPC result retire original intent. Keep the account-lifetime 128-entry receipt/tombstone bound; negative or expired imports cannot restart clocks. Collected device signatures are observations, never package/Add/Welcome/join authority.

Selected-chat offer production must use the original revision-checked approved consent and fixed deadline. Register bounded Weak-owner exact cleanup before replying; lost replies, exact cancellation and last shared handle Drop retire the package without cancelling an independent alias. Reopen abandons pending packages without restoring consent. No ordinary admission/delivery claim from offer metadata.

Original request offer collection retains exact approved response bytes and one
immutable authenticated package observation per selected indexed sibling. Recheck
the original request/ordinary/protected anchors before and after authentication;
propagate storage errors without trying another response. Exact offer retries
are revision-idempotent; conflicting frames never replace the prior observation.
Offer counts and snapshots do not grant Add, Welcome publication or joining.


Selected-chat private offers carry the intact Core leaf-signed offer plus a genuine unpublished signed30443 event in a bounded canonical private envelope. Verify event signature/account/content/reference/expected tags against the authenticated offer; retain exact wire in the original consent and verified source ID only in its original request offer slot. Register negative package cleanup before signing awaits, recheck the fixed original lease afterward, and interrupt signing on exact cancellation, expiry or abandoned reply. No directory publication or fabricated source ID. Original selected publication retains frozen Commit/Welcomes and the actual ACK report, confirms the exact pending identity before each fresh successor check, and observes ordinary send effects/projection/routes before releasing Welcomes. Do not use the native-only observer for ordinary EpochChanged. Never place selected permission/fanout into generic replay. InviteConfirmed observes source confirmation, not recipient joining/history. See the real public ABC+A/D four-leaf exact-new-message regression and its scoped qualification proof.

Selected recipient expiry acceptance uses a per-fixture lifetime captured only at
the original consent constructor under test + test-policy-overrides. Keep the
production 600-second lifetime unchanged; never renew imported/retained owners or
advance a global clock. The real SQL-rollback control requires original expiry,
exact Pending-purpose/private-bundle retirement, no same-request restart, and no
late admission after releasing the fault while other actual copies keep delivering.

Selected publication cancellation acceptance must hold the actual original Commit
or Welcome before real relay publication. Retain the same public request while
dropping its RPC receiver to isolate lost-reply custody. Exact cancellation must
interrupt blocked transport without waiting for it; releasing the gate must never
publish canceled work. Before Commit confirmation retire only exact pending MLS
work; after confirmation preserve canonical membership while preventing Welcome
release. Independent sibling consent is not revoked by source cancellation.


Original opt-in history actors must derive authenticated scope and source proof
from real Core/MLS delivery, freeze whole bounded logical snapshots, and require
explicit original recipient revision approval. Keep private controls hidden in
both direct and replay paths; imported archives are source-attested, never live
MLS projection or recovery authority. No row can restore a consent lease.
Preserve exact fixed deadlines and original alias custody. Negative staging
cleanup must survive SQL failure; committed import completion must precede
fallible receipt publication; source expiry must be filtered before serialization.
Test fresh-outer same-request replay, not only duplicate ciphertext, before
claiming cancellation/restart acceptance. Current actor checkpoint explicitly
leaves these lifecycle/privacy repairs and native presentation unqualified.

History account owners retain a bounded128-entry negative transfer-ID set across
active and retired actions. Never recycle this process-lifetime budget when an
entry expires/cancels; a fresh authentic MLS envelope containing the same signed
Request must not recreate consent or restart a clock. Keep the actual new-ratchet
replay regression and unchanged normal import positive. Reopen cannot derive
positive consent from these facts; durable restart denial remains separate.

History export must evaluate persisted source retention against the captured
source snapshot time before serializing plaintext. An expired-unpruned record
must contribute only a zero-payload tombstone, not plaintext that a recipient
later hides. Keep the actual frozen-archive witness and decrypted ordinary MLS
fixture; no recipient-page absence or fake record is sufficient privacy proof.
Expiry while publication is delayed remains a separate original-owner control.

History staging maintenance must retain the exact cancelled negative entry when
SQL cleanup fails; retire channel keys before retry and never reconstruct positive
consent from staging rows. A committed Imported receipt updates read-only progress
once before fallible wire sealing. Exact cancellation still prevents publication,
and completed staging must not be denied as unfinished work. Keep both actual
SQL-boundary cancellation controls and normal multi-fragment import regression.

History publication must interrupt the actual adapter future on original
revocation, unchanged deadline or abandoned continuation reply. Register the
Notify waiter before the live check; cancellation must win a ready transport
branch. Keep the public owner alive in lost-reply controls, resume the worker
before releasing the gate, and verify no late recipient chunk/import.

History publisher runtime shutdown must observe the existing lifecycle watch
while actual transport waits; forced account-worker abort is not responsive
original-owner retirement. Reopened clients inherit only that terminal negative
observation. Test expiry with a source-only lifetime consumed at original
construction under test-policy-overrides; never modify an existing deadline or
production600-second lifetime. Preserve real gate-release/no-late-chunk controls.

History recipient intake must authenticate the actual received MLS source and exact
addressed Core request before the private15 negative observation transaction. Never
construct a new owner for an already-observed request after restart, and never
restore consent, keys or deadlines from these rows. Only the fresh authenticated
call can create its original process owner. Retain the genuine encrypted reopen
control using a new outer MLS frame from the unchanged original source, plus the
distinct fresh request acceptance control. Capacity is cumulative128 and fails
closed; this experimental fence is not an unbounded sync journal.

One-group device revocation begins as an opaque original administrator review in `device_revocation`, with serial child RPC/client modules. Target device bytes are a selector only. Keep exact originating account/client identity, fixed original600-second deadline, fresh Core full-tree/epoch/generation checks, cancel/Drop/abandoned-reply retirement and one active original. Snapshot success is not removal, publication, protected-roster revocation or a per-group completion result.

The original one-group revocation review now supports approve(displayed revision), real direct relay ACK, ordinary confirmation and actual sender projection. Account owner retains one exact negative pending identity across cancellation/drop; rows never recreate the action. Qualified actual A/B/C/D regression removes C only and verifies A/B/D messages plus C realized-eviction refusal. Blocked-publication/lost-reply/expiry/reopen controls and full protected/multigroup revocation remain pending; see docs/device-sync-exact-device-leaf-removal-verification.json.
