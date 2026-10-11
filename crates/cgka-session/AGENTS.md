# AGENTS.md - crates/cgka-session

Agent map for the account-device session crate. Overview and test coverage: [`README.md`](README.md). Test placement:
[`tests/AGENTS.md`](tests/AGENTS.md).

## Scope

Wires `Engine<SqliteAccountStorage>` into an app-facing session lifecycle. All code is in `src/lib.rs`
(`SessionConfig`, `AccountDeviceSession`, `SessionEffects` / `PublishWork`). Does not own a transport adapter, account
key derivation, relay sync, or UI projection.

## Rules

- Keep SQLCipher keys app-provided. Do not add key derivation or recovery here.
- Keep transport-specific code out. Inject a `TransportPeeler`; Nostr crates are dev-dependencies only.
- Surface engine effects as app events plus publishable transport work.
- `open` validates profile and convergence policy before opening storage or hydrating; keep new open-time checks
  ahead of any durable mutation.
- Keep storage-only legacy-format promotion explicit and host-scheduled after readiness; do not add it to the
  session-open critical path or widen the generic engine storage API for it.
- Prefer behavior tests over internal state assertions.
- Experimental private genesis methods delegate creation, fresh origin validation
  and exact retirement to the engine. Keep consent and roster settlement in the
  account-scoped App coordinator; a reopened birth must never restore a verifier.
  Public-boundary regressions live in `tests/session_lifecycle/private_device_genesis.rs`.
- Nostr consumer tests independently check authenticated source-leaf metadata when
  the feature is enabled and absence when disabled. Existing `test-policy-overrides`
  belong only to test invocations, never production native artifacts.

## Verification

```sh
cargo test -p cgka-session
```


Feature-only private invite preparation, borrowed cleanup and exact raw-attempt
retirement remain thin Engine forwarders in `src/lib.rs`. The components variant
of private genesis creation passes transport-neutral App components before
protected birth capture; routing generation belongs to the App. Do not embed
Nostr or SDK policy here. Opaque prepared objects must survive failed cleanup for
an exact retry; durable facts do not restore consent.

Private dispatch is also a thin borrowed Engine forwarder. Keep the caller's
original opaque preparation on pre-intent storage failure; never accept native
permission flags or reconstruct it from durable facts. Session does not release
a Welcome or settle publication.

Experimental predecessor metadata export/validation remain thin Engine forwards.
Use scratch public storage for portable authentication; never restore a member or
consent from its result. SDK context and all-leaf approval belong to the App owner.

Private enrollment proposal preparation/wrapping are thin feature-only Engine
forwards. Retain the opaque original-owner producer in App custody across retries;
never rebuild it from request metadata, storage or an SDK context DTO.

Endorsement wrapping/receipt draining and original local proposal signature/
collection remain thin Core forwarders. Never reconstruct the original action
from a wire packet or treat complete signatures as transition/join permission.

Bounded request/receipt draining and single-receipt original-lease validation are
thin Engine forwards. `None` denotes invalid receipt metadata; owner/storage
errors remain errors. App owns deduplication and its shared retention allowance.

### Selected-chat consent observation forwarding

The four experimental selected-chat observation methods delegate to Core. Authenticated packet objects are metadata only; Session cannot mint live App consent or recipient join authority from them. No transport or package creation is implicit.

Account-chat sharing forwarding lives in `src/account_chat_sharing.rs`. Keep original keys, transcript and fixed-lease checks in Core, explicit approval and publication custody in App. No Session-owned timer, permission DTO or transport policy.
