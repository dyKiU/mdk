# cgka-traits

The shared trait surface and cross-boundary value types for the CGKA stack. Anything that crosses a crate boundary
between engine, peeler, transport adapter, storage, and caller imports from here (`cgka_traits::...`).

## What lives in here

- `CgkaEngine` — the engine trait the rest of the system depends on.
- `TransportPeeler` — async crypto-boundary trait: `peel_group_message`, `peel_welcome`, `wrap_group_message`,
  `wrap_welcome`, plus `wrap_group_message_with_metadata` / `wrap_welcome_with_metadata` (default to the plain wraps).
- `TransportAdapter` — account-aware network boundary for activation, subscription refresh, publish receipts, and
  inbound deliveries.
- `StorageProvider` and the Marmot storage traits it aggregates (groups, messages, outbound intents and fanouts,
  leave/disband requests and tombstones, Welcomes, capabilities, convergence policy and passes, deferred-peel
  generations, member-validation cache, account-device signer, KeyPackage bundles, maintenance) — plus an accessor for
  the underlying OpenMLS storage provider.
- `EpochState`, `WelcomeState`, `IngestOutcome`, `StaleReason`, `EngineError` — the typed state-machine and error
  vocabulary.
- `MessageRecord`, `MessageState`, `StoredMessagePayload` — durable message state plus the typed envelope that
  distinguishes raw transport bytes, delivery-aware outbound Welcomes, and peeled OpenMLS wire bytes.
- Cross-boundary value types: `TransportMessage`, `TransportEnvelope`, `TransportAccountActivation`,
  `TransportPublishRequest`, `TransportDelivery`, `PeeledMessage`, `EncryptedPayload`, `SendIntent`, `SendResult`,
  `AutoPublish`, `GroupEvent`, `PendingStateRef`, `MessageId`, `GroupId`, `MemberId`, `EpochId`, `Group`, `Member`.
  `GroupEvent` separates renderable account activity from device-local termination,
  restoration and leaf-destination cleanup. Consumers must not reconstruct these
  effects from newer engine state. `GroupMemberLeaf` names account and leaf index.
- App-component value types: `AppComponentSet`, `AppComponentData`, and typed component states (`NostrRoutingV1`,
  `GroupProfileV1`, `GroupLifecycleV1`, `GroupAvatarUrlV1`, `GroupBlossomImageV1`, frozen `BlobStoreEndpointV1` /
  `EncryptedMediaPolicyV1`, current `BlobStoreEndpointV2` / `EncryptedMediaPolicyV2`), plus the public-IP / loopback
  host classifiers used by the dial-safety rules.
- `MarmotAppEvent` — the typed application-message event — and the poll (NIP-88 profile) and group-report
  interpretations carried in app messages.
- Capability negotiation types: `Capability`, `Feature`, `RequirementLevel`, `CapabilityRequirement`,
  `GroupCapabilities`, `FeatureStatus`.
- `GroupContextSnapshot` — the cross-boundary group-context view.
- Durable convergence-pass and maintenance/publication-recovery records.
- `MirroredChatScope`, `MirroredChatEntry`, and optional `MirroredChatCatalogStorage`
  store paired-source chat observations separately from MLS membership. Stored
  metadata never restores approval or authorizes message delivery.
- Agent text stream preview values: QUIC policy/component state (`AgentTextStreamQuicPolicyV1`), role/feature bits,
  length-delimited records (`AgentTextStreamRecordV1`), and key-context/transcript-hash helpers
  (`AgentTextStreamKeyContextV1`, `AgentTextStreamTranscriptV1`).

The rustdoc on each trait in `src/` is the reference for method responsibilities: legal states, which errors fire, and
ordering guarantees.

## Key contracts

**Publish-before-apply.** `AutoPublish` follows the same contract as explicit group evolution: callers publish the
message, then confirm or fail the attached `PendingStateRef`.

**Publish receipts.** `TransportEndpointReceipt` carries optional typed ACK detail in `ack_kind`. Rust callers that
construct a receipt must set it, usually to `None` for an injected or reconstructed receipt:

```rust
TransportEndpointReceipt {
    endpoint,
    accepted_at: None,
    ack_kind: None,
}
```

`Some(Affirmative)` means an affirmative endpoint ACK was observed without a typed duplicate marker; `Some(Duplicate)`
means the endpoint reported an already-held exact event; `None` means the detail was unavailable, not that the event
was new. Serialized receipts without `ack_kind` decode as `None`, and `None` is omitted when serializing. `ack_kind`
does not change publish quorum decisions.

## Run the tests

```sh
cargo test -p cgka-traits
cargo bench -p cgka-traits --bench stored_message_codec
```

`tests/snapshots.rs` uses `insta` to lock the JSON / debug shape of cross-boundary value types.

## Stability

Versioned with the workspace; no public consumers outside it. Snapshot tests catch accidental drift; deliberate drift
is a normal trait-evolution change for now.

Agent-facing scope and file map: [`AGENTS.md`](AGENTS.md).

`accepted_welcome::AcceptedWelcomeReceipt` is an experimental immutable
accepted-join fact with an optional `AcceptedWelcomeStorage` capability. It
contains public identity bindings and an epoch-authenticator digest, never
secrets or authorization. Its JSON shape is pinned in the snapshot suite.

Experimental source-leaf evidence uses the optional
`GroupEvent::MessageReceived.source_leaf` field. Absence remains omitted from
JSON and old events decode with `None`. `SourceLeafProof` binds a leaf index and
MLS signature public key to an authenticated source epoch/branch; it grants no
enrollment or history authorization. Consumers must compare it with current
authoritative settled state. `Member.id` is the account credential identity and
`Member.credential` is the MLS signature key; this member view has no actual
leaf index and is not a settled device roster.


The experimental accepted-device-group anchor contract carries bounded
trusted-core join metadata and a local selected-lineage scope. Its optional
storage accessor defaults unavailable. Serialized facts are neither SDK consent
nor roster settlement, and must not be accepted through native/wire DTOs.

The transport peeler also exposes default-deny private-linking Welcome wrapping,
authenticated single-chunk observation and complete-batch authentication/reassembly. `PrivateLinkingWelcomeContext` is exact transport
metadata (account, separate device signers, local generations, group, pairing
nonce/digest, exact KeyPackage and commit/Welcome digests), never an enrollment
permit. Nostr-specific framing stays in the Nostr peeler.

`PrivateLinkingWelcomeObservation` carries bounded authenticated context, index,
count and total bytes. It has no Debug/serialization or permission semantics.
The caller must check known bindings against its actual live SDK attempt before
buffering; the complete batch and actual MLS tree remain independently validated.

Experimental anchored roster settlement is a separate optional persistence capability
(`private_roster_settlement.rs`), not generic ACK capture or authorization. It stores
one checked-generation owner-bound round, at most 128 occupied leaf facts, exact
prepared ciphertext/outbound retries and atomic last-slot completion. Completed
metadata never mints live admission; Engine must independently validate protected
origin/current tree and a fixed monotonic live round. No deadline or SDK permission
is serialized. The account owner must explicitly abandon unfinished rounds on
authoritative exclusive startup; storage does not run that lifecycle hook itself.

The experimental `revoked_device_group_anchor` contract retains bounded authenticated
single-Remove successor metadata and permanent denial references. Its optional
storage accessor defaults unavailable. Retained rows and serialized drafts never
restore original consent, a deadline, or settlement admission.

`approved_account_sharing_policy` stores immutable explicit pairing approvals,
permanent revocations and a bounded local-source sequence journal. Stable policy
identity is symmetric and independent of ephemeral encryption channels. Retained
facts only schedule fresh authenticated Core checks; they never restore a grant.

`mirrored_chat_messages` carries bounded source-attested logical content/tags and
chronological cursors. Active bodies retain a verified SHA256 content digest;
empty terminal records may have an unknown digest and permanently fence the
ordinary event ID. These records remain separate from confirmed MLS events.

`account_chat_send_queue` retains exact original inner events, independent approved
routes and genuine ordinary-ID receipts. No Debug, live permission or queue-ID
alias. Retry observations retain original time/digest after terminal payload erase.
Fair intent/route and receipt-digest cursors are separate from message chronology.
Optional storage defaults unavailable; Core still validates original authority.

`account_chat_record_stream` retains canonical logical batches until an actual
authenticated peer receipt. Record sequences, outbox digest cursors and message
chronology are separate. Source expiry/deletion can permanently deny a queued
batch and erase bytes without claiming delivery. Metadata carries no restored
keys, deadlines or original authority; the storage capability defaults unavailable.

Generation-specific record acknowledgment separates stable batch identity from
coverage of the actual peer projection generation authenticated by Core. Its
bounded metadata read and atomic acknowledgment require original before/tail
validation. Global terminal receipts remain immutable; missing coverage never
restores payload, channel keys or authority to replay.
