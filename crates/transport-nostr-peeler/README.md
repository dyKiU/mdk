# transport-nostr-peeler

Nostr transport peeler for the Marmot CGKA engine.

This crate sits below `cgka-engine` and above the relay adapter (`transport-nostr-adapter`, which depends on this crate
for Nostr event DTO conversion). It turns Nostr-shaped events into `cgka_traits::TransportMessage` values, and
wraps / peels Marmot group MLS bytes for Nostr kind `445`.

## What this crate does

- Maps kind `445` events with an `h` tag into group `TransportMessage`s.
- Maps kind `1059` events with a `p` tag into welcome `TransportMessage`s.
- Encrypts and decrypts kind `445` group envelopes with ChaCha20Poly1305 (`content = base64(nonce || ciphertext)`,
  empty AAD) using the engine exporter snapshot.
- Carries no source-epoch hint in the kind `445` envelope: an undecryptable message returns `DecryptFailed`, and the
  engine falls back to retained-epoch snapshots / deferred-peel retry rather than a transport-carried epoch.
- Wraps and peels MLS Welcome bytes as NIP-59 gift wraps when a local Nostr signer/decrypter is injected through the
  `MarmotNostrSigner` boundary (`SdkSigner` adapts it to rust-nostr's signer traits).

## What this crate does not do

- No relay connections, subscriptions, retry policy, relay selection, or relay persistence.
- No application session or account-device lifecycle.
- No Nostr SDK key management. The caller supplies the signer/decrypter that already belongs to the account-device
  identity.

## Welcome validation

Welcome peeling fails closed unless all of these hold:

- the outer event is kind `1059` and verifies as a signed Nostr event,
- the event `p` tag matches the `TransportEnvelope::Welcome` recipient,
- NIP-59 unwrap succeeds with the injected local signer/decrypter,
- the NIP-59 seal verifies and the seal signer matches the rumor author,
- the decrypted rumor is Marmot kind `444`,
- the rumor carries an `e` tag holding a 32-byte hex KeyPackage event id,
- the rumor carries a `relays` tag with at least one non-empty relay,
- the rumor content decodes to non-empty MLS Welcome bytes.

## Boundary shape

Inbound:

```text
real Nostr event -> NostrTransportEvent -> TransportMessage -> NostrMlsPeeler -> PeeledMessage
```

Outbound:

```text
EncryptedPayload + GroupContextSnapshot -> NostrMlsPeeler -> TransportMessage
```

The outbound `TransportMessage` carries a Nostr DTO payload. Outbound kind `445` events are signed at wrap time with a
fresh ephemeral Nostr key generated per event, so the event id is final and the adapter publishes the event as-is (no
pre-signing-id replacement). Welcome outputs are already signed NIP-59 gift wraps because NIP-59 construction needs the
local signer.

## Run tests

```sh
cargo test -p transport-nostr-peeler
```

See [`AGENTS.md`](AGENTS.md) for the strict tag validation contract. The Nostr transport spec lives in
[marmot-protocol/marmot](https://github.com/marmot-protocol/marmot).

## Experimental private enrollment transport

`experimental-device-sync` adds a dedicated private Welcome wrapper and bounded
batch peeler. This uses local draft rumor kind38174/profile
`whitenoise.experimental.linking-welcome.v1` inside signed NIP-59 gift wraps.
It does not change ordinary kind444 Welcome validation or fabricate a published
KeyPackage event ID. The shared account signer authenticates the pairing context;
recipient MLS signer and exact KeyPackage bindings are separate fields.

Welcomes are bounded to2MiB and split into24KiB raw chunks (at most86 events).
Each event is bounded to128KiB before JSON parsing/decryption and each decoded
rumor to40KiB. The complete batch is authenticated against an exact caller-owned
context, reassembled by unique indices and verified against its raw Welcome
SHA-256 digest. Missing, duplicate, mixed or substituted batches fail closed.
These are application resource limits; the pinned Nostr implementation supports
NIP-44 extended lengths. Returned bytes are transport evidence only and never
supply SDK consent, MLS membership or enrollment permission.

This private format is not an adopted interoperable Marmot protocol. Relay
collection, original pairing deadlines, durable retry and trusted recipient join
remain owned above this pure transport crate.


The experimental `observe_private_linking_welcome` method authenticates one
bounded chunk and exposes its context and collection bounds without requiring
artifact hashes that are created after pairing. This observation is not a
complete Welcome or consent. The account owner must compare every already-known
SDK binding (identities, generations, group, nonce/context digest and exact
KeyPackage reference/digest) before collection or admission. Post-preparation
commit/Welcome hashes are authenticated transport metadata. The complete batch
still requires exact common context, unique indices and final raw Welcome digest;
actual enrollment independently requires the live NewDevice SDK policy and
cryptographically validated MLS tree.

`TransportPeeler::peel_private_linking_welcome_batch` delegates to this same
complete-batch validator when the experimental feature is enabled. Its default
implementation rejects private input. App transport decorators must forward the
operation to retain that validation; reassembled bytes still carry no join
permission, and ordinary `peel_welcome` continues to reject private framing.

`TransportPeeler::observe_private_linking_welcome` delegates to the same concrete
single-chunk validator under the experimental feature; default implementations
reject. The existing `PrivateWelcomeObservation` export aliases the shared
`PrivateLinkingWelcomeObservation` type. Decorators forward this operation too.
This exposes metadata through the product boundary without granting admission.
