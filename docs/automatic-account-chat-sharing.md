# Automatic sharing between paired account devices

Implementation starts from `c9bc674a`. This is a development design, not an
adopted public wire profile or a completed native feature.

The approved product policy covers existing and future accepted conversations
between fully paired non-revoked account devices. Pairing must explicitly offer
this policy; old pairing approval alone does not enable it. Signing in with the
same account key is insufficient. Pending stranger invitations remain pending.

## Ownership and authentication

Core derives a catalog from actual local live MLS memberships under a fresh
Completed protected roster. Entries bind canonical group IDs, epochs, profile,
local occupied leaf and actual administrator status. The initial read-only
`account_chat_catalog` returns pages of at most 128 observations with an exclusive
group-ID cursor. It lists storage metadata before loading only eligible page
members; it is an initial reconciliation operation, not a steady-state sweep.
Neither a returned entry nor its serialized copy authorizes a send or an Add.

The subsequent account-scoped policy owner will authorize fresh bounded actions
under that original pairing policy. Persisted intent permits retry scheduling,
never reconstruction of an expired action, private package, consent or key.
Every operation revalidates account, actual device signer, protected roster and
settlement generation. Revocation fences disclosure and queued sends before
publication; leave/delete generations prevent resurrection from older catalogs.

## Actual membership and forwarding

Administrator-supported admission may produce a new device leaf through genuine
Add and Welcome. Incoming non-admin conversations cannot use that permission.
The accepted fallback retains the actual member installation as a bridge. It
receives ordinary ciphertext through its own valid MLS state and relays logical
records to explicitly paired siblings using recipient-only encrypted transport.
A mirrored conversation remains source-attested; it is not a synthetic MLS
group or independently verified leaf. No MLS databases, ratchets, exporter keys
or account stores are copied.

An authenticated sibling send intent is bound to account, target member device,
canonical group, policy generation and immutable idempotency token/body digest.
The actual member checks fresh membership/lifecycle and sends using the existing
ordinary App submission path. Its retained original submission produces the
canonical ordinary event and confirmation returned to the sibling. A repeated
token with different content is refused. If every eligible actual member is
offline, sends remain queued with explicit availability; a source-attested
mirror cannot independently emit ordinary MLS ciphertext.

Existing history channels cannot be widened by dropping checks: their recipient
also reads the ordinary MLS epoch. A separate bridge scope must authenticate
source membership while validating the absent recipient solely through the
protected group and explicit sharing policy. Existing denied history-selection
controls remain unchanged.

## App and binding integration

Normal group-list and timeline queries must include an explicit conversation
delivery mode: actual local membership or paired-member bridge. Both use the
canonical group ID and account scope. Mirrored rows preserve source provenance,
retention, deletions and media-verification verdicts. Send dispatch follows that
mode and returns queued/confirmed/refused status. A separate archive reader is
not the normal completed conversation flow.

Native adapters forward policy setup, normal conversation queries and ordinary
send commands; they do not accept packet/roster/permission DTOs. Manual chat
controls remain available until actual backend replacement is qualified.

## Qualification sequence

1. Real independent-store Core catalog discovery, non-admin membership and
   same-title distinct canonical IDs, unchanged authority and terminal exclusion.
2. Explicit pairing-policy original ownership plus authenticated encrypted
   bidirectional catalog reconciliation on a real relay; wrong account/device,
   stale generation, replay and revoked source refusal.
3. Initial and later create/accepted-invite discovery; source-attested records
   through the normal list/timeline, without automatically accepting invitations.
4. Durable authenticated sibling intents, actual member ordinary sends and exact
   confirmation; duplicate/body conflict, offline/restart/cancel/revocation.
5. Installed Mac/iOS normal conversation navigation and bidirectional messaging,
   retained history, reconnect, leave/delete and account replacement. Public
   production peers retain the ordinary invitation/message protocol.

No wire kind or protocol identifier is assigned by this design. Framing and
resource bounds require focused actual transport acceptance before adoption.
