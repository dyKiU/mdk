# Experimental retained own Add reconciliation

The default-off `experimental-retained-own-commit` feature adds
`MlsGroup::process_retained_own_commit`. Ordinary `process_message` is unchanged.
This API authenticates a previously built local public commit; it never admits a
fresh Add, merges a pending commit, confirms publication, or authorizes delivery.

During ordinary local commit staging, only a public commit with one inline Add
retains its exact authenticated content, up to 64 KiB. The normal builder has
already validated the package and constructed the staged successor. The bytes
include the group, epoch, sender, AAD, complete proposal/path body, signature,
and confirmation tag. They live in the private pending `StagedCommit`, persisted
with the existing group-state provider write. Clearing, replacing or merging the
pending commit removes that matching scope. Older pending records without this
field cannot be reconstructed or admitted by the new API. Other commit shapes,
references, private ciphertexts and oversized content are deliberately ineligible.

Inbound processing reuses existing framing, group/epoch, membership-tag and sender
key validation. It verifies the real outer signature, requires this group's current
own member leaf, compares the entire authenticated content exactly, and checks the
actual pending confirmation tag. Only then can the library create
`ProcessedMessageContent::OwnPendingCommit`, retaining real source metadata.
It performs no KeyPackage lifetime reconversion: the equality is to already
validated retained content, rather than a bypass for new incoming packages.
SafeAAD validation remains active when required by the authenticated group context.

This is a local experimental API, with no protocol identifier or version change.
It requires provider transactions at the application boundary: OpenMLS's existing
builder writes group state before subsequent framing/storage operations and does
not supply a generic transaction abstraction. Applications must roll back the
complete prepare/merge operation on failure and atomically couple a processed
proof with their durable disposition. The optional retained-content field is
last in the staged structure: MessagePack omits it when absent, preserving stock
positional fields and allowing stock pending records to decode without inventing
a retained receipt. A retained Add round-trips with its receipt intact. This is
not downgrade support for feature-upgraded pending state. The unpublished12e8
prototype put this field first; its experimental positional receipts are not a
supported native storage cohort.

The encrypted-reopen dependency fixture encrypts a real serialized MemoryStorage
provider snapshot using AES-GCM, writes it to a temporary file, creates a new
provider, decrypts it and loads the real group. This validates persisted retained
content, not SQLite/SQLCipher transaction behavior. The separate MDK encrypted
SQLCipher confirmation/rollback regressions remain the integration gate before
changing the pinned dependency or claiming delayed reconciliation there.
