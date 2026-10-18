# Private storage ownership at the upstream boundary

This inventory retains the private schema and source paths while applying the
upstream table-ownership boundary. It changes no migration, receipt, provider,
authentication check or live authority. Both feature cohorts create the same
private schema: disabling the experimental feature rejects activated private
state rather than deleting it. The registry therefore has unconditional entries.

The three private migration receipt, bridge-audit and activation tables belong
to Base. The immutable ledger is scanned as Base; the two named migration-body
directories are schema history, covered by the fresh-schema checks and the
existing private-ledger compatibility tests. There is no general `private_*`
exemption. Unknown production roots fail classification.

## Protocol ownership

These eleven modules own fifteen tables. Their Engine storage contracts create
or consume authenticated facts atomically with actual MLS operations. Their
facts never restore the original SDK consent or a live enrollment owner.

| Module | Engine contract and callers |
| --- | --- |
| `accepted_welcome` | `group_lifecycle` persists the immutable accepted-join receipt inside the join transaction. |
| `accepted_device_group_anchor` | `private_successor`, `device_group_lineage` and `private_transport` validate accepted successor provenance. |
| `existing_device_group_anchor` | `private_enrollment_endorsement/existing` persists the selected existing-member successor. |
| `revoked_device_group_anchor` | `device_leaf_revocation/transition` persists the exact post-revocation successor. |
| `private_device_invite` | `private_device_invite/preparation` and `/confirmation` own outgoing Add staging and confirmed lineage. |
| `device_group_genesis` | `device_group_genesis` owns actual birth selection and negative retirement. |
| `private_group_privacy` | `group_lifecycle` writes the permanent exclusion atomically; `private_transport` uses it for private-route classification. |
| `private_roster_settlement` | `private_roster_settlement`, its receive path and `message_processor` own authenticated round/fact persistence; the Engine owns live admission. |
| `roster_ack_capture` | `roster_ack_capture`, `message_processor/store` and `openmls_projection` own authenticated capture facts. |
| `device_linking_key_package` | `key_package`, `private_enrollment_request/recipient` and `group_lifecycle` bind and consume the exact purpose bundle. |
| `selected_chat_key_package` | `selected_chat_consent/package` and `group_lifecycle` bind and consume the independently selected recipient purpose. |

All sixteen optional private `StorageProvider` capabilities remain implemented
once in `protocol/provider.rs`. A capability does not make every exposed table
Protocol-owned: the App also exposes durable policy and mirror stores through
that aggregate. In particular the Engine reads approved sharing policies only
as a negative historical-policy veto during bootstrap retirement; the App owns
their creation and orchestration.

## App ownership

The twelve App modules own thirty-two tables:

- `device_linking` stores verifier generation/context/terminal facts.
- `synchronized_history` stores staged archive observations, completion receipts
  and retention fences, separately from authenticated Engine history.
- `approved_account_sharing_policy` stores explicit approval metadata and source
  counters/journal; it cannot resurrect live consent.
- `mirrored_chat_catalog`, `mirrored_chat_messages` and
  `mirrored_chat_presentation` store and present paired-source observations,
  separately from local MLS membership.
- `account_chat_record_stream`, `account_chat_send_queue`, `account_chat_source`,
  `account_chat_legacy_acceptance`, `account_chat_origin_observation` and
  `account_chat_departure` own source lineage, stream/outbox/receipt and departure
  observations under current App policy.

`mirrored_chat_live_catalog` is a view, so it is not registered as a table. The
upstream scanner's documented name-based limitations remain; this inventory
does not claim that it proves live authorization.

## Why the retained crossings exist

The retained allow-list lines record existing checks rather than remove them:

- `device_linking` reads the Protocol purpose bundle and unresolved invite
  helper before allocating another verifier generation, so a verified but
  unconsumed bundle or outgoing Add cannot be orphaned.
- `device_linking_key_package` and `private_device_invite` read the App attempt
  generation/context/terminal fact while validating the exact original purpose.
- The eight Protocol files listing `account_state` compare the configured App
  account with their captured account before committing Protocol facts. This
  retains the wrong-account fail-closed fence.
- `approved_account_sharing_policy` reads the Protocol device-signer binding to
  require the actual local account/device. It never substitutes the projection
  alone for that signer check.
- `mirrored_chat_presentation` reads `cgka_groups` to exclude mirrors of groups
  already present as local MLS groups.
- `account_chat_legacy_acceptance` reads App-owned approval metadata directly
  through `ApprovedAccountSharingPolicyStorage` on `SqliteAppStorage`. It rejects
  revoked or mismatched approvals, requires explicitly accepted source changes
  and retains original-owner callbacks before and after its transaction. The
  obsolete aggregate-provider method allowance is removed; no consent is granted
  and no second policy implementation is introduced.
- `synchronized_history/request_observation` reads the Protocol signer binding
  inside the observation transaction. It requires the configured App account
  and the actual signer account/device to match before recording an immutable,
  bounded request identity. This is a negative replay fence; the observation
  never restores an owner, keys, consent or a deadline.

The ten private `with_transaction` call sites and the four private group-delete
triggers are Protocol-to-Protocol after semantic classification; listing them
as crossings would misstate ownership. Protocol group deletion still retires
private settlement and anchor facts atomically. Activation triggers write only
the Base cohort marker and retain the upstream Base exemption.

The initial unchanged incoming boundary checks failed at runtime on both
cohorts at `234c9b064bf6c3702a08898b2ea0ab25aa62265d`, run `39055385890`
(six actual bodies: two passed, four failed, none ignored). This adaptation
requires fresh remote GREEN and mutation evidence; historical passes do not
qualify the adapted source.

## App-handle receivers after the protocol-handle move

The twelve App-owned root modules retain their public module/type paths and use
`SqliteAppStorage` for their SQL operations. Callers obtain it through the account
handle's `app_storage()`; it clones the same SharedConnection and opens nothing.
The five App capabilities retain their existing borrowed StorageProvider slots
through the named `MirroredChatCatalogStorage`,
`ApprovedAccountSharingPolicyStorage`, `MirroredChatMessageStorage`,
`AccountChatRecordStreamStorage` and `AccountChatSendQueueStorage` delegates in
`cross/private_app_capabilities.rs`. All sixteen provider slots still return
`Some(self)`. Those delegates
forward every argument and original-owner callback without adding transactions,
permissions, retries or a second implementation. The eleven Protocol capability
implementations remain on the account handle.

Legacy acceptance reads the App-owned policy trait directly on the App handle;
its former aggregate-provider method crossing is removed. Its outer transaction
and both original validations remain. Paired conversation presentation uses the
same deferred SharedConnection read transaction and query-only protection as
the original protocol snapshot, without giving the App handle StorageProvider.
