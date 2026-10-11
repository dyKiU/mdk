# Account chat views

The experimental account view combines ordinary local MLS conversations with
authenticated observations received from paired devices. Pair approval and
message transport belong to App. These read interfaces do not approve sharing,
admit a device to an ordinary chat, or grant send or media authority.

## Automatically refreshed screens

`open_account_chat_list_window(account_ref, initial_rows)` retains 2–128 rows in
two bounded lanes. `LocalMls` rows retain the ordinary presentation and anchor
metadata. `PairedSource` rows carry the canonical group ID and authenticated
source metadata. The initial replacement is taken once with `snapshot()`;
`next()` receives subsequent complete replacements after committed catalog or
ordinary account changes. Hosts should drive the receiver while the account
screen is open, without exposing a refresh or per-chat synchronization action.

`paired_page(sequence, after_group_id_hex)` replaces the paired lane with a
bounded page. Use the installed sequence and returned opaque cursor. Ordinary
list ordering, paging and moderation remain owned by the ordinary window;
the paired cursor is not an ordinary list anchor.

`open_account_conversation_window(account_ref, group_id_hex, initial_rows)`
retains 1–128 chronological rows. `LocalMls` and `PairedSource` remain distinct
in both the header and rows. A local header carries the actual ordinary
revision and prepared presentation; a paired header is an observation, not
an invented ordinary group. `older_page(sequence, before)` uses the returned
chronological cursor and installed sequence. The ordinary event takes
precedence when both sources contain the same canonical message ID. Merged
local rows carry no ordinary window system-authentication proof, so their mapper
does not expose `group_system` as authoritative. Keep the ordinary conversation
owner for authenticated system content, prepared references and actions.

App applies account selection, current policy/generation checks, blocked
authors, expiry and deletion before exposing records. Committed changes and
retention deadlines refresh the view. Account reset, shutdown, cancellation
and relevant protected lifecycle changes terminate or refresh the owner;
reopen a terminal window rather than continuing to use its old sequence.

Commands and the receiver have independent ownership. `cancel()` retires the
original App handle synchronously and wakes a pending receive. Cancellation is
idempotent; dropping the native object also cancels. A previously returned
snapshot remains a value owned by its caller, so the host must clear displayed
data when closing or changing the account. No new consent is reconstructed
from that snapshot.

## Bounded local reads

`paired_chat_list_page` and `paired_chat_message_page` read at most 128 entries
from the current eligible source scopes. Message cursors contain canonical
event time and ID. Group IDs are nonempty opaque MLS bytes, including existing
16-byte IDs; account, device, digest and event identifiers retain their own
32-byte validation rules. These APIs read committed local observations and
do not initiate network synchronization.

Ordered media verdicts and Markdown display tokens accompany message records.
Their presence does not authorize downloading an attachment or applying
ordinary moderation to a paired copy. Preserve the existing authorized APIs
and original owners for those actions. Unsupported content kinds remain
explicit rather than being rendered as interpreted chat content.

## Native ownership and compatibility

Default builds return `AccountSharingUnsupported` before decoding query
inputs or opening an account worker. Experimental builds report invalid query,
not-ready, stale-window, closed, runtime-unavailable and invalid-record errors
through the existing typed binding errors. DTO debug output is redacted.

C window handles must be freed before their client. Blocking receives support
timeouts without consuming updates, and commands may run during a receive.
Every output is preflighted before effects. Each returned page or snapshot
owns its nested strings, rows and cursor; free it exactly once with its matching
root free function. Embedded entries have no independent free. Borrow input
cursors only while their owning page or snapshot remains alive, and never free
a handle concurrently with an active call.

These surfaces are additive and preserve ordinary invitation and chat wire
contracts. Source tests do not establish generated-language ABI, matched SDK
packaging, installed app adoption or a three-device demonstration.
