# Account-wide sharing approval

These experimental default-off controls forward original App-owned approvals.
They establish a durable account-wide policy between authenticated paired devices;
source support is not proof of automatic chat presentation, forwarding delivery,
generated-language ABI, or installed-app acceptance.

For a newly verified pair, display that pairing shares existing and future chats,
history, and messaging, then invoke `continue_linking_and_share_chats` on the
same original session at its displayed revision. Ordinary `continue_linking`
retains its narrower pairing scope. Existing-device endorsement is a separate
original action; approval of one pair must not silently authorize another pair.

For an already completed pair, obtain `account_chat_sharing_targets`, select an
actual current public device identity, and begin one `begin_account_chat_sharing`
original. Display its broad scope before calling `approve`. The other device
observes its addressed original through `pending_account_chat_sharing` and must
approve that original at its displayed revision. These are account/device setup
controls; no per-chat action is required by the scope. Target observation and
pending polling do not grant permission.

Retain the opaque owner throughout review. Shared clones alias the same owner;
releasing the last alias cancels unfinished work. Cancellation does not revoke a
completed policy. Preserve the account selection and displayed revision across
asynchronous operations. Treat Unsupported, NotReady, Closed, StaleRevision and
RuntimeUnavailable as typed failures. Never reconstruct approval from device
bytes, booleans, snapshots, stored policies or transfer packets.

App/Core revalidate the actual protected roster, original ownership, retained
approval epoch and revocation state. Stable approved policy facts do not restore
an expired channel, keys, nonce counters or deadline. Removed and subsequently
re-added devices require fresh explicit approval. Keep device identities and
private packet contents out of diagnostic logs.

The C ABI adds opaque aliases, list-owned entries, root-owned targets/snapshots,
and appended status values 121–125. Use each matching deep-free, clone retained
list entries first, and ship the matching generated header/native library.
Swift/Kotlin consumers require matched generated bindings and native libraries.
