# Exact-device revocation

`begin_device_revocation(account_ref, target_device)` creates one original administrator review from fresh authenticated Core state. The target is an exact 32-byte device identity and is only a selector. The factory captures the protected group and relevant ordinary groups; explicit `approve(revision)` removes that device's occupied leaf, preserving other same-account leaves. Approval revalidates the held original, current group lineage, and displayed revision. No review record or stored completion can create another action.

Hold the returned `DeviceRevocation` object throughout review and approval. `snapshot()` returns the captured target, protected group, ordinary groups, completed groups, revision and whole-scope completion. Group identifiers are opaque MLS IDs encoded as hex. Partial `completed_group_ids_hex` entries describe confirmed group work; they do not imply unfinished groups are revoked. Protected removal follows ordinary removals. A failure may retain confirmed progress under the same original; query its current snapshot before retrying the displayed revision. Cancellation does not undo already confirmed removals.

`cancel()` permanently retires the original. Shared foreign aliases retain the same App owner: dropping one alias preserves other aliases, while dropping the last alias retires it. Account shutdown, cancellation and the original fixed 600-second deadline fence later approval. The runtime bounds original actions and captured groups to 128; no call renews the acquisition deadline or rebuilds permission after restart. Default builds return `DeviceRevocationUnsupported` before input/account effects.

The API exposes no general linked-device inventory. `device_linking_targets` returns protected selectors/counts, while `history_transfer_recipients` observes only eligible devices for a selected ordinary chat. Neither creates revocation permission. A settings-wide target picker requires a separate authenticated inventory query; do not substitute pasted secret material or infer devices from cached review records.

## C ownership

`marmot_begin_device_revocation` clears the required output before reading foreign inputs. Experimental target length must be exactly 32 bytes. C calls block through the callback-safe runtime dispatcher; invoke them off the UI thread. `marmot_device_revocation_clone` retains the same original. Release each alias exactly once using `marmot_device_revocation_free`, and never free concurrently with a call. Explicit cancellation affects every alias.

`marmot_device_revocation_snapshot_free` deep-frees the owned target buffer and every captured/completed group string. Snapshot fields are observations, not borrowed handles. Frees accept NULL. Status values 126–132 append the seven revocation errors after account-sharing statuses121–125 without changing earlier values. Use matching generated Swift/Kotlin source or C header and library from one feature/source cohort.

Source tests and host ABI validation do not constitute installed Mac/iOS revocation acceptance or shipment of a regenerated Apple SDK.
