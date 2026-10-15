# Supplemental acceptance using an existing Apple SDK

`Upstream supplemental native acceptance` runs only for pushes to dedicated
`ci/upstream-acceptance-*` branches or an explicit manual dispatch. Opening its
review PR does not trigger a second supplemental run. The committed
`acceptance-cohort.json` supplies exact SDK producer, SDK source and app commit
identities for push mode. Manual inputs can specify a different immutable
cohort explicitly.

The Linux preparation job waits for the named artifact from the existing SDK
producer. It does not dispatch, rebuild, cancel or retry that producer. The
Apple jobs validate its package provenance using the original producer run ID
and source SHA; the supplemental workflow/tool commit remains a distinct
identity. These helpers do not change any running qualification checkout.

The five hosted lanes establish separate evidence:

- Published 0.13.0 versus experimental iOS SDK interoperability: separately
  compiled simulator workers on two isolated simulators, independent accounts,
  invitation receipt/acceptance, authenticated messages in both directions,
  original-store restart, offline messages and offline invitations. The published
  native archive must match the app's immutable release checksum and the
  generated Swift must match the pinned app source.
- Hosted native history and lifecycle scenarios from `hosted_history.py`, using
  unchanged committed acceptance helpers with their recorded source hashes.
- The final iOS full experimental suite with the same existing SDK, followed by
  a missing-German-translation mutant against two already built native catalog
  tests. Exact catalog bytes are restored before the passing controls. Empty
  filtered runs or compile failures do not count as mutation detection.
- The final Mac full experimental suite, Release build and static analysis,
  consuming the existing matching Mac SDK package.
- The original one-scan native scenarios, including existing/new direct chats,
  discovery, history and offline recovery, using the original frozen controller
  and the same existing SDK source. Producer identity remains the original
  `sdk_run_id`, even when that producer's obsolete app jobs were cancelled.

Only aggregate native/controller results and provenance are uploaded. Native
worker IPC, private stderr, credential keys and account stores are excluded.
The final iOS XCTest result bundle and its execution summary are retained as
standard app-test evidence. The simulator and native SDK journeys establish no
installed TestFlight UI, physical-device or APNS claim. See the hosted history
result's explicit remaining limitations before treating a scenario as qualified.
