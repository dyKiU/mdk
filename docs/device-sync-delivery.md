# Experimental device-sync delivery

This branch reconciles the qualified 1,810-file source checkpoint onto MDK
f8b5552 plus the separately committed upstream 7692e266/076841eb prerequisites.
The original dirty checkout and untested actor129/local-producer drafts were
preserved separately and are excluded.

## Dependency source

`vendor/openmls-retained-own` is the exact source archive of signed local commit
`98666ed02d254ff6e2cc7d88f756d3701703be16`. The adjacent JSON records every source
hash; `openmls-retained-own-commit.txt` preserves the signed commit object. The
MIT license remains in the archive. All five direct OpenMLS dependencies use
relative paths; the sixth companion serialization-helper dependency resolves
inside that same library workspace. Registry versions remain locked. The archive preserves existing upstream
whitespace in fixtures/documentation; `git diff --check` is clean for the MDK
overlay and packaging files, with inherited vendor whitespace reported separately.

This source has not been published to a remote fork. It is not the older live
12e8 implementation. Its retained-own feature is default off: actual retained
receipt presence selects strict verification; receipt absence selects ordinary
stock own-pending validation, including lifetime checks. Verification errors
never fall back to a weaker path. Replace the whole family together after a
reviewed upstream/fork publication and repeat encrypted old-writer/reopen tests.

## Qualification and limits

The reconciled Rust files match the independently verified qualified checkpoint.
Recent focused gates passed: received proposal validation8, real observer3,
feature all-target Core/Session/App Clippy, default all-target checks and format.
Earlier cumulative request13/Core29, filtered App120/Session26, real relay SDK
settlement and acquisition/reissue controls remain separate historical gates;
no full-workspace or full App pass is asserted. Default checks retain the known
unused `published_events_snapshot` fixture warning.

The portable packaging passed locked resolution, default and experimental
Core/Session/App all-target checks, the expired own-commit reconciliation test
(1/1), genuine SDK/WebSocket proposal validation (1/1), and workspace format on
M5 with Rust1.97.1. See `device-sync-delivery-verification.json` for commands,
counts and terminal log hashes. No generated bindings, native artifact, installed application,
live database, release bump, push or interoperability claim is included.

Two-device SDK/MLS settlement is qualified. Later all-current-leaf enrollment,
atomic sibling/recipient transition, App actor129 retention/backpressure and
native runtime exports remain incomplete. Received proposals and endorsements
are authenticated metadata, never reconstructed SDK consent or native grants.
The known full third-device test remains a preserved expected failure at the
recipient bootstrap boundary.
