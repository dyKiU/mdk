# Hosted upstream Apple qualification

The `Upstream experimental Apple qualification` workflow builds one immutable
experimental Apple SDK cohort and consumes it in clean checkouts of the exact
Mac and iOS candidate commits. Dispatch it on the intended
`ci/upstream-develop-dy-*` branch with full `mdk_sha`, `mac_sha` and `ios_sha`
inputs. The MDK source and workflow commit must match. It creates Actions
artifacts and isolated test hosts only: no tags, releases, deployment or
installation on user devices.

The workflow also bootstraps directly from qualification PRs when this workflow
or its supporting subtree changes. In PR mode, `cohort.json` pins the exact Mac
and iOS candidates; all jobs use those validated immutable identities and the
actual MDK PR head. The PR must target master, and its recorded base must be an
ancestor of its head so GitHub's synthetic merge cannot introduce different
source or workflow inputs. Reconcile an advanced base on the candidate before
retrying. This mode does not require adding private workflow files to master.

The existing MDK builders produce the four inputs. Assembly verifies their
source, builder, run, feature and compiler provenance before running native
artifact and Swift consumer checks. `qualification.json` records complete
native/header/Swift/privacy inventories and package checksums. `install.py`
validates those inventories before installing a temporary app overlay, then
invokes the app's own independently maintained device-sync guard. These local
SDK overlays and binaries must never be committed.

Both full experimental app suites consume the same SDK packages. Mac also runs
its experimental Release build and static analysis. The existing published SDK
PR suites remain separate gates. XCResult summaries retain actual execution
counts and skips; a skipped scenario does not establish acceptance.

The native job compiles the canonical workspace harness recorded in
`native/SOURCE.json` and verifies every vendored file's hash first. It runs real
one-scan pairing, history, existing/new direct chat discovery, contacts and
offline recovery through independent synthetic stores and an owned loopback
relay on one hosted Mac. Only aggregate results are uploaded; private IPC,
runtime roots, signing credentials and message contents remain on the ephemeral
runner. The imported controller modules retain their original cross-host
functions, but this workflow does not invoke them or access M5.

This single-host SDK evidence does not qualify installed application UI,
physical phones, APNS, cross-host/simulator topology, or interoperability with
a published client. Full backend, mutation and required additional acceptance
gates remain necessary before promotion to `upstream/develop_dy`.
