# Hosted app fixture counterparts

These helpers prepare real native stores and run existing gated app tests on a
single hosted Apple runner. They do not claim cross-host, physical-device,
installed-production-app or full-history equivalence. They are prepared source;
qualification requires actual execution against the final matching SDK.

Build both agents from the same validated SDK producer and derived native source.
Install the iOS package as `SDK` and Mac package as `SDK/macos` with `install.py`.
Use `prepare-hosted-agent.py --output DERIVED`, then the unchanged
`DERIVED/build.sh SDK MAC_AGENT` and
`build-hosted-simulator-agent.sh SDK DERIVED SIM_AGENT`. Set the existing automatic,
one-scan, history, recipient-query, departure and revocation compile flags to 1.
The simulator helper also requires `SOURCE_SHA`, `SDK_RUN_ID` and an existing
`NATIVE_MODULE_CACHE_PATH`; it records SDK/source inputs before compilation and
requires unchanged inputs afterward. Reuse these agents across the fixture cases
for that exact cohort. Never copy an account store between platforms.

Prebuild the actual app products before creating a live native bridge. Preserve
that build's source/SDK receipt. Use the job-owned, booted simulator named
`WN-Upstream-UI-$GITHUB_RUN_ID`. Run the iOS external UI attach control (one unit
and one UI test, zero skips) before fixture UI cases. The native QR app-codec test
is separate and needs `WN_NATIVE_PAIRING_QR_ACCEPTANCE=1` with the same owned relay.

The controller CLI is:

```text
python3 scripts/upstream_apple_ci/hosted-app-fixtures.py
  --scenario automatic-switch|imported-reader|source-picker|source-transfer|recipient-transfer
  --platform macos|ios-simulator
  --mac-agent ABS --mac-sha SHA256 --sim-agent ABS --sim-sha SHA256
  --simulator UUID --relay ABS
  --sdk-source EXACT_SHA --sdk-run-id PRODUCER_RUN
  --base NEW_ABSOLUTE_PRIVATE_BASE
  --environment NEW_PRIVATE_ENVIRONMENT_JSON
  --application-command EXISTING_PRIVATE_COMMAND_JSON
  --app-result-bundle NEW_ABSOLUTE_UNIT_XCRESULT
  --output NEW_AGGREGATE_JSON_OUTSIDE_BASE
```

The mode-0600 command file contains `{"argv":[...]}` with an explicit executable
and arguments, never a shell string. The controller exclusively creates the
private environment file before invoking that command. Its bridge is
`BASE/private-bridge`. Pass those two paths to the prebuilt test runner; fixture
variables must enter the selected xctestrun target's `EnvironmentVariables`.
All app tests retain their existing assertions and deadlines. The controller owns
relay port 18181; do not start `test-with-relay.sh` inside the command.

For existing non-UI model/pane tests, use `hosted-app-unit.py` as the command:

```text
python3 scripts/upstream_apple_ci/hosted-app-unit.py
  --platform macos|ios-simulator --source APP --source-commit EXACT_APP_SHA
  --sdk-package APP_SDK_PACKAGE --sdk-source EXACT_SDK_SHA
  --products PREBUILT_PRODUCTS --xctestrun ORIGINAL_PLAN
  --selector EXISTING_SUITE/EXISTING_TEST --environment PRIVATE_ENVIRONMENT_JSON
  --destination EXACT_DESTINATION --developer-dir SELECTED_XCODE_DEVELOPER_DIR
  --prefix FRESH_REPORT_PREFIX --result-bundle NEW_UNIT_XCRESULT
```

This runner selects one allowlisted existing test, preserves original plan
metadata/environment, freezes source/SDK/products/plans and uses only
`test-without-building`. It requires exactly one native pass and zero failures or
skips. The calling CI build receipt still establishes compilation provenance;
freezing prebuilt products alone does not prove which source compiled them.
For iOS public-button tests, use `hosted-app-ui.py --stage run` with its successful
frozen build receipt; it independently requires one unit and one UI pass. A Mac
external button driver is a separate prerequisite, not replaced by model calls.

| Fixture scenario | Actual native counterpart and handoff |
| --- | --- |
| `automatic-switch` | Real prepair ordinary message, explicit first/third enrollment and sharing, exact paired message on B/C; all four native workers close before the app reopens C. |
| `imported-reader` | Real selected-chat membership and explicit original history transfer; all native workers close before an observation-only descriptor lets the app read B's committed import. |
| `source-picker` | Same closed B fixture plus two distinct actual Core recipient observations; the app queries Core again and creates/cancels its own fresh original. Use distinct fixture runs for model and external-button tests. |
| `source-transfer` | Source A closes before the app opens that same original root. Native B explicitly approves its newly received original; immutable review fields, final receipt, exact imported record/provenance, live precedence and empty nonrecipient archive are checked. |
| `recipient-transfer` | B closes with no pending original before the app opens B. Native A creates a fresh original only after app readiness; the app explicitly approves it. Mac recipient runs use an actual simulator-native iOS source. After app retirement, a fresh native reader reopens B without reconstructing approval and verifies the committed import. |

All native iOS fixture roots originate through `simctl spawn` using the simulator
agent. Other native roles use Mac agents. The app test helper accepts only private
runner-owned direct children of the explicit CI base, matching SDK/run/agent and
platform metadata, the existing marker and a positively closed producer. The
legacy dedicated-host guards remain in place. Metadata carries observations;
consent and authority must still originate from fresh SDK factories.

Upload only aggregate controller/unit/UI reports, input hashes and SDK/source
provenance. Do not upload fixture descriptors, environment files, credential
files, private logs, worker IPC, stores or native-fixture XCResults/screenshots.
On success, private stores are retired only after positive native closure and app
runner exit. Failed closure/forced app termination remains a failure and defers
private cleanup to the ephemeral runner; it never qualifies a fixture.
