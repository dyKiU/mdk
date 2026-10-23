#!/usr/bin/env bash
set -euo pipefail
python3 scripts/upstream_apple_ci/install.py --packages packages --source "$SOURCE_SHA" \
  --run-id "$SDK_RUN_ID" --platform ios --output "$RUNNER_TEMP/pagination-sdk"
python3 scripts/upstream_apple_ci/install.py --packages packages --source "$SOURCE_SHA" \
  --run-id "$SDK_RUN_ID" --platform macos --output "$RUNNER_TEMP/pagination-sdk/macos"
export NATIVE_AUTOMATIC_ACCEPTANCE=1 NATIVE_ONE_SCAN_ACCEPTANCE=1
export NATIVE_HISTORY_ACCEPTANCE=1 NATIVE_HISTORY_RECIPIENT_QUERY=1
export NATIVE_ACCOUNT_DEPARTURE_ACCEPTANCE=1 NATIVE_DEVICE_REVOCATION_ACCEPTANCE=1
python3 scripts/upstream_apple_ci/prepare-hosted-agent.py --history-pagination --output "$RUNNER_TEMP/pagination-agent-source"
bash "$RUNNER_TEMP/pagination-agent-source/build.sh" "$RUNNER_TEMP/pagination-sdk" "$RUNNER_TEMP/pagination-agent"
agent_sha=$(shasum -a 256 "$RUNNER_TEMP/pagination-agent" | cut -d ' ' -f 1)
python3 scripts/upstream_apple_ci/hosted_history.py --agent "$RUNNER_TEMP/pagination-agent" \
  --agent-sha256 "$agent_sha" --relay "$PWD/ios/build/TestRelay/debug/white-noise-sync-test-relay" \
  --sdk-source "$SOURCE_SHA" --output "$RUNNER_TEMP/hosted-history-pagination-evidence" --port 18516 \
  --agent-provenance "$RUNNER_TEMP/pagination-agent-source/DERIVED-SOURCE.json" \
  --scenarios pagination
