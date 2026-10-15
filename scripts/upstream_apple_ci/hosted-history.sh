#!/usr/bin/env bash
set -euo pipefail
python3 scripts/upstream_apple_ci/install.py --packages packages --source "$SOURCE_SHA" \
  --run-id "$SDK_RUN_ID" --platform ios --output "$RUNNER_TEMP/history-sdk"
python3 scripts/upstream_apple_ci/install.py --packages packages --source "$SOURCE_SHA" \
  --run-id "$SDK_RUN_ID" --platform macos --output "$RUNNER_TEMP/history-sdk/macos"
export NATIVE_AUTOMATIC_ACCEPTANCE=1 NATIVE_ONE_SCAN_ACCEPTANCE=1
export NATIVE_HISTORY_ACCEPTANCE=1 NATIVE_HISTORY_RECIPIENT_QUERY=1
export NATIVE_ACCOUNT_DEPARTURE_ACCEPTANCE=1 NATIVE_DEVICE_REVOCATION_ACCEPTANCE=1
bash scripts/upstream_apple_ci/native/build.sh "$RUNNER_TEMP/history-sdk" "$RUNNER_TEMP/history-agent"
agent_sha=$(shasum -a 256 "$RUNNER_TEMP/history-agent" | cut -d ' ' -f 1)
python3 scripts/upstream_apple_ci/hosted_history.py --agent "$RUNNER_TEMP/history-agent" \
  --agent-sha256 "$agent_sha" --relay "$PWD/ios/build/TestRelay/debug/white-noise-sync-test-relay" \
  --sdk-source "$SOURCE_SHA" --output "$RUNNER_TEMP/hosted-history-evidence" --port 18515
