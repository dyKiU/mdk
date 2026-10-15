#!/usr/bin/env bash
set -euo pipefail
test "$(uname -m)" = arm64
python3 - <<'PY'
import hashlib,json
from pathlib import Path
root=Path('scripts/upstream_apple_ci/native')
proof=json.loads((root/'SOURCE.json').read_text())
if proof['workspace_commit'] != 'be04fc60b6a4c40bd85423fbf9e35e8982ae4b84':
    raise ValueError('Native acceptance source changed')
for name, expected in proof['files'].items():
    if hashlib.sha256((root/name).read_bytes()).hexdigest() != expected:
        raise ValueError('Vendored native acceptance bytes changed')
PY
python3 scripts/upstream_apple_ci/install.py --packages packages --source "$SOURCE_SHA" \
  --run-id "$SDK_RUN_ID" --platform ios --output "$RUNNER_TEMP/one-scan-sdk"
python3 scripts/upstream_apple_ci/install.py --packages packages --source "$SOURCE_SHA" \
  --run-id "$SDK_RUN_ID" --platform macos --output "$RUNNER_TEMP/one-scan-sdk/macos"
export NATIVE_AUTOMATIC_ACCEPTANCE=1 NATIVE_ONE_SCAN_ACCEPTANCE=1
export NATIVE_HISTORY_ACCEPTANCE=1 NATIVE_HISTORY_RECIPIENT_QUERY=1
export NATIVE_ACCOUNT_DEPARTURE_ACCEPTANCE=1 NATIVE_DEVICE_REVOCATION_ACCEPTANCE=1
python3 scripts/upstream_apple_ci/prepare-hosted-agent.py --output "$RUNNER_TEMP/one-scan-agent-source"
bash "$RUNNER_TEMP/one-scan-agent-source/build.sh" "$RUNNER_TEMP/one-scan-sdk" "$RUNNER_TEMP/one-scan-agent"
agent_sha=$(shasum -a 256 "$RUNNER_TEMP/one-scan-agent" | cut -d ' ' -f 1)
python3 scripts/upstream_apple_ci/hosted_one_scan.py --agent "$RUNNER_TEMP/one-scan-agent" \
  --agent-provenance "$RUNNER_TEMP/one-scan-agent-source/DERIVED-SOURCE.json" \
  --agent-sha256 "$agent_sha" --relay "$PWD/ios/build/TestRelay/debug/white-noise-sync-test-relay" \
  --sdk-source "$SOURCE_SHA" --output "$RUNNER_TEMP/hosted-one-scan" --port 18535 \
  --contacts --three-device-chats --direct-chats
