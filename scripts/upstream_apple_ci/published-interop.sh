#!/usr/bin/env bash
set -euo pipefail
test "$(uname -m)" = arm64
test "$(git -C ios rev-parse HEAD)" = "$IOS_SHA"
python3 scripts/upstream_apple_ci/install.py --packages packages \
  --source "$SOURCE_SHA" --run-id "$SDK_RUN_ID" --platform ios \
  --output "$RUNNER_TEMP/interop-experimental-sdk"
mkdir -p "$RUNNER_TEMP/published-assets" "$RUNNER_TEMP/interop-evidence"
gh release download marmotkit-v0.13.0 --repo marmot-protocol/mdk \
  --pattern MarmotKitFFI-0.13.0.xcframework.zip \
  --pattern MarmotKit-0.13.0.swift --pattern marmotkit-ios-0.13.0.manifest.json \
  --dir "$RUNNER_TEMP/published-assets"
python3 scripts/upstream_apple_ci/published-sdk.py --assets "$RUNNER_TEMP/published-assets" \
  --ios ios --output "$RUNNER_TEMP/interop-published-sdk"
cp "$RUNNER_TEMP/interop-published-sdk/published-provenance.json" "$RUNNER_TEMP/interop-evidence/"
bash ios/scripts/public-chat-acceptance/build.sh \
  "$RUNNER_TEMP/published-assets/MarmotKit-0.13.0.swift" \
  "$RUNNER_TEMP/interop-published-sdk/MarmotKit.xcframework/ios-arm64-simulator" \
  "$RUNNER_TEMP/published-worker" "$RUNNER_TEMP/published-worker-modules"
bash ios/scripts/public-chat-acceptance/build.sh \
  "$RUNNER_TEMP/interop-experimental-sdk/MarmotKit.swift" \
  "$RUNNER_TEMP/interop-experimental-sdk/MarmotKit.xcframework/ios-arm64-simulator" \
  "$RUNNER_TEMP/experimental-worker" "$RUNNER_TEMP/experimental-worker-modules"
runtime=$(xcrun simctl list runtimes --json | python3 -c 'import json,sys; r=[r for r in json.load(sys.stdin)["runtimes"] if r.get("isAvailable") and r["identifier"].startswith("com.apple.CoreSimulator.SimRuntime.iOS-26")]; print(max(r,key=lambda r:tuple(map(int,r["version"].split("."))))["identifier"])')
device_type=$(xcrun simctl list devices available --json | python3 -c 'import json,sys; rows=json.load(sys.stdin)["devices"].get(sys.argv[1], []); compatible=[r for r in rows if r.get("isAvailable") and r["name"].startswith("iPhone") and r.get("deviceTypeIdentifier")]; print(compatible[0]["deviceTypeIdentifier"])' "$runtime")
published_device=""
experimental_device=""
cleanup() {
  if [[ -f "$RUNNER_TEMP/published-interop-private/result.json" && ! -f "$RUNNER_TEMP/interop-evidence/result.json" ]]; then
    cp "$RUNNER_TEMP/published-interop-private/result.json" "$RUNNER_TEMP/interop-evidence/result.json"
  fi
  for device in "$published_device" "$experimental_device"; do
    if [[ -n "$device" ]]; then
      xcrun simctl shutdown "$device" || true
      xcrun simctl delete "$device" || true
    fi
  done
}
trap cleanup EXIT
published_device=$(xcrun simctl create "UpstreamPublished-$GITHUB_RUN_ID" "$device_type" "$runtime")
experimental_device=$(xcrun simctl create "UpstreamExperimental-$GITHUB_RUN_ID" "$device_type" "$runtime")
xcrun simctl boot "$published_device"
xcrun simctl boot "$experimental_device"
xcrun simctl bootstatus "$published_device" -b
xcrun simctl bootstatus "$experimental_device" -b
python3 scripts/upstream_apple_ci/observed-public-interop.py --scenario mixed-version \
  --published "$RUNNER_TEMP/published-worker" --experimental "$RUNNER_TEMP/experimental-worker" \
  --published-device "$published_device" --experimental-device "$experimental_device" \
  --relay-binary "$PWD/ios/build/TestRelay/debug/white-noise-sync-test-relay" \
  --port 18525 --output "$RUNNER_TEMP/published-interop-private"
cp "$RUNNER_TEMP/published-interop-private/result.json" "$RUNNER_TEMP/interop-evidence/result.json"
python3 - <<'PY'
import json,os
from pathlib import Path
root=Path(os.environ['RUNNER_TEMP'])/'interop-evidence'
value=json.loads((root/'result.json').read_text())
if value.get('passed') != 2 or value.get('failed') != 0:
    raise ValueError('Both published/experimental sponsor directions must execute')
value['experimental_sdk_sha']=os.environ['SOURCE_SHA']
value['sdk_run_id']=os.environ['SDK_RUN_ID']
value['ios_tools_sha']=os.environ['IOS_SHA']
value['workflow_tools_sha']=os.environ['GITHUB_SHA']
(root/'result.json').write_text(json.dumps(value,indent=2)+'\n')
PY
