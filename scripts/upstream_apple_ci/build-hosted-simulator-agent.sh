#!/usr/bin/env bash
set -euo pipefail
# Simulator counterpart of frozen native/build.sh; same sources and flags,
# linked only against the already validated matching simulator SDK slice.
if [[ $# != 3 ]]; then
  echo 'usage: build-hosted-simulator-agent.sh validated-sdk-output derived-native-source output-binary' >&2
  exit 2
fi
sdk=$(cd "$1" && pwd)
source_dir=$(cd "$2" && pwd)
out=$3
native="$sdk/MarmotKit.xcframework/ios-arm64-simulator"
test -r "$sdk/MarmotKit.swift"
test -r "$native/libmarmot_uniffi.a"
test -r "$source_dir/DERIVED-SOURCE.json"
module_cache="${NATIVE_MODULE_CACHE_PATH:?Use the existing task simulator module cache}"
mkdir -p "$module_cache" "$(dirname "$out")"
flags=()
for flag in NATIVE_AUTOMATIC_ACCEPTANCE NATIVE_ONE_SCAN_ACCEPTANCE NATIVE_HISTORY_ACCEPTANCE \
  NATIVE_HISTORY_RECIPIENT_QUERY NATIVE_ACCOUNT_DEPARTURE_ACCEPTANCE NATIVE_DEVICE_REVOCATION_ACCEPTANCE; do
  if [[ "${!flag:-0}" == 1 ]]; then flags+=(-D "$flag"); fi
done
python3 - "$sdk" "$source_dir" "$out.inputs.json" <<'PYTHON'
import hashlib
import json
import os
from pathlib import Path
import sys
sdk, source, destination = map(Path, sys.argv[1:])
manifest = json.loads((sdk / 'manifest.json').read_text())
if (manifest['source_sha'] != manifest['builder_sha']
        or manifest['source_sha'] != os.environ['SOURCE_SHA']
        or str(manifest['workflow_run_id']) != os.environ['SDK_RUN_ID']
        or manifest['features'] != ['otlp-export', 'product-analytics-export', 'experimental-device-sync']):
    raise ValueError('Matching validated simulator SDK required')
provenance = json.loads((source / 'DERIVED-SOURCE.json').read_text())
hashes = {}
for name, row in provenance['files'].items():
    path = source / name
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != row['derived_sha256']:
        raise ValueError('Derived native source changed')
    hashes[str(path)] = actual
for path in [sdk / 'manifest.json', sdk / 'MarmotKit.swift',
             sdk / 'MarmotKit.xcframework/ios-arm64-simulator/libmarmot_uniffi.a',
             sdk / 'MarmotKit.xcframework/ios-arm64-simulator/Headers/marmot_uniffiFFI.h']:
    hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
with destination.open('x') as output:
    json.dump({'sdk_source': manifest['source_sha'], 'sdk_run_id': str(manifest['workflow_run_id']),
               'platform': 'ios-simulator', 'inputs': hashes}, output, indent=2)
PYTHON
sysroot=$(xcrun --sdk iphonesimulator --show-sdk-path)
xcrun swiftc "${flags[@]}" -swift-version 5 -parse-as-library -target arm64-apple-ios18.0-simulator \
  -sdk "$sysroot" -module-cache-path "$module_cache" -I "$native/Headers" \
  "$sdk/MarmotKit.swift" "$source_dir/Acceptance.swift" "$source_dir/Agent.swift" \
  "$source_dir/StoreControls.swift" "$native/libmarmot_uniffi.a" \
  -framework Security -framework SystemConfiguration -framework CoreFoundation \
  -framework Network -lc++ -o "$out"
codesign --force --sign - "$out"
python3 - "$out" <<'PYTHON'
import hashlib
import json
from pathlib import Path
import sys
binary = Path(sys.argv[1])
proof = json.loads(Path(str(binary) + '.inputs.json').read_text())
for name, expected in proof['inputs'].items():
    if hashlib.sha256(Path(name).read_bytes()).hexdigest() != expected:
        raise ValueError('Native simulator input changed during compilation')
proof['inputs_unchanged'] = True
proof['agent_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
with Path(str(binary) + '.provenance.json').open('x') as output:
    json.dump(proof, output, indent=2)
    output.write('\n')
PYTHON
