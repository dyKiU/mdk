#!/usr/bin/env bash
set -euo pipefail
part=${1:?Apple input part required}
test "$(git rev-parse HEAD)" = "$SOURCE_SHA"
test "$SOURCE_SHA" = "$WORKFLOW_HEAD_SHA"
test -z "$(git status --porcelain --untracked-files=no)"
test "$(uname -m)" = arm64
python3 - "$part" <<'PY_CAPACITY'
import hashlib, json, os, shutil, sys
from pathlib import Path
minimum = 8 * 1024**3
paths = [Path.cwd(), Path(os.environ.get('CARGO_TARGET_DIR', 'target')).resolve(),
         Path(os.environ['RUNNER_TEMP']).resolve()]
observations = []
for path in paths:
    while not path.exists():
        path = path.parent
    usage = shutil.disk_usage(path)
    observations.append({'path': str(path), 'free_bytes': usage.free, 'total_bytes': usage.total})
record = {'source_sha': os.environ['SOURCE_SHA'], 'part': sys.argv[1],
          'minimum_free_bytes': minimum, 'volumes': observations,
          'cargo_incremental': os.environ.get('CARGO_INCREMENTAL'),
          'cargo_lock_sha256': hashlib.sha256(Path('Cargo.lock').read_bytes()).hexdigest(),
          'cleanup_performed': False}
record['passed'] = record['cargo_incremental'] == '1' and all(row['free_bytes'] >= minimum for row in observations)
Path('apple-capacity-preflight.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record, sort_keys=True), flush=True)
if not record['passed']:
    raise SystemExit('Apple input requires incremental=1 and eight GiB available on each build volume')
PY_CAPACITY
toolchain=$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)
rustup toolchain install "$toolchain" --profile minimal
rustup default "$toolchain"
export MARMOTKIT_WORKSPACE_DIR=$PWD
export MARMOTKIT_CRATE_DIR=$PWD/crates/marmot-uniffi
export BUILDER_SHA=$SOURCE_SHA
mkdir -p stage
case "$part" in
  swift)
    bash crates/marmot-uniffi/xcframework.sh generate
    cp crates/marmot-uniffi/build/ios/swift/* stage/
    ;;
  macos)
    bash crates/marmot-uniffi/xcframework-macos.sh native
    cp target/aarch64-apple-darwin/release/libmarmot_uniffi.a stage/
    ;;
  ios-device|ios-simulator)
    target=aarch64-apple-ios
    if [[ "$part" == ios-simulator ]]; then target=aarch64-apple-ios-sim; fi
    bash crates/marmot-uniffi/xcframework.sh native "$target"
    cp "target/$target/release/libmarmot_uniffi.a" stage/
    ;;
  *) exit 2 ;;
esac
python3 crates/marmot-uniffi/build-provenance.py record "$part" stage/build-provenance.json
git diff --exit-code
