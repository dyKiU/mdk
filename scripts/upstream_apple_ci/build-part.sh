#!/usr/bin/env bash
set -euo pipefail
part=${1:?Apple input part required}
test "$(git rev-parse HEAD)" = "$SOURCE_SHA"
test "$SOURCE_SHA" = "$WORKFLOW_HEAD_SHA"
test -z "$(git status --porcelain --untracked-files=no)"
test "$(uname -m)" = arm64
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
