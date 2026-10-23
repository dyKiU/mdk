#!/usr/bin/env bash
set -euo pipefail
test "$(git rev-parse HEAD)" = "$SOURCE_SHA"
test "$SOURCE_SHA" = "$WORKFLOW_HEAD_SHA"
export BUILDER_SHA=$SOURCE_SHA
export MARMOTKIT_WORKSPACE_DIR=$PWD
export MARMOTKIT_CRATE_DIR=$PWD/crates/marmot-uniffi
crate=$MARMOTKIT_CRATE_DIR
toolchain=$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)
rustup toolchain install "$toolchain" --profile minimal
rustup default "$toolchain"
mkdir -p "$crate/build/ios/swift" "$crate/build/macos/swift"
cp inputs/swift/* "$crate/build/ios/swift/"
cp inputs/swift/* "$crate/build/macos/swift/"
for item in macos ios-device ios-simulator; do
  case "$item" in
    macos) target=aarch64-apple-darwin ;;
    ios-device) target=aarch64-apple-ios ;;
    ios-simulator) target=aarch64-apple-ios-sim ;;
  esac
  mkdir -p "target/$target/release"
  cp "inputs/$item/libmarmot_uniffi.a" "target/$target/release/"
done
python3 "$crate/build-provenance.py" verify macos inputs/swift/build-provenance.json inputs/macos/build-provenance.json
python3 "$crate/build-provenance.py" verify ios inputs/swift/build-provenance.json inputs/ios-device/build-provenance.json inputs/ios-simulator/build-provenance.json
# Verification exports the compilers observed by input jobs, not this assembler.
while IFS= read -r setting; do export "$setting"; done < "$GITHUB_ENV"
bash "$crate/xcframework-macos.sh" assemble
bash "$crate/xcframework.sh" assemble
cmp "$crate/output/MarmotKit.swift" "$crate/output/macos/MarmotKit.swift"
bash "$crate/validate-macos-artifact.sh" "$crate/output/macos/MarmotKit.xcframework" 15.0
bash "$crate/validate-ios-artifact.sh" "$crate/output/MarmotKit.xcframework" 18.0
bash "$crate/validate-swift-package-macos.sh" "$crate/output/macos/MarmotKit.xcframework" - "$crate/output/macos/MarmotKit.swift"
bash "$crate/validate-swift-package.sh" "$crate/output/MarmotKit.xcframework" - "$crate/output/MarmotKit.swift"
id=$(python3 scripts/upstream_apple_ci/sdk_profiles.py release-id "$SOURCE_SHA")
mkdir -p packages
bash "$crate/package-macos-artifacts.sh" "$id" "$id" "$SOURCE_SHA" dist "$SOURCE_SHA"
bash "$crate/package-ios-artifacts.sh" "$id" "$id" "$SOURCE_SHA" dist "$SOURCE_SHA"
python3 scripts/upstream_apple_ci/package-evidence.py
git diff --exit-code
