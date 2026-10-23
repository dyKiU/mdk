#!/usr/bin/env bash
# Matched host Swift ABI checks; no Apple packaging or enrollment claim.
set -euo pipefail
cd "$(dirname "$0")/../.."
command -v swiftc >/dev/null
selected_features="$(python3 crates/marmot-uniffi/marmotkit_features.py csv)"
build_features="cli${selected_features:+,$selected_features}"
cargo build --locked -p marmot-uniffi --features "$build_features"
smoke_target="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
case "$(uname -s)" in
  Darwin) smoke_library="$smoke_target/libmarmot_uniffi.dylib" ;;
  Linux) smoke_library="$smoke_target/libmarmot_uniffi.so" ;;
  *) echo 'Host Swift smoke requires macOS or Linux' >&2; exit 2 ;;
esac
smoke_dir="$(mktemp -d)"
trap 'rm -rf "$smoke_dir"' EXIT
"$smoke_target/uniffi-bindgen" generate --library "$smoke_library" --language swift --out-dir "$smoke_dir"
cat "$smoke_dir/marmot_uniffi.swift" crates/marmot-uniffi/tests/device_linking_smoke.swift > "$smoke_dir/CombinedSmoke.swift"
swiftc -parse-as-library -I "$smoke_dir" -Xcc "-fmodule-map-file=$smoke_dir/marmot_uniffiFFI.modulemap" \
  -L "$smoke_target" -lmarmot_uniffi "$smoke_dir/CombinedSmoke.swift" -o "$smoke_dir/smoke"
DYLD_LIBRARY_PATH="$smoke_target" LD_LIBRARY_PATH="$smoke_target" "$smoke_dir/smoke"
