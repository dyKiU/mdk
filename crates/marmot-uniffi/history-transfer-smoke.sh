#!/usr/bin/env bash
# Matched host ABI only; no artifact packaging or original history acceptance.
set -euo pipefail
cd "$(dirname "$0")/../.."
selected="$(python3 crates/marmot-uniffi/marmotkit_features.py csv)"
cargo build --locked -p marmot-uniffi --features "cli${selected:+,$selected}"
target="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
case "$(uname -s)" in
  Darwin) library="$target/libmarmot_uniffi.dylib" ;;
  Linux) library="$target/libmarmot_uniffi.so" ;;
  *) exit 2 ;;
esac
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
"$target/uniffi-bindgen" generate --library "$library" --language swift --out-dir "$work"
cat "$work/marmot_uniffi.swift" crates/marmot-uniffi/tests/history_transfer_smoke.swift > "$work/Combined.swift"
swiftc -parse-as-library -I "$work" -Xcc "-fmodule-map-file=$work/marmot_uniffiFFI.modulemap" \
  -L "$target" -lmarmot_uniffi "$work/Combined.swift" -o "$work/smoke"
DYLD_LIBRARY_PATH="$target" LD_LIBRARY_PATH="$target" "$work/smoke"
