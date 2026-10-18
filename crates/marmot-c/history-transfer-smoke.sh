#!/usr/bin/env bash
# Matched debug host ABI checks; no release packaging or live-history acceptance.
set -euo pipefail
cd "$(dirname "$0")/../.."
selected="$(python3 crates/marmot-uniffi/marmotkit_features.py csv)"
if [[ -n "$selected" ]]; then
  cargo build --locked -p marmot-c --features "$selected"
else
  cargo build --locked -p marmot-c
fi
target="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
case "$(uname -s)" in
  Darwin) libs=(-lm -pthread -framework Security -framework CoreFoundation -liconv) ;;
  *) libs=(-lm -pthread -ldl) ;;
esac
for linkage in shared static; do
  if [[ "$linkage" == shared ]]; then link=(-L"$target" -lmarmot_c); else link=("$target/libmarmot_c.a" "${libs[@]}"); fi
  cc -std=c11 -Wall -Wextra -Werror -I crates/marmot-c/include \
    crates/marmot-c/examples/history_transfer_smoke.c "${link[@]}" -o "$work/smoke-$linkage"
  mkdir -m 700 "$work/home-$linkage"
  DYLD_LIBRARY_PATH="$target" LD_LIBRARY_PATH="$target" \
    "$work/smoke-$linkage" "$work/home-$linkage" "${EXPERIMENTAL_DEVICE_SYNC:-0}"
done
