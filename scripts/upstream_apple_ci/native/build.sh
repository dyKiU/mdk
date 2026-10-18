#!/bin/bash
set -euo pipefail
if [[ $# != 2 ]]; then echo 'usage: build.sh validated-sdk-output output-binary' >&2; exit 2; fi
sdk=$(cd "$1" && pwd)
out=$2
script_dir=$(cd "$(dirname "$0")" && pwd)
native="$sdk/macos/MarmotKit.xcframework/macos-arm64"
test -r "$sdk/MarmotKit.swift"
test -r "$native/libmarmot_uniffi.a"
mkdir -p "$(dirname "$out")"
set --
if [[ "${NATIVE_HISTORY_ACCEPTANCE:-0}" == 1 ]]; then set -- -D NATIVE_HISTORY_ACCEPTANCE; fi
if [[ "${NATIVE_HISTORY_RECIPIENT_QUERY:-0}" == 1 ]]; then
  if [[ "${NATIVE_HISTORY_ACCEPTANCE:-0}" != 1 ]]; then
    echo 'recipient query requires native history acceptance and matching SDK bindings' >&2
    exit 2
  fi
  set -- "$@" -D NATIVE_HISTORY_RECIPIENT_QUERY
fi
if [[ "${NATIVE_AUTOMATIC_ACCEPTANCE:-0}" == 1 ]]; then set -- "$@" -D NATIVE_AUTOMATIC_ACCEPTANCE; fi
if [[ "${NATIVE_ACCOUNT_DEPARTURE_ACCEPTANCE:-0}" == 1 ]]; then
  test "${NATIVE_AUTOMATIC_ACCEPTANCE:-0}" == 1 || { echo 'departure requires automatic acceptance and matching SDK bindings' >&2; exit 2; }
  set -- "$@" -D NATIVE_ACCOUNT_DEPARTURE_ACCEPTANCE
fi
if [[ "${NATIVE_DEVICE_REVOCATION_ACCEPTANCE:-0}" == 1 ]]; then
  set -- "$@" -D NATIVE_DEVICE_REVOCATION_ACCEPTANCE
fi
if [[ "${NATIVE_ONE_SCAN_ACCEPTANCE:-0}" == 1 ]]; then
  test "${NATIVE_AUTOMATIC_ACCEPTANCE:-0}" == 1 || { echo 'one-scan requires automatic acceptance and matching SDK bindings' >&2; exit 2; }
  set -- "$@" -D NATIVE_ONE_SCAN_ACCEPTANCE
fi
if [[ -n "${NATIVE_MODULE_CACHE_PATH:-}" ]]; then
  test -d "$NATIVE_MODULE_CACHE_PATH"
  set -- "$@" -module-cache-path "$NATIVE_MODULE_CACHE_PATH"
fi
if [[ "${NATIVE_PAIRING_QR_ACCEPTANCE:-0}" == 1 ]]; then
  test -r "${NATIVE_PAIRING_QR_CODEC_SOURCE:?Actual unchanged app codec source required}"
  set -- "$@" -D NATIVE_PAIRING_QR_ACCEPTANCE -D WN_EXPERIMENTAL_DEVICE_SYNC \
    "$script_dir/PairingQRControls.swift" "$NATIVE_PAIRING_QR_CODEC_SOURCE"
fi
xcrun swiftc "$@" -swift-version 5 -parse-as-library -target arm64-apple-macosx15.0 \
  -I "$native/Headers" "$sdk/MarmotKit.swift" "$script_dir/Acceptance.swift" "$script_dir/Agent.swift" "$script_dir/StoreControls.swift" \
  "$native/libmarmot_uniffi.a" -framework Security -framework SystemConfiguration \
  -framework CoreFoundation -framework Network -lc++ -o "$out"
