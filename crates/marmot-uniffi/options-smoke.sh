#!/usr/bin/env bash
# Native runtime options defaults, callbacks, and construction. This does not package Apple/Android artifacts.
set -euo pipefail
cd "$(dirname "$0")/../.."
smoke_language="${1:-swift}"
case "$smoke_language" in
  swift) command -v swiftc >/dev/null ;;
  kotlin)
    command -v kotlinc >/dev/null
    : "${MDK_KOTLIN_CLASSPATH:?Supply JNA with native libraries, Android platform, annotations, and coroutines jars}"
    ;;
  *) echo 'Usage: options-smoke.sh swift|kotlin' >&2; exit 2 ;;
esac
cargo build -p marmot-uniffi --features cli --locked
smoke_target="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
case "$(uname -s)" in
  Darwin) smoke_library="$smoke_target/libmarmot_uniffi.dylib" ;;
  Linux) smoke_library="$smoke_target/libmarmot_uniffi.so" ;;
  *) echo 'Native smoke runner supports macOS and Linux' >&2; exit 2 ;;
esac
smoke_dir="$(mktemp -d)"
trap 'rm -rf "$smoke_dir"' EXIT
"$smoke_target/uniffi-bindgen" generate --library "$smoke_library" --language "$smoke_language" --out-dir "$smoke_dir"
if [[ "$smoke_language" == swift ]]; then
  cat "$smoke_dir/marmot_uniffi.swift" crates/marmot-uniffi/tests/options_smoke.swift > "$smoke_dir/CombinedSmoke.swift"
  swiftc -parse-as-library -I "$smoke_dir" -Xcc "-fmodule-map-file=$smoke_dir/marmot_uniffiFFI.modulemap" \
    -L "$smoke_target" -lmarmot_uniffi "$smoke_dir/CombinedSmoke.swift" -o "$smoke_dir/smoke"
  DYLD_LIBRARY_PATH="$smoke_target" LD_LIBRARY_PATH="$smoke_target" "$smoke_dir/smoke"
else
  kotlinc "$smoke_dir/dev/ipf/marmotkit/marmot_uniffi.kt" crates/marmot-uniffi/tests/options_smoke.kt \
    -cp "$MDK_KOTLIN_CLASSPATH" -include-runtime -d "$smoke_dir/smoke.jar"
  java -Djna.library.path="$smoke_target" -cp "$smoke_dir/smoke.jar:$MDK_KOTLIN_CLASSPATH" \
    dev.ipf.marmotkit.Options_smokeKt
fi
# Optional qualification receipt, emitted only after the real host program exits successfully.
if [[ -n "${MDK_OPTIONS_SMOKE_RECEIPT:-}" ]]; then
  python3 - "$MDK_OPTIONS_SMOKE_RECEIPT" "$smoke_language" "$smoke_library" "$smoke_dir" <<'PY'
import hashlib,json,os,subprocess,sys
from pathlib import Path
output,language,library,generated=sys.argv[1:]
root=Path(generated)
binding=root/('marmot_uniffi.swift' if language=='swift' else 'dev/ipf/marmotkit/marmot_uniffi.kt')
files=[binding]+([root/'marmot_uniffiFFI.h',root/'marmot_uniffiFFI.modulemap'] if language=='swift' else [])
assert all(p.is_file() for p in files)
record={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
 'language':language,'build_argv':['cargo','build','-p','marmot-uniffi','--features','cli','--locked'],
 'selected_features':['cli'],'default_features':True,'experimental_device_sync':False,
 'host_program_exit_code':0,'generated_files_sha256':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
 'host_library_sha256':hashlib.sha256(Path(library).read_bytes()).hexdigest(),
 'compiler_environment':{k:os.environ.get(k) for k in ['CARGO_INCREMENTAL','CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS']}}
Path(output).write_text(json.dumps(record,indent=2)+'\n')
PY
fi
