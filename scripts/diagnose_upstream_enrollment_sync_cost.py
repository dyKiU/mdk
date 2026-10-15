#!/usr/bin/env python3
"""Remote fixed synchronous bucket diagnostic; no raw runtime logs exported."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

BUCKETS = {'completed', 'sharing-context', 'completed-round-sql', 'sharing-decode', 'completed-facts-check', 'sharing-verify', 'sharing-roster', 'completed-tree-origin', 'candidate', 'roster', 'sharing-ed25519', 'completed-record-sql', 'successor', 'completed-leaf-proof', 'completed-facts-sql', 'sql-state-query', 'sql-state-decode', 'sql-state-validate', 'sql-read-consistency', 'sql-facts-whole', 'sql-facts-query-setup', 'sql-fact-decode', 'sql-fact-validate'}
KEYS = ["count", "cpu_ns", "wall_ns", "unknown_cpu", "cpu_reads", "cpu_read_failures", "active", "max_cpu_ns", "max_wall_ns", "byte_observations", "bytes_total", "max_bytes"]
PATTERN = re.compile(r"enrollment-sync-cost phase=(third|fourth) bucket=([a-z0-9-]+) " + " ".join(key+r"=(\d+)" for key in KEYS))
def parse_metric_lines(raw):
    rows = []
    seen = set()
    for line in raw.splitlines():
        if not line.startswith("enrollment-sync-cost phase="):
            continue
        match = PATTERN.fullmatch(line)
        if not match:
            raise ValueError("malformed bounded diagnostic row")
        phase,bucket,*numbers = match.groups()
        if bucket not in BUCKETS or (phase,bucket) in seen:
            raise ValueError("unknown or duplicate bounded diagnostic row")
        seen.add((phase,bucket))
        rows.append({"phase":phase,"bucket":bucket,**dict(zip(KEYS,map(int,numbers)))})
        if len(rows)>2*len(BUCKETS):
            raise ValueError("bounded diagnostic row count exceeded")
    return rows

def parser_preflight():
    recorder = Path("crates/traits/src/enrollment_sync_cost.rs").read_text()
    declared = recorder[recorder.index("const NAMES:"):recorder.index("static PHASE:")]
    declared = re.findall(r'"([a-z0-9-]+)"',declared)
    assert len(declared)==len(BUCKETS) and set(declared)==BUCKETS
    format_lines = [line for line in recorder.splitlines() if '"enrollment-sync-cost phase=' in line]
    assert len(format_lines)==1
    assert re.findall(r"([a-z_]+)=\{\}",format_lines[0])==KEYS
    lines = []
    expected = []
    for phase in ["third","fourth"]:
        for index,bucket in enumerate(sorted(BUCKETS)):
            metrics = {key:index+offset for offset,key in enumerate(KEYS)}
            lines.append("enrollment-sync-cost phase="+phase+" bucket="+bucket+" "+" ".join(key+"="+str(metrics[key]) for key in KEYS))
            expected.append({"phase":phase,"bucket":bucket,**metrics})
    assert parse_metric_lines("\n".join(lines))==expected
    malformed = [lines[0].replace("bucket="+sorted(BUCKETS)[0],"bucket=unknown-bucket"),lines[0].rsplit(" ",1)[0],lines[0].replace("count=0","count=invalid"),lines[0]+"\n"+lines[0]]
    for line in malformed:
        try:
            parse_metric_lines(line)
        except ValueError:
            continue
        raise AssertionError("invalid parser fixture accepted")
    receipt = {"parser_preflight_passed":True,"bucket_count":len(BUCKETS),"schema_keys":KEYS,"fabricated_rows":len(expected),"rejected_invalid_fixtures":len(malformed),"product_tests_executed":0}
    Path("cost-partition-parser.json").write_text(json.dumps(receipt,indent=2)+"\n")
    print(json.dumps(receipt))

if sys.argv[1:]==["--parser-preflight"]:
    parser_preflight()
    raise SystemExit(0)
assert not sys.argv[1:]

os.umask(0o077)
OUT = Path("sync-cost-evidence")
OUT.mkdir()
TEST = "native_device_linking::automatic_pairing_acceptance::third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts"
FEATURES = "marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks"
report = {"source": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
          "tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip(),
          "product_baseline": "3dde689febbe364b70af35ff778e3d74a6bc5622", "selector": TEST,
          "features": FEATURES, "diagnostic_only": True, "qualification_passed": False,
          "cpu_usable": False,
          "original_deadline_seconds": 15, "original_runtime_flavor": "current_thread",
          "stack_bytes": 4194304, "automatic_retries": 0,
          "cpu_scope": "synchronous calling-thread scheduled CPU only; never async await duration",
          "bucket_times": "roster/successor/candidate/completed/sharing-verify inclusive and NONADDITIVE; completed stage and sharing stage siblings partition their respective measured work; facts-whole includes query stepping/decode/validation; query-setup excludes iterator stepping; nested callee costs still overlap; probe overhead included",
          "schedstat_resolution": "kernel accounting resolution and zero-delta quantization unknown; no precision guarantee or overhead subtraction",
          "observer_overhead": "two proc schedstat reads and bounded mutex counters per active completed span plus bounded per-blob size counters; not subtracted",
          "compile_environment": {key: os.environ.get(key) for key in ["CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "RUSTFLAGS"]}}
def save(): (OUT/"result.json").write_text(json.dumps(report, indent=2)+"\n")
def inputs():
    files = subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\0")
    manifest = hashlib.sha256()
    count = 0
    for name in sorted(value for value in files if value):
        path = Path(name)
        content = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
        manifest.update(name.encode()+b"\0"+hashlib.sha256(content).digest())
        count += 1
    return {"tracked_count": count, "manifest_sha256": manifest.hexdigest(),
            "tracked_pristine": subprocess.run(["git", "diff", "--quiet", "HEAD"]).returncode==0}
assert os.environ.get("GITHUB_ACTIONS")=="true" and os.environ.get("GITHUB_SHA")==report["source"]
assert os.environ.get("CARGO_INCREMENTAL")=="1" and not os.environ.get("CARGO_ENCODED_RUSTFLAGS") and not os.environ.get("RUSTC_BOOTSTRAP")
report["inputs_before"] = inputs()
save()
report["diagnostic_source_hashes"] = {name: hashlib.sha256(Path(name).read_bytes()).hexdigest()
    for name in subprocess.check_output(["git", "diff", "--name-only", report["product_baseline"], "HEAD"], text=True).splitlines()}
assert os.environ["RUST_MIN_STACK"] == "4194304" and not os.environ.get("RUSTFLAGS")
report["toolchain"] = subprocess.check_output(["rustc", "--version"], text=True).strip()
report["lock_sha256"] = hashlib.sha256(Path("Cargo.lock").read_bytes()).hexdigest()
start = time.monotonic()
listing = subprocess.run(["cargo", "nextest", "list", "--locked", "-p", "marmot-app", "--lib", "--features", FEATURES, "-E", "test(="+TEST+")", "--message-format", "json"], capture_output=True, text=True)
report.update(compile_seconds=time.monotonic()-start, compile_exit_code=listing.returncode)
report["inputs_after_compile"] = inputs()
if listing.returncode:
    report["compile_error_codes"] = sorted(set(re.findall(r"error\[(E[0-9]+)\]", listing.stderr)))
    report["compile_locations"] = sorted(set(re.findall(r"--> (crates/[A-Za-z0-9_./-]+\.rs:[0-9]+:[0-9]+)", listing.stderr)))[:20]
    save()
    raise SystemExit(1)
inventory = json.loads(listing.stdout)
suites = [suite for suite in inventory["rust-suites"].values() if TEST in suite["testcases"]]
assert len(suites)==1 and not suites[0]["testcases"][TEST]["ignored"]
report["selected_nonignored"] = 1
binary = Path(suites[0]["binary-path"])
report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
save()
start = time.monotonic()
try:
    result = subprocess.run([str(binary), "--exact", TEST, "--nocapture", "--test-threads=1"], capture_output=True, text=True, timeout=300)
except subprocess.TimeoutExpired:
    report["watchdog_triggered"] = True
    save()
    raise SystemExit(1)
report.update(body_seconds=time.monotonic()-start, body_exit_code=result.returncode)
raw = result.stdout+result.stderr
summary = re.search(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", raw)
if summary:
    report.update(passed=int(summary[1]), failed=int(summary[2]), ignored=int(summary[3]))
    report["executed_nonignored"] = report["passed"]+report["failed"]
report["original_phase_assertion"] = "automatic pairing did not reach required phase:" in raw
report["panic_locations"] = [{"file": file, "line": int(line), "column": int(column)} for file,line,column in re.findall(r"panicked at (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)", raw)]
report["markers"] = re.findall(r"automatic-enrollment-control stage=((?:third|fourth)-device-complet(?:ion|ed))", raw)
report["phase_boundaries"] = [{"phase": phase, "arm_conflict": conflict=="true", "panicking": panic=="true"} for phase,conflict,panic in re.findall(r"enrollment-sync-cost-boundary phase=(third|fourth) arm_conflict=(true|false) panicking=(true|false)", raw)]
report["inputs_after_execution"] = inputs()
report["inputs_pristine"] = (report["inputs_before"]==report["inputs_after_compile"]==report["inputs_after_execution"] and report["inputs_after_execution"]["tracked_pristine"])
save()
try:
    rows = parse_metric_lines(raw)
except Exception as error:
    # Retain actual body/phase evidence; exception messages may contain raw data.
    report["parser_exception"] = type(error).__name__
    report["synchronous_buckets"] = []
    report["cpu_usable"] = False
    report["diagnostic_complete"] = False
    save()
    raise SystemExit(1)
report["synchronous_buckets"] = rows
report["diagnostic_complete"] = (report["inputs_pristine"] and report.get("executed_nonignored")==1 and report.get("ignored")==0
    and bool(report["phase_boundaries"]) and all(not item["arm_conflict"] for item in report["phase_boundaries"])
    and len(rows)==23*len(report["phase_boundaries"])
    and all(item["active"]==0 for item in rows)
    and all({item["bucket"] for item in rows if item["phase"]==boundary["phase"]}==BUCKETS for boundary in report["phase_boundaries"]))
expected_phases = {marker.split("-", 1)[0] for marker in report["markers"] if marker.endswith("-completion")}
observed_phases = [boundary["phase"] for boundary in report["phase_boundaries"]]
report["phase_coverage_valid"] = (set(observed_phases)==expected_phases and len(observed_phases)==len(expected_phases))
report["sql_probe_presence"] = []
for phase in observed_phases:
    phase_rows = {item["bucket"]:item for item in rows if item["phase"]==phase}
    presence = {"phase":phase,
        "all_sql_buckets_observed": all(phase_rows.get(bucket,{}).get("count",0)>0 for bucket in BUCKETS if bucket.startswith("sql-")),
        "state_blob_sizes_observed": phase_rows.get("sql-state-decode",{}).get("byte_observations",0)>0 and phase_rows.get("sql-state-decode",{}).get("bytes_total",0)>0,
        "fact_blob_sizes_observed": phase_rows.get("sql-fact-decode",{}).get("byte_observations",0)>0 and phase_rows.get("sql-fact-decode",{}).get("bytes_total",0)>0}
    report["sql_probe_presence"].append(presence)
report["sql_probes_observed"] = bool(report["sql_probe_presence"]) and all(item["all_sql_buckets_observed"] and item["state_blob_sizes_observed"] and item["fact_blob_sizes_observed"] for item in report["sql_probe_presence"])
report["cpu_usable"] = (report["diagnostic_complete"] and report["phase_coverage_valid"]
    and report["sql_probes_observed"]
    and all(item["unknown_cpu"]==0 and item["cpu_read_failures"]==0 and item["active"]==0 and item["cpu_reads"]==2*item["count"] for item in rows))
report["cpu_usable_limits"] = "collection validity only; kernel resolution/zero-delta quantization and probe overhead remain unknown; bucket call cohorts differ, so do not subtract global nested totals"
save()
raise SystemExit(0 if report["diagnostic_complete"] else 1)
