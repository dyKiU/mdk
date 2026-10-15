#!/usr/bin/env python3
"""One normal regression and same-binary fourth-phase CPU diagnostic, remote only."""
import collections
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import tarfile
import tempfile
import threading
import time

BASELINE = "cd61ea2a14711d15072f77d7a0adc233ccef60ea"
TEST = "native_device_linking::automatic_pairing_acceptance::third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts"
FEATURES = "marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks"
ARGS = ["--locked", "-p", "marmot-app", "--lib", "--features", FEATURES]
os.umask(0o077)
root = Path("current-perf-evidence")
root.mkdir()
report = {"source": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(), "product_baseline": BASELINE,
          "source_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip(),
          "diagnostic_only": True, "qualification_passed": False, "selector": TEST, "features": FEATURES,
          "rust_min_stack_bytes": 4194304, "test_threads": 1, "automatic_retries": 0,
          "profile": "normal unoptimized test; no profiling build or Rust flag changes",
          "marker_detection_lag": "unknown; marker observed through a pipe, not assumed to equal emission time",
          "cpu_scope": "whole owned test process; synchronous CPU samples, no per-account attribution"}
def digest(path):
    with Path(path).open("rb") as source:
        value = hashlib.sha256()
        for block in iter(lambda: source.read(1024*1024), b""): value.update(block)
        return value.hexdigest()
def save():
    (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")
def finish(reason):
    report["disposition"] = reason
    report["diagnostic_complete"] = True
    save()
    raise SystemExit(0)
def ticks(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError): return None

def stop_perf(process):
    if process is not None and process.poll() is None:
        subprocess.run(["sudo", "-n", "/bin/kill", "-INT", "--", "-" + str(process.pid)], capture_output=True, timeout=5)
        try: process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            subprocess.run(["sudo", "-n", "/bin/kill", "-KILL", "--", "-" + str(process.pid)], capture_output=True, timeout=5)
            process.communicate(timeout=5)

def body(binary, perf=None, capture=None):
    proof = {"profiled": perf is not None, "markers": [], "panic_locations": [], "original_phase_assertion": False}
    process = subprocess.Popen([str(binary), "--exact", TEST, "--nocapture", "--test-threads=1"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
    lines = queue.Queue()
    def pump():
        for line in process.stdout: lines.put((time.monotonic(), line))
        lines.put((time.monotonic(), None))
    threading.Thread(target=pump, daemon=True).start()
    started = time.monotonic()
    sampler = None
    start_cpu = None
    end_cpu = None
    try:
        while True:
            if time.monotonic() - started > 300:
                os.killpg(process.pid, signal.SIGKILL)
                proof["watchdog_triggered"] = True
                break
            try: at, raw = lines.get(timeout=0.1)
            except queue.Empty: continue
            if raw is None: break
            line = re.sub(r"\x1b\[[0-9;]*m", "", raw)
            marker = re.search(r"automatic-enrollment-control stage=([a-z-]+)", line)
            if marker and marker[1] in {"third-device-completion", "fourth-device-completion", "fourth-device-completed"}:
                proof["markers"].append(marker[1])
                if marker[1] == "fourth-device-completion":
                    proof["phase_start_detected_monotonic"] = at
                    start_cpu = ticks(process.pid)
                    if perf is not None:
                        sampler = subprocess.Popen(["sudo", "-n", perf, "record", "--clockid", "mono", "-e", "cpu-clock:u", "-F", "49", "--call-graph", "fp", "-p", str(process.pid), "-o", str(capture)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                        proof["perf_launch_monotonic"] = time.monotonic()
                elif marker[1] == "fourth-device-completed":
                    proof["phase_end_detected_monotonic"] = at
                    end_cpu = ticks(process.pid)
                    stop_perf(sampler)
            if "automatic pairing did not reach required phase:" in line:
                proof["original_phase_assertion"] = True
                proof["phase_end_detected_monotonic"] = at
                end_cpu = ticks(process.pid)
                stop_perf(sampler)
            for file, number, column in re.findall(r"panicked at (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)", line):
                proof["panic_locations"].append({"file": file, "line": int(number), "column": int(column)})
            summary = re.search(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", line)
            if summary:
                proof.update(passed=int(summary[1]), failed=int(summary[2]), ignored=int(summary[3]))
                proof["executed_nonignored"] = proof["passed"] + proof["failed"]
        process.wait(timeout=15)
    finally:
        stop_perf(sampler)
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
    proof["exit_code"] = process.returncode
    proof["whole_body_wall_seconds"] = time.monotonic() - started
    if "phase_start_detected_monotonic" in proof and "phase_end_detected_monotonic" in proof:
        proof["phase_wall_seconds_observed"] = proof["phase_end_detected_monotonic"] - proof["phase_start_detected_monotonic"]
        proof["phase_cpu_seconds_observed"] = end_cpu - start_cpu if end_cpu is not None and start_cpu is not None else None
    proof["perf_exit_code"] = sampler.returncode if sampler is not None else None
    return proof

assert os.environ["RUST_MIN_STACK"] == "4194304"
assert json.loads(Path("perf-evidence/result.json").read_text())["feasible"]
assert not subprocess.check_output(["git", "diff", BASELINE, "HEAD", "--", "crates", "Cargo.toml", "Cargo.lock"]), "normal product/test source must match latest qualified main baseline"
assert not os.environ.get("RUSTFLAGS"), "no profiling Rust flags"
report["compile_environment"] = {key: os.environ.get(key) for key in ["CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "RUSTFLAGS"]}
report["toolchain"] = subprocess.check_output(["rustc", "--version"], text=True).strip()
report["cargo_lock_sha256"] = digest("Cargo.lock")
report["nextest_config_sha256"] = digest(".config/nextest.toml")
report["cargo_config_sha256"] = digest(".cargo/config.toml")
started = time.monotonic()
listing = subprocess.run(["cargo", "nextest", "list", *ARGS, "-E", "package(marmot-app) & test(=" + TEST + ")", "--message-format", "json"], capture_output=True, text=True)
report["compile_list_seconds"] = time.monotonic() - started
report["compile_exit_code"] = listing.returncode
save()
assert listing.returncode == 0, "normal exact test compilation failed; not behavioral RED"
inventory = json.loads(listing.stdout)
suites = [suite for suite in inventory["rust-suites"].values() if TEST in suite["testcases"]]
assert len(suites) == 1 and not suites[0]["testcases"][TEST]["ignored"]
binary = Path(suites[0]["binary-path"]).resolve()
report["selected_nonignored"] = 1
report["binary_sha256"] = digest(binary)
report["normal"] = body(binary)
save()
normal = report["normal"]
# Preserve genuine normal RED. Different stages/passes are evidence, not a reason
# to repeat the test until a desired fourth-phase trajectory appears.
if not (normal.get("executed_nonignored") == 1 and normal.get("passed") == 0 and normal.get("failed") == 1 and normal.get("ignored") == 0 and normal["original_phase_assertion"] and "fourth-device-completion" in normal["markers"]):
    finish("NormalControlDidNotEstablishFourthPhaseRed")
assert digest(binary) == report["binary_sha256"]
report["normal_fourth_red_verified"] = True
# Archive only compiled code + provenance, never runtime stores, raw logs, perf
# captures, credentials, account directories or SDK overlays.
(root / "provenance.json").write_text(json.dumps(report, indent=2) + "\n")
archive = root / "normal-test-binary.tar.gz"
with tarfile.open(archive, "w:gz") as output:
    output.add(binary, arcname="marmot-app-test", recursive=False)
    output.add(root / "provenance.json", arcname="provenance.json", recursive=False)
report["archive_sha256"] = digest(archive)
report["no_compilation_between_runs"] = True
save()
perf = shutil.which("perf")
assert perf is not None
with tempfile.TemporaryDirectory(prefix="owned-ordinary-perf-") as temporary:
    capture = Path(temporary) / "perf.data"
    try:
        report["profiled"] = body(binary, perf, capture)
        assert digest(binary) == report["binary_sha256"]
        if not capture.exists() or report["profiled"]["perf_exit_code"] != 0:
            finish("ActualProductPerfCaptureUnavailable")
        decoded = subprocess.run(["sudo", "-n", perf, "script", "-i", str(capture), "-F", "time,ip,sym"], capture_output=True, text=True, timeout=30)
        report["decode_exit_code"] = decoded.returncode
        if decoded.returncode != 0: finish("ActualProductPerfDecodeUnavailable")
        leaves = collections.Counter()
        callers = collections.Counter()
        namespaces = collections.Counter()
        owned_chains = collections.Counter()
        sample_times = []
        named = 0
        chains = 0
        owned = 0
        maximum_depth = 0
        undecodable = 0
        decoded_groups = 0
        outside_phase = 0
        for group in re.split(r"\n\s*\n", decoded.stdout):
            if not group.strip(): continue
            stamp = re.search(r"(?:^|\n)\s*(\d+\.\d+):", group)
            if not stamp:
                undecodable += 1
                continue
            decoded_groups += 1
            at = float(stamp[1])
            start = report["profiled"].get("phase_start_detected_monotonic")
            end = report["profiled"].get("phase_end_detected_monotonic")
            if start is None or end is None or not start <= at <= end:
                outside_phase += 1
                continue
            sample_times.append(at)
            symbols = []
            for line in group.splitlines():
                match = re.fullmatch(r"\s*(?:(?:\d+\.\d+):\s+)?[0-9a-fA-F]+\s+(.+?)\s*", line)
                if not match: continue
                value = re.sub(r"\s+\([^)]*\)$", "", match[1])
                value = re.sub(r"\+0x[0-9a-fA-F]+(?:/0x[0-9a-fA-F]+)?$", "", value)
                if value in {"[unknown]", "[kernel.kallsyms]"} or not re.search(r"[A-Za-z_]", value): continue
                # Static symbols only. No IPs, offsets, object paths, arguments,
                # locals, raw stacks or memory are exported.
                if len(value) > 512: value = value[:500] + "<truncated>"
                symbols.append(value)
            named += bool(symbols)
            chains += len(symbols) >= 2
            maximum_depth = max(maximum_depth, len(symbols))
            if symbols: leaves[symbols[0]] += 1
            found = []
            for name in symbols:
                prefix = name.lstrip("<").split("::", 1)[0]
                if prefix in {"marmot_app", "cgka_engine", "storage_sqlite", "transport_nostr_adapter", "cgka_session"}:
                    found.append(name)
                    namespaces[prefix] += 1
            if found:
                owned += 1
                callers[found[0]] += 1
                owned_chains[tuple(found[:4])] += 1
        report["phase_sampling"] = {"samples": len(sample_times), "named_samples": named, "callchain_samples": chains,
            "owned_caller_samples": owned, "maximum_depth": maximum_depth, "undecodable_groups": undecodable,
            "decoded_groups": decoded_groups, "outside_phase_groups": outside_phase,
            "first_sample_after_marker_detection_ms": (min(sample_times)-report["profiled"]["phase_start_detected_monotonic"])*1000 if sample_times else None,
            "sample_span_seconds": max(sample_times)-min(sample_times) if sample_times else None,
            "leaf_functions": [{"function": name, "samples": count} for name,count in leaves.most_common(30)],
            "nearest_owned_functions": [{"function": name, "samples": count} for name,count in callers.most_common(40)],
            "bounded_owned_function_chains": [{"functions_leaf_to_outer": list(names), "samples": count} for names,count in owned_chains.most_common(30)],
            "inclusive_namespace_frame_counts": dict(namespaces),
            "product_unwind_usable": len(sample_times) >= 20 and owned >= 20}
        finish("PhaseFunctionAttributionAvailable" if report["phase_sampling"]["product_unwind_usable"] else "ProductFpUnwindOrPhaseCoverageInsufficient")
    finally:
        # Deletes private raw perf.data and any alternate capture. Only bounded
        # static-function aggregates and the separate code archive survive.
        pass
