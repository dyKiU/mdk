#!/usr/bin/env python3
"""Run one unchanged normal f4 case, freeze its compiled binary, then diagnose it."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SOURCE = "f4d7da6f60bee6682e7e7524f6e1d91edefd7fe6"
TEST = "native_device_linking::automatic_pairing_acceptance::third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts"
FEATURES = "marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks"

def command(*args):
    return subprocess.check_output(args, text=True).strip()

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

assert command("git", "rev-parse", "HEAD") == SOURCE
assert os.environ["RUST_MIN_STACK"] == "4194304"
root = Path("pairing-f4-evidence")
root.mkdir()
args = ["--locked", "-p", "marmot-app", "--lib", "--features", FEATURES]
selected = "package(marmot-app) & binary(=marmot_app) & test(=" + TEST + ")"
started = __import__("time").monotonic()
inventory = json.loads(subprocess.check_output(["cargo", "nextest", "list", *args, "-E", selected, "--message-format", "json"], text=True))
compile_seconds = __import__("time").monotonic() - started
suites = [suite for suite in inventory["rust-suites"].values() if any(name == TEST and not case["ignored"] and case["filter-match"]["status"] == "matches" for name, case in suite["testcases"].items())]
assert len(suites) == 1 and suites[0]["package-name"] == "marmot-app"
binary = Path(suites[0]["binary-path"])
binary_hash = digest(binary)
(root / "inventory.json").write_text(json.dumps(inventory))
normal = subprocess.run(["cargo", "nextest", "run", *args, "-E", selected, "--profile", "m5-bounded", "--test-threads", "1", "--retries", "0", "--no-fail-fast"], capture_output=True, text=True)
output = re.sub(r"\x1b\[[0-9;]*m", "", normal.stdout + normal.stderr)
rows = re.findall(r"Summary\s+\[[^\]]*\]\s+(\d+)(?:/\d+)?\s+tests? run:\s*([^\n]*)", output)
assert len(rows) == 1 and rows[0][0] == "1", "one actual unchanged normal execution required"
def count(label):
    match = re.search(r"(\d+) " + label, rows[0][1])
    return int(match[1]) if match else 0
normal_proof = {"source": SOURCE, "source_tree": command("git", "rev-parse", "HEAD^{tree}"), "binary_sha256": binary_hash, "compile_seconds": compile_seconds, "selected_nonignored": 1, "passed": count("passed"), "failed": count("failed"), "exit_code": normal.returncode, "rust_min_stack_bytes": 4194304, "retries": 0, "test_threads": 1, "qualification_scope": "One unchanged original regression only; independent of later debugger-influenced diagnosis"}
(root / "normal-result.json").write_text(json.dumps(normal_proof, indent=2) + "\n")
assert normal_proof["passed"] + normal_proof["failed"] == 1
archive = root / "tests.tar.zst"
packaged = subprocess.run(["cargo", "nextest", "archive", *args, "--archive-file", str(archive)], capture_output=True, text=True)
assert packaged.returncode == 0 and digest(binary) == binary_hash
rebuild = bool(re.search(r"^\s*Compiling\s", re.sub(r"\x1b\[[0-9;]*m", "", packaged.stdout + packaged.stderr), re.M))
proof = {"source": SOURCE, "source_tree": normal_proof["source_tree"], "features": FEATURES, "toolchain": command("rustc", "--version"), "build_profile": "test (unoptimized)", "nextest_profile": "m5-bounded", "rust_min_stack_bytes": 4194304, "selector": TEST, "binary_sha256": binary_hash, "archive_sha256": digest(archive), "unexpected_rebuild": rebuild, "producer_run": int(os.environ["GITHUB_RUN_ID"])}
(root / "provenance.json").write_text(json.dumps(proof, indent=2) + "\n")
assert not rebuild, "do not silently profile a rebuilt binary"
subprocess.run([sys.executable, os.environ["RUNNER_TEMP"] + "/pairing-cpu.py", "--inventory", str(root / "inventory.json"), "--archive", str(archive), "--provenance", str(root / "provenance.json"), "--report", str(root / "cpu-result.json")], check=True)
