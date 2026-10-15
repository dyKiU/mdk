#!/usr/bin/env python3
"""Freeze exact previously failed 92e binary, then perform one influenced diagnosis."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SOURCE = "92e125d70cfe991038d20b92f060f33007b3afe7"
TEST = "native_device_linking::automatic_pairing_acceptance::third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts"
FEATURES = "marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks"

def command(*args):
    return subprocess.check_output(args, text=True).strip()

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

assert command("git", "rev-parse", "HEAD") == SOURCE
assert os.environ["RUST_MIN_STACK"] == "4194304"
root = Path("pairing-92e-evidence")
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
archive = root / "tests.tar.zst"
packaged = subprocess.run(["cargo", "nextest", "archive", *args, "--archive-file", str(archive)], capture_output=True, text=True)
assert packaged.returncode == 0 and digest(binary) == binary_hash
rebuild = bool(re.search(r"^\s*Compiling\s", re.sub(r"\x1b\[[0-9;]*m", "", packaged.stdout + packaged.stderr), re.M))
symbols = subprocess.check_output(["nm", "-C", str(binary)], text=True)
sections = subprocess.check_output(["readelf", "-S", str(binary)], text=True)
preflight = {"rust_app_symbols": sum("marmot_app::" in line for line in symbols.splitlines()), "rust_engine_symbols": sum("cgka_engine::" in line for line in symbols.splitlines()), "eh_frame_present": ".eh_frame" in sections}
proof = {"source": SOURCE, "source_tree": command("git", "rev-parse", "HEAD^{tree}"), "binary_preflight": preflight, "compile_or_cached_list_seconds": compile_seconds, "cargo_lock_sha256": digest(Path("Cargo.lock")), "nextest_config_sha256": digest(Path(".config/nextest.toml")), "compile_environment": {key: os.environ.get(key) for key in ["CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG"]}, "features": FEATURES, "toolchain": command("rustc", "--version"), "build_profile": "test (unoptimized)", "nextest_profile": "m5-bounded", "rust_min_stack_bytes": 4194304, "selector": TEST, "binary_sha256": binary_hash, "archive_sha256": digest(archive), "unexpected_rebuild": rebuild, "producer_run": int(os.environ["GITHUB_RUN_ID"])}
(root / "provenance.json").write_text(json.dumps(proof, indent=2) + "\n")
assert not rebuild, "do not silently profile a rebuilt binary"
subprocess.run([sys.executable, os.environ["RUNNER_TEMP"] + "/pairing-cpu.py", "--inventory", str(root / "inventory.json"), "--archive", str(archive), "--provenance", str(root / "provenance.json"), "--report", str(root / "cpu-result.json")], check=True)
