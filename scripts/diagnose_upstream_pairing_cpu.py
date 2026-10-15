#!/usr/bin/env python3
"""Sample one immutable native test; export static leaf symbols and aggregates only."""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

SOURCE = "ef4e687c0ba5d92cd8ea1c5d1f97766534d97077"
PRODUCER = 38725598470
ARTIFACT = 11968357472
TEST = "native_device_linking::automatic_pairing_acceptance::third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get("RUST_MIN_STACK") == "4194304"
    inventory = json.loads(args.inventory.read_text())
    selected = [suite for suite in inventory["rust-suites"].values() if any(
        name == TEST and not case["ignored"] and case["filter-match"]["status"] == "matches"
        for name, case in suite["testcases"].items())]
    assert len(selected) == 1 and selected[0]["package-name"] == "marmot-app"
    assert selected[0]["binary-name"] == "marmot_app"
    binary = Path(selected[0]["binary-path"])
    provenance = json.loads(args.provenance.read_text())
    archive_hash = hashlib.file_digest(args.archive.open("rb"), "sha256").hexdigest()
    binary_hash = hashlib.file_digest(binary.open("rb"), "sha256").hexdigest()
    assert provenance["source"] == SOURCE and provenance["selector"] == TEST
    assert provenance["rust_min_stack_bytes"] == 4194304 and not provenance["unexpected_rebuild"]
    assert provenance["archive_sha256"] == archive_hash and provenance["binary_sha256"] == binary_hash
    candidates = [path for path in sorted(Path("/usr/lib/linux-tools").glob("*/perf")) if os.access(path, os.X_OK)]
    if shutil.which("perf"):
        candidates.append(Path(shutil.which("perf")))
    perf = None
    preflight = False
    version = None
    for candidate in candidates:
        control = subprocess.run(["sudo", "-n", str(candidate), "stat", "-e", "cpu-clock:u", "--", "/usr/bin/true"], capture_output=True, timeout=20)
        if control.returncode == 0:
            perf = str(candidate)
            preflight = True
            version = subprocess.check_output([perf, "--version"], text=True).strip()
            break
    report = {
        "source": SOURCE, "source_tree": provenance["source_tree"],
        "producer_run": PRODUCER, "artifact_id": ARTIFACT,
        "archive_sha256": archive_hash, "binary_sha256": binary_hash,
        "features": provenance["features"], "toolchain": provenance["toolchain"],
        "build_profile": provenance["build_profile"], "original_nextest_profile": provenance["nextest_profile"],
        "test": TEST, "selected_nonignored": 1, "rust_min_stack_bytes": 4194304,
        "automatic_retries": 0, "test_threads": 1, "diagnostic_watchdog_seconds": 220, "sampler": "perf software cpu-clock:u leaf-only 99Hz",
        "perf_version": version, "preflight_passed": preflight,
        "qualification_passed": False,
        "scope": "Sampler-influenced diagnostic only; original unchanged normal failure retained. Static symbols only, no callgraph memory capture.",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    if not preflight:
        report["blocker"] = "software-cpu-clock-preflight-unavailable"
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        raise SystemExit("Software CPU sampling unavailable; no test executed")
    raw_path = Path(os.environ["RUNNER_TEMP"]) / "owned-pairing-leaf.perf.data"
    command = ["sudo", "-n", "--preserve-env", perf, "record", "-q", "-e", "cpu-clock:u", "-F", "99", "-o", str(raw_path), "--", "/usr/bin/timeout", "--signal=TERM", "--kill-after=10s", "220s",
               "sudo", "-n", "--preserve-env", "-u", "#" + str(os.getuid()), "--",
               str(binary), "--exact", TEST, "--test-threads=1", "--nocapture"]
    try:
        # All inferior output remains memory-only and is never printed/uploaded.
        result = subprocess.run(command, capture_output=True, text=True, timeout=240)
        runtime = result.stdout + result.stderr
        started = bool(re.search(r"running 1 test\b", runtime))
        summary = re.search(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", runtime)
        script = subprocess.run(["sudo", "-n", perf, "script", "-i", str(raw_path), "-F", "sym"], capture_output=True, text=True, timeout=60)
        counts = collections.Counter()
        for line in script.stdout.splitlines():
            name = re.sub(r"\+0x[0-9a-fA-F]+(?:/0x[0-9a-fA-F]+)?$", "", line.strip())
            name = name.split("(", 1)[0].strip()
            if not name:
                continue
            if len(name) > 400 or re.search(r"0x[0-9a-fA-F]+", name) or not re.fullmatch(r"[A-Za-z0-9_:<>, &*~.$?{}\[\]#=+!;\-]+", name):
                name = "unavailable"
            counts[name] += 1
        report.update({
            "runtime_body_started": started, "sampler_exit_code": result.returncode,
            "runtime_summary": {"passed": int(summary[2]), "failed": int(summary[3]), "ignored": int(summary[4])} if summary else None,
            "sample_decode_passed": script.returncode == 0,
            "leaf_sample_count": sum(counts.values()),
            "static_symbol_aggregates": [{"function": name, "samples": count} for name, count in counts.most_common(100)],
            "unexported_symbol_count": max(0, len(counts) - 100),
            "diagnostic_complete": started and summary is not None and script.returncode == 0 and bool(counts),
        })
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        if not report["diagnostic_complete"]:
            raise SystemExit("Required exact-body runtime and static sample evidence unavailable")
    except subprocess.TimeoutExpired:
        report["blocker"] = "owned-sampler-timeout"
        report["diagnostic_complete"] = False
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        raise SystemExit("Owned sampler exceeded diagnostic bound")
    finally:
        # Only this helper's private profiler files are removed, never fixtures or caches.
        subprocess.run(["sudo", "-n", "rm", "-f", "--", str(raw_path), str(raw_path) + ".old"], check=False, capture_output=True)


if __name__ == "__main__":
    main()
