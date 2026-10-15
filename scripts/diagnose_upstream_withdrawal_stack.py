#!/usr/bin/env python3
"""Diagnose one archived runtime failure; export only function names and counts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

TEST = (
    "native_device_linking::tests::automatic_forwarding_non_admin_acceptance::"
    "automatic_nonadmin_leave_withdraws_mirrors_without_turning_local_hide_into_departure"
)
SOURCE = "3090a323ae823de6b213eb60561aec7031f276bc"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get("RUST_MIN_STACK") == "4194304", "Original stack budget required"
    inventory = json.loads(args.inventory.read_text())
    selected = [
        suite
        for suite in inventory["rust-suites"].values()
        if any(
            name == TEST
            and case["filter-match"]["status"] == "matches"
            and not case["ignored"]
            for name, case in suite["testcases"].items()
        )
    ]
    assert len(selected) == 1, "Exactly one intended nonignored body required"
    suite = selected[0]
    assert suite["package-name"] == "marmot-app" and suite["binary-name"] == "marmot_app"
    binary = Path(suite["binary-path"])
    assert binary.is_file(), "Persistent archive extraction must provide the exact binary"
    commands = [
        "set pagination off",
        "set confirm off",
        "set startup-with-shell off",
        "set debuginfod enabled off",
        "set print thread-events off",
        "set print frame-arguments none",
        "set print entry-values no",
        "set print address off",
        "handle SIGPIPE nostop noprint pass",
        "handle SIGSEGV stop print nopass",
        "handle SIGABRT stop print nopass",
        "run",
        "bt 60",
    ]
    command = ["gdb", "--batch", "--quiet", "--nx"]
    for item in commands:
        command.extend(["-ex", item])
    command.extend(["--args", str(binary), "--exact", TEST, "--test-threads=1", "--nocapture"])
    # Raw debugger output remains memory-only and is never printed or uploaded.
    # In particular, do not export paths, argument values, stores or test output.
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        raw = result.stdout + result.stderr
        returncode = result.returncode
        timed_out = False
    except subprocess.TimeoutExpired:
        raw = ""
        returncode = None
        timed_out = True
    signals = re.findall(r"received signal (SIGSEGV|SIGABRT)\b", raw)
    frames = []
    for line in raw.splitlines():
        match = re.match(r"^#(\d+)\s+(.+)$", line)
        if not match:
            continue
        name = re.sub(r"^0x[0-9a-fA-F]+\s+(?:in\s+)?", "", match[2])
        name = name.split(" at ", 1)[0].split(" from ", 1)[0].split("(", 1)[0].strip()
        # Fail closed rather than export unrecognized debugger text or paths.
        if not re.fullmatch(r"[A-Za-z0-9_:<>, &*~.$?{}\[\]#=+!-]+", name):
            name = "unavailable"
        frames.append({"index": int(match[1]), "function": name})
        if len(frames) == 60:
            break
    started = bool(re.search(r"running 1 test\b", raw)) and TEST in raw
    complete = started and bool(signals) and bool(frames) and not timed_out
    report = {
        "source": SOURCE,
        "producer_run": 38681649626,
        "artifact_id": 11949746329,
        "archive_sha256": hashlib.file_digest(args.archive.open("rb"), "sha256").hexdigest(),
        "test": TEST,
        "selected_nonignored_tests": 1,
        "runtime_body_started": started,
        "runtime_signal": signals[-1] if signals else None,
        "debugger_exit_code": returncode,
        "diagnostic_timeout": timed_out,
        "rust_min_stack_bytes": 4194304,
        "automatic_retries": 0,
        "test_threads": 1,
        "frames": frames,
        "frame_count": len(frames),
        "diagnostic_complete": complete,
        "qualification_passed": False,
        "scope": "Function-only debugger evidence for the unchanged archived runtime failure; a successful diagnostic job is not a passing test.",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if not complete:
        raise SystemExit("Required exact-body runtime signal and function-only frames were not obtained")


if __name__ == "__main__":
    main()
