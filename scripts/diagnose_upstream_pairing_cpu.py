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
import select
import signal
import subprocess

SOURCE = "ef4e687c0ba5d92cd8ea1c5d1f97766534d97077"
PRODUCER = 38725598470
ARTIFACT = 11968357472
TEST = "native_device_linking::automatic_pairing_acceptance::third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts"


def record_owned(perf, command, raw_path):
    """Attach before exec, without an inferior credential transition or callgraph."""
    control_path = raw_path.with_suffix(".control")
    ack_path = raw_path.with_suffix(".ack")
    os.mkfifo(control_path, 0o600)
    os.mkfifo(ack_path, 0o600)
    control = os.open(control_path, os.O_RDWR | os.O_NONBLOCK)
    ack = os.open(ack_path, os.O_RDWR | os.O_NONBLOCK)
    target = subprocess.Popen(
        ["/bin/sh", "-c", 'kill -STOP "$$"; exec "$@"', "owned-cpu-target", *command],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    profiler = None
    try:
        _, status = os.waitpid(target.pid, os.WUNTRACED)
        assert os.WIFSTOPPED(status), "owned target must be stopped before execution"
        profiler = subprocess.Popen(
            ["sudo", "-n", perf, "record", "-q", "-e", "cpu-clock:u", "-F", "99", "-p", str(target.pid),
             "--delay=-1", "--control=fifo:" + str(control_path) + "," + str(ack_path), "-o", str(raw_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
        )
        os.write(control, b"enable\n")
        assert select.select([ack], [], [], 20)[0], "perf did not acknowledge target attachment"
        assert b"ack" in os.read(ack, 4096), "perf did not enable the exact owned target"
        os.kill(target.pid, signal.SIGCONT)
        stdout, stderr = target.communicate(timeout=240)
        return target.returncode, stdout + stderr
    finally:
        if target.poll() is None:
            os.killpg(target.pid, signal.SIGKILL)
            target.communicate(timeout=10)
        if profiler is not None and profiler.poll() is None:
            subprocess.run(["sudo", "-n", "/bin/kill", "-INT", "--", "-" + str(profiler.pid)], capture_output=True, check=False)
            try:
                profiler.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                subprocess.run(["sudo", "-n", "/bin/kill", "-KILL", "--", "-" + str(profiler.pid)], capture_output=True, check=False)
                profiler.communicate(timeout=10)
        os.close(control)
        os.close(ack)
        control_path.unlink(missing_ok=True)
        ack_path.unlink(missing_ok=True)


def decode_symbols(perf, raw_path):
    result = subprocess.run(["sudo", "-n", perf, "script", "-i", str(raw_path), "-F", "sym"], capture_output=True, text=True, timeout=60)
    counts = collections.Counter()
    for line in result.stdout.splitlines():
        name = re.sub(r"\+0x[0-9a-fA-F]+(?:/0x[0-9a-fA-F]+)?$", "", line.strip())
        name = name.split("(", 1)[0].strip()
        if not name:
            continue
        if len(name) > 400 or re.search(r"0x[0-9a-fA-F]+", name) or not re.fullmatch(r"[A-Za-z0-9_:<>, &*~.$?{}\[\]#=+!;\-]+", name):
            name = "unavailable"
        counts[name] += 1
    return result.returncode == 0, counts


def remove_raw(path):
    subprocess.run(["sudo", "-n", "rm", "-f", "--", str(path), str(path) + ".old"], check=False, capture_output=True)


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
        "automatic_retries": 0, "test_threads": 1, "diagnostic_watchdog_seconds": 240, "sampler": "perf software cpu-clock:u leaf-only 99Hz, exact original-user PID attached before exec",
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
    control_raw = raw_path.with_name("owned-positive-control.perf.data")
    try:
        # Require actual samples through the identical attach-before-exec path.
        control_command = ["/usr/bin/python3", "-c", "import time; end=time.monotonic()+1.5\nwhile time.monotonic()<end: pass"]
        control_exit, _ = record_owned(perf, control_command, control_raw)
        control_decoded, control_counts = decode_symbols(perf, control_raw)
        report["positive_control_samples"] = sum(control_counts.values())
        report["positive_control_passed"] = control_exit == 0 and control_decoded and bool(control_counts)
        remove_raw(control_raw)
        if not report["positive_control_passed"]:
            report["blocker"] = "attach-before-exec-positive-control-had-no-samples"
            args.report.write_text(json.dumps(report, indent=2) + "\n")
            raise SystemExit("CPU sample positive control failed; product body not executed")
        runtime_exit, runtime = record_owned(perf, [str(binary), "--exact", TEST, "--test-threads=1", "--nocapture"], raw_path)
        started = bool(re.search(r"running 1 test\b", runtime))
        summary = re.search(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", runtime)
        decoded, counts = decode_symbols(perf, raw_path)
        report.update({
            "runtime_body_started": started, "runtime_exit_code": runtime_exit,
            "runtime_summary": {"passed": int(summary[2]), "failed": int(summary[3]), "ignored": int(summary[4])} if summary else None,
            "sample_decode_passed": decoded,
            "leaf_sample_count": sum(counts.values()),
            "static_symbol_aggregates": [{"function": name, "samples": count} for name, count in counts.most_common(100)],
            "unexported_symbol_count": max(0, len(counts) - 100),
            "diagnostic_complete": started and summary is not None and decoded and bool(counts),
        })
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        if not report["diagnostic_complete"]:
            raise SystemExit("Required exact-body runtime and static sample evidence unavailable")
    except (subprocess.TimeoutExpired, AssertionError):
        report["blocker"] = "owned-attach-or-sampling-control-unavailable"
        report["diagnostic_complete"] = False
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        raise SystemExit("Owned attachment/sampling control failed; no raw output exported")
    finally:
        remove_raw(control_raw)
        remove_raw(raw_path)


if __name__ == "__main__":
    main()
