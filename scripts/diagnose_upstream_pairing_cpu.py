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
import queue
import threading
import time
import signal
import subprocess

SOURCE = "ef4e687c0ba5d92cd8ea1c5d1f97766534d97077"
PRODUCER = 38725598470
ARTIFACT = 11968357472
TEST = "native_device_linking::automatic_pairing_acceptance::third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts"


class Debugger:
    """Consume MI output privately; expose only selected static frame names."""
    def __init__(self, pid):
        self.process = subprocess.Popen(
            ["sudo", "-n", "gdb", "--quiet", "--nx", "--interpreter=mi2"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            start_new_session=True,
        )
        self.lines = queue.Queue()
        self.stopped = False
        self.exited = False
        self.token = 0
        def read():
            for line in self.process.stdout:
                self.lines.put(line.strip())
        threading.Thread(target=read, daemon=True).start()
        self.command("-gdb-set pagination off")
        self.command("-gdb-set mi-async on")
        self.command('-interpreter-exec console "handle SIGSTOP nostop noprint nopass"')
        self.command("-target-attach " + str(pid))
        self.wait_stop()

    def receive(self, timeout=15):
        line = self.lines.get(timeout=timeout)
        if line.startswith("*stopped"):
            self.stopped = True
            if 'reason="exited' in line:
                self.exited = True
        if "ptrace:" in line.lower() or "operation not permitted" in line.lower():
            global LAST_ERROR
            LAST_ERROR = "ptrace-denied"
        if line.startswith("*running"):
            self.stopped = False
        return line

    def wait_stop(self):
        deadline = time.monotonic() + 20
        while not self.stopped:
            self.receive(max(0.01, deadline - time.monotonic()))

    def command(self, command):
        global LAST_STAGE
        LAST_STAGE = "mi-" + command.split()[0].lstrip("-")
        self.token += 1
        prefix = str(self.token)
        self.process.stdin.write(prefix + command + "\n")
        self.process.stdin.flush()
        while True:
            line = self.receive()
            if line.startswith(prefix + "^"):
                if line.startswith(prefix + "^error"):
                    global LAST_ERROR
                    lower = line.lower()
                    LAST_ERROR = next((category for fragment, category in [
                        ("ptrace", "ptrace-denied"), ("operation not permitted", "operation-not-permitted"),
                        ("permission denied", "permission-denied"), ("undefined", "undefined-command"),
                        ("running", "inferior-running"), ("not supported", "unsupported-command"),
                        ("not being run", "inferior-not-running"), ("no registers", "no-registers"),
                    ] if fragment in lower), "other-mi-error")
                    raise AssertionError("owned debugger command failed")
                return line

    def close(self):
        if self.process.poll() is None:
            try:
                self.command("-gdb-exit")
            except (AssertionError, queue.Empty, BrokenPipeError):
                subprocess.run(["sudo", "-n", "/bin/kill", "-KILL", "--", "-" + str(self.process.pid)], capture_output=True)
            self.process.wait(timeout=15)


def cpu_ticks(pid):
    values = {}
    for path in Path("/proc").joinpath(str(pid), "task").glob("*/stat"):
        try:
            fields = path.read_text().rsplit(")", 1)[1].split()
            values[int(path.parent.name)] = int(fields[11]) + int(fields[12])
        except (FileNotFoundError, ProcessLookupError):
            pass
    return values


def record_owned(_sampler, command, _raw_path):
    """Bounded leaf-only debugger sampling, weighting active-thread CPU deltas."""
    import tempfile
    samples = []
    global LAST_STAGE
    LAST_STAGE = "owned-child-stopped"
    with tempfile.TemporaryFile(mode="w+") as output:
        target = subprocess.Popen(
            ["/bin/sh", "-c", 'kill -STOP "$$"; exec "$@"', "owned-cpu-target", *command],
            stdout=output, stderr=output, text=True, start_new_session=True,
        )
        debugger = None
        try:
            _, status = os.waitpid(target.pid, os.WUNTRACED)
            assert os.WIFSTOPPED(status), "owned target must stop before execution"
            LAST_STAGE = "debugger-attach"
            debugger = Debugger(target.pid)
            started = time.monotonic()
            before = cpu_ticks(target.pid)
            LAST_STAGE = "sampling-active"
            debugger.command("-exec-continue")
            while target.poll() is None and time.monotonic() - started < 240:
                time.sleep(0.2)
                if target.poll() is not None:
                    break
                debugger.command("-exec-interrupt --all")
                debugger.wait_stop()
                if debugger.exited:
                    break
                after = cpu_ticks(target.pid)
                deltas = {tid: ticks - before.get(tid, ticks) for tid, ticks in after.items()}
                tid = max(deltas, key=deltas.get) if deltas else None
                threads = debugger.command("-thread-info")
                matches = re.findall(r'id="([0-9]+)",target-id="[^"]*LWP ([0-9]+)[^"]*"', threads)
                selected = next((identifier for identifier, lwp in matches if int(lwp) == tid), None)
                if selected is not None and deltas[tid] > 0:
                    debugger.command("-thread-select " + selected)
                    frame = debugger.command("-stack-info-frame")
                    match = re.search(r'func=("(?:[^"\\]|\\.)*")', frame)
                    name = json.loads(match[1]) if match else "unavailable"
                    name = name.split("(", 1)[0].strip()
                    if len(name) > 400 or not re.fullmatch(r"[A-Za-z0-9_:<>, &*~.$?{}\[\]#=+!;\-]+", name):
                        name = "unavailable"
                    # Request static frames only, never arguments or locals. Raw MI stays private.
                    stack = debugger.command("-stack-list-frames 0 39")
                    callers = []
                    for encoded in re.findall(r'func=("(?:[^"\\]|\\.)*")', stack):
                        caller = json.loads(encoded).split("(", 1)[0].strip()
                        if len(caller) <= 400 and re.fullmatch(r"[A-Za-z0-9_:<>, &*~.$?{}\[\]#=+!;\-]+", caller):
                            if any(fragment in caller for fragment in ["marmot_app::", "cgka_engine::", "storage_sqlite::", "openmls::", "nostr_sdk::", "secrets::", "secrecy::"]):
                                if caller not in callers:
                                    callers.append(caller)
                    samples.append((time.monotonic() - started, name, deltas[tid], tuple(callers[:6])))
                before = after
                debugger.command("-exec-continue")
            LAST_STAGE = "release-debugger-before-child-reap"
            # Release ptrace custody before the original parent reaps its child.
            debugger.close()
            debugger = None
            if target.poll() is None:
                target.wait(timeout=10)
            output.seek(0)
            return target.returncode, output.read(), samples
        finally:
            if debugger is not None:
                debugger.close()
            if target.poll() is None:
                os.killpg(target.pid, signal.SIGKILL)
                target.wait(timeout=10)


def summarize(samples):
    counts = collections.Counter(name for _, name, _, _ in samples)
    weights = collections.Counter()
    for _, name, ticks, _ in samples:
        weights[name] += ticks
    return [{"function": name, "samples": count, "active_thread_cpu_ticks": weights[name]}
            for name, count in counts.most_common(100)]


def caller_summary(samples):
    counts = collections.Counter((name, callers) for _, name, _, callers in samples)
    return [{"leaf": name, "static_callers": list(callers), "samples": count}
            for (name, callers), count in counts.most_common(60)]


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
    perf = shutil.which("gdb")
    preflight = bool(perf)
    version = subprocess.check_output([perf, "--version"], text=True).splitlines()[0] if perf else None
    report = {
        "source": SOURCE, "source_tree": provenance["source_tree"],
        "producer_run": PRODUCER, "artifact_id": ARTIFACT,
        "archive_sha256": archive_hash, "binary_sha256": binary_hash,
        "features": provenance["features"], "toolchain": provenance["toolchain"],
        "build_profile": provenance["build_profile"], "original_nextest_profile": provenance["nextest_profile"],
        "test": TEST, "selected_nonignored": 1, "rust_min_stack_bytes": 4194304,
        "automatic_retries": 0, "test_threads": 1, "diagnostic_watchdog_seconds": 240, "sampler": "GDB bounded static leaf and allowlisted caller sampling at 5Hz, highest CPU-delta owned thread",
        "debugger_version": version, "preflight_passed": preflight,
        "ptrace_scope": Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip() if Path("/proc/sys/kernel/yama/ptrace_scope").exists() else "unavailable",
        "proc_task_stat_readable": os.access("/proc/self/task", os.R_OK),
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
        control_exit, _, control_samples = record_owned(perf, control_command, control_raw)
        control_counts = collections.Counter(name for _, name, _, _ in control_samples)
        control_decoded = True
        report["positive_control_samples"] = sum(control_counts.values())
        report["positive_control_passed"] = control_exit == 0 and control_decoded and any(name != "unavailable" for name in control_counts)
        remove_raw(control_raw)
        if not report["positive_control_passed"]:
            report["blocker"] = "attach-before-exec-positive-control-had-no-samples"
            args.report.write_text(json.dumps(report, indent=2) + "\n")
            raise SystemExit("CPU sample positive control failed; product body not executed")
        runtime_exit, runtime, samples = record_owned(perf, [str(binary), "--exact", TEST, "--test-threads=1", "--nocapture"], raw_path)
        started = bool(re.search(r"running 1 test\b", runtime))
        summary = re.search(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", runtime)
        decoded = True
        counts = collections.Counter(name for _, name, _, _ in samples)
        last = samples[-1][0] if samples else 0
        report.update({
            "runtime_body_started": started, "runtime_exit_code": runtime_exit,
            "runtime_summary": {"passed": int(summary[2]), "failed": int(summary[3]), "ignored": int(summary[4])} if summary else None,
            "sample_decode_passed": decoded,
            "leaf_sample_count": sum(counts.values()),
            "static_symbol_aggregates": summarize(samples),
            "static_caller_aggregates": caller_summary(samples),
            "last_20_seconds_static_caller_aggregates": caller_summary([sample for sample in samples if sample[0] >= last - 20]),
            "last_20_seconds_static_symbol_aggregates": summarize([sample for sample in samples if sample[0] >= last - 20]),
            "attribution_limits": "Debugger pauses influence timing; leaf sampled after interrupt may differ from the CPU-hot function. Whole case includes startup/import. ef4 includes unqualified early-finalization extra checks. CPU ticks weight intervals, not exact per-function CPU time.",
            "unexported_symbol_count": max(0, len(counts) - 100),
            "diagnostic_complete": started and summary is not None and decoded and bool(counts),
        })
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        if not report["diagnostic_complete"]:
            raise SystemExit("Required exact-body runtime and static sample evidence unavailable")
    except (subprocess.TimeoutExpired, AssertionError, queue.Empty):
        report["blocker"] = "owned-attach-or-sampling-control-unavailable"
        report["closed_harness_stage"] = globals().get("LAST_STAGE", "preflight")
        report["closed_harness_error"] = globals().get("LAST_ERROR", "no-mi-error-observed")
        report["diagnostic_complete"] = False
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        raise SystemExit("Owned attachment/sampling control failed; no raw output exported")
    finally:
        remove_raw(control_raw)
        remove_raw(raw_path)


if __name__ == "__main__":
    main()
