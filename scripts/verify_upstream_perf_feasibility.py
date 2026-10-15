#!/usr/bin/env python3
"""Remote owned-process perf control; never export raw capture or process data."""
import collections
import glob
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

os.umask(0o077)
root = Path("perf-evidence")
root.mkdir()
report = {"diagnostic_only": True, "qualification_passed": False, "rust_compilation": False,
          "kernel_reconfigured": False, "tools_installed": False, "feasible": False,
          "product_unwind_verified": False, "source": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()}
def save():
    (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")
def finish(reason):
    report["disposition"] = reason
    report["diagnostic_complete"] = True
    save()
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0)

candidates = [shutil.which("perf")] + sorted(glob.glob("/usr/lib/linux-tools/*/perf"))
perf = None
for candidate in dict.fromkeys(value for value in candidates if value):
    version = subprocess.run([candidate, "--version"], capture_output=True, text=True, timeout=10)
    if version.returncode == 0 and re.search(r"perf version [0-9.]+", version.stdout):
        perf = candidate
        report["perf_version"] = re.search(r"perf version [0-9.]+", version.stdout).group()
        break
if perf is None:
    finish("PerfUnavailableForRunnerKernel")
prefix = [perf]
# This is a dedicated ephemeral runner and only our synthetic child is sampled.
# No kernel options or product runtime configuration are changed.
if os.geteuid() != 0:
    sudo = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5)
    if sudo.returncode == 0:
        prefix = ["sudo", "-n", perf]
report["sampling_privilege"] = "owned-child-root-tool" if prefix[0] == "sudo" else "owned-child-current-user"
report["sample_event"] = "cpu-clock:u"
report["callgraph_mode"] = "fp"
report["frequency_hz"] = 49
control = None
with tempfile.TemporaryDirectory(prefix="owned-perf-control-") as temporary:
    capture = Path(temporary) / "perf.data"
    try:
        control = subprocess.Popen([sys.executable, "-c", "import hashlib\nwhile True: hashlib.sha256(b'public synthetic profiling control').digest()"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.2)
        recorded = subprocess.run(prefix + ["record", "-e", "cpu-clock:u", "-F", "49", "--call-graph", "fp", "-p", str(control.pid), "-o", str(capture), "--", "sleep", "2"], capture_output=True, timeout=15)
        report["record_exit_code"] = recorded.returncode
        if recorded.returncode != 0:
            reason = "PerfPermissionOrCapabilityUnavailable" if b"ermission" in recorded.stderr or b"not permitted" in recorded.stderr else "PerfRecordUnsupported"
            finish(reason)
        decoded = subprocess.run(prefix + ["script", "-i", str(capture), "-F", "ip,sym"], capture_output=True, text=True, timeout=15)
        report["decode_exit_code"] = decoded.returncode
        if decoded.returncode != 0:
            finish("PerfStaticSymbolDecodeUnavailable")
        samples = []
        for group in re.split(r"\n\s*\n", decoded.stdout):
            symbols = []
            for line in group.splitlines():
                match = re.fullmatch(r"\s*[0-9a-fA-F]+\s+([A-Za-z_][A-Za-z_0-9.$:@<>~]*)(?:\+0x[0-9a-fA-F]+(?:/0x[0-9a-fA-F]+)?)?\s*", line)
                if match:
                    symbols.append(match.group(1))
            if group.strip():
                samples.append(symbols)
        count = len(samples)
        resolved = sum(bool(sample) for sample in samples)
        chained = sum(len(sample) >= 2 for sample in samples)
        report["control_samples"] = count
        report["resolved_samples"] = resolved
        report["resolved_callchain_samples"] = chained
        report["maximum_resolved_depth"] = max(map(len, samples), default=0)
        report["resolved_leaf_aggregates"] = [{"function": name, "samples": value} for name, value in collections.Counter(sample[0] for sample in samples if sample).most_common(20)]
        report["control_callchain_coverage"] = chained / count if count else 0
        report["feasible"] = count >= 20 and chained >= 10
        finish("OwnedControlSamplingUsableProductUnwindStillUnknown" if report["feasible"] else "InsufficientOwnedControlResolvedCallchains")
    except subprocess.TimeoutExpired:
        finish("PerfOwnedControlTimedOut")
    finally:
        if control is not None:
            control.kill()
            control.wait(timeout=5)
        # TemporaryDirectory removes ALL raw perf.data/stack captures. Only the
        # bounded static-name result above survives this process.
