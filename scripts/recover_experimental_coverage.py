#!/usr/bin/env python3
"""Recover exact missing coverage from the cancelled, immutable 0cb archive."""
import argparse
import hashlib
import json
from pathlib import Path
import re


SOURCE = "0cbff718b3d6dfe4d95b4a1966fe8e139423140c"
RUN = 38511641089
LOGS = {
    "115684849829": "d7ffadb4980ced42f265e891c0bb733e6ef40e6374a2145e3de9fabb6ed0ac98",
    "115684849834": "1c6398998fd79dc8617b642d4893f820df947bed3b6feaa5b1999eccfe00c613",
    "115684849847": "f6c3ed2fd298663dcfaa2437b9f51d828d393fcef33d5a2f8474b85fc6c32e6f",
    "115684849872": "92677eac15296d7302f6d42b12f47fd4bc83734521c4e6651aedfece02b55c5e",
    "115684849960": "aaa30c250c81645b47c5798dee9cc5ea0da3073d9b4883c7a6be201ffd1654e9",
}
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TERMINAL = re.compile(
    r"^\S+\s+(PASS|FAIL|TIMEOUT|LEAK)\s+\[[^\]\n]+\]"
    r"\s+\(\s*\d+/\d+\)\s+(\S+)\s+(.+?)\s*$", re.M
)


def recover(inventory, logs):
    selected = {}
    for suite_id, suite in inventory["rust-suites"].items():
        for name, case in suite["testcases"].items():
            if case["filter-match"]["status"] == "matches" and not case["ignored"]:
                selected[(suite_id, name)] = {
                    "suite": suite_id, "test": name,
                    "package": suite["package-name"], "binary": suite["binary-name"],
                }
    if not selected:
        raise ValueError("Empty runnable archive inventory")
    observed = {}
    for job, raw in logs.items():
        for status, suite, name in TERMINAL.findall(ANSI.sub("", raw)):
            key = (suite, name)
            if key not in selected:
                raise ValueError(f"Terminal case absent from runnable inventory: {key}")
            if key in observed:
                raise ValueError(f"Duplicate terminal case: {key}")
            observed[key] = dict(status=status, job=job)
    passed, remaining = [], []
    for key, case in sorted(selected.items()):
        outcome = observed.get(key, {"status": "uncompleted", "job": None})
        row = dict(case, **outcome)
        (passed if outcome["status"] == "PASS" else remaining).append(row)
    return passed, remaining


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--logs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    logs = {}
    for job, expected in LOGS.items():
        raw = (args.logs / f"{job}.log").read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError(f"Original job log changed: {job}")
        logs[job] = raw.decode("utf-8")
    passed, remaining = recover(json.loads(args.inventory.read_text()), logs)
    counts = {status: sum(row["status"] == status for row in remaining)
              for status in ("FAIL", "TIMEOUT", "LEAK", "uncompleted")}
    if len(passed) != 4658 or len(passed) + len(remaining) != 8230:
        raise ValueError("Archive inventory does not match original execution coverage")
    if counts != {"FAIL": 5, "TIMEOUT": 0, "LEAK": 1, "uncompleted": 3566}:
        raise ValueError(f"Original nonpassing coverage changed: {counts}")
    args.output.mkdir(exist_ok=False)
    for name, value in [("passed-cases.json", passed), ("remaining-cases.json", remaining)]:
        (args.output / name).write_text(json.dumps(value, indent=2) + "\n")
    summary = dict(source=SOURCE, run=RUN, inventory_sha256=hashlib.sha256(
        args.inventory.read_bytes()).hexdigest(), original_log_hashes=LOGS,
        clean_passes=len(passed), needs_execution=len(remaining), **counts,
        scope="Recovered coverage only; no new execution or backend qualification")
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
