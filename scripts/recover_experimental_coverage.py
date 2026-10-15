#!/usr/bin/env python3
"""Recover exact missing coverage from the cancelled, immutable 0cb archive."""
import argparse
import hashlib
import json
from collections import defaultdict
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


def replacement(row):
    """Name required follow-up evidence; this does not mark a case passing."""
    if row["package"] == "wn-cli":
        return "latest-experimental-cli-component"
    if row["package"] == "cgka-engine" and (
        row["binary"] == "crash_recovery_sqlite"
        or row["test"].endswith(
            "account_sharing_peer_generation_uses_authenticated_role_and_live_original")
        or row["test"] == "confirmed_publish_retries_failed_inbound_replay_through_normal_advance"
    ):
        return "latest-core-regressions"
    if row["package"] == "agent-connector" and row["test"] == (
        "tests::connector_relay_list_edit_preserves_entries_the_request_did_not_name"
    ):
        return "latest-connector-regression"
    if row["package"] == "cgka-conformance-simulator" and row["test"] == (
        "tests::kills_and_reaps_a_worker_that_exceeds_its_timeout"
    ):
        return "latest-campaign-regression"
    return None


def make_plan(remaining, partitions=12):
    if partitions < 1:
        raise ValueError("Partition count must be positive")
    buckets = [[] for _ in range(partitions)]
    replacements = []
    seen = set()
    for row in remaining:
        key = (row["suite"], row["test"])
        if key in seen:
            raise ValueError("Duplicate remaining case")
        seen.add(key)
        role = replacement(row)
        if role:
            replacements.append(dict(row, required_followup=role, qualified=False))
        else:
            identifier = "\0".join(key).encode()
            bucket = int.from_bytes(hashlib.sha256(identifier).digest()[:8], "big") % partitions
            buckets[bucket].append(row)
    plan = []
    for index, rows in enumerate(buckets):
        groups = defaultdict(list)
        for row in rows:
            if not re.fullmatch(r"[A-Za-z0-9_:]+", row["test"]):
                raise ValueError("Unsupported test identifier in filter")
            for field in ("package", "binary"):
                if not re.fullmatch(r"[A-Za-z0-9_-]+", row[field]):
                    raise ValueError("Unsupported suite identifier in filter")
            groups[(row["package"], row["binary"])].append(row["test"])
        clauses = []
        for (package, binary), names in sorted(groups.items()):
            tests = " | ".join(f"test(={name})" for name in sorted(names))
            clauses.append(f"(package(={package}) & binary(={binary}) & ({tests}))")
        expression = " | ".join(clauses) if clauses else "none()"
        if len(expression.encode()) > 100_000:
            raise ValueError("Partition filter exceeds argument budget")
        plan.append(dict(partition=index + 1, count=len(rows), cases=rows, filter=expression))
    if sum(row["count"] for row in plan) + len(replacements) != len(remaining):
        raise ValueError("Remaining coverage was lost")
    return plan, replacements


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
    plan, replacements = make_plan(remaining)
    (args.output / "execution-plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    (args.output / "required-followups.json").write_text(json.dumps(replacements, indent=2) + "\n")
    summary = dict(source=SOURCE, run=RUN, inventory_sha256=hashlib.sha256(
        args.inventory.read_bytes()).hexdigest(), original_log_hashes=LOGS,
        clean_passes=len(passed), needs_execution=len(remaining), **counts,
        archive_cases_to_execute=sum(row["count"] for row in plan),
        cases_requiring_latest_followups=len(replacements),
        scope="Recovered coverage only; no new execution or backend qualification")
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
