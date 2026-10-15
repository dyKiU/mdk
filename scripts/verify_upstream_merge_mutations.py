#!/usr/bin/env python3
"""Require runtime detection of merge regressions and exact source restoration."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    transport = root / "crates/transport-nostr-adapter/src/lib.rs"
    status = root / "crates/marmot-c/src/status.rs"
    originals = {path: path.read_bytes() for path in (transport, status)}
    report = {
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip(),
        "source_hashes": {
            str(path.relative_to(root)): hashlib.sha256(data).hexdigest()
            for path, data in originals.items()
        },
        "baselines": {},
        "checks": [],
        "completed": False,
    }

    def save() -> None:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    def replace_once(text: str, old: str, new: str) -> str:
        if text.count(old) != 1:
            raise RuntimeError(f"Mutation target must be unique: {old!r}")
        return text.replace(old, new, 1)

    routing = originals[transport].decode()
    start = routing.index("        self.accounts\n", routing.index("    fn observation_wire_id("))
    end = routing.index(
        '\n    }\n    #[cfg(feature = "experimental-device-sync")]\n    fn private_observation_ready_for',
        start,
    )
    transport_cmd = [
        "cargo", "test", "--locked", "-p", "transport-nostr-adapter",
        "--test", "inbound_routing", "--features", "experimental-device-sync",
    ]
    status_cmd = [
        "cargo", "test", "--locked", "-p", "marmot-c", "--lib",
        "--features", "experimental-device-sync,alloc-audit",
    ]
    cancel = "cancelled_private_group_sync_closes_its_exact_wire_id"
    batches = "ordinary_batched_live_receipts_follow_eose_and_repacking"
    abi = "status::tests::every_runtime_error_variant_maps_to_a_distinct_status"
    mutations = [
        ("premature-noop", transport, transport_cmd, cancel,
         replace_once(routing, " && !private_changed", "")),
        ("legacy-group-wire", transport, transport_cmd, batches,
         routing[:start] + "        Some(group_subscription(account, route, None, attempt).subscription_id())" + routing[end:]),
        ("stale-wire-index", transport, transport_cmd, batches,
         replace_once(routing, "account.group_wire_ids = issued_group_wire_ids(batches);", "")),
        ("wrong-departure-status", status, status_cmd, abi,
         replace_once(originals[status].decode(),
                      "MarmotKitError::AccountChatDepartureDenied => MarmotStatus::AccountChatDepartureDenied,",
                      "MarmotKitError::AccountChatDepartureDenied => MarmotStatus::InvalidArgument,")),
    ]

    def run(label: str, command: list[str], test: str) -> dict:
        command = command + [test, "--", "--exact", "--test-threads=1"]
        log = output / f"{label}.log"
        with log.open("x") as stream:
            result = subprocess.run(command, cwd=root, stdout=stream, stderr=subprocess.STDOUT)
        rows = re.findall(
            r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;",
            log.read_text(),
        )
        return {
            "command": command,
            "exit_code": result.returncode,
            "log": log.name,
            "counts": rows,
            "green": result.returncode == 0 and rows == [("ok", "1", "0", "0")],
            "behavioral_red": result.returncode != 0 and rows == [("FAILED", "0", "1", "0")],
        }

    save()
    try:
        for name, path, command, test, mutant in mutations:
            if test not in report["baselines"]:
                baseline = run(name + "-baseline", command, test)
                report["baselines"][test] = baseline
                save()
                if not baseline["green"]:
                    raise RuntimeError(f"Baseline did not execute exactly one passing test: {name}")
            row = {"name": name}
            try:
                path.write_text(mutant)
                row["mutant"] = run(name + "-mutant", command, test)
            finally:
                path.write_bytes(originals[path])
            row["restored"] = run(name + "-restored", command, test)
            row["source_restored"] = path.read_bytes() == originals[path]
            row["killed"] = (
                row["mutant"]["behavioral_red"] and row["restored"]["green"]
                and row["source_restored"]
            )
            report["checks"].append(row)
            save()
            if not row["killed"]:
                raise RuntimeError(f"Mutation survived, failed compilation, or lacked a passing restore: {name}")
        report["completed"] = True
    finally:
        for path, data in originals.items():
            path.write_bytes(data)
        report["all_sources_restored"] = all(
            path.read_bytes() == data for path, data in originals.items()
        )
        save()


if __name__ == "__main__":
    main()
