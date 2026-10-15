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
    routing_tests = root / "crates/transport-nostr-adapter/tests/inbound_routing.rs"
    frozen = {path: path.read_bytes() for path in (
        transport, status, routing_tests, root / "Cargo.toml", root / "Cargo.lock",
        root / "rust-toolchain.toml",
    )}
    originals = {path: path.read_bytes() for path in (transport, status)}
    report = {
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip(),
        "source_hashes": {
            str(path.relative_to(root)): hashlib.sha256(data).hexdigest()
            for path, data in originals.items()
        },
        "frozen_inputs": {
            str(path.relative_to(root)): hashlib.sha256(data).hexdigest()
            for path, data in frozen.items()
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

    # These exact runtime assertions are evidenced in the retained 3f18,
    # 3090, f4d7 and cb77 mutation logs. Check their current source, too.
    routing_oracle_source = frozen[routing_tests].decode()
    source_oracles = {
        "premature-noop": (
            "crates/transport-nostr-adapter/tests/inbound_routing.rs",
            "timed out waiting until the added group's subscribe is held", None,
        ),
        "legacy-group-wire": (
            "crates/transport-nostr-adapter/tests/inbound_routing.rs",
            "assertion `left == right` failed: only post-EOSE capture is live", ("false", "true"),
        ),
        "stale-wire-index": (
            "crates/transport-nostr-adapter/tests/inbound_routing.rs",
            "assertion `left == right` failed: retired batch evidence stays negative", ("false", "true"),
        ),
    }
    for literal in (
        'wait_until("the added group\'s subscribe is held",',
        '"only post-EOSE capture is live"',
        '"retired batch evidence stays negative"',
    ):
        if routing_oracle_source.count(literal) != 1:
            raise RuntimeError("Expected routing runtime oracle must be unique in current source")
    status_source = originals[status].decode()
    denied = re.search(r"^\s*AccountChatDepartureDenied = (\d+),$", status_source, re.M)
    invalid = re.search(r"^\s*InvalidArgument = (\d+),$", status_source, re.M)
    status_assertions = re.findall(
        r"assert_eq!\(\s*status_from_error\(&MarmotKitError::AccountChatDepartureDenied\)"
        r" as i32,\s*(\d+)\s*\);", status_source,
    )
    if not denied or not invalid or status_assertions != [denied[1]]:
        raise RuntimeError("Expected departure-status assertion must match the current ABI enum")
    source_oracles["wrong-departure-status"] = (
        "crates/marmot-c/src/status.rs", "assertion `left == right` failed",
        (invalid[1], denied[1]),
    )

    def run(label: str, command: list[str], test: str) -> dict:
        command = command + [test, "--", "--exact", "--test-threads=1"]
        log = output / f"{label}.log"
        with log.open("x") as stream:
            result = subprocess.run(command, cwd=root, stdout=stream, stderr=subprocess.STDOUT)
        raw_text = log.read_text()
        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw_text)
        rows = re.findall(
            r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", text,
        )
        compiler_diagnostics = re.findall(
            r"^error(?:\[[^]\n]+\])?: (?!test failed(?:,|$))[^\n]*", text, re.M,
        )
        compiler_codes = sorted(set(re.findall(r"error\[(E\d+)\]", text)))
        panics = re.findall(
            r"^thread '([^']+)'(?: \(\d+\))? panicked at ([^\n]+):(\d+):(\d+):\n([^\n]+)",
            text, re.M,
        )
        one_named_body = (
            len(re.findall(r"^running 1 test$", text, re.M)) == 1
            and bool(re.search(r"^test " + re.escape(test) + r" \.\.\. (?:ok|FAILED)$", text, re.M))
        )
        oracle_name = label.removesuffix("-mutant").removesuffix("-baseline").removesuffix("-restored")
        expected_file, expected_message, expected_values = source_oracles[oracle_name]
        own_panic = (
            len(panics) == 1 and panics[0][0] == test and panics[0][1] == expected_file
            and panics[0][4] == expected_message
        )
        actual_values = re.findall(r"^  left: ([^\n]+)\n right: ([^\n]+)$", text, re.M)
        comparison_matches = expected_values is None or actual_values == [expected_values]
        return {
            "command": command,
            "exit_code": result.returncode,
            "log": log.name,
            "log_sha256": hashlib.sha256(raw_text.encode()).hexdigest(),
            "ansi_csi_sequences_removed": text != raw_text,
            "counts": rows,
            "actual_named_body": one_named_body,
            "compiler_error_codes": compiler_codes,
            "compiler_diagnostics": compiler_diagnostics,
            "panic_count": len(panics),
            "expected_panic_file": expected_file,
            "expected_panic_message": expected_message,
            "expected_comparison": expected_values,
            "named_panic_matches": own_panic,
            "comparison_matches": comparison_matches,
            "green": (result.returncode == 0 and rows == [("ok", "1", "0", "0")]
                      and one_named_body and not panics and not compiler_diagnostics and not compiler_codes),
            "behavioral_red": (
                result.returncode == 101 and rows == [("FAILED", "0", "1", "0")]
                and one_named_body and not compiler_diagnostics and not compiler_codes
                and own_panic and comparison_matches
            ),
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
            row = {"name": name, "mutated_source_sha256": hashlib.sha256(mutant.encode()).hexdigest()}
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
        report["frozen_inputs_unchanged"] = all(
            path.read_bytes() == data for path, data in frozen.items()
        )
        report["completed"] = report["completed"] and report["frozen_inputs_unchanged"]
        save()
    if not report["completed"]:
        raise RuntimeError("Mutation proof incomplete or frozen inputs changed")


if __name__ == "__main__":
    main()
