#!/usr/bin/env python3
"""Narrow upstream savepoint controls; retain only static, credential-free evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

BASE = "87c992d1ffa478c477b6841e33f1680768dfe329"
OLD = "288bbdd9f1e59474ef309da6236276ccb2b9c986"
SCOPE = os.environ["SAVEPOINT_SCOPE"]
COHORT = os.environ.get("SAVEPOINT_COHORT", "experimental")
ROOT = Path("savepoint-evidence")
ROOT.mkdir()
assert os.environ["RUST_MIN_STACK"] == "4194304"
assert not subprocess.check_output(["git", "diff", BASE, "HEAD", "--", "crates", "Cargo.toml", "Cargo.lock"])
FEATURES = "cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks"
if COHORT == "experimental":
    FEATURES += ",cgka-engine/experimental-device-sync"
if SCOPE == "storage":
    FEATURES = "storage-sqlite/experimental-device-sync" if COHORT == "experimental" else ""
FEATURE_ARGS = ["--features", FEATURES] if FEATURES else []
report = {
    "source": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
    "product_baseline": BASE, "counterfactual_source": OLD, "scope": SCOPE,
    "cohort": COHORT, "controls": {}, "qualification_passed": False,
    "compile_environment_observed": {key: os.environ.get(key) for key in ["CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "RUST_MIN_STACK"]},
    "rustc_incremental_invocation": "not captured; environment only",
    "lock_sha256": hashlib.sha256(Path("Cargo.lock").read_bytes()).hexdigest(),
    "automatic_retries": 0, "test_threads": 1,
}

def save():
    (ROOT / "result.json").write_text(json.dumps(report, indent=2) + "\n")

def execute(label, args, selected, expected=None, required_failure=None):
    started = time.monotonic()
    inventory = subprocess.run(["cargo", "nextest", "list", "--locked", *args, *FEATURE_ARGS, "-E", selected, "--message-format", "json"], capture_output=True, text=True)
    entry = {"filter": selected, "cargo_arguments": args, "features": FEATURES, "list_exit_code": inventory.returncode}
    report["controls"][label] = entry
    save()
    assert inventory.returncode == 0, "compile/list failure is not behavioral evidence"
    suites = json.loads(inventory.stdout)["rust-suites"]
    names = [name for suite in suites.values() for name, case in suite["testcases"].items() if case["filter-match"]["status"] == "matches" and not case["ignored"]]
    assert names and all(re.fullmatch(r"[A-Za-z0-9_:]+", name) for name in names)
    assert expected is None or len(names) == expected, "exact nonignored count required"
    entry.update(selected_case_names=names, selected_nonignored=len(names), ignored_inventory=sum(case["ignored"] for suite in suites.values() for case in suite["testcases"].values()), compile_or_cached_list_seconds=time.monotonic() - started)
    started = time.monotonic()
    result = subprocess.run(["cargo", "nextest", "run", "--locked", *args, *FEATURE_ARGS, "-E", selected, "--profile", "m5-bounded", "--test-threads", "1", "--retries", "0", "--no-fail-fast"], capture_output=True, text=True)
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
    rows = re.findall(r"Summary\s+\[[^\]]*\]\s+(\d+)(?:/\d+)?\s+tests? run:\s*([^\n]*)", output)
    entry.update(exit_code=result.returncode, execution_command_seconds=time.monotonic() - started)
    save()
    assert len(rows) == 1 and int(rows[0][0]) == len(names), "actual execution count required"
    def count(label):
        found = re.search(r"(\d+) " + label, rows[0][1])
        return int(found[1]) if found else 0
    entry.update(executed_nonignored=int(rows[0][0]), passed=count("passed"), failed=count("failed"), filtered_or_skipped=count("skipped"))
    fail_lines = [line for line in output.splitlines() if re.search(r"\bFAIL\b", line)]
    entry["failed_case_names"] = [name for name in names if any(name in line for line in fail_lines)]
    entry["panic_locations"] = [{"file": file, "line": int(line), "column": int(column)} for file, line, column in re.findall(r"panicked at (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)", output)]
    entry["required_behavioral_assertion_observed"] = required_failure in output if required_failure else None
    save()
    if required_failure:
        assert len(names) == 1 and result.returncode != 0 and entry["failed"] == 1 and entry["passed"] == 0 and entry["required_behavioral_assertion_observed"], "genuine designated runtime assertion required"
    else:
        assert result.returncode == 0 and entry["passed"] == len(names) and entry["failed"] == 0, "all selected runtime controls must pass"

def changed_source(path, replacement, body):
    target = Path(path)
    original = target.read_bytes()
    before = hashlib.sha256(original).hexdigest()
    report["mutation_source"] = {"path": path, "before_sha256": before, "changed_sha256": hashlib.sha256(replacement).hexdigest()}
    save()
    try:
        target.write_bytes(replacement)
        body()
    finally:
        target.write_bytes(original)
        restored = hashlib.sha256(target.read_bytes()).hexdigest()
        report["mutation_source"]["restored_sha256"] = restored
        report["mutation_source"]["exact_restore"] = restored == before
        save()
        assert restored == before

if SCOPE == "storage":
    names = ["failed_group_savepoint_undoes_only_its_own_work_inside_a_committing_transaction", "group_savepoint_commits_alone_and_nests", "group_savepoint_undoes_a_panic_the_caller_catches_before_committing", "failed_savepoint_rollback_blocks_a_catching_caller_from_committing", "group_snapshot_fallback_restores_the_group_inside_a_committing_transaction"]
    selected = " | ".join("test(=" + "connection::tests::" + name + ")" for name in names)
    args = ["-p", "storage-sqlite", "--lib"]
    execute("five-storage-controls", args, selected, 5)
    one = "test(=connection::tests::failed_savepoint_rollback_blocks_a_catching_caller_from_committing)"
    path = "crates/storage-sqlite/src/connection.rs"
    data = Path(path).read_bytes()
    old = b'            Err(err) => Err(self.mark_transaction_unusable(format!(\n                "sqlite ROLLBACK TO SAVEPOINT failed ({err}); connection marked unusable",\n            ))),'
    assert data.count(old) == 1
    changed_source(path, data.replace(old, b"            Err(err) => Err(err),"), lambda: execute("rollback-latch-runtime-mutant", args, one, 1, "a failed savepoint rollback must fail the enclosing commit"))
    execute("rollback-latch-exact-restored-control", args, one, 1)
elif SCOPE == "counterfactual":
    args = ["-p", "cgka-engine", "--test", "record_write_atomicity"]
    one = "test(=failed_canonical_apply_rolls_back_inside_a_committing_caller_without_a_full_snapshot)"
    path = "crates/cgka-engine/src/openmls_projection.rs"
    old = subprocess.check_output(["git", "show", OLD + ":" + path])
    assert b"check_applied" in old and b"is_live()" in old
    changed_source(path, old, lambda: execute("old-canonical-full-snapshot-runtime-red", args, one, 1, "neither the failed nor the successful apply may copy the whole group ledger"))
    execute("upstream-savepoint-exact-restored-green", args, one, 1)
elif SCOPE == "engine":
    args = ["-p", "cgka-engine", "--test", "record_write_atomicity", "--test", "crash_recovery_sqlite", "--test", "publish_lifecycle"]
    execute("affected-engine-binaries", args, "binary(record_write_atomicity) | binary(crash_recovery_sqlite) | binary(publish_lifecycle)")
elif SCOPE == "private":
    assert COHORT == "experimental"
    names = ["private_enrollment_endorsement_owned_action_cannot_transfer_or_survive_cancel_reopen", "private_enrollment_endorsement_original_received_deadline_cannot_be_renewed", "private_enrollment_endorsement_same_tree_completed_reselection_denies_original_action", "private_enrollment_local_proposal_core_teardown_cannot_preserve_original_owner", "revoked_successor_retry_scope_refuses_terminal_mismatch_expiry_and_cancellation", "private_enrollment_request_sql_fault_preserves_crypto_and_original_retry"]
    selected = " | ".join("test(=" + "private_roster_settlement_tests::" + name + ")" for name in names)
    execute("six-private-original-tail-controls", ["-p", "cgka-engine", "--lib"], selected, 6)
else:
    raise AssertionError("unsupported scope")
report["scoped_controls_passed"] = True
save()
