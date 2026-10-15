#!/usr/bin/env python3
"""Qualify the bounded cache candidate and detect a fresh-facts bypass at runtime."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

FEATURES = "marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks"
APP = "native_device_linking::automatic_pairing_acceptance::"
APP_NAMES = [
    "third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts",
    "blocked_sibling_consent_does_not_starve_another_approved_peer",
    "automatic_sync_does_not_block_foreground_enrollment_completion",
    "automatic_transport_cannot_keep_dropped_original_authority_alive",
    "ordinary_one_scan_enrollment_has_original_cancellation_without_chat_sharing",
    "automatic_one_scan_exchange_keeps_both_human_comparisons_required",
    "automatic_pairing_requires_explicit_enrollment_and_shares_existing_and_later_chats",
]
OWNER = "client::device_linking::sibling_sharing::tests::"
CORE_NAMES = [
    "private_roster_settlement_warm_group_cache_rejects_foreign_mls_tree_deletion",
    "private_roster_settlement_warm_group_cache_rechecks_foreign_confirmation_facts",
    "private_roster_settlement_warm_group_cache_rechecks_foreign_denial",
    "private_roster_settlement_requires_exact_confirmations_on_both_real_successors",
    "private_roster_settlement_completed_encrypted_reopen_preserves_roster_without_admission",
    "private_roster_settlement_delete_permanently_fences_completed_round",
    "private_roster_settlement_delete_sql_fault_preserves_crypto_round_and_live_admission",
]
app = [APP + name for name in APP_NAMES] + [OWNER + name for name in ["original_choice_cancel_wakes_every_registered_child_without_actor_rpc", "original_choice_children_do_not_extend_the_captured_deadline"]]
args = ["--locked", "-p", "marmot-app", "-p", "cgka-engine", "--lib", "--features", FEATURES]
report = {"source": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(), "rust_min_stack_bytes": 4194304, "test_threads": 1, "automatic_retries": 0, "controls": {}, "qualification_passed": False}
root = Path("settled-cache-evidence")
root.mkdir()
def save():
    (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")
def run(name, selected, expected):
    inventory = json.loads(subprocess.check_output(["cargo", "nextest", "list", *args, "-E", selected, "--message-format", "json"], text=True))
    cases = [test for suite in inventory["rust-suites"].values() for test, case in suite["testcases"].items() if case["filter-match"]["status"] == "matches" and not case["ignored"]]
    assert len(cases) == expected, "exact nonignored selection count required"
    result = subprocess.run(["cargo", "nextest", "run", *args, "-E", selected, "--profile", "m5-bounded", "--test-threads", "1", "--retries", "0", "--no-fail-fast"], capture_output=True, text=True)
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
    rows = re.findall(r"Summary\s+\[[^\]]*\]\s+(\d+)(?:/\d+)?\s+tests? run:\s*([^\n]*)", output)
    assert len(rows) == 1 and int(rows[0][0]) == expected, "actual runtime counts required"
    def count(label):
        match = re.search(r"(\d+) " + label, rows[0][1])
        return int(match[1]) if match else 0
    proof = {"executed_nonignored": expected, "passed": count("passed"), "failed": count("failed"), "exit_code": result.returncode}
    safe_names = app + CORE_NAMES
    failed_lines = [line for line in output.splitlines() if re.search(r"\bFAIL\b", line)]
    proof["failed_case_names"] = [case for case in safe_names if any(case in line for line in failed_lines)]
    allowed_stages = {"third-device-completion", "fourth-device-completion", "sibling-consent-held-before-peer-progress", "automatic-publication-held-before-completion"}
    proof["completion_stage_markers"] = [stage for stage in re.findall(r"automatic-enrollment-control stage=([a-z-]+)", output) if stage in allowed_stages]
    proof["panic_locations"] = [{"file": file, "line": int(line), "column": int(column)} for file, line, column in re.findall(r"panicked at (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)", output)]
    error_names = {"Storage", "Backend", "Other", "UnknownGroup", "Serialize", "InvalidState", "InvalidArgument"}
    proof["unwrap_error_categories"] = [value for value in re.findall(r"Err.? value: ([A-Za-z]+)", output) if value in error_names]
    proof["closed_failure_categories"] = [category for needle, category in [
        ("automatic pairing did not reach required phase", "original-phase-not-reached"),
        ("one blocked consent publication must not starve another approved sibling", "original-combined-sibling-fairness"),
        ("the actual automatic publication must be held before completion", "original-automatic-held-setup"),
        ("cached parsed state never revives a denied settlement", "fresh-denial-assertion"),
        ("corrupt completed facts retain their exact typed storage error", "typed-corruption-assertion"),
        ("cached parsed state cannot conceal an authoritative foreign tree deletion", "foreign-tree-assertion"),
    ] if needle in output]
    report["controls"][name] = proof
    save()
    return proof, output
import os
if os.environ.get("SETTLED_CACHE_DIAGNOSTIC") == "three-existing":
    for case in app[:3]:
        run(case, "package(marmot-app) & test(=" + case + ")", 1)
    report["diagnostic_complete"] = True
    save()
    raise SystemExit(0)
if os.environ.get("SETTLED_CACHE_DIAGNOSTIC") == "safety-only":
    selected = "package(cgka-engine) & (" + " | ".join("test(" + case + ")" for case in CORE_NAMES[:2]) + ")"
    run("two-safety-fixture-diagnosis", selected, 2)
    raise SystemExit(0)
all_filter = "(" + " | ".join("test(=" + name + ")" for name in app) + ") | (package(cgka-engine) & (" + " | ".join("test(" + name + ")" for name in CORE_NAMES) + "))"
safety_only = os.environ.get("SETTLED_CACHE_DIAGNOSTIC") == "denial-controls"
if safety_only:
    selected = "package(cgka-engine) & (" + " | ".join("test(" + case + ")" for case in CORE_NAMES[:3]) + ")"
    proof, _ = run("three-safety-controls", selected, 3)
    assert proof["passed"] == 3 and proof["failed"] == 0
else:
    proof, _ = run("original-nine-and-seven-safety-controls", all_filter, 16)
# Preserve failures but still execute the independent narrow mutation evidence.
report["all_sixteen_passed"] = not safety_only and proof["passed"] == 16 and proof["failed"] == 0
fact_filter = "package(cgka-engine) & test(private_roster_settlement_warm_group_cache_rechecks_foreign_denial)"
proof, _ = run("denial-baseline", fact_filter, 1)
assert proof["passed"] == 1 and proof["failed"] == 0
path = Path("crates/cgka-engine/src/private_roster_settlement.rs")
original = path.read_bytes()
original_hash = hashlib.sha256(original).hexdigest()
anchor = b"let Some(state) = completed_round_for_tree(storage, group, &actual)? else {"
replacement = b"let Some(state) = storage.private_roster_settlement_storage().ok_or_else(unavailable)?.read_round()? else {"
assert original.count(anchor) == 1
try:
    path.write_bytes(original.replace(anchor, replacement))
    proof, output = run("completed-check-bypass-mutant", fact_filter, 1)
    report["denial_mutant_runtime_detected"] = proof["passed"] == 0 and proof["failed"] == 1 and "cached parsed state never revives a denied settlement" in output
    save()
    assert report["denial_mutant_runtime_detected"], "actual fresh-facts assertion must kill mutant"
finally:
    path.write_bytes(original)
    report["source_sha256_before"] = original_hash
    report["source_sha256_restored"] = hashlib.sha256(path.read_bytes()).hexdigest()
    save()
assert report["source_sha256_restored"] == original_hash
proof, _ = run("denial-restored", fact_filter, 1)
assert proof["passed"] == 1 and proof["failed"] == 0
report["safety_and_mutation_passed"] = report["denial_mutant_runtime_detected"]
report["qualification_passed"] = report["all_sixteen_passed"] and report["denial_mutant_runtime_detected"]
save()
assert report["safety_and_mutation_passed"] if safety_only else report["qualification_passed"], "original regression or safety/mutation gate remains failing"
