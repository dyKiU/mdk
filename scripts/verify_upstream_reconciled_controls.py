#!/usr/bin/env python3
"""Run narrow reconciled-source controls; export only static identifiers and typed aggregates."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

BASELINE = "0883c91cf0829c527c6b9aa5fa18e476150d8fee"
UPSTREAM = "d20329e9ac6337294a9b4414a55f97bc76b6581d"
FEATURES = "marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks"
APP = "native_device_linking::automatic_pairing_acceptance::"
NATIVE = [APP + name for name in [
    "third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts",
    "blocked_sibling_consent_does_not_starve_another_approved_peer",
    "automatic_sync_does_not_block_foreground_enrollment_completion",
]]
QUARANTINE = [
    "tests::quarantine_receive::quarantined_group_does_not_block_account_receives",
    "tests::quarantine_receive::locally_deleted_quarantined_group_does_not_block_account_receives",
] + ["client::sync::projection_retry_tests::" + name for name in [
    "quarantined_group_events_do_not_retain_account_projection",
    "strict_quarantined_group_read_defers_instead_of_holding_receives",
    "ordinary_projection_failure_stays_retained_and_counts_toward_stall_warning",
    "deferral_skips_only_unprojected_events_of_deferred_groups",
    "failed_drained_checkpoint_counts_toward_stall_warning",
]]
assert os.environ["RUST_MIN_STACK"] == "4194304"
subprocess.run(["git", "merge-base", "--is-ancestor", UPSTREAM, "HEAD"], check=True)
source_paths = ["crates", "Cargo.toml", "Cargo.lock"]
if os.environ["RECONCILED_SCOPE"] in {"spill", "spill-qualification"}:
    test_file = "crates/marmot-app/src/client/delivery_spill.rs"
    original = subprocess.check_output(["git", "show", BASELINE + ":" + test_file])
    if os.environ["RECONCILED_SCOPE"] == "spill":
        assert Path(test_file).read_bytes().startswith(original), "RED source must leave all original product bytes unchanged"
    else:
        source_paths.append(":!crates/marmot-app/src/client/sync.rs")
    source_paths.append(":!" + test_file)
assert not subprocess.check_output(["git", "diff", BASELINE, "HEAD", "--", *source_paths]), "controller branch must not import product experiments"
root = Path("reconciled-evidence")
root.mkdir()
report = {"source": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(), "product_baseline": BASELINE, "upstream_master": UPSTREAM, "scope": os.environ["RECONCILED_SCOPE"], "cohort": os.environ.get("RECONCILED_COHORT", "experimental"), "rust_min_stack_bytes": 4194304, "test_threads": 1, "automatic_retries": 0, "controls": {}, "qualification_passed": False, "lock_sha256": hashlib.sha256(Path("Cargo.lock").read_bytes()).hexdigest()}
def save():
    (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")

FAILURES = {"Owner", "Collection", "Runtime", "Engine", "Genesis", "Gate", "PrivateInvite"}
PUBLICATION_STAGES = {"BeforeCoreWrap", "AfterCoreWrap", "BeforeRelayPublication", "AfterRelayPublication"}
OBSERVATION_REASONS = {"VerifierFallback", "NoRound", "GuardInvalid", "NoSettledRoster", "SharingPending", "Complete"}

def aggregate_value(text):
    # Interpret only this closed Rust Debug subset; never evaluate source or calls.
    if len(text) > 4096 or not re.fullmatch(r"[A-Za-z0-9_,()\[\]\s]+", text):
        raise ValueError("unsupported aggregate grammar")
    def decode(node, depth=0):
        if depth > 8:
            raise ValueError("aggregate nesting bound")
        if isinstance(node, ast.Constant) and (node.value is None or type(node.value) is int and 0 <= node.value < 2**64):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in {"true", "false"}:
                return node.id == "true"
            if node.id in FAILURES | PUBLICATION_STAGES | OBSERVATION_REASONS:
                return node.id
        if isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) <= 128:
            return [decode(item, depth + 1) for item in node.elts]
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Some" and len(node.args) == 1 and not node.keywords:
            return decode(node.args[0], depth + 1)
        raise ValueError("unsupported aggregate type")
    return decode(ast.parse(text, mode="eval").body)

def integers(value, size):
    return value is None or isinstance(value, list) and len(value) == size and all(type(item) is int for item in value)

def channel(value):
    return value is None or isinstance(value, list) and len(value) == 5 and all(type(item) is int for item in value[:3]) and (value[3] is None or value[3] in FAILURES) and (value[4] is None or value[4] in PUBLICATION_STAGES)

def existing_aggregates(output):
    records = {}
    rejected = 0
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("automatic-enrollment-control ") or "stage=" in line:
            continue
        try:
            match = re.fullmatch(r"automatic-enrollment-control side=(left|right) primary/expected/children/completed=(.*?) intake=(.*?) rejections=(.*?) context_rejections=(.*?) projection=(.*)", line)
            if match:
                side = match[1]
                values = [aggregate_value(match[index]) for index in range(2, 7)]
                completion = values[0]
                assert completion is None or isinstance(completion, list) and len(completion) == 4 and type(completion[0]) is bool and (completion[1] is None or type(completion[1]) is int) and all(type(value) is int for value in completion[2:])
                assert all(integers(value, size) for value, size in zip(values[1:], [8, 4, 9, 4]))
                records[side + "_completion"] = dict(zip(["completion", "intake", "rejections", "context_rejections", "projection"], values))
                continue
            match = re.fullmatch(r"automatic-enrollment-control side=(left|right) (child_channels|native_rpc_counts/elapsed_ms/branch)=(.*)", line)
            if match:
                value = aggregate_value(match[3])
                if match[2] == "child_channels":
                    assert value is None or isinstance(value, list) and all(channel(item) for item in value)
                    key = match[1] + "_child_channels"
                else:
                    assert value is None or isinstance(value, list) and len(value) == 3 and integers(value[0], 6) and integers(value[1], 6) and (value[2] is None or isinstance(value[2], list) and len(value[2]) == 2 and value[2][0] in OBSERVATION_REASONS and type(value[2][1]) is int)
                    key = match[1] + "_native_rpc"
                records[key] = value
                continue
            match = re.fullmatch(r"automatic-enrollment-control existing_index=([0-9]+) child_channel=(.*)", line)
            if match:
                assert int(match[1]) < 128
                value = aggregate_value(match[2])
                assert channel(value)
                if len(records) >= 12:
                    raise ValueError("aggregate record bound")
                records["existing_" + match[1]] = value
                continue
            rejected += 1
        except (SyntaxError, ValueError, AssertionError, RecursionError, TypeError):
            rejected += 1
    return records, rejected

def run(name, selected, expected, args):
    listed_at = time.monotonic()
    inventory = json.loads(subprocess.check_output(["cargo", "nextest", "list", *args, "-E", selected, "--message-format", "json"], text=True))
    cases = [test for suite in inventory["rust-suites"].values() for test, case in suite["testcases"].items() if case["filter-match"]["status"] == "matches" and not case["ignored"]]
    assert all(re.fullmatch(r"[A-Za-z0-9_:]+", case) for case in cases)
    expected = len(cases) if expected is None else expected
    assert expected > 0 and len(cases) == expected, "exact nonignored selection count required"
    list_seconds = time.monotonic() - listed_at
    executed_at = time.monotonic()
    result = subprocess.run(["cargo", "nextest", "run", *args, "-E", selected, "--profile", "m5-bounded", "--test-threads", "1", "--retries", "0", "--no-fail-fast"], capture_output=True, text=True)
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
    rows = re.findall(r"Summary\s+\[[^\]]*\]\s+(\d+)(?:/\d+)?\s+tests? run:\s*([^\n]*)", output)
    assert len(rows) == 1 and int(rows[0][0]) == expected, "actual runtime counts required"
    def count(label):
        match = re.search(r"(\d+) " + label, rows[0][1])
        return int(match[1]) if match else 0
    proof = {"executed_nonignored": expected, "passed": count("passed"), "failed": count("failed"), "exit_code": result.returncode}
    safe_names = cases
    failed_lines = [line for line in output.splitlines() if re.search(r"\bFAIL\b", line)]
    proof["failed_case_names"] = [case for case in safe_names if any(case in line for line in failed_lines)]
    allowed_stages = {"third-device-completion", "fourth-device-completion", "sibling-consent-held-before-peer-progress", "automatic-publication-held-before-completion"}
    proof["completion_stage_markers"] = [stage for stage in re.findall(r"automatic-enrollment-control stage=([a-z-]+)", output) if stage in allowed_stages]
    proof["panic_locations"] = [{"file": file, "line": int(line), "column": int(column)} for file, line, column in re.findall(r"panicked at (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)", output)]
    error_names = {"Storage", "Backend", "Other", "UnknownGroup", "Serialize", "InvalidState", "InvalidArgument"}
    proof["unwrap_error_categories"] = [value for value in re.findall(r"Err.? value: ([A-Za-z]+)", output) if value in error_names]
    proof["closed_failure_categories"] = [category for needle, category in [
        ("a cancelled cooperative offer must not be repeated before the same durable receive", "cancelled-spill-offer-repeated"),
        ("automatic pairing did not reach required phase", "original-phase-not-reached"),
        ("one blocked consent publication must not starve another approved sibling", "original-combined-sibling-fairness"),
        ("the actual automatic publication must be held before completion", "original-automatic-held-setup"),
        ("cached parsed state never revives a denied settlement", "fresh-denial-assertion"),
        ("corrupt completed facts retain their exact typed storage error", "typed-corruption-assertion"),
        ("cached parsed state cannot conceal an authoritative foreign tree deletion", "foreign-tree-assertion"),
    ] if needle in output]
    proof["existing_numeric_enum_aggregates"], proof["aggregate_parse_rejections"] = existing_aggregates(output)
    proof["compile_or_cached_list_seconds"] = list_seconds
    proof["execution_command_seconds"] = time.monotonic() - executed_at
    proof["filtered_or_skipped"] = count("skipped")
    proof["cargo_arguments"] = args
    proof["filter"] = selected
    proof["selected_case_names"] = cases
    proof["ignored_in_inventory_all_cases"] = sum(1 for suite in inventory["rust-suites"].values() for case in suite["testcases"].values() if case["ignored"])
    report["controls"][name] = proof
    save()
    return proof, output
scope = report["scope"]
features = FEATURES if report["cohort"] == "experimental" else FEATURES.replace(",marmot-app/experimental-device-sync", "")
args = ["--locked", "-p", "marmot-app", "--lib", "--features", features]
if scope in {"native", "quarantine", "experimental"}:
    quarantine_ok = True
    if scope in {"quarantine", "experimental"}:
        selected = "package(marmot-app) & (" + " | ".join("test(=" + case + ")" for case in QUARANTINE) + ")"
        proof, _ = run("seven-new-upstream-quarantine-controls", selected, 7, args)
        quarantine_ok = proof["passed"] == 7 and proof["failed"] == 0
    native_ok = True
    if scope in {"native", "experimental"}:
        for case in NATIVE:
            proof, _ = run(case, "package(marmot-app) & test(=" + case + ")", 1, args)
            native_ok = native_ok and proof["passed"] == 1 and proof["failed"] == 0
    report["diagnostic_complete"] = True
    report["quarantine_controls_passed"] = quarantine_ok
    report["native_controls_passed"] = native_ok
    save()
    assert quarantine_ok and native_ok, "reconciled unchanged scoped controls remain failing"
elif scope == "spill":
    case = "client::delivery_spill::yield_handoff_tests::cancelled_spill_receive_keeps_its_cooperative_offer_and_real_message"
    proof, _ = run(case, "package(marmot-app) & test(=" + case + ")", 1, args)
    report["expected_regression_red"] = proof["passed"] == 0 and proof["failed"] == 1 and "cancelled-spill-offer-repeated" in proof["closed_failure_categories"]
    save()
    assert report["expected_regression_red"], "expected exact behavioral RED was not established"
elif scope == "spill-qualification":
    case = "client::delivery_spill::yield_handoff_tests::cancelled_spill_receive_keeps_its_cooperative_offer_and_real_message"
    controls = ["client::delivery_spill::tests::" + name for name in [
        "spilled_row_stays_until_its_event_is_seen",
        "unreadable_receipts_keep_the_row_without_spending_an_attempt",
        "a_failed_spill_read_waits_instead_of_blocking_live_delivery",
        "a_failed_undecodable_discard_keeps_a_paced_retry",
        "unsettled_hand_off_is_read_again",
        "unadmitted_row_becomes_queue_loss_after_its_last_retry",
    ]] + [case]
    selected = "package(marmot-app) & (" + " | ".join("test(=" + name + ")" for name in controls) + ")"
    proof, _ = run("seven-real-spill-controls", selected, 7, args)
    assert proof["passed"] == 7 and proof["failed"] == 0, "spill baseline controls must all pass"
    path = Path("crates/marmot-app/src/client/sync.rs")
    original = path.read_bytes()
    original_hash = hashlib.sha256(original).hexdigest()
    anchor = b"if self.delivery_spill.pending() && self.delivery_spill.offer_cooperative_turn() {"
    assert original.count(anchor) == 1, "exact new cancellation handoff anchor required"
    mutant = original.replace(anchor, b"if self.delivery_spill.pending() {", 1)
    report["mutation"] = {"name": "remove-reader-cooperative-handoff", "source_before_sha256": original_hash, "mutant_sha256": hashlib.sha256(mutant).hexdigest(), "runtime_detected": False, "restored_exact": False}
    save()
    try:
        path.write_bytes(mutant)
        proof, _ = run("remove-reader-handoff-mutant", "package(marmot-app) & test(=" + case + ")", 1, args)
        report["mutation"]["runtime_detected"] = proof["passed"] == 0 and proof["failed"] == 1 and proof["closed_failure_categories"] == ["cancelled-spill-offer-repeated"]
        save()
    finally:
        path.write_bytes(original)
        restored_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        report["mutation"]["restored_sha256"] = restored_hash
        report["mutation"]["restored_exact"] = restored_hash == original_hash
        save()
    proof, _ = run("exact-restored-handoff-control", "package(marmot-app) & test(=" + case + ")", 1, args)
    report["mutation"]["restored_runtime_passed"] = proof["passed"] == 1 and proof["failed"] == 0
    report["scoped_controls_passed"] = all(report["mutation"][key] for key in ["runtime_detected", "restored_exact", "restored_runtime_passed"])
    save()
    assert report["scoped_controls_passed"], "genuine runtime handoff detection and exact restored control required"
elif scope == "media":
    proof, _ = run("new-media-store-crate-suite", "package(media-store)", None, ["--locked", "-p", "media-store", "--all-targets"])
    docs = subprocess.run(["cargo", "test", "--locked", "-p", "media-store", "--doc"], capture_output=True, text=True)
    doc_output = re.sub(r"\x1b\[[0-9;]*m", "", docs.stdout + docs.stderr)
    summary = re.search(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", doc_output)
    report["doc_tests"] = {"exit_code": docs.returncode, "passed": int(summary[2]), "failed": int(summary[3]), "ignored": int(summary[4])} if summary else {"exit_code": docs.returncode, "summary_missing": True}
    report["scoped_controls_passed"] = proof["passed"] == proof["executed_nonignored"] and proof["failed"] == 0 and docs.returncode == 0 and summary is not None
    save()
    assert report["scoped_controls_passed"], "media-store suite or doc tests failed"
else:
    raise SystemExit("unknown scoped control")
