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

BASELINE = "8707ecac9f686a15c4088bf4f92aa07a7e029bc9"
UPSTREAM = "31f74030660572831521fd75f9d220b6a1206113"
FEATURES = "marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks"
APP = "native_device_linking::automatic_pairing_acceptance::"
NATIVE = [APP + name for name in [
    "third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts",
    "blocked_sibling_consent_does_not_starve_another_approved_peer",
    "automatic_sync_does_not_block_foreground_enrollment_completion",
]]
SPILL_CASES = ["client::delivery_spill::tests::" + name for name in [
    "spilled_row_stays_until_its_event_is_seen",
    "unreadable_receipts_keep_the_row_without_spending_an_attempt",
    "a_failed_spill_read_waits_instead_of_blocking_live_delivery",
    "a_failed_undecodable_discard_keeps_a_paced_retry",
    "unsettled_hand_off_is_read_again",
    "unadmitted_row_becomes_queue_loss_after_its_last_retry",
]] + ["client::delivery_spill::yield_handoff_tests::cancelled_spill_receive_keeps_its_cooperative_offer_and_real_message"]
assert os.environ["RUST_MIN_STACK"] == "4194304"
subprocess.run(["git", "merge-base", "--is-ancestor", UPSTREAM, "HEAD"], check=True)
source_paths = ["crates", "Cargo.toml", "Cargo.lock"]
for adapted in [
    "crates/marmot-app/src/runtime/account_worker.rs",
    "crates/marmot-app/src/client/device_linking.rs",
    "crates/marmot-app/src/client/device_linking/sibling_sharing.rs",
    "crates/marmot-app/src/account_chat_sharing/enabled.rs",
    "crates/marmot-app/src/client/private_enrollment_proposal.rs",
    "crates/marmot-app/src/native_device_linking/enabled.rs",
    "crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs",
]:
    source_paths.append(":!" + adapted)
assert not subprocess.check_output(["git", "diff", BASELINE, "HEAD", "--", *source_paths]), "controller branch must not import unrelated product experiments"
root = Path("latest-evidence")
root.mkdir()
report = {"source": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(), "product_baseline": BASELINE, "upstream_master": UPSTREAM, "scope": os.environ["RECONCILED_SCOPE"], "cohort": os.environ.get("RECONCILED_COHORT", "experimental"), "rust_min_stack_bytes": 4194304, "test_threads": 1, "automatic_retries": 0, "controls": {}, "qualification_passed": False, "lock_sha256": hashlib.sha256(Path("Cargo.lock").read_bytes()).hexdigest()}
report["compile_environment_observed"] = {name: os.environ.get(name) for name in ["CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "RUST_MIN_STACK"]}
report["cargo_config_sha256"] = hashlib.sha256(Path(".cargo/config.toml").read_bytes()).hexdigest() if Path(".cargo/config.toml").is_file() else None
report["rustc_incremental_invocation"] = "not captured; environment recorded without inferring a compiler flag"
report["relevant_source_sha256"] = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in ["crates/marmot-app/src/client/delivery_spill.rs", "crates/marmot-app/src/client/sync.rs", "crates/marmot-app/src/runtime/account_worker.rs", "crates/marmot-app/src/client/device_linking/sibling_sharing.rs", "crates/cgka-engine/src/openmls_projection.rs", "crates/storage-sqlite/src/connection.rs", "crates/traits/src/storage.rs"]}
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
    listing = subprocess.run(["cargo", "nextest", "list", *args, "-E", selected, "--message-format", "json"], capture_output=True, text=True)
    report["controls"][name] = {"list_exit_code": listing.returncode, "compile_error_codes": re.findall(r"error\[(E[0-9]+)\]", listing.stderr), "compile_error_locations": re.findall(r"(?:-->|:::)\s+(crates/[A-Za-z0-9_./-]+\.rs:[0-9]+:[0-9]+)", listing.stderr)}
    save()
    assert listing.returncode == 0, "compile/list failure is not behavioral evidence"
    inventory = json.loads(listing.stdout)
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
        ("automatic pairing did not reach required phase", "original-phase-not-reached"),
        ("one blocked consent publication must not starve another approved sibling", "original-combined-sibling-fairness"),
        ("the actual automatic publication must be held before completion", "original-automatic-held-setup"),
        ("cached parsed state never revives a denied settlement", "fresh-denial-assertion"),
        ("corrupt completed facts retain their exact typed storage error", "typed-corruption-assertion"),
        ("cached parsed state cannot conceal an authoritative foreign tree deletion", "foreign-tree-assertion"),
    ] if needle in output]
    proof["existing_numeric_enum_aggregates"], proof["aggregate_parse_rejections"] = existing_aggregates(output)
    harvest_events = [[int(before), int(after), error == "true"] for before, after, error in re.findall(r"sibling-harvest-control slots_before=(\d+) slots_remaining=(\d+) error=(true|false)", output)]
    assert len(harvest_events) <= 128 and all(0 <= after <= before <= 4 for before, after, error in harvest_events), "bounded owned result service observations required"
    proof["owned_harvest_service"] = {"events": len(harvest_events), "owned_slots_examined": sum(before for before, after, error in harvest_events), "results_removed": sum(before-after for before, after, error in harvest_events), "error_events": sum(error for before, after, error in harvest_events), "records": harvest_events}

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
if scope in {"latest-three", "latest-controls", "latest-fourth-trace"}:
    assert report["cohort"] == "experimental"
    cases = NATIVE[:1] if scope == "latest-fourth-trace" else NATIVE
    if scope == "latest-controls":
        cases = cases + [APP + case for case in [
            "automatic_transport_cannot_keep_dropped_original_authority_alive",
            "ordinary_one_scan_enrollment_has_original_cancellation_without_chat_sharing",
            "automatic_one_scan_exchange_keeps_both_human_comparisons_required",
            "automatic_pairing_requires_explicit_enrollment_and_shares_existing_and_later_chats",
        ]] + ["client::device_linking::sibling_sharing::tests::" + case for case in [
            "original_choice_cancel_wakes_every_registered_child_without_actor_rpc",
            "original_choice_children_do_not_extend_the_captured_deadline",
        ]] + [
            "tests::device_linking_startup::device_linking_worker_commands_are_scoped_and_idle_cleanup_retries",
            "native_device_linking::tests::actual::native_original_worker_expiry_cannot_revive_terminal_session",
            "native_device_linking::tests::actual::native_shutdown_closes_original_session_without_a_new_worker",
        ]
    passed = True
    for case in cases:
        proof, output = run(case, "package(marmot-app) & test(=" + case + ")", 1, args)
        if scope == "latest-fourth-trace":
            rows = []
            rejected = 0
            for line in output.splitlines():
                if not line.strip().startswith("sibling-fourth-lifecycle "): continue
                try:
                    row = json.loads(line.strip().removeprefix("sibling-fourth-lifecycle "))
                    assert set(row) == {"peer", "role", "snapshot"} and type(row["peer"]) is int and row["peer"] in {0,1} and type(row["role"]) is int and row["role"] in {0,1}
                    snap = row["snapshot"]
                    if snap is not None:
                        assert set(snap) == {"records", "before_window", "dropped", "pending", "owner_state_live"}
                        assert type(snap["before_window"]) is int and type(snap["dropped"]) is int and type(snap["owner_state_live"]) is bool
                        assert snap["pending"] is None or (len(snap["pending"]) == 2 and type(snap["pending"][0]) is bool and snap["pending"][1] in {0,1,2})
                        assert len(snap["records"]) <= 256
                        for at, stage, flags, pending, ready in snap["records"]:
                            assert type(at) is int and at >= 0 and type(stage) is int and 0 <= stage <= 7
                            assert flags is None or (type(flags) is int and 0 <= flags <= 255)
                            assert pending is None or type(pending) is bool
                            assert type(ready) is int and ready in {0,1,2}
                    rows.append(row)
                except (KeyError, TypeError, ValueError, AssertionError): rejected += 1
            report["fourth_lifecycle"] = rows
            report["fourth_lifecycle_parse_rejections"] = rejected
            report["lifecycle_stage_names"] = ["PeriodicEntry", "PeriodicReturn", "WakeEntry", "WakeReturn", "PolicyCommitted", "PublicationScheduled", "ResultSent", "ControlReturned"]
            report["lifecycle_flags"] = ["originalLive", "stateLive", "ready", "handshakePublished", "policyCommitted", "proofPublished", "peerCommitted", "complete"]
            report["lifecycle_columns"] = ["fourth_elapsed_ms", "stage", "fresh_flags_or_null", "pending_proof_or_null", "result_status_0pending_1success_2error"]
            report["diagnostic_only"] = True
            save()
            assert proof["failed"] == 1 and "fourth-device-completion" in proof["completion_stage_markers"] and "original-phase-not-reached" in proof["closed_failure_categories"]
            assert not rejected and len(rows) == 4 and {(row["peer"],row["role"]) for row in rows} == {(0,0),(0,1),(1,0),(1,1)}
            assert all(row["snapshot"] is not None and row["snapshot"]["dropped"] == 0 for row in rows), "complete bounded fourth-entry evidence required"
            report["diagnostic_complete"] = True
            save()
            raise SystemExit(0)
        passed = passed and proof["passed"] == 1 and proof["failed"] == 0
    report["original_controls_passed"] = passed
    report["scoped_controls_passed"] = passed
    save()
    assert report["scoped_controls_passed"], "latest upstream original controls remain unqualified"
elif scope == "latest-spill":
    selected = "package(marmot-app) & (" + " | ".join("test(=" + case + ")" for case in SPILL_CASES) + ")"
    proof, _ = run("seven-real-spill-controls", selected, 7, args)
    report["scoped_controls_passed"] = proof["passed"] == 7 and proof["failed"] == 0
    save()
    assert report["scoped_controls_passed"], "all seven real spill controls required"
else:
    raise SystemExit("unknown latest-upstream scope")
