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

BASELINE = "288bbdd9f1e59474ef309da6236276ccb2b9c986"
UPSTREAM = "ab1de296fb16d846306a90d10c2de44ba67bf9ae"
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
    "crates/marmot-app/src/client/delivery_spill.rs",
    "crates/marmot-app/src/client/sync.rs",
    "crates/marmot-app/src/client/device_linking/sibling_sharing.rs",
]:
    source_paths.append(":!" + adapted)
assert not subprocess.check_output(["git", "diff", BASELINE, "HEAD", "--", *source_paths]), "controller branch must not import unrelated product experiments"
root = Path("checkpoint-evidence")
root.mkdir()
report = {"source": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(), "product_baseline": BASELINE, "upstream_master": UPSTREAM, "scope": os.environ["RECONCILED_SCOPE"], "cohort": os.environ.get("RECONCILED_COHORT", "experimental"), "rust_min_stack_bytes": 4194304, "test_threads": 1, "automatic_retries": 0, "controls": {}, "qualification_passed": False, "lock_sha256": hashlib.sha256(Path("Cargo.lock").read_bytes()).hexdigest()}
report["adapted_source_sha256"] = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in ["crates/marmot-app/src/runtime/account_worker.rs", "crates/marmot-app/src/client/delivery_spill.rs", "crates/marmot-app/src/client/sync.rs", "crates/marmot-app/src/client/device_linking/sibling_sharing.rs"]}
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
if scope in {"checkpoint-controls", "pipeline-three"}:
    assert report["cohort"] == "experimental"
    cases = NATIVE + [APP + case for case in [
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
    if scope == "pipeline-three":
        cases = NATIVE
    passed = True
    for case in cases:
        proof, _ = run(case, "package(marmot-app) & test(=" + case + ")", 1, args)
        passed = passed and proof["passed"] == 1 and proof["failed"] == 0
    report["original_controls_passed"] = passed
    qualified_spill_hashes = {'crates/marmot-app/src/client/delivery_spill.rs': 'f7155f16933ce395b4e4bae820e7e49049db277c5a8bbc9bc3d8682dac9db527', 'crates/marmot-app/src/client/sync.rs': '5bf3b6a413d28856cd34d2342df40dbf5a807f2aea476306c1eb6bfe5188aa7c'}
    unchanged_spill = all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected for path, expected in qualified_spill_hashes.items())
    assert unchanged_spill, "reuse only exact qualified spill source"
    report["reused_spill_evidence"] = {"source": "d6f2f8b473372d269ee2d8a535626e6f6a39ecca", "default_run": 38758834947, "experimental_run": 38758834888, "unchanged_source": unchanged_spill}
    report["diagnostic_complete"] = True
    report["scoped_controls_passed"] = passed
    save()
    assert passed, "outer checkpoint remains unqualified"
elif scope == "spill-controls":
    selected = "package(marmot-app) & (" + " | ".join("test(=" + case + ")" for case in SPILL_CASES) + ")"
    proof, _ = run("seven-real-spill-controls", selected, 7, args)
    report["scoped_controls_passed"] = proof["passed"] == 7 and proof["failed"] == 0
    save()
    assert report["scoped_controls_passed"], "all seven actual spill controls required"
elif scope in {"remove-outer-checkpoint", "remove-due-order", "remove-second-pass"}:
    assert report["cohort"] == "experimental"
    case = NATIVE[0]
    selected = "package(marmot-app) & test(=" + case + ")"
    proof, _ = run("baseline-original-four-device", selected, 1, args)
    assert proof["passed"] == 1 and proof["failed"] == 0, "actual baseline completion required before mutation"
    if scope == "remove-second-pass":
        path = Path("crates/marmot-app/src/client/device_linking/sibling_sharing.rs")
        anchor = b"                scheduled.push(index);"
        assert path.read_bytes().count(anchor) == 1
        mutant = path.read_bytes().replace(anchor, b"                // Mutation: omit only the bounded second-pass admission.", 1)
    else:
        path = Path("crates/marmot-app/src/runtime/account_worker.rs")
        checkpoint = b"        // arm; here every previous durable operation has already completed.\n        tokio::task::yield_now().await;"
        assert path.read_bytes().count(checkpoint) == 1
        if scope == "remove-due-order":
            # Reconstruct only the original order, preserving the exact outer
            # checkpoint; sibling/other source files are never mutated here.
            mutant = subprocess.check_output(["git", "show", BASELINE + ":" + str(path)])
            insert_before = b'        #[cfg(feature = "experimental-device-sync")]\n        let private_echo_busy = private_echo_recovery.is_some();'
            assert mutant.count(insert_before) == 1
            checkpoint_lines = b"        // Ready inputs can complete an owned turn without suspending this task.\n        // Hand back to the executor between turns so I/O and timer readiness can\n        // advance. Inside select this yield could be absorbed by another ready\n        // arm; here every previous durable operation has already completed.\n        tokio::task::yield_now().await;\n"
            mutant = mutant.replace(insert_before, checkpoint_lines + insert_before, 1)
        else:
            mutant = path.read_bytes().replace(checkpoint, b"        // arm; here every previous durable operation has already completed.", 1)
    original = path.read_bytes()
    before = hashlib.sha256(original).hexdigest()
    assert original != mutant
    report["mutation"] = {"name": scope, "source_before_sha256": before, "mutant_sha256": hashlib.sha256(mutant).hexdigest(), "runtime_detected": False, "restored_exact": False}
    save()
    try:
        path.write_bytes(mutant)
        proof, _ = run("mutated-original-four-device", selected, 1, args)
        report["mutation"]["runtime_detected"] = proof["passed"] == 0 and proof["failed"] == 1 and bool({"third-device-completion", "fourth-device-completion"}.intersection(proof["completion_stage_markers"])) and proof["closed_failure_categories"] == ["original-phase-not-reached"] and any(location["file"] == "crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs" and location["line"] == 816 for location in proof["panic_locations"])
        save()
    finally:
        path.write_bytes(original)
        report["mutation"]["restored_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        report["mutation"]["restored_exact"] = report["mutation"]["restored_sha256"] == before
        save()
    proof, _ = run("restored-original-four-device", selected, 1, args)
    report["mutation"]["restored_runtime_passed"] = proof["passed"] == 1 and proof["failed"] == 0
    report["scoped_controls_passed"] = all(report["mutation"][key] for key in ["runtime_detected", "restored_exact", "restored_runtime_passed"])
    save()
    assert report["scoped_controls_passed"], "actual original third/fourth completion assertion runtime kill and exact restored green required"
else:
    raise SystemExit("unknown checkpoint scope")
