#!/usr/bin/env python3
"""Exact scoped controls and independent runtime mutations; remote CI only."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
MODE = "controls"
assert not sys.argv[1:]
OUT = Path("public-proof-memo-evidence")
OUT.mkdir(exist_ok=True)
os.umask(0o077)
FEATURES = "marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks"
CORE_FEATURES = "cgka-engine/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks,storage-sqlite/experimental-device-sync"
SQL_TESTS = ['private_settlement_decode_memo_direct_group_deletions_retire_warm_metadata', 'private_settlement_decode_memo_reuses_only_real_serde_results', 'private_settlement_decode_memo_clears_absent_invalid_and_oversized_rows', 'private_settlement_decode_memo_rechecks_indexes_and_confirmation_facts', 'private_settlement_decode_memo_rollback_reloads_committed_original_bytes', 'private_settlement_decode_memo_is_connection_local_and_close_retires_it', 'private_settlement_decode_memo_close_drains_inflight_sql_before_clearing', 'close_is_idempotent_and_leaves_every_handle_reporting_closed', 'close_rejects_new_admissions_while_waiting_for_the_active_operation', 'close_under_a_live_writer_is_prompt_and_leaves_no_torn_transaction', 'failed_savepoint_rollback_blocks_a_catching_caller_from_committing', 'forget_group_local_is_atomic_and_prevents_protocol_resurrection']
CORE_TESTS = ['private_roster_settlement_fresh_read_rejects_foreign_mls_tree_deletion', 'private_roster_settlement_fresh_read_rechecks_foreign_confirmation_facts', 'private_roster_settlement_fresh_read_rechecks_foreign_denial', 'private_roster_settlement_fresh_read_rechecks_foreign_generation', 'private_roster_settlement_fresh_read_rechecks_foreign_origin_denial', 'private_roster_settlement_decode_memo_stays_inside_pinned_snapshot', 'private_roster_settlement_fresh_read_rejects_missing_nonlocal_confirmation', 'private_roster_settlement_decode_memo_rechecks_same_generation_original_bytes', 'private_roster_settlement_delete_permanently_fences_completed_round', 'private_roster_settlement_delete_sql_fault_preserves_crypto_round_and_live_admission', 'private_roster_settlement_completed_encrypted_reopen_preserves_roster_without_admission']
CORE_TESTS += ['private_proof_memo_exact_positive_reuse_and_changed_signature_rejection', 'private_proof_memo_every_request_field_uses_exact_key_and_default_result', 'private_proof_memo_legacy_timestamp_is_keyed_without_new_rejection', 'private_proof_memo_admission_limits_preserve_legitimate_oversized_verification', 'private_proof_memo_capacity_is_bounded_and_fifo_eviction_reverifies', 'private_proof_memo_poison_falls_back_to_original_verifier', 'private_proof_memo_is_engine_local_and_preserves_real_leaf_binding_guards']
APP_TESTS = ["third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts", "blocked_sibling_consent_does_not_starve_another_approved_peer", "automatic_sync_does_not_block_foreground_enrollment_completion"]
APP_SAFETY_TESTS = ["device_linking_settlement_cancel_sql_fault_revokes_original_delivery_permission", "device_linking_settlement_reservation_cleanup_fault_does_not_allocate_inaccessible_scope"]
report = {"source": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(), "mode": MODE,
          "baseline": "9eae9ce1069ecfd25b6a7da24e9de6a0bce95f59", "features": FEATURES,
          "expected_executed_nonignored":35, "stack_bytes":4194304, "test_threads":1, "automatic_retries":0,
          "full_qualification_passed":False, "qualification_scope":"Engine-owned pure proof memo, unchanged raw-decode SQL/Core/lifecycle safety and original enrollment bodies",
          "qualification_passed":False, "checks":{},
          "environment":{key:os.environ.get(key) for key in ["CARGO_INCREMENTAL","CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG","RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS","RUSTC_BOOTSTRAP","CARGO_PROFILE_TEST_OPT_LEVEL","CARGO_PROFILE_DEV_OPT_LEVEL"]}}
def save(): (OUT/"result.json").write_text(json.dumps(report,indent=2)+"\n")
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def fingerprint(exclude=()):
    value=hashlib.sha256()
    for name in sorted(subprocess.check_output(["git","ls-files"],text=True).splitlines()):
        if name in exclude: continue
        path=Path(name)
        data=os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
        value.update(name.encode()+b"\0"+hashlib.sha256(data).digest())
    return value.hexdigest()
assert os.environ["RUST_MIN_STACK"]=="4194304" and not os.environ.get("RUSTFLAGS")
assert os.environ.get("GITHUB_ACTIONS")=="true" and report["source"]==os.environ["GITHUB_SHA"]
assert os.environ.get("CARGO_INCREMENTAL")=="1" and not os.environ.get("CARGO_ENCODED_RUSTFLAGS") and not os.environ.get("RUSTC_BOOTSTRAP")
report["tree"]=subprocess.check_output(["git","rev-parse","HEAD^{tree}"],text=True).strip()
report["source_before_sha256"]=fingerprint()
report["lock_sha256"]=digest("Cargo.lock")
report["nextest_config_sha256"]=digest(".config/nextest.toml")
report["cargo_config_sha256"]=digest(".cargo/config.toml")
report["toolchain"]=subprocess.check_output(["rustc","--version"],text=True).strip()
save()
def run(names,label):
    packages=sorted({"storage-sqlite" if name in SQL_TESTS else "cgka-engine" if name in CORE_TESTS else "marmot-app" for name in names})
    if "marmot-app" not in packages:
        packages=["cgka-engine","storage-sqlite"]
    features=FEATURES if "marmot-app" in packages else CORE_FEATURES
    args=["cargo","nextest","list","--locked","--lib","--features",features]
    for package in packages: args.extend(["-p",package])
    args.extend(["-E"," | ".join("test("+name+")" for name in names),"--message-format","json"])
    starting_inputs=fingerprint()
    assert digest("Cargo.lock")==report["lock_sha256"] and digest(".config/nextest.toml")==report["nextest_config_sha256"] and digest(".cargo/config.toml")==report["cargo_config_sha256"]
    assert starting_inputs==report["source_before_sha256"]
    started=time.monotonic()
    listing=subprocess.run(args,capture_output=True,text=True)
    proof={"features":features,"packages":packages,"compile_exit_code":listing.returncode,"compile_seconds":time.monotonic()-started,"source_inputs_sha256":starting_inputs,"cases":[]}
    report["checks"][label]=proof
    save()
    if listing.returncode:
        proof["compile_error_codes"]=sorted(set(re.findall(r"error\[(E[0-9]+)\]",listing.stderr)))
        proof["compile_locations"]=sorted(set(re.findall(r"--> (crates/[A-Za-z0-9_./-]+\.rs:[0-9]+:[0-9]+)",listing.stderr)))[:20]
        save()
        return False
    assert fingerprint()==starting_inputs
    suites=json.loads(listing.stdout)["rust-suites"].values()
    selected={}
    for suffix in names:
        matches=[(name,suite) for suite in suites for name,case in suite["testcases"].items() if name.endswith("::"+suffix) and not case["ignored"]]
        assert len(matches)==1, "exact nonignored selector required"
        selected[suffix]=matches[0]
    proof["selected_nonignored"]=len(selected)
    for suffix in names:
        name,suite=selected[suffix]
        binary=Path(suite["binary-path"])
        case={"test":name,"binary_sha256":digest(binary)}
        assert fingerprint()==starting_inputs
        started=time.monotonic()
        try:
            result=subprocess.run([str(binary),"--exact",name,"--nocapture","--test-threads=1"],capture_output=True,text=True,timeout=300)
        except subprocess.TimeoutExpired:
            case["watchdog_triggered"]=True
            proof["cases"].append(case)
            save()
            return False
        raw=result.stdout+result.stderr
        case.update(seconds=time.monotonic()-started,exit_code=result.returncode)
        summary=re.search(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;",raw)
        if summary:
            case.update(passed=int(summary[1]),failed=int(summary[2]),ignored=int(summary[3]))
            case["executed_nonignored"]=case["passed"]+case["failed"]
        case["panic_locations"]=[{"file":file,"line":int(line),"column":int(column)} for file,line,column in re.findall(r"panicked at (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)",raw)]
        case["original_phase_oracle"]=("automatic pairing did not reach required phase: expected=EnrollmentComplete" in raw and len(case["panic_locations"])==1 and case["panic_locations"][0]["file"]=="crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs" and case["panic_locations"][0]["line"]==839)
        case["completion_markers"]=re.findall(r"automatic-enrollment-control stage=((?:third|fourth)-device-completion)",raw)
        case["observed_completion_phase"]=case["completion_markers"][-1].split("-",1)[0] if case["completion_markers"] else None
        assert fingerprint()==starting_inputs
        proof["cases"].append(case)
        save()
    return all(case.get("executed_nonignored")==1 and case.get("passed")==1 and case.get("failed")==0 and case.get("ignored")==0 and case["exit_code"]==0 for case in proof["cases"])
safe=run(SQL_TESTS+CORE_TESTS,"safety")
report["safety_passed"]=safe
report["app_safety_passed"]=run(APP_SAFETY_TESTS,"app-safety") if safe else False
report["originals_passed"]=run(APP_TESTS,"originals") if safe and report["app_safety_passed"] else False
report["qualification_passed"]=safe and report["app_safety_passed"] and report["originals_passed"]
report["source_after_sha256"]=fingerprint()
report["inputs_pristine"]=report["source_after_sha256"]==report["source_before_sha256"] and subprocess.run(["git","diff","--quiet","HEAD"]).returncode==0
report["qualification_passed"] &= report["inputs_pristine"]
save()
raise SystemExit(0 if report["qualification_passed"] else 1)
