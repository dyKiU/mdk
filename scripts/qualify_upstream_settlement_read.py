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
MODE = sys.argv[1]
assert MODE in {"controls", "consistency-mutant", "performance-mutant"}
OUT = Path("settlement-read-evidence")
OUT.mkdir(exist_ok=True)
os.umask(0o077)
FEATURES = "marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks"
CORE_FEATURES = "cgka-engine/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks,storage-sqlite/experimental-device-sync"
SQL_TESTS = ["private_settlement_combined_read_matches_validated_round_and_facts", "private_settlement_combined_read_preserves_typed_corruption_error", "private_settlement_legacy_combined_read_never_eagerly_loads_facts", "private_settlement_combined_read_rejects_indexed_generation_mismatch"]
CORE_TESTS = ["private_roster_settlement_fresh_read_rejects_foreign_mls_tree_deletion", "private_roster_settlement_fresh_read_rechecks_foreign_confirmation_facts", "private_roster_settlement_fresh_read_rechecks_foreign_denial", "private_roster_settlement_fresh_read_rechecks_foreign_generation", "private_roster_settlement_fresh_read_rechecks_foreign_origin_denial", "private_roster_settlement_loaded_facts_stay_inside_pinned_snapshot", "private_roster_settlement_fresh_read_rejects_missing_nonlocal_confirmation"]
APP_TESTS = ["third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts", "blocked_sibling_consent_does_not_starve_another_approved_peer", "automatic_sync_does_not_block_foreground_enrollment_completion"]
report = {"source": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(), "mode": MODE,
          "baseline": "46230f5744139d7f46c1ba266784919361fdcd1d", "features": FEATURES,
          "stack_bytes":4194304, "test_threads":1, "automatic_retries":0,
          "full_qualification_passed":False, "qualification_scope":"eleven safety controls and three original enrollment bodies, or one independent runtime mutation",
          "qualification_passed":False, "checks":{}, "mutant_killed":False,
          "environment":{key:os.environ.get(key) for key in ["CARGO_INCREMENTAL","CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG","RUSTFLAGS"]}}
def save(): (OUT/"result.json").write_text(json.dumps(report,indent=2)+"\n")
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def fingerprint():
    value=hashlib.sha256()
    for name in sorted(subprocess.check_output(["git","ls-files"],text=True).splitlines()):
        path=Path(name)
        data=os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
        value.update(name.encode()+b"\0"+hashlib.sha256(data).digest())
    return value.hexdigest()
assert os.environ["RUST_MIN_STACK"]=="4194304" and not os.environ.get("RUSTFLAGS")
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
    started=time.monotonic()
    listing=subprocess.run(args,capture_output=True,text=True)
    proof={"features":features,"packages":packages,"compile_exit_code":listing.returncode,"compile_seconds":time.monotonic()-started,"cases":[]}
    report["checks"][label]=proof
    save()
    if listing.returncode:
        proof["compile_error_codes"]=sorted(set(re.findall(r"error\[(E[0-9]+)\]",listing.stderr)))
        proof["compile_locations"]=sorted(set(re.findall(r"--> (crates/[A-Za-z0-9_./-]+\.rs:[0-9]+:[0-9]+)",listing.stderr)))[:20]
        save()
        return False
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
        case["original_phase_oracle"]=("automatic pairing did not reach required phase: expected=EnrollmentComplete" in raw and any(item["file"]=="crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs" and item["line"]==839 for item in case["panic_locations"]))
        case["completion_markers"]=re.findall(r"automatic-enrollment-control stage=((?:third|fourth)-device-completion)",raw)
        case["nonlocal_consistency_oracle"]="missing genuine non-local receipt retains the exact completed-facts corruption error" in raw
        proof["cases"].append(case)
        save()
    return all(case.get("executed_nonignored")==1 and case.get("passed")==1 and case.get("failed")==0 and case.get("ignored")==0 and case["exit_code"]==0 for case in proof["cases"])
if MODE=="controls":
    safe=run(SQL_TESTS+CORE_TESTS,"safety")
    report["safety_passed"]=safe
    report["originals_passed"]=run(APP_TESTS,"originals") if safe else False
    report["qualification_passed"]=safe and report["originals_passed"]
else:
    names=[CORE_TESTS[-1]] if MODE=="consistency-mutant" else [APP_TESTS[0]]
    target=Path("crates/storage-sqlite/src/private_roster_settlement.rs" if MODE=="consistency-mutant" else "crates/cgka-engine/src/private_roster_settlement.rs")
    before=target.read_bytes()
    report["mutation_source_before_sha256"]=digest(target)
    if not run(names,"baseline"):
        save()
        raise SystemExit(1)
    if MODE=="consistency-mutant":
        anchor="(state.phase == PrivateSettlementPhase::Completed) != complete\n        || (complete && state.prepared_ciphertext.is_none())"
        replacement="complete && state.prepared_ciphertext.is_none()"
    else:
        anchor="completed_round_for_tree_in_snapshot(storage, group, &actual)"
        replacement="completed_round_for_tree(storage, group, &actual)"
    source=before.decode()
    assert source.count(anchor)==1
    try:
        target.write_text(source.replace(anchor,replacement,1))
        assert subprocess.check_output(["git","diff","--name-only","HEAD"],text=True).splitlines()==[str(target)]
        report["mutation_source_sha256"]=digest(target)
        mutant_green=run(names,"mutant")
        cases=report["checks"]["mutant"]["cases"]
        if len(cases)==1:
            case=cases[0]
            oracle=case["nonlocal_consistency_oracle"] if MODE=="consistency-mutant" else case["original_phase_oracle"] and bool(case["completion_markers"])
            report["mutant_killed"]=(not mutant_green and case.get("executed_nonignored")==1 and case.get("passed")==0 and case.get("failed")==1 and case.get("ignored")==0 and case.get("exit_code")==101 and oracle)
    finally:
        target.write_bytes(before)
        report["mutation_source_restored_sha256"]=digest(target)
        report["source_restored_exact"]=fingerprint()==report["source_before_sha256"]
        save()
    restored=run(names,"restored")
    report["restored_passed"]=restored
    report["qualification_passed"]=report["mutant_killed"] and report["source_restored_exact"] and restored
report["source_after_sha256"]=fingerprint()
report["inputs_pristine"]=report["source_after_sha256"]==report["source_before_sha256"] and subprocess.run(["git","diff","--quiet","HEAD"]).returncode==0
report["qualification_passed"] &= report["inputs_pristine"]
save()
raise SystemExit(0 if report["qualification_passed"] else 1)
