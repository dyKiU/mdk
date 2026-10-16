#!/usr/bin/env python3
"""Five independent runtime counterfactuals; source restored before every exit."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

BASE = '21b5cbbf0f806580e75147e6e02e27dc3149031b'
PROOF = 'crates/cgka-engine/src/account_identity_proof_memo.rs'
PROOF_TEST = 'crates/cgka-engine/src/account_identity_proof_memo_tests.rs'
SQL = 'crates/storage-sqlite/src/private_roster_settlement.rs'
CONNECTION = 'crates/storage-sqlite/src/connection.rs'
APP_TEST = 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
CORE_TEST = 'crates/cgka-engine/src/private_roster_settlement_tests.rs'
SQL_TEST = 'crates/storage-sqlite/src/private_roster_settlement/tests.rs'
APP_FEATURES = 'marmot-app/otlp-export,marmot-app/product-analytics-export,marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks'
CORE_FEATURES = 'cgka-engine/experimental-device-sync,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks,storage-sqlite/experimental-device-sync'
CASES = {
    'request-equality': (PROOF, 'cgka-engine', 'private_proof_memo_every_request_field_uses_exact_key_and_default_result', PROOF_TEST, 'each changed public request field retains original verifier behavior'),
    'signature-equality': (PROOF, 'cgka-engine', 'private_proof_memo_exact_positive_reuse_and_changed_signature_rejection', PROOF_TEST, 'changed signature must never reuse warmed proof'),
    'proof-deoptimization': (PROOF, 'marmot-app', 'third_and_later_device_enrollment_need_no_extra_qr_or_manual_artifacts', APP_TEST, 'automatic pairing did not reach required phase: expected={phase:?} observed={observed:?}'),
    'raw-byte-equality': (SQL, 'cgka-engine', 'private_roster_settlement_decode_memo_rechecks_same_generation_original_bytes', CORE_TEST, 'same-generation changed original bytes cannot reuse a previous parsed settlement'),
    'post-drain-close': (CONNECTION, 'storage-sqlite', 'private_settlement_decode_memo_close_drains_inflight_sql_before_clearing', SQL_TEST, 'close must clear after the last in-flight SQL decoder releases its guard'),
}

class GateError(Exception):
    pass

def require(condition, code):
    if not condition:
        raise GateError(code)

def digest(value):
    return hashlib.sha256(value).hexdigest()

def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()

def baseline(path):
    return subprocess.check_output(['git', 'show', BASE + ':' + path])

def tracked_hashes():
    result = {}
    for name in git('ls-files').splitlines():
        path = Path(name)
        data = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
        result[name] = digest(data)
    return result

def fingerprint(values):
    result = hashlib.sha256()
    for name, value in sorted(values.items()):
        result.update(name.encode() + b'\0' + bytes.fromhex(value))
    return result.hexdigest()

def exception_receipt(error):
    return {'class': type(error).__name__, 'reason': str(error) if isinstance(error, GateError) else 'controller-exception'}

def assertion_line(path, marker):
    lines = baseline(path).decode().splitlines()
    hits = [index for index, line in enumerate(lines) if marker in line]
    require(len(hits) == 1, 'oracle-message-not-unique')
    index = hits[0]
    if 'panic!(' in lines[index]:
        return index + 1
    for previous in range(index, max(-1, index - 30), -1):
        if re.search(r'\bassert(?:_eq|_ne)?!\(', lines[previous]):
            return previous + 1
    raise GateError('oracle-assertion-not-found')

def transform(case, original):
    text = original.decode()
    if case in ['request-equality', 'signature-equality', 'proof-deoptimization']:
        split = text.index('        verify_proof_signature(request, signature)?;')
        lookup, tail = text[:split], text[split:]
        if case == 'request-equality':
            before, after = 'entry.request == *request && entry.signature == *signature', 'entry.signature == *signature'
        elif case == 'signature-equality':
            before, after = 'entry.request == *request && entry.signature == *signature', 'entry.request == *request'
        else:
            before, after = '        if admissible\n            && let Ok(entries)', '        if admissible && false\n            && let Ok(entries)'
        require(lookup.count(before) == 1, 'lookup-anchor-not-unique')
        return (lookup.replace(before, after, 1) + tail).encode()
    if case == 'raw-byte-equality':
        before, after = '            && raw.as_slice() == bytes', '            && { let _ = raw; true }'
    else:
        before = '// Drain in-flight SQL first: a previous reader cannot reinsert after this.\n            self.clear_private_settlement_decode();'
        after = '// Drain in-flight SQL first: a previous reader cannot reinsert after this.\n            // Mutant omits only post-drain decode-memo retirement.'
    require(text.count(before) == 1, 'mutation-anchor-not-unique')
    return text.replace(before, after, 1).encode()

require(len(sys.argv) == 2, 'one-case-or-preflight-required')
mode = sys.argv[1]
require(mode == '--preflight' or mode in CASES, 'unknown-case')
os.umask(0o077)
out = Path('proof-memo-mutation-evidence')
out.mkdir(exist_ok=True)
report = {'controller_source': git('rev-parse', 'HEAD'), 'product_baseline': BASE, 'mode': mode,
          'qualification_passed': False, 'full_qualification_passed': False,
          'stack_bytes': 4194304, 'test_threads': 1, 'automatic_retries': 0, 'checks': {}}
def save():
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
save()
require(os.environ.get('GITHUB_ACTIONS') == 'true', 'remote-ci-required')
require(report['controller_source'] == os.environ.get('GITHUB_SHA'), 'workflow-source-mismatch')
require(os.environ.get('CARGO_INCREMENTAL') == '1', 'incremental-one-required')
require(os.environ.get('RUST_MIN_STACK') == '4194304', 'original-stack-required')
for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP', 'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']:
    require(not os.environ.get(key), 'unexpected-compiler-override')
for key in ['CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG']:
    require(os.environ.get(key) == '0', 'original-debug-profile-required')
require(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-inputs-dirty')
allowed = {'.github/workflows/experimental-sync-ci.yml', 'scripts/qualify_upstream_proof_memo_mutations.py'}
require(set(git('diff', '--name-only', BASE).splitlines()) <= allowed, 'controller-branch-changes-product')
frozen = tracked_hashes()
report.update(tree=git('rev-parse', 'HEAD^{tree}'), source_before_sha256=fingerprint(frozen),
              lock_sha256=frozen['Cargo.lock'], nextest_config_sha256=frozen['.config/nextest.toml'],
              cargo_config_sha256=frozen['.cargo/config.toml'],
              environment={key: os.environ.get(key) for key in ['CARGO_INCREMENTAL', 'RUST_MIN_STACK', 'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP']})
report['oracles'] = {}
save()

def normal_guard():
    require(tracked_hashes() == frozen, 'normal-guard-inputs-not-pristine')
    result = subprocess.run([sys.executable, 'scripts/verify_upstream_public_proof_memo_source.py'], capture_output=True, text=True, timeout=300)
    require(result.returncode == 0, 'normal-source-guard-failed')
    require(tracked_hashes() == frozen, 'normal-guard-changed-inputs')

if mode == '--preflight':
    report['oracles'] = {case: {'test': spec[2], 'file': spec[3], 'line': assertion_line(spec[3], spec[4]),
                              'original_sha256': digest(baseline(spec[0])), 'mutant_sha256': digest(transform(case, baseline(spec[0])))} for case, spec in CASES.items()}
    normal_guard()
    report['preflight_passed'] = True
    report['source_after_sha256'] = fingerprint(tracked_hashes())
    save()
    raise SystemExit(0)

path, package, suffix, oracle_path, marker = CASES[mode]
original = baseline(path)
require(Path(path).read_bytes() == original, 'target-not-original')
expected_mutant = None
report.update(target_path=path, original_sha256=digest(original), toolchain=subprocess.check_output(['rustc', '--version'], text=True).strip())
save()

def check_inputs(expected):
    require(tracked_hashes() == expected, 'unexpected-tracked-input-change')
    actual_changed = set(git('diff', '--name-only', 'HEAD').splitlines())
    require(actual_changed == ({path} if expected == expected_mutant else set()), 'permitted-mutant-diff-mismatch')


def run(label, expected):
    check_inputs(expected)
    features = APP_FEATURES if package == 'marmot-app' else CORE_FEATURES
    packages = ['marmot-app'] if package == 'marmot-app' else ['cgka-engine', 'storage-sqlite']
    args = ['cargo', 'nextest', 'list', '--locked', '--lib', '--features', features]
    for selected_package in packages:
        args.extend(['-p', selected_package])
    args.extend(['-E', 'test(' + suffix + ')', '--message-format', 'json'])
    proof = {'source_inputs_sha256': fingerprint(expected), 'packages': packages, 'features': features,
             'compile_exit_code': None, 'executed_nonignored': 0, 'case_started': False}
    report['checks'][label] = proof
    save()
    started = time.monotonic()
    try:
        listing = subprocess.run(args, capture_output=True, text=True, timeout=1200)
    except subprocess.TimeoutExpired:
        proof.update(compile_watchdog_triggered=True, compile_seconds=time.monotonic()-started, mutation_outcome='invalid-compile-watchdog' if label == 'mutant' else None)
        save()
        return False
    proof.update(compile_exit_code=listing.returncode, compile_seconds=time.monotonic()-started)
    compiler_text = re.sub(r'\x1b\[[0-9;]*m', '', listing.stderr)
    proof['compiler_error_count'] = len(re.findall(r'^error(?:\[E[0-9]+\])?:', compiler_text, flags=re.M))
    proof['compiler_error_codes'] = sorted(set(re.findall(r'error\[(E[0-9]+)\]', compiler_text)))
    proof['compiler_error_headers'] = [line[:500] for line in compiler_text.splitlines() if re.match(r'^(?:error(?:\[E[0-9]+\])?:|note:|help:|\s*--> crates/[A-Za-z0-9_./-]+\.rs:[0-9]+:[0-9]+)', line)][:40]
    check_inputs(expected)
    save()
    if listing.returncode != 0:
        if label == 'mutant':
            proof['mutation_outcome'] = 'invalid-compile-failure'
            save()
        return False
    suites = json.loads(listing.stdout)['rust-suites'].values()
    matches = [(name, suite) for suite in suites for name, case in suite['testcases'].items()
               if name.endswith('::' + suffix) and not case['ignored']]
    require(len(matches) == 1, 'exact-one-nonignored-body-required')
    name, suite = matches[0]
    binary = Path(suite['binary-path'])
    proof.update(test=name, binary_sha256=digest(binary.read_bytes()), selected_nonignored=1)
    check_inputs(expected)
    proof['case_started'] = True
    save()
    started = time.monotonic()
    try:
        result = subprocess.run([str(binary), '--exact', name, '--nocapture', '--test-threads=1'], capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        proof.update(watchdog_triggered=True, seconds=time.monotonic()-started, mutation_outcome='invalid-runtime-watchdog' if label == 'mutant' else None)
        save()
        return False
    raw = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout + result.stderr)
    proof.update(exit_code=result.returncode, seconds=time.monotonic()-started)
    summaries = re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', raw)
    if len(summaries) == 1:
        passed, failed, ignored = map(int, summaries[0])
        proof.update(passed=passed, failed=failed, ignored=ignored, executed_nonignored=passed+failed)
    proof['panic_locations'] = [{'file': file, 'line': int(line), 'column': int(column)} for file, line, column in re.findall(r'panicked at (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)', raw)]
    proof['completion_markers'] = re.findall(r'automatic-enrollment-control stage=((?:third|fourth)-device-completion)', raw)
    proof['observed_completion_phase'] = proof['completion_markers'][-1].split('-',1)[0] if proof['completion_markers'] else None
    runtime_marker = 'automatic pairing did not reach required phase: expected=EnrollmentComplete' if mode == 'proof-deoptimization' else marker
    proof['intended_oracle_message_observed'] = runtime_marker in raw
    oracle = report['oracles'].get(mode, {})
    proof['sole_intended_panic'] = len(proof['panic_locations']) == 1 and proof['panic_locations'][0]['file'] == oracle.get('file') and proof['panic_locations'][0]['line'] == oracle.get('line')
    check_inputs(expected)
    save()
    if label == 'mutant':
        phase_valid = mode != 'proof-deoptimization' or proof['observed_completion_phase'] in ['third', 'fourth']
        proof['runtime_mutation_killed'] = (proof.get('compile_exit_code') == 0 and proof.get('compiler_error_count') == 0 and result.returncode == 101
            and proof.get('passed') == 0 and proof.get('failed') == 1 and proof.get('ignored') == 0
            and proof['executed_nonignored'] == 1 and proof['sole_intended_panic']
            and proof['intended_oracle_message_observed'] and phase_valid)
        proof['mutation_outcome'] = 'killed-at-intended-runtime-oracle' if proof['runtime_mutation_killed'] else 'survived' if result.returncode == 0 and proof.get('passed') == 1 and proof.get('failed') == 0 else 'invalid-unrelated-runtime-failure'
        save()
        return proof['runtime_mutation_killed']
    return proof.get('compiler_error_count') == 0 and result.returncode == 0 and proof.get('passed') == 1 and proof.get('failed') == 0 and proof.get('ignored') == 0 and proof['executed_nonignored'] == 1 and not proof['panic_locations']

try:
    mutant = transform(mode, original)
    expected_mutant = {**frozen, path: digest(mutant)}
    report['oracles'][mode] = {'test': suffix, 'file': oracle_path, 'line': assertion_line(oracle_path, marker)}
    report.update(expected_mutant_sha256=digest(mutant), expected_mutant_inputs_sha256=fingerprint(expected_mutant))
    save()
    normal_guard()
    report['baseline_passed'] = run('baseline', frozen)
    if report['baseline_passed']:
        Path(path).write_bytes(mutant)
        check_inputs(expected_mutant)
        report['mutant_killed'] = run('mutant', expected_mutant)
    else:
        report['mutant_killed'] = False
        report['mutation_not_attempted'] = 'baseline-not-green'
except Exception as error:
    report['controller_exception'] = exception_receipt(error)
finally:
    # Restoration and its actual runtime control are attempted even for invalid
    # mutations, compile failures, watchdogs, survivors or controller exceptions.
    try:
        Path(path).write_bytes(original)
        report['restored_source_sha256'] = digest(Path(path).read_bytes())
    except Exception as error:
        report['source_restore_exception'] = exception_receipt(error)
    try:
        normal_guard()
    except Exception as error:
        report['restored_guard_exception'] = exception_receipt(error)
    try:
        report['restored_passed'] = run('restored', frozen)
    except Exception as error:
        report['restored_controller_exception'] = exception_receipt(error)
    report['source_after_sha256'] = fingerprint(tracked_hashes())
    report['inputs_pristine'] = tracked_hashes() == frozen and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
    report['actual_executed_nonignored'] = sum(check.get('executed_nonignored', 0) for check in report['checks'].values())
    report['required_actual_body_count_satisfied'] = len(report['checks']) == 3 and report['actual_executed_nonignored'] == 3
    report['qualification_passed'] = (report['required_actual_body_count_satisfied'] and report.get('baseline_passed') is True and report.get('mutant_killed') is True
        and report.get('restored_passed') is True and report['inputs_pristine']
        and not any(key.endswith('exception') for key in report))
    save()
raise SystemExit(0 if report['qualification_passed'] else 1)
