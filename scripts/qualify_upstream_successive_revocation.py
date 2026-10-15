#!/usr/bin/env python3
"""Remote-only successive real revocation rollback regression and first-remove control."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--phase', choices=('red',), default='red')
args = parser.parse_args()
if os.environ.get('GITHUB_ACTIONS') != 'true':
    raise SystemExit('Run this qualification only in remote GitHub Actions')
os.umask(0o077)
output = Path('successive-revocation-proof')
output.mkdir(mode=0o700)
BASELINE = 'c6432b23f3d0c1771976bb97b9b6c2ca0b60c8d8'
FIXTURE = 'crates/marmot-app/src/selected_chat_copy/tests.rs'
FEATURES = ','.join(('marmot-app/otlp-export', 'marmot-app/product-analytics-export',
                     'marmot-app/test-policy-overrides', 'marmot-app/experimental-device-sync',
                     'cgka-engine/test-policy-overrides', 'cgka-engine/test-crash-hooks'))
TESTS = (
    'successive_device_revocation_rollback_keeps_fresh_challenge_intake',
    'device_revocation_challenge_initial_peel_before_storage_retry_preserves_fresh_authority',
)
report = {'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
          'baseline': BASELINE, 'phase': args.phase, 'passed': False, 'executions': [],
          'required_executions': 2, 'retries': 0, 'rust_min_stack': os.environ.get('RUST_MIN_STACK'),
          'toolchain': subprocess.check_output(['rustc', '-Vv'], text=True)}


def source_hashes():
    paths = subprocess.check_output(['git', 'ls-files', 'crates/marmot-app/src',
                                    'crates/cgka-engine/src', 'crates/storage-sqlite/src',
                                    'crates/traits/src', 'Cargo.lock', 'Cargo.toml',
                                    '.config/nextest.toml', 'rust-toolchain.toml'], text=True).splitlines()
    return {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in paths}


frozen = source_hashes()
report['frozen_inputs'] = frozen


def save():
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


def execute(name, expected):
    test = 'selected_chat_copy::tests::actual::' + name
    command = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--features', FEATURES,
               test, '--', '--exact', '--nocapture', '--test-threads=1']
    row = {'test': test, 'command': command, 'expected': expected, 'qualified': False}
    report['executions'].append(row)
    save()
    with tempfile.TemporaryFile(mode='w+') as log:
        started = time.monotonic()
        process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=2400)
        row.update(exit_code=process.returncode, command_seconds=round(time.monotonic() - started, 3))
        log.seek(0)
        text = log.read()
    row['command_seconds_include_compilation'] = True
    row['log_sha256'] = hashlib.sha256(text.encode()).hexdigest()
    summaries = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    durations = re.findall(r'test result: (?:ok|FAILED)\.[^\n]*; finished in ([0-9.]+)s', text)
    row['runtime_seconds'] = float(durations[0]) if len(durations) == 1 else None
    row['runtime_counts_available'] = len(summaries) == 1
    if len(summaries) == 1:
        _, passed, failed, ignored = summaries[0]
        row.update(passed=int(passed), failed=int(failed), ignored=int(ignored))
    one_body = (row.get('passed', 0) + row.get('failed', 0) == 1 and row.get('ignored') == 0
                and re.search(r'^running 1 test$', text, re.M)
                and re.search(r'^test ' + re.escape(test) + r' \.\.\.', text, re.M))
    panics = re.findall(r'panicked at ([^\n]+):(\d+):\d+:\n([^\n]*)', text)
    row['panic_locations'] = [{'file': name, 'line': int(line)} for name, line, _ in panics]
    row['compiler_error_codes'] = sorted(set(re.findall(r'error\[(E\d+)\]', text)))
    row['fixture_positive_close_marker'] = 'revocation_runtime_positive_closes=4 original_verdict_preserved=true' in text
    row['actual_previous_live_received_original'] = ('successive_revocation_predecessor actual_four_leaf_enrollment=true first_remove_completed=true previous_received_control_live=true source_only_cancelled=true' in text)
    row['extra_e_positive_close'] = 'successive_revocation_extra_positive_closes=1 original_verdict_preserved=true' in text
    if expected == 'successive-red':
        own_panic = (len(panics) == 1 and panics[0][0] == FIXTURE
                     and panics[0][2].startswith('genuine current successor challenge must be published while B\'s actual Remove is rolled back: "exact challenge initial peel epoch prerequisite timed out"'))
        row['intended_runtime_failure'] = bool(own_panic and row['actual_previous_live_received_original'])
        row['qualified'] = bool(one_body and process.returncode == 101 and row.get('failed') == 1
                                and row['intended_runtime_failure'] and row['fixture_positive_close_marker'] and row['extra_e_positive_close'])
        row['failure_class'] = 'successive-revocation-intake-behavioral-red' if row['qualified'] else 'prerequisite-or-other-failure'
    else:
        row['qualified'] = bool(one_body and process.returncode == 0 and row.get('passed') == 1
                                and row['fixture_positive_close_marker'])
    save()
    print(json.dumps(row, sort_keys=True), flush=True)
    return row['qualified']


try:
    allowed = {FIXTURE, 'crates/marmot-app/src/client/private_settlement.rs',
               'crates/marmot-app/src/runtime/account_worker.rs', 'crates/marmot-app/src/runtime/commands.rs',
               'scripts/qualify_upstream_successive_revocation.py', '.github/workflows/upstream-successive-revocation.yml'}
    changed = set(subprocess.check_output(['git', 'diff', '--name-only', BASELINE, 'HEAD'], text=True).splitlines())
    if not changed.issubset(allowed) or subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode:
        raise ValueError('Unexpected or uncommitted qualification source changes')
    production = 'crates/marmot-app/src/client/private_settlement.rs'
    def retry_classifier(text):
        return text[text.index('    pub(crate) fn revoked_confirmation_storage_retry('):text.index('    pub(crate) fn pending_existing_private_settlement(')]
    previous = subprocess.check_output(['git', 'show', BASELINE + ':' + production], text=True)
    if retry_classifier(previous) != retry_classifier(Path(production).read_text()):
        raise ValueError('The old production retry classifier must remain unchanged for genuine RED')
    report['old_classifier_unchanged'] = True
    report['changed_paths'] = sorted(changed)
    outcomes = [execute(TESTS[0], 'successive-red')]
    if not report['executions'][0]['compiler_error_codes']:
        outcomes.append(execute(TESTS[1], 'green'))
    report['passed'] = all(outcomes) and len(report['executions']) == report['required_executions']
finally:
    report['inputs_unchanged'] = source_hashes() == frozen
    report['tracked_source_pristine'] = subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
    report['passed'] = report['passed'] and report['inputs_unchanged'] and report['tracked_source_pristine']
    save()
if not report['passed']:
    raise SystemExit('Successive revocation did not satisfy its runtime oracle; prerequisites are not behavioral RED')
