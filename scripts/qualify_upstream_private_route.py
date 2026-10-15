#!/usr/bin/env python3
"""Remote-only genuine rollback-route regression and encrypted-reopen control."""
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
parser.add_argument('--phase', choices=('red', 'green'), default='red')
args = parser.parse_args()
if os.environ.get('GITHUB_ACTIONS') != 'true':
    raise SystemExit('Run this qualification only in remote GitHub Actions')
os.umask(0o077)
output = Path('private-route-proof')
output.mkdir(mode=0o700)
BASELINE = '87c992d1ffa478c477b6841e33f1680768dfe329'
FIXTURE = 'crates/marmot-app/src/selected_chat_copy/tests.rs'
FEATURES = ','.join(('marmot-app/otlp-export', 'marmot-app/product-analytics-export',
                     'marmot-app/test-policy-overrides', 'marmot-app/experimental-device-sync',
                     'cgka-engine/test-policy-overrides', 'cgka-engine/test-crash-hooks'))
TESTS = (
    'device_revocation_original_rollback_keeps_actual_receive_route_until_reconciliation',
    'device_revocation_retained_remove_cannot_restore_positive_guard_after_encrypted_reopen',
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
    row['actual_rollback_without_current_evidence_and_route'] = (
        'revocation_rollback_route actual_original_retry=true evidence_absent=true actual_subscriptions_refreshed=true retained=false' in text)
    if expected == 'route-red':
        own_panic = (len(panics) == 1 and panics[0][0] == FIXTURE
                     and (panics[0][2].startswith('actual live rollback original must retain its existing receive route through subscription refresh')
                          or panics[0][2].startswith('genuine current successor challenge must be published while B\'s actual Remove is rolled back: "exact challenge initial peel epoch prerequisite timed out"')))
        row['intended_runtime_failure'] = bool(own_panic and row['actual_rollback_without_current_evidence_and_route'])
        row['qualified'] = bool(one_body and process.returncode == 101 and row.get('failed') == 1
                                and row['intended_runtime_failure'] and row['fixture_positive_close_marker'])
        row['failure_class'] = 'route-retention-behavioral-red' if row['qualified'] else 'prerequisite-or-other-failure'
    else:
        row['qualified'] = bool(one_body and process.returncode == 0 and row.get('passed') == 1
                                and row['fixture_positive_close_marker'])
    save()
    print(json.dumps(row, sort_keys=True), flush=True)
    return row['qualified']


try:
    allowed = {FIXTURE, 'crates/marmot-app/src/client/private_transport.rs',
               'crates/marmot-app/src/runtime/account_worker.rs', 'crates/marmot-app/src/runtime/commands.rs',
               'scripts/qualify_upstream_private_route.py', '.github/workflows/upstream-private-route-regression.yml'}
    changed = set(subprocess.check_output(['git', 'diff', '--name-only', BASELINE, 'HEAD'], text=True).splitlines())
    if not changed.issubset(allowed) or subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode:
        raise ValueError('Unexpected or uncommitted qualification source changes')
    report['changed_paths'] = sorted(changed)
    outcomes = [execute(TESTS[0], 'route-red' if args.phase == 'red' else 'green')]
    outcomes.append(execute(TESTS[1], 'green'))
    report['passed'] = all(outcomes) and len(report['executions']) == report['required_executions']
finally:
    report['inputs_unchanged'] = source_hashes() == frozen
    report['tracked_source_pristine'] = subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
    report['passed'] = report['passed'] and report['inputs_unchanged'] and report['tracked_source_pristine']
    save()
if not report['passed']:
    raise SystemExit('Route regression did not satisfy its runtime oracle; prerequisites are not behavioral RED')
