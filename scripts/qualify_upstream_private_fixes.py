#!/usr/bin/env python3
"""Scoped remote-only baseline qualification for reconciled private fixes."""
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
parser.add_argument('--scope', choices=('cli-default-red', 'cli-experimental-red', 'revocation-baseline'), required=True)
args = parser.parse_args()
if os.environ.get('GITHUB_ACTIONS') != 'true':
    raise SystemExit('This qualification runs only through remote GitHub Actions')
os.umask(0o077)
output = Path('private-fix-proof')
output.mkdir(mode=0o700)
report = {'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
          'scope': args.scope, 'executions': [], 'passed': False,
          'rust_min_stack': os.environ.get('RUST_MIN_STACK'), 'retries': 0}
report['baseline'] = '288bbdd9f1e59474ef309da6236276ccb2b9c986'
report['tree'] = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip()
report['lock_sha256'] = hashlib.sha256(Path('Cargo.lock').read_bytes()).hexdigest()
report['toolchain'] = subprocess.check_output(['rustc', '-Vv'], text=True)
report['config_sha256'] = hashlib.sha256(Path('.config/nextest.toml').read_bytes()).hexdigest()


def source_hashes():
    paths = subprocess.check_output([
        'git', 'ls-files', 'crates/cli/src', 'crates/cli/tests',
        'crates/marmot-app/src/client/private_settlement.rs',
        'crates/marmot-app/src/client/private_transport.rs',
        'crates/marmot-app/src/runtime/account_worker.rs',
        'crates/marmot-app/src/selected_chat_copy/tests.rs',
        'Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml', '.config/nextest.toml',
    ], text=True).splitlines()
    return {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in paths}


FROZEN_SOURCE = source_hashes()
report['frozen_inputs'] = FROZEN_SOURCE


def save():
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


def execute(test, package, features, expected):
    command = ['cargo', 'test', '--locked', '-p', package,
               '--test', 'cli'] if package == 'wn-cli' else ['cargo', 'test', '--locked', '-p', package, '--lib']
    command += ['--features', features, test, '--', '--exact', '--nocapture', '--test-threads=1']
    row = {'test': test, 'command': command, 'expected': expected, 'qualified': False}
    report['executions'].append(row)
    save()
    with tempfile.TemporaryFile(mode='w+') as log:
        started = time.monotonic()
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=2400)
        row['seconds'] = round(time.monotonic() - started, 3)
        row['exit_code'] = result.returncode
        log.seek(0)
        text = log.read()
    row['panic_locations'] = [{'file': name, 'line': int(line)}
                              for name, line in re.findall(r'panicked at ([^\n]+):(\d+):\d+:', text)]
    row['compiler_error_codes'] = sorted(set(re.findall(r'error\[(E\d+)\]', text)))
    summaries = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    row['runtime_counts_available'] = len(summaries) == 1
    if len(summaries) == 1:
        _, passed, failed, ignored = summaries[0]
        row.update(passed=int(passed), failed=int(failed), ignored=int(ignored))
    one_body = (row.get('passed', 0) + row.get('failed', 0) == 1
                and row.get('ignored') == 0 and re.search(r'^running 1 test$', text, re.M)
                and re.search(r'^test ' + re.escape(test) + r' \.\.\.', text, re.M))
    if expected == 'foreign-author-red':
        panics = re.findall(r'panicked at ([^\n]+):(\d+):\d+:\n([^\n]*)', text)
        intended = (len(panics) == 1 and panics[0][0] == 'crates/cli/tests/cli.rs'
                    and panics[0][2] == 'wn unexpectedly succeeded'
                    and '"foreign publisher"' in text)
        row['intended_runtime_failure'] = bool(intended)
        row['qualified'] = bool(one_body and result.returncode == 101 and row.get('failed') == 1 and intended)
    else:
        row['qualified'] = bool(one_body and result.returncode == 0 and row.get('passed') == 1)
    row['log_sha256'] = hashlib.sha256(text.encode()).hexdigest()
    save()
    print(json.dumps(row, sort_keys=True), flush=True)
    return row['qualified']


try:
    allowed = {'crates/cli/tests/cli.rs', '.github/workflows/upstream-private-fix-reconciliation.yml',
               'scripts/qualify_upstream_private_fixes.py'}
    changed = set(subprocess.check_output(['git', 'diff', '--name-only', report['baseline'], 'HEAD'], text=True).splitlines())
    if not changed.issubset(allowed):
        raise ValueError('Baseline source includes unreviewed production or configuration changes')
    if subprocess.check_output(['git', 'diff', 'HEAD', '--name-only'], text=True).strip():
        raise ValueError('Baseline source is not pristine')
    report['changed_paths'] = sorted(changed)
    outcomes = []
    if args.scope.startswith('cli-'):
        features = 'wn-cli/test-policy-overrides'
        if args.scope == 'cli-experimental-red':
            features += ',marmot-app/experimental-device-sync'
        outcomes.append(execute('stream_start_quic_chunks_and_final_payload_verify_through_mls_messages',
                                'wn-cli', features, 'foreign-author-red'))
    else:
        features = ','.join(('marmot-app/otlp-export', 'marmot-app/product-analytics-export',
                             'marmot-app/test-policy-overrides', 'marmot-app/experimental-device-sync',
                             'cgka-engine/test-policy-overrides', 'cgka-engine/test-crash-hooks'))
        for name in (
            'device_revocation_original_receipt_survives_incoming_storage_rollback_retry',
            'device_revocation_challenge_published_before_storage_retry_preserves_fresh_authority',
            'device_revocation_challenge_initial_peel_before_storage_retry_preserves_fresh_authority',
            'device_revocation_confirmation_fact_rollback_preserves_owned_successor_authority',
            'device_revocation_survivors_regain_fresh_original_history_authority',
            'device_revocation_retained_remove_cannot_restore_positive_guard_after_encrypted_reopen',
        ):
            outcomes.append(execute('selected_chat_copy::tests::actual::' + name,
                                    'marmot-app', features, 'green-baseline'))
    report['passed'] = all(outcomes)
finally:
    report['inputs_restored'] = source_hashes() == FROZEN_SOURCE
    report['tracked_source_pristine'] = subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
    report['passed'] = report['passed'] and report['inputs_restored'] and report['tracked_source_pristine']
    save()
if not report['passed']:
    raise SystemExit('Scoped qualification did not meet its runtime oracle; retain result.json')
