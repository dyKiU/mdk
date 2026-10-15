#!/usr/bin/env python3
"""Remote-only real opaque-owner cancel regressions for the owned-runtime migration."""
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
parser.add_argument('--phase', choices=('cancel-red', 'receives'), default='cancel-red')
args = parser.parse_args()

if os.environ.get('GITHUB_ACTIONS') != 'true':
    raise SystemExit('Run product execution only in remote GitHub Actions')
os.umask(0o077)
BASELINE = 'f1bdf469dc284348b1a38befe36a2988bf2c6912'
FEATURES = ','.join(('marmot-uniffi/experimental-device-sync', 'marmot-uniffi/otlp-export',
                     'marmot-uniffi/product-analytics-export'))
CASES = (('session', 'Session', 3), ('approval', 'Approval', 3),
         ('request', 'selected', 4), ('consent', 'selected', 4))
output = Path('private-runtime-proof')
output.mkdir(mode=0o700)
report = {'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
          'baseline': BASELINE, 'phase': args.phase, 'executions': [], 'passed': False,
          'rust_min_stack': os.environ.get('RUST_MIN_STACK'), 'retries': 0}


def hashes():
    names = subprocess.check_output(['git', 'ls-files', 'crates/marmot-uniffi',
        'crates/marmot-uniffi-macros', 'crates/marmot-app/src', 'crates/cgka-engine/src',
        'crates/traits/src', 'crates/storage-sqlite/src', 'Cargo.toml', 'Cargo.lock',
        'rust-toolchain.toml', '.config/nextest.toml'], text=True).splitlines()
    return {n: hashlib.sha256(Path(n).read_bytes()).hexdigest() for n in names}


def save():
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


RECEIVES = (
    ('commands::device_linking::tests::linking_receive_cancellation_preserves_actual_terminal_update',
     'crates/marmot-uniffi/src/commands/device_linking.rs',
     '    #[marmot_uniffi_macros::receive]\n    pub async fn next(&self)',
     'cancelled linking receive consumed the actual terminal update',
     'private_receive_positive_closes=3 actual_public_verification_and_terminal_cancel=true'),
    ('commands::account_chat_windows::tests::account_list_receive_cancellation_preserves_actual_command_update',
     'crates/marmot-uniffi/src/subscriptions/account_chat_windows.rs',
     '    #[marmot_uniffi_macros::receive]\n    pub async fn next(&self) -> Result<Option<AccountChatListWindowSnapshotFfi>',
     'cancelled private receive consumed the actual command replacement',
     'private_receive_positive_closes=1 actual_command_replacement=true conversation=false'),
    ('commands::account_chat_windows::tests::account_conversation_receive_cancellation_preserves_actual_command_update',
     'crates/marmot-uniffi/src/subscriptions/account_chat_windows.rs',
     '    #[marmot_uniffi_macros::receive]\n    pub async fn next(\n        &self,',
     'cancelled private receive consumed the actual command replacement',
     'private_receive_positive_closes=1 actual_command_replacement=true conversation=true'),
)


def receive_execution(test, marker, failure=None, integration=False):
    command = ['cargo', 'test', '--locked', '-p', 'marmot-uniffi']
    command += ['--test', 'runtime_threads'] if integration else ['--lib']
    command += ['--features', FEATURES, test, '--', '--exact', '--nocapture', '--test-threads=1']
    row = {'test': test, 'command': command, 'expected': 'receive-omission-red' if failure else 'green', 'qualified': False}
    report['executions'].append(row)
    save()
    with tempfile.TemporaryFile(mode='w+') as log:
        started = time.monotonic()
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=2400)
        row.update(exit_code=result.returncode, command_seconds=round(time.monotonic() - started, 3))
        log.seek(0)
        text = log.read()
    row['log_sha256'] = hashlib.sha256(text.encode()).hexdigest()
    row['command_seconds_include_compilation'] = True
    summary = re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    if len(summary) == 1:
        row.update(zip(('passed', 'failed', 'ignored'), map(int, summary[0])))
    runtime = re.findall(r'test result: (?:ok|FAILED)\.[^\n]*; finished in ([0-9.]+)s', text)
    row['runtime_seconds'] = float(runtime[0]) if len(runtime) == 1 else None
    row['positive_close_marker'] = marker in text
    row['compiler_error_codes'] = sorted(set(re.findall(r'error\[(E\d+)\]', text)))
    one = (len(summary) == 1 and row.get('passed', 0) + row.get('failed', 0) == 1
           and row.get('ignored') == 0 and re.search(r'^running 1 test$', text, re.M)
           and re.search(r'^test ' + re.escape(test) + r' \.\.\.', text, re.M))
    panics = re.findall(r'panicked at ([^\n]+):(\d+):\d+:\n([^\n]*)', text)
    row['panic_locations'] = [{'file': path, 'line': int(line)} for path, line, _ in panics]
    if failure:
        own = len(panics) == 1 and panics[0][0].startswith('crates/marmot-uniffi/src/commands/') and panics[0][2].startswith(failure)
        row['qualified'] = bool(one and row.get('failed') == 1 and result.returncode == 101 and own and row['positive_close_marker'])
    else:
        row['qualified'] = bool(one and row.get('passed') == 1 and result.returncode == 0 and row['positive_close_marker'])
    row['failure_class'] = 'intended-runtime-outcome' if row['qualified'] else 'prerequisite-or-other-failure'
    save()
    print(json.dumps(row, sort_keys=True), flush=True)
    return row['qualified']


def qualify_receives():
    controls = [receive_execution(test, marker) for test, _, _, _, marker in RECEIVES]
    foreign = receive_execution('private_pairing_exports_complete_on_a_foreign_executor_without_tokio',
        'private_foreign_executor_positive_closes=2 actual_two_device_enrollment=true', integration=True)
    if not all(controls) or not foreign:
        return False
    report['receive_mutations'] = []
    for test, path, anchor, failure, marker in RECEIVES:
        source = Path(path)
        original = source.read_bytes()
        if original.decode().count(anchor) != 1:
            raise ValueError('Receive omission anchor must be unique')
        mutated = original.decode().replace(anchor, anchor.replace('    #[marmot_uniffi_macros::receive]\n', ''), 1)
        mutation = {'test': test, 'source': path, 'original_sha256': hashlib.sha256(original).hexdigest(),
                    'mutated_sha256': hashlib.sha256(mutated.encode()).hexdigest()}
        report['receive_mutations'].append(mutation)
        try:
            source.write_text(mutated)
            mutation['runtime_detected'] = receive_execution(test, marker, failure)
        finally:
            source.write_bytes(original)
            mutation['exact_source_restored'] = source.read_bytes() == original
            save()
        mutation['restored_control_passed'] = receive_execution(test, marker)
        if not mutation['runtime_detected'] or not mutation['exact_source_restored'] or not mutation['restored_control_passed']:
            return False
    departure = output / 'departure-runtime-omission'
    command = ['python3', 'scripts/verify_upstream_boundary_mutations.py', '--case', 'departure', '--output', str(departure)]
    result = subprocess.run(command, timeout=3600)
    report['departure_controller'] = {'command': command, 'exit_code': result.returncode}
    return (len(report['executions']) == 10 and all(row['qualified'] for row in report['executions'])
            and result.returncode == 0)


frozen = hashes()
report['frozen_inputs'] = frozen
try:
    if subprocess.run(['git', 'merge-base', '--is-ancestor', BASELINE, 'HEAD']).returncode:
        raise ValueError('Missing exact composed upstream baseline')
    if subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode:
        raise ValueError('Uncommitted qualification inputs')
    if args.phase == 'cancel-red':
        for name, original, closes in CASES:
            test = 'commands::device_linking::tests::dropped_' + name + '_cancel_export_retires_actual_original'
            command = ['cargo', 'test', '--locked', '-p', 'marmot-uniffi', '--lib', '--features',
                       FEATURES, test, '--', '--exact', '--nocapture', '--test-threads=1']
            row = {'test': test, 'command': command, 'expected': 'behavioral-red', 'qualified': False}
            report['executions'].append(row)
            save()
            with tempfile.TemporaryFile(mode='w+') as log:
                start = time.monotonic()
                process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=2400)
                row['command_seconds'] = round(time.monotonic() - start, 3)
                log.seek(0)
                text = log.read()
            row['exit_code'] = process.returncode
            row['log_sha256'] = hashlib.sha256(text.encode()).hexdigest()
            row['command_seconds_include_compilation'] = True
            summary = re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
            runtime = re.findall(r'test result: (?:ok|FAILED)\.[^\n]*; finished in ([0-9.]+)s', text)
            row['runtime_seconds'] = float(runtime[0]) if len(runtime) == 1 else None
            if len(summary) == 1:
                row.update(zip(('passed', 'failed', 'ignored'), map(int, summary[0])))
            row['compiler_error_codes'] = sorted(set(re.findall(r'error\[(E\d+)\]', text)))
            row['positive_close_marker'] = f'private_boundary_positive_closes={closes}' in text
            panics = re.findall(r'panicked at ([^\n]+):(\d+):\d+:\n([^\n]*)', text)
            row['panic_locations'] = [{'file': path, 'line': int(line)} for path, line, _ in panics]
            intended = (len(panics) == 1 and panics[0][0] == 'crates/marmot-uniffi/src/commands/device_linking/tests.rs'
                        and panics[0][2].startswith('dropped ' + original + ' cancel left actual original live'))
            one = (len(summary) == 1 and row.get('passed') == 0 and row.get('failed') == 1
                   and row.get('ignored') == 0 and re.search(r'^running 1 test$', text, re.M)
                   and re.search(r'^test ' + re.escape(test) + r' \.\.\.', text, re.M))
            row['qualified'] = bool(one and process.returncode == 101 and intended and row['positive_close_marker'])
            row['failure_class'] = 'actual-original-cancel-behavioral-red' if row['qualified'] else 'prerequisite-or-other-failure'
            save()
            print(json.dumps(row, sort_keys=True), flush=True)
            if row['compiler_error_codes']:
                break
        report['passed'] = len(report['executions']) == 4 and all(r['qualified'] for r in report['executions'])
    else:
        report['passed'] = qualify_receives()
finally:
    report['inputs_unchanged'] = hashes() == frozen
    report['tracked_source_pristine'] = subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
    report['passed'] &= report['inputs_unchanged'] and report['tracked_source_pristine']
    save()
if not report['passed']:
    raise SystemExit('Opaque original cancel RED prerequisite or behavioral oracle failed')
