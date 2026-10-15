#!/usr/bin/env python3
"""Remote-only real opaque-owner cancel regressions for the owned-runtime migration."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

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
          'baseline': BASELINE, 'phase': 'cancel-baseline-red', 'executions': [], 'passed': False,
          'rust_min_stack': os.environ.get('RUST_MIN_STACK'), 'retries': 0}


def hashes():
    names = subprocess.check_output(['git', 'ls-files', 'crates/marmot-uniffi',
        'crates/marmot-uniffi-macros', 'crates/marmot-app/src', 'crates/cgka-engine/src',
        'crates/traits/src', 'crates/storage-sqlite/src', 'Cargo.toml', 'Cargo.lock',
        'rust-toolchain.toml', '.config/nextest.toml'], text=True).splitlines()
    return {n: hashlib.sha256(Path(n).read_bytes()).hexdigest() for n in names}


def save():
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


frozen = hashes()
report['frozen_inputs'] = frozen
try:
    if subprocess.run(['git', 'merge-base', '--is-ancestor', BASELINE, 'HEAD']).returncode:
        raise ValueError('Missing exact composed upstream baseline')
    if subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode:
        raise ValueError('Uncommitted qualification inputs')
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
finally:
    report['inputs_unchanged'] = hashes() == frozen
    report['tracked_source_pristine'] = subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
    report['passed'] &= report['inputs_unchanged'] and report['tracked_source_pristine']
    save()
if not report['passed']:
    raise SystemExit('Opaque original cancel RED prerequisite or behavioral oracle failed')
