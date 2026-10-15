#!/usr/bin/env python3
"""Count narrow options controls and execute generated host language fixtures."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

scope = sys.argv[1]
assert scope in {'default', 'experimental', 'swift', 'kotlin'}
assert os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('CARGO_INCREMENTAL') == '1'
assert not any(os.environ.get(n) for n in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP'))
os.umask(0o077)
out = Path('pairing-options-proof')
out.mkdir(mode=0o700)
source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
assert source == os.environ['GITHUB_SHA']
files = subprocess.check_output(['git', 'ls-files', '-z'], text=True).split('\0')
frozen = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in files if p and Path(p).is_file()}
report = {'source': source, 'scope': scope, 'commands': [], 'passed': False,
          'source_inventory_sha256': hashlib.sha256(json.dumps(frozen, sort_keys=True).encode()).hexdigest(),
          'compiler_environment': {k: os.environ.get(k) for k in ('CARGO_INCREMENTAL', 'CARGO_BUILD_JOBS',
              'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG', 'RUST_MIN_STACK')},
          'lock_sha256': frozen['Cargo.lock'], 'sdk_packages': 0, 'automatic_retries': 0}


def save():
    out.joinpath('result.json').write_text(json.dumps(report, indent=2) + '\n')


def run(label, argv):
    row = {'label': label, 'argv': argv}
    report['commands'].append(row)
    save()
    started = time.monotonic()
    with tempfile.TemporaryFile(mode='w+') as private:
        try:
            p = subprocess.run(argv, stdout=private, stderr=subprocess.STDOUT, timeout=3600)
            row['exit_code'] = p.returncode
        except subprocess.TimeoutExpired:
            row['timeout'] = True
        private.seek(0)
        text = private.read()
    row.update(seconds=round(time.monotonic() - started, 3), private_log_sha256=hashlib.sha256(text.encode()).hexdigest(),
               compiler_error_codes=sorted(set(re.findall(r'error\[(E\d+)\]', text))))
    save()
    assert row.get('exit_code') == 0, label + ' failed; retained compiler categories and hash'
    return row, text


try:
    if scope in {'default', 'experimental'}:
        features = ('marmot-c/otlp-export,marmot-c/product-analytics-export,'
                    'marmot-app/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks')
        if scope == 'experimental':
            features += ',marmot-c/experimental-device-sync'
        case = 'tests::runtime_options_defaults_and_combined_policies'
        row, text = run('exact-options-runtime', ['cargo', 'test', '--locked', '-p', 'marmot-uniffi', '--lib',
            '--features', features.replace('marmot-c/', 'marmot-uniffi/'), case, '--', '--exact', '--nocapture', '--test-threads=1'])
        row['actual_cases'] = re.findall(r'^test ([\w:]+) \.\.\.', text, re.M)
        counts = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
        assert row['actual_cases'] == [case] and counts == [('1', '0', '0')]
        row.update(passed=1, failed=0, ignored=0)
        run('affected-clippy', ['cargo', 'clippy', '--locked', '-p', 'marmot-app', '-p', 'marmot-uniffi',
            '-p', 'marmot-c', '--all-targets', '--features', features, '--', '-D', 'warnings'])
        run('canonical-rust-format', ['cargo', 'fmt', '--all', '--', '--check'])
    else:
        report['host_feature_cohort'] = 'default plus cli; experimental-device-sync off'
        if scope == 'kotlin':
            dependency_record = Path(os.environ['RUNNER_TEMP']) / 'peer-kotlin/dependencies.json'
            out.joinpath('host-dependencies.json').write_bytes(dependency_record.read_bytes())
        run('host-compiler', ['swiftc', '--version'] if scope == 'swift' else ['kotlinc', '-version'])
        receipt = out.joinpath('host-generated.json').resolve()
        os.environ['MDK_OPTIONS_SMOKE_RECEIPT'] = str(receipt)
        row, text = run('generated-host-options-program', ['bash', 'crates/marmot-uniffi/options-smoke.sh', scope])
        generated = json.loads(receipt.read_text())
        assert generated['source'] == source and generated['language'] == scope
        assert generated['selected_features'] == ['cli'] and not generated['experimental_device_sync']
        assert generated['host_program_exit_code'] == 0 and generated['generated_files_sha256']
        row['generated_binding_receipt'] = generated

        assert (scope.capitalize() + ' runtime options defaults and host-store construction passed') in text
        fixture = 'crates/marmot-uniffi/tests/options_smoke.' + ('swift' if scope == 'swift' else 'kt')
        row.update(programs_executed=1, fixture_sha256=frozen[fixture], actual_shutdown_and_storage_closed=True)
        target = Path('target/debug') / ('libmarmot_uniffi.dylib' if scope == 'swift' else 'libmarmot_uniffi.so')
        row['host_library_sha256'] = hashlib.sha256(target.read_bytes()).hexdigest()
        assert row['host_library_sha256'] == generated['host_library_sha256']
    report['passed'] = True
finally:
    report['source_unchanged'] = all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == digest for p, digest in frozen.items())
    report['tracked_pristine'] = subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
    report['passed'] = report['passed'] and report['source_unchanged'] and report['tracked_pristine']
    save()
if not report['passed']:
    raise SystemExit('Component options qualification remains pending')
