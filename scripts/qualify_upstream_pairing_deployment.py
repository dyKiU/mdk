#!/usr/bin/env python3
"""Explicit real configured-route qualification; synthetic identities only."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

assert os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('CARGO_INCREMENTAL') == '1'
assert os.environ.get('RUST_MIN_STACK') == '4194304'
assert not any(os.environ.get(n) for n in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP'))
os.umask(0o077)
out = Path('pairing-deployment-proof')
out.mkdir(mode=0o700)
source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
assert source == os.environ['GITHUB_SHA']
cohort = json.loads(Path('scripts/upstream_pairing_relay_cohort.json').read_text())
assert cohort['phase'] == 'public'
routes = cohort['configured_routes']
assert routes == ['wss://nos.lol', 'wss://relay.primal.net']
assert set(cohort['configuration_sources']) == {'mac', 'ios'}
files = subprocess.check_output(['git', 'ls-files', '-z'], text=True).split('\0')
frozen = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in files if p and Path(p).is_file()}
assert all(frozen[p] == digest for p, digest in cohort['tested_source_sha256'].items())
features = ('marmot-app/otlp-export,marmot-app/product-analytics-export,'
            'marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,'
            'cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks')
report = {'source': source, 'executions': [], 'configured_routes': routes,
          'configuration_sources': cohort['configuration_sources'],
          'source_inventory_sha256': hashlib.sha256(json.dumps(frozen, sort_keys=True).encode()).hexdigest(),
          'tested_source_sha256': cohort['tested_source_sha256'], 'automatic_retries': 0,
          'sdk_builds': 0, 'passed': False}


def save():
    out.joinpath('result.json').write_text(json.dumps(report, indent=2) + '\n')


def execute(case, selected, marker):
    env = os.environ.copy()
    env['WN_PAIRING_TEST_RELAYS'] = ','.join(selected)
    command = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--features', features,
               case, '--', '--ignored', '--exact', '--nocapture', '--test-threads=1']
    row = {'case': case, 'routes': selected, 'command': command,
           'WN_PAIRING_TEST_RELAYS': env['WN_PAIRING_TEST_RELAYS'], 'qualified': False}
    report['executions'].append(row)
    save()
    started = time.monotonic()
    with tempfile.TemporaryFile(mode='w+') as private:
        try:
            process = subprocess.run(command, env=env, stdout=private, stderr=subprocess.STDOUT, timeout=2400)
            row['exit_code'] = process.returncode
        except subprocess.TimeoutExpired:
            row['timeout'] = True
        private.seek(0)
        text = private.read()
    row.update(compile_and_execution_seconds=round(time.monotonic() - started, 3),
               private_output_sha256=hashlib.sha256(text.encode()).hexdigest(),
               compiler_error_codes=sorted(set(re.findall(r'error\[(E\d+)\]', text))),
               panic_locations=re.findall(r'panicked at ([^\s:]+\.rs:\d+:\d+)', text),
               actual_cases=re.findall(r'^test ([\w:]+) \.\.\.', text, re.M),
               completion_marker=marker in text)
    summaries = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    if len(summaries) == 1:
        _, passed, failed, ignored = summaries[0]
        row.update(passed=int(passed), failed=int(failed), ignored=int(ignored))
    row['qualified'] = bool(row.get('exit_code') == 0 and row['actual_cases'] == [case]
                            and re.search(r'^running 1 test$', text, re.M)
                            and (row.get('passed'), row.get('failed'), row.get('ignored')) == (1, 0, 0)
                            and row['completion_marker'] and not row['compiler_error_codes'])
    save()
    print(json.dumps(row, sort_keys=True), flush=True)
    return row['qualified']


try:
    case = 'relay_plane::pairing::tests::public_pairing_relays_exchange_encrypted_packets_both_ways'
    marker = 'pairing_encrypted_exchange directions=2 deliveries=4 retry_fresh_ids=true plane_closes=2'
    results = [execute(case, selected, marker) for selected in (routes, [routes[0]], [routes[1]])]
    results.append(execute(
        'native_device_linking::automatic_pairing_acceptance::public_one_scan_exchange_keeps_both_human_comparisons_required',
        routes, 'pairing_native_comparison display_directions=2 bilateral_explicit=true runtime_closes=4'))
    report['passed'] = all(results) and len(report['executions']) == 4
finally:
    report['source_unchanged'] = all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == digest for p, digest in frozen.items())
    report['tracked_pristine'] = subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
    report['passed'] = report['passed'] and report['source_unchanged'] and report['tracked_pristine']
    save()
if not report['passed']:
    raise SystemExit('Configured deployment transport qualification remains pending')
