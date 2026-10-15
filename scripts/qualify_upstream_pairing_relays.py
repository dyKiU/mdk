#!/usr/bin/env python3
"""Remote-only counted websocket regression controls; no SDK packaging."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

BASELINE = '4368869e7b2eeb31ae7c71dd0372e843da53aac6'
PRODUCT = 'crates/marmot-app/src/relay_plane/pairing.rs'
TEST = 'crates/marmot-app/src/relay_plane/pairing/deployment_regressions.rs'
FEATURES = ('marmot-app/otlp-export,marmot-app/product-analytics-export,'
            'marmot-app/test-policy-overrides,marmot-app/experimental-device-sync,'
            'cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks')
CASES = (
    ('rejected_pairing_subscription_cannot_export_a_mailbox',
     'pairing_closed_export actual_req=true actual_closed=true sockets_closed=true',
     'pairing_subscription_rejected_before_mailbox_export'),
    ('healthy_pairing_ack_survives_another_accepted_route_without_ok',
     'pairing_ack_witness actual_req=true actual_eose=true actual_event=true decrypted_delivery=true sockets_closed=true',
     'healthy_pairing_ack_not_discarded_by_another_route_timeout'),
)
if os.environ.get('GITHUB_ACTIONS') != 'true':
    raise SystemExit('Remote GitHub Actions only')
os.umask(0o077)
output = Path('pairing-relay-proof')
output.mkdir(mode=0o700)
source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
assert source == os.environ['GITHUB_SHA']
assert os.environ.get('CARGO_INCREMENTAL') == '1'
assert os.environ.get('RUST_MIN_STACK') == '4194304'
assert not any(os.environ.get(name) for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP'))
cohort = json.loads(Path('scripts/upstream_pairing_relay_cohort.json').read_text())
assert cohort == {'phase': 'red', 'baseline': BASELINE}
suffix = b'\n#[cfg(test)]\n#[path = "pairing/deployment_regressions.rs"]\nmod deployment_regressions;\n'
original = subprocess.check_output(['git', 'show', BASELINE + ':' + PRODUCT])
assert Path(PRODUCT).read_bytes() == original + suffix, 'RED must retain exact original mailbox product'
tracked = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
frozen = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in tracked if p and Path(p).is_file()}
report = {'source': source, 'baseline': BASELINE, 'phase': 'red', 'executions': [],
          'source_files': {p: frozen[p] for p in (PRODUCT, TEST, 'Cargo.lock')},
          'source_inventory_digest': hashlib.sha256(json.dumps(frozen, sort_keys=True).encode()).hexdigest(),
          'compiler_environment': {n: os.environ.get(n) for n in ('CARGO_INCREMENTAL', 'CARGO_BUILD_JOBS',
              'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG', 'RUST_MIN_STACK')},
          'sdk_builds': 0, 'public_endpoint_probes': 0, 'automatic_retries': 0, 'passed': False}


def save():
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


def execute(short, witness, oracle):
    case = 'relay_plane::pairing::deployment_regressions::' + short
    command = ['cargo', 'test', '--locked', '-p', 'marmot-app', '--lib', '--features', FEATURES,
               case, '--', '--exact', '--nocapture', '--test-threads=1']
    row = {'case': case, 'command': command, 'witness': False, 'qualified': False}
    report['executions'].append(row)
    save()
    started = time.monotonic()
    with tempfile.TemporaryFile(mode='w+') as private:
        process = subprocess.run(command, stdout=private, stderr=subprocess.STDOUT, timeout=2400)
        private.seek(0)
        text = private.read()
    row.update(exit_code=process.returncode, compile_and_execution_seconds=round(time.monotonic() - started, 3),
               private_log_sha256=hashlib.sha256(text.encode()).hexdigest(),
               compiler_error_codes=sorted(set(re.findall(r'error\[(E\d+)\]', text))),
               panic_locations=re.findall(r'panicked at ([^\s:]+\.rs:\d+:\d+)', text))
    summaries = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    actual = re.findall(r'^test ([\w:]+) \.\.\.', text, re.M)
    row['actual_cases'] = actual
    row['witness'] = witness in text
    if len(summaries) == 1:
        _, passed, failed, ignored = summaries[0]
        row.update(passed=int(passed), failed=int(failed), ignored=int(ignored))
    exact = actual == [case] and re.search(r'^running 1 test$', text, re.M)
    runtime_red = (exact and row['witness'] and process.returncode == 101
                   and (row.get('passed'), row.get('failed'), row.get('ignored')) == (0, 1, 0)
                   and oracle in text and len(row['panic_locations']) == 1)
    runtime_green = (exact and row['witness'] and process.returncode == 0
                     and (row.get('passed'), row.get('failed'), row.get('ignored')) == (1, 0, 0))
    row['classification'] = ('genuine-runtime-red' if runtime_red else
                             'original-runtime-control-green' if runtime_green else 'unqualified-failure')
    row['qualified'] = bool(runtime_red if short == CASES[0][0] else runtime_red or runtime_green)
    save()
    print(json.dumps(row, sort_keys=True), flush=True)
    return row['qualified']


try:
    results = [execute(*case) for case in CASES]
    report['passed'] = all(results) and len(report['executions']) == 2
finally:
    report['source_unchanged'] = all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == h for p, h in frozen.items())
    report['tracked_source_pristine'] = subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
    report['passed'] = report['passed'] and report['source_unchanged'] and report['tracked_source_pristine']
    save()
if not report['passed']:
    raise SystemExit('Pairing relay RED prerequisites or intended runtime failure not established')
