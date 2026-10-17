#!/usr/bin/env python3
"""Directed real-SDK late peer-proof RED; never product/native qualification."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
from upstream_completion_ci import compile_cases, digest, ensure, environment, headers, identity, parse_body
from qualify_upstream_body_negative import freeze, layout, feature_identity

BASE = '14291f0b377a72880390239fd561e28466f3bc67'
CASE = 'authenticated_late_peer_proof_completes_without_periodic_tick'
TEST = 'native_device_linking::automatic_pairing_acceptance::late_peer_proof_acceptance::' + CASE
FILE = 'crates/marmot-app/src/native_device_linking/tests/late_peer_proof_acceptance.rs'
MESSAGE = 'authenticated_late_peer_proof_must_complete_without_periodic_tick'
HOOKS = {
    'crates/marmot-app/src/client/device_linking/sibling_sharing.rs': 3,
    'crates/marmot-app/src/runtime/device_linking/setup.rs': 3,
    'crates/marmot-app/src/native_device_linking/enabled.rs': 1,
    'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs': 1,
}
NEW = {FILE, 'crates/marmot-app/src/client/device_linking/sibling_sharing/peer_proof_probe.rs',
       'scripts/qualify_upstream_peer_proof.py'}
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
FIELDS = ['held', 'own_harvested', 'periodic_observed', 'fresh_before', 'authenticated_peer',
          'gated_complete', 'enrollment_complete', 'public_cancelled']
MARKER = ('late-peer-proof ' + ' '.join(field + '=(true|false)' for field in FIELDS)
          + r' runtime_closes=([0-9]+) planes_shutdown=([0-9]+) relay_closed=(true|false) attempt_completed=(true|false)')
OUT = Path('peer-proof-evidence')


def assertion_location():
    lines = Path(FILE).read_text().splitlines()
    matches = [index for index, line in enumerate(lines) if MESSAGE in line]
    ensure(len(matches) == 1, 'one-exact-own-final-assertion')
    line = max(index for index in range(matches[0] + 1) if 'assert!(' in lines[index]) + 1
    return {'file': FILE, 'line': line}


def parse(raw, exit_code):
    raw = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    row = parse_body(raw, CASE)
    row.update(body_exit_code=exit_code, compiler_error_count=headers(raw)['compiler_error_count'])
    row['executed_case_names'] = re.findall(r'(?m)^test ([A-Za-z0-9_:]+) \.\.\.', raw)
    prefix = r'(?:test ' + re.escape(TEST) + r' \.\.\. )?'
    matches = re.findall(r'(?m)^' + prefix + MARKER + '$', raw)
    row['marker_count'] = len(matches)
    if len(matches) == 1:
        values = matches[0]
        row['facts'] = dict(zip(FIELDS, [value == 'true' for value in values[:8]]))
        row.update(runtime_closes=int(values[8]), planes_shutdown=int(values[9]), relay_closed=values[10] == 'true', attempt_completed=values[11] == 'true')
    row['intended_assertion_observed'] = MESSAGE in raw
    return row


def prerequisites(row):
    return (row.get('marker_count') == 1 and row.get('runtime_closes') == 3 and row.get('planes_shutdown') == 3
            and row.get('relay_closed') is True and row.get('attempt_completed') is True
            and all(row.get('facts', {}).get(field) is True for field in FIELDS if field != 'gated_complete'))


def intended_red(row):
    own = assertion_location()
    panics = row.get('panic_locations', [])
    return (row.get('body_exit_code') == 101 and row.get('passed') == 0
            and row.get('failed') == 1 and row.get('ignored') == 0
            and row.get('executed_nonignored') == 1 and row.get('compiler_error_count') == 0
            and row.get('executed_case_names') == [TEST]
            and row.get('all_panic_header_count') == 1 and len(panics) == 1
            and all(panics[0].get(key) == value for key, value in own.items())
            and row.get('intended_assertion_observed') is True and prerequisites(row)
            and row.get('facts', {}).get('gated_complete') is False
            and not row.get('watchdog_triggered'))


def parser_preflight():
    own = assertion_location()
    marker = 'late-peer-proof ' + ' '.join(field + '=' + ('false' if field == 'gated_complete' else 'true') for field in FIELDS)
    marker += ' runtime_closes=3 planes_shutdown=3 relay_closed=true attempt_completed=true'
    panic = "thread '" + TEST + "' panicked at " + own['file'] + ':' + str(own['line']) + ':5:\n' + MESSAGE
    raw = 'running 1 test\ntest ' + TEST + ' ... ' + marker + '\n' + panic + '\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;\n'
    ensure(intended_red(parse(raw, 101)), 'positive-prefixed-runtime-red-parser')
    ensure(intended_red(parse(raw.replace(' ... ' + marker, ' ... \n' + marker), 101)), 'positive-own-line-runtime-red-parser')
    negatives = [raw + marker + '\n', raw.replace(TEST, 'foreign::test'), raw.replace('gated_complete=false', 'gated_complete=true'),
                 raw.replace('runtime_closes=3', 'runtime_closes=2'), raw.replace('planes_shutdown=3', 'planes_shutdown=2'), raw.replace('relay_closed=true', 'relay_closed=false'),
                 raw.replace('attempt_completed=true', 'attempt_completed=false'), raw.replace('1 failed', '0 failed'),
                 raw + '\nthread extra panicked at ' + FILE + ':1:1:\n', raw.replace(own['file'] + ':' + str(own['line']), own['file'] + ':1'),
                 raw.replace(marker, 'arbitrary ' + marker), raw.replace(marker, marker + ' extra'),
                 'error[E0000]: compilation failure\n', 'test result: ok. 0 passed; 0 failed; 0 ignored;\n']
    for field in FIELDS:
        if field != 'gated_complete': negatives.append(raw.replace(field + '=true', field + '=false'))
    for value in negatives:
        ensure(not intended_red(parse(value, 101)), 'adversarial-runtime-red-parser')
    return {'positive': 2, 'negative': len(negatives), 'actual_rust_bodies': 0}


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and source == os.environ.get('GITHUB_SHA'), 'exact-approved-remote-source')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-source')
    changed = set(subprocess.check_output(['git', 'diff', '--name-only', BASE, 'HEAD'], text=True).splitlines())
    ensure(changed <= set(HOOKS) | NEW | {WORKFLOW}, 'only-reviewed-test-probes-controller-workflow')
    pattern = rb'(?m)^[ \t]*// PEER_PROOF_TEST_BEGIN\n.*?^[ \t]*// PEER_PROOF_TEST_END\n'
    for name, count in HOOKS.items():
        current = Path(name).read_bytes()
        ensure(current.count(b'PEER_PROOF_TEST_BEGIN') == current.count(b'PEER_PROOF_TEST_END') == count, 'exact-test-hook-count')
        ensure(re.sub(pattern, b'', current, flags=re.S) == subprocess.check_output(['git', 'show', BASE + ':' + name]), 'production-and-old-fixtures-exact-after-strip')
        ensure(subprocess.check_output(['git', 'ls-tree', BASE, name]).split()[0]
               == subprocess.check_output(['git', 'ls-tree', 'HEAD', name]).split()[0], 'hook-file-mode-exact')
    return {'source': source, 'baseline': BASE, 'production_and_existing_fixtures_exact_after_strip': True,
            'test_hook_counts': HOOKS, 'historical_results_reused': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    OUT.mkdir(exist_ok=True)
    report = {'qualification_passed': False, 'genuine_behavioral_red': False, 'actual_rust_bodies': 0}
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['source_guard'] = source_guard()
        report['parser_controls'] = parser_preflight()
        frozen, frozen_layout = freeze(), layout()
        report['input_manifest_sha256'] = identity(frozen)
        report['source_preflight_passed'] = True
        save()
        if args.preflight: return
        report.update(environment())
        compilation, cases = compile_cases([CASE])
        report['compilation'] = compilation; save()
        ensure(compilation.get('compile_exit_code') == 0 and compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and set(cases) == {CASE} and cases[CASE]['name'] == TEST, 'actual-sole-compiled-feature-cohort')
        report['compiled_feature_identity'] = feature_identity(compilation)
        ensure(freeze() == frozen and layout() == frozen_layout, 'compile-source-drift')
        case = cases[CASE]
        started = time.monotonic()
        try:
            result = subprocess.run([case['binary'], '--exact', TEST, '--nocapture', '--test-threads=1'], capture_output=True, text=True, timeout=300)
            report['runtime'] = parse(result.stdout + result.stderr, result.returncode)
        except subprocess.TimeoutExpired:
            report['runtime'] = {'watchdog_triggered': True, 'actual_count_unknown': True}
        report['runtime']['seconds'] = time.monotonic() - started
        report['genuine_behavioral_red'] = intended_red(report['runtime'])
        report['actual_rust_bodies'] = report['runtime'].get('executed_nonignored')
        report['inputs_pristine'] = freeze() == frozen and layout() == frozen_layout and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
        ensure(report['genuine_behavioral_red'] and report['inputs_pristine'], 'genuine-sole-directed-red-not-established')
    except Exception as error:
        report['controller_exception'] = type(error).__name__
        raise
    finally:
        save()


if __name__ == '__main__': main()
