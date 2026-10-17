#!/usr/bin/env python3
"""One real SDK recipient-admission event-ordering RED; never full qualification."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
from upstream_completion_ci import compile_cases, digest, ensure, environment, headers, identity, parse_body
from qualify_upstream_body_negative import feature_identity, freeze, layout

BASE = 'a302c2194c777bef87ae48aff51a8bc570cbc588'
SELF = 'scripts/qualify_upstream_recipient_admission_red.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
FILE = 'crates/marmot-app/src/native_device_linking/tests/recipient_sibling_admission_acceptance.rs'
PROBE = 'crates/marmot-app/src/client/device_linking/sibling_sharing/peer_proof_probe.rs'
REGISTER = 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
PRODUCT = 'crates/marmot-app/src/client/device_linking/sibling_sharing.rs'
CASE = 'admitted_recipient_starts_first_consent_without_periodic_tick'
TEST = 'native_device_linking::automatic_pairing_acceptance::recipient_sibling_admission_acceptance::' + CASE
MESSAGE = 'admitted_recipient_must_start_first_consent_without_periodic_tick'
FIELDS = ['primary_ready', 'periodic_observed', 'fresh_admitted', 'first_consent_before_gate',
          'actual_consent_held', 'exact_proof_nonce', 'enrollment_complete', 'public_cancelled']
MARKER = 'recipient-sibling-admission ' + ' '.join(name + '=(true|false)' for name in FIELDS)
MARKER += r' runtime_closes=([0-9]{1,2}) planes_shutdown=([0-9]{1,2}) relay_closed=(true|false) attempt_completed=(true|false)'
OUT = Path('recipient-admission-red-evidence')


def location():
    lines = Path(FILE).read_text().splitlines()
    matches = [index for index, line in enumerate(lines) if MESSAGE in line]
    ensure(len(matches) == 1, 'one-own-recipient-admission-final-oracle')
    line = max(index for index in range(matches[0] + 1) if 'assert!(' in lines[index]) + 1
    return {'file': FILE, 'line': line}


def parse(raw, exit_code):
    raw = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    row = parse_body(raw, CASE)
    row.update(body_exit_code=exit_code, compiler_error_count=headers(raw)['compiler_error_count'])
    row['executed_case_names'] = re.findall(r'(?m)^test ([A-Za-z0-9_:]+) \.\.\.', raw)
    prefix = r'(?:test ' + re.escape(TEST) + r' \.\.\. )?'
    values = re.findall(r'(?m)^' + prefix + MARKER + '$', raw)
    row['marker_count'] = len(values)
    row['marker_header_count'] = raw.count('recipient-sibling-admission ')
    row['running_counts'] = [int(value) for value in re.findall(r'(?m)^running ([0-9]{1,3}) tests?$', raw)]
    if len(values) == 1:
        values = values[0]
        row['facts'] = dict(zip(FIELDS, [value == 'true' for value in values[:len(FIELDS)]]))
        row.update(runtime_closes=int(values[len(FIELDS)]), planes_shutdown=int(values[len(FIELDS) + 1]),
                   relay_closed=values[len(FIELDS) + 2] == 'true', attempt_completed=values[len(FIELDS) + 3] == 'true')
    row['intended_assertion_observed'] = MESSAGE in raw
    return row


def intended_red(row):
    counts = {'body_exit_code': 101, 'passed': 0, 'failed': 1, 'ignored': 0,
              'executed_nonignored': 1, 'compiler_error_count': 0, 'all_panic_header_count': 1}
    panics = row.get('panic_locations', [])
    return (all(type(row.get(name)) is int and row[name] == value for name, value in counts.items())
            and row.get('executed_case_names') == [TEST] and row.get('marker_count') == row.get('marker_header_count') == 1
            and row.get('running_counts') == [1]
            and row.get('runtime_closes') == row.get('planes_shutdown') == 3
            and row.get('relay_closed') is True and row.get('attempt_completed') is True
            and row.get('facts', {}).get('first_consent_before_gate') is False
            and all(row.get('facts', {}).get(name) is True for name in FIELDS if name != 'first_consent_before_gate')
            and len(panics) == 1 and all(panics[0].get(name) == value for name, value in location().items())
            and row.get('intended_assertion_observed') is True and not row.get('watchdog_triggered')
            and not row.get('actual_count_unknown'))


def parser_controls():
    own = location()
    marker = 'recipient-sibling-admission ' + ' '.join(name + '=' + ('false' if name == 'first_consent_before_gate' else 'true') for name in FIELDS)
    marker += ' runtime_closes=3 planes_shutdown=3 relay_closed=true attempt_completed=true'
    raw = 'running 1 test\ntest ' + TEST + ' ... ' + marker + '\n'
    raw += "thread '" + TEST + "' panicked at " + FILE + ':' + str(own['line']) + ':5:\n' + MESSAGE
    raw += '\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;\n'
    for value in [raw, raw.replace(' ... ' + marker, ' ... \n' + marker)]:
        ensure(intended_red(parse(value, 101)), 'positive-own-recipient-admission-red-parser')
    negatives = [raw + marker + '\n', raw.replace(marker, 'recipient-sibling-admission malformed=true'),
                 raw + 'recipient-sibling-admission malformed=true\n', raw.replace('running 1 test', 'running 0 tests'),
                 raw.replace('0 ignored', '1 ignored'), raw + 'test result: FAILED. 0 passed; 1 failed; 0 ignored;\n', raw.replace(TEST, 'foreign::case'), raw.replace('first_consent_before_gate=false', 'first_consent_before_gate=true'),
                 raw.replace('runtime_closes=3', 'runtime_closes=2'), raw.replace('planes_shutdown=3', 'planes_shutdown=2'),
                 raw.replace('relay_closed=true', 'relay_closed=false'), raw.replace('attempt_completed=true', 'attempt_completed=false'),
                 raw.replace(FILE + ':' + str(own['line']), FILE + ':1'), raw.replace(MESSAGE, 'unrelated'),
                 raw + '\nthread extra panicked at crates/other.rs:1:1:\n', raw.replace('1 failed', '0 failed'),
                 'error: compilation failed\n', 'test result: ok. 0 passed; 0 failed; 0 ignored;\n']
    negatives += [raw.replace(name + '=true', name + '=false') for name in FIELDS if name != 'first_consent_before_gate']
    negatives += [raw.replace(' ' + name + '=' + ('false' if name == 'first_consent_before_gate' else 'true'), '') for name in FIELDS]
    for value in negatives:
        ensure(not intended_red(parse(value, 101)), 'missing-prerequisite-or-unrelated-red-rejected')
    valid = parse(raw, 101)
    for change in [{'watchdog_triggered': True}, {'actual_count_unknown': True}, {'passed': False}, {'compiler_error_count': 1}, {'body_exit_code': 0}, {'executed_nonignored': 0},
                   {'marker_count': 0}, {'executed_case_names': [TEST, TEST]}]:
        ensure(not intended_red(dict(valid, **change)), 'nonbehavioral-count-or-watchdog-rejected')
    return {'positive': 2, 'negative': len(negatives) + 8, 'actual_runtime_bodies': 0}


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and source == os.environ.get('GITHUB_SHA'), 'approved-exact-remote-source')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-source')
    old = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if not entry:
            continue
        header, name = entry.split(b'\t', 1)
        mode, kind, _ = header.decode().split()
        ensure(kind == 'blob', 'baseline-ordinary-blob-inventory')
        old[os.fsdecode(name)] = mode
    metadata = layout()
    ensure(SELF not in old and FILE not in old and set(metadata) == set(old) | {SELF, FILE},
           'exact-whole-tracked-inventory')
    for name, row in metadata.items():
        expected = old.get(name, '100644')
        ensure(row['git_mode'] == expected and (row['symlink'] or row['actual_executable'] == (expected == '100755'))
               and row['symlink'] == (expected == '120000'), 'whole-tracked-layout-preserved')
    changed = set(subprocess.check_output(['git', 'diff', '--name-only', '--no-renames', BASE, 'HEAD'], text=True).splitlines())
    ensure(changed == {SELF, WORKFLOW, FILE, PROBE, REGISTER, PRODUCT},
           'only-exact-reviewed-recipient-test-and-metadata')
    pattern = rb'(?m)^[ \t]*// RECIPIENT_ADMISSION_TEST_BEGIN\n.*?^[ \t]*// RECIPIENT_ADMISSION_TEST_END\n'
    for name in [PROBE, REGISTER, PRODUCT]:
        data = Path(name).read_bytes()
        ensure(data.count(b'RECIPIENT_ADMISSION_TEST_BEGIN') == data.count(b'RECIPIENT_ADMISSION_TEST_END') == 1,
               'one-passive-test-block-per-path')
        ensure(re.sub(pattern, b'', data, flags=re.S) == subprocess.check_output(['git', 'show', BASE + ':' + name]),
               'all-existing-product-probe-and-fixture-bytes-preserved')
    workflow = Path(WORKFLOW).read_text()
    begin, end = '  # RECIPIENT_ADMISSION_RED_JOBS_BEGIN\n', '  # RECIPIENT_ADMISSION_RED_JOBS_END\n'
    ensure(workflow.count(begin) == workflow.count(end) == 1, 'one-isolated-red-workflow-addition')
    before, rest = workflow.split(begin)
    _, after = rest.split(end)
    restored = (before + after).replace('options: [recipient-admission-preflight, recipient-admission-red, ', 'options: [', 1)
    ensure(restored.encode() == subprocess.check_output(['git', 'show', BASE + ':' + WORKFLOW]),
           'all-existing-workflow-bytes-preserved')
    return {'source': source, 'baseline': BASE, 'only_passive_test_probe_additions': True,
            'all_existing_product_fixtures_controllers_sdk_deadlines_unchanged': True,
            'four_device_failure_cause_established': False}


def main(preflight):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'genuine_behavioral_red': False, 'qualification_passed': False, 'actual_runtime_bodies': 0}
    frozen, metadata = freeze(), layout()
    report['input_manifest_sha256'] = identity(frozen)
    def pristine(): return freeze() == frozen and layout() == metadata
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['source_preflight'] = source_guard(); report['source'] = report['source_preflight']['source']
        report['parser_controls'] = parser_controls(); save()
        if preflight: return
        report.update(environment())
        compilation, cases = compile_cases([CASE]); report['compilation'] = compilation; save()
        ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and set(cases) == {CASE} and cases[CASE]['name'] == TEST, 'actual-sole-nonignored-compiled-feature-cohort')
        report['compiled_feature_identity'] = feature_identity(compilation)
        ensure(pristine(), 'compiled-inputs-exact')
        case = cases[CASE]
        report['compiled_binary_sha256'] = case['binary_sha256']
        ensure(digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'selected-binary-exact')
        started = time.monotonic()
        try:
            result = subprocess.run([case['binary'], '--exact', TEST, '--nocapture', '--test-threads=1'], capture_output=True, text=True, timeout=300)
            report['runtime'] = parse(result.stdout + result.stderr, result.returncode)
        except subprocess.TimeoutExpired:
            report['runtime'] = {'watchdog_triggered': True, 'actual_count_unknown': True}
        report['runtime']['seconds'] = time.monotonic() - started
        ensure(pristine() and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'actual-runtime-source-binary-unchanged')
        report['actual_runtime_bodies'] = report['runtime'].get('executed_nonignored')
        report['genuine_behavioral_red'] = intended_red(report['runtime']); save()
        ensure(report['genuine_behavioral_red'], 'sole-own-runtime-recipient-admission-red-not-established')
    except Exception as error:
        report['controller_exception'] = type(error).__name__
        raise
    finally:
        report['inputs_pristine'] = pristine() and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
        save()
        ensure(report['inputs_pristine'], 'final-source-not-pristine')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    main(parser.parse_args().preflight)
