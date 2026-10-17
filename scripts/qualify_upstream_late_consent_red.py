#!/usr/bin/env python3
"""One real SDK late-Consent event-ordering RED; never four-device qualification."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
from upstream_completion_ci import compile_cases, digest, ensure, environment, headers, identity, parse_body
from qualify_upstream_body_negative import feature_identity, freeze, layout

BASE = 'a6642b03bd3bb29a529c0fe94b6e3b73d351517c'
SELF = 'scripts/qualify_upstream_late_consent_red.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
FILE = 'crates/marmot-app/src/native_device_linking/tests/late_sibling_consent_acceptance.rs'
PROBE = 'crates/marmot-app/src/client/device_linking/sibling_sharing/peer_proof_probe.rs'
REGISTER = 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
CASE = 'authenticated_late_consent_starts_initial_proof_without_periodic_tick'
TEST = 'native_device_linking::automatic_pairing_acceptance::late_sibling_consent_acceptance::' + CASE
MESSAGE = 'authenticated_late_consent_must_start_initial_proof_without_periodic_tick'
FIELDS = ['consent_held', 'request_ack_harvested', 'periodic_observed', 'fresh_before', 'consent_bound',
          'peer_proof_held', 'initial_progress', 'enrollment_complete', 'public_cancelled']
MARKER = 'late-sibling-consent ' + ' '.join(name + '=(true|false)' for name in FIELDS)
MARKER += r' runtime_closes=([0-9]+) planes_shutdown=([0-9]+) relay_closed=(true|false) attempt_completed=(true|false)'
OUT = Path('late-consent-red-evidence')


def location():
    lines = Path(FILE).read_text().splitlines()
    matches = [index for index, line in enumerate(lines) if MESSAGE in line]
    ensure(len(matches) == 1, 'one-own-late-consent-final-oracle')
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
    if len(values) == 1:
        values = values[0]
        row['facts'] = dict(zip(FIELDS, [value == 'true' for value in values[:9]]))
        row.update(runtime_closes=int(values[9]), planes_shutdown=int(values[10]),
                   relay_closed=values[11] == 'true', attempt_completed=values[12] == 'true')
    row['intended_assertion_observed'] = MESSAGE in raw
    return row


def intended_red(row):
    counts = {'body_exit_code': 101, 'passed': 0, 'failed': 1, 'ignored': 0,
              'executed_nonignored': 1, 'compiler_error_count': 0, 'all_panic_header_count': 1}
    panics = row.get('panic_locations', [])
    return (all(type(row.get(name)) is int and row[name] == value for name, value in counts.items())
            and row.get('executed_case_names') == [TEST] and row.get('marker_count') == 1
            and row.get('runtime_closes') == row.get('planes_shutdown') == 3
            and row.get('relay_closed') is True and row.get('attempt_completed') is True
            and row.get('facts', {}).get('initial_progress') is False
            and all(row.get('facts', {}).get(name) is True for name in FIELDS if name != 'initial_progress')
            and len(panics) == 1 and all(panics[0].get(name) == value for name, value in location().items())
            and row.get('intended_assertion_observed') is True and not row.get('watchdog_triggered')
            and not row.get('actual_count_unknown'))


def parser_controls():
    own = location()
    marker = 'late-sibling-consent ' + ' '.join(name + '=' + ('false' if name == 'initial_progress' else 'true') for name in FIELDS)
    marker += ' runtime_closes=3 planes_shutdown=3 relay_closed=true attempt_completed=true'
    raw = 'running 1 test\ntest ' + TEST + ' ... ' + marker + '\n'
    raw += "thread '" + TEST + "' panicked at " + FILE + ':' + str(own['line']) + ':5:\n' + MESSAGE
    raw += '\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;\n'
    for value in [raw, raw.replace(' ... ' + marker, ' ... \n' + marker)]:
        ensure(intended_red(parse(value, 101)), 'positive-own-late-consent-red-parser')
    negatives = [raw + marker + '\n', raw.replace(TEST, 'foreign::case'), raw.replace('initial_progress=false', 'initial_progress=true'),
                 raw.replace('runtime_closes=3', 'runtime_closes=2'), raw.replace('planes_shutdown=3', 'planes_shutdown=2'),
                 raw.replace('relay_closed=true', 'relay_closed=false'), raw.replace('attempt_completed=true', 'attempt_completed=false'),
                 raw.replace(FILE + ':' + str(own['line']), FILE + ':1'), raw.replace(MESSAGE, 'unrelated'),
                 raw + '\nthread extra panicked at crates/other.rs:1:1:\n', raw.replace('1 failed', '0 failed'),
                 'error: compilation failed\n', 'test result: ok. 0 passed; 0 failed; 0 ignored;\n']
    negatives += [raw.replace(name + '=true', name + '=false') for name in FIELDS if name != 'initial_progress']
    negatives += [raw.replace(' ' + name + '=' + ('false' if name == 'initial_progress' else 'true'), '') for name in FIELDS]
    for value in negatives:
        ensure(not intended_red(parse(value, 101)), 'missing-prerequisite-or-unrelated-red-rejected')
    valid = parse(raw, 101)
    for change in [{'watchdog_triggered': True}, {'actual_count_unknown': True}, {'passed': False}, {'compiler_error_count': 1}]:
        ensure(not intended_red(dict(valid, **change)), 'nonbehavioral-count-or-watchdog-rejected')
    return {'positive': 2, 'negative': len(negatives) + 4, 'actual_runtime_bodies': 0}


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and source == os.environ.get('GITHUB_SHA'), 'approved-exact-remote-source')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-source')
    changed = set(subprocess.check_output(['git', 'diff', '--name-only', BASE, 'HEAD'], text=True).splitlines())
    ensure(changed <= {SELF, WORKFLOW, FILE, PROBE, REGISTER}, 'only-reviewed-late-consent-test-and-metadata')
    pattern = rb'(?m)^[ \t]*// LATE_CONSENT_TEST_BEGIN\n.*?^[ \t]*// LATE_CONSENT_TEST_END\n'
    metadata = layout()
    for name, count in [(PROBE, 2), (REGISTER, 1)]:
        data = Path(name).read_bytes()
        ensure(data.count(b'LATE_CONSENT_TEST_BEGIN') == data.count(b'LATE_CONSENT_TEST_END') == count, 'bounded-passive-test-blocks')
        ensure(re.sub(pattern, b'', data, flags=re.S) == subprocess.check_output(['git', 'show', BASE + ':' + name]), 'all-existing-probe-and-fixture-bytes-preserved')
    for name in changed:
        ensure(metadata[name]['git_mode'] == '100644' and not metadata[name]['actual_executable'] and not metadata[name]['symlink'], 'reviewed-ordinary-test-metadata-modes')
    workflow = Path(WORKFLOW).read_text()
    begin, end = '  # LATE_CONSENT_RED_JOBS_BEGIN\n', '  # LATE_CONSENT_RED_JOBS_END\n'
    ensure(workflow.count(begin) == workflow.count(end) == 1, 'one-isolated-red-workflow-addition')
    before, rest = workflow.split(begin)
    _, after = rest.split(end)
    restored = (before + after).replace('options: [late-consent-red, ', 'options: [', 1)
    ensure(restored.encode() == subprocess.check_output(['git', 'show', BASE + ':' + WORKFLOW]), 'all-existing-workflow-bytes-preserved')
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
        ensure(report['genuine_behavioral_red'], 'sole-own-runtime-late-consent-red-not-established')
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
