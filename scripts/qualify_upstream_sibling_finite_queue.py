#!/usr/bin/env python3
"""One real-tick finite-queue scheduling control; not full sync qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from upstream_completion_ci import compile_cases, digest, ensure, environment, headers, identity, parse_body
from qualify_upstream_body_negative import feature_identity, freeze, layout

BASE = '50c2df29223b94963597325a1572eba4cf8492ae'
SELF = 'scripts/qualify_upstream_sibling_finite_queue.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
FILE = 'crates/marmot-app/src/native_device_linking/tests/sibling_finite_queue_acceptance.rs'
PROBE = 'crates/marmot-app/src/runtime/test_sibling_finite_queue.rs'
CASE = 'live_sibling_due_turn_precedes_second_finite_status_reply'
TEST = 'native_device_linking::automatic_pairing_acceptance::sibling_finite_queue_acceptance::' + CASE
MESSAGE = 'live_sibling_due_turn_must_precede_second_finite_status_reply'
OUT = Path('sibling-finite-queue-evidence')
FIELDS = ['live_source', 'real_latch', 'matched_service', 'original_live', 'enrollment_complete', 'public_cancelled']
MARKER = 'sibling-finite-queue ' + ' '.join(name + '=(true|false)' for name in FIELDS)
MARKER += r' command_replies=([0-9]{1,2}) service_after=(None|Some\([0-9]{1,2}\)) runtime_closes=([0-9]{1,2}) planes_shutdown=([0-9]{1,2}) relay_closed=(true|false) attempt_completed=(true|false)'
BLOCKS = {
    'crates/marmot-app/src/runtime/mod.rs': 4,
    'crates/marmot-app/src/runtime/account_worker.rs': 5,
    'crates/marmot-app/src/client/device_linking/sibling_sharing.rs': 1,
    'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs': 1,
}
BEGIN = '  # SIBLING_FINITE_QUEUE_JOBS_BEGIN\n'
END = '  # SIBLING_FINITE_QUEUE_JOBS_END\n'
OPTIONS = 'options: [sibling-finite-queue-preflight, sibling-finite-queue-control, '


def parse(raw, exit_code):
    raw = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    row = parse_body(raw, CASE)
    row.update(body_exit_code=exit_code, compiler_error_count=headers(raw)['compiler_error_count'])
    row['executed_case_names'] = re.findall(r'(?m)^test ([A-Za-z0-9_:]+) \.\.\.', raw)
    values = re.findall(r'(?m)^(?:test ' + re.escape(TEST) + r' \.\.\. )?' + MARKER + '$', raw)
    row['marker_count'] = len(values)
    row['marker_header_count'] = raw.count('sibling-finite-queue ')
    row['running_counts'] = [int(value) for value in re.findall(r'(?m)^running ([0-9]{1,3}) tests?$', raw)]
    if len(values) == 1:
        values = values[0]
        row['facts'] = dict(zip(FIELDS, [value == 'true' for value in values[:6]]))
        row.update(command_replies=int(values[6]), service_after=None if values[7] == 'None' else int(values[7][5:-1]),
                   runtime_closes=int(values[8]), planes_shutdown=int(values[9]),
                   relay_closed=values[10] == 'true', attempt_completed=values[11] == 'true')
    return row


def green(row):
    counts = {'body_exit_code': 0, 'passed': 1, 'failed': 0, 'ignored': 0,
              'executed_nonignored': 1, 'compiler_error_count': 0, 'all_panic_header_count': 0,
              'command_replies': 3, 'runtime_closes': 3, 'planes_shutdown': 3}
    return (all(type(row.get(name)) is int and row[name] == value for name, value in counts.items())
            and row.get('executed_case_names') == [TEST] and row.get('marker_count') == row.get('marker_header_count') == 1
            and row.get('running_counts') == [1] and row.get('relay_closed') is True
            and row.get('attempt_completed') is True and all(row.get('facts', {}).get(name) is True for name in FIELDS)
            and type(row.get('service_after')) is int and row['service_after'] in {0, 1}
            and not row.get('watchdog_triggered') and not row.get('actual_count_unknown'))


def parser_controls():
    marker = 'sibling-finite-queue ' + ' '.join(name + '=true' for name in FIELDS)
    marker += ' command_replies=3 service_after=Some(1) runtime_closes=3 planes_shutdown=3 relay_closed=true attempt_completed=true'
    raw = 'running 1 test\ntest ' + TEST + ' ... ' + marker + '\n'
    raw += 'test result: ok. 1 passed; 0 failed; 0 ignored;\n'
    ensure(green(parse(raw, 0)), 'positive-actual-counts-ordinal-parser')
    ensure(green(parse(raw.replace('Some(1)', 'Some(0)'), 0)), 'earlier-service-permitted')
    negatives = [raw + marker + '\n', raw.replace(marker, ''), raw.replace(TEST, 'foreign::case'),
                 raw.replace('running 1 test', 'running 0 tests'), raw.replace('0 ignored', '1 ignored'),
                 raw.replace('Some(1)', 'Some(2)'), raw.replace('Some(1)', 'Some(3)'), raw.replace('Some(1)', 'None'),
                 raw.replace('command_replies=3', 'command_replies=2'), raw.replace('runtime_closes=3', 'runtime_closes=2'),
                 raw.replace('planes_shutdown=3', 'planes_shutdown=2'), raw.replace('relay_closed=true', 'relay_closed=false'),
                 raw.replace('attempt_completed=true', 'attempt_completed=false'), raw + 'sibling-finite-queue malformed=true\n',
                 raw + '\nthread extra panicked at crates/foreign.rs:1:1:\n',
                 raw + 'test result: ok. 1 passed; 0 failed; 0 ignored;\n', 'error: compilation failed\n']
    negatives += [raw.replace(name + '=true', name + '=false') for name in FIELDS]
    negatives += [raw.replace(' ' + name + '=true', '') for name in FIELDS]
    for value in negatives:
        ensure(not green(parse(value, 0)), 'missing-fact-or-late-service-rejected')
    for change in [{'passed': True}, {'watchdog_triggered': True}, {'actual_count_unknown': True},
                   {'body_exit_code': 101}, {'service_after': True}, {'compiler_error_count': 1}]:
        ensure(not green(dict(parse(raw, 0), **change)), 'strict-counts-and-termination')
    return {'positive': 2, 'negative': len(negatives) + 6, 'actual_runtime_bodies': 0}


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and source == os.environ.get('GITHUB_SHA')
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
           and os.environ.get('GITHUB_REF') == 'refs/heads/ci/upstream-sibling-finite-queue-20261018'
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@refs/heads/ci/upstream-sibling-finite-queue-20261018'
           and os.environ.get('CARGO_INCREMENTAL') == '1'
           and os.environ.get('CARGO_BUILD_JOBS') == '2', 'exact-reviewed-remote-source-and-bounded-build')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-source')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if entry:
            metadata, name = entry.split(b'\t', 1)
            mode, kind, blob = metadata.decode().split()
            ensure(kind == 'blob', 'ordinary-baseline-inventory')
            baseline[os.fsdecode(name)] = (mode, blob)
    metadata = layout()
    ensure(set(metadata) == set(baseline) | {SELF, FILE, PROBE}, 'whole-tracked-inventory-exact')
    pattern = rb'(?m)^[ \t]*// FINITE_QUEUE_TEST_BEGIN\n.*?^[ \t]*// FINITE_QUEUE_TEST_END\n'
    for name, row in metadata.items():
        mode, blob = baseline.get(name, ('100644', None))
        ensure(row['git_mode'] == mode and row['symlink'] == (mode == '120000')
               and (row['symlink'] or row['actual_executable'] == (mode == '100755')), 'whole-mode-layout:' + name)
        data = os.fsencode(os.readlink(name)) if row['symlink'] else Path(name).read_bytes()
        if name in BLOCKS:
            ensure(data.count(b'FINITE_QUEUE_TEST_BEGIN') == data.count(b'FINITE_QUEUE_TEST_END') == BLOCKS[name],
                   'exact-passive-probe-block-count:' + name)
            data = re.sub(pattern, b'', data, flags=re.S)
        if name == WORKFLOW:
            text = data.decode()
            ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'unique-isolated-workflow')
            before, rest = text.split(BEGIN); _, after = rest.split(END)
            data = (before + after).replace(OPTIONS, 'options: [', 1).encode()
        if blob is not None:
            ensure(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob,
                   'entire-original-content-restored:' + name)
    allowed = {str(OUT / 'result.json')}
    untracked = subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).splitlines()
    ensure(set(untracked) <= allowed, 'no-untracked-source-overlays')
    return {'source': source, 'baseline': BASE, 'whole_original_content_modes_verified': True,
            'real_timer_unchanged': True, 'comparison_admission_gate_necessity_proved': False,
            'full_sync_qualified': False}


def main(preflight):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'component_passed': False, 'actual_runtime_bodies': 0, 'mutation_qualified': False}
    frozen, metadata = freeze(), layout()
    def pristine(): return freeze() == frozen and layout() == metadata
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['source_preflight'] = source_guard(); report['parser_controls'] = parser_controls()
        report['input_manifest_sha256'] = identity(frozen); save()
        if preflight: return
        report.update(environment())
        compilation, cases = compile_cases([CASE]); report['compilation'] = compilation; save()
        ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and set(cases) == {CASE} and cases[CASE]['name'] == TEST, 'actual-one-case-feature-cohort')
        report['feature_identity'] = feature_identity(compilation)
        case = cases[CASE]; report['binary_sha256'] = case['binary_sha256']
        ensure(pristine() and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'compiled-inputs-exact')
        started = time.monotonic()
        try:
            result = subprocess.run([case['binary'], '--exact', TEST, '--nocapture', '--test-threads=1'],
                                    capture_output=True, text=True, timeout=300)
            report['runtime'] = parse(result.stdout + result.stderr, result.returncode)
        except subprocess.TimeoutExpired:
            report['runtime'] = {'watchdog_triggered': True, 'actual_count_unknown': True}
        report['runtime']['seconds'] = time.monotonic() - started
        report['actual_runtime_bodies'] = report['runtime'].get('executed_nonignored')
        report['component_passed'] = green(report['runtime'])
        ensure(pristine() and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'runtime-inputs-exact')
        save(); ensure(report['component_passed'], 'finite-queue-runtime-control-not-green')
    except Exception as error:
        report['controller_exception'] = type(error).__name__
        raise
    finally:
        report['inputs_pristine'] = pristine() and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
        save(); ensure(report['inputs_pristine'], 'final-inputs-not-pristine')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    main(parser.parse_args().preflight)
