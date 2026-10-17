#!/usr/bin/env python3
"""One real-tick finite-queue scheduling control; not full sync qualification."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time
import zipfile
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
OPTIONS = 'options: [sibling-finite-queue-preflight, sibling-finite-queue-control, sibling-finite-queue-mutations, '


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
    row['intended_assertion_observed'] = MESSAGE in raw
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


CONTROL_SOURCE = '16364c45ac6a0fba9e862ff9dc5cafb4ffa4484f'
CONTROL_RUN = 39074337020
CONTROL_ARTIFACT = 12116816679
CONTROL_ZIP_SHA256 = '07be2be63e624c245d15014148773d3a8442d693bc4e8e47a75387ac206d8553'
CONTROL_MANIFEST = 'bc44af1c3cee3ad193f637509162b165ac58cb8dace26e587c5f39a4444f584a'
WORKER = 'crates/marmot-app/src/runtime/account_worker.rs'
ANCHOR = b'let sibling_service_turn = sibling_maintenance_due && sibling_maintenance_yielded;'
MUTANT = b'let sibling_service_turn = false;'


def own_location():
    lines = Path(FILE).read_text().splitlines()
    messages = [index for index, line in enumerate(lines) if MESSAGE in line]
    ensure(len(messages) == 1, 'unique-existing-final-finite-queue-oracle')
    line = max(index for index in range(messages[0] + 1) if 'assert!(' in lines[index]) + 1
    return {'file': FILE, 'line': line}


def intended_red(row):
    counts = {'body_exit_code': 101, 'passed': 0, 'failed': 1, 'ignored': 0,
              'executed_nonignored': 1, 'compiler_error_count': 0, 'all_panic_header_count': 1,
              'command_replies': 3, 'runtime_closes': 3, 'planes_shutdown': 3, 'service_after': 3}
    panics = row.get('panic_locations', [])
    return (all(type(row.get(name)) is int and row[name] == value for name, value in counts.items())
            and row.get('executed_case_names') == [TEST] and row.get('marker_count') == row.get('marker_header_count') == 1
            and row.get('running_counts') == [1] and row.get('relay_closed') is True
            and row.get('attempt_completed') is True and all(row.get('facts', {}).get(name) is True for name in FIELDS)
            and len(panics) == 1 and all(panics[0].get(name) == value for name, value in own_location().items())
            and row.get('intended_assertion_observed') is True
            and not row.get('watchdog_triggered') and not row.get('actual_count_unknown'))


def mutation_parser_controls():
    own = own_location()
    marker = 'sibling-finite-queue ' + ' '.join(name + '=true' for name in FIELDS)
    marker += ' command_replies=3 service_after=Some(3) runtime_closes=3 planes_shutdown=3 relay_closed=true attempt_completed=true'
    raw = 'running 1 test\ntest ' + TEST + ' ... ' + marker + '\n'
    raw += "thread '" + TEST + "' panicked at " + FILE + ':' + str(own['line']) + ':5:\n' + MESSAGE
    raw += '\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;\n'
    for value in [raw, raw.replace(' ... ' + marker, ' ... \n' + marker)]:
        ensure(intended_red(parse(value, 101)), 'positive-sole-final-ordinal-runtime-red')
    negatives = [raw + marker + '\n', raw.replace(marker, ''), raw.replace(TEST, 'foreign::case'),
                 raw.replace('running 1 test', 'running 0 tests'), raw.replace('0 ignored', '1 ignored'),
                 raw.replace('Some(3)', 'Some(2)'), raw.replace('Some(3)', 'Some(1)'), raw.replace('Some(3)', 'None'),
                 raw.replace('command_replies=3', 'command_replies=2'), raw.replace('runtime_closes=3', 'runtime_closes=2'),
                 raw.replace('planes_shutdown=3', 'planes_shutdown=2'), raw.replace('relay_closed=true', 'relay_closed=false'),
                 raw.replace('attempt_completed=true', 'attempt_completed=false'), raw.replace(MESSAGE, 'other assertion'),
                 raw.replace(FILE + ':' + str(own['line']), FILE + ':1'),
                 raw + '\nthread extra panicked at crates/foreign.rs:1:1:\n',
                 raw + 'test result: FAILED. 0 passed; 1 failed; 0 ignored;\n', 'error: compilation failed\n']
    negatives += [raw.replace(name + '=true', name + '=false') for name in FIELDS]
    negatives += [raw.replace(' ' + name + '=true', '') for name in FIELDS]
    for value in negatives:
        ensure(not intended_red(parse(value, 101)), 'nonordinal-missing-cleanup-or-prerequisite-red-rejected')
    for change in [{'passed': True}, {'service_after': True}, {'watchdog_triggered': True},
                   {'actual_count_unknown': True}, {'body_exit_code': 0}, {'compiler_error_count': 1},
                   {'executed_nonignored': 0}, {'executed_case_names': [TEST, TEST]}]:
        ensure(not intended_red(dict(parse(raw, 101), **change)), 'actual-runtime-only-ordinal-kill')
    return {'positive': 2, 'negative': len(negatives) + 8, 'actual_runtime_bodies': 0}


def prior_receipt(current_environment):
    source = os.environ['GITHUB_SHA']
    subprocess.run(['git', 'merge-base', '--is-ancestor', CONTROL_SOURCE, source], check=True)
    changed = set(subprocess.check_output(['git', 'diff', '--name-only', '--no-renames', CONTROL_SOURCE, source], text=True).splitlines())
    ensure(changed <= {SELF, WORKFLOW}, 'descendant-only-controller-workflow-changes-since-real-control')
    old_layout = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', CONTROL_SOURCE]).split(b'\0'):
        if entry:
            header, name = entry.split(b'\t', 1)
            mode, kind, _ = header.decode().split()
            ensure(kind == 'blob', 'control-ordinary-tree')
            old_layout[os.fsdecode(name)] = mode
    current_layout = layout()
    ensure(set(current_layout) == set(old_layout), 'same-control-source-inventory')
    ensure(all(row['git_mode'] == old_layout[name] for name, row in current_layout.items()), 'same-control-source-modes')
    ensure(Path(WORKER).read_bytes().count(ANCHOR) == 1, 'one-reviewed-owed-priority-expression')
    def api(path):
        return subprocess.check_output(['gh', 'api', 'repos/dyKiU/mdk/' + path], timeout=30)
    run = json.loads(api('actions/runs/' + str(CONTROL_RUN)))
    ensure(run.get('head_sha') == CONTROL_SOURCE and run.get('conclusion') == 'success'
           and run.get('event') == 'workflow_dispatch' and run.get('path') == WORKFLOW,
           'actual-prior-whole-success-at-qualified-control-source')
    artifact = json.loads(api('actions/artifacts/' + str(CONTROL_ARTIFACT)))
    ensure(artifact.get('id') == CONTROL_ARTIFACT and artifact.get('name') == 'sibling-finite-queue-control-runtime'
           and artifact.get('expired') is False and artifact.get('size_in_bytes') == 3211
           and artifact.get('digest') == 'sha256:' + CONTROL_ZIP_SHA256
           and artifact.get('workflow_run', {}).get('id') == CONTROL_RUN
           and artifact['workflow_run'].get('head_sha') == CONTROL_SOURCE, 'exact-qualified-bounded-control-artifact')
    archive_bytes = api('actions/artifacts/' + str(CONTROL_ARTIFACT) + '/zip')
    ensure(len(archive_bytes) == 3211 and digest(archive_bytes) == CONTROL_ZIP_SHA256, 'exact-prior-artifact-bytes')
    result_name = 'mdk/mdk/sibling-finite-queue-evidence/result.json'
    capacity_name = '_temp/sibling-finite-queue-control-capacity.json'
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        entries = archive.infolist()
        ensure(len(entries) == 2 and {entry.filename for entry in entries} == {result_name, capacity_name}, 'exact-two-nontraversing-control-entries')
        ensure(all(not entry.is_dir() and not entry.flag_bits & 1 and 0 < entry.file_size < 250_000
                   and 0 < entry.compress_size < 250_000 and (entry.external_attr >> 16) & 0o170000 in {0, 0o100000}
                   for entry in entries), 'bounded-regular-unencrypted-control-json')
        receipt = json.loads(archive.read(result_name)); capacity = json.loads(archive.read(capacity_name))
    ensure(receipt.get('source') == CONTROL_SOURCE and receipt.get('source_preflight', {}).get('source') == CONTROL_SOURCE
           and receipt['source_preflight'].get('baseline') == BASE
           and receipt['source_preflight'].get('whole_original_content_modes_verified') is True
           and receipt.get('input_manifest_sha256') == CONTROL_MANIFEST and receipt.get('inputs_pristine') is True
           and receipt.get('component_passed') is True and type(receipt.get('actual_runtime_bodies')) is int
           and receipt['actual_runtime_bodies'] == 1 and green(receipt.get('runtime', {})), 'actual-one-pass-pristine-original-control')
    compilation = receipt.get('compilation', {})
    ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
           and compilation.get('compiled_fingerprints', {}).get('verified') is True
           and receipt.get('feature_identity') == feature_identity(compilation), 'verified-prior-actual-feature-cohort')
    for key in ['toolchain', 'environment']:
        ensure(receipt.get(key) and receipt[key] == current_environment.get(key), 'same-actual-control-toolchain-profile-environment')
    ensure(capacity.get('source_sha') == CONTROL_SOURCE and capacity.get('passed') is True
           and capacity.get('cargo_lock_sha256') == digest(Path('Cargo.lock').read_bytes()), 'prior-real-capacity-and-same-lock')
    return {'run': CONTROL_RUN, 'artifact_id': CONTROL_ARTIFACT, 'zip_sha256': CONTROL_ZIP_SHA256,
            'source': CONTROL_SOURCE, 'manifest': CONTROL_MANIFEST,
            'feature_identity': receipt['feature_identity'], 'binary_sha256': receipt['binary_sha256'],
            'current_source': source, 'same_commit_claimed': False,
            'only_controller_workflow_metadata_changed': True, 'changed_paths': sorted(changed)}


def main(preflight, mutations=False):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'mode': 'mutations' if mutations else 'control', 'component_passed': False,
              'actual_runtime_bodies': 0, 'mutation_qualified': False, 'phases': {},
              'comparison_admission_gate_necessity_proved': False}
    frozen, metadata = freeze(), layout()
    original = Path(WORKER).read_bytes()
    def pristine(expected=frozen): return freeze() == expected and layout() == metadata
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    def compile_for(expected):
        ensure(pristine(expected), 'precompile-source-and-modes-exact')
        compilation, cases = compile_cases([CASE]); report.setdefault('compilations', []).append(compilation); save()
        ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and set(cases) == {CASE} and cases[CASE]['name'] == TEST, 'actual-one-case-feature-cohort')
        features = feature_identity(compilation)
        if 'feature_identity' in report:
            ensure(features == report['feature_identity'], 'same-phase-features-profile-flags')
        else:
            report['feature_identity'] = features
        if report.get('prior_control'):
            ensure(features == report['prior_control']['feature_identity'], 'same-prior-control-compiled-feature-cohort')
        ensure(pristine(expected), 'compiled-inputs-exact')
        return compilation, cases[CASE]
    def execute(case, expected, label):
        ensure(pristine(expected) and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'before-runtime-source-binary')
        row = {'compiled_binary_sha256': case['binary_sha256'], 'manifest': identity(expected)}
        report['phases'][label] = row; save(); started = time.monotonic()
        try:
            result = subprocess.run([case['binary'], '--exact', TEST, '--nocapture', '--test-threads=1'],
                                    capture_output=True, text=True, timeout=300)
            row['body'] = parse(result.stdout + result.stderr, result.returncode)
        except subprocess.TimeoutExpired:
            row['body'] = {'watchdog_triggered': True, 'actual_count_unknown': True}
        row['body']['seconds'] = time.monotonic() - started
        ensure(pristine(expected) and digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'after-runtime-source-binary')
        row['green_passed'] = green(row['body']); save(); return row
    try:
        report['source_preflight'] = source_guard(); report['parser_controls'] = parser_controls()
        report['mutation_parser_controls'] = mutation_parser_controls()
        report['input_manifest_sha256'] = identity(frozen); save()
        if preflight: return
        report.update(environment())
        if mutations:
            report['prior_control'] = prior_receipt(report); save()
        compilation, case = compile_for(frozen)
        report['compilation'] = compilation
        report['binary_sha256'] = case['binary_sha256']
        baseline = execute(case, frozen, 'baseline')
        report['runtime'] = baseline['body']
        ensure(baseline['green_passed'], 'fresh-baseline-must-pass-before-any-counterfactual')
        report['component_passed'] = True
        if not mutations: return
        ensure(original.count(ANCHOR) == 1, 'one-exact-priority-counterfactual')
        killed = False; mutation_error = None
        try:
            changed = original.replace(ANCHOR, MUTANT, 1)
            Path(WORKER).write_bytes(changed)
            expected = freeze()
            ensure(layout() == metadata and set(expected) == set(frozen)
                   and {name for name in frozen if expected[name] != frozen[name]} == {WORKER}, 'one-expression-only-counterfactual')
            compilation, case = compile_for(expected)
            mutant = execute(case, expected, 'priority_omission')
            mutant['compilation'] = compilation
            mutant['mutant_source_sha256'] = digest(changed)
            mutant['binary_differs'] = case['binary_sha256'] != report['binary_sha256']
            mutant['runtime_killed'] = intended_red(mutant['body'])
            killed = mutant['binary_differs'] and mutant['runtime_killed']; save()
        except Exception as error:
            mutation_error = type(error).__name__; report['mutation_exception'] = mutation_error; save()
        finally:
            Path(WORKER).write_bytes(original)
            ensure(pristine(), 'entire-exact-source-and-modes-restored')
        compilation, case = compile_for(frozen)
        restored = execute(case, frozen, 'restored')
        restored['compilation'] = compilation
        restored['binary_identical_to_baseline'] = case['binary_sha256'] == report['binary_sha256']
        report['mutation_qualified'] = mutation_error is None and killed and restored['green_passed'] and restored['binary_identical_to_baseline']
        save(); ensure(report['mutation_qualified'], 'sole-intended-priority-omission-and-restored-green-required')
    except Exception as error:
        report['controller_exception'] = type(error).__name__; raise
    finally:
        Path(WORKER).write_bytes(original)
        report['inputs_pristine'] = pristine() and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
        rows = [row.get('body', {}) for row in report['phases'].values()]
        for key, output in [('executed_nonignored', 'actual_runtime_bodies'), ('passed', 'actual_passed'),
                            ('failed', 'actual_failed'), ('ignored', 'actual_ignored')]:
            values = [row.get(key) for row in rows]
            report[output] = sum(values) if all(type(value) is int and value >= 0 for value in values) else None
        report['actual_counts_complete'] = bool(rows) and all(type(row.get('executed_nonignored')) is int
                                                           and row['executed_nonignored'] == 1 for row in rows)
        report['component_passed'] = bool(report['component_passed'] and report['inputs_pristine'])
        report['mutation_qualified'] = bool(report['mutation_qualified'] and report['inputs_pristine']
                                            and report['actual_counts_complete'] and len(rows) == 3
                                            and report['actual_runtime_bodies'] == 3 and report['actual_passed'] == 2
                                            and report['actual_failed'] == 1 and report['actual_ignored'] == 0)
        save(); ensure(report['inputs_pristine'], 'final-inputs-not-pristine')
        if mutations and not preflight and 'controller_exception' not in report:
            ensure(report['mutation_qualified'], 'exact-three-body-final-mutation-qualification-required')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--mutations', action='store_true')
    options = parser.parse_args()
    main(options.preflight, options.mutations)
