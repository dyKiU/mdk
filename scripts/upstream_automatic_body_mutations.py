#!/usr/bin/env python3
"""Draft remote-only Body detach omission; never full enrollment qualification."""
import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import zipfile

import qualify_upstream_automatic_body as body
from upstream_completion_ci import DEFAULT_FEATURES, FEATURES, NEW, ORIGINALS, compile_cases, digest, ensure, environment, freeze, identity

BASE = 'a5b1d906134f566580c65a1372211ff751f92eef'
SELF = 'scripts/upstream_automatic_body_mutations.py'
TARGET = 'crates/marmot-app/src/client/account_chat_sharing/automatic.rs'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
# Filled only after root reviews the peer-owned registered-workflow wiring.
# No source/parser/runtime gate can pass while that exact blob is unreviewed.
REVIEWED_WORKFLOW_BLOB = '4cf4fc897d8c6731e7ab0de3d0ee03c93e21c41b'
ANCHOR = '        let task = tokio::spawn(publication_future);'
REPLACEMENT = '''        let task = if body_context.is_some() {
            let outcome = publication_future.await;
            tokio::spawn(async move { outcome })
        } else {
            tokio::spawn(publication_future)
        };'''
OUT = Path('automatic-body-mutation-evidence')


def working_mode(name):
    mode = os.lstat(name).st_mode
    if stat.S_ISLNK(mode):
        return '120000'
    ensure(stat.S_ISREG(mode), 'unsupported-working-file-type')
    return '100755' if mode & stat.S_IXUSR else '100644'


def working_blob(name):
    mode = working_mode(name)
    raw = os.readlink(os.fsencode(name)) if mode == '120000' else Path(name).read_bytes()
    # This is the exact raw Git blob object, without clean filters, decoding,
    # newline/string normalization or a per-file subprocess.
    oid = hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()
    return mode, oid


def source_boundary():
    """One tree read freezes raw blobs/modes; only reviewed workflow may differ."""
    ensure(subprocess.check_output(['git', 'rev-parse', '--show-object-format'], text=True).strip() == 'sha1', 'git-object-format-must-be-sha1')
    ensure(isinstance(REVIEWED_WORKFLOW_BLOB, str) and re.fullmatch('[0-9a-f]{40}', REVIEWED_WORKFLOW_BLOB), 'reviewed-workflow-blob-not-configured')
    entries = subprocess.check_output(['git', 'ls-tree', '-rz', '--full-tree', BASE]).split(b'\0')
    tree = {}
    for entry in entries:
        if not entry:
            continue
        info, raw_name = entry.split(b'\t', 1)
        mode, kind, oid = info.decode('ascii').split(' ')
        ensure(kind == 'blob' and mode in {'100644', '100755', '120000'}, 'unsupported-baseline-tree-entry')
        name = os.fsdecode(raw_name)
        ensure(name not in tree, 'duplicate-tree-entry')
        tree[name] = (mode, oid)
    names = {os.fsdecode(name) for name in subprocess.check_output(['git', 'ls-files', '-z']).split(b'\0') if name}
    ensure(names == set(tree) | {SELF}, 'controller-only-tracked-inventory')
    for name, (mode, oid) in tree.items():
        expected = REVIEWED_WORKFLOW_BLOB if name == WORKFLOW else oid
        actual_mode, actual_oid = working_blob(name)
        ensure(actual_mode == mode and actual_oid == expected, 'reviewed-input-byte-or-mode-drift:' + name)
    ensure(working_mode(SELF) == '100644', 'controller-file-mode')
    ensure(Path(TARGET).read_text().count(ANCHOR) == 1, 'unique-body-detach-anchor')
    for name, expected in body.PRODUCT_BLOBS.items():
        ensure(tree.get(name, (None, None))[1] == expected, 'reviewed-product-blob')
    return {'product_source': BASE, 'all_other_original_tracked_bytes_exact': True, 'only_added_path': SELF,
            'modes_exact': True, 'checked_original_files': len(tree),
            'sole_reviewed_workflow_exception': {'path': WORKFLOW, 'git_blob': REVIEWED_WORKFLOW_BLOB},
            'reviewed_product_blobs': body.PRODUCT_BLOBS, 'test_panic': body.expected_panic()}


def feature_identity(compilation):
    data = compilation.get('compiled_fingerprints', {})
    required = {'marmot_app', 'cgka_engine', 'storage_sqlite', 'cgka_session', 'marmot_account'}
    ensure(data.get('verified') is True and not data.get('unresolved') and required <= set(data.get('nodes', {})), 'actual-feature-fingerprints')
    return {name: {key: row.get(key) for key in ['features', 'profile', 'compile_kind', 'rustflags', 'rustflags_sha256']}
            for name, row in sorted(data['nodes'].items())}


def runtime_outcome(compilation, row, red=False):
    if compilation.get('compile_exit_code') != 0 or compilation.get('compiler_error_count') != 0 or compilation.get('compiled_fingerprints', {}).get('verified') is not True:
        return False
    if red:
        # The unchanged fixture is executed directly, so libtest failure is 101.
        # This is not cargo-nextest's TEST_RUN_FAILED exit code 100.
        if row.get('expected_panic') != body.expected_panic():
            return False
        try:
            return bool(body.intended_red(row))
        except (KeyError, TypeError):
            return False
    return bool(body.body_green(row))


def prior_component(report, source):
    expected_tests = [body.NAME] + ['native_device_linking::automatic_pairing_acceptance::' + suffix for suffix in [NEW, *ORIGINALS]]
    return (report.get('source') == source and report.get('mode') == 'controls'
            and report.get('actual_counts_complete') is True and report.get('actual_executed_nonignored') == 5
            and [row.get('suffix') for row in report.get('bodies', [])] == [body.CASE, NEW, *ORIGINALS]
            and [row.get('test') for row in report.get('bodies', [])] == expected_tests
            and all(row.get('executed_nonignored') == 1 and row.get('ignored') == 0
                    and row.get('passed', 0) + row.get('failed', 0) == 1
                    and not row.get('watchdog_triggered') and not row.get('actual_count_unknown')
                    for row in report.get('bodies', []))
            and body.body_component_green(report))


def prior_static(report, source, cohort):
    gate = report.get('source_preflight', {})
    expected_command = ['cargo', 'clippy', '--locked', '-p', 'marmot-app', '--all-targets', '--features', FEATURES if cohort == 'experimental' else DEFAULT_FEATURES, '--', '-D', 'warnings']
    return (report.get('source') == source and report.get('mode') == 'static' and report.get('cohort') == cohort
            and report.get('static_passed') is True and report.get('exit_code') == 0 and report.get('compiler_error_count') == 0
            and report.get('actual_runtime_bodies') == 0 and report.get('inputs_pristine') is True
            and bool(report.get('source_before_sha256')) and report.get('source_before_sha256') == report.get('source_after_sha256')
            and report.get('command') == expected_command and gate.get('source') == source
            and gate.get('fixture_baseline') == body.FIXTURE_BASE and gate.get('reviewed_product_blobs') == body.PRODUCT_BLOBS
            and gate.get('original_four_controls_and_body_fixture_unchanged') is True)


def prior_green(run_id):
    ensure(run_id.isdecimal(), 'prior-controls-run-required')
    repository = os.environ.get('GITHUB_REPOSITORY')
    ensure(repository == 'dyKiU/mdk', 'verified-fork-only')

    def api(path):
        return json.loads(subprocess.check_output(['gh', 'api', path], text=True))

    run = api('repos/' + repository + '/actions/runs/' + run_id)
    ensure(run.get('head_sha') == BASE and run.get('event') == 'workflow_dispatch'
           and run.get('path') == '.github/workflows/experimental-sync-ci.yml' and run.get('status') == 'completed'
           and run.get('conclusion') in {'success', 'failure'}, 'prior-run-identity-and-terminal')
    # Original enrollment failures may keep this run red. ONLY the independently
    # proven Body component plus BOTH actual static cohorts authorize this chain.
    rows = api('repos/' + repository + '/actions/runs/' + run_id + '/artifacts?per_page=100')['artifacts']
    evidence = {'run_id': int(run_id), 'source': BASE, 'run_conclusion': run['conclusion'], 'artifacts': [],
                'scope': 'Body component and both static cohorts only; original enrollment/full matrix qualification remains separate'}
    for name in ['automatic-body-controls', 'automatic-body-static-default', 'automatic-body-static-experimental']:
        found = [row for row in rows if row.get('name') == name and not row.get('expired')]
        ensure(len(found) == 1, 'one-live-prior-artifact')
        artifact = found[0]
        ensure(0 < artifact.get('size_in_bytes', 0) < 2000000 and artifact.get('workflow_run', {}).get('head_sha') == BASE, 'bounded-prior-artifact-source')
        raw = subprocess.check_output(['gh', 'api', 'repos/' + repository + '/actions/artifacts/' + str(artifact['id']) + '/zip'])
        ensure(len(raw) < 2000000 and artifact.get('digest') == 'sha256:' + digest(raw), 'prior-artifact-digest')
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            matches = [entry for entry in archive.infolist() if Path(entry.filename).name == 'result.json']
            ensure(len(matches) == 1 and matches[0].file_size < 2000000, 'one-bounded-prior-result')
            report = json.loads(archive.read(matches[0]))
        if name == 'automatic-body-controls':
            ensure(prior_component(report, BASE), 'actual-prior-body-component-green')
            evidence['compiled_feature_identity'] = feature_identity(report['compilation'])
            evidence['original_five_all_green'] = report.get('all_five_controls_passed') is True
        else:
            ensure(prior_static(report, BASE, name.rsplit('-', 1)[1]), 'actual-prior-static-green')
        evidence['artifacts'].append({'name': name, 'id': artifact['id'], 'digest': artifact['digest']})
    evidence['body_component_and_both_statics_green'] = True
    return evidence


def parser_preflight():
    original = body.parser_preflight()
    events = ['automatic-body-control stage=' + stage + (' responsive=false' if index == 4 else ' index=' + str(index - 8) if index in [8, 9] else '') for index, stage in enumerate(body.STAGES)]
    panic = body.expected_panic()
    raw = ('test ' + body.NAME + ' ... FAILED\n' + '\n'.join(events)
           + '\nthread case panicked at ' + body.FILE + ':' + str(panic['line']) + ':5:\n' + body.MESSAGE
           + '\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;')
    red = dict(body.parse(raw), body_exit_code=101)
    compilation = {'compile_exit_code': 0, 'compiler_error_count': 0, 'compiled_fingerprints': {'verified': True}}
    ensure(runtime_outcome(compilation, red, True), 'mutation-runtime-oracle-positive')
    negative = 0
    for changes in [{'compile_exit_code': 101}, {'compiler_error_count': 1}, {'compiled_fingerprints': {'verified': False}}, {'compile_exit_code': None}]:
        ensure(not runtime_outcome(dict(compilation, **changes), red, True), 'mutation-compile-negative')
        negative += 1
    for changes in [{'body_exit_code': 100}, {'body_exit_code': 0}, {'executed_nonignored': 0}, {'ignored': 1},
                    {'watchdog_triggered': True}, {'actual_count_unknown': True}, {'named_assertion_observed': False},
                    {'all_prerequisites_and_two_positive_closes': False}, {'expected_panic': {'file': body.FILE, 'line': panic['line'] + 1}},
                    {'all_panic_header_count': 2}, {'panic_locations': []}, {'responsive_while_held': True}]:
        ensure(not runtime_outcome(compilation, dict(red, **changes), True), 'mutation-unrelated-or-incomplete-negative')
        negative += 1
    ensure(not runtime_outcome(compilation, {}, True), 'partial-row-negative')
    ensure(not prior_component({}, BASE) and not prior_static({}, BASE, 'experimental'), 'missing-prior-evidence-negative')
    passed_raw = ('test ' + body.NAME + ' ... ok\n' + '\n'.join(events).replace('responsive=false', 'responsive=true')
                  + '\ntest result: ok. 1 passed; 0 failed; 0 ignored;')
    good = dict(body.parse(passed_raw), body_exit_code=0, suffix=body.CASE)
    gate = {'source': BASE, 'fixture_baseline': body.FIXTURE_BASE, 'reviewed_product_blobs': body.PRODUCT_BLOBS,
            'original_four_controls_and_body_fixture_unchanged': True}
    source = {'source': BASE, 'source_preflight': gate, 'inputs_pristine': True,
              'source_before_sha256': 'fixture', 'source_after_sha256': 'fixture'}
    expected_rows = [dict(good, test=body.NAME)] + [dict(good, suffix=suffix, test='native_device_linking::automatic_pairing_acceptance::' + suffix) for suffix in [NEW, *ORIGINALS]]
    component = dict(source, mode='controls', actual_counts_complete=True, actual_executed_nonignored=5,
                     compilation=compilation, bodies=expected_rows)
    ensure(prior_component(component, BASE), 'prior-component-positive')
    for change in [{'source': 'other'}, {'actual_executed_nonignored': 0}, {'actual_counts_complete': False},
                   {'inputs_pristine': False}, {'source_after_sha256': 'changed'}, {'bodies': []},
                   {'source_preflight': dict(gate, reviewed_product_blobs={})},
                   {'bodies': [dict(row, ignored=1) for row in expected_rows]},
                   {'bodies': [dict(row, test='unrelated::test') if index == 1 else row for index, row in enumerate(expected_rows)]},
                   {'bodies': [dict(row, test=body.NAME) for row in expected_rows]}]:
        ensure(not prior_component(dict(component, **change), BASE), 'prior-component-negative')
        negative += 1
    for cohort in ['default', 'experimental']:
        static = dict(source, mode='static', cohort=cohort, static_passed=True, exit_code=0, compiler_error_count=0,
                      actual_runtime_bodies=0, command=['cargo', 'clippy', '--locked', '-p', 'marmot-app', '--all-targets', '--features', FEATURES if cohort == 'experimental' else DEFAULT_FEATURES, '--', '-D', 'warnings'])
        ensure(prior_static(static, BASE, cohort), 'prior-static-positive')
        for change in [{'source': 'other'}, {'exit_code': 101}, {'compiler_error_count': 1}, {'static_passed': False},
                       {'actual_runtime_bodies': 1}, {'inputs_pristine': False}, {'source_after_sha256': 'changed'},
                       {'command': []}, {'source_preflight': dict(gate, reviewed_product_blobs={})}]:
            ensure(not prior_static(dict(static, **change), BASE, cohort), 'prior-static-negative')
            negative += 1
    return {'existing_body_parser': original, 'mutation_positive': 1, 'mutation_negative': negative + 3,
            'prior_component_positive': 1, 'prior_static_positive': 2,
            'actual_product_bodies': 0, 'qualification_passed': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['preflight', 'run'], required=True)
    parser.add_argument('--control-run-id', default='')
    args = parser.parse_args()
    os.umask(0o077)
    OUT.mkdir(exist_ok=True)
    report = {'mode': args.mode, 'qualification_passed': False, 'mutation_qualified': False, 'mutation_attempted': False, 'restoration_control_attempted': False,
              'product_source': BASE, 'scope': 'Body-only omission of detach; no full enrollment/SDK/native qualification'}

    def save():
        (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    save()
    try:
        report['source_boundary'] = source_boundary()
        ast.parse(Path(SELF).read_text(), filename=SELF)
        report['parser_preflight'] = parser_preflight()
        save()
        if args.mode == 'preflight':
            return
        report.update(environment())
        report['baseline_test_source'] = body.FIXTURE_BASE
        report['prior_green'] = prior_green(args.control_run_id)
        save()
    except Exception as error:
        report['preflight_or_prior_exception'] = type(error).__name__
        save()
        raise SystemExit(1)

    frozen = freeze()
    frozen_modes = {name: working_mode(name) for name in frozen}
    report['source_before_sha256'] = identity(frozen)
    report['input_sha256'] = frozen
    report['input_modes_sha256'] = digest(json.dumps(frozen_modes, sort_keys=True).encode())
    save()
    prior_features = report['prior_green']['compiled_feature_identity']

    def pristine():
        return inputs_match(frozen) and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0

    def inputs_match(expected):
        return freeze() == expected and all(working_mode(name) == mode for name, mode in frozen_modes.items())

    def phase(label, expected):
        row = {'source_before_sha256': identity(expected), 'bodies': []}
        report[label] = row
        save()
        ensure(inputs_match(expected), 'phase-before-compile-inputs')
        compilation, cases = compile_cases([body.CASE])
        row['compilation'] = compilation
        save()
        ensure(inputs_match(expected), 'phase-after-compile-inputs')
        ensure(compilation.get('compile_exit_code') == 0 and compilation.get('compiler_error_count') == 0
               and set(cases) == {body.CASE}, 'one-real-body-compilation')
        row['feature_identity'] = feature_identity(compilation)
        ensure(row['feature_identity'] == prior_features, 'same-reviewed-feature-profile-cohort')
        case = cases[body.CASE]
        ensure(case.get('name') == body.NAME, 'exact-frozen-body-name')
        result = {'test': case['name'], 'binary_sha256': case['binary_sha256']}
        row['bodies'].append(result)
        save()
        started = time.monotonic()
        try:
            actual = subprocess.run([case['binary'], '--exact', case['name'], '--nocapture', '--test-threads=1'], capture_output=True, text=True, timeout=300)
            raw = actual.stdout + actual.stderr
            result['body_exit_code'] = actual.returncode
        except subprocess.TimeoutExpired as error:
            def text(value):
                return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
            raw = text(error.stdout) + text(error.stderr)
            result.update(watchdog_triggered=True, actual_count_unknown=True)
        result['body_seconds'] = time.monotonic() - started
        save()
        try:
            result.update(body.parse(raw))
        except Exception as error:
            result['parser_exception'] = type(error).__name__
            save()
            raise
        ensure(inputs_match(expected), 'phase-after-body-inputs')
        row['source_after_sha256'] = identity(freeze())
        row['green'] = runtime_outcome(compilation, result)
        row['intended_red'] = runtime_outcome(compilation, result, True)
        save()
        return row['green']

    original = None
    baseline_ok = mutant_ok = restored_ok = False
    try:
        source_boundary()  # Normal source guard only on pristine source.
        baseline_ok = phase('baseline', frozen)
        report['baseline_passed'] = baseline_ok
        save()
        ensure(baseline_ok, 'actual-baseline-not-green')
        original = Path(TARGET).read_bytes()
        text = original.decode()
        ensure(text.count(ANCHOR) == 1, 'unique-mutation-anchor')
        mutant = text.replace(ANCHOR, REPLACEMENT, 1).encode()
        expected = dict(frozen)
        expected[TARGET] = digest(mutant)
        report['mutation'] = {'path': TARGET, 'before_sha256': digest(original), 'expected_mutant_sha256': digest(mutant),
                              'allowed_changed_paths': [TARGET], 'handshake_spawn_path_unchanged': True}
        save()
        Path(TARGET).write_bytes(mutant)
        report['mutation_attempted'] = True
        ensure(inputs_match(expected), 'exact-one-path-mutant')
        phase('mutant', expected)
        mutant_ok = report['mutant']['intended_red'] is True
        report['mutant_runtime_killed'] = mutant_ok
        report['mutant_survived'] = report['mutant']['green'] is True
        save()
    except Exception as error:
        report['mutation_or_controller_exception'] = type(error).__name__
    finally:
        if original is not None:
            Path(TARGET).write_bytes(original)
        report['exact_source_restored_before_control'] = pristine()
        report['restoration_control_attempted'] = True
        save()
        # Even invalid anchors, survivor/partial rows or a guard exception cannot
        # suppress the mandatory actual restored control after exact restoration.
        try:
            report['restored_source_boundary'] = source_boundary()
        except Exception as error:
            report['restored_guard_exception'] = type(error).__name__
        try:
            ensure(pristine(), 'source-not-restored')
            restored_ok = phase('restored', frozen)
            report['restored_control_passed'] = restored_ok
        except Exception as error:
            report['restored_control_exception'] = type(error).__name__
        report['inputs_pristine'] = pristine()
        report['source_after_sha256'] = identity(freeze())
        report['actual_executed_nonignored'] = sum(row.get('executed_nonignored', 0)
                                                   for label in ['baseline', 'mutant', 'restored']
                                                   for row in report.get(label, {}).get('bodies', []))
        report['mutation_qualified'] = bool(baseline_ok and mutant_ok and restored_ok and report['inputs_pristine']
                                            and report.get('restored_source_boundary') and not report.get('restored_guard_exception'))
        save()
    raise SystemExit(0 if report['mutation_qualified'] else 1)


if __name__ == '__main__':
    main()
