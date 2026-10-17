#!/usr/bin/env python3
"""Fresh MLS-object reuse controls; settlement authority and native qualification stay separate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import qualify_upstream_late_consent_candidate as candidate
from qualify_upstream_body_negative import freeze, layout
from upstream_completion_ci import digest, ensure, environment, headers, identity, parse_body

BASE = 'a302c2194c777bef87ae48aff51a8bc570cbc588'
SELF = 'scripts/qualify_upstream_settled_roster_reuse.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
PRODUCT = 'crates/cgka-engine/src/private_roster_settlement.rs'
TESTS = 'crates/cgka-engine/src/private_roster_settlement_tests.rs'
CACHE = 'crates/cgka-engine/src/mls_group_cache.rs'
REVIEWED = {
    'crates/cgka-engine/src/private_roster_settlement.rs': '2ec5dcfdd1c62c4c50677f138bac3d357de3bc2a31c98ca298d5e03732dacbae',
    'crates/cgka-engine/src/private_roster_settlement_tests.rs': 'a4790ffbeb8044f900677c76b3135c79633d06fe9b6025446b38185988bce596',
    'crates/cgka-engine/src/mls_group_cache.rs': '575386b6e84da462addd8d9354c02338005cfee7aeb76cd6f64af4eba64e4857',
}
OUT = Path('settled-roster-reuse-evidence')
BEGIN = '  # SETTLED_ROSTER_REUSE_JOBS_BEGIN\n'
END = '  # SETTLED_ROSTER_REUSE_JOBS_END\n'
OPTIONS = 'options: [settled-roster-reuse-preflight, settled-roster-reuse-green, settled-roster-reuse-engine, '
ENGINE_FEATURES = 'experimental-device-sync,test-policy-overrides,test-crash-hooks'
DEFAULT_ENGINE_FEATURES = 'test-policy-overrides,test-crash-hooks'
DIRECTED_PARSER_CONTROLS = candidate.parser_controls
ENGINE_CASES = [
    'private_roster_settlement::tests::private_roster_reuses_mls_object_without_reusing_settlement_authority',
    'private_roster_settlement::tests::private_roster_reuse_returns_object_after_fresh_storage_error',
    'private_roster_settlement::tests::private_roster_reuse_preserves_missing_and_closed_storage_errors',
    'mls_group_cache::tests::cached_group_is_reused_until_storage_is_written_behind_it',
    'private_roster_settlement::tests::private_roster_settlement_completed_encrypted_reopen_preserves_roster_without_admission',
    'private_roster_settlement::tests::private_roster_settlement_delete_permanently_fences_completed_round',
]


def source_guard():
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and source == os.environ.get('GITHUB_SHA'), 'approved-exact-remote-source')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, source], check=True)
    ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-pristine-source')
    ensure(set(REVIEWED) == {PRODUCT, TESTS, CACHE}, 'only-three-explicit-reviewed-engine-substitutions')
    ensure(subprocess.check_output(['git', 'rev-parse', '--show-object-format'], text=True).strip() == 'sha1', 'explicit-git-blob-format')
    baseline = {}
    for entry in subprocess.check_output(['git', 'ls-tree', '-r', '-z', BASE]).split(b'\0'):
        if not entry: continue
        metadata, name = entry.split(b'\t', 1)
        mode, kind, blob = metadata.decode().split()
        ensure(kind == 'blob' and mode in {'100644', '100755', '120000'}, 'ordinary-reviewed-baseline-tree')
        baseline[os.fsdecode(name)] = (mode, blob)
    current = layout()
    ensure(SELF not in baseline and set(current) == set(baseline) | {SELF}, 'entire-tracked-inventory-exact')
    ensure(current[SELF] == {'git_mode': '100644', 'actual_executable': False, 'symlink': False, 'symlink_target': None}, 'ordinary-new-controller-mode')
    for name, (mode, blob) in baseline.items():
        metadata = current[name]
        ensure(metadata['git_mode'] == mode and (mode == '120000' or metadata['actual_executable'] == (mode == '100755'))
               and metadata['symlink'] == (mode == '120000'), 'whole-tracked-layout-exact:' + name)
        data = os.fsencode(os.readlink(name)) if mode == '120000' else Path(name).read_bytes()
        if name in REVIEWED:
            ensure(mode == '100644' and digest(data) == REVIEWED[name], 'exact-reviewed-engine-bytes:' + name)
            continue
        if name == WORKFLOW:
            text = data.decode()
            ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'one-exact-isolated-workflow-overlay')
            before, rest = text.split(BEGIN); _, after = rest.split(END)
            data = (before + after).replace(OPTIONS, 'options: [', 1).encode()
        ensure(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob, 'all-other-source-and-tests-exact:' + name)
    old_tests = subprocess.check_output(['git', 'show', BASE + ':' + TESTS])
    test_bytes = Path(TESTS).read_bytes()
    start = b'#[tokio::test]\nasync fn private_roster_reuses_mls_object_without_reusing_settlement_authority()'
    end = b'#[tokio::test]\nasync fn private_roster_settlement_completed_encrypted_reopen_preserves_roster_without_admission()'
    ensure(test_bytes.count(start) == test_bytes.count(end) == 1, 'one-new-test-block-before-unchanged-original')
    first, last = test_bytes.index(start), test_bytes.index(end)
    ensure(first < last and test_bytes[:first] + test_bytes[last:] == old_tests, 'all-original-engine-test-bytes-preserved')
    return {'source': source, 'baseline': BASE, 'reviewed_engine_sha256': REVIEWED,
            'all_original_app_tests_deadlines_controllers_and_worker_unchanged': True,
            'all_original_engine_tests_unchanged': True, 'no_yield_or_signature_memo': True,
            'historical_runtime_evidence_reused': False,
            'original_failure_cause_not_established': True,
            'original_failure_closure_counters': 'absent; normal originals assert shutdown only on successful path'}


def engine_green(row, name):
    counts = {'body_exit_code': 0, 'passed': 1, 'failed': 0, 'ignored': 0,
              'executed_nonignored': 1, 'compiler_error_count': 0, 'all_panic_header_count': 0}
    return (all(type(row.get(key)) is int and row[key] == value for key, value in counts.items())
            and row.get('executed_case_names') == [name] and not row.get('watchdog_triggered')
            and not row.get('actual_count_unknown'))


def parse_engine(raw, name, code):
    ensure(len(raw.encode()) <= 8 * 1024 * 1024, 'bounded-engine-runtime-output')
    raw = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    row = parse_body(raw, name.rsplit('::', 1)[-1])
    row.update(body_exit_code=code, compiler_error_count=headers(raw)['compiler_error_count'],
               executed_case_names=re.findall(r'(?m)^test ([A-Za-z0-9_:]+) \.\.\.', raw))
    return row


def parser_controls():
    prior = DIRECTED_PARSER_CONTROLS()
    name = ENGINE_CASES[0]
    good = 'test ' + name + ' ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
    ensure(engine_green(parse_engine(good, name, 0), name), 'one-exact-engine-control-parser')
    negative = [good.replace(name, 'foreign::test'), good + 'test foreign::test ... ok\n',
                good.replace('1 passed', '0 passed'), good.replace('0 failed', '1 failed'),
                good.replace('0 ignored', '1 ignored'), good + 'error[E0000]: compile failure\n',
                good + 'thread test panicked at crates/other.rs:1:1:\n', good + good]
    for raw in negative: ensure(not engine_green(parse_engine(raw, name, 0), name), 'false-engine-green-rejected')
    row = parse_engine(good, name, 0)
    for change in [{'passed': True}, {'body_exit_code': 101}, {'watchdog_triggered': True}, {'actual_count_unknown': True}]:
        ensure(not engine_green(dict(row, **change), name), 'invalid-engine-count-or-watchdog-rejected')
    return {'unchanged_directed': prior, 'engine_positive': 1, 'engine_negative': len(negative) + 4, 'actual_runtime_bodies': 0}


def engine_features(binary):
    # Same emitted dependency-companion binding as the existing owner helper,
    # but rooted explicitly at this Core LIB test binary, not an App or ABI unit.
    directory = binary.parent.parent / '.fingerprint'
    suffix = binary.name.rsplit('-', 1)[-1]
    root = directory / ('cgka-engine-' + suffix) / 'test-lib-cgka_engine.json'
    wanted = {'cgka_engine', 'cgka_traits', 'storage_sqlite'}
    result = {'verified': False, 'root_kind': 'cgka-engine-lib-test', 'coverage_required': sorted(wanted), 'nodes': {}, 'unresolved': []}
    expected_units = {}
    def read(file, name):
        data = json.loads(file.read_text()); features = data.get('features', [])
        if isinstance(features, str): features = json.loads(features)
        ensure(isinstance(features, list) and all(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_./+-]+', value) for value in features), 'fingerprint-feature-schema')
        flags = data.get('rustflags', [])
        result['nodes'][name] = {'features': features, 'profile': data.get('profile'), 'compile_kind': data.get('compile_kind'),
            'rustflags_sha256': digest(json.dumps(flags, sort_keys=True).encode()), 'rustflags_empty': flags == [], 'fingerprint_json_sha256': digest(file.read_bytes())}
        for dep in data.get('deps', []):
            if len(dep) != 4 or dep[1] not in wanted: continue
            depname, expected = dep[1], dep[3]
            if depname in result['nodes']:
                if expected_units.get(depname) != expected: result['unresolved'].append(depname + '-multiple-units')
                continue
            if type(expected) is not int:
                result['unresolved'].append(depname); continue
            matches = []
            for file in directory.glob(depname.replace('_', '-') + '-*/lib-' + depname + '.json'):
                companion = file.with_suffix('')
                if not companion.is_file(): continue
                value = companion.read_text().strip()
                if not re.fullmatch('[0-9a-fA-F]{16}', value): continue
                raw = bytes.fromhex(value)
                if expected in (int.from_bytes(raw, 'little'), int.from_bytes(raw, 'big')): matches.append(file)
            if len(matches) != 1:
                result['unresolved'].append(depname); continue
            expected_units[depname] = expected
            read(matches[0], depname)
            result['nodes'][depname]['expected_dependency_fingerprint_u64'] = expected
    if root.is_file(): read(root, 'cgka_engine')
    result['verified'] = (wanted <= set(result['nodes']) and not result['unresolved']
        and all(node['rustflags_empty'] for node in result['nodes'].values())
        and {'experimental-device-sync', 'test-policy-overrides', 'test-crash-hooks'} <= set(result['nodes'].get('cgka_engine', {}).get('features', []))
        and 'experimental-device-sync' in result['nodes'].get('storage_sqlite', {}).get('features', []))
    return result


def engine_mode(options):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'mode': options.mode, 'qualification_passed': False, 'engine_controls_passed': False, 'bodies': []}
    frozen, metadata = freeze(), layout()
    report['input_manifest_sha256'] = identity(frozen)
    def pristine(): return freeze() == frozen and layout() == metadata
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['source_preflight'] = source_guard(); report['source'] = report['source_preflight']['source']
        report['parser_controls'] = parser_controls(); save()
        if options.preflight: return
        report.update(environment())
        if options.mode == 'engine-static':
            ensure(options.cohort in {'default', 'experimental'}, 'explicit-engine-static-cohort')
            features = ENGINE_FEATURES if options.cohort == 'experimental' else DEFAULT_ENGINE_FEATURES
            command = ['cargo', 'clippy', '--locked', '-p', 'cgka-engine', '--all-targets', '--features', features, '--', '-D', 'warnings']
            started = time.monotonic(); result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
            report.update(cohort=options.cohort, command=command, exit_code=result.returncode, seconds=time.monotonic() - started, **headers(result.stderr))
            report['static_passed'] = result.returncode == report['compiler_error_count'] == 0 and pristine()
            ensure(report['static_passed'], 'strict-engine-static-cohort-not-green'); return
        expression = ' | '.join('test(=' + name + ')' for name in ENGINE_CASES)
        command = ['cargo', 'nextest', 'list', '--locked', '--lib', '-p', 'cgka-engine', '--features', ENGINE_FEATURES, '-E', expression, '--message-format', 'json']
        started = time.monotonic(); result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
        report['compilation'] = {'command': command, 'features_requested': ENGINE_FEATURES, 'compile_exit_code': result.returncode,
                                 'compile_seconds': time.monotonic() - started, **headers(result.stderr)}; save()
        ensure(result.returncode == report['compilation']['compiler_error_count'] == 0 and pristine(), 'actual-engine-lib-compilation')
        selected = [(name, suite) for suite in json.loads(result.stdout)['rust-suites'].values()
                    for name, case in suite['testcases'].items() if not case['ignored'] and case.get('filter-match', {}).get('status') == 'matches']
        report['compilation']['selected_case_names'] = [name for name, _ in selected]
        ensure(len(selected) == len(ENGINE_CASES) and {name for name, _ in selected} == set(ENGINE_CASES), 'exact-six-nonignored-engine-cases')
        binaries = {suite['binary-path'] for _, suite in selected}
        ensure(len(binaries) == 1, 'one-actual-engine-lib-binary')
        binary = Path(next(iter(binaries))); binary_sha256 = digest(binary.read_bytes())
        report['compilation']['compiled_fingerprints'] = engine_features(binary)
        ensure(report['compilation']['compiled_fingerprints']['verified'] is True, 'actual-core-lib-feature-dependency-cohort')
        report['compiled_binary_sha256'] = binary_sha256; save()
        for name in ENGINE_CASES:
            ensure(pristine() and digest(binary.read_bytes()) == binary_sha256, 'before-engine-body-source-and-binary-exact')
            row = {'test': name, 'compiled_binary_sha256': binary_sha256, 'actual_counts_complete': False}; report['bodies'].append(row); save()
            started = time.monotonic()
            try:
                result = subprocess.run([str(binary), '--exact', name, '--nocapture', '--test-threads=1'], capture_output=True, text=True, timeout=300)
                row.update(parse_engine(result.stdout + result.stderr, name, result.returncode))
            except subprocess.TimeoutExpired: row.update(watchdog_triggered=True, actual_count_unknown=True)
            row['body_seconds'] = time.monotonic() - started
            row['actual_counts_complete'] = (all(type(row.get(key)) is int and row[key] >= 0 for key in ['passed', 'failed', 'ignored', 'executed_nonignored'])
                                             and row['executed_nonignored'] == row['passed'] + row['failed'] == 1 and not row.get('watchdog_triggered'))
            row['control_passed'] = engine_green(row, name)
            ensure(pristine() and digest(binary.read_bytes()) == binary_sha256, 'after-engine-body-source-and-binary-exact'); save()
        report['engine_controls_passed'] = all(row['control_passed'] for row in report['bodies']) and len(report['bodies']) == len(ENGINE_CASES)
        ensure(report['engine_controls_passed'], 'all-six-engine-runtime-controls-required')
    except Exception as error:
        report['controller_exception'] = type(error).__name__
        raise
    finally:
        report['inputs_pristine'] = pristine() and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
        report['actual_counts_complete'] = all(row.get('actual_counts_complete') is True for row in report['bodies'])
        for key in ['passed', 'failed', 'ignored', 'executed_nonignored']:
            report['actual_' + key] = sum(row.get(key, 0) for row in report['bodies'])
        report['actual_runtime_bodies'] = report['actual_executed_nonignored']
        report['engine_controls_passed'] = bool(report['engine_controls_passed'] and report['inputs_pristine'] and report['actual_counts_complete'])
        save(); ensure(report['inputs_pristine'], 'final-engine-source-pristine')


def main(options):
    if options.mode in {'engine', 'engine-static'}:
        engine_mode(options)
    else:
        candidate.source_guard = source_guard
        candidate.OUT = OUT
        candidate.parser_controls = parser_controls
        # All existing directed parsing, feature, binary and positive-close
        # oracles remain in the unchanged historical implementation.
        candidate.main(argparse.Namespace(mode='static' if options.mode == 'app-static' else 'green', cohort=options.cohort, preflight=options.preflight))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--mode', choices=['green', 'app-static', 'engine-static', 'engine'], default='green')
    parser.add_argument('--cohort', choices=['default', 'experimental'])
    main(parser.parse_args())
