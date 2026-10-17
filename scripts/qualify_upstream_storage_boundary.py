#!/usr/bin/env python3
"""Run only the incoming SQLite ownership assertions; failures never qualify."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time

from upstream_extraction_cohort import frozen_inputs, workflow_identity

INCOMING = '3aec65433eb84f0882430d000b2d31dabf987c24'
MERGE = 'cbd0e5f09224aae1481c87d69d41c8b0cf033461'
RED = '234c9b064bf6c3702a08898b2ea0ab25aa62265d'
SELF = 'scripts/qualify_upstream_storage_boundary.py'
WORKFLOW = '.github/workflows/upstream-boundary-regressions.yml'
BOUNDARY = [
    'crates/storage-sqlite/src/base/mod.rs',
    'crates/storage-sqlite/src/base/boundary_tests.rs',
    'crates/storage-sqlite/src/base/table_owners.rs',
    'crates/storage-sqlite/src/cross/allow-list.txt',
]
TESTS = sorted('base::boundary_tests::' + name for name in [
    'table_registry_names_every_table', 'storage_boundary_matches_the_allow_list',
    'cfg_predicates_skip_only_test_builds',
])
ADDED_TEST = 'base::boundary_tests::unknown_production_roots_cannot_escape_boundary_scan'
OWNERSHIP_DOC = 'crates/storage-sqlite/src/cross/private-ownership.md'
OUT = Path('storage-boundary-evidence')


class GateFailure(ValueError):
    """A fixed, source-owned diagnostic label, never child output."""


def ensure(value, label):
    if not value:
        raise GateFailure(label)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()


def capture(command, timeout, limit=16 * 1024 * 1024):
    """Bound raw output in memory, never publish SQL/payload-bearing panic text."""
    started = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    chunks, size = [], 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                ensure(time.monotonic() - started < timeout, 'bounded-command-timeout')
                for key, _ in selector.select(timeout=0.2):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    size += len(data)
                    ensure(size <= limit, 'bounded-command-output-limit')
                    chunks.append(data)
        code = process.wait(timeout=10)
        return code, b''.join(chunks).decode('utf-8', errors='replace'), round(time.monotonic() - started, 3)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        process.stdout.close()


def parse_body(output, code, name):
    output = re.sub(r'\x1b\[[0-9;]*m', '', output)
    summaries = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', output, re.M)
    names = re.findall(r'^test (base::boundary_tests::[A-Za-z_]+) \.\.\. ', output, re.M)
    panic_headers = re.findall(r"^thread '([^'\n]+)'(?: \(\d+\))? panicked at ([^\n]+):", output, re.M)
    panics = []
    for owner, location in panic_headers:
        match = re.fullmatch(r'(crates/storage-sqlite/src/base/boundary_tests\.rs):(\d+):(\d+)', location)
        panics.append({'selected_test': owner == name, 'known_source_location': match is not None,
                       'line': int(match[2]) if match else None,
                       'column': int(match[3]) if match else None})
    row = {'exit_code': code, 'actual_counts_complete': False, 'passed': None, 'failed': None,
           'ignored': None, 'executed_nonignored': None, 'exact_selected_name': names == [name],
           'panic_count': output.count('panicked at '), 'safe_panic_locations': panics,
           'compiler_error_count': len(re.findall(r'^error(?:\[E\d+\])?:', output, re.M)),
           'registry_assertion_observed': 'src/base/table_owners.rs must name every table of a fresh database exactly once.' in output,
           'boundary_missing_owner_observed': bool(re.search(r'\bhas no owner\b', output)),
           'boundary_allow_list_assertion_observed': 'crossing(s) between the protocol and app sides are not on' in output}
    if len(summaries) == 1:
        status, passed, failed, ignored, measured, _ = summaries[0]
        passed, failed, ignored = int(passed), int(failed), int(ignored)
        complete = (passed + failed == 1 and ignored == 0 and int(measured) == 0
                    and names == [name] and status == ('FAILED' if failed else 'ok'))
        row.update(actual_counts_complete=complete, passed=passed, failed=failed, ignored=ignored,
                   executed_nonignored=passed + failed if complete else None)
    row['passed_gate'] = (row['actual_counts_complete'] and code == 0 and row['passed'] == 1
                          and row['failed'] == 0 and row['panic_count'] == 0
                          and row['compiler_error_count'] == 0)
    return row


def safe_compiler_diagnostic(value, known_sources):
    """Closed compiler metadata only; messages, snippets and external paths stay private."""
    message = value.get('message')
    if not isinstance(message, dict) or message.get('level') != 'error':
        return None
    raw_code = message.get('code')
    code = raw_code.get('code') if isinstance(raw_code, dict) else None
    code_state = 'known' if isinstance(code, str) and re.fullmatch(r'E[0-9]{4}', code) else ('absent' if raw_code is None else 'unknown')
    row = {'code': code if code_state == 'known' else 'generic', 'code_state': code_state,
           'primary_locations': [], 'unknown_primary_location_count': 0,
           'locations_complete': False, 'locations_truncated': False}
    spans = message.get('spans')
    if not isinstance(spans, list):
        row['unknown_primary_location_count'] = 1
        return row
    primary = [span for span in spans if isinstance(span, dict) and span.get('is_primary') is True]
    row['unknown_primary_location_count'] += sum(not isinstance(span, dict) or type(span.get('is_primary')) is not bool for span in spans)
    row['locations_truncated'] = len(primary) > 8
    for span in primary[:8]:
        name = span.get('file_name')
        line, column = span.get('line_start'), span.get('column_start')
        if (isinstance(name, str) and name in known_sources and name.endswith('.rs')
                and type(line) is int and 0 < line <= 2147483647
                and type(column) is int and 0 < column <= 2147483647):
            row['primary_locations'].append({'file': name, 'line': line, 'column': column})
        else:
            row['unknown_primary_location_count'] += 1
    row['locations_complete'] = bool(primary) and row['unknown_primary_location_count'] == 0 and not row['locations_truncated']
    return row


def diagnostic_parser_preflight():
    name = BOUNDARY[1]
    span = {'file_name': name, 'line_start': 42, 'column_start': 5, 'is_primary': True,
            'text': [{'text': 'PRIVATE_RAW_MESSAGE_ACCOUNT_SQL'}]}
    def event(code, spans):
        return {'reason': 'compiler-message', 'message': {'level': 'error', 'code': code,
                'message': 'PRIVATE_RAW_MESSAGE_ACCOUNT_SQL', 'rendered': 'PRIVATE_RAW_MESSAGE_ACCOUNT_SQL', 'spans': spans}}
    known = safe_compiler_diagnostic(event({'code': 'E0277'}, [span]), {name})
    ensure(known['code'] == 'E0277' and known['locations_complete']
           and known['primary_locations'] == [{'file': name, 'line': 42, 'column': 5}], 'compiler-parser-known-code-and-primary')
    ensure(safe_compiler_diagnostic(event(None, []), {name})['code_state'] == 'absent', 'compiler-parser-generic-error')
    invalid = [dict(span, file_name='/private/account/SECRET.rs'), dict(span, file_name='../SECRET.rs'),
               dict(span, file_name='PRIVATE_RAW_MESSAGE_ACCOUNT_SQL'), dict(span, line_start=True),
               dict(span, line_start=-1), dict(span, column_start='5'), dict(span, is_primary='true'),
               'PRIVATE_RAW_MESSAGE_ACCOUNT_SQL']
    for bad in invalid:
        row = safe_compiler_diagnostic(event({'code': 'PRIVATE_RAW_MESSAGE_ACCOUNT_SQL'}, [bad]), {name})
        ensure(not row['locations_complete'] and not row['primary_locations'] and row['code_state'] == 'unknown'
               and 'PRIVATE_RAW_MESSAGE_ACCOUNT_SQL' not in json.dumps(row), 'compiler-parser-rejects-untrusted-metadata')
    row = safe_compiler_diagnostic(event({'code': 'E0277'}, [span] * 9), {name})
    ensure(row['locations_truncated'] and not row['locations_complete'] and len(row['primary_locations']) == 8, 'compiler-parser-bounded-spans')
    ensure(safe_compiler_diagnostic({'message': {'level': 'warning'}}, {name}) is None, 'compiler-parser-no-warning-as-error')
    return {'positive': 2, 'negative': len(invalid) + 2, 'actual_runtime_bodies': 0}


def parser_preflight():
    name = TESTS[0]
    raw = 'running 1 test\ntest ' + name + ' ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.1s\n'
    ensure(parse_body(raw, 0, name)['passed_gate'], 'parser-positive-exact-body')
    negative = [raw.replace(name, 'foreign::test'), raw.replace('1 passed', '0 passed'),
                raw.replace('0 ignored', '1 ignored'), raw + raw, raw + '\nthread other panicked at foreign.rs:1:1:\n',
                raw + '\nerror[E0001]: compiler failure\n', 'error: failed to compile\n', raw.replace('0 measured', '1 measured')]
    for value in negative:
        ensure(not parse_body(value, 0, name)['passed_gate'], 'parser-rejects-incomplete-or-foreign-body')
    ensure(not parse_body(raw, 101, name)['passed_gate'], 'parser-rejects-nonzero')
    failed = raw.replace(' ... ok', ' ... \nthread \'' + name + "' panicked at crates/storage-sqlite/src/base/boundary_tests.rs:42:5:\nprivate SQL must stay private\nFAILED")
    failed = failed.replace('test result: ok. 1 passed; 0 failed', 'test result: FAILED. 0 passed; 1 failed')
    row = parse_body(failed, 101, name)
    ensure(row['actual_counts_complete'] and row['failed'] == 1 and not row['passed_gate']
           and row['safe_panic_locations'] == [{'selected_test': True, 'known_source_location': True, 'line': 42, 'column': 5}], 'parser-safe-failure-receipt')
    return {'positive': 2, 'negative': len(negative) + 1, 'actual_runtime_bodies': 0}


def rust_function(source, name):
    """Exact top-level source body identity, not a Rust parser or proof oracle."""
    anchor = '\nfn ' + name + '('
    ensure(source.count(anchor) == 1, 'one-frozen-top-level-function')
    start = source.index(anchor) + 1
    end = source.index('\n}\n', start) + 3
    return source[start:end]


def source_guard(baseline, ownership_adaptation):
    ensure(isinstance(baseline, str) and re.fullmatch('[0-9a-f]{40}', baseline), 'explicit-reviewed-full-cohort-required')
    source = git('rev-parse', 'HEAD')
    workflow = workflow_identity(source)
    ensure(os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'isolated-manual-scope-only')
    ensure(not git('diff', 'HEAD', '--name-only'), 'initial-tracked-inputs-pristine')
    for ancestor, target in [(MERGE, baseline), (INCOMING, baseline), (baseline, source)]:
        subprocess.run(['git', 'merge-base', '--is-ancestor', ancestor, target], check=True)
    changed = set(git('diff', '--name-only', baseline, source).splitlines())
    ensure(changed <= {SELF, WORKFLOW}, 'only-reviewed-metadata-overlay')
    adaptation = {}
    if ownership_adaptation:
        subprocess.run(['git', 'merge-base', '--is-ancestor', RED, baseline], check=True)
        allowed = {SELF, WORKFLOW, OWNERSHIP_DOC, *BOUNDARY[1:]}
        red_changed = set(git('diff', '--name-only', RED, source).splitlines())
        ensure(red_changed <= allowed, 'all-private-providers-migrations-production-and-fixtures-exact-red')
        ensure(Path(BOUNDARY[0]).read_bytes() == subprocess.check_output(['git', 'show', INCOMING + ':' + BOUNDARY[0]]), 'incoming-base-module-registration-exact')
        old = subprocess.check_output(['git', 'show', INCOMING + ':' + BOUNDARY[1]]).decode()
        current = Path(BOUNDARY[1]).read_text()
        old_functions = re.findall(r'^fn ([A-Za-z_]+)\(', old, re.M)
        frozen_functions = [name for name in old_functions if name not in {'side_of', 'path_target', 'root_reexports'}]
        for name in frozen_functions:
            ensure(rust_function(old, name) == rust_function(current, name), 'original-assertion-and-scanner-function-exact')
        scan_start, scan_end = "impl<'ast> Visit<'ast> for Scan<'_> {", '\nfn use_paths('
        ensure(current[current.index(scan_start):current.index(scan_end)] == old[old.index(scan_start):old.index(scan_end)], 'original-ast-visitor-protections-exact')
        old_registry = subprocess.check_output(['git', 'show', INCOMING + ':' + BOUNDARY[2]]).decode()
        registry = Path(BOUNDARY[2]).read_text()
        start = registry.index('    // Private ownership inventory:')
        end = registry.index('    // The engine:', start)
        ensure(registry[:start] + registry[end:] == old_registry, 'upstream-table-owner-entries-unmodified')
        ensure(Path(BOUNDARY[3]).read_bytes().startswith(subprocess.check_output(['git', 'show', INCOMING + ':' + BOUNDARY[3]])), 'all-upstream-allow-list-entries-retained')
        adaptation = {'historical_red_source': RED, 'historical_red_run_id': 39055385890,
                      'original_three_test_bodies_exact': True, 'unchanged_scanner_functions': frozen_functions,
                      'all_private_provider_migration_and_product_inputs_exact_red': True,
                      'reviewed_ownership_paths': sorted(red_changed - {SELF, WORKFLOW}),
                      'historical_green_or_mutation_results_reused': False}
    else:
        for name in BOUNDARY:
            ensure(Path(name).read_bytes() == subprocess.check_output(['git', 'show', INCOMING + ':' + name]), 'incoming-boundary-source-remains-exact-before-red')
    ensure(all(not os.environ.get(key) for key in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS']), 'no-unrecorded-rust-flags')
    expected_environment = {'CARGO_INCREMENTAL': '1', 'CARGO_BUILD_JOBS': '2',
                            'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0',
                            'RUST_MIN_STACK': '4194304'}
    ensure(all(os.environ.get(key) == value for key, value in expected_environment.items()), 'exact-reviewed-build-environment')
    return {'source': source, 'reviewed_cohort_baseline': baseline, 'baseline_tree': git('rev-parse', baseline + '^{tree}'),
            'workflow_identity': workflow, 'incoming_master': INCOMING, 'incoming_boundary_sources_unchanged': not ownership_adaptation,
            'ownership_adaptation': adaptation, 'overlay_paths': sorted(changed), 'historical_results_reused': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort', choices=['default', 'experimental'], required=True)
    parser.add_argument('--cohort-baseline', default=os.environ.get('UPSTREAM_EXTRACTION_COHORT_BASELINE'))
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--compile-only', action='store_true')
    parser.add_argument('--ownership-adaptation', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    OUT.mkdir(exist_ok=True)
    report = {'cohort': args.cohort, 'compile_only': args.compile_only, 'qualification_passed': False, 'boundary_controls_passed': False,
              'actual_counts_complete': False, 'actual_executed_nonignored': 0, 'bodies': {}}
    frozen = frozen_inputs()
    report['input_manifest_sha256'] = digest(json.dumps(frozen, sort_keys=True, separators=(',', ':')).encode())
    def save():
        (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report.update(source_guard(args.cohort_baseline, args.ownership_adaptation))
        report['parser_fixtures'] = parser_preflight()
        report['compiler_parser_fixtures'] = diagnostic_parser_preflight()
        ensure(not args.compile_only or args.cohort == 'default', 'diagnostic-scope-default-only')
        report['toolchain'] = {name: subprocess.check_output([name, '--version'], text=True).strip() for name in ['cargo', 'rustc']}
        report['environment'] = {key: os.environ.get(key) for key in ['CARGO_INCREMENTAL', 'CARGO_BUILD_JOBS', 'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG', 'RUST_MIN_STACK']}
        save()
        if args.preflight:
            report['preflight_passed'] = True
            return 0
        selected_tests = sorted(TESTS + ([ADDED_TEST] if args.ownership_adaptation else []))
        expected_count = len(selected_tests)
        command = ['cargo', 'test', '--locked', '-p', 'storage-sqlite', '--lib', '--no-run', '--message-format=json']
        expected_features = []
        if args.cohort == 'experimental':
            command += ['--features', 'experimental-device-sync']
            expected_features = ['experimental-device-sync']
        report['compile_command'] = command
        code, raw, seconds = capture(command, 1800)
        artifacts, errors, diagnostics = [], 0, []
        for line in raw.splitlines():
            if not line.startswith('{'):
                continue
            value = json.loads(line)
            if value.get('reason') == 'compiler-message' and value.get('message', {}).get('level') == 'error':
                errors += 1
                if len(diagnostics) < 16:
                    diagnostics.append(safe_compiler_diagnostic(value, frozen))
            if value.get('reason') == 'compiler-artifact':
                artifacts.append(value)
        selected = [value for value in artifacts if value['target']['name'] == 'storage_sqlite' and value['target']['kind'] == ['lib'] and value['profile']['test'] and value.get('executable')]
        report['compilation'] = {'exit_code': code, 'compiler_error_count': errors, 'wall_seconds': seconds,
                                 'selected_test_artifact_count': len(selected), 'compiled_features': None,
                                 'safe_compiler_diagnostics': diagnostics, 'diagnostics_truncated': errors > 16}
        save()
        ensure(code == 0 and errors == 0 and len(selected) == 1, 'actual-storage-lib-compilation-required')
        artifact = selected[0]
        ensure(sorted(artifact['features']) == expected_features, 'exact-default-or-experimental-storage-feature-cohort')
        binary = Path(artifact['executable'])
        binary_hash = digest(binary.read_bytes())
        report['compilation'].update(compiled_features=sorted(artifact['features']), binary_sha256=binary_hash)
        fingerprints = sorted([{'package': value['package_id'], 'target': value['target']['name'],
                                'kind': value['target']['kind'], 'features': sorted(value['features']), 'profile': value['profile']}
                               for value in artifacts], key=lambda value: json.dumps(value, sort_keys=True))
        report['compilation']['compiler_artifact_feature_manifest_sha256'] = digest(json.dumps(fingerprints, sort_keys=True).encode())
        ensure(frozen_inputs() == frozen, 'inputs-exact-after-compilation')
        if args.compile_only:
            report['compile_only_completed'] = True
            report['compile_only_is_not_runtime_green'] = True
            return 0
        code, inventory, _ = capture([str(binary), 'base::boundary_tests::', '--list', '--format', 'terse'], 60)
        names = sorted(re.findall(r'^(base::boundary_tests::[A-Za-z_]+): test$', inventory, re.M))
        inventory_lines = [line for line in inventory.splitlines() if line]
        allowed_lines = {name + ': test' for name in selected_tests} | {str(expected_count) + ' tests, 0 benchmarks'}
        ensure(code == 0 and names == selected_tests and all(line in allowed_lines for line in inventory_lines), 'exact-reviewed-body-inventory-required')
        code, ignored, _ = capture([str(binary), 'base::boundary_tests::', '--ignored', '--list', '--format', 'terse'], 60)
        ensure(code == 0 and ignored.strip() in {'', '0 tests, 0 benchmarks'}, 'no-selected-ignored-bodies')
        report['inventory'] = {'selected_names': names, 'selected_nonignored': expected_count, 'selected_ignored': 0}
        for name in names:
            ensure(frozen_inputs() == frozen and digest(binary.read_bytes()) == binary_hash, 'inputs-and-binary-exact-before-body')
            command = [str(binary), name, '--exact', '--nocapture', '--test-threads=1']
            code, raw, seconds = capture(command, 300)
            row = parse_body(raw, code, name)
            row['wall_seconds'] = seconds
            row['binary_sha256'] = binary_hash
            report['bodies'][name] = row
            known = list(report['bodies'].values())
            report['actual_executed_nonignored'] = sum(item['executed_nonignored'] for item in known) if all(item['actual_counts_complete'] for item in known) else None
            save()
            ensure(frozen_inputs() == frozen and digest(binary.read_bytes()) == binary_hash, 'inputs-and-binary-exact-after-body')
        rows = list(report['bodies'].values())
        report['actual_counts_complete'] = len(rows) == expected_count and all(row['actual_counts_complete'] for row in rows)
        report['actual_executed_nonignored'] = sum(row['executed_nonignored'] for row in rows) if report['actual_counts_complete'] else None
        report['boundary_controls_passed'] = report['actual_counts_complete'] and all(row['passed_gate'] for row in rows)
        return 0 if report['boundary_controls_passed'] else 1
    except Exception as error:
        report['controller_failure_type'] = type(error).__name__
        report['controller_failure_gate'] = str(error) if isinstance(error, GateFailure) else None
        # No exception payload: a child process can include raw SQL or account data.
        return 1
    finally:
        report['inputs_pristine'] = frozen_inputs() == frozen
        save()
        if not report['inputs_pristine']:
            raise SystemExit(1)


if __name__ == '__main__':
    raise SystemExit(main())
