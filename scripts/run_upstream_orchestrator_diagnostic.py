"""Two unchanged real integration bodies; raw runtime data stays on the runner."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from verify_upstream_orchestrator_diagnostic_source import verify

CASES = [
    'orchestrator_runs_canonical_schedule_with_isolated_process_roots',
    'process_kill_disconnect_reconnect_and_restart_agree_with_uninterrupted_execution',
]
FEATURES = 'marmot-app/otlp-export,marmot-uniffi/otlp-export,marmot-c/otlp-export,wn-cli/otlp-export,agent-connector/otlp-export,marmot-app/product-analytics-export,marmot-uniffi/product-analytics-export,marmot-c/product-analytics-export,wn-cli/product-analytics-export,agent-connector/product-analytics-export,wn-cli/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks,experimental-device-sync'
KEYS = ['expected', 'retained', 'unique', 'gift_wrap', 'mls_group', 'expected_ids', 'matched_ids', 'missing_ids']
PREFIX = 'relay-action-publication-timeout '
CAPSULE_RE = re.compile(PREFIX + ' '.join(key + r'=(\d+)' for key in KEYS))
OUTPUT = Path('orchestrator-diagnostic')


def ensure(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def parse(raw):
    raw = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    records = []
    for line in raw.splitlines():
        if PREFIX not in line:
            continue
        match = CAPSULE_RE.fullmatch(line.strip())
        ensure(match is not None, 'malformed-numeric-capsule')
        values = list(map(int, match.groups()))
        ensure(all(value <= 1000000 for value in values), 'numeric-capsule-bound')
        row = dict(zip(KEYS, values))
        ensure(row['matched_ids'] + row['missing_ids'] == row['expected_ids'], 'capsule-identity-counts')
        ensure(row['unique'] <= row['retained'] and row['matched_ids'] <= row['unique'], 'capsule-retained-counts')
        records.append(row)
    ensure(len(records) <= 4, 'capsule-record-cap')
    summaries = re.findall(r'Summary\s+\[[^]]*\]\s+(\d+) tests? run:\s*([^\n]*)', raw)
    result = {'capsules': records, 'summary_count': len(summaries),
              'panic_header_count': len(re.findall(r'panicked at', raw)),
              'panic_locations': [{'file': file, 'line': int(line), 'column': int(column)} for file, line, column in re.findall(r'panicked at (crates/[A-Za-z0-9_./-]+\.rs):(\d+):(\d+)', raw)],
              'relay_action_publication_timeout_observed': 'relay_action_publication_timeout' in raw}
    if len(summaries) == 1:
        total, text = summaries[0]
        result['executed_nonignored'] = int(total)
        for name in ['passed', 'failed', 'skipped']:
            match = re.search(r'\b(\d+) ' + name + r'\b', text)
            result[name if name != 'skipped' else 'skipped_or_filtered'] = int(match.group(1)) if match else 0
    return result


def parser_preflight():
    capsule = PREFIX + 'expected=2 retained=1 unique=1 gift_wrap=0 mls_group=1 expected_ids=2 matched_ids=1 missing_ids=1'
    valid = capsule + '\nSummary [1.0s] 1 test run: 0 passed, 1 failed, 17 skipped\n'
    ensure(parse(valid)['capsules'][0]['missing_ids'] == 1, 'parser-positive')
    ensure(parse('Summary [1.0s] 1 test run: 1 passed, 17 skipped')['passed'] == 1, 'parser-green')
    negatives = [capsule.replace('retained=1', 'retained=x'), capsule + ' secret=x',
                 capsule.replace('missing_ids=1', 'missing_ids=0'), capsule.replace('unique=1', 'unique=2'),
                 '\n'.join([capsule] * 5), capsule.replace('expected=2 ', ''),
                 capsule.replace('expected=2', 'expected=1000001')]
    for sample in negatives:
        try:
            parse(sample)
        except ValueError:
            continue
        raise ValueError('parser-negative-accepted')
    return {'positive': 2, 'negative': len(negatives), 'runtime_bodies': 0}


def fingerprints(binary):
    """Resolve Cargo unit edges against actual companion fingerprints, never guess."""
    directory = binary.parent.parent / '.fingerprint'
    root = directory / ('cgka-conformance-simulator-' + binary.name.rsplit('-', 1)[-1]) / 'test-integration-test-process_orchestrator.json'
    wanted = {'cgka_conformance_simulator', 'marmot_app', 'cgka_engine', 'storage_sqlite', 'marmot_account', 'cgka_session'}
    result = {'verified': False, 'required': sorted(wanted), 'nodes': {}, 'unresolved': []}
    expected_seen = {}

    def read(path, name):
        data = json.loads(path.read_text())
        features = data['features']
        if isinstance(features, str):
            features = json.loads(features)
        ensure(isinstance(features, list) and all(isinstance(x, str) and re.fullmatch(r'[A-Za-z0-9_./+-]+', x) for x in features), 'fingerprint-feature-schema')
        result['nodes'][name] = {'features': features, 'json_sha256': sha(path), 'profile': data.get('profile'),
                                 'compile_kind': data.get('compile_kind'), 'rustflags_empty': data.get('rustflags') == []}
        for dep in data.get('deps', []):
            if len(dep) != 4 or dep[1] not in wanted:
                continue
            label, expected = dep[1], dep[3]
            if label in result['nodes']:
                if expected_seen.get(label) != expected:
                    result['unresolved'].append(label + '-multiple-units')
                continue
            candidates = []
            for candidate in directory.glob(label.replace('_', '-') + '-*/lib-' + label + '.json'):
                companion = candidate.with_suffix('')
                if not companion.is_file():
                    continue
                value = companion.read_text().strip()
                if not re.fullmatch(r'[0-9a-fA-F]{16}', value):
                    continue
                raw = bytes.fromhex(value)
                if type(expected) is int and expected in [int.from_bytes(raw, 'little'), int.from_bytes(raw, 'big')]:
                    candidates.append(candidate)
            if len(candidates) != 1:
                result['unresolved'].append(label)
                continue
            expected_seen[label] = expected
            read(candidates[0], label)
            result['nodes'][label]['expected_dependency_u64'] = expected
            result['nodes'][label]['companion_sha256'] = sha(candidates[0].with_suffix(''))

    if not root.is_file():
        result['unresolved'] = ['integration-root-missing']
        return result
    read(root, 'process_orchestrator')
    result['verified'] = wanted <= set(result['nodes']) and not result['unresolved'] and all(row['rustflags_empty'] for row in result['nodes'].values()) and all('experimental-device-sync' in result['nodes'][name]['features'] for name in ['marmot_app', 'cgka_engine', 'storage_sqlite'])
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--parser-preflight', action='store_true')
    args = parser.parse_args()
    OUTPUT.mkdir(exist_ok=True)
    if args.parser_preflight:
        (OUTPUT / 'parser.json').write_text(json.dumps(parser_preflight(), indent=2) + '\n')
        return
    report = {'qualification_passed': False, 'diagnostic_complete': False, 'cases': [], 'runtime_bodies_attempted': 0,
              'scope': 'two unchanged integration tests only; broader workspace compilation preserves experimental feature unification',
              'ignored_inventory': 'each selected inventory must be nonignored; nextest skipped means excluded/filtered, not ignored'}

    def save():
        (OUTPUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    save()
    try:
        before = verify()['tracked_sha256']
        source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
        ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_SHA') == source, 'remote-source')
        ensure(subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'initial-source-not-pristine')
        ensure(os.environ.get('SYNC_FEATURES') == FEATURES, 'original-workspace-feature-text')
        expected_env = {'CARGO_INCREMENTAL': '0', 'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0', 'RUST_MIN_STACK': '4194304'}
        ensure(all(os.environ.get(k) == v for k, v in expected_env.items()), 'original-build-environment')
        ensure(not any(os.environ.get(k) for k in ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_BOOTSTRAP', 'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_TEST_OPT_LEVEL']), 'compiler-overrides')
        report.update(source=source, tree=subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
                      input_hashes=before, environment=expected_env, rustc=subprocess.check_output(['rustc', '-Vv'], text=True).strip(),
                      nextest=subprocess.check_output(['cargo', 'nextest', '--version'], text=True).strip(), features=FEATURES,
                      stack_bytes=4194304, retries=0, scheduler_slots=6,
                      incremental_exception='Explicit incremental=0 reproduction of b111 experimental workspace archive cohort; not the routine incremental=1 preference')
        free = shutil.disk_usage('.').free
        report['free_bytes_before_compile'] = free
        save()
        ensure(free >= 25 * 1024 ** 3, 'compile-capacity-reserve')
        archive = Path(os.environ['RUNNER_TEMP']) / 'orchestrator-tests.tar.zst'
        command = ['cargo', 'nextest', 'archive', '--workspace', '--features', FEATURES, '--locked', '--archive-file', str(archive)]
        report['compile_command'] = command
        save()
        started = time.monotonic()
        build = subprocess.run(command, capture_output=True, text=True)
        report['compilation'] = {'exit_code': build.returncode, 'wall_seconds': time.monotonic() - started,
                                 'compiler_error_count': len(re.findall(r'^error(?:\[E\d+\])?:', build.stderr, re.M)),
                                 'compiler_error_codes': sorted(set(re.findall(r'^error\[(E\d+)\]:', build.stderr, re.M)))}
        save()
        ensure(build.returncode == 0 and report['compilation']['compiler_error_count'] == 0, 'compile-failed-no-runtime-credit')
        report['archive_sha256'] = sha(archive)
        expression = 'package(cgka-conformance-simulator) & binary(=process_orchestrator) & (' + ' | '.join('test(=' + case + ')' for case in CASES) + ')'
        # Extract exactly once. Both later runs consume the extracted metadata;
        # --archive-file on each run would needlessly unpack the archive again.
        archive_args = ['--archive-file', str(archive), '--extract-to', os.environ['GITHUB_WORKSPACE'], '--extract-overwrite', '--workspace-remap', os.environ['GITHUB_WORKSPACE']]
        inventory = subprocess.run(['cargo', 'nextest', 'list', *archive_args, '-E', expression, '--message-format', 'json'], capture_output=True, text=True)
        report['inventory_exit_code'] = inventory.returncode
        save()
        ensure(inventory.returncode == 0, 'archive-inventory-failed')
        metadata = Path(os.environ['GITHUB_WORKSPACE']) / 'target/nextest'
        reuse_args = ['--binaries-metadata', str(metadata / 'binaries-metadata.json'),
                      '--cargo-metadata', str(metadata / 'cargo-metadata.json'),
                      '--workspace-remap', os.environ['GITHUB_WORKSPACE']]
        report['extraction_count'] = 1
        report['reuse_metadata_sha256'] = {name: sha(metadata / name) for name in ['binaries-metadata.json', 'cargo-metadata.json']}
        suites = json.loads(inventory.stdout)['rust-suites']
        selected = [(name, suite) for suite in suites.values() for name, row in suite['testcases'].items() if row.get('filter-match', {}).get('status') == 'matches' and not row['ignored']]
        ensure(len(selected) == 2 and {name for name, _ in selected} == set(CASES), 'exact-two-nonignored-inventory')
        binaries = {Path(suite['binary-path']) for _, suite in selected}
        ensure(len(binaries) == 1, 'single-compiled-integration-binary')
        binary = next(iter(binaries))
        report['binary_sha256'] = sha(binary)
        report['compiled_fingerprints'] = fingerprints(binary)
        save()
        ensure(report['compiled_fingerprints']['verified'], 'compiled-feature-context-unverified')
        ensure(verify()['tracked_sha256'] == before, 'source-changed-before-bodies')
        for case in CASES:
            row = {'test': case, 'selected_nonignored': 1, 'selected_ignored': 0, 'same_binary_sha256': sha(binary)}
            report['cases'].append(row)
            report['runtime_bodies_attempted'] += 1
            save()
            try:
                ensure(verify()['tracked_sha256'] == before and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0, 'pristine-before-body')
                ensure(sha(binary) == report['binary_sha256'], 'same-binary-before-body')
                ensure({name: sha(metadata / name) for name in report['reuse_metadata_sha256']} == report['reuse_metadata_sha256'], 'same-reuse-metadata-before-body')
                exact = 'package(cgka-conformance-simulator) & binary(=process_orchestrator) & test(=' + case + ')'
                command = ['cargo', 'nextest', 'run', *reuse_args, '-E', exact, '--profile', 'm5-bounded', '--test-threads', '6', '--retries', '0', '--no-fail-fast', '--failure-output', 'immediate']
                row['command'] = command
                started = time.monotonic()
                body = subprocess.run(command, capture_output=True, text=True)
                row.update(exit_code=body.returncode, wall_seconds=time.monotonic() - started)
                save()  # Preserve the actual exit even if parsing fails.
                row.update(parse(body.stdout + body.stderr))
                row['collection_complete'] = row.get('executed_nonignored') == 1 and row.get('passed', 0) + row.get('failed', 0) == 1 and body.returncode in [0, 101]
            except Exception as error:
                row['controller_exception'] = type(error).__name__
                row['collection_complete'] = False
            finally:
                row['source_pristine_after'] = verify()['tracked_sha256'] == before and subprocess.run(['git', 'diff', '--quiet', 'HEAD']).returncode == 0
                save()
        report['source_pristine_after'] = verify()['tracked_sha256'] == before
        report['diagnostic_complete'] = len(report['cases']) == 2 and all(row.get('collection_complete') and row.get('source_pristine_after') for row in report['cases']) and report['source_pristine_after']
    except Exception as error:
        report['controller_exception'] = type(error).__name__
        report['diagnostic_complete'] = False
    finally:
        save()
    ensure(report['diagnostic_complete'], 'diagnostic-collection-incomplete')


if __name__ == '__main__':
    main()
