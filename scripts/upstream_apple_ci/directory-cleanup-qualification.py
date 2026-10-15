"""Focused remote controls and one exact critical-section omission mutant."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

METHODS = Path('crates/marmot-app/src/directory/methods.rs')
BASE = '835a1675cc33cc53730219e1f5c0a42f3a585da7'
BLOCK = '''        let lock = crate::sqlcipher::database_open_lock(&marker_path);
        let _cleanup = lock.lock();
        if marker_path.exists() {
            return Ok(());
        }
'''
CASE = 'sqlcipher::concurrency_tests::delayed_directory_cleanup_preserves_published_encrypted_cache'
CASES = [CASE,
    'sqlcipher::concurrency_tests::concurrent_first_directory_opens_share_one_handle',
    'sqlcipher::concurrency_tests::concurrent_first_account_opens_preserve_reopenability',
    'sqlcipher::concurrency_tests::database_lock_is_stable_across_file_creation_and_parent_aliases',
    'tests::legacy_plaintext_directory_cache_migrates_once_into_resident_cache',
    'tests::legacy_plaintext_directory_cache_migrates_to_shared_storage_without_account_caches',
    'tests::legacy_plaintext_directory_cache_keeps_file_when_migration_fails']


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(value, label):
    if not value:
        raise ValueError(label)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cohort', choices=('format', 'static', 'default', 'experimental'), required=True)
    cohort = parser.parse_args().cohort
    require(os.environ.get('GITHUB_ACTIONS') == 'true', 'remote-ci-required')
    output = Path('directory-cleanup-proof')
    output.mkdir(mode=0o700)
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    tracked = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
    frozen = {name: digest(Path(name).read_bytes()) for name in tracked if name and Path(name).is_file()}
    original = METHODS.read_bytes()
    require(original.count(BLOCK.encode()) == 1, 'exact-new-critical-section-required')
    mutant = original.replace(BLOCK.encode(), b'', 1)
    old = subprocess.check_output(['git', 'show', BASE + ':' + str(METHODS)])
    require(mutant == old, 'mutant-must-be-exact-proven-red-product-source')
    report = {'source': source, 'cohort': cohort, 'product_fix': '84560501c968fce54ccd34101eca2831d7dc171f',
              'methods_original_sha256': digest(original), 'methods_mutant_sha256': digest(mutant),
              'mutant_matches_proven_red_source': True, 'commands': [], 'controls': [], 'passed': False}

    def save():
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    def run(name, argv, json_stdout=False):
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix='directory-qualification-private-') as folder:
            log = Path(folder) / 'command.log'
            with log.open('x') as stream, (Path(folder) / 'compiler.log').open('x') as compiler:
                result = subprocess.run(argv, stdout=stream,
                    stderr=compiler if json_stdout else subprocess.STDOUT, timeout=2700)
            text = log.read_text(errors='replace')
        row = {'name': name, 'argv': argv, 'exit_code': result.returncode,
               'compile_and_execution_seconds': round(time.monotonic() - started, 3)}
        report['commands'].append(row)
        if cohort in ('static', 'format') and name != 'locked-metadata':
            print(text, flush=True)
        save()
        return row, text

    features = ['marmot-app/otlp-export', 'marmot-app/product-analytics-export',
        'marmot-app/test-policy-overrides', 'cgka-engine/test-policy-overrides', 'cgka-engine/test-crash-hooks']
    if cohort == 'experimental':
        features.append('marmot-app/experimental-device-sync')
    cargo = ['--locked', '-p', 'marmot-app', '--lib', '--features', ','.join(features)]

    def test(name, case, intended_red=False):
        row, text = run(name, ['cargo', 'test', *cargo, case, '--', '--exact', '--nocapture', '--test-threads=1'])
        counts = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
        require(len(counts) == 1 and re.search(r'(?m)^running 1 test$', text)
                and re.search(r'(?m)^test ' + re.escape(case) + r' \.\.\. ', text), 'one-exact-runtime-body-required')
        _, passed, failed, ignored = counts[0]
        row.update(case=case, passed_count=int(passed), failed_count=int(failed), ignored_count=int(ignored))
        expected = (0, 1, 0) if intended_red else (1, 0, 0)
        require((int(passed), int(failed), int(ignored)) == expected, 'actual-runtime-counts-mismatch')
        if intended_red:
            panics = re.findall(r"panicked at ([^\r\n]+):\r?\n([^\r\n]+)", text)
            allowed = ('late cleanup removed a published directory database',
                       'assertion `left == right` failed: late cleanup replaced a published directory database')
            require(row['exit_code'] != 0 and text.count('panicked at ') == len(panics) == 1
                    and re.fullmatch(r'crates/marmot-app/src/sqlcipher/concurrency_tests\.rs:\d+:\d+', panics[0][0])
                    and panics[0][1] in allowed, 'exact-filesystem-runtime-mutant-required')
            row['panic_site'] = panics[0][0]
            row['panic_category'] = 'published_directory_database_removed_or_replaced'
            row['runtime_mutant_detected'] = True
        else:
            require(row['exit_code'] == 0, 'runtime-control-failed')
        report['controls'].append(row)
        save()
        return row

    save()
    try:
        if cohort in ('static', 'format'):
            checks = [('format', ['cargo', 'fmt', '--all', '--check']),
                ('locked-metadata', ['cargo', 'metadata', '--locked', '--format-version', '1', '--no-deps'])]
            if cohort == 'static':
                checks += [
                ('clippy-default', ['cargo', 'clippy', '-p', 'marmot-app', '--all-targets', '--locked', '--', '-D', 'warnings']),
                ('clippy-experimental', ['cargo', 'clippy', '-p', 'marmot-app', '--all-targets', '--features',
                    'experimental-device-sync,otlp-export,product-analytics-export,test-policy-overrides', '--locked', '--', '-D', 'warnings'])]
            rows = [run(name, argv)[0] for name, argv in checks]
            require(all(row['exit_code'] == 0 for row in rows), 'affected-static-check-failed')
        else:
            selection = ' | '.join('test(=' + case + ')' for case in CASES)
            row, text = run('inventory', ['cargo', 'nextest', 'list', *cargo, '-E', selection, '--message-format', 'json'], json_stdout=True)
            require(row['exit_code'] == 0, 'inventory-build-failed')
            inventory = json.loads(text)
            cases = [(name, case) for suite in inventory['rust-suites'].values() for name, case in suite['testcases'].items()]
            selected = [(name, case) for name, case in cases if case['filter-match']['status'] == 'matches']
            require({name for name, _ in selected} == set(CASES)
                    and all(case.get('ignored') is False for _, case in selected), 'exact-seven-nonignored-controls-required')
            report['inventory'] = {'total': len(cases), 'selected': len(selected), 'selected_ignored': 0,
                                   'selected_runnable': len(selected), 'filtered': len(cases) - len(selected)}
            save()
            for index, case in enumerate(CASES):
                test('green-' + str(index), case)
            try:
                METHODS.write_bytes(mutant)
                require(all(digest(Path(name).read_bytes()) == value for name, value in frozen.items()
                            if name != str(METHODS)), 'mutation-touched-unrelated-tracked-source')
                test('omit-critical-section-mutant', CASE, intended_red=True)
            finally:
                METHODS.write_bytes(original)
                report['source_restored'] = METHODS.read_bytes() == original
                save()
            require(report['source_restored'], 'exact-source-restoration-required')
            test('restored-control', CASE)
        report['source_unchanged'] = all(digest(Path(name).read_bytes()) == value for name, value in frozen.items())
        require(report['source_unchanged'], 'tracked-source-or-lock-drift')
        report['passed'] = True
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        report['failure_category'] = type(error).__name__
        if isinstance(error, ValueError) and re.fullmatch('[a-z-]+', str(error)):
            report['failure_stage'] = str(error)
    finally:
        # Also restore on parser/compiler/timeout failure; none earns mutant credit.
        METHODS.write_bytes(original)
        report['source_restored'] = METHODS.read_bytes() == original
        save()
    require(report['passed'], 'directory-focused-qualification-failed')


if __name__ == '__main__':
    main()
