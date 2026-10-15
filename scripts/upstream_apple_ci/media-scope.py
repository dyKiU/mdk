#!/usr/bin/env python3
"""Remote-only qualification of unchanged upstream media and migration tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET

BASE = 'fdf437fd92853f03250431bf840e661b4a92e000'
ROOT = Path.cwd()
OUT = ROOT / 'media-scope-evidence'


def require(value, label):
    if not value:
        raise ValueError(label)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cohort', choices=('static', 'default', 'experimental'), required=True)
    cohort = parser.parse_args().cohort
    require(os.environ.get('GITHUB_ACTIONS') == 'true', 'remote-ci-required')
    OUT.mkdir(exist_ok=False)
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip()
    # Only the new workflow and controller may differ from the approved merge.
    changed = subprocess.check_output(['git', 'diff', '--name-only', BASE, 'HEAD'], text=True).splitlines()
    require(set(changed) == {'.github/workflows/upstream-media-scope.yml',
                            'scripts/upstream_apple_ci/media-scope.py'}, 'only-scoped-harness-delta-permitted')
    report = {'source': source, 'tree': tree, 'product_base': BASE, 'cohort': cohort,
              'commands': [], 'passed': False, 'scope': 'No SDK, packaging, profiling or broad workspace/storage runtime matrix.'}

    def save():
        (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    def command(name, argv, stdout_file=None):
        started = time.monotonic()
        log = stdout_file or OUT / (name + '.log')
        with log.open('w') as stream:
            process = subprocess.run(argv, stdout=stream, stderr=None if stdout_file else subprocess.STDOUT)
        row = {'name': name, 'argv': argv, 'exit_code': process.returncode,
               'seconds': round(time.monotonic() - started, 3)}
        report['commands'].append(row)
        save()
        return process.returncode

    save()
    try:
        require(command('locked-metadata', ['cargo', 'metadata', '--locked', '--format-version', '1', '--no-deps'],
                        OUT / 'metadata.json') == 0, 'locked-metadata-failed')
        if cohort == 'static':
            commands = [
                ('format', ['cargo', 'fmt', '--all', '--check']),
                ('media-clippy', ['cargo', 'clippy', '-p', 'media-store', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings']),
                ('storage-clippy-default', ['cargo', 'clippy', '-p', 'storage-sqlite', '--all-targets', '--locked', '--', '-D', 'warnings']),
                ('storage-clippy-experimental', ['cargo', 'clippy', '-p', 'storage-sqlite', '--all-targets', '--features', 'experimental-device-sync', '--locked', '--', '-D', 'warnings']),
            ]
            exits = [command(name, argv) for name, argv in commands]
            report['passed'] = all(code == 0 for code in exits)
        else:
            features = ['--features', 'storage-sqlite/experimental-device-sync'] if cohort == 'experimental' else []
            # Keep original profile deadlines/groups intact, adding only XML output.
            config = OUT / 'nextest.toml'
            config.write_text((ROOT / '.config/nextest.toml').read_text()
                              + '\n[profile.ci.junit]\npath = "media-scope.xml"\n')
            suites = [
                ('media-store', ['-p', 'media-store', '--all-targets'], ['media-store']),
                ('catalog-migrations', ['-p', 'storage-sqlite', '--lib', *features, '-E',
                    'test(media_catalog) | test(migrations::) | test(private_migration_ledger)'],
                 ['media_catalog', 'migrations::media_open_upgrade_tests', 'migrations::tests',
                  'private_migration_ledger'] if cohort == 'experimental' else
                 ['media_catalog', 'migrations::media_open_upgrade_tests', 'migrations::tests']),
            ]
            all_passed = True
            report['suites'] = []
            for name, selection, families in suites:
                inventory = OUT / (name + '-inventory.json')
                require(command(name + '-inventory', ['cargo', 'nextest', 'list', '--locked',
                    '--message-format', 'json', *selection], inventory) == 0, 'inventory-failed')
                value = json.loads(inventory.read_text())
                cases = [(suite['package-name'], test, case) for suite in value['rust-suites'].values()
                         for test, case in suite['testcases'].items()]
                require(cases and all(type(case.get('ignored')) is bool for _, _, case in cases), 'actual-ignored-metadata-required')
                selected = [(package, test, case) for package, test, case in cases if case['filter-match']['status'] == 'matches']
                runnable = [(package, test, case) for package, test, case in selected if not case['ignored']]
                counts = {'inventory_total': len(cases), 'selected_total': len(selected),
                    'selected_ignored': len(selected) - len(runnable), 'selected_runnable': len(runnable),
                    'filtered': len(cases) - len(selected)}
                require(runnable and all(any(family in package or family in test for package, test, _ in runnable)
                                         for family in families), 'required-nonignored-test-family-missing')
                junit = ROOT / 'target/nextest/ci/media-scope.xml'
                junit.unlink(missing_ok=True)
                code = command(name + '-runtime', ['cargo', 'nextest', 'run', '--config-file', str(config),
                    '--profile', 'ci', '--retries', '0', '--locked', *selection])
                actual = {'xml_present': junit.exists()}
                if junit.exists():
                    xml = junit.read_bytes()
                    (OUT / (name + '-junit.xml')).write_bytes(xml)
                    tests = ET.fromstring(xml).findall('.//testcase')
                    skipped = sum(test.find('skipped') is not None for test in tests)
                    failed = sum(test.find('failure') is not None or test.find('error') is not None for test in tests)
                    actual.update(total=len(tests), passed=len(tests) - skipped - failed,
                                  failed=failed, skipped=skipped)
                passed = code == 0 and actual.get('passed') == len(runnable) and actual.get('failed') == 0
                report['suites'].append({'name': name, 'inventory': counts, 'actual': actual, 'passed': passed})
                all_passed &= passed
                save()
            # nextest does not execute rustdoc tests; qualify that full-crate leg separately.
            docs = command('media-doctests', ['cargo', 'test', '-p', 'media-store', '--doc', '--locked'])
            report['passed'] = all_passed and docs == 0
        report['locked_file_unchanged'] = subprocess.run(['git', 'diff', '--exit-code', '--', 'Cargo.lock'], stdout=subprocess.DEVNULL).returncode == 0
        report['passed'] &= report['locked_file_unchanged']
    except (ValueError, OSError, KeyError, subprocess.SubprocessError, ET.ParseError) as error:
        report['failure'] = str(error)
        report['passed'] = False
    finally:
        report['controller_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        save()
    require(report['passed'], 'scoped-media-qualification-failed')


if __name__ == '__main__':
    main()
