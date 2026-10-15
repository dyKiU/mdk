#!/usr/bin/env python3
"""Kill one missing-translation mutant using already built native tests, then restore exact bytes."""
import hashlib
import json
import os
from pathlib import Path
import subprocess


root = Path('ios').resolve(strict=True)
catalog = root / 'Shared/Localizable.xcstrings'
original = catalog.read_bytes()
original_sha = hashlib.sha256(original).hexdigest()
temp = Path(os.environ['RUNNER_TEMP'])
output = temp / 'localization-mutation'
output.mkdir(mode=0o700)
derived = temp / 'final-ios-derived-data'
destination = os.environ['WN_TEST_DESTINATION']
selectors = ['sharedCatalogHasNoMissingLocalizedValuesAndKeepsPlaceholders', 'sharedCatalogMarksEveryLocaleTranslated']
command = ['xcrun', 'xcodebuild', 'test-without-building', '-project', 'whitenoise-ios.xcodeproj',
           '-scheme', 'Whitenoise (Staging)', '-destination', destination,
           '-derivedDataPath', str(derived), '-clonedSourcePackagesDirPath', str(temp / 'final-ios-packages'),
           '-skipPackagePluginValidation', '-skipMacroValidation',
           *['-only-testing:whitenoise-iosTests/LocalizationCatalogTests/' + name + '()' for name in selectors]]
proof = {'app_sha': os.environ['IOS_SHA'], 'sdk_sha': os.environ['SOURCE_SHA'],
         'sdk_run_id': os.environ['SDK_RUN_ID'], 'catalog_sha256': original_sha,
         'mutation': 'Remove de localization for Shared from a linked device', 'runs': []}


def execute(name):
    bundle = output / (name + '.xcresult')
    with (output / (name + '.log')).open('x') as log:
        result = subprocess.run(command + ['-resultBundlePath', str(bundle)], cwd=root,
                                stdout=log, stderr=subprocess.STDOUT, timeout=900)
    summary = json.loads(subprocess.check_output(
        ['xcrun', 'xcresulttool', 'get', 'test-results', 'summary', '--path', str(bundle), '--format', 'json'], text=True))
    row = {'phase': name, 'exit_code': result.returncode, 'summary': summary}
    proof['runs'].append(row)
    (output / 'result.json').write_text(json.dumps(proof, indent=2) + '\n')
    return row


try:
    value = json.loads(original)
    locales = value['strings']['Shared from a linked device']['localizations']
    if 'de' not in locales:
        raise ValueError('Mutation baseline is already missing German localization')
    del locales['de']
    catalog.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    red = execute('mutant')
    if (red['exit_code'] == 0 or red['summary'].get('failedTests', 0) < 1
            or red['summary'].get('totalTestCount', 0) != 2
            or 'Missing de localization for Shared from a linked device' not in json.dumps(red['summary'])):
        raise ValueError('Mutation was not detected by the intended runtime localization regression')
finally:
    catalog.write_bytes(original)
    proof['source_restored'] = hashlib.sha256(catalog.read_bytes()).hexdigest() == original_sha
    (output / 'result.json').write_text(json.dumps(proof, indent=2) + '\n')
if not proof['source_restored']:
    raise ValueError('Catalog restoration failed')
green = execute('restored-control')
if (green['exit_code'] != 0 or green['summary'].get('passedTests') != 2
        or green['summary'].get('failedTests') != 0 or green['summary'].get('skippedTests') != 0):
    raise ValueError('Restored control did not execute both passing tests')
proof['mutation_killed'] = True
(output / 'result.json').write_text(json.dumps(proof, indent=2) + '\n')
