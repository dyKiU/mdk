#!/usr/bin/env python3
"""Require actual runtime detection of hosted test-fixture provenance regressions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--platform', choices=('macos', 'ios'), required=True)
args = parser.parse_args()
mac = args.platform == 'macos'
root = Path('mac' if mac else 'ios').resolve(strict=True)
target = 'whitenoise-macTests' if mac else 'whitenoise-iosTests'
head = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
if head != os.environ['MAC_SHA' if mac else 'IOS_SHA']:
    raise ValueError('Fixture guard checkout differs from the pinned app')
source = root / target / 'HostedNativeFixtureRoot.swift'
original = source.read_bytes()
relative = str(source.relative_to(root))
if original != subprocess.check_output(['git', '-C', str(root), 'show', head + ':' + relative]):
    raise ValueError('Fixture guard source differs from committed bytes')
temp = Path(os.environ['RUNNER_TEMP'])
output = temp / ('hosted-root-mutations-' + args.platform)
output.mkdir(mode=0o700)
definitions = (
    ('closed-owner', 'provenance.version == 1 && provenance.originalWorkerClosed',
     'provenance.version == 1 && true', 'testMismatchedSDKProducerPlatformOrUnclosedWorkerIsRefused'),
    ('sdk-identity', '&& provenance.platform == platform && provenance.sdkSource == sdkSource',
     '&& provenance.platform == platform && true', 'testMismatchedSDKProducerPlatformOrUnclosedWorkerIsRefused'),
    ('private-permissions', '&& (values[.posixPermissions] as? NSNumber)?.intValue == mode',
     '&& true', 'testBroadPermissionsOrMissingMarkerAreRefused'),
)
proof = {'platform': args.platform, 'app_sha': head, 'sdk_source': os.environ['SOURCE_SHA'],
         'sdk_run_id': os.environ['SDK_RUN_ID'], 'tools_sha': os.environ['GITHUB_SHA'],
         'source': relative, 'original_sha256': hashlib.sha256(original).hexdigest(),
         'expected_mutants': len(definitions), 'mutants': []}


def save():
    (output / 'result.json').write_text(json.dumps(proof, indent=2) + '\n')


def execute(record, phase):
    bundle = output / (record['name'] + '-' + phase + '.xcresult')
    environment = dict(os.environ, WN_EXPERIMENTAL_DEVICE_SYNC='1', WN_TEST_JOBS='2',
                       WN_TEST_DERIVED_DATA=str(temp / ('final-mac-derived-data' if mac else 'final-ios-derived-data')),
                       WN_TEST_RESULT_BUNDLE=str(bundle))
    if not mac:
        environment['WN_TEST_SOURCE_PACKAGES'] = str(temp / 'final-ios-packages')
        environment['WN_TEST_RELAY_BINARY'] = str(root / 'build/TestRelay/debug/white-noise-sync-test-relay')
    command = ['bash', 'scripts/test-isolated.sh' if mac else 'scripts/test-with-relay.sh',
               '-only-testing:' + target + '/HostedNativeFixtureRootTests/' + record['method']]
    row = {'phase': phase, 'command': command}
    record['runs'].append(row)
    save()
    with (output / (record['name'] + '-' + phase + '.log')).open('x') as log:
        result = subprocess.run(command, cwd=root, env=environment, stdout=log,
                                stderr=subprocess.STDOUT, timeout=1200)
    row.update(exit_code=result.returncode, runtime_result_present=bundle.exists())
    save()
    if not bundle.exists():
        raise ValueError('No native execution result; compilation cannot kill a mutant')
    summary = json.loads(subprocess.check_output(
        ['xcrun', 'xcresulttool', 'get', 'test-results', 'summary', '--path', str(bundle)], text=True))
    fields = ('totalTestCount', 'passedTests', 'failedTests', 'skippedTests')
    if any(type(summary.get(key)) is not int or summary[key] < 0 for key in fields):
        raise ValueError('Missing or invalid native execution counts')
    row['counts'] = {key: summary[key] for key in fields}
    row['green'] = (result.returncode == 0 and row['counts'] == dict(zip(fields, (1, 1, 0, 0))))
    row['red'] = (result.returncode != 0 and row['counts'] == dict(zip(fields, (1, 0, 1, 0))))
    save()
    return row


save()
for name, old, new, method in definitions:
    if original.decode().count(old) != 1:
        raise ValueError('Expected exactly one reviewed fixture guard')
    record = {'name': name, 'method': method, 'runs': []}
    proof['mutants'].append(record)
    save()
    if not execute(record, 'baseline')['green']:
        raise ValueError('Fixture guard baseline did not execute exactly one passing test')
    mutant = original.decode().replace(old, new, 1).encode()
    record['mutant_sha256'] = hashlib.sha256(mutant).hexdigest()
    try:
        source.write_bytes(mutant)
        record['runtime_red_confirmed'] = execute(record, 'mutant')['red']
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        record['runtime_red_confirmed'] = False
        record['mutation_attempt_error_category'] = type(error).__name__
    finally:
        source.write_bytes(original)
        record['source_restored'] = source.read_bytes() == original
        save()
    if not record['source_restored']:
        raise ValueError('Exact fixture guard restoration failed')
    record['restored_control_passed'] = execute(record, 'restored-control')['green']
    record['final_source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
    record['mutation_killed'] = (record['runtime_red_confirmed'] and record['restored_control_passed']
                                 and record['final_source_sha256'] == proof['original_sha256'])
    save()
    if not record['restored_control_passed'] or record['final_source_sha256'] != proof['original_sha256']:
        raise ValueError('Exact restored fixture guard control did not qualify')
proof['killed_mutants'] = sum(row.get('mutation_killed') is True for row in proof['mutants'])
proof['passed'] = proof['killed_mutants'] == len(definitions)
save()
if not proof['passed']:
    raise SystemExit('Not every hosted fixture guard mutant was detected and restored')
