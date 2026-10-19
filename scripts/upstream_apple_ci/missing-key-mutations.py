#!/usr/bin/env python3
"""Require runtime detection of obsolete-publication invite misclassification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


profile = os.environ.get('WN_SDK_PROFILE') or 'experimental'
if profile not in {'default', 'experimental'}:
    raise ValueError('API adaptation mutations require a current SDK profile')
private_flag = '0' if profile == 'default' else '1'
if os.environ.get('WN_EXPERIMENTAL_DEVICE_SYNC', private_flag) != private_flag:
    raise ValueError('Mutation profile differs from private opt-in')


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--platform', choices=['macos', 'ios'], required=True)
args = parser.parse_args()
mac = args.platform == 'macos'
root = Path('mac' if mac else 'ios').resolve(strict=True)
head = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
if head != os.environ['MAC_SHA' if mac else 'IOS_SHA']:
    raise ValueError('Mutation source differs from the qualified app candidate')
temp = Path(os.environ['RUNNER_TEMP'])
output = temp / ('missing-key-mutations-' + args.platform)
output.mkdir(mode=0o700)
definitions = [
    ('mac-obsolete-invite', 'whitenoise-mac/Core/ChatCreationFailure.swift',
     '.MissingKeyPackage(let account, .notFound)', '.MissingKeyPackage(let account, _)',
     'whitenoise-macTests/ChatInviteRuleTests/obsoletePublicationUsesGenericErrorWithoutAnInviteOrAccountDisclosure()')
] if mac else [
    ('ios-obsolete-recipient', 'whitenoise-ios/Recipients/MissingKeyPackageInvitationPresentation.swift',
     '.MissingKeyPackage(let account, .notFound)', '.MissingKeyPackage(let account, _)',
     'whitenoise-iosTests/MissingKeyPackageInvitationPresentationTests/obsoletePublicationDoesNotIdentifySomeoneAsAbsentFromWhiteNoise()'),
    ('ios-obsolete-direct-chat', 'whitenoise-ios/Recipients/DirectChatStarter.swift',
     '.MissingKeyPackage(_, .notFound)', '.MissingKeyPackage(_, _)',
     'whitenoise-iosTests/DirectChatStarterTests/obsoletePublicationOffersAnErrorInsteadOfSharingTheApp()'),
]
proof = {'platform': args.platform, 'app_sha': head, 'sdk_sha': os.environ['SOURCE_SHA'],
         'sdk_run_id': os.environ['SDK_RUN_ID'], 'sdk_profile': profile, 'private_flag': private_flag, 'workflow_tools_sha': os.environ['GITHUB_SHA'],
         'expected_mutants': len(definitions), 'mutants': []}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save():
    (output / 'result.json').write_text(json.dumps(proof, indent=2) + '\n')


def execute(record, phase):
    bundle = output / (record['name'] + '-' + phase + '.xcresult')
    environment = dict(os.environ, WN_EXPERIMENTAL_DEVICE_SYNC=private_flag, WN_TEST_JOBS='2',
                       WN_TEST_DERIVED_DATA=str(temp / ('final-mac-derived-data' if mac else 'final-ios-derived-data')),
                       WN_TEST_RESULT_BUNDLE=str(bundle))
    if not mac:
        environment['WN_TEST_SOURCE_PACKAGES'] = str(temp / 'final-ios-packages')
        environment['WN_TEST_RELAY_BINARY'] = str(root / 'build/TestRelay/debug/white-noise-sync-test-relay')
    # Both supported runners compile changed Swift incrementally before the
    # selected test. Merely testing old binaries cannot detect a source mutant.
    command = ['bash', 'scripts/test-isolated.sh' if mac else 'scripts/test-with-relay.sh',
               '-only-testing:' + record['selector']]
    with (output / (record['name'] + '-' + phase + '.log')).open('x') as log:
        result = subprocess.run(command, cwd=root, env=environment, stdout=log,
                                stderr=subprocess.STDOUT, timeout=1200)
    row = {'phase': phase, 'exit_code': result.returncode, 'command': command,
           'runtime_result_present': bundle.exists()}
    record['runs'].append(row)
    save()
    if not bundle.exists():
        raise ValueError('No executed native result; compilation failure is not a mutation kill')
    summary = json.loads(subprocess.check_output(
        ['xcrun', 'xcresulttool', 'get', 'test-results', 'summary', '--path', str(bundle)], text=True))
    row['summary'] = {key: summary[key] for key in [
        'result', 'totalTestCount', 'passedTests', 'failedTests', 'skippedTests',
    ] if key in summary}
    save()
    return row


for name, relative, old, new, selector in definitions:
    source = root / relative
    original = source.read_bytes()
    text = original.decode()
    if text.count(old) != 1:
        raise ValueError('Expected one reviewed missing-key classification branch')
    mutant = text.replace(old, new, 1).encode()
    record = {'name': name, 'source': relative, 'selector': selector,
              'original_sha256': digest(original), 'mutant_sha256': digest(mutant),
              'mutation': 'Treat every MissingKeyPackage reason as notFound', 'runs': []}
    proof['mutants'].append(record)
    save()
    red_error = None
    try:
        source.write_bytes(mutant)
        red = execute(record, 'mutant')
        summary = red['summary']
        if (red['exit_code'] == 0 or summary.get('totalTestCount') != 1
                or summary.get('failedTests') != 1 or summary.get('passedTests') != 0
                or summary.get('skippedTests') != 0):
            raise ValueError('Selected obsolete-publication runtime test did not kill mutant')
        record['runtime_red_confirmed'] = True
    except (ValueError, subprocess.CalledProcessError) as error:
        record['runtime_red_confirmed'] = False
        record['mutation_attempt_error_category'] = type(error).__name__
        red_error = error
    finally:
        source.write_bytes(original)
        record['source_restored'] = digest(source.read_bytes()) == record['original_sha256']
        save()
    if not record['source_restored']:
        raise ValueError('Original app source restoration failed')
    green = execute(record, 'restored-control')
    summary = green['summary']
    record['restored_control_passed'] = (green['exit_code'] == 0 and summary.get('totalTestCount') == 1
                                        and summary.get('passedTests') == 1 and summary.get('failedTests') == 0
                                        and summary.get('skippedTests') == 0)
    record['final_source_sha256'] = digest(source.read_bytes())
    record['mutation_killed'] = (record['runtime_red_confirmed'] and record['restored_control_passed']
                                 and record['final_source_sha256'] == record['original_sha256'])
    save()
    if not record['restored_control_passed'] or record['final_source_sha256'] != record['original_sha256']:
        raise ValueError('Restored source/control did not qualify')
    # Record a completed invalid mutation attempt, then continue the independent
    # iOS classifier gate. Neither is accepted merely because the other passed.
    if red_error is not None:
        record['mutation_killed'] = False
        save()
proof['killed_mutants'] = sum(record.get('mutation_killed') is True for record in proof['mutants'])
proof['all_controls_passed'] = all(record.get('restored_control_passed') is True for record in proof['mutants'])
save()
if proof['killed_mutants'] != len(definitions) or not proof['all_controls_passed']:
    raise SystemExit('Not every classification mutant was detected with a passing restored control')
