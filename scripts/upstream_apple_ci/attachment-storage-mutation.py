#!/usr/bin/env python3
"""Require a runtime storage-retry regression and exact-source restored control."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


profile = os.environ.get('WN_SDK_PROFILE') or 'experimental'
if profile not in {'default', 'experimental'}:
    raise ValueError('API adaptation mutations require a current SDK profile')
private_flag = '0' if profile == 'default' else '1'
if os.environ.get('WN_EXPERIMENTAL_DEVICE_SYNC', private_flag) != private_flag:
    raise ValueError('Mutation profile differs from private opt-in')


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--case', choices=['retry', 'rearm'], default='retry')
args = parser.parse_args()
root = Path('mac').resolve(strict=True)
head = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
if head != os.environ['MAC_SHA']:
    raise ValueError('Mac mutation checkout differs from the qualified candidate')
source = root / ('whitenoise-mac/Views/RetainedSharedMediaViews.swift' if args.case == 'retry'
                 else 'whitenoise-mac/Features/Attachments/AttachmentViewModel.swift')
original = source.read_bytes()
original_sha = hashlib.sha256(original).hexdigest()
text = original.decode()
if args.case == 'retry':
    start = text.index('    var canRetry: Bool {')
    end = text.index('    var canRemove: Bool {', start)
    pattern, replacement = r'(case \.storageBlocked:\s*\n[ \t]*)true', r'\1false'
    mutation = 'storageBlocked canRetry true to false'
else:
    start = text.index('    var needsRearmToDownload: Bool {')
    end = len(text)
    pattern, replacement = r'(case \.storageBlocked:\n(?:[ \t]*//[^\n]*\n)*[ \t]*)false', r'\1true'
    mutation = 'storageBlocked needsRearmToDownload false to true'
section, replacements = re.subn(pattern, replacement, text[start:end])
if replacements != 1:
    raise ValueError('Expected exactly one selected experimental storageBlocked branch')
mutated = (text[:start] + section + text[end:]).encode()
temp = Path(os.environ['RUNNER_TEMP'])
output = temp / ('attachment-storage-mutation' if args.case == 'retry' else 'attachment-storage-rearm-mutation')
output.mkdir(mode=0o700)
selector = 'whitenoise-macTests/AttachmentStorageAdmissionTests/storagePressureKeepsCheckpointRetryAndRemovalAvailable()'
command = ['bash', 'scripts/test-isolated.sh', '-only-testing:' + selector]
proof = {'app_sha': head, 'sdk_sha': os.environ['SOURCE_SHA'], 'sdk_run_id': os.environ['SDK_RUN_ID'],
         'sdk_profile': profile, 'private_flag': private_flag, 'workflow_tools_sha': os.environ['GITHUB_SHA'], 'source_path': str(source.relative_to(root)),
         'original_sha256': original_sha, 'mutant_sha256': hashlib.sha256(mutated).hexdigest(),
         'case': args.case, 'mutation': mutation, 'selector': selector,
         'command': command, 'runs': []}


def save():
    (output / 'result.json').write_text(json.dumps(proof, indent=2) + '\n')


def execute(name):
    bundle = output / (name + '.xcresult')
    environment = dict(os.environ, WN_EXPERIMENTAL_DEVICE_SYNC=private_flag, WN_TEST_JOBS='2',
                       WN_TEST_DERIVED_DATA=str(temp / 'final-mac-derived-data'),
                       WN_TEST_RESULT_BUNDLE=str(bundle))
    with (output / (name + '.log')).open('x') as log:
        result = subprocess.run(command, cwd=root, env=environment, stdout=log,
                                stderr=subprocess.STDOUT, timeout=1200)
    row = {'phase': name, 'exit_code': result.returncode, 'runtime_result_present': bundle.exists()}
    proof['runs'].append(row)
    save()
    # A compilation failure without an executed XCResult cannot kill a mutant.
    if not bundle.exists():
        raise ValueError('Mutation gate produced no native test result')
    summary = json.loads(subprocess.check_output(
        ['xcrun', 'xcresulttool', 'get', 'test-results', 'summary', '--path', str(bundle)], text=True))
    row['summary'] = summary
    save()
    return row


red_error = None
try:
    source.write_bytes(mutated)
    red = execute('mutant')
    summary = red['summary']
    if (red['exit_code'] == 0 or summary.get('totalTestCount') != 1
            or summary.get('failedTests') != 1 or summary.get('passedTests') != 0
            or summary.get('skippedTests') != 0):
        raise ValueError('The selected runtime regression did not kill the selected storage mutant')
    proof['runtime_red_confirmed'] = True
except (ValueError, subprocess.CalledProcessError) as error:
    # Still exercise restored source when a completed mutation attempt fails
    # qualification. Do not count compiler or empty-filter outcomes as RED.
    red_error = error
    proof['runtime_red_confirmed'] = False
    proof['mutation_attempt_error_category'] = type(error).__name__
finally:
    source.write_bytes(original)
    proof['source_restored'] = hashlib.sha256(source.read_bytes()).hexdigest() == original_sha
    save()
if not proof['source_restored']:
    raise ValueError('Original Mac source was not restored')
green = execute('restored-control')
summary = green['summary']
if (green['exit_code'] != 0 or summary.get('totalTestCount') != 1
        or summary.get('passedTests') != 1 or summary.get('failedTests') != 0
        or summary.get('skippedTests') != 0):
    raise ValueError('Restored Mac control did not pass exactly one runtime regression')
proof['restored_control_passed'] = True
proof['final_source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
save()
if proof['final_source_sha256'] != original_sha:
    raise ValueError('Mac source changed while running the restored control')
if red_error is not None:
    raise ValueError('Mutation attempt failed qualification; restored control passed') from red_error
proof['mutation_killed'] = True
save()
