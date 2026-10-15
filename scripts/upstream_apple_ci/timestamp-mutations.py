#!/usr/bin/env python3
"""Detect literal timestamp fallback regressions through actual iOS test execution."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

root = Path('ios').resolve(strict=True)
head = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
if head != os.environ['IOS_SHA']:
    raise ValueError('Timestamp mutation source differs from the pinned iOS candidate')
temp = Path(os.environ['RUNNER_TEMP'])
output = temp / 'ios-timestamp-mutations'
output.mkdir(mode=0o700)
definitions = [
    ('display-literal-fallback', 'whitenoise-ios/Conversation/MarkdownMessageModel.swift',
     'emitted = appendTimestamp(unixSeconds, style: style, to: &out, context: context, budget: &budget) || emitted',
     'emitted = append(MarkdownTimestampFormatter.literalToken(unixSeconds: unixSeconds, style: style), to: &out, context: context, budget: &budget) || emitted',
     'whitenoise-iosTests/MarkdownTimestampTests/displayRunIsSubtlyStyledAndCarriesItsSpokenInstant()'),
    ('preview-literal-fallback', 'whitenoise-ios/Core/MarkdownPlainText.swift',
     'state.append(MarkdownTimestampFormatter.staticText(unixSeconds: unixSeconds, style: style))',
     'state.append(MarkdownTimestampFormatter.literalToken(unixSeconds: unixSeconds, style: style))',
     'whitenoise-iosTests/MarkdownTimestampTests/plainTextPreviewsNeverShowRelativePhrases()'),
]
proof = {'app_sha': head, 'sdk_sha': os.environ['SOURCE_SHA'],
         'sdk_run_id': os.environ['SDK_RUN_ID'], 'workflow_tools_sha': os.environ['GITHUB_SHA'],
         'expected_mutants': len(definitions), 'mutants': []}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save():
    (output / 'result.json').write_text(json.dumps(proof, indent=2) + '\n')


def execute(record, phase):
    bundle = output / (record['name'] + '-' + phase + '.xcresult')
    environment = dict(os.environ, WN_EXPERIMENTAL_DEVICE_SYNC='1', WN_TEST_JOBS='2',
                       WN_TEST_DERIVED_DATA=str(temp / 'final-ios-derived-data'),
                       WN_TEST_SOURCE_PACKAGES=str(temp / 'final-ios-packages'),
                       WN_TEST_RELAY_BINARY=str(root / 'build/TestRelay/debug/white-noise-sync-test-relay'),
                       WN_TEST_RESULT_BUNDLE=str(bundle))
    # The supported runner rebuilds changed Swift before the exact selected
    # runtime test; test-without-building alone would exercise stale binaries.
    command = ['bash', 'scripts/test-with-relay.sh', '-only-testing:' + record['selector']]
    row = {'phase': phase, 'command': command}
    record['runs'].append(row)
    save()
    with (output / (record['name'] + '-' + phase + '.log')).open('x') as log:
        result = subprocess.run(command, cwd=root, env=environment, stdout=log,
                                stderr=subprocess.STDOUT, timeout=1200)
    row.update(exit_code=result.returncode, runtime_result_present=bundle.exists())
    save()
    if not bundle.exists():
        raise ValueError('No executed native result; compilation failure is not behavioral RED')
    summary = json.loads(subprocess.check_output(
        ['xcrun', 'xcresulttool', 'get', 'test-results', 'summary', '--path', str(bundle)], text=True))
    fields = ('totalTestCount', 'passedTests', 'failedTests', 'skippedTests')
    if any(type(summary.get(key)) is not int or summary[key] < 0 for key in fields):
        raise ValueError('Missing or invalid native execution counts')
    row['summary'] = {key: summary[key] for key in ('result',) + fields if key in summary}
    row['green'] = (result.returncode == 0 and summary['totalTestCount'] == 1
                    and summary['passedTests'] == 1 and summary['failedTests'] == 0
                    and summary['skippedTests'] == 0)
    row['behavioral_red'] = (result.returncode != 0 and summary['totalTestCount'] == 1
                             and summary['passedTests'] == 0 and summary['failedTests'] == 1
                             and summary['skippedTests'] == 0)
    save()
    return row


save()
for name, relative, old, new, selector in definitions:
    source = root / relative
    original = source.read_bytes()
    committed = subprocess.check_output(['git', '-C', str(root), 'show', head + ':' + relative])
    if original != committed:
        raise ValueError('Timestamp source differs from the pinned committed bytes')
    text = original.decode()
    if text.count(old) != 1:
        raise ValueError('Expected one reviewed timestamp rendering branch')
    mutant = text.replace(old, new, 1).encode()
    record = {'name': name, 'source': relative, 'selector': selector,
              'original_sha256': digest(original), 'mutant_sha256': digest(mutant),
              'original_matches_git': True, 'runs': []}
    proof['mutants'].append(record)
    save()
    baseline = execute(record, 'baseline')
    if not baseline['green']:
        raise ValueError('Timestamp baseline did not execute exactly one passing runtime test')
    try:
        source.write_bytes(mutant)
        red = execute(record, 'mutant')
        record['runtime_red_confirmed'] = red['behavioral_red']
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        record['runtime_red_confirmed'] = False
        record['mutation_attempt_error_category'] = type(error).__name__
    finally:
        source.write_bytes(original)
        record['source_restored'] = source.read_bytes() == original
        save()
    if not record['source_restored']:
        raise ValueError('Exact timestamp source restoration failed')
    control = execute(record, 'restored-control')
    record['restored_control_passed'] = control['green']
    record['final_source_sha256'] = digest(source.read_bytes())
    record['mutation_killed'] = (record['runtime_red_confirmed'] and control['green']
                                 and record['final_source_sha256'] == record['original_sha256'])
    save()
    if not control['green'] or record['final_source_sha256'] != record['original_sha256']:
        raise ValueError('Restored timestamp source/control did not qualify')
proof['killed_mutants'] = sum(row.get('mutation_killed') is True for row in proof['mutants'])
proof['all_controls_passed'] = all(row.get('restored_control_passed') is True for row in proof['mutants'])
save()
if proof['killed_mutants'] != len(definitions) or not proof['all_controls_passed']:
    raise SystemExit('Not every timestamp mutant was detected with a passing restored control')
