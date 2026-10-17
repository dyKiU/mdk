#!/usr/bin/env python3
"""One unchanged ordinary enrollment failure, passive closed observations only."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import qualify_upstream_storage_boundary as bounded
from upstream_completion_ci import ORIGINALS, FILE, compile_cases, digest, ensure, environment, parse_body
from qualify_upstream_body_negative import feature_identity
from upstream_extraction_cohort import frozen_inputs

BASE = '50c2df29223b94963597325a1572eba4cf8492ae'
SELF = 'scripts/diagnose_upstream_recipient_intake.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
PRODUCT = 'crates/marmot-app/src/client/device_linking/sibling_sharing.rs'
PROBE = 'crates/marmot-app/src/client/device_linking/sibling_sharing/intake_trace.rs'
OUT = Path('recipient-intake-diagnostic-evidence')
CASE = ORIGINALS[0]
NAME = 'native_device_linking::automatic_pairing_acceptance::' + CASE
EVENTS = ['ExpectedCaptured', 'PrimaryCommitted', 'RetainedBeforePrimary', 'RetainedAfterPrimary',
          'RetainedPrimaryUnknown', 'RetryEntry', 'RetryAttempt', 'RetryAuthenticated', 'RetryAuthenticationFailed',
          'RetryDispatched', 'RetryDispatchFailed', 'RequestAdmitted', 'WakeSent', 'CompletionEntered',
          'CompletionReturned', 'ConsentAttempted', 'ConsentStarted', 'ConsentDeferred', 'ConsentDeniedGate',
          'ConsentDeniedEngine', 'ConsentDeniedOwner', 'ConsentDeniedRuntime', 'ConsentDeniedOther']
PHASES = 'AwaitingSetup|AwaitingPeer|ComparisonAvailable|AwaitingPeerVerification|VerificationCompleteEnrollmentPending|Cancelled|Expired|Failed|EnrollmentComplete'
NUMBER = r'(?:0|[1-9][0-9]{0,9})'
BOOLEAN = r'(?:true|false)'
FAILURE = r'(?:Owner|Collection|Runtime|Engine|Genesis|Gate|PrivateInvite)'
STAGE = r'(?:BeforeCoreWrap|AfterCoreWrap|BeforeRelayPublication|AfterRelayPublication)'
REASON = r'(?:VerifierFallback|NoRound|GuardInvalid|NoSettledRoster|SharingPending|Complete)'
def option(pattern): return r'(?:None|Some\(' + pattern + r'\))'
def array(length): return r'\[' + ', '.join([NUMBER] * length) + r'\]'
CHANNEL = r'\(' + ', '.join([NUMBER] * 3 + [option(FAILURE), option(STAGE)]) + r'\)'
CHILDREN = option(r'\[(?:' + CHANNEL + r'(?:, ' + CHANNEL + r'){0,7})?\]')
AGGREGATES = option(r'\(' + BOOLEAN + ', ' + option(NUMBER) + ', ' + NUMBER + ', ' + NUMBER + r'\)')
RPC = option(r'\(' + array(6) + ', ' + array(6) + ', ' + option(r'\(' + REASON + ', ' + NUMBER + r'\)') + r'\)')
SCHEMAS = [
    ('aggregates', r'side=(left|right) primary/expected/children/completed=(' + AGGREGATES + ') intake=(' + option(array(8)) + ') rejections=(' + option(array(4)) + ') context_rejections=(' + option(array(9)) + ') projection=(' + option(array(4)) + ')'),
    ('child_channels', r'side=(left|right) child_channels=(' + CHILDREN + ')'),
    ('native_rpc', r'side=(left|right) native_rpc_counts/elapsed_ms/branch=(' + RPC + ')'),
    ('existing_child', r'existing_index=([01]) child_channel=(' + option(CHANNEL) + ')'),
]
STAGES = {'initial-two-comparison', 'initial-two-completion', 'initial-two-completed', 'third-device-comparison', 'third-device-completion', 'third-device-completed', 'fourth-device-comparison', 'fourth-device-completion', 'fourth-device-completed', 'sibling-consent-held-before-peer-progress', 'automatic-publication-held-before-completion'}


def git(*args): return subprocess.check_output(['git', *args], text=True).strip()


def source_guard():
    head = git('rev-parse', 'HEAD')
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and os.environ.get('GITHUB_SHA') == head
           and os.environ.get('GITHUB_REF', '').startswith('refs/heads/ci/upstream-recipient-intake-diagnostic-')
           and os.environ.get('UPSTREAM_RECIPIENT_INTAKE_BASELINE') == BASE, 'exact-owned-reviewed-diagnostic-cohort')
    ensure(os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + os.environ['GITHUB_REF'], 'owned-existing-workflow-identity')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, head], check=True)
    ensure(not git('diff', 'HEAD', '--name-only'), 'pristine-tracked-source')
    changed = set(git('diff', '--name-only', BASE, head).splitlines())
    ensure(changed <= {SELF, WORKFLOW, PRODUCT, PROBE}, 'only-reviewed-passive-module-hooks-and-metadata')
    frozen = frozen_inputs()
    ensure(all(row['actual_executable'] == (row['mode'] == '100755') for row in frozen.values() if row['mode'] != '120000'), 'all-source-executable-modes-exact')
    ensure(all(frozen[name]['mode'] == '100644' and not frozen[name]['actual_executable'] for name in changed), 'ordinary-diagnostic-overlay-modes')
    for name in git('ls-files', '--others', '--exclude-standard').splitlines():
        ensure(name.startswith('recipient-intake-diagnostic-evidence/'), 'no-untracked-source-overlay')
    source = Path(PRODUCT).read_text()
    pattern = r'^[ \t]*// INTAKE_TRACE_BEGIN\n.*?^[ \t]*// INTAKE_TRACE_END\n'
    blocks = re.findall(pattern, source, re.M | re.S)
    ensure(len(blocks) == 18 and source.count('INTAKE_TRACE_BEGIN') == source.count('INTAKE_TRACE_END') == 18, 'exact-eighteen-passive-hook-blocks')
    ensure(re.sub(pattern, '', source, flags=re.M | re.S).encode() == subprocess.check_output(['git', 'show', BASE + ':' + PRODUCT]), 'exact-original-af330-product-after-observation-stripping')
    workflow = Path(WORKFLOW).read_text()
    begin, end = '  # RECIPIENT_INTAKE_DIAGNOSTIC_BEGIN\n', '  # RECIPIENT_INTAKE_DIAGNOSTIC_END\n'
    ensure(workflow.count(begin) == workflow.count(end) == 1, 'one-isolated-diagnostic-workflow-union')
    before, rest = workflow.split(begin); _, after = rest.split(end)
    restored = (before + after).replace('options: [recipient-intake-preflight, recipient-intake-diagnostic, ', 'options: [', 1)
    ensure(restored.encode() == subprocess.check_output(['git', 'show', BASE + ':' + WORKFLOW]), 'all-eight-green-gates-and-historical-workflow-inputs-unchanged')
    ensure(os.environ.get('CARGO_BUILD_JOBS') == '2', 'bounded-build-cohort')
    return {'source': head, 'baseline': BASE, 'baseline_tree': git('rev-parse', BASE + '^{tree}'),
            'whole_original_product_after_hook_stripping': True, 'historical_fixtures_controllers_and_deadlines_unchanged': True,
            'af330_admission_fix_unchanged': True, 'overlay': sorted(changed),
            'probe_sha256': digest(Path(PROBE).read_bytes()), 'hook_blocks_sha256': digest(''.join(blocks).encode()),
            'input_manifest_sha256': digest(json.dumps(frozen, sort_keys=True).encode()), 'historical_evidence_reused': False}


def diagnostics(raw):
    ensure(len(raw.encode()) <= 16 * 1024 * 1024, 'bounded-raw-observation')
    original, trace, stages, phases, seen = [], [], [], [], set()
    for line in raw.splitlines():
        if line.startswith('ordinary-recipient-intake '):
            match = re.fullmatch('ordinary-recipient-intake role=(recipient|sponsor|other) seq=(' + NUMBER + ') counts=(' + array(23) + ') first=(' + array(23) + ') last=(' + array(23) + ') unknown=(' + BOOLEAN + ')', line)
            ensure(match is not None and match[1] not in {row['role'] for row in trace}, 'unique-closed-intake-trace')
            seq = int(match[2]); counts, first, last = [json.loads(match[index]) for index in [3, 4, 5]]
            ensure(seq <= 1_000_000_000 and all(value <= 1_000_000_000 for values in [counts, first, last] for value in values), 'bounded-trace-numbers')
            ensure(sum(counts) == seq and all((count == start == stop == 0) or (0 < start <= stop <= seq and 0 < count <= stop - start + 1) for count, start, stop in zip(counts, first, last)), 'trace-counter-sequence-consistency')
            trace.append({'role': match[1], 'sequence': seq, 'counts': counts, 'first': first, 'last': last, 'unknown': match[6] == 'true'})
        elif line.startswith('automatic-enrollment-control '):
            payload = line.removeprefix('automatic-enrollment-control ')
            ensure(len(payload) <= 4096, 'bounded-original-failure-dump-line')
            if payload.startswith('stage='):
                value = payload.removeprefix('stage='); ensure(value in STAGES and len(stages) < 16, 'closed-original-stage'); stages.append(value); continue
            matched = False
            for category, pattern in SCHEMAS:
                match = re.fullmatch(pattern, payload)
                if match:
                    key = category, match[1]
                    ensure(key not in seen and len(original) < 8 and all(int(number) <= 1_000_000_000 for number in re.findall('[0-9]+', payload)), 'bounded-unique-original-failure-inventory')
                    seen.add(key)
                    if category in {'child_channels', 'existing_child'}:
                        flags = re.findall(r'\((' + NUMBER + '), ' + NUMBER + ', ' + NUMBER + r', (?:None|Some\(' + FAILURE + r'\)),', payload)
                        ensure(all(int(value) <= 255 for value in flags), 'closed-original-channel-bitmask')
                    original.append({'category': category, 'side_or_index': match[1], 'closed_schema_values': list(match.groups()[1:])})
                    matched = True; break
            ensure(matched, 'unknown-original-failure-output-schema')
        elif line.startswith('automatic pairing did not reach required phase:'):
            match = re.fullmatch('automatic pairing did not reach required phase: expected=(' + PHASES + ') observed=(None|Some\\(\\((' + PHASES + '), (' + PHASES + ')\\)\\))', line)
            ensure(match is not None and not phases, 'closed-original-phase-panic')
            phases.append({'expected': match[1], 'missing': match[2] == 'None', 'left': match[3], 'right': match[4]})
    expected = {(category, side) for category in ['aggregates', 'child_channels', 'native_rpc'] for side in ['left', 'right']} | {('existing_child', '0'), ('existing_child', '1')}
    return {'original_failure_dump': original, 'original_failure_inventory_complete': seen == expected,
            'original_stages': stages, 'original_phase': phases, 'traces': trace,
            'trace_inventory_complete': {row['role'] for row in trace} == {'recipient', 'sponsor'},
            'trace_values_known': len(trace) == 2 and all(not row['unknown'] for row in trace), 'event_order': EVENTS,
            'intake_index4_is_reserved_not_an_admission_counter': True}


def parser_preflight():
    empty = '[' + ', '.join(['0'] * 23) + ']'
    raw = 'ordinary-recipient-intake role=recipient seq=0 counts=' + empty + ' first=' + empty + ' last=' + empty + ' unknown=false\n'
    ensure(diagnostics(raw)['traces'][0]['unknown'] is False, 'known-empty-typed-trace-positive')
    ensure(diagnostics(raw.replace('unknown=false', 'unknown=true'))['traces'][0]['unknown'] is True, 'poison-or-contention-remains-unknown-not-zero')
    negatives = [raw + raw, raw.replace('recipient', 'PRIVATE_ACCOUNT', 1), raw.replace('seq=0', 'seq=1000000001'),
                 raw.replace('seq=0', 'seq="PRIVATE_ACCOUNT"'), raw.replace('unknown=false', 'unknown=maybe'),
                 raw.replace('[0, ', '[', 1), raw.replace('unknown=false', 'unknown=false extra=PRIVATE_ACCOUNT'),
                 raw.replace('first=[0', 'first=[1', 1)]
    for value in negatives:
        try: diagnostics(value)
        except ValueError: continue
        raise ValueError('malformed-private-or-inconsistent-trace-was-accepted')
    return {'positive': 2, 'negative': len(negatives), 'actual_runtime_bodies': 0}


def main(preflight):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'qualification_passed': False, 'whole_eight_green_prerequisite_waived': False,
              'diagnostic_evidence_complete': False, 'product_test_green_claim': False,
              'native_close_counts': 'unknown-original-fixture-does-not-emit-them',
              'consent_error_categories_cover': 'completion-watch-first-shot-only',
              'periodic_consent_error_categories_available': False}
    frozen = frozen_inputs()
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['source_guard'] = source_guard(); report['environment'] = environment()
        report['parser_controls'] = parser_preflight(); save()
        if preflight: report['preflight_passed'] = True; return
        compilation, cases = compile_cases([CASE])
        report['compilation'] = {key: value for key, value in compilation.items() if key not in {'compiler_headers'}}; save()
        ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints', {}).get('verified') is True
               and set(cases) == {CASE} and cases[CASE]['name'] == NAME, 'actual-one-compiled-nonignored-original-case')
        report['compiler_error_count'] = compilation['compiler_error_count']
        report['compiled_feature_identity'] = feature_identity(compilation)
        case = cases[CASE]; binary = Path(case['binary'])
        ensure(frozen_inputs() == frozen and digest(binary.read_bytes()) == case['binary_sha256'], 'exact-source-and-selected-binary-before-runtime')
        # Restore the process environment even on bounded capture errors.
        previous = os.environ.get('MDK_UPSTREAM_RECIPIENT_INTAKE_TRACE')
        os.environ['MDK_UPSTREAM_RECIPIENT_INTAKE_TRACE'] = '1'
        try: code, raw, seconds = bounded.capture([str(binary), '--exact', NAME, '--nocapture', '--test-threads=1'], 300)
        finally:
            if previous is None: os.environ.pop('MDK_UPSTREAM_RECIPIENT_INTAKE_TRACE', None)
            else: os.environ['MDK_UPSTREAM_RECIPIENT_INTAKE_TRACE'] = previous
        parsed = parse_body(raw, CASE)
        report['body'] = {key: parsed.get(key) for key in ['passed', 'failed', 'ignored', 'executed_nonignored', 'all_panic_header_count', 'original_phase_markers']}
        report['body'].update(exit_code=code, seconds=seconds, binary_sha256=case['binary_sha256'], compiler_error_count=compilation['compiler_error_count'])
        report['body']['executed_case_names'] = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. ', raw, re.M)
        report['observations'] = diagnostics(raw)
        ensure(frozen_inputs() == frozen and digest(binary.read_bytes()) == case['binary_sha256'], 'actual-runtime-source-and-binary-unchanged')
        ensure(all(type(report['body'].get(key)) is int for key in ['passed', 'failed', 'ignored', 'executed_nonignored', 'all_panic_header_count'])
               and parsed['passed'] + parsed['failed'] == parsed['executed_nonignored'] == 1 and parsed['ignored'] == 0
               and report['body']['executed_case_names'] == [NAME], 'one-actual-nonignored-original-body')
        report['actual_counts_complete'] = True
        report['original_case_passed'] = code == 0 and parsed['passed'] == 1 and parsed['failed'] == parsed['all_panic_header_count'] == 0
        anchor = 'panic!("automatic pairing did not reach required phase: expected={phase:?} observed={observed:?}")'
        original = Path(FILE).read_text(); ensure(original.count(anchor) == 1, 'original-phase-assertion-unchanged')
        line = original[:original.index(anchor)].count('\n') + 1
        header = r"^thread '" + re.escape(NAME) + r"'(?: \([0-9]+\))? panicked at " + re.escape(FILE) + ':' + str(line) + r':[0-9]+:\n'
        observed = report['observations']
        report['diagnostic_evidence_complete'] = (code == 101 and parsed['failed'] == parsed['all_panic_header_count'] == 1
            and len(re.findall(header, raw, re.M)) == 1 and observed['original_failure_inventory_complete']
            and observed['trace_inventory_complete'] and observed['trace_values_known']
            and observed['original_phase'] == [{'expected': 'EnrollmentComplete', 'missing': False,
                                                'left': 'EnrollmentComplete', 'right': 'VerificationCompleteEnrollmentPending'}])
        # A known original failure can complete diagnosis; never call it GREEN.
        ensure(report['diagnostic_evidence_complete'], 'original-failure-diagnostic-incomplete-or-different-outcome')
    except Exception as error:
        report['failure_type'] = type(error).__name__; raise
    finally:
        report['inputs_pristine'] = frozen_inputs() == frozen
        save(); ensure(report['inputs_pristine'], 'diagnostic-inputs-not-pristine')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--preflight', action='store_true')
    main(parser.parse_args().preflight)
