#!/usr/bin/env python3
"""Remote-only unchanged enrollment fixtures; bounded, closed-schema evidence only."""
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time

from upstream_completion_ci import ORIGINALS, compile_cases, ensure, environment, identity, parse_body
from qualify_upstream_body_negative import feature_identity, freeze, layout

BASE = '0b50673c5b9e76266b50e660958bb8b24fe926e0'
SELF = 'scripts/qualify_upstream_enrollment_diagnostics.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
OUT = Path('enrollment-diagnostic-evidence')
PHASES = 'AwaitingSetup|AwaitingPeer|ComparisonAvailable|AwaitingPeerVerification|VerificationCompleteEnrollmentPending|Cancelled|Expired|Failed|EnrollmentComplete'
NUMBER = r'(?:0|[1-9][0-9]{0,18})'
BOOLEAN = r'(?:true|false)'
FAILURE = r'(?:Owner|Collection|Runtime|Engine|Genesis|Gate|PrivateInvite)'
STAGE = r'(?:BeforeCoreWrap|AfterCoreWrap|BeforeRelayPublication|AfterRelayPublication)'
REASON = r'(?:VerifierFallback|NoRound|GuardInvalid|NoSettledRoster|SharingPending|Complete)'

def option(pattern):
    return r'(?:None|Some\(' + pattern + r'\))'

def sequence(pattern, length, opening=r'\(', closing=r'\)'):
    return opening + ', '.join([pattern] * length) + closing

def array(length):
    return sequence(NUMBER, length, r'\[', r'\]')

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
PREFIX = 'automatic-enrollment-control '
PHASE_LINE = r'automatic pairing did not reach required phase: expected=(' + PHASES + r') observed=(None|Some\((' + PHASES + '), (' + PHASES + r')\))'


def diagnostics(raw):
    ensure(len(raw.encode()) <= 8 * 1024 * 1024, 'bounded-runtime-output')
    # No raw log/panic strings survive this function. Even diagnostic values
    # must match their complete closed tuple schema, without quoted strings.
    rows = []
    stages = []
    phase_rows = []
    seen = set()
    for line in raw.splitlines():
        if line.startswith(PREFIX):
            payload = line[len(PREFIX):]
            ensure(len(payload) <= 4096, 'bounded-diagnostic-line')
            if payload.startswith('stage='):
                stage = payload[6:]
                ensure(stage in STAGES and len(stages) < 16, 'known-bounded-stage')
                stages.append(stage)
                continue
            matched = False
            for category, pattern in SCHEMAS:
                match = re.fullmatch(pattern, payload)
                if not match:
                    continue
                key = (category, match[1])
                ensure(key not in seen and len(rows) < 8, 'unique-bounded-aggregate')
                seen.add(key)
                # Bit flags are the FIRST field; visits and failures follow.
                if category in {'child_channels', 'existing_child'}:
                    flags = re.findall(r'\((' + NUMBER + '), ' + NUMBER + ', ' + NUMBER + r', (?:None|Some\(' + FAILURE + r'\)),', payload)
                    ensure(all(int(value) <= 255 for value in flags), 'known-channel-bitmask')
                rows.append({'category': category, 'side_or_existing_index': match[1], 'closed_schema_values': list(match.groups()[1:])})
                matched = True
                break
            ensure(matched, 'unknown-aggregate-schema')
        elif line.startswith('automatic pairing did not reach required phase:'):
            match = re.fullmatch(PHASE_LINE, line)
            ensure(match is not None and not phase_rows, 'known-unique-phase-schema')
            phase_rows.append({'expected': match[1], 'observed_missing': match[2] == 'None', 'left': match[3], 'right': match[4]})
        elif re.match(r'(?:left|right) expected=', line):
            match = re.fullmatch(r'(left|right) expected=(' + PHASES + r') observed=(' + PHASES + r')', line)
            ensure(match is not None and not phase_rows, 'known-unique-terminal-phase-schema')
            phase_rows.append({'side': match[1], 'expected': match[2], 'observed': match[3]})
    return {'aggregates': rows, 'stages': stages, 'phase_failures': phase_rows, 'missing_diagnostics': not rows}


def parser_controls():
    aggregate = PREFIX + 'side=left primary/expected/children/completed=Some((true, Some(2), 2, 0)) intake=Some([0, 1, 2, 3, 4, 5, 6, 7]) rejections=None context_rejections=None projection=None'
    channel = PREFIX + 'side=right child_channels=Some([(255, 2, 1, Some(Genesis), Some(AfterRelayPublication))])'
    rpc = PREFIX + 'side=left native_rpc_counts/elapsed_ms/branch=Some(([1, 2, 3, 4, 5, 6], [0, 0, 1, 2, 3, 4], Some((SharingPending, 12))))'
    existing = PREFIX + 'existing_index=1 child_channel=None'
    phase = 'automatic pairing did not reach required phase: expected=EnrollmentComplete observed=Some((VerificationCompleteEnrollmentPending, AwaitingPeerVerification))'
    positives = [aggregate, channel, rpc, existing, phase, 'left expected=EnrollmentComplete observed=Failed', 'private runtime output must be discarded']
    for value in positives:
        diagnostics(value)
    negatives = [aggregate + ' private', aggregate.replace('side=left', 'side=secret'), aggregate.replace('Some(2)', 'Some(-2)'), aggregate.replace('Some(2)', 'Some(12345678901234567890)'), aggregate.replace('true', 'secret'), channel.replace('255', '256'), channel.replace('Genesis', 'Unknown'), channel.replace('AfterRelayPublication', 'Unknown'), rpc.replace('SharingPending', 'Unknown'), existing.replace('index=1', 'index=2'), phase.replace('AwaitingPeerVerification', 'Unknown'), 'left expected=EnrollmentComplete observed=secret', phase + '\n' + phase, aggregate + '\n' + aggregate, PREFIX + 'private=secret', PREFIX + 'x' * 4097, PREFIX + 'stage=unknown', PREFIX + 'stage=third-device-completion\n' + '\n'.join([PREFIX + 'stage=third-device-completion'] * 16), channel.replace('(255, 2, 1', '("secret", 2, 1')]
    for value in negatives:
        try:
            diagnostics(value)
        except ValueError:
            continue
        raise ValueError('adversarial-parser-control-accepted')
    ensure(diagnostics(phase)['phase_failures'][0]['left'] == 'VerificationCompleteEnrollmentPending', 'phase-projection')
    ensure(not diagnostics('private runtime output')['aggregates'], 'unrelated-raw-output-discarded')
    return {'positive_controls': len(positives), 'negative_controls': len(negatives), 'passed': True}


def source_guard():
    ensure(os.environ.get('UPSTREAM_EXTRACTION_COHORT_BASELINE') == BASE, 'explicit-reviewed-source-cohort')
    ensure(subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, 'HEAD']).returncode == 0, 'reviewed-baseline-ancestor')
    changed = set(subprocess.check_output(['git', 'diff', '--name-only', BASE, 'HEAD'], text=True).splitlines())
    ensure(changed <= {SELF, WORKFLOW}, 'diagnostic-only-source-delta')
    workflow = Path(WORKFLOW).read_text()
    start = '  # ENROLLMENT_DIAGNOSTIC_JOB_BEGIN\n'
    end = '  # ENROLLMENT_DIAGNOSTIC_JOB_END\n'
    ensure(workflow.count(start) == workflow.count(end) == 1, 'unique-isolated-diagnostic-job')
    before, job = workflow.split(start)
    _, after = job.split(end)
    restored = (before + after).replace('options: [enrollment-diagnostics, ', 'options: [', 1)
    ensure(restored.encode() == subprocess.check_output(['git', 'show', BASE + ':' + WORKFLOW]), 'existing-workflow-scopes-unchanged')
    ensure(not subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).strip(), 'no-untracked-source-inputs')
    return {'baseline': BASE, 'changed_paths': sorted(changed), 'unchanged_product_tests_oracles_deadlines': True}


def execute(case, suffix):
    started = time.monotonic()
    command = [case['binary'], '--exact', case['name'], '--nocapture', '--test-threads=1']
    row = {'test': case['name'], 'binary_sha256': case['binary_sha256'], 'watchdog_triggered': False, 'output_limit_triggered': False}
    data = bytearray()
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() - started >= 300:
                    row['watchdog_triggered'] = True
                    process.kill()
                    break
                for key, _ in selector.select(timeout=0.25):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if len(data) + len(chunk) > 8 * 1024 * 1024:
                        row['output_limit_triggered'] = True
                        process.kill()
                        break
                    data.extend(chunk)
                if row['output_limit_triggered']:
                    break
        process.wait(timeout=10)
        row['body_exit_code'] = process.returncode
    raw = data.decode('utf-8', errors='replace')
    counts = parse_body(raw, suffix)
    # Export only counts, never arbitrary parsed panic paths/stage strings.
    row.update({key: counts[key] for key in ['passed', 'failed', 'ignored', 'executed_nonignored', 'all_panic_header_count'] if key in counts})
    try:
        row.update(diagnostics(raw))
        row['diagnostic_parser_passed'] = True
    except ValueError:
        row['diagnostic_parser_passed'] = False
        row['diagnostic_parser_error'] = 'ClosedSchemaRejected'

    row['body_seconds'] = time.monotonic() - started
    row['runtime_completed'] = row['diagnostic_parser_passed'] and not row['watchdog_triggered'] and not row['output_limit_triggered'] and row.get('executed_nonignored') == 1 and row.get('ignored') == 0
    row['test_passed'] = row['runtime_completed'] and row['body_exit_code'] == 0 and row.get('passed') == 1 and row.get('failed') == 0
    return row


def main(preflight):
    OUT.mkdir(exist_ok=True)
    report = {'qualification_passed': False, 'diagnostic_only': True, 'baseline_test_source': BASE, 'cases': [], 'automatic_retries': 0}
    original = freeze()
    original_layout = layout()
    try:
        report.update(environment())
        report['baseline_test_source'] = BASE
        report['source_guard'] = source_guard()
        report['aggregate_field_order'] = {
            'completion': ['primary', 'expected_optional', 'children', 'completed'],
            'child_channel': ['channel_bits', 'visits', 'failures', 'failure_optional', 'stage_optional'],
            'native_rpc': ['DispatchStarted', 'WorkerStarted', 'WorkerReturned', 'FacadeReturned', 'AutomaticEntered', 'AutomaticExited'],
            'channel_bits_low_to_high': ['original_live', 'state_live', 'ready', 'handshake_published', 'policy_committed', 'proof_published', 'peer_committed', 'complete'],
        }
        report['parser_controls'] = parser_controls()
        report['source_before_sha256'] = identity(original)
        if preflight:
            report['preflight_passed'] = True
            return
        compilation, cases = compile_cases(ORIGINALS)
        report['compilation'] = compilation
        ensure(set(cases) == set(ORIGINALS), 'exact-three-original-inventory')
        report['compiled_feature_identity'] = feature_identity(compilation)
        for suffix in ORIGINALS:
            ensure(freeze() == original and layout() == original_layout, 'unchanged-inputs-before-body')
            report['cases'].append(execute(cases[suffix], suffix))
        report['actual_executed'] = sum(row.get('executed_nonignored', 0) for row in report['cases'])
        report['diagnostic_execution_completed'] = all(row['runtime_completed'] for row in report['cases'])
        report['all_three_originals_passed'] = all(row['test_passed'] for row in report['cases'])
        ensure(report['diagnostic_execution_completed'], 'incomplete-diagnostic-execution')
        ensure(report['all_three_originals_passed'], 'original-enrollment-failures-preserved')
    except Exception as error:
        # Exception text may contain private runtime data; emit class only.
        report['exception_type'] = type(error).__name__
        raise
    finally:
        pristine = freeze() == original and layout() == original_layout
        report['inputs_pristine'] = pristine
        report['source_after_sha256'] = identity(freeze())
        (OUT / ('preflight.json' if preflight else 'result.json')).write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        ensure(pristine, 'source-inputs-changed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--preflight', action='store_true')
    args = parser.parse_args()
    main(args.preflight)
