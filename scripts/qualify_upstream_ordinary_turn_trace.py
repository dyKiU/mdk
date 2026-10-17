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

from upstream_completion_ci import ORIGINALS, compile_cases, digest, ensure, environment, identity, parse_body
from qualify_upstream_body_negative import feature_identity, freeze, layout

BASE = 'a302c2194c777bef87ae48aff51a8bc570cbc588'
SELF = 'scripts/qualify_upstream_ordinary_turn_trace.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
OUT = Path('ordinary-turn-trace-evidence')
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
CASE = ORIGINALS[0]
TURN_STAGES = 'WorkerLoop|BeforeSelect|Enter|OpaqueStart|OpaqueDone|PendingStart|PendingDone|BeginStart|BeginDone|LoopStart|AdvanceStart|AdvanceEnd|Return|ChildAdded'
TURN_COUNTS = array(14)
TURN_TIMES = sequence(option(NUMBER), 14, r'\[', r'\]')
TURN_INDEX = r'(?:[0-9]|[1-9][0-9]|1[01][0-9]|12[0-7])'
TURN_POINT = option(r'\((' + TURN_STAGES + '), ' + option(TURN_INDEX) + ', ' + NUMBER + r'\)')
TURN_RETURN = option(r'\((' + TURN_STAGES + '), ' + NUMBER + r'\)')
TURN_DUE = option(sequence(BOOLEAN, 3, r'\[', r'\]'))
TURN_LINE = r'ordinary-sibling-turn side=(left|right) trace=(\(' + ', '.join([TURN_COUNTS, TURN_TIMES, TURN_POINT, TURN_RETURN, TURN_DUE, BOOLEAN, NUMBER]) + r'\))'
TIMER_LINE = r'ordinary-sibling-timer side=(left|right) timer=(\(' + ', '.join([array(3), sequence(option(NUMBER), 3, r'\[', r'\]'), option(r'\(' + BOOLEAN + ', ' + NUMBER + r'\)'), option(BOOLEAN), option(sequence(BOOLEAN, 2, r'\[', r'\]')), array(2), array(2), NUMBER, option(BOOLEAN)]) + r'\))'
SIBLING = 'crates/marmot-app/src/client/device_linking/sibling_sharing.rs'
PROBE = 'crates/marmot-app/src/client/device_linking/sibling_sharing/turn_probe.rs'
PROOF_PROBE = 'crates/cgka-engine/src/ordinary_proof_cost.rs'
HOOKS = {SIBLING: 13, 'crates/marmot-app/src/client/device_linking/sibling_sharing/tests.rs': 1, 'crates/marmot-app/src/runtime/account_worker.rs': 3,
         'crates/marmot-app/src/native_device_linking/enabled.rs': 1,
         'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs': 4,
         'crates/cgka-engine/src/lib.rs': 1,
         'crates/cgka-engine/src/account_identity_proof.rs': 1,
         'crates/cgka-engine/src/private_roster_settlement.rs': 1}

PHASE_LINE = r'automatic pairing did not reach required phase: expected=(' + PHASES + r') observed=(None|Some\(\((' + PHASES + '), (' + PHASES + r')\)\))'


def proof_cost_diagnostics(raw):
    snapshots = []
    for line in raw.splitlines():
        if not line.startswith('ordinary-proof-cost '):
            continue
        match = re.fullmatch(r'ordinary-proof-cost values=(' + array(14) + ')', line)
        ensure(match is not None and len(line) <= 512, 'closed-proof-cost-numeric-array')
        values = json.loads(match[1])
        ensure(all(type(value) is int and 0 <= value <= 1_000_000_000_000_000_000 for value in values), 'bounded-proof-cost-integers')
        ensure(values[0] in {0, 1, 2} and values[2] in {0, 1} and values[3] in {0, 1}, 'known-proof-cost-stage-and-validity')
        ensure(len(snapshots) < 2 and values[0] not in {row[0] for row in snapshots}, 'unique-bounded-proof-cost-snapshots')
        if values[2] and not values[3]:
            for offset in [4, 9]:
                entered, completed, total, maximum, inflight = values[offset:offset + 5]
                ensure(completed <= entered and inflight == entered - completed and maximum <= total
                       and (completed > 0 or total == maximum == 0), 'consistent-cumulative-proof-cost-counters')
        snapshots.append(values)
    ensure(len(snapshots) < 2 or (snapshots[0][0] == 0 and snapshots[1][0] in {1, 2}), 'proof-cost-start-precedes-end')
    complete = len(snapshots) == 2
    known = complete and snapshots[1][0] == 1 and all(row[2] == 1 and row[3] == 0 for row in snapshots)
    result = {'numeric_snapshots': snapshots, 'snapshot_pair_complete': complete,
              'missing_start': not snapshots or snapshots[0][0] != 0,
              'missing_end': not snapshots or snapshots[-1][0] == 0,
              'normal_end_marker': complete and snapshots[1][0] == 1,
              'measurement_known': known, 'window_elapsed_ns': None, 'spans': []}
    if known:
        start, end = snapshots
        ensure(end[1] >= start[1], 'monotonic-proof-cost-snapshot-time')
        result['window_elapsed_ns'] = end[1] - start[1]
        for offset in [4, 9]:
            before, after = start[offset:offset + 5], end[offset:offset + 5]
            ensure(all(after[index] >= before[index] for index in range(4)), 'monotonic-proof-cost-cumulative-fields')
            straddling = before[4] != 0 or after[4] != 0
            result['spans'].append({'entered_delta': after[0] - before[0],
                                    'completed_delta': after[1] - before[1],
                                    'completed_span_total_delta_ns': after[2] - before[2],
                                    'boundary_straddling': straddling,
                                    'exact_window_total_ns': None if straddling else after[2] - before[2],
                                    'start_cumulative_max_ns': before[3], 'end_cumulative_max_ns': after[3],
                                    'window_max_ns': None})
    return result


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
    turn_rows = []
    for line in raw.splitlines():
        if not line.startswith('ordinary-sibling-turn '): continue
        match = re.fullmatch(TURN_LINE, line)
        ensure(match is not None and len(line) <= 4096 and match[1] not in {row['side'] for row in turn_rows}, 'closed-unique-turn-trace')
        ensure(all(int(value) <= 1_000_000_000 for value in re.findall(r'[0-9]+', match[2])), 'bounded-turn-trace-integers')
        turn_rows.append({'side': match[1], 'closed_tuple': match[2]})
    timer_rows = []
    for line in raw.splitlines():
        if not line.startswith('ordinary-sibling-timer '): continue
        match = re.fullmatch(TIMER_LINE, line)
        ensure(match is not None and len(line) <= 1024 and match[1] not in {row['side'] for row in timer_rows}, 'closed-unique-timer-trace')
        ensure(all(int(value) <= 1_000_000_000 for value in re.findall(r'[0-9]+', match[2])), 'bounded-timer-trace-integers')
        timer_rows.append({'side': match[1], 'closed_tuple': match[2]})
    return {'proof_cost': proof_cost_diagnostics(raw),
            'aggregates': rows, 'stages': stages, 'phase_failures': phase_rows, 'missing_diagnostics': not rows,
            'turn_traces': turn_rows, 'missing_turn_trace': not turn_rows,
            'missing_recipient_turn_trace': not any(row['side'] == 'right' for row in turn_rows),
            'timer_traces': timer_rows, 'missing_timer_trace': not timer_rows,
            'missing_recipient_timer_trace': not any(row['side'] == 'right' for row in timer_rows)}


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
    trace = 'ordinary-sibling-turn side=right trace=(' + '[' + ', '.join(['0'] * 14) + '], [' + ', '.join(['None'] * 14) + '], Some((BeginStart, None, 10)), Some((BeginStart, 2)), Some([true, false, false]), false, 12)'
    ensure(diagnostics(trace)['turn_traces'][0]['side'] == 'right', 'closed-turn-trace-positive')
    trace_variants = [trace.replace('right', 'secret'), trace.replace('BeginStart', 'SecretStage'), trace.replace('None', '"secret"', 1),
                      trace.replace('10)', '1000000001)'), trace + '\n' + trace, trace + ' extra',
                      trace.replace('[0, ', '[' , 1), trace.replace('false, 12)', 'secret, 12)'), trace.replace('BeginStart, None, 10', 'BeginStart, Some(128), 10')]
    for changed in trace_variants:
        try: diagnostics(changed)
        except ValueError: continue
        raise ValueError('adversarial-turn-trace-accepted')
    ensure(diagnostics('unrelated')['missing_recipient_turn_trace'] is True, 'missing-turn-trace-not-zero')
    timer = 'ordinary-sibling-timer side=right timer=([3, 2, 1], [Some(12), Some(11), Some(12)], Some((true, 2)), Some(false), Some([true, true]), [0, 1], [0, 2], 5, Some(true))'
    timer_missing = 'ordinary-sibling-timer side=left timer=([0, 0, 0], [None, None, None], None, None, None, [0, 0], [0, 0], 0, None)'
    for value in [timer, timer_missing]:
        ensure(len(diagnostics(value)['timer_traces']) == 1, 'closed-timer-trace-positive')
    timer_variants = [timer.replace('right', 'secret'), timer.replace('true', 'secret'), timer.replace('Some(false)', 'Some(1)'),
                      timer.replace('12)', '1000000001)'), timer.replace('[3, 2, 1]', '[3, 2]'), timer + '\n' + timer,
                      timer + ' private', timer.replace('Some(11)', 'Some(-1)'), timer.replace('Some(11)', '"private"'),
                      timer.replace('Some([true, true])', 'Some([true])'),
                      timer.replace('[0, 1]', '[0, "private"]'), timer.replace('], 5, Some(true)', '], 1000000001, Some(true)')]
    for changed in timer_variants:
        try: diagnostics(changed)
        except ValueError: continue
        raise ValueError('adversarial-timer-trace-accepted')
    ensure(diagnostics('unrelated')['missing_recipient_timer_trace'] is True, 'missing-timer-trace-not-zero')
    proof_start = [0, 10, 1, 0, 2, 2, 8, 4, 0, 1, 1, 9, 9, 0]
    proof_end = [1, 30, 1, 0, 4, 4, 14, 4, 0, 2, 2, 20, 11, 0]
    def proof_line(values):
        return 'ordinary-proof-cost values=' + json.dumps(values)
    proof = proof_line(proof_start) + '\n' + proof_line(proof_end)
    receipt = proof_cost_diagnostics(proof)
    ensure(receipt['measurement_known'] and receipt['window_elapsed_ns'] == 20
           and receipt['spans'][0]['exact_window_total_ns'] == 6
           and receipt['spans'][1]['window_max_ns'] is None, 'proof-cost-known-cumulative-pair')
    straddled = proof_end.copy()
    straddled[4], straddled[8] = 5, 1
    receipt = proof_cost_diagnostics(proof_line(proof_start) + '\n' + proof_line(straddled))
    ensure(receipt['spans'][0]['boundary_straddling'] and receipt['spans'][0]['exact_window_total_ns'] is None, 'proof-cost-straddling-is-not-exact-window-cost')
    unknown = [1, 0, 0, 0] + [0] * 10
    ensure(not proof_cost_diagnostics(proof_line(proof_start) + '\n' + proof_line(unknown))['measurement_known'], 'proof-cost-poison-unknown-not-zero')
    poisoned_start = [0] * 14
    receipt = proof_cost_diagnostics(proof_line(poisoned_start) + '\n' + proof_line(unknown))
    ensure(receipt['snapshot_pair_complete'] and receipt['normal_end_marker']
           and not receipt['measurement_known'] and receipt['window_elapsed_ns'] is None,
           'proof-cost-poison-both-boundaries-one-terminal-unknown')
    overflow = proof_end.copy()
    overflow[3] = 1
    ensure(not proof_cost_diagnostics(proof_line(proof_start) + '\n' + proof_line(overflow))['measurement_known'], 'proof-cost-overflow-unknown-not-zero')
    fallback = proof_end.copy()
    fallback[0] = 2
    ensure(not proof_cost_diagnostics(proof_line(proof_start) + '\n' + proof_line(fallback))['normal_end_marker'], 'proof-cost-unwind-end-distinct')
    ensure(proof_cost_diagnostics(proof_line(proof_end))['missing_start']
           and not proof_cost_diagnostics(proof_line(proof_end))['measurement_known'], 'proof-cost-missing-start-not-zero')
    ensure(not proof_cost_diagnostics(proof_line(proof_start))['snapshot_pair_complete']
           and not proof_cost_diagnostics('unrelated')['measurement_known'], 'proof-cost-missing-end-not-zero')
    proof_invalid = [proof + '\n' + proof_line(proof_end), proof_line(proof_end) + '\n' + proof_line(proof_start),
                     proof.replace('values=[', 'values=["private", ', 1), proof + ' private',
                     proof.replace('[0, 10', '[3, 10', 1), proof.replace('[0, 10', '[0, -10', 1),
                     proof.replace('[0, 10', '[0, 1000000000000000001', 1),
                     proof.replace('[0, 10', '[0, true', 1), proof_line(proof_start[:-1])]
    for index, value in [(1, 9), (2, 2), (4, 1), (5, 1), (6, 7), (7, 15), (8, 1)]:
        changed = proof_end.copy()
        changed[index] = value
        proof_invalid.append(proof_line(proof_start) + '\n' + proof_line(changed))
    for value in proof_invalid:
        try: proof_cost_diagnostics(value)
        except ValueError: continue
        raise ValueError('adversarial-proof-cost-observation-accepted')
    return {'positive_controls': len(positives) + 3, 'negative_controls': len(negatives) + len(trace_variants) + len(timer_variants),
            'proof_cost_positive_controls': 8, 'proof_cost_negative_controls': len(proof_invalid), 'passed': True}


def source_guard():
    ensure(os.environ.get('WN_ORDINARY_SIBLING_TURN_TRACE') == '1', 'optional-diagnostic-only-probe-enabled')
    ensure(os.environ.get('UPSTREAM_EXTRACTION_COHORT_BASELINE') == BASE, 'explicit-reviewed-source-cohort')
    ensure(subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, 'HEAD']).returncode == 0, 'reviewed-baseline-ancestor')
    changed = set(subprocess.check_output(['git', 'diff', '--name-only', BASE, 'HEAD'], text=True).splitlines())
    ensure(changed <= set(HOOKS) | {SELF, PROBE, PROOF_PROBE, WORKFLOW}, 'only-passive-test-hooks-and-diagnostic-metadata')
    pattern = rb'(?m)^[ \t]*// ORDINARY_TURN_TEST_BEGIN\n.*?^[ \t]*// ORDINARY_TURN_TEST_END\n'
    for name, count in HOOKS.items():
        data = Path(name).read_bytes()
        ensure(data.count(b'ORDINARY_TURN_TEST_BEGIN') == data.count(b'ORDINARY_TURN_TEST_END') == count, 'exact-passive-hook-count')
        ensure(re.sub(pattern, b'', data, flags=re.S) == subprocess.check_output(['git', 'show', BASE + ':' + name]), 'exact-existing-product-and-fixture-after-passive-strip')
    metadata = layout()
    for name in changed:
        ensure(metadata[name]['git_mode'] == '100644' and not metadata[name]['actual_executable'] and not metadata[name]['symlink'], 'ordinary-passive-test-and-metadata-modes')
    workflow = Path(WORKFLOW).read_text()
    start = '  # ORDINARY_TURN_TRACE_JOBS_BEGIN\n'
    end = '  # ORDINARY_TURN_TRACE_JOBS_END\n'
    ensure(workflow.count(start) == workflow.count(end) == 1, 'unique-isolated-turn-trace-jobs')
    before, job = workflow.split(start)
    _, after = job.split(end)
    restored = (before + after).replace('options: [ordinary-turn-trace, ', 'options: [', 1)
    ensure(restored.encode() == subprocess.check_output(['git', 'show', BASE + ':' + WORKFLOW]), 'existing-workflow-scopes-unchanged')
    return {'baseline': BASE, 'changed_paths': sorted(changed), 'unchanged_product_tests_oracles_deadlines_after_passive_strip': True}


def execute(case, suffix):
    started = time.monotonic()
    command = [case['binary'], '--exact', case['name'], '--nocapture', '--test-threads=1']
    ensure(digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'selected-ordinary-binary-exact')
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

    ensure(digest(Path(case['binary']).read_bytes()) == case['binary_sha256'], 'executed-ordinary-binary-unchanged')
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
        report['turn_trace_schema'] = {'stage_order': TURN_STAGES.split('|'),
            'counts': '14 bounded counters', 'last_times': '14 optional elapsed milliseconds',
            'point': 'optional stage/index/elapsed-since-point milliseconds',
            'returned': 'optional last routine stage/elapsed-routine milliseconds',
            'due': 'optional due/yielded/service booleans', 'active': 'routine entered without return',
            'clock': 'bounded elapsed milliseconds since this exact original was captured',
            'failure_interpretation': 'BeginStart without BeginDone plus Return means exited before successful begin; no typed error is invented',
            'timing_interpretation': 'inclusive stage duration, not exclusive CPU cost',
            'worker_events': 'loop and preselect only; no explicit timer-latch or selection hook inside the unchanged select macro'}
        report['timer_trace_schema'] = {
            'counts_and_last_times_order': ['actual_tick_poll', 'pending', 'ready'],
            'times': 'optional bounded milliseconds since exact original capture',
            'scheduled_vs_observed': 'optional (observed_at_or_after_scheduled, absolute_delta_ms) for last actual Ready',
            'stopping': 'optional lifecycle.is_stopping sampled before select',
            'delegation': 'one original tick future poll per adapter poll; exact Ready Instant returned; no reset or wake',
            'last_budget': 'optional [before, after] read-only cooperative budget availability for last delegated poll',
            'overdue_pending_and_max_lateness_order': ['before_budget_false', 'before_budget_true'],
            'overdue_definition': 'Pending at or after conservative last-Ready observation + unchanged interval period',
            'maximum_poll_gap_ms': 'maximum observed gap between actual delegated polls for this exact original',
            'last_pending_overdue': 'optional bool, missing before a known deadline bound or any Pending',
            'interpretation': 'budget-false supports cooperative denial; budget-true overdue Pending means underlying timer still Pending, not proof of a particular expensive operation',
            'scope': 'timer readiness only; no explicit latch/service/gate instrumentation',
        }
        report['diagnostic_environment'] = {'WN_ORDINARY_SIBLING_TURN_TRACE': os.environ.get('WN_ORDINARY_SIBLING_TURN_TRACE')}
        report['proof_cost_schema'] = {
            'scope': 'process-wide aggregates from all fixture Engines, no identity attribution',
            'row_order': ['verify_proof_signature', 'validated_settled_device_roster'],
            'numeric_snapshot_order': ['stage', 'elapsed_ns', 'known', 'overflow',
                                       'signature_entered', 'signature_completed', 'signature_total_ns', 'signature_max_ns', 'signature_inflight',
                                       'roster_entered', 'roster_completed', 'roster_total_ns', 'roster_max_ns', 'roster_inflight'],
            'stage_order': ['fourth_wait_start', 'normal_success_or_timeout_end', 'other_unwind_end'],
            'duration_semantics': 'monotonic inclusive wall durations; roster contains signature work, never add nested totals',
            'straddling': 'completed-duration delta is not exact window cost when either boundary has an in-flight span',
            'maxima': 'cumulative maxima are reported separately; no subtraction or invented window maximum',
            'unknown': 'missing, poison or overflow is not zero cost',
        }
        report['parser_controls'] = parser_controls()
        report['source_before_sha256'] = identity(original)
        if preflight:
            report['preflight_passed'] = True
            return
        compilation, cases = compile_cases([CASE])
        report['compilation'] = compilation
        ensure(set(cases) == {CASE} and cases[CASE]['name'] == 'native_device_linking::automatic_pairing_acceptance::' + CASE, 'exact-one-original-ordinary-inventory')
        report['compiled_feature_identity'] = feature_identity(compilation)
        for suffix in [CASE]:
            ensure(freeze() == original and layout() == original_layout, 'unchanged-inputs-before-body')
            report['cases'].append(execute(cases[suffix], suffix))
        report['actual_executed'] = sum(row.get('executed_nonignored', 0) for row in report['cases'])
        report['diagnostic_execution_completed'] = all(row['runtime_completed'] for row in report['cases'])
        report['ordinary_case_passed'] = all(row['test_passed'] for row in report['cases'])
        ensure(report['diagnostic_execution_completed'], 'incomplete-diagnostic-execution')
        ensure(report['ordinary_case_passed'], 'original-enrollment-failures-preserved')
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
