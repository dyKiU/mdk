#!/usr/bin/env python3
"""Remote-only actual backend ACK/context regression and restored mutation proof."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import time
from upstream_completion_ci import compile_cases, digest, ensure, environment, headers, identity, parse_body
from qualify_upstream_body_negative import freeze, layout, feature_identity
from verify_upstream_completion_candidate_source import normalize

BASE = '0b50673c5b9e76266b50e660958bb8b24fe926e0'
PRODUCT = 'crates/marmot-app/src/client/account_chat_sharing/automatic.rs'
REGISTER = 'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
TEST = 'crates/marmot-app/src/native_device_linking/tests/automatic_body_late_ack_acceptance.rs'
PROBE = 'crates/marmot-app/src/client/account_chat_sharing/automatic/body_late_ack_probe.rs'
PROXY = 'crates/marmot-app/src/native_device_linking/tests/automatic_body_late_ack_relay.rs'
SELF = 'scripts/qualify_upstream_body_late_ack.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
CASES = ['authenticated_receipt_retires_final_catalog_body_before_late_backend_ack',
         'unchanged_catalog_context_accepts_the_same_real_backend_ack']
PREFIX = 'native_device_linking::automatic_pairing_acceptance::body_late_ack_acceptance::'
MESSAGE = 'late Catalog ACK must not advance a superseded Body context; unchanged context must retain real ACK progress'
ANCHOR = '            if !context_matches\n                || entry.renew'
MUTANT = '            if false\n                || entry.renew'
OUT = Path('body-late-ack-evidence')


def oracle_line():
    source = Path(TEST).read_text()
    ensure(source.count(MESSAGE) == 1, 'sole-behavioral-oracle')
    location = source.rfind('assert!(', 0, source.index(MESSAGE))
    ensure(location >= 0, 'behavioral-assertion-location')
    return source[:location].count('\n') + 1



def cleanup_diagnostics(raw):
    number = r'(?:0|[1-9][0-9]{0,18})'
    def array(length):
        return r'\[' + ', '.join([number] * length) + r'\]'
    matrix = r'\[' + ', '.join([array(14)] * 8) + r'\]'
    handshakes = r'\[' + ', '.join([array(8)] * 2) + r'\]'
    pattern = (r'body-late-ack-cleanup runtime1=(true|false) runtime2=(true|false) relay_planes=(' + number
               + r') connections=(' + number + r') closed_connections=(' + number
               + r') invalid=(true|false) task_outcome=([0-5]) child_outcomes=('
               + array(4) + r') io_categories=(' + matrix + r') close_handshakes=(' + handshakes + r')')
    lines = [line for line in raw.splitlines() if line.startswith('body-late-ack-cleanup ')]
    if len(lines) != 1 or len(lines[0]) > 8192:
        return {'valid': False, 'line_count': min(len(lines), 2)}
    match = re.fullmatch(pattern, lines[0])
    if match is None:
        return {'valid': False, 'line_count': 1}
    return {'valid': True, 'runtime1_closed': match[1] == 'true',
            'runtime2_closed': match[2] == 'true', 'relay_planes_completed': int(match[3]),
            'connections': int(match[4]), 'closed_connections': int(match[5]),
            'invalid': match[6] == 'true', 'task_outcome': int(match[7]),
            'child_outcomes': json.loads(match[8]), 'io_categories': json.loads(match[9]),
            'close_handshakes': json.loads(match[10])}


def cleanup_parser_controls():
    matrix = [[0] * 14 for _ in range(8)]
    matrix[2][6] = 1  # Frontend write / BrokenPipe remains failed cleanup.
    sample = ('body-late-ack-cleanup runtime1=true runtime2=true relay_planes=2 connections=2 '
              'closed_connections=1 invalid=false task_outcome=1 child_outcomes=[1, 1, 0, 0] io_categories='
              + json.dumps(matrix) + ' close_handshakes=' + json.dumps([[0] * 8 for _ in range(2)]))
    parsed = cleanup_diagnostics(sample)
    ensure(parsed.get('valid') and parsed['io_categories'][2][6] == 1
           and parsed['task_outcome'] == 1 and parsed['closed_connections'] == 1, 'closed-cleanup-parser')
    negatives = [sample + ' private', sample.replace('task_outcome=1', 'task_outcome=6'),
                 sample.replace('runtime1=true', 'runtime1=secret'), sample.replace('relay_planes=2', 'relay_planes=-2'),
                 sample.replace('connections=2', 'connections=12345678901234567890'),
                 sample.replace('child_outcomes=[1, 1, 0, 0]', 'child_outcomes=[1, 1, 0]'),
                 sample + '\n' + sample, sample.replace('io_categories=[[0', 'io_categories=[["secret"'),
                 sample.replace('io_categories=[[0', 'io_categories=[[true'),
                 sample.replace('close_handshakes=[[0', 'close_handshakes=[[true'),
                 sample.replace('close_handshakes=[[0', 'close_handshakes=[[-1')]
    for value in negatives:
        ensure(cleanup_diagnostics(value).get('valid') is False, 'reject-private-or-malformed-cleanup')
    return {'positive': 1, 'negative': len(negatives), 'runtime_bodies': 0}


def parse(raw, case, exit_code):
    row = parse_body(raw, case)
    row.update(body_exit_code=exit_code, compiler_error_count=headers(raw)['compiler_error_count'])
    if 'executed_nonignored' not in row: row['actual_count_unknown'] = True
    row['case_names'] = re.findall(r'(?m)^test ([A-Za-z0-9_:]+) \.\.\.', raw)
    records = re.findall(r'body-late-ack-control hold_receipt=(true|false) prerequisites=(true|false) cleanup=(true|false) followup=(true|false) old_body_effects=(\d+) sdk_success=(\d+) successful_harvest=(\d+) context_rejected=(\d+) future_dropped=(\d+) retired=(\d+)', raw)
    if len(records) == 1:
        values = records[0]
        row['observed'] = dict(zip(['hold_receipt', 'prerequisites', 'cleanup', 'followup'], [value == 'true' for value in values[:4]]))
        row['observed'].update(dict(zip(['old_body_effects', 'sdk_success', 'successful_harvest', 'context_rejected', 'future_dropped', 'retired'], map(int, values[4:]))))
    row['named_oracle_count'] = raw.count(MESSAGE)
    row['cleanup_diagnostics'] = cleanup_diagnostics(raw)
    return row


def prerequisites(row, case):
    observed = row.get('observed', {})
    return (row.get('case_names') == [PREFIX + case]
            and row.get('executed_nonignored') == 1 and row.get('ignored') == 0
            and row.get('compiler_error_count') == 0 and not row.get('watchdog_triggered')
            and observed.get('hold_receipt') is (case == CASES[1])
            and observed.get('prerequisites') is True and observed.get('cleanup') is True
            and type(observed.get('future_dropped')) is int and observed['future_dropped'] > 0)


def green(row, case):
    expected = 1 if case == CASES[1] else 0
    return (prerequisites(row, case) and row.get('body_exit_code') == 0
            and row.get('passed') == 1 and row.get('failed') == 0
            and row.get('all_panic_header_count') == 0
            and row['observed'].get('old_body_effects') == expected
            and row['observed'].get('followup') is True)


def killed(row):
    return (prerequisites(row, CASES[0]) and row.get('body_exit_code') == 101
            and row.get('passed') == 0 and row.get('failed') == 1
            and row.get('all_panic_header_count') == 1 and row.get('named_oracle_count') == 1
            and row.get('panic_locations') == [{'file': TEST, 'line': oracle_line(), 'column': 5}]
            and row['observed'].get('old_body_effects', 0) > 0
            and row['observed'].get('sdk_success') == 1
            and row['observed'].get('successful_harvest') == 1)


def parser_controls():
    row = {'case_names': [PREFIX + CASES[0]], 'executed_nonignored': 1, 'ignored': 0,
           'compiler_error_count': 0, 'body_exit_code': 101, 'passed': 0, 'failed': 1,
           'all_panic_header_count': 1, 'named_oracle_count': 1,
           'panic_locations': [{'file': TEST, 'line': oracle_line(), 'column': 5}],
           'observed': {'hold_receipt': False, 'prerequisites': True, 'cleanup': True, 'followup': True,
                        'future_dropped': 1, 'old_body_effects': 1, 'sdk_success': 1,
                        'successful_harvest': 1}}
    ensure(killed(row), 'positive-runtime-red-parser')
    count = 0
    for key, value in [('body_exit_code', 0), ('executed_nonignored', 0), ('ignored', 1),
                       ('compiler_error_count', 1), ('all_panic_header_count', 2),
                       ('named_oracle_count', 0), ('panic_locations', []),
                       ('case_names', [PREFIX + CASES[1]]), ('watchdog_triggered', True)]:
        bad = copy.deepcopy(row); bad[key] = value
        ensure(not killed(bad), 'negative-runtime-red-parser'); count += 1
    for key, value in [('prerequisites', False), ('cleanup', False), ('future_dropped', 0),
                       ('old_body_effects', 0), ('successful_harvest', 0), ('sdk_success', 0)]:
        bad = copy.deepcopy(row); bad['observed'][key] = value
        ensure(not killed(bad), 'negative-runtime-witness-parser'); count += 1
    control = copy.deepcopy(row)
    control.update(body_exit_code=0, passed=1, failed=0, all_panic_header_count=0)
    control['observed']['old_body_effects'] = 0
    ensure(green(control, CASES[0]), 'positive-green-parser')
    no_followup = copy.deepcopy(control); no_followup['observed']['followup'] = False
    ensure(not green(no_followup, CASES[0]) and not killed(no_followup), 'failed-followup-alone-is-not-a-mutation-kill')
    count += 1
    record = 'body-late-ack-control hold_receipt=false prerequisites=true cleanup=true followup=true old_body_effects=1 sdk_success=1 successful_harvest=1 context_rejected=0 future_dropped=1 retired=0\n'
    raw = 'test ' + PREFIX + CASES[0] + ' ... FAILED\n' + record
    raw += f"thread 'fixture' panicked at {TEST}:{oracle_line()}:5:\n" + MESSAGE + '\n'
    raw += 'test result: FAILED. 0 passed; 1 failed; 0 ignored;\n'
    ensure(killed(parse(raw, CASES[0], 101)), 'positive-actual-log-red-parser')
    ensure(not killed(parse(raw + record, CASES[0], 101)), 'duplicate-log-witness-denied')
    return {'positive': 3, 'negative': count + 1, 'runtime_bodies': 0, 'cleanup_diagnostics': cleanup_parser_controls()}


def source_guard():
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true', 'remote-only')
    ensure(subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == os.environ.get('GITHUB_SHA'), 'exact-remote-source')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, 'HEAD'], check=True)
    allowed = {PRODUCT, REGISTER, TEST, PROBE, PROXY, SELF, WORKFLOW}
    tracked = subprocess.check_output(['git', 'ls-files'], text=True).splitlines()
    current_modes = {line.split('\t', 1)[1]: line.split()[0] for line in subprocess.check_output(['git', 'ls-files', '--stage'], text=True).splitlines()}
    baseline_modes = {line.split('\t', 1)[1]: line.split()[0] for line in subprocess.check_output(['git', 'ls-tree', '-r', BASE], text=True).splitlines()}
    ensure(all(current_modes[name] == baseline_modes.get(name, '100644') for name in tracked), 'baseline-source-modes-preserved')
    old = {line.split('\t', 1)[1]: line.split()[2] for line in subprocess.check_output(['git', 'ls-tree', '-r', BASE], text=True).splitlines()}
    ensure(set(tracked) - set(old) == {TEST, PROBE, PROXY, SELF}, 'only-reviewed-new-files')
    ensure(not set(old) - set(tracked), 'no-removed-baseline-files')
    for name in set(old) - allowed:
        content = os.readlink(name).encode() if Path(name).is_symlink() else Path(name).read_bytes()
        git_blob = digest(content)
        ensure(git_blob == digest(subprocess.check_output(['git', 'show', BASE + ':' + name])), 'unreviewed-source-drift:' + name)
    pattern = r'(?m)^[ \t]*// BODY_LATE_ACK_TEST_BEGIN\n.*?^[ \t]*// BODY_LATE_ACK_TEST_END\n'
    counts = {}
    for name in [PRODUCT, REGISTER]:
        text = Path(name).read_text()
        blocks = re.findall(pattern, text, re.S)
        ensure(blocks and len(blocks) == text.count('BODY_LATE_ACK_TEST_BEGIN') == text.count('BODY_LATE_ACK_TEST_END'), 'balanced-test-hook-blocks')
        stripped = re.sub(pattern, '', text, flags=re.S)
        baseline = subprocess.check_output(['git', 'show', BASE + ':' + name], text=True)
        ensure(normalize(stripped) == normalize(baseline), 'stripped-product-or-original-fixture-changed')
        counts[name] = len(blocks)
    source = Path(PRODUCT).read_text()
    ensure(source.count(ANCHOR) == 1 and MUTANT not in source, 'one-main-context-mutation-anchor')
    ensure(source.index('body_late_ack_probe::arm(') < source.index('let task = tokio::spawn(publication_future)'), 'arm-before-spawn')
    ensure('self.original.cancel();' in source and 'self.channel.retire();' in source and 'body_negative_probe::retired(self);' in source, 'existing-retirement-seam-preserved')
    return {'baseline': BASE, 'hook_blocks': counts, 'parser_controls': parser_controls()}


def main():
    arguments = argparse.ArgumentParser()
    arguments.add_argument('--preflight', action='store_true')
    options = arguments.parse_args()
    guard = source_guard()
    if options.preflight:
        print(json.dumps(guard, indent=2)); return
    OUT.mkdir(exist_ok=False)
    report = environment()
    report.update(baseline_test_source=BASE, reviewed_product_baseline=BASE, scope='Actual backend ACK of final Catalog after real recipient import/receipt changes original context; Linux SDK witness, not Apple native acceptance', source_guard=guard, phases={}, qualification_passed=False)
    report['cleanup_schema'] = {
        'io_operations': ['frontend_read', 'backend_read', 'frontend_write', 'backend_write', 'frontend_close', 'backend_close', 'frontend_handshake', 'backend_connect'],
        'io_categories': ['success', 'eof', 'close_frame', 'connection_closed', 'already_closed', 'io_reset', 'io_broken_pipe', 'io_unexpected_eof', 'io_other', 'protocol_reset_without_close', 'protocol_send_after_closing', 'protocol_received_after_closing', 'protocol_other', 'other'],
        'child_outcomes': ['success', 'returned_error', 'cancelled_join', 'panicked_join'],
        'close_handshakes': ['initiated', 'received', 'flushed', 'terminal', 'other_drained_frame', 'timeout', 'failure', 'completed'],
        'close_handshake_sides': ['frontend', 'backend'],
        'task_outcomes': ['success', 'child_server_error', 'join_failure', 'timeout_abort', 'missing_task', 'invalid_or_incomplete_socket_counts'],
    }
    frozen = freeze(); original_layout = layout(); original = Path(PRODUCT).read_bytes()
    report['source_before'] = identity(frozen)
    def save(): (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    save()
    def phase(label, expected):
        ensure(freeze() == expected and layout() == original_layout, 'phase-entry-source-drift')
        row = {}; report['phases'][label] = row; save()
        compilation, cases = compile_cases(CASES); row['compilation'] = compilation; save()
        ensure(compilation.get('compile_exit_code') == 0 and compilation.get('compiler_error_count') == 0 and set(cases) == set(CASES), 'compile-or-case-inventory-not-qualified')
        row['features'] = feature_identity(compilation)
        if label != 'baseline': ensure(row['features'] == report['phases']['baseline']['features'], 'exact-compiled-feature-cohort')
        ensure(freeze() == expected and layout() == original_layout, 'compiled-source-drift')
        row['cases'] = {}
        for case in CASES:
            selected = cases[case]
            ensure(selected['name'] == PREFIX + case, 'exact-runtime-case-name')
            started = time.monotonic()
            try:
                result = subprocess.run([selected['binary'], '--exact', selected['name'], '--nocapture', '--test-threads=1'], capture_output=True, text=True, timeout=300)
                body = parse(result.stdout + result.stderr, case, result.returncode)
            except subprocess.TimeoutExpired:
                body = {'watchdog_triggered': True, 'actual_count_unknown': True}
            row['cases'][case] = dict(body, seconds=time.monotonic() - started, binary_sha256=selected['binary_sha256'])
            save(); ensure(freeze() == expected and layout() == original_layout, 'runtime-source-drift')
        return row['cases']
    try:
        baseline = phase('baseline', frozen)
        ensure(all(green(baseline[case], case) for case in CASES), 'baseline-not-green')
        mutation_error = None
        try:
            Path(PRODUCT).write_bytes(original.replace(ANCHOR.encode(), MUTANT.encode(), 1))
            mutant_inputs = freeze()
            ensure({name for name in frozen if frozen[name] != mutant_inputs[name]} == {PRODUCT}, 'one-mutation-only')
            mutant = phase('mutant', mutant_inputs)
            report['mutant_detected'] = killed(mutant[CASES[0]]) and green(mutant[CASES[1]], CASES[1])
            ensure(report['mutant_detected'], 'mutant-not-detected-at-intended-runtime-oracle')
        except Exception as error:
            mutation_error = str(error); report['mutation_error'] = mutation_error
        finally:
            Path(PRODUCT).write_bytes(original)
            report['source_restored'] = freeze() == frozen and layout() == original_layout
            save()
            restored = phase('restored', frozen)
            report['restored_green'] = all(green(restored[case], case) for case in CASES)
            save()
        ensure(mutation_error is None and report.get('mutant_detected') and report.get('restored_green'), 'mutation-chain-incomplete')
        report['qualification_passed'] = True
    except Exception as error:
        report['error'] = str(error); raise
    finally:
        report['source_pristine'] = freeze() == frozen and layout() == original_layout
        report['qualification_passed'] &= report['source_pristine']
        report['source_after'] = identity(freeze())
        report['actual_validated_executions'] = sum(case.get('executed_nonignored', 0) for row in report['phases'].values() for case in row.get('cases', {}).values())
        save()
        if not report['source_pristine'] and 'error' not in report: raise RuntimeError('final-source-not-pristine')


if __name__ == '__main__': main()
