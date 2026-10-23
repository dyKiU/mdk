"""Remote-only replay controls and scoped omission chains; no full-suite credit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from upstream_current_backend_probe import ANSI, capture
from upstream_extraction_cohort import frozen_inputs, git, reviewed_cohort

PREFIX = 'offline-replay-diagnostic '
CASES = {
    'offline': ('relay_runtime', 'offline_replay::offline_replay_crosses_queue',
                'crates/marmot-app/tests/relay_runtime/offline_replay.rs'),
    'inline': ('marmot_app', 'client::sync::queued_outbound_schedule_tests::inline_epoch_change_keeps_stale_own_leave_worker_wake',
               'crates/marmot-app/src/client/sync/queued_outbound_schedule_tests.rs'),
    'input-only': ('marmot_app', 'client::sync::queued_outbound_schedule_tests::stale_own_leave_after_input_only_convergence_keeps_worker_wake',
                   'crates/marmot-app/src/client/sync/queued_outbound_schedule_tests.rs'),
    'spill': ('marmot_app', 'client::delivery_spill::yield_handoff_tests::cancelled_spill_receive_keeps_its_cooperative_offer_and_real_message',
              'crates/marmot-app/src/client/delivery_spill.rs'),
}
CASES.update({
    'revoked-anchor': ('storage_sqlite', 'revoked_device_group_anchor::tests::revoked_anchor_encrypted_reopen_and_group_deletion_preserve_terminal_bytes',
                       'crates/storage-sqlite/src/revoked_device_group_anchor/tests.rs'),
    'sharing-policy': ('storage_sqlite', 'approved_account_sharing_policy::tests::sharing_policy_encrypted_restart_retains_sequences_revocation_and_closed_owner',
                       'crates/storage-sqlite/src/approved_account_sharing_policy/tests.rs'),
    'late-consent': ('marmot_app', 'native_device_linking::automatic_pairing_acceptance::late_sibling_consent_acceptance::authenticated_late_consent_starts_initial_proof_without_periodic_tick',
                     'crates/marmot-app/src/native_device_linking/tests/late_sibling_consent_acceptance.rs'),
    'spill-experimental': CASES['spill'],
    'watch-pressure': ('marmot_app', 'native_device_linking::automatic_pairing_acceptance::watch_pressure_acceptance::authenticated_body_is_serviced_before_eight_ready_watch_services',
                       'crates/marmot-app/src/native_device_linking/tests/watch_pressure_acceptance.rs'),
})
EXPERIMENTAL_CASES = {'revoked-anchor', 'sharing-policy', 'late-consent', 'spill-experimental', 'watch-pressure'}
STORAGE_CASES = {'revoked-anchor', 'sharing-policy'}


def package_for(case):
    return 'storage-sqlite' if case in STORAGE_CASES else 'marmot-app'


OPERATIONS = {'ingest', 'ingest_engine', 'ingest_effect_publish', 'worker_catch_up',
              'worker_convergence', 'worker_receive', 'storage_connection_wait',
              'storage_transaction', 'storage_write_begin', 'projection_checkpoint'}
ROW = {'started', 'completed', 'failures', 'in_flight', 'sum_ms'}
SCALARS = {'senders', 'per_sender', 'expected', 'snapshot', 'observed', 'stored',
           'catchup_elapsed_ms', 'completed_group_pages', 'refused_comparisons',
           'projection_attempts', 'projection_successes', 'projection_failures', 'projection_sum_ms'}
FIELDS = SCALARS | {'completed', 'arrival_buckets_10s', 'maximum_group_page', 'runtime_operations'}
LIB_FEATURES = ['marmot-app/test-policy-overrides', 'marmot-app/otlp-export',
                'marmot-app/product-analytics-export', 'cgka-engine/test-policy-overrides',
                'cgka-engine/test-crash-hooks']
FAILURES = {'admission', 'environment', 'inventory-command', 'inventory-shape',
            'inventory-source', 'body-command', 'runtime-shape', 'diagnostic', 'body-not-passed', 'closure', 'internal'}


def uint(value):
    return type(value) is int and 0 <= value <= 2**64 - 1


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate-key')
        result[key] = value
    return result


def closed(value):
    if type(value) is not dict or set(value) != FIELDS:
        raise ValueError('diagnostic-fields')
    if any(not uint(value[key]) for key in SCALARS) or type(value['completed']) is not bool:
        raise ValueError('diagnostic-scalars')
    if value['maximum_group_page'] is not None and not uint(value['maximum_group_page']):
        raise ValueError('diagnostic-page')
    buckets = value['arrival_buckets_10s']
    if type(buckets) is not list or len(buckets) != 6 or not all(uint(v) for v in buckets):
        raise ValueError('diagnostic-buckets')
    rows = value['runtime_operations']
    if type(rows) is not list or len(rows) != len(OPERATIONS):
        raise ValueError('diagnostic-operations')
    names = []
    for pair in rows:
        if type(pair) is not list or len(pair) != 2 or type(pair[0]) is not str or pair[0] not in OPERATIONS:
            raise ValueError('diagnostic-operation-pair')
        name, row = pair
        if type(row) is not dict or set(row) != ROW or not all(uint(v) for v in row.values()):
            raise ValueError('diagnostic-operation-row')
        names.append(name)
    if len(set(names)) != len(OPERATIONS):
        raise ValueError('diagnostic-duplicate-operation')
    # These facts are collected after the frozen timeout. Do not equate stored
    # with observed, or elapsed with the timeout edge; either may advance later.
    if (value['snapshot'] + sum(buckets) != value['observed']
            or value['observed'] > value['expected'] or value['snapshot'] > value['expected']):
        raise ValueError('diagnostic-delivery-counts')
    return value


def marker(raw):
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    lines = [line for line in text.splitlines() if PREFIX in line]
    if len(lines) != 1 or text.count(PREFIX) != 1:
        raise ValueError('diagnostic-cardinality')
    match = re.fullmatch(r'[ \t]{0,8}' + re.escape(PREFIX) + r'(\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    if match is None or len(lines[0]) > 16384:
        raise ValueError('diagnostic-envelope')
    return closed(json.loads(match[1], object_pairs_hook=unique))


def compiler(raw, inputs):
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    codes = sorted(set(re.findall(r'\berror\[(E[0-9]{4})\]', text)))
    headers = re.findall(r'^error(?:\[E[0-9]{4}\])?:.*$', text, re.M)
    # Only the exact nextest terminal is a runtime wrapper, never a compiler code.
    count = sum(line != 'error: test run failed' for line in headers)
    sites, unknown = [], 0
    for path, line, column in re.findall(r'^\s*--> ([^\s]+\.rs):(\d+):(\d+)\s*$', text, re.M):
        if path in inputs and path.startswith('crates/') and 0 < int(line) <= 1000000 and 0 < int(column) <= 1000000:
            if len(sites) < 64:
                sites.append({'path': path, 'line': int(line), 'column': int(column)})
            else:
                unknown += 1
        else:
            unknown += 1
    return {'codes': codes, 'header_count': count, 'sites': sites, 'unknown_or_excess_sites': unknown}


def panic_facts(raw, case):
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    sites, unknown = [], 0
    headers = re.findall(r"(?m)^[ \t]{0,8}thread '([^'\r\n]+)'(?: \([0-9]+\))? panicked at ([^\s]+\.rs):([0-9]+):([0-9]+):", text)
    for thread, path, line, column in headers:
        if path == CASES[case][2] and 0 < int(line) <= 1000000 and 0 < int(column) <= 1000000 and len(sites) < 8:
            sites.append({'expected_thread': thread == CASES[case][1], 'expected_source': True,
                          'line': int(line), 'column': int(column)})
        else:
            unknown += 1
    unknown += max(0, text.count('panicked at ') - len(headers))
    return {'sites': sites, 'unknown_or_excess_headers': unknown}


def summary_counts(raw):
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    found = re.findall(r'Summary\s+\[[^\]]+\]\s+(\d+)(?:/\d+)?\s+tests? run:\s*([^\n]*)', text)
    if len(found) != 1:
        return {'summary_count': len(found), 'counts': None}
    executed, tail = found[0]
    result = {'executed': int(executed)}
    for label in ['passed', 'failed', 'skipped']:
        matches = re.findall(r'(\d+) ' + label + r'\b', tail)
        if len(matches) > 1:
            return {'summary_count': 1, 'counts': None}
        result[label] = int(matches[0]) if matches else 0
    return {'summary_count': 1, 'counts': result}


def counts(raw, case):
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    result = summary_counts(raw)['counts']
    binary, test, _ = CASES[case]
    # Native nextest library display is the package, not Cargo's underscore
    # binary spelling. Integration display has either known qualified form.
    display = re.escape(package_for(case)) if case != 'offline' else r'(?:marmot-app::)?relay_runtime'
    names = re.findall(r'^\s*(PASS|FAIL)\s+\[[^\]]+\]\s+(?:\([ \t]{0,8}1/1\)[ \t]+)?' + display + r'\s+' + re.escape(test) + r'\s*$', text, re.M)
    if (result is None or result['executed'] != 1 or result['passed'] + result['failed'] != 1
            or len(names) != 1 or (names[0] == 'PASS') != (result['passed'] == 1)):
        raise ValueError('one-exact-runtime-body')
    return result


def selected_case(inventory, expected):
    selected = [(name, item['ignored']) for suite in inventory['rust-suites'].values()
                for name, item in suite['testcases'].items() if item['filter-match']['status'] == 'matches']
    if len(selected) != 1 or selected[0][0] != expected or selected[0][1] is not False:
        raise ValueError('inventory-shape')
    return 1


def controls():
    value = {key: 0 for key in SCALARS}
    value.update(completed=False, arrival_buckets_10s=[0] * 6, maximum_group_page=None,
                 runtime_operations=[[name, {key: 0 for key in ROW}] for name in sorted(OPERATIONS)])
    assert closed(value) == value
    raw = (PREFIX + json.dumps(value) + '\n').encode()
    assert marker(raw) == value
    bad = []
    for key, replacement in [('expected', True), ('stored', -1), ('projection_sum_ms', 2**64),
                             ('maximum_group_page', 'PRIVATE'), ('completed', 1),
                             ('arrival_buckets_10s', [0] * 5), ('runtime_operations', [])]:
        bad.append(dict(value, **{key: replacement}))
    bad.append(dict(value, private='PRIVATE'))
    row = json.loads(json.dumps(value)); row['runtime_operations'][0][0] = 'PRIVATE'; bad.append(row)
    row = json.loads(json.dumps(value)); row['runtime_operations'][0] = row['runtime_operations'][1]; bad.append(row)
    row = json.loads(json.dumps(value)); row['runtime_operations'][0][1]['private'] = 0; bad.append(row)
    row = json.loads(json.dumps(value)); row['runtime_operations'][0][1]['started'] = True; bad.append(row)
    row = json.loads(json.dumps(value)); del row['projection_attempts']; bad.append(row)
    negatives = 0
    for item in bad:
        try:
            closed(item)
        except ValueError:
            negatives += 1
        else:
            raise AssertionError('negative-schema-accepted')
    malformed = [raw + raw, b'PRIVATE ' + raw, raw.replace(b'"stored": 0', b'"stored": 0, "stored": 0'),
                 b' ' * 9 + raw, raw + b'PRIVATE ' + raw]
    for invalid in malformed:
        try:
            marker(invalid)
        except ValueError:
            negatives += 1
        else:
            raise AssertionError('negative-envelope-accepted')
    for case, (binary, test, source) in CASES.items():
        display = package_for(case) if case != 'offline' else 'marmot-app::relay_runtime'
        runtime = ('PASS [ 1.0s] ' + display + ' ' + test + '\nSummary [ 1s] 1 test run: 1 passed, 0 skipped\n').encode()
        assert counts(runtime, case)['passed'] == 1
        failed = runtime.replace(b'PASS [', b'FAIL [').replace(b'1 passed, 0 skipped', b'0 passed, 1 failed, 9 skipped')
        assert counts(failed, case)['failed'] == 1
        counter = failed.replace(('] ' + display + ' ').encode(), ('] (1/1) ' + display + ' ').encode())
        assert counts(counter, case)['failed'] == 1
        unknown_name = runtime.replace(test.encode(), b'PRIVATE')
        assert summary_counts(unknown_name)['counts']['passed'] == 1
        assert panic_facts(("thread '" + test + "' (7) panicked at " + source + ":1:2:\nPRIVATE\n").encode(), case)['sites'][0]['expected_thread']
        assert panic_facts(b"PRIVATE thread 'x' panicked at PRIVATE:1:2:\n", case)['unknown_or_excess_headers'] == 1
        assert compiler(b'error[E0308]: PRIVATE\n', {})['header_count'] == 1
        valid_inventory = {'rust-suites': {'fixed': {'testcases': {test: {'filter-match': {'status': 'matches'}, 'ignored': False}}}}}
        assert selected_case(valid_inventory, test) == 1
        for ignored in [True, 0, 'PRIVATE']:
            altered = json.loads(json.dumps(valid_inventory)); altered['rust-suites']['fixed']['testcases'][test]['ignored'] = ignored
            try:
                selected_case(altered, test)
            except ValueError:
                negatives += 1
            else:
                raise AssertionError('negative-inventory-accepted')
        for invalid in [runtime + runtime, unknown_name, runtime.replace(b'1 passed', b'0 passed'),
                        runtime.replace(b'1 test run', b'0 test run'), counter.replace(b'(1/1)', b'(2/1)'),
                        counter.replace(b'(1/1)', b'(1/2)'), runtime.replace(display.encode(), b'PRIVATE'),
                        runtime.replace(b'1 passed, 0 skipped', b'1 passed, 1 passed, 0 skipped')]:
            try:
                counts(invalid, case)
            except ValueError:
                negatives += 1
            else:
                raise AssertionError('negative-runtime-accepted')
    return {'schema_positive': 2, 'runtime_positive': 3 * len(CASES), 'negative': negatives,
            'synthetic_metadata_only': True, 'product_bodies': 0}


def snapshot():
    inputs = frozen_inputs()
    # No tracked ancestor may redirect otherwise-identical file bytes.
    for name in inputs:
        for parent in Path(name).parents:
            if parent != Path('.') and parent.is_symlink():
                raise ValueError('source-parent-symlink')
    return {'head': git('rev-parse', 'HEAD'), 'index': hashlib.sha256(subprocess.check_output(['git', 'ls-files', '--stage', '-z'])).hexdigest(),
            'inputs': inputs, 'tracked_clean': not git('diff', 'HEAD', '--name-only')}


PFP = {
    'inline': ('crates/marmot-app/src/client/sync.rs',
               '        self.observe_recovery_evidence(effects);\n        self.remember_pending_convergence_groups(effects);\n        self.remember_published_reports(effects);',
               '        self.observe_recovery_evidence(effects);\n        self.remember_published_reports(effects);',
               'inline epoch-change effects must notify the worker about the stale original leave',
               r'assert!\(\s*inline_epoch_change_wake_retained,\s*"{message}"\s*\);'),
    'spill': ('crates/marmot-app/src/client/delivery_spill.rs',
              '    pub(super) fn offer_cooperative_turn(&mut self) -> bool {\n        !std::mem::replace(&mut self.yield_offered, true)\n    }',
              '    pub(super) fn offer_cooperative_turn(&mut self) -> bool {\n        !std::mem::replace(&mut self.yield_offered, false)\n    }',
              'a cancelled cooperative offer must not be repeated before the same durable receive',
              r'panic!\(\s*"{message}"\s*\)'),
}


def inverse(case):
    path, old, new, message, pattern = PFP[case]
    original = Path(path).read_bytes()
    text = original.decode('utf-8')
    if text.count(old) != 1:
        raise ValueError('inverse-anchor')
    if case == 'inline':
        start = text.index('    fn retain_effect_projection(')
        end = text.index('    fn enqueue_effect_projection(', start)
        if old not in text[start:end]:
            raise ValueError('inverse-owner')
    fixture = Path(CASES[case][2]).read_text()
    found = list(re.finditer(pattern.replace('{message}', re.escape(message)), fixture))
    if len(found) != 1:
        raise ValueError('inverse-oracle-source')
    site = {'line': fixture[:found[0].start()].count('\n') + 1,
            'column': found[0].start() - fixture.rfind('\n', 0, found[0].start())}
    return path, original, text.replace(old, new, 1).encode(), site


def own_failure(raw, case, site):
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    if text.count('panicked at ') != 1:
        return False
    pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(CASES[case][1])
               + r"'(?: \([0-9]+\))? panicked at " + re.escape(CASES[case][2])
               + ':' + str(site['line']) + r':([0-9]+):[ \t]*\n(?:[ \t]*\n){0,2}'
               + re.escape(PFP[case][3]) + r'[ \t]*(?:\n|$)')
    match = re.search(pattern, text)
    return match is not None and 0 < int(match[1]) <= 1000000


def pfp_controls(case, site):
    header = ("thread '" + CASES[case][1] + "' (7) panicked at "
              + CASES[case][2] + ':' + str(site['line']) + ':' + str(site['column']) + ':\n')
    valid = (header + PFP[case][3] + '\n').encode()
    assert own_failure(valid, case, site)
    assert own_failure(valid.replace(b"' (7)", b"'"), case, site)
    invalid = [valid + valid, b'PRIVATE ' + valid, valid.replace(PFP[case][3].encode(), b'PRIVATE'),
               valid.replace(CASES[case][1].encode(), b'PRIVATE'),
               valid.replace(CASES[case][2].encode(), b'PRIVATE.rs'),
               valid.replace((':' + str(site['line']) + ':').encode(), b':999999:'),
               valid + b"thread 'PRIVATE' panicked at PRIVATE.rs:1:2:\n"]
    assert all(not own_failure(raw, case, site) for raw in invalid)
    return {'positive': 2, 'negative': len(invalid), 'synthetic_metadata_only': True, 'product_bodies': 0}


def pfp(args):
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {'case': args.case, 'stage': 'pfp', 'source': git('rev-parse', 'HEAD'),
              'baseline': args.baseline, 'qualification_passed': False, 'pfp_passed': False,
              'phases': [], 'automatic_retries': 0, 'profile': 'ci', 'features': LIB_FEATURES,
              'test_threads': 1, 'rust_min_stack': os.environ.get('RUST_MIN_STACK')}
    before, fd, original, identity, parents = None, None, None, None, None
    stage, result = 'admission', 1
    def save():
        temp = output.with_suffix('.pending')
        temp.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        temp.replace(output)
    def parent_chain(path):
        return [(str(parent), parent.lstat().st_dev, parent.lstat().st_ino)
                for parent in Path(path).parents if parent != Path('.')]
    def verify_target(path):
        current = Path(path).lstat()
        if (Path(path).is_symlink() or parent_chain(path) != parents
                or (current.st_dev, current.st_ino) != identity):
            raise ValueError('inverse-physical-source')
    def write_source(path, data, mode):
        verify_target(path)
        os.lseek(fd, 0, os.SEEK_SET)
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise ValueError('inverse-write')
            view = view[count:]
        os.ftruncate(fd, len(data))
        os.fchmod(fd, mode)
        os.fsync(fd)
    def phase(label, expected):
        if snapshot() != expected:
            raise ValueError('phase-source')
        row = {'phase': label, 'inventory_attempted': True,
               'source_manifest_sha256': hashlib.sha256(json.dumps(expected['inputs'], sort_keys=True).encode()).hexdigest()}
        report['phases'].append(row)
        save()
        flags = ['-p', 'marmot-app', '--lib', '--features', ','.join(LIB_FEATURES), '--locked', '--profile', 'ci']
        selection = 'package(marmot-app) & test(=' + CASES[args.case][1] + ')'
        code, raw, elapsed, stderr = capture(['cargo', 'nextest', 'list'] + flags + ['--message-format', 'json', '-E', selection], 1800, separate=True)
        row['inventory'] = {'exit_code': code, 'elapsed_seconds': elapsed,
                            'stdout_sha256': hashlib.sha256(raw).hexdigest(), 'stdout_bytes': len(raw),
                            'stderr_sha256': hashlib.sha256(stderr).hexdigest(), 'stderr_bytes': len(stderr),
                            'compiler': compiler(stderr, expected['inputs'])}
        save()
        if code != 0 or row['inventory']['compiler']['header_count'] or row['inventory']['compiler']['codes']:
            raise ValueError('phase-inventory-command')
        selected_case(json.loads(raw, object_pairs_hook=unique), CASES[args.case][1])
        row['inventory'].update(selected_nonignored=1, selected_ignored=0)
        save()
        if snapshot() != expected:
            raise ValueError('phase-inventory-source')
        row['body_attempted'] = True
        save()
        code, raw, elapsed, _ = capture(['cargo', 'nextest', 'run'] + flags + ['--retries', '0', '--test-threads', '1',
                                      '--status-level', 'pass', '--final-status-level', 'none', '--no-fail-fast',
                                      '--success-output', 'immediate', '-E', selection], 1800)
        row['body'] = {'exit_code': code, 'elapsed_seconds': elapsed, 'raw_bytes': len(raw),
                       'raw_sha256': hashlib.sha256(raw).hexdigest(), 'runtime_summary': summary_counts(raw),
                       'compiler': compiler(raw, expected['inputs']), 'panic': panic_facts(raw, args.case)}
        save()
        row['body']['counts'] = counts(raw, args.case)
        save()
        row['source_exact_after_body'] = snapshot() == expected
        clean_compile = not row['body']['compiler']['codes'] and row['body']['compiler']['header_count'] == 0
        if label == 'mutant':
            row['own_runtime_failure'] = own_failure(raw, args.case, site)
            row['accepted'] = (code == 100 and row['body']['counts']['failed'] == 1
                               and clean_compile and row['own_runtime_failure']
                               and row['source_exact_after_body'])
        else:
            row['accepted'] = (code == 0 and row['body']['counts']['passed'] == 1 and clean_compile
                               and row['body']['panic'] == {'sites': [], 'unknown_or_excess_headers': 0}
                               and row['source_exact_after_body'])
        save()
        if not row['accepted']:
            raise ValueError('phase-runtime-oracle')
    try:
        if args.case not in PFP:
            raise ValueError('unsupported-pfp-case')
        report['cohort'] = reviewed_cohort(args.baseline)
        ref = os.environ.get('GITHUB_REF', '')
        if (args.baseline != report['source'] or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
                or not ref.startswith('refs/heads/ci/upstream-develop-dy-')
                or os.environ.get('GITHUB_WORKFLOW_SHA') != report['source']
                or os.environ.get('GITHUB_WORKFLOW_REF') != 'dyKiU/mdk/.github/workflows/upstream-backend-probes.yml@' + ref):
            raise ValueError('pfp-identity')
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(), object_pairs_hook=unique)
        if any(event['inputs'].get(key) != value for key, value in
               [('scope', 'replay-controls'), ('replay_case', args.case), ('replay_stage', 'pfp'), ('reviewed_baseline', args.baseline)]):
            raise ValueError('pfp-inputs')
        before = snapshot()
        path, original, mutant, site = inverse(args.case)
        admitted_parents = parent_chain(path)
        report['mutated_source'] = {'path': path, 'original_sha256': hashlib.sha256(original).hexdigest(),
                                    'mutant_sha256': hashlib.sha256(mutant).hexdigest(), 'own_assert_site': site}
        report['parser_controls'] = controls()
        report['own_oracle_controls'] = pfp_controls(args.case, site)
        if args.mode == 'preflight':
            result = 0
        else:
            stage = 'environment'
            denied = ['RUST_MIN_STACK', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS',
                      'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP']
            if (any(os.environ.get(key) for key in denied)
                    or any(value for key, value in os.environ.items() if key.startswith('CARGO_TARGET_') and key.endswith('_RUSTFLAGS'))
                    or os.environ.get('CARGO_BUILD_JOBS') != '2' or os.environ.get('CARGO_INCREMENTAL') != '1'):
                raise ValueError('pfp-environment')
            stage = 'baseline'
            phase('baseline', before)
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
            info = os.fstat(fd)
            identity, parents = (info.st_dev, info.st_ino), admitted_parents
            verify_target(path)
            if os.read(fd, len(original) + 1) != original:
                raise ValueError('inverse-original-fd')
            mode = info.st_mode & 0o777
            primary_failure = None
            try:
                stage = 'mutant'
                write_source(path, mutant, mode)
                expected = json.loads(json.dumps(before))
                expected['inputs'][path]['sha256'] = hashlib.sha256(mutant).hexdigest()
                expected['tracked_clean'] = False
                phase('mutant', expected)
            except Exception:
                primary_failure = stage
                report['primary_failure_category'] = primary_failure
                save()
            finally:
                stage_before_restore = stage
                stage = 'restore'
                verify_target(path)
                if Path(path).read_bytes() != original or (Path(path).stat().st_mode & 0o777) != mode:
                    write_source(path, original, mode)
                report['source_restored'] = snapshot() == before
                save()
                stage = stage_before_restore
            if report.get('source_restored') is not True:
                raise ValueError('restore-source-closure')
            stage = 'restored'
            phase('restored', before)
            report['pfp_passed'] = (primary_failure is None and len(report['phases']) == 3
                                    and all(row.get('accepted') is True for row in report['phases']))
            result = 0 if report['pfp_passed'] else 1
            if primary_failure is not None:
                report['failure_category'] = primary_failure
    except Exception:
        report['failure_category'] = stage
    finally:
        if fd is not None:
            os.close(fd)
        try:
            report['source_closure_exact'] = before is not None and snapshot() == before
        except Exception:
            report['source_closure_exact'] = False
        if not report['source_closure_exact']:
            report['pfp_passed'] = False
            result = 1
        report['preflight_passed'] = args.mode == 'preflight' and result == 0
        save()
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['preflight', 'run'], required=True)
    parser.add_argument('--stage', choices=['positive', 'pfp'], default='positive')
    parser.add_argument('--case', choices=CASES, required=True)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if args.stage == 'pfp':
        return pfp(args)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    features = (['experimental-device-sync'] if args.case in STORAGE_CASES else
                LIB_FEATURES + ['marmot-app/experimental-device-sync'] if args.case in EXPERIMENTAL_CASES else
                ['test-policy-overrides'] if args.case == 'offline' else LIB_FEATURES)
    profile = 'm5-bounded' if args.case in EXPERIMENTAL_CASES else 'ci'
    expected_stack = '4194304' if args.case in EXPERIMENTAL_CASES else None
    package = package_for(args.case)
    report = {'case': args.case, 'diagnostic_only': True, 'qualification_passed': False,
              'body_passed': False, 'source': git('rev-parse', 'HEAD'), 'baseline': args.baseline,
              'features': features, 'profile': profile, 'package': package, 'automatic_retries': 0, 'test_threads': 1,
              'rust_min_stack': os.environ.get('RUST_MIN_STACK'), 'expected_test': CASES[args.case][1]}
    before = None
    stage = 'admission'
    result = 1
    def save():
        temporary = output.with_suffix('.pending')
        temporary.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        temporary.replace(output)
    try:
        report['cohort'] = reviewed_cohort(args.baseline)
        source = report['source']
        ref = os.environ.get('GITHUB_REF', '')
        if (args.baseline != source or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
                or not ref.startswith('refs/heads/ci/upstream-develop-dy-')
                or os.environ.get('GITHUB_WORKFLOW_SHA') != source
                or os.environ.get('GITHUB_WORKFLOW_REF') != 'dyKiU/mdk/.github/workflows/upstream-backend-probes.yml@' + ref):
            raise ValueError('replay-manual-source-identity')
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(), object_pairs_hook=unique)
        if (event['inputs'].get('scope') != 'replay-controls'
                or event['inputs'].get('replay_stage', 'positive') != 'positive'
                or event['inputs'].get('replay_case') != args.case
                or event['inputs'].get('reviewed_baseline') != args.baseline):
            raise ValueError('replay-event-inputs')
        before = snapshot()
        report['input_manifest_sha256'] = hashlib.sha256(json.dumps(before['inputs'], sort_keys=True).encode()).hexdigest()
        report['parser_controls'] = controls()
        if args.mode == 'preflight':
            result = 0
        else:
            stage = 'environment'
            denied = ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS',
                      'CARGO_ENCODED_RUSTDOCFLAGS', 'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP']
            if ((os.environ.get('RUST_MIN_STACK') or None) != expected_stack
                    or any(os.environ.get(key) for key in denied)
                    or any(value for key, value in os.environ.items() if key.startswith('CARGO_TARGET_') and key.endswith('_RUSTFLAGS'))
                    or os.environ.get('CARGO_BUILD_JOBS') != '2' or os.environ.get('CARGO_INCREMENTAL') != '1'):
                raise ValueError('replay-environment')
            binary, test, _ = CASES[args.case]
            flags = ['-p', package, '--test', binary] if args.case == 'offline' else ['-p', package, '--lib']
            flags += ['--features', ','.join(features), '--locked', '--profile', profile]
            selection = 'package(' + package + ') & test(=' + test + ')'
            if args.case == 'offline':
                selection += ' & binary(=relay_runtime)'
            stage = 'inventory-command'
            code, raw, elapsed, stderr = capture(['cargo', 'nextest', 'list'] + flags + ['--message-format', 'json', '-E', selection], 1800, separate=True)
            report['inventory'] = {'exit_code': code, 'elapsed_seconds': elapsed, 'stdout_bytes': len(raw),
                                   'stdout_sha256': hashlib.sha256(raw).hexdigest(), 'stderr_bytes': len(stderr),
                                   'stderr_sha256': hashlib.sha256(stderr).hexdigest(), 'compiler': compiler(stderr, before['inputs'])}
            save()
            if code != 0:
                raise ValueError('inventory-command')
            stage = 'inventory-shape'
            inventory = json.loads(raw, object_pairs_hook=unique)
            selected_case(inventory, test)
            report['inventory']['selected_nonignored'] = 1
            report['inventory']['selected_ignored'] = 0
            save()
            stage = 'inventory-source'
            if snapshot() != before:
                raise ValueError('inventory-source')
            stage = 'body-command'
            report['body_command_attempted'] = True
            save()
            code, raw, elapsed, _ = capture(['cargo', 'nextest', 'run'] + flags + ['--retries', '0', '--test-threads', '1',
                                          '--status-level', 'pass', '--final-status-level', 'none', '--no-fail-fast',
                                          '--success-output', 'immediate', '-E', selection], 1800)
            report['body'] = {'exit_code': code, 'elapsed_seconds': elapsed, 'raw_bytes': len(raw),
                              'raw_sha256': hashlib.sha256(raw).hexdigest(), 'compiler': compiler(raw, before['inputs']),
                              'panic': panic_facts(raw, args.case), 'runtime_summary': summary_counts(raw)}
            save()  # An actual attempted body survives any later parser/closure error.
            stage = 'runtime-shape'
            report['body']['counts'] = counts(raw, args.case)
            save()
            if args.case == 'offline':
                stage = 'diagnostic'
                report['body']['observation'] = marker(raw)
                save()
            stage = 'body-not-passed'
            report['body_passed'] = (code == 0 and report['body']['counts']['passed'] == 1
                                     and report['body']['compiler']['header_count'] == 0
                                     and not report['body']['compiler']['codes']
                                     and report['body']['panic'] == {'sites': [], 'unknown_or_excess_headers': 0})
            result = 0 if report['body_passed'] else 1
            if result:
                report['failure_category'] = 'body-not-passed'
    except Exception:
        report['failure_category'] = stage if stage in FAILURES else 'internal'
    finally:
        try:
            report['source_closure_exact'] = before is not None and snapshot() == before
        except Exception:
            report['source_closure_exact'] = False
        if not report['source_closure_exact']:
            report['failure_category'] = 'closure'
            report['body_passed'] = False
            result = 1
        report['preflight_passed'] = args.mode == 'preflight' and result == 0
        report['scoped_control_passed'] = args.mode == 'run' and result == 0
        save()
    return result


if __name__ == '__main__':
    raise SystemExit(main())
