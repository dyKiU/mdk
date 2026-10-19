"""Remote-only, one exact default-CI body; closed post-verdict observations only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time

from upstream_extraction_cohort import frozen_inputs, git, reviewed_cohort

CASES = {
    'key-package': ('marmot-app', 'relay_runtime',
                    'cancelled_key_package_setup_resumes_exact_pending_attempt_after_restart',
                    'crates/marmot-app/tests/relay_runtime.rs', 'key-package-cancel-control '),
    'avatar': ('wn-cli', 'cli', 'groups_set_avatar_url_round_trips_through_sync_and_show',
               'crates/cli/tests/cli.rs', 'avatar-clear-control '),
}
PHASES = {'local_state_created', 'local_ready', 'bootstrap_publication_started',
          'bootstrap_publication_confirmed', 'key_package_publication_started',
          'key_package_publication_confirmed', 'companion_ready'}
AVATAR = {'sender_clear_present', 'receiver_present', 'sync_events',
          'sync_projection_updates', 'sync_epoch_stall_escalations',
          'clear_published', 'clear_message_count', 'core_observation', 'ingest_observation'}
AVATAR_CORE = {'core_avatar_present', 'app_avatar_present', 'core_epoch', 'clear_receipt_cached'}
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
LIMIT = 16 * 1024 * 1024
PRIOR_COLLECTOR = '9d24755e3f48cc19fd0643c85b3e00f771e25da4'


def uint(value):
    return type(value) is int and 0 <= value <= 2**64 - 1


KP_RUNTIME_OPERATIONS = {
    'worker_acquire', 'lifecycle_lock_wait', 'account_startup_open_queued',
    'account_startup_account_state', 'account_startup_session_open',
    'account_startup_client_restore', 'account_startup_ready_handoff', 'worker_hydration',
}
KP_RUNTIME_FIELDS = {'started', 'completed', 'in_flight', 'oldest_tracked_in_flight_ms',
                     'untracked_in_flight', 'sum_ms'}
KP_APP_OPERATIONS = {'account_worker_readiness', 'account_initial_key_package_publish'}
KP_APP_FIELDS = {'attempts', 'successes', 'failures', 'sum_ms'}


def closed_key_package_telemetry(value):
    if not isinstance(value, dict) or set(value) != {'runtime_operations'} | KP_APP_OPERATIONS:
        raise ValueError('kp-telemetry-keys')
    runtime = value['runtime_operations']
    if not isinstance(runtime, dict) or set(runtime) != KP_RUNTIME_OPERATIONS:
        raise ValueError('kp-telemetry-inventory')
    for row, fields in [(runtime[name], KP_RUNTIME_FIELDS) for name in sorted(KP_RUNTIME_OPERATIONS)] + [
            (value[name], KP_APP_FIELDS) for name in sorted(KP_APP_OPERATIONS)]:
        # A missing/unknown row is not a fabricated zero. Refuse collection,
        # preserving independently parsed actual test counts before this call.
        if not isinstance(row, dict) or set(row) != fields or not all(uint(item) for item in row.values()):
            raise ValueError('kp-telemetry-row')
    return value


def telemetry_fixture():
    return {'runtime_operations': {name: {field: 0 for field in KP_RUNTIME_FIELDS}
                                   for name in KP_RUNTIME_OPERATIONS},
            **{name: {field: 0 for field in KP_APP_FIELDS} for name in KP_APP_OPERATIONS}}


def telemetry_controls():
    valid = telemetry_fixture()
    assert closed_key_package_telemetry(valid) == valid
    bad = []
    def changed():
        return json.loads(json.dumps(valid))
    row = changed(); del row['runtime_operations']['worker_acquire']; bad.append(row)
    row = changed(); row['runtime_operations']['PRIVATE'] = {}; bad.append(row)
    row = changed(); row['runtime_operations']['worker_acquire'] = None; bad.append(row)
    row = changed(); row['runtime_operations']['worker_acquire']['started'] = True; bad.append(row)
    row = changed(); row['runtime_operations']['worker_acquire']['sum_ms'] = 2**64; bad.append(row)
    row = changed(); row['runtime_operations']['worker_acquire']['private'] = 'PRIVATE'; bad.append(row)
    row = changed(); row['account_worker_readiness']['attempts'] = 'PRIVATE'; bad.append(row)
    row = changed(); del row['account_initial_key_package_publish']; bad.append(row)
    for value in bad:
        try:
            closed_key_package_telemetry(value)
        except ValueError:
            pass
        else:
            raise AssertionError('kp-telemetry-negative-accepted')
    assert 'PRIVATE' not in json.dumps(closed_key_package_telemetry(valid))
    return {'positive': 1, 'negative': len(bad)}

NATIVE_STAGES = {
    'attachment_task_queued', 'account_resolution', 'account_storage_cache', 'storage_admission',
    'database_open_lock', 'signing_keys', 'external_database_secret', 'key_derivation', 'salt_read',
    'recovery_probe', 'recovery_rekey', 'encrypted_store_open', 'cipher_configuration',
    'cipher_key_application', 'operational_pragmas', 'migration_inspection', 'migration_apply',
    'attachment_local_read', 'attachment_future_wait', 'product_analytics_admission',
}
NATIVE_BOOLEANS = {'enabled', 'bounded', 'observations_present', 'monotonic', 'overflow',
                   'observed_intervals_usable', 'retained_intervals_complete'}
NATIVE_NUMBERS = {'history_events', 'active_scopes', 'dropped_events', 'dropped_scopes',
                  'duplicate_entries', 'unattributed_prefix_ms', 'unknown_stages', 'metadata_controls_passed'}
NATIVE_FIELDS = {'events', 'active', 'observed_interval_ms', 'max_active_stage_ms'}


def closed_native_summary(value):
    if not isinstance(value, dict) or set(value) != NATIVE_BOOLEANS | NATIVE_NUMBERS | {'stages'}:
        raise ValueError('native-summary-keys')
    if any(type(value[key]) is not bool for key in NATIVE_BOOLEANS) or not all(uint(value[key]) for key in NATIVE_NUMBERS):
        raise ValueError('native-summary-types')
    rows = value['stages']
    if not isinstance(rows, dict) or set(rows) != NATIVE_STAGES:
        raise ValueError('native-stage-inventory')
    if any(not isinstance(row, dict) or set(row) != NATIVE_FIELDS or not all(uint(item) for item in row.values())
           for row in rows.values()):
        raise ValueError('native-stage-types')
    history, active = value['history_events'], value['active_scopes']
    if history > 96 or active > 16 or not value['bounded'] or value['metadata_controls_passed'] != 11:
        raise ValueError('native-bounds')
    if (sum(row['events'] + row['active'] for row in rows.values()) + value['unknown_stages'] != history + active
            or value['observations_present'] != (history + active > 0)):
        raise ValueError('native-inventory-counts')
    usable = value['monotonic'] and not value['overflow'] and value['unknown_stages'] == 0
    complete = (value['enabled'] and usable and value['observations_present']
                and value['duplicate_entries'] == 0 and value['unattributed_prefix_ms'] == 0
                and value['dropped_events'] == 0 and value['dropped_scopes'] == 0)
    if value['observed_intervals_usable'] != usable or value['retained_intervals_complete'] != complete:
        raise ValueError('native-completeness-flags')
    return value


def native_fixture():
    value = {key: 0 for key in NATIVE_NUMBERS}
    value.update({key: True for key in NATIVE_BOOLEANS})
    value.update({'overflow': False, 'history_events': 1, 'metadata_controls_passed': 11,
                  'stages': {name: {field: 0 for field in NATIVE_FIELDS} for name in NATIVE_STAGES}})
    value['stages']['key_derivation']['events'] = 1
    return value


def native_controls():
    valid = native_fixture()
    assert closed_native_summary(valid) == valid
    positives = 1
    for field in ('dropped_events', 'dropped_scopes', 'duplicate_entries', 'unattributed_prefix_ms'):
        partial = json.loads(json.dumps(valid)); partial[field] = 1
        partial['retained_intervals_complete'] = False
        assert closed_native_summary(partial)['retained_intervals_complete'] is False
        positives += 1
    partial = json.loads(json.dumps(valid)); partial['monotonic'] = False
    partial['observed_intervals_usable'] = False; partial['retained_intervals_complete'] = False
    assert closed_native_summary(partial)['observed_intervals_usable'] is False
    positives += 1
    partial = json.loads(json.dumps(valid)); partial['unknown_stages'] = 1
    partial['stages']['key_derivation']['events'] = 0
    partial['observed_intervals_usable'] = False; partial['retained_intervals_complete'] = False
    assert closed_native_summary(partial)['observed_intervals_usable'] is False
    positives += 1
    bad = []
    def changed():
        return json.loads(json.dumps(valid))
    row = changed(); row['stages']['PRIVATE'] = {}; bad.append(row)
    row = changed(); row['token'] = 1; bad.append(row)
    row = changed(); row['stages']['key_derivation']['observed_interval_ms'] = 'PRIVATE'; bad.append(row)
    row = changed(); del row['stages']['key_derivation']; bad.append(row)
    row = changed(); row['dropped_events'] = 1; bad.append(row)
    row = changed(); row['observed_intervals_usable'] = False; bad.append(row)
    row = changed(); row['history_events'] = True; bad.append(row)
    row = changed(); row['active_scopes'] = 17; bad.append(row)
    row = changed(); row['metadata_controls_passed'] = 0; bad.append(row)
    for value in bad:
        try:
            closed_native_summary(value)
        except ValueError:
            pass
        else:
            raise AssertionError('native-negative-accepted')
    assert 'PRIVATE' not in json.dumps(valid)
    return {'positive': positives, 'negative': len(bad)}


AVATAR_INGEST_BOUNDARIES = {'account_ingest', 'receive_receipt_skip',
                           'recovery_receipt_skip', 'drain_receipt_skip'}
AVATAR_INGEST_OUTCOMES = {'processed', 'buffered', 'transport_deferred', 'local_state',
                         'stale', 'rejected', 'ignored_duplicate', 'ignored_own_echo',
                         'ignored_other', 'resource_refused', 'error', 'cached_receipt'}


def closed_avatar_ingest(value):
    if (not isinstance(value, dict) or set(value) != {'rows', 'complete'}
            or type(value['complete']) is not bool or not isinstance(value['rows'], list)
            or len(value['rows']) > 8):
        raise ValueError('avatar-ingest-collection')
    for row in value['rows']:
        if (not isinstance(row, dict) or set(row) != {'boundary', 'outcome', 'left_object_unpersisted'}
                or type(row['boundary']) is not str or type(row['outcome']) is not str
                or row['boundary'] not in AVATAR_INGEST_BOUNDARIES
                or row['outcome'] not in AVATAR_INGEST_OUTCOMES):
            raise ValueError('avatar-ingest-row')
        boundary, outcome, left = row['boundary'], row['outcome'], row['left_object_unpersisted']
        if boundary == 'account_ingest':
            valid = left is None if outcome == 'error' else type(left) is bool and outcome != 'cached_receipt'
        else:
            valid = outcome == 'cached_receipt' and left is None
        if not valid:
            raise ValueError('avatar-ingest-coherence')
    # complete means bounded capture/grammar only; zero rows is not proof that
    # the event never arrived or that no earlier/other path handled it.
    return value


def avatar_ingest_fixture(boundary='account_ingest', outcome='processed', left=False):
    return {'rows': [{'boundary': boundary, 'outcome': outcome, 'left_object_unpersisted': left}],
            'complete': True}


def avatar_ingest_controls():
    positives = 0
    valid = avatar_ingest_fixture()
    cases = [avatar_ingest_fixture(outcome=name) for name in sorted(AVATAR_INGEST_OUTCOMES - {'error', 'cached_receipt'})]
    cases += [avatar_ingest_fixture(outcome='error', left=None)]
    cases += [avatar_ingest_fixture(name, 'cached_receipt', None)
              for name in sorted(AVATAR_INGEST_BOUNDARIES - {'account_ingest'})]
    cases += [{'rows': [], 'complete': True}, {'rows': [], 'complete': False},
              {'rows': valid['rows'] * 8, 'complete': True},
              dict(valid, complete=False)]
    for value in cases:
        assert closed_avatar_ingest(value) == value
        positives += 1
    def changed():
        return json.loads(json.dumps(valid))
    bad = [None, [], dict(valid, private='PRIVATE'), dict(valid, complete=1),
           dict(valid, complete=None), dict(valid, rows='PRIVATE'),
           dict(valid, rows=valid['rows'] * 9), dict(valid, rows=[None]),
           dict(valid, rows=[['PRIVATE']])]
    for field, value in [('boundary', 'PRIVATE'), ('outcome', 'PRIVATE'),
                         ('boundary', ['PRIVATE']), ('outcome', {'private': 'PRIVATE'}),
                         ('left_object_unpersisted', 1), ('left_object_unpersisted', None)]:
        row = changed(); row['rows'][0][field] = value; bad.append(row)
    row = changed(); row['rows'][0]['private'] = 'PRIVATE'; bad.append(row)
    row = changed(); del row['rows'][0]['outcome']; bad.append(row)
    row = changed(); del row['complete']; bad.append(row)
    bad += [avatar_ingest_fixture(outcome='cached_receipt', left=None),
            avatar_ingest_fixture(outcome='error', left=False),
            avatar_ingest_fixture('drain_receipt_skip', 'processed', False),
            avatar_ingest_fixture('drain_receipt_skip', 'cached_receipt', True)]
    for value in bad:
        try:
            closed_avatar_ingest(value)
        except ValueError:
            pass
        else:
            raise AssertionError('avatar-ingest-negative-accepted')
    assert all('PRIVATE' not in json.dumps(closed_avatar_ingest(value)) for value in cases)
    return {'positive': positives, 'negative': len(bad)}


def closed_marker(case, value):
    if not isinstance(value, dict):
        raise ValueError('marker-shape')
    if case == 'key-package':
        if set(value) != {'observed', 'elapsed_ms', 'setup_finished', 'journal_read_ok', 'journal_phase', 'telemetry', 'native'}:
            raise ValueError('marker-keys')
        if any(type(value[k]) is not bool for k in ('observed', 'setup_finished', 'journal_read_ok')):
            raise ValueError('marker-bool')
        if value['elapsed_ms'] is not None and not uint(value['elapsed_ms']):
            raise ValueError('marker-duration')
        if value['journal_phase'] is not None and value['journal_phase'] not in PHASES:
            raise ValueError('marker-phase')
        closed_key_package_telemetry(value['telemetry'])
        closed_native_summary(value['native'])
    else:
        if set(value) != AVATAR:
            raise ValueError('marker-keys')
        for key, item in value.items():
            if key == 'ingest_observation':
                closed_avatar_ingest(item)
                continue
            if key == 'core_observation':
                if not isinstance(item, dict) or set(item) != AVATAR_CORE:
                    raise ValueError('avatar-core-shape')
                for field, fact in item.items():
                    valid = uint(fact) if field == 'core_epoch' else type(fact) is bool
                    if fact is not None and not valid:
                        raise ValueError('avatar-core-type')
                continue
            valid = type(item) is bool if key in {'sender_clear_present', 'receiver_present'} else uint(item)
            if item is not None and not valid:
                raise ValueError('marker-type')
    return value


def parse_marker(case, raw):
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    prefix = CASES[case][4]
    found = []
    for line in text.splitlines():
        if prefix in line:
            # No arbitrary prefix/suffix, duplicate keys or private strings survive.
            envelope = re.fullmatch(r'[ \t]{0,8}' + re.escape(prefix) + r'(\{[^\r\n]*\})[ \t]{0,8}', line)
            if envelope is None or len(line) > (16384 if case == 'key-package' else 4096):
                raise ValueError('marker-envelope')
            payload = envelope[1]
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError('marker-duplicate-key')
                    result[key] = value
                return result
            found.append(closed_marker(case, json.loads(payload, object_pairs_hook=unique)))
    if len(found) != 1:
        raise ValueError('marker-cardinality')
    return found[0]


def parse_core(case, raw):
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    package, binary, test, source, _ = CASES[case]
    summaries = re.findall(r'Summary\s+\[[^\]]+\]\s+(\d+)(?:/\d+)?\s+tests? run:\s*([^\n]*)', text)
    if len(summaries) != 1:
        raise ValueError('summary-cardinality')
    executed, tail = summaries[0]
    def count(label):
        matches = re.findall(r'(\d+) ' + label + r'\b', tail)
        if len(matches) > 1:
            raise ValueError('summary-duplicate')
        return int(matches[0]) if matches else 0
    counts = {'executed': int(executed), 'passed': count('passed'), 'failed': count('failed'),
              'skipped': count('skipped')}
    named = re.findall(r'^\s*(PASS|FAIL)\s+\[[^\]]+\]\s+(?:\([ \t]{0,8}1/1\)[ \t]+)?' + r'(?:' + re.escape(package) + r'::)?' + re.escape(binary) + r'\s+' + re.escape(test) + r'\s*$', text, re.M)
    if counts['executed'] != 1 or counts['passed'] + counts['failed'] != 1 or len(named) != 1:
        raise ValueError('actual-one-named-body')
    if (named[0] == 'PASS') != (counts['passed'] == 1):
        raise ValueError('body-summary-mismatch')
    codes = sorted(set(re.findall(r'\berror\[(E\d{4})\]', text)))
    headers = [line for line in text.splitlines() if re.match(r'^error(?:\[E\d{4}\])?:', line)
               and not re.match(r'^error: test run failed\s*$', line)]
    sites = []
    for path, line, column in re.findall(r'panicked at ([^\s]+\.rs):(\d+):(\d+):', text):
        if path == source and 1 <= int(line) <= 1_000_000 and 1 <= int(column) <= 1_000_000:
            sites.append({'expected_source': True, 'line': int(line), 'column': int(column)})
    return {'counts': counts, 'named_case_observed': True,
            'compiler_codes': codes, 'compiler_header_count': len(headers),
            'expected_source_panic_sites': sites,
            'raw_sha256': hashlib.sha256(raw).hexdigest(), 'raw_bytes': len(raw)}


def parse(case, raw):
    result = parse_core(case, raw)
    result['observation'] = parse_marker(case, raw)
    return result


def capture(command, timeout, separate=False):
    """Bounded RAM and runner-temp only; never tee private test output."""
    start = time.monotonic()
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE if separate else subprocess.STDOUT, start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, 'stdout')
    if separate:
        selector.register(proc.stderr, selectors.EVENT_READ, 'stderr')
    raw = {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        while selector.get_map():
            if time.monotonic() - start > timeout:
                raise TimeoutError('bounded-command-timeout')
            for key, _ in selector.select(1):
                block = os.read(key.fd, 65536)
                if not block:
                    selector.unregister(key.fileobj)
                else:
                    raw[key.data].extend(block)
                    if sum(map(len, raw.values())) > LIMIT:
                        raise ValueError('bounded-command-output')
        code = proc.wait(timeout=5)
        return code, bytes(raw['stdout']), round(time.monotonic() - start, 3), bytes(raw['stderr'])
    finally:
        selector.close()
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=10)


def parser_controls():
    # Authored controls execute only on the remote preflight lane.
    positives = 0
    negatives = 0
    historical = {'__name__': 'historical_closed_collector'}
    prior = git('show', PRIOR_COLLECTOR + ':scripts/upstream_current_backend_probe.py')
    exec(compile(prior, '<immutable-prior-collector>', 'exec'), historical)
    counter_regressions = 0
    for case in CASES:
        values = ({'observed': False, 'elapsed_ms': 10000, 'setup_finished': False,
                   'journal_read_ok': True, 'journal_phase': 'local_state_created',
                   'telemetry': telemetry_fixture(), 'native': native_fixture()}
                  if case == 'key-package' else dict({key: None for key in AVATAR},
                      core_observation={key: None for key in AVATAR_CORE},
                      ingest_observation={'rows': [], 'complete': True}))
        package, binary, test, source, prefix = CASES[case]
        raw = (prefix + json.dumps(values) + '\nFAIL [1s] ' + binary + ' ' + test + '\n'
               + "thread 'PRIVATE' panicked at " + source + ':2206:10:\nPRIVATE_PAYLOAD\n'
               + 'Summary [1s] 1 test run: 0 passed, 1 failed, 99 skipped\nerror: test run failed\n').encode()
        result = parse(case, raw)
        assert result['compiler_header_count'] == 0 and 'PRIVATE' not in json.dumps(result)
        positives += 1
        counter = raw.replace(('] ' + binary + ' ').encode(), ('] (  1/1) ' + package + '::' + binary + ' ').encode())
        # Real prior helper accepts its old envelope, rejects the pinned nextest
        # progress-counter envelope, and the corrected helper accepts that envelope.
        assert historical['parse_core'](case, raw)['counts']['failed'] == 1
        try:
            historical['parse_core'](case, counter)
        except ValueError:
            pass
        else:
            raise AssertionError('historical-counter-regression-not-reproduced')
        assert parse(case, counter)['counts']['failed'] == 1
        counter_regressions += 1
        assert parse(case, raw.replace(('] ' + binary + ' ').encode(), ('] ' + package + '::' + binary + ' ').encode()))['named_case_observed']
        positives += 1
        missing = raw.replace(prefix.encode(), b'uncollected-control ')
        partial = parse_core(case, missing)
        assert partial['counts']['failed'] == 1 and partial['compiler_header_count'] == 0
        assert 'observation' not in partial and 'PRIVATE' not in json.dumps(partial)
        positives += 1
        altered = [counter.replace(b'1/1)', b'2/1)'), counter.replace(b'1/1)', b'1/2)'),
                   raw.replace(prefix.encode(), b'private-control '), raw + raw,
                   raw.replace(prefix.encode(), b'PRIVATE ' + prefix.encode()),
                   raw.replace(prefix.encode(), b'{\"private\":\"PRIVATE\"} ' + prefix.encode()),
                   raw.replace(test.encode(), b'wrong_test'), raw.replace(b'1 test run', b'0 test run'),
                   raw.replace(b'0 passed, 1 failed', b'0 passed, 0 failed'),
                   raw.replace(('] ' + binary + ' ').encode(), ('] wrong-package::' + binary + ' ').encode())]
        bad_values = [dict(values, private='PRIVATE'), {}]
        if case == 'key-package':
            bad_values += [dict(values, journal_phase='PRIVATE'), dict(values, elapsed_ms=True)]
        else:
            bad_values += [dict(values, receiver_present='PRIVATE'), dict(values, sync_events=True)]
            bad_values += [dict(values, core_observation=None),
                           dict(values, core_observation={'private': 'PRIVATE'}),
                           dict(values, core_observation=dict(values['core_observation'], core_epoch=True))]
        altered += [raw.replace(json.dumps(values).encode(), json.dumps(v).encode()) for v in bad_values]
        for invalid in altered:
            try:
                parse(case, invalid)
            except (ValueError, TypeError):
                negatives += 1
            else:
                raise AssertionError('negative-control-accepted')
        assert parse(case, raw + b'error[E0308]: PRIVATE\n')['compiler_header_count'] == 1
        positives += 1
    closure_report = {'body_passed': True, 'body': {'counts': {'passed': 1}}}
    def broken_probe():
        raise FileNotFoundError('PRIVATE')
    assert not close_inputs(closure_report, {}, broken_probe, lambda: '')
    assert closure_report['body']['counts']['passed'] == 1
    assert closure_report['body_passed'] is False
    assert closure_report['all_tracked_inputs_exact'] is False
    assert closure_report['git_pristine'] is False
    assert closure_report['closure_exception_class'] == 'FileNotFoundError'
    assert 'PRIVATE' not in json.dumps(closure_report)
    return {'positive': positives, 'negative': negatives, 'closure_fault_controls': 1,
            'historical_counter_regressions': counter_regressions,
            'historical_collector': PRIOR_COLLECTOR,
            'key_package_telemetry_controls': telemetry_controls(),
            'key_package_native_controls': native_controls(),
            'avatar_ingest_controls': avatar_ingest_controls()}


def close_inputs(report, before, input_probe=frozen_inputs, diff_probe=None):
    try:
        report['all_tracked_inputs_exact'] = before is not None and input_probe() == before
        report['git_pristine'] = not (diff_probe() if diff_probe else git('diff', 'HEAD', '--name-only'))
    except Exception as error:
        report['all_tracked_inputs_exact'] = False
        report['git_pristine'] = False
        report['closure_exception_class'] = type(error).__name__
    exact = report['all_tracked_inputs_exact'] and report['git_pristine']
    if not exact:
        report['body_passed'] = False
    return exact


def main():
    os.umask(0o077)
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument('--case', choices=CASES, required=True)
    args.add_argument('--baseline', required=True)
    args.add_argument('--mode', choices=('preflight', 'run'), required=True)
    args.add_argument('--output', required=True)
    options = args.parse_args()
    output = Path(options.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {'case': options.case, 'source': git('rev-parse', 'HEAD'), 'qualification_passed': False,
              'automatic_retries': 0, 'profile': 'ci', 'features': ['test-policy-overrides'],
              'status_level': 'pass', 'final_status_level': 'none',
              'rust_min_stack': os.environ.get('RUST_MIN_STACK'), 'diagnostic_only': True,
              'expected_package': CASES[options.case][0], 'expected_binary': CASES[options.case][1],
              'expected_test': CASES[options.case][2], 'trusted_test_source': CASES[options.case][3]}
    def save():
        output.write_text(json.dumps(report, indent=2) + '\n')
    before = None
    exit_code = 1
    try:
        report['cohort'] = reviewed_cohort(options.baseline)
        before = frozen_inputs()
        report['parser_controls'] = parser_controls()
        if options.mode == 'preflight':
            exit_code = 0
        else:
            if os.environ.get('RUST_MIN_STACK') or os.environ.get('RUSTFLAGS') or os.environ.get('CARGO_ENCODED_RUSTFLAGS'):
                raise ValueError('default-cohort-launch-environment')
            package, binary, test, _, _ = CASES[options.case]
            base = ['cargo', 'nextest']
            flags = ['-p', package, '--test', binary, '--features', 'test-policy-overrides', '--locked', '--profile', 'ci']
            selection = 'package(' + package + ') & binary(=' + binary + ') & test(=' + test + ')'
            code, raw, elapsed, compiler = capture(base + ['list'] + flags + ['--message-format', 'json', '-E', selection], 1200, separate=True)
            report['inventory_exit'] = code
            report['inventory_elapsed_seconds'] = elapsed
            report['inventory_raw_sha256'] = hashlib.sha256(raw).hexdigest()
            report['inventory_stderr_sha256'] = hashlib.sha256(compiler).hexdigest()
            report['inventory_stdout_bytes'] = len(raw)
            report['inventory_stderr_bytes'] = len(compiler)
            report['inventory_compiler_codes'] = sorted(set(re.findall(rb'error\[(E[0-9]{4})\]', compiler)))
            report['inventory_compiler_codes'] = [value.decode('ascii') for value in report['inventory_compiler_codes']]
            save()
            if code != 0:
                raise ValueError('inventory-compile-failed')
            inventory = json.loads(raw)
            selected = [name for suite in inventory['rust-suites'].values()
                        for name, item in suite['testcases'].items()
                        if item['filter-match']['status'] == 'matches' and not item['ignored']]
            if len(selected) != 1 or selected[0] != test:
                raise ValueError('inventory-not-one-exact-case')
            if frozen_inputs() != before or git('diff', 'HEAD', '--name-only'):
                raise ValueError('inventory-source-changed')
            report['selected_nonignored'] = 1
            code, raw, elapsed, _ = capture(base + ['run'] + flags + ['--retries', '0', '--test-threads', '1',
                                      '--status-level', 'pass', '--final-status-level', 'none',
                                      '--no-fail-fast', '--success-output', 'immediate', '-E', selection], 1200)
            report['body'] = {'exit_code': code, 'elapsed_seconds': elapsed,
                              'raw_sha256': hashlib.sha256(raw).hexdigest(), 'raw_bytes': len(raw)}
            save()  # Actual execution survives parser failure.
            report['body'].update(parse_core(options.case, raw))
            report['marker_collection_complete'] = False
            save()  # Preserve actual named-body counts/compiler facts before marker validation.
            report['body']['observation'] = parse_marker(options.case, raw)
            report['marker_collection_complete'] = True
            report['body_passed'] = (code == 0 and report['body']['counts']['passed'] == 1
                                     and report['body']['compiler_header_count'] == 0
                                     and not report['body']['compiler_codes'])
            exit_code = 0 if report['body_passed'] else 1
    except Exception as error:
        # Closed class only; exception text can contain private test payloads.
        report['controller_exception_class'] = type(error).__name__
    finally:
        if not close_inputs(report, before):
            exit_code = 1
        save()
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
