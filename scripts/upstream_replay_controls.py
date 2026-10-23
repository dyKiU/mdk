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
from upstream_offline_fingerprints import controls as fingerprint_controls, snapshot as fingerprint_snapshot

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
    'worker-input-offer': ('marmot_app', 'runtime::account_worker::tests::worker_input_selection_tests::owed_offer_selects_ready_delivery_and_preserves_replay',
                         'crates/marmot-app/src/runtime/account_worker/tests/worker_input_selection_tests.rs'),
    'worker-input-replay-first': ('marmot_app', 'runtime::account_worker::tests::worker_input_selection_tests::ordinary_turn_selects_ready_replay_and_preserves_delivery',
                         'crates/marmot-app/src/runtime/account_worker/tests/worker_input_selection_tests.rs'),
    'worker-input-pending': ('marmot_app', 'runtime::account_worker::tests::worker_input_selection_tests::owed_pending_receive_allows_replay_and_later_real_delivery',
                         'crates/marmot-app/src/runtime/account_worker/tests/worker_input_selection_tests.rs'),
    'worker-input-disabled': ('marmot_app', 'runtime::account_worker::tests::worker_input_selection_tests::disabled_receive_selects_replay_and_retains_ready_packet',
                         'crates/marmot-app/src/runtime/account_worker/tests/worker_input_selection_tests.rs'),
    'adapter-thousand-default': ('relay_limit_subscriptions', 'a_thousand_groups_fit_in_a_few_reqs_and_every_group_delivers',
                         'crates/transport-nostr-adapter/tests/relay_limit_subscriptions.rs'),
    'adapter-thousand': ('relay_limit_subscriptions', 'a_thousand_groups_fit_in_a_few_reqs_and_every_group_delivers',
                         'crates/transport-nostr-adapter/tests/relay_limit_subscriptions.rs'),
    'adapter-clamped': ('relay_limit_subscriptions', 'stored_replay_beyond_500_is_paged_before_counting_complete',
                        'crates/transport-nostr-adapter/tests/relay_limit_subscriptions.rs'),
    'hidden-echo': ('marmot_app', 'runtime::device_linking::tests::device_linking_hidden_route_unknown_reopen_and_refresh_use_real_echo',
                    'crates/marmot-app/src/runtime/device_linking.rs'),
    'departure-native': ('marmot_app', 'native_device_linking::tests::automatic_account_departure_acceptance::account_departure_completes_when_own_leave_precedes_replayed_proposal',
                         'crates/marmot-app/src/native_device_linking/tests/automatic_account_departure_acceptance.rs'),
    'revoked-anchor': ('storage_sqlite', 'revoked_device_group_anchor::tests::revoked_anchor_encrypted_reopen_and_group_deletion_preserve_terminal_bytes',
                       'crates/storage-sqlite/src/revoked_device_group_anchor/tests.rs'),
    'sharing-policy': ('storage_sqlite', 'approved_account_sharing_policy::tests::sharing_policy_encrypted_restart_retains_sequences_revocation_and_closed_owner',
                       'crates/storage-sqlite/src/approved_account_sharing_policy/tests.rs'),
    'late-consent': ('marmot_app', 'native_device_linking::automatic_pairing_acceptance::late_sibling_consent_acceptance::authenticated_late_consent_starts_initial_proof_without_periodic_tick',
                     'crates/marmot-app/src/native_device_linking/tests/late_sibling_consent_acceptance.rs'),
    'mirrored-catalog': ('storage_sqlite', 'mirrored_chat_catalog::tests::mirrored_catalog_encrypted_reopen_preserves_terminal_fence_and_close_is_final',
                         'crates/storage-sqlite/src/mirrored_chat_catalog/tests.rs'),
    'mirrored-messages': ('storage_sqlite', 'mirrored_chat_messages::tests::mirrored_messages_encrypted_restart_retains_body_and_terminal_close_is_final',
                          'crates/storage-sqlite/src/mirrored_chat_messages/tests.rs'),
    'adapter-cancelled': ('transport_nostr_adapter', 'sdk_client::tests::enrollment_acquisition_cancelled_issued_request_revokes_freshness_and_can_reactivate',
                          'crates/transport-nostr-adapter/src/sdk_client.rs'),
    'adapter-failed-route': ('transport_nostr_adapter', 'sdk_client::tests::enrollment_acquisition_failed_private_route_sync_burns_freshness_until_valid_reissue',
                             'crates/transport-nostr-adapter/src/sdk_client.rs'),
    'existing-anchor': ('storage_sqlite', 'existing_device_group_anchor::tests::existing_anchor_encrypted_reopen_preserves_denial_and_original_bytes',
                        'crates/storage-sqlite/src/existing_device_group_anchor/tests.rs'),
    'command-backlog': ('marmot_app', 'native_device_linking::automatic_pairing_acceptance::command_backlog_acceptance::authenticated_body_is_serviced_before_eight_queued_history_reads',
                        'crates/marmot-app/src/native_device_linking/tests/command_backlog_acceptance.rs'),
    'higher-source': ('marmot_app', 'native_device_linking::tests::pending_restart_higher_source_delivers_catalog_and_record',
                      'crates/marmot-app/src/client/account_chat_sharing/automatic/tests/pending_restart_acceptance.rs'),
    'spill-experimental': CASES['spill'],
    'watch-pressure': ('marmot_app', 'native_device_linking::automatic_pairing_acceptance::watch_pressure_acceptance::authenticated_body_is_serviced_before_eight_ready_watch_services',
                       'crates/marmot-app/src/native_device_linking/tests/watch_pressure_acceptance.rs'),
})
EXPERIMENTAL_CASES = {'worker-input-offer', 'worker-input-replay-first', 'worker-input-pending', 'worker-input-disabled', 'adapter-thousand', 'adapter-clamped', 'hidden-echo', 'departure-native', 'existing-anchor', 'command-backlog', 'adapter-cancelled', 'adapter-failed-route', 'mirrored-catalog', 'mirrored-messages', 'revoked-anchor', 'sharing-policy', 'late-consent', 'spill-experimental', 'watch-pressure', 'higher-source'}
STORAGE_CASES = {'existing-anchor', 'revoked-anchor', 'sharing-policy', 'mirrored-catalog', 'mirrored-messages'}

BOUNDED_CASES = EXPERIMENTAL_CASES | {'adapter-thousand-default'}
THOUSAND_CASES = {'adapter-thousand', 'adapter-thousand-default'}
ADAPTER_CASES = {'adapter-thousand-default', 'adapter-cancelled', 'adapter-failed-route', 'adapter-thousand', 'adapter-clamped'}
INTEGRATION_CASES = {'adapter-thousand-default', 'offline', 'adapter-thousand', 'adapter-clamped'}
SDK_REPLAY_CASES = THOUSAND_CASES | {'adapter-clamped'}
WORKER_INPUT_CASES = {'worker-input-offer', 'worker-input-replay-first', 'worker-input-pending', 'worker-input-disabled'}


def package_for(case):
    if case in ADAPTER_CASES:
        return 'transport-nostr-adapter'
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


RESTART_PREFIX = 'pending-restart-approval '
RESTART_OPTIONAL = {'lower_is_recipient', 'lower_ready', 'lower_handshake_published',
                    'lower_original_live', 'lower_nonce_matches_x', 'lower_request_content_exists',
                    'higher_is_recipient', 'higher_ready', 'higher_handshake_published',
                    'higher_nonce_matches_x', 'higher_channel_core_valid',
                    'higher_request_row_read_succeeded', 'higher_request_processed'}


def restart_closed(value):
    fields = {'approval_completed', 'sync_started', 'sync_completed', 'approval_elapsed_ms',
              'failure_snapshot_collected', 'failure_snapshot'}
    if type(value) is not dict or set(value) != fields:
        raise ValueError('restart-fields')
    if (any(type(value[key]) is not bool for key in ['approval_completed', 'failure_snapshot_collected'])
            or any(not uint(value[key]) for key in ['sync_started', 'sync_completed', 'approval_elapsed_ms'])
            or not value['sync_completed'] <= value['sync_started'] <= value['sync_completed'] + 1):
        raise ValueError('restart-types-counts')
    snapshot = value['failure_snapshot']
    if value['approval_completed']:
        if (value['failure_snapshot_collected'] or snapshot is not None
                or value['sync_started'] == 0 or value['sync_started'] != value['sync_completed']):
            raise ValueError('restart-success-snapshot')
        return value
    if (not value['failure_snapshot_collected'] or type(snapshot) is not dict
            or set(snapshot) != RESTART_OPTIONAL | {'lower_entry_present', 'higher_entry_present'}):
        raise ValueError('restart-failure-snapshot')
    if any(type(snapshot[key]) is not bool for key in ['lower_entry_present', 'higher_entry_present']):
        raise ValueError('restart-presence')
    if any(snapshot[key] is not None and type(snapshot[key]) is not bool for key in RESTART_OPTIONAL):
        raise ValueError('restart-optional-types')
    for side, keys in [('lower', {'lower_is_recipient', 'lower_ready', 'lower_handshake_published',
                                  'lower_original_live', 'lower_nonce_matches_x', 'lower_request_content_exists'}),
                       ('higher', {'higher_is_recipient', 'higher_ready', 'higher_handshake_published',
                                   'higher_nonce_matches_x', 'higher_channel_core_valid'})]:
        if any((snapshot[key] is None) == snapshot[side + '_entry_present'] for key in keys):
            raise ValueError('restart-presence-conditional')
    if (snapshot['higher_request_row_read_succeeded'] is True) != (snapshot['higher_request_processed'] is not None):
        raise ValueError('restart-read-conditional')
    return value


def restart_marker(raw):
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    namespace = RESTART_PREFIX.rstrip()
    lines = [line for line in text.splitlines() if namespace in line]
    if len(lines) != 1 or text.count(namespace) != 1 or len(lines[0]) > 8192:
        raise ValueError('restart-marker-cardinality')
    match = re.fullmatch(r'[ \t]{0,8}' + re.escape(RESTART_PREFIX) + r'(\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    if match is None:
        raise ValueError('restart-marker-envelope')
    return restart_closed(json.loads(match[1], object_pairs_hook=unique))


def restart_controls():
    success = {'approval_completed': True, 'sync_started': 1, 'sync_completed': 1,
               'approval_elapsed_ms': 1, 'failure_snapshot_collected': False, 'failure_snapshot': None}
    snapshot = {key: False for key in RESTART_OPTIONAL}
    snapshot.update(lower_entry_present=True, higher_entry_present=True, higher_request_processed=None)
    failure = dict(success, approval_completed=False, sync_completed=0, approval_elapsed_ms=20000,
                   failure_snapshot_collected=True, failure_snapshot=snapshot)
    absent = dict(failure, failure_snapshot={key: None for key in RESTART_OPTIONAL}
                  | {'lower_entry_present': False, 'higher_entry_present': False})
    for valid in [success, failure, absent]:
        assert restart_closed(valid) == valid
        assert restart_marker((RESTART_PREFIX + json.dumps(valid) + '\n').encode()) == valid
    invalid = [dict(success, private='PRIVATE'), dict(success, sync_started=True),
               dict(success, sync_completed=2), dict(success, approval_elapsed_ms=2**64),
               dict(success, failure_snapshot_collected=True), dict(failure, failure_snapshot=None),
               dict(failure, failure_snapshot=dict(snapshot, private='PRIVATE')),
               dict(failure, failure_snapshot=dict(snapshot, lower_ready='PRIVATE')),
               dict(failure, failure_snapshot=dict(snapshot, lower_entry_present=False)),
               dict(failure, failure_snapshot=dict(snapshot, higher_channel_core_valid=None)),
               dict(failure, failure_snapshot=dict(snapshot, higher_request_processed=True))]
    negatives = 0
    for value in invalid:
        try:
            restart_closed(value)
        except ValueError:
            negatives += 1
        else:
            raise AssertionError('restart-negative-schema-accepted')
    raw = (RESTART_PREFIX + json.dumps(failure) + '\n').encode()
    for value in [raw + raw, b'PRIVATE ' + raw, b' ' * 9 + raw,
                  raw.replace(b'"sync_started": 1', b'"sync_started": 1, "sync_started": 1'),
                  raw + b'pending-restart-approval-PRIVATE\n']:
        try:
            restart_marker(value)
        except ValueError:
            negatives += 1
        else:
            raise AssertionError('restart-negative-envelope-accepted')
    return {'positive': 6, 'negative': negatives, 'synthetic_metadata_only': True, 'product_bodies': 0}


WATCH_SELECTION_PREFIX = 'watch-selection-observation '
WATCH_STAGES = ('WatchYield', 'WatchSelected', 'ReplayAfterClearedDebt', 'ReplayWithDebt',
                'ReplayWithoutDebt', 'ReceiveArm', 'AppReceiveFirstPending',
                'AppReceiveFirstReady', 'ReceiveSelected')


def watch_selection(value):
    if type(value) is not dict or set(value) != {'final_snapshot', 'at_acceptance'}:
        raise ValueError('watch-selection-fields')
    for snapshot in value.values():
        if snapshot is None:
            continue
        if type(snapshot) is not list or len(snapshot) != 5:
            raise ValueError('watch-selection-snapshot')
        counts_, turns, services, total, unknown = snapshot
        if (not uint(total) or total > 256 or type(unknown) is not bool
                or any(type(row) is not list or len(row) != 9 for row in (counts_, turns, services))
                or any(not uint(v) or v > 256 for v in counts_ + turns)
                or any(not uint(v) or v > 8 for v in services)):
            raise ValueError('watch-selection-types')
        if any((count == 0) != (turn == 0) or turn > total
               or (count == 0 and service != 0)
               for count, turn, service in zip(counts_, turns, services)):
            raise ValueError('watch-selection-order')
    return value


def watch_closed(value):
    fields = {'queued_body', 'facts', 'completed_before', 'runtime_closes', 'plane_shutdown_returns',
              'relay_closed', 'attempt_completed', 'pressure', 'pause_rx_len', 'target_queue',
              'own_id_bound', 'own_queue', 'ingress', 'selection'}
    if type(value) is not dict or set(value) != fields:
        raise ValueError('watch-fields')
    if any(type(value[k]) is not bool for k in ('queued_body', 'relay_closed', 'attempt_completed')):
        raise ValueError('watch-bools')
    facts = value['facts']
    if type(facts) is not list or len(facts) != 13 or any(type(v) is not bool for v in facts):
        raise ValueError('watch-facts')
    if any(not uint(value[k]) for k in ('runtime_closes', 'plane_shutdown_returns')):
        raise ValueError('watch-counts')
    for key, bound in [('completed_before', 8), ('pause_rx_len', 2**64-1)]:
        v = value[key]
        if v is not None and (not uint(v) or v > bound):
            raise ValueError('watch-option-count')
    if value['own_id_bound'] is not None and type(value['own_id_bound']) is not bool:
        raise ValueError('watch-own-binding')
    pressure = value['pressure']
    if pressure is not None and (type(pressure) is not list or len(pressure) != 4
            or type(pressure[0]) is not bool or any(not uint(v) or v > 8 for v in pressure[1:])):
        raise ValueError('watch-pressure')
    ingress = value['ingress']
    if ingress is not None and (type(ingress) is not list or len(ingress) != 5
            or type(ingress[0]) is not list or len(ingress[0]) != 4
            or any(type(v) is not bool for v in ingress[0])
            or any(not uint(v) for v in ingress[1:4]) or type(ingress[4]) is not bool):
        raise ValueError('watch-ingress')
    for observation in (value['target_queue'], value['own_queue']):
        if observation is None:
            continue
        if (type(observation) is not list or len(observation) != 6
                or type(observation[0]) is not list or len(observation[0]) != 8
                or type(observation[1]) is not list or len(observation[1]) != 6
                or any(not uint(v) for v in observation[0] + observation[1])
                or (observation[2] is not None and (type(observation[2]) is not list
                    or len(observation[2]) != 2 or any(not uint(v) for v in observation[2])))
                or not uint(observation[3]) or type(observation[4]) is not bool or type(observation[5]) is not bool):
            raise ValueError('watch-queue')
    watch_selection(value['selection'])
    return value


def watch_marker(raw):
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    lines = [line for line in text.splitlines() if 'watch-pressure' in line or WATCH_SELECTION_PREFIX.rstrip() in line]
    if (len(lines) != 5 or text.count('watch-pressure') != 4
            or text.count(WATCH_SELECTION_PREFIX.rstrip()) != 1
            or any(len(line) > 16384 for line in lines)):
        raise ValueError('watch-marker-cardinality')
    boolean, number = r'(?:true|false)', r'[0-9]{1,20}'
    array = lambda atom, n: r'\[' + ', '.join([atom]*n) + r'\]'
    optional = lambda atom: r'(?:None|Some\(' + atom + r'\))'
    pair = r'\(' + number + ', ' + number + r'\)'
    queue = r'\(' + array(number, 8) + ', ' + array(number, 6) + ', ' + optional(pair) + ', ' + number + ', ' + boolean + ', ' + boolean + r'\)'
    patterns = {
        'facts': r'watch-pressure facts=' + array(boolean, 13) + ' completed_before=' + optional(number)
            + ' runtime_closes=' + number + ' plane_shutdown_returns=' + number
            + ' relay_closed=' + boolean + ' attempt_completed=' + boolean,
        'services': r'watch-pressure-services snapshot=' + optional(r'\(' + boolean + ', [0-8], [0-8], [0-8]' + r'\)'),
        'ingress': r'watch-pressure-ingress schedule=' + optional(r'\(' + array(boolean, 4) + ', ' + number + ', ' + number + ', ' + number + ', ' + boolean + r'\)'),
        'queue': r'watch-pressure-queue pause_rx_len=' + optional(number) + ' target=' + optional(queue)
            + ' own_id_bound=' + optional(boolean) + ' own=' + optional(queue),
        'selection': re.escape(WATCH_SELECTION_PREFIX) + r'(\{[^\r\n]*\})',
    }
    found, selection = set(), None
    for line in lines:
        for kind, pattern in patterns.items():
            match = re.fullmatch(r'[ \t]{0,8}' + pattern + r'[ \t]{0,8}', line)
            if match is None:
                continue
            if kind in found:
                raise ValueError('watch-marker-duplicate')
            found.add(kind)
            if kind == 'selection':
                selection = watch_closed(json.loads(match[1], object_pairs_hook=unique))
            break
        else:
            raise ValueError('watch-marker-envelope')
    if found != set(patterns):
        raise ValueError('watch-marker-inventory')
    # False original oracle/cleanup facts and unknown observations are retained,
    # never relabeled as a PASS. JSON copies those same original owned values.
    return selection


def watch_controls():
    empty = [[0]*9, [0]*9, [0]*9, 0, False]
    value = {'queued_body': True, 'facts': [True]*11+[False, True], 'completed_before': 2,
             'runtime_closes': 3, 'plane_shutdown_returns': 3, 'relay_closed': True,
             'attempt_completed': True, 'pressure': [True, 8, 8, 0], 'pause_rx_len': 0,
             'target_queue': [[1,1,0,1,0,1,0,1], [1,0,0,0,0,0], [0,1], 0, False, False],
             'own_id_bound': True, 'own_queue': None, 'ingress': [[True]*4,1,3,3,False],
             'selection': {'final_snapshot': empty, 'at_acceptance': empty}}
    assert watch_closed(value) == value
    assert watch_selection({'final_snapshot': None, 'at_acceptance': None})['at_acceptance'] is None
    source_rows = (b'watch-pressure facts=[true, true, true, true, true, true, true, true, true, true, true, false, true] completed_before=Some(2) runtime_closes=3 plane_shutdown_returns=3 relay_closed=true attempt_completed=true\n'
                   b'watch-pressure-services snapshot=Some((true, 8, 8, 0))\n'
                   b'watch-pressure-ingress schedule=Some(([true, true, true, true], 1, 3, 3, false))\n'
                   b'watch-pressure-queue pause_rx_len=Some(0) target=Some(([1, 1, 0, 1, 0, 1, 0, 1], [1, 0, 0, 0, 0, 0], Some((0, 1)), 0, false, false)) own_id_bound=Some(true) own=None\n')
    row = (WATCH_SELECTION_PREFIX + json.dumps(value) + '\n').encode()
    raw = source_rows + row
    assert watch_marker(raw)['facts'][11] is False
    assert watch_marker(raw.replace(b'\n', b'\r\n')) == value
    negatives = 0
    bad = [dict(value, private='PRIVATE'), dict(value, completed_before=True),
           dict(value, target_queue='PRIVATE'), dict(value, own_id_bound=1),
           dict(value, selection={'final_snapshot': [[True]+[0]*8,[0]*9,[0]*9,0,False], 'at_acceptance': None}),
           dict(value, selection={'final_snapshot': [[1]+[0]*8,[0]*9,[0]*9,1,False], 'at_acceptance': None}),
           dict(value, selection={'final_snapshot': [[0]*9,[0]*9,[9]+[0]*8,0,False], 'at_acceptance': None}),
           dict(value, selection={'final_snapshot': [[0]*9,[0]*9,[0]*9,257,False], 'at_acceptance': None})]
    for invalid in bad:
        try:
            watch_closed(invalid)
        except ValueError:
            negatives += 1
        else:
            raise AssertionError('watch-negative-schema-accepted')
    for invalid in [raw+row, raw+b'watch-pressure-unknown PRIVATE\n',
                    raw.replace(row, b'PRIVATE '+row), raw.replace(row, b' '*9+row),
                    raw.replace(b'"queued_body":', b'"queued_body":false,"queued_body":'),
                    raw.replace(b'own_id_bound=Some(true)', b'own_id_bound=Some(1)')]:
        try:
            watch_marker(invalid)
        except ValueError:
            negatives += 1
        else:
            raise AssertionError('watch-negative-marker-accepted')
    return {'positive': 4, 'negative': negatives, 'metadata_only': True, 'product_bodies': 0}


SDK_REPLAY_PREFIX = 'sdk-replay-forwarder-diagnostic '
SDK_REPLAY_FIELDS = {'case', 'clamp', 'expected', 'delivered', 'forwarder_finished',
                     'forwarder', 'loss', 'replay', 'coverage', 'relay_requests'}


def sdk_replay_closed(value, case):
    if case not in SDK_REPLAY_CASES:
        raise ValueError('sdk-replay-case')
    if type(value) is not dict or set(value) != SDK_REPLAY_FIELDS:
        raise ValueError('sdk-replay-fields')
    expected_case, expected_count = (1, 1000) if case in THOUSAND_CASES else (2, 1200)
    if (not uint(value['case']) or value['case'] != expected_case
            or not uint(value['expected']) or value['expected'] != expected_count
            or not uint(value['delivered']) or value['delivered'] > expected_count
            or type(value['forwarder_finished']) is not bool
            or (value['clamp'] is not None and (not uint(value['clamp']) or value['clamp'] != 500))
            or (case in THOUSAND_CASES and value['clamp'] is not None)):
        raise ValueError('sdk-replay-scalars')
    for key, length, optional in [('forwarder',15,True), ('loss',2,True), ('replay',12,True),
                                  ('coverage',6,False), ('relay_requests',2,False)]:
        row = value[key]
        if row is None and optional:
            continue
        if type(row) is not list or len(row) != length or not all(uint(v) for v in row):
            raise ValueError('sdk-replay-vector')
    forwarder, replay = value['forwarder'], value['replay']
    if (forwarder is not None and (forwarder[0] > 8 or forwarder[12] > 1 or forwarder[14] > 1)
            or replay is not None and (replay[0] > 1 or replay[11] > 1)):
        raise ValueError('sdk-replay-enums')
    # Separate source/counter/coverage sampling is not a coherent transaction.
    # In particular do not enforce enqueued-dispatched == pending.
    return value


def sdk_replay_marker(raw, case, body_passed):
    if case not in SDK_REPLAY_CASES or type(body_passed) is not bool:
        raise ValueError('sdk-replay-context')
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    namespace = SDK_REPLAY_PREFIX.rstrip()
    lines = [line for line in text.splitlines() if namespace in line]
    if (len(lines) not in ([1] if case in THOUSAND_CASES else [1,2])
            or text.count(namespace) != len(lines) or any(len(line) > 8192 for line in lines)):
        raise ValueError('sdk-replay-cardinality')
    rows = []
    for line in lines:
        match = re.fullmatch(r'[ \t]{0,8}' + re.escape(SDK_REPLAY_PREFIX) + r'(\{[^\r\n]*\})[ \t]{0,8}', line)
        if match is None:
            raise ValueError('sdk-replay-envelope')
        rows.append(sdk_replay_closed(json.loads(match[1], object_pairs_hook=unique), case))
    if [row['clamp'] for row in rows] != ([None] if len(rows) == 1 else [None,500]):
        raise ValueError('sdk-replay-clamp-order')
    if body_passed and (len(rows) != (1 if case in THOUSAND_CASES else 2)
                        or any(row['delivered'] != row['expected'] for row in rows)):
        raise ValueError('sdk-replay-pass-inventory')
    return rows


def sdk_replay_controls():
    base = {'case':1, 'clamp':None, 'expected':1000, 'delivered':0, 'forwarder_finished':True,
            'forwarder':[1,257,1000,2,1,742,1,0,258,1003,100,10,0,0,1],
            'loss':[1,258], 'replay':[1,258,0,0,0,1000,0,0,0,0,0,0],
            'coverage':[21,0,21,0,0,0], 'relay_requests':[21,0]}
    line = lambda row: (SDK_REPLAY_PREFIX + json.dumps(row) + '\n').encode()
    raw = line(base)
    assert sdk_replay_marker(raw,'adapter-thousand',False) == [base]
    assert sdk_replay_marker(raw,'adapter-thousand-default',False) == [base]
    assert sdk_replay_marker(line(dict(base,delivered=1000)),'adapter-thousand-default',True)[0]['delivered'] == 1000
    default_config = positive_configuration('adapter-thousand-default')
    experimental_config = positive_configuration('adapter-thousand')
    assert default_config == (['sdk','test-policy-overrides'], 'm5-bounded', '4194304')
    assert experimental_config == (['sdk','experimental-device-sync','test-policy-overrides'], *default_config[1:])
    assert 'adapter-thousand-default' not in EXPERIMENTAL_CASES and 'adapter-thousand-default' not in PFP
    assert CASES['adapter-thousand-default'] == CASES['adapter-thousand']
    assert sdk_replay_marker(b' '*8+raw.replace(b'\n',b'\r\n'),'adapter-thousand',False) == [base]
    first = dict(base,case=2,expected=1200,delivered=1200,forwarder_finished=False)
    second = dict(first,clamp=500)
    both = line(first)+line(second)
    assert sdk_replay_marker(both,'adapter-clamped',True) == [first,second]
    assert sdk_replay_marker(line(dict(first,delivered=0)),'adapter-clamped',False)[0]['delivered'] == 0
    assert sdk_replay_marker(line(dict(base,forwarder=None,replay=None,loss=None)),'adapter-thousand',False)[0]['forwarder'] is None
    invalid = [raw+raw, b'PRIVATE '+raw, b' '*9+raw, raw+b'sdk-replay-forwarder-diagnostic-unknown PRIVATE\n',
               raw.replace(b'"case": 1',b'"case": 1,"case": 1'), raw.replace(b'"case": 1',b'"case": true'),
               line(dict(base,private='PRIVATE')), line(dict(base,expected=True)), line(dict(base,delivered=-1)),
               line(dict(base,forwarder='PRIVATE')), line(dict(base,loss=[True,0])),
               line(dict(base,replay=[0]*11)), line(dict(base,coverage=None)),
               line(dict(base,forwarder=[9]+[0]*14)), line(dict(base,forwarder=[0]*12+[2,0,1])),
               line(dict(base,replay=[0]*11+[2])), line(dict(base,clamp=500)), raw+line(base)+line(base),
               line(dict(base,forwarder=[True]+[0]*14)), line(dict(base,coverage=[True]+[0]*5)),
               line(dict(base,replay=[True]+[0]*11)), line(dict(base,relay_requests=[False,0])),
               line(dict(base,loss=[2**64,0])), line(dict(base,forwarder=[0]*14+[2])),
               raw.replace(b'"delivered": 0', b'"delivered": '+b'9'*8192)]
    for bad in invalid:
        try:
            sdk_replay_marker(bad,'adapter-thousand',False)
        except ValueError:
            pass
        else:
            raise AssertionError('sdk-replay-negative-accepted')
    scoped = [(line(first),'adapter-clamped',True), (line(second),'adapter-clamped',False),
              (line(second)+line(first),'adapter-clamped',False), (both+line(second),'adapter-clamped',False),
              (line(dict(first,clamp=True)),'adapter-clamped',False), (raw,'adapter-thousand',True),
              (line(dict(base,clamp=500)),'adapter-thousand-default',False),
              (line(first),'adapter-thousand-default',False),
              (raw+raw,'adapter-thousand-default',False),
              (raw,'adapter-thousand-default',True)]
    for bad, case, passed in scoped:
        try:
            sdk_replay_marker(bad,case,passed)
        except ValueError:
            pass
        else:
            raise AssertionError('sdk-replay-scoped-negative-accepted')
    return {'positive':10, 'negative':len(invalid)+len(scoped), 'synthetic_metadata_only':True, 'product_bodies':0}


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
    display = (r'(?:' + re.escape(package_for(case)) + r'::)?' + re.escape(binary)
               if case in INTEGRATION_CASES else re.escape(package_for(case)))
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
        display = package_for(case) + '::' + binary if case in INTEGRATION_CASES else package_for(case)
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
    'worker-input-offer': ('crates/marmot-app/src/runtime/account_worker.rs',
              '    if owed {\n        tokio::select! {\n            biased;\n            received = &mut receive, if receive_enabled => futures::future::Either::Right(received),\n            changed = &mut replay => futures::future::Either::Left(changed),\n        }\n',
              '    if owed {\n        tokio::select! {\n            biased;\n            changed = &mut replay => futures::future::Either::Left(changed),\n            received = &mut receive, if receive_enabled => futures::future::Either::Right(received),\n        }\n',
              'owed input offer must select ready delivery and preserve the replay version',
              r'assert!\(\s*delivery_selected\s*&&\s*replay_unconsumed\s*&&\s*delivery_consumed,\s*"{message}"\s*\);'),
    'watch-pressure': ('crates/marmot-app/src/runtime/account_worker.rs',
              '    if owed {\n        tokio::select! {\n            biased;\n            received = &mut receive, if receive_enabled => futures::future::Either::Right(received),\n            changed = &mut replay => futures::future::Either::Left(changed),\n        }\n',
              '    if owed {\n        tokio::select! {\n            biased;\n            changed = &mut replay => futures::future::Either::Left(changed),\n            received = &mut receive, if receive_enabled => futures::future::Either::Right(received),\n        }\n',
              'authenticated_body_must_precede_second_ready_watch_service',
              r'assert!\(\s*facts\.into_iter\(\)\.all\(\|value\| value\)\s*&& runtime_closes == 3\s*&& planes_shutdown == 3\s*&& relay_closed\s*&& attempt_completed,\s*"{message}"\s*\);'),
    'inline': ('crates/marmot-app/src/client/sync.rs',
               '        self.observe_recovery_evidence(effects);\n        // Upstream report bookkeeping also retains convergence and superseded edges.\n        self.remember_published_reports(effects);',
               '        self.observe_recovery_evidence(effects);\n        let prior_pending_convergence_groups = self.pending_convergence_groups.clone();\n        self.remember_published_reports(effects);\n        self.pending_convergence_groups = prior_pending_convergence_groups;',
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
    if case in {'watch-pressure', 'worker-input-offer'}:
        start = text.index('async fn wait_for_worker_input<Receive, Replay>(')
        end = text.index('async fn wait_for_replay_change(', start)
        if old not in text[start:end]:
            raise ValueError('inverse-input-selector-owner')
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
               + r'[ \t]{0,8}' + re.escape(PFP[case][3]) + r'[ \t]*(?:\n|$)')
    match = re.search(pattern, text)
    return match is not None and 0 < int(match[1]) <= 1000000


def pfp_controls(case, site):
    header = ("thread '" + CASES[case][1] + "' (7) panicked at "
              + CASES[case][2] + ':' + str(site['line']) + ':' + str(site['column']) + ':\n')
    valid = (header + PFP[case][3] + '\n').encode()
    assert own_failure(valid, case, site)
    assert own_failure(valid.replace(b"' (7)", b"'"), case, site)
    assert own_failure(header.encode() + b' '*4 + PFP[case][3].encode() + b'\n', case, site)
    assert own_failure(header.encode() + b' '*8 + PFP[case][3].encode() + b'\n', case, site)
    invalid = [header.encode() + b' '*9 + PFP[case][3].encode() + b'\n',
               valid + valid, b'PRIVATE ' + valid, valid.replace(PFP[case][3].encode(), b'PRIVATE'),
               valid.replace(CASES[case][1].encode(), b'PRIVATE'),
               valid.replace(CASES[case][2].encode(), b'PRIVATE.rs'),
               valid.replace((':' + str(site['line']) + ':').encode(), b':999999:'),
               valid + b"thread 'PRIVATE' panicked at PRIVATE.rs:1:2:\n"]
    assert all(not own_failure(raw, case, site) for raw in invalid)
    return {'positive': 4, 'negative': len(invalid), 'synthetic_metadata_only': True, 'product_bodies': 0}


def pfp_configuration(case):
    return ((LIB_FEATURES + ['marmot-app/experimental-device-sync'], 'm5-bounded', '4194304')
            if case in {'watch-pressure', 'worker-input-offer'} else (LIB_FEATURES, 'ci', None))


def watch_pfp_oracle(value, mutant):
    # The fairness fact alone may differ; every real setup/security/cleanup
    # prerequisite stays positive. Unknown bounded selection data earns no credit.
    if (not value['queued_body'] or value['facts'] != [True]*11 + [not mutant, True]
            or value['runtime_closes'] != 3 or value['plane_shutdown_returns'] != 3
            or not value['relay_closed'] or not value['attempt_completed']
            or value['pressure'] != [True, 8, 8, 0]
            or type(value['completed_before']) is not int
            or not (2 <= value['completed_before'] <= 8 if mutant else 0 <= value['completed_before'] <= 1)):
        return False
    for key in ['final_snapshot', 'at_acceptance']:
        row = value['selection'][key]
        if (row is None or row[4] or row[3] == 0
                or row[0][1] < value['completed_before']
                or row[0][5] == 0 or row[0][8] == 0):
            return False
    return True


def watch_pfp_controls():
    empty = [[0]*9, [0]*9, [0]*9, 0, False]
    green_selection = [[0,1,0,0,0,1,0,1,1], [0,1,0,0,0,2,0,2,2], [0,0,0,0,0,1,0,1,1], 2, False]
    red_selection = [[1,2,1,0,0,1,0,1,1], [2,1,2,0,0,4,0,4,4], [1,0,1,0,0,2,0,2,2], 4, False]
    green = {'queued_body': True, 'facts': [True]*13, 'completed_before': 1,
             'runtime_closes': 3, 'plane_shutdown_returns': 3, 'relay_closed': True,
             'attempt_completed': True, 'pressure': [True, 8, 8, 0],
             'selection': {'final_snapshot': green_selection, 'at_acceptance': green_selection}}
    red = dict(green, facts=[True]*11+[False, True], completed_before=2,
               selection={'final_snapshot': red_selection, 'at_acceptance': red_selection})
    assert watch_pfp_oracle(green, False)
    assert watch_pfp_oracle(red, True)
    bad = [dict(red, completed_before=None), dict(red, completed_before=1),
           dict(red, runtime_closes=2), dict(red, plane_shutdown_returns=2),
           dict(red, relay_closed=False), dict(red, attempt_completed=False),
           dict(red, queued_body=False), dict(red, pressure=[True,8,7,0]),
           dict(red, selection={'final_snapshot': None, 'at_acceptance': empty}),
           dict(red, selection={'final_snapshot': empty, 'at_acceptance': [[0]*9,[0]*9,[0]*9,0,True]})]
    for index in list(range(11)) + [12]:
        facts = list(red['facts']); facts[index] = False
        bad.append(dict(red, facts=facts))
    assert all(not watch_pfp_oracle(value, True) for value in bad)
    assert not watch_pfp_oracle(red, False) and not watch_pfp_oracle(green, True)
    assert pfp_configuration('inline') == (LIB_FEATURES, 'ci', None)
    assert pfp_configuration('spill') == (LIB_FEATURES, 'ci', None)
    assert pfp_configuration('watch-pressure') == (LIB_FEATURES + ['marmot-app/experimental-device-sync'], 'm5-bounded', '4194304')
    return {'positive': 2, 'negative': len(bad)+2, 'configuration_controls': 3,
            'synthetic_metadata_only': True, 'product_bodies': 0}


def worker_input_controls(site):
    case = 'worker-input-offer'
    expected = (LIB_FEATURES + ['marmot-app/experimental-device-sync'], 'm5-bounded', '4194304')
    assert pfp_configuration(case) == expected
    assert 'watch-pressure' in PFP and case in PFP
    for control in WORKER_INPUT_CASES - {case}:
        assert control not in PFP and control in EXPERIMENTAL_CASES
    assert pfp_configuration('inline') == (LIB_FEATURES, 'ci', None)
    assert pfp_configuration('spill') == (LIB_FEATURES, 'ci', None)
    # Real library spelling and exact named status; own source and static
    # assertion message remain independently required for a mutant kill.
    status = ('FAIL [ 0.001s] (1/1) marmot-app ' + CASES[case][1]
              + '\nSummary [ 0.01s] 1 test run: 0 passed, 1 failed, 0 skipped\n').encode()
    header = ("thread '" + CASES[case][1] + "' (7) panicked at " + CASES[case][2]
              + ':' + str(site['line']) + ':' + str(site['column']) + ':\n')
    raw = status + (header + '    ' + PFP[case][3] + '\n').encode()
    assert counts(raw, case)['failed'] == 1 and own_failure(raw, case, site)
    negatives = 0
    for bad in [raw.replace(CASES[case][1].encode(), b'PRIVATE'),
                raw.replace(CASES[case][2].encode(), b'PRIVATE.rs'),
                raw.replace(PFP[case][3].encode(), b'PRIVATE'),
                raw + (header + PFP[case][3] + '\n').encode()]:
        assert not own_failure(bad, case, site)
        negatives += 1
    assert compiler(raw + b'error[E0308]: PRIVATE\n', {})['header_count'] == 1
    return {'positive': 1, 'negative': negatives, 'configuration_controls': 7,
            'compiler_rejection_controls': 1, 'synthetic_metadata_only': True, 'product_bodies': 0}


def pfp(args):
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    features, profile, expected_stack = pfp_configuration(args.case)
    report = {'case': args.case, 'stage': 'pfp', 'source': git('rev-parse', 'HEAD'),
              'baseline': args.baseline, 'qualification_passed': False, 'pfp_passed': False,
              'phases': [], 'automatic_retries': 0, 'profile': profile, 'features': features,
              'test_threads': 1, 'rust_min_stack': os.environ.get('RUST_MIN_STACK')}
    if args.case in WORKER_INPUT_CASES:
        report.update(evidence_scope='worker-input-selection-mechanism-only', native_protocol_qualification=False)
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
        flags = ['-p', 'marmot-app', '--lib', '--features', ','.join(features), '--locked', '--profile', profile]
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
        watch_accepted = True
        if args.case == 'watch-pressure':
            row['body']['watch_observation'] = watch_marker(raw)
            watch_accepted = watch_pfp_oracle(row['body']['watch_observation'], label == 'mutant')
            row['watch_prerequisites_accepted'] = watch_accepted
            save()
        if label == 'mutant':
            row['own_runtime_failure'] = own_failure(raw, args.case, site)
            row['accepted'] = (code == 100 and row['body']['counts']['failed'] == 1
                               and clean_compile and watch_accepted and row['own_runtime_failure']
                               and row['source_exact_after_body'])
        else:
            row['accepted'] = (code == 0 and row['body']['counts']['passed'] == 1 and clean_compile and watch_accepted
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
        if args.case == 'worker-input-offer':
            report['worker_input_controls'] = worker_input_controls(site)
        if args.case == 'watch-pressure':
            report['watch_parser_controls'] = watch_controls()
            report['watch_pfp_controls'] = watch_pfp_controls()
        if args.mode == 'preflight':
            result = 0
        else:
            stage = 'environment'
            denied = ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS',
                      'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP']
            if ((os.environ.get('RUST_MIN_STACK') or None) != expected_stack
                    or any(os.environ.get(key) for key in denied)
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


def positive_configuration(case):
    features = (['sdk', 'test-policy-overrides'] if case == 'adapter-thousand-default' else
                ['sdk', 'experimental-device-sync', 'test-policy-overrides'] if case in ADAPTER_CASES else
                ['experimental-device-sync'] if case in STORAGE_CASES else
                LIB_FEATURES + ['marmot-app/experimental-device-sync'] if case in EXPERIMENTAL_CASES else
                ['test-policy-overrides'] if case == 'offline' else LIB_FEATURES)
    profile = 'm5-bounded' if case in BOUNDED_CASES else 'ci'
    expected_stack = '4194304' if case in BOUNDED_CASES else None
    return features, profile, expected_stack


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
    features, profile, expected_stack = positive_configuration(args.case)
    package = package_for(args.case)
    report = {'case': args.case, 'diagnostic_only': True, 'qualification_passed': False,
              'body_passed': False, 'source': git('rev-parse', 'HEAD'), 'baseline': args.baseline,
              'features': features, 'profile': profile, 'package': package, 'automatic_retries': 0, 'test_threads': 1,
              'rust_min_stack': os.environ.get('RUST_MIN_STACK'), 'expected_test': CASES[args.case][1]}
    if args.case in WORKER_INPUT_CASES:
        report.update(evidence_scope='worker-input-selection-mechanism-only', native_protocol_qualification=False)
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
        if args.case == 'offline':
            report['fingerprint_parser_controls'] = fingerprint_controls()
        if args.case in SDK_REPLAY_CASES:
            report['sdk_replay_parser_controls'] = sdk_replay_controls()
        if args.case == 'watch-pressure':
            report['watch_parser_controls'] = watch_controls()
        if args.case == 'higher-source':
            report['restart_parser_controls'] = restart_controls()
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
            flags = ['-p', package, '--test', binary] if args.case in INTEGRATION_CASES else ['-p', package, '--lib']
            flags += ['--features', ','.join(features), '--locked', '--profile', profile]
            selection = 'package(' + package + ') & test(=' + test + ')'
            if args.case in INTEGRATION_CASES:
                selection += ' & binary(=' + binary + ')'
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
            if args.case == 'offline':
                report['compiled_fingerprints'] = fingerprint_snapshot(
                    inventory, test, os.environ.get('CARGO_TARGET_DIR', 'target'))
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
            if args.case in SDK_REPLAY_CASES:
                stage = 'diagnostic'
                report['body']['sdk_replay_observations'] = sdk_replay_marker(
                    raw, args.case, code == 0 and report['body']['counts']['passed'] == 1)
                save()
            if args.case == 'higher-source':
                stage = 'diagnostic'
                report['body']['restart_observation'] = restart_marker(raw)
                save()
            if args.case == 'watch-pressure':
                stage = 'diagnostic'
                report['body']['watch_observation'] = watch_marker(raw)
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
