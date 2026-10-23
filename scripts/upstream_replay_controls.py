"""Remote-only replay controls and scoped omission chains; no full-suite credit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from upstream_current_backend_probe import ANSI, capture
from upstream_body_resources import start as resource_start, finish as resource_finish, controls as resource_controls
from upstream_uniffi_receive_controls import (CASES as UNIFFI_CASES, observe as uniffi_receive_marker,
    oracle as uniffi_receive_oracle, controls as uniffi_receive_controls)
from upstream_extraction_cohort import frozen_inputs, git, reviewed_cohort
from upstream_offline_fingerprints import controls as fingerprint_controls, snapshot as fingerprint_snapshot

from upstream_sibling_send_observation import parse as sibling_send_observation, controls as sibling_send_controls
from upstream_sibling_worker_observation import parse as sibling_worker_observation, controls as sibling_worker_controls
from upstream_adapter_exit_observation import parse as adapter_exit_observation, controls as adapter_exit_controls
from upstream_fresh_rejoin_observation import fresh_rejoin_observation, controls as fresh_rejoin_controls

PREFIX = 'offline-replay-diagnostic '
CASES = {
    'fresh-rejoin-observation': ('marmot_app', 'native_device_linking::tests::automatic_fresh_rejoin_acceptance::automatic_fresh_accepted_rejoin_restores_only_the_new_source_lineage',
                                 'crates/marmot-app/src/native_device_linking/tests/automatic_fresh_rejoin_acceptance.rs'),
    'sibling-send-default': ('marmot_app', 'runtime::account_worker::tests::local_submission_queue_tests::blocked_account_admission_does_not_delay_sibling_send_or_resurrect_deleted_timing',
                                 'crates/marmot-app/src/runtime/account_worker/tests/local_submission_queue_tests.rs'),
    'sibling-send-experimental': ('marmot_app', 'runtime::account_worker::tests::local_submission_queue_tests::blocked_account_admission_does_not_delay_sibling_send_or_resurrect_deleted_timing',
                                 'crates/marmot-app/src/runtime/account_worker/tests/local_submission_queue_tests.rs'),
    'request-cleanup-experimental': ('marmot_app', 'native_device_linking::automatic_pairing_acceptance::request_retry_completion_acceptance::authenticated_consent_retires_obsolete_request_retry_before_proof',
                                      'crates/marmot-app/src/native_device_linking/tests/request_retry_completion_acceptance.rs'),
    'priority-cleanup-experimental': ('marmot_app', 'native_device_linking::automatic_pairing_acceptance::recipient_retry_priority_acceptance::older_recipient_proof_retry_precedes_later_consent_retry',
                                       'crates/marmot-app/src/native_device_linking/tests/recipient_retry_priority_acceptance.rs'),
    'recipient-admission-experimental': ('marmot_app', 'native_device_linking::automatic_pairing_acceptance::recipient_sibling_admission_acceptance::admitted_recipient_starts_first_consent_without_periodic_tick',
                                         'crates/marmot-app/src/native_device_linking/tests/recipient_sibling_admission_acceptance.rs'),
    'cursor-promotion-observation': ('marmot_app', 'tests::live_ingest_promotes_the_cursor_as_far_as_a_restart_still_fetches_the_queue',
                                   'crates/marmot-app/src/tests.rs'),
    'peer-leave-observation': ('marmot_app', 'tests::due_peer_leave_does_not_shorten_a_collecting_convergence_pass',
                               'crates/marmot-app/src/tests.rs'),
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
    'private-classifier-authentication': ('cgka_engine', 'private_roster_settlement::tests::private_enrollment_classifier_rejects_unauthenticated_or_noncanonical_payloads',
                          'crates/cgka-engine/src/private_roster_settlement_tests.rs'),
    'private-classifier-kinds': ('cgka_engine', 'private_roster_settlement::tests::private_enrollment_endorsement_malformed_and_wrong_kind_are_private_controls',
                          'crates/cgka-engine/src/private_roster_settlement_tests.rs'),
    'engine-validator-empty': ('cgka_engine', 'app_payload::tests::empty_sender_is_rejected_even_when_event_pubkey_is_empty',
                          'crates/cgka-engine/src/app_payload.rs'),
    'engine-validator-mismatch': ('cgka_engine', 'app_payload::tests::pubkey_mismatch_is_rejected',
                          'crates/cgka-engine/src/app_payload.rs'),
    'engine-validator-match': ('cgka_engine', 'app_payload::tests::matching_sender_validates',
                          'crates/cgka-engine/src/app_payload.rs'),
    'engine-private-sql': ('cgka_engine', 'private_roster_settlement::tests::private_enrollment_request_sql_fault_preserves_crypto_and_original_retry',
                          'crates/cgka-engine/src/private_roster_settlement_tests.rs'),
    'engine-private-history': ('cgka_engine', 'private_roster_settlement::tests::private_enrollment_request_ordinary_history_ingress_never_becomes_live_metadata',
                          'crates/cgka-engine/src/private_roster_settlement_tests.rs'),
    'engine-private-deadline': ('cgka_engine', 'private_roster_settlement::tests::private_enrollment_request_acquisition_deadline_expired_before_ingest_stays_private',
                          'crates/cgka-engine/src/private_roster_settlement_tests.rs'),
    'offline-experimental': CASES['offline'],
    'uniffi-conversation': ('marmot_uniffi', 'commands::account_chat_windows::tests::account_conversation_receive_cancellation_preserves_actual_command_update',
                            'crates/marmot-uniffi/src/commands/account_chat_windows/tests.rs'),
    'uniffi-list': ('marmot_uniffi', 'commands::account_chat_windows::tests::account_list_receive_cancellation_preserves_actual_command_update',
                    'crates/marmot-uniffi/src/commands/account_chat_windows/tests.rs'),
    'uniffi-conversation-stale': ('marmot_uniffi', 'commands::account_chat_windows::tests::account_conversation_actual_stale_sequence_preserves_cancelled_command_update',
                                  'crates/marmot-uniffi/src/commands/account_chat_windows/tests.rs'),
    'wrong-recipient-routing': ('marmot_app', 'native_device_linking::tests::sibling_sharing_routing_acceptance::public_wrong_recipient_sharing_request_is_not_retained_by_c_original',
                                 'crates/marmot-app/src/native_device_linking/sibling_sharing_routing_acceptance.rs'),
    'command-owned-cleanup': ('marmot_app', 'native_device_linking::automatic_pairing_acceptance::command_backlog_acceptance::owned_mock_relay_cleanup_finishes_without_an_observed_initial_stop',
                         'crates/marmot-app/src/native_device_linking/tests/command_backlog_acceptance.rs'),
    'late-commit-extra-epoch': ('marmot_app', 'runtime::account_worker::tests::selective_history_tests::late_commit_700_recovers_after_a_real_later_epoch',
                           'crates/marmot-app/src/runtime/account_worker/tests/selective_history_tests.rs'),
    'late-commit-default': ('marmot_app', 'runtime::account_worker::tests::selective_history_tests::late_commit_700_recovers',
                          'crates/marmot-app/src/runtime/account_worker/tests/selective_history_tests.rs'),
    'sdk-private-capture-control': ('transport_nostr_adapter', 'live_delivery::tests::sdk_private_capture_skips_ordinary_wire_but_generic_capture_is_preserved',
                         'crates/transport-nostr-adapter/src/live_delivery.rs'),
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
    'command-backlog-held': ('marmot_app', 'native_device_linking::automatic_pairing_acceptance::command_backlog_acceptance::eight_history_reads_complete_while_actual_peer_proof_is_held',
                        'crates/marmot-app/src/native_device_linking/tests/command_backlog_acceptance.rs'),
    'command-backlog': ('marmot_app', 'native_device_linking::automatic_pairing_acceptance::command_backlog_acceptance::authenticated_body_is_serviced_before_eight_queued_history_reads',
                        'crates/marmot-app/src/native_device_linking/tests/command_backlog_acceptance.rs'),
    'higher-source': ('marmot_app', 'native_device_linking::tests::pending_restart_higher_source_delivers_catalog_and_record',
                      'crates/marmot-app/src/client/account_chat_sharing/automatic/tests/pending_restart_acceptance.rs'),
    'spill-experimental': CASES['spill'],
    'watch-pressure': ('marmot_app', 'native_device_linking::automatic_pairing_acceptance::watch_pressure_acceptance::authenticated_body_is_serviced_before_eight_ready_watch_services',
                       'crates/marmot-app/src/native_device_linking/tests/watch_pressure_acceptance.rs'),
})
CASES['cursor-promotion-experimental'] = CASES['cursor-promotion-observation']
CURSOR_CASES = {'cursor-promotion-observation', 'cursor-promotion-experimental'}
SELECTIVE_CASES = {'late-commit-default', 'late-commit-extra-epoch'}
ENGINE_CLASSIFIER_CASES = {'private-classifier-authentication', 'private-classifier-kinds'}
ENGINE_SUPPORT_CASES = {'engine-validator-empty', 'engine-validator-match', 'engine-private-deadline', 'engine-private-history', 'engine-private-sql', 'engine-validator-mismatch'}
ENGINE_CASES = ENGINE_CLASSIFIER_CASES | ENGINE_SUPPORT_CASES
ENGINE_FEATURES = ['experimental-device-sync', 'test-policy-overrides']
ENGINE_CONTROL_ORDER = ['private-classifier-authentication', 'private-classifier-kinds', 'engine-validator-empty', 'engine-validator-mismatch', 'engine-validator-match', 'engine-private-sql', 'engine-private-history', 'engine-private-deadline']
OFFLINE_CASES = {'offline', 'offline-experimental'}
COMMAND_BACKLOG_CASES = {'command-backlog', 'command-backlog-held'}
EXPERIMENTAL_CASES = {'command-owned-cleanup', 'command-backlog-held', 'sdk-private-capture-control', 'worker-input-offer', 'worker-input-replay-first', 'worker-input-pending', 'worker-input-disabled', 'adapter-thousand', 'adapter-clamped', 'hidden-echo', 'departure-native', 'existing-anchor', 'command-backlog', 'adapter-cancelled', 'adapter-failed-route', 'mirrored-catalog', 'mirrored-messages', 'revoked-anchor', 'sharing-policy', 'late-consent', 'spill-experimental', 'watch-pressure', 'higher-source'}
EXPERIMENTAL_CASES |= UNIFFI_CASES | {'fresh-rejoin-observation', 'sibling-send-experimental', 'offline-experimental', 'wrong-recipient-routing', 'recipient-admission-experimental', 'request-cleanup-experimental', 'priority-cleanup-experimental'}
EXPERIMENTAL_CASES.add('cursor-promotion-experimental')
STORAGE_CASES = {'existing-anchor', 'revoked-anchor', 'sharing-policy', 'mirrored-catalog', 'mirrored-messages'}

BOUNDED_CASES = EXPERIMENTAL_CASES | {'adapter-thousand-default'}
THOUSAND_CASES = {'adapter-thousand', 'adapter-thousand-default'}
ADAPTER_CASES = {'sdk-private-capture-control', 'adapter-thousand-default', 'adapter-cancelled', 'adapter-failed-route', 'adapter-thousand', 'adapter-clamped'}
INTEGRATION_CASES = {'adapter-thousand-default', 'offline', 'offline-experimental', 'adapter-thousand', 'adapter-clamped'}
SDK_REPLAY_CASES = THOUSAND_CASES | {'adapter-clamped'}
WORKER_INPUT_CASES = {'worker-input-offer', 'worker-input-replay-first', 'worker-input-pending', 'worker-input-disabled'}


def package_for(case):
    if case in ENGINE_CASES:
        return 'cgka-engine'
    if case in UNIFFI_CASES:
        return 'marmot-uniffi'
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
FIELDS = SCALARS | {'completed', 'arrival_buckets_10s', 'maximum_group_page', 'runtime_operations', 'process_window'}
PROCESS_COUNTERS = {'user_ticks', 'system_ticks', 'rchar', 'wchar', 'syscr', 'syscw',
                    'read_bytes', 'write_bytes', 'cancelled_write_bytes'}
LIB_FEATURES = ['marmot-app/test-policy-overrides', 'marmot-app/otlp-export',
                'marmot-app/product-analytics-export', 'cgka-engine/test-policy-overrides',
                'cgka-engine/test-crash-hooks']
UNIFFI_FEATURES = LIB_FEATURES + ['marmot-uniffi/otlp-export',
                                  'marmot-uniffi/product-analytics-export',
                                  'marmot-uniffi/experimental-device-sync']
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
    window = value['process_window']
    if type(window) is not dict or set(window) != PROCESS_COUNTERS:
        raise ValueError('diagnostic-process-window')
    for row in window.values():
        if (type(row) is not list or len(row) != 3
                or any(item is not None and not uint(item) for item in row)):
            raise ValueError('diagnostic-process-counter')
        start, end, delta = row
        expected = end - start if start is not None and end is not None and end >= start else None
        if delta != expected:
            raise ValueError('diagnostic-process-delta')
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


FIXTURE_OBSERVATION_BASES = {
    'peer-leave-observation': 'peer-leave-initial-delay-observation',
    'cursor-promotion-observation': 'cursor-promotion-observation',
    'cursor-promotion-experimental': 'cursor-promotion-observation',
}
PEER_OPTIONAL_BOOLS = {'same_epoch', 'advanced_epoch', 'regressed_epoch', 'group_terminal',
                       'group_unrecoverable', 'bob_member', 'own_leave_present'}
CURSOR_BOOLS = {'first_is_newer', 'first_is_older', 'in_memory_is_newer', 'checkpoint_is_initial',
                'seal_before', 'seal_after', 'delivery_loss', 'transport_cursor_settled'}


def fixture_observation(raw, case):
    base = FIXTURE_OBSERVATION_BASES[case]
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    if any(other != base and other in text for other in FIXTURE_OBSERVATION_BASES.values()):
        raise ValueError('fixture-observation-other-namespace')
    occurrences = text.count(base)
    if occurrences == 0 and case == 'peer-leave-observation':
        # Absence is allowed, but proves neither getter Some nor reaching it.
        return dict(marker_present=False, marker_sha256=None, observation=None)
    lines = [line for line in text.splitlines() if base in line]
    if occurrences != 1 or len(lines) != 1 or len(lines[0]) > 2_048:
        raise ValueError('fixture-observation-cardinality')
    match = re.fullmatch(r'[ \t]{0,8}' + re.escape(base) + r' (\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    if match is None:
        raise ValueError('fixture-observation-envelope')
    value = json.loads(match[1], object_pairs_hook=unique)
    if type(value) is not dict:
        raise ValueError('fixture-observation-object')
    if case == 'peer-leave-observation':
        if (set(value) != PEER_OPTIONAL_BOOLS | {'collected', 'initial_delay_present', 'epoch_state', 'member_count'}
                or value['collected'] is not True or value['initial_delay_present'] is not False
                or type(value['epoch_state']) is not str
                or value['epoch_state'] not in {'unknown', 'stable', 'pending_publish', 'merging',
                                                'recovering', 'unrecoverable', 'disbanded'}
                or any(value[key] is not None and type(value[key]) is not bool for key in PEER_OPTIONAL_BOOLS)
                or value['member_count'] is not None and not uint(value['member_count'])):
            raise ValueError('fixture-observation-peer-schema')
    elif (set(value) != CURSOR_BOOLS | {'persisted_relative_to_initial'}
            or any(type(value[key]) is not bool for key in CURSOR_BOOLS)
            or value['persisted_relative_to_initial'] is not None
            and (type(value['persisted_relative_to_initial']) is not int
                 or not -(2**63) <= value['persisted_relative_to_initial'] < 2**63)):
        raise ValueError('fixture-observation-cursor-schema')
    return dict(marker_present=True, marker_sha256=hashlib.sha256(lines[0].encode()).hexdigest(),
                observation=value)


def fixture_observation_controls():
    peer = dict.fromkeys(PEER_OPTIONAL_BOOLS, None)
    peer.update(collected=True, initial_delay_present=False, epoch_state='unknown', member_count=None)
    cursor = dict.fromkeys(CURSOR_BOOLS, False)
    cursor['persisted_relative_to_initial'] = None
    positives = negatives = 0
    for case, value in [('peer-leave-observation', peer), ('cursor-promotion-observation', cursor)]:
        base = FIXTURE_OBSERVATION_BASES[case]
        raw = (base + ' ' + json.dumps(value) + '\n').encode()
        assert fixture_observation(raw, case)['observation'] == value
        assert fixture_observation(b'\x1b[0m' + b' ' * 8 + raw.replace(b'\n', b'\r\n'), case)['observation'] == value
        positives += 2
        bad = [raw + raw, b'PRIVATE ' + raw, b' ' * 9 + raw,
               raw.replace((base + ' ').encode(), (base + '-unknown ').encode()),
               raw + (base + '-extra PRIVATE\n').encode(), raw.replace(b'{', b'{"private": true,', 1),
               (base + ' ' + 'x' * 2_049).encode(), (base + ' []').encode()]
        if case == 'peer-leave-observation':
            for key, invalid in [('collected', False), ('initial_delay_present', True),
                                 ('epoch_state', 'PRIVATE'), ('member_count', True),
                                 ('member_count', -1), ('member_count', 2**64), ('bob_member', 0)]:
                bad.append((base + ' ' + json.dumps(dict(value, **{key: invalid}))).encode())
            known = dict.fromkeys(PEER_OPTIONAL_BOOLS, False)
            known.update(collected=True, initial_delay_present=False, epoch_state='stable', member_count=3)
            assert fixture_observation((base + ' ' + json.dumps(known)).encode(), case)['observation'] == known
            assert fixture_observation(b'no owned marker\n', case)['marker_present'] is False
            positives += 2
        else:
            bad.append(b'no owned marker\n')
            for delta in [True, 'PRIVATE', -(2**63)-1, 2**63]:
                bad.append((base + ' ' + json.dumps(dict(value, persisted_relative_to_initial=delta))).encode())
            bad.append((base + ' ' + json.dumps(dict(value, seal_before=0))).encode())
            for delta in [-(2**63), 0, 1_120, 2**63-1]:
                assert fixture_observation((base + ' ' + json.dumps(dict(value, persisted_relative_to_initial=delta))).encode(), case)['marker_present']
                positives += 1
        other = next(item for item in FIXTURE_OBSERVATION_BASES.values() if item != base)
        bad.append(raw + (other + ' {}\n').encode())
        key = next(iter(value))
        bad.append(raw.replace(b'{', ('{' + json.dumps(key) + ': ' + json.dumps(value[key]) + ',').encode(), 1))
        missing = dict(value); missing.pop(key)
        bad.append((base + ' ' + json.dumps(missing)).encode())
        for invalid in bad:
            try:
                fixture_observation(invalid, case)
            except (ValueError, TypeError):
                negatives += 1
            else:
                raise AssertionError('malformed-fixed-fixture-observation-accepted')
    return dict(passed=True, positive=positives, negative=negatives, product_bodies=0)


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


def command_debug_value(text):
    # Called only after a complete closed Debug grammar match. No eval/code/data strings.
    tokens = re.findall(r'Some|None|true|false|[0-9]+|[\[\](),]', text)
    if len(tokens) > 256:
        raise ValueError('command-debug-cap')
    position = 0
    def value(depth=0):
        nonlocal position
        if depth > 8 or position >= len(tokens):
            raise ValueError('command-debug-depth')
        token = tokens[position]; position += 1
        if token == 'Some':
            if tokens[position] != '(':
                raise ValueError('command-debug-option')
            position += 1
            result = value(depth + 1)
            if tokens[position] != ')':
                raise ValueError('command-debug-option')
            position += 1
            return result
        if token in {'None', 'true', 'false'}:
            return {'None': None, 'true': True, 'false': False}[token]
        if token.isdecimal():
            result = int(token)
            if not uint(result):
                raise ValueError('command-debug-integer')
            return result
        if token in {'[', '('}:
            end = ']' if token == '[' else ')'
            result = []
            while position < len(tokens) and tokens[position] != end:
                result.append(value(depth + 1))
                if position < len(tokens) and tokens[position] != end:
                    if tokens[position] != ',':
                        raise ValueError('command-debug-separator')
                    position += 1
            if position >= len(tokens):
                raise ValueError('command-debug-array')
            position += 1
            return result
        raise ValueError('command-debug-token')
    result = value()
    if position != len(tokens):
        raise ValueError('command-debug-tail')
    return result


def command_backlog_marker(raw, case):
    if case not in COMMAND_BACKLOG_CASES:
        raise ValueError('command-marker-case')
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    lines = [line for line in text.splitlines() if 'command-backlog' in line]
    if len(lines) != 3 or text.count('command-backlog') != 3 or any(len(line) > 16384 for line in lines):
        raise ValueError('command-marker-cardinality')
    boolean, number = r'(?:true|false)', r'[0-9]{1,20}'
    array = lambda atom, n: r'\[' + ', '.join([atom]*n) + r'\]'
    optional = lambda atom: r'(?:None|Some\(' + atom + r'\))'
    pair = r'\(' + number + ', ' + number + r'\)'
    queue = r'\(' + array(number,8) + ', ' + array(number,6) + ', ' + optional(pair) + ', ' + number + ', ' + boolean + ', ' + boolean + r'\)'
    held = case == 'command-backlog-held'
    prefix = 'command-backlog-progress' if held else 'command-backlog'
    patterns = [
        prefix + ' facts=(?P<facts>' + array(boolean,11 if held else 13) + ') completed_before=(?P<completed_before>' + optional(number)
            + ') runtime_closes=(?P<runtime_closes>' + number + ') plane_shutdown_returns=(?P<plane_shutdown_returns>' + number
            + ') relay_closed=(?P<relay_closed>' + boolean + ') attempt_completed=(?P<attempt_completed>' + boolean + ')',
        'command-backlog-ingress schedule=(?P<ingress>' + optional(r'\(' + array(boolean,4) + ', ' + number + ', ' + number + ', ' + number + ', ' + boolean + r'\)') + ')',
        'command-backlog-queue pause_rx_len=(?P<pause_rx_len>' + optional(number) + ') target=(?P<target_queue>' + optional(queue)
            + ') own_id_bound=(?P<own_id_bound>' + optional(boolean) + ') own=(?P<own_queue>' + optional(queue) + ')',
    ]
    result = {}
    for line, pattern in zip(lines, patterns):
        match = re.fullmatch(r'[ \t]{0,8}' + pattern + r'[ \t]{0,8}', line)
        if match is None:
            raise ValueError('command-marker-envelope-or-order')
        result.update({name: command_debug_value(value) for name, value in match.groupdict().items()})
    # The complete grammar fixes exact field inventory, bool/int distinction,
    # tuple/array arities, and bounded unsigned counts before anything is exported.
    if result['completed_before'] is not None and result['completed_before'] > 8:
        raise ValueError('command-completion-count')
    return result


def command_backlog_oracle(value, case, mutant=False):
    held = case == 'command-backlog-held'
    if case not in COMMAND_BACKLOG_CASES or (held and mutant):
        return False
    if (value['facts'] != ([True]*11 if held else [True]*11 + [not mutant, True])
            or value['runtime_closes'] != 3 or value['plane_shutdown_returns'] != 3
            or not value['relay_closed'] or not value['attempt_completed']
            or type(value['completed_before']) is not int
            or not (value['completed_before'] == 8 if held else
                    2 <= value['completed_before'] <= 8 if mutant else 0 <= value['completed_before'] <= 1)):
        return False
    ingress = value['ingress']
    if (ingress is None or ingress[0] != [True]*4 or ingress[1] != 1
            or not (0 <= ingress[2] <= 32 and 0 <= ingress[3] <= 32)
            or ingress[2] != ingress[3] or ingress[4]):
        return False
    if not held:
        queue = value['target_queue']
        if (queue is None or queue[1][0] == 0 or queue[2] != [0,1]
                or queue[3:] != [0,False,False]):
            return False
    return True


def command_backlog_controls(site):
    queue = ('Some(([1, 1, 0, 1, 0, 1, 0, 1], [1, 0, 0, 0, 0, 0], Some((0, 1)), 0, false, false))')
    def rows(held=False, mutant=False):
        prefix = 'command-backlog-progress' if held else 'command-backlog'
        facts = ['true']*(11 if held else 13)
        if mutant:
            facts[11] = 'false'
        first = (prefix + ' facts=[' + ', '.join(facts) + '] completed_before=Some(' + ('8' if held else '2' if mutant else '1')
            + ') runtime_closes=3 plane_shutdown_returns=3 relay_closed=true attempt_completed=true\n')
        return (first + 'command-backlog-ingress schedule=Some(([true, true, true, true], 1, 3, 3, false))\n'
            + 'command-backlog-queue pause_rx_len=Some(0) target=' + queue + ' own_id_bound=Some(true) own=None\n').encode()
    green, red, held = rows(), rows(mutant=True), rows(held=True)
    assert command_backlog_oracle(command_backlog_marker(green, 'command-backlog'), 'command-backlog')
    assert command_backlog_oracle(command_backlog_marker(red, 'command-backlog'), 'command-backlog', True)
    assert command_backlog_oracle(command_backlog_marker(held, 'command-backlog-held'), 'command-backlog-held')
    assert command_backlog_marker(red.replace(b'\n',b'\r\n'), 'command-backlog')['facts'][11] is False
    assert command_backlog_marker(b' '*8+green, 'command-backlog')['completed_before'] == 1
    negatives = 0
    for bad, case in [(red+red, 'command-backlog'), (red+b'command-backlog-unknown PRIVATE\n','command-backlog'),
            (b'PRIVATE '+red,'command-backlog'), (b' '*9+red,'command-backlog'),
            (red.replace(b'target=Some(',b'target=PRIVATE('),'command-backlog'),
            (red.replace(b'own_id_bound=Some(true)',b'own_id_bound=Some(1)'),'command-backlog'),
            (red.replace(b'completed_before=Some(2)',b'completed_before=Some(9)'),'command-backlog'),
            (red.replace(b'pause_rx_len=Some(0)',b'pause_rx_len=Some(18446744073709551616)'),'command-backlog'),
            (b'\n'.join(red.splitlines()[::-1])+b'\n','command-backlog'),
            (held,'command-backlog'),(red,'command-backlog-held')]:
        try:
            command_backlog_marker(bad,case)
        except ValueError:
            negatives += 1
        else:
            raise AssertionError('command-marker-negative-accepted')
    parsed = command_backlog_marker(red,'command-backlog')
    bad = [dict(parsed, completed_before=1), dict(parsed, completed_before=None),
           dict(parsed, facts=[True]*13), dict(parsed, runtime_closes=2), dict(parsed, plane_shutdown_returns=2),
           dict(parsed, relay_closed=False), dict(parsed, attempt_completed=False), dict(parsed, target_queue=None),
           dict(parsed, ingress=None), dict(parsed, ingress=[[True]*4,1,3,2,False]),
           dict(parsed, ingress=[[True]*4,1,33,33,False]),
           dict(parsed, ingress=[[True]*4,1,3,3,True])]
    for index in range(13):
        if index != 11:
            facts = list(parsed['facts']); facts[index] = False
            bad.append(dict(parsed, facts=facts))
    for value in bad:
        assert not command_backlog_oracle(value,'command-backlog',True)
        negatives += 1
    assert not command_backlog_oracle(command_backlog_marker(held,'command-backlog-held'),'command-backlog-held',True)
    assert pfp_configuration('command-backlog') == (LIB_FEATURES + ['marmot-app/experimental-device-sync'], 'm5-bounded','4194304')
    assert 'command-backlog-held' not in PFP and positive_configuration('command-backlog-held') == pfp_configuration('command-backlog')
    assert PFP['command-backlog'][1].count('command_input_service_owed = true;') == 1
    assert PFP['command-backlog'][2] == PFP['command-backlog'][1].replace('true','false')
    status = ('FAIL [ 0.001s] (1/1) marmot-app ' + CASES['command-backlog'][1]
              + '\nSummary [ 0.01s] 1 test run: 0 passed, 1 failed, 0 skipped\n').encode()
    header = ("thread '" + CASES['command-backlog'][1] + "' (7) panicked at " + CASES['command-backlog'][2]
              + ':' + str(site['line']) + ':' + str(site['column']) + ':\n')
    own = status + red + (header + PFP['command-backlog'][3] + '\n').encode()
    assert counts(own,'command-backlog')['failed'] == 1 and own_failure(own,'command-backlog',site)
    assert compiler(own+b'error[E0308]: PRIVATE\n',{})['header_count'] == 1
    return {'positive':6,'negative':negatives+1,'configuration_controls':4,'compiler_rejection_controls':1,
            'synthetic_metadata_only':True,'product_bodies':0}


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



UNIFFI_STALE_ASSERT = 'actual stale replacement must preserve the cancelled command update'
UNIFFI_STALE_PATTERN = r'assert!\(\s*stale_observed\s*&&\s*command_after_stale\s*&&\s*observed,\s*"{message}"\s*\);'


def uniffi_receive_site():
    # Positive causal RED deliberately accepts the marked break-None source.
    # Only inverse() admits the green continue arm for a PFP mutation.
    text = Path(CASES['uniffi-conversation-stale'][2]).read_text()
    found = list(re.finditer(UNIFFI_STALE_PATTERN.replace('{message}', re.escape(UNIFFI_STALE_ASSERT)), text))
    if len(found) != 1:
        raise ValueError('uniffi-own-oracle-source')
    return {'line': text[:found[0].start()].count('\n') + 1,
            'column': found[0].start() - text.rfind('\n', 0, found[0].start())}


def routing_prerequisite_marker(raw):
    prefix = 'sibling-routing-prerequisite '
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    lines = [line for line in text.splitlines() if prefix.rstrip() in line]
    if len(lines) != 1 or text.count(prefix.rstrip()) != 1 or len(lines[0]) > 2048:
        raise ValueError('routing-prerequisite-cardinality')
    match = re.fullmatch(r'[ \t]{0,8}' + re.escape(prefix) + r'(\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    if match is None:
        raise ValueError('routing-prerequisite-envelope')
    value = json.loads(match[1], object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != {'addressed_a_intake', 'c_observed_count', 'wait_succeeded'}
            or any(type(value[k]) is not bool for k in ['addressed_a_intake', 'wait_succeeded'])
            or (value['c_observed_count'] is not None and not uint(value['c_observed_count']))):
        raise ValueError('routing-prerequisite-fields')
    if (not value['addressed_a_intake'] and value['c_observed_count'] is not None
            or value['wait_succeeded'] and (not value['addressed_a_intake']
                or value['c_observed_count'] is None or value['c_observed_count'] == 0)):
        raise ValueError('routing-prerequisite-short-circuit')
    return value


def routing_prerequisite_controls():
    prefix = 'sibling-routing-prerequisite '
    positive = [{'addressed_a_intake': True, 'c_observed_count': 1, 'wait_succeeded': True},
                {'addressed_a_intake': False, 'c_observed_count': None, 'wait_succeeded': False},
                {'addressed_a_intake': True, 'c_observed_count': 0, 'wait_succeeded': False},
                {'addressed_a_intake': True, 'c_observed_count': None, 'wait_succeeded': False}]
    for row in positive:
        assert routing_prerequisite_marker((prefix + json.dumps(row) + '\n').encode()) == row
    good = positive[0]
    bad = [dict(good, private='PRIVATE'), dict(good, addressed_a_intake=1),
           dict(good, wait_succeeded=1), dict(good, c_observed_count=True),
           dict(good, c_observed_count=-1), dict(good, c_observed_count=2**64),
           dict(good, c_observed_count=0), dict(good, c_observed_count=None),
           dict(good, addressed_a_intake=False), dict(positive[1], c_observed_count=0)]
    raw = (prefix + json.dumps(good) + '\n').encode()
    invalid = [(prefix + json.dumps(row) + '\n').encode() for row in bad]
    invalid += [raw + raw, b'PRIVATE ' + raw, b' '*9 + raw,
                raw.replace(b'"c_observed_count": 1', b'"c_observed_count": 1, "c_observed_count": 1'),
                raw + b'sibling-routing-prerequisite-PRIVATE\n']
    for raw in invalid:
        try:
            routing_prerequisite_marker(raw)
        except ValueError:
            pass
        else:
            raise AssertionError('routing-prerequisite-negative-accepted')
    return {'positive': len(positive), 'negative': len(invalid),
            'synthetic_metadata_only': True, 'product_bodies': 0}


def replay_configuration_controls():
    assert positive_configuration('sibling-send-default') == (LIB_FEATURES, 'ci', None)
    assert positive_configuration('sibling-send-experimental') == (LIB_FEATURES + ['marmot-app/experimental-device-sync'], 'm5-bounded', '4194304')
    assert positive_configuration('offline') == (['test-policy-overrides'], 'ci', None)
    assert positive_configuration('offline-experimental') == (LIB_FEATURES + ['marmot-app/experimental-device-sync'], 'm5-bounded', '4194304')
    for case in UNIFFI_CASES:
        assert package_for(case) == 'marmot-uniffi' and CASES[case][0] == 'marmot_uniffi'
        assert positive_configuration(case) == (UNIFFI_FEATURES, 'm5-bounded', '4194304')
    assert pfp_configuration('uniffi-conversation-stale') == (UNIFFI_FEATURES, 'm5-bounded', '4194304')
    assert positive_configuration('wrong-recipient-routing') == (LIB_FEATURES + ['marmot-app/experimental-device-sync'], 'm5-bounded', '4194304')
    assert positive_configuration('late-commit-extra-epoch') == (['test-policy-overrides', 'cgka-engine/test-policy-overrides', 'cgka-engine/test-crash-hooks'], 'ci', None)
    return {'positive': 10, 'synthetic_metadata_only': True, 'product_bodies': 0}


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
    value['process_window'] = {key: [None, None, None] for key in PROCESS_COUNTERS}
    assert closed(value) == value
    # Unknown, successful, and regressed counters never decide the body verdict.
    for sample in [[3, 8, 5], [8, 3, None], [None, 8, None], [0, 0, 0]]:
        accepted = json.loads(json.dumps(value))
        accepted['process_window']['user_ticks'] = sample
        assert closed(accepted) == accepted
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
    for sample in [[True, 8, 7], [-1, 8, 9], [0, 2**64, None], [3, 8, 4],
                   [8, 3, 0], [None, 8, 0], [0, 0], ['PRIVATE', 0, None]]:
        row = json.loads(json.dumps(value)); row['process_window']['user_ticks'] = sample; bad.append(row)
    for window in [{}, dict(value['process_window'], private=[0, 0, 0]), None]:
        bad.append(dict(value, process_window=window))
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
    'cursor-promotion-observation': ('crates/marmot-app/src/client/sync.rs',
              '        self.checkpointed_transport_timestamp = previous.max(reached);',
              '        self.checkpointed_transport_timestamp = previous.max(self.state.last_transport_timestamp);',
              'the older delivery still queued caps the promotion where a restart refetches it',
              r'assert_eq!\(\s*persisted,\s*Some\(cursor_before\s*\+\s*1_000\s*\+\s*120\),\s*"{message}"\s*\);'),
    'private-classifier-authentication': ('crates/cgka-engine/src/private_enrollment_request.rs', 'pub(crate) fn is_request_payload(payload: &[u8], sender: Option<&MemberId>) -> bool {\n    let Some(sender) = sender else { return false };\n    let Ok(event) = crate::app_payload::validate_app_payload_for_sender(payload, sender) else {', 'pub(crate) fn is_request_payload(payload: &[u8], sender: Option<&MemberId>) -> bool {\n    let Some(sender) = sender else { return false };\n    let Ok(event) = cgka_traits::app_event::MarmotAppEvent::decode(payload).map(|event| { let _ = sender; event }) else {', 'private classification must require exact authenticated sender', 'assert!\\(\\s*!crate::private_enrollment_request::is_request_payload\\(&payload,\\s*Some\\(&other\\)\\),\\s*"{message}"\\s*\\);'),
    'private-classifier-kinds': ('crates/cgka-engine/src/private_enrollment_request.rs', '    if matches!(\n        event.kind,\n        REQUEST_KIND | crate::private_enrollment_endorsement::ENDORSEMENT_KIND\n    ) {', '    if false && matches!(\n        event.kind,\n        REQUEST_KIND | crate::private_enrollment_endorsement::ENDORSEMENT_KIND\n    ) {', 'reserved private kinds and protocol hints must stay private', 'assert!\\(\\s*crate::private_enrollment_request::is_request_payload\\(\\s*&payload,\\s*Some\\(&sender\\)\\s*\\),\\s*"{message}"\\s*\\);'),
    'uniffi-conversation-stale': ('crates/marmot-uniffi/src/commands/account_chat_windows/tests.rs',
              '                    // ACTUAL_STALE_COMMAND_RECOVERY_BEGIN\n                    continue;\n                    // ACTUAL_STALE_COMMAND_RECOVERY_END',
              '                    // ACTUAL_STALE_COMMAND_RECOVERY_BEGIN\n                    break None;\n                    // ACTUAL_STALE_COMMAND_RECOVERY_END',
              UNIFFI_STALE_ASSERT, UNIFFI_STALE_PATTERN),
    'command-owned-cleanup': ('crates/marmot-app/src/native_device_linking/tests/recipient_sibling_admission_acceptance.rs',
              '            // accepts. The locked MockRelay stop notification is not sticky;\n            // this does not establish why any earlier stop was unobserved.\n            relay.shutdown();',
              '            // accepts. The locked MockRelay stop notification is not sticky;\n            // this does not establish why any earlier stop was unobserved.\n            let _ = relay;',
              'owned MockRelay cleanup must finish without an observed initial stop',
              r'assert!\(\s*listener_started\s*&&\s*closed_in_original_bound\s*&&\s*owned_cleanup_completed,\s*"{message}"\s*\);'),
    'command-backlog': ('crates/marmot-app/src/runtime/account_worker.rs',
              '                                { command_input_service_owed = true; }',
              '                                { command_input_service_owed = false; }',
              'authenticated_body_must_precede_second_queued_history_read',
              r'assert!\(\s*facts\.into_iter\(\)\.all\(\|value\| value\)\s*&& runtime_closes == 3\s*&& planes_shutdown == 3\s*&& relay_closed\s*&& attempt_completed,\s*"{message}"\s*\);'),
    'sdk-private-capture-control': ('crates/transport-nostr-adapter/src/live_delivery.rs',
              '    pub(crate) async fn observe_private_sdk_eose(\n        &mut self,\n        endpoint: cgka_traits::TransportEndpoint,\n        subscription: &str,\n    ) {\n        let state = self.adapter.state.read().await;\n        self.eose.retain(|token| token.matches_current(&state));\n        let parsed_endpoint = nostr::prelude::RelayUrl::parse(endpoint.as_str()).ok();\n        for (account_id, wire) in &state.private_observation_wires {\n            if self\n                .account\n                .as_ref()\n                .is_some_and(|wanted| wanted != account_id)\n                || !wire.ready\n                || wire.actual != subscription\n                || !state\n                    .accounts\n                    .get(account_id)\n                    .is_some_and(|account| account.attempt == wire.attempt)\n            {\n                continue;\n            }\n            let crate::NostrSubscription::Group {\n                group_id,\n                transport_group_id,\n                endpoints,\n                ..\n            } = &wire.subscription\n            else {\n                continue;\n            };\n            if &wire.group != group_id\n                || !endpoints.iter().any(|candidate| {\n                    crate::CanonicalEndpoint::new(candidate)\n                        .matches(&endpoint, parsed_endpoint.as_ref())\n                })\n            {\n                continue;\n            }\n            let token = ReceiverEose {\n                account: account_id.clone(),\n                group: group_id.clone(),\n                transport_group: transport_group_id.clone(),\n                endpoint: endpoint.clone(),\n                subscription: subscription.to_owned(),\n                attempt: wire.attempt,\n            };\n            // Reuse the existing full route/attempt/current-wire validation.\n            if token.matches_current(&state)\n                && !self.eose.iter().any(|old| {\n                    old.account == token.account\n                        && old.group == token.group\n                        && old.endpoint == token.endpoint\n                        && old.subscription == token.subscription\n                })\n            {\n                self.eose.push(token);\n            }\n        }\n    }\n\n',
              '    pub(crate) async fn observe_private_sdk_eose(\n        &mut self,\n        endpoint: cgka_traits::TransportEndpoint,\n        subscription: &str,\n    ) {\n        self.observe_eose(endpoint, subscription).await;\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n    }\n\n',
              'ordinary SDK copies must skip private capture while generic capture remains available',
              'assert!\\(\\s*sdk_skipped\\s*&&\\s*generic_preserved,\\s*"{message}"\\s*\\);'),
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

PFP['cursor-promotion-experimental'] = PFP['cursor-promotion-observation']


def validate_sdk_capture_inverse(text, old, new):
    start = text.index('    pub(crate) async fn observe_private_sdk_eose(')
    end = text.index('    /// No captured private EOSE', start)
    signature = old[:old.index('    ) {\n') + len('    ) {\n')]
    allowed = re.escape(signature) + '[ \\t\\n]*self\\.observe_eose\\(endpoint, subscription\\)\\.await;[ \\t\\n]*\\}\\n\\n'
    if (text.count(old) != 1 or text[start:end] != old
            or old.count('\n') != new.count('\n')
            or re.fullmatch(allowed, new) is None):
        raise ValueError('inverse-sdk-capture-owner-or-lines')


CURSOR_INNER_THREAD = 'live-cursor-promotion'
CURSOR_JOIN_MESSAGE = 'called `Result::unwrap()` on an `Err` value: Any { .. }'


def bind_cursor_composed_site(fixture, case, site):
    function = 'fn ' + CASES[case][1].split('::')[-1] + '() {'
    start = fixture.index(function)
    end = fixture.index('\n#[test]', start)
    body = fixture[start:end]
    call = 'run_composed_app_runtime_test("' + CURSOR_INNER_THREAD + '", || async {'
    wrapper_start = fixture.index('fn run_composed_app_runtime<F, Fut>(')
    wrapper_end = fixture.index('\n#[test]', wrapper_start)
    wrapper = fixture[wrapper_start:wrapper_end]
    line = '    test_thread.join().unwrap();'
    if (body.count(call) != 1 or fixture.count(line) != 1
            or wrapper.count(line) != 1
            or '.name(thread_name.to_owned())' not in wrapper):
        raise ValueError('cursor-composed-thread-source')
    offset = fixture.index(line, wrapper_start)
    bound = dict(site)
    bound['inner_thread'] = CURSOR_INNER_THREAD
    bound['wrapper'] = {'line': fixture[:offset].count('\n') + 1,
                        'column': line.index('unwrap()') + 1}
    return bound


def cursor_failure_facts(raw, case, site):
    text = ANSI.sub('', raw.decode('utf-8', errors='replace'))
    pattern = (r"(?m)^[ \t]{0,8}thread '([^'\r\n]{1,256})'"
               + r"(?: \([1-9][0-9]{0,9}\))? panicked at ([A-Za-z0-9_./-]{1,256}):"
               + r'([1-9][0-9]{0,5}):([1-9][0-9]{0,5}):[ \t]*\r?\n'
               + r'(?:[ \t]{0,8}\r?\n){0,2}[ \t]{0,8}([^\r\n]{1,512})')
    headers = [match.groups() for match in re.finditer(pattern, text)]
    inner = (site['inner_thread'], CASES[case][2], str(site['line']), str(site['column']),
             runtime_assert_message(case))
    wrapper = (CASES[case][1], CASES[case][2], str(site['wrapper']['line']),
               str(site['wrapper']['column']), CURSOR_JOIN_MESSAGE)
    expected = [inner, wrapper]
    known = []
    for role, row in zip(('inner', 'composed_join'), expected):
        if sum(header[:4] == row[:4] for header in headers) == 1:
            known.append({'role': role, 'file': row[1], 'line': int(row[2]), 'column': int(row[3])})
    count = text.count('panicked at ')
    return {'header_count': count, 'known_sites': known,
            'unknown_or_excess_headers': max(0, count - len(known)),
            'exact_inner_assertion': len(headers) >= 1 and headers[0] == inner,
            'exact_composed_join': len(headers) == 2 and headers[1] == wrapper,
            'ordered_exact_inner_and_join': count == 2 and headers == expected}


def cursor_synthetic_failure(case, site):
    def header(thread, line, column):
        return ("thread '" + thread + "' (7) panicked at " + CASES[case][2]
                + ':' + str(line) + ':' + str(column) + ':\n')
    return (header(site['inner_thread'], site['line'], site['column'])
            + runtime_assert_message(case) + '\n  left: Some(5000)\n right: Some(2120)\n'
            + header(CASES[case][1], site['wrapper']['line'], site['wrapper']['column'])
            + CURSOR_JOIN_MESSAGE + '\n').encode()


def cursor_pfp_own_controls(case, site):
    valid = cursor_synthetic_failure(case, site)
    assert own_failure(valid, case, site)
    assert own_failure(valid.replace(b"' (7)", b"'"), case, site)
    assert own_failure(valid.replace(b'\n', b'\r\n'), case, site)
    assert own_failure(valid.replace(runtime_assert_message(case).encode(), b' '*8 + runtime_assert_message(case).encode()), case, site)
    inner, wrapper = valid.split(("thread '" + CASES[case][1] + "' (7)").encode(), 1)
    outer = ("thread '" + CASES[case][1] + "' (7)").encode() + wrapper
    invalid = [valid + valid, outer + inner, inner,
               valid.replace(site['inner_thread'].encode(), b'PRIVATE'),
               valid.replace(CASES[case][1].encode(), b'PRIVATE'),
               valid.replace(CASES[case][2].encode(), b'PRIVATE.rs'),
               valid.replace((':' + str(site['line']) + ':').encode(), b':999999:'),
               valid.replace((':' + str(site['wrapper']['line']) + ':').encode(), b':999999:'),
               valid.replace((':' + str(site['column']) + ':\n').encode(), b':999999:\n', 1),
               valid.replace(b'assertion `left == right` failed: ', b''),
               valid.replace(b'left == right', b'left != right'),
               valid.replace(CURSOR_JOIN_MESSAGE.encode(), b'PRIVATE'),
               b'PRIVATE ' + valid,
               valid.replace(runtime_assert_message(case).encode(), b' '*9 + runtime_assert_message(case).encode()),
               valid + b"thread 'PRIVATE' panicked at PRIVATE.rs:1:1:\nPRIVATE\n"]
    for raw in invalid:
        assert not own_failure(raw, case, site)
    facts = cursor_failure_facts(valid, case, site)
    assert len(facts['known_sites']) == 2 and facts['unknown_or_excess_headers'] == 0
    return {'positive': 4, 'negative': len(invalid), 'synthetic_metadata_only': True, 'product_bodies': 0}


def validate_cursor_inverse(text, old, new):
    start = text.index('    pub(crate) fn seal_transport_cursor(&mut self) -> SealedTransportCursor {')
    end = text.index('    pub(crate) fn abandon_transport_cursor(', start)
    if (text.count(old) != 1 or old not in text[start:end]
            or old != '        self.checkpointed_transport_timestamp = previous.max(reached);'
            or new != '        self.checkpointed_transport_timestamp = previous.max(self.state.last_transport_timestamp);'
            or old.count('\n') != new.count('\n')):
        raise ValueError('inverse-cursor-seal-owner')


def runtime_assert_message(case):
    message = PFP[case][3]
    return 'assertion `left == right` failed: ' + message if case in CURSOR_CASES else message


def cursor_pfp_oracle(value, mutant):
    if (type(value) is not dict or value.get('marker_present') is not True
            or type(value.get('observation')) is not dict):
        return False
    expected = dict(first_is_newer=True, first_is_older=False, in_memory_is_newer=True,
                    checkpoint_is_initial=False, seal_before=True, seal_after=True,
                    delivery_loss=False, transport_cursor_settled=True,
                    persisted_relative_to_initial=4000 if mutant else 1120)
    return value['observation'] == expected


def cursor_pfp_controls(case, site):
    path, old, new, message, pattern = PFP[case]
    source = Path(path).read_text()
    validate_cursor_inverse(source, old, new)
    assert pfp_configuration('cursor-promotion-observation') == (LIB_FEATURES, 'ci', None)
    assert pfp_configuration('cursor-promotion-experimental') == (LIB_FEATURES + ['marmot-app/experimental-device-sync'], 'm5-bounded', '4194304')
    assert package_for(case) == 'marmot-app' and CASES[case] == CASES['cursor-promotion-observation']
    scope_bad = [(source + old, new),
                 (source.replace('    pub(crate) fn seal_transport_cursor(&mut self)', '    pub(crate) fn PRIVATE(&mut self)'), new),
                 (source, new + ' self.checkpointed_transport_timestamp = None;')]
    for changed, inverse in scope_bad:
        try:
            validate_cursor_inverse(changed, old, inverse)
        except ValueError:
            pass
        else:
            raise AssertionError('cursor-inverse-scope-negative-accepted')
    good = dict(first_is_newer=True, first_is_older=False, in_memory_is_newer=True,
                checkpoint_is_initial=False, seal_before=True, seal_after=True,
                delivery_loss=False, transport_cursor_settled=True,
                persisted_relative_to_initial=1120)
    encode = lambda row: ('cursor-promotion-observation ' + json.dumps(row) + '\n').encode()
    green = fixture_observation(encode(good), case)
    red = fixture_observation(encode(dict(good, persisted_relative_to_initial=4000)), case)
    assert cursor_pfp_oracle(green, False) and cursor_pfp_oracle(red, True)
    negative = 0
    for mutant, row in [(True, green), (False, red), (True, dict(red, marker_present=False)),
                        (True, dict(red, observation=None))]:
        assert not cursor_pfp_oracle(row, mutant)
        negative += 1
    for key in CURSOR_BOOLS:
        row = dict(good, persisted_relative_to_initial=4000)
        row[key] = not row[key]
        assert not cursor_pfp_oracle(fixture_observation(encode(row), case), True)
        negative += 1
    status = ('FAIL [ 0.001s] (1/1) marmot-app ' + CASES[case][1]
              + '\nSummary [ 0.01s] 1 test run: 0 passed, 1 failed, 0 skipped\n').encode()
    raw = status + cursor_synthetic_failure(case, site)
    assert counts(raw, case)['failed'] == 1 and own_failure(raw, case, site)
    assert compiler(raw + b'error[E0308]: PRIVATE\n', {})['header_count'] == 1
    return {'positive': 3, 'negative': negative, 'scope_negative': len(scope_bad),
            'configuration_controls': 3, 'compiler_rejection_controls': 1,
            'synthetic_metadata_only': True, 'product_bodies': 0}


def inverse(case):
    path, old, new, message, pattern = PFP[case]
    original = Path(path).read_bytes()
    text = original.decode('utf-8')
    if text.count(old) != 1:
        raise ValueError('inverse-anchor')
    if case in CURSOR_CASES:
        validate_cursor_inverse(text, old, new)
    if case in ENGINE_CLASSIFIER_CASES:
        start = text.index('pub(crate) fn is_request_payload(')
        end = text.index('pub(crate) fn stage(', start)
        if old not in text[start:end] or old.count('\n') != new.count('\n'):
            raise ValueError('inverse-engine-classifier-owner')
    if case == 'sdk-private-capture-control':
        validate_sdk_capture_inverse(text, old, new)
    if case == 'uniffi-conversation-stale':
        start = text.index('async fn actual_window_receive_cancellation(')
        end = text.index('        let observed = if let Some((pending, completed_before, replacement))', start)
        if old not in text[start:end]:
            raise ValueError('inverse-uniffi-stale-owner')
    if case == 'command-backlog':
        start = text.index('async fn run_app_runtime_account_worker(')
        owner = text.index('                            Some((command, approved_pending)) => {', start)
        end = text.index('                                #[cfg(test)]', owner)
        if text.count(old) != 1 or old not in text[owner:end]:
            raise ValueError('inverse-command-dispatch-owner')
    if case == 'command-owned-cleanup':
        start = text.index('// OWNED_MOCK_RELAY_CLEANUP_BEGIN')
        end = text.index('// OWNED_MOCK_RELAY_CLEANUP_END', start)
        if old not in text[start:end]:
            raise ValueError('inverse-owned-cleanup-owner')
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
    if case in CURSOR_CASES:
        site = bind_cursor_composed_site(fixture, case, site)
    return path, original, text.replace(old, new, 1).encode(), site


def own_failure(raw, case, site):
    if case in CURSOR_CASES:
        return cursor_failure_facts(raw, case, site)['ordered_exact_inner_and_join']
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
    if case in CURSOR_CASES:
        return cursor_pfp_own_controls(case, site)
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
    if case in ENGINE_CLASSIFIER_CASES:
        return ENGINE_FEATURES, 'ci', None
    if case == 'uniffi-conversation-stale':
        return UNIFFI_FEATURES, 'm5-bounded', '4194304'
    if case == 'sdk-private-capture-control':
        return (['sdk', 'experimental-device-sync', 'test-policy-overrides'], 'm5-bounded', '4194304')
    return ((LIB_FEATURES + ['marmot-app/experimental-device-sync'], 'm5-bounded', '4194304')
            if case in {'cursor-promotion-experimental', 'command-owned-cleanup', 'watch-pressure', 'worker-input-offer', 'command-backlog'} else (LIB_FEATURES, 'ci', None))


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


def sdk_private_capture_controls(site):
    case = 'sdk-private-capture-control'
    path, old, new, message, pattern = PFP[case]
    assert pfp_configuration(case) == (['sdk', 'experimental-device-sync', 'test-policy-overrides'], 'm5-bounded', '4194304')
    assert package_for(case) == 'transport-nostr-adapter' and case in ADAPTER_CASES and case not in INTEGRATION_CASES
    assert pfp_configuration('inline') == pfp_configuration('spill') == (LIB_FEATURES, 'ci', None)
    assert pfp_configuration('watch-pressure') == pfp_configuration('worker-input-offer') == (LIB_FEATURES + ['marmot-app/experimental-device-sync'], 'm5-bounded', '4194304')
    assert old.count('\n') == new.count('\n') and new.count('self.observe_eose(endpoint, subscription).await;') == 1
    fixture = Path(path).read_text()
    validate_sdk_capture_inverse(fixture, old, new)
    scope_negatives = [
        (fixture + old, new),
        (fixture.replace('    pub(crate) async fn observe_private_sdk_eose(', '    pub(crate) async fn PRIVATE('), new),
        (fixture, new + '\n'),
        (fixture, new.replace('self.observe_eose(endpoint, subscription).await;', 'self.observe_eose(endpoint, subscription).await; self.eose.clear();')),
    ]
    for changed_source, changed_inverse in scope_negatives:
        try:
            validate_sdk_capture_inverse(changed_source, old, changed_inverse)
        except ValueError:
            pass
        else:
            raise AssertionError('sdk-capture-scope-negative-accepted')
    changed = fixture.replace(old, new, 1)
    expression = pattern.replace('{message}', re.escape(message))
    original_sites = list(re.finditer(expression, fixture))
    mutant_sites = list(re.finditer(expression, changed))
    assert len(original_sites) == len(mutant_sites) == 1
    assert fixture[:original_sites[0].start()].count('\n') == changed[:mutant_sites[0].start()].count('\n') == site['line'] - 1
    prefix = "FAIL [ 0.001s] (1/1) transport-nostr-adapter " + CASES[case][1]
    status = (prefix + "\nSummary [ 0.01s] 1 test run: 0 passed, 1 failed, 0 skipped\n").encode()
    header = ("thread '" + CASES[case][1] + "' (7) panicked at " + path
              + ':' + str(site['line']) + ':' + str(site['column']) + ':\n')
    raw = status + (header + message + '\n').encode()
    assert counts(raw, case)['failed'] == 1 and own_failure(raw, case, site)
    negatives = 0
    for bad in [raw.replace(CASES[case][1].encode(), b'PRIVATE'),
                raw.replace(path.encode(), b'PRIVATE.rs'), raw.replace(message.encode(), b'PRIVATE'),
                raw + (header + message + '\n').encode(),
                raw.replace((':' + str(site['line']) + ':').encode(), b':999999:')]:
        assert not own_failure(bad, case, site)
        negatives += 1
    try:
        counts(raw.replace(b'transport-nostr-adapter ', b'marmot-app '), case)
    except ValueError:
        negatives += 1
    else:
        raise AssertionError('sdk-pfp-wrong-package-accepted')
    assert compiler(raw + b'error[E0308]: PRIVATE\n', {})['header_count'] == 1
    return {'positive': 5, 'negative': negatives, 'configuration_controls': 4, 'scope_negative_controls': len(scope_negatives),
            'compiler_rejection_controls': 1, 'synthetic_metadata_only': True, 'product_bodies': 0}


def owned_cleanup_marker(raw):
    prefix = b'command-backlog-owned-cleanup '
    namespace = b'command-backlog-owned-cleanup'
    if len(raw) > 16 * 1024 * 1024 or raw.count(namespace) != 1:
        raise ValueError('owned-cleanup-namespace')
    rows = re.findall(rb'(?m)^[ \t]{0,8}' + re.escape(prefix) + rb'([^\r\n]{1,1024})\r?$', raw)
    if len(rows) != 1:
        raise ValueError('owned-cleanup-envelope')
    value = json.loads(rows[0], object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != {'listener_started', 'closed_in_original_bound', 'owned_cleanup_completed'}
            or any(type(item) is not bool for item in value.values())):
        raise ValueError('owned-cleanup-fields')
    return value


def owned_cleanup_oracle(value, mutant):
    return value == {'listener_started': True, 'closed_in_original_bound': not mutant, 'owned_cleanup_completed': True}


def owned_cleanup_site():
    case = 'command-owned-cleanup'
    text = Path(CASES[case][2]).read_text()
    pattern = PFP[case][4].replace('{message}', re.escape(PFP[case][3]))
    matches = list(re.finditer(pattern, text))
    if len(matches) != 1:
        raise ValueError('owned-cleanup-source-assertion')
    return {'line': text[:matches[0].start()].count('\n') + 1,
            'column': matches[0].start() - text.rfind('\n', 0, matches[0].start())}


def owned_cleanup_controls(site):
    case = 'command-owned-cleanup'
    green = {'listener_started': True, 'closed_in_original_bound': True, 'owned_cleanup_completed': True}
    red = dict(green, closed_in_original_bound=False)
    raw = b'command-backlog-owned-cleanup ' + json.dumps(green).encode() + b'\n'
    positives = 0
    for good in [raw, b' '*4 + raw, b' '*8 + raw, raw.replace(b'\n', b'\r\n')]:
        assert owned_cleanup_marker(good) == green
        positives += 1
    assert owned_cleanup_marker(b'command-backlog-owned-cleanup ' + json.dumps(red).encode() + b'\n') == red
    positives += 1
    bad_values = [dict(green, extra=False), dict(green, listener_started=1), dict(green, owned_cleanup_completed=None),
                  {key: value for key, value in green.items() if key != 'listener_started'}, []]
    bad = [b'command-backlog-owned-cleanup ' + json.dumps(value).encode() + b'\n' for value in bad_values]
    bad += [raw + raw, b'PRIVATE ' + raw, b' '*9 + raw,
            raw.replace(b'"listener_started": true', b'"listener_started": true, "listener_started": true'),
            b'command-backlog-owned-cleanup-unknown {}\n', raw + b'command-backlog-owned-cleanup-unknown {}\n',
            b'command-backlog-owned-cleanup ' + b'x'*1025 + b'\n']
    negatives = 0
    for invalid in bad:
        try:
            owned_cleanup_marker(invalid)
        except (ValueError, json.JSONDecodeError):
            negatives += 1
        else:
            raise AssertionError('owned-cleanup-invalid-accepted')
    assert owned_cleanup_oracle(green, False) and owned_cleanup_oracle(red, True)
    assert not owned_cleanup_oracle(red, False) and not owned_cleanup_oracle(green, True)
    assert not owned_cleanup_oracle(dict(red, listener_started=False), True)
    assert not owned_cleanup_oracle(dict(red, owned_cleanup_completed=False), True)
    assert pfp_configuration(case) == pfp_configuration('command-backlog')
    header = ("thread '" + CASES[case][1] + "' (7) panicked at " + CASES[case][2] + ':' + str(site['line']) + ':5:\n').encode()
    failed = header + PFP[case][3].encode() + b'\n'
    assert own_failure(failed, case, site)
    assert not own_failure(failed.replace(CASES[case][1].encode(), b'PRIVATE'), case, site)
    return {'positive': positives + 1, 'negative': negatives + 5, 'configuration_controls': 1,
            'synthetic_metadata_only': True, 'product_bodies': 0}


def pfp(args):
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    features, profile, expected_stack = pfp_configuration(args.case)
    report = {'case': args.case, 'stage': 'pfp', 'source': git('rev-parse', 'HEAD'),
              'baseline': args.baseline, 'qualification_passed': False, 'pfp_passed': False,
              'phases': [], 'automatic_retries': 0, 'profile': profile, 'features': features,
              'test_threads': 1, 'rust_min_stack': os.environ.get('RUST_MIN_STACK')}
    if args.case in ENGINE_CLASSIFIER_CASES:
        report.update(evidence_scope='private-Engine-classifier-and-preserved-ingress-controls-only',
                      package='cgka-engine', binary='cgka_engine',
                      native_protocol_qualification=False, throughput_fix_established=False)
    if args.case in UNIFFI_CASES:
        report.update(evidence_scope='uniffi-window-cancellation-fixture-mechanism-only',
                      package='marmot-uniffi', binary='marmot_uniffi',
                      native_protocol_qualification=False, sdk_native_acceptance_qualification=False)
    if args.case in {'offline-experimental', 'wrong-recipient-routing'}:
        report.update(evidence_scope='scoped-experimental-App-only',
                      native_protocol_qualification=False, full_workspace_feature_union=False)
    if args.case in CURSOR_CASES:
        report.update(evidence_scope='cursor-router-pin-fixture-mechanism-only', native_protocol_qualification=False,
                      historical_full_failure_cause_proven=False)
    if args.case == 'command-owned-cleanup':
        report.update(evidence_scope='owned-mock-relay-cleanup-mechanism-only', native_protocol_qualification=False)
    if args.case in WORKER_INPUT_CASES:
        report.update(evidence_scope='worker-input-selection-mechanism-only', native_protocol_qualification=False)
    if args.case == 'sdk-private-capture-control':
        report.update(evidence_scope='sdk-private-capture-component-only',
                      native_protocol_qualification=False, queue_overflow_remedy_qualified=False)
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
    def phase(label, expected, *, case=None):
        phase_case = args.case if case is None else case
        if case is not None and (args.case != 'command-backlog' or case != 'command-backlog-held' or label not in {'baseline-held', 'restored-held'}):
            raise ValueError('phase-case-scope')
        if snapshot() != expected:
            raise ValueError('phase-source')
        row = {'phase': label, 'case': phase_case, 'inventory_attempted': True,
               'source_manifest_sha256': hashlib.sha256(json.dumps(expected['inputs'], sort_keys=True).encode()).hexdigest()}
        report['phases'].append(row)
        save()
        package = package_for(phase_case)
        flags = ['-p', package, '--lib', '--features', ','.join(features), '--locked', '--profile', profile]
        selection = 'package(' + package + ') & test(=' + CASES[phase_case][1] + ')'
        if phase_case in UNIFFI_CASES:
            selection += ' & binary(=marmot_uniffi)'
        if phase_case in ENGINE_CASES:
            selection += ' & binary(=cgka_engine)'
        code, raw, elapsed, stderr = capture(['cargo', 'nextest', 'list'] + flags + ['--message-format', 'json', '-E', selection], 1800, separate=True)
        row['inventory'] = {'exit_code': code, 'elapsed_seconds': elapsed,
                            'stdout_sha256': hashlib.sha256(raw).hexdigest(), 'stdout_bytes': len(raw),
                            'stderr_sha256': hashlib.sha256(stderr).hexdigest(), 'stderr_bytes': len(stderr),
                            'compiler': compiler(stderr, expected['inputs'])}
        save()
        if code != 0 or row['inventory']['compiler']['header_count'] or row['inventory']['compiler']['codes']:
            raise ValueError('phase-inventory-command')
        selected_case(json.loads(raw, object_pairs_hook=unique), CASES[phase_case][1])
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
                       'compiler': compiler(raw, expected['inputs']), 'panic': panic_facts(raw, phase_case)}
        save()
        row['body']['counts'] = counts(raw, phase_case)
        save()
        row['source_exact_after_body'] = snapshot() == expected
        clean_compile = not row['body']['compiler']['codes'] and row['body']['compiler']['header_count'] == 0
        watch_accepted = True
        if args.case in CURSOR_CASES:
            row['body']['cursor_panic_facts'] = cursor_failure_facts(raw, phase_case, site)
            save()
            row['body']['fixture_observation'] = fixture_observation(raw, phase_case)
            watch_accepted = cursor_pfp_oracle(row['body']['fixture_observation'], label == 'mutant')
            row['cursor_prerequisites_accepted'] = watch_accepted
            save()
        if args.case == 'command-owned-cleanup':
            row['body']['owned_cleanup_observation'] = owned_cleanup_marker(raw)
            watch_accepted = owned_cleanup_oracle(row['body']['owned_cleanup_observation'], label == 'mutant')
            row['cleanup_prerequisites_accepted'] = watch_accepted
            save()
        if args.case == 'watch-pressure':
            row['body']['watch_observation'] = watch_marker(raw)
            watch_accepted = watch_pfp_oracle(row['body']['watch_observation'], label == 'mutant')
            row['watch_prerequisites_accepted'] = watch_accepted
            save()
        if phase_case in COMMAND_BACKLOG_CASES:
            row['body']['command_backlog_observation'] = command_backlog_marker(raw, phase_case)
            watch_accepted = command_backlog_oracle(row['body']['command_backlog_observation'], phase_case, label == 'mutant')
            row['command_prerequisites_accepted'] = watch_accepted
            save()
        if phase_case in UNIFFI_CASES:
            observation = uniffi_receive_marker(raw, phase_case, ANSI)
            row['body']['uniffi_receive_observation'] = observation
            watch_accepted = uniffi_receive_oracle(observation, phase_case, label == 'mutant')
            row['uniffi_prerequisites_accepted'] = watch_accepted
            save()
        if label == 'mutant':
            row['own_runtime_failure'] = own_failure(raw, phase_case, site)
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
        if args.case in CURSOR_CASES:
            report['cursor_pfp_controls'] = cursor_pfp_controls(args.case, site)
        if args.case in ENGINE_CLASSIFIER_CASES:
            report['engine_bundle_controls'] = engine_bundle_controls()
        report['configuration_controls'] = replay_configuration_controls()
        if args.case in UNIFFI_CASES:
            report['uniffi_receive_controls'] = uniffi_receive_controls(ANSI)
        if args.case == 'command-owned-cleanup':
            report['owned_cleanup_controls'] = owned_cleanup_controls(site)
        if args.case == 'command-backlog':
            report['command_backlog_controls'] = command_backlog_controls(site)
        if args.case == 'sdk-private-capture-control':
            report['sdk_private_capture_controls'] = sdk_private_capture_controls(site)
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
            if args.case == 'command-backlog':
                phase('baseline-held', before, case='command-backlog-held')
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
            if args.case == 'command-backlog':
                phase('restored-held', before, case='command-backlog-held')
            report['pfp_passed'] = (primary_failure is None and len(report['phases']) == (5 if args.case == 'command-backlog' else 3)
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


SELECTIVE_RECEIPT_PREFIX = 'selective-history-receipt '


def selective_receipt_marker(raw):
    rows = []
    fields = {'stage', 'receipts', 'selected_kinds', 'selected_bound', 'captured_event_count',
              'wait_succeeded', 'expected_message_present', 'local_epoch', 'target_epoch', 'window_requests', 'mapped_outer_id_counts'}
    for line in raw.decode('utf-8', errors='replace').splitlines():
        stripped = line.lstrip(' \t')
        if 'selective-history-receipt' not in stripped:
            continue
        if len(line) - len(stripped) > 8 or not stripped.startswith(SELECTIVE_RECEIPT_PREFIX) or len(stripped) > 2048:
            raise ValueError('selective-receipt-prefix')
        row = json.loads(stripped[len(SELECTIVE_RECEIPT_PREFIX):], object_pairs_hook=unique)
        if type(row) is not dict or set(row) != fields or row['stage'] != len(rows) or type(row['stage']) is not int:
            raise ValueError('selective-receipt-fields-order')
        if len(rows) >= 2:
            raise ValueError('selective-receipt-count')
        for key in ['captured_event_count', 'target_epoch', 'window_requests']:
            if not uint(row[key]):
                raise ValueError('selective-receipt-count-type')
        if (type(row['receipts']) is not list or len(row['receipts']) != 3
                or any(type(item) is not list or len(item) != 3
                       or any(not uint(value) or value > 65535 for value in item) for item in row['receipts'])):
            raise ValueError('selective-receipt-matrix')
        if (type(row['selected_kinds']) is not list or len(row['selected_kinds']) != 3
                or any(not uint(value) or value > 65535 for value in row['selected_kinds'])
                or type(row['selected_bound']) is not list or len(row['selected_bound']) != 3
                or any(type(value) is not bool for value in row['selected_bound'])):
            raise ValueError('selective-receipt-bindings')
        if (type(row['mapped_outer_id_counts']) is not list or len(row['mapped_outer_id_counts']) != 3
                or any(not uint(value) or value > 65535 for value in row['mapped_outer_id_counts'])):
            raise ValueError('selective-receipt-mapped-counts')
        if any(count == 0 and (row['selected_bound'][index] or row['receipts'][index][2] != 0)
               for index, count in enumerate(row['mapped_outer_id_counts'])):
            raise ValueError('selective-receipt-unknown-mapping')
        if row['stage'] == 0:
            if any(row[key] is not None for key in ['wait_succeeded', 'expected_message_present', 'local_epoch']):
                raise ValueError('selective-receipt-early-verdict')
        elif (any(type(row[key]) is not bool for key in ['wait_succeeded', 'expected_message_present'])
              or not uint(row['local_epoch'])):
            raise ValueError('selective-receipt-verdict')
        rows.append(row)
    if len(rows) != 2:
        raise ValueError('selective-receipt-incomplete')
    for key in ['receipts', 'selected_kinds', 'selected_bound', 'mapped_outer_id_counts', 'captured_event_count', 'target_epoch']:
        if rows[0][key] != rows[1][key]:
            raise ValueError('selective-receipt-input-changed')
    if rows[1]['window_requests'] < rows[0]['window_requests']:
        raise ValueError('selective-receipt-counter-regressed')
    return rows


def selective_receipt_controls():
    first = {'stage': 0, 'receipts': [[1, 1, 1]] * 3, 'selected_kinds': [1, 2, 3],
             'selected_bound': [True, False, True], 'mapped_outer_id_counts': [1, 1, 1], 'captured_event_count': 4,
             'wait_succeeded': None, 'expected_message_present': None, 'local_epoch': None,
             'target_epoch': 2, 'window_requests': 0}
    last = dict(first, stage=1, wait_succeeded=False, expected_message_present=False, local_epoch=3, window_requests=11)
    def encoded(a, b):
        return (SELECTIVE_RECEIPT_PREFIX + json.dumps(a) + '\n'
                + SELECTIVE_RECEIPT_PREFIX + json.dumps(b) + '\n').encode()
    raw = encoded(first, last)
    assert selective_receipt_marker(raw) == [first, last]
    assert selective_receipt_marker(raw.replace(b'\n', b'\r\n')) == [first, last]
    unknown = dict(first, mapped_outer_id_counts=[0, 1, 0], selected_bound=[False, True, False],
                   receipts=[[1, 1, 0], [1, 1, 1], [1, 1, 0]])
    unknown_last = dict(unknown, stage=1, wait_succeeded=False, expected_message_present=False, local_epoch=3, window_requests=11)
    assert selective_receipt_marker(encoded(unknown, unknown_last)) == [unknown, unknown_last]
    bad = [encoded(dict(first, private='PRIVATE'), last), encoded(dict(first, stage=True), last),
           encoded(first, dict(last, local_epoch=True)), encoded(first, dict(last, wait_succeeded=1)),
           encoded(dict(first, receipts=[[1, 1, 'PRIVATE']] * 3), last),
           encoded(dict(first, selected_bound=[1, False, True]), last),
           encoded(dict(first, selected_kinds=[65536] * 3), last),
           encoded(dict(first, wait_succeeded=True), last),
           encoded(first, dict(last, target_epoch=3)), encoded(last, first), raw + raw,
           raw.replace(b'"stage": 0', b'"stage":0,"stage":0'),
           raw.replace(SELECTIVE_RECEIPT_PREFIX.encode(), b'PRIVATE ' + SELECTIVE_RECEIPT_PREFIX.encode()),
           raw.replace(b'"captured_event_count": 4', b'"captured_event_count":18446744073709551616'),
           (SELECTIVE_RECEIPT_PREFIX + json.dumps(first) + '\n').encode()]
    bad += [encoded(dict(first, mapped_outer_id_counts=[True, 1, 1]), last),
            encoded(dict(first, mapped_outer_id_counts=[1, 1]), last),
            encoded(dict(first, mapped_outer_id_counts=[65536, 1, 1]), last),
            encoded(dict(first, mapped_outer_id_counts=[0, 1, 1]), last),
            encoded(first, dict(last, mapped_outer_id_counts=[1, 0, 1])),
            encoded({key: value for key, value in first.items() if key != 'mapped_outer_id_counts'},
                    {key: value for key, value in last.items() if key != 'mapped_outer_id_counts'})]
    for invalid in bad:
        try:
            selective_receipt_marker(invalid)
        except (ValueError, TypeError):
            pass
        else:
            raise AssertionError('selective-receipt-negative-accepted')
    return {'positive': 3, 'negative': len(bad), 'metadata_only': True, 'product_bodies': 0}


EXTRA_EPOCH_PREFIX = 'selective-history-extra-epoch '
EXTRA_EPOCH_CLOSE = 'selective-history-extra-epoch-close runtime_closed=true relay_shutdown_returned=true'


def extra_epoch_marker(raw):
    rows, order, closed = [], [], False
    fields = {'stage', 'epoch_before', 'epoch_after', 'published', 'publication_ids',
              'captured_unique', 'distinct_original_wires', 'original_bindings',
              'wait_succeeded', 'expected_message_present', 'alice_epoch',
              'runtime_closed', 'relay_shutdown_returned'}
    expected_order = ['extra0', 'receipt0', 'extra1', 'receipt1', 'close']
    for line in raw.decode('utf-8', errors='replace').splitlines():
        stripped = line.lstrip(' \t')
        if 'selective-history-extra-epoch' in stripped:
            if len(line) - len(stripped) > 8 or len(stripped) > 2048:
                raise ValueError('extra-epoch-prefix')
            if stripped == EXTRA_EPOCH_CLOSE:
                if closed:
                    raise ValueError('extra-epoch-duplicate-close')
                closed = True
                order.append('close')
                continue
            if not stripped.startswith(EXTRA_EPOCH_PREFIX):
                raise ValueError('extra-epoch-namespace')
            row = json.loads(stripped[len(EXTRA_EPOCH_PREFIX):], object_pairs_hook=unique)
            if (type(row) is not dict or set(row) != fields or type(row['stage']) is not int
                    or row['stage'] != len(rows) or len(rows) >= 2):
                raise ValueError('extra-epoch-fields-order')
            for key in ['epoch_before', 'epoch_after', 'published', 'publication_ids', 'captured_unique']:
                if not uint(row[key]):
                    raise ValueError('extra-epoch-integer')
            if (any(type(row[key]) is not bool for key in
                    ['distinct_original_wires', 'runtime_closed', 'relay_shutdown_returned'])
                    or row['runtime_closed'] or row['relay_shutdown_returned']
                    or type(row['original_bindings']) is not list or len(row['original_bindings']) != 3
                    or any(type(value) is not bool for value in row['original_bindings'])):
                raise ValueError('extra-epoch-booleans')
            if row['stage'] == 0:
                if any(row[key] is not None for key in ['wait_succeeded', 'expected_message_present', 'alice_epoch']):
                    raise ValueError('extra-epoch-early-verdict')
            elif (any(type(row[key]) is not bool for key in ['wait_succeeded', 'expected_message_present'])
                  or not uint(row['alice_epoch'])):
                raise ValueError('extra-epoch-verdict')
            if rows and any(rows[0][key] != row[key] for key in fields -
                            {'stage', 'wait_succeeded', 'expected_message_present', 'alice_epoch'}):
                raise ValueError('extra-epoch-input-changed')
            rows.append(row)
            order.append('extra' + str(row['stage']))
        elif 'selective-history-receipt' in stripped:
            if not stripped.startswith(SELECTIVE_RECEIPT_PREFIX):
                raise ValueError('extra-epoch-receipt-prefix')
            row = json.loads(stripped[len(SELECTIVE_RECEIPT_PREFIX):], object_pairs_hook=unique)
            if type(row) is not dict or type(row.get('stage')) is not int or row['stage'] not in [0, 1]:
                raise ValueError('extra-epoch-receipt-order')
            order.append('receipt' + str(row['stage']))
    if (len(order) != len(set(order)) or any(item not in expected_order for item in order)
            or [expected_order.index(item) for item in order] != sorted(expected_order.index(item) for item in order)):
        raise ValueError('extra-epoch-marker-order')
    return {'rows': rows, 'positive_close': closed, 'marker_order': order,
            'collection_complete': order == expected_order, 'backend_shutdown_is_socket_ack': False}


def extra_epoch_oracle(observation, receipts):
    if not observation['collection_complete'] or not observation['positive_close'] or len(receipts) != 2:
        return False
    first, last = observation['rows']
    return (first['epoch_before'] == 2 and first['epoch_after'] == 3
            and all(first[key] == 1 for key in ['published', 'publication_ids', 'captured_unique'])
            and first['distinct_original_wires'] and first['original_bindings'] == [True] * 3
            and last['wait_succeeded'] and last['expected_message_present'] and last['alice_epoch'] >= 3
            and all(row['selected_bound'] == [True] * 3 and row['mapped_outer_id_counts'] == [1] * 3
                    and row['receipts'] == [[1, 1, 1]] * 3 and row['target_epoch'] == 2 for row in receipts)
            and receipts[1]['wait_succeeded'] == last['wait_succeeded']
            and receipts[1]['expected_message_present'] == last['expected_message_present']
            and receipts[1]['local_epoch'] == last['alice_epoch'])


def extra_epoch_controls():
    first = {'stage': 0, 'epoch_before': 2, 'epoch_after': 3, 'published': 1,
             'publication_ids': 1, 'captured_unique': 1, 'distinct_original_wires': True,
             'original_bindings': [True] * 3, 'wait_succeeded': None,
             'expected_message_present': None, 'alice_epoch': None,
             'runtime_closed': False, 'relay_shutdown_returned': False}
    last = dict(first, stage=1, wait_succeeded=True, expected_message_present=True, alice_epoch=3)
    receipt0 = {'stage': 0, 'receipts': [[1, 1, 1]] * 3, 'selected_kinds': [445] * 3,
                'selected_bound': [True] * 3, 'mapped_outer_id_counts': [1] * 3,
                'captured_event_count': 4, 'wait_succeeded': None,
                'expected_message_present': None, 'local_epoch': None, 'target_epoch': 2, 'window_requests': 0}
    receipt1 = dict(receipt0, stage=1, wait_succeeded=True, expected_message_present=True, local_epoch=3, window_requests=1)
    def encoded(a=first, b=last, c=receipt0, d=receipt1, close=EXTRA_EPOCH_CLOSE):
        lines = [EXTRA_EPOCH_PREFIX + json.dumps(a), SELECTIVE_RECEIPT_PREFIX + json.dumps(c),
                 EXTRA_EPOCH_PREFIX + json.dumps(b), SELECTIVE_RECEIPT_PREFIX + json.dumps(d)]
        if close:
            lines.append(close)
        return ('\n'.join(lines) + '\n').encode()
    raw = encoded()
    assert extra_epoch_oracle(extra_epoch_marker(raw), selective_receipt_marker(raw))
    assert extra_epoch_oracle(extra_epoch_marker(raw.replace(b'\n', b'\r\n')), selective_receipt_marker(raw))
    partial = encoded(close='')
    assert len(extra_epoch_marker(partial)['rows']) == 2 and not extra_epoch_marker(partial)['collection_complete']
    failed = encoded(b=dict(last, wait_succeeded=False), d=dict(receipt1, wait_succeeded=False))
    assert not extra_epoch_oracle(extra_epoch_marker(failed), selective_receipt_marker(failed))
    malformed = [raw + raw, raw.replace(b'"stage": 0', b'"stage":0,"stage":0', 1),
                 encoded(a=dict(first, stage=True)), encoded(a=dict(first, epoch_before=True)),
                 encoded(a=dict(first, epoch_before=-1)), encoded(a=dict(first, epoch_after=2**64)),
                 encoded(a=dict(first, publication_ids='PRIVATE')), encoded(a=dict(first, extra='PRIVATE')),
                 encoded(a=dict(first, original_bindings=[1, True, True])),
                 encoded(a=dict(first, original_bindings=[True])), encoded(a=dict(first, runtime_closed=True)),
                 encoded(a=dict(first, wait_succeeded=True)), encoded(b=dict(last, alice_epoch=True)),
                 encoded(b=dict(last, wait_succeeded=1)), encoded(b=dict(last, published=2)),
                 encoded(close=EXTRA_EPOCH_CLOSE + ' PRIVATE'),
                 raw.replace(EXTRA_EPOCH_PREFIX.encode(), b'PRIVATE ' + EXTRA_EPOCH_PREFIX.encode(), 1),
                 raw.replace(EXTRA_EPOCH_CLOSE.encode(), b'selective-history-extra-epoch-unknown'),
                 raw.replace(EXTRA_EPOCH_CLOSE.encode(), (EXTRA_EPOCH_CLOSE + '\n' + EXTRA_EPOCH_CLOSE).encode()),
                 encoded(a=last, b=first)]
    for invalid in malformed:
        try:
            extra_epoch_marker(invalid)
        except (ValueError, TypeError):
            pass
        else:
            raise AssertionError('extra-epoch-negative-accepted')
    rejected = [encoded(a=dict(first, epoch_before=1), b=dict(last, epoch_before=1)),
                encoded(a=dict(first, epoch_after=4), b=dict(last, epoch_after=4)),
                encoded(a=dict(first, published=0), b=dict(last, published=0)),
                encoded(a=dict(first, publication_ids=2), b=dict(last, publication_ids=2)),
                encoded(a=dict(first, captured_unique=0), b=dict(last, captured_unique=0)),
                encoded(a=dict(first, distinct_original_wires=False), b=dict(last, distinct_original_wires=False)),
                encoded(a=dict(first, original_bindings=[True, False, True]), b=dict(last, original_bindings=[True, False, True])),
                encoded(b=dict(last, alice_epoch=2), d=dict(receipt1, local_epoch=2)),
                encoded(b=dict(last, expected_message_present=False), d=dict(receipt1, expected_message_present=False)),
                encoded(d=dict(receipt1, local_epoch=4)),
                encoded(c=dict(receipt0, selected_bound=[False, True, True]), d=dict(receipt1, selected_bound=[False, True, True])),
                encoded(c=dict(receipt0, receipts=[[2, 1, 1]] * 3), d=dict(receipt1, receipts=[[2, 1, 1]] * 3)),
                encoded(c=dict(receipt0, mapped_outer_id_counts=[2, 1, 1]), d=dict(receipt1, mapped_outer_id_counts=[2, 1, 1])),
                partial, failed]
    for invalid in rejected:
        assert not extra_epoch_oracle(extra_epoch_marker(invalid), selective_receipt_marker(invalid))
    return {'positive': 4, 'malformed_negative': len(malformed), 'oracle_negative': len(rejected),
            'metadata_only': True, 'product_bodies': 0}


def engine_bundle_selection():
    return 'package(cgka-engine) & binary(=cgka_engine) & (' + ' | '.join(
        'test(=' + CASES[case][1] + ')' for case in ENGINE_CONTROL_ORDER) + ')'


def selected_engine_bundle(inventory):
    selected = []
    for suite in inventory['rust-suites'].values():
        for name, item in suite['testcases'].items():
            if item['filter-match']['status'] != 'matches':
                continue
            if suite.get('binary-name') != 'cgka_engine' or suite.get('kind') != 'lib' or item['ignored'] is not False:
                raise ValueError('engine-bundle-binary-or-ignored')
            selected.append(name)
    expected = [CASES[case][1] for case in ENGINE_CONTROL_ORDER]
    if len(selected) != len(expected) or len(set(selected)) != len(expected) or set(selected) != set(expected):
        raise ValueError('engine-bundle-exact-inventory')
    return {'selected_nonignored': len(expected), 'selected_ignored': 0, 'tests': expected,
            'binary': 'cgka_engine', 'package': 'cgka-engine'}


def engine_bundle_controls():
    names = [CASES[case][1] for case in ENGINE_CONTROL_ORDER]
    suite = {'binary-name': 'cgka_engine', 'kind': 'lib',
             'testcases': {name: {'ignored': False, 'filter-match': {'status': 'matches'}} for name in names}}
    good = {'rust-suites': {'unit': suite}}
    assert selected_engine_bundle(good)['selected_nonignored'] == 8
    bad = []
    for key, value in [('binary-name', 'marmot_app'), ('kind', 'test')]:
        row = json.loads(json.dumps(good)); row['rust-suites']['unit'][key] = value; bad.append(row)
    for key, value in [('ignored', True), ('ignored', 0), ('filter-match', {'status': 'mismatch'})]:
        row = json.loads(json.dumps(good)); row['rust-suites']['unit']['testcases'][names[0]][key] = value; bad.append(row)
    row = json.loads(json.dumps(good)); del row['rust-suites']['unit']['testcases'][names[0]]; bad.append(row)
    row = json.loads(json.dumps(good)); row['rust-suites']['unit']['testcases']['PRIVATE'] = {'ignored': False, 'filter-match': {'status': 'matches'}}; bad.append(row)
    row = json.loads(json.dumps(good)); row['rust-suites']['duplicate'] = suite; bad.append(row)
    for invalid in bad:
        try:
            selected_engine_bundle(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError('engine-bundle-negative-accepted')
    for case in ENGINE_CLASSIFIER_CASES:
        assert package_for(case) == 'cgka-engine' and CASES[case][0] == 'cgka_engine'
        assert positive_configuration(case) == pfp_configuration(case) == (ENGINE_FEATURES, 'ci', None)
    return {'positive': 1, 'negative': len(bad), 'configuration': 2, 'product_bodies': 0, 'metadata_only': True}


def engine_support_bodies(report, before, flags, save):
    # All eight names were admitted by ONE exact inventory; the primary body has
    # already passed. Reuse the same frozen binary/flags for seven real controls.
    rows = report['supporting_controls'] = []
    for case in ENGINE_CONTROL_ORDER[1:]:
        row = {'case': case, 'expected_test': CASES[case][1], 'body_attempted': False}
        rows.append(row)
        if snapshot() != before:
            raise ValueError('phase-source')
        selection = 'package(cgka-engine) & binary(=cgka_engine) & test(=' + CASES[case][1] + ')'
        row['body_attempted'] = True
        save()
        code, raw, elapsed, _ = capture(['cargo', 'nextest', 'run'] + flags + ['--retries', '0', '--test-threads', '1',
                                      '--status-level', 'pass', '--final-status-level', 'none', '--no-fail-fast',
                                      '--success-output', 'immediate', '-E', selection], 1800)
        row['body'] = {'exit_code': code, 'elapsed_seconds': elapsed, 'raw_bytes': len(raw),
                       'raw_sha256': hashlib.sha256(raw).hexdigest(), 'runtime_summary': summary_counts(raw),
                       'compiler': compiler(raw, before['inputs']), 'panic': panic_facts(raw, case)}
        save()
        row['body']['counts'] = counts(raw, case)
        row['source_exact_after_body'] = snapshot() == before
        row['accepted'] = (code == 0 and row['body']['counts']['passed'] == 1
                           and row['body']['compiler']['header_count'] == 0 and not row['body']['compiler']['codes']
                           and row['body']['panic'] == {'sites': [], 'unknown_or_excess_headers': 0}
                           and row['source_exact_after_body'])
        save()
        if not row['accepted']:
            return 1
    report['control_bundle_actual'] = {'executed': 8, 'passed': 8, 'failed': 0, 'selected_ignored': 0}
    save()
    return 0


def positive_configuration(case):
    if case in ENGINE_CASES:
        return ENGINE_FEATURES, 'ci', None
    if case in UNIFFI_CASES:
        return UNIFFI_FEATURES, 'm5-bounded', '4194304'
    features = (['test-policy-overrides', 'cgka-engine/test-policy-overrides', 'cgka-engine/test-crash-hooks'] if case in SELECTIVE_CASES else
                ['sdk', 'test-policy-overrides'] if case == 'adapter-thousand-default' else
                ['sdk', 'experimental-device-sync', 'test-policy-overrides'] if case in ADAPTER_CASES else
                ['experimental-device-sync'] if case in STORAGE_CASES else
                LIB_FEATURES + ['marmot-app/experimental-device-sync'] if case in EXPERIMENTAL_CASES else
                ['test-policy-overrides'] if case == 'offline' else LIB_FEATURES)
    profile = 'm5-bounded' if case in BOUNDED_CASES else 'ci'
    expected_stack = '4194304' if case in BOUNDED_CASES else None
    return features, profile, expected_stack


def positive(args):
    # The positive path is shared unchanged; sample retains the real event stage.
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    features, profile, expected_stack = positive_configuration(args.case)
    package = package_for(args.case)
    report = {'case': args.case, 'diagnostic_only': True, 'qualification_passed': False,
              'body_passed': False, 'source': git('rev-parse', 'HEAD'), 'baseline': args.baseline,
              'features': features, 'profile': profile, 'package': package, 'automatic_retries': 0, 'test_threads': 1,
              'rust_min_stack': os.environ.get('RUST_MIN_STACK'), 'expected_test': CASES[args.case][1]}
    if args.case == 'late-commit-extra-epoch':
        report.update(evidence_scope='valid-real-extra-epoch-history-scenario-only',
                      native_protocol_qualification=False, original_full_failure_cause_established=False,
                      mutation_necessity_claimed=False)
    if args.case in ENGINE_CLASSIFIER_CASES:
        report.update(evidence_scope='private-Engine-classifier-and-preserved-ingress-controls-only',
                      package='cgka-engine', binary='cgka_engine',
                      native_protocol_qualification=False, throughput_fix_established=False)
    if args.case in UNIFFI_CASES:
        report.update(evidence_scope='uniffi-window-cancellation-fixture-mechanism-only',
                      package='marmot-uniffi', binary='marmot_uniffi',
                      native_protocol_qualification=False, sdk_native_acceptance_qualification=False)
    if args.case in {'offline-experimental', 'wrong-recipient-routing'}:
        report.update(evidence_scope='scoped-experimental-App-only',
                      native_protocol_qualification=False, full_workspace_feature_union=False)
    if args.case in CURSOR_CASES:
        report.update(evidence_scope='cursor-router-pin-fixture-mechanism-only', native_protocol_qualification=False,
                      historical_full_failure_cause_proven=False)
    if args.case == 'command-owned-cleanup':
        report.update(evidence_scope='owned-mock-relay-cleanup-mechanism-only', native_protocol_qualification=False)
    if args.case in WORKER_INPUT_CASES:
        report.update(evidence_scope='worker-input-selection-mechanism-only', native_protocol_qualification=False)
    if args.case == 'sdk-private-capture-control':
        report.update(evidence_scope='sdk-private-capture-component-only',
                      native_protocol_qualification=False, queue_overflow_remedy_qualified=False)
    if args.stage == 'sample':
        report['execution_stage'] = 'sample'
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
                or event['inputs'].get('replay_stage', 'positive') != args.stage
                or event['inputs'].get('replay_case') != args.case
                or event['inputs'].get('reviewed_baseline') != args.baseline):
            raise ValueError('replay-event-inputs')
        before = snapshot()
        report['input_manifest_sha256'] = hashlib.sha256(json.dumps(before['inputs'], sort_keys=True).encode()).hexdigest()
        report['parser_controls'] = controls()
        report['configuration_controls'] = replay_configuration_controls()
        if args.stage == 'sample':
            if args.case != 'sibling-send-experimental':
                raise ValueError('sample-case')
            report['sample_parser_controls'] = sample_controls()
        if args.case in FIXTURE_OBSERVATION_BASES:
            report['fixture_observation_controls'] = fixture_observation_controls()
        if args.case in {'sibling-send-default', 'sibling-send-experimental'}:
            report['sibling_send_parser_controls'] = sibling_send_controls()
            report['sibling_worker_parser_controls'] = sibling_worker_controls()
        if args.case in ENGINE_CLASSIFIER_CASES:
            report['engine_bundle_controls'] = engine_bundle_controls()
        if args.case in UNIFFI_CASES:
            uniffi_site = uniffi_receive_site()
            report['uniffi_receive_controls'] = uniffi_receive_controls(ANSI)
            report['uniffi_own_oracle_controls'] = pfp_controls('uniffi-conversation-stale', uniffi_site)
        if args.case == 'wrong-recipient-routing':
            report['routing_prerequisite_controls'] = routing_prerequisite_controls()
        if args.case == 'command-owned-cleanup':
            report['owned_cleanup_controls'] = owned_cleanup_controls(owned_cleanup_site())
        if args.case in SELECTIVE_CASES:
            report['selective_receipt_parser_controls'] = selective_receipt_controls()
        if args.case == 'late-commit-extra-epoch':
            report['extra_epoch_parser_controls'] = extra_epoch_controls()
        if args.case in OFFLINE_CASES:
            report['fingerprint_parser_controls'] = fingerprint_controls()
            report['body_resource_controls'] = resource_controls()
        if args.case in SDK_REPLAY_CASES:
            report['sdk_replay_parser_controls'] = sdk_replay_controls()
        if args.case == 'adapter-clamped':
            report['adapter_exit_parser_controls'] = adapter_exit_controls()
        if args.case == 'fresh-rejoin-observation':
            report['fresh_rejoin_parser_controls'] = fresh_rejoin_controls()
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
            if args.case in INTEGRATION_CASES or args.case in UNIFFI_CASES or args.case in ENGINE_CASES:
                selection += ' & binary(=' + binary + ')'
            body_selection = selection
            if args.case == 'private-classifier-authentication':
                selection = engine_bundle_selection()
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
            if args.case == 'private-classifier-authentication':
                report['engine_control_inventory'] = selected_engine_bundle(inventory)
            else:
                selected_case(inventory, test)
            selection = body_selection
            if args.case in OFFLINE_CASES:
                report['compiled_fingerprints'] = fingerprint_snapshot(
                    inventory, test, os.environ.get('CARGO_TARGET_DIR', 'target'))
            report['inventory']['selected_nonignored'] = 8 if args.case == 'private-classifier-authentication' else 1
            report['inventory']['selected_ignored'] = 0
            save()
            stage = 'inventory-source'
            if snapshot() != before:
                raise ValueError('inventory-source')
            stage = 'body-command'
            report['body_command_attempted'] = True
            save()
            resource_token = resource_start() if args.case in OFFLINE_CASES else None
            try:
                code, raw, elapsed, _ = capture(['cargo', 'nextest', 'run'] + flags + ['--retries', '0', '--test-threads', '1',
                                              '--status-level', 'pass', '--final-status-level', 'none', '--no-fail-fast',
                                              '--success-output', 'immediate', '-E', selection], 1800)
            finally:
                if args.case in OFFLINE_CASES:
                    report['body_resources'] = resource_finish(resource_token)
            report['body'] = {'exit_code': code, 'elapsed_seconds': elapsed, 'raw_bytes': len(raw),
                              'raw_sha256': hashlib.sha256(raw).hexdigest(), 'compiler': compiler(raw, before['inputs']),
                              'panic': panic_facts(raw, args.case), 'runtime_summary': summary_counts(raw)}
            save()  # An actual attempted body survives any later parser/closure error.
            stage = 'runtime-shape'
            report['body']['counts'] = counts(raw, args.case)
            save()
            if args.case in {'sibling-send-default', 'sibling-send-experimental'}:
                try:
                    report['body']['sibling_send_observation'] = sibling_send_observation(ANSI.sub('', raw.decode('utf-8', errors='strict')).encode())
                    report['body']['sibling_send_export_complete'] = True
                except (ValueError, UnicodeError):
                    report['body']['sibling_send_observation'] = None
                    report['body']['sibling_send_export_complete'] = False
                save()
                try:
                    report['body']['sibling_worker_observation'] = sibling_worker_observation(ANSI.sub('', raw.decode('utf-8', errors='strict')).encode())
                    report['body']['sibling_worker_export_complete'] = True
                except (ValueError, UnicodeError):
                    report['body']['sibling_worker_observation'] = None
                    report['body']['sibling_worker_export_complete'] = False
                save()
            if args.case in FIXTURE_OBSERVATION_BASES:
                # Supplemental facts never replace the actual runtime verdict.
                try:
                    report['body']['fixture_observation'] = fixture_observation(raw, args.case)
                    report['body']['fixture_observation_export_complete'] = True
                except Exception:
                    report['body']['fixture_observation'] = None
                    report['body']['fixture_observation_export_complete'] = False
                    report['body']['fixture_observation_error'] = 'absent-or-invalid-fixed-observation'
                save()
            if args.case == 'late-commit-extra-epoch':
                stage = 'diagnostic'
                report['body']['extra_epoch_observation'] = extra_epoch_marker(raw)
                save()
            if args.case in SELECTIVE_CASES:
                stage = 'diagnostic'
                report['body']['receipt_observations'] = selective_receipt_marker(raw)
                save()
            if args.case == 'fresh-rejoin-observation':
                try:
                    report['body']['fresh_rejoin_observation'] = fresh_rejoin_observation(raw)
                    report['body']['fresh_rejoin_export_complete'] = True
                except (ValueError, UnicodeError):
                    report['body']['fresh_rejoin_observation'] = None
                    report['body']['fresh_rejoin_export_complete'] = False
                save()
            if args.case == 'adapter-clamped':
                try:
                    report['body']['adapter_exit_observation'] = adapter_exit_observation(ANSI.sub('', raw.decode('utf-8', errors='strict')).encode())
                    report['body']['adapter_exit_export_complete'] = True
                except (ValueError, UnicodeError):
                    report['body']['adapter_exit_observation'] = None
                    report['body']['adapter_exit_export_complete'] = False
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
            command_accepted = True
            if args.case == 'late-commit-extra-epoch':
                command_accepted = extra_epoch_oracle(report['body']['extra_epoch_observation'], report['body']['receipt_observations'])
                report['body']['extra_epoch_observation_passed'] = command_accepted
                save()
            if args.case == 'command-owned-cleanup':
                stage = 'diagnostic'
                observation = owned_cleanup_marker(raw)
                report['body']['owned_cleanup_observation'] = observation
                report['body']['own_runtime_failure'] = own_failure(raw, args.case, owned_cleanup_site())
                report['body']['expected_cleanup_runtime_red'] = (
                    code == 100 and report['body']['counts']['failed'] == 1
                    and report['body']['compiler']['codes'] == [] and report['body']['compiler']['header_count'] == 0
                    and owned_cleanup_oracle(observation, True) and report['body']['own_runtime_failure'])
                command_accepted = owned_cleanup_oracle(observation, False)
                save()
            if args.case in UNIFFI_CASES:
                stage = 'diagnostic'
                observation = uniffi_receive_marker(raw, args.case, ANSI)
                report['body']['uniffi_receive_observation'] = observation
                command_accepted = uniffi_receive_oracle(observation, args.case)
                if args.case == 'uniffi-conversation-stale':
                    report['body']['expected_stale_runtime_red'] = (
                        code == 100 and report['body']['counts']['failed'] == 1
                        and report['body']['compiler']['codes'] == [] and report['body']['compiler']['header_count'] == 0
                        and uniffi_receive_oracle(observation, args.case, True)
                        and own_failure(raw, args.case, uniffi_site))
                save()
            if args.case == 'wrong-recipient-routing':
                stage = 'diagnostic'
                observation = routing_prerequisite_marker(raw)
                report['body']['routing_prerequisite_observation'] = observation
                command_accepted = observation['wait_succeeded']
                report['body']['prerequisite_observation_passed'] = command_accepted
                report['body']['behavioral_red_qualified'] = False
                save()
            if args.case in COMMAND_BACKLOG_CASES:
                stage = 'diagnostic'
                report['body']['command_backlog_observation'] = command_backlog_marker(raw, args.case)
                command_accepted = command_backlog_oracle(report['body']['command_backlog_observation'], args.case)
                save()
            if args.case == 'watch-pressure':
                stage = 'diagnostic'
                report['body']['watch_observation'] = watch_marker(raw)
                save()
            if args.case in OFFLINE_CASES:
                stage = 'diagnostic'
                report['body']['observation'] = marker(raw)
                save()
            stage = 'body-not-passed'
            report['body_passed'] = (command_accepted and code == 0 and report['body']['counts']['passed'] == 1
                                     and report['body']['compiler']['header_count'] == 0
                                     and not report['body']['compiler']['codes']
                                     and report['body']['panic'] == {'sites': [], 'unknown_or_excess_headers': 0})
            result = 0 if report['body_passed'] else 1
            if result == 0 and args.case == 'private-classifier-authentication':
                report['primary_body_passed'] = True
                result = 1
                report['body_passed'] = False
                save()
                result = engine_support_bodies(report, before, flags, save)
                report['body_passed'] = result == 0
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


SAMPLE_LIMIT = 6


def sample_trial_status(report, code, source):
    """A compile/zero-body/controller failure is never a runtime-failure witness."""
    if (type(code) is not int or report.get('source') != source
            or report.get('baseline') != source
            or report.get('case') != 'sibling-send-experimental'
            or report.get('source_closure_exact') is not True):
        return 'guard-error'
    inventory, body = report.get('inventory', {}), report.get('body', {})
    if (type(inventory.get('exit_code')) is not int or inventory.get('exit_code') != 0
            or type(inventory.get('selected_nonignored')) is not int
            or inventory.get('selected_nonignored') != 1
            or type(inventory.get('selected_ignored')) is not int
            or inventory.get('selected_ignored') != 0):
        return 'guard-error'
    for item in (inventory, body):
        if (type(item.get('compiler', {}).get('header_count')) is not int
                or type(item.get('compiler', {}).get('unknown_or_excess_sites')) is not int
                or item.get('compiler') != {'codes': [], 'header_count': 0,
                                    'sites': [], 'unknown_or_excess_sites': 0}):
            return 'guard-error'
    counts = body.get('counts', {})
    if (any(type(counts.get(key)) is not int for key in ('executed', 'passed', 'failed'))
            or counts['executed'] != 1 or counts['passed'] + counts['failed'] != 1
            or type(body.get('exit_code')) is not int):
        return 'guard-error'
    if code != 0 and body['exit_code'] != 0 and counts['failed'] == 1:
        return 'actual-runtime-failure'
    if (code != 0 or body['exit_code'] != 0 or counts['passed'] != 1
            or report.get('body_passed') is not True
            or body.get('panic') != {'sites': [], 'unknown_or_excess_headers': 0}
            or body.get('sibling_send_export_complete') is not True
            or body.get('sibling_worker_export_complete') is not True
            or body.get('sibling_worker_observation', {}).get('collection_complete') is not True):
        return 'guard-error'
    return 'actual-pass'


def sample_controls():
    # Metadata only; no target invocation, source mutation, or synthetic RED credit.
    fixture = {'source': 's', 'baseline': 's', 'case': 'sibling-send-experimental',
               'source_closure_exact': True, 'body_passed': True,
               'inventory': {'exit_code': 0, 'selected_nonignored': 1, 'selected_ignored': 0},
               'body': {'counts': {'executed': 1, 'passed': 1, 'failed': 0}, 'exit_code': 0,
                        'panic': {'sites': [], 'unknown_or_excess_headers': 0},
                        'sibling_send_export_complete': True, 'sibling_worker_export_complete': True,
                        'sibling_worker_observation': {'collection_complete': True}}}
    clean = {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
    fixture['inventory']['compiler'] = clean
    fixture['body']['compiler'] = clean
    def copy():
        return json.loads(json.dumps(fixture))
    if sample_trial_status(fixture, 0, 's') != 'actual-pass':
        raise ValueError('sample-positive-control')
    failed = copy()
    failed['body_passed'] = False
    failed['body']['counts'].update(passed=0, failed=1)
    failed['body']['exit_code'] = 100
    if sample_trial_status(failed, 1, 's') != 'actual-runtime-failure':
        raise ValueError('sample-retained-failure-control')
    negatives = []
    for section, key, value in [('inventory', 'selected_nonignored', 0),
                                ('inventory', 'selected_nonignored', True),
                                ('inventory', 'selected_ignored', 1),
                                ('body', 'exit_code', True),
                                ('body', 'sibling_send_export_complete', False),
                                ('body', 'sibling_worker_export_complete', False)]:
        row = copy(); row[section][key] = value; negatives.append(row)
    row = copy(); row['body']['counts'].update(executed=0, passed=0); negatives.append(row)
    row = copy(); row['body']['counts']['executed'] = True; negatives.append(row)
    row = copy(); row['source_closure_exact'] = False; negatives.append(row)
    row = copy(); row['source'] = 'other'; negatives.append(row)
    row = copy(); row['body']['compiler']['header_count'] = 1; negatives.append(row)
    row = json.loads(json.dumps(failed)); row['body']['compiler']['codes'] = ['E0000']; negatives.append(row)
    row = copy(); row['body']['sibling_worker_observation']['collection_complete'] = False; negatives.append(row)
    for row in negatives:
        if sample_trial_status(row, 0, 's') != 'guard-error':
            raise ValueError('sample-negative-control')
    if sample_trial_status(negatives[-2], 1, 's') != 'guard-error':
        raise ValueError('sample-compiler-is-not-runtime-control')
    # A failed trial stops the sequence; it cannot be replaced by a later pass.
    statuses = ['actual-pass', 'actual-runtime-failure', 'actual-pass']
    retained = []
    for status in statuses:
        retained.append(status)
        if status != 'actual-pass':
            break
    if retained != statuses[:2] or SAMPLE_LIMIT - len(retained) != 4:
        raise ValueError('sample-stop-control')
    return {'positive': 3, 'negative': len(negatives) + 1,
            'product_bodies': 0, 'qualification_passed': False}


def sample(args):
    """Bounded failure capture, not retry-to-green or a qualification gate."""
    if args.case != 'sibling-send-experimental':
        raise ValueError('sample-case')
    if args.mode == 'preflight':
        return positive(args)  # One normal source/parser admission; zero product bodies.
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {'source': git('rev-parse', 'HEAD'), 'baseline': args.baseline,
              'case': args.case, 'stage': 'sample', 'diagnostic_only': True,
              'qualification_passed': False, 'automatic_retries': 0,
              'max_trials': SAMPLE_LIMIT, 'trials': [], 'not_executed': SAMPLE_LIMIT,
              'stop_reason': 'guard-error', 'all_attempted_passed': False}
    def save():
        pending = output.with_suffix('.pending')
        pending.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        pending.replace(output)
    save()
    result = 1
    try:
        report['sample_parser_controls'] = sample_controls()
        for number in range(1, SAMPLE_LIMIT + 1):
            trial_path = output.with_name(output.stem + '.trial-' + str(number) + '.json')
            trial_args = argparse.Namespace(**vars(args))
            trial_args.output = str(trial_path)
            entry = {'trial': number, 'status': 'guard-error', 'controller_exit_code': None,
                     'result_file': trial_path.name, 'body_command_attempted': None}
            report['trials'].append(entry)
            report['not_executed'] = SAMPLE_LIMIT - number  # Remaining unstarted trial slots.
            save()
            try:
                code = positive(trial_args)
                trial = json.loads(trial_path.read_text(), object_pairs_hook=unique)
                status = sample_trial_status(trial, code, report['source'])
                body = trial.get('body', {})
                entry.update(status=status, controller_exit_code=code,
                             result_sha256=hashlib.sha256(trial_path.read_bytes()).hexdigest(),
                             body_command_attempted=trial.get('body_command_attempted', False),
                             counts=body.get('counts'), body_exit_code=body.get('exit_code'),
                             send=body.get('sibling_send_observation'),
                             worker=body.get('sibling_worker_observation'))
            except Exception:
                status = 'guard-error'  # Keep the partial trial file and bounded entry, never raw errors.
            report['stop_reason'] = status
            save()  # Keep the actual failed trial before deciding whether another may start.
            if status != 'actual-pass':
                break
        else:
            report['stop_reason'] = 'sample-limit-all-passed'
            report['all_attempted_passed'] = True
            result = 0
    except Exception:
        report['stop_reason'] = 'guard-error'
    finally:
        save()
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['preflight', 'run'], required=True)
    parser.add_argument('--stage', choices=['positive', 'pfp', 'sample'], default='positive')
    parser.add_argument('--case', choices=[case for case in CASES if case not in ENGINE_SUPPORT_CASES], required=True)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if args.stage == 'pfp':
        return pfp(args)
    if args.stage == 'sample':
        return sample(args)
    return positive(args)


if __name__ == '__main__':
    raise SystemExit(main())
