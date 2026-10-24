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
from upstream_sibling_worker_observation import parse as sibling_worker_observation, controls as sibling_worker_controls, parse_transitions as sibling_worker_transitions, transition_controls as sibling_transition_controls
from upstream_adapter_exit_observation import parse as adapter_exit_observation, controls as adapter_exit_controls
from upstream_fresh_rejoin_observation import fresh_rejoin_observation, controls as fresh_rejoin_controls

PREFIX = 'offline-replay-diagnostic '
SCOPED_REPORT_PROBE_PREFIX = 'private-scoped-report-prerequisites'
SCOPED_REPORT_PROBE_BOOLS = {
    'actual_id_distinct', 'real_sdk_id', 'account_tracks_actual',
    'account_tracks_logical_plan', 'tracking_prerequisite', 'owed_actual',
    'actual_reconnect_replay_and_eose', 'cleanup_complete', 'active_account_before',
}
SCOPED_REPORT_PROBE_COUNTS = {'activations_degraded', 'activations_full', 'activations_failed'}


def scoped_report_probe(raw):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    lines = [line for line in text.splitlines() if SCOPED_REPORT_PROBE_PREFIX in line]
    if len(lines) != 1 or text.count(SCOPED_REPORT_PROBE_PREFIX) != 1 or len(lines[0]) > 2048:
        raise ValueError('scoped-report-probe-cardinality')
    match = re.fullmatch(r'[ \t]{0,8}' + re.escape(SCOPED_REPORT_PROBE_PREFIX) + r' (\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    if match is None:
        raise ValueError('scoped-report-probe-envelope')
    value = json.loads(match[1], object_pairs_hook=unique)
    if type(value) is not dict or set(value) != SCOPED_REPORT_PROBE_BOOLS | SCOPED_REPORT_PROBE_COUNTS:
        raise ValueError('scoped-report-probe-fields')
    if any(type(value[key]) is not bool for key in SCOPED_REPORT_PROBE_BOOLS):
        raise ValueError('scoped-report-probe-bools')
    if any(type(value[key]) is not int or not 0 <= value[key] <= 2**63-1 for key in SCOPED_REPORT_PROBE_COUNTS):
        raise ValueError('scoped-report-probe-counts')
    return value


def scoped_report_probe_controls():
    value = dict.fromkeys(SCOPED_REPORT_PROBE_BOOLS, True)
    value.update(dict.fromkeys(SCOPED_REPORT_PROBE_COUNTS, 0))
    def row(item):
        return (SCOPED_REPORT_PROBE_PREFIX + ' ' + json.dumps(item) + '\n').encode()
    valid = row(value)
    assert scoped_report_probe(valid) == value
    malformed = [valid + valid, b'PRIVATE ' + valid, b' '*9 + valid,
        row(dict(value, private=True)), row(dict(value, tracking_prerequisite=1)),
        row(dict(value, activations_failed=True)), row(dict(value, activations_failed=-1)),
        row(dict(value, activations_full=2**63)), row(dict(value, activations_full=0.5)),
        row({key: item for key, item in value.items() if key != 'real_sdk_id'}),
        valid.replace(b'{', b'{"cleanup_complete":true,', 1)]
    for raw in malformed:
        try:
            scoped_report_probe(raw)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError('scoped-report-probe-invalid-accepted')
    return {'positive': 1, 'negative': len(malformed), 'product_bodies': 0, 'synthetic_metadata_only': True}



FAMILY_STABILITY_CASE = 'sdk-private-family-stability'
FAMILY_STABILITY_PREFIX = 'private-family-stability-prerequisites'
FAMILY_STABILITY_MESSAGE = 'unrelated family sync must preserve private actual and untouched ordinary wire identities'
FAMILY_STABILITY_PREREQUISITES = {
    'initial_private_registered', 'initial_ordinary_registered', 'initial_private_exact_index',
    'sync_succeeded', 'final_coverage_complete', 'final_private_registered',
    'changed_family_registered', 'cleanup_complete', 'distinct_ordinary_families',
}
FAMILY_STABILITY_VERDICTS = {
    'private_actual_unchanged', 'untouched_family_wire_unchanged', 'original_private_wire_current',
}


def family_stability_probe(raw):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    lines = [line for line in text.splitlines() if FAMILY_STABILITY_PREFIX in line]
    if len(lines) != 1 or text.count(FAMILY_STABILITY_PREFIX) != 1 or len(lines[0]) > 2048:
        raise ValueError('family-stability-cardinality')
    match = re.fullmatch(r'[ \t]{0,8}' + re.escape(FAMILY_STABILITY_PREFIX) + r' (\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    if match is None:
        raise ValueError('family-stability-envelope')
    value = json.loads(match[1], object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != FAMILY_STABILITY_PREREQUISITES | FAMILY_STABILITY_VERDICTS
            or any(type(item) is not bool for item in value.values())):
        raise ValueError('family-stability-fields')
    return value


def family_stability_site():
    text = Path(CASES[FAMILY_STABILITY_CASE][2]).read_text()
    pattern = (r'assert!\(\s*private_actual_unchanged\s*&&\s*untouched_family_wire_unchanged'
        r'\s*&&\s*original_private_wire_current,\s*"' + re.escape(FAMILY_STABILITY_MESSAGE) + r'"\s*\);')
    found = list(re.finditer(pattern, text))
    if len(found) != 1:
        raise ValueError('family-stability-source-site')
    return {'line': text[:found[0].start()].count('\n') + 1,
            'column': found[0].start() - text.rfind('\n', 0, found[0].start())}


def family_stability_failure(raw, site):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    value = family_stability_probe(raw)
    if (not all(value[key] for key in FAMILY_STABILITY_PREREQUISITES)
            or all(value[key] for key in FAMILY_STABILITY_VERDICTS)
            or text.count('panicked at ') != 1):
        return False
    pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(CASES[FAMILY_STABILITY_CASE][1])
        + r"'(?: \([0-9]+\))? panicked at " + re.escape(CASES[FAMILY_STABILITY_CASE][2])
        + ':' + str(site['line']) + ':' + str(site['column'])
        + r':[ \t]*\n(?:[ \t]*\n){0,2}[ \t]{0,8}' + re.escape(FAMILY_STABILITY_MESSAGE) + r'[ \t]*(?:\n|$)')
    found = re.search(pattern, text)
    return found is not None and text.index(FAMILY_STABILITY_PREFIX) < found.start()


def family_stability_controls(site):
    value = dict.fromkeys(FAMILY_STABILITY_PREREQUISITES | FAMILY_STABILITY_VERDICTS, True)
    def row(item):
        return (FAMILY_STABILITY_PREFIX + ' ' + json.dumps(item) + '\n').encode()
    valid = row(value)
    assert family_stability_probe(valid) == value
    red = dict(value, private_actual_unchanged=False, original_private_wire_current=False)
    header = ("thread '" + CASES[FAMILY_STABILITY_CASE][1] + "' (7) panicked at "
        + CASES[FAMILY_STABILITY_CASE][2] + ':' + str(site['line']) + ':' + str(site['column']) + ':\n'
        + FAMILY_STABILITY_MESSAGE + '\n').encode()
    assert family_stability_failure(row(red) + header, site)
    bad_rows = [valid + valid, b'PRIVATE ' + valid, b' ' * 9 + valid,
        row(dict(value, private=True)), row(dict(value, cleanup_complete=1)),
        row({key: item for key, item in value.items() if key != 'sync_succeeded'}),
        valid.replace(b'{', b'{"cleanup_complete":true,', 1)]
    for raw in bad_rows:
        try:
            family_stability_probe(raw)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError('family-stability-invalid-accepted')
    invalid = [row(value) + header, row(red) + header + header, header + row(red),
        row(red) + header.replace(FAMILY_STABILITY_MESSAGE.encode(), b'PRIVATE'),
        row(red) + header.replace((":" + str(site['line']) + ":").encode(), b':0:'),
        row(red) + header.replace(CASES[FAMILY_STABILITY_CASE][1].encode(), b'PRIVATE')]
    invalid += [row(dict(red, **{key: False})) + header for key in FAMILY_STABILITY_PREREQUISITES]
    assert all(not family_stability_failure(raw, site) for raw in invalid)
    return {'positive': 2, 'negative': len(bad_rows) + len(invalid),
            'synthetic_metadata_only': True, 'product_bodies': 0}


PRIVATE_ROLE_CASES = {
    'sdk-private-family-partial': {
        'test': 'private_family_survives_partial_ordinary_failure_and_retry',
        'prefix': 'private-family-partial-prerequisites',
        'prerequisites': {
            'distinct_relays', 'initial_registered', 'terminal_ban', 'partial_failed',
            'retry_succeeded', 'final_native_eose', 'retried_registered', 'cleanup_complete',
        },
        'verdicts': {
            'healthy_committed', 'healthy_registered', 'healthy_native_eose',
            'failed_family_retained', 'private_partial_unchanged',
            'retry_keeps_successful_carriers', 'retried_family_committed',
            'old_b_absent_from_retry_instance',
        },
    },
    'sdk-private-role-transition': {
        'test': 'failed_private_selection_never_exposes_prior_logical_wire',
        'prefix': 'private-role-transition-prerequisites',
        'prerequisites': {
            'distinct_relays', 'initial_actual_registered', 'terminal_ban',
            'replacement_failed', 'prior_standalone_retained', 'successor_not_ready',
            'predecessor_closed', 'healthy_registered', 'healthy_native_eose',
            'retry_succeeded', 'retry_native_eose', 'replacement_registered',
            'demotion_succeeded', 'demotion_native_eose', 'demoted_batch_registered',
            'cleanup_complete',
        },
        'verdicts': {
            'prior_negative', 'successor_negative', 'prior_ordinary_is_new_batch',
            'healthy_unchanged', 'healthy_after_demotion', 'demotion_has_no_standalone',
            'demotion_uses_new_batch', 'replacement_actual_closed',
        },
    },
    'sdk-private-configuration-aba': {
        'test': 'configuration_aba_during_private_close_cannot_reauthorise_replacement',
        'prefix': 'private-configuration-aba-prerequisites',
        'prerequisites': {
            'initial_actual_registered', 'initially_revoked', 'distinct_successor_actual',
            'predecessor_still_registered', 'successor_absent_while_held',
            'held_revocation', 'predecessor_closed', 'cleanup_complete',
        },
        'verdicts': {
            'sync_rejected', 'preparation_not_reauthorised', 'successor_not_registered',
        },
    },
}
ROLE_REGISTRY_PREFIX = 'private-role-registry-diagnostic'
ROLE_REGISTRY_FIELDS = {
    'held_demoted_registration', 'current_pool_lookup_succeeded',
    'current_pool_relay_present', 'current_pool_demoted_registration',
    'current_pool_old_private_actual_absent',
    'post_deactivation_pool_lookup_succeeded', 'post_deactivation_pool_empty',
    'post_deactivation_all_pools_empty',
}


def private_role_registry_probe(raw):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    lines = [line for line in text.splitlines() if ROLE_REGISTRY_PREFIX in line]
    if len(lines) != 1 or text.count(ROLE_REGISTRY_PREFIX) != 1 or len(lines[0]) > 1024:
        raise ValueError('role-registry-cardinality')
    match = re.fullmatch(r'[ \t]{0,8}' + re.escape(ROLE_REGISTRY_PREFIX)
                         + r' (\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    if match is None:
        raise ValueError('role-registry-envelope')
    value = json.loads(match[1], object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != ROLE_REGISTRY_FIELDS
            or any(type(item) is not bool for item in value.values())):
        raise ValueError('role-registry-fields')
    # Diagnostic observations do not alter the original 24-field verdict.
    return value


def private_role_registry_controls():
    value = dict.fromkeys(ROLE_REGISTRY_FIELDS, True)
    def row(item):
        return (ROLE_REGISTRY_PREFIX + ' ' + json.dumps(item) + '\n').encode()
    valid = row(value)
    assert private_role_registry_probe(valid) == value
    assert private_role_registry_probe(row(dict.fromkeys(ROLE_REGISTRY_FIELDS, False))) == dict.fromkeys(ROLE_REGISTRY_FIELDS, False)
    bad = [valid + valid, b'PRIVATE ' + valid, b' ' * 9 + valid, valid + b'\xff',
           row(dict(value, private=True)), row(dict(value, private_account_id='PRIVATE')),
           valid.replace(b'\n', b' trailing\n'),
           (ROLE_REGISTRY_PREFIX + ' []\n').encode(), b'']
    for key in sorted(value):
        bad.append(row({name: item for name, item in value.items() if name != key}))
        bad.append(valid.replace(b'{', ('{' + json.dumps(key) + ':true,').encode(), 1))
        bad.append(row(dict(value, **{key: 1})))
    for raw in bad:
        try:
            private_role_registry_probe(raw)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError('role-registry-invalid-accepted')
    return {'positive': 2, 'negative': len(bad),
            'synthetic_metadata_only': True, 'product_bodies': 0}


PRIVATE_ABA_CASE = 'sdk-private-configuration-aba'
PRIVATE_ABA_MESSAGE = 'configuration ABA must not reauthorise the private replacement prepared before revocation'


def private_role_probe(raw, case):
    spec = PRIVATE_ROLE_CASES[case]
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    prefix = spec['prefix']
    lines = [line for line in text.splitlines() if prefix in line]
    if (len(lines) != 1 or text.count(prefix) != 1 or len(lines[0]) > 2048
            or any(other['prefix'] in text for key, other in PRIVATE_ROLE_CASES.items() if key != case)):
        raise ValueError('private-role-cardinality-namespace')
    match = re.fullmatch(r'[ \t]{0,8}' + re.escape(prefix)
                         + r' (\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    if match is None:
        raise ValueError('private-role-envelope')
    value = json.loads(match[1], object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != spec['prerequisites'] | spec['verdicts']
            or any(type(item) is not bool for item in value.values())):
        raise ValueError('private-role-fields')
    return value


def private_role_green(value, case):
    spec = PRIVATE_ROLE_CASES[case]
    return (type(value) is dict and set(value) == spec['prerequisites'] | spec['verdicts']
            and all(type(item) is bool and item is True for item in value.values()))


def private_aba_site():
    text = Path(CASES[PRIVATE_ABA_CASE][2]).read_text()
    pattern = (r'assert!\(\s*sync_rejected\s*&&\s*preparation_not_reauthorised'
               r'\s*&&\s*successor_not_registered,\s*"' + re.escape(PRIVATE_ABA_MESSAGE)
               + r'"\s*,?\s*\);')
    found = list(re.finditer(pattern, text))
    if len(found) != 1:
        raise ValueError('private-aba-source-site')
    return {'line': text[:found[0].start()].count('\n') + 1,
            'column': found[0].start() - text.rfind('\n', 0, found[0].start())}


def private_aba_failure(raw, site):
    try:
        value = private_role_probe(raw, PRIVATE_ABA_CASE)
        text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    except (ValueError, UnicodeError):
        return False
    spec = PRIVATE_ROLE_CASES[PRIVATE_ABA_CASE]
    if (not all(value[key] is True for key in spec['prerequisites'])
            or all(value[key] is True for key in spec['verdicts'])
            or text.count('panicked at ') != 1):
        return False
    pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(CASES[PRIVATE_ABA_CASE][1])
               + r"'(?: \([0-9]+\))? panicked at " + re.escape(CASES[PRIVATE_ABA_CASE][2])
               + ':' + str(site['line']) + ':' + str(site['column'])
               + r':[ \t]*\n(?:[ \t]*\n){0,2}[ \t]{0,8}'
               + re.escape(PRIVATE_ABA_MESSAGE) + r'[ \t]*(?:\n|$)')
    found = re.search(pattern, text)
    return found is not None and text.index(spec['prefix']) < found.start()


def private_role_controls(case):
    """Only synthetic parser/oracle adversaries; zero product execution credit."""
    spec = PRIVATE_ROLE_CASES[case]
    value = dict.fromkeys(spec['prerequisites'] | spec['verdicts'], True)
    def row(item):
        return (spec['prefix'] + ' ' + json.dumps(item) + '\n').encode()
    valid = row(value)
    assert private_role_probe(valid, case) == value and private_role_green(value, case)
    bad = [valid + valid, b'PRIVATE ' + valid, b' ' * 9 + valid, valid + b'\xff',
           row(dict(value, private=True)), row(dict(value, private_account_id='PRIVATE')),
           valid.replace(b'\n', b' trailing\n'),
           (spec['prefix'] + ' []\n').encode(),
           (spec['prefix'] + ' null\n').encode(), b'']
    first = sorted(value)[0]
    for key in sorted(value):
        bad.append(row({name: item for name, item in value.items() if name != key}))
        bad.append(valid.replace(b'{', ('{' + json.dumps(key) + ':true,').encode(), 1))
        false = dict(value, **{key: False})
        assert private_role_probe(row(false), case) == false and not private_role_green(false, case)
    for replacement in [1, 0, None, 'PRIVATE', [], {}, 0.5]:
        bad.append(row(dict(value, **{first: replacement})))
    for key, other in PRIVATE_ROLE_CASES.items():
        if key != case:
            other_row = (other['prefix'] + ' ' + json.dumps(dict.fromkeys(other['prerequisites'] | other['verdicts'], True)) + '\n').encode()
            bad.extend([other_row, valid + other_row])
    for raw in bad:
        try:
            private_role_probe(raw, case)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError('private-role-invalid-accepted')
    result = {'positive': 1 + len(value), 'negative': len(bad),
              'synthetic_metadata_only': True, 'product_bodies': 0}
    if case == PRIVATE_ABA_CASE:
        site = private_aba_site()
        header = ("thread '" + CASES[case][1] + "' (7) panicked at " + CASES[case][2]
                  + ':' + str(site['line']) + ':' + str(site['column']) + ':\n'
                  + PRIVATE_ABA_MESSAGE + '\n').encode()
        red = dict(value, sync_rejected=False)
        for key in sorted(spec['verdicts']):
            assert private_aba_failure(row(dict(value, **{key: False})) + header, site)
        invalid = [row(value) + header, row(red), row(red) + header + header,
                   header + row(red), row(red) + header.replace(PRIVATE_ABA_MESSAGE.encode(), b'PRIVATE'),
                   row(red) + header.replace(CASES[case][1].encode(), b'PRIVATE'),
                   row(red) + header.replace(CASES[case][2].encode(), b'PRIVATE.rs'),
                   row(red) + header.replace((':' + str(site['line']) + ':').encode(), b':0:'),
                   row(red) + header.replace((':' + str(site['column']) + ':\n').encode(), b':0:\n')]
        invalid += [row(dict(red, **{key: False})) + header for key in spec['prerequisites']]
        assert all(not private_aba_failure(raw, site) for raw in invalid)
        result['own_red_positive'] = len(spec['verdicts'])
        result['own_red_negative'] = len(invalid)
    return result



AUTOMATIC_NEGOTIATION_CASE = 'native-automatic-negotiation-cohort'
FOUR_DEVICE_MUTATIONS_CASE = 'native-four-device-mutations'
# Passive projection only. Never exports arbitrary lines, identifiers or content.
FOUR_DEVICE_STATES = (
    'ready', 'not observed', 'catalog not ready', 'modifier rendered as a message',
    'record not received', 'deletion differs', 'content differs',
    'edit metadata differs', 'duplicate canonical rows',
)
FOUR_DEVICE_STAGES = tuple('original origin=' + str(index) for index in range(4)) + (
    'legacy-queue-restart', 'legacy-queue-recovered-and-live')
FOUR_DEVICE_CANONICAL_MESSAGE = 'canonical state did not converge: '


def four_device_diagnostic_site():
    path = CASES[FOUR_DEVICE_MUTATIONS_CASE][2]
    source = Path(path).read_text()
    begin = source.index('async fn wait_for_device_message_state(')
    end = source.index('\n#[tokio::test', begin)
    helper = source[begin:end]
    pattern = (r'assert!\(\s*result\.is_ok\(\),\s*'
        r'"canonical state did not converge: deleted=\{deleted\}, edited=\{\}, device states=\{last_states:\?\}",\s*'
        r'edit_id\.is_some\(\)\s*\);')
    found = list(re.finditer(pattern, helper))
    if len(found) != 1 or source.count('async fn wait_for_device_message_state(') != 1:
        raise ValueError('four-device-diagnostic-source-site')
    offset = begin + found[0].start()
    # Every exported enum comes from the unchanged canonical helper's literals.
    if any(helper.count('"' + state + '"') != (2 if state == 'ready' else 1)
           for state in FOUR_DEVICE_STATES):
        raise ValueError('four-device-diagnostic-source-states')
    emissions = (
        'eprintln!("four-device-mutations stage=original origin={origin}");',
        'eprintln!("four-device-mutations stage=legacy-queue-restart");',
        'eprintln!("four-device-mutations stage=legacy-queue-recovered-and-live");',
    )
    if any(source.count(row) != 1 for row in emissions):
        raise ValueError('four-device-diagnostic-source-stages')
    return {'line': source[:offset].count('\n') + 1,
            'column': offset - source.rfind('\n', 0, offset)}


def four_device_diagnostic(raw, site, failed):
    if type(raw) is not bytes or len(raw) > 2 * 1024 * 1024 or type(failed) is not bool:
        raise ValueError('four-device-diagnostic-bound')
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    prefix = 'four-device-mutations stage='
    lines = [line for line in text.splitlines() if prefix in line]
    if len(lines) > 6 or text.count(prefix) != len(lines):
        raise ValueError('four-device-diagnostic-stage-cardinality')
    stages = []
    for line in lines:
        match = re.fullmatch(r'[ \t]{0,8}' + re.escape(prefix) + r'([^\r\n]{1,64})', line)
        if match is None or match[1] not in FOUR_DEVICE_STAGES:
            raise ValueError('four-device-diagnostic-stage-envelope')
        stages.append(match[1])
    if stages != list(FOUR_DEVICE_STAGES[:len(stages)]):
        raise ValueError('four-device-diagnostic-stage-order')
    headers = re.findall(r"(?m)^[ \t]{0,8}thread '[^'\r\n]{1,500}'(?: \([0-9]+\))? panicked at [^\r\n]{1,512}$", text)
    panic = None
    if FOUR_DEVICE_CANONICAL_MESSAGE in text:
        path = CASES[FOUR_DEVICE_MUTATIONS_CASE][2]
        header = (r"[ \t]{0,8}thread '" + re.escape(CASES[FOUR_DEVICE_MUTATIONS_CASE][1])
            + r"'(?: \([0-9]+\))? panicked at " + re.escape(path)
            + ':' + str(site['line']) + ':' + str(site['column']) + ':')
        pattern = ('(?m)^' + header + r'\n[ \t]{0,8}' + re.escape(FOUR_DEVICE_CANONICAL_MESSAGE)
            + r'deleted=(true|false), edited=(true|false), device states=(\[[^\r\n]{1,512}\])$')
        matches = list(re.finditer(pattern, text))
        if (not failed or len(matches) != 1 or len(headers) != 1
                or text.count('panicked at ') != 1
                or text.count(FOUR_DEVICE_CANONICAL_MESSAGE) != 1):
            raise ValueError('four-device-diagnostic-panic-envelope')
        match = matches[0]
        states = json.loads(match[3])
        if (type(states) is not list or len(states) not in (3, 4)
                or any(type(state) is not str or state not in FOUR_DEVICE_STATES for state in states)):
            raise ValueError('four-device-diagnostic-state-enum')
        panic = {'deleted': match[1] == 'true', 'edited': match[2] == 'true',
                 'device_states': states, 'line': site['line'], 'column': site['column'],
                 'exact_thread_source_and_message': True}
    elif headers or 'panicked at ' in text:
        raise ValueError('four-device-diagnostic-noncanonical-panic')
    return {'stage_sequence': stages, 'full_stage_sequence_seen': len(stages) == 6,
            'canonical_panic': panic,
            'complete': panic is not None if failed else len(stages) == 6,
            'passive_only': True, 'qualification_passed': False}


def four_device_diagnostic_controls(site):
    stage = lambda rows: ''.join('four-device-mutations stage=' + row + '\n' for row in rows).encode()
    header = ("thread '" + CASES[FOUR_DEVICE_MUTATIONS_CASE][1] + "' (7) panicked at "
        + CASES[FOUR_DEVICE_MUTATIONS_CASE][2] + ':' + str(site['line']) + ':' + str(site['column']) + ':\n')
    message = ('canonical state did not converge: deleted=false, edited=true, device states='
        '["ready", "record not received", "edit metadata differs", "ready"]\n')
    valid = stage(FOUR_DEVICE_STAGES[:2]) + (header + message).encode()
    observed = four_device_diagnostic(valid, site, True)
    assert observed['complete'] and observed['canonical_panic']['edited'] is True
    assert observed['canonical_panic']['deleted'] is False
    assert four_device_diagnostic((header + message.replace(', "ready"]', ']')).encode(), site, True)['complete']
    assert four_device_diagnostic(stage(FOUR_DEVICE_STAGES), site, False)['complete']
    assert four_device_diagnostic(b'', site, True)['complete'] is False
    assert four_device_diagnostic(stage(FOUR_DEVICE_STAGES[:2]), site, False)['complete'] is False
    for indent in (' ', ' ' * 8, ' \t' * 4):
        indented = ''.join(indent + line + '\n' for line in valid.decode().splitlines()).encode()
        assert four_device_diagnostic(indented, site, True)['complete']
    bad = [
        valid + (header + message).encode(), valid + stage(FOUR_DEVICE_STAGES[:1]),
        valid.replace(b'origin=1', b'origin=2'), valid.replace(b'origin=1', b'origin=PRIVATE'),
        b'PRIVATE ' + valid, valid.replace(b'edited=true', b'edited=1'),
        valid.replace(b'deleted=false', b'deleted=False'),
        valid.replace(b'edit metadata differs', b'PRIVATE'),
        valid.replace(b'["ready",', b'[7,'),
        valid.replace(b', "ready"]', b', "ready", "ready"]'),
        valid.replace(b'["ready", "record not received", ', b'['),
        valid.replace(CASES[FOUR_DEVICE_MUTATIONS_CASE][1].encode(), b'PRIVATE'),
        valid.replace(CASES[FOUR_DEVICE_MUTATIONS_CASE][2].encode(), b'PRIVATE.rs'),
        valid.replace((':' + str(site['line']) + ':').encode(), b':0:'),
        valid.replace((':' + str(site['column']) + ':\n').encode(), b':0:\n'),
        valid.replace(b'canonical state did not converge:', b'canonical state did not converge: PRIVATE'),
        valid + b"thread 'PRIVATE' panicked at PRIVATE.rs:1:1:\n",
        valid + b'four-device-mutations stage=legacy-queue-restart\n',
        valid + b'four-device-mutations stage=PRIVATE\n',
        b'\xff' + valid, b'x' * (2 * 1024 * 1024 + 1),
        b' ' * 9 + valid, b' \t' * 4 + b' ' + valid,
        valid.replace(message.encode(), (' ' * 9 + message).encode()),
        valid.replace(message.encode(), (' \t' * 4 + ' ' + message).encode()),
        valid.replace(header.encode(), (' ' * 9 + header).encode()),
    ]
    for raw in bad:
        try:
            four_device_diagnostic(raw, site, True)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError('four-device-diagnostic-invalid-accepted')
    try:
        four_device_diagnostic(valid, site, False)
    except ValueError:
        pass
    else:
        raise AssertionError('four-device-diagnostic-panic-in-pass')
    assert 'PRIVATE' not in json.dumps(observed)
    return {'positive': 8, 'negative': len(bad) + 1,
            'synthetic_metadata_only': True, 'product_bodies': 0}


WATCH_HELD_CASE = 'native-watch-held-counterpart'
WATCH_HELD_TEST = 'native_device_linking::automatic_pairing_acceptance::watch_pressure_acceptance::eight_watch_services_complete_while_actual_peer_proof_is_held'
WATCH_CLEANUP_CASE = 'native-watch-owned-cleanup'
WATCH_CLEANUP_TEST = 'native_device_linking::automatic_pairing_acceptance::watch_pressure_acceptance::watch_owned_mock_relay_cleanup_finishes_without_an_observed_initial_stop'
WATCH_CLEANUP_PATH = 'crates/marmot-app/src/native_device_linking/tests/watch_pressure_acceptance.rs'
WATCH_CLEANUP_MESSAGE = 'watch owned MockRelay cleanup must finish without an observed initial stop'
OWNED_CLEANUP_NAMESPACES = {'command-owned-cleanup': 'command-backlog-owned-cleanup',
                          WATCH_CLEANUP_CASE: 'watch-owned-cleanup'}


SQLITE_CACHE_CASE = 'storage-modifier-statement-cache'
SQLITE_CACHE_TEST = 'app::timeline::tests::modifier_lookups_reuse_their_compiled_statements'
SQLITE_CACHE_PATH = 'crates/storage-sqlite/src/app/timeline/tests.rs'
SQLITE_CACHE_TEST_SHA256 = '80712a55f215a8710fc5535dd7556f71085c356bba0787d5ee869961c62177db'


SQLITE_CACHE_SQL_PATH = 'crates/storage-sqlite/src/app/timeline.rs'
SQLITE_CACHE_INVERSES = {
    'app_events_targeting_message_tx': (
        'fn app_events_targeting_message_tx(\n    tx: &Connection,\n    group_id_hex: &str,\n    kind: u64,\n    target_message_id_hex: &str,\n) -> StorageResult<Vec<RawAppEvent>> {\n    // The edge table encodes exactly the old `tag_values(tags, EVENT_REF_TAG)\n    // .any(|t| t == target)` relationship (one edge per "e" tag value), so the\n    // indexed join is equivalent to the former JSON `LIKE` scan plus Rust-side\n    // re-filter, without either. Ordering is preserved byte-for-byte.\n    // Keep the target index outermost; scanning history to avoid a small\n    // modifier sort makes even a message with no modifiers cost O(history).\n    // `kind` is a literal, not a parameter: the partial index\n    // `content_report_labels` (`WHERE kind=1985`) makes SQLite recompile a\n    // statement on every rebind of a parameter compared with its predicate.\n    // Callers pass constant kinds, so each kind keeps one cached plan.\n    let mut stmt = tx\n        .prepare_cached(&format!(\n            "SELECT app_events.group_id_hex, app_events.message_id_hex, app_events.source_message_id_hex,\n                    app_events.source_epoch, app_events.direction, app_events.sender,\n                    app_events.plaintext, app_events.kind, app_events.tags_json,\n                    app_events.recorded_at, app_events.received_at,\n                    app_events.invalidated, app_events.invalidation_reason,\n                    app_events.moderation_grant\n             FROM message_modifier_edges AS edges\n             CROSS JOIN app_events\n               ON app_events.group_id_hex = edges.group_id_hex\n              AND app_events.message_id_hex = edges.modifier_message_id_hex\n             WHERE edges.group_id_hex = ?1\n               AND edges.kind = {}\n               AND edges.target_message_id_hex = ?2\n               AND app_events.invalidated = 0\n             ORDER BY app_events.recorded_at, app_events.message_id_hex, app_events.insert_order",\n            u64_to_i64(kind)?\n        ))\n        .storage()?;\n    stmt.query_map(\n        params![group_id_hex, target_message_id_hex],\n        raw_event_from_row,\n    )\n    .storage()?\n    .collect::<Result<Vec<_>, _>>()\n    .storage()\n}\n\n',
        'fn app_events_targeting_message_tx(\n    tx: &Connection,\n    group_id_hex: &str,\n    kind: u64,\n    target_message_id_hex: &str,\n) -> StorageResult<Vec<RawAppEvent>> {\n    // The edge table encodes exactly the old `tag_values(tags, EVENT_REF_TAG)\n    // .any(|t| t == target)` relationship (one edge per "e" tag value), so the\n    // indexed join is equivalent to the former JSON `LIKE` scan plus Rust-side\n    // re-filter, without either. Ordering is preserved byte-for-byte.\n    // Keep the target index outermost; scanning history to avoid a small\n    // modifier sort makes even a message with no modifiers cost O(history).\n    let mut stmt = tx\n        .prepare_cached(\n            "SELECT app_events.group_id_hex, app_events.message_id_hex, app_events.source_message_id_hex,\n                    app_events.source_epoch, app_events.direction, app_events.sender,\n                    app_events.plaintext, app_events.kind, app_events.tags_json,\n                    app_events.recorded_at, app_events.received_at,\n                    app_events.invalidated, app_events.invalidation_reason,\n                    app_events.moderation_grant\n             FROM message_modifier_edges AS edges\n             CROSS JOIN app_events\n               ON app_events.group_id_hex = edges.group_id_hex\n              AND app_events.message_id_hex = edges.modifier_message_id_hex\n             WHERE edges.group_id_hex = ?1\n               AND edges.kind = ?2\n               AND edges.target_message_id_hex = ?3\n               AND app_events.invalidated = 0\n             ORDER BY app_events.recorded_at, app_events.message_id_hex, app_events.insert_order",\n        )\n        .storage()?;\n    stmt.query_map(\n        params![group_id_hex, u64_to_i64(kind)?, target_message_id_hex],\n        raw_event_from_row,\n    )\n    .storage()?\n    .collect::<Result<Vec<_>, _>>()\n    .storage()\n}\n\n\n\n\n\n\n'),
    'deleted_reaction_ids_for_target_tx': (
        'fn deleted_reaction_ids_for_target_tx(\n    tx: &Connection,\n    group_id_hex: &str,\n    reactions: &[RawAppEvent],\n) -> StorageResult<HashSet<String>> {\n    if reactions.is_empty() {\n        return Ok(HashSet::new());\n    }\n    // Set-based queries collect every (reaction id, deleting sender) pair for\n    // the given reactions instead of issuing one lookup per reaction (N+1). A\n    // reaction is retracted only when a non-invalidated DELETE by the SAME\n    // sender targets it. Reaction ids are bound in fixed-size chunks so the\n    // placeholder count per statement stays well under SQLite\'s variable limit\n    // even on hot messages with very many reactions (same pattern as\n    // `delete_timeline_projection_rows_by_ids_tx`).\n    let mut delete_pairs = Vec::<(String, String)>::new();\n    // A literal kind keeps one cached plan; see `app_events_targeting_message_tx`.\n    let delete_kind = u64_to_i64(MARMOT_APP_EVENT_KIND_DELETE)?;\n    for chunk in reactions.chunks(SQLITE_BIND_PARAMETER_CHUNK) {\n        let placeholders = std::iter::repeat_n("?", chunk.len())\n            .collect::<Vec<_>>()\n            .join(", ");\n        let sql = format!(\n            "SELECT edges.target_message_id_hex, app_events.sender\n             FROM message_modifier_edges AS edges\n             JOIN app_events\n               ON app_events.group_id_hex = edges.group_id_hex\n              AND app_events.message_id_hex = edges.modifier_message_id_hex\n             WHERE edges.group_id_hex = ?\n               AND edges.kind = {delete_kind}\n               AND app_events.invalidated = 0\n               AND edges.target_message_id_hex IN ({placeholders})"\n        );\n        let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 1);\n        values.push(rusqlite::types::Value::Text(group_id_hex.to_owned()));\n        values.extend(\n            chunk\n                .iter()\n                .map(|reaction| rusqlite::types::Value::Text(reaction.message_id_hex.clone())),\n        );\n        let mut stmt = tx.prepare_cached(&sql).storage()?;\n        let chunk_pairs = stmt\n            .query_map(params_from_iter(values.iter()), |row| {\n                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))\n            })\n            .storage()?\n            .collect::<Result<Vec<_>, _>>()\n            .storage()?;\n        delete_pairs.extend(chunk_pairs);\n    }\n\n    let reaction_senders: HashMap<&str, &str> = reactions\n        .iter()\n        .map(|reaction| (reaction.message_id_hex.as_str(), reaction.sender.as_str()))\n        .collect();\n    let mut deleted = HashSet::new();\n    for (target, delete_sender) in &delete_pairs {\n        if reaction_senders\n            .get(target.as_str())\n            .is_some_and(|reaction_sender| *reaction_sender == delete_sender.as_str())\n        {\n            deleted.insert(target.clone());\n        }\n    }\n    Ok(deleted)\n}\n\n',
        'fn deleted_reaction_ids_for_target_tx(\n    tx: &Connection,\n    group_id_hex: &str,\n    reactions: &[RawAppEvent],\n) -> StorageResult<HashSet<String>> {\n    if reactions.is_empty() {\n        return Ok(HashSet::new());\n    }\n    // Set-based queries collect every (reaction id, deleting sender) pair for\n    // the given reactions instead of issuing one lookup per reaction (N+1). A\n    // reaction is retracted only when a non-invalidated DELETE by the SAME\n    // sender targets it. Reaction ids are bound in fixed-size chunks so the\n    // placeholder count per statement stays well under SQLite\'s variable limit\n    // even on hot messages with very many reactions (same pattern as\n    // `delete_timeline_projection_rows_by_ids_tx`).\n    let mut delete_pairs = Vec::<(String, String)>::new();\n    for chunk in reactions.chunks(SQLITE_BIND_PARAMETER_CHUNK) {\n        let placeholders = std::iter::repeat_n("?", chunk.len())\n            .collect::<Vec<_>>()\n            .join(", ");\n        let sql = format!(\n            "SELECT edges.target_message_id_hex, app_events.sender\n             FROM message_modifier_edges AS edges\n             JOIN app_events\n               ON app_events.group_id_hex = edges.group_id_hex\n              AND app_events.message_id_hex = edges.modifier_message_id_hex\n             WHERE edges.group_id_hex = ?\n               AND edges.kind = ?\n               AND app_events.invalidated = 0\n               AND edges.target_message_id_hex IN ({placeholders})"\n        );\n        let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 2);\n        values.push(rusqlite::types::Value::Text(group_id_hex.to_owned()));\n        values.push(rusqlite::types::Value::Integer(u64_to_i64(MARMOT_APP_EVENT_KIND_DELETE)?));\n        values.extend(\n            chunk\n                .iter()\n                .map(|reaction| rusqlite::types::Value::Text(reaction.message_id_hex.clone())),\n        );\n        let mut stmt = tx.prepare_cached(&sql).storage()?;\n        let chunk_pairs = stmt\n            .query_map(params_from_iter(values.iter()), |row| {\n                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))\n            })\n            .storage()?\n            .collect::<Result<Vec<_>, _>>()\n            .storage()?;\n        delete_pairs.extend(chunk_pairs);\n    }\n\n    let reaction_senders: HashMap<&str, &str> = reactions\n        .iter()\n        .map(|reaction| (reaction.message_id_hex.as_str(), reaction.sender.as_str()))\n        .collect();\n    let mut deleted = HashSet::new();\n    for (target, delete_sender) in &delete_pairs {\n        if reaction_senders\n            .get(target.as_str())\n            .is_some_and(|reaction_sender| *reaction_sender == delete_sender.as_str())\n        {\n            deleted.insert(target.clone());\n        }\n    }\n    Ok(deleted)\n}\n\n\n'),
    'effective_poll_votes': (
        'fn effective_poll_votes(\n    conn: &Connection,\n    messages: &[TimelineMessageRecord],\n) -> StorageResult<Vec<(usize, PollDefinition, Vec<PollVote>)>> {\n    let mut definitions = HashMap::new();\n    for (index, message) in messages.iter().enumerate() {\n        if message.kind != MARMOT_APP_EVENT_KIND_POLL\n            || message.deleted\n            || message.invalidation_status.is_some()\n        {\n            continue;\n        }\n        let event = MarmotAppEvent {\n            id: message.message_id_hex.clone(),\n            pubkey: message.sender.clone(),\n            created_at: message.timeline_at,\n            kind: message.kind,\n            tags: message.tags.clone(),\n            content: message.plaintext.clone(),\n        };\n        if let Ok(definition) = parse_poll(&event) {\n            definitions.insert(\n                (message.group_id_hex.clone(), message.message_id_hex.clone()),\n                (index, definition, message.timeline_at),\n            );\n        }\n    }\n    if definitions.is_empty() {\n        return Ok(Vec::new());\n    }\n    let mut by_group = BTreeMap::<String, Vec<String>>::new();\n    for (group, poll_id) in definitions.keys() {\n        by_group\n            .entry(group.clone())\n            .or_default()\n            .push(poll_id.clone());\n    }\n    let mut responses = Vec::new();\n    // Literal kinds keep one cached plan; see `app_events_targeting_message_tx`.\n    let response_kind = u64_to_i64(MARMOT_APP_EVENT_KIND_POLL_RESPONSE)?;\n    let delete_kind = u64_to_i64(MARMOT_APP_EVENT_KIND_DELETE)?;\n    for (group, poll_ids) in by_group {\n        for chunk in poll_ids.chunks(SQLITE_BIND_PARAMETER_CHUNK) {\n            let placeholders = std::iter::repeat_n("?", chunk.len())\n                .collect::<Vec<_>>()\n                .join(", ");\n            let sql = format!(\n                "SELECT group_id_hex, message_id_hex, sender, tags_json, recorded_at\n                 FROM (\n                    SELECT app_events.*,\n                           ROW_NUMBER() OVER (\n                               PARTITION BY edges.target_message_id_hex, app_events.sender\n                               ORDER BY app_events.recorded_at DESC, app_events.message_id_hex DESC\n                           ) AS voter_rank\n                    FROM message_modifier_edges AS edges\n                    JOIN app_events\n                      ON app_events.group_id_hex = edges.group_id_hex\n                     AND app_events.message_id_hex = edges.modifier_message_id_hex\n                    WHERE edges.group_id_hex = ?\n                      AND edges.kind = {response_kind}\n                      AND app_events.invalidated = 0\n                      AND NOT EXISTS (\n                          SELECT 1\n                          FROM message_modifier_edges AS delete_edges\n                          JOIN app_events AS delete_events\n                            ON delete_events.group_id_hex = delete_edges.group_id_hex\n                           AND delete_events.message_id_hex = delete_edges.modifier_message_id_hex\n                          WHERE delete_edges.group_id_hex = app_events.group_id_hex\n                            AND delete_edges.kind = {delete_kind}\n                            AND delete_edges.target_message_id_hex = app_events.message_id_hex\n                            AND delete_events.invalidated = 0\n                            AND (\n                                delete_events.sender = app_events.sender\n                                OR delete_events.moderation_grant = 1\n                            )\n                      )\n                      AND edges.target_message_id_hex IN ({placeholders})\n                 )\n                 WHERE voter_rank <= ?"\n            );\n            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 2);\n            values.push(rusqlite::types::Value::Text(group.clone()));\n            values.extend(chunk.iter().cloned().map(rusqlite::types::Value::Text));\n            values.push(rusqlite::types::Value::Integer(\n                MAX_POLL_RESPONSES_PER_AUTHOR as i64,\n            ));\n            let mut stmt = conn.prepare_cached(&sql).storage()?;\n            responses.extend(\n                stmt.query_map(\n                    params_from_iter(values.iter()),\n                    poll_response_candidate_from_row,\n                )\n                .storage()?\n                .collect::<Result<Vec<_>, _>>()\n                .storage()?,\n            );\n        }\n    }\n\n    let mut effective = HashMap::<(String, String, String), (u64, String, Vec<String>)>::new();\n    for response in responses {\n        let event = MarmotAppEvent {\n            id: response.message_id_hex.clone(),\n            pubkey: response.sender.clone(),\n            created_at: response.recorded_at,\n            kind: MARMOT_APP_EVENT_KIND_POLL_RESPONSE,\n            tags: response.tags.clone(),\n            content: String::new(),\n        };\n        let Ok((poll_id, selections)) = parse_poll_response(&event) else {\n            continue;\n        };\n        let Some((_, poll, poll_created_at)) =\n            definitions.get(&(response.group_id_hex.clone(), poll_id.clone()))\n        else {\n            continue;\n        };\n        if validate_poll_response(poll, *poll_created_at, response.recorded_at, &selections)\n            .is_err()\n        {\n            continue;\n        }\n        let key = (\n            response.group_id_hex.clone(),\n            poll_id,\n            response.sender.clone(),\n        );\n        let order = (response.recorded_at, response.message_id_hex.as_str());\n        let replace = effective\n            .get(&key)\n            .is_none_or(|current| order > (current.0, current.1.as_str()));\n        if replace {\n            effective.insert(\n                key,\n                (response.recorded_at, response.message_id_hex, selections),\n            );\n        }\n    }\n\n    let mut effective_by_poll = HashMap::<(String, String), Vec<PollVote>>::new();\n    for ((group, poll_id, voter), (voted_at, _, option_ids)) in effective {\n        effective_by_poll\n            .entry((group, poll_id))\n            .or_default()\n            .push(PollVote {\n                voter,\n                option_ids,\n                voted_at,\n            });\n    }\n\n    Ok(definitions\n        .into_iter()\n        .map(|(key, (index, definition, _))| {\n            let mut votes = effective_by_poll.remove(&key).unwrap_or_default();\n            votes.sort_by(|a, b| (a.voted_at, &a.voter).cmp(&(b.voted_at, &b.voter)));\n            (index, definition, votes)\n        })\n        .collect())\n}\n\n',
        'fn effective_poll_votes(\n    conn: &Connection,\n    messages: &[TimelineMessageRecord],\n) -> StorageResult<Vec<(usize, PollDefinition, Vec<PollVote>)>> {\n    let mut definitions = HashMap::new();\n    for (index, message) in messages.iter().enumerate() {\n        if message.kind != MARMOT_APP_EVENT_KIND_POLL\n            || message.deleted\n            || message.invalidation_status.is_some()\n        {\n            continue;\n        }\n        let event = MarmotAppEvent {\n            id: message.message_id_hex.clone(),\n            pubkey: message.sender.clone(),\n            created_at: message.timeline_at,\n            kind: message.kind,\n            tags: message.tags.clone(),\n            content: message.plaintext.clone(),\n        };\n        if let Ok(definition) = parse_poll(&event) {\n            definitions.insert(\n                (message.group_id_hex.clone(), message.message_id_hex.clone()),\n                (index, definition, message.timeline_at),\n            );\n        }\n    }\n    if definitions.is_empty() {\n        return Ok(Vec::new());\n    }\n    let mut by_group = BTreeMap::<String, Vec<String>>::new();\n    for (group, poll_id) in definitions.keys() {\n        by_group\n            .entry(group.clone())\n            .or_default()\n            .push(poll_id.clone());\n    }\n    let mut responses = Vec::new();\n    for (group, poll_ids) in by_group {\n        for chunk in poll_ids.chunks(SQLITE_BIND_PARAMETER_CHUNK) {\n            let placeholders = std::iter::repeat_n("?", chunk.len())\n                .collect::<Vec<_>>()\n                .join(", ");\n            let sql = format!(\n                "SELECT group_id_hex, message_id_hex, sender, tags_json, recorded_at\n                 FROM (\n                    SELECT app_events.*,\n                           ROW_NUMBER() OVER (\n                               PARTITION BY edges.target_message_id_hex, app_events.sender\n                               ORDER BY app_events.recorded_at DESC, app_events.message_id_hex DESC\n                           ) AS voter_rank\n                    FROM message_modifier_edges AS edges\n                    JOIN app_events\n                      ON app_events.group_id_hex = edges.group_id_hex\n                     AND app_events.message_id_hex = edges.modifier_message_id_hex\n                    WHERE edges.group_id_hex = ?\n                      AND edges.kind = ?\n                      AND app_events.invalidated = 0\n                      AND NOT EXISTS (\n                          SELECT 1\n                          FROM message_modifier_edges AS delete_edges\n                          JOIN app_events AS delete_events\n                            ON delete_events.group_id_hex = delete_edges.group_id_hex\n                           AND delete_events.message_id_hex = delete_edges.modifier_message_id_hex\n                          WHERE delete_edges.group_id_hex = app_events.group_id_hex\n                            AND delete_edges.kind = ?\n                            AND delete_edges.target_message_id_hex = app_events.message_id_hex\n                            AND delete_events.invalidated = 0\n                            AND (\n                                delete_events.sender = app_events.sender\n                                OR delete_events.moderation_grant = 1\n                            )\n                      )\n                      AND edges.target_message_id_hex IN ({placeholders})\n                 )\n                 WHERE voter_rank <= ?"\n            );\n            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 4);\n            values.push(rusqlite::types::Value::Text(group.clone()));\n            values.push(rusqlite::types::Value::Integer(u64_to_i64(MARMOT_APP_EVENT_KIND_POLL_RESPONSE)?));\n            values.push(rusqlite::types::Value::Integer(u64_to_i64(MARMOT_APP_EVENT_KIND_DELETE)?));\n            values.extend(chunk.iter().cloned().map(rusqlite::types::Value::Text));\n            values.push(rusqlite::types::Value::Integer(\n                MAX_POLL_RESPONSES_PER_AUTHOR as i64,\n            ));\n            let mut stmt = conn.prepare_cached(&sql).storage()?;\n            responses.extend(\n                stmt.query_map(\n                    params_from_iter(values.iter()),\n                    poll_response_candidate_from_row,\n                )\n                .storage()?\n                .collect::<Result<Vec<_>, _>>()\n                .storage()?,\n            );\n        }\n    }\n\n    let mut effective = HashMap::<(String, String, String), (u64, String, Vec<String>)>::new();\n    for response in responses {\n        let event = MarmotAppEvent {\n            id: response.message_id_hex.clone(),\n            pubkey: response.sender.clone(),\n            created_at: response.recorded_at,\n            kind: MARMOT_APP_EVENT_KIND_POLL_RESPONSE,\n            tags: response.tags.clone(),\n            content: String::new(),\n        };\n        let Ok((poll_id, selections)) = parse_poll_response(&event) else {\n            continue;\n        };\n        let Some((_, poll, poll_created_at)) =\n            definitions.get(&(response.group_id_hex.clone(), poll_id.clone()))\n        else {\n            continue;\n        };\n        if validate_poll_response(poll, *poll_created_at, response.recorded_at, &selections)\n            .is_err()\n        {\n            continue;\n        }\n        let key = (\n            response.group_id_hex.clone(),\n            poll_id,\n            response.sender.clone(),\n        );\n        let order = (response.recorded_at, response.message_id_hex.as_str());\n        let replace = effective\n            .get(&key)\n            .is_none_or(|current| order > (current.0, current.1.as_str()));\n        if replace {\n            effective.insert(\n                key,\n                (response.recorded_at, response.message_id_hex, selections),\n            );\n        }\n    }\n\n    let mut effective_by_poll = HashMap::<(String, String), Vec<PollVote>>::new();\n    for ((group, poll_id, voter), (voted_at, _, option_ids)) in effective {\n        effective_by_poll\n            .entry((group, poll_id))\n            .or_default()\n            .push(PollVote {\n                voter,\n                option_ids,\n                voted_at,\n            });\n    }\n\n    Ok(definitions\n        .into_iter()\n        .map(|(key, (index, definition, _))| {\n            let mut votes = effective_by_poll.remove(&key).unwrap_or_default();\n            votes.sort_by(|a, b| (a.voted_at, &a.voter).cmp(&(b.voted_at, &b.voter)));\n            (index, definition, votes)\n        })\n        .collect())\n}\n\n\n'),
}


def sqlite_cache_inverses():
    original = Path(SQLITE_CACHE_SQL_PATH).read_bytes()
    text = original.decode('utf-8')
    mutants = []
    for name, (green, old) in SQLITE_CACHE_INVERSES.items():
        start = text.index('fn ' + name + '(')
        later = re.search(r'^fn ', text[start + 1:], re.M)
        if later is None:
            raise ValueError('sqlite-cache-function-end')
        end = start + 1 + later.start()
        if (text[start:end] != green or text.count(green) != 1
                or green == old or green.count('\n') != old.count('\n')
                or not old.startswith('fn ' + name + '(')):
            raise ValueError('sqlite-cache-function-owner')
        mutant = (text[:start] + old + text[end:]).encode()
        if mutant == original or mutant.count(b'\n') != original.count(b'\n'):
            raise ValueError('sqlite-cache-inverse-shape')
        mutants.append((name, mutant))
    if len(mutants) != 3 or len({hashlib.sha256(data).hexdigest() for _, data in mutants}) != 3:
        raise ValueError('sqlite-cache-three-distinct-inverses')
    return SQLITE_CACHE_SQL_PATH, original, mutants, sqlite_cache_site()


def sqlite_cache_site():
    source = Path(SQLITE_CACHE_PATH).read_text()
    begin = source.index('#[test]\nfn modifier_lookups_reuse_their_compiled_statements()')
    end = source.index('fn no_mentions(', begin)
    fixture = source[begin:end]
    if hashlib.sha256(fixture.encode()).hexdigest() != SQLITE_CACHE_TEST_SHA256:
        raise ValueError('sqlite-cache-upstream-fixture')
    final = 'assert_eq!(REPREPARES.load(Ordering::Relaxed), 0);'
    if fixture.count(final) != 1:
        raise ValueError('sqlite-cache-final-site')
    offset = begin + fixture.index(final)
    return {'line': source[:offset].count('\n') + 1,
            'column': offset - source.rfind('\n', 0, offset)}


def sqlite_cache_failure(raw, site):
    if type(raw) is not bytes or len(raw) > 2 * 1024 * 1024:
        return False
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    if text.count('panicked at ') != 1:
        return False
    pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(SQLITE_CACHE_TEST)
        + r"'(?: \([0-9]+\))? panicked at " + re.escape(SQLITE_CACHE_PATH)
        + ':' + str(site['line']) + ':' + str(site['column'])
        + r':[ \t]*\n(?:[ \t]*\n){0,2}[ \t]{0,8}assertion `left == right` failed[ \t]*\n'
        + r'[ \t]{0,8}left: ([1-9][0-9]{0,9})[ \t]*\n[ \t]{0,8}right: 0[ \t]*(?:\n|$)')
    return re.search(pattern, text) is not None


def sqlite_cache_controls(site):
    assert positive_configuration(SQLITE_CACHE_CASE) == ([], 'm5-bounded', None)
    assert package_for(SQLITE_CACHE_CASE) == 'storage-sqlite'
    assert SQLITE_CACHE_CASE not in STORAGE_CASES | EXPERIMENTAL_CASES | INTEGRATION_CASES
    header = ("thread '" + SQLITE_CACHE_TEST + "' (7) panicked at " + SQLITE_CACHE_PATH
        + ':' + str(site['line']) + ':' + str(site['column']) + ':\n'
        + 'assertion `left == right` failed\n  left: 42\n right: 0\n').encode()
    for indent in (b'', b' ', b' ' * 6):
        assert sqlite_cache_failure(b'\n'.join(indent + line for line in header.split(b'\n')), site)
    invalid = [b'', header + header, header.replace(SQLITE_CACHE_TEST.encode(), b'PRIVATE'),
        header.replace(SQLITE_CACHE_PATH.encode(), b'PRIVATE.rs'),
        header.replace((':' + str(site['line']) + ':').encode(), b':0:'),
        header.replace((':' + str(site['column']) + ':\n').encode(), b':0:\n'),
        header.replace(b'left: 42', b'left: 0'), header.replace(b'left: 42', b'left: -1'),
        header.replace(b'left: 42', b'left: 0.1'), header.replace(b'right: 0', b'right: 1'),
        header.replace(b'failed\n', b'failed: PRIVATE\n'),
        header.replace(b'42', b'1' * 11), b' ' * 9 + header,
        b'\n'.join(b' ' * 8 + line for line in header.split(b'\n'))]
    for raw in invalid:
        assert not sqlite_cache_failure(raw, site)
    tests = {SQLITE_CACHE_TEST: SQLITE_CACHE_PATH}
    good = ('PASS [ 0.1s] storage-sqlite ' + SQLITE_CACHE_TEST + '\n'
        + 'Summary [ 0.1s] 1 test run: 1 passed, 0 skipped\n').encode()
    assert automatic_negotiation_runtime(good, tests, 'storage-sqlite')['complete']
    bad_rows = [b'', good + good, good.replace(b'storage-sqlite', b'PRIVATE'),
        good.replace(SQLITE_CACHE_TEST.encode(), b'PRIVATE'),
        good.replace(b'1 test run', b'0 tests run'), good.replace(b'1 passed', b'0 passed')]
    for raw in bad_rows:
        assert not automatic_negotiation_runtime(raw, tests, 'storage-sqlite')['complete']
    return {'positive': 4, 'negative': len(invalid) + len(bad_rows),
            'product_bodies': 0, 'synthetic_metadata_only': True}


MUTATION_ADMISSION_CASE = 'native-mutation-admission-contract'
MUTATION_ADMISSION_TEST = 'tests::actual_runtime_edit_completion_unknown_preserves_exact_canonical_identity'
MUTATION_ADMISSION_PATH = 'crates/marmot-app/src/tests.rs'
MUTATION_ADMISSION_PREFIX = 'MUTATION_ADMISSION_PROBE'
MUTATION_ADMISSION_MESSAGE = 'mutation admission must agree with its actual typed send outcome'
MUTATION_ADMISSION_FIELDS = {
    'healthy_original_published', 'actual_unknown', 'actual_zero_published',
    'exact_one_distinct_edit_id', 'durable_edit_bound', 'frozen_transport_verified',
    'attempted_exact_frozen', 'recovered_exact_transport_once', 'canonical_edit_exact_once',
    'no_standalone_edit_row', 'fanout_retired', 'cleanup_complete',
}


def mutation_admission_probe(raw):
    if type(raw) is not bytes or len(raw) > 2 * 1024 * 1024:
        raise ValueError('mutation-admission-bound')
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    lines = [line for line in text.splitlines() if MUTATION_ADMISSION_PREFIX in line]
    if len(lines) != 1 or text.count(MUTATION_ADMISSION_PREFIX) != 1 or len(lines[0]) > 4096:
        raise ValueError('mutation-admission-cardinality')
    match = re.fullmatch(r'[ \t]{0,8}' + MUTATION_ADMISSION_PREFIX
        + r' (\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    if match is None:
        raise ValueError('mutation-admission-envelope')
    value = json.loads(match[1], object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != MUTATION_ADMISSION_FIELDS
            or any(type(item) is not bool for item in value.values())):
        raise ValueError('mutation-admission-fields')
    return value


def mutation_admission_site(text=None):
    if text is None:
        text = Path(MUTATION_ADMISSION_PATH).read_text()
    start = text.index('pub(crate) fn assert_mutation_admitted(')
    end = text.index('\n}', start) + 2
    helper = text[start:end]
    # Bind the pending assertion to the exact typed branch, preserving Published=1.
    pattern = (r'match\s+summary\.accept_disposition\s*\{\s*'
        r'cgka_traits::SendAcceptDisposition::Published\s*=>\s*'
        r'assert_eq!\(\s*summary\.published,\s*1\s*\),\s*'
        r'cgka_traits::SendAcceptDisposition::AcceptedPending\s*'
        r'\|\s*cgka_traits::SendAcceptDisposition::CompletionUnknown\s*=>\s*\{\s*'
        r'(?P<own>assert_eq!\(\s*summary\.published,\s*0,\s*"'
        + re.escape(MUTATION_ADMISSION_MESSAGE) + r'"\s*,?\s*\);)\s*\}\s*\}')
    matches = list(re.finditer(pattern, helper))
    if (text.count('pub(crate) fn assert_mutation_admitted(') != 1 or len(matches) != 1
            or helper.count('assert_eq!(summary.message_ids.len(), 1);') != 1):
        raise ValueError('mutation-admission-typed-helper-source')
    offset = start + matches[0].start('own')
    return {'line': text[:offset].count('\n') + 1,
            'column': offset - text.rfind('\n', 0, offset)}


def mutation_admission_failure(raw, site):
    try:
        value = mutation_admission_probe(raw)
        text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    except (ValueError, UnicodeError):
        return False
    if not all(value.values()) or text.count('panicked at ') != 1:
        return False
    pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(MUTATION_ADMISSION_TEST)
        + r"'(?: \([0-9]+\))? panicked at " + re.escape(MUTATION_ADMISSION_PATH)
        + ':' + str(site['line']) + ':' + str(site['column']) + r':[ \t]*\n'
        + r'(?:[ \t]*\n){0,2}[ \t]{0,8}assertion `left == right` failed: '
        + re.escape(MUTATION_ADMISSION_MESSAGE)
        + r'[ \t]*\n[ \t]{0,8}left: 0[ \t]*\n[ \t]{0,8}right: 1[ \t]*(?:\n|$)')
    found = re.search(pattern, text)
    return found is not None and text.index(MUTATION_ADMISSION_PREFIX) < found.start()


def mutation_admission_controls(site):
    """Authored metadata only; actual summary/recovery/cleanup must run separately."""
    value = dict.fromkeys(MUTATION_ADMISSION_FIELDS, True)
    row = lambda item: (MUTATION_ADMISSION_PREFIX + ' ' + json.dumps(item) + '\n').encode()
    good = row(value)
    assert mutation_admission_probe(good) == value
    bad = [b'', good + good, b'\xff' + good, b'PRIVATE ' + good,
        b' ' * 9 + good, good.replace(b'\n', b' PRIVATE\n'),
        row(dict(value, private_id='PRIVATE')), (MUTATION_ADMISSION_PREFIX + ' []\n').encode()]
    for key in sorted(value):
        bad += [row({name: item for name, item in value.items() if name != key}),
            good.replace(b'{', ('{' + json.dumps(key) + ':true,').encode(), 1),
            row(dict(value, **{key: 1}))]
    for raw in bad:
        try:
            mutation_admission_probe(raw)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError('mutation-admission-invalid-probe-accepted')
    header = ("thread '" + MUTATION_ADMISSION_TEST + "' (7) panicked at " + MUTATION_ADMISSION_PATH
        + ':' + str(site['line']) + ':' + str(site['column']) + ':\n'
        + 'assertion `left == right` failed: ' + MUTATION_ADMISSION_MESSAGE + '\n  left: 0\n right: 1\n').encode()
    assert mutation_admission_failure(good + header, site)
    invalid = [good, header + good, good + header + header,
        good + header.replace(MUTATION_ADMISSION_TEST.encode(), b'PRIVATE'),
        good + header.replace(MUTATION_ADMISSION_PATH.encode(), b'PRIVATE.rs'),
        good + header.replace(MUTATION_ADMISSION_MESSAGE.encode(), b'PRIVATE'),
        good + header.replace((':' + str(site['line']) + ':').encode(), b':0:'),
        good + header.replace((':' + str(site['column']) + ':\n').encode(), b':0:\n'),
        good + header.replace(b'left: 0', b'left: 1'),
        good + header.replace(b'right: 1', b'right: 0'),
        good + header + b"thread 'PRIVATE' panicked at PRIVATE.rs:1:1:\n"]
    invalid += [row(dict(value, **{key: False})) + header for key in value]
    assert all(not mutation_admission_failure(raw, site) for raw in invalid)
    tests = {MUTATION_ADMISSION_TEST: MUTATION_ADMISSION_PATH}
    passing = ('PASS [ 0.001s] marmot-app ' + MUTATION_ADMISSION_TEST
        + '\nSummary [ 0.1s] 1 test run: 1 passed, 0 failed, 0 skipped\n').encode()
    failing = passing.replace(b'PASS ', b'FAIL ', 1).replace(b'1 passed, 0 failed', b'0 passed, 1 failed')
    assert automatic_negotiation_runtime(passing, tests)['complete']
    assert automatic_negotiation_runtime(failing, tests)['complete']
    invalid_runtime = [b'', passing + passing, passing.replace(MUTATION_ADMISSION_TEST.encode(), b'PRIVATE'),
        passing.replace(b'marmot-app', b'PRIVATE'), passing.replace(b'1 test run', b'0 tests run'),
        passing.replace(b'1 passed, 0 failed', b'0 passed, 1 failed')]
    assert all(not automatic_negotiation_runtime(raw, tests)['complete'] for raw in invalid_runtime)
    return {'probe_positive': 1, 'probe_negative': len(bad), 'own_positive': 1,
            'own_negative': len(invalid), 'runtime_positive': 2, 'runtime_negative': len(invalid_runtime),
            'synthetic_metadata_only': True, 'product_bodies': 0}


AUTOMATIC_SCAN_EXPIRY_CASE = 'native-automatic-scan-expiry'
AUTOMATIC_NEGOTIATION_TESTS = {
    'native_device_linking::enabled::negotiated::tests::cancel_before_activation_retires_the_reserved_original':
        'crates/marmot-app/src/native_device_linking/enabled/negotiated.rs',
    'native_device_linking::enabled::negotiated::tests::cancellation_revokes_original_before_waiting_for_activation_lock':
        'crates/marmot-app/src/native_device_linking/enabled/negotiated.rs',
    'native_device_linking::enabled::negotiated::tests::cancelled_transport_rejects_and_retires_a_late_genuine_original':
        'crates/marmot-app/src/native_device_linking/enabled/negotiated.rs',
    'native_device_linking::automatic_pairing_acceptance::role_neutral_first_pair_merges_both_devices_chats':
        'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs',
    'native_device_linking::automatic_pairing_acceptance::role_neutral_first_pair_reversed_merges_both_devices_chats':
        'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs',
    'native_device_linking::automatic_pairing_acceptance::fresh_scanner_can_join_existing_display_group':
        'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs',
}


def automatic_negotiation_selection(tests=AUTOMATIC_NEGOTIATION_TESTS, package='marmot-app', binary='marmot_app'):
    return 'package(' + package + ') & binary(=' + binary + ') & (' + ' | '.join(
        'test(=' + name + ')' for name in tests) + ')'


def selected_automatic_negotiation(inventory, tests=AUTOMATIC_NEGOTIATION_TESTS, package='marmot-app', binary='marmot_app'):
    selected = []
    for suite in inventory['rust-suites'].values():
        for name, item in suite['testcases'].items():
            if item['filter-match']['status'] != 'matches':
                continue
            if (suite.get('binary-name') != binary or suite.get('kind') != 'lib'
                    or item['ignored'] is not False):
                raise ValueError('automatic-negotiation-binary-or-ignored')
            selected.append(name)
    expected = list(tests)
    if (len(selected) != len(expected) or len(set(selected)) != len(expected)
            or set(selected) != set(expected)):
        raise ValueError('automatic-negotiation-exact-inventory')
    return {'selected_nonignored': len(expected), 'selected_ignored': 0,
            'tests': expected, 'binary': binary, 'package': package,
            'compiler_scope': 'one shared exact library inventory and one shared runtime command'}


def automatic_negotiation_runtime(raw, tests=AUTOMATIC_NEGOTIATION_TESTS, package='marmot-app'):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    found = re.findall(
        r'(?m)^\s*(PASS|FAIL)\s+\[\s*([0-9]{1,5}(?:\.[0-9]{1,9})?)s\s*\]\s+'
        r'(?:\(([0-9]{1,3})/([0-9]{1,3})\)[ \t]+)?' + re.escape(package) + r'[ \t]+([^\s]+)[ \t]*$', text)
    rows = []
    unexpected = max(0, len(re.findall(r'(?m)^\s*(?:PASS|FAIL)\s+', text)) - len(found))
    progress = []
    for outcome, duration, ordinal, total, name in found:
        if ordinal or total:
            progress.append((int(ordinal), int(total)))
        if name not in tests or not 0 <= float(duration) <= 1800:
            unexpected += 1
            continue
        rows.append({'test': name, 'outcome': outcome, 'runtime_seconds': float(duration)})
    summary = summary_counts(raw)
    counts_value = summary['counts']
    expected = set(tests)
    complete = (unexpected == 0
                and (not progress or (len(progress) == len(expected)
                    and {ordinal for ordinal, _ in progress} == set(range(1, len(expected) + 1))
                    and all(total == len(expected) for _, total in progress)))
                and len(rows) == len(expected)
                and len({row['test'] for row in rows}) == len(expected)
                and {row['test'] for row in rows} == expected
                and counts_value is not None
                and counts_value['executed'] == len(expected)
                and counts_value['passed'] + counts_value['failed'] == len(expected)
                and counts_value['passed'] == sum(row['outcome'] == 'PASS' for row in rows)
                and counts_value['failed'] == sum(row['outcome'] == 'FAIL' for row in rows))
    # Preserve incomplete/failed actual observations without certifying them.
    return {'counts': counts_value, 'rows': rows, 'unexpected_terminal_rows': unexpected,
            'complete': complete, 'runtime_summary': summary}


def automatic_negotiation_panics(raw, tests=AUTOMATIC_NEGOTIATION_TESTS):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    headers = re.findall(
        r"(?m)^[ \t]{0,8}thread '([^'\r\n]+)'(?: \([0-9]+\))? panicked at ([^\s]+\.rs):([0-9]+):([0-9]+):", text)
    sites = []
    unknown = max(0, text.count('panicked at ') - len(headers))
    for thread, path, line, column in headers:
        if (thread in tests and path == tests[thread]
                and 0 < int(line) <= 1000000 and 0 < int(column) <= 1000000 and len(sites) < 8):
            sites.append({'test': thread, 'path': path, 'line': int(line), 'column': int(column)})
        else:
            unknown += 1
    return {'sites': sites, 'unknown_or_excess_headers': unknown}


def automatic_negotiation_controls():
    """Metadata controls only; never credit six synthetic rows as execution."""
    names = list(AUTOMATIC_NEGOTIATION_TESTS)
    suite = {'binary-name': 'marmot_app', 'kind': 'lib', 'testcases': {
        name: {'ignored': False, 'filter-match': {'status': 'matches'}} for name in names}}
    good = {'rust-suites': {'unit': suite}}
    assert selected_automatic_negotiation(good)['selected_nonignored'] == len(names)
    bad_inventory = []
    for key, value in [('binary-name', 'PRIVATE'), ('kind', 'test')]:
        changed = json.loads(json.dumps(good)); changed['rust-suites']['unit'][key] = value; bad_inventory.append(changed)
    for key, value in [('ignored', True), ('ignored', 0), ('filter-match', {'status': 'mismatch'})]:
        changed = json.loads(json.dumps(good)); changed['rust-suites']['unit']['testcases'][names[0]][key] = value; bad_inventory.append(changed)
    changed = json.loads(json.dumps(good)); del changed['rust-suites']['unit']['testcases'][names[0]]; bad_inventory.append(changed)
    changed = json.loads(json.dumps(good)); changed['rust-suites']['extra'] = suite; bad_inventory.append(changed)
    changed = json.loads(json.dumps(good)); changed['rust-suites']['unit']['testcases']['PRIVATE'] = {'ignored': False, 'filter-match': {'status': 'matches'}}; bad_inventory.append(changed)
    for changed in bad_inventory:
        try:
            selected_automatic_negotiation(changed)
        except ValueError:
            pass
        else:
            raise AssertionError('automatic-negotiation-inventory-negative')
    def runtime(outcomes, selected=names):
        rows = ''.join(outcome + ' [ 0.001s] marmot-app ' + name + '\n' for outcome, name in zip(outcomes, selected))
        return (rows + 'Summary [ 0.1s] ' + str(len(selected)) + ' tests run: '
                + str(outcomes.count('PASS')) + ' passed, ' + str(outcomes.count('FAIL')) + ' failed, 0 skipped\n').encode()
    positive = runtime(['PASS'] * len(names))
    failed = runtime(['FAIL'] + ['PASS'] * (len(names) - 1))
    assert automatic_negotiation_runtime(positive)['complete']
    assert automatic_negotiation_runtime(failed)['complete'] and automatic_negotiation_runtime(failed)['counts']['failed'] == 1
    progress = positive
    for ordinal, name in enumerate(names, 1):
        progress = progress.replace(('marmot-app ' + name).encode(),
            ('(' + str(ordinal) + '/' + str(len(names)) + ') marmot-app ' + name).encode())
    assert automatic_negotiation_runtime(progress)['complete']
    bad_runtime = [progress.replace(b'(1/', b'(0/', 1),
        progress.replace(('(1/' + str(len(names)) + ')').encode(), b'(1/1)', 1),
        progress.replace(('(1/' + str(len(names)) + ') ').encode(), b'', 1),
        progress + b'PASS [ PRIVATE] PRIVATE\n', b'', positive + positive, runtime(['PASS'] * (len(names) - 1), names[:-1]),
        runtime(['PASS'] * len(names), names[:-1] + [names[0]]),
        runtime(['PASS'] * len(names), names[:-1] + ['PRIVATE']),
        positive.replace((str(len(names)) + ' tests run:').encode(), b'0 tests run:'),
        positive.replace((str(len(names)) + ' passed').encode(), (str(len(names) - 1) + ' passed').encode()), positive.replace(b'0 failed', b'1 failed'),
        positive.replace(b'PASS', b'FAIL', 1), positive.replace(b'0.001s', b'PRIVATE', 1)]
    assert all(not automatic_negotiation_runtime(raw)['complete'] for raw in bad_runtime)
    return {'inventory_positive': 1, 'inventory_negative': len(bad_inventory),
            'runtime_positive': 3, 'runtime_negative': len(bad_runtime),
            'synthetic_metadata_only': True, 'product_bodies': 0}


AUTOMATIC_SCAN_EXPIRY_RED_CASE = 'native-automatic-scan-expiry-red'
AUTOMATIC_SCAN_EXPIRY_TEST = 'runtime::device_linking::tests::expired_automatic_scan_is_rejected_after_real_roster_wait'
AUTOMATIC_SCAN_EXPIRY_PATH = 'crates/marmot-app/src/runtime/device_linking.rs'
AUTOMATIC_SCAN_EXPIRY_PREFIX = 'AUTOMATIC_SCAN_EXPIRY_PROBE'
AUTOMATIC_SCAN_EXPIRY_MESSAGE = 'expired scanned bootstrap must not be renewed by the protected roster wait'
AUTOMATIC_SCAN_EXPIRY_PREREQUISITES = {
    'initial_targets_empty', 'initial_code_valid', 'roster_wait_pending',
    'wall_expired_before_release', 'scan_completed', 'cleanup_succeeded',
}
AUTOMATIC_SCAN_EXPIRY_FIELDS = AUTOMATIC_SCAN_EXPIRY_PREREQUISITES | {'expired_scan_rejected'}
AUTOMATIC_SCAN_EXPIRY_CASES = {AUTOMATIC_SCAN_EXPIRY_CASE, AUTOMATIC_SCAN_EXPIRY_RED_CASE}
AUTOMATIC_NATIVE_CASES = AUTOMATIC_SCAN_EXPIRY_CASES | {AUTOMATIC_NEGOTIATION_CASE, FOUR_DEVICE_MUTATIONS_CASE, MUTATION_ADMISSION_CASE, WATCH_CLEANUP_CASE, WATCH_HELD_CASE}


def automatic_scan_expiry_probe(raw):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    lines = [line for line in text.splitlines() if AUTOMATIC_SCAN_EXPIRY_PREFIX in line]
    if (len(lines) != 1 or text.count(AUTOMATIC_SCAN_EXPIRY_PREFIX) != 1
            or len(lines[0]) > 1024):
        raise ValueError('automatic-scan-expiry-cardinality')
    match = re.fullmatch(r'[ \t]{0,8}' + AUTOMATIC_SCAN_EXPIRY_PREFIX
                         + r' (\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    if match is None:
        raise ValueError('automatic-scan-expiry-envelope')
    value = json.loads(match[1], object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != AUTOMATIC_SCAN_EXPIRY_FIELDS
            or any(type(item) is not bool for item in value.values())):
        raise ValueError('automatic-scan-expiry-fields')
    return value


def automatic_scan_expiry_site():
    text = Path(AUTOMATIC_SCAN_EXPIRY_PATH).read_text()
    pattern = (r'assert!\(\s*expired_scan_rejected,\s*"'
               + re.escape(AUTOMATIC_SCAN_EXPIRY_MESSAGE) + r'"\s*,?\s*\);')
    found = list(re.finditer(pattern, text))
    if len(found) != 1:
        raise ValueError('automatic-scan-expiry-source-site')
    return {'line': text[:found[0].start()].count('\n') + 1,
            'column': found[0].start() - text.rfind('\n', 0, found[0].start())}


def automatic_scan_expiry_failure(raw, site):
    try:
        value = automatic_scan_expiry_probe(raw)
        text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    except (ValueError, UnicodeError):
        return False
    if (not all(value[key] is True for key in AUTOMATIC_SCAN_EXPIRY_PREREQUISITES)
            or value['expired_scan_rejected'] is not False or text.count('panicked at ') != 1):
        return False
    pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(AUTOMATIC_SCAN_EXPIRY_TEST)
               + r"'(?: \([0-9]+\))? panicked at " + re.escape(AUTOMATIC_SCAN_EXPIRY_PATH)
               + ':' + str(site['line']) + ':' + str(site['column'])
               + r':[ \t]*\n(?:[ \t]*\n){0,2}[ \t]{0,8}'
               + re.escape(AUTOMATIC_SCAN_EXPIRY_MESSAGE) + r'[ \t]*(?:\n|$)')
    found = re.search(pattern, text)
    return found is not None and text.index(AUTOMATIC_SCAN_EXPIRY_PREFIX) < found.start()


def automatic_scan_expiry_controls(site):
    """Authored parser adversaries; these are not product execution."""
    value = dict.fromkeys(AUTOMATIC_SCAN_EXPIRY_FIELDS, True)
    def row(item):
        return (AUTOMATIC_SCAN_EXPIRY_PREFIX + ' ' + json.dumps(item) + '\n').encode()
    good = row(value)
    assert automatic_scan_expiry_probe(good) == value
    bad = [b'', good + good, good + b'\xff', b'PRIVATE ' + good,
           b' ' * 9 + good, good.replace(b'\n', b' PRIVATE\n'),
           row(dict(value, private_account_id='PRIVATE')),
           (AUTOMATIC_SCAN_EXPIRY_PREFIX + ' []\n').encode()]
    for key in sorted(value):
        bad.extend([row({name: item for name, item in value.items() if name != key}),
                    good.replace(b'{', ('{' + json.dumps(key) + ':true,').encode(), 1),
                    row(dict(value, **{key: 1}))])
    for raw in bad:
        try:
            automatic_scan_expiry_probe(raw)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError('automatic-scan-expiry-invalid-accepted')
    header = ("thread '" + AUTOMATIC_SCAN_EXPIRY_TEST + "' (7) panicked at "
              + AUTOMATIC_SCAN_EXPIRY_PATH + ':' + str(site['line']) + ':' + str(site['column'])
              + ':\n' + AUTOMATIC_SCAN_EXPIRY_MESSAGE + '\n').encode()
    red = dict(value, expired_scan_rejected=False)
    assert automatic_scan_expiry_failure(row(red) + header, site)
    invalid = [row(value) + header, row(red), header + row(red), row(red) + header + header,
               row(red) + header.replace(AUTOMATIC_SCAN_EXPIRY_TEST.encode(), b'PRIVATE'),
               row(red) + header.replace(AUTOMATIC_SCAN_EXPIRY_PATH.encode(), b'PRIVATE.rs'),
               row(red) + header.replace(AUTOMATIC_SCAN_EXPIRY_MESSAGE.encode(), b'PRIVATE'),
               row(red) + header.replace((':' + str(site['line']) + ':').encode(), b':0:'),
               row(red) + header.replace((':' + str(site['column']) + ':\n').encode(), b':0:\n')]
    invalid += [row(dict(red, **{key: False})) + header for key in AUTOMATIC_SCAN_EXPIRY_PREREQUISITES]
    assert all(not automatic_scan_expiry_failure(raw, site) for raw in invalid)
    return {'marker_positive': 1, 'marker_negative': len(bad), 'own_red_positive': 1,
            'own_red_negative': len(invalid), 'synthetic_metadata_only': True, 'product_bodies': 0}


CASES = {
    'sdk-private-missing-route': ('transport_nostr_adapter', 'sdk_client::tests::enrollment_acquisition_failed_private_route_sync_burns_freshness_until_valid_reissue', 'crates/transport-nostr-adapter/src/sdk_client.rs'),
    FAMILY_STABILITY_CASE: ('transport_nostr_adapter', 'sdk_client::tests::unrelated_family_sync_preserves_private_and_untouched_wire_ids', 'crates/transport-nostr-adapter/src/sdk_client.rs'),
    'sdk-scoped-reporting': ('transport_nostr_adapter', 'sdk_client::tests::selected_private_scoped_route_preserves_owed_report_and_reconnect_id', 'crates/transport-nostr-adapter/src/sdk_client.rs'),
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
PRIVATE_SEND_CASE = 'engine-private-send-admission'
PRIVATE_MAINTENANCE_ORDER_CASE = 'engine-private-maintenance-pending-order'
PRIVATE_MAINTENANCE_ORDER_MESSAGE = 'recovery must wait while genuine crypto owns publication'
CASES[PRIVATE_MAINTENANCE_ORDER_CASE] = ('cgka_engine',
    'device_group_genesis::tests::private_maintenance_recovery_preserves_a_real_pending_publish',
    'crates/cgka-engine/src/device_group_genesis.rs')
ENGINE_CASES.add(PRIVATE_MAINTENANCE_ORDER_CASE)


PRIVATE_MAINTENANCE_CASE = 'engine-private-maintenance-recovery'
PRIVATE_MAINTENANCE_TESTS = {
    'device_group_genesis::tests::private_group_retires_legacy_unapproved_queue_without_touching_ordinary_work':
        'crates/cgka-engine/src/device_group_genesis.rs',
    'device_group_genesis::tests::private_maintenance_recovery_preserves_a_real_pending_publish':
        'crates/cgka-engine/src/device_group_genesis.rs',
}
PRIVATE_MAINTENANCE_MESSAGE = 'unsupported private queue must retire without publication; remaining=1'
CASES[PRIVATE_MAINTENANCE_CASE] = ('cgka_engine', PRIVATE_MAINTENANCE_CASE,
    'crates/cgka-engine/src/device_group_genesis.rs')
ENGINE_CASES.add(PRIVATE_MAINTENANCE_CASE)


def private_maintenance_site():
    text = Path(CASES[PRIVATE_MAINTENANCE_CASE][2]).read_text()
    pattern = (r'assert!\(\s*result.is_ok\(\),\s*'
               r'"unsupported private queue must retire without publication; remaining=\{remaining\}"\s*,?\s*\);')
    found = list(re.finditer(pattern, text))
    if len(found) != 1:
        raise ValueError('private-maintenance-source-site')
    return {'line': text[:found[0].start()].count('\n') + 1,
            'column': found[0].start() - text.rfind('\n', 0, found[0].start())}


def private_maintenance_failure(raw, site):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    first = next(iter(PRIVATE_MAINTENANCE_TESTS))
    pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(first)
               + r"'(?: \([0-9]+\))? panicked at " + re.escape(PRIVATE_MAINTENANCE_TESTS[first])
               + ':' + str(site['line']) + ':' + str(site['column'])
               + r':[ \t]*\n(?:[ \t]*\n){0,2}[ \t]{0,8}'
               + re.escape(PRIVATE_MAINTENANCE_MESSAGE) + r'[ \t]*(?:\n|$)')
    return len(re.findall(pattern, text)) == 1


def private_maintenance_controls(site):
    names = list(PRIVATE_MAINTENANCE_TESTS)
    suite = {'binary-name': 'cgka_engine', 'kind': 'lib', 'testcases': {
        name: {'ignored': False, 'filter-match': {'status': 'matches'}} for name in names}}
    inventory = {'rust-suites': {'lib': suite}}
    assert selected_automatic_negotiation(inventory, PRIVATE_MAINTENANCE_TESTS, 'cgka-engine', 'cgka_engine')['selected_nonignored'] == 2
    def rows(outcomes):
        return (''.join(outcome + ' [ 0.001s] cgka-engine ' + name + '\n' for outcome, name in zip(outcomes, names))
                + 'Summary [ 0.01s] 2 tests run: ' + str(outcomes.count('PASS')) + ' passed, '
                + str(outcomes.count('FAIL')) + ' failed, 0 skipped\n').encode()
    for outcomes in [['PASS', 'PASS'], ['FAIL', 'FAIL'], ['FAIL', 'PASS']]:
        assert automatic_negotiation_runtime(rows(outcomes), PRIVATE_MAINTENANCE_TESTS, 'cgka-engine')['complete']
    bad = [b'', rows(['PASS', 'PASS']) + rows(['PASS', 'PASS']),
           rows(['PASS', 'PASS']).replace(names[1].encode(), names[0].encode()),
           rows(['PASS', 'PASS']).replace(b'2 tests run:', b'1 test run:'),
           rows(['PASS', 'PASS']).replace(b'2 passed', b'1 passed'),
           rows(['PASS', 'PASS']).replace(b'cgka-engine', b'PRIVATE', 1)]
    assert all(not automatic_negotiation_runtime(raw, PRIVATE_MAINTENANCE_TESTS, 'cgka-engine')['complete'] for raw in bad)
    header = ("thread '" + names[0] + "' (7) panicked at " + PRIVATE_MAINTENANCE_TESTS[names[0]]
              + ':' + str(site['line']) + ':' + str(site['column']) + ':\n' + PRIVATE_MAINTENANCE_MESSAGE + '\n').encode()
    assert private_maintenance_failure(header, site)
    own_bad = [b'', header + header, header.replace(b'remaining=1', b'remaining=0'),
               header.replace(names[0].encode(), b'PRIVATE'),
               header.replace(PRIVATE_MAINTENANCE_TESTS[names[0]].encode(), b'PRIVATE.rs'),
               header.replace((':' + str(site['line']) + ':').encode(), b':0:'),
               header.replace((':' + str(site['column']) + ':\n').encode(), b':0:\n')]
    assert all(not private_maintenance_failure(raw, site) for raw in own_bad)
    assert positive_configuration(PRIVATE_MAINTENANCE_CASE) == (ENGINE_FEATURES, 'ci', None)
    return {'inventory_positive': 1, 'runtime_positive': 3, 'runtime_negative': len(bad),
            'own_positive': 1, 'own_negative': len(own_bad), 'synthetic_metadata_only': True, 'product_bodies': 0}


PRIVATE_HYDRATION_CASE = 'engine-private-maintenance-hydration'
PRIVATE_HYDRATION_TESTS = {
    'device_group_genesis::tests::hydration_retires_legacy_private_maintenance_before_bootstrap_reads':
        'crates/cgka-engine/src/device_group_genesis.rs',
    'device_group_genesis::tests::hydration_preserves_private_maintenance_behind_durable_pending_crypto':
        'crates/cgka-engine/src/device_group_genesis.rs',
}
PRIVATE_HYDRATION_MESSAGE = 'unsupported private maintenance must retire during hydration, before network bootstrap'
PRIVATE_HYDRATION_PATTERN = (r'assert_eq!\(\s*private_queued,\s*0,\s*"'
    + re.escape(PRIVATE_HYDRATION_MESSAGE) + r'"\s*,?\s*\);')
CASES[PRIVATE_HYDRATION_CASE] = ('cgka_engine', PRIVATE_HYDRATION_CASE,
    'crates/cgka-engine/src/device_group_genesis.rs')
ENGINE_CASES.add(PRIVATE_HYDRATION_CASE)
PRIVATE_MAINTENANCE_COHORTS = {PRIVATE_MAINTENANCE_CASE, PRIVATE_HYDRATION_CASE}


def maintenance_tests_for(case):
    if case == PRIVATE_HYDRATION_CASE:
        return PRIVATE_HYDRATION_TESTS
    if case == PRIVATE_MAINTENANCE_CASE:
        return PRIVATE_MAINTENANCE_TESTS
    raise ValueError('closed-maintenance-cohort')


def private_hydration_site():
    text = Path(CASES[PRIVATE_HYDRATION_CASE][2]).read_text()
    found = list(re.finditer(PRIVATE_HYDRATION_PATTERN, text))
    if len(found) != 1:
        raise ValueError('private-hydration-source-site')
    return {'line': text[:found[0].start()].count('\n') + 1,
            'column': found[0].start() - text.rfind('\n', 0, found[0].start())}


def private_hydration_failure(raw, site):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    if text.count('panicked at ') != 1:
        return False
    first = next(iter(PRIVATE_HYDRATION_TESTS))
    pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(first)
        + r"'(?: \([0-9]+\))? panicked at " + re.escape(PRIVATE_HYDRATION_TESTS[first])
        + ':' + str(site['line']) + ':' + str(site['column'])
        + r':[ \t]*\n(?:[ \t]*\n){0,2}[ \t]{0,8}assertion `left == right` failed: '
        + re.escape(PRIVATE_HYDRATION_MESSAGE)
        + r'[ \t]*\n[ \t]{0,8}left: 1[ \t]*\n[ \t]{0,8}right: 0[ \t]*(?:\n|$)')
    return re.search(pattern, text) is not None


def private_hydration_runtime(raw, red):
    runtime = automatic_negotiation_runtime(raw, PRIVATE_HYDRATION_TESTS, 'cgka-engine')
    panics = automatic_negotiation_panics(raw, PRIVATE_HYDRATION_TESTS)
    names = list(PRIVATE_HYDRATION_TESTS)
    expected = {names[0]: 'FAIL' if red else 'PASS', names[1]: 'PASS'}
    wanted = {'executed': 2, 'passed': 1 if red else 2, 'failed': 1 if red else 0}
    actual = runtime['counts']
    accepted = (runtime['complete'] and actual is not None
        and {key: actual[key] for key in wanted} == wanted
        and type(actual['skipped']) is int and actual['skipped'] >= 0
        and runtime['runtime_summary'] == summary_counts(raw)
        and runtime['runtime_summary']['summary_count'] == 1
        and runtime['runtime_summary']['counts'] == actual
        and {row['test']: row['outcome'] for row in runtime['rows']} == expected
        and panics['unknown_or_excess_headers'] == 0
        and len(panics['sites']) == (1 if red else 0)
        and (not red or private_hydration_failure(raw, private_hydration_site())))
    return {'runtime': runtime, 'panics': panics, 'accepted': accepted}


def private_hydration_controls(site):
    names = list(PRIVATE_HYDRATION_TESTS)
    suite = {'binary-name': 'cgka_engine', 'kind': 'lib', 'testcases': {
        name: {'ignored': False, 'filter-match': {'status': 'matches'}} for name in names}}
    inventory = {'rust-suites': {'lib': suite}}
    assert selected_automatic_negotiation(inventory, PRIVATE_HYDRATION_TESTS, 'cgka-engine', 'cgka_engine')['selected_nonignored'] == 2
    assert set(names).isdisjoint(PRIVATE_MAINTENANCE_TESTS)
    bad_inventory = []
    for key, value in [('binary-name', 'PRIVATE'), ('kind', 'test')]:
        changed = json.loads(json.dumps(inventory)); changed['rust-suites']['lib'][key] = value; bad_inventory.append(changed)
    for key, value in [('ignored', True), ('ignored', 0), ('filter-match', {'status': 'mismatch'})]:
        changed = json.loads(json.dumps(inventory)); changed['rust-suites']['lib']['testcases'][names[0]][key] = value; bad_inventory.append(changed)
    changed = json.loads(json.dumps(inventory)); del changed['rust-suites']['lib']['testcases'][names[1]]; bad_inventory.append(changed)
    changed = json.loads(json.dumps(inventory)); changed['rust-suites']['duplicate'] = suite; bad_inventory.append(changed)
    for changed in bad_inventory:
        try:
            selected_automatic_negotiation(changed, PRIVATE_HYDRATION_TESTS, 'cgka-engine', 'cgka_engine')
        except ValueError:
            pass
        else:
            raise AssertionError('private-hydration-inventory-negative')
    def rows(outcomes, filtered=0):
        return (''.join(outcome + ' [ 0.001s] cgka-engine ' + name + '\n' for outcome, name in zip(outcomes, names))
            + 'Summary [ 0.01s] 2 tests run: ' + str(outcomes.count('PASS')) + ' passed, '
            + str(outcomes.count('FAIL')) + ' failed, ' + str(filtered) + ' skipped\n').encode()
    header = ("thread '" + names[0] + "' (7) panicked at " + PRIVATE_HYDRATION_TESTS[names[0]]
        + ':' + str(site['line']) + ':' + str(site['column'])
        + ':\nassertion `left == right` failed: ' + PRIVATE_HYDRATION_MESSAGE + '\n  left: 1\n right: 0\n').encode()
    assert private_hydration_failure(header, site)
    assert private_hydration_runtime(rows(['PASS', 'PASS']), False)['accepted']
    assert private_hydration_runtime(rows(['FAIL', 'PASS']) + header, True)['accepted']
    assert private_hydration_runtime(rows(['PASS', 'PASS'], 273), False)['accepted']
    assert private_hydration_runtime(rows(['FAIL', 'PASS'], 273) + header, True)['accepted']
    bad_own = [b'', header + header, header.replace(b'left: 1', b'left: 0'), header.replace(b'right: 0', b'right: 1'),
        header.replace(b'left: 1', b'left: 01'), header.replace(names[0].encode(), names[1].encode()),
        header.replace(PRIVATE_HYDRATION_TESTS[names[0]].encode(), b'PRIVATE.rs'),
        header.replace(PRIVATE_HYDRATION_MESSAGE.encode(), b'PRIVATE'),
        header.replace((':' + str(site['line']) + ':').encode(), b':0:'),
        header.replace((':' + str(site['column']) + ':\n').encode(), b':0:\n')]
    assert all(not private_hydration_failure(raw, site) for raw in bad_own)
    bad_runtime = [rows(['FAIL', 'FAIL']) + header, rows(['PASS', 'FAIL']) + header,
        rows(['FAIL', 'PASS']), rows(['PASS', 'PASS']) + header,
        rows(['FAIL', 'PASS']) + header + header,
        (rows(['FAIL', 'PASS']) + header).replace(b'2 tests run:', b'1 test run:'),
        (rows(['FAIL', 'PASS']) + header).replace(names[1].encode(), names[0].encode()),
        (rows(['FAIL', 'PASS'], 273) + header).replace(b'1 failed', b'0 failed'),
        (rows(['FAIL', 'PASS'], 273) + header).replace(b'1 passed', b'2 passed')]
    assert all(not private_hydration_runtime(raw, True)['accepted'] for raw in bad_runtime)
    assert positive_configuration(PRIVATE_HYDRATION_CASE) == (ENGINE_FEATURES, 'ci', None)
    return {'inventory_positive': 1, 'inventory_negative': len(bad_inventory), 'runtime_positive': 4,
        'runtime_negative': len(bad_runtime), 'own_positive': 1, 'own_negative': len(bad_own),
        'configuration_positive': 1, 'synthetic_metadata_only': True, 'product_bodies': 0}


PRIVATE_SEND_MESSAGE = 'generic private send must be rejected before queue admission; queued=1'
CASES[PRIVATE_SEND_CASE] = ('cgka_engine',
    'device_group_genesis::tests::private_group_generic_send_is_rejected_before_queue_admission',
    'crates/cgka-engine/src/device_group_genesis.rs')
ENGINE_CASES.add(PRIVATE_SEND_CASE)


def private_send_site():
    text = Path(CASES[PRIVATE_SEND_CASE][2]).read_text()
    pattern = (r'assert!\(\s*matches!\(result, Err\(cgka_traits::EngineError::InvalidTransition\(error\)\) if error.from == "PrivateDeviceGroup"\),'
               r'\s*"generic private send must be rejected before queue admission; queued=\{queued\}"\s*,?\s*\);')
    found = list(re.finditer(pattern, text))
    if len(found) != 1:
        raise ValueError('private-send-source-site')
    return {'line': text[:found[0].start()].count('\n') + 1,
            'column': found[0].start() - text.rfind('\n', 0, found[0].start())}


def private_send_failure(raw, site):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    if text.count('panicked at ') != 1:
        return False
    pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(CASES[PRIVATE_SEND_CASE][1])
               + r"'(?: \([0-9]+\))? panicked at " + re.escape(CASES[PRIVATE_SEND_CASE][2])
               + ':' + str(site['line']) + ':' + str(site['column'])
               + r':[ \t]*\n(?:[ \t]*\n){0,2}[ \t]{0,8}'
               + re.escape(PRIVATE_SEND_MESSAGE) + r'[ \t]*(?:\n|$)')
    return re.search(pattern, text) is not None


def private_send_controls(site):
    header = ("thread '" + CASES[PRIVATE_SEND_CASE][1] + "' (7) panicked at "
              + CASES[PRIVATE_SEND_CASE][2] + ':' + str(site['line']) + ':' + str(site['column'])
              + ':\n' + PRIVATE_SEND_MESSAGE + '\n').encode()
    assert private_send_failure(header, site)
    bad = [b'', header + header, header.replace(b'queued=1', b'queued=0'),
           header.replace(b'queued=1', b'queued=2'), header.replace(b'queued=1', b'queued=10'),
           header.replace(CASES[PRIVATE_SEND_CASE][1].encode(), b'PRIVATE'),
           header.replace(CASES[PRIVATE_SEND_CASE][2].encode(), b'PRIVATE.rs'),
           header.replace((':' + str(site['line']) + ':').encode(), b':0:'),
           header.replace((':' + str(site['column']) + ':\n').encode(), b':0:\n'),
           header.replace(PRIVATE_SEND_MESSAGE.encode(), b'PRIVATE')]
    assert all(not private_send_failure(raw, site) for raw in bad)
    assert positive_configuration(PRIVATE_SEND_CASE) == (ENGINE_FEATURES, 'ci', None)
    assert package_for(PRIVATE_SEND_CASE) == 'cgka-engine' and PRIVATE_SEND_CASE not in INTEGRATION_CASES
    return {'own_positive': 1, 'own_negative': len(bad), 'configuration_positive': 1,
            'synthetic_metadata_only': True, 'product_bodies': 0}


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
PENDING_REQUEST_CASE = 'pending-restart-request-observation'
CASES[PENDING_REQUEST_CASE] = ('marmot_app',
    'native_device_linking::tests::pending_lower_request_recovers_after_higher_restarts_before_consent',
    'crates/marmot-app/src/client/account_chat_sharing/automatic/tests/pending_restart_acceptance.rs')
EXPERIMENTAL_CASES.add(PENDING_REQUEST_CASE)
BOUNDED_CASES.add(PENDING_REQUEST_CASE)
QUIET_CONTRACT_CASE = 'adapter-quiet-pending-contract'
QUIET_DEFAULT_CASE = 'adapter-quiet-pending-contract-default'
QUIET_CONTRACT_CASES = {QUIET_CONTRACT_CASE, QUIET_DEFAULT_CASE}
CLAMPED_CASES = {'adapter-clamped', 'adapter-clamped-default'}
CASES[QUIET_CONTRACT_CASE] = ('relay_limit_subscriptions',
    'quiet_gap_does_not_finish_success_expected_native_replay',
    'crates/transport-nostr-adapter/tests/relay_limit_subscriptions.rs')
CASES[QUIET_DEFAULT_CASE] = CASES[QUIET_CONTRACT_CASE]
CASES['adapter-clamped-default'] = CASES['adapter-clamped']
for _quiet_cases in (ADAPTER_CASES, INTEGRATION_CASES, BOUNDED_CASES):
    _quiet_cases.update(QUIET_CONTRACT_CASES | {'adapter-clamped-default'})
EXPERIMENTAL_CASES.add(QUIET_CONTRACT_CASE)
SDK_REPLAY_CASES.add('adapter-clamped-default')



LIVE_SEAL_CASES = {'live-seal-spill-default', 'live-seal-spill-experimental'}
for _case in LIVE_SEAL_CASES:
    CASES[_case] = ('transport_nostr',
        'tests::deliveries_placed_after_a_live_seal_spill_what_only_that_promotion_stopped_covering',
        'crates/transport-nostr/src/tests.rs')
EXPERIMENTAL_CASES.add('live-seal-spill-experimental')
BOUNDED_CASES.add('live-seal-spill-experimental')
for _scoped_reporting_set in (ADAPTER_CASES, EXPERIMENTAL_CASES, BOUNDED_CASES):
    _scoped_reporting_set.add('sdk-scoped-reporting')
    _scoped_reporting_set.add(FAMILY_STABILITY_CASE)
    _scoped_reporting_set.add('sdk-private-missing-route')



for _private_role_case, _private_role_spec in PRIVATE_ROLE_CASES.items():
    CASES[_private_role_case] = ('transport_nostr_adapter',
        'sdk_client::tests::' + _private_role_spec['test'],
        'crates/transport-nostr-adapter/src/sdk_client.rs')
    ADAPTER_CASES.add(_private_role_case)
    EXPERIMENTAL_CASES.add(_private_role_case)
    BOUNDED_CASES.add(_private_role_case)


FAMILY_PFP_CASES = {'sdk-private-family-refresh-pfp', 'sdk-private-family-ordinary-pfp'}
for _family_pfp_case in FAMILY_PFP_CASES:
    CASES[_family_pfp_case] = CASES[FAMILY_STABILITY_CASE]
    ADAPTER_CASES.add(_family_pfp_case)
    EXPERIMENTAL_CASES.add(_family_pfp_case)
    BOUNDED_CASES.add(_family_pfp_case)


CASES[AUTOMATIC_NEGOTIATION_CASE] = ('marmot_app', AUTOMATIC_NEGOTIATION_CASE,
    'crates/marmot-app/src/native_device_linking/enabled/negotiated.rs')
CASES[FOUR_DEVICE_MUTATIONS_CASE] = ('marmot_app',
    'native_device_linking::automatic_pairing_acceptance::approved_four_device_messages_edits_and_deletions_converge',
    'crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs')
CASES[MUTATION_ADMISSION_CASE] = ('marmot_app', MUTATION_ADMISSION_TEST, MUTATION_ADMISSION_PATH)
for automatic_case in AUTOMATIC_SCAN_EXPIRY_CASES:
    CASES[automatic_case] = ('marmot_app', AUTOMATIC_SCAN_EXPIRY_TEST, AUTOMATIC_SCAN_EXPIRY_PATH)
EXPERIMENTAL_CASES |= AUTOMATIC_NATIVE_CASES
BOUNDED_CASES |= AUTOMATIC_NATIVE_CASES


CASES[WATCH_CLEANUP_CASE] = ('marmot_app', WATCH_CLEANUP_TEST, WATCH_CLEANUP_PATH)
CASES[WATCH_HELD_CASE] = ('marmot_app', WATCH_HELD_TEST, WATCH_CLEANUP_PATH)
CASES[SQLITE_CACHE_CASE] = ('storage_sqlite', SQLITE_CACHE_TEST, SQLITE_CACHE_PATH)


def package_for(case):
    if case == SQLITE_CACHE_CASE:
        return 'storage-sqlite'
    if case in LIVE_SEAL_CASES:
        return 'transport-nostr'
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



PENDING_APPROVAL_MESSAGE = 'actual higher Core approval of X before any Consent publication'
PENDING_INNER_THREAD = 'pending-real-lower-request'


def pending_request_stage(stage):
    if stage != 'positive':
        raise ValueError('pending-request-positive-only')


def pending_request_marker(raw):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict'))
    namespace = 'pending-restart-request-dispatch'
    if len(raw) > 16 * 1024 * 1024 or text.count(namespace) != 1:
        raise ValueError('pending-request-namespace')
    found = re.findall(r'(?m)^[ \t]{0,8}' + namespace + r' (\{[^\r\n]*\})[ \t]{0,8}\r?$', text)
    lines = [line for line in text.splitlines() if namespace in line]
    if len(found) != 1 or len(lines) != 1 or len(lines[0].encode('utf-8')) > 8192:
        raise ValueError('pending-request-envelope')
    value = json.loads(found[0], object_pairs_hook=unique)
    keys = {'capture_available', 'higher_present_before_tick', 'higher_matches_x_before_tick', 'counts', 'overflow'}
    if (type(value) is not dict or set(value) != keys
            or any(type(value[key]) is not bool for key in ('capture_available', 'higher_present_before_tick'))
            or value['higher_matches_x_before_tick'] is not None and type(value['higher_matches_x_before_tick']) is not bool
            or (value['higher_matches_x_before_tick'] is not None) != value['higher_present_before_tick']):
        raise ValueError('pending-request-types')
    counts_value, overflow = value['counts'], value['overflow']
    if counts_value is None:
        if overflow is not None:
            raise ValueError('pending-request-unavailable')
    elif (not value['capture_available'] or type(counts_value) is not list or len(counts_value) != 10
            or any(type(item) is not int or not 0 <= item <= 64 for item in counts_value)
            or sum(counts_value) > 64 or type(overflow) is not bool):
        raise ValueError('pending-request-counter-cap')
    return value


def pending_request_sites():
    fixture = Path(CASES[PENDING_REQUEST_CASE][2]).read_text()
    matches = list(re.finditer(r'approval\s*\.\s*(?P<callee>expect)\(\s*"'
        + re.escape(PENDING_APPROVAL_MESSAGE) + r'"\s*,?\s*\)', fixture))
    native = Path('crates/marmot-app/src/native_device_linking/tests.rs').read_text()
    body = re.search(r'fn ' + re.escape(CASES[PENDING_REQUEST_CASE][1].split('::')[-1]) + r'\(\)\s*\{([^}]+)\}', native)
    if (len(matches) != 1 or body is None or not re.search(r'run_composed_app_runtime_test\(\s*"'
            + re.escape(PENDING_INNER_THREAD) + r'"\s*,', body[1])):
        raise ValueError('pending-request-original-composed-source')
    helper = Path('crates/marmot-app/src/tests.rs').read_text()
    wrapper_start = helper.index('fn run_composed_app_runtime<F, Fut>(')
    wrapper_end = helper.index('\n#[test]', wrapper_start)
    wrapper_body = helper[wrapper_start:wrapper_end]
    wrapper = list(re.finditer(r'test_thread\.join\(\)\.(?P<callee>unwrap)\(\);', helper))
    if (len(wrapper) != 1 or not wrapper_start <= wrapper[0].start() < wrapper_end
            or '.name(thread_name.to_owned())' not in wrapper_body or 'test_runtime.block_on(body());' not in wrapper_body):
        raise ValueError('pending-request-composed-join-source')
    site = lambda text, match: {'line': text[:match.start('callee')].count('\n') + 1,
        'column': match.start('callee') - text.rfind('\n', 0, match.start('callee'))}
    return {'approval': site(fixture, matches[0]), 'join': site(helper, wrapper[0])}


def pending_request_panics(raw, sites):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict'))
    expected = [('approval', PENDING_INNER_THREAD, CASES[PENDING_REQUEST_CASE][2],
        PENDING_APPROVAL_MESSAGE + ': Elapsed(())'),
        ('join', CASES[PENDING_REQUEST_CASE][1], 'crates/marmot-app/src/tests.rs', CURSOR_JOIN_MESSAGE)]
    spans, known = [], []
    for label, thread, path, message in expected:
        location = sites[label]
        pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(thread) + r"'(?: \([0-9]+\))? panicked at "
            + re.escape(path) + ':' + str(location['line']) + ':' + str(location['column'])
            + r':[ \t]*\r?\n(?:[ \t]*\r?\n){0,2}[ \t]{0,8}' + re.escape(message) + r'[ \t]*(?:\r?\n|$)')
        found = list(re.finditer(pattern, text))
        if len(found) == 1:
            spans.append(found[0].start())
            known.append({'source': label, 'line': location['line'], 'column': location['column']})
    count = text.count('panicked at ')
    return {'header_count': count, 'known_sites': known,
        'ordered_exact_approval_timeout_and_join': count == 2 and len(spans) == 2 and spans[0] < spans[1],
        'unknown_or_excess_headers': max(0, count - len(known))}


def pending_request_controls(sites):
    case = PENDING_REQUEST_CASE
    row = dict(capture_available=True, higher_present_before_tick=True, higher_matches_x_before_tick=False,
               counts=[1,1,0,0,1,1,1,0,1,1], overflow=False)
    encode = lambda value: ('pending-restart-request-dispatch ' + json.dumps(value) + '\n').encode()
    raw = encode(row)
    good = [raw, b' '*4 + raw, b' '*8 + raw, raw.replace(b'\n', b'\r\n')]
    for data in good:
        assert pending_request_marker(data) == row
    for value in [dict(row, capture_available=False, counts=None, overflow=None),
                  dict(row, counts=None, overflow=None), dict(row, higher_present_before_tick=False, higher_matches_x_before_tick=None),
                  dict(row, counts=[0]*10, overflow=True)]:
        assert pending_request_marker(encode(value)) == value
    bad = [dict(row, private='PRIVATE'), dict(row, capture_available=1), dict(row, higher_matches_x_before_tick=0),
        dict(row, counts='PRIVATE'), dict(row, higher_matches_x_before_tick='PRIVATE'),
        dict(row, higher_present_before_tick=False), dict(row, counts=[1]*9), dict(row, counts=[True]*10),
        dict(row, counts=[-1]*10), dict(row, counts=[65]+[0]*9), dict(row, counts=[64]*10),
        dict(row, counts=None), dict(row, overflow=0), dict(row, capture_available=False),
        {key: value for key, value in row.items() if key != 'overflow'}]
    invalid = [encode(value) for value in bad] + [raw+raw, b'PRIVATE '+raw, b' '*9+raw,
        raw+b'pending-restart-request-dispatch-PRIVATE\n', b'\xff'+raw,
        raw.replace(b'"capture_available": true', b'"capture_available": true, "capture_available": true')]
    for data in invalid:
        try:
            pending_request_marker(data)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError('pending-request-negative-accepted')
    def header(thread, path, location):
        return ("thread '" + thread + "' (7) panicked at " + path + ':' + str(location['line'])
            + ':' + str(location['column']) + ':\n')
    inner = header(PENDING_INNER_THREAD, CASES[case][2], sites['approval']) + PENDING_APPROVAL_MESSAGE + ': Elapsed(())\n'
    outer = header(CASES[case][1], 'crates/marmot-app/src/tests.rs', sites['join']) + CURSOR_JOIN_MESSAGE + '\n'
    both = (inner+outer).encode()
    assert pending_request_panics(both, sites)['ordered_exact_approval_timeout_and_join']
    assert pending_request_panics(both.replace(b"' (7)", b"'"), sites)['ordered_exact_approval_timeout_and_join']
    denied = [(outer+inner).encode(), inner.encode(), outer.encode(), both+inner.encode(),
        both.replace(PENDING_INNER_THREAD.encode(), b'PRIVATE'), both.replace(PENDING_APPROVAL_MESSAGE.encode(), b'PRIVATE'),
        both.replace(b'Elapsed(())', b'PRIVATE'), b'PRIVATE '+both,
        both.replace((':' + str(sites['approval']['line']) + ':').encode(), b':999999:', 1)]
    assert all(not pending_request_panics(data, sites)['ordered_exact_approval_timeout_and_join'] for data in denied)
    assert positive_configuration(case) == (LIB_FEATURES + ['marmot-app/experimental-device-sync'], 'm5-bounded', '4194304')
    assert case not in PFP and case not in INTEGRATION_CASES
    for stage in ('pfp', 'sample'):
        try:
            pending_request_stage(stage)
        except ValueError:
            pass
        else:
            raise AssertionError('pending-request-stage-negative')
    return {'positive': len(good) + 4, 'negative': len(invalid) + len(denied) + 2,
        'panic_positive': 2, 'configuration_controls': 2, 'product_bodies': 0, 'synthetic_metadata_only': True}


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
    assert sdk_replay_marker(both,'adapter-clamped-default',True) == [first,second]
    assert CASES['adapter-clamped-default'] == CASES['adapter-clamped']
    assert positive_configuration('adapter-clamped-default') == (['sdk','test-policy-overrides'], 'm5-bounded', '4194304')
    assert 'adapter-clamped-default' not in EXPERIMENTAL_CASES and 'adapter-clamped-default' not in PFP
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
    return {'positive':11, 'negative':len(invalid)+len(scoped), 'synthetic_metadata_only':True, 'product_bodies':0}



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
    assert positive_configuration('sdk-scoped-reporting') == (['sdk', 'experimental-device-sync', 'test-policy-overrides'], 'm5-bounded', '4194304')
    assert package_for('sdk-scoped-reporting') == 'transport-nostr-adapter' and 'sdk-scoped-reporting' not in INTEGRATION_CASES
    for role_case in PRIVATE_ROLE_CASES:
        assert positive_configuration(role_case) == (['sdk', 'experimental-device-sync', 'test-policy-overrides'], 'm5-bounded', '4194304')
        assert package_for(role_case) == 'transport-nostr-adapter' and role_case not in INTEGRATION_CASES
        assert role_case in ADAPTER_CASES & EXPERIMENTAL_CASES & BOUNDED_CASES

    for case in AUTOMATIC_NATIVE_CASES:
        assert positive_configuration(case) == (LIB_FEATURES + ['marmot-app/experimental-device-sync'], 'm5-bounded', '4194304')
        assert package_for(case) == 'marmot-app' and case not in INTEGRATION_CASES | ADAPTER_CASES
    assert positive_configuration(PRIVATE_HYDRATION_CASE) == (ENGINE_FEATURES, 'ci', None)
    assert len(PRIVATE_HYDRATION_TESTS) == 2 and set(PRIVATE_HYDRATION_TESTS).isdisjoint(PRIVATE_MAINTENANCE_TESTS)
    return {'positive': 21 + len(AUTOMATIC_NATIVE_CASES), 'synthetic_metadata_only': True, 'product_bodies': 0}


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

QUIET_GREEN_CALL = '    collect_authoritative_replay(adapter, account, expected, deadline, recorded).await'
QUIET_OLD_CALL = '    { let _ = collect_authoritative_replay; let _ = (account, expected, recorded); distinct_deliveries(adapter, deadline.saturating_duration_since(tokio::time::Instant::now())).await }'
for _quiet_case in QUIET_CONTRACT_CASES:
    PFP[_quiet_case] = (CASES[_quiet_case][2], QUIET_GREEN_CALL, QUIET_OLD_CALL,
        'quiet delivery gap must not finish success-expected replay while its actual source is pending',
        r'assert!\(\s*complete_at_return,\s*"{message}"\s*,?\s*\);')


FAMILY_PFP_LITERALS = {'sdk-private-family-refresh-pfp': {'green': '    let account_id = &sync.account_id;\n    // The live families, and the one that carries each live route.\n    let mut live = HashMap::<RepackFamily, Vec<NostrSubscription>>::new();\n', 'inverse': '    let refresh_private = refresh_private || selected_private.is_some(); let account_id = &sync.account_id;\n    // The live families, and the one that carries each live route.\n    let mut live = HashMap::<RepackFamily, Vec<NostrSubscription>>::new();\n', 'mutant_verdicts': {'private_actual_unchanged': False, 'untouched_family_wire_unchanged': True, 'original_private_wire_current': False}}, 'sdk-private-family-ordinary-pfp': {'green': '    let mut dirty = wanted\n        .iter()\n        .filter(|(_, _, _, _, always)| *always)\n        .filter_map(|(_, carrier, _, _, _)| carrier.clone())\n        .chain(\n            removed\n                .iter()\n                .chain(added.values())\n                .filter_map(|route| carried_by.get(&route.route_key()).cloned()),\n        )\n        .collect::<HashSet<_>>();\n', 'inverse': '    let mut dirty = wanted\n        .iter()\n        .filter(|(_, _, _, _, always)| *always)\n        .filter_map(|(_, carrier, _, _, _)| carrier.clone())\n        .chain(\n            removed\n                .iter()\n                .chain(added.values())\n                .filter_map(|route| carried_by.get(&route.route_key()).cloned()),\n        )\n        .collect::<HashSet<_>>(); dirty.extend(live_order.iter().filter(|family| !family.is_private()).cloned());\n', 'mutant_verdicts': {'private_actual_unchanged': True, 'untouched_family_wire_unchanged': False, 'original_private_wire_current': True}}}
FAMILY_PFP_PATTERN = (r'assert!\(\s*private_actual_unchanged\s*&&\s*untouched_family_wire_unchanged'
    r'\s*&&\s*original_private_wire_current,\s*"{message}"\s*\);')
for _family_case, _family_spec in FAMILY_PFP_LITERALS.items():
    PFP[_family_case] = ('crates/transport-nostr-adapter/src/lib.rs',
        _family_spec['green'], _family_spec['inverse'], FAMILY_STABILITY_MESSAGE, FAMILY_PFP_PATTERN)


def validate_family_pfp_inverse(text, case, old, new):
    owner = 'fn plan_scoped_family_repacks('
    boundary = '\n#[cfg(feature = "experimental-device-sync")]\nfn issued_group_wire_ids('
    spec = FAMILY_PFP_LITERALS[case]
    if text.count(owner) != 1 or text.count(boundary) != 1:
        raise ValueError('family-pfp-owner-cardinality')
    start = text.index(owner)
    end = text.index(boundary, start)
    if (old != spec['green'] or new != spec['inverse'] or text.count(old) != 1
            or old not in text[start:end] or old.count('\n') != new.count('\n')):
        raise ValueError('family-pfp-inverse-owner')


def family_pfp_ready(value, case, mutant=False):
    expected = (FAMILY_PFP_LITERALS[case]['mutant_verdicts'] if mutant
                else dict.fromkeys(FAMILY_STABILITY_VERDICTS, True))
    return (type(value) is dict
            and set(value) == FAMILY_STABILITY_PREREQUISITES | FAMILY_STABILITY_VERDICTS
            and all(type(item) is bool for item in value.values())
            and all(value[key] is True for key in FAMILY_STABILITY_PREREQUISITES)
            and all(value[key] is expected[key] for key in FAMILY_STABILITY_VERDICTS))


def family_pfp_failure(raw, case, site):
    return (family_stability_failure(raw, site)
            and family_pfp_ready(family_stability_probe(raw), case, mutant=True))


def family_pfp_controls(case, site):
    probe_controls = family_stability_controls(site)
    value = dict.fromkeys(FAMILY_STABILITY_PREREQUISITES | FAMILY_STABILITY_VERDICTS, True)
    mutant = dict(value, **FAMILY_PFP_LITERALS[case]['mutant_verdicts'])
    def row(item):
        return (FAMILY_STABILITY_PREFIX + ' ' + json.dumps(item) + '\n').encode()
    header = ("thread '" + CASES[case][1] + "' (7) panicked at " + CASES[case][2]
        + ':' + str(site['line']) + ':' + str(site['column']) + ':\n'
        + FAMILY_STABILITY_MESSAGE + '\n').encode()
    valid = row(mutant) + header
    positives = [valid, valid.replace(b"' (7)", b"'"), valid.replace(b'\n', b'\r\n'), b' '*8 + valid]
    assert all(family_pfp_failure(raw, case, site) for raw in positives)
    keys = sorted(FAMILY_STABILITY_VERDICTS)
    vector_controls = 0
    for ordinal in range(8):
        vector = {key: bool(ordinal & (1 << index)) for index, key in enumerate(keys)}
        observation = dict(value, **vector)
        expected_control = all(vector.values())
        expected_mutant = vector == FAMILY_PFP_LITERALS[case]['mutant_verdicts']
        assert family_pfp_ready(observation, case) is expected_control
        assert family_pfp_ready(observation, case, mutant=True) is expected_mutant
        assert family_pfp_failure(row(observation) + header, case, site) is expected_mutant
        vector_controls += 3
    invalid = [row(dict(mutant, **{key: False})) + header for key in FAMILY_STABILITY_PREREQUISITES]
    invalid += [valid + header, header + row(mutant),
        valid.replace(CASES[case][1].encode(), b'PRIVATE'),
        valid.replace(CASES[case][2].encode(), b'PRIVATE.rs'),
        valid.replace((':' + str(site['line']) + ':').encode(), b':999999:'),
        valid.replace((':' + str(site['column']) + ':').encode(), b':999999:'),
        valid.replace(FAMILY_STABILITY_MESSAGE.encode(), b'PRIVATE'),
        row(mutant) + b'PRIVATE ' + header]
    assert all(not family_pfp_failure(raw, case, site) for raw in invalid)
    spec = FAMILY_PFP_LITERALS[case]
    product = Path(PFP[case][0]).read_text()
    validate_family_pfp_inverse(product, case, spec['green'], spec['inverse'])
    bad_owners = [product.replace('fn plan_scoped_family_repacks(', 'fn PRIVATE(', 1),
        spec['green'] + product.replace(spec['green'], '', 1),
        product + '\nfn plan_scoped_family_repacks(', product + spec['green'],
        product.replace('fn issued_group_wire_ids(', 'fn PRIVATE(', 1)]
    for changed in bad_owners:
        try:
            validate_family_pfp_inverse(changed, case, spec['green'], spec['inverse'])
        except ValueError:
            pass
        else:
            raise AssertionError('family-pfp-owner-negative')
    bad_inverses = [spec['green'], spec['inverse'] + '\n',
        FAMILY_PFP_LITERALS[next(key for key in FAMILY_PFP_CASES if key != case)]['inverse']]
    for changed in bad_inverses:
        try:
            validate_family_pfp_inverse(product, case, spec['green'], changed)
        except ValueError:
            pass
        else:
            raise AssertionError('family-pfp-inverse-negative')
    assert pfp_configuration(case) == positive_configuration(case)
    return {'positive': len(positives), 'negative': len(invalid) + len(bad_owners) + len(bad_inverses),
        'verdict_vector_controls': vector_controls, 'configuration_controls': 1,
        'probe_controls': probe_controls, 'synthetic_metadata_only': True, 'product_bodies': 0}


PRIVATE_ROLE_PFP_LITERALS = {
    'sdk-private-family-partial': {
        'owner': '    fn commit_group_sync(',
        'boundary': "    /// Add a repack's batches",
        'green': '        #[cfg(feature = "experimental-device-sync")]\n        {\n            account.group_wire_ids = issued_group_wire_ids(&account.batches);\n        }\n',
        'inverse': '        #[cfg(feature = "experimental-device-sync")]\n        {\n            account.group_wire_ids = issued_group_wire_ids(&account.batches[account.batches.len().saturating_sub(1)..]);\n        }\n',
        'message': 'a failed ordinary family must preserve private and independently committed healthy carriers through retry',
        'pattern': 'assert!\\(\\s*healthy_committed\\s*&&\\s*healthy_registered\\s*&&\\s*healthy_native_eose\\s*&&\\s*failed_family_retained\\s*&&\\s*private_partial_unchanged\\s*&&\\s*retry_keeps_successful_carriers\\s*&&\\s*retried_family_committed\\s*&&\\s*old_b_absent_from_retry_instance,\\s*"{message}"\\s*,?\\s*\\);',
        'false_verdicts': {'retry_keeps_successful_carriers', 'failed_family_retained'},
    },
    'sdk-private-role-transition': {
        'owner': 'fn issued_group_wire_ids(',
        'boundary': '/// Pack per-route group REQs into batches',
        'green': 'fn issued_group_wire_ids(\n    batches: &[NostrSubscription],\n) -> HashMap<NostrSubscriptionRouteKey, String> {\n    let mut ids = HashMap::new();\n    for batch in batches {\n        let id = batch.subscription_id();\n        // Standalone carriers are private even when a failed selection\n        // leaves their predecessor authoritative. Never expose their\n        // logical id through ordinary capture fallback. The selected\n        // private route resolves only its exact scoped actual above.\n        if let NostrSubscription::GroupBatch {\n            account_id,\n            routes,\n            endpoints,\n            ..\n        } = batch\n        {\n            let endpoints = normalized_endpoints(endpoints);\n            for route in routes {\n                ids.insert(\n                    NostrSubscriptionRouteKey::Group {\n                        account_id: account_id.clone(),\n                        group_id: route.group_id.clone(),\n                        transport_group_id: route.transport_group_id.clone(),\n                        endpoints: endpoints.clone(),\n                    },\n                    id.clone(),\n                );\n            }\n        }\n    }\n    ids\n}\n',
        'inverse': 'fn issued_group_wire_ids(\n    batches: &[NostrSubscription],\n) -> HashMap<NostrSubscriptionRouteKey, String> {\n    let mut ids = HashMap::new();\n    for batch in batches {\n        let id = batch.subscription_id();\n        // Standalone carriers are private even when a failed selection\n        // leaves their predecessor authoritative. Never expose their\n        // logical id through ordinary capture fallback. The selected\n        // private route resolves only its exact scoped actual above.\n        if let NostrSubscription::GroupBatch {\n            account_id,\n            routes,\n            endpoints,\n            ..\n        } = batch\n        {\n            let endpoints = normalized_endpoints(endpoints);\n            for route in routes {\n                ids.insert(\n                    NostrSubscriptionRouteKey::Group {\n                        account_id: account_id.clone(),\n                        group_id: route.group_id.clone(),\n                        transport_group_id: route.transport_group_id.clone(),\n                        endpoints: endpoints.clone(),\n                    },\n                    id.clone(),\n                );\n            }\n        } else if matches!(batch, NostrSubscription::Group { .. }) { ids.insert(batch.route_key(), id); }\n    }\n    ids\n}\n',
        'message': 'failed private roles stay negative and become ordinary only through their own committed batch',
        'pattern': 'assert!\\(\\s*prior_negative\\s*&&\\s*successor_negative\\s*&&\\s*prior_ordinary_is_new_batch\\s*&&\\s*healthy_unchanged\\s*&&\\s*healthy_after_demotion\\s*&&\\s*demotion_has_no_standalone\\s*&&\\s*demotion_uses_new_batch\\s*&&\\s*replacement_actual_closed,\\s*"{message}"\\s*,?\\s*\\);',
        'false_verdicts': {'prior_negative'},
    },
    'sdk-private-configuration-aba': {
        'owner': '    async fn prepare_private_observation_wire(',
        'boundary': '    async fn finish_private_observation_wire(',
        'green': '        if current.actual != replacement.actual || current.selection_revoked {\n',
        'inverse': '        if current.actual != replacement.actual {\n',
        'message': 'configuration ABA must not reauthorise the private replacement prepared before revocation',
        'pattern': 'assert!\\(\\s*sync_rejected\\s*&&\\s*preparation_not_reauthorised\\s*&&\\s*successor_not_registered,\\s*"{message}"\\s*,?\\s*\\);',
        'false_verdicts': {'sync_rejected', 'preparation_not_reauthorised', 'successor_not_registered'},
    },
}
PRIVATE_ROLE_PFP_CASES = set(PRIVATE_ROLE_PFP_LITERALS)
for _role_pfp_case, _role_pfp_spec in PRIVATE_ROLE_PFP_LITERALS.items():
    PFP[_role_pfp_case] = ('crates/transport-nostr-adapter/src/lib.rs',
        _role_pfp_spec['green'], _role_pfp_spec['inverse'],
        _role_pfp_spec['message'], _role_pfp_spec['pattern'])


def validate_private_role_pfp_inverse(text, case, old, new):
    spec = PRIVATE_ROLE_PFP_LITERALS[case]
    if text.count(spec['owner']) != 1 or text.count(spec['boundary']) != 1:
        raise ValueError('role-pfp-owner-cardinality')
    start = text.index(spec['owner'])
    end = text.index(spec['boundary'], start)
    if (old != spec['green'] or new != spec['inverse'] or text.count(old) != 1
            or old not in text[start:end] or old.count('\n') != new.count('\n')):
        raise ValueError('role-pfp-inverse-owner')


def private_role_pfp_ready(value, case, mutant=False):
    spec = PRIVATE_ROLE_CASES[case]
    false_verdicts = PRIVATE_ROLE_PFP_LITERALS[case]['false_verdicts'] if mutant else set()
    return (type(value) is dict and set(value) == spec['prerequisites'] | spec['verdicts']
        and all(type(item) is bool for item in value.values())
        and all(value[key] is True for key in spec['prerequisites'])
        and all(value[key] is (key not in false_verdicts) for key in spec['verdicts']))


def private_role_pfp_failure(raw, case, site):
    try:
        value = private_role_probe(raw, case)
        text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    except (ValueError, UnicodeError):
        return False
    if not private_role_pfp_ready(value, case, mutant=True) or text.count('panicked at ') != 1:
        return False
    if case == PRIVATE_ABA_CASE:
        return private_aba_failure(raw, site)
    pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(CASES[case][1])
        + r"'(?: \([0-9]+\))? panicked at " + re.escape(CASES[case][2])
        + ':' + str(site['line']) + ':' + str(site['column'])
        + r':[ \t]*\n(?:[ \t]*\n){0,2}[ \t]{0,8}' + re.escape(PFP[case][3])
        + r'[ \t]*(?:\n|$)')
    found = re.search(pattern, text)
    return found is not None and text.index(PRIVATE_ROLE_CASES[case]['prefix']) < found.start()


def private_role_pfp_controls(case, site):
    spec = PRIVATE_ROLE_CASES[case]
    literal = PRIVATE_ROLE_PFP_LITERALS[case]
    probe_controls = private_role_controls(case)
    green = dict.fromkeys(spec['prerequisites'] | spec['verdicts'], True)
    mutant = dict(green, **dict.fromkeys(literal['false_verdicts'], False))
    def row(item):
        return (spec['prefix'] + ' ' + json.dumps(item) + '\n').encode()
    header = ("thread '" + CASES[case][1] + "' (7) panicked at " + CASES[case][2]
        + ':' + str(site['line']) + ':' + str(site['column']) + ':\n' + PFP[case][3] + '\n').encode()
    valid = row(mutant) + header
    positives = [valid, valid.replace(b"' (7)", b"'"), valid.replace(b'\n', b'\r\n'), b' '*8 + valid]
    assert all(private_role_pfp_failure(raw, case, site) for raw in positives)
    invalid = [row(green) + header, valid + header, header + row(mutant), row(mutant),
        row(mutant) + header.replace(PFP[case][3].encode(), b'PRIVATE'),
        row(mutant) + header.replace(CASES[case][1].encode(), b'PRIVATE'),
        row(mutant) + header.replace(CASES[case][2].encode(), b'PRIVATE.rs'),
        row(mutant) + header.replace((':' + str(site['line']) + ':').encode(), b':999999:'),
        row(mutant) + header.replace((':' + str(site['column']) + ':\n').encode(), b':999999:\n'),
        valid + b"thread 'PRIVATE' panicked at PRIVATE.rs:1:2:\n"]
    vectors = []
    for key in sorted(green):
        vectors.append(dict(mutant, **{key: not mutant[key]}))
    assert all(not private_role_pfp_failure(row(value) + header, case, site) for value in vectors)
    assert private_role_pfp_ready(green, case) and not private_role_pfp_ready(green, case, mutant=True)
    assert private_role_pfp_ready(mutant, case, mutant=True) and not private_role_pfp_ready(mutant, case)
    assert all(not private_role_pfp_failure(raw, case, site) for raw in invalid)
    product = Path(PFP[case][0]).read_text()
    validate_private_role_pfp_inverse(product, case, literal['green'], literal['inverse'])
    bad_owners = [product.replace(literal['owner'], 'PRIVATE'),
        product.replace(literal['boundary'], 'PRIVATE'), product + literal['green'],
        product.replace(literal['green'], '') + literal['green']]
    for changed in bad_owners:
        try:
            validate_private_role_pfp_inverse(changed, case, literal['green'], literal['inverse'])
        except ValueError:
            pass
        else:
            raise AssertionError('role-pfp-owner-negative')
    bad_inverses = [literal['green'], literal['inverse'] + '\n',
        literal['inverse'].replace('\n', '\n\n', 1)]
    bad_inverses += [other['inverse'] for key, other in PRIVATE_ROLE_PFP_LITERALS.items() if key != case]
    for changed in bad_inverses:
        try:
            validate_private_role_pfp_inverse(product, case, literal['green'], changed)
        except ValueError:
            pass
        else:
            raise AssertionError('role-pfp-inverse-negative')
    assert pfp_configuration(case) == positive_configuration(case)
    return {'positive': len(positives), 'negative': len(invalid) + len(bad_owners) + len(bad_inverses),
        'verdict_vector_controls': len(vectors), 'configuration_controls': 1,
        'probe_controls': probe_controls, 'synthetic_metadata_only': True, 'product_bodies': 0}


PRIVATE_MAINTENANCE_PRODUCT = 'crates/cgka-engine/src/message_processor/mod.rs'
PRIVATE_MAINTENANCE_GREEN = '        // Older builds could retain an ordinary SelfUpdate that this private\n        // group can never authorize. Retire only unexposed maintenance work;\n        // normal convergence still owns every actual crypto/input transition.\n        #[cfg(feature = "experimental-device-sync")]\n        self.retire_queued_private_maintenance(group_id)?;\n'
PRIVATE_MAINTENANCE_INVERSE = PRIVATE_MAINTENANCE_GREEN.replace(
    '        self.retire_queued_private_maintenance(group_id)?;\n',
    '        if false { self.retire_queued_private_maintenance(group_id)?; }\n')
PFP[PRIVATE_MAINTENANCE_CASE] = (
    PRIVATE_MAINTENANCE_PRODUCT, PRIVATE_MAINTENANCE_GREEN, PRIVATE_MAINTENANCE_INVERSE,
    PRIVATE_MAINTENANCE_MESSAGE,
    r'assert!\(\s*result.is_ok\(\),\s*'
    r'"unsupported private queue must retire without publication; remaining=\{remaining\}"\s*,?\s*\);')


def validate_private_maintenance_inverse(text, old, new):
    owner = '    fn prepare_convergence_input_advance('
    if text.count(owner) != 1:
        raise ValueError('private-maintenance-inverse-owner')
    start = text.index(owner)
    end = text.index('    async fn run_drain_maintenance(', start)
    gate = '        if let Some(state) = self.epoch_manager.state(group_id)'
    if (old != PRIVATE_MAINTENANCE_GREEN or new != PRIVATE_MAINTENANCE_INVERSE
            or text.count(old) != 1 or old not in text[start:end]
            or text[start:end].count(gate) != 1
            or text.index(old, start) < text.index(gate, start)
            or old.count('\n') != new.count('\n') or old.count('\n') != 5
            or old.count('self.retire_queued_private_maintenance(group_id)?;') != 1):
        raise ValueError('private-maintenance-inverse-scope')


def private_maintenance_pfp_controls(site):
    result = private_maintenance_controls(site)
    source = Path(PRIVATE_MAINTENANCE_PRODUCT).read_text()
    old, new = PRIVATE_MAINTENANCE_GREEN, PRIVATE_MAINTENANCE_INVERSE
    validate_private_maintenance_inverse(source, old, new)
    invalid = [(source + old, old, new),
               (source.replace('fn prepare_convergence_input_advance(', 'fn PRIVATE('), old, new),
               (source.replace(old, '') + old, old, new),
               (source, old, new + '\n'), (source, old, old),
               (source, old, '\n' * 5),
               (source, old, '        panic!("PRIVATE");' + new)]
    for text, original, mutant in invalid:
        try:
            validate_private_maintenance_inverse(text, original, mutant)
        except ValueError:
            pass
        else:
            raise AssertionError('private-maintenance-inverse-negative')
    assert pfp_configuration(PRIVATE_MAINTENANCE_CASE) == positive_configuration(PRIVATE_MAINTENANCE_CASE)
    result.update(inverse_positive=1, inverse_negative=len(invalid))
    return result


PRIVATE_MAINTENANCE_ORDER_GATE = '        if let Some(state) = self.epoch_manager.state(group_id)\n            && !matches!(state, EpochState::Stable { .. })\n        {\n            return Ok(false);\n        }\n'
PRIVATE_MAINTENANCE_ORDER_GREEN = PRIVATE_MAINTENANCE_ORDER_GATE + PRIVATE_MAINTENANCE_GREEN
PRIVATE_MAINTENANCE_ORDER_INVERSE = PRIVATE_MAINTENANCE_GREEN + PRIVATE_MAINTENANCE_ORDER_GATE
PFP[PRIVATE_MAINTENANCE_ORDER_CASE] = (
    PRIVATE_MAINTENANCE_PRODUCT, PRIVATE_MAINTENANCE_ORDER_GREEN, PRIVATE_MAINTENANCE_ORDER_INVERSE,
    PRIVATE_MAINTENANCE_ORDER_MESSAGE,
    r'assert_eq!\(\s*storage.list_queued_outbound_intents\(&group\).unwrap\(\).len\(\),\s*1,\s*"{message}"\s*,?\s*\);')


def validate_private_maintenance_order_inverse(text, old, new):
    owner = '    fn prepare_convergence_input_advance('
    if text.count(owner) != 1:
        raise ValueError('private-maintenance-order-owner')
    start = text.index(owner)
    end = text.index('    async fn run_drain_maintenance(', start)
    if (old != PRIVATE_MAINTENANCE_ORDER_GREEN or new != PRIVATE_MAINTENANCE_ORDER_INVERSE
            or text.count(old) != 1 or old not in text[start:end]
            or old.count('\n') != new.count('\n') or old.count('\n') != 10):
        raise ValueError('private-maintenance-order-scope')


def private_maintenance_order_failure(raw, site):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    if text.count('panicked at ') != 1:
        return False
    pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(CASES[PRIVATE_MAINTENANCE_ORDER_CASE][1])
        + r"'(?: \([0-9]+\))? panicked at " + re.escape(CASES[PRIVATE_MAINTENANCE_ORDER_CASE][2])
        + ':' + str(site['line']) + ':' + str(site['column'])
        + r':[ \t]*\n(?:[ \t]*\n){0,2}[ \t]{0,8}assertion `left == right` failed: '
        + re.escape(PRIVATE_MAINTENANCE_ORDER_MESSAGE)
        + r'[ \t]*\n[ \t]{0,8}left: 0[ \t]*\n[ \t]{0,8}right: 1[ \t]*(?:\n|$)')
    return re.search(pattern, text) is not None


def private_maintenance_order_controls(site):
    source = Path(PRIVATE_MAINTENANCE_PRODUCT).read_text()
    old, new = PRIVATE_MAINTENANCE_ORDER_GREEN, PRIVATE_MAINTENANCE_ORDER_INVERSE
    validate_private_maintenance_order_inverse(source, old, new)
    bad = [(source + old, old, new),
        (source.replace('fn prepare_convergence_input_advance(', 'fn PRIVATE('), old, new),
        (source.replace(old, '') + old, old, new), (source, old, old),
        (source, old, new + '\n'), (source, old, PRIVATE_MAINTENANCE_GREEN + '\n' * 5)]
    for text, original, mutant in bad:
        try:
            validate_private_maintenance_order_inverse(text, original, mutant)
        except ValueError:
            pass
        else:
            raise AssertionError('private-maintenance-order-inverse-negative')
    header = ("thread '" + CASES[PRIVATE_MAINTENANCE_ORDER_CASE][1] + "' (7) panicked at "
        + CASES[PRIVATE_MAINTENANCE_ORDER_CASE][2] + ':' + str(site['line']) + ':' + str(site['column'])
        + ':\nassertion `left == right` failed: ' + PRIVATE_MAINTENANCE_ORDER_MESSAGE
        + '\n  left: 0\n right: 1\n').encode()
    assert private_maintenance_order_failure(header, site)
    failures = [b'', header + header, header.replace(b'left: 0', b'left: 1'),
        header.replace(b'right: 1', b'right: 0'), header.replace(b'left: 0', b'left: 00'),
        header.replace(CASES[PRIVATE_MAINTENANCE_ORDER_CASE][1].encode(), b'PRIVATE'),
        header.replace(CASES[PRIVATE_MAINTENANCE_ORDER_CASE][2].encode(), b'PRIVATE.rs'),
        header.replace(PRIVATE_MAINTENANCE_ORDER_MESSAGE.encode(), b'PRIVATE'),
        header.replace((':' + str(site['line']) + ':').encode(), b':0:'),
        header.replace((':' + str(site['column']) + ':\n').encode(), b':0:\n')]
    assert all(not private_maintenance_order_failure(raw, site) for raw in failures)
    assert pfp_configuration(PRIVATE_MAINTENANCE_ORDER_CASE) == (ENGINE_FEATURES, 'ci', None)
    return {'inverse_positive': 1, 'inverse_negative': len(bad), 'own_positive': 1,
        'own_negative': len(failures), 'configuration_positive': 1,
        'synthetic_metadata_only': True, 'product_bodies': 0}


PRIVATE_HYDRATION_PRODUCT = 'crates/cgka-engine/src/engine.rs'
PRIVATE_HYDRATION_GREEN = '        // Negative upgrade recovery must precede bootstrap reads and network\n        // replay. Those can fail before the host receives a convergence wake.\n        // Full hydration has validated the actual tree and restored any real\n        // pending publication; never retire maintenance through that barrier.\n        #[cfg(feature = "experimental-device-sync")]\n        let has_queued_intents = if has_queued_intents\n            && !group.is_terminal()\n            && !group.unrecoverable\n            && matches!(\n                self.epoch_manager.state(group_id),\n                Some(cgka_traits::EpochState::Stable { .. })\n            ) {\n            self.retire_queued_private_maintenance(group_id)\n                .map_err(|_| GroupHydrationQuarantineReason::GroupRecordLoadFailed)?;\n            !self\n                .storage\n                .list_queued_outbound_intents(group_id)\n                .map_err(|_| GroupHydrationQuarantineReason::GroupRecordLoadFailed)?\n                .is_empty()\n        } else {\n            has_queued_intents\n        };\n'
PRIVATE_HYDRATION_INVERSE = '\n' * 22
PFP[PRIVATE_HYDRATION_CASE] = (
    PRIVATE_HYDRATION_PRODUCT, PRIVATE_HYDRATION_GREEN, PRIVATE_HYDRATION_INVERSE,
    PRIVATE_HYDRATION_MESSAGE, PRIVATE_HYDRATION_PATTERN)


def validate_private_hydration_inverse(text, old, new):
    owner = '    fn hydrate_one_stored_group('
    if text.count(owner) != 1:
        raise ValueError('private-hydration-inverse-owner')
    start = text.index(owner)
    end = text.index('    fn restore_durable_group_evolution_on_hydrate(', start)
    if (old != PRIVATE_HYDRATION_GREEN or new != PRIVATE_HYDRATION_INVERSE
            or text.count(old) != 1 or old not in text[start:end]
            or old.count('self.retire_queued_private_maintenance(group_id)') != 1
            or old.count('Some(cgka_traits::EpochState::Stable { .. })') != 1
            or old.count('!group.is_terminal()') != 1 or old.count('!group.unrecoverable') != 1
            or old.count('\n') != new.count('\n')
            or new != '\n' * PRIVATE_HYDRATION_GREEN.count('\n')):
        raise ValueError('private-hydration-inverse-scope')


def private_hydration_pfp_controls(site):
    result = private_hydration_controls(site)
    source = Path(PRIVATE_HYDRATION_PRODUCT).read_text()
    old, new = PRIVATE_HYDRATION_GREEN, PRIVATE_HYDRATION_INVERSE
    validate_private_hydration_inverse(source, old, new)
    invalid = [(source + old, old, new),
        (source.replace('fn hydrate_one_stored_group(', 'fn PRIVATE('), old, new),
        (source.replace(old, '') + old, old, new), (source, old, old),
        (source, old, new + '\n'), (source, old, '        panic!("PRIVATE");' + new),
        (source.replace('Some(cgka_traits::EpochState::Stable { .. })', 'Some(cgka_traits::EpochState::PRIVATE { .. })'), old, new)]
    for text, original, mutant in invalid:
        try:
            validate_private_hydration_inverse(text, original, mutant)
        except ValueError:
            pass
        else:
            raise AssertionError('private-hydration-inverse-negative')
    assert pfp_configuration(PRIVATE_HYDRATION_CASE) == (ENGINE_FEATURES, 'ci', None)
    result.update(inverse_positive=1, inverse_negative=len(invalid))
    return result


PRIVATE_SEND_PRODUCT = 'crates/cgka-engine/src/message_processor/mod.rs'
PRIVATE_SEND_GREEN = '        // Reject generic private-group work before convergence preflight or\n        // durable queue admission. A later dispatch-only refusal can strand\n        // an unsupported maintenance intent and invalidate settled reads.\n        // Keep the dispatch guard too: retained queues must remain fenced.\n        #[cfg(feature = "experimental-device-sync")]\n        if self.with_mls_group(&group_id, |group| {\n            crate::device_group_genesis::has_private_component(group)\n        })? {\n            return Err(EngineError::InvalidTransition(\n                cgka_traits::engine_state::InvalidTransition {\n                    from: "PrivateDeviceGroup",\n                    to: crate::audit_helpers::send_intent_kind_str(intent),\n                    reason: "authenticated private-group approval is required",\n                },\n            ));\n        }\n'
PRIVATE_SEND_INVERSE = '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n'
PFP[PRIVATE_SEND_CASE] = (PRIVATE_SEND_PRODUCT, PRIVATE_SEND_GREEN, PRIVATE_SEND_INVERSE,
    PRIVATE_SEND_MESSAGE,
    r'assert!\(\s*matches!\(result, Err\(cgka_traits::EngineError::InvalidTransition\(error\)\) if error.from == "PrivateDeviceGroup"\),'
    r'\s*"generic private send must be rejected before queue admission; queued=\{queued\}"\s*,?\s*\);')


def validate_private_send_inverse(text, old, new):
    owner = '    fn validate_send_acceptance(&mut self, intent: &SendIntent) -> Result<GroupId, EngineError> {'
    if text.count(owner) != 1:
        raise ValueError('private-send-inverse-owner')
    start = text.index(owner)
    end = text.index('    pub(crate) async fn advance_convergence_and_drain_queued(', start)
    if (old != PRIVATE_SEND_GREEN or new != PRIVATE_SEND_INVERSE
            or text.count(old) != 1 or old not in text[start:end]
            or old.count('\n') != new.count('\n') or new != '\n' * 16):
        raise ValueError('private-send-inverse-scope')


def private_send_pfp_controls(site):
    result = private_send_controls(site)
    source = Path(PRIVATE_SEND_PRODUCT).read_text()
    old, new = PRIVATE_SEND_GREEN, PRIVATE_SEND_INVERSE
    validate_private_send_inverse(source, old, new)
    invalid = [
        (source + old, old, new),
        (source.replace('fn validate_send_acceptance(', 'fn PRIVATE('), old, new),
        (source.replace(old, '') + old, old, new),
        (source, old, new + '\n'),
        (source, old, old),
        (source, old, new[:-1]),
        (source, old, '        panic!("PRIVATE");' + new),
    ]
    for text, original, mutant in invalid:
        try:
            validate_private_send_inverse(text, original, mutant)
        except ValueError:
            pass
        else:
            raise AssertionError('private-send-inverse-negative')
    assert pfp_configuration(PRIVATE_SEND_CASE) == positive_configuration(PRIVATE_SEND_CASE)
    result.update(inverse_positive=1, inverse_negative=len(invalid))
    return result


AUTOMATIC_SCAN_EXPIRY_PRODUCT = 'crates/marmot-app/src/native_device_linking/enabled/negotiated.rs'
AUTOMATIC_SCAN_EXPIRY_GREEN = '        let targets = self.device_linking_targets(account_ref).await?;\n        if targets.len() > 1 {\n            return Err(DeviceLinkingError::NotReady);\n        }\n        let now = Timestamp::now().as_secs();\n'
AUTOMATIC_SCAN_EXPIRY_INVERSE = '        let now = Timestamp::now().as_secs();\n        let targets = self.device_linking_targets(account_ref).await?;\n        if targets.len() > 1 {\n            return Err(DeviceLinkingError::NotReady);\n        }\n'
PFP[AUTOMATIC_SCAN_EXPIRY_CASE] = (
    AUTOMATIC_SCAN_EXPIRY_PRODUCT, AUTOMATIC_SCAN_EXPIRY_GREEN, AUTOMATIC_SCAN_EXPIRY_INVERSE,
    AUTOMATIC_SCAN_EXPIRY_MESSAGE,
    r'assert!\(\s*expired_scan_rejected,\s*"{message}"\s*,?\s*\);')


MUTATION_ADMISSION_GREEN = '            assert_eq!(\n                summary.published, 0,\n                "mutation admission must agree with its actual typed send outcome"\n            );\n'
MUTATION_ADMISSION_INVERSE = '            assert_eq!(\n                summary.published, 1,\n                "mutation admission must agree with its actual typed send outcome"\n            );\n'
PFP[MUTATION_ADMISSION_CASE] = (
    MUTATION_ADMISSION_PATH, MUTATION_ADMISSION_GREEN, MUTATION_ADMISSION_INVERSE,
    MUTATION_ADMISSION_MESSAGE,
    r'assert_eq!\(\s*summary\.published,\s*0,\s*"{message}"\s*,?\s*\);')


def validate_mutation_admission_inverse(text, old, new):
    if (old != MUTATION_ADMISSION_GREEN or new != MUTATION_ADMISSION_INVERSE
            or old == new or old.count('\n') != new.count('\n')
            or text.count(old) != 1):
        raise ValueError('mutation-admission-exact-inverse')
    # Verify Published=1, Pending|Unknown=0 and the single-ID assertion together.
    mutation_admission_site(text)
    start = text.index('pub(crate) fn assert_mutation_admitted(')
    end = text.index('\n}', start) + 2
    if old not in text[start:end]:
        raise ValueError('mutation-admission-inverse-owner')


def mutation_admission_pfp_controls(site):
    result = mutation_admission_controls(site)
    text = Path(MUTATION_ADMISSION_PATH).read_text()
    old, new = MUTATION_ADMISSION_GREEN, MUTATION_ADMISSION_INVERSE
    validate_mutation_admission_inverse(text, old, new)
    start = text.index('pub(crate) fn assert_mutation_admitted(')
    end = text.index('\n}', start) + 2
    helper = text[start:end]
    changed_helper = lambda value: text[:start] + value + text[end:]
    invalid = [(text, old, old), (text, new, old), (text, old, '\n' * old.count('\n')),
        (text, old, new + '\n'),
        (text.replace('pub(crate) fn assert_mutation_admitted(', 'pub(crate) fn PRIVATE('), old, new),
        (changed_helper(helper.replace('Published => assert_eq!(summary.published, 1)',
                      'Published => assert_eq!(summary.published, 0)')), old, new),
        (changed_helper(helper.replace('assert_eq!(summary.message_ids.len(), 1);',
                      'assert_eq!(summary.message_ids.len(), 2);')), old, new),
        (text.replace(old, '') + old, old, new)]
    for source, before, after in invalid:
        try:
            validate_mutation_admission_inverse(source, before, after)
        except ValueError:
            pass
        else:
            raise AssertionError('mutation-admission-invalid-inverse-accepted')
    assert pfp_configuration(MUTATION_ADMISSION_CASE) == positive_configuration(MUTATION_ADMISSION_CASE)
    result.update(inverse_positive=1, inverse_negative=len(invalid), configuration_positive=1)
    return result


def validate_automatic_scan_expiry_inverse(text, old, new):
    owner = '    pub async fn scan_automatic_device_linking_session('
    if text.count(owner) != 1:
        raise ValueError('automatic-scan-expiry-inverse-owner')
    start = text.index(owner)
    end = text.index('\n}\n\n#[cfg(all(test, feature = "test-policy-overrides"))]', start)
    if (old != AUTOMATIC_SCAN_EXPIRY_GREEN or new != AUTOMATIC_SCAN_EXPIRY_INVERSE
            or text.count(old) != 1 or old not in text[start:end]
            or old.count('\n') != new.count('\n')):
        raise ValueError('automatic-scan-expiry-inverse-scope')


def automatic_scan_expiry_pfp_controls(site):
    result = automatic_scan_expiry_controls(site)
    source = Path(AUTOMATIC_SCAN_EXPIRY_PRODUCT).read_text()
    old, new = AUTOMATIC_SCAN_EXPIRY_GREEN, AUTOMATIC_SCAN_EXPIRY_INVERSE
    validate_automatic_scan_expiry_inverse(source, old, new)
    invalid = [
        (source + old, old, new),
        (source.replace('pub async fn scan_automatic_device_linking_session(',
                        'pub async fn PRIVATE('), old, new),
        (source.replace(old, '') + old, old, new),
        (source, old, new + '\n'),
        (source, old, old),
        (source, old, new.replace('Timestamp::now()', 'Timestamp::from_secs(0)')),
    ]
    for text, original, mutant in invalid:
        try:
            validate_automatic_scan_expiry_inverse(text, original, mutant)
        except ValueError:
            pass
        else:
            raise AssertionError('automatic-scan-expiry-inverse-negative')
    assert pfp_configuration(AUTOMATIC_SCAN_EXPIRY_CASE) == positive_configuration(AUTOMATIC_SCAN_EXPIRY_CASE)
    result.update(inverse_positive=1, inverse_negative=len(invalid), configuration_positive=1)
    return result


MISSING_ROUTE_CASE = 'sdk-private-missing-route'
MISSING_ROUTE_MESSAGE = 'failed owner operation leaves this exact private wire ineligible'
MISSING_ROUTE_GREEN = '                            // Failure must revoke the predecessor even when\n                            // planning rejects the route before preparation.\n                            if let Some(wire) =\n                                state.private_observation_wires.get_mut(&sync.account_id)\n                            {\n                                wire.ready = false;\n                                wire.completed = false;\n                            }\n                            return Err(TransportAdapterError::Subscription(\n                                "selected private observation route unavailable".into(),\n                            ));\n'
MISSING_ROUTE_INVERSE = '                            // Failure must revoke the predecessor even when\n                            // planning rejects the route before preparation.\n                            if let Some(wire) =\n                                state.private_observation_wires.get_mut(&sync.account_id)\n                            {\n                                let _ = wire.ready;\n                                let _ = wire.completed;\n                            }\n                            return Err(TransportAdapterError::Subscription(\n                                "selected private observation route unavailable".into(),\n                            ));\n'
PFP[MISSING_ROUTE_CASE] = ('crates/transport-nostr-adapter/src/lib.rs',
    MISSING_ROUTE_GREEN, MISSING_ROUTE_INVERSE, MISSING_ROUTE_MESSAGE,
    r'assert!\(\s*wire\.actual\s*==\s*actual\s*&&\s*wire\.attempt\s*==\s*attempt\s*&&\s*!wire\.ready,\s*"{message}"\s*,?\s*\);')


def validate_missing_route_inverse(text, old, new):
    owner = '    async fn sync_account_groups('
    boundary = '    async fn deactivate_account('
    if text.count(owner) != 1 or text.count(boundary) != 1:
        raise ValueError('missing-route-owner-cardinality')
    start = text.index(owner)
    end = text.index(boundary, start)
    if (old != MISSING_ROUTE_GREEN or new != MISSING_ROUTE_INVERSE
            or text.count(old) != 1 or old not in text[start:end]
            or old.count('wire.ready = false;') != 1
            or old.count('wire.completed = false;') != 1
            or old.count('return Err(') != 1
            or old.count('Failure must revoke the predecessor even when') != 1
            or old.count('selected private observation route unavailable') != 1
            or old.count('\n') != new.count('\n')):
        raise ValueError('missing-route-inverse-owner')


def missing_route_failure(raw, site):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    if text.count('panicked at ') != 1:
        return False
    pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(CASES[MISSING_ROUTE_CASE][1])
        + r"'(?: \([0-9]+\))? panicked at " + re.escape(CASES[MISSING_ROUTE_CASE][2])
        + ':' + str(site['line']) + ':' + str(site['column'])
        + r':[ \t]*\n(?:[ \t]*\n){0,2}[ \t]{0,8}' + re.escape(MISSING_ROUTE_MESSAGE)
        + r'[ \t]*(?:\n|$)')
    return re.search(pattern, text) is not None


def missing_route_controls(site):
    header = ("thread '" + CASES[MISSING_ROUTE_CASE][1] + "' (7) panicked at "
        + CASES[MISSING_ROUTE_CASE][2] + ':' + str(site['line']) + ':' + str(site['column']) + ':\n')
    valid = (header + MISSING_ROUTE_MESSAGE + '\n').encode()
    positive = [valid, valid.replace(b"' (7)", b"'"), valid.replace(b'\n', b'\r\n'), b' '*8 + valid]
    assert all(missing_route_failure(raw, site) for raw in positive)
    invalid = [valid + valid, b'PRIVATE ' + valid, b' '*9 + valid,
        valid.replace(MISSING_ROUTE_MESSAGE.encode(), b'PRIVATE'),
        valid.replace(CASES[MISSING_ROUTE_CASE][1].encode(), b'PRIVATE'),
        valid.replace(CASES[MISSING_ROUTE_CASE][2].encode(), b'PRIVATE.rs'),
        valid.replace((':' + str(site['line']) + ':').encode(), b':999999:'),
        valid.replace((':' + str(site['column']) + ':').encode(), b':999999:'),
        valid + b"thread 'PRIVATE' panicked at PRIVATE.rs:1:2:\n",
        valid.replace(MISSING_ROUTE_MESSAGE.encode(), ('assertion failed: ' + MISSING_ROUTE_MESSAGE).encode())]
    assert all(not missing_route_failure(raw, site) for raw in invalid)
    product = Path(PFP[MISSING_ROUTE_CASE][0]).read_text()
    validate_missing_route_inverse(product, MISSING_ROUTE_GREEN, MISSING_ROUTE_INVERSE)
    bad_owners = [product.replace('    async fn sync_account_groups(', '    async fn unrelated('),
        product.replace('    async fn deactivate_account(', '    async fn unrelated('),
        product + MISSING_ROUTE_GREEN, product.replace(MISSING_ROUTE_GREEN, '') + MISSING_ROUTE_GREEN]
    for changed in bad_owners:
        try:
            validate_missing_route_inverse(changed, MISSING_ROUTE_GREEN, MISSING_ROUTE_INVERSE)
        except ValueError:
            pass
        else:
            raise AssertionError('missing-route-owner-negative')
    bad_inverses = [MISSING_ROUTE_GREEN, MISSING_ROUTE_INVERSE + '\n',
        MISSING_ROUTE_INVERSE.replace('let _ = wire.ready;', 'wire.ready = false;'),
        MISSING_ROUTE_INVERSE.replace('let _ = wire.completed;', 'wire.completed = false;'),
        MISSING_ROUTE_INVERSE.replace('return Err(', 'return Ok(')]
    for changed in bad_inverses:
        try:
            validate_missing_route_inverse(product, MISSING_ROUTE_GREEN, changed)
        except ValueError:
            pass
        else:
            raise AssertionError('missing-route-inverse-negative')
    assert pfp_configuration(MISSING_ROUTE_CASE) == positive_configuration(MISSING_ROUTE_CASE)
    return {'positive': len(positive), 'negative': len(invalid) + len(bad_owners) + len(bad_inverses),
        'configuration_controls': 1, 'synthetic_metadata_only': True, 'product_bodies': 0}


SCOPED_REPORT_CASE = 'sdk-scoped-reporting'
SCOPED_REPORT_MESSAGE = 'selected private scoped subscription must preserve the actual degraded activation report'
SCOPED_REPORT_GREEN = '                        Some(actual) => {\n                            relay_client\n                                .subscribe_scoped_reporting(subscription.clone(), actual.clone())\n                                .await\n                        }\n'
SCOPED_REPORT_INVERSE = '                        Some(actual) => {\n                            relay_client\n                                .subscribe_scoped_reporting(subscription.clone(), actual.clone())\n                                .await.map(|_report| NostrSubscribeReport::default())\n                        }\n'
PFP[SCOPED_REPORT_CASE] = ('crates/transport-nostr-adapter/src/lib.rs',
    SCOPED_REPORT_GREEN, SCOPED_REPORT_INVERSE, SCOPED_REPORT_MESSAGE,
    r'assert!\(\s*metrics\.activations_degraded\s*==\s*1\s*&&\s*metrics\.activations_full\s*==\s*0\s*&&\s*metrics\.activations_failed\s*==\s*0,\s*"{message}"\s*,?\s*\);')


def scoped_report_ready(value, mutant=False):
    expected = (0, 1, 0) if mutant else (1, 0, 0)
    return (type(value) is dict
            and set(value) == SCOPED_REPORT_PROBE_BOOLS | SCOPED_REPORT_PROBE_COUNTS
            and all(value[key] is True for key in SCOPED_REPORT_PROBE_BOOLS)
            and all(type(value[key]) is int for key in SCOPED_REPORT_PROBE_COUNTS)
            and tuple(value[key] for key in ('activations_degraded', 'activations_full', 'activations_failed')) == expected)


def validate_scoped_report_inverse(text, old, new):
    owner = '    async fn subscribe_each('
    boundary = '    /// Drain relay unsubscribes queued'
    if text.count(owner) != 1 or text.count(boundary) != 1:
        raise ValueError('scoped-report-inverse-owner-cardinality')
    start = text.index(owner)
    end = text.index(boundary, start)
    if (old != SCOPED_REPORT_GREEN or new != SCOPED_REPORT_INVERSE
            or text.count(old) != 1 or old not in text[start:end]
            or old.count('\n') != new.count('\n')):
        raise ValueError('scoped-report-inverse-owner')


def scoped_report_failure(raw, site):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    if text.count('panicked at ') != 1:
        return False
    pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(CASES[SCOPED_REPORT_CASE][1])
        + r"'(?: \([0-9]+\))? panicked at " + re.escape(CASES[SCOPED_REPORT_CASE][2])
        + ':' + str(site['line']) + ':' + str(site['column'])
        + r':[ \t]*\n(?:[ \t]*\n){0,2}[ \t]{0,8}' + re.escape(SCOPED_REPORT_MESSAGE)
        + r'[ \t]*(?:\n|$)')
    found = re.search(pattern, text)
    return (found is not None and scoped_report_ready(scoped_report_probe(raw), mutant=True)
            and text.index(SCOPED_REPORT_PROBE_PREFIX) < found.start())


def scoped_report_controls(site):
    value = dict.fromkeys(SCOPED_REPORT_PROBE_BOOLS, True)
    value.update(activations_degraded=0, activations_full=1, activations_failed=0)
    def row(item):
        return (SCOPED_REPORT_PROBE_PREFIX + ' ' + json.dumps(item) + '\n').encode()
    marker = row(value)
    header = ("thread '" + CASES[SCOPED_REPORT_CASE][1] + "' (7) panicked at "
        + CASES[SCOPED_REPORT_CASE][2] + ':' + str(site['line']) + ':' + str(site['column']) + ':\n')
    valid = marker + (header + SCOPED_REPORT_MESSAGE + '\n').encode()
    positives = [valid, valid.replace(b"' (7)", b"'"), valid.replace(b'\n', b'\r\n'), b' '*8 + valid]
    for raw in positives:
        assert scoped_report_failure(raw, site)
    probe_controls = scoped_report_probe_controls()
    rejected = [valid + (header + SCOPED_REPORT_MESSAGE + '\n').encode(),
        valid.replace(CASES[SCOPED_REPORT_CASE][1].encode(), b'PRIVATE'),
        valid.replace(CASES[SCOPED_REPORT_CASE][2].encode(), b'PRIVATE.rs'),
        valid.replace((':' + str(site['line']) + ':').encode(), b':999999:'),
        valid.replace((':' + str(site['column']) + ':').encode(), b':999999:'),
        valid.replace(SCOPED_REPORT_MESSAGE.encode(), b'PRIVATE'),
        (header + SCOPED_REPORT_MESSAGE + '\n').encode() + marker,
        marker + b'PRIVATE ' + (header + SCOPED_REPORT_MESSAGE + '\n').encode()]
    rejected += [row(dict(value, **{key: False})) + (header + SCOPED_REPORT_MESSAGE + '\n').encode()
                 for key in SCOPED_REPORT_PROBE_BOOLS]
    assert all(not scoped_report_failure(raw, site) for raw in rejected)
    assert all(not scoped_report_ready(dict(value, **{key: False}), mutant=True) for key in SCOPED_REPORT_PROBE_BOOLS)
    control = dict(value, activations_degraded=1, activations_full=0)
    assert scoped_report_ready(control) and not scoped_report_ready(control, mutant=True)
    assert scoped_report_ready(value, mutant=True) and not scoped_report_ready(value)
    wrong_metrics = [dict(value, activations_degraded=1), dict(value, activations_full=0),
        dict(value, activations_failed=1), dict(value, activations_full=True),
        dict(value, activations_full=1.0)]
    assert all(not scoped_report_ready(item, mutant=True) for item in wrong_metrics)
    wrong_metric_panics = [row(item) + (header + SCOPED_REPORT_MESSAGE + '\n').encode()
                          for item in [control] + wrong_metrics[:3]]
    assert all(not scoped_report_failure(raw, site) for raw in wrong_metric_panics)
    product = Path(PFP[SCOPED_REPORT_CASE][0]).read_text()
    validate_scoped_report_inverse(product, SCOPED_REPORT_GREEN, SCOPED_REPORT_INVERSE)
    bad_inverses = [SCOPED_REPORT_GREEN, SCOPED_REPORT_INVERSE + '\n',
        SCOPED_REPORT_INVERSE.replace('actual.clone()', 'subscription.subscription_id()'),
        SCOPED_REPORT_INVERSE.replace('NostrSubscribeReport::default()', 'panic!("PRIVATE")')]
    for changed in bad_inverses:
        try:
            validate_scoped_report_inverse(product, SCOPED_REPORT_GREEN, changed)
        except ValueError:
            pass
        else:
            raise AssertionError('scoped-report-inverse-negative')
    bad_owners = [
        product.replace('    async fn subscribe_each(', '    async fn subscribe_all(', 1),
        SCOPED_REPORT_GREEN + product.replace(SCOPED_REPORT_GREEN, '', 1),
        product + '\n    async fn subscribe_each(',
        product + SCOPED_REPORT_GREEN,
        product.replace('    /// Drain relay unsubscribes queued', '    /// Unknown boundary', 1),
    ]
    for changed in bad_owners:
        try:
            validate_scoped_report_inverse(changed, SCOPED_REPORT_GREEN, SCOPED_REPORT_INVERSE)
        except ValueError:
            pass
        else:
            raise AssertionError('scoped-report-owner-negative')
    assert pfp_configuration(SCOPED_REPORT_CASE) == positive_configuration(SCOPED_REPORT_CASE)
    return {'positive': len(positives), 'negative': len(rejected) + len(bad_inverses) + len(wrong_metrics) + len(wrong_metric_panics) + len(bad_owners) + 2,
            'configuration_controls': 1, 'probe_controls': probe_controls,
            'synthetic_metadata_only': True, 'product_bodies': 0}


def validate_quiet_inverse(text, old, new):
    expected_new = '    { let _ = collect_authoritative_replay; let _ = (account, expected, recorded); distinct_deliveries(adapter, deadline.saturating_duration_since(tokio::time::Instant::now())).await }'
    begin_marker = '    // SUCCESS_EXPECTED_COLLECTOR_BEGIN\n'
    end_marker = '    // SUCCESS_EXPECTED_COLLECTOR_END'
    owner = 'async fn success_expected_replay_deliveries('
    if (text.count(owner) != 1 or text.count(begin_marker) != 1 or text.count(end_marker) != 1
            or old != QUIET_GREEN_CALL or new != expected_new
            or old.count('\n') != new.count('\n') or text.count(old) != 1):
        raise ValueError('inverse-quiet-exact-expression')
    start = text.index(owner)
    begin = text.index(begin_marker)
    end = text.index(end_marker)
    if (not start < begin < end or text[begin + len(begin_marker):end] != old + '\n'
            or 'async fn ' in text[start + len(owner):end]):
        raise ValueError('inverse-quiet-owned-body')


def quiet_inverse_controls(text, old, new):
    validate_quiet_inverse(text, old, new)
    bad = [
        (text, old, new.replace('let _ = collect_authoritative_replay;', 'let _ = collect_authoritative_replay(adapter, account, expected, deadline, recorded).await;')),
        (text, old, new.replace('distinct_deliveries(adapter,', 'distinct_deliveries(adapter.clone(),')),
        (text, old, new + '\n'),
        (text.replace(old, old.replace('account, expected', 'expected, account')), old, new),
        (text.replace('    // SUCCESS_EXPECTED_COLLECTOR_BEGIN', '    // OTHER_COLLECTOR_BEGIN'), old, new),
        (text, old.replace('account, expected', 'expected, account'), new),
    ]
    for source, before, after in bad:
        try:
            validate_quiet_inverse(source, before, after)
        except ValueError:
            pass
        else:
            raise AssertionError('quiet-inverse-owner-negative-accepted')
    return {'positive': 1, 'negative': len(bad), 'product_bodies': 0, 'synthetic_metadata_only': True}


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


for _case in LIVE_SEAL_CASES:
    PFP[_case] = ('crates/transport-nostr/src/lib.rs', '        replay.spill_pending = state.spill_in_flight > 0;\n        if replay.pending || replay.spill_pending || !authorize(replay) {\n            return None;\n        }\n        if state.pending || state.spill_in_flight > 0 || state.admission.epoch != epoch {\n            return None;\n        }\n', '        replay.spill_pending = state.spill_in_flight > 0;\n        if replay.pending || false || !authorize(replay) {\n            return None;\n        }\n        if state.pending || false || state.admission.epoch != epoch {\n            return None;\n        }\n', 'no commit passes a delivery still in the spill hand-off', 'assert_eq!\\(\\s*adapter\\.seal_transport_cursor\\(Some\\(OPENED_CURSOR\\s*\\+\\s*3_000\\),\\s*\\|_\\|\\s*true\\),\\s*None,\\s*"{message}"\\s*\\);')


def validate_live_seal_inverse(text, old, new):
    start = text.index('    fn seal_cursor(')
    end = text.index('    fn unseal_cursor(', start)
    wanted = old.replace('replay.pending || replay.spill_pending ||', 'replay.pending || false ||', 1)
    wanted = wanted.replace('state.pending || state.spill_in_flight > 0 ||', 'state.pending || false ||', 1)
    if (old not in text[start:end] or old.count('\n') != new.count('\n') or new != wanted
            or old.count('replay.pending || replay.spill_pending ||') != 1
            or old.count('state.pending || state.spill_in_flight > 0 ||') != 1):
        raise ValueError('live-seal-two-real-fences-only')


def live_seal_site(fixture):
    case = 'live-seal-spill-default'
    matches = list(re.finditer(PFP[case][4].replace('{message}', re.escape(PFP[case][3])), fixture))
    if len(matches) != 1:
        raise ValueError('live-seal-own-second-assertion')
    found = matches[0]
    return {'line': fixture[:found.start()].count('\n') + 1,
            'column': found.start() - fixture.rfind('\n', 0, found.start())}


def validate_live_seal_fixture(fixture):
    start = fixture.index('async fn deliveries_placed_after_a_live_seal_spill_what_only_that_promotion_stopped_covering()')
    end = fixture.index('\n}\n', start)
    body = fixture[start:end]
    anchors = ['let (store, kept, spill_gate) = gated_recording_spill_store();',
               'adapter.delivery_loss_blocks_cursor(),',
               '"no commit passes a delivery still in the spill hand-off"',
               'spill_gate.open();', 'timeout(Duration::from_secs(5), async {',
               'assert_eq!(spilled, [1, 4]);']
    if any(body.count(anchor) != 1 for anchor in anchors):
        raise ValueError('live-seal-held-real-writer-fixture')
    offsets = [body.index(anchor) for anchor in anchors]
    if offsets != sorted(offsets):
        raise ValueError('live-seal-release-only-after-both-assertions')
    live_seal_site(fixture)


def live_seal_failure(raw, case, site):
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    if text.count('panicked at ') != 1:
        return False
    header = (r"(?m)^[ \t]{0,8}thread '" + re.escape(CASES[case][1])
        + r"'(?: \([0-9]+\))? panicked at " + re.escape(CASES[case][2])
        + ':' + str(site['line']) + ':' + str(site['column']) + r':[ \t]*\n')
    # This is assert_eq!'s actual runtime prefix, not a bare assert! message.
    payload = (r'[ \t]{0,8}assertion `left == right` failed: '
        + re.escape(PFP[case][3]) + r'[ \t]*\n'
        + r'[ \t]{0,8}left: Some\([0-9]{1,20}\)[ \t]*\n'
        + r'[ \t]{0,8}right: None[ \t]*(?:\n|$)')
    return re.search(header + payload, text) is not None


def live_seal_controls(case, site):
    header = ("thread '" + CASES[case][1] + "' (7) panicked at " + CASES[case][2]
              + ':' + str(site['line']) + ':' + str(site['column']) + ':\n')
    payload = ('assertion `left == right` failed: ' + PFP[case][3]
               + '\n  left: Some(12000)\n right: None\n')
    valid = (header + payload).encode()
    positive = [valid, valid.replace(b"' (7)", b"'"), valid.replace(b'\n', b'\r\n'),
                (header + '\n'.join('    ' + line for line in payload.splitlines()) + '\n').encode()]
    for raw in positive:
        assert live_seal_failure(raw, case, site)
    invalid = [valid + valid, b'PRIVATE ' + valid,
        valid.replace(CASES[case][1].encode(), b'PRIVATE'),
        valid.replace(CASES[case][2].encode(), b'PRIVATE.rs'),
        valid.replace((':' + str(site['line']) + ':').encode(), b':999999:'),
        valid.replace((':' + str(site['column']) + ':').encode(), b':999999:'),
        valid.replace(b'assertion `left == right` failed: ', b''),
        valid.replace(PFP[case][3].encode(), b'PRIVATE'),
        valid.replace(b'left: Some(12000)', b'left: None'),
        valid.replace(b'right: None', b'right: Some(12000)'),
        valid + b"thread 'PRIVATE' panicked at PRIVATE.rs:1:2:\n"]
    for raw in invalid:
        assert not live_seal_failure(raw, case, site)
    status = ('FAIL [ 0.001s] (1/1) transport-nostr ' + CASES[case][1]
              + '\nSummary [ 0.001s] 1 test run: 0 passed, 1 failed, 0 skipped\n').encode()
    assert counts(status + valid, case)['failed'] == 1
    assert compiler(status + valid + b'error[E0000]: PRIVATE\n', {})['header_count'] == 1
    path, original, mutant, _, _ = PFP[case]
    product = Path(path).read_text()
    validate_live_seal_inverse(product, original, mutant)
    denied = [original, mutant.replace('replay.pending || false ||', 'false || false ||'),
              mutant.replace('!authorize(replay)', 'false'),
              mutant.replace('state.admission.epoch != epoch', 'false'),
              mutant.replace('state.pending || false ||', 'state.pending || state.spill_in_flight > 0 ||'),
              mutant + '\n']
    for altered in denied:
        try:
            validate_live_seal_inverse(product, original, altered)
        except ValueError:
            pass
        else:
            raise AssertionError('live-seal-guard-mutation-control')
    fixture = Path(CASES[case][2]).read_text()
    validate_live_seal_fixture(fixture)
    assert package_for(case) == 'transport-nostr' and CASES[case][0] == 'transport_nostr'
    assert positive_configuration(case) == pfp_configuration(case)
    return {'positive': len(positive), 'negative': len(invalid) + len(denied), 'compiler_rejection_controls': 1,
            'configuration_controls': 2, 'product_bodies': 0, 'synthetic_metadata_only': True}


PFP[SQLITE_CACHE_CASE] = (SQLITE_CACHE_SQL_PATH, '', '', '', '')


PFP[WATCH_CLEANUP_CASE] = (*PFP['command-owned-cleanup'][:3],
    WATCH_CLEANUP_MESSAGE, PFP['command-owned-cleanup'][4])


def inverse(case):
    if case == SQLITE_CACHE_CASE:
        path, original, mutants, site = sqlite_cache_inverses()
        return path, original, mutants[0][1], site
    path, old, new, message, pattern = PFP[case]
    original = Path(path).read_bytes()
    text = original.decode('utf-8')
    if text.count(old) != 1:
        raise ValueError('inverse-anchor')
    if case in PRIVATE_ROLE_PFP_CASES:
        validate_private_role_pfp_inverse(text, case, old, new)
    if case in FAMILY_PFP_CASES:
        validate_family_pfp_inverse(text, case, old, new)
    if case == PRIVATE_MAINTENANCE_ORDER_CASE:
        validate_private_maintenance_order_inverse(text, old, new)
    if case == PRIVATE_HYDRATION_CASE:
        validate_private_hydration_inverse(text, old, new)
    if case == PRIVATE_MAINTENANCE_CASE:
        validate_private_maintenance_inverse(text, old, new)
    if case == PRIVATE_SEND_CASE:
        validate_private_send_inverse(text, old, new)
    if case == MUTATION_ADMISSION_CASE:
        validate_mutation_admission_inverse(text, old, new)
    if case == AUTOMATIC_SCAN_EXPIRY_CASE:
        validate_automatic_scan_expiry_inverse(text, old, new)
    if case == MISSING_ROUTE_CASE:
        validate_missing_route_inverse(text, old, new)
    if case == SCOPED_REPORT_CASE:
        validate_scoped_report_inverse(text, old, new)
    if case in LIVE_SEAL_CASES:
        validate_live_seal_inverse(text, old, new)
        validate_live_seal_fixture(Path(CASES[case][2]).read_text())
    if case in CURSOR_CASES:
        validate_cursor_inverse(text, old, new)
    if case in QUIET_CONTRACT_CASES:
        validate_quiet_inverse(text, old, new)
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
    if case in OWNED_CLEANUP_NAMESPACES:
        if case == WATCH_CLEANUP_CASE:
            fixture = Path(WATCH_CLEANUP_PATH).read_text()
            if ('use super::recipient_sibling_admission_acceptance::owned_loopback_listener_is_closed;' not in fixture
                    or 'async fn owned_loopback_listener_is_closed(' in fixture):
                raise ValueError('watch-cleanup-must-use-qualified-shared-helper')
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
    if case == SQLITE_CACHE_CASE:
        return sqlite_cache_failure(raw, site)
    if case == PRIVATE_MAINTENANCE_ORDER_CASE:
        return private_maintenance_order_failure(raw, site)
    if case == PRIVATE_HYDRATION_CASE:
        return private_hydration_failure(raw, site)
    if case == PRIVATE_MAINTENANCE_CASE:
        return private_maintenance_failure(raw, site)
    if case == PRIVATE_SEND_CASE:
        return private_send_failure(raw, site)
    if case == MUTATION_ADMISSION_CASE:
        return mutation_admission_failure(raw, site)
    if case == AUTOMATIC_SCAN_EXPIRY_CASE:
        return automatic_scan_expiry_failure(raw, site)
    if case in PRIVATE_ROLE_PFP_CASES:
        return private_role_pfp_failure(raw, case, site)
    if case == MISSING_ROUTE_CASE:
        return missing_route_failure(raw, site)
    if case in FAMILY_PFP_CASES:
        return family_pfp_failure(raw, case, site)
    if case == SCOPED_REPORT_CASE:
        return scoped_report_failure(raw, site)
    if case in LIVE_SEAL_CASES:
        return live_seal_failure(raw, case, site)
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
    if case == WATCH_CLEANUP_CASE:
        return watch_cleanup_controls(site)
    if case == SQLITE_CACHE_CASE:
        return sqlite_cache_controls(site)
    if case == PRIVATE_MAINTENANCE_ORDER_CASE:
        return private_maintenance_order_controls(site)
    if case == PRIVATE_HYDRATION_CASE:
        return private_hydration_pfp_controls(site)
    if case == PRIVATE_MAINTENANCE_CASE:
        return private_maintenance_pfp_controls(site)
    if case == PRIVATE_SEND_CASE:
        return private_send_pfp_controls(site)
    if case == MUTATION_ADMISSION_CASE:
        return mutation_admission_pfp_controls(site)
    if case == AUTOMATIC_SCAN_EXPIRY_CASE:
        return automatic_scan_expiry_pfp_controls(site)
    if case in PRIVATE_ROLE_PFP_CASES:
        return private_role_pfp_controls(case, site)
    if case == MISSING_ROUTE_CASE:
        return missing_route_controls(site)
    if case in FAMILY_PFP_CASES:
        return family_pfp_controls(case, site)
    if case == SCOPED_REPORT_CASE:
        return scoped_report_controls(site)
    if case in LIVE_SEAL_CASES:
        return live_seal_controls(case, site)
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
    if case == WATCH_CLEANUP_CASE:
        return positive_configuration(case)
    if case == SQLITE_CACHE_CASE:
        return positive_configuration(case)
    if case == MUTATION_ADMISSION_CASE:
        return positive_configuration(case)
    if case == PRIVATE_HYDRATION_CASE:
        return positive_configuration(case)
    if case == PRIVATE_MAINTENANCE_ORDER_CASE:
        return positive_configuration(case)
    if case == PRIVATE_MAINTENANCE_CASE:
        return positive_configuration(case)
    if case == PRIVATE_SEND_CASE:
        return positive_configuration(case)
    if case == AUTOMATIC_SCAN_EXPIRY_CASE:
        return positive_configuration(case)
    if case in PRIVATE_ROLE_PFP_CASES:
        return positive_configuration(case)
    if case == MISSING_ROUTE_CASE:
        return positive_configuration(case)
    if case in FAMILY_PFP_CASES:
        return positive_configuration(case)
    if case == SCOPED_REPORT_CASE:
        return positive_configuration(case)
    if case in LIVE_SEAL_CASES:
        return ((['test-policy-overrides', 'experimental-device-sync'], 'm5-bounded', '4194304')
                if case == 'live-seal-spill-experimental' else (['test-policy-overrides'], 'ci', None))
    if case in QUIET_CONTRACT_CASES:
        return positive_configuration(case)
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



QUIET_CONTRACT_MESSAGE = 'quiet delivery gap must not finish success-expected replay while its actual source is pending'
QUIET_CONTRACT_KEYS = {'captured_exact', 'held_eose_exact', 'initial_coverage_incomplete',
    'returned_before_deadline', 'returned_zero', 'collected_exact', 'pending_at_return',
    'spill_pending_at_return', 'coverage_incomplete_at_return', 'loss_absent_at_return',
    'release_completed', 'released_exact_order', 'final_coverage_complete',
    'final_placement_complete', 'no_extra_after_release', 'owned_shutdown_returned'}


def quiet_contract_stage(stage):
    if stage not in {'positive', 'pfp'}:
        raise ValueError('quiet-contract-positive-or-pfp-only')


def quiet_contract_site():
    text = Path(CASES[QUIET_CONTRACT_CASE][2]).read_text()
    target = text.split('async fn ' + CASES[QUIET_CONTRACT_CASE][1] + '()', 1)
    if len(target) != 2:
        raise ValueError('quiet-contract-source-function')
    pattern = r'assert!\(\s*complete_at_return,\s*"' + re.escape(QUIET_CONTRACT_MESSAGE) + r'"\s*,?\s*\);'
    matches = list(re.finditer(pattern, text))
    if len(matches) != 1 or matches[0].start() < len(target[0]):
        raise ValueError('quiet-contract-source-assertion')
    return {'line': text[:matches[0].start()].count('\n') + 1,
            'column': matches[0].start() - text.rfind('\n', 0, matches[0].start())}


def quiet_contract_observe(raw, site):
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError('quiet-contract-output-cap')
    text = ANSI.sub('', raw.decode('utf-8', errors='strict'))
    def row(namespace):
        if text.count(namespace) != 1:
            raise ValueError('quiet-contract-namespace')
        found = list(re.finditer(r'(?m)^[ \t]{0,8}' + re.escape(namespace + ' ')
            + r'(\{[^\r\n]{1,8190}\})[ \t]{0,8}\r?$', text))
        if len(found) != 1 or len(found[0][0].encode('utf-8')) > 8192:
            raise ValueError('quiet-contract-envelope')
        return json.loads(found[0][1], object_pairs_hook=unique), found[0]
    marker, marker_match = row('adapter-quiet-pending-contract')
    exit_row, exit_match = row('adapter-distinct-deliveries-exit')
    if (type(marker) is not dict or set(marker) != QUIET_CONTRACT_KEYS
            or any(type(value) is not bool for value in marker.values())):
        raise ValueError('quiet-contract-marker-fields')
    exit_keys = {'reason', 'delivered', 'wait_ms', 'elapsed_ms', 'remaining_ms'}
    if (type(exit_row) is not dict or set(exit_row) != exit_keys
            or type(exit_row['reason']) is not str
            or exit_row['reason'] not in {'quiet_timeout', 'deadline_timeout', 'receive_error', 'stream_closed', 'authoritative_complete'}
            or any(type(exit_row[key]) is not int or not 0 <= exit_row[key] < 2**64
                   for key in exit_keys - {'reason'})
            or not 0 < exit_row['wait_ms'] <= 15000
            or exit_row['remaining_ms'] > exit_row['wait_ms']
            or (exit_row['elapsed_ms'] < exit_row['wait_ms']
                and exit_row['elapsed_ms'] + exit_row['remaining_ms'] not in (exit_row['wait_ms'] - 1, exit_row['wait_ms']))
            or (exit_row['elapsed_ms'] >= exit_row['wait_ms'] and exit_row['remaining_ms'] != 0)
            or exit_match.end() >= marker_match.start()):
        raise ValueError('quiet-contract-original-helper-exit')
    pattern = (r"(?m)^[ \t]{0,8}thread '" + re.escape(CASES[QUIET_CONTRACT_CASE][1])
        + r"'(?: \([0-9]+\))? panicked at " + re.escape(CASES[QUIET_CONTRACT_CASE][2])
        + ':' + str(site['line']) + ':' + str(site['column'])
        + r':[ \t]*\r?\n(?:[ \t]*\r?\n){0,2}[ \t]{0,8}'
        + re.escape(QUIET_CONTRACT_MESSAGE) + r'[ \t]*(?:\r?\n|$)')
    found = list(re.finditer(pattern, text))
    own = text.count('panicked at ') == 1 and len(found) == 1 and marker_match.end() < found[0].start()
    return {'marker': marker, 'helper_exit': exit_row, 'sole_source_owned_final_assertion': own,
            'expected_site': site, 'panic_header_count': text.count('panicked at ')}


def quiet_contract_complete(value):
    marker = value['marker']
    return (marker['collected_exact'] and not marker['returned_zero']
        and value['helper_exit']['reason'] == 'authoritative_complete'
        and value['helper_exit']['delivered'] == 12 and value['helper_exit']['elapsed_ms'] >= 1500
        and value['helper_exit']['remaining_ms'] > 0
        and value['panic_header_count'] == 0
        and not marker['pending_at_return']
        and not marker['spill_pending_at_return'] and not marker['coverage_incomplete_at_return']
        and marker['loss_absent_at_return'] and marker['returned_before_deadline']
        and all(marker[key] for key in ('captured_exact', 'held_eose_exact', 'initial_coverage_incomplete',
            'release_completed', 'released_exact_order', 'final_coverage_complete',
            'final_placement_complete', 'no_extra_after_release', 'owned_shutdown_returned')))


def quiet_contract_red(body, inventory):
    if (type(body.get('exit_code')) is not int or body['exit_code'] != 100
            or any(type(body.get('counts', {}).get(key)) is not int
                   or body['counts'][key] != number
                   for key, number in {'executed': 1, 'passed': 0, 'failed': 1}.items())
            or body.get('compiler') != {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
            or any(type(inventory.get(key)) is not int or inventory[key] != number
                   for key, number in {'exit_code': 0, 'selected_nonignored': 1, 'selected_ignored': 0}.items())):
        return False
    value = body.get('quiet_contract_observation', {})
    expected = {key: key not in {'collected_exact', 'spill_pending_at_return'} for key in QUIET_CONTRACT_KEYS}
    exit_row = value.get('helper_exit', {})
    return (value.get('marker') == expected and value.get('sole_source_owned_final_assertion') is True
        and value.get('panic_header_count') == 1
        and exit_row.get('reason') == 'quiet_timeout' and exit_row.get('delivered') == 0
        and exit_row.get('elapsed_ms', 0) >= 1500 and exit_row.get('remaining_ms', 0) > 0)


def quiet_contract_controls(site):
    case = QUIET_CONTRACT_CASE
    marker = {key: key not in {'collected_exact', 'spill_pending_at_return'} for key in QUIET_CONTRACT_KEYS}
    exit_row = dict(reason='quiet_timeout', delivered=0, wait_ms=14900, elapsed_ms=1500, remaining_ms=13400)
    header = ("thread '" + CASES[case][1] + "' (7) panicked at " + CASES[case][2]
        + ':' + str(site['line']) + ':' + str(site['column']) + ':\n')
    status = ('FAIL [ 2.7s] (1/1) transport-nostr-adapter::relay_limit_subscriptions '
        + CASES[case][1] + '\nSummary [ 2.7s] 1 test run: 0 passed, 1 failed, 0 skipped\n')
    def encode(value=marker, event=exit_row):
        return ('adapter-distinct-deliveries-exit ' + json.dumps(event) + '\n'
            + 'adapter-quiet-pending-contract ' + json.dumps(value) + '\n')
    raw = (status + encode() + header + QUIET_CONTRACT_MESSAGE + '\n').encode()
    inventory = dict(exit_code=0, selected_nonignored=1, selected_ignored=0)
    def body(data):
        return dict(exit_code=100, counts=counts(data, case), compiler=compiler(data, {}),
            quiet_contract_observation=quiet_contract_observe(data, site))
    positives = [raw, raw.replace(b'\nadapter-', b'\n    adapter-'),
        raw.replace(b'\nadapter-', b'\n        adapter-'), raw.replace(b'\n', b'\r\n')]
    for data in positives:
        assert quiet_contract_red(body(data), inventory)
    invalid = [encode(dict(marker, private=True)), encode(dict(marker, collected_exact=0)),
        encode({key: val for key, val in marker.items() if key != 'captured_exact'}),
        encode(dict(marker, captured_exact=None)), encode(event=dict(exit_row, delivered=True)),
        encode(event=dict(exit_row, reason='PRIVATE')), encode(event=dict(exit_row, remaining_ms=-1)),
        encode(event=dict(exit_row, elapsed_ms=0)), encode(event=dict(exit_row, wait_ms=15001)),
        encode().replace('"captured_exact": true', '"captured_exact": true, "captured_exact": true')]
    invalid += [encode() + encode(), 'PRIVATE ' + encode(), ' '*9 + encode(),
        encode() + 'adapter-quiet-pending-contract-PRIVATE\n',
        encode() + 'adapter-distinct-deliveries-exit-PRIVATE\n', '', encode().replace('}\n', '}' + ' '*9 + '\n', 1),
        b'\xff' + raw]
    for data in invalid:
        try:
            quiet_contract_observe(data.encode() if type(data) is str else data, site)
        except (ValueError, UnicodeError):
            pass
        else:
            raise AssertionError('quiet-contract-malformed-accepted')
    denied = [raw + (header + QUIET_CONTRACT_MESSAGE + '\n').encode(),
        raw.replace(header.encode(), header.replace(CASES[case][1], 'PRIVATE').encode()),
        raw.replace(header.encode(), header.replace(CASES[case][2], 'PRIVATE.rs').encode()),
        raw.replace(header.encode(), header.replace(':' + str(site['line']) + ':', ':' + str(site['line'] + 1) + ':').encode()),
        raw.replace(QUIET_CONTRACT_MESSAGE.encode(), b'PRIVATE'),
        raw.replace(header.encode(), header.replace(':' + str(site['column']) + ':', ':' + str(site['column'] + 1) + ':').encode()),
        (status + encode(event=dict(exit_row, delivered=1)) + header + QUIET_CONTRACT_MESSAGE + '\n').encode(),
        (status + header + QUIET_CONTRACT_MESSAGE + '\n' + encode()).encode()]
    denied += [(status + encode(dict(marker, **{key: not marker[key]})) + header + QUIET_CONTRACT_MESSAGE + '\n').encode()
        for key in QUIET_CONTRACT_KEYS]
    denied += [(status + encode(event=dict(exit_row, reason=reason)) + header + QUIET_CONTRACT_MESSAGE + '\n').encode()
        for reason in ('deadline_timeout', 'receive_error', 'stream_closed')]
    for data in denied:
        assert not quiet_contract_red(body(data), inventory)
    for key, bad in [('exit_code', 0), ('exit_code', True), ('counts', dict(executed=0, passed=0, failed=0)),
                     ('counts', dict(executed=True, passed=0, failed=1)), ('counts', dict(executed=1, passed=1, failed=0)),
                     ('compiler', dict(codes=['E0000'], header_count=1, sites=[], unknown_or_excess_sites=0))]:
        value = body(raw); value[key] = bad
        assert not quiet_contract_red(value, inventory)
    for key, bad in [('exit_code', 1), ('selected_nonignored', 0), ('selected_nonignored', True), ('selected_ignored', 1)]:
        assert not quiet_contract_red(body(raw), dict(inventory, **{key: bad}))
    for stage in ('sample',):
        try:
            quiet_contract_stage(stage)
        except ValueError:
            pass
        else:
            raise AssertionError('quiet-contract-nonpositive-stage')
    assert package_for(case) == 'transport-nostr-adapter' and case in INTEGRATION_CASES and case in PFP
    assert positive_configuration(case) == (['sdk', 'experimental-device-sync', 'test-policy-overrides'], 'm5-bounded', '4194304')
    green = dict(marker, returned_zero=False, collected_exact=True, pending_at_return=False,
                 coverage_incomplete_at_return=False)
    green_exit = dict(exit_row, reason='authoritative_complete', delivered=12)
    green_raw = (encode(green, green_exit)).encode()
    assert quiet_contract_complete(quiet_contract_observe(green_raw, site))
    assert not quiet_contract_complete(quiet_contract_observe(raw, site))
    assert not quiet_contract_red(body(status.encode() + green_raw), inventory)
    for key in QUIET_CONTRACT_KEYS:
        changed = dict(green, **{key: not green[key]})
        assert not quiet_contract_complete(quiet_contract_observe(encode(changed, green_exit).encode(), site))
    for reason in ('quiet_timeout', 'deadline_timeout', 'receive_error', 'stream_closed'):
        assert not quiet_contract_complete(quiet_contract_observe(encode(green, dict(green_exit, reason=reason)).encode(), site))
    quiet_contract_stage('pfp')
    assert positive_configuration(QUIET_DEFAULT_CASE) == (['sdk', 'test-policy-overrides'], 'm5-bounded', '4194304')
    assert pfp_configuration(QUIET_DEFAULT_CASE) == positive_configuration(QUIET_DEFAULT_CASE)
    return {'positive': len(positives) + 1, 'negative': len(invalid) + len(denied) + 33,
        'configuration_controls': 4, 'product_bodies': 0, 'synthetic_metadata_only': True}


def owned_cleanup_marker(raw, case='command-owned-cleanup'):
    namespace = OWNED_CLEANUP_NAMESPACES[case].encode()
    prefix = namespace + b' '
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


def owned_cleanup_site(case='command-owned-cleanup'):
    text = Path(CASES[case][2]).read_text()
    pattern = PFP[case][4].replace('{message}', re.escape(PFP[case][3]))
    matches = list(re.finditer(pattern, text))
    if len(matches) != 1:
        raise ValueError('owned-cleanup-source-assertion')
    return {'line': text[:matches[0].start()].count('\n') + 1,
            'column': matches[0].start() - text.rfind('\n', 0, matches[0].start())}


def owned_cleanup_runtime_failure(raw, case, site):
    observation = owned_cleanup_marker(raw, case)
    if not owned_cleanup_oracle(observation, True) or not own_failure(raw, case, site):
        return False
    if panic_facts(raw, case) != {'sites': [{'expected_thread': True, 'expected_source': True,
            'line': site['line'], 'column': site['column']}], 'unknown_or_excess_headers': 0}:
        return False
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    namespace = OWNED_CLEANUP_NAMESPACES[case]
    return text.index(namespace + ' ') < text.index('panicked at ')


def watch_cleanup_controls(site):
    shared = owned_cleanup_controls(site, WATCH_CLEANUP_CASE)
    red = {'listener_started': True, 'closed_in_original_bound': False, 'owned_cleanup_completed': True}
    marker = ('watch-owned-cleanup ' + json.dumps(red) + '\n').encode()
    header = ("thread '" + WATCH_CLEANUP_TEST + "' (7) panicked at " + WATCH_CLEANUP_PATH
        + ':' + str(site['line']) + ':' + str(site['column']) + ':\n'
        + WATCH_CLEANUP_MESSAGE + '\n').encode()
    good = marker + header
    assert owned_cleanup_runtime_failure(good, WATCH_CLEANUP_CASE, site)
    invalid = [header + marker, good + marker, good + header,
        good.replace(WATCH_CLEANUP_TEST.encode(), b'PRIVATE'),
        good.replace(WATCH_CLEANUP_PATH.encode(), b'PRIVATE.rs'),
        good.replace(WATCH_CLEANUP_MESSAGE.encode(), b'PRIVATE'),
        good.replace(b'"listener_started": true', b'"listener_started": false'),
        good.replace(b'"owned_cleanup_completed": true', b'"owned_cleanup_completed": false'),
        good.replace(b'"closed_in_original_bound": false', b'"closed_in_original_bound": true')]
    for raw in invalid:
        try:
            accepted = owned_cleanup_runtime_failure(raw, WATCH_CLEANUP_CASE, site)
        except (ValueError, UnicodeError):
            accepted = False
        assert not accepted
    return {'shared': shared, 'own_order_positive': 1, 'own_order_negative': len(invalid),
            'synthetic_metadata_only': True, 'product_bodies': 0}


def owned_cleanup_controls(site, case='command-owned-cleanup'):
    namespace = OWNED_CLEANUP_NAMESPACES[case]
    prefix = (namespace + ' ').encode()
    green = {'listener_started': True, 'closed_in_original_bound': True, 'owned_cleanup_completed': True}
    red = dict(green, closed_in_original_bound=False)
    raw = prefix + json.dumps(green).encode() + b'\n'
    positives = 0
    for good in [raw, b' '*4 + raw, b' '*8 + raw, raw.replace(b'\n', b'\r\n')]:
        assert owned_cleanup_marker(good, case) == green
        positives += 1
    assert owned_cleanup_marker(prefix + json.dumps(red).encode() + b'\n', case) == red
    positives += 1
    bad_values = [dict(green, extra=False), dict(green, listener_started=1), dict(green, owned_cleanup_completed=None),
                  {key: value for key, value in green.items() if key != 'listener_started'}, []]
    bad = [prefix + json.dumps(value).encode() + b'\n' for value in bad_values]
    bad += [raw + raw, b'PRIVATE ' + raw, b' '*9 + raw,
            raw.replace(b'"listener_started": true', b'"listener_started": true, "listener_started": true'),
            (namespace + '-unknown {}\n').encode(), raw + (namespace + '-unknown {}\n').encode(),
            prefix + b'x'*1025 + b'\n']
    negatives = 0
    for invalid in bad:
        try:
            owned_cleanup_marker(invalid, case)
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
    if args.case == SQLITE_CACHE_CASE:
        report.update(evidence_scope='actual-SQLite-three-query-cache-inverses-only',
            native_qualification=False, full_suite_qualification=False,
            expected_actual_bodies={'executed': 7, 'passed': 4, 'failed': 3})
    if args.case == PRIVATE_HYDRATION_CASE:
        report.update(expected_tests=list(PRIVATE_HYDRATION_TESTS), expected_runtime_count=2,
            expected_phase_counts={'baseline': {'executed': 2, 'passed': 2, 'failed': 0},
                'mutant': {'executed': 2, 'passed': 1, 'failed': 1},
                'restored': {'executed': 2, 'passed': 2, 'failed': 0}},
            selected_ignored_required=0, unselected_filtered_count='observed-nonnegative-from-runtime-summary')
    if args.case == PRIVATE_MAINTENANCE_ORDER_CASE:
        report.update(evidence_scope='real-private-MLS-maintenance-PendingPublish-order-only',
            native_protocol_qualification=False, full_suite_qualification=False,
            cold_restart_qualification=False, postassert_mutant_cleanup_proven=False)
    if args.case in PRIVATE_MAINTENANCE_COHORTS:
        report.update(evidence_scope=('validated-private-MLS-hydration-retirement-only' if args.case == PRIVATE_HYDRATION_CASE else 'real-private-MLS-maintenance-call-necessity-only'),
            native_protocol_qualification=False, full_suite_qualification=False,
            pending_publish_gate_mutation_qualified=False, cold_restart_qualification=False)
    if args.case == PRIVATE_SEND_CASE:
        report.update(evidence_scope='real-private-MLS-generic-send-admission-single-mutation-only',
            native_protocol_qualification=False, full_suite_qualification=False,
            successful_rollback_on_mutant_proven=False, existing_queued_work_recovery_qualified=False)
    if args.case == MUTATION_ADMISSION_CASE:
        report.update(evidence_scope='actual-runtime-edit-admission-scripted-transport-single-mutation-only',
            scripted_transport_only=True, actual_sdk_relay_qualification=False,
            native_protocol_qualification=False, apple_native_acceptance=False,
            native_host_ui_acceptance=False, full_suite_qualification=False,
            expected_runtime_count=1,
            expected_phase_counts={'baseline': {'executed': 1, 'passed': 1, 'failed': 0},
                'mutant': {'executed': 1, 'passed': 0, 'failed': 1},
                'restored': {'executed': 1, 'passed': 1, 'failed': 0}})
    if args.case == AUTOMATIC_SCAN_EXPIRY_CASE:
        report.update(evidence_scope='real-App-held-roster-scan-expiry-single-mutation-only',
            native_protocol_qualification=False, apple_native_acceptance=False,
            full_suite_qualification=False)
    if args.case in PRIVATE_ROLE_PFP_CASES:
        report.update(evidence_scope='real-SDK-private-family-role-single-mutation-only',
            native_protocol_qualification=False, full_suite_qualification=False)
    if args.case == MISSING_ROUTE_CASE:
        report.update(evidence_scope='existing-real-SDK-missing-route-freshness-revocation-only',
            native_protocol_qualification=False, teardown_on_mutant_proven=False,
            separate_wire_operands_exported=False)
    if args.case in LIVE_SEAL_CASES:
        report.update(evidence_scope='real-in-flight-spill-cursor-fence-only',
                      package='transport-nostr', binary='transport_nostr',
                      native_protocol_qualification=False, historical_full_failure_cause_proven=False)
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
    if args.case in OWNED_CLEANUP_NAMESPACES:
        report.update(evidence_scope='owned-mock-relay-cleanup-mechanism-only', native_protocol_qualification=False)
        if args.case == WATCH_CLEANUP_CASE:
            report.update(evidence_scope='actual-watch-owned-loopback-stop-omission-only',
                apple_native_acceptance=False, full_suite_qualification=False)
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
    def phase(label, expected, *, case=None, mutation=None):
        phase_case = args.case if case is None else case
        if case is not None and (args.case != 'command-backlog' or case != 'command-backlog-held' or label not in {'baseline-held', 'restored-held'}):
            raise ValueError('phase-case-scope')
        if snapshot() != expected:
            raise ValueError('phase-source')
        row = {'phase': label, 'case': phase_case, 'inventory_attempted': True,
               'source_manifest_sha256': hashlib.sha256(json.dumps(expected['inputs'], sort_keys=True).encode()).hexdigest()}
        if mutation is not None:
            if args.case != SQLITE_CACHE_CASE or mutation not in SQLITE_CACHE_INVERSES:
                raise ValueError('sqlite-cache-phase-mutation')
            row['mutation'] = mutation
        report['phases'].append(row)
        save()
        package = package_for(phase_case)
        flags = (['-p', package, '--test', CASES[phase_case][0]] if phase_case in QUIET_CONTRACT_CASES
                 else ['-p', package, '--lib']) + (['--features', ','.join(features)] if features else []) + ['--locked', '--profile', profile]
        selection = 'package(' + package + ') & test(=' + CASES[phase_case][1] + ')'
        if phase_case == SQLITE_CACHE_CASE:
            selection += ' & binary(=storage_sqlite)'
        if phase_case in {WATCH_CLEANUP_CASE, AUTOMATIC_SCAN_EXPIRY_CASE, MUTATION_ADMISSION_CASE}:
            selection += ' & binary(=marmot_app)'
        if phase_case in QUIET_CONTRACT_CASES:
            selection += ' & binary(=relay_limit_subscriptions)'
        if phase_case in UNIFFI_CASES:
            selection += ' & binary(=marmot_uniffi)'
        if phase_case in ENGINE_CASES:
            selection += ' & binary(=cgka_engine)'
        if phase_case in LIVE_SEAL_CASES:
            selection += ' & binary(=transport_nostr)'
        if phase_case in PRIVATE_MAINTENANCE_COHORTS:
            selection = automatic_negotiation_selection(maintenance_tests_for(phase_case), 'cgka-engine', 'cgka_engine')
        code, raw, elapsed, stderr = capture(['cargo', 'nextest', 'list'] + flags + ['--message-format', 'json', '-E', selection], 1800, separate=True)
        row['inventory'] = {'exit_code': code, 'elapsed_seconds': elapsed,
                            'stdout_sha256': hashlib.sha256(raw).hexdigest(), 'stdout_bytes': len(raw),
                            'stderr_sha256': hashlib.sha256(stderr).hexdigest(), 'stderr_bytes': len(stderr),
                            'compiler': compiler(stderr, expected['inputs'])}
        save()
        if code != 0 or row['inventory']['compiler']['header_count'] or row['inventory']['compiler']['codes']:
            raise ValueError('phase-inventory-command')
        if phase_case in FAMILY_PFP_CASES | PRIVATE_ROLE_PFP_CASES | {WATCH_CLEANUP_CASE, SQLITE_CACHE_CASE, SCOPED_REPORT_CASE, MISSING_ROUTE_CASE, AUTOMATIC_SCAN_EXPIRY_CASE, MUTATION_ADMISSION_CASE, PRIVATE_SEND_CASE, PRIVATE_MAINTENANCE_CASE, PRIVATE_HYDRATION_CASE, PRIVATE_MAINTENANCE_ORDER_CASE} and row['inventory']['compiler'] != {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}:
            raise ValueError('scoped-report-inventory-compiler')
        inventory = json.loads(raw, object_pairs_hook=unique)
        if phase_case in PRIVATE_MAINTENANCE_COHORTS:
            row['private_maintenance_inventory'] = selected_automatic_negotiation(inventory, maintenance_tests_for(phase_case), 'cgka-engine', 'cgka_engine')
        else:
            selected_case(inventory, CASES[phase_case][1])
        if phase_case in {WATCH_CLEANUP_CASE, SQLITE_CACHE_CASE, AUTOMATIC_SCAN_EXPIRY_CASE, MUTATION_ADMISSION_CASE, PRIVATE_SEND_CASE, PRIVATE_MAINTENANCE_ORDER_CASE}:
            matched_suites = [suite for suite in inventory['rust-suites'].values()
                if any(item['filter-match']['status'] == 'matches' for item in suite['testcases'].values())]
            if len(matched_suites) != 1 or matched_suites[0].get('binary-name') != CASES[phase_case][0] or matched_suites[0].get('kind') != 'lib':
                raise ValueError('one-exact-pfp-library-binary')
        row['inventory'].update(selected_nonignored=2 if phase_case in PRIVATE_MAINTENANCE_COHORTS else 1, selected_ignored=0)
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
        if phase_case in PRIVATE_MAINTENANCE_COHORTS:
            row['body']['panic'] = automatic_negotiation_panics(raw, maintenance_tests_for(phase_case))
            row['body']['private_maintenance_runtime'] = automatic_negotiation_runtime(raw, maintenance_tests_for(phase_case), 'cgka-engine')
            row['body']['counts'] = row['body']['private_maintenance_runtime']['counts']
        else:
            row['body']['counts'] = counts(raw, phase_case)
        save()
        row['source_exact_after_body'] = snapshot() == expected
        clean_compile = not row['body']['compiler']['codes'] and row['body']['compiler']['header_count'] == 0
        if phase_case in {WATCH_CLEANUP_CASE, SQLITE_CACHE_CASE, MISSING_ROUTE_CASE, AUTOMATIC_SCAN_EXPIRY_CASE, MUTATION_ADMISSION_CASE, PRIVATE_SEND_CASE, PRIVATE_MAINTENANCE_CASE, PRIVATE_HYDRATION_CASE, PRIVATE_MAINTENANCE_ORDER_CASE}:
            clean_compile = row['body']['compiler'] == {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
        watch_accepted = True
        if phase_case == SQLITE_CACHE_CASE:
            runtime = automatic_negotiation_runtime(raw, {SQLITE_CACHE_TEST: SQLITE_CACHE_PATH}, 'storage-sqlite')
            row['body']['sqlite_cache_runtime'] = runtime
            watch_accepted = runtime['complete']
            save()
        if phase_case in PRIVATE_MAINTENANCE_COHORTS:
            runtime = row['body']['private_maintenance_runtime']
            watch_accepted = (runtime['complete']
                and row['body']['panic']['unknown_or_excess_headers'] == 0
                and sorted(site['test'] for site in row['body']['panic']['sites']) == sorted(item['test'] for item in runtime['rows'] if item['outcome'] == 'FAIL'))
            save()
        if phase_case == PRIVATE_HYDRATION_CASE:
            row['body']['private_hydration_oracle'] = private_hydration_runtime(raw, label == 'mutant')
            watch_accepted = row['body']['private_hydration_oracle']['accepted']
            save()
        if phase_case == MUTATION_ADMISSION_CASE:
            row['body']['mutation_admission_probe'] = mutation_admission_probe(raw)
            save()  # Counts/compiler/actual command facts preceded strict decoding.
            runtime = automatic_negotiation_runtime(raw,
                {MUTATION_ADMISSION_TEST: MUTATION_ADMISSION_PATH})
            row['body']['mutation_admission_runtime'] = runtime
            expected_counts = dict(executed=1, passed=int(label != 'mutant'),
                failed=int(label == 'mutant'), skipped=row['body']['counts']['skipped'])
            watch_accepted = (all(row['body']['mutation_admission_probe'].values())
                and runtime['complete'] and runtime['counts'] == expected_counts
                and row['body']['counts'] == expected_counts)
            save()
        if phase_case == AUTOMATIC_SCAN_EXPIRY_CASE:
            row['body']['automatic_scan_expiry_probe'] = automatic_scan_expiry_probe(raw)
            probe = row['body']['automatic_scan_expiry_probe']
            watch_accepted = (all(probe[key] is True for key in AUTOMATIC_SCAN_EXPIRY_PREREQUISITES)
                              and probe['expired_scan_rejected'] is (label != 'mutant'))
            save()
        if phase_case in PRIVATE_ROLE_PFP_CASES:
            row['body']['private_role_probe'] = private_role_probe(raw, phase_case)
            watch_accepted = private_role_pfp_ready(row['body']['private_role_probe'], phase_case, mutant=label == 'mutant')
            clean_compile = row['body']['compiler'] == {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
            save()
        if phase_case in FAMILY_PFP_CASES:
            row['body']['family_stability_probe'] = family_stability_probe(raw)
            watch_accepted = family_pfp_ready(row['body']['family_stability_probe'], phase_case, mutant=label == 'mutant')
            clean_compile = row['body']['compiler'] == {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
            save()
        if phase_case == SCOPED_REPORT_CASE:
            row['body']['scoped_report_probe'] = scoped_report_probe(raw)
            watch_accepted = scoped_report_ready(row['body']['scoped_report_probe'], mutant=label == 'mutant')
            clean_compile = row['body']['compiler'] == {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
            save()
        if args.case in QUIET_CONTRACT_CASES:
            row['body']['quiet_contract_observation'] = quiet_contract_observe(raw, site)
            save()
            watch_accepted = (quiet_contract_red(row['body'], row['inventory']) if label == 'mutant'
                              else quiet_contract_complete(row['body']['quiet_contract_observation']))
            row['quiet_prerequisites_accepted'] = watch_accepted
            save()
        if args.case in CURSOR_CASES:
            row['body']['cursor_panic_facts'] = cursor_failure_facts(raw, phase_case, site)
            save()
            row['body']['fixture_observation'] = fixture_observation(raw, phase_case)
            watch_accepted = cursor_pfp_oracle(row['body']['fixture_observation'], label == 'mutant')
            row['cursor_prerequisites_accepted'] = watch_accepted
            save()
        if args.case in OWNED_CLEANUP_NAMESPACES:
            row['body']['owned_cleanup_observation'] = owned_cleanup_marker(raw, args.case)
            watch_accepted = owned_cleanup_oracle(row['body']['owned_cleanup_observation'], label == 'mutant')
            if args.case == WATCH_CLEANUP_CASE:
                runtime = automatic_negotiation_runtime(raw, {WATCH_CLEANUP_TEST: WATCH_CLEANUP_PATH})
                row['body']['watch_cleanup_runtime'] = runtime
                watch_accepted = watch_accepted and runtime['complete']
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
            if phase_case == WATCH_CLEANUP_CASE:
                row['own_runtime_failure'] = owned_cleanup_runtime_failure(raw, phase_case, site)
            row['accepted'] = (code == 100 and row['body']['counts']['failed'] == (2 if phase_case == PRIVATE_MAINTENANCE_CASE else 1)
                               and clean_compile and watch_accepted and row['own_runtime_failure']
                               and row['source_exact_after_body'])
        else:
            row['accepted'] = (code == 0 and row['body']['counts']['passed'] == (2 if phase_case in PRIVATE_MAINTENANCE_COHORTS else 1) and clean_compile and watch_accepted
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
        if args.case == SQLITE_CACHE_CASE:
            checked_path, checked_original, sqlite_mutants, checked_site = sqlite_cache_inverses()
            if (checked_path, checked_original, checked_site) != (path, original, site):
                raise ValueError('sqlite-cache-inverse-recheck')
            report['sqlite_mutations'] = [{'function': name, 'mutant_sha256': hashlib.sha256(data).hexdigest()} for name, data in sqlite_mutants]
        admitted_parents = parent_chain(path)
        report['mutated_source'] = {'path': path, 'original_sha256': hashlib.sha256(original).hexdigest(),
                                    'mutant_sha256': hashlib.sha256(mutant).hexdigest(), 'own_assert_site': site}
        if args.case in QUIET_CONTRACT_CASES:
            report['quiet_inverse_controls'] = quiet_inverse_controls(Path(path).read_text(), QUIET_GREEN_CALL, QUIET_OLD_CALL)
        report['parser_controls'] = controls()
        report['own_oracle_controls'] = pfp_controls(args.case, site)
        if args.case in QUIET_CONTRACT_CASES:
            report['quiet_contract_parser_controls'] = quiet_contract_controls(site)
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
            mutations = sqlite_mutants if args.case == SQLITE_CACHE_CASE else [(None, mutant)]
            for mutation_name, mutant_bytes in mutations:
                try:
                    stage = 'mutant'
                    write_source(path, mutant_bytes, mode)
                    expected = json.loads(json.dumps(before))
                    expected['inputs'][path]['sha256'] = hashlib.sha256(mutant_bytes).hexdigest()
                    expected['tracked_clean'] = False
                    phase('mutant', expected, mutation=mutation_name)
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
                phase('restored', before, mutation=mutation_name)
                if primary_failure is not None:
                    break
            if args.case == 'command-backlog':
                phase('restored-held', before, case='command-backlog-held')
            expected_phase_total = 7 if args.case == SQLITE_CACHE_CASE else 5 if args.case == 'command-backlog' else 3
            report['pfp_passed'] = (primary_failure is None and len(report['phases']) == expected_phase_total
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


LATE_COMMIT_STAGE_PREFIX = 'late-commit-stage '
LATE_COMMIT_STAGE_STATES = {'sent', 'created', 'processed', 'failed', 'retryable',
    'convergence-deferred', 'peel-deferred', 'epoch-invalidated', 'absent'}
LATE_COMMIT_STAGE_FIELDS = {'schema', 'after_timed_verdict', 'atomic_snapshot',
    'sender_scan_complete', 'sender_binding_count', 'original_outer_only',
    'raw_state', 'inner_state', 'expected_pending_app_event', 'pending_app_probe_available',
    'active_pass', 'deferred_peel_generation', 'parked_commit',
    'projection_present', 'projection_invalidated'}


def late_commit_stage_marker(raw):
    # A passive, closed observation only. It never changes the actual body verdict.
    if type(raw) is not bytes or len(raw) > 2 * 1024 * 1024:
        raise ValueError('late-stage-output-bound')
    text = ANSI.sub('', raw.decode('utf-8', errors='strict')).replace('\r\n', '\n')
    lines = [line for line in text.splitlines() if LATE_COMMIT_STAGE_PREFIX in line]
    if len(lines) != 1 or text.count(LATE_COMMIT_STAGE_PREFIX) != 1 or len(lines[0].encode()) > 4096:
        raise ValueError('late-stage-cardinality-bound')
    match = re.fullmatch(r'[ \t]{0,8}' + re.escape(LATE_COMMIT_STAGE_PREFIX)
        + r'(\{[^\r\n]*\})[ \t]{0,8}', lines[0])
    if match is None:
        raise ValueError('late-stage-envelope')
    value = json.loads(match[1], object_pairs_hook=unique)
    if type(value) is not dict or set(value) != LATE_COMMIT_STAGE_FIELDS:
        raise ValueError('late-stage-fields')
    if (type(value['schema']) is not int or value['schema'] != 1
            or value['after_timed_verdict'] is not True or value['atomic_snapshot'] is not False
            or value['original_outer_only'] is not True
            or value['pending_app_probe_available'] is not False
            or value['expected_pending_app_event'] is not None):
        raise ValueError('late-stage-scope')
    if (type(value['sender_scan_complete']) is not bool
            or type(value['sender_binding_count']) is not int
            or not 0 <= value['sender_binding_count'] <= 64):
        raise ValueError('late-stage-binding')
    for key in ('raw_state', 'inner_state'):
        if value[key] is not None and (type(value[key]) is not str or value[key] not in LATE_COMMIT_STAGE_STATES):
            raise ValueError('late-stage-state')
    for key in ('active_pass', 'deferred_peel_generation', 'parked_commit',
                'projection_present', 'projection_invalidated'):
        if value[key] is not None and type(value[key]) is not bool:
            raise ValueError('late-stage-tristate')
    if ((not value['sender_scan_complete'] or value['sender_binding_count'] != 1)
            and value['inner_state'] is not None):
        raise ValueError('late-stage-inner-unavailable')
    if ((value['projection_present'] is not True and value['projection_invalidated'] is not None)
            or (value['projection_present'] is True and type(value['projection_invalidated']) is not bool)):
        raise ValueError('late-stage-projection-unavailable')
    return value


def late_commit_stage_controls():
    def encode(value):
        return (LATE_COMMIT_STAGE_PREFIX + json.dumps(value) + '\n').encode()
    value = dict.fromkeys(LATE_COMMIT_STAGE_FIELDS, None)
    value.update(schema=1, after_timed_verdict=True, atomic_snapshot=False,
        sender_scan_complete=False, sender_binding_count=0, original_outer_only=True,
        expected_pending_app_event=None, pending_app_probe_available=False)
    good = [encode(value), encode(dict(value, sender_scan_complete=True,
        sender_binding_count=1, raw_state='processed', inner_state='created',
        active_pass=True, deferred_peel_generation=False, parked_commit=True,
        projection_present=True, projection_invalidated=False)),
        encode(dict(value, sender_scan_complete=True, sender_binding_count=64,
                    raw_state='absent', projection_present=False))]
    good.extend(encode(dict(value, sender_scan_complete=True, sender_binding_count=1,
                            inner_state=state)) for state in sorted(LATE_COMMIT_STAGE_STATES))
    good.extend([b' ' * 8 + good[0], b'\t' * 8 + good[0]])
    for raw in good:
        assert set(late_commit_stage_marker(raw)) == LATE_COMMIT_STAGE_FIELDS
    invalid = [b'', good[0] + good[0], b'PRIVATE ' + good[0], b' ' * 9 + good[0],
        good[0].replace(b'{', b'{"schema":1,', 1),
        encode(dict(value, private='PRIVATE')), encode({key:item for key,item in value.items() if key != 'parked_commit'}),
        encode(dict(value, schema=True)), encode(dict(value, schema=2)),
        encode(dict(value, after_timed_verdict=False)), encode(dict(value, atomic_snapshot=True)),
        encode(dict(value, original_outer_only=False)),
        encode(dict(value, pending_app_probe_available=True)),
        encode(dict(value, expected_pending_app_event=False)),
        encode(dict(value, expected_pending_app_event=True)),
        encode(dict(value, sender_scan_complete=1)),
        encode(dict(value, sender_binding_count=True)), encode(dict(value, sender_binding_count=-1)),
        encode(dict(value, sender_binding_count=65)), encode(dict(value, sender_binding_count=1.0)),
        encode(dict(value, raw_state='PRIVATE')), encode(dict(value, raw_state=1)),
        encode(dict(value, inner_state='processed')),
        encode(dict(value, sender_scan_complete=True, sender_binding_count=2, inner_state='processed')),
        encode(dict(value, projection_invalidated=False)),
        encode(dict(value, projection_present=False, projection_invalidated=False)),
        encode(dict(value, projection_present=True)), b'\xff' + good[0],
        b'x' * (2 * 1024 * 1024 + 1),
        (LATE_COMMIT_STAGE_PREFIX + '{"private":"' + 'x' * 4096 + '"}\n').encode()]
    invalid.extend(encode(dict(value, **{key:0})) for key in (
        'active_pass', 'deferred_peel_generation', 'parked_commit',
        'projection_present', 'projection_invalidated'))
    for raw in invalid:
        try:
            late_commit_stage_marker(raw)
        except (ValueError, UnicodeError):
            continue
        raise AssertionError('late-stage-negative-control')
    return {'positive':len(good), 'negative':len(invalid),
            'synthetic_metadata_only':True, 'product_bodies':0}


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
    if case == SQLITE_CACHE_CASE:
        return [], 'm5-bounded', None
    if case in LIVE_SEAL_CASES:
        return ((['test-policy-overrides', 'experimental-device-sync'], 'm5-bounded', '4194304')
                if case == 'live-seal-spill-experimental' else (['test-policy-overrides'], 'ci', None))
    if case in ENGINE_CASES:
        return ENGINE_FEATURES, 'ci', None
    if case in UNIFFI_CASES:
        return UNIFFI_FEATURES, 'm5-bounded', '4194304'
    features = (['test-policy-overrides', 'cgka-engine/test-policy-overrides', 'cgka-engine/test-crash-hooks'] if case in SELECTIVE_CASES else
                ['sdk', 'test-policy-overrides'] if case in {'adapter-thousand-default', QUIET_DEFAULT_CASE, 'adapter-clamped-default'} else
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
    if args.case in AUTOMATIC_NATIVE_CASES:
        report.update(evidence_scope='scoped-real-App-automatic-negotiation-only',
                      native_protocol_qualification=False, apple_native_acceptance=False,
                      full_suite_qualification=False, mutation_qualification=False)
        if args.case == AUTOMATIC_NEGOTIATION_CASE:
            del report['expected_test']
            report['expected_tests'] = list(AUTOMATIC_NEGOTIATION_TESTS)
            report['expected_runtime_count'] = len(AUTOMATIC_NEGOTIATION_TESTS)
    if args.case == WATCH_HELD_CASE:
        report.update(evidence_scope='actual-Rust-SDK-held-peer-proof-eight-watch-counterpart-only',
                      native_protocol_qualification=False, apple_native_acceptance=False,
                      full_suite_qualification=False, mutation_qualification=False)
    if args.case == FOUR_DEVICE_MUTATIONS_CASE:
        report.update(evidence_scope='real-Rust-SDK-four-device-message-mutations-and-disk-reopen-only',
                      apple_native_acceptance=False, native_host_ui_acceptance=False,
                      public_relay_qualification=False, full_suite_qualification=False,
                      mutation_qualification=False)
    if args.case == WATCH_CLEANUP_CASE:
        report.update(evidence_scope='actual-watch-owned-loopback-cleanup-only',
                      native_protocol_qualification=False, apple_native_acceptance=False,
                      full_suite_qualification=False, mutation_qualification=False)
    if args.case == MUTATION_ADMISSION_CASE:
        report.update(evidence_scope='actual-runtime-edit-admission-scripted-transport-only',
                      scripted_transport_only=True, actual_sdk_relay_qualification=False,
                      native_protocol_qualification=False, apple_native_acceptance=False,
                      native_host_ui_acceptance=False, full_suite_qualification=False,
                      mutation_qualification=False)
    if args.case in PRIVATE_MAINTENANCE_COHORTS:
        report.pop('expected_test')
        report.update(expected_tests=list(maintenance_tests_for(args.case)), expected_runtime_count=2,
                      evidence_scope=('validated-private-MLS-hydration-retirement-only' if args.case == PRIVATE_HYDRATION_CASE else 'real-private-MLS-legacy-maintenance-recovery-only'),
                      native_protocol_qualification=False, full_suite_qualification=False,
                      retained_queue_recovery_qualification=False)
    if args.case == PRIVATE_SEND_CASE:
        report.update(evidence_scope='real-private-MLS-generic-send-queue-admission-only',
                      native_protocol_qualification=False, full_suite_qualification=False,
                      existing_queued_work_recovery_qualified=False)
    if args.case == 'late-commit-extra-epoch':
        report.update(evidence_scope='valid-real-extra-epoch-history-scenario-only',
                      native_protocol_qualification=False, original_full_failure_cause_established=False,
                      mutation_necessity_claimed=False)
    if args.case in LIVE_SEAL_CASES:
        report.update(evidence_scope='real-in-flight-spill-cursor-fence-only',
                      package='transport-nostr', binary='transport_nostr',
                      native_protocol_qualification=False, historical_full_failure_cause_proven=False)
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

    if args.case in PRIVATE_ROLE_CASES:
        report.update(evidence_scope='real-SDK-private-family-role-component-only',
                      native_protocol_qualification=False, full_suite_qualification=False,
                      mutation_qualification=False, behavioral_red_qualified=False)
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
        if args.case == SQLITE_CACHE_CASE:
            sqlite_site = sqlite_cache_site()
            report['sqlite_cache_controls'] = sqlite_cache_controls(sqlite_site)
            report['evidence_scope'] = 'actual-SQLite-timeline-statement-cache-only'
            report['full_suite_qualification'] = False
            report['native_qualification'] = False
        if args.case in PRIVATE_MAINTENANCE_COHORTS:
            maintenance_site = private_hydration_site() if args.case == PRIVATE_HYDRATION_CASE else private_maintenance_site()
            report['private_maintenance_controls'] = (private_hydration_controls(maintenance_site) if args.case == PRIVATE_HYDRATION_CASE else private_maintenance_controls(maintenance_site))
        if args.case == PRIVATE_SEND_CASE:
            private_send_source_site = private_send_site()
            report['private_send_controls'] = private_send_controls(private_send_source_site)
        if args.case == AUTOMATIC_NEGOTIATION_CASE:
            report['automatic_negotiation_controls'] = automatic_negotiation_controls()
        if args.case in AUTOMATIC_SCAN_EXPIRY_CASES:
            expiry_site = automatic_scan_expiry_site()
            report['automatic_scan_expiry_controls'] = automatic_scan_expiry_controls(expiry_site)
        if args.case in LIVE_SEAL_CASES:
            fixture = Path(CASES[args.case][2]).read_text()
            validate_live_seal_fixture(fixture)
            report['live_seal_controls'] = live_seal_controls(args.case, live_seal_site(fixture))
        if args.stage == 'sample':
            if args.case != 'sibling-send-experimental':
                raise ValueError('sample-case')
            report['sample_parser_controls'] = sample_controls()
        if args.case in FIXTURE_OBSERVATION_BASES:
            report['fixture_observation_controls'] = fixture_observation_controls()
        if args.case in {'sibling-send-default', 'sibling-send-experimental'}:
            report['sibling_send_parser_controls'] = sibling_send_controls()
            report['sibling_worker_parser_controls'] = sibling_worker_controls()
            report['sibling_transition_parser_controls'] = sibling_transition_controls()
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
            report['late_commit_stage_parser_controls'] = late_commit_stage_controls()
        if args.case == 'late-commit-extra-epoch':
            report['extra_epoch_parser_controls'] = extra_epoch_controls()
        if args.case in OFFLINE_CASES:
            report['fingerprint_parser_controls'] = fingerprint_controls()
            report['body_resource_controls'] = resource_controls()
        if args.case in SDK_REPLAY_CASES:
            report['sdk_replay_parser_controls'] = sdk_replay_controls()
        if args.case in CLAMPED_CASES:
            report['adapter_exit_parser_controls'] = adapter_exit_controls()
        if args.case in QUIET_CONTRACT_CASES:
            report['quiet_contract_parser_controls'] = quiet_contract_controls(quiet_contract_site())
        if args.case == 'fresh-rejoin-observation':
            report['fresh_rejoin_parser_controls'] = fresh_rejoin_controls()
        if args.case == 'watch-pressure':
            report['watch_parser_controls'] = watch_controls()
        if args.case in {'higher-source', PENDING_REQUEST_CASE}:
            report['restart_parser_controls'] = restart_controls()
        if args.case == PENDING_REQUEST_CASE:
            report['pending_request_parser_controls'] = pending_request_controls(pending_request_sites())
        if args.case == MUTATION_ADMISSION_CASE:
            mutation_admission_source_site = mutation_admission_site()
            report['mutation_admission_controls'] = mutation_admission_controls(mutation_admission_source_site)
        if args.case == WATCH_CLEANUP_CASE:
            watch_cleanup_site = owned_cleanup_site(WATCH_CLEANUP_CASE)
            report['watch_cleanup_controls'] = watch_cleanup_controls(watch_cleanup_site)
        if args.case == FOUR_DEVICE_MUTATIONS_CASE:
            report['four_device_diagnostic_controls'] = four_device_diagnostic_controls(four_device_diagnostic_site())
        if args.case == FAMILY_STABILITY_CASE:
            report['family_stability_controls'] = family_stability_controls(family_stability_site())
        if args.case in PRIVATE_ROLE_CASES:
            report['private_role_controls'] = private_role_controls(args.case)
        if args.case == 'sdk-private-role-transition':
            report['private_role_registry_controls'] = private_role_registry_controls()


        if args.case in FAMILY_PFP_CASES:
            report['family_pfp_controls'] = family_pfp_controls(args.case, family_stability_site())
        if args.case == 'sdk-scoped-reporting':
            report['scoped_report_probe_controls'] = scoped_report_probe_controls()
        if args.case == SCOPED_REPORT_CASE:
            fixture = Path(CASES[args.case][2]).read_text()
            found = list(re.finditer(PFP[args.case][4].replace('{message}', re.escape(SCOPED_REPORT_MESSAGE)), fixture))
            if len(found) != 1:
                raise ValueError('scoped-report-positive-source-site')
            site = {'line': fixture[:found[0].start()].count('\n') + 1,
                    'column': found[0].start() - fixture.rfind('\n', 0, found[0].start())}
            report['scoped_report_controls'] = scoped_report_controls(site)
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
            flags += (['--features', ','.join(features)] if features else []) + ['--locked', '--profile', profile]
            selection = 'package(' + package + ') & test(=' + test + ')'
            if args.case in INTEGRATION_CASES or args.case in UNIFFI_CASES or args.case in ENGINE_CASES or args.case in LIVE_SEAL_CASES:
                selection += ' & binary(=' + binary + ')'
            if args.case == SQLITE_CACHE_CASE:
                selection += ' & binary(=storage_sqlite)'
            if args.case == AUTOMATIC_NEGOTIATION_CASE:
                selection = automatic_negotiation_selection()
            if args.case in AUTOMATIC_SCAN_EXPIRY_CASES | {WATCH_CLEANUP_CASE, WATCH_HELD_CASE, FOUR_DEVICE_MUTATIONS_CASE, MUTATION_ADMISSION_CASE}:
                selection += ' & binary(=marmot_app)'
            if args.case in PRIVATE_MAINTENANCE_COHORTS:
                selection = automatic_negotiation_selection(maintenance_tests_for(args.case), 'cgka-engine', 'cgka_engine')
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
            if args.case in AUTOMATIC_NATIVE_CASES | {SQLITE_CACHE_CASE, PRIVATE_SEND_CASE, PRIVATE_MAINTENANCE_CASE, PRIVATE_HYDRATION_CASE} and report['inventory']['compiler'] != {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}:
                raise ValueError('automatic-native-inventory-compiler')
            if args.case in PRIVATE_MAINTENANCE_COHORTS:
                report['private_maintenance_inventory'] = selected_automatic_negotiation(inventory, maintenance_tests_for(args.case), 'cgka-engine', 'cgka_engine')
            elif args.case == AUTOMATIC_NEGOTIATION_CASE:
                report['automatic_negotiation_inventory'] = selected_automatic_negotiation(inventory)
            elif args.case in AUTOMATIC_SCAN_EXPIRY_CASES | {WATCH_CLEANUP_CASE, WATCH_HELD_CASE, SQLITE_CACHE_CASE, PRIVATE_SEND_CASE, FOUR_DEVICE_MUTATIONS_CASE, MUTATION_ADMISSION_CASE}:
                selected_case(inventory, test)
                matched_suites = [suite for suite in inventory['rust-suites'].values()
                    if any(item['filter-match']['status'] == 'matches' for item in suite['testcases'].values())]
                if len(matched_suites) != 1 or matched_suites[0].get('binary-name') != binary or matched_suites[0].get('kind') != 'lib':
                    raise ValueError('exact-library-binary')
            elif args.case == 'private-classifier-authentication':
                report['engine_control_inventory'] = selected_engine_bundle(inventory)
            else:
                selected_case(inventory, test)
            selection = body_selection
            if args.case in OFFLINE_CASES:
                report['compiled_fingerprints'] = fingerprint_snapshot(
                    inventory, test, os.environ.get('CARGO_TARGET_DIR', 'target'))
            report['inventory']['selected_nonignored'] = (2 if args.case in PRIVATE_MAINTENANCE_COHORTS else len(AUTOMATIC_NEGOTIATION_TESTS) if args.case == AUTOMATIC_NEGOTIATION_CASE else 8 if args.case == 'private-classifier-authentication' else 1)
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
            if args.case in PRIVATE_MAINTENANCE_COHORTS:
                report['body']['panic'] = automatic_negotiation_panics(raw, maintenance_tests_for(args.case))
                report['body']['private_maintenance_runtime'] = automatic_negotiation_runtime(raw, maintenance_tests_for(args.case), 'cgka-engine')
                report['body']['counts'] = report['body']['private_maintenance_runtime']['counts']
            elif args.case == AUTOMATIC_NEGOTIATION_CASE:
                report['body']['panic'] = automatic_negotiation_panics(raw)
                report['body']['automatic_negotiation_runtime'] = automatic_negotiation_runtime(raw)
                report['body']['counts'] = report['body']['automatic_negotiation_runtime']['counts']
            else:
                report['body']['counts'] = counts(raw, args.case)
            save()
            if args.case in SELECTIVE_CASES:
                # Counts/compiler facts precede this supplemental diagnostic decoder.
                # Missing/invalid observations remain unavailable, never raw log exports.
                try:
                    report['body']['late_commit_stage_observation'] = late_commit_stage_marker(raw)
                    report['body']['late_commit_stage_export_complete'] = True
                except (ValueError, UnicodeError):
                    report['body']['late_commit_stage_observation'] = None
                    report['body']['late_commit_stage_export_complete'] = False
                    report['body']['late_commit_stage_error'] = 'absent-or-invalid-fixed-observation'
                save()
            if args.case == SQLITE_CACHE_CASE:
                report['body']['sqlite_cache_runtime'] = automatic_negotiation_runtime(raw,
                    {SQLITE_CACHE_TEST: SQLITE_CACHE_PATH}, 'storage-sqlite')
                report['body']['own_runtime_failure'] = sqlite_cache_failure(raw, sqlite_site)
                save()  # Preserve actual body facts before RED interpretation.
            if args.case == MUTATION_ADMISSION_CASE:
                report['body']['mutation_admission_probe'] = mutation_admission_probe(raw)
                save()  # Original actual counts/compiler/panic survive later strict decoding.
                report['body']['mutation_admission_runtime'] = automatic_negotiation_runtime(raw,
                    {MUTATION_ADMISSION_TEST: MUTATION_ADMISSION_PATH})
                report['body']['own_runtime_failure'] = mutation_admission_failure(raw, mutation_admission_source_site)
                save()
            if args.case == WATCH_HELD_CASE:
                report['body']['watch_held_runtime'] = automatic_negotiation_runtime(raw,
                    {WATCH_HELD_TEST: WATCH_CLEANUP_PATH})
                save()
            if args.case == WATCH_CLEANUP_CASE:
                report['body']['watch_cleanup_runtime'] = automatic_negotiation_runtime(raw,
                    {WATCH_CLEANUP_TEST: WATCH_CLEANUP_PATH})
                report['body']['owned_cleanup_observation'] = owned_cleanup_marker(raw, WATCH_CLEANUP_CASE)
                report['body']['own_runtime_failure'] = owned_cleanup_runtime_failure(raw, WATCH_CLEANUP_CASE, watch_cleanup_site)
                save()
            if args.case == FOUR_DEVICE_MUTATIONS_CASE:
                # Original runtime counts/panics/compiler facts are already durable.
                # Diagnostics never alter command acceptance or reinterpret failure.
                try:
                    observation = four_device_diagnostic(raw, four_device_diagnostic_site(),
                        report['body']['counts']['failed'] == 1)
                    report['body']['four_device_diagnostic'] = observation
                    report['body']['four_device_diagnostic_complete'] = observation['complete']
                except (ValueError, UnicodeError):
                    report['body']['four_device_diagnostic'] = None
                    report['body']['four_device_diagnostic_complete'] = False
                save()
            if args.case in AUTOMATIC_SCAN_EXPIRY_CASES:
                report['body']['automatic_scan_expiry_probe'] = automatic_scan_expiry_probe(raw)
                save()
            if args.case in PRIVATE_ROLE_CASES:
                report['body']['private_role_probe'] = private_role_probe(raw, args.case)
                save()  # Actual command, compiler and exact runtime counts were already saved.
                if args.case == 'sdk-private-role-transition':
                    report['body']['private_role_registry_probe'] = private_role_registry_probe(raw)
                    report['body']['registry_probe_is_diagnostic_only'] = True
                    save()  # Never substitute current-pool observations for original verdict fields.
                if args.case == PRIVATE_ABA_CASE:
                    aba_site = private_aba_site()
                    report['body']['own_runtime_failure'] = private_aba_failure(raw, aba_site)
                    report['expected_configuration_aba_runtime_red_before_closure'] = (
                        code == 100 and report['body']['counts']['executed'] == 1
                        and report['body']['counts']['passed'] == 0
                        and report['body']['counts']['failed'] == 1
                        and report['inventory']['selected_nonignored'] == 1
                        and report['inventory']['selected_ignored'] == 0
                        and all(part['compiler'] == {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
                                for part in [report['inventory'], report['body']])
                        and report['body']['panic'] == {'sites': [{'expected_thread': True, 'expected_source': True,
                            'line': aba_site['line'], 'column': aba_site['column']}], 'unknown_or_excess_headers': 0}
                        and report['body']['own_runtime_failure'])
                    save()  # Expected behavioral RED remains a failed positive command.
            if args.case == FAMILY_STABILITY_CASE:
                report['body']['family_stability_probe'] = family_stability_probe(raw)
                report['body']['own_runtime_failure'] = family_stability_failure(raw, family_stability_site())
                report['expected_family_runtime_red_before_closure'] = (
                    code == 100 and report['body']['counts']['executed'] == 1
                    and report['body']['counts']['failed'] == 1
                    and report['inventory']['selected_nonignored'] == 1
                    and report['inventory']['selected_ignored'] == 0
                    and all(part['compiler'] == {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
                            for part in [report['inventory'], report['body']])
                    and report['body']['own_runtime_failure'])
                save()  # Exact attempted body and frozen prerequisites precede interpretation.
            if args.case == 'sdk-scoped-reporting':
                report['body']['scoped_report_probe'] = scoped_report_probe(raw)
                report['behavioral_red_qualified'] = False
                save()  # Frozen verdict/counts survive observation or later closure failures.
            if args.case == PENDING_REQUEST_CASE:
                report['body']['pending_request_panics'] = pending_request_panics(raw, pending_request_sites())
                report['behavioral_red_qualified'] = False
                save()  # Actual body/panic facts precede interpretation of the optional probe.
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
                try:
                    report['body']['sibling_worker_transitions'] = sibling_worker_transitions(ANSI.sub('', raw.decode('utf-8', errors='strict')).encode())
                    report['body']['sibling_transition_export_complete'] = True
                except (ValueError, UnicodeError):
                    report['body']['sibling_worker_transitions'] = None
                    report['body']['sibling_transition_export_complete'] = False
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
            if args.case in CLAMPED_CASES:
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
            if args.case in {'higher-source', PENDING_REQUEST_CASE}:
                stage = 'diagnostic'
                report['body']['restart_observation'] = restart_marker(raw)
                save()
            if args.case == PENDING_REQUEST_CASE:
                stage = 'diagnostic'
                if (code not in (0, 100) or report['body']['compiler'] != {'codes': [], 'header_count': 0,
                        'sites': [], 'unknown_or_excess_sites': 0}):
                    raise ValueError('pending-request-runtime-not-compiler')
                report['body']['pending_request_observation'] = pending_request_marker(raw)
                report['body']['probe_complete'] = (report['body']['pending_request_observation']['capture_available']
                    and report['body']['pending_request_observation']['counts'] is not None
                    and report['body']['pending_request_observation']['overflow'] is False)
                report['body']['original_approval_timeout_observed'] = (
                    code == 100 and report['body']['counts']['failed'] == 1
                    and report['body']['pending_request_panics']['ordered_exact_approval_timeout_and_join']
                    and report['body']['restart_observation']['approval_completed'] is False)
                report['evidence_scope'] = 'passive-exact-original-request-intake-and-replacement-only'
                report['historical_cause_proven'] = False
                save()
            command_accepted = True
            if args.case in PRIVATE_MAINTENANCE_COHORTS:
                runtime = report['body']['private_maintenance_runtime']
                command_accepted = (runtime['complete'] and all(part['compiler'] == {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
                    for part in (report['inventory'], report['body'])))
                if args.case == PRIVATE_HYDRATION_CASE:
                    report['body']['private_hydration_oracle'] = private_hydration_runtime(raw, code == 100)
                    command_accepted = command_accepted and report['body']['private_hydration_oracle']['accepted']
                report['expected_private_maintenance_runtime_red_before_closure'] = (
                    command_accepted and code == 100 and runtime['counts']['failed'] >= 1
                    and report['body']['panic']['unknown_or_excess_headers'] == 0
                    and sorted(site['test'] for site in report['body']['panic']['sites']) == sorted(row['test'] for row in runtime['rows'] if row['outcome'] == 'FAIL')
                    and any(row['test'] == next(iter(maintenance_tests_for(args.case))) and row['outcome'] == 'FAIL' for row in runtime['rows'])
                    and (private_hydration_failure(raw, maintenance_site) if args.case == PRIVATE_HYDRATION_CASE else private_maintenance_failure(raw, maintenance_site)))
            if args.case == PRIVATE_SEND_CASE:
                command_accepted = all(part['compiler'] == {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
                                       for part in (report['inventory'], report['body']))
                report['expected_private_send_runtime_red_before_closure'] = (
                    command_accepted and code == 100 and report['body']['counts']['executed'] == 1
                    and report['body']['counts']['passed'] == 0 and report['body']['counts']['failed'] == 1
                    and private_send_failure(raw, private_send_source_site))
            if args.case == SQLITE_CACHE_CASE:
                command_accepted = (report['body']['sqlite_cache_runtime']['complete']
                    and all(part['compiler'] == {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
                            for part in (report['inventory'], report['body'])))
                report['expected_sqlite_cache_runtime_red_before_closure'] = (
                    command_accepted and code == 100
                    and report['inventory']['selected_nonignored'] == 1
                    and report['inventory']['selected_ignored'] == 0
                    and report['body']['counts']['executed'] == 1
                    and report['body']['counts']['failed'] == 1
                    and report['body']['counts']['passed'] == 0
                    and report['body']['own_runtime_failure']
                    and report['body']['panic'] == {'sites': [{'expected_thread': True,
                        'expected_source': True, 'line': sqlite_site['line'], 'column': sqlite_site['column']}],
                        'unknown_or_excess_headers': 0})
            if args.case in AUTOMATIC_NATIVE_CASES:
                command_accepted = all(part['compiler'] == {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
                                       for part in (report['inventory'], report['body']))
                if args.case == AUTOMATIC_NEGOTIATION_CASE:
                    command_accepted = command_accepted and report['body']['automatic_negotiation_runtime']['complete']
                elif args.case == WATCH_HELD_CASE:
                    command_accepted = command_accepted and report['body']['watch_held_runtime']['complete']
                elif args.case == MUTATION_ADMISSION_CASE:
                    command_accepted = (command_accepted
                        and report['body']['mutation_admission_runtime']['complete']
                        and all(report['body']['mutation_admission_probe'].values()))
                    report['expected_mutation_admission_runtime_red_before_closure'] = (
                        command_accepted and code == 100
                        and report['inventory']['selected_nonignored'] == 1
                        and report['inventory']['selected_ignored'] == 0
                        and report['body']['counts'] == dict(executed=1, passed=0, failed=1,
                            skipped=report['body']['counts']['skipped'])
                        and report['body']['own_runtime_failure']
                        and report['body']['panic'] == {'sites': [{'expected_thread': True,
                            'expected_source': True, 'line': mutation_admission_source_site['line'],
                            'column': mutation_admission_source_site['column']}], 'unknown_or_excess_headers': 0})
                elif args.case in AUTOMATIC_SCAN_EXPIRY_CASES:
                    probe = report['body']['automatic_scan_expiry_probe']
                    report['expected_automatic_scan_expiry_runtime_red_before_closure'] = (
                        command_accepted and code == 100
                        and report['body']['counts'] == dict(executed=1, passed=0, failed=1, skipped=report['body']['counts']['skipped'])
                        and automatic_scan_expiry_failure(raw, expiry_site))
                    command_accepted = command_accepted and all(probe.values())
            if args.case in FAMILY_PFP_CASES:
                report['body']['family_stability_probe'] = family_stability_probe(raw)
                command_accepted = (family_pfp_ready(report['body']['family_stability_probe'], args.case)
                    and all(part['compiler'] == {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
                            for part in [report['inventory'], report['body']]))
                save()
            if args.case == FAMILY_STABILITY_CASE:
                command_accepted = all(report['body']['family_stability_probe'].values())
            if args.case in PRIVATE_ROLE_CASES:
                command_accepted = (private_role_green(report['body']['private_role_probe'], args.case)
                    and all(part['compiler'] == {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
                            for part in [report['inventory'], report['body']]))
                save()

            if args.case == SCOPED_REPORT_CASE:
                command_accepted = (scoped_report_ready(report['body']['scoped_report_probe'])
                    and all(part['compiler'] == {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
                            for part in [report['inventory'], report['body']]))
                save()
            if args.case == 'late-commit-extra-epoch':
                command_accepted = extra_epoch_oracle(report['body']['extra_epoch_observation'], report['body']['receipt_observations'])
                report['body']['extra_epoch_observation_passed'] = command_accepted
                save()
            if args.case in QUIET_CONTRACT_CASES:
                stage = 'diagnostic'
                observation = quiet_contract_observe(raw, quiet_contract_site())
                report['body']['quiet_contract_observation'] = observation
                report['body']['expected_contract_runtime_red_before_closure'] = quiet_contract_red(report['body'], report['inventory'])
                report['historical_cause_proven'] = False
                report['evidence_scope'] = 'under-page-success-expected-collector-contract-only'
                command_accepted = quiet_contract_complete(observation)
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
            if args.case == WATCH_CLEANUP_CASE:
                clean = all(part['compiler'] == {'codes': [], 'header_count': 0, 'sites': [], 'unknown_or_excess_sites': 0}
                            for part in (report['inventory'], report['body']))
                complete = report['body']['watch_cleanup_runtime']['complete']
                report['expected_watch_cleanup_runtime_red_before_closure'] = (
                    clean and complete and code == 100
                    and report['inventory']['selected_nonignored'] == 1 and report['inventory']['selected_ignored'] == 0
                    and report['body']['counts']['executed'] == 1 and report['body']['counts']['failed'] == 1
                    and report['body']['counts']['passed'] == 0 and report['body']['own_runtime_failure'])
                command_accepted = clean and complete and owned_cleanup_oracle(report['body']['owned_cleanup_observation'], False)
            stage = 'body-not-passed'
            report['body_passed'] = (command_accepted and code == 0 and report['body']['counts']['passed'] == (2 if args.case in PRIVATE_MAINTENANCE_COHORTS else len(AUTOMATIC_NEGOTIATION_TESTS) if args.case == AUTOMATIC_NEGOTIATION_CASE else 1)
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
        if args.case in QUIET_CONTRACT_CASES:
            report['expected_contract_runtime_red'] = (args.mode == 'run' and report['source_closure_exact'] is True
                and report.get('body', {}).get('expected_contract_runtime_red_before_closure') is True)
        if args.case == SQLITE_CACHE_CASE:
            report['expected_sqlite_cache_runtime_red'] = (args.mode == 'run'
                and report['source_closure_exact'] is True
                and report.get('expected_sqlite_cache_runtime_red_before_closure') is True)
        if args.case == FAMILY_STABILITY_CASE:
            report['expected_family_runtime_red'] = (args.mode == 'run' and report['source_closure_exact'] is True
                and report.get('expected_family_runtime_red_before_closure') is True)
        if args.case == PRIVATE_ABA_CASE:
            report['expected_configuration_aba_runtime_red'] = (
                args.mode == 'run' and report['source_closure_exact'] is True
                and report.get('expected_configuration_aba_runtime_red_before_closure') is True)

        if args.case in PRIVATE_MAINTENANCE_COHORTS:
            report['expected_private_maintenance_runtime_red'] = (
                args.mode == 'run' and report['source_closure_exact'] is True
                and report.get('expected_private_maintenance_runtime_red_before_closure') is True)
        if args.case == PRIVATE_SEND_CASE:
            report['expected_private_send_runtime_red'] = (
                args.mode == 'run' and report['source_closure_exact'] is True
                and report.get('expected_private_send_runtime_red_before_closure') is True)
        if args.case == MUTATION_ADMISSION_CASE:
            report['expected_mutation_admission_runtime_red'] = (
                args.mode == 'run' and report['source_closure_exact'] is True
                and report.get('expected_mutation_admission_runtime_red_before_closure') is True)
            # A genuine RED is reported truthfully as a failed positive workflow.
        if args.case in AUTOMATIC_SCAN_EXPIRY_CASES:
            report['expected_automatic_scan_expiry_runtime_red'] = (
                args.mode == 'run' and report['source_closure_exact'] is True
                and report.get('expected_automatic_scan_expiry_runtime_red_before_closure') is True)
            if args.case == AUTOMATIC_SCAN_EXPIRY_RED_CASE and args.mode == 'run':
                report['body_passed'] = False
                result = 1
                if report['expected_automatic_scan_expiry_runtime_red']:
                    report['failure_category'] = 'expected-own-runtime-red'
        if args.case == WATCH_CLEANUP_CASE:
            report['expected_watch_cleanup_runtime_red'] = (args.mode == 'run' and report['source_closure_exact'] is True
                and report.get('expected_watch_cleanup_runtime_red_before_closure') is True)
        report['preflight_passed'] = args.mode == 'preflight' and result == 0
        report['scoped_control_passed'] = args.mode == 'run' and result == 0 and args.case != AUTOMATIC_SCAN_EXPIRY_RED_CASE
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
                             worker=body.get('sibling_worker_observation'),
                             transitions=body.get('sibling_worker_transitions'))
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
    if args.case == WATCH_HELD_CASE and args.stage != 'positive':
        raise ValueError('watch-held-positive-only')
    if args.case == WATCH_CLEANUP_CASE and args.stage not in {'positive', 'pfp'}:
        raise ValueError('watch-cleanup-positive-or-pfp-only')
    if args.case == SQLITE_CACHE_CASE and args.stage not in {'positive', 'pfp'}:
        raise ValueError('sqlite-cache-positive-or-pfp-only')
    if args.case == PENDING_REQUEST_CASE:
        pending_request_stage(args.stage)
    if args.case in QUIET_CONTRACT_CASES:
        quiet_contract_stage(args.stage)
    if (args.case in AUTOMATIC_NATIVE_CASES and args.stage != 'positive'
            and not (args.case in {WATCH_CLEANUP_CASE, AUTOMATIC_SCAN_EXPIRY_CASE, MUTATION_ADMISSION_CASE} and args.stage == 'pfp')):
        raise ValueError('automatic-native-positive-or-expiry-pfp-only')
    if args.case in PRIVATE_MAINTENANCE_COHORTS and args.stage not in {'positive', 'pfp'}:
        raise ValueError('private-maintenance-positive-or-pfp-only')
    if args.case == PRIVATE_SEND_CASE and args.stage not in {'positive', 'pfp'}:
        raise ValueError('private-send-positive-or-pfp-only')
    if args.case == PRIVATE_MAINTENANCE_ORDER_CASE and args.stage != 'pfp':
        raise ValueError('private-maintenance-order-pfp-only')
    if args.stage == 'pfp':
        return pfp(args)
    if args.stage == 'sample':
        return sample(args)
    return positive(args)


if __name__ == '__main__':
    raise SystemExit(main())
