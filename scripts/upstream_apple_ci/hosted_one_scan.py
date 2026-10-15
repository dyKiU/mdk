#!/usr/bin/env python3
"""Observe frozen one-scan calls without changing authority, commands or wait deadlines."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'native'))
import one_scan as frozen
from cross_host import GateFailure, Peer


PAIRS = []
ACTIVE = None
KNOWN_PHASES = {
    'awaitingSetup', 'awaitingPeer', 'comparisonAvailable', 'awaitingPeerVerification',
    'verificationCompleteEnrollmentPending', 'enrollmentComplete', 'cancelled', 'expired', 'failed',
    'awaitingApproval', 'approvedAwaitingPacket', 'awaitingSettlement', 'settled',
}
KNOWN_CATEGORIES = {
    'sdk-not-ready', 'sdk-stale-revision', 'sdk-closed', 'sdk-unknown-group',
    'sdk-group-removed', 'sdk-group-disbanding', 'sdk-group-repair-required',
    'sdk-forwarding-unavailable', 'sdk-runtime', 'sdk-storage-busy',
    'sdk-sharing-unsupported', 'sdk-sharing-not-ready', 'sdk-sharing-closed',
    'sdk-sharing-stale-revision', 'sdk-sharing-runtime-unavailable',
    'sdk-history-not-ready', 'sdk-history-closed', 'sdk-history-stale-revision',
    'sdk-device-revocation-unsupported', 'sdk-device-revocation-not-ready',
    'sdk-device-revocation-closed', 'sdk-device-revocation-invalid-selection',
    'sdk-device-revocation-busy', 'sdk-device-revocation-stale-revision',
    'sdk-device-revocation-runtime-unavailable', 'sdk', 'harness',
    'harness-cancelled', 'harness-decoding', 'harness-encoding', 'harness-unclassified',
    'harness-uniffi-bufferOverflow', 'harness-uniffi-incompleteData',
    'harness-uniffi-unexpectedOptionalTag', 'harness-uniffi-unexpectedEnumCase',
    'harness-uniffi-unexpectedNullPointer', 'harness-uniffi-unexpectedRustCallStatusCode',
    'harness-uniffi-unexpectedRustCallError', 'harness-uniffi-unexpectedStaleHandle',
    'harness-uniffi-rustPanic', 'harness-uniffi-unclassified',
    'harness-uniffi-rustPanic-no-tokio-runtime',
}


def safe_phase(value):
    return value if value in KNOWN_PHASES else 'unclassified-phase'


def safe_failure(error):
    message = str(error)
    category = next((name for name in sorted(KNOWN_CATEGORIES, key=len, reverse=True)
                     if message.endswith('-' + name)), None)
    # The derived Swift agent emits a fixed UniFFI case or numeric Foundation
    # classification. Never retain associated SDK error text or peer payloads.
    derived = re.search(r'-(harness-foundation-(?:NSCocoaErrorDomain|NSPOSIXErrorDomain|NSURLErrorDomain)--?[0-9]{1,12})$', message)
    if derived:
        category = derived[1]
    if message.startswith('pairing-timeout-'):
        kind = 'pairing-timeout'
    elif message.startswith('pairing-terminal-before-'):
        kind = 'terminal-pairing-phase'
    elif message.startswith('agent-'):
        kind = 'native-agent-error'
    else:
        kind = 'controller-refusal'
    return {'kind': kind, 'native_category': category}


class ObservedPeer(Peer):
    def __init__(self, command, error_log):
        super().__init__(command, error_log)
        self.diagnostic_cohort = error_log.parent.name if error_log.parent.name in {'forward', 'reverse'} else 'unknown'

    def ask(self, command, **fields):
        role = ACTIVE['_roles'].get(id(self)) if ACTIVE else None
        try:
            value = super().ask(command, **fields)
        except GateFailure as error:
            if role:
                record = ACTIVE['originals'][role]
                record['last_native_error'] = safe_failure(error)
                record['last_native_error']['expected_probe_refusal'] = (
                    command == 'one-scan-share' and str(error).endswith('-sdk-not-ready')
                    or command == 'approval-share' and str(error).endswith('-sdk-stale-revision'))
                # Comparison-denial probes intentionally produce not-ready.
                record['last_error_command'] = command if command in {
                    'snapshot', 'approval-pending', 'approval-snapshot', 'approval-share',
                    'one-scan-share', 'confirm', 'one-scan-begin', 'one-scan-approve',
                } else 'other-command'
            raise
        if role and isinstance(value, dict):
            record = ACTIVE['originals'][role]
            if command in {'snapshot', 'approval-snapshot'}:
                name = 'last_phase' if command == 'snapshot' else 'last_approval_phase'
                phase = safe_phase(value.get('phase'))
                if record.get(name) != phase:
                    record['phase_change_count'] += 1
                record[name] = phase
            if command == 'approval-pending':
                count = value.get('count')
                if type(count) is int and 0 <= count <= 128:
                    record['pending_approval_count'] = count
        return value


original_pair, original_wait = frozen.pair, frozen.wait_phase


def observed_pair(display, scanner, target=None, existing=None):
    global ACTIVE
    roles = {'display': display, 'scanner': scanner}
    if existing is not None:
        roles['existing_approver'] = existing
    record = {'ordinal': len(PAIRS) + 1, 'cohort': display.diagnostic_cohort,
              'scope': 'third-device-enrollment' if existing is not None else 'initial-enrollment',
              'originals': {name: {'phase_change_count': 0, 'pending_approval_count': None,
                                   'last_native_error': None} for name in roles},
              'waits': [], 'completed': False,
              '_roles': {id(peer): name for name, peer in roles.items()}}
    PAIRS.append(record)
    ACTIVE = record
    try:
        result = original_pair(display, scanner, target=target, existing=existing)
        record['completed'] = True
        return result
    except GateFailure as error:
        record['failure'] = safe_failure(error)
        raise
    finally:
        record.pop('_roles')
        ACTIVE = None


def observed_wait(peer, phase, timeout=90):
    # Call the original implementation with precisely its requested deadline.
    # No additional snapshot, pending-approval or mutation command is issued.
    record = {'original': ACTIVE['_roles'].get(id(peer), 'unknown'),
              'expected_phase': safe_phase(phase), 'deadline_seconds': timeout,
              'completed': False}
    ACTIVE['waits'].append(record)
    started = time.monotonic()
    try:
        result = original_wait(peer, phase, timeout=timeout)
        record['completed'] = True
        return result
    except GateFailure as error:
        record['failure'] = safe_failure(error)
        raise
    finally:
        record['elapsed_seconds'] = round(time.monotonic() - started, 3)


def main():
    # Remove only this adapter-owned argument before invoking the frozen CLI.
    provenance_index = sys.argv.index('--agent-provenance')
    provenance_path = Path(sys.argv[provenance_index + 1])
    provenance_bytes = provenance_path.read_bytes()
    provenance = json.loads(provenance_bytes)
    if provenance['frozen_workspace_commit'] != '3048d444ffe681fbae2dc1fb8e4f49d2a1c14372':
        raise ValueError('Unexpected diagnostic agent source cohort')
    del sys.argv[provenance_index:provenance_index + 2]
    frozen.Peer = ObservedPeer
    frozen.pair = observed_pair
    frozen.wait_phase = observed_wait
    status = frozen.main()
    # The frozen CLI already validates this explicit fresh output argument.
    output = Path(sys.argv[sys.argv.index('--output') + 1]) / 'result.json'
    result = json.loads(output.read_text())
    result['phase_diagnostics'] = PAIRS
    result['diagnostic_adapter_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result['frozen_controller_sha256'] = hashlib.sha256((HERE / 'native/one_scan.py').read_bytes()).hexdigest()
    result['derived_agent_source'] = provenance
    result['derived_agent_provenance_sha256'] = hashlib.sha256(provenance_bytes).hexdigest()
    result['diagnostic_scope'] = 'Observed original commands only; no additional authority acquisition or changed waits.'
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return status


if __name__ == '__main__':
    raise SystemExit(main())
