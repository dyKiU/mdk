#!/usr/bin/env python3
"""Separate genuine current-factory public mode; original frozen routes remain unchanged."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import hosted_one_scan as observed
from one_scan import (wait_phase, denied_share, approve_existing_device, capture_current_phases,
                      exact_mirror, direct_lookup, eventually, confirmed, accept)
from cross_host import GateFailure, require

IDENTITY = 'current-automatic-factories-public-existing-roster-v1'

def current_pair(display, scanner, target=None, existing=None):
    # This is the only cross-device artifact transported by the controller.
    require(target is None, 'current-factory-never-accepts-manual-target')
    bootstrap = display.ask('current-auto-begin')['packet']
    raw = base64.b64decode(bootstrap, validate=True)
    prefix = b'WNPAIR2:' if existing is not None else b'WNPAIR1:'
    require(len(raw) <= 1024 and raw.startswith(prefix), 'actual-current-factory-bootstrap-role')
    scanner.ask('current-auto-scan', packet=bootstrap)
    del raw
    del bootstrap
    a = observed.frozen.wait_phase(display, 'comparisonAvailable')
    b = observed.frozen.wait_phase(scanner, 'comparisonAvailable')
    require(a.get('comparison') and a['comparison'] == b.get('comparison'), 'independent-comparison-mismatch')
    denied_share(display)
    display.ask('confirm', revision=a['revision'])
    denied_share(display)
    b = observed.frozen.wait_phase(scanner, 'comparisonAvailable')
    require(b.get('comparison') == a['comparison'], 'comparison-changed-before-second-confirmation')
    scanner.ask('confirm', revision=b['revision'])
    for peer in (display, scanner):
        observed.frozen.wait_phase(peer, 'verificationCompleteEnrollmentPending')
    for peer in (display, scanner):
        value = peer.ask('snapshot')
        peer.ask('one-scan-share', revision=value['revision'])
    if existing is not None:
        approve_existing_device(existing, display, scanner)
    try:
        for peer in (display, scanner):
            observed.frozen.wait_phase(peer, 'enrollmentComplete')
    except GateFailure:
        capture_current_phases(display, scanner, existing)
        raise
    return dict(factory_identity=IDENTITY, bootstrap_kind="wnpair2" if existing is not None else "wnpair1",
                single_bootstrap=True, automatic_encrypted_exchange=True,
                both_comparisons_required=True, explicit_bilateral_sharing=True)


def current_third_device_chats(a, b, third, contact, target, group, text, event, direct_observations=None):
    exact_mirror(b, group, text, event)
    if direct_observations is not None:
        direct_lookup(b, group, target, 'second-after-pairing', direct_observations)
    a.ask('cancel')
    b.ask('cancel')
    targets = a.ask('targets')
    require(len(targets) == 1 and targets[0]['device_count'] == 2,
            'third-device-needs-existing-two-device-target')
    enrollment = observed.frozen.pair(a, third, existing=b)
    require(enrollment['bootstrap_kind'] == 'wnpair2', 'genuine-existing-display-fresh-scan-required')
    for peer in (a, b, third):
        eventually(lambda p=peer: p.ask('targets'),
                   lambda rows: len(rows) == 1 and rows[0]['device_count'] == 3,
                   'three-device-roster-not-settled')
    exact_mirror(third, group, text, event)
    if direct_observations is not None:
        direct_lookup(third, group, target, 'third-after-pairing', direct_observations)
    for index, origin in enumerate((a, b, third)):
        text = 'native-one-scan-three-device-send-' + str(index)
        if origin is a:
            event = a.ask('send-text', group=group, text=text)['message']
        else:
            token = 'three-device-token-' + str(index)
            origin.ask('send-token', group=group, text=text, token=token)
            event = confirmed(origin, group, token)
        for receiver in (a, contact):
            eventually(lambda p=receiver: p.ask('message-seen', group=group, message=event, text=text),
                       lambda v: v['seen'], 'three-device-ordinary-peer-delivery')
        for receiver in (b, third):
            exact_mirror(receiver, group, text, event)
    later = b.ask('create-chat', member=target)['group']
    accept(contact, later)
    later_text = 'native-one-scan-later-chat-from-second-device'
    later_event = b.ask('send-text', group=later, text=later_text)['message']
    for receiver in (a, third):
        exact_mirror(receiver, later, later_text, later_event)
    summary = dict(current_existing_display_fresh_scanner=enrollment["bootstrap_kind"] == "wnpair2",
                   single_bootstrap_per_new_device=True,
                   existing_device_explicit_review=True,
                   stale_review_denied=True, roster_size=3,
                   existing_and_later_chats=True,
                   send_from_each_device=True)
    return text, event, later, summary


def main():
    index = sys.argv.index('--agent-provenance')
    provenance = json.loads(Path(sys.argv[index + 1]).read_text())
    require(provenance.get('current_factories') is True
            and provenance.get('current_factory_identity') == IDENTITY,
            'separate-current-factory-derived-agent-required')
    fragment = Path(__file__).with_name('current-factory-commands.swift.txt')
    require(provenance.get('current_factory_commands_sha256') == hashlib.sha256(fragment.read_bytes()).hexdigest(),
            'exact-current-factory-command-source-required')
    observed.original_pair = current_pair
    observed.frozen.third_device_chats = current_third_device_chats
    result = observed.main()
    output = Path(sys.argv[sys.argv.index('--output') + 1]) / 'result.json'
    value = json.loads(output.read_text())
    value['current_factory_identity'] = IDENTITY
    value['current_factory_driver_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    output.write_text(json.dumps(value, indent=2) + '\n')
    return result


if __name__ == '__main__':
    raise SystemExit(main())
