#!/usr/bin/env python3
"""Actual Apple SDK one-scan acceptance; only aggregate evidence leaves private IPC."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import select
import socket
import subprocess
import time

from cross_host import GateFailure, Peer, require, supported_companion
from automatic_chat import accept, exact_mirror, eventually, confirmed


def wait_phase(peer, phase, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = peer.ask('snapshot')
        if value['phase'] == phase:
            return value
        require(value['phase'] not in ('cancelled', 'expired', 'failed'), 'pairing-terminal-before-' + phase)
        time.sleep(0.1)
    raise GateFailure('pairing-timeout-' + phase)


def denied_share(peer):
    value = peer.ask('snapshot')
    try:
        peer.ask('one-scan-share', revision=value['revision'])
    except GateFailure as error:
        require(str(error) == 'agent-one-scan-share-sdk-not-ready', 'comparison-denial-must-be-typed')
        return
    raise GateFailure('enrollment-accepted-before-both-human-comparisons')


def approve_existing_device(existing, display, scanner):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        pending = existing.ask('approval-pending')
        require(pending.get('count') in (0, 1), 'ambiguous-existing-device-approval')
        if pending['count'] == 1:
            break
        time.sleep(0.1)
    else:
        raise GateFailure('existing-device-approval-not-arriving')
    require(all(p.ask('snapshot')['phase'] != 'enrollmentComplete' for p in (display, scanner)),
            'third-device-enrolled-before-existing-device-approval')
    revision = existing.ask('approval-snapshot')['revision']
    reviewed = existing.ask('approval-review', revision=revision)
    require(reviewed.get('review_valid') is True, 'existing-device-review-invalid')
    try:
        existing.ask('approval-share', revision=revision + 1)
    except GateFailure as error:
        require(str(error) == 'agent-original-explicit-broad-sibling-sdk-stale-revision',
                'existing-device-stale-approval-not-typed')
    else:
        raise GateFailure('existing-device-accepted-stale-approval')
    existing.ask('approval-share', revision=revision)


def pair(display, scanner, target=None, existing=None):
    # This is the only cross-device artifact transported by the controller.
    bootstrap = display.ask('one-scan-begin')['packet']
    fields = {'packet': bootstrap}
    if target is not None:
        fields['target'] = target
    scanner.ask('one-scan-approve', **fields)
    del bootstrap
    a = wait_phase(display, 'comparisonAvailable')
    b = wait_phase(scanner, 'comparisonAvailable')
    require(a.get('comparison') and a['comparison'] == b.get('comparison'), 'independent-comparison-mismatch')
    denied_share(display)
    display.ask('confirm', revision=a['revision'])
    denied_share(display)
    b = wait_phase(scanner, 'comparisonAvailable')
    require(b.get('comparison') == a['comparison'], 'comparison-changed-before-second-confirmation')
    scanner.ask('confirm', revision=b['revision'])
    for peer in (display, scanner):
        wait_phase(peer, 'verificationCompleteEnrollmentPending')
    for peer in (display, scanner):
        value = peer.ask('snapshot')
        peer.ask('one-scan-share', revision=value['revision'])
    if existing is not None:
        approve_existing_device(existing, display, scanner)
    for peer in (display, scanner):
        wait_phase(peer, 'enrollmentComplete')
    return dict(single_bootstrap=True, automatic_encrypted_exchange=True,
                both_comparisons_required=True, explicit_bilateral_sharing=True)


def wait_contacts(devices, expected, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        values = [peer.ask('contact-list') for peer in devices]
        require(all(isinstance(v, dict) and isinstance(v.get('accounts'), list) for v in values),
                'invalid-contact-list')
        if all(v['accounts'] == expected for v in values):
            return
        time.sleep(0.1)
    raise GateFailure('live-contact-list-did-not-converge')


def live_contacts(devices, target):
    require(len(devices) == 3, 'three-contact-installations-required')
    wait_contacts(devices, [])
    for origin, follow in zip(devices, (True, False, True)):
        # Signed kind-3 replacements use second-resolution Nostr timestamps.
        time.sleep(1.1)
        result = origin.ask('contact-follow' if follow else 'contact-unfollow', member=target)
        expected = [target] if follow else []
        require(result == {'accounts': expected}, 'contact-mutation-not-committed')
        wait_contacts(devices, expected)
    return dict(installations=3, live_add=True, live_remove=True,
                mutation_from_each_installation=True, peer_invitation_required=False)


def direct_lookup(peer, group, target, role, observations):
    value = peer.ask('direct-lookup', group=group, member=target)
    fields = ('found', 'same_group', 'reusable', 'paired_source')
    require(isinstance(value, dict) and set(value) == set(fields) and
            all(type(value[k]) is bool for k in fields), 'malformed-direct-lookup')
    observations.append(dict(role=role, **{k: value[k] for k in fields}))
    require(all(value[k] for k in ('found', 'same_group', 'reusable')), 'direct-reuse-missing-' + role)
    require(value['paired_source'] == (not role.startswith('source')),
            'direct-route-provenance-mismatch-' + role)


def third_device_chats(a, b, third, contact, target, group, text, event, direct_observations=None):
    exact_mirror(b, group, text, event)
    if direct_observations is not None:
        direct_lookup(b, group, target, 'second-after-pairing', direct_observations)
    a.ask('cancel')
    b.ask('cancel')
    targets = a.ask('targets')
    require(len(targets) == 1 and targets[0]['device_count'] == 2,
            'third-device-needs-existing-two-device-target')
    pair(third, a, target=targets[0]['selector'], existing=b)
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
    summary = dict(single_bootstrap_per_new_device=True,
                   existing_device_explicit_review=True,
                   stale_review_denied=True, roster_size=3,
                   existing_and_later_chats=True,
                   send_from_each_device=True)
    return text, event, later, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--agent-sha256', required=True)
    parser.add_argument('--relay', type=Path, required=True)
    parser.add_argument('--sdk-source', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--port', type=int, default=18485)
    parser.add_argument('--contacts', action='store_true',
                        help='Also verify the public kind-3 list across three independent installations')
    parser.add_argument('--three-device-chats', action='store_true',
                        help='Pair the third contact installation and verify existing/new chats and sends')
    parser.add_argument('--direct-chats', action='store_true',
                        help='Use the actual iOS direct-chat creation API and require lookup reuse after sync')
    args = parser.parse_args()
    if args.three_device_chats and not args.contacts:
        parser.error('--three-device-chats requires --contacts')
    if args.direct_chats and not args.three_device_chats:
        parser.error('--direct-chats requires --three-device-chats')
    require(re.fullmatch('[0-9a-f]{40}', args.sdk_source) is not None, 'full-sdk-source-required')
    require(1024 <= args.port <= 65535, 'loopback-port-bound')
    require(hashlib.sha256(args.agent.read_bytes()).hexdigest() == args.agent_sha256, 'agent-hash-mismatch')
    require(not args.output.exists(), 'fresh-output-required')
    args.output.mkdir(parents=True, mode=0o700)
    os.umask(0o077)
    checks, peers, failure = [], [], None
    direct_observations = []
    relay = None
    with (args.output / 'relay.stderr').open('xb') as relay_log:
        try:
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', args.port))
            relay = subprocess.Popen([str(args.relay), '--port', str(args.port)], stdout=subprocess.PIPE, stderr=relay_log)
            require(bool(select.select([relay.stdout], [], [], 10)[0]), 'relay-ready-timeout')
            require(bool(relay.stdout.readline()) and relay.poll() is None, 'relay-start-refused')
            for reverse in (False, True):
                folder = args.output / ('reverse' if reverse else 'forward')
                folder.mkdir(mode=0o700)
                created = []
                for name in ('source', 'companion'):
                    peer = Peer(['/usr/bin/env', 'NATIVE_ACCEPTANCE_RELAY_PORT=' + str(args.port),
                                 str(args.agent), 'serve', str(folder / name)], folder / (name + '.stderr'))
                    peers.append(peer)
                    created.append(peer)
                a, b = created
                identity = a.ask('create')
                imported = supported_companion(b, identity['secret'])
                require(identity['account'] == imported['account'], 'same-independent-test-identity')
                if args.contacts:
                    third = Peer(['/usr/bin/env', 'NATIVE_ACCEPTANCE_RELAY_PORT=' + str(args.port),
                                  str(args.agent), 'serve', str(folder / 'third')], folder / 'third.stderr')
                    peers.append(third)
                    third_identity = supported_companion(third, identity['secret'])
                    require(third_identity['account'] == identity['account'], 'third-contact-identity-mismatch')
                    contact = Peer(['/usr/bin/env', 'NATIVE_ACCEPTANCE_RELAY_PORT=' + str(args.port),
                                    str(args.agent), 'serve', str(folder / 'contact')], folder / 'contact.stderr')
                    peers.append(contact)
                    contact_identity = contact.ask('create')
                    target = contact_identity['account']
                    del contact_identity['secret']
                del identity['secret']
                if args.three_device_chats:
                    group = a.ask('create-direct-chat' if args.direct_chats else 'create-chat', member=target)['group']
                    accept(contact, group)
                    if args.direct_chats:
                        direct_lookup(a, group, target, 'source-before-pairing', direct_observations)
                    text = 'native-one-scan-before-pairing'
                    event = a.ask('send-text', group=group, text=text)['message']
                    eventually(lambda: contact.ask('message-seen', group=group, message=event, text=text),
                               lambda v: v['seen'], 'ordinary-peer-before-pairing')
                check = pair(b, a) if reverse else pair(a, b)
                if args.three_device_chats:
                    text, event, later, check['three_devices'] = third_device_chats(
                        a, b, third, contact, target, group, text, event,
                        direct_observations if args.direct_chats else None)
                if args.contacts:
                    check['public_contacts'] = live_contacts((a, b, third), target)
                    third.close()
                    peers.remove(third)
                    time.sleep(1.1)
                    a.ask('contact-unfollow', member=target)
                    if args.three_device_chats:
                        offline_text = 'native-one-scan-offline-third-chat'
                        offline_event = b.ask('send-text', group=later, text=offline_text)['message']
                    third = Peer(['/usr/bin/env', 'NATIVE_ACCEPTANCE_RELAY_PORT=' + str(args.port),
                                  str(args.agent), 'serve', str(folder / 'third')], folder / 'third-restart.stderr')
                    peers.append(third)
                    third.ask('resume')
                    wait_contacts((a, b, third), [])
                    if args.three_device_chats:
                        exact_mirror(third, group, text, event)
                        exact_mirror(third, later, offline_text, offline_event)
                        check['three_devices']['offline_chat_recovery'] = True
                    check['public_contacts']['offline_restart_recovery'] = True
                    for peer in (third, contact):
                        peer.close()
                        peers.remove(peer)
                checks.append(dict(reverse=reverse, **check))
                for peer in (a, b):
                    peer.close()
                    peers.remove(peer)
        except (GateFailure, OSError, ValueError, subprocess.SubprocessError) as error:
            failure = str(error) if isinstance(error, GateFailure) else 'controller-refused'
        finally:
            for peer in peers:
                try:
                    peer.close()
                except (GateFailure, OSError):
                    failure = failure or 'agent-cleanup-failed'
            if relay is not None:
                relay.terminate()
                try:
                    relay.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    relay.kill()
                    relay.wait()
                    failure = failure or 'relay-cleanup-timeout'
                relay.stdout.close()
    value = dict(passed=len(checks) if failure is None else 0, failed=int(failure is not None),
                 failure=failure, checks=checks, sdk_source=args.sdk_source,
                 agent_sha256=args.agent_sha256, relay_port=args.port,
                 scope='Actual compiled Apple SDK on isolated native workers and loopback relay. Synthetic identities only; no app UI, platform credential store, iPhone or APNS claim.')
    if args.direct_chats:
        value['direct_lookup_observations'] = direct_observations
    (args.output / 'result.json').write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps(value))
    return int(failure is not None)


if __name__ == '__main__':
    raise SystemExit(main())
