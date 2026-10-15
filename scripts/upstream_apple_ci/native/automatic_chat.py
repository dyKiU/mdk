#!/usr/bin/env python3
"""Private native automatic sharing acceptance. Aggregate stdout; private isolated IPC."""
import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
from pathlib import Path
import time
from concurrent.futures import ThreadPoolExecutor
import cross_host
from cross_host import Peer, GateFailure, require, first_pair, third_device


def eventually(read, predicate, stage, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = read()
        if predicate(value):
            return value
        time.sleep(0.1)
    raise GateFailure(stage)


def accept(peer, group):
    eventually(lambda: peer.ask('ordinary-invitations'), lambda rows: group in rows,
               'ordinary-independent-invitation')
    peer.ask('ordinary-accept', group=group)


def mirror(peer, group, text):
    eventually(lambda: peer.ask('automatic-list'), lambda value: group in value['paired_groups'],
               'automatic-normal-chat-list')
    return eventually(lambda: peer.ask('automatic-conversation', group=group, text=text),
                      lambda value: value['paired_source'] and bool(value['matching_ids']),
                      'automatic-normal-conversation-history')


def require_completed_originals(a, b, c=None):
    if c is None:
        phases = [a.ask('snapshot')['phase'], b.ask('snapshot')['phase']]
        require(phases == ['enrollmentComplete', 'enrollmentComplete'],
                'held-ab-originals-remain-completed')
    else:
        phases = [a.ask('snapshot')['phase'], c.ask('snapshot')['phase'],
                  b.ask('approval-snapshot')['phase']]
        require(phases == ['enrollmentComplete', 'enrollmentComplete', 'settled'],
                'held-abc-originals-remain-completed')


def confirmed(peer, group, token):
    value = eventually(lambda: peer.ask('send-token-status', group=group, token=token),
                       lambda value: value['state'] in ('completed', 'rejected'), 'forwarding-canonical-receipt')
    require(value['state'] == 'completed' and len(value.get('ordinary_ids', [])) == 1,
            'forwarding-not-confirmed-with-real-id')
    return value['ordinary_ids'][0]


def exact_mirror(peer, group, text, event):
    value = mirror(peer, group, text)
    require(value['matching_ids'] == [event], 'exact-one-source-attested-event')
    rows = peer.ask('automatic-list')['paired_groups']
    require(rows.count(group) == 1, 'exact-one-canonical-chat-row')


def held_sibling_source(a, b, c, d, outsider):
    group = b.ask('create-chat', member=outsider)['group']
    accept(d, group)
    text = 'native-held-abc-b-owned-history'
    event = b.ask('send-text', group=group, text=text)['message']
    eventually(lambda: d.ask('message-seen', group=group, message=event, text=text),
               lambda value: value['seen'], 'held-b-independent-ordinary-delivery')
    for receiver in (a,c):
        exact_mirror(receiver, group, text, event)
    require_completed_originals(a,b,c)


def concurrent_groups(a, b, outsider):
    # Separate actual runtimes execute concurrently; each Peer has a single caller.
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(a.ask, 'create-chat', member=outsider)
        second = pool.submit(b.ask, 'create-chat', member=outsider)
        groups = (first.result()['group'], second.result()['group'])
    require(groups[0] != groups[1], 'concurrent-same-title-canonical-identity')
    return groups


def reconciliation_extension(a, b, c, d, outsider, commands, output, peers):
    groups = concurrent_groups(a, b, outsider)
    for index, (source, recipient, group) in enumerate(zip((a,b), (b,a), groups)):
        accept(d, group)
        text = 'native-concurrent-history-' + str(index)
        event = source.ask('send-text', group=group, text=text)['message']
        eventually(lambda: d.ask('message-seen', group=group, message=event, text=text),
                   lambda value: value['seen'], 'concurrent-independent-ordinary-delivery')
        for receiver in (recipient, c):
            exact_mirror(receiver, group, text, event)
            # Fresh public windows read the same canonical row/event repeatedly.
            # This is rescan dedup evidence, not injected duplicate wire announcements.
            exact_mirror(receiver, group, text, event)
    b.close()
    offline_group = a.ask('create-chat', member=outsider)['group']
    require(offline_group not in groups, 'offline-new-canonical-chat')
    accept(d, offline_group)
    text = 'native-recipient-offline-history'
    event = a.ask('send-text', group=offline_group, text=text)['message']
    eventually(lambda: d.ask('message-seen', group=offline_group, message=event, text=text),
               lambda value: value['seen'], 'offline-recipient-source-ordinary-delivery')
    # The same positively closed root reopens through supported public account resume.
    b = Peer(commands['recipient'], output/'recipient-reopened-private-stderr.log')
    peers.append(b)
    b.ask('resume')
    exact_mirror(b, offline_group, text, event)
    return b


def withdrawal_probe(a, b, c, d, incoming, hidden, commands, output, peers):
    # Local projection deletion retains actual MLS membership. It must not mint
    # an account-wide departure/tombstone or withdraw already-approved siblings.
    hidden_group, hidden_text, hidden_event = hidden
    require(a.ask('ordinary-delete-local', group=hidden_group)['changed'], 'actual-local-hide')
    require(hidden_group not in a.ask('automatic-list')['local_groups'], 'local-hide-not-visible')
    exact_mirror(b, hidden_group, hidden_text, hidden_event)
    exact_mirror(c, hidden_group, hidden_text, hidden_event)
    fresh = 'native-local-hide-fresh-ordinary-recreation'
    fresh_id = d.ask('send-text', group=hidden_group, text=fresh)['message']
    eventually(lambda: a.ask('message-seen', group=hidden_group, message=fresh_id, text=fresh),
               lambda value: value['seen'], 'local-hide-retains-real-decryption')
    require(hidden_group in a.ask('automatic-list')['local_groups'], 'fresh-traffic-recreates-local-chat')
    # Incoming group was created by independent D, accepted by A before pairing.
    # A is an actual ordinary non-admin member; no role edits or fake group rows.
    group, text, event = incoming
    for receiver in (b,c):
        exact_mirror(receiver, group, text, event)
    require(a.ask('ordinary-leave', group=group)['published'] >= 1, 'actual-nonadmin-leave-publication')
    eventually(lambda: d.ask('group-state', group=group), lambda value: value['members'] == 1,
               'independent-canonical-member-removal')
    for receiver in (b,c):
        eventually(lambda: receiver.ask('automatic-list'),
                   lambda value: group not in value['paired_groups'], 'committed-leave-withdrawal')
    a.close()
    b.close()
    a = Peer(commands['source'], output/'source-withdrawal-reopened-private-stderr.log')
    b = Peer(commands['recipient'], output/'recipient-withdrawal-reopened-private-stderr.log')
    peers.extend((a,b))
    a.ask('resume')
    b.ask('resume')
    # Keep the live third recipient observing renewal after encrypted reopen.
    # A new ordinary message in the unrelated still-member chat is a witness
    # that fresh automatic transport has resumed, rather than an immediate
    # absence check before actors have negotiated.
    witness = 'native-withdrawal-renewal-witness'
    canonical = a.ask('send-text', group=hidden_group, text=witness)['message']
    for receiver in (b,c):
        exact_mirror(receiver, hidden_group, witness, canonical)
        require(group not in receiver.ask('automatic-list')['paired_groups'],
                'old-active-catalog-cannot-resurrect-left-chat')
    return a,b


def reopen_peer(peer, role, commands, output, peers, suffix):
    peer.close()
    replacement = Peer(commands[role], output/(role+'-'+suffix+'-private-stderr.log'))
    peers.append(replacement)
    replacement.ask('resume')
    return replacement


def absent(peer, group, stage):
    eventually(lambda: peer.ask('automatic-list'),
               lambda value: group not in value['paired_groups'] and group not in value['local_groups'], stage)


def unshared_for(peers, group, stage):
    until = time.monotonic() + 20
    while time.monotonic() < until:
        for peer in peers:
            value = peer.ask('automatic-list')
            require(group not in value['paired_groups'] and group not in value['local_groups'], stage)
        time.sleep(0.25)


def fresh_rejoin_probe(a, b, c, d, incoming, identity, witness, commands, output, peers):
    group, text, event = incoming
    for peer in (b,c):
        exact_mirror(peer, group, text, event)
    require(a.ask('ordinary-leave', group=group)['published'] >= 1, 'rejoin-device-self-remove')
    eventually(lambda: d.ask('group-state', group=group), lambda value: value['members'] == 1,
               'rejoin-independent-canonical-removal')
    for peer in (b,c):
        absent(peer, group, 'rejoin-old-source-withdrawn')
    b.close()  # Rejoin and acceptance occur while a genuine recipient is offline.
    require(d.ask('ordinary-invite', group=group, member=identity['account'])['published'] >= 1,
            'fresh-same-canonical-group-invite')
    eventually(lambda: a.ask('ordinary-invitations'), lambda rows: group in rows,
               'fresh-rejoin-welcome-pending')
    pending = 'native-fresh-rejoin-pending-message'
    pending_id = d.ask('send-text', group=group, text=pending)['message']
    eventually(lambda: a.ask('message-seen', group=group, message=pending_id, text=pending),
               lambda value: value['seen'], 'fresh-rejoin-real-welcome-decryption')
    require(group in a.ask('ordinary-invitations'), 'rejoin-decryption-not-acceptance')
    witness_group = witness[0]
    live_text = 'native-rejoin-pending-live-policy-witness'
    live_id = a.ask('send-text', group=witness_group, text=live_text)['message']
    exact_mirror(c, witness_group, live_text, live_id)
    unshared_for((c,), group, 'fresh-pending-origin-not-shared')
    a.ask('ordinary-accept', group=group)
    require(group not in a.ask('ordinary-invitations'), 'fresh-rejoin-explicit-accept-completed')
    accepted = 'native-fresh-rejoin-accepted-message'
    accepted_id = d.ask('send-text', group=group, text=accepted)['message']
    require(accepted_id != pending_id and accepted_id != event, 'fresh-rejoin-new-canonical-event')
    eventually(lambda: a.ask('message-seen', group=group, message=accepted_id, text=accepted),
               lambda value: value['seen'], 'fresh-rejoin-real-member-delivery')
    exact_mirror(c, group, accepted, accepted_id)
    b = Peer(commands['recipient'], output/'recipient-rejoin-private-stderr.log')
    peers.append(b)
    b.ask('resume')
    exact_mirror(b, group, accepted, accepted_id)
    a = reopen_peer(a, 'source', commands, output, peers, 'rejoin')
    b = reopen_peer(b, 'recipient', commands, output, peers, 'rejoin-again')
    fresh = 'native-fresh-rejoin-encrypted-reopen-message'
    fresh_id = a.ask('send-text', group=group, text=fresh)['message']
    eventually(lambda: d.ask('message-seen', group=group, message=fresh_id, text=fresh),
               lambda value: value['seen'], 'rejoined-source-ordinary-send-after-reopen')
    for peer in (b,c):
        exact_mirror(peer, group, fresh, fresh_id)
    return a,b


def departure_observation(peer, group, operation=None):
    value = peer.ask('account-departure-state', group=group)
    require(value['state'] in ('available','pending','needsAdministrator','completed','unavailable'),
            'typed-account-departure-state')
    if operation is not None:
        require(value['operation'] == operation, 'durable-same-departure-operation')
    return value


def departure_send_denied(peer, group, role):
    value = peer.ask('account-departure-denied-send', group=group,
                     text='native-departure-forbidden-post', token='native-departure-denial-'+role)
    require(value['denied'] is True, 'typed-departure-send-refusal')


def account_departure_probe(a, b, c, d, incoming, witness, commands, output, peers):
    # One genuine ordinary non-admin A source plus source-attested B/C mirrors.
    # This does not invent or qualify two ordinary sibling leaves.
    group, text, event = incoming
    for peer in (b,c):
        exact_mirror(peer, group, text, event)
    require(departure_observation(a, group)['state'] == 'available', 'fresh-departure-available')
    b.close()
    admitted = a.ask('account-departure-leave', group=group)
    require(admitted['state'] == 'pending' and bool(admitted['operation']),
            'offline-peer-departure-not-completed')
    operation = admitted['operation']
    eventually(lambda: d.ask('group-state', group=group), lambda value: value['members'] == 1,
               'departure-real-ordinary-self-remove')
    absent(c, group, 'authenticated-account-departure-withdrawal')
    departure_send_denied(c, group, 'pending-third')
    require(departure_observation(a, group, operation)['state'] == 'pending',
            'departure-awaits-offline-peer-receipt')
    a = reopen_peer(a, 'source', commands, output, peers, 'departure')
    require(departure_observation(a, group, operation)['state'] == 'pending',
            'pending-departure-survives-source-reopen')
    b = Peer(commands['recipient'], output/'recipient-departure-private-stderr.log')
    peers.append(b)
    b.ask('resume')
    for peer in (b,c):
        absent(peer, group, 'departure-offline-peer-cannot-resurrect')
    eventually(lambda: departure_observation(a, group, operation),
               lambda value: value['state'] == 'completed', 'actual-all-peer-departure-receipts')
    a = reopen_peer(a, 'source', commands, output, peers, 'departure-completed')
    require(departure_observation(a, group, operation)['state'] == 'completed',
            'completed-departure-survives-reopen')
    witness_group = witness[0]
    live = 'native-account-departure-unrelated-live-witness'
    live_id = a.ask('send-text', group=witness_group, text=live)['message']
    for peer in (b,c):
        exact_mirror(peer, witness_group, live, live_id)
        absent(peer, group, 'durable-negative-fence-after-fresh-channel')
    unshared_for((b,c), group, 'durable-negative-fence-after-fresh-channel')
    for role,peer in zip(('source','recipient','third'),(a,b,c)):
        departure_send_denied(peer, group, role)
    return a,b


def ssh_argv(host, command):
    return ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
            '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2', host, command]


def offline_forwarding(a, c, d, group, commands, output, peers):
    # The sole actual ordinary member goes offline; source-attested siblings stay alive.
    a.close()
    pending_token = 'native-automatic-offline-v1'
    pending_text = 'native-automatic-offline-message'
    queued = c.ask('send-token',group=group,text=pending_text,token=pending_token)
    state = c.ask('send-token-status',group=group,token=pending_token)
    require(state['state'] in ('queued','engine-owned'), 'offline-not-confirmed')
    a = Peer(commands['source'],output/'source-reopened-private-stderr.log')
    peers.append(a)
    a.ask('resume')
    require(c.ask('send-token',group=group,text=pending_text,token=pending_token) == queued,
            'offline-retry-same-admission')
    sent = confirmed(c,group,pending_token)
    eventually(lambda: d.ask('message-seen',group=group,message=sent,text=pending_text),
               lambda value: value['seen'], 'offline-reopen-exact-delivery')
    return a


def worker_argv(argv, binary):
    remote = argv[0] == 'ssh'
    if remote:
        require(len(argv) >= 4 and not argv[1].startswith('-'), 'explicit-remote-host')
    command = argv[2:] if remote else argv
    require(Path(binary).is_absolute(), 'absolute-agent-executable')
    simulator = bool(command and Path(command[0]).name == 'xcrun')
    if simulator:
        require(len(command) == 7 and command[1:3] == ['simctl', 'spawn'] and
                re.fullmatch(r'[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}', command[3]) and
                command[4] == binary, 'supported-simulator-spawn')
    else:
        require(command == [binary, 'serve', argv[-1]], 'supported-native-serve')
    require(command[-2] == 'serve' and Path(command[-1]).is_absolute(), 'explicit-isolated-serve-root')
    # ssh joins arguments into a remote shell command: quote every argument once.
    if remote and simulator:
        command = ['env', 'DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer', *command]
    return ssh_argv(argv[1], shlex.join(command)) if remote else list(command)


def require_cross_device_topology(document):
    roles = document['roles']
    remote = [entry['argv'][0] == 'ssh' for entry in roles.values()]
    require(any(remote) and not all(remote), 'actual-local-and-remote-host-required')
    third = roles['third']['argv']
    command = third[2:] if third[0] == 'ssh' else third
    require(command and Path(command[0]).name == 'xcrun', 'actual-ios-simulator-third-required')


def verified_commands(document, sdk_source):
    require(document.get('sdk_source') == sdk_source, 'commands-sdk-source-mismatch')
    roles = document.get('roles', {})
    require(set(roles) == {'source', 'recipient', 'third', 'outsider'}, 'four-independent-roles')
    result = {}
    stores = set()
    for role, entry in roles.items():
        argv, binary, expected = entry['argv'], entry['binary'], entry['sha256']
        require(isinstance(argv, list) and len(argv) >= 3 and all(isinstance(v, str) for v in argv), 'explicit-supported-argv')
        executable_argv = worker_argv(argv, binary)
        store = (argv[1] if argv[0] == 'ssh' else 'local', argv[-1])
        require(store not in stores, 'independent-store-roots')
        stores.add(store)
        require(binary in argv and len(expected) == 64, 'pinned-agent-executable')
        if argv[0] == 'ssh':
            require(len(argv) >= 4 and not argv[1].startswith('-'), 'explicit-remote-host')
            actual = subprocess.check_output(
                ssh_argv(argv[1], 'shasum -a 256 ' + shlex.quote(binary)),
                text=True, timeout=30).split()[0]
        else:
            actual = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
        require(actual == expected, 'agent-executable-hash-mismatch')
        result[role] = executable_argv
    require(len({tuple(command) for command in result.values()}) == 4, 'independent-stores-and-workers')
    return result


def pending_stranger_probe(a, b, c, d, identity):
    group = d.ask('create-chat', member=identity['account'])['group']
    eventually(lambda: a.ask('ordinary-invitations'), lambda rows: group in rows,
               'actual-stranger-invitation-pending')
    text = 'native-pending-stranger-private-message'
    event = d.ask('send-text', group=group, text=text)['message']
    eventually(lambda: a.ask('message-seen', group=group, message=event, text=text),
               lambda value: value['seen'], 'actual-pending-welcome-membership')
    require(group in a.ask('ordinary-invitations'), 'message-does-not-accept-stranger')
    # A decrypted Welcome is not an explicit invitation acceptance. Observe a
    # real steady-state interval while the approved sibling actor is online.
    until = time.monotonic() + 20
    while time.monotonic() < until:
        for peer in (b, c):
            require(group not in peer.ask('automatic-list')['paired_groups'],
                    'pending-stranger-not-shared')
        time.sleep(0.25)
    require(a.ask('ordinary-decline', group=group)['declined'],
            'actual-explicit-stranger-decline')
    eventually(lambda: d.ask('group-state', group=group),
               lambda value: value['members'] == 1, 'declined-canonical-member-removal')
    require(group not in a.ask('ordinary-invitations'), 'declined-invitation-resolved')
    for peer in (b, c):
        require(group not in peer.ask('automatic-list')['paired_groups'],
                'declined-stranger-not-shared')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commands', type=Path, required=True,
                        help='Private JSON with four argv arrays: source, recipient, third, outsider; isolated serve roots')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sdk-source', required=True)
    parser.add_argument('--pending-stranger-probe', action='store_true',
                        help='Actual paired incoming Welcome requires explicit acceptance before sharing')
    parser.add_argument('--withdrawal-probe', action='store_true',
                        help='Actual non-admin leave and separate local-only hide regression')
    parser.add_argument('--fresh-rejoin-probe', action='store_true',
                        help='Same canonical group, actual new Welcome/explicit accept, offline recipient and encrypted reopen')
    parser.add_argument('--account-departure-probe', action='store_true',
                        help='Future matched SDK: authenticated principal departure, pending offline receipt and durable completion')
    parser.add_argument('--device-revocation-probe', action='store_true',
                        help='Exact third-device removal, settled survivors and no fresh disclosure; requires native revocation driver')
    parser.add_argument('--extended-reconciliation', action='store_true',
                        help='Additional real bidirectional concurrent create and offline recipient acceptance')
    parser.add_argument('--retain-completed-originals', action='store_true',
                        help='Keep real completed AB/ABC handles through discovery, matching installed hosts')
    args = parser.parse_args()
    require(sum((args.withdrawal_probe, args.fresh_rejoin_probe, args.account_departure_probe,
                 args.device_revocation_probe)) <= 1,
            'one-independent-departure-scenario-per-journey')
    require(not args.device_revocation_probe or
            (args.retain_completed_originals and not args.extended_reconciliation and
             not args.pending_stranger_probe), 'revocation-requires-independent-live-original-journey')
    os.umask(0o077)
    require(len(args.sdk_source) == 40 and all(c in '0123456789abcdef' for c in args.sdk_source), 'immutable-sdk-pin')
    require(not args.output.exists(), 'fresh-private-output')
    document = json.loads(args.commands.read_text())
    commands = verified_commands(document, args.sdk_source)
    require_cross_device_topology(document)
    args.output.mkdir(parents=True, mode=0o700)
    peers = []
    failure = None
    revocation_progress = []
    try:
        for role in ('source', 'recipient', 'third', 'outsider'):
            peers.append(Peer(commands[role], args.output/(role+'-private-stderr.log')))
        a,b,c,d = peers
        identity = a.ask('create')
        outsider = d.ask('create')
        group = a.ask('create-chat', member=outsider['account'])['group']
        accept(d, group)
        seed = 'native-automatic-prepair-history'
        original = a.ask('send-text', group=group, text=seed)['message']
        eventually(lambda: d.ask('message-seen', group=group, message=original, text=seed),
                   lambda value: value['seen'], 'prepair-independent-ordinary-delivery')
        incoming = None
        if args.withdrawal_probe or args.fresh_rejoin_probe or args.account_departure_probe:
            incoming_group = d.ask('create-chat', member=identity['account'])['group']
            require(incoming_group != group, 'independent-incoming-canonical-id')
            accept(a, incoming_group)
            incoming_text = 'native-incoming-nonadmin-history'
            incoming_event = d.ask('send-text', group=incoming_group, text=incoming_text)['message']
            eventually(lambda: a.ask('message-seen', group=incoming_group, message=incoming_event, text=incoming_text),
                       lambda value: value['seen'], 'genuine-incoming-ordinary-membership')
            incoming = (incoming_group, incoming_text, incoming_event)
        first_pair(a,b,c,automatic=True,identity=identity,
                   retain_completed=args.retain_completed_originals)
        if args.retain_completed_originals:
            exact_mirror(b,group,seed,original)
            require_completed_originals(a,b)
            # A new explicit third-device ceremony closes the prior originals;
            # automatic AB discovery above did not require their cancellation.
            a.ask('cancel')
            b.ask('cancel')
        third_device(a,b,c,automatic=True,
                     retain_completed=args.retain_completed_originals)
        for peer in (b,c):
            require(original in mirror(peer,group,seed)['matching_ids'], 'prejoin-canonical-history-id')
        # Discovery of a later ordinary chat uses no selected-copy/history action.
        later = a.ask('create-chat', member=outsider['account'])['group']
        require(later != group, 'same-name-chats-have-distinct-canonical-ids')
        accept(d,later)
        future = 'native-automatic-postpair-message'
        canonical = a.ask('send-text', group=later, text=future)['message']
        for peer in (b,c):
            require(canonical in mirror(peer,later,future)['matching_ids'], 'later-canonical-message-id')
        token = 'native-automatic-forwarding-v1'
        text = 'native-automatic-sibling-send'
        admitted = c.ask('send-token',group=later,text=text,token=token)
        repeated = c.ask('send-token',group=later,text=text,token=token)
        require(admitted == repeated and admitted['token'] == token, 'same-token-idempotent-admission')
        sent = confirmed(c,later,token)
        eventually(lambda: d.ask('message-seen',group=later,message=sent,text=text),
                   lambda value: value['seen'], 'independent-ordinary-forwarded-delivery')
        if args.retain_completed_originals:
            held_sibling_source(a,b,c,d,outsider['account'])
        if args.device_revocation_probe:
            from revocation_probe import device_revocation_probe
            require_completed_originals(a,b,c)
            device_revocation_probe(a,b,c,d,outsider['account'],(later,future,canonical),
                                    progress=revocation_progress.append)
        else:
            a = offline_forwarding(a,c,d,later,commands,args.output,peers)
        if args.extended_reconciliation:
            b = reconciliation_extension(a,b,c,d,outsider['account'],commands,args.output,peers)
        if args.pending_stranger_probe:
            pending_stranger_probe(a,b,c,d,identity)
        if args.withdrawal_probe:
            a,b = withdrawal_probe(a,b,c,d,incoming,(later,future,canonical),commands,args.output,peers)
        if args.fresh_rejoin_probe:
            a,b = fresh_rejoin_probe(a,b,c,d,incoming,identity,(later,future,canonical),commands,args.output,peers)
        if args.account_departure_probe:
            a,b = account_departure_probe(a,b,c,d,incoming,(later,future,canonical),commands,args.output,peers)
    except (GateFailure, OSError, ValueError, KeyError) as error:
        failure = str(error) if isinstance(error, GateFailure) else 'native-controller-boundary'
    finally:
        for peer in peers:
            if not peer.closed_successfully:
                try: peer.close()
                except (GateFailure,OSError): failure = failure or 'positive-native-close-required'
    result = {'gate':'automatic-native-chat-sync', 'passed':0 if failure else 1,
              'failed':1 if failure else 0, 'failure':failure, 'sdk_source':args.sdk_source,
              'peers_closed':sum(peer.closed_successfully for peer in peers),
              'commands_manifest_sha256':hashlib.sha256(args.commands.read_bytes()).hexdigest(),
              'controller_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'original_controller_sha256':hashlib.sha256(Path(cross_host.__file__).read_bytes()).hexdigest(),
              'retain_completed_originals': args.retain_completed_originals,
              'extended_reconciliation': args.extended_reconciliation,
              'withdrawal_probe': args.withdrawal_probe,
              'fresh_rejoin_probe': args.fresh_rejoin_probe,
              'account_departure_probe': args.account_departure_probe,
              'device_revocation_probe': args.device_revocation_probe,
              'device_revocation_progress': revocation_progress,
              'revocation_probe_sha256': hashlib.sha256(
                  Path(__file__).with_name('revocation_probe.py').read_bytes()).hexdigest()
                  if args.device_revocation_probe else None,
              'pending_stranger_probe': args.pending_stranger_probe,
              'scope':'Native originals and normal account windows; not installed UI or APNS'}
    (args.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':result['passed'],'failed':result['failed'],'peers_closed':result['peers_closed']}))
    return int(bool(failure))


if __name__ == '__main__': raise SystemExit(main())
